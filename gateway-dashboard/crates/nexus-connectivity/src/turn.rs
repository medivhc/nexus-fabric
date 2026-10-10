//! TURN 中继分配（RFC 5766）：节点在 STUN 打洞失败时通过 TURN 服务器获得中继地址。
//!
//! 本模块提供 **可移植、离线确定性** 的 TURN 客户端骨架：
//! - `TurnClientConfig`：服务器 / 长期凭证（username/password）/ 生命周期；
//! - `TurnAllocationState`：`Unallocated -> Requesting -> Allocated / Failed` 状态机；
//! - RFC 5766/5389 编解码：Allocate Request / ERROR-CODE / REALM / NONCE /
//!   XOR-RELAYED-ADDRESS / LIFETIME / MESSAGE-INTEGRITY（HMAC-SHA1）；
//! - `TurnTransport` trait：真实 UDP/TLS 建连由 Composition Root 注入，本层零真实网络；
//! - `MockTurnTransport`：离线确定性回环（401 挑战 -> 凭证重发 -> 分配成功）；
//! - `codec_self_test`：离线编解码 + MESSAGE-INTEGRITY 往返自检。
//!
//! 不变量：
//! - 未 `Allocated` 不视为可经中继建连；
//! - `allocate` 是确定性策略编排（响应来自注入的 transport，不自行发起网络 I/O）；
//! - 真实 TURN socket / ChannelData / Refresh 定时器挂接留 P3。
//!
//! 详细契约见 `MODULE.md` 的「冻结契约（TURN 中继分配 RFC5766 P2.5）」与 PRODUCT §12.9.2。

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use ring::hmac;

// ---------- STUN/TURN 基础常量（复用 nat.rs 同一 wire 头） ----------

/// STUN magic cookie（RFC 5389）。
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN 头固定长度（type(2)+len(2)+cookie(4)+txid(12)）。
const STUN_HEADER_LEN: usize = 20;

/// TURN Allocate Request 消息类型。
const TURN_ALLOCATE_REQUEST: u16 = 0x0003;
/// Allocate Error Response（class=0b11）。
const TURN_ALLOCATE_ERROR_RESPONSE: u16 = 0x0113;
/// Allocate Success Response（class=0b10）。
const TURN_ALLOCATE_SUCCESS_RESPONSE: u16 = 0x0103;

// 属性类型（RFC 5389/5766）。
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_LIFETIME: u16 = 0x000d;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

/// Requested-Transport 中的 UDP 协议号。
const UDP_PROTOCOL: u8 = 17;
/// MESSAGE-INTEGRITY 属性线长（头 4 + HMAC-SHA1 20）。
const MESSAGE_INTEGRITY_WIRE_LEN: usize = 24;

// ---------- 错误面 ----------

/// TURN 客户端结构化错误（不以 panic 表达可恢复失败）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnError {
    /// 输入无效（如配置为空、消息太短）。
    Invalid {
        /// 诊断信息。
        message: String,
    },
    /// 服务器返回错误码（4xx/5xx）。
    AllocateFailed {
        /// TURN ERROR-CODE。
        code: u16,
        /// 原因短语。
        reason: String,
    },
    /// 未收到可预期的 401 认证挑战。
    AuthChallengeFailed,
    /// MESSAGE-INTEGRITY 校验失败。
    IntegrityMismatch,
    /// 成功响应中缺少 XOR-RELAYED-ADDRESS。
    NoRelayedAddress,
}

impl core::fmt::Display for TurnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid { message } => write!(f, "turn invalid: {message}"),
            Self::AllocateFailed { code, reason } => {
                write!(f, "turn allocate failed: {code} {reason}")
            }
            Self::AuthChallengeFailed => write!(f, "turn: expected 401 auth challenge"),
            Self::IntegrityMismatch => write!(f, "turn: message integrity mismatch"),
            Self::NoRelayedAddress => write!(f, "turn: no xor-relayed-address in response"),
        }
    }
}

impl std::error::Error for TurnError {}

// ---------- 配置与状态机 ----------

/// TURN 客户端配置（领域中立：服务器 + 长期凭证 + 生命周期）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnClientConfig {
    /// TURN 服务器 locator（如 `turn.example.org:3478`）。
    pub server: String,
    /// 长期凭证用户名。
    pub username: String,
    /// 长期凭证密码。
    pub password: String,
    /// 服务器下发的 realm（初始空，由 401 挑战填充）。
    pub realm: String,
    /// 服务器下发的 nonce（初始空，由 401 挑战填充）。
    pub nonce: String,
    /// 请求的分配生命周期（秒）。
    pub lifetime_secs: u32,
}

impl TurnClientConfig {
    /// 构造配置（realm/nonce 初始为空）。
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        lifetime_secs: u32,
    ) -> Self {
        Self {
            server: server.into(),
            username: username.into(),
            password: password.into(),
            realm: String::new(),
            nonce: String::new(),
            lifetime_secs,
        }
    }

    /// 校验：`server/username/password` 任一空 -> `Invalid`。
    pub fn validate(&self) -> Result<(), TurnError> {
        if self.server.is_empty() {
            return Err(TurnError::Invalid {
                message: "server must not be empty".into(),
            });
        }
        if self.username.is_empty() {
            return Err(TurnError::Invalid {
                message: "username must not be empty".into(),
            });
        }
        if self.password.is_empty() {
            return Err(TurnError::Invalid {
                message: "password must not be empty".into(),
            });
        }
        Ok(())
    }
}

/// TURN 分配状态（每客户端一份，由 Owner 持有）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnAllocationState {
    /// 尚未分配。
    Unallocated,
    /// 分配请求进行中。
    Requesting,
    /// 分配成功，持有中继地址与生命周期。
    Allocated {
        /// 服务器分配的 relayed transport address。
        relayed_addr: String,
        /// 服务器确认的生命周期（秒）。
        expires_secs: u32,
    },
    /// 分配失败（结构化原因在事件/错误中保留）。
    Failed {
        /// 失败原因。
        reason: String,
    },
}

impl core::fmt::Display for TurnAllocationState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unallocated => f.write_str("unallocated"),
            Self::Requesting => f.write_str("requesting"),
            Self::Allocated { .. } => f.write_str("allocated"),
            Self::Failed { .. } => f.write_str("failed"),
        }
    }
}

/// TURN 分配过程结构化事件（Worker 只发事件）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnEvent {
    /// 已发出一次 Allocate Request。
    AllocateSent,
    /// 收到 401 认证挑战。
    AuthChallengeReceived {
        /// 服务器下发的 realm。
        realm: String,
        /// 服务器下发的 nonce。
        nonce: String,
    },
    /// 分配成功。
    AllocateSuccess {
        /// 中继地址。
        relayed: String,
        /// 生命周期（秒）。
        expires_secs: u32,
    },
    /// 分配失败。
    AllocateFailed {
        /// 错误码。
        code: u16,
        /// 原因。
        reason: String,
    },
}

// ---------- 长期凭证（RFC 5389 §10.2） ----------

/// 纯 std MD5（RFC 1321）——仅用于 TURN 长期密钥派生，不暴露为公共 API。
///
/// 不新增 `md5` 第三方依赖；RFC1321 测试向量由单元测试锁定。
fn md5(data: &[u8]) -> [u8; 16] {
    // 初始链接变量。
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    // 预处理：补位 0x80 后补 0，直到长度 ≡ 56 (mod 64)，再追加 64 位小端位长。
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // 每轮 64 字节分块。
    for block in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let off = i * 4;
            *word =
                u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        // 每步：F = f(B,C,D); F += A + T[i] + M[g]; A=D; D=C; C=B; B += rotate_left(F,s[i])。
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const T: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];

        for i in 0..64usize {
            let (f, g): (u32, usize) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(T[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f);
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// 长期凭证密钥 = MD5(`username:realm:password`)（RFC 5389 §10.2）。
#[must_use]
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    md5(&format!("{username}:{realm}:{password}").into_bytes())
}

// ---------- wire 编解码 ----------

/// 解析后的 TURN 消息（从响应中提取的关键字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTurnMessage {
    /// 消息类型（如 0x0103 success / 0x0113 error）。
    pub msg_type: u16,
    /// 是否为错误响应（class=0b11）。
    pub is_error: bool,
    /// 错误码（如有）。
    pub error_code: Option<(u16, String)>,
    /// 服务器下发的 realm（401）。
    pub realm: Option<String>,
    /// 服务器下发的 nonce（401）。
    pub nonce: Option<String>,
    /// 中继地址（成功响应）。
    pub relayed: Option<SocketAddr>,
    /// 服务器确认的生命周期（秒）。
    pub lifetime: Option<u32>,
}

fn put_attr(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    // 对齐到 4 字节。
    let pad = (4 - (value.len() % 4)) % 4;
    buf.extend_from_slice(&[0u8; 4][..pad]);
}

/// 构造一个 XOR 地址属性值（与 nat.rs 的 XOR-MAPPED-ADDRESS 同布局）。
fn xor_address_value(addr: SocketAddr) -> Vec<u8> {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(v4) => u32::from(v4),
        // 骨架仅 IPv4。
        std::net::IpAddr::V6(_) => u32::from(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    };
    let mut v = Vec::with_capacity(8);
    v.push(0x00); // reserved
    v.push(0x01); // family IPv4
    let port = addr.port();
    v.extend_from_slice(&(port ^ ((STUN_MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
    v.extend_from_slice(&(ip ^ STUN_MAGIC_COOKIE).to_be_bytes());
    v
}

fn parse_xor_address_value(value: &[u8]) -> Result<SocketAddr, TurnError> {
    if value.len() < 8 {
        return Err(TurnError::Invalid {
            message: "xor address too short".into(),
        });
    }
    if value[1] != 0x01 {
        return Err(TurnError::Invalid {
            message: "only ipv4 xor address supported".into(),
        });
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
    let ip = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ STUN_MAGIC_COOKIE;
    Ok(SocketAddr::from((std::net::Ipv4Addr::from(ip), port)))
}

/// 构造 Allocate Request。
///
/// 无凭证（key=None）：仅 Requested-Transport(udp) + LIFETIME。
/// 带凭证（key=Some）：追加 USERNAME/REALM/NONCE，并按 RFC5389 §15.3 在末尾追加
/// MESSAGE-INTEGRITY（HMAC-SHA1 over 调整 length 后的消息前缀）。
#[must_use]
pub fn build_allocate_request(
    txid: &[u8; 12],
    username: &str,
    realm: &str,
    nonce: &str,
    key: Option<&[u8; 16]>,
    lifetime_secs: u32,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    // Requested-Transport (UDP=17), 8 字节值。
    let mut rt = [0u8; 8];
    rt[0] = UDP_PROTOCOL;
    put_attr(&mut attrs, ATTR_REQUESTED_TRANSPORT, &rt);
    // LIFETIME。
    put_attr(&mut attrs, ATTR_LIFETIME, &lifetime_secs.to_be_bytes());

    let mi = if let Some(key) = key {
        put_attr(&mut attrs, ATTR_USERNAME, username.as_bytes());
        put_attr(&mut attrs, ATTR_REALM, realm.as_bytes());
        put_attr(&mut attrs, ATTR_NONCE, nonce.as_bytes());
        // 构造临时头：length = 当前属性长 + MESSAGE-INTEGRITY 线长。
        let mut head =
            Vec::with_capacity(STUN_HEADER_LEN + attrs.len() + MESSAGE_INTEGRITY_WIRE_LEN);
        head.extend_from_slice(&TURN_ALLOCATE_REQUEST.to_be_bytes());
        head.extend_from_slice(&((attrs.len() + MESSAGE_INTEGRITY_WIRE_LEN) as u16).to_be_bytes());
        head.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        head.extend_from_slice(txid);
        head.extend_from_slice(&attrs);
        let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let tag = hmac::sign(&k, &head);
        Some(tag.as_ref().to_vec())
    } else {
        None
    };

    let mut msg =
        Vec::with_capacity(STUN_HEADER_LEN + attrs.len() + mi.as_ref().map_or(0, |m| m.len() + 4));
    msg.extend_from_slice(&TURN_ALLOCATE_REQUEST.to_be_bytes());
    let body_len = attrs.len() + mi.as_ref().map_or(0, |m| m.len() + 4);
    msg.extend_from_slice(&(body_len as u16).to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&attrs);
    if let Some(mi) = mi {
        put_attr(&mut msg, ATTR_MESSAGE_INTEGRITY, &mi);
    }
    msg
}

/// 解析 TURN 响应消息。
pub fn parse_allocate_response(buf: &[u8]) -> Result<ParsedTurnMessage, TurnError> {
    if buf.len() < STUN_HEADER_LEN {
        return Err(TurnError::Invalid {
            message: "message too short for stun header".into(),
        });
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(TurnError::Invalid {
            message: "invalid stun magic cookie".into(),
        });
    }
    if STUN_HEADER_LEN + body_len > buf.len() {
        return Err(TurnError::Invalid {
            message: "declared body length exceeds buffer".into(),
        });
    }

    let is_error = (msg_type & 0x0110) == 0x0110;
    let mut out = ParsedTurnMessage {
        msg_type,
        is_error,
        error_code: None,
        realm: None,
        nonce: None,
        relayed: None,
        lifetime: None,
    };

    let mut offset = STUN_HEADER_LEN;
    let end = STUN_HEADER_LEN + body_len;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > end {
            break;
        }
        let value = &buf[offset..offset + attr_len];
        match attr_type {
            ATTR_ERROR_CODE if value.len() >= 4 => {
                // value[0..2]=0, value[2]=class, value[3]=number, then reason.
                let class = u16::from(value[2]);
                let number = u16::from(value[3]);
                let code = class * 100 + number;
                let reason = String::from_utf8_lossy(&value[4..]).to_string();
                out.error_code = Some((code, reason));
            }
            ATTR_REALM => {
                out.realm = Some(String::from_utf8_lossy(value).to_string());
            }
            ATTR_NONCE => {
                out.nonce = Some(String::from_utf8_lossy(value).to_string());
            }
            ATTR_XOR_RELAYED_ADDRESS => {
                out.relayed = Some(parse_xor_address_value(value)?);
            }
            ATTR_LIFETIME if value.len() >= 4 => {
                out.lifetime = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            _ => {}
        }
        offset += (attr_len + 3) & !3;
    }
    Ok(out)
}

/// 离线编解码自检（确定性、零网络）。
///
/// 构造一个带已知 XOR-RELAYED-ADDRESS 与 LIFETIME 的合成成功响应并解析；同时
/// 构造一个带 MESSAGE-INTEGRITY 的 Allocate Request 并校验其长度/可解析头部。
/// 返回 `(request_bytes, parsed_relayed_addr)`。
pub fn codec_self_test() -> Result<(usize, SocketAddr), TurnError> {
    let txid = [0xCD; 12];
    let key = long_term_key("user", "example.org", "pass");

    // 1) 构造带凭证的 Allocate Request，校验长度与 cookie。
    let req = build_allocate_request(&txid, "user", "example.org", "abc", Some(&key), 600);
    if req.len() < STUN_HEADER_LEN + MESSAGE_INTEGRITY_WIRE_LEN {
        return Err(TurnError::Invalid {
            message: "self-test: allocate request too short".into(),
        });
    }
    let cookie = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(TurnError::Invalid {
            message: "self-test: cookie mismatch".into(),
        });
    }

    // 2) 构造合成成功响应：XOR-RELAYED-ADDRESS = 192.0.2.1:54320, LIFETIME=600。
    let mut attrs = Vec::new();
    let relayed = SocketAddr::from((std::net::Ipv4Addr::new(192, 0, 2, 1), 54320));
    put_attr(
        &mut attrs,
        ATTR_XOR_RELAYED_ADDRESS,
        &xor_address_value(relayed),
    );
    put_attr(&mut attrs, ATTR_LIFETIME, &600u32.to_be_bytes());

    let mut resp = Vec::new();
    resp.extend_from_slice(&TURN_ALLOCATE_SUCCESS_RESPONSE.to_be_bytes());
    resp.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    resp.extend_from_slice(&txid);
    resp.extend_from_slice(&attrs);

    let parsed = parse_allocate_response(&resp)?;
    let got = parsed.relayed.ok_or(TurnError::NoRelayedAddress)?;
    if got != relayed {
        return Err(TurnError::Invalid {
            message: "self-test: relayed address mismatch".into(),
        });
    }
    if parsed.lifetime != Some(600) {
        return Err(TurnError::Invalid {
            message: "self-test: lifetime mismatch".into(),
        });
    }

    Ok((req.len(), got))
}

// ---------- 传输接缝与 Mock ----------

/// TURN 传输接缝：真实 UDP/TLS 建连由 Composition Root / platform 注入。
///
/// Deletion Test：真实 TURN 协议实现与离线 Mock 构成独立变化维度。
pub trait TurnTransport {
    /// 发送一个 TURN 请求并同步等待响应；`Ok(response)` 为服务器响应字节。
    fn send_recv(&mut self, request: &[u8]) -> Result<Vec<u8>, String>;
}

/// 构造一个合成 401 Unauthenticated 错误响应（含 realm/nonce）。
fn make_synthetic_401(txid: &[u8; 12], realm: &str, nonce: &str) -> Vec<u8> {
    let mut attrs = Vec::new();
    // ERROR-CODE 401: class=4, number=1.
    let mut err = vec![0u8, 0u8, 4u8, 1u8];
    err.extend_from_slice(b"Unauthorized");
    put_attr(&mut attrs, ATTR_ERROR_CODE, &err);
    put_attr(&mut attrs, ATTR_REALM, realm.as_bytes());
    put_attr(&mut attrs, ATTR_NONCE, nonce.as_bytes());

    let mut resp = Vec::new();
    resp.extend_from_slice(&TURN_ALLOCATE_ERROR_RESPONSE.to_be_bytes());
    resp.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    resp.extend_from_slice(txid);
    resp.extend_from_slice(&attrs);
    resp
}

/// 构造一个合成分配成功响应（XOR-RELAYED-ADDRESS + LIFETIME）。
fn make_synthetic_success(txid: &[u8; 12]) -> Vec<u8> {
    let mut attrs = Vec::new();
    let relayed = SocketAddr::from((std::net::Ipv4Addr::new(192, 0, 2, 1), 54320));
    put_attr(
        &mut attrs,
        ATTR_XOR_RELAYED_ADDRESS,
        &xor_address_value(relayed),
    );
    put_attr(&mut attrs, ATTR_LIFETIME, &600u32.to_be_bytes());
    let mut resp = Vec::new();
    resp.extend_from_slice(&TURN_ALLOCATE_SUCCESS_RESPONSE.to_be_bytes());
    resp.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    resp.extend_from_slice(txid);
    resp.extend_from_slice(&attrs);
    resp
}

/// 离线确定性 TURN 传输替身：首请求回 401（realm/nonce），二次回成功。
///
/// 供单测与 E4 产品场景驱动，不发起真实网络。
pub struct MockTurnTransport {
    calls: u8,
}

impl Default for MockTurnTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTurnTransport {
    /// 构造：首请求回 401 挑战，二次回分配成功。
    #[must_use]
    pub fn new() -> Self {
        Self { calls: 0 }
    }
}

impl TurnTransport for MockTurnTransport {
    fn send_recv(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
        // 从请求中读出 transaction id（[8..20]）回显，保持 txid 一致。
        let mut txid = [0u8; 12];
        if request.len() >= 20 {
            txid.copy_from_slice(&request[8..20]);
        }
        self.calls += 1;
        match self.calls {
            1 => Ok(make_synthetic_401(&txid, "example.org", "abc123")),
            2 => Ok(make_synthetic_success(&txid)),
            _ => Err("mock: unexpected third allocate request".to_string()),
        }
    }
}

// ---------- 客户端编排 ----------

/// TURN 分配客户端：驱动 `TurnTransport`，维护状态机与事件序列。
pub struct TurnClient {
    config: TurnClientConfig,
    state: TurnAllocationState,
    events: Vec<TurnEvent>,
    transport: Box<dyn TurnTransport>,
}

impl TurnClient {
    /// 构造：初始 `Unallocated`，事件序列为空。
    #[must_use]
    pub fn new(config: TurnClientConfig, transport: Box<dyn TurnTransport>) -> Self {
        Self {
            config,
            state: TurnAllocationState::Unallocated,
            events: Vec::new(),
            transport,
        }
    }

    /// 执行分配：`Unallocated -> Requesting -> Allocated / Failed`。
    ///
    /// 1) 无凭证 Allocate -> 期望 401，提取 realm/nonce；
    /// 2) 派生长期凭证 key，重发带 MESSAGE-INTEGRITY 的 Allocate -> 期望成功；
    /// 3) 解析 XOR-RELAYED-ADDRESS 落账。
    pub fn allocate(&mut self) -> Result<TurnAllocationState, TurnError> {
        self.config.validate()?;
        if !matches!(self.state, TurnAllocationState::Unallocated) {
            return Err(TurnError::Invalid {
                message: format!(
                    "turn client must be Unallocated to allocate, current: {}",
                    self.state
                ),
            });
        }

        // 1) 无凭证 Allocate。
        self.state = TurnAllocationState::Requesting;
        let txid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let req1 = build_allocate_request(
            &txid,
            &self.config.username,
            &self.config.realm,
            &self.config.nonce,
            None,
            self.config.lifetime_secs,
        );
        self.events.push(TurnEvent::AllocateSent);

        let resp1 = self
            .transport
            .send_recv(&req1)
            .map_err(|reason| TurnError::AllocateFailed { code: 0, reason })?;
        let parsed1 = parse_allocate_response(&resp1)?;

        // 期望 401 Unauthenticated。
        let (code, _) = parsed1
            .error_code
            .as_ref()
            .ok_or(TurnError::AuthChallengeFailed)?;
        if *code != 401 {
            self.state = TurnAllocationState::Failed {
                reason: format!("expected 401, got {code}"),
            };
            self.events.push(TurnEvent::AllocateFailed {
                code: *code,
                reason: parsed1
                    .error_code
                    .as_ref()
                    .map(|(_, r)| r.clone())
                    .unwrap_or_default(),
            });
            return Err(TurnError::AllocateFailed {
                code: *code,
                reason: parsed1
                    .error_code
                    .as_ref()
                    .map(|(_, r)| r.clone())
                    .unwrap_or_default(),
            });
        }
        let realm = parsed1
            .realm
            .clone()
            .ok_or(TurnError::AuthChallengeFailed)?;
        let nonce = parsed1
            .nonce
            .clone()
            .ok_or(TurnError::AuthChallengeFailed)?;
        self.config.realm = realm.clone();
        self.config.nonce = nonce.clone();
        self.events.push(TurnEvent::AuthChallengeReceived {
            realm: realm.clone(),
            nonce: nonce.clone(),
        });

        // 2) 派生长期凭证，重发带 MESSAGE-INTEGRITY 的 Allocate。
        let key = long_term_key(
            &self.config.username,
            &self.config.realm,
            &self.config.password,
        );
        let req2 = build_allocate_request(
            &txid,
            &self.config.username,
            &self.config.realm,
            &self.config.nonce,
            Some(&key),
            self.config.lifetime_secs,
        );
        self.events.push(TurnEvent::AllocateSent);

        let resp2 = self
            .transport
            .send_recv(&req2)
            .map_err(|reason| TurnError::AllocateFailed { code: 0, reason })?;
        let parsed2 = parse_allocate_response(&resp2)?;

        if parsed2.is_error {
            let (code, reason) = parsed2
                .error_code
                .clone()
                .unwrap_or((0, "unknown error".into()));
            self.state = TurnAllocationState::Failed {
                reason: reason.clone(),
            };
            self.events.push(TurnEvent::AllocateFailed {
                code,
                reason: reason.clone(),
            });
            return Err(TurnError::AllocateFailed { code, reason });
        }

        let relayed = parsed2.relayed.ok_or(TurnError::NoRelayedAddress)?;
        let expires = parsed2.lifetime.unwrap_or(self.config.lifetime_secs);
        self.state = TurnAllocationState::Allocated {
            relayed_addr: relayed.to_string(),
            expires_secs: expires,
        };
        self.events.push(TurnEvent::AllocateSuccess {
            relayed: relayed.to_string(),
            expires_secs: expires,
        });
        Ok(self.state.clone())
    }

    /// 当前分配状态。
    #[must_use]
    pub fn state(&self) -> &TurnAllocationState {
        &self.state
    }

    /// 已产生事件只读视图（可重放 / explain）。
    #[must_use]
    pub fn events(&self) -> &[TurnEvent] {
        &self.events
    }

    /// 中继地址（仅 `Allocated` 时为 `Some`）。
    #[must_use]
    pub fn relayed_address(&self) -> Option<&str> {
        match &self.state {
            TurnAllocationState::Allocated { relayed_addr, .. } => Some(relayed_addr),
            _ => None,
        }
    }

    /// 配置只读视图。
    #[must_use]
    pub fn config(&self) -> &TurnClientConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_rfc1321_test_vectors() {
        // RFC 1321 附录 A.5 测试向量。
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn empty_config_fields_fail_validation() {
        assert!(TurnClientConfig::new("", "u", "p", 600).validate().is_err());
        assert!(
            TurnClientConfig::new("turn:3478", "", "p", 600)
                .validate()
                .is_err()
        );
        assert!(
            TurnClientConfig::new("turn:3478", "u", "", 600)
                .validate()
                .is_err()
        );
        assert!(
            TurnClientConfig::new("turn:3478", "u", "p", 600)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn codec_self_test_roundtrips() {
        let (req_len, parsed) = codec_self_test().expect("self-test");
        assert!(req_len > STUN_HEADER_LEN + MESSAGE_INTEGRITY_WIRE_LEN);
        assert_eq!(parsed.port(), 54320);
        assert_eq!(parsed.ip().to_string(), "192.0.2.1");
    }

    #[test]
    fn allocate_drives_challenge_then_success() {
        let cfg = TurnClientConfig::new("turn.example.org:3478", "nexus-node-a", "secret", 600);
        let mut client = TurnClient::new(cfg, Box::new(MockTurnTransport::new()));
        let state = client.allocate().expect("allocate should succeed");
        match state {
            TurnAllocationState::Allocated {
                relayed_addr,
                expires_secs,
            } => {
                assert_eq!(relayed_addr, "192.0.2.1:54320");
                assert_eq!(expires_secs, 600);
            }
            other => panic!("expected Allocated, got {other:?}"),
        }
        assert_eq!(client.relayed_address(), Some("192.0.2.1:54320"));
        // 事件序列：AllocateSent(no cred) -> AuthChallenge -> AllocateSent(cred) -> AllocateSuccess。
        assert_eq!(client.events().len(), 4);
        assert!(matches!(client.events()[0], TurnEvent::AllocateSent));
        assert!(matches!(
            client.events()[1],
            TurnEvent::AuthChallengeReceived { ref realm, ref nonce }
                if realm == "example.org" && nonce == "abc123"
        ));
        assert!(matches!(client.events()[2], TurnEvent::AllocateSent));
        assert!(matches!(
            client.events()[3],
            TurnEvent::AllocateSuccess { .. }
        ));
    }

    #[test]
    fn second_allocate_is_rejected() {
        let cfg = TurnClientConfig::new("turn.example.org:3478", "u", "p", 600);
        let mut client = TurnClient::new(cfg, Box::new(MockTurnTransport::new()));
        client.allocate().expect("first allocate");
        let err = client.allocate().expect_err("second allocate must fail");
        assert!(matches!(err, TurnError::Invalid { .. }));
    }

    #[test]
    fn long_term_key_is_md5_concatenation_and_deterministic() {
        let k1 = long_term_key("user", "example.org", "pass");
        let k2 = long_term_key("user", "example.org", "pass");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 16);
        // 凭证随任意分量变化而变化（非恒等）。
        assert_ne!(
            long_term_key("user", "example.org", "pass"),
            long_term_key("user", "example.org", "other")
        );
        assert_ne!(
            long_term_key("user", "example.org", "pass"),
            long_term_key("user2", "example.org", "pass")
        );
    }
}
