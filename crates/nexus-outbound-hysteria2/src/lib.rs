//! nexus-outbound-hysteria2
//!
//! Hysteria2 出站 adapter：基于 QUIC（RFC 9000）+ DATAGRAM（RFC 9221）的
//! TCP/UDP 代理协议的 clean-room 实现。
//!
//! 协议语义见 `docs/protocols/hysteria2.md`（不拷贝任何既有代码）。
//! 本 crate 覆盖协议中已确认的部分：
//!
//! - QUIC varint 编解码（RFC 9000 §16）：首字节高 2 位决定长度。
//! - TCP 中继：`TcpRequest`（`0x401 | varint地址长 | 地址文本"host:port" |
//!   varint pad长 | pad`）与 `TcpResponse`（`status(1) | varint消息长 | 消息 |
//!   varint pad长 | pad`）。**地址为文本形式**（区别于 SOCKS5/VLESS 二进制）。
//! - UDP 中继：`UdpMessage`（`session_id u32BE | packet_id u16BE | frag_id(1) |
//!   frag_count(1) | varint地址长 | 地址文本 | 载荷`），经 QUIC DATAGRAM 传输。
//! - 最小 HTTP/3 认证：控制流（stream 2）空 SETTINGS 帧；stream 0 上 QPACK
//!   编码的 HEADERS（`:method/:scheme/:authority/:path` + `Hysteria-Auth` +
//!   `Hysteria-CC-RX` + `Hysteria-Padding`）；响应校验 `:status == 233`。
//! - QUIC 传输参数构造：ALPN `h3`、禁用 grease、启用 DATAGRAM、窗口/超时。
//! - 配置门禁：必填项、端口范围、`obfs: gecko` 拒绝、hop ports 解析、
//!   hop-interval 钳制（最小 5s）。
//!
//! 未实现（文档注明，后续增强）：
//! - Salamander 混淆完整实现（需 BLAKE2b 第三方依赖，待评审；配置启用时
//!   fail-closed 返回 `SalamanderNotImplemented`）；
//! - 端口跳跃运行时（定时轮换 + 源地址归一化由上层 driver 完成）；
//! - Brutal CC（`rx_bps` 仅进请求头，不实现固定速率发送）；
//! - 完整 QUIC I/O driver（UDP socket + 事件循环由上层装配；quinn-proto 为 sans-IO）。

#![forbid(unsafe_code)]

use nexus_connectivity::{ConnectivityError, OutboundAdapter, OutboundHandoff};

// ---------- 协议常量 ----------

/// Hysteria2 认证的 HTTP/3 ALPN。
pub const HYSTERIA2_ALPN: &[u8] = b"h3";

/// 认证成功的状态码（`233 HyOK`）。
pub const AUTH_STATUS_OK: u16 = 233;

/// 认证路径。
pub const AUTH_PATH: &str = "/auth";

/// 认证用的伪 authority（协议规定）。
pub const AUTH_AUTHORITY: &str = "hysteria";

/// TCPRequest 帧 ID（QUIC varint 编码）。
pub const TCP_REQUEST_ID: u64 = 0x401;

/// TCPResponse status OK。
pub const TCP_RESPONSE_OK: u8 = 0x00;
/// TCPResponse status Error。
pub const TCP_RESPONSE_ERROR: u8 = 0x01;

/// 认证用控制流 stream id（单向控制流）。
pub const AUTH_CONTROL_STREAM_ID: u64 = 2;
/// 认证用请求 stream id（client-initiated bidi 从 0 开始）。
pub const AUTH_REQUEST_STREAM_ID: u64 = 0;
/// 代理 bidi stream 起始 id（0 被认证占用，从 4 开始、步进 4）。
pub const PROXY_STREAM_ID_START: u64 = 4;
/// 代理 bidi stream 步进。
pub const PROXY_STREAM_ID_STEP: u64 = 4;

/// HTTP/3 空 SETTINGS 帧（控制流上）：`[stream type 0x00, SETTINGS 0x04, len 0x00]`。
pub const H3_SETTINGS_FRAME: &[u8] = &[0x00, 0x04, 0x00];

/// HTTP/3 HEADERS 帧类型。
pub const H3_HEADERS_FRAME_TYPE: u8 = 0x01;

/// 流接收窗口（8MB）。
pub const QUIC_STREAM_RECV_WINDOW: u32 = 8 * 1024 * 1024;
/// 连接接收窗口（20MB）。
pub const QUIC_CONN_RECV_WINDOW: u32 = 20 * 1024 * 1024;
/// 最大空闲超时（30s）。
pub const QUIC_MAX_IDLE_TIMEOUT_SECS: u64 = 30;
/// DATAGRAM 收发队列长度（各 1024）。
pub const QUIC_DATAGRAM_QUEUE_LEN: usize = 1024;
/// 最大并发双向/单向流（各 1024）。
pub const QUIC_MAX_CONCURRENT_STREAMS: u32 = 1024;

/// UDP 最大载荷。
pub const MAX_UDP_PAYLOAD: usize = 4096;

/// Hysteria-Padding 随机串长度范围（256~2048）。
pub const AUTH_PADDING_MIN_LEN: usize = 256;
pub const AUTH_PADDING_MAX_LEN: usize = 2048;

/// hop-interval 最小钳制（5s）。
pub const HOP_INTERVAL_MIN_SECS: u64 = 5;
/// hop-interval 默认（30s）。
pub const HOP_INTERVAL_DEFAULT_SECS: u64 = 30;

/// 保活间隔（10s）。
pub const KEEPALIVE_INTERVAL_SECS: u64 = 10;

// ---------- 结构化错误 ----------

/// Hysteria2 出站结构化错误（不以日志文本代替类型；错误展示绝不回显 password）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2Error {
    /// server 地址为空。
    MissingServer,
    /// 端口超出范围（1~65535）。
    InvalidPort { port: u32 },
    /// password 为空。
    MissingPassword,
    /// 不支持的 obfs 类型（仅 salamander 占位，gecko 明确拒绝）。
    UnsupportedObfs { obfs: String },
    /// obfs=salamander 但未提供 obfs_password。
    MissingObfsPassword,
    /// Salamander 完整实现待后续增强（需 BLAKE2b 依赖评审）。
    SalamanderNotImplemented,
    /// hop ports 解析失败。
    InvalidHopPorts { reason: String },
    /// varint 编码值超出 u62 上限。
    VarintTooLarge { value: u64 },
    /// varint 字节不完整。
    TruncatedVarint,
    /// TCPRequest 帧 ID 不是 0x401。
    InvalidTcpRequestId { id: u64 },
    /// TCPRequest/Response 字节不完整。
    TruncatedTcpFrame,
    /// UDPMessage 字节不完整。
    TruncatedUdpMessage,
    /// UDP 载荷超过上限。
    UdpPayloadTooLarge { len: usize },
    /// 地址为空。
    EmptyAddress,
    /// 认证响应状态码不是 233。
    AuthFailed { status: u16 },
    /// 认证响应缺少 Hysteria-UDP 头。
    MissingUdpHeader,
    /// Hysteria-UDP 头值非法。
    InvalidUdpHeader { value: String },
    /// QPACK 编码失败。
    QpackEncodeError,
    /// 响应 HEADERS 解析失败。
    ResponseParseError { reason: String },
    /// ALPN 不是 h3。
    InvalidAlpn { alpn: String },
    /// pin-sha256 长度非法（应为 32 字节）。
    InvalidPinLength { len: usize },
}

impl core::fmt::Display for Hysteria2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingServer => write!(f, "hysteria2 missing server"),
            Self::InvalidPort { port } => write!(f, "hysteria2 invalid port {port}"),
            Self::MissingPassword => write!(f, "hysteria2 missing password"),
            Self::UnsupportedObfs { obfs } => write!(f, "hysteria2 unsupported obfs '{obfs}'"),
            Self::MissingObfsPassword => write!(f, "hysteria2 missing obfs-password"),
            Self::SalamanderNotImplemented => {
                write!(
                    f,
                    "hysteria2 salamander not implemented (future enhancement)"
                )
            }
            Self::InvalidHopPorts { reason } => {
                write!(f, "hysteria2 invalid hop ports: {reason}")
            }
            Self::VarintTooLarge { value } => write!(f, "hysteria2 varint too large ({value})"),
            Self::TruncatedVarint => write!(f, "hysteria2 truncated varint"),
            Self::InvalidTcpRequestId { id } => {
                write!(f, "hysteria2 invalid tcp request id {id:#x}")
            }
            Self::TruncatedTcpFrame => write!(f, "hysteria2 truncated tcp frame"),
            Self::TruncatedUdpMessage => write!(f, "hysteria2 truncated udp message"),
            Self::UdpPayloadTooLarge { len } => {
                write!(f, "hysteria2 udp payload too large ({len} bytes)")
            }
            Self::EmptyAddress => write!(f, "hysteria2 empty address"),
            Self::AuthFailed { status } => write!(f, "hysteria2 auth failed (status {status})"),
            Self::MissingUdpHeader => write!(f, "hysteria2 missing hysteria-udp header"),
            Self::InvalidUdpHeader { value } => {
                write!(f, "hysteria2 invalid hysteria-udp value '{value}'")
            }
            Self::QpackEncodeError => write!(f, "hysteria2 qpack encode error"),
            Self::ResponseParseError { reason } => {
                write!(f, "hysteria2 response parse error: {reason}")
            }
            Self::InvalidAlpn { alpn } => write!(f, "hysteria2 invalid alpn '{alpn}'"),
            Self::InvalidPinLength { len } => {
                write!(f, "hysteria2 invalid pin-sha256 length ({len}, want 32)")
            }
        }
    }
}

impl std::error::Error for Hysteria2Error {}

// ---------- QUIC varint（RFC 9000 §16） ----------

/// 编码 QUIC varint：首字节高 2 位决定长度（00=1字节，01=2字节，10=4字节，11=8字节）。
pub fn encode_varint(value: u64) -> Result<Vec<u8>, Hysteria2Error> {
    if value > 0x3FFF_FFFF_FFFF_FFFF {
        return Err(Hysteria2Error::VarintTooLarge { value });
    }
    let mut out = Vec::new();
    if value <= 0x3F {
        out.push(value as u8);
    } else if value <= 0x3FFF {
        out.push(0x40 | ((value >> 8) as u8));
        out.push((value & 0xFF) as u8);
    } else if value <= 0x3FFF_FFFF {
        out.push(0x80 | ((value >> 24) as u8));
        out.push(((value >> 16) & 0xFF) as u8);
        out.push(((value >> 8) & 0xFF) as u8);
        out.push((value & 0xFF) as u8);
    } else {
        out.push(0xC0 | ((value >> 56) as u8));
        for i in (0..7).rev() {
            out.push(((value >> (i * 8)) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// 解码 QUIC varint，返回 `(值, 消费字节数)`。
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), Hysteria2Error> {
    if buf.is_empty() {
        return Err(Hysteria2Error::TruncatedVarint);
    }
    let len_bits = buf[0] >> 6;
    let len = match len_bits {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    if buf.len() < len {
        return Err(Hysteria2Error::TruncatedVarint);
    }
    let mut value: u64 = (buf[0] & 0x3F) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Ok((value, len))
}

// ---------- TCP 中继帧 ----------

/// TCPRequest：`0x401(varint) | varint地址长 | 地址文本"host:port" | varint pad长 | pad`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    /// 目标地址文本（`host:port`）。
    pub address: String,
    /// padding（随机字节）。
    pub padding: Vec<u8>,
}

impl TcpRequest {
    /// 编码 TCPRequest。
    pub fn encode(&self) -> Result<Vec<u8>, Hysteria2Error> {
        if self.address.is_empty() {
            return Err(Hysteria2Error::EmptyAddress);
        }
        let mut out = encode_varint(TCP_REQUEST_ID)?;
        let addr_bytes = self.address.as_bytes();
        out.extend(encode_varint(addr_bytes.len() as u64)?);
        out.extend_from_slice(addr_bytes);
        out.extend(encode_varint(self.padding.len() as u64)?);
        out.extend_from_slice(&self.padding);
        Ok(out)
    }

    /// 解码 TCPRequest。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        let (id, mut pos) = decode_varint(buf)?;
        if id != TCP_REQUEST_ID {
            return Err(Hysteria2Error::InvalidTcpRequestId { id });
        }
        let (addr_len, n) = decode_varint(&buf[pos..])?;
        pos += n;
        let addr_len = addr_len as usize;
        if buf.len() < pos + addr_len {
            return Err(Hysteria2Error::TruncatedTcpFrame);
        }
        let address = String::from_utf8_lossy(&buf[pos..pos + addr_len]).to_string();
        pos += addr_len;
        let (pad_len, n) = decode_varint(&buf[pos..])?;
        pos += n;
        let pad_len = pad_len as usize;
        if buf.len() < pos + pad_len {
            return Err(Hysteria2Error::TruncatedTcpFrame);
        }
        let padding = buf[pos..pos + pad_len].to_vec();
        pos += pad_len;
        Ok((Self { address, padding }, pos))
    }
}

/// TCPResponse：`status(1) | varint消息长 | 消息 | varint pad长 | pad`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    /// 状态（0x00=OK，0x01=Error）。
    pub status: u8,
    /// 消息字符串。
    pub message: String,
    /// padding。
    pub padding: Vec<u8>,
}

impl TcpResponse {
    /// 编码 TCPResponse。
    pub fn encode(&self) -> Result<Vec<u8>, Hysteria2Error> {
        let mut out = vec![self.status];
        let msg_bytes = self.message.as_bytes();
        out.extend(encode_varint(msg_bytes.len() as u64)?);
        out.extend_from_slice(msg_bytes);
        out.extend(encode_varint(self.padding.len() as u64)?);
        out.extend_from_slice(&self.padding);
        Ok(out)
    }

    /// 解码 TCPResponse。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        if buf.is_empty() {
            return Err(Hysteria2Error::TruncatedTcpFrame);
        }
        let status = buf[0];
        let mut pos = 1;
        let (msg_len, n) = decode_varint(&buf[pos..])?;
        pos += n;
        let msg_len = msg_len as usize;
        if buf.len() < pos + msg_len {
            return Err(Hysteria2Error::TruncatedTcpFrame);
        }
        let message = String::from_utf8_lossy(&buf[pos..pos + msg_len]).to_string();
        pos += msg_len;
        let (pad_len, n) = decode_varint(&buf[pos..])?;
        pos += n;
        let pad_len = pad_len as usize;
        if buf.len() < pos + pad_len {
            return Err(Hysteria2Error::TruncatedTcpFrame);
        }
        let padding = buf[pos..pos + pad_len].to_vec();
        pos += pad_len;
        Ok((
            Self {
                status,
                message,
                padding,
            },
            pos,
        ))
    }

    /// 是否成功。
    pub fn is_ok(&self) -> bool {
        self.status == TCP_RESPONSE_OK
    }
}

// ---------- UDP 中继帧 ----------

/// UDPMessage：`session_id u32BE | packet_id u16BE | frag_id(1) | frag_count(1) |
/// varint地址长 | 地址文本 | 载荷`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    /// Session ID（本地唯一，u32 大端）。
    pub session_id: u32,
    /// Packet ID（u16 大端）。
    pub packet_id: u16,
    /// Fragment ID（从 0 起）。
    pub fragment_id: u8,
    /// Fragment Count（不分片时为 1）。
    pub fragment_count: u8,
    /// 目标地址文本（`host:port`）。
    pub address: String,
    /// 载荷。
    pub payload: Vec<u8>,
}

impl UdpMessage {
    /// 编码 UDPMessage。
    pub fn encode(&self) -> Result<Vec<u8>, Hysteria2Error> {
        if self.address.is_empty() {
            return Err(Hysteria2Error::EmptyAddress);
        }
        if self.payload.len() > MAX_UDP_PAYLOAD {
            return Err(Hysteria2Error::UdpPayloadTooLarge {
                len: self.payload.len(),
            });
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.push(self.fragment_id);
        out.push(self.fragment_count);
        let addr_bytes = self.address.as_bytes();
        out.extend(encode_varint(addr_bytes.len() as u64)?);
        out.extend_from_slice(addr_bytes);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// 解码 UDPMessage。
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        // 固定头 8 字节：session_id(4) + packet_id(2) + frag_id(1) + frag_count(1)
        if buf.len() < 8 {
            return Err(Hysteria2Error::TruncatedUdpMessage);
        }
        let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
        let fragment_id = buf[6];
        let fragment_count = buf[7];
        let mut pos = 8;
        let (addr_len, n) = decode_varint(&buf[pos..])?;
        pos += n;
        let addr_len = addr_len as usize;
        if buf.len() < pos + addr_len {
            return Err(Hysteria2Error::TruncatedUdpMessage);
        }
        let address = String::from_utf8_lossy(&buf[pos..pos + addr_len]).to_string();
        pos += addr_len;
        let payload = buf[pos..].to_vec();
        pos = buf.len();
        Ok((
            Self {
                session_id,
                packet_id,
                fragment_id,
                fragment_count,
                address,
                payload,
            },
            pos,
        ))
    }
}

// ---------- 最小 QPACK 编码器 ----------

/// QPACK literal field line（不索引、不引用动态表）编码单个头字段。
///
/// 编码格式（RFC 9204 §4.5.4 Literal Field Line Without Name Reference 的简化）：
/// `0x20 | varint(name_len) | name | varint(value_len) | value`。
/// 仅用于认证请求头构造，不实现完整 QPACK。
fn qpack_encode_field(name: &str, value: &str) -> Result<Vec<u8>, Hysteria2Error> {
    if name.is_empty() || name.bytes().any(|b| b > 127) {
        return Err(Hysteria2Error::QpackEncodeError);
    }
    // value 允许非 ASCII（如 password），按字节处理
    let mut out = vec![0x20]; // literal without name reference, no Huffman
    out.extend(encode_varint(name.len() as u64)?);
    out.extend_from_slice(name.as_bytes());
    out.extend(encode_varint(value.len() as u64)?);
    out.extend_from_slice(value.as_bytes());
    Ok(out)
}

/// QPACK 编码一组头字段（按给定顺序）。
pub fn qpack_encode_headers(headers: &[(&str, &str)]) -> Result<Vec<u8>, Hysteria2Error> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend(qpack_encode_field(name, value)?);
    }
    Ok(out)
}

// ---------- HTTP/3 认证 ----------

/// 构造认证 HEADERS 帧载荷（QPACK 编码块）。
///
/// 按协议文档 §2.1 顺序：`:method/:scheme/:authority/:path` +
/// `Hysteria-Auth` + `Hysteria-CC-RX` + `Hysteria-Padding`。
pub fn build_auth_headers(
    password: &str,
    rx_bps: u64,
    padding: &str,
) -> Result<Vec<u8>, Hysteria2Error> {
    let rx_str = rx_bps.to_string();
    let headers: [(&str, &str); 7] = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", AUTH_AUTHORITY),
        (":path", AUTH_PATH),
        ("hysteria-auth", password),
        ("hysteria-cc-rx", rx_str.as_str()),
        ("hysteria-padding", padding),
    ];
    // 头字段名小写化（HTTP/3 要求小写；QPACK 编码前统一）
    let mut out = Vec::new();
    for (name, value) in &headers {
        out.extend(qpack_encode_field(name, value)?);
    }
    Ok(out)
}

/// 构造完整的 HEADERS 帧：`0x01 | varint(载荷长) | 载荷`。
pub fn build_headers_frame(qpack_block: &[u8]) -> Result<Vec<u8>, Hysteria2Error> {
    let mut out = vec![H3_HEADERS_FRAME_TYPE];
    out.extend(encode_varint(qpack_block.len() as u64)?);
    out.extend_from_slice(qpack_block);
    Ok(out)
}

/// 认证响应解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    /// `:status`（必须为 233）。
    pub status: u16,
    /// `Hysteria-UDP`（true/false）。
    pub udp_enabled: bool,
    /// `Hysteria-CC-RX` 响应值：`None` = 未提供；`Some(0)` = 无限制；
    /// `Some(n)` = 具体速率。`"auto"` 按文档映射为 `None`（需自适应）。
    pub cc_rx_bps: Option<u64>,
}

/// 解析认证响应头（已解码的头字段列表）。
///
/// `headers` 为 `(name, value)` 对，name 已小写化。
pub fn parse_auth_response(headers: &[(&str, &str)]) -> Result<AuthResponse, Hysteria2Error> {
    let mut status: Option<u16> = None;
    let mut udp: Option<bool> = None;
    let mut cc_rx: Option<Option<u64>> = None;

    for (name, value) in headers {
        match *name {
            ":status" => {
                let s: u16 = value
                    .parse()
                    .map_err(|_| Hysteria2Error::ResponseParseError {
                        reason: "invalid :status".to_string(),
                    })?;
                status = Some(s);
            }
            "hysteria-udp" => {
                let v = match *value {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(Hysteria2Error::InvalidUdpHeader {
                            value: value.to_string(),
                        });
                    }
                };
                udp = Some(v);
            }
            "hysteria-cc-rx" => {
                let parsed =
                    if *value == "auto" {
                        None
                    } else {
                        Some(value.parse::<u64>().map_err(|_| {
                            Hysteria2Error::ResponseParseError {
                                reason: "invalid hysteria-cc-rx".to_string(),
                            }
                        })?)
                    };
                cc_rx = Some(parsed);
            }
            _ => {} // 未知头忽略（Hysteria-Padding 等）
        }
    }

    let status = status.ok_or(Hysteria2Error::ResponseParseError {
        reason: "missing :status".to_string(),
    })?;
    if status != AUTH_STATUS_OK {
        return Err(Hysteria2Error::AuthFailed { status });
    }
    let udp_enabled = udp.ok_or(Hysteria2Error::MissingUdpHeader)?;

    Ok(AuthResponse {
        status,
        udp_enabled,
        cc_rx_bps: cc_rx.flatten(),
    })
}

// ---------- QUIC 传输配置 ----------

/// Hysteria2 QUIC 传输参数（供上层 driver 构造 quinn-proto `ClientConfig`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTransportParams {
    /// ALPN（固定 `h3`）。
    pub alpn: Vec<u8>,
    /// 是否禁用 QUIC bit greasing（hysteria2 明确禁用）。
    pub grease_disabled: bool,
    /// 是否启用 DATAGRAM（RFC 9221）。
    pub datagram_enabled: bool,
    /// DATAGRAM 收发队列长度。
    pub datagram_queue_len: usize,
    /// 流接收窗口。
    pub stream_recv_window: u32,
    /// 连接接收窗口。
    pub conn_recv_window: u32,
    /// 最大空闲超时（秒）。
    pub max_idle_timeout_secs: u64,
    /// 最大并发双向流。
    pub max_concurrent_bidi_streams: u32,
    /// 最大并发单向流。
    pub max_concurrent_uni_streams: u32,
}

impl Default for QuicTransportParams {
    fn default() -> Self {
        Self {
            alpn: HYSTERIA2_ALPN.to_vec(),
            grease_disabled: true,
            datagram_enabled: true,
            datagram_queue_len: QUIC_DATAGRAM_QUEUE_LEN,
            stream_recv_window: QUIC_STREAM_RECV_WINDOW,
            conn_recv_window: QUIC_CONN_RECV_WINDOW,
            max_idle_timeout_secs: QUIC_MAX_IDLE_TIMEOUT_SECS,
            max_concurrent_bidi_streams: QUIC_MAX_CONCURRENT_STREAMS,
            max_concurrent_uni_streams: QUIC_MAX_CONCURRENT_STREAMS,
        }
    }
}

impl QuicTransportParams {
    /// 校验 ALPN（仅接受 `h3`）。
    pub fn validate_alpn(alpn: &[u8]) -> Result<(), Hysteria2Error> {
        if alpn != HYSTERIA2_ALPN {
            return Err(Hysteria2Error::InvalidAlpn {
                alpn: String::from_utf8_lossy(alpn).to_string(),
            });
        }
        Ok(())
    }
}

// ---------- 端口跳跃 ----------

/// 跳跃端口集合（解析 `ports` 配置，如 `"10000-20000,30000"`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopPorts {
    /// 展开后的端口列表（已排序去重）。
    pub ports: Vec<u16>,
}

impl HopPorts {
    /// 解析端口集合字符串。
    ///
    /// 格式：逗号分隔的端口或端口段，如 `"10000-20000,30000"`。
    /// fail-closed：任何非法片段直接返回错误。
    pub fn parse(s: &str) -> Result<Self, Hysteria2Error> {
        let mut ports = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(Hysteria2Error::InvalidHopPorts {
                    reason: "empty port segment".to_string(),
                });
            }
            if let Some((start_s, end_s)) = part.split_once('-') {
                let start: u16 =
                    start_s
                        .trim()
                        .parse()
                        .map_err(|_| Hysteria2Error::InvalidHopPorts {
                            reason: format!("invalid range start '{start_s}'"),
                        })?;
                let end: u16 =
                    end_s
                        .trim()
                        .parse()
                        .map_err(|_| Hysteria2Error::InvalidHopPorts {
                            reason: format!("invalid range end '{end_s}'"),
                        })?;
                if start > end {
                    return Err(Hysteria2Error::InvalidHopPorts {
                        reason: format!("range start {start} > end {end}"),
                    });
                }
                for p in start..=end {
                    ports.push(p);
                }
            } else {
                let p: u16 = part.parse().map_err(|_| Hysteria2Error::InvalidHopPorts {
                    reason: format!("invalid port '{part}'"),
                })?;
                if p == 0 {
                    return Err(Hysteria2Error::InvalidHopPorts {
                        reason: "port 0 not allowed".to_string(),
                    });
                }
                ports.push(p);
            }
        }
        if ports.is_empty() {
            return Err(Hysteria2Error::InvalidHopPorts {
                reason: "no ports".to_string(),
            });
        }
        ports.sort_unstable();
        ports.dedup();
        Ok(Self { ports })
    }
}

// ---------- Salamander 混淆（占位） ----------

/// Salamander 混淆线格式常量：salt 8 字节。
pub const SALAMANDER_SALT_LEN: usize = 8;
/// Salamander 密钥流哈希长度（BLAKE2b-256）。
pub const SALAMANDER_HASH_LEN: usize = 32;

/// Salamander 混淆（v1 占位）。
///
/// 线格式：`[8字节 salt][payload XOR BLAKE2b-256(key||salt) 循环密钥流]`。
/// 完整实现需 BLAKE2b 第三方依赖（待依赖评审），v1 返回 fail-closed 错误。
#[allow(dead_code)]
pub struct Salamander {
    key: Vec<u8>,
}

impl Salamander {
    /// 创建 Salamander 实例（校验 key 非空）。
    pub fn new(key: &[u8]) -> Result<Self, Hysteria2Error> {
        if key.is_empty() {
            return Err(Hysteria2Error::MissingObfsPassword);
        }
        Ok(Self { key: key.to_vec() })
    }

    /// 加密（seal）：v1 占位，返回 `SalamanderNotImplemented`。
    pub fn seal(&self, _payload: &[u8], _salt: &[u8; 8]) -> Result<Vec<u8>, Hysteria2Error> {
        Err(Hysteria2Error::SalamanderNotImplemented)
    }

    /// 解密（open）：v1 占位，返回 `SalamanderNotImplemented`。
    pub fn open(&self, _packet: &[u8]) -> Result<Vec<u8>, Hysteria2Error> {
        Err(Hysteria2Error::SalamanderNotImplemented)
    }
}

// ---------- 配置 ----------

/// Hysteria2 出站配置。
#[derive(Debug, Clone)]
pub struct Hysteria2Config {
    /// 出站 tag。
    pub tag: String,
    /// 服务器地址（IP 或域名）。
    pub server: String,
    /// QUIC 端口。
    pub port: u16,
    /// 认证密码（`Hysteria-Auth`）。
    pub password: String,
    /// QUIC TLS SNI（为空时用 server host）。
    pub sni: String,
    /// 跳过证书校验。
    pub skip_cert_verify: bool,
    /// 叶子证书 DER 的 SHA-256 pin（32 字节，优先于 insecure）。
    pub pin_sha256: Option<[u8; 32]>,
    /// 上行带宽（Mbps，0=未知）。
    pub up_mbps: u64,
    /// 下行带宽（Mbps，0=未知；→ `Hysteria-CC-RX` 请求头）。
    pub down_mbps: u64,
    /// 混淆类型（`None` 或 `"salamander"`；`"gecko"` 拒绝）。
    pub obfs: Option<String>,
    /// Salamander 预共享 key。
    pub obfs_password: String,
    /// 跳跃端口集合原文（`None` = 不启用）。
    pub ports: Option<String>,
    /// 跳跃间隔（秒，None=默认 30s；钳制最小 5s）。
    pub hop_interval_secs: Option<u64>,
    /// TCP fast-open（默认 true）。
    pub fast_open: bool,
    /// 是否启用 UDP（默认 true；与 server 协商取交集）。
    pub udp: bool,
}

impl Hysteria2Config {
    /// 校验配置（fail-closed）。
    pub fn validate(&self) -> Result<(), Hysteria2Error> {
        if self.server.is_empty() {
            return Err(Hysteria2Error::MissingServer);
        }
        if self.port == 0 {
            return Err(Hysteria2Error::InvalidPort {
                port: self.port as u32,
            });
        }
        if self.password.is_empty() {
            return Err(Hysteria2Error::MissingPassword);
        }
        if let Some(pin) = &self.pin_sha256 {
            if pin.len() != 32 {
                return Err(Hysteria2Error::InvalidPinLength { len: pin.len() });
            }
        }
        match self.obfs.as_deref() {
            None | Some("") => {}
            Some("salamander") => {
                if self.obfs_password.is_empty() {
                    return Err(Hysteria2Error::MissingObfsPassword);
                }
            }
            Some(other) => {
                return Err(Hysteria2Error::UnsupportedObfs {
                    obfs: other.to_string(),
                });
            }
        }
        if let Some(ports) = &self.ports {
            HopPorts::parse(ports)?;
        }
        Ok(())
    }

    /// 有效 SNI（为空时用 server）。
    pub fn effective_sni(&self) -> &str {
        if self.sni.is_empty() {
            &self.server
        } else {
            &self.sni
        }
    }

    /// 有效 hop-interval（秒，钳制最小 5s）。
    pub fn effective_hop_interval_secs(&self) -> u64 {
        let v = self.hop_interval_secs.unwrap_or(HOP_INTERVAL_DEFAULT_SECS);
        v.max(HOP_INTERVAL_MIN_SECS)
    }

    /// 下行带宽转 bytes/s（`Hysteria-CC-RX` 请求头值；0=未知）。
    pub fn rx_bps(&self) -> u64 {
        self.down_mbps.saturating_mul(1_000_000 / 8)
    }

    /// 解析后的 hop ports（未配置时 None）。
    pub fn hop_ports(&self) -> Result<Option<HopPorts>, Hysteria2Error> {
        match &self.ports {
            None => Ok(None),
            Some(s) => Ok(Some(HopPorts::parse(s)?)),
        }
    }
}

// ---------- Adapter ----------

/// Hysteria2 出站 adapter。
pub struct Hysteria2Adapter {
    tag: String,
    config: Hysteria2Config,
}

impl Hysteria2Adapter {
    /// 创建 adapter（先校验配置）。
    pub fn new(tag: &str, config: Hysteria2Config) -> Result<Self, Hysteria2Error> {
        config.validate()?;
        Ok(Self {
            tag: tag.to_string(),
            config,
        })
    }

    /// 从配置创建（tag 取自配置）。
    pub fn from_config(config: Hysteria2Config) -> Result<Self, Hysteria2Error> {
        let tag = config.tag.clone();
        Self::new(&tag, config)
    }

    /// 服务端 locator（`server:port`）。
    pub fn locator(&self) -> String {
        format!("{}:{}", self.config.server, self.config.port)
    }

    /// 配置引用。
    pub fn config(&self) -> &Hysteria2Config {
        &self.config
    }

    /// QUIC 传输参数（供上层 driver 构造 quinn-proto ClientConfig）。
    pub fn quic_transport_params(&self) -> QuicTransportParams {
        QuicTransportParams::default()
    }
}

impl OutboundAdapter for Hysteria2Adapter {
    fn outbound_kind(&self) -> &'static str {
        "hysteria2"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError> {
        Ok(OutboundHandoff {
            kind: self.outbound_kind().to_string(),
            tag: self.tag.clone(),
            locator: locator.to_string(),
        })
    }
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Hysteria2Config {
        Hysteria2Config {
            tag: "hy2-test".to_string(),
            server: "example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            sni: String::new(),
            skip_cert_verify: false,
            pin_sha256: None,
            up_mbps: 0,
            down_mbps: 100,
            obfs: None,
            obfs_password: String::new(),
            ports: None,
            hop_interval_secs: None,
            fast_open: true,
            udp: true,
        }
    }

    // ----- varint -----

    #[test]
    fn varint_encode_1byte() {
        assert_eq!(encode_varint(0).unwrap(), vec![0x00]);
        assert_eq!(encode_varint(63).unwrap(), vec![0x3F]);
    }

    #[test]
    fn varint_encode_2byte() {
        assert_eq!(encode_varint(64).unwrap(), vec![0x40, 0x40]);
        assert_eq!(encode_varint(0x3FFF).unwrap(), vec![0x7F, 0xFF]);
    }

    #[test]
    fn varint_encode_4byte() {
        assert_eq!(encode_varint(0x4000).unwrap(), vec![0x80, 0x00, 0x40, 0x00]);
    }

    #[test]
    fn varint_encode_8byte() {
        let v = encode_varint(0x4000_0000).unwrap();
        assert_eq!(v.len(), 8);
        assert_eq!(v[0] >> 6, 0b11);
    }

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            63,
            64,
            15293,
            0x3FFF,
            0x4000,
            0x3FFF_FFFF,
            0x4000_0000,
        ] {
            let enc = encode_varint(v).unwrap();
            let (dec, n) = decode_varint(&enc).unwrap();
            assert_eq!(dec, v);
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn varint_too_large_rejected() {
        assert!(matches!(
            encode_varint(0x4000_0000_0000_0000),
            Err(Hysteria2Error::VarintTooLarge { .. })
        ));
    }

    #[test]
    fn varint_truncated_rejected() {
        assert!(matches!(
            decode_varint(&[]),
            Err(Hysteria2Error::TruncatedVarint)
        ));
        assert!(matches!(
            decode_varint(&[0x40]),
            Err(Hysteria2Error::TruncatedVarint)
        ));
    }

    // ----- TCP 帧 -----

    #[test]
    fn tcp_request_roundtrip() {
        let req = TcpRequest {
            address: "example.com:443".to_string(),
            padding: vec![1, 2, 3, 4],
        };
        let enc = req.encode().unwrap();
        // 首字段为 varint 0x401
        let (id, _) = decode_varint(&enc).unwrap();
        assert_eq!(id, TCP_REQUEST_ID);
        let (dec, _) = TcpRequest::decode(&enc).unwrap();
        assert_eq!(dec, req);
    }

    #[test]
    fn tcp_request_empty_address_rejected() {
        let req = TcpRequest {
            address: String::new(),
            padding: vec![],
        };
        assert!(matches!(req.encode(), Err(Hysteria2Error::EmptyAddress)));
    }

    #[test]
    fn tcp_request_wrong_id_rejected() {
        let mut bad = encode_varint(0x402).unwrap();
        bad.extend(encode_varint(0).unwrap());
        assert!(matches!(
            TcpRequest::decode(&bad),
            Err(Hysteria2Error::InvalidTcpRequestId { .. })
        ));
    }

    #[test]
    fn tcp_response_roundtrip() {
        let resp = TcpResponse {
            status: TCP_RESPONSE_OK,
            message: "ok".to_string(),
            padding: vec![9, 9],
        };
        let enc = resp.encode().unwrap();
        assert_eq!(enc[0], TCP_RESPONSE_OK);
        let (dec, _) = TcpResponse::decode(&enc).unwrap();
        assert_eq!(dec, resp);
        assert!(dec.is_ok());
    }

    #[test]
    fn tcp_response_error_status() {
        let resp = TcpResponse {
            status: TCP_RESPONSE_ERROR,
            message: "refused".to_string(),
            padding: vec![],
        };
        let enc = resp.encode().unwrap();
        let (dec, _) = TcpResponse::decode(&enc).unwrap();
        assert!(!dec.is_ok());
        assert_eq!(dec.message, "refused");
    }

    // ----- UDP 帧 -----

    #[test]
    fn udp_message_roundtrip() {
        let msg = UdpMessage {
            session_id: 42,
            packet_id: 7,
            fragment_id: 0,
            fragment_count: 1,
            address: "1.2.3.4:53".to_string(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let enc = msg.encode().unwrap();
        // 大端序检查
        assert_eq!(&enc[0..4], &42u32.to_be_bytes());
        assert_eq!(&enc[4..6], &7u16.to_be_bytes());
        assert_eq!(enc[6], 0);
        assert_eq!(enc[7], 1);
        let (dec, _) = UdpMessage::decode(&enc).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn udp_message_too_large_rejected() {
        let msg = UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: "a:1".to_string(),
            payload: vec![0u8; MAX_UDP_PAYLOAD + 1],
        };
        assert!(matches!(
            msg.encode(),
            Err(Hysteria2Error::UdpPayloadTooLarge { .. })
        ));
    }

    #[test]
    fn udp_message_truncated_rejected() {
        assert!(matches!(
            UdpMessage::decode(&[0x00, 0x01]),
            Err(Hysteria2Error::TruncatedUdpMessage)
        ));
    }

    // ----- QPACK / 认证 -----

    #[test]
    fn qpack_field_order_preserved() {
        let headers = [(":method", "POST"), (":path", "/auth")];
        let enc = qpack_encode_headers(&headers).unwrap();
        // 两个 literal field，顺序保留
        assert!(enc.windows(7).any(|w| w == b":method"));
        assert!(enc.windows(5).any(|w| w == b":path"));
        let method_pos = enc.windows(7).position(|w| w == b":method").unwrap();
        let path_pos = enc.windows(5).position(|w| w == b":path").unwrap();
        assert!(method_pos < path_pos);
    }

    #[test]
    fn auth_headers_contains_required_fields() {
        let block = build_auth_headers("secret", 12_500_000, "pad").unwrap();
        for needle in [
            b":method".as_slice(),
            b"hysteria-auth".as_slice(),
            b"hysteria-cc-rx".as_slice(),
            b"hysteria-padding".as_slice(),
        ] {
            assert!(
                block.windows(needle.len()).any(|w| w == needle),
                "missing field"
            );
        }
        // password 不应被截断
        assert!(block.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn headers_frame_format() {
        let block = vec![0xAA, 0xBB];
        let frame = build_headers_frame(&block).unwrap();
        assert_eq!(frame[0], H3_HEADERS_FRAME_TYPE);
        let (len, n) = decode_varint(&frame[1..]).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&frame[1 + n..], &[0xAA, 0xBB]);
    }

    #[test]
    fn auth_response_ok() {
        let headers = [
            (":status", "233"),
            ("hysteria-udp", "true"),
            ("hysteria-cc-rx", "12500000"),
        ];
        let resp = parse_auth_response(&headers).unwrap();
        assert_eq!(resp.status, 233);
        assert!(resp.udp_enabled);
        assert_eq!(resp.cc_rx_bps, Some(12_500_000));
    }

    #[test]
    fn auth_response_auto_cc() {
        let headers = [(":status", "233"), ("hysteria-udp", "false")];
        let resp = parse_auth_response(&headers).unwrap();
        assert!(!resp.udp_enabled);
        assert_eq!(resp.cc_rx_bps, None);
    }

    #[test]
    fn auth_response_non_233_rejected() {
        let headers = [(":status", "404"), ("hysteria-udp", "true")];
        assert!(matches!(
            parse_auth_response(&headers),
            Err(Hysteria2Error::AuthFailed { status: 404 })
        ));
    }

    #[test]
    fn auth_response_missing_udp_rejected() {
        let headers = [(":status", "233")];
        assert!(matches!(
            parse_auth_response(&headers),
            Err(Hysteria2Error::MissingUdpHeader)
        ));
    }

    #[test]
    fn auth_response_bad_udp_value_rejected() {
        let headers = [(":status", "233"), ("hysteria-udp", "maybe")];
        assert!(matches!(
            parse_auth_response(&headers),
            Err(Hysteria2Error::InvalidUdpHeader { .. })
        ));
    }

    // ----- 传输参数 -----

    #[test]
    fn quic_params_defaults() {
        let p = QuicTransportParams::default();
        assert_eq!(p.alpn, b"h3");
        assert!(p.grease_disabled);
        assert!(p.datagram_enabled);
        assert_eq!(p.stream_recv_window, QUIC_STREAM_RECV_WINDOW);
        assert_eq!(p.max_idle_timeout_secs, QUIC_MAX_IDLE_TIMEOUT_SECS);
    }

    #[test]
    fn quic_alpn_validation() {
        assert!(QuicTransportParams::validate_alpn(b"h3").is_ok());
        assert!(matches!(
            QuicTransportParams::validate_alpn(b"h2"),
            Err(Hysteria2Error::InvalidAlpn { .. })
        ));
    }

    // ----- 端口跳跃 -----

    #[test]
    fn hop_ports_parse() {
        let hp = HopPorts::parse("10000-10002,30000").unwrap();
        assert_eq!(hp.ports, vec![10000, 10001, 10002, 30000]);
    }

    #[test]
    fn hop_ports_single() {
        let hp = HopPorts::parse("443").unwrap();
        assert_eq!(hp.ports, vec![443]);
    }

    #[test]
    fn hop_ports_invalid() {
        assert!(HopPorts::parse("").is_err());
        assert!(HopPorts::parse("20000-10000").is_err());
        assert!(HopPorts::parse("abc").is_err());
        assert!(HopPorts::parse("0").is_err());
    }

    #[test]
    fn hop_ports_dedup_sorted() {
        let hp = HopPorts::parse("30000,10000-10001,10000").unwrap();
        assert_eq!(hp.ports, vec![10000, 10001, 30000]);
    }

    // ----- 配置 -----

    #[test]
    fn config_validate_ok() {
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn config_missing_server_rejected() {
        let mut c = test_config();
        c.server = String::new();
        assert!(matches!(c.validate(), Err(Hysteria2Error::MissingServer)));
    }

    #[test]
    fn config_missing_password_rejected() {
        let mut c = test_config();
        c.password = String::new();
        assert!(matches!(c.validate(), Err(Hysteria2Error::MissingPassword)));
    }

    #[test]
    fn config_gecko_rejected() {
        let mut c = test_config();
        c.obfs = Some("gecko".to_string());
        assert!(matches!(
            c.validate(),
            Err(Hysteria2Error::UnsupportedObfs { .. })
        ));
    }

    #[test]
    fn config_salamander_requires_password() {
        let mut c = test_config();
        c.obfs = Some("salamander".to_string());
        // 未设 obfs_password → 拒绝
        assert!(matches!(
            c.validate(),
            Err(Hysteria2Error::MissingObfsPassword)
        ));
        c.obfs_password = "s".to_string();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_effective_sni() {
        let c = test_config();
        assert_eq!(c.effective_sni(), "example.com");
        let mut c2 = c.clone();
        c2.sni = "sni.example".to_string();
        assert_eq!(c2.effective_sni(), "sni.example");
    }

    #[test]
    fn config_hop_interval_clamped() {
        let mut c = test_config();
        c.hop_interval_secs = Some(1);
        assert_eq!(c.effective_hop_interval_secs(), HOP_INTERVAL_MIN_SECS);
        c.hop_interval_secs = Some(60);
        assert_eq!(c.effective_hop_interval_secs(), 60);
        c.hop_interval_secs = None;
        assert_eq!(c.effective_hop_interval_secs(), HOP_INTERVAL_DEFAULT_SECS);
    }

    #[test]
    fn config_rx_bps() {
        let c = test_config(); // down_mbps = 100
        assert_eq!(c.rx_bps(), 12_500_000);
    }

    // ----- Salamander 占位 -----

    #[test]
    fn salamander_not_implemented() {
        let s = Salamander::new(b"key").unwrap();
        assert!(matches!(
            s.seal(b"payload", &[0u8; 8]),
            Err(Hysteria2Error::SalamanderNotImplemented)
        ));
        assert!(matches!(
            s.open(b"packet"),
            Err(Hysteria2Error::SalamanderNotImplemented)
        ));
    }

    #[test]
    fn salamander_empty_key_rejected() {
        assert!(matches!(
            Salamander::new(b""),
            Err(Hysteria2Error::MissingObfsPassword)
        ));
    }

    // ----- Adapter -----

    #[test]
    fn adapter_kind_tag_handoff() {
        let cfg = test_config();
        let a = Hysteria2Adapter::from_config(cfg).unwrap();
        assert_eq!(a.outbound_kind(), "hysteria2");
        assert_eq!(a.tag(), "hy2-test");
        assert_eq!(a.locator(), "example.com:443");
        let h = a.handoff("example.com:443").unwrap();
        assert_eq!(h.kind, "hysteria2");
        assert_eq!(h.tag, "hy2-test");
    }

    #[test]
    fn adapter_rejects_bad_config() {
        let mut cfg = test_config();
        cfg.password = String::new();
        assert!(Hysteria2Adapter::from_config(cfg).is_err());
    }

    #[test]
    fn error_display_no_password_leak() {
        // 错误展示绝不回显 password
        let e = Hysteria2Error::MissingPassword;
        assert!(!format!("{e}").contains("secret"));
        let e2 = Hysteria2Error::UnsupportedObfs {
            obfs: "gecko".to_string(),
        };
        assert!(format!("{e2}").contains("gecko")); // obfs 名可显示
    }
}
