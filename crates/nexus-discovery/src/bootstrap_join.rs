//! Bootstrap 自动入网外层帧（v2 §5.2）。
//!
//! 与数据面共用同一 UDP socket，以 magic 前缀 `nxb:`（首字节 `0x6E`，与
//! NXP1 管线 `0x4E` / `hs:` `0x68` / `ph:pa:` `0x70` / AEAD `0x01` / 明文头
//! `0x30..=0x39` 两两互斥）做确定性分流。剥掉 magic 后的 payload 有两种：
//!
//! - **Plain 明文握手帧**（JoinInit/JoinReply/Error）：外层 tag `0x10/0x11/0x12`，
//!   只含 X25519 公钥与申请值，不含秘密；
//! - **Secured 会话密文**：首个 AEAD 控制帧起，整段为 `encrypt_frame` 输出，
//!   首字节恒为 `0x01`（`WIRE_VERSION`）。
//!
//! Secured 必须用「首字节 == 0x01 且长度足够」显式探针判定；**禁止**用
//! 「未知外层 tag 即当密文」的 fallback（未来扩展外层 tag 时会误判，v2 M1）。
//!
//! 字节规则与 `auto_discovery` 一致：u16 BE 长度前缀字符串 + UTF-8，u32/u64
//! 大端；未知 tag / 截断 / 非法 UTF-8 / trailing bytes 一律 `Transport`。

use crate::{DiscoveryError, get_str, put_str};

/// 外层 magic（`0x6E 0x78 0x62 0x3A`，即 ASCII "nxb:"）。
pub const NXB_MAGIC: &[u8; 4] = b"nxb:";

/// 外层 tag：必须避开数据面 `0x01`(WIRE_VERSION) / `0x02`(HANDSHAKE_RESP) /
/// `0x03`(FRAME_DATA)——剥掉 `nxb:` 后 Secured 密文首字节恒为 `0x01`。
pub const OUTER_JOIN_INIT: u8 = 0x10;
/// S -> C，明文握手响应。
pub const OUTER_JOIN_REPLY: u8 = 0x11;
/// 服务端错误（见 v2 §5.3：线上 AuthFailed 对 PSK 不符不可达）。
pub const OUTER_ERROR: u8 = 0x12;

/// Secured 探针最小长度：AEAD 定长帧头（22B）+ Poly1305 tag（16B）= 38B。
/// discovery 不依赖 connectivity 的 `encryption` 模块，此处按 wire 布局固化。
const SECURED_MIN_LEN: usize = 22 + 16;

/// Bootstrap 错误码（v2 §5.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapErrorCode {
    /// PSK 认证失败。
    AuthFailed = 1,
    /// 申请 VIP 不合法 / 不在 CIDR。
    BadVip = 2,
    /// VIP 冲突（保留语义；软冲突时不回，改在 JoinReply 注明实际值）。
    VipConflict = 3,
    /// 对端未开启 bootstrap 服务端角色。
    NotBootstrap = 4,
    /// 半开/速率触顶。
    RateLimited = 5,
    /// 控制帧格式损坏。
    MalformedFrame = 6,
}

impl BootstrapErrorCode {
    /// 在线编码为单字节（确定性）。
    #[must_use]
    pub fn wire(self) -> u8 {
        self as u8
    }

    /// 从单字节解码；未知码 -> `Transport`。
    pub fn from_wire(b: u8) -> Result<Self, DiscoveryError> {
        match b {
            1 => Ok(Self::AuthFailed),
            2 => Ok(Self::BadVip),
            3 => Ok(Self::VipConflict),
            4 => Ok(Self::NotBootstrap),
            5 => Ok(Self::RateLimited),
            6 => Ok(Self::MalformedFrame),
            other => Err(DiscoveryError::Transport(format!(
                "unknown bootstrap error code: {other}"
            ))),
        }
    }
}

/// Bootstrap 外层明文帧（C<->S 握手阶段；认证后内层走 AEAD）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapJoinFrame {
    /// C -> S，明文：发起入网。仅 X25519 公钥 + 申请值，无秘密。
    JoinInit {
        /// 客户端临时 ephemeral 公钥（32B）。
        eph_pub: [u8; 32],
        /// 客户端持久 static 公钥（32B；权威 node_id 派生来源）。
        static_pub: [u8; 32],
        /// VIP 申请值；`None` = 请服务端权威分配。
        requested_vip: Option<String>,
        /// 客户端随机 nonce（与 server_nonce 绑定进 AEAD 明文前缀，M3）。
        client_nonce: u64,
    },
    /// S -> C，明文：入网应答，权威确认 VIP。
    JoinReply {
        /// 服务端临时 ephemeral 公钥（32B）。
        eph_pub: [u8; 32],
        /// 服务端持久 static 公钥（32B）。
        static_pub: [u8; 32],
        /// 服务端权威确认的 VIP（客户端一律以此为准）。
        assigned_vip: String,
        /// 注册租约秒数。
        lease_secs: u32,
        /// 心跳间隔毫秒。
        hb_interval_ms: u32,
        /// PeerList 刷新间隔毫秒。
        refresh_interval_ms: u32,
        /// 服务端随机 nonce（与 client_nonce 绑定）。
        server_nonce: u64,
    },
    /// 服务端错误（小体积；未认证阶段不回敏感信息）。
    Error {
        /// 错误码。
        code: BootstrapErrorCode,
        /// 可读消息。
        message: String,
    },
}

/// 剥掉 `NXB_MAGIC` 后的外层判别结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OuterFrame<'a> {
    /// 已认证会话密文：交会话 `decrypt_frame` + `ReplayWindow`。
    Secured(&'a [u8]),
    /// 明文握手帧。
    Plain(BootstrapJoinFrame),
}

/// 写入 u32（大端 4 字节）。
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// 读取 u32（大端 4 字节）；越界 -> `Transport`。
fn get_u32(buf: &[u8], pos: &mut usize) -> Result<u32, DiscoveryError> {
    if *pos + 4 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_be_bytes(bytes))
}

/// 写入 u64（大端 8 字节）。
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// 读取 u64（大端 8 字节）；越界 -> `Transport`。
fn get_u64(buf: &[u8], pos: &mut usize) -> Result<u64, DiscoveryError> {
    if *pos + 8 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_be_bytes(bytes))
}

/// 读取固定 32B 公钥；越界 -> `Transport`。
fn get_pubkey(buf: &[u8], pos: &mut usize) -> Result<[u8; 32], DiscoveryError> {
    if *pos + 32 > buf.len() {
        return Err(DiscoveryError::Transport("frame truncated".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[*pos..*pos + 32]);
    *pos += 32;
    Ok(key)
}

/// 校验解码已消费全部字节。
fn expect_frame_end(payload: &[u8], pos: usize) -> Result<(), DiscoveryError> {
    if pos != payload.len() {
        return Err(DiscoveryError::Transport("trailing bytes".into()));
    }
    Ok(())
}

/// 编码一帧外层明文握手帧（**不含** `nxb:` magic；上线路径由调用方前置 magic）。
///
/// 确定性、可移植、无新依赖；字符串 = u16 BE 长度前缀 + UTF-8。
pub fn encode_join_frame(frame: &BootstrapJoinFrame) -> Result<Vec<u8>, DiscoveryError> {
    let mut out = Vec::new();
    match frame {
        BootstrapJoinFrame::JoinInit {
            eph_pub,
            static_pub,
            requested_vip,
            client_nonce,
        } => {
            out.push(OUTER_JOIN_INIT);
            out.extend_from_slice(eph_pub);
            out.extend_from_slice(static_pub);
            match requested_vip {
                None => out.push(0u8),
                Some(v) => {
                    out.push(1u8);
                    put_str(&mut out, v)?;
                }
            }
            put_u64(&mut out, *client_nonce);
        }
        BootstrapJoinFrame::JoinReply {
            eph_pub,
            static_pub,
            assigned_vip,
            lease_secs,
            hb_interval_ms,
            refresh_interval_ms,
            server_nonce,
        } => {
            out.push(OUTER_JOIN_REPLY);
            out.extend_from_slice(eph_pub);
            out.extend_from_slice(static_pub);
            put_str(&mut out, assigned_vip)?;
            put_u32(&mut out, *lease_secs);
            put_u32(&mut out, *hb_interval_ms);
            put_u32(&mut out, *refresh_interval_ms);
            put_u64(&mut out, *server_nonce);
        }
        BootstrapJoinFrame::Error { code, message } => {
            out.push(OUTER_ERROR);
            out.push(code.wire());
            put_str(&mut out, message)?;
        }
    }
    Ok(out)
}

/// 编码一帧并前置 `nxb:` magic（上线路径便捷函数）。
pub fn encode_join_frame_wire(frame: &BootstrapJoinFrame) -> Result<Vec<u8>, DiscoveryError> {
    let body = encode_join_frame(frame)?;
    let mut out = Vec::with_capacity(NXB_MAGIC.len() + body.len());
    out.extend_from_slice(NXB_MAGIC);
    out.extend(body);
    Ok(out)
}

/// 解码一帧外层明文握手帧（与 [`encode_join_frame`] 对偶；不含 magic）。
/// 空帧 / 未知 tag / 截断 / 非法 UTF-8 / trailing bytes 一律 `Transport`。
pub fn decode_join_frame(payload: &[u8]) -> Result<BootstrapJoinFrame, DiscoveryError> {
    let Some(&tag) = payload.first() else {
        return Err(DiscoveryError::Transport("empty join frame".into()));
    };
    let mut pos = 1;
    match tag {
        OUTER_JOIN_INIT => {
            let eph_pub = get_pubkey(payload, &mut pos)?;
            let static_pub = get_pubkey(payload, &mut pos)?;
            if pos >= payload.len() {
                return Err(DiscoveryError::Transport("frame truncated".into()));
            }
            let presence = payload[pos];
            pos += 1;
            let requested_vip = match presence {
                0 => None,
                1 => Some(get_str(payload, &mut pos)?),
                other => {
                    return Err(DiscoveryError::Transport(format!(
                        "bad requested_vip presence: {other}"
                    )));
                }
            };
            let client_nonce = get_u64(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(BootstrapJoinFrame::JoinInit {
                eph_pub,
                static_pub,
                requested_vip,
                client_nonce,
            })
        }
        OUTER_JOIN_REPLY => {
            let eph_pub = get_pubkey(payload, &mut pos)?;
            let static_pub = get_pubkey(payload, &mut pos)?;
            let assigned_vip = get_str(payload, &mut pos)?;
            let lease_secs = get_u32(payload, &mut pos)?;
            let hb_interval_ms = get_u32(payload, &mut pos)?;
            let refresh_interval_ms = get_u32(payload, &mut pos)?;
            let server_nonce = get_u64(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(BootstrapJoinFrame::JoinReply {
                eph_pub,
                static_pub,
                assigned_vip,
                lease_secs,
                hb_interval_ms,
                refresh_interval_ms,
                server_nonce,
            })
        }
        OUTER_ERROR => {
            if pos >= payload.len() {
                return Err(DiscoveryError::Transport("frame truncated".into()));
            }
            let code = BootstrapErrorCode::from_wire(payload[pos])?;
            pos += 1;
            let message = get_str(payload, &mut pos)?;
            expect_frame_end(payload, pos)?;
            Ok(BootstrapJoinFrame::Error { code, message })
        }
        other => Err(DiscoveryError::Transport(format!(
            "unknown bootstrap outer tag: {other:#04x}"
        ))),
    }
}

/// 判别外层 payload（**已剥掉 `NXB_MAGIC`**）。
///
/// Secured 探针：首字节 == `0x01`（WIRE_VERSION）且 `len >= 22(帧头)+16(tag)=38`。
/// 未知外层 tag **不**当密文 fallback（M1），直接报 `Transport`。
pub fn split_outer(payload: &[u8]) -> Result<OuterFrame<'_>, DiscoveryError> {
    if payload.is_empty() {
        return Err(DiscoveryError::Transport("empty nxb payload".into()));
    }
    if payload[0] == 0x01 && payload.len() >= SECURED_MIN_LEN {
        return Ok(OuterFrame::Secured(payload));
    }
    let frame = decode_join_frame(payload)?;
    Ok(OuterFrame::Plain(frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_frame_roundtrip_all_variants() {
        let frames = vec![
            BootstrapJoinFrame::JoinInit {
                eph_pub: [1u8; 32],
                static_pub: [2u8; 32],
                requested_vip: None,
                client_nonce: 0x0102030405060708,
            },
            BootstrapJoinFrame::JoinInit {
                eph_pub: [3u8; 32],
                static_pub: [4u8; 32],
                requested_vip: Some("10.144.144.7".into()),
                client_nonce: 42,
            },
            BootstrapJoinFrame::JoinReply {
                eph_pub: [5u8; 32],
                static_pub: [6u8; 32],
                assigned_vip: "10.144.144.5".into(),
                lease_secs: 60,
                hb_interval_ms: 20000,
                refresh_interval_ms: 60000,
                server_nonce: 0x0807060504030201,
            },
            BootstrapJoinFrame::Error {
                code: BootstrapErrorCode::RateLimited,
                message: "too many pending".into(),
            },
        ];
        for f in &frames {
            let enc = encode_join_frame(f).expect("encode ok");
            assert_eq!(decode_join_frame(&enc).expect("decode ok"), *f);
        }
    }

    #[test]
    fn wire_roundtrip_prepends_magic() {
        let frame = BootstrapJoinFrame::Error {
            code: BootstrapErrorCode::NotBootstrap,
            message: "no server".into(),
        };
        let wire = encode_join_frame_wire(&frame).expect("encode wire ok");
        assert!(wire.starts_with(NXB_MAGIC));
        let body = &wire[NXB_MAGIC.len()..];
        assert_eq!(decode_join_frame(body).expect("decode ok"), frame);
    }

    #[test]
    fn split_outer_demuxes_secured_plain_and_unknown() {
        // Secured 探针：首字节 0x01 且长度 >= 38。
        let mut secured = vec![0x01u8; SECURED_MIN_LEN];
        secured[1] = 0x03; // FRAME_DATA
        match split_outer(&secured).expect("split ok") {
            OuterFrame::Secured(b) => assert_eq!(b.len(), SECURED_MIN_LEN),
            other => panic!("expected Secured, got {other:?}"),
        }
        // 首字节 0x01 但太短：不是 Secured，也不是已知明文 tag -> Transport。
        let short = [0x01u8; 10];
        assert!(matches!(
            split_outer(&short),
            Err(DiscoveryError::Transport(_))
        ));
        // 明文 JoinInit。
        let init = BootstrapJoinFrame::JoinInit {
            eph_pub: [1u8; 32],
            static_pub: [2u8; 32],
            requested_vip: None,
            client_nonce: 9,
        };
        let body = encode_join_frame(&init).expect("encode ok");
        match split_outer(&body).expect("split ok") {
            OuterFrame::Plain(f) => assert_eq!(f, init),
            OuterFrame::Secured(_) => panic!("expected plain"),
        }
        // 未知外层 tag：绝不 fallback 当密文。
        assert!(matches!(
            split_outer(&[0x7f, 0x01, 0x02]),
            Err(DiscoveryError::Transport(_))
        ));
        // 空 payload。
        assert!(matches!(
            split_outer(&[]),
            Err(DiscoveryError::Transport(_))
        ));
    }

    #[test]
    fn decode_rejects_truncated_trailing_and_bad_presence() {
        // 截断 JoinInit（缺 client_nonce）。
        let mut init = encode_join_frame(&BootstrapJoinFrame::JoinInit {
            eph_pub: [1u8; 32],
            static_pub: [2u8; 32],
            requested_vip: None,
            client_nonce: 1,
        })
        .expect("encode ok");
        init.truncate(init.len() - 3);
        assert!(matches!(
            decode_join_frame(&init),
            Err(DiscoveryError::Transport(_))
        ));
        // trailing bytes。
        let mut reply = encode_join_frame(&BootstrapJoinFrame::JoinReply {
            eph_pub: [5u8; 32],
            static_pub: [6u8; 32],
            assigned_vip: "10.0.0.1".into(),
            lease_secs: 60,
            hb_interval_ms: 1,
            refresh_interval_ms: 2,
            server_nonce: 3,
        })
        .expect("encode ok");
        reply.push(0xaa);
        assert!(matches!(
            decode_join_frame(&reply),
            Err(DiscoveryError::Transport(_))
        ));
        // 非法 requested_vip presence。
        let mut bad = Vec::new();
        bad.push(OUTER_JOIN_INIT);
        bad.extend_from_slice(&[7u8; 64]); // eph+static
        bad.push(99u8); // presence != 0/1
        assert!(matches!(
            decode_join_frame(&bad),
            Err(DiscoveryError::Transport(_))
        ));
    }

    #[test]
    fn error_code_wire_roundtrip() {
        for c in [
            BootstrapErrorCode::AuthFailed,
            BootstrapErrorCode::BadVip,
            BootstrapErrorCode::VipConflict,
            BootstrapErrorCode::NotBootstrap,
            BootstrapErrorCode::RateLimited,
            BootstrapErrorCode::MalformedFrame,
        ] {
            assert_eq!(BootstrapErrorCode::from_wire(c.wire()).unwrap(), c);
        }
        assert!(BootstrapErrorCode::from_wire(0).is_err());
        assert!(BootstrapErrorCode::from_wire(99).is_err());
    }
}
