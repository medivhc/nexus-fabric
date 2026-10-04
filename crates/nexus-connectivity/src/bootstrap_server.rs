//! Bootstrap 自动入网——服务端纯逻辑与 codec 解耦边界（v2 §5.5/§6.1）。
//!
//! **架构红线**：本模块位于 `nexus-connectivity`，**绝不直接命名/依赖**
//! `nexus-discovery` 的帧类型（见 `fib_resolver.rs`：connectivity 不能依赖
//! discovery）。与 discovery 帧之间的字节映射由 `BootstrapFrameCodec` trait
//! 抽象，具体实现（`DiscoveryBootstrapCodec`）在 `apps/nexus` 组合根注入——
//! 与 `FibResolver`（`virtual_subnet.rs`）完全同构。
//!
//! P1：仅落地与 discovery 解耦的控制消息子集、codec trait 与错误类型；
//! 服务端状态机（会话/VIP/目录/半开防护）在 P2 补齐。

use crate::coord::CoordError;
use crate::encryption::EncryptionError;

/// 与 discovery 帧解耦的一个 bootstrap 在线 peer（仅 bootstrap 所需子集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// 权威 node_id（由握手 static 公钥派生，非客户端自报）。
    pub node_id: String,
    /// 服务端权威分配的虚拟 IP。
    pub virtual_ip: String,
    /// NAT 源 locator（目录以此为准，忽略自报值）。
    pub locator: String,
}

/// 与 discovery `AutoDiscoveryFrame` 解耦的 bootstrap 控制消息子集。
///
/// 组合根 codec 负责在 `BootstrapCtrl` 与 `AutoDiscoveryFrame` 字节之间映射：
/// `Register/GetPeers/PeerList/Heartbeat` 复用既有 tag 11–14；
/// `RegisterAck` 增量 tag 15（v2 §5.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapCtrl {
    /// C -> S：注册/刷新本节点（帧内 node_id 仅作显示，服务端以权威派生值为准）。
    Register {
        /// 客户端自报 node_id（日志用；权威值由 static 公钥派生）。
        node_id: String,
        /// 客户端申请/确认的 VIP。
        virtual_ip: String,
        /// 客户端自报 locator（仅日志；目录以 NAT 源为准）。
        locator: String,
    },
    /// S -> C：注册结果确认。
    RegisterAck {
        /// 是否被接受。
        accepted: bool,
        /// 服务端认可的租约秒数。
        ttl_secs: u32,
    },
    /// C -> S：拉取在线 peer 列表。
    GetPeers {
        /// 发起方 node_id（被 exclude）。
        node_id: String,
    },
    /// S -> C：在线 peer 列表（含服务端自身第 0 条，exclude 发起方）。
    PeerList {
        /// 在线 peers。
        peers: Vec<BootstrapPeer>,
    },
    /// C -> S：心跳保活。
    Heartbeat {
        /// 发起方 node_id。
        node_id: String,
        /// 客户端当前时间（秒）。
        now: u64,
    },
}

/// Bootstrap 服务端结构化错误（typed Result，禁止 panic 表示业务失败）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootstrapServerError {
    /// PSK 认证失败。
    AuthFailed,
    /// 申请 VIP 不合法 / 不在 CIDR。
    BadVip(String),
    /// VIP 冲突。
    VipConflict(String),
    /// 控制帧格式损坏。
    Malformed(String),
    /// 半开/速率触顶。
    RateLimited,
    /// 底层 Coordinator / VIP 分配错误。
    Coord(CoordError),
    /// 底层 AEAD / 防重放错误。
    Crypto(EncryptionError),
}

impl core::fmt::Display for BootstrapServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthFailed => write!(f, "BOOTSTRAP_AUTH_FAILED"),
            Self::BadVip(s) => write!(f, "BOOTSTRAP_BAD_VIP: {s}"),
            Self::VipConflict(s) => write!(f, "BOOTSTRAP_VIP_CONFLICT: {s}"),
            Self::Malformed(s) => write!(f, "BOOTSTRAP_MALFORMED: {s}"),
            Self::RateLimited => write!(f, "BOOTSTRAP_RATE_LIMITED"),
            Self::Coord(e) => write!(f, "BOOTSTRAP_COORD: {e}"),
            Self::Crypto(e) => write!(f, "BOOTSTRAP_CRYPTO: {e}"),
        }
    }
}

impl std::error::Error for BootstrapServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coord(e) => Some(e),
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CoordError> for BootstrapServerError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}

impl From<EncryptionError> for BootstrapServerError {
    fn from(e: EncryptionError) -> Self {
        Self::Crypto(e)
    }
}

/// 由 `apps/nexus` 组合根实现：`BootstrapCtrl` ↔ `AutoDiscoveryFrame` 字节。
///
/// connectivity 不依赖 discovery，故此处把内层控制帧的字节编解码抽象为 trait；
/// 具体实现内部调用 `nexus_discovery::encode/decode_auto_frame`。
pub trait BootstrapFrameCodec {
    /// 把一条 bootstrap 控制消息编码为内层字节（随后会被 AEAD 加密）。
    fn encode(&self, f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError>;
    /// 把一段内层明文（AEAD 解密之后）解码为 bootstrap 控制消息。
    fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn error_display_and_conversions() {
        assert_eq!(
            BootstrapServerError::RateLimited.to_string(),
            "BOOTSTRAP_RATE_LIMITED"
        );
        assert!(BootstrapServerError::AuthFailed.source().is_none());
        let coord = BootstrapServerError::from(CoordError::NoAddressAvailable);
        assert!(matches!(
            coord,
            BootstrapServerError::Coord(CoordError::NoAddressAvailable)
        ));
        let crypto = BootstrapServerError::from(EncryptionError::DecryptionFailed);
        assert!(matches!(
            crypto,
            BootstrapServerError::Crypto(EncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn bootstrap_peer_and_ctrl_are_plain_data() {
        let p = BootstrapPeer {
            node_id: "abc".into(),
            virtual_ip: "10.0.0.2".into(),
            locator: "udp://h:1".into(),
        };
        let ctrl = BootstrapCtrl::PeerList { peers: vec![p] };
        let round = ctrl.clone();
        assert_eq!(ctrl, round);
    }
}
