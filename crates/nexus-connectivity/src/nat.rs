//! NAT 词汇模块：本模块保留 `NatEvent` / `NatError`。
//!
//! `NatType` / `StunMapping` 已下沉 `nexus-domain::nat`（2026-10-26，划界见
//! `docs/adr/0001-dual-stack-boundary.md`），本模块以 `pub use` 保旧路径
//! `nexus_connectivity::nat::{NatType, StunMapping}`。
//! STUN 编解码与打洞实现已分别归一到 `nexus-turn`
//! 与 `nexus-nat-traversal`。旧实现（`StunClient`、`HolePuncher`、
//! `nat_path_decision`、`codec_self_test`及 `NatEvent` 的打洞三变体）
//! 已退役（#1 运行时所有权归一）。

use std::net::SocketAddr;

pub use nexus_domain::nat::{NatType, StunMapping};

/// NAT 事件（结构化日志，支持 replay）
#[derive(Debug, Clone)]
pub enum NatEvent {
    /// STUN 请求已发送
    StunRequestSent {
        /// STUN 服务器地址
        server: SocketAddr,
        /// 事务 ID
        transaction_id: [u8; 12],
    },
    /// STUN 响应已接收
    StunResponseReceived {
        /// STUN 服务器地址
        server: SocketAddr,
        /// 公网映射地址
        public_mapping: SocketAddr,
        /// RTT
        rtt_ms: u64,
    },
    /// NAT 类型检测完成
    NatTypeDetected {
        /// 检测到的 NAT 类型
        nat_type: NatType,
    },
}

/// NAT 错误类型
#[derive(Debug)]
pub enum NatError {
    /// IO 错误
    Io(std::io::Error),
    /// STUN 解析错误
    StunParse(String),
    /// 无效响应
    InvalidResponse,
}

impl std::fmt::Display for NatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatError::Io(e) => write!(f, "IO error: {}", e),
            NatError::StunParse(s) => write!(f, "STUN parse error: {}", s),
            NatError::InvalidResponse => write!(f, "invalid response"),
        }
    }
}

impl std::error::Error for NatError {}

impl From<std::io::Error> for NatError {
    fn from(e: std::io::Error) -> Self {
        NatError::Io(e)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_debug() {
        assert_eq!(format!("{:?}", NatType::FullCone), "FullCone");
    }

    #[test]
    fn test_nat_event_debug() {
        let event = NatEvent::NatTypeDetected {
            nat_type: NatType::RestrictedCone,
        };
        let s = format!("{:?}", event);
        assert!(s.contains("NatTypeDetected"));
    }
}
// test
