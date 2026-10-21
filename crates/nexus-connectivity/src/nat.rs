//! NAT 词汇模块：类型与事件定义。
//!
//! 本模块仅保留共享词汇（`NatType`、`StunMapping`、`NatEvent`）；
//! STUN 编解码与打洞实现已分别归一到 `nexus-turn`
//! 与 `nexus-nat-traversal`。旧实现（`StunClient`、`HolePuncher`、
//! `nat_path_decision`、`codec_self_test`及 `NatEvent` 的打洞三变体）
//! 已退役（#1 运行时所有权归一）。

use std::net::SocketAddr;

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

/// NAT 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 完全锥型：任何外部主机都能发包到映射端口
    FullCone,
    /// 限制锥型：只有目标 IP 允许的主机能发包
    RestrictedCone,
    /// 端口限制锥型：只有目标 IP:Port 允许的主机能发包
    PortRestrictedCone,
    /// 对称型：每个目标都分配不同端口
    Symmetric,
    /// 未知
    Unknown,
}

/// STUN 映射结果
#[derive(Debug, Clone)]
pub struct StunMapping {
    /// 本地地址
    pub local: SocketAddr,
    /// 公网映射地址
    pub public: SocketAddr,
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
