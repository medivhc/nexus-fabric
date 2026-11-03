//! 透明入站与捕获规则的平台抽象（spec §9.1 / §9.2）。
//!
//! 只描述“已经 accept 的流/数据报 + 原始目的地”和“捕获规则集”的契约；
//! 平台句柄、sockopt、ancillary 解析由 `nexus-platform-*` 适配器实现。
//! Portable core 不直接调用任何平台 API。

use core::fmt;
use std::net::{SocketAddr, SocketAddrV4, TcpStream};

/// 透明入站错误（spec §8.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentIngressError {
    /// 内核不支持 TPROXY / `IP_TRANSPARENT`。
    CapabilityUnavailable {
        /// 缺少的能力名。
        capability: &'static str,
    },
    /// 权限不足（`EPERM` / `EACCES`）。
    PermissionDenied {
        /// 失败的操作。
        operation: &'static str,
        /// errno。
        errno: i32,
    },
    /// listener bind 失败。
    BindFailed {
        /// 地址。
        addr: String,
        /// errno。
        errno: i32,
    },
    /// `setsockopt` 非权限类失败。
    SockOptFailed {
        /// 选项名。
        opt: &'static str,
        /// errno。
        errno: i32,
    },
    /// 原始目的地缺失（TCP local == listener / UDP 无 ancillary）。
    OrigDstMissing {
        /// 对端。
        peer: String,
    },
    /// 原始目的地非法（族/端口）。
    OrigDstInvalid {
        /// 原始值。
        raw: String,
    },
    /// ancillary 解析失败。
    AncillaryParseFailed {
        /// 细节。
        detail: String,
    },
    /// 非 AF_INET（IPv6 等）。
    UnsupportedFamily {
        /// 地址族。
        family: u16,
    },
    /// 其它 I/O 错误。
    Io {
        /// 操作。
        operation: &'static str,
        /// 信息。
        message: String,
    },
}

impl fmt::Display for TransparentIngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityUnavailable { capability } => {
                write!(f, "TRANSPARENT_CAPABILITY_UNAVAILABLE: {capability}")
            }
            Self::PermissionDenied { operation, errno } => {
                write!(
                    f,
                    "TRANSPARENT_PERMISSION_DENIED: {operation} errno={errno}"
                )
            }
            Self::BindFailed { addr, errno } => {
                write!(f, "TRANSPARENT_BIND_FAILED: addr={addr} errno={errno}")
            }
            Self::SockOptFailed { opt, errno } => {
                write!(f, "TRANSPARENT_SOCKOPT_FAILED: opt={opt} errno={errno}")
            }
            Self::OrigDstMissing { peer } => {
                write!(f, "TRANSPARENT_ORIG_DST_MISSING: peer={peer}")
            }
            Self::OrigDstInvalid { raw } => {
                write!(f, "TRANSPARENT_ORIG_DST_INVALID: raw={raw}")
            }
            Self::AncillaryParseFailed { detail } => {
                write!(f, "TRANSPARENT_ANCILLARY_PARSE_FAILED: {detail}")
            }
            Self::UnsupportedFamily { family } => {
                write!(f, "TRANSPARENT_UNSUPPORTED_FAMILY: {family}")
            }
            Self::Io { operation, message } => {
                write!(f, "TRANSPARENT_IO: {operation}: {message}")
            }
        }
    }
}

impl std::error::Error for TransparentIngressError {}

/// 捕获规则错误（spec §8.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureRuleError {
    /// 写规则时权限不足。
    PermissionDenied {
        /// 步骤。
        step: &'static str,
    },
    /// 工具缺失（iptables/nft/ip）。
    ToolMissing {
        /// 工具名。
        tool: &'static str,
    },
    /// 命令非 0 退出。
    CommandFailed {
        /// 步骤。
        step: &'static str,
        /// 退出码。
        exit_code: Option<i32>,
        /// stderr 前 512 字节。
        stderr: String,
    },
    /// 回收失败。
    CleanupFailed {
        /// 步骤。
        step: &'static str,
        /// 细节。
        detail: String,
    },
    /// 未支持的 backend。
    UnsupportedBackend {
        /// backend 名。
        backend: String,
    },
}

impl fmt::Display for CaptureRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied { step } => {
                write!(f, "CAPTURE_RULE_PERMISSION_DENIED: step={step}")
            }
            Self::ToolMissing { tool } => write!(f, "CAPTURE_RULE_TOOL_MISSING: tool={tool}"),
            Self::CommandFailed {
                step,
                exit_code,
                stderr,
            } => write!(
                f,
                "CAPTURE_RULE_COMMAND_FAILED: step={step} exit={exit_code:?} stderr={stderr}"
            ),
            Self::CleanupFailed { step, detail } => {
                write!(
                    f,
                    "CAPTURE_RULE_CLEANUP_FAILED: step={step} detail={detail}"
                )
            }
            Self::UnsupportedBackend { backend } => {
                write!(f, "CAPTURE_RULE_UNSUPPORTED_BACKEND: {backend}")
            }
        }
    }
}

impl std::error::Error for CaptureRuleError {}

/// 一条已 accept 的透明 TCP 连接（平台句柄交给 core 前的最小形状）。
#[derive(Debug)]
pub struct AcceptedTcpStream {
    /// 已 accept 的流。
    pub stream: TcpStream,
    /// 对端地址。
    pub peer: SocketAddrV4,
    /// 原始目的地（透明 bind 的 local 地址）。
    pub orig_dst: SocketAddrV4,
    /// accept 的单调毫秒（driver 时钟）。
    pub accepted_at_millis: u64,
}

/// 一条透明 UDP 数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedDatagram {
    /// 载荷。
    pub payload: Vec<u8>,
    /// 对端地址。
    pub peer: SocketAddrV4,
    /// 原始目的地（ancillary `IP_ORIGDSTADDR`）。
    pub orig_dst: SocketAddrV4,
    /// 收到的单调毫秒（driver 时钟）。
    pub received_at_millis: u64,
}

/// 透明 TCP 入站（spec §9.1）。
pub trait TransparentTcpIngress: Send {
    /// 幂等启动确认。
    fn start(&mut self) -> Result<(), TransparentIngressError>;
    /// listener 本地地址。
    fn local_addr(&self) -> Result<SocketAddr, TransparentIngressError>;
    /// 非阻塞 accept 一条连接。
    fn accept(
        &mut self,
        now_millis: u64,
    ) -> Result<Option<AcceptedTcpStream>, TransparentIngressError>;
    /// 关闭并释放 fd。
    fn shutdown(&mut self) -> Result<(), TransparentIngressError>;
}

/// 透明 UDP 入站（spec §9.1；单 socket + ancillary）。
pub trait TransparentUdpIngress: Send {
    /// 幂等启动确认。
    fn start(&mut self) -> Result<(), TransparentIngressError>;
    /// socket 本地地址。
    fn local_addr(&self) -> Result<SocketAddr, TransparentIngressError>;
    /// 非阻塞接收一条数据报。
    fn recv(
        &mut self,
        now_millis: u64,
    ) -> Result<Option<ReceivedDatagram>, TransparentIngressError>;
    /// 以原始目的地（IP 与端口）为源地址回包；做不到时返回错误而不改用其它源地址。
    fn send_from(
        &mut self,
        orig_dst: SocketAddrV4,
        peer: SocketAddrV4,
        payload: &[u8],
    ) -> Result<usize, TransparentIngressError>;
    /// 关闭并释放 fd。
    fn shutdown(&mut self) -> Result<(), TransparentIngressError>;
}

/// 捕获 backend。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// iptables（默认）。
    Iptables,
    /// nftables（可选）。
    Nftables,
    /// external：只校验不写。
    External,
}

impl CaptureBackend {
    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
            Self::External => "external",
        }
    }
}

/// 捕获规则规格（spec §9.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRuleSpec {
    /// backend。
    pub backend: CaptureBackend,
    /// 专用链名。
    pub chain: String,
    /// TCP 监听端口。
    pub tcp_port: u16,
    /// UDP 监听端口。
    pub udp_port: u16,
    /// fwmark。
    pub mark: u32,
    /// fwmark 掩码。
    pub mark_mask: u32,
    /// 策略路由表。
    pub route_table: u32,
    /// 拦截目的 CIDR。
    pub intercept_dst_cidrs: Vec<String>,
    /// 排除目的 CIDR。
    pub exclude_dst_cidrs: Vec<String>,
    /// 必须为 true（本 run IPv4-only）。
    pub ipv4_only: bool,
}

impl CaptureRuleSpec {
    /// 按 spec 默认值构造（端口 7895 / mark 0x1f3 / table 100）。
    #[must_use]
    pub fn new(backend: CaptureBackend) -> Self {
        Self {
            backend,
            chain: "NEXUS_TPROXY".to_string(),
            tcp_port: 7895,
            udp_port: 7895,
            mark: 0x1f3,
            mark_mask: 0x1f3,
            route_table: 100,
            intercept_dst_cidrs: vec!["0.0.0.0/0".to_string()],
            exclude_dst_cidrs: Vec::new(),
            ipv4_only: true,
        }
    }
}

/// `apply()` 报告。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleApplyReport {
    /// 是否创建了链。
    pub chain_created: bool,
    /// 添加的 mangle 规则数。
    pub rules_added: u32,
    /// 添加的 `ip rule` 数。
    pub ip_rules_added: u32,
    /// 添加的 `ip route` 数。
    pub routes_added: u32,
}

/// `cleanup()` 报告。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleCleanupReport {
    /// 删除的 mangle 规则数。
    pub rules_removed: u32,
    /// 删除的 `ip rule` 数。
    pub ip_rules_removed: u32,
    /// 删除的 `ip route` 数。
    pub routes_removed: u32,
    /// 是否删除链。
    pub chain_removed: bool,
}

/// 捕获规则集（spec §9.2）。
pub trait TransparentCaptureRules: Send {
    /// 幂等装配规则。
    fn apply(&mut self, spec: &CaptureRuleSpec) -> Result<RuleApplyReport, CaptureRuleError>;
    /// 捕获失败且 `on_capture_failure=block` 时安装 DROP 规则。
    fn enforce_block(
        &mut self,
        spec: &CaptureRuleSpec,
    ) -> Result<RuleApplyReport, CaptureRuleError>;
    /// 逆序回收本实例添加的条目。
    fn cleanup(&mut self) -> Result<RuleCleanupReport, CaptureRuleError>;
    /// 规则是否处于生效状态。
    fn is_active(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_error_display_keeps_all_fields() {
        let err = TransparentIngressError::PermissionDenied {
            operation: "bind",
            errno: 1,
        };
        let text = err.to_string();
        assert!(text.contains("bind"));
        assert!(text.contains("1"));
        let err = TransparentIngressError::BindFailed {
            addr: "0.0.0.0:7895".to_string(),
            errno: 98,
        };
        assert!(err.to_string().contains("0.0.0.0:7895"));
        assert!(err.to_string().contains("98"));
    }

    #[test]
    fn capture_rule_error_display_keeps_step_and_stderr() {
        let err = CaptureRuleError::CommandFailed {
            step: "add-rule",
            exit_code: Some(2),
            stderr: "bad rule".to_string(),
        };
        let text = err.to_string();
        assert!(text.contains("add-rule"));
        assert!(text.contains("bad rule"));
        assert!(text.contains("2"));
    }

    #[test]
    fn capture_rule_spec_defaults_match_spec() {
        let spec = CaptureRuleSpec::new(CaptureBackend::Iptables);
        assert_eq!(spec.chain, "NEXUS_TPROXY");
        assert_eq!(spec.tcp_port, 7895);
        assert_eq!(spec.udp_port, 7895);
        assert_eq!(spec.mark, 0x1f3);
        assert_eq!(spec.mark_mask, 0x1f3);
        assert_eq!(spec.route_table, 100);
        assert_eq!(spec.intercept_dst_cidrs, vec!["0.0.0.0/0".to_string()]);
        assert!(spec.exclude_dst_cidrs.is_empty());
        assert!(spec.ipv4_only);
    }
}
