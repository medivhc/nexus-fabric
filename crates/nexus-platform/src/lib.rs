//! Portable host-capability traits.
//!
//! 定义 Platform 能力抽象与结构化平台错误。具体 OS API 只存在于 `nexus-platform-*`。

#![forbid(unsafe_code)]

use core::fmt;

/// 平台能力位：Virtual Packet Interface 的能力声明（供 Planner/Policy 评估）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInterfaceCapabilities {
    pub packet_ingress: bool,
    pub packet_injection: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub route_include: bool,
    pub route_exclude: bool,
    pub dns_override: bool,
    pub mtu_configurable: bool,
    pub per_app_routing: bool,
    pub underlay_bypass: bool,
}

/// 结构化平台错误（替代自由文本 `String`）。
///
/// PRODUCT §7：平台缺少某项能力时必须返回显式 `Unavailable`，
/// 禁止静默改变产品语义；其余错误保留可诊断原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// 平台缺少所需能力（对应 PRODUCT §2 `PLATFORM_CAPABILITY_UNAVAILABLE`）。
    Unavailable { capability: String },
    /// I/O 或系统调用失败。
    Io { operation: String, message: String },
    /// 请求的条目不存在（如 SecureStore 缺失键由 `Ok(None)` 表达时不用此变体）。
    NotFound { key: String },
    /// 输入或参数无效。
    Invalid { message: String },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { capability } => {
                write!(f, "platform capability unavailable: {capability}")
            }
            Self::Io { operation, message } => {
                write!(f, "platform io error during {operation}: {message}")
            }
            Self::NotFound { key } => write!(f, "platform entry not found: {key}"),
            Self::Invalid { message } => write!(f, "platform invalid input: {message}"),
        }
    }
}

impl std::error::Error for PlatformError {}

pub trait Clock: Send + Sync {
    fn monotonic_millis(&self) -> u64;
}

pub trait RandomSource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), PlatformError>;
}

pub trait SecureStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError>;
    fn put(&self, key: &str, value: &[u8]) -> Result<(), PlatformError>;
}

pub trait VirtualPacketInterface: Send {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError>;
    fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError>;
}

pub trait TransparentIngressProvider: Send {
    fn start(&mut self) -> Result<(), PlatformError>;
    fn stop(&mut self) -> Result<(), PlatformError>;
}
