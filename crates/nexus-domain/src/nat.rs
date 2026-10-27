//! 跨栈 NAT 词汇（v9 CLI 运行时与 N1 运行时共用）。
//!
//! 2026-10-26 由 `nexus-connectivity::nat` 逐字迁入（划界见
//! `docs/adr/0001-dual-stack-boundary.md`）：只放纯类型，无 I/O、无编解码、无方法。
//! `NatEvent` / `NatError` 仍留在 `nexus-connectivity`。
//!
//! `nexus-connectivity` 以 `pub use` 保旧路径；`nexus-nat-traversal` /
//! `nexus-nat-wireup` / `nexusd` 直接引用本模块。

use std::net::SocketAddr;

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
