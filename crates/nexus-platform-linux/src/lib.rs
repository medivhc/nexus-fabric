//! nexus-platform-linux
//!
//! 实现 Linux 平台 Capability Adapter，包括 TUN、透明拦截、Mount/Filesystem、Service/Privilege 等宿主桥接。
//!
//! P3.x OS 装配（PRODUCT §12.59）：TUN 配 IP、路由表事务性装配、内置 DNS、daemon。
//!
//! 详细边界见同目录 `MODULE.md`。

#![deny(unsafe_op_in_unsafe_fn)]

/// TUN 接口 IP 地址装配（幂等）。
pub mod addr;
/// OS 装配顶层编排（`OsAssemble` 生产 API）。
pub mod assemble;
/// 自研 daemon：PID 文件、信号处理、退出清理。
pub mod daemon;
/// 内置 DNS server（只服务 TUN 网段，不碰 /etc/resolv.conf）。
pub mod dns;
/// netlink 窄绑定（socket + RTM_NEWADDR/GETADDR/NEWROUTE/DELROUTE/GETROUTE）。
pub mod netlink;
/// 路由表事务性装配（快照/apply/rollback）。
pub mod route;
pub mod secure_store;
/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub mod tun;
pub mod tun_vpi;

pub use assemble::{CleanupReport, OsAssemble, OsAssembleConfig};
pub use secure_store::FileSecureStore;
pub use tun_vpi::TunVpi;

pub const NEXUS_PLATFORM_LINUX_MODULE: &str = "nexus-platform-linux";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 Linux 平台 Capability Adapter，包括 TUN、透明拦截、Mount/Filesystem、Service/Privilege 等宿主桥接。"
}
