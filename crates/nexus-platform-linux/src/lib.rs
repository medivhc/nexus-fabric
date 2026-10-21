//! nexus-platform-linux
//!
//! 实现 Linux 平台 Capability Adapter，包括 TUN、透明拦截、Mount/Filesystem、Service/Privilege 等宿主桥接。
//!
//! P3.x OS 装配（PRODUCT §12.59）：TUN 配 IP、路由表事务性装配、内置 DNS、daemon。
//!
//! 详细边界见同目录 `MODULE.md`。

#![deny(unsafe_op_in_unsafe_fn)]

pub mod addr;
/// OS 装配顶层编排（`OsAssemble` 生产 API）。
pub mod assemble;
/// 自研 daemon：PID 文件、信号处理、退出清理。
pub mod daemon;
/// Atomic Linux no-replace publication primitive.
#[cfg(target_os = "linux")]
pub mod directory_publish;
/// 内置 DNS server（只服务 TUN 网段，不碰 /etc/resolv.conf）。
pub mod dns;
/// Nonblocking Linux file leases; callers retain the owning file descriptor.
#[cfg(target_os = "linux")]
pub mod file_lease;
/// TUN 接口 IP 地址装配（幂等）。
/// Linux FUSE adapter projecting a workspace as a filesystem (v9 §22).
/// Consumes the portable `nexus_platform::ProjectedWorkspace` trait; owns
/// no replica selection / path planning / cache policy / commit semantics.
pub mod fuse_ws;
/// netlink 窄绑定（socket + RTM_NEWADDR/GETADDR/NEWROUTE/DELROUTE/GETROUTE）。
pub mod netlink;
/// OS 装配操作日志（O6）。
pub mod op_log;
/// 路由表事务性装配（快照/apply/rollback）。
pub mod route;
pub mod secure_store;
/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub mod tun;
pub mod tun_vpi;

pub use assemble::{CleanupReport, OsAssemble, OsAssembleConfig};
pub use secure_store::FileSecureStore;
pub use tun_vpi::TunVpi;
