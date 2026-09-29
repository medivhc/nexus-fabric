//! nexus-platform-linux
//!
//! 实现 Linux 平台 Capability Adapter，包括 TUN、透明拦截、Mount/Filesystem、Service/Privilege 等宿主桥接。
//!
//! 详细边界见同目录 `MODULE.md`。

#![deny(unsafe_op_in_unsafe_fn)]

pub mod secure_store;
/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub mod tun;
pub mod tun_vpi;

pub use secure_store::FileSecureStore;
pub use tun_vpi::TunVpi;

pub const NEXUS_PLATFORM_LINUX_MODULE: &str = "nexus-platform-linux";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 Linux 平台 Capability Adapter，包括 TUN、透明拦截、Mount/Filesystem、Service/Privilege 等宿主桥接。"
}
