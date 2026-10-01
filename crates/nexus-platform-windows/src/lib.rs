//! nexus-platform-windows
//!
//! 实现 Windows 平台 Capability Adapter（首期：wintun 窄 FFI 的
//! VirtualPacketInterface）。详细边界见同目录 `MODULE.md`。
//!
//! unsafe 纪律（AGENTS.md §18）：所有 `unsafe` 集中在 `wintun.rs` 一个模块，
//! 每处带 Safety Invariant；本文件与其他模块仅经公开安全 API 使用之。

#![deny(unsafe_op_in_unsafe_fn)]
#![forbid(missing_docs)]

pub mod autostart;
pub mod dpapi;
pub mod netcfg;
pub mod secure_store;
pub mod vpi;
pub mod wininet_proxy;
pub mod wintun;

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_PLATFORM_WINDOWS_MODULE: &str = "nexus-platform-windows";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 Windows 平台 Capability Adapter（wintun VirtualPacketInterface）。"
}

pub use autostart::TaskSchedulerAutostart;
pub use secure_store::DpapiSecureStore;
pub use vpi::WintunVpiAdapter;
pub use wininet_proxy::WinInetSystemProxy;
