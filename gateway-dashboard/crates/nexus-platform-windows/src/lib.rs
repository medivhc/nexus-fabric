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

pub use autostart::TaskSchedulerAutostart;
pub use secure_store::DpapiSecureStore;
pub use vpi::WintunVpiAdapter;
pub use wininet_proxy::WinInetSystemProxy;
