//! nexusd library: 统一数据面等可复用模块。
//!
//! Binary (`main.rs`) 为 Composition Root；可测试逻辑下沉到此。

pub mod assembly;
pub mod config;
pub mod dataplane;
pub mod nat_switch;
pub mod proxy_fwd;
/// nexusd Workspace 生产接线（C1；仅 Linux：FUSE 挂载）。
#[cfg(target_os = "linux")]
pub mod workspace;
