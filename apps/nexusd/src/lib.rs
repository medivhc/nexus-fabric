//! nexusd library: 统一数据面等可复用模块。
//!
//! Binary (`main.rs`) 为 Composition Root；可测试逻辑下沉到此。

pub mod assembly;
pub mod config;
pub mod dataplane;
pub mod nat_switch;
pub mod proxy_fwd;
pub mod recovery;
/// nexusd Workspace sync 传输适配（C2；fabric QUIC bi-stream）。
pub mod sync_transport;
/// nexusd Workspace 生产接线（C1；仅 Linux：FUSE 挂载）。
#[cfg(target_os = "linux")]
pub mod workspace;

pub mod snapshot_store;
/// N3-1 acceptance persistence, not yet connected to daemon product routes.
pub mod task_store;
