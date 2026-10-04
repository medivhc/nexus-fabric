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
/// Provider-internal Linux execution adapter; no public protocol routes.
#[cfg(target_os = "linux")]
pub mod task_executor;
#[cfg(target_os = "linux")]
mod task_runtime_store;
/// N3-1 acceptance persistence, not yet connected to daemon product routes.
pub mod task_store;

/// Local receiver: resumable verified publication without overwriting outputs.
#[cfg(target_os = "linux")]
pub mod artifact_download;
#[cfg(target_os = "linux")]
mod artifact_fs;
/// Provider-private Artifact publication and authorized byte reads.
#[cfg(target_os = "linux")]
pub mod task_artifacts;

/// Linux requester cache and durable cancellation outbox.
#[cfg(target_os = "linux")]
pub mod task_requester_store;
