//! nexusd library: 统一数据面等可复用模块。
//!
//! Binary (`main.rs`) 为 Composition Root；可测试逻辑下沉到此。

#![recursion_limit = "256"]

pub mod assembly;
pub mod config;
pub mod dataplane;
pub mod discovery_runtime;
/// DNS-time proxy classification from the `proxy.yaml` domain subset.
pub mod dns_classify;
/// DNS service thread: single owner + bounded queues (wired in C11).
pub mod dns_service;
/// DNS service snapshot (`/dns/status`); wired in C11.
pub mod dns_status;
/// Non-blocking upstream DNS engine (pending table/retry/failover/cache).
pub mod dns_upstream;
/// 热路径日志限频（per `(tag, cause)`；PRODUCT hot-path 契约）。
mod log_throttle;
pub mod nat_consumer;
pub mod nat_gather;
pub mod nat_relay;
pub mod nat_status;
pub mod nat_stun;
pub mod nat_switch;
pub mod nat_turn;
pub mod peer_source;
pub mod proxy_fwd;
pub mod recovery;
/// nexusd Workspace sync 传输适配（C2；fabric QUIC bi-stream）。
pub mod sync_transport;
pub mod tproxy_egress;
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

/// Separately provisioned snapshot staging; independent of the Task wire.
pub mod snapshot_service;
/// Bounded versioned LocalAPI protocol.
pub mod task_http;
/// Optional N3 local provider application service.
pub mod task_service;

/// Explicit provider allocations, atomically coupled to accepted Tasks.
#[cfg(target_os = "linux")]
pub mod task_capacity;
#[cfg(target_os = "linux")]
mod task_capacity_recovery;
#[cfg(target_os = "linux")]
mod task_sessions;

/// Local operator initialization; no Task protocol operation invokes it.
#[cfg(target_os = "linux")]
pub mod task_provider_init;

/// N3-12 Linux snapshot staging adapter.
#[cfg(target_os = "linux")]
pub mod snapshot_staging;
