//! Explicit, bounded snapshot staging; independent of accepted task storage.
use crate::task_provider_init::InitFailure;
use nexus_control_api::snapshot::{SnapshotEnvelope, SnapshotRequest, SnapshotService, UploadView};
use nexus_control_api::task::TaskCallContext;
use nexus_domain::task::{TaskError, TaskErrorCode};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingStatus {
    pub provider: String,
    pub workspace: String,
    pub principal: String,
    pub policy_digest: String,
    pub changed: bool,
}
#[cfg(target_os = "linux")]
#[path = "snapshot_staging/backend.rs"]
mod backend;
#[cfg(all(test, target_os = "linux"))]
use backend::initialize_with_test_fault;
#[cfg(target_os = "linux")]
pub use backend::{FileSnapshotStaging, initialize};
#[cfg(not(target_os = "linux"))]
fn unsupported() -> TaskError {
    TaskError::new(
        TaskErrorCode::UnsupportedCapability,
        "snapshot staging requires Linux safe IO",
        false,
    )
}
#[cfg(not(target_os = "linux"))]
pub fn initialize(_: &Path, _: &Path) -> Result<StagingStatus, InitFailure> {
    Err(unsupported().into())
}
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct FileSnapshotStaging;
#[cfg(not(target_os = "linux"))]
impl FileSnapshotStaging {
    pub fn open(_: &Path) -> Result<Option<Self>, TaskError> {
        Err(unsupported())
    }
    pub fn execute_local(&self, request: SnapshotRequest) -> SnapshotEnvelope {
        let upload_id = match request {
            SnapshotRequest::Begin { .. } => None,
            SnapshotRequest::PutChunk { upload_id, .. }
            | SnapshotRequest::Get { upload_id }
            | SnapshotRequest::Seal { upload_id }
            | SnapshotRequest::Cancel { upload_id } => Some(upload_id),
        };
        SnapshotEnvelope::Error {
            error: unsupported(),
            upload_id,
        }
    }
}
#[cfg(not(target_os = "linux"))]
impl SnapshotService for FileSnapshotStaging {
    fn execute(&self, _: &TaskCallContext, _: SnapshotRequest) -> Result<UploadView, TaskError> {
        Err(unsupported())
    }
}
#[cfg(test)]
#[path = "snapshot_staging_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "snapshot_staging_expiry_tests.rs"]
mod expiry_tests;

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestChunkIntent {
    old_offset: u64,
    next_offset: u64,
    chunk_sha256: nexus_domain::task::Sha256Digest,
}
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestDurableObservation {
    view: UploadView,
    chunk: Option<TestChunkIntent>,
    // The original admitted ceiling retained in the actual ledger record.
    future_ceiling_bytes: u64,
    // Actual canonical bytes of that complete private record, not UploadView
    // size and not a fabricated test estimate. No private JSON layout is frozen.
    actual_record_bytes: u64,
}

#[cfg(test)]
struct TestBeforeLease {
    arrived: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
