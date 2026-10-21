//! Composition wrapper for the separately provisioned snapshot staging adapter.
use nexus_control_api::snapshot::{SnapshotEnvelope, SnapshotRequest, UploadId};
use nexus_domain::task::{TaskError, TaskErrorCode};
use std::path::Path;

/// Boot opens and recovers once; requests never provision staging authority.
pub struct LocalSnapshotService {
    #[cfg(target_os = "linux")]
    staging: Option<crate::snapshot_staging::FileSnapshotStaging>,
}

impl LocalSnapshotService {
    pub fn open(config_root: &Path) -> Result<Self, TaskError> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                staging: crate::snapshot_staging::FileSnapshotStaging::open(config_root)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config_root;
            Ok(Self {})
        }
    }

    pub fn execute(&self, request: SnapshotRequest) -> SnapshotEnvelope {
        let upload_id = request_upload_id(&request);
        if let Err(error) = request.validate() {
            return SnapshotEnvelope::Error { error, upload_id };
        }
        #[cfg(target_os = "linux")]
        let response = match &self.staging {
            Some(staging) => staging.execute_local(request.clone()),
            None => SnapshotEnvelope::Error {
                error: TaskError::new(
                    TaskErrorCode::UnsupportedCapability,
                    "snapshot staging is not configured; explicit staging-init is required",
                    false,
                ),
                upload_id: upload_id.clone(),
            },
        };
        #[cfg(not(target_os = "linux"))]
        let response = SnapshotEnvelope::Error {
            error: TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "snapshot staging requires Linux",
                false,
            ),
            upload_id: upload_id.clone(),
        };
        match response.validate_for(&request) {
            Ok(()) => response,
            Err(error) => SnapshotEnvelope::Error {
                error: TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    format!("snapshot service response rejected: {}", error.reason),
                    false,
                ),
                upload_id,
            },
        }
    }
}

fn request_upload_id(request: &SnapshotRequest) -> Option<UploadId> {
    match request {
        SnapshotRequest::Begin { .. } => None,
        SnapshotRequest::PutChunk { upload_id, .. }
        | SnapshotRequest::Get { upload_id }
        | SnapshotRequest::Seal { upload_id }
        | SnapshotRequest::Cancel { upload_id } => Some(upload_id.clone()),
    }
}
