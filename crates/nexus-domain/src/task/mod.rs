//! N3 versioned domain DTOs and pure invariants (no I/O or executor).
pub mod codec;
mod validation;
use codec::{CanonicalDto, DigestFn, Value};
use std::collections::BTreeMap;
pub use validation::{relative_path, validate_provider_transition};
/// Largest exact integer allowed by the frozen wire contract.
pub const MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// Validated SHA-256 reference; legacy CAS locators are not this type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);
impl Sha256Digest {
    pub fn parse(value: String) -> Result<Self, TaskError> {
        if value.len() != 71
            || !value.starts_with("sha256:")
            || !value.as_bytes()[7..]
                .iter()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(x))
        {
            return Err(TaskError::invalid("invalid SHA-256 reference"));
        }
        Ok(Self(value))
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        const H: &[u8] = b"0123456789abcdef";
        let mut s = String::from("sha256:");
        for b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 15) as usize] as char);
        }
        Self(s)
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
macro_rules! id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn new(v: String) -> Result<Self, TaskError> {
                validation::id(&v)?;
                Ok(Self(v))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl CanonicalDto for $name {
            fn to_value(&self) -> Value {
                self.0.to_value()
            }
            fn from_value(v: Value) -> Result<Self, TaskError> {
                Self::new(String::from_value(v)?)
            }
        }
    };
}
id!(TaskId);
id!(ArtifactId);
/// Snapshot identifiers are strong digest references.
pub type SnapshotId = Sha256Digest;
macro_rules! strings {
    ($name:ident {$($variant:ident => $label:literal),+ $(,)?}) => {
        #[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum $name { $($variant),+ }
        impl $name { #[must_use] pub fn as_str(self)->&'static str { match self { $(Self::$variant=>$label),+ } } }
        impl CanonicalDto for $name {
            fn to_value(&self)->Value { self.as_str().to_string().to_value() }
            fn from_value(v:Value)->Result<Self,TaskError> { let s=String::from_value(v)?; match s.as_str() { $($label=>Ok(Self::$variant)),+, _=>Err(TaskError::invalid(concat!("unknown ",stringify!($name)))) } }
        }
    }
}
strings!(TaskPhase {Waiting=>"Waiting",Preparing=>"Preparing",Running=>"Running",Finalizing=>"Finalizing",Finished=>"Finished"});
strings!(TaskOutcome {Unfinished=>"Unfinished",Completed=>"Completed",Failed=>"Failed",Cancelled=>"Cancelled"});
strings!(ExecutionState {NotStarted=>"NotStarted",Running=>"Running",Exited=>"Exited",Stopped=>"Stopped"});
strings!(DeliveryState {Pending=>"Pending",Complete=>"Complete",Failed=>"Failed",NotRequired=>"NotRequired"});
strings!(CancellationState {None=>"None",Requested=>"Requested",Confirmed=>"Confirmed",TooLate=>"TooLate"});
strings!(CancelRequestState {None=>"None",Queued=>"Queued",Acknowledged=>"Acknowledged",Rejected=>"Rejected"});
strings!(IntentOrigin {RequesterIntent=>"RequesterIntent"});
strings!(Observation {Confirmed=>"Confirmed",PendingVerification=>"PendingVerification"});
strings!(PublicationState {Pending=>"Pending",Published=>"Published"});
strings!(TaskErrorCode {
 InvalidRequest=>"INVALID_REQUEST",UnsupportedVersion=>"UNSUPPORTED_VERSION",UnsupportedCapability=>"UNSUPPORTED_CAPABILITY",
 AuthDenied=>"AUTH_DENIED",ProviderUnreachable=>"PROVIDER_UNREACHABLE",EnvironmentMismatch=>"ENVIRONMENT_MISMATCH",
 CapacityUnavailable=>"CAPACITY_UNAVAILABLE",IdempotencyConflict=>"IDEMPOTENCY_CONFLICT",PersistenceFailed=>"PERSISTENCE_FAILED",
 StateCorrupt=>"STATE_CORRUPT",InputUnavailable=>"INPUT_UNAVAILABLE",InputIntegrityFailed=>"INPUT_INTEGRITY_FAILED",
 InvalidPath=>"INVALID_PATH", OutputExists=>"OUTPUT_EXISTS",ArtifactMissing=>"ARTIFACT_MISSING",ArtifactIntegrityFailed=>"ARTIFACT_INTEGRITY_FAILED",
 ArtifactUnavailable=>"ARTIFACT_UNAVAILABLE",WorkloadExit=>"WorkloadExit",Timeout=>"Timeout",
 PrepareDeadlineExceeded=>"PrepareDeadlineExceeded",DeliveryDeadlineExceeded=>"DeliveryDeadlineExceeded",ExecutionLost=>"ExecutionLost"
});
/// Frozen v1 SnapshotRef fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRef {
    pub schema_version: u64,
    pub snapshot_id: Sha256Digest,
    pub workspace: String,
    pub commit_id: String,
    pub root_manifest_id: String,
    pub manifest_sha256: Sha256Digest,
    pub selection_digest: Sha256Digest,
    pub file_count: u64,
    pub total_bytes: u64,
}
impl CanonicalDto for SnapshotRef {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("schema_version".to_string(), self.schema_version.to_value()),
            ("snapshot_id".to_string(), self.snapshot_id.to_value()),
            ("workspace".to_string(), self.workspace.to_value()),
            ("commit_id".to_string(), self.commit_id.to_value()),
            (
                "root_manifest_id".to_string(),
                self.root_manifest_id.to_value(),
            ),
            (
                "manifest_sha256".to_string(),
                self.manifest_sha256.to_value(),
            ),
            (
                "selection_digest".to_string(),
                self.selection_digest.to_value(),
            ),
            ("file_count".to_string(), self.file_count.to_value()),
            ("total_bytes".to_string(), self.total_bytes.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            schema_version: <u64>::from_value(
                fields
                    .remove("schema_version")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.schema_version"))?,
            )?,
            snapshot_id: <Sha256Digest>::from_value(
                fields
                    .remove("snapshot_id")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.snapshot_id"))?,
            )?,
            workspace: <String>::from_value(
                fields
                    .remove("workspace")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.workspace"))?,
            )?,
            commit_id: <String>::from_value(
                fields
                    .remove("commit_id")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.commit_id"))?,
            )?,
            root_manifest_id: <String>::from_value(
                fields
                    .remove("root_manifest_id")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.root_manifest_id"))?,
            )?,
            manifest_sha256: <Sha256Digest>::from_value(
                fields
                    .remove("manifest_sha256")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.manifest_sha256"))?,
            )?,
            selection_digest: <Sha256Digest>::from_value(
                fields
                    .remove("selection_digest")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.selection_digest"))?,
            )?,
            file_count: <u64>::from_value(
                fields
                    .remove("file_count")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.file_count"))?,
            )?,
            total_bytes: <u64>::from_value(
                fields
                    .remove("total_bytes")
                    .ok_or_else(|| TaskError::invalid("missing SnapshotRef.total_bytes"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 EnvironmentRequirement fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRequirement {
    pub os: String,
    pub architecture: String,
    pub image_digest: Sha256Digest,
    pub isolation: String,
    pub network: String,
}
impl CanonicalDto for EnvironmentRequirement {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("os".to_string(), self.os.to_value()),
            ("architecture".to_string(), self.architecture.to_value()),
            ("image_digest".to_string(), self.image_digest.to_value()),
            ("isolation".to_string(), self.isolation.to_value()),
            ("network".to_string(), self.network.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result =
            Self {
                os: <String>::from_value(
                    fields
                        .remove("os")
                        .ok_or_else(|| TaskError::invalid("missing EnvironmentRequirement.os"))?,
                )?,
                architecture: <String>::from_value(fields.remove("architecture").ok_or_else(
                    || TaskError::invalid("missing EnvironmentRequirement.architecture"),
                )?)?,
                image_digest: <Sha256Digest>::from_value(
                    fields.remove("image_digest").ok_or_else(|| {
                        TaskError::invalid("missing EnvironmentRequirement.image_digest")
                    })?,
                )?,
                isolation: <String>::from_value(fields.remove("isolation").ok_or_else(|| {
                    TaskError::invalid("missing EnvironmentRequirement.isolation")
                })?)?,
                network: <String>::from_value(fields.remove("network").ok_or_else(|| {
                    TaskError::invalid("missing EnvironmentRequirement.network")
                })?)?,
            };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 TaskLimits fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLimits {
    pub timeout_seconds: u64,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    pub log_bytes: u64,
}
impl CanonicalDto for TaskLimits {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            (
                "timeout_seconds".to_string(),
                self.timeout_seconds.to_value(),
            ),
            ("cpu_millis".to_string(), self.cpu_millis.to_value()),
            ("memory_bytes".to_string(), self.memory_bytes.to_value()),
            ("storage_bytes".to_string(), self.storage_bytes.to_value()),
            ("log_bytes".to_string(), self.log_bytes.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            timeout_seconds: <u64>::from_value(
                fields
                    .remove("timeout_seconds")
                    .ok_or_else(|| TaskError::invalid("missing TaskLimits.timeout_seconds"))?,
            )?,
            cpu_millis: <u64>::from_value(
                fields
                    .remove("cpu_millis")
                    .ok_or_else(|| TaskError::invalid("missing TaskLimits.cpu_millis"))?,
            )?,
            memory_bytes: <u64>::from_value(
                fields
                    .remove("memory_bytes")
                    .ok_or_else(|| TaskError::invalid("missing TaskLimits.memory_bytes"))?,
            )?,
            storage_bytes: <u64>::from_value(
                fields
                    .remove("storage_bytes")
                    .ok_or_else(|| TaskError::invalid("missing TaskLimits.storage_bytes"))?,
            )?,
            log_bytes: <u64>::from_value(
                fields
                    .remove("log_bytes")
                    .ok_or_else(|| TaskError::invalid("missing TaskLimits.log_bytes"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 OutputSpec fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSpec {
    pub path: String,
    pub required: bool,
}
impl CanonicalDto for OutputSpec {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("path".to_string(), self.path.to_value()),
            ("required".to_string(), self.required.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            path: <String>::from_value(
                fields
                    .remove("path")
                    .ok_or_else(|| TaskError::invalid("missing OutputSpec.path"))?,
            )?,
            required: <bool>::from_value(
                fields
                    .remove("required")
                    .ok_or_else(|| TaskError::invalid("missing OutputSpec.required"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 SubmitTaskRequest fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitTaskRequest {
    pub schema_version: u64,
    pub workspace: String,
    pub resource: String,
    pub provider: String,
    pub input_snapshot: SnapshotRef,
    pub command: Vec<String>,
    pub cwd: String,
    pub environment: EnvironmentRequirement,
    pub limits: TaskLimits,
    pub outputs: Vec<OutputSpec>,
    pub success_exit_codes: Vec<u8>,
    pub idempotency_key: String,
    pub idempotency_ttl_seconds: u64,
}
impl CanonicalDto for SubmitTaskRequest {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("schema_version".to_string(), self.schema_version.to_value()),
            ("workspace".to_string(), self.workspace.to_value()),
            ("resource".to_string(), self.resource.to_value()),
            ("provider".to_string(), self.provider.to_value()),
            ("input_snapshot".to_string(), self.input_snapshot.to_value()),
            ("command".to_string(), self.command.to_value()),
            ("cwd".to_string(), self.cwd.to_value()),
            ("environment".to_string(), self.environment.to_value()),
            ("limits".to_string(), self.limits.to_value()),
            ("outputs".to_string(), self.outputs.to_value()),
            (
                "success_exit_codes".to_string(),
                self.success_exit_codes.to_value(),
            ),
            (
                "idempotency_key".to_string(),
                self.idempotency_key.to_value(),
            ),
            (
                "idempotency_ttl_seconds".to_string(),
                self.idempotency_ttl_seconds.to_value(),
            ),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result =
            Self {
                schema_version: <u64>::from_value(fields.remove("schema_version").ok_or_else(
                    || TaskError::invalid("missing SubmitTaskRequest.schema_version"),
                )?)?,
                workspace: <String>::from_value(
                    fields
                        .remove("workspace")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.workspace"))?,
                )?,
                resource: <String>::from_value(
                    fields
                        .remove("resource")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.resource"))?,
                )?,
                provider: <String>::from_value(
                    fields
                        .remove("provider")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.provider"))?,
                )?,
                input_snapshot: <SnapshotRef>::from_value(
                    fields.remove("input_snapshot").ok_or_else(|| {
                        TaskError::invalid("missing SubmitTaskRequest.input_snapshot")
                    })?,
                )?,
                command: <Vec<String>>::from_value(
                    fields
                        .remove("command")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.command"))?,
                )?,
                cwd: <String>::from_value(
                    fields
                        .remove("cwd")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.cwd"))?,
                )?,
                environment: <EnvironmentRequirement>::from_value(
                    fields.remove("environment").ok_or_else(|| {
                        TaskError::invalid("missing SubmitTaskRequest.environment")
                    })?,
                )?,
                limits: <TaskLimits>::from_value(
                    fields
                        .remove("limits")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.limits"))?,
                )?,
                outputs: <Vec<OutputSpec>>::from_value(
                    fields
                        .remove("outputs")
                        .ok_or_else(|| TaskError::invalid("missing SubmitTaskRequest.outputs"))?,
                )?,
                success_exit_codes: <Vec<u8>>::from_value(
                    fields.remove("success_exit_codes").ok_or_else(|| {
                        TaskError::invalid("missing SubmitTaskRequest.success_exit_codes")
                    })?,
                )?,
                idempotency_key: <String>::from_value(
                    fields.remove("idempotency_key").ok_or_else(|| {
                        TaskError::invalid("missing SubmitTaskRequest.idempotency_key")
                    })?,
                )?,
                idempotency_ttl_seconds: <u64>::from_value(
                    fields.remove("idempotency_ttl_seconds").ok_or_else(|| {
                        TaskError::invalid("missing SubmitTaskRequest.idempotency_ttl_seconds")
                    })?,
                )?,
            };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 TaskError fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskError {
    pub code: TaskErrorCode,
    pub reason: String,
    pub retryable: bool,
}
impl CanonicalDto for TaskError {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("code".to_string(), self.code.to_value()),
            ("reason".to_string(), self.reason.to_value()),
            ("retryable".to_string(), self.retryable.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            code: <TaskErrorCode>::from_value(
                fields
                    .remove("code")
                    .ok_or_else(|| TaskError::invalid("missing TaskError.code"))?,
            )?,
            reason: <String>::from_value(
                fields
                    .remove("reason")
                    .ok_or_else(|| TaskError::invalid("missing TaskError.reason"))?,
            )?,
            retryable: <bool>::from_value(
                fields
                    .remove("retryable")
                    .ok_or_else(|| TaskError::invalid("missing TaskError.retryable"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 AcceptedContract fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedContract {
    pub request: SubmitTaskRequest,
    pub request_digest: Sha256Digest,
    pub authenticated_principal: String,
    pub environment_evidence: EnvironmentRequirement,
    pub capacity_reservation_id: String,
    pub accepted_at_unix: u64,
    pub idempotency_expires_at_unix: u64,
    pub prepare_deadline_unix: u64,
    pub delivery_deadline_unix: u64,
}
impl CanonicalDto for AcceptedContract {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("request".to_string(), self.request.to_value()),
            ("request_digest".to_string(), self.request_digest.to_value()),
            (
                "authenticated_principal".to_string(),
                self.authenticated_principal.to_value(),
            ),
            (
                "environment_evidence".to_string(),
                self.environment_evidence.to_value(),
            ),
            (
                "capacity_reservation_id".to_string(),
                self.capacity_reservation_id.to_value(),
            ),
            (
                "accepted_at_unix".to_string(),
                self.accepted_at_unix.to_value(),
            ),
            (
                "idempotency_expires_at_unix".to_string(),
                self.idempotency_expires_at_unix.to_value(),
            ),
            (
                "prepare_deadline_unix".to_string(),
                self.prepare_deadline_unix.to_value(),
            ),
            (
                "delivery_deadline_unix".to_string(),
                self.delivery_deadline_unix.to_value(),
            ),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            request: <SubmitTaskRequest>::from_value(
                fields
                    .remove("request")
                    .ok_or_else(|| TaskError::invalid("missing AcceptedContract.request"))?,
            )?,
            request_digest: <Sha256Digest>::from_value(
                fields
                    .remove("request_digest")
                    .ok_or_else(|| TaskError::invalid("missing AcceptedContract.request_digest"))?,
            )?,
            authenticated_principal: <String>::from_value(
                fields.remove("authenticated_principal").ok_or_else(|| {
                    TaskError::invalid("missing AcceptedContract.authenticated_principal")
                })?,
            )?,
            environment_evidence: <EnvironmentRequirement>::from_value(
                fields.remove("environment_evidence").ok_or_else(|| {
                    TaskError::invalid("missing AcceptedContract.environment_evidence")
                })?,
            )?,
            capacity_reservation_id: <String>::from_value(
                fields.remove("capacity_reservation_id").ok_or_else(|| {
                    TaskError::invalid("missing AcceptedContract.capacity_reservation_id")
                })?,
            )?,
            accepted_at_unix: <u64>::from_value(
                fields.remove("accepted_at_unix").ok_or_else(|| {
                    TaskError::invalid("missing AcceptedContract.accepted_at_unix")
                })?,
            )?,
            idempotency_expires_at_unix: <u64>::from_value(
                fields
                    .remove("idempotency_expires_at_unix")
                    .ok_or_else(|| {
                        TaskError::invalid("missing AcceptedContract.idempotency_expires_at_unix")
                    })?,
            )?,
            prepare_deadline_unix: <u64>::from_value(
                fields.remove("prepare_deadline_unix").ok_or_else(|| {
                    TaskError::invalid("missing AcceptedContract.prepare_deadline_unix")
                })?,
            )?,
            delivery_deadline_unix: <u64>::from_value(
                fields.remove("delivery_deadline_unix").ok_or_else(|| {
                    TaskError::invalid("missing AcceptedContract.delivery_deadline_unix")
                })?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 TaskExecution fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskExecution {
    pub state: ExecutionState,
    pub started_at_unix: Option<u64>,
    pub exit_code: Option<u8>,
    pub signal: Option<String>,
    pub stop_reason: Option<String>,
    pub result_confirmed: bool,
    pub workload_succeeded: Option<bool>,
}
impl CanonicalDto for TaskExecution {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("state".to_string(), self.state.to_value()),
            (
                "started_at_unix".to_string(),
                self.started_at_unix.to_value(),
            ),
            ("exit_code".to_string(), self.exit_code.to_value()),
            ("signal".to_string(), self.signal.to_value()),
            ("stop_reason".to_string(), self.stop_reason.to_value()),
            (
                "result_confirmed".to_string(),
                self.result_confirmed.to_value(),
            ),
            (
                "workload_succeeded".to_string(),
                self.workload_succeeded.to_value(),
            ),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            state: <ExecutionState>::from_value(
                fields
                    .remove("state")
                    .ok_or_else(|| TaskError::invalid("missing TaskExecution.state"))?,
            )?,
            started_at_unix: <Option<u64>>::from_value(
                fields
                    .remove("started_at_unix")
                    .ok_or_else(|| TaskError::invalid("missing TaskExecution.started_at_unix"))?,
            )?,
            exit_code: <Option<u8>>::from_value(
                fields
                    .remove("exit_code")
                    .ok_or_else(|| TaskError::invalid("missing TaskExecution.exit_code"))?,
            )?,
            signal: <Option<String>>::from_value(
                fields
                    .remove("signal")
                    .ok_or_else(|| TaskError::invalid("missing TaskExecution.signal"))?,
            )?,
            stop_reason: <Option<String>>::from_value(
                fields
                    .remove("stop_reason")
                    .ok_or_else(|| TaskError::invalid("missing TaskExecution.stop_reason"))?,
            )?,
            result_confirmed: <bool>::from_value(
                fields
                    .remove("result_confirmed")
                    .ok_or_else(|| TaskError::invalid("missing TaskExecution.result_confirmed"))?,
            )?,
            workload_succeeded: <Option<bool>>::from_value(
                fields.remove("workload_succeeded").ok_or_else(|| {
                    TaskError::invalid("missing TaskExecution.workload_succeeded")
                })?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 TaskDelivery fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDelivery {
    pub state: DeliveryState,
    pub error: Option<TaskError>,
}
impl CanonicalDto for TaskDelivery {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("state".to_string(), self.state.to_value()),
            ("error".to_string(), self.error.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            state: <DeliveryState>::from_value(
                fields
                    .remove("state")
                    .ok_or_else(|| TaskError::invalid("missing TaskDelivery.state"))?,
            )?,
            error: <Option<TaskError>>::from_value(
                fields
                    .remove("error")
                    .ok_or_else(|| TaskError::invalid("missing TaskDelivery.error"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 TaskCancellation fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCancellation {
    pub state: CancellationState,
    pub reason: Option<String>,
    pub requested_at_unix: Option<u64>,
}
impl CanonicalDto for TaskCancellation {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("state".to_string(), self.state.to_value()),
            ("reason".to_string(), self.reason.to_value()),
            (
                "requested_at_unix".to_string(),
                self.requested_at_unix.to_value(),
            ),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            state: <CancellationState>::from_value(
                fields
                    .remove("state")
                    .ok_or_else(|| TaskError::invalid("missing TaskCancellation.state"))?,
            )?,
            reason: <Option<String>>::from_value(
                fields
                    .remove("reason")
                    .ok_or_else(|| TaskError::invalid("missing TaskCancellation.reason"))?,
            )?,
            requested_at_unix: <Option<u64>>::from_value(
                fields.remove("requested_at_unix").ok_or_else(|| {
                    TaskError::invalid("missing TaskCancellation.requested_at_unix")
                })?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 CancelRequestIntent fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequestIntent {
    pub origin: IntentOrigin,
    pub state: CancelRequestState,
    pub requested_at_unix: Option<u64>,
    pub reason: Option<String>,
    pub error: Option<TaskError>,
}
impl CanonicalDto for CancelRequestIntent {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("origin".to_string(), self.origin.to_value()),
            ("state".to_string(), self.state.to_value()),
            (
                "requested_at_unix".to_string(),
                self.requested_at_unix.to_value(),
            ),
            ("reason".to_string(), self.reason.to_value()),
            ("error".to_string(), self.error.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            origin: <IntentOrigin>::from_value(
                fields
                    .remove("origin")
                    .ok_or_else(|| TaskError::invalid("missing CancelRequestIntent.origin"))?,
            )?,
            state: <CancelRequestState>::from_value(
                fields
                    .remove("state")
                    .ok_or_else(|| TaskError::invalid("missing CancelRequestIntent.state"))?,
            )?,
            requested_at_unix: <Option<u64>>::from_value(
                fields.remove("requested_at_unix").ok_or_else(|| {
                    TaskError::invalid("missing CancelRequestIntent.requested_at_unix")
                })?,
            )?,
            reason: <Option<String>>::from_value(
                fields
                    .remove("reason")
                    .ok_or_else(|| TaskError::invalid("missing CancelRequestIntent.reason"))?,
            )?,
            error: <Option<TaskError>>::from_value(
                fields
                    .remove("error")
                    .ok_or_else(|| TaskError::invalid("missing CancelRequestIntent.error"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 TaskView fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskView {
    pub schema_version: u64,
    pub task_id: TaskId,
    pub accepted_contract: AcceptedContract,
    pub contract_digest: Sha256Digest,
    pub phase: TaskPhase,
    pub outcome: TaskOutcome,
    pub error: Option<TaskError>,
    pub execution: TaskExecution,
    pub delivery: TaskDelivery,
    pub cancellation: TaskCancellation,
    pub cancel_request: CancelRequestIntent,
    pub observation: Observation,
    pub last_event_seq: u64,
    pub session_ids: Vec<String>,
    pub artifact_ids: Vec<ArtifactId>,
}
impl CanonicalDto for TaskView {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("schema_version".to_string(), self.schema_version.to_value()),
            ("task_id".to_string(), self.task_id.to_value()),
            (
                "accepted_contract".to_string(),
                self.accepted_contract.to_value(),
            ),
            (
                "contract_digest".to_string(),
                self.contract_digest.to_value(),
            ),
            ("phase".to_string(), self.phase.to_value()),
            ("outcome".to_string(), self.outcome.to_value()),
            ("error".to_string(), self.error.to_value()),
            ("execution".to_string(), self.execution.to_value()),
            ("delivery".to_string(), self.delivery.to_value()),
            ("cancellation".to_string(), self.cancellation.to_value()),
            ("cancel_request".to_string(), self.cancel_request.to_value()),
            ("observation".to_string(), self.observation.to_value()),
            ("last_event_seq".to_string(), self.last_event_seq.to_value()),
            ("session_ids".to_string(), self.session_ids.to_value()),
            ("artifact_ids".to_string(), self.artifact_ids.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result = Self {
            schema_version: <u64>::from_value(
                fields
                    .remove("schema_version")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.schema_version"))?,
            )?,
            task_id: <TaskId>::from_value(
                fields
                    .remove("task_id")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.task_id"))?,
            )?,
            accepted_contract: <AcceptedContract>::from_value(
                fields
                    .remove("accepted_contract")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.accepted_contract"))?,
            )?,
            contract_digest: <Sha256Digest>::from_value(
                fields
                    .remove("contract_digest")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.contract_digest"))?,
            )?,
            phase: <TaskPhase>::from_value(
                fields
                    .remove("phase")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.phase"))?,
            )?,
            outcome: <TaskOutcome>::from_value(
                fields
                    .remove("outcome")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.outcome"))?,
            )?,
            error: <Option<TaskError>>::from_value(
                fields
                    .remove("error")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.error"))?,
            )?,
            execution: <TaskExecution>::from_value(
                fields
                    .remove("execution")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.execution"))?,
            )?,
            delivery: <TaskDelivery>::from_value(
                fields
                    .remove("delivery")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.delivery"))?,
            )?,
            cancellation: <TaskCancellation>::from_value(
                fields
                    .remove("cancellation")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.cancellation"))?,
            )?,
            cancel_request: <CancelRequestIntent>::from_value(
                fields
                    .remove("cancel_request")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.cancel_request"))?,
            )?,
            observation: <Observation>::from_value(
                fields
                    .remove("observation")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.observation"))?,
            )?,
            last_event_seq: <u64>::from_value(
                fields
                    .remove("last_event_seq")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.last_event_seq"))?,
            )?,
            session_ids: <Vec<String>>::from_value(
                fields
                    .remove("session_ids")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.session_ids"))?,
            )?,
            artifact_ids: <Vec<ArtifactId>>::from_value(
                fields
                    .remove("artifact_ids")
                    .ok_or_else(|| TaskError::invalid("missing TaskView.artifact_ids"))?,
            )?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}
/// Frozen v1 ArtifactRecord fields; validate before hashing or publishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub schema_version: u64,
    pub artifact_id: ArtifactId,
    pub task_id: TaskId,
    pub snapshot_id: Sha256Digest,
    pub environment_digest: Sha256Digest,
    pub producer_node: String,
    pub workspace: String,
    pub owner_principal: String,
    pub path: String,
    pub size_bytes: u64,
    pub content_sha256: Sha256Digest,
    pub storage_ref: String,
    pub created_at_unix: u64,
    pub retain_until_unix: u64,
    pub publication_state: PublicationState,
}
impl CanonicalDto for ArtifactRecord {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("schema_version".to_string(), self.schema_version.to_value()),
            ("artifact_id".to_string(), self.artifact_id.to_value()),
            ("task_id".to_string(), self.task_id.to_value()),
            ("snapshot_id".to_string(), self.snapshot_id.to_value()),
            (
                "environment_digest".to_string(),
                self.environment_digest.to_value(),
            ),
            ("producer_node".to_string(), self.producer_node.to_value()),
            ("workspace".to_string(), self.workspace.to_value()),
            (
                "owner_principal".to_string(),
                self.owner_principal.to_value(),
            ),
            ("path".to_string(), self.path.to_value()),
            ("size_bytes".to_string(), self.size_bytes.to_value()),
            ("content_sha256".to_string(), self.content_sha256.to_value()),
            ("storage_ref".to_string(), self.storage_ref.to_value()),
            (
                "created_at_unix".to_string(),
                self.created_at_unix.to_value(),
            ),
            (
                "retain_until_unix".to_string(),
                self.retain_until_unix.to_value(),
            ),
            (
                "publication_state".to_string(),
                self.publication_state.to_value(),
            ),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("expected object"));
        };
        let result =
            Self {
                schema_version: <u64>::from_value(
                    fields.remove("schema_version").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.schema_version")
                    })?,
                )?,
                artifact_id: <ArtifactId>::from_value(
                    fields
                        .remove("artifact_id")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.artifact_id"))?,
                )?,
                task_id: <TaskId>::from_value(
                    fields
                        .remove("task_id")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.task_id"))?,
                )?,
                snapshot_id: <Sha256Digest>::from_value(
                    fields
                        .remove("snapshot_id")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.snapshot_id"))?,
                )?,
                environment_digest: <Sha256Digest>::from_value(
                    fields.remove("environment_digest").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.environment_digest")
                    })?,
                )?,
                producer_node: <String>::from_value(
                    fields.remove("producer_node").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.producer_node")
                    })?,
                )?,
                workspace: <String>::from_value(
                    fields
                        .remove("workspace")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.workspace"))?,
                )?,
                owner_principal: <String>::from_value(
                    fields.remove("owner_principal").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.owner_principal")
                    })?,
                )?,
                path: <String>::from_value(
                    fields
                        .remove("path")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.path"))?,
                )?,
                size_bytes: <u64>::from_value(
                    fields
                        .remove("size_bytes")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.size_bytes"))?,
                )?,
                content_sha256: <Sha256Digest>::from_value(
                    fields.remove("content_sha256").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.content_sha256")
                    })?,
                )?,
                storage_ref: <String>::from_value(
                    fields
                        .remove("storage_ref")
                        .ok_or_else(|| TaskError::invalid("missing ArtifactRecord.storage_ref"))?,
                )?,
                created_at_unix: <u64>::from_value(fields.remove("created_at_unix").ok_or_else(
                    || TaskError::invalid("missing ArtifactRecord.created_at_unix"),
                )?)?,
                retain_until_unix: <u64>::from_value(
                    fields.remove("retain_until_unix").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.retain_until_unix")
                    })?,
                )?,
                publication_state: <PublicationState>::from_value(
                    fields.remove("publication_state").ok_or_else(|| {
                        TaskError::invalid("missing ArtifactRecord.publication_state")
                    })?,
                )?,
            };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown object field"));
        }
        result.validate()?;
        Ok(result)
    }
}

impl TaskError {
    #[must_use]
    pub fn new(code: TaskErrorCode, reason: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            reason: reason.into(),
            retryable,
        }
    }
    #[must_use]
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::new(TaskErrorCode::InvalidRequest, reason, false)
    }
}
impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.reason)
    }
}
impl std::error::Error for TaskError {}
impl SubmitTaskRequest {
    /// Validated request digest excludes only key/TTL, never command or quotas.
    pub fn request_digest(&self, hash: DigestFn) -> Result<Sha256Digest, TaskError> {
        self.validate()?;
        self.input_snapshot.verify_digest(hash)?;
        let Value::Object(mut v) = self.to_value() else {
            unreachable!()
        };
        v.remove("idempotency_key");
        v.remove("idempotency_ttl_seconds");
        Ok(hash(&Value::Object(v).canonical_bytes()))
    }
}
impl AcceptedContract {
    pub fn contract_digest(&self, hash: DigestFn) -> Result<Sha256Digest, TaskError> {
        self.validate()?;
        if self.request.request_digest(hash)? != self.request_digest {
            return Err(TaskError::invalid("request digest mismatch"));
        }
        Ok(hash(&self.to_value().canonical_bytes()))
    }
}
impl TaskView {
    pub fn verify_digests(&self, hash: DigestFn) -> Result<(), TaskError> {
        self.validate()?;
        if self.accepted_contract.contract_digest(hash)? != self.contract_digest {
            return Err(TaskError::invalid("contract digest mismatch"));
        }
        Ok(())
    }
}

impl SnapshotRef {
    /// Identity covers every other SnapshotRef field including schema version.
    pub fn verify_digest(&self, hash: DigestFn) -> Result<(), TaskError> {
        self.validate()?;
        let Value::Object(mut fields) = self.to_value() else {
            unreachable!()
        };
        fields.remove("snapshot_id");
        if hash(&Value::Object(fields).canonical_bytes()) != self.snapshot_id {
            return Err(TaskError::new(
                TaskErrorCode::InputIntegrityFailed,
                "snapshot identity mismatch",
                false,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
