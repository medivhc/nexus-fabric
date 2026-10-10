//! N3 Application API. Authentication, current authorization and persistence
//! belong to daemon adapters; these DTOs never confer authority or spawn work.
pub use nexus_domain::task::codec::{CanonicalDto, Value};
pub use nexus_domain::task::{
    ArtifactId, ArtifactRecord, MAX_INTEGER, SubmitTaskRequest, TaskError, TaskErrorCode, TaskId,
    TaskView,
};
use std::collections::BTreeMap;

/// Upper bound for one log or artifact page (independent byte offsets).
pub const MAX_PAGE_BYTES: u64 = 65_536;

/// Constructed only by the authenticated service boundary, never deserialized
/// from a request. Construction validates identifiers, not credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCallContext {
    principal: String,
    workspace: String,
}
impl TaskCallContext {
    pub fn from_authenticated(principal: String, workspace: String) -> Result<Self, TaskError> {
        TaskId::new(principal.clone())?;
        TaskId::new(workspace.clone())?;
        Ok(Self {
            principal,
            workspace,
        })
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn workspace(&self) -> &str {
        &self.workspace
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}
impl CanonicalDto for LogStream {
    fn to_value(&self) -> Value {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
        .to_string()
        .to_value()
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        match String::from_value(value)?.as_str() {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => Err(TaskError::invalid("stream must be stdout or stderr")),
        }
    }
}

/// Versioned messages; principal and local filesystem destinations are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRequest {
    Submit {
        request: Box<SubmitTaskRequest>,
    },
    Get {
        task_id: TaskId,
    },
    ReadLogs {
        task_id: TaskId,
        stream: LogStream,
        offset: u64,
        max_bytes: u64,
    },
    Cancel {
        task_id: TaskId,
    },
    ListArtifacts {
        task_id: TaskId,
    },
    GetArtifact {
        artifact_id: ArtifactId,
        offset: u64,
        max_bytes: u64,
    },
}
impl TaskRequest {
    pub fn task_id(&self) -> Option<&TaskId> {
        match self {
            Self::Get { task_id }
            | Self::ReadLogs { task_id, .. }
            | Self::Cancel { task_id }
            | Self::ListArtifacts { task_id } => Some(task_id),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<(), TaskError> {
        match self {
            Self::Submit { request } => request.validate(),
            Self::ReadLogs {
                offset, max_bytes, ..
            }
            | Self::GetArtifact {
                offset, max_bytes, ..
            } => page_request(*offset, *max_bytes),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLogsPage {
    pub task_id: TaskId,
    pub stream: LogStream,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
    pub truncated: bool,
}
impl TaskLogsPage {
    pub fn validate(&self) -> Result<(), TaskError> {
        page_response(self.offset, &self.bytes, self.next_offset)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskArtifactPage {
    pub record: ArtifactRecord,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
}
impl TaskArtifactPage {
    pub fn validate(&self) -> Result<(), TaskError> {
        self.record.validate()?;
        if self.record.publication_state != nexus_domain::task::PublicationState::Published {
            return Err(TaskError::invalid(
                "artifact page requires a Published record",
            ));
        }
        page_response(self.offset, &self.bytes, self.next_offset)?;
        if (self.bytes.is_empty() && !self.eof)
            || self.next_offset > self.record.size_bytes
            || self.eof != (self.next_offset == self.record.size_bytes)
        {
            return Err(TaskError::invalid("artifact page EOF/size mismatch"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskArtifactList {
    pub task_id: TaskId,
    pub records: Vec<ArtifactRecord>,
}
impl TaskArtifactList {
    pub fn validate(&self) -> Result<(), TaskError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if record.task_id != self.task_id
                || !seen.insert(&record.artifact_id)
                || !paths.insert(&record.path)
            {
                return Err(TaskError::invalid(
                    "artifact list has foreign task or duplicate ID/path",
                ));
            }
            if self.records.first().is_some_and(|first| {
                first.workspace != record.workspace
                    || first.owner_principal != record.owner_principal
                    || first.snapshot_id != record.snapshot_id
                    || first.environment_digest != record.environment_digest
                    || first.producer_node != record.producer_node
            }) {
                return Err(TaskError::invalid("artifact list mixes task provenance"));
            }
        }
        Ok(())
    }
}

/// PASS concerns handling this operation; a Task response may have Failed outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskResponse {
    Task(Box<TaskView>),
    Logs(TaskLogsPage),
    Artifacts(TaskArtifactList),
    Artifact(Box<TaskArtifactPage>),
}
impl TaskResponse {
    pub fn validate(&self) -> Result<(), TaskError> {
        match self {
            Self::Task(v) => v.validate(),
            Self::Logs(v) => v.validate(),
            Self::Artifacts(v) => v.validate(),
            Self::Artifact(v) => v.validate(),
        }
    }
}

/// Authentication is a separate boundary. Implementations must recheck current
/// authorization for every operation, persist before acknowledging acceptance or
/// queued cancellation, and leave terminal writes to the provider TaskOwner.
/// Deletion test: deleting this interface couples portable frontends to daemon
/// storage/executor/authentication; fake adapters can test dispatch independently.
pub trait TaskApplicationService: Send + Sync {
    fn execute(
        &self,
        context: &TaskCallContext,
        request: TaskRequest,
    ) -> Result<TaskResponse, TaskError>;
}

/// CLI / client envelope. task_id is explicitly null for pre-acceptance errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskEnvelope {
    Success(TaskResponse),
    Error {
        error: TaskError,
        task_id: Option<TaskId>,
    },
}
impl TaskEnvelope {
    pub fn validate(&self) -> Result<(), TaskError> {
        match self {
            Self::Success(response) => response.validate(),
            Self::Error { error, .. } => error.validate(),
        }
    }
}
fn page_request(offset: u64, max_bytes: u64) -> Result<(), TaskError> {
    if offset > MAX_INTEGER || !(1..=MAX_PAGE_BYTES).contains(&max_bytes) {
        return Err(TaskError::invalid("invalid page offset or max_bytes"));
    }
    Ok(())
}
fn page_response(offset: u64, bytes: &[u8], next_offset: u64) -> Result<(), TaskError> {
    if offset > MAX_INTEGER
        || next_offset > MAX_INTEGER
        || bytes.len() > MAX_PAGE_BYTES as usize
        || offset.checked_add(bytes.len() as u64) != Some(next_offset)
    {
        return Err(TaskError::invalid(
            "invalid page byte range or missing progress",
        ));
    }
    Ok(())
}
fn object(value: Value) -> Result<BTreeMap<String, Value>, TaskError> {
    if let Value::Object(fields) = value {
        Ok(fields)
    } else {
        Err(TaskError::invalid("expected object"))
    }
}
fn take<T: CanonicalDto>(fields: &mut BTreeMap<String, Value>, name: &str) -> Result<T, TaskError> {
    T::from_value(
        fields
            .remove(name)
            .ok_or_else(|| TaskError::invalid(format!("missing {name}")))?,
    )
}
fn end(fields: &BTreeMap<String, Value>) -> Result<(), TaskError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(TaskError::invalid("unknown object field"))
    }
}
fn version(fields: &mut BTreeMap<String, Value>) -> Result<(), TaskError> {
    if take::<u64>(fields, "schema_version")? != 1 {
        return Err(TaskError::new(
            TaskErrorCode::UnsupportedVersion,
            "unsupported Application API version",
            false,
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests;
mod wire;
