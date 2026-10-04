//! Pure checks additional to JSON shape: ownership, paths and state combinations.
use super::*;
use std::collections::BTreeSet;

pub(super) fn id(v: &str) -> Result<(), TaskError> {
    if v.is_empty() || v.chars().count() > 256 || v.contains('\0') {
        return Err(TaskError::invalid(
            "identifier must contain 1..256 characters without NUL",
        ));
    }
    Ok(())
}
fn integer(v: u64) -> Result<(), TaskError> {
    if v > MAX_INTEGER {
        Err(TaskError::invalid("integer exceeds 2^53-1"))
    } else {
        Ok(())
    }
}
fn version(v: u64) -> Result<(), TaskError> {
    if v != 1 {
        Err(TaskError::new(
            TaskErrorCode::UnsupportedVersion,
            "N3 schema_version must be 1",
            false,
        ))
    } else {
        Ok(())
    }
}
/// Validate a normalized portable relative path. Actual filesystem collisions,
/// symlinks and directory membership still require the Workspace adapter.
pub fn relative_path(v: &str) -> Result<(), TaskError> {
    if v.is_empty()
        || v.chars().count() > 4096
        || v.contains(['\0', '\\'])
        || (v.as_bytes().get(1) == Some(&b':') && v.as_bytes()[0].is_ascii_alphabetic())
        || v.split('/').any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(TaskError::new(
            TaskErrorCode::InvalidPath,
            "unsafe relative path",
            false,
        ));
    }
    Ok(())
}
fn unique_ids<'a>(vs: impl Iterator<Item = &'a str>) -> Result<(), TaskError> {
    let mut seen = BTreeSet::new();
    for v in vs {
        id(v)?;
        if !seen.insert(v) {
            return Err(TaskError::invalid("duplicate identifier"));
        }
    }
    Ok(())
}
impl SnapshotRef {
    pub fn validate(&self) -> Result<(), TaskError> {
        version(self.schema_version)?;
        id(&self.workspace)?;
        id(&self.commit_id)?;
        id(&self.root_manifest_id)?;
        integer(self.file_count)?;
        integer(self.total_bytes)
    }
}
impl EnvironmentRequirement {
    pub fn validate(&self) -> Result<(), TaskError> {
        if self.os != "linux"
            || !["x86_64", "aarch64"].contains(&self.architecture.as_str())
            || self.isolation != "container"
            || self.network != "none"
        {
            return Err(TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "N3 requires isolated Linux container/network none",
                false,
            ));
        }
        Ok(())
    }
}
impl TaskLimits {
    pub fn validate(&self) -> Result<(), TaskError> {
        for v in [
            self.timeout_seconds,
            self.cpu_millis,
            self.memory_bytes,
            self.storage_bytes,
            self.log_bytes,
        ] {
            integer(v)?;
            if v == 0 {
                return Err(TaskError::invalid("hard limits must be positive"));
            }
        }
        Ok(())
    }
}
impl OutputSpec {
    pub fn validate(&self) -> Result<(), TaskError> {
        relative_path(&self.path)
    }
}
impl SubmitTaskRequest {
    pub fn validate(&self) -> Result<(), TaskError> {
        version(self.schema_version)?;
        for v in [
            &self.workspace,
            &self.resource,
            &self.provider,
            &self.idempotency_key,
        ] {
            id(v)?;
        }
        self.input_snapshot.validate()?;
        if self.workspace != self.input_snapshot.workspace {
            return Err(TaskError::invalid(
                "snapshot Workspace differs from request",
            ));
        }
        self.environment.validate()?;
        self.limits.validate()?;
        if self.command.is_empty()
            || self.command.len() > 1024
            || self.command[0].is_empty()
            || self
                .command
                .iter()
                .any(|v| v.chars().count() > 32768 || v.contains('\0'))
        {
            return Err(TaskError::invalid("invalid argv"));
        }
        if self.cwd != "." {
            relative_path(&self.cwd)?;
        }
        if !(1..=86400).contains(&self.idempotency_ttl_seconds) {
            return Err(TaskError::invalid(
                "idempotency TTL must be 1..86400 seconds",
            ));
        }
        if self.outputs.len() > 1024 {
            return Err(TaskError::invalid("too many outputs"));
        }
        let mut paths = BTreeSet::new();
        for v in &self.outputs {
            v.validate()?;
            if !paths.insert(&v.path) {
                return Err(TaskError::invalid("duplicate output path"));
            }
        }
        let mut exits = BTreeSet::new();
        if self.success_exit_codes.is_empty()
            || self.success_exit_codes.iter().any(|v| !exits.insert(v))
        {
            return Err(TaskError::invalid("invalid success exit code set"));
        }
        Ok(())
    }
}
impl TaskError {
    pub fn validate(&self) -> Result<(), TaskError> {
        Ok(())
    }
}
impl AcceptedContract {
    pub fn validate(&self) -> Result<(), TaskError> {
        self.request.validate()?;
        self.environment_evidence.validate()?;
        id(&self.authenticated_principal)?;
        id(&self.capacity_reservation_id)?;
        if self.request.environment != self.environment_evidence {
            return Err(TaskError::new(
                TaskErrorCode::EnvironmentMismatch,
                "resolved environment differs from request",
                false,
            ));
        }
        for v in [
            self.accepted_at_unix,
            self.idempotency_expires_at_unix,
            self.prepare_deadline_unix,
            self.delivery_deadline_unix,
        ] {
            integer(v)?;
        }
        if self
            .accepted_at_unix
            .checked_add(self.request.idempotency_ttl_seconds)
            != Some(self.idempotency_expires_at_unix)
        {
            return Err(TaskError::invalid(
                "idempotency expiry differs from initial TTL",
            ));
        }
        if self.prepare_deadline_unix <= self.accepted_at_unix
            || self.delivery_deadline_unix <= self.prepare_deadline_unix
        {
            return Err(TaskError::invalid("invalid preparation/delivery deadlines"));
        }
        Ok(())
    }
}
impl TaskExecution {
    pub fn validate(&self) -> Result<(), TaskError> {
        if let Some(t) = self.started_at_unix {
            integer(t)?;
        }
        if let Some(v) = &self.signal {
            id(v)?;
        }
        if let Some(v) = &self.stop_reason {
            id(v)?;
        }
        let valid = match self.state {
            ExecutionState::NotStarted => {
                self.started_at_unix.is_none()
                    && self.exit_code.is_none()
                    && self.signal.is_none()
                    && self.stop_reason.is_none()
                    && !self.result_confirmed
                    && self.workload_succeeded.is_none()
            }
            ExecutionState::Running => {
                self.started_at_unix.is_some()
                    && self.exit_code.is_none()
                    && self.signal.is_none()
                    && self.stop_reason.is_none()
                    && !self.result_confirmed
                    && self.workload_succeeded.is_none()
            }
            ExecutionState::Exited => {
                self.started_at_unix.is_some()
                    && self.exit_code.is_some()
                    && self.signal.is_none()
                    && self.stop_reason.is_none()
                    && self.result_confirmed
                    && self.workload_succeeded.is_some()
            }
            // Unstarted cancellation remains NotStarted; Stopped has a real start.
            ExecutionState::Stopped => {
                self.started_at_unix.is_some()
                    && self.exit_code.is_none()
                    && self.stop_reason.is_some()
                    && self.result_confirmed
                    && self.workload_succeeded.is_none()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(TaskError::invalid("inconsistent execution state"))
        }
    }
}
impl TaskDelivery {
    pub fn validate(&self) -> Result<(), TaskError> {
        if let Some(e) = &self.error {
            e.validate()?;
        }
        let valid = match self.state {
            DeliveryState::Pending => self.error.as_ref().is_none_or(|e| e.retryable),
            DeliveryState::Failed => self.error.as_ref().is_some_and(|e| !e.retryable),
            DeliveryState::Complete | DeliveryState::NotRequired => self.error.is_none(),
        };
        if valid {
            Ok(())
        } else {
            Err(TaskError::invalid("inconsistent delivery/error"))
        }
    }
}
impl TaskCancellation {
    pub fn validate(&self) -> Result<(), TaskError> {
        if let Some(v) = &self.reason {
            id(v)?;
        }
        if let Some(t) = self.requested_at_unix {
            integer(t)?;
        }
        let valid = if self.state == CancellationState::None {
            self.reason.is_none() && self.requested_at_unix.is_none()
        } else {
            self.reason.is_some() && self.requested_at_unix.is_some()
        };
        if valid {
            Ok(())
        } else {
            Err(TaskError::invalid("inconsistent provider cancellation"))
        }
    }
}
impl CancelRequestIntent {
    pub fn validate(&self) -> Result<(), TaskError> {
        if let Some(v) = &self.reason {
            id(v)?;
        }
        if let Some(t) = self.requested_at_unix {
            integer(t)?;
        }
        let valid = if self.state == CancelRequestState::None {
            self.reason.is_none() && self.requested_at_unix.is_none()
        } else {
            self.reason.is_some() && self.requested_at_unix.is_some()
        };
        if !valid || (self.state == CancelRequestState::Rejected) != self.error.is_some() {
            return Err(TaskError::invalid("inconsistent requester cancel intent"));
        }
        if let Some(e) = &self.error {
            e.validate()?;
        }
        Ok(())
    }
}
impl TaskView {
    /// Validate facts without inferring authoritative results from observation loss.
    pub fn validate(&self) -> Result<(), TaskError> {
        version(self.schema_version)?;
        self.accepted_contract.validate()?;
        integer(self.last_event_seq)?;
        self.execution.validate()?;
        self.delivery.validate()?;
        self.cancellation.validate()?;
        self.cancel_request.validate()?;
        unique_ids(self.session_ids.iter().map(String::as_str))?;
        unique_ids(self.artifact_ids.iter().map(ArtifactId::as_str))?;
        if let Some(e) = &self.error {
            e.validate()?;
        }
        if (self.outcome == TaskOutcome::Failed) != self.error.is_some()
            || (self.phase == TaskPhase::Finished) == (self.outcome == TaskOutcome::Unfinished)
        {
            return Err(TaskError::invalid("phase/outcome/error mismatch"));
        }
        if let Some(t) = self.execution.started_at_unix {
            if t < self.accepted_contract.accepted_at_unix {
                return Err(TaskError::invalid("execution predates acceptance"));
            }
        }
        if self.execution.state == ExecutionState::Exited {
            let success = self.execution.exit_code.is_some_and(|c| {
                self.accepted_contract
                    .request
                    .success_exit_codes
                    .contains(&c)
            });
            if self.execution.workload_succeeded != Some(success) {
                return Err(TaskError::invalid(
                    "exit success does not match accepted codes",
                ));
            }
        }
        let valid = match self.phase {
            TaskPhase::Waiting | TaskPhase::Preparing => {
                self.execution.state == ExecutionState::NotStarted
                    && self.delivery.state == DeliveryState::Pending
            }
            TaskPhase::Running => {
                self.execution.state == ExecutionState::Running
                    && self.delivery.state == DeliveryState::Pending
            }
            TaskPhase::Finalizing => {
                [ExecutionState::Exited, ExecutionState::Stopped].contains(&self.execution.state)
                    && self.delivery.state == DeliveryState::Pending
            }
            TaskPhase::Finished => {
                self.execution.state != ExecutionState::Running
                    && match self.outcome {
                        TaskOutcome::Completed => {
                            self.execution.state == ExecutionState::Exited
                                && self.execution.workload_succeeded == Some(true)
                                && self.delivery.state == DeliveryState::Complete
                                && self.cancellation.state != CancellationState::Confirmed
                        }
                        TaskOutcome::Cancelled => {
                            [ExecutionState::NotStarted, ExecutionState::Stopped]
                                .contains(&self.execution.state)
                                && self.cancellation.state == CancellationState::Confirmed
                                && self.delivery.state == DeliveryState::NotRequired
                                && (self.execution.state == ExecutionState::NotStarted
                                    || self.execution.stop_reason == self.cancellation.reason)
                                && self.cancellation.reason.as_deref() != Some("Timeout")
                        }
                        TaskOutcome::Failed => match self.execution.state {
                            ExecutionState::NotStarted | ExecutionState::Stopped => {
                                self.delivery.state == DeliveryState::NotRequired
                            }
                            ExecutionState::Exited => {
                                self.delivery.state == DeliveryState::Failed
                                    || (self.delivery.state == DeliveryState::Complete
                                        && self.execution.workload_succeeded == Some(false)
                                        && self
                                            .error
                                            .as_ref()
                                            .is_some_and(|e| e.code == TaskErrorCode::WorkloadExit))
                            }
                            ExecutionState::Running => false,
                        },
                        TaskOutcome::Unfinished => false,
                    }
            }
        };
        if !valid {
            return Err(TaskError::invalid(
                "phase/execution/delivery/outcome mismatch",
            ));
        }
        if self.cancellation.state == CancellationState::Confirmed
            && [ExecutionState::Running, ExecutionState::Exited].contains(&self.execution.state)
        {
            return Err(TaskError::invalid(
                "cancellation confirmed without stopping",
            ));
        }
        if self.cancellation.state == CancellationState::TooLate
            && self.execution.state != ExecutionState::Exited
        {
            return Err(TaskError::invalid(
                "TooLate cancellation requires a confirmed natural exit",
            ));
        }
        if self.execution.state == ExecutionState::Stopped
            && self.execution.stop_reason.as_deref() == Some("Timeout")
            && self.outcome != TaskOutcome::Unfinished
            && (self.outcome != TaskOutcome::Failed
                || self
                    .error
                    .as_ref()
                    .is_none_or(|e| e.code != TaskErrorCode::Timeout))
        {
            return Err(TaskError::invalid(
                "confirmed timeout must finish as Failed/Timeout",
            ));
        }
        if let Some(error) = &self.error {
            let consistent = match error.code {
                TaskErrorCode::WorkloadExit => {
                    self.execution.state == ExecutionState::Exited
                        && self.execution.workload_succeeded == Some(false)
                        && self.delivery.state == DeliveryState::Complete
                }
                TaskErrorCode::Timeout => {
                    self.execution.state == ExecutionState::Stopped
                        && self.execution.stop_reason.as_deref() == Some("Timeout")
                        && self.delivery.state == DeliveryState::NotRequired
                }
                TaskErrorCode::PrepareDeadlineExceeded => {
                    self.execution.state == ExecutionState::NotStarted
                        && self.delivery.state == DeliveryState::NotRequired
                }
                TaskErrorCode::DeliveryDeadlineExceeded | TaskErrorCode::ArtifactMissing => {
                    self.execution.state == ExecutionState::Exited
                        && self.delivery.state == DeliveryState::Failed
                }
                _ => true,
            };
            if !consistent {
                return Err(TaskError::invalid(
                    "failure reason differs from execution/delivery facts",
                ));
            }
        }
        Ok(())
    }
}
impl ArtifactRecord {
    pub fn validate(&self) -> Result<(), TaskError> {
        version(self.schema_version)?;
        for v in [
            &self.producer_node,
            &self.workspace,
            &self.owner_principal,
            &self.storage_ref,
        ] {
            id(v)?;
        }
        relative_path(&self.path)?;
        integer(self.size_bytes)?;
        integer(self.created_at_unix)?;
        integer(self.retain_until_unix)?;
        if self.retain_until_unix < self.created_at_unix {
            return Err(TaskError::invalid("retention predates creation"));
        }
        Ok(())
    }
}

/// Check a provider event update without mutating either observation. Local
/// requester intents cannot change accepted execution facts or commit outcomes.
pub fn validate_provider_transition(previous: &TaskView, next: &TaskView) -> Result<(), TaskError> {
    previous.validate()?;
    next.validate()?;
    if previous == next {
        return Ok(());
    }
    if previous.task_id != next.task_id
        || previous.accepted_contract != next.accepted_contract
        || previous.contract_digest != next.contract_digest
        || next.last_event_seq <= previous.last_event_seq
    {
        return Err(TaskError::invalid(
            "accepted identity changed or event sequence did not advance",
        ));
    }
    let rank = |p: TaskPhase| match p {
        TaskPhase::Waiting => 0,
        TaskPhase::Preparing => 1,
        TaskPhase::Running => 2,
        TaskPhase::Finalizing => 3,
        TaskPhase::Finished => 4,
    };
    if rank(next.phase) < rank(previous.phase) {
        return Err(TaskError::invalid("phase regressed"));
    }
    if previous.outcome != TaskOutcome::Unfinished
        && (previous.outcome != next.outcome
            || previous.phase != next.phase
            || previous.error != next.error
            || previous.execution != next.execution
            || previous.delivery != next.delivery)
    {
        return Err(TaskError::invalid(
            "terminal outcome or execution facts changed",
        ));
    }
    if previous.execution.result_confirmed && previous.execution != next.execution {
        return Err(TaskError::invalid("confirmed execution result changed"));
    }
    if let Some(t) = previous.execution.started_at_unix {
        if next.execution.started_at_unix != Some(t) {
            return Err(TaskError::invalid("execution start identity/time changed"));
        }
    }
    if previous.execution.state != ExecutionState::NotStarted
        && next.execution.state == ExecutionState::NotStarted
    {
        return Err(TaskError::invalid("execution reset"));
    }
    if previous.delivery.state != DeliveryState::Pending && previous.delivery != next.delivery {
        return Err(TaskError::invalid("final delivery result changed"));
    }
    let cancellation_valid = match previous.cancellation.state {
        CancellationState::None => true,
        CancellationState::Requested => {
            next.cancellation.state != CancellationState::None
                && previous.cancellation.reason == next.cancellation.reason
                && previous.cancellation.requested_at_unix == next.cancellation.requested_at_unix
        }
        CancellationState::Confirmed | CancellationState::TooLate => {
            previous.cancellation == next.cancellation
        }
    };
    if !cancellation_valid {
        return Err(TaskError::invalid(
            "cancellation regressed or changed identity",
        ));
    }
    if previous
        .session_ids
        .iter()
        .any(|id| !next.session_ids.contains(id))
        || previous
            .artifact_ids
            .iter()
            .any(|id| !next.artifact_ids.contains(id))
    {
        return Err(TaskError::invalid(
            "accepted event history references were removed",
        ));
    }
    Ok(())
}
