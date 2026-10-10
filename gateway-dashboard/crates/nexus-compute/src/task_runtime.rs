//! Durable provider events. The existing TaskOwner remains the only state writer.
//! Execution adapters supply confirmed facts; they never assign TaskOutcome.
use crate::task::{AcceptedTask, TaskAcceptanceStore, TaskOwner, record_codec};
use nexus_domain::task::{
    codec::{CanonicalDto, DigestFn, Value},
    *,
};
use std::collections::BTreeMap;

/// Internal journal commands, not a caller-authored wire protocol. The service
/// must recheck authorization and capacity and verify inputs before StartIntent.
/// Started/Exited/Stopped/NeverStarted require independent execution-adapter
/// evidence. Stopped means the complete subtree was stopped and reaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeAction {
    /// Trusted composition has checked the existing resource Session, its Plan,
    /// authorization and concrete capacity. This event never owns that Session.
    SessionAttached {
        session_id: String,
    },
    Prepare,
    StartIntent {
        handle: String,
    },
    Started {
        at_unix: u64,
    },
    Exited {
        exit_code: u8,
    },
    Cancel {
        reason: String,
        at_unix: u64,
    },
    Stopped {
        reason: String,
        signal: Option<String>,
    },
    NeverStarted,
    PreparationFailed {
        error: TaskError,
    },
    PrepareDeadline {
        now_unix: u64,
    },
    DeliveryDeadline {
        now_unix: u64,
    },
    DeliveryReady {
        artifacts: Vec<ArtifactRecord>,
        logs: Vec<crate::task_artifact::RegisteredLog>,
        at_unix: u64,
    },
    DeliveryPending {
        error: TaskError,
    },
    ArtifactsMissing {
        paths: Vec<String>,
    },
    ObservationLost,
    /// Adapter has revalidated the same original completed execution identity.
    /// Never confirms a running or ambiguous StartIntent, nor writes Outcome.
    ObservationConfirmed {
        handle: String,
    },
}
/// Sequence is contiguous and local to one Task. Same sequence/action replay is
/// idempotent; conflicting, stale or skipped events are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub sequence: u64,
    pub action: RuntimeAction,
}
/// Immutable acceptance remains separate. This versioned journal binds to its
/// digest and replays facts instead of accepting arbitrary TaskView images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeJournal {
    pub schema_version: u64,
    pub task_id: TaskId,
    pub contract_digest: Sha256Digest,
    pub events: Vec<RuntimeEvent>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeState {
    pub view: TaskView,
    /// Durable non-PID identity recorded before any workload spawn. An adapter
    /// must bind it to this Task/contract and never recycle it for another run.
    pub execution_handle: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUpdate {
    pub state: RuntimeState,
    /// Only a newly applied StartIntent can permit a first spawn. A replay or
    /// ambiguous persistence failure requires reconciliation, never another run.
    pub applied: bool,
}
/// Atomic event storage shares acceptance's process-independent lock, reloads
/// and validates both authorities, and fsyncs before acknowledging an event.
/// Each transaction appends exactly one event or is an unchanged replay;
/// RuntimeUpdate.applied must match that fact and cannot be supplied freely.
/// Deletion Test: portable Compute cannot depend on Linux files/flock/fsync.
pub trait TaskRuntimeStore: TaskAcceptanceStore {
    fn runtime_read(&self, id: &TaskId) -> Result<(AcceptedTask, RuntimeJournal), TaskError>;
    fn runtime_transact(
        &self,
        id: &TaskId,
        update: &mut dyn FnMut(
            &AcceptedTask,
            &mut RuntimeJournal,
        ) -> Result<RuntimeUpdate, TaskError>,
    ) -> Result<RuntimeUpdate, TaskError>;
}
impl RuntimeJournal {
    pub fn initial(accepted: &AcceptedTask) -> Self {
        Self {
            schema_version: 1,
            task_id: accepted.view.task_id.clone(),
            contract_digest: accepted.view.contract_digest.clone(),
            events: Vec::new(),
        }
    }
    /// Corrupt history is preserved and rejected, never cleared to Waiting.
    pub fn replay(
        &self,
        accepted: &AcceptedTask,
        hash: DigestFn,
    ) -> Result<RuntimeState, TaskError> {
        let replay = || {
            accepted.view.verify_digests(hash)?;
            let initial = &accepted.view;
            if initial.phase != TaskPhase::Waiting
                || initial.last_event_seq != 0
                || initial.cancellation.state != CancellationState::None
                || initial.cancel_request.state != CancelRequestState::None
                || initial.observation != Observation::Confirmed
                || !initial.session_ids.is_empty()
                || !initial.artifact_ids.is_empty()
                || accepted.input_pin_intent != initial.accepted_contract.request.input_snapshot
            {
                return Err(TaskError::invalid(
                    "runtime base is not an initial accepted record",
                ));
            }
            if self.schema_version != 1
                || self.task_id != accepted.view.task_id
                || self.contract_digest != accepted.view.contract_digest
            {
                return Err(TaskError::invalid(
                    "runtime journal identity/version mismatch",
                ));
            }
            let mut state = RuntimeState {
                view: accepted.view.clone(),
                execution_handle: None,
            };
            for event in &self.events {
                apply(&mut state, event, hash)?;
            }
            Ok(state)
        };
        replay().map_err(|e: TaskError| {
            TaskError::new(TaskErrorCode::StateCorrupt, e.to_string(), false)
        })
    }
}
impl<S: TaskRuntimeStore> TaskOwner<S> {
    /// Provider-internal view; external reads require current authorization.
    pub fn runtime(&self, id: &TaskId) -> Result<RuntimeState, TaskError> {
        let (accepted, journal) = self.store.runtime_read(id)?;
        journal.replay(&accepted, self.hash)
    }
    pub fn record_event(
        &self,
        id: &TaskId,
        event: RuntimeEvent,
    ) -> Result<RuntimeUpdate, TaskError> {
        self.store.runtime_transact(id, &mut |accepted, journal| {
            let mut state = journal.replay(accepted, self.hash)?;
            if let Some(existing) = journal.events.iter().find(|e| e.sequence == event.sequence) {
                if existing != &event {
                    return Err(TaskError::invalid("conflicting runtime event replay"));
                }
                return Ok(RuntimeUpdate {
                    state,
                    applied: false,
                });
            }
            apply(&mut state, &event, self.hash)?;
            journal.events.push(event.clone());
            journal.replay(accepted, self.hash)?;
            Ok(RuntimeUpdate {
                state,
                applied: true,
            })
        })
    }
}
fn apply(state: &mut RuntimeState, event: &RuntimeEvent, hash: DigestFn) -> Result<(), TaskError> {
    if event.sequence > MAX_INTEGER
        || state.view.last_event_seq.checked_add(1) != Some(event.sequence)
    {
        return Err(TaskError::invalid(
            "runtime event sequence is not contiguous",
        ));
    }
    let previous = state.view.clone();
    let v = &mut state.view;
    // Terminal facts are immutable. Observation can become uncertain; a late
    // cancel on a confirmed natural exit only records TooLate.
    if v.outcome != TaskOutcome::Unfinished
        && !matches!(
            event.action,
            RuntimeAction::ObservationLost
                | RuntimeAction::ObservationConfirmed { .. }
                | RuntimeAction::Cancel { .. }
        )
    {
        return Err(TaskError::invalid(
            "terminal Task cannot accept execution events",
        ));
    }
    match &event.action {
        RuntimeAction::SessionAttached { session_id } => {
            TaskId::new(session_id.clone())?;
            require(
                v.outcome == TaskOutcome::Unfinished,
                "terminal Task cannot acquire a resource Session",
            )?;
            if !v.session_ids.contains(session_id) {
                v.session_ids.push(session_id.clone());
            }
        }
        RuntimeAction::Prepare => {
            require(
                v.phase == TaskPhase::Waiting && v.cancellation.state == CancellationState::None,
                "Task is not waiting",
            )?;
            v.phase = TaskPhase::Preparing;
        }
        RuntimeAction::StartIntent { handle } => {
            require(
                v.phase == TaskPhase::Preparing
                    && state.execution_handle.is_none()
                    && v.cancellation.state == CancellationState::None,
                "Task cannot acquire a second start intent",
            )?;
            // Reuse domain's opaque-ID constraints without introducing a PID DTO.
            TaskId::new(handle.clone())?;
            state.execution_handle = Some(handle.clone());
            v.observation = Observation::PendingVerification;
        }
        RuntimeAction::Started { at_unix } => {
            require(
                v.phase == TaskPhase::Preparing && state.execution_handle.is_some(),
                "Started requires durable StartIntent",
            )?;
            require(*at_unix <= MAX_INTEGER, "start clock exceeds integer range")?;
            v.phase = TaskPhase::Running;
            v.execution.state = ExecutionState::Running;
            v.execution.started_at_unix = Some(*at_unix);
            v.observation = Observation::Confirmed;
        }
        RuntimeAction::Exited { exit_code } => {
            require(
                v.execution.state == ExecutionState::Running,
                "Exit requires a confirmed start",
            )?;
            v.phase = TaskPhase::Finalizing;
            v.execution.state = ExecutionState::Exited;
            v.execution.exit_code = Some(*exit_code);
            v.execution.result_confirmed = true;
            v.execution.workload_succeeded = Some(
                v.accepted_contract
                    .request
                    .success_exit_codes
                    .contains(exit_code),
            );
            v.observation = Observation::Confirmed;
            if v.cancellation.state == CancellationState::Requested {
                v.cancellation.state = CancellationState::TooLate;
            }
            // Even outputs=[] needs registered logs; N3-4 owns delivery evidence.
        }
        RuntimeAction::Cancel { reason, at_unix } => {
            require(
                v.outcome == TaskOutcome::Unfinished
                    || v.execution.state == ExecutionState::Exited
                    || v.cancellation.state == CancellationState::Confirmed,
                "terminal Task without a natural exit cannot accept a new cancellation",
            )?;
            require(
                reason != "Timeout"
                    && *at_unix >= v.accepted_contract.accepted_at_unix
                    && *at_unix <= MAX_INTEGER,
                "invalid cancellation identity/time",
            )?;
            TaskId::new(reason.clone())?;
            if v.cancellation.state == CancellationState::None {
                v.cancellation = TaskCancellation {
                    state: CancellationState::Requested,
                    reason: Some(reason.clone()),
                    requested_at_unix: Some(*at_unix),
                };
                if v.execution.state == ExecutionState::Exited {
                    v.cancellation.state = CancellationState::TooLate;
                } else if v.execution.state == ExecutionState::NotStarted
                    && state.execution_handle.is_none()
                {
                    cancel_finished(v);
                }
            } else {
                require(
                    v.cancellation.reason.as_ref() == Some(reason),
                    "cancellation reason cannot be replaced",
                )?;
            }
        }
        RuntimeAction::Stopped { reason, signal } => {
            require(
                v.execution.state == ExecutionState::Running,
                "Stop requires a confirmed start and reap",
            )?;
            let timeout = reason == "Timeout";
            require(
                timeout
                    || (v.cancellation.state == CancellationState::Requested
                        && v.cancellation.reason.as_ref() == Some(reason)),
                "Stop must match timeout or requested cancellation",
            )?;
            v.execution.state = ExecutionState::Stopped;
            v.execution.signal = signal.clone();
            v.execution.stop_reason = Some(reason.clone());
            v.execution.result_confirmed = true;
            v.observation = Observation::Confirmed;
            if timeout {
                fail_finished(
                    v,
                    TaskError::new(
                        TaskErrorCode::Timeout,
                        "workload timeout confirmed after subtree reap",
                        false,
                    ),
                );
            } else {
                cancel_finished(v);
            }
        }
        RuntimeAction::NeverStarted => {
            require(
                v.execution.state == ExecutionState::NotStarted
                    && state.execution_handle.is_some()
                    && v.cancellation.state == CancellationState::Requested,
                "NeverStarted requires adapter confirmation and pending cancel",
            )?;
            v.observation = Observation::Confirmed;
            cancel_finished(v);
        }
        RuntimeAction::PreparationFailed { error } => {
            require(
                v.execution.state == ExecutionState::NotStarted
                    && state.execution_handle.is_none()
                    && matches!(v.phase, TaskPhase::Waiting | TaskPhase::Preparing),
                "preparation failure cannot hide an ambiguous spawn",
            )?;
            // Reject errors whose frozen semantics require execution/delivery facts.
            require(
                !matches!(
                    error.code,
                    TaskErrorCode::WorkloadExit
                        | TaskErrorCode::Timeout
                        | TaskErrorCode::PrepareDeadlineExceeded
                        | TaskErrorCode::DeliveryDeadlineExceeded
                        | TaskErrorCode::ArtifactMissing
                        | TaskErrorCode::ExecutionLost
                ),
                "error requires different execution facts",
            )?;
            fail_finished(v, error.clone());
        }
        RuntimeAction::PrepareDeadline { now_unix } => {
            require(
                *now_unix <= MAX_INTEGER
                    && *now_unix >= v.accepted_contract.prepare_deadline_unix
                    && v.execution.state == ExecutionState::NotStarted
                    && state.execution_handle.is_none(),
                "deadline cannot prove an ambiguous execution never started",
            )?;
            fail_finished(
                v,
                TaskError::new(
                    TaskErrorCode::PrepareDeadlineExceeded,
                    "preparation deadline reached before StartIntent",
                    false,
                ),
            );
        }
        RuntimeAction::DeliveryDeadline { now_unix } => {
            require(
                *now_unix <= MAX_INTEGER
                    && *now_unix >= v.accepted_contract.delivery_deadline_unix
                    && v.execution.state == ExecutionState::Exited,
                "delivery deadline requires confirmed natural exit",
            )?;
            let error = TaskError::new(
                TaskErrorCode::DeliveryDeadlineExceeded,
                "delivery deadline reached after confirmed exit",
                false,
            );
            v.phase = TaskPhase::Finished;
            v.outcome = TaskOutcome::Failed;
            v.error = Some(error.clone());
            v.delivery = TaskDelivery {
                state: DeliveryState::Failed,
                error: Some(error),
            };
        }
        RuntimeAction::DeliveryReady {
            artifacts,
            logs,
            at_unix,
        } => {
            require(
                v.execution.state == ExecutionState::Exited
                    && v.observation == Observation::Confirmed,
                "delivery completion requires confirmed natural exit",
            )?;
            require(
                *at_unix >= v.accepted_contract.accepted_at_unix
                    && *at_unix < v.accepted_contract.delivery_deadline_unix
                    && *at_unix <= MAX_INTEGER,
                "delivery completion exceeded its accepted deadline",
            )?;
            crate::task_artifact::validate_registration(v, artifacts, logs, hash)?;
            v.artifact_ids = artifacts.iter().map(|a| a.artifact_id.clone()).collect();
            v.delivery = TaskDelivery {
                state: DeliveryState::Complete,
                error: None,
            };
            v.phase = TaskPhase::Finished;
            if v.execution.workload_succeeded == Some(true) {
                v.outcome = TaskOutcome::Completed;
                v.error = None;
            } else {
                v.outcome = TaskOutcome::Failed;
                v.error = Some(TaskError::new(
                    TaskErrorCode::WorkloadExit,
                    "confirmed workload exit is outside success_exit_codes",
                    false,
                ));
            }
        }
        RuntimeAction::DeliveryPending { error } => {
            require(
                v.execution.state == ExecutionState::Exited
                    && error.retryable
                    && matches!(
                        error.code,
                        TaskErrorCode::PersistenceFailed
                            | TaskErrorCode::ArtifactUnavailable
                            | TaskErrorCode::ProviderUnreachable
                            | TaskErrorCode::CapacityUnavailable
                    ),
                "delivery retry requires a retryable transport/storage error",
            )?;
            v.delivery = TaskDelivery {
                state: DeliveryState::Pending,
                error: Some(error.clone()),
            };
        }
        RuntimeAction::ArtifactsMissing { paths } => {
            require(
                v.execution.state == ExecutionState::Exited
                    && v.observation == Observation::Confirmed
                    && !paths.is_empty(),
                "missing outputs require confirmed natural exit",
            )?;
            let mut unique = std::collections::BTreeSet::new();
            require(
                paths.iter().all(|p| {
                    unique.insert(p)
                        && v.accepted_contract
                            .request
                            .outputs
                            .iter()
                            .any(|o| o.required && &o.path == p)
                }),
                "missing paths must be unique required outputs",
            )?;
            let error = TaskError::new(
                TaskErrorCode::ArtifactMissing,
                format!("required outputs unavailable: {}", paths.join(", ")),
                false,
            );
            v.phase = TaskPhase::Finished;
            v.outcome = TaskOutcome::Failed;
            v.error = Some(error.clone());
            v.delivery = TaskDelivery {
                state: DeliveryState::Failed,
                error: Some(error),
            };
        }
        RuntimeAction::ObservationLost => {
            v.observation = Observation::PendingVerification;
        }
        RuntimeAction::ObservationConfirmed { handle } => {
            require(
                state.execution_handle.as_ref() == Some(handle)
                    && matches!(
                        v.execution.state,
                        ExecutionState::Exited | ExecutionState::Stopped
                    )
                    && v.execution.result_confirmed,
                "observation confirmation requires the original completed execution",
            )?;
            v.observation = Observation::Confirmed;
        }
    }
    v.last_event_seq = event.sequence;
    validate_provider_transition(&previous, v)
}
fn require(valid: bool, detail: &str) -> Result<(), TaskError> {
    if valid {
        Ok(())
    } else {
        Err(TaskError::invalid(detail))
    }
}
fn cancel_finished(v: &mut TaskView) {
    v.cancellation.state = CancellationState::Confirmed;
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Cancelled;
    v.delivery = TaskDelivery {
        state: DeliveryState::NotRequired,
        error: None,
    };
}
fn fail_finished(v: &mut TaskView, error: TaskError) {
    v.observation = Observation::Confirmed;
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Failed;
    v.error = Some(error);
    v.delivery = TaskDelivery {
        state: DeliveryState::NotRequired,
        error: None,
    };
}

impl CanonicalDto for RuntimeAction {
    fn to_value(&self) -> Value {
        let (kind, extra) = match self {
            Self::SessionAttached { session_id } => (
                "SessionAttached",
                vec![("session_id", session_id.to_value())],
            ),
            Self::Prepare => ("Prepare", vec![]),
            Self::StartIntent { handle } => ("StartIntent", vec![("handle", handle.to_value())]),
            Self::Started { at_unix } => ("Started", vec![("at_unix", at_unix.to_value())]),
            Self::Exited { exit_code } => ("Exited", vec![("exit_code", exit_code.to_value())]),
            Self::Cancel { reason, at_unix } => (
                "Cancel",
                vec![
                    ("reason", reason.to_value()),
                    ("at_unix", at_unix.to_value()),
                ],
            ),
            Self::Stopped { reason, signal } => (
                "Stopped",
                vec![("reason", reason.to_value()), ("signal", signal.to_value())],
            ),
            Self::NeverStarted => ("NeverStarted", vec![]),
            Self::PreparationFailed { error } => {
                ("PreparationFailed", vec![("error", error.to_value())])
            }
            Self::PrepareDeadline { now_unix } => {
                ("PrepareDeadline", vec![("now_unix", now_unix.to_value())])
            }
            Self::DeliveryDeadline { now_unix } => {
                ("DeliveryDeadline", vec![("now_unix", now_unix.to_value())])
            }
            Self::DeliveryReady {
                artifacts,
                logs,
                at_unix,
            } => (
                "DeliveryReady",
                vec![
                    ("artifacts", artifacts.to_value()),
                    ("logs", logs.to_value()),
                    ("at_unix", at_unix.to_value()),
                ],
            ),
            Self::DeliveryPending { error } => {
                ("DeliveryPending", vec![("error", error.to_value())])
            }
            Self::ArtifactsMissing { paths } => {
                ("ArtifactsMissing", vec![("paths", paths.to_value())])
            }
            Self::ObservationLost => ("ObservationLost", vec![]),
            Self::ObservationConfirmed { handle } => {
                ("ObservationConfirmed", vec![("handle", handle.to_value())])
            }
        };
        let mut fields: BTreeMap<_, _> =
            extra.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        fields.insert("kind".into(), kind.to_string().to_value());
        Value::Object(fields)
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut f) = value else {
            return Err(TaskError::invalid("expected runtime action object"));
        };
        let kind: String = take(&mut f, "kind")?;
        let action = match kind.as_str() {
            "SessionAttached" => Self::SessionAttached {
                session_id: take(&mut f, "session_id")?,
            },
            "Prepare" => Self::Prepare,
            "StartIntent" => Self::StartIntent {
                handle: take(&mut f, "handle")?,
            },
            "Started" => Self::Started {
                at_unix: take(&mut f, "at_unix")?,
            },
            "Exited" => Self::Exited {
                exit_code: take(&mut f, "exit_code")?,
            },
            "Cancel" => Self::Cancel {
                reason: take(&mut f, "reason")?,
                at_unix: take(&mut f, "at_unix")?,
            },
            "Stopped" => Self::Stopped {
                reason: take(&mut f, "reason")?,
                signal: take(&mut f, "signal")?,
            },
            "NeverStarted" => Self::NeverStarted,
            "PreparationFailed" => Self::PreparationFailed {
                error: take(&mut f, "error")?,
            },
            "PrepareDeadline" => Self::PrepareDeadline {
                now_unix: take(&mut f, "now_unix")?,
            },
            "DeliveryDeadline" => Self::DeliveryDeadline {
                now_unix: take(&mut f, "now_unix")?,
            },
            "DeliveryReady" => Self::DeliveryReady {
                artifacts: take(&mut f, "artifacts")?,
                logs: take(&mut f, "logs")?,
                at_unix: take(&mut f, "at_unix")?,
            },
            "DeliveryPending" => Self::DeliveryPending {
                error: take(&mut f, "error")?,
            },
            "ArtifactsMissing" => Self::ArtifactsMissing {
                paths: take(&mut f, "paths")?,
            },
            "ObservationLost" => Self::ObservationLost,
            "ObservationConfirmed" => Self::ObservationConfirmed {
                handle: take(&mut f, "handle")?,
            },
            _ => return Err(TaskError::invalid("unknown runtime action")),
        };
        require(f.is_empty(), "unknown runtime action field")?;
        Ok(action)
    }
}
fn take<T: CanonicalDto>(f: &mut BTreeMap<String, Value>, key: &str) -> Result<T, TaskError> {
    T::from_value(
        f.remove(key)
            .ok_or_else(|| TaskError::invalid(format!("missing runtime field {key}")))?,
    )
}
record_codec!(RuntimeEvent {
    sequence: u64,
    action: RuntimeAction
});
record_codec!(RuntimeJournal { schema_version: u64, task_id: TaskId, contract_digest: Sha256Digest, events: Vec<RuntimeEvent> });

#[cfg(test)]
#[path = "task_runtime_session_tests.rs"]
mod session_tests;
