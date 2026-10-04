//! Provider-owned N3 acceptance. No process, transport or Session owner is created.
use nexus_domain::task::{
    codec::{CanonicalDto, DigestFn, Value},
    *,
};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable accepted record and durable input pin intent, published together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedTask {
    pub view: TaskView,
    pub input_pin_intent: SnapshotRef,
}
/// An idempotency key has authority only inside this complete authenticated scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IdempotencyScope {
    pub workspace: String,
    pub authenticated_principal: String,
    pub provider: String,
    pub key: String,
}
/// Durable index; expiry is fixed at the first acceptance, never extended on replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyEntry {
    pub scope: IdempotencyScope,
    pub task_id: TaskId,
    pub request_digest: Sha256Digest,
    pub expires_at_unix: u64,
}
/// Single atomic acceptance image. Old tasks survive expiry and key reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceLedger {
    pub schema_version: u64,
    pub tasks: Vec<AcceptedTask>,
    pub idempotency: Vec<IdempotencyEntry>,
}
impl Default for AcceptanceLedger {
    fn default() -> Self {
        Self {
            schema_version: 1,
            tasks: Vec::new(),
            idempotency: Vec::new(),
        }
    }
}
impl AcceptanceLedger {
    /// Fail closed on broken links, duplicate scopes, malformed facts or digests.
    pub fn validate(&self, hash: DigestFn) -> Result<(), TaskError> {
        let check = || {
            if self.schema_version != 1 {
                return Err(TaskError::invalid("unsupported acceptance ledger version"));
            }
            let mut tasks = BTreeMap::new();
            for task in &self.tasks {
                task.view.verify_digests(hash)?;
                task.input_pin_intent.validate()?;
                if task.input_pin_intent != task.view.accepted_contract.request.input_snapshot {
                    return Err(TaskError::invalid(
                        "pin intent differs from accepted snapshot",
                    ));
                }
                if task.view.phase != TaskPhase::Waiting
                    || task.view.last_event_seq != 0
                    || task.view.cancel_request.state != CancelRequestState::None
                    || task.view.observation != Observation::Confirmed
                    || task.view.cancellation.state != CancellationState::None
                    || !task.view.session_ids.is_empty()
                    || !task.view.artifact_ids.is_empty()
                {
                    return Err(TaskError::invalid(
                        "acceptance record is not initial provider state",
                    ));
                }
                if tasks.insert(&task.view.task_id, task).is_some() {
                    return Err(TaskError::invalid("duplicate TaskId"));
                }
            }
            let mut scopes = BTreeSet::new();
            for entry in &self.idempotency {
                if !scopes.insert(&entry.scope) {
                    return Err(TaskError::invalid("duplicate idempotency scope"));
                }
                let task = tasks.get(&entry.task_id).ok_or_else(|| {
                    TaskError::invalid("idempotency index references missing Task")
                })?;
                let c = &task.view.accepted_contract;
                if entry.scope != scope_of(c)
                    || entry.expires_at_unix != c.idempotency_expires_at_unix
                    || entry.request_digest != c.request_digest
                {
                    return Err(TaskError::invalid(
                        "idempotency index differs from accepted record",
                    ));
                }
            }
            // Every scope retains its latest accepted record. Replaced older records
            // remain protected; absence of a scope index is never a cache miss.
            for task in &self.tasks {
                let c = &task.view.accepted_contract;
                let entry = self
                    .idempotency
                    .iter()
                    .find(|e| e.scope == scope_of(c))
                    .ok_or_else(|| TaskError::invalid("accepted scope has no idempotency index"))?;
                let latest = tasks
                    .get(&entry.task_id)
                    .ok_or_else(|| TaskError::invalid("missing latest Task"))?;
                if latest.view.accepted_contract.accepted_at_unix < c.accepted_at_unix {
                    return Err(TaskError::invalid(
                        "idempotency index regressed to an older acceptance",
                    ));
                }
            }
            Ok(())
        };
        check().map_err(|e: TaskError| {
            TaskError::new(TaskErrorCode::StateCorrupt, e.to_string(), false)
        })
    }
}
fn scope_of(c: &AcceptedContract) -> IdempotencyScope {
    IdempotencyScope {
        workspace: c.request.workspace.clone(),
        authenticated_principal: c.authenticated_principal.clone(),
        provider: c.request.provider.clone(),
        key: c.request.idempotency_key.clone(),
    }
}
/// Atomic storage boundary, injected by the composition root. Implementations must
/// serialize independent processes, reload under that lock, invoke update once,
/// and durably publish the entire image before returning a newly accepted Task.
/// A failed commit can be ambiguous: the caller retries the same scoped key.
/// No in-memory-only fallback or automatic task execution is permitted.
/// Prior accepted records are immutable and retained. A transaction appends one
/// accepted record with replayed=false, or changes nothing with replayed=true;
/// its returned record must exist exactly in the image and current scoped index. Any runtime authority
/// sharing the store must be validated against the updated image before publish.
pub trait TaskAcceptanceStore {
    fn read(&self) -> Result<AcceptanceLedger, TaskError>;
    fn transact(
        &self,
        update: &mut dyn FnMut(&mut AcceptanceLedger) -> Result<AcceptanceResult, TaskError>,
    ) -> Result<AcceptanceResult, TaskError>;
}
/// Successful processing distinguishes first durable acceptance from replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceResult {
    pub task: AcceptedTask,
    pub replayed: bool,
}
/// Evidence from the authenticated, authorized composition-root service, never
/// a caller-supplied principal. The service must check Use grant, workspace/data
/// scope, resolved immutable environment and capacity before first acceptance.
#[derive(Debug, Clone)]
pub struct AcceptanceContext {
    pub authenticated_principal: String,
    pub provider: String,
    pub environment_evidence: EnvironmentRequirement,
    pub capacity_reservation_id: String,
    pub now_unix: u64,
    pub prepare_deadline_unix: u64,
    pub delivery_deadline_unix: u64,
}
/// Provider acceptance owner. Backend transactions serialize every owner sharing
/// the store. N3-1 only accepts immutable Waiting records; it cannot spawn work.
pub struct TaskOwner<S> {
    pub(crate) store: S,
    pub(crate) hash: DigestFn,
    next_id: fn() -> Result<TaskId, TaskError>,
}
impl<S: TaskAcceptanceStore> TaskOwner<S> {
    pub fn new(store: S, hash: DigestFn, next_id: fn() -> Result<TaskId, TaskError>) -> Self {
        Self {
            store,
            hash,
            next_id,
        }
    }
    /// Accept after the service has authenticated and authorized the operation.
    /// Replays return the original contract, pin and TTL even if key TTL changes.
    pub fn accept_verified(
        &self,
        request: SubmitTaskRequest,
        context: AcceptanceContext,
    ) -> Result<AcceptanceResult, TaskError> {
        let request_digest = request.request_digest(self.hash)?;
        // Even a replay may not use an untrusted principal or another provider.
        if context.provider != request.provider
            || context.authenticated_principal.is_empty()
            || context.authenticated_principal.chars().count() > 256
            || context.authenticated_principal.contains('\0')
        {
            return Err(TaskError::new(
                TaskErrorCode::AuthDenied,
                "invalid authenticated acceptance context",
                false,
            ));
        }
        if context.now_unix > MAX_INTEGER {
            return Err(TaskError::invalid(
                "acceptance clock exceeds exact integer range",
            ));
        }
        let scope = IdempotencyScope {
            workspace: request.workspace.clone(),
            authenticated_principal: context.authenticated_principal.clone(),
            provider: request.provider.clone(),
            key: request.idempotency_key.clone(),
        };
        self.store.transact(&mut |ledger| {
            ledger.validate(self.hash)?;
            if let Some(entry) = ledger
                .idempotency
                .iter()
                .find(|e| e.scope == scope && context.now_unix < e.expires_at_unix)
            {
                if entry.request_digest != request_digest {
                    return Err(TaskError::new(
                        TaskErrorCode::IdempotencyConflict,
                        "active key already names a different request",
                        false,
                    ));
                }
                let task = ledger
                    .tasks
                    .iter()
                    .find(|t| t.view.task_id == entry.task_id)
                    .ok_or_else(|| {
                        TaskError::new(
                            TaskErrorCode::StateCorrupt,
                            "idempotency Task is absent",
                            false,
                        )
                    })?;
                return Ok(AcceptanceResult {
                    task: task.clone(),
                    replayed: true,
                });
            }
            let contract = AcceptedContract {
                request: request.clone(),
                request_digest: request_digest.clone(),
                authenticated_principal: context.authenticated_principal.clone(),
                environment_evidence: context.environment_evidence.clone(),
                capacity_reservation_id: context.capacity_reservation_id.clone(),
                accepted_at_unix: context.now_unix,
                idempotency_expires_at_unix: context
                    .now_unix
                    .checked_add(request.idempotency_ttl_seconds)
                    .ok_or_else(|| TaskError::invalid("expiry overflow"))?,
                prepare_deadline_unix: context.prepare_deadline_unix,
                delivery_deadline_unix: context.delivery_deadline_unix,
            };
            let digest = contract.contract_digest(self.hash)?;
            let task_id = (self.next_id)()?;
            if ledger.tasks.iter().any(|t| t.view.task_id == task_id) {
                return Err(TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    "TaskId collision",
                    false,
                ));
            }
            let task = AcceptedTask {
                input_pin_intent: request.input_snapshot.clone(),
                view: TaskView {
                    schema_version: 1,
                    task_id: task_id.clone(),
                    accepted_contract: contract.clone(),
                    contract_digest: digest,
                    phase: TaskPhase::Waiting,
                    outcome: TaskOutcome::Unfinished,
                    error: None,
                    execution: TaskExecution {
                        state: ExecutionState::NotStarted,
                        started_at_unix: None,
                        exit_code: None,
                        signal: None,
                        stop_reason: None,
                        result_confirmed: false,
                        workload_succeeded: None,
                    },
                    delivery: TaskDelivery {
                        state: DeliveryState::Pending,
                        error: None,
                    },
                    cancellation: TaskCancellation {
                        state: CancellationState::None,
                        reason: None,
                        requested_at_unix: None,
                    },
                    cancel_request: CancelRequestIntent {
                        origin: IntentOrigin::RequesterIntent,
                        state: CancelRequestState::None,
                        requested_at_unix: None,
                        reason: None,
                        error: None,
                    },
                    observation: Observation::Confirmed,
                    last_event_seq: 0,
                    session_ids: Vec::new(),
                    artifact_ids: Vec::new(),
                },
            };
            task.view.verify_digests(self.hash)?;
            ledger.idempotency.retain(|entry| entry.scope != scope);
            ledger.idempotency.push(IdempotencyEntry {
                scope: scope.clone(),
                task_id,
                request_digest: request_digest.clone(),
                expires_at_unix: contract.idempotency_expires_at_unix,
            });
            ledger.tasks.push(task.clone());
            ledger.validate(self.hash)?;
            Ok(AcceptanceResult {
                task,
                replayed: false,
            })
        })
    }
    /// Internal provider lookup. External show/logs must independently authorize.
    pub fn accepted(&self, id: &TaskId) -> Result<Option<AcceptedTask>, TaskError> {
        let ledger = self.store.read()?;
        ledger.validate(self.hash)?;
        Ok(ledger.tasks.into_iter().find(|t| &t.view.task_id == id))
    }
}

macro_rules! record_codec {
    ($name:ident {$($field:ident:$ty:ty),+}) => {
        impl CanonicalDto for $name {
            fn to_value(&self)->Value { Value::Object(BTreeMap::from([$( (stringify!($field).to_string(),self.$field.to_value()) ),+])) }
            fn from_value(v:Value)->Result<Self,TaskError> { let Value::Object(mut f)=v else { return Err(TaskError::invalid("expected acceptance object")); }; let r=Self { $( $field:<$ty>::from_value(f.remove(stringify!($field)).ok_or_else(||TaskError::invalid(concat!("missing ",stringify!($field))))?)? ),+ }; if !f.is_empty() { return Err(TaskError::invalid("unknown acceptance field")); } Ok(r) }
        }
    }
}
pub(crate) use record_codec;
record_codec!(AcceptedTask {
    view: TaskView,
    input_pin_intent: SnapshotRef
});
record_codec!(IdempotencyScope {
    workspace: String,
    authenticated_principal: String,
    provider: String,
    key: String
});
record_codec!(IdempotencyEntry {
    scope: IdempotencyScope,
    task_id: TaskId,
    request_digest: Sha256Digest,
    expires_at_unix: u64
});
record_codec!(AcceptanceLedger {schema_version:u64,tasks:Vec<AcceptedTask>,idempotency:Vec<IdempotencyEntry>});
