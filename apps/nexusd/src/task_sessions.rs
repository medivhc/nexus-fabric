//! Trusted composition bridge to the original resource Session owner.
//! Task journal links and cleanup intents never assign either owner's outcome.
use crate::{
    artifact_fs as disk, task_service::SharedSessionManager, task_store::FileTaskAcceptanceStore,
};
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_compute::{
    task::{TaskAcceptanceStore, TaskOwner},
    task_runtime::{RuntimeAction, RuntimeEvent, RuntimeState},
};
use nexus_domain::{
    LifecyclePhase, SessionId, TerminalOutcome, plan_id_of,
    task::{CancellationState, TaskError, TaskErrorCode, TaskId, TaskOutcome},
};
use nexus_session::{SessionManager, SessionRecordStore};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const INTENTS: &str = "intents-v1.json";
const RECEIPT: &[u8] = b"n3-session-bridge-v1\n";

pub(crate) struct TaskSessionBridge {
    config_root: PathBuf,
    store: FileTaskAcceptanceStore,
    sessions: SharedSessionManager,
    cleanup: CleanupStore,
}
impl TaskSessionBridge {
    pub(crate) fn open(
        config_root: &Path,
        store: FileTaskAcceptanceStore,
        sessions: SharedSessionManager,
    ) -> Result<Self, TaskError> {
        let owner = TaskOwner::new(store.clone(), sha256, new_task_id);
        let mut has_bindings = false;
        for task in store.read()?.tasks {
            has_bindings |= !owner
                .runtime(&task.view.task_id)?
                .view
                .session_ids
                .is_empty();
        }
        let cleanup = CleanupStore::open(&config_root.join("data/n3/tasks"), !has_bindings)?;
        let bridge = Self {
            config_root: config_root.to_owned(),
            store,
            sessions,
            cleanup,
        };
        bridge.with_manager(|_| Ok(()))?;
        Ok(bridge)
    }

    fn with_manager<T>(
        &self,
        operation: impl FnOnce(&mut SessionManager) -> Result<T, TaskError>,
    ) -> Result<T, TaskError> {
        let mut guard = self
            .sessions
            .lock()
            .map_err(|_| unavailable("resource Session owner lock is poisoned"))?;
        let manager = guard
            .as_mut()
            .ok_or_else(|| unavailable("resource Session owner is unavailable"))?;
        operation(manager)
    }

    /// Serialized across independent composition processes; no Session is created.
    pub(crate) fn bind_existing(
        &self,
        owner: &TaskOwner<FileTaskAcceptanceStore>,
        id: &TaskId,
        session: &SessionId,
    ) -> Result<RuntimeState, TaskError> {
        TaskId::new(session.0.clone())?;
        let _lease = self.cleanup.lock()?;
        let state = owner.runtime(id)?;
        self.check_exclusive(owner, id, session)?;
        if state.view.session_ids.contains(&session.0) {
            self.with_manager(|manager| self.verify_session(manager, &state, session, false))?;
            return Ok(state);
        }
        if state.view.outcome != TaskOutcome::Unfinished {
            return Err(TaskError::invalid(
                "terminal Task cannot acquire a resource Session",
            ));
        }
        self.store
            .verify_capacity_for_start(&state.view.accepted_contract)?;
        self.with_manager(|manager| {
            self.verify_session(manager, &state, session, true)?;
            // Keep the resource owner locked until its verified identity is linked.
            for _ in 0..16 {
                let current = owner.runtime(id)?;
                if current.view.session_ids.contains(&session.0) {
                    return Ok(current);
                }
                let sequence = current
                    .view
                    .last_event_seq
                    .checked_add(1)
                    .ok_or_else(|| disk::corrupt("Task event sequence overflow"))?;
                match owner.record_event(
                    id,
                    RuntimeEvent {
                        sequence,
                        action: RuntimeAction::SessionAttached {
                            session_id: session.0.clone(),
                        },
                    },
                ) {
                    Ok(update) => return Ok(update.state),
                    Err(error)
                        if error.code == TaskErrorCode::InvalidRequest
                            && owner.runtime(id)?.view.last_event_seq
                                != current.view.last_event_seq => {}
                    Err(error) => return Err(error),
                }
            }
            Err(disk::io(std::io::Error::other(
                "Task changed repeatedly during Session binding",
            )))
        })
    }

    fn check_exclusive(
        &self,
        owner: &TaskOwner<FileTaskAcceptanceStore>,
        id: &TaskId,
        session: &SessionId,
    ) -> Result<(), TaskError> {
        for accepted in self.store.read()?.tasks {
            if &accepted.view.task_id != id
                && owner
                    .runtime(&accepted.view.task_id)?
                    .view
                    .session_ids
                    .contains(&session.0)
            {
                return Err(TaskError::invalid(
                    "resource Session is already attached to another Task",
                ));
            }
        }
        Ok(())
    }

    fn verify_session(
        &self,
        manager: &SessionManager,
        state: &RuntimeState,
        session: &SessionId,
        active: bool,
    ) -> Result<(), TaskError> {
        let view = manager
            .get(session)
            .ok_or_else(|| disk::corrupt("bound resource Session is missing from its owner"))?;
        let snapshot = view
            .plan_snapshot
            .as_ref()
            .ok_or_else(|| disk::corrupt("resource Session has no historical Plan"))?;
        let request = &state.view.accepted_contract.request;
        if snapshot.plan_id != plan_id_of(&snapshot.plan, &snapshot.decision_trace)
            || snapshot.plan.provider_id.0 != request.provider
            || snapshot.decision_trace.selected != snapshot.plan.provider_id
            || view.provider != snapshot.plan.provider_id
            || view.resource != snapshot.plan.resource_id
            || !snapshot.decision_trace.considered.iter().any(|candidate| {
                candidate.provider == snapshot.plan.provider_id
                    && candidate.rejected_reason.is_none()
            })
        {
            return Err(disk::corrupt(
                "resource Session Plan or selected provider differs from accepted Task",
            ));
        }
        let n2 = nexus::n2_store::N2Store::open(&self.config_root).map_err(store_error)?;
        let names = n2.load_names().map_err(store_error)?;
        let mut matched = names.iter().filter(|entry| {
            entry.workspace.0 == request.workspace && entry.name.as_str() == request.resource
        });
        if matched.next().map(|entry| &entry.resource_id) != Some(&snapshot.plan.resource_id)
            || matched.next().is_some()
        {
            return Err(disk::corrupt(
                "explicit Workspace/resource name does not identify the Session Plan resource",
            ));
        }
        let record = n2
            .sessions()
            .load()
            .map_err(store_error)?
            .into_iter()
            .find(|record| &record.session == session)
            .ok_or_else(|| disk::corrupt("resource Session has no same-root durable record"))?;
        if record.plan_snapshot.as_ref() != Some(snapshot)
            || record.phase != view.phase
            || record.outcome != view.outcome
        {
            return Err(disk::corrupt(
                "resource Session owner differs from its same-root durable record",
            ));
        }
        if active {
            if view.phase != LifecyclePhase::Active || view.outcome != TerminalOutcome::Unfinished {
                return Err(TaskError::invalid(
                    "new Task binding requires an Active/Unfinished Session",
                ));
            }
            if !n2.load_ads().map_err(store_error)?.iter().any(|ad| {
                ad.resource == snapshot.plan.resource_id && ad.provider == snapshot.plan.provider_id
            }) {
                return Err(disk::corrupt(
                    "accepted provider has no matching persisted N2 resource advertisement",
                ));
            }
        }
        Ok(())
    }

    /// Production boot consumer. Historical Session outcomes are inspected only.
    pub(crate) fn reconcile(
        &self,
        owner: &TaskOwner<FileTaskAcceptanceStore>,
    ) -> Result<(), TaskError> {
        let _lease = self.cleanup.lock()?;
        let mut bindings = BTreeMap::new();
        for accepted in self.store.read()?.tasks {
            let state = owner.runtime(&accepted.view.task_id)?;
            for session in &state.view.session_ids {
                if bindings
                    .insert(session.clone(), state.view.task_id.clone())
                    .is_some()
                {
                    return Err(disk::corrupt("resource Session is bound to multiple Tasks"));
                }
                self.with_manager(|manager| {
                    self.verify_session(manager, &state, &SessionId(session.clone()), false)
                })?;
            }
            self.close_confirmed_locked(owner, &state)?;
        }
        // Every outstanding intent must retain a matching confirmed Task binding.
        for intent in self.cleanup.read()? {
            let state = owner.runtime(&intent.task_id)?;
            intent.verify(&state)?;
            self.close_confirmed_locked(owner, &state)?;
        }
        Ok(())
    }

    pub(crate) fn close_confirmed(
        &self,
        owner: &TaskOwner<FileTaskAcceptanceStore>,
        state: &RuntimeState,
    ) -> Result<(), TaskError> {
        let _lease = self.cleanup.lock()?;
        self.close_confirmed_locked(owner, state)
    }

    fn close_confirmed_locked(
        &self,
        owner: &TaskOwner<FileTaskAcceptanceStore>,
        observed: &RuntimeState,
    ) -> Result<(), TaskError> {
        let state = owner.runtime(&observed.view.task_id)?;
        if !confirmed_cancel(&state) {
            return Ok(());
        }
        for id in &state.view.session_ids {
            let session = SessionId(id.clone());
            let intent = CleanupIntent {
                task_id: state.view.task_id.clone(),
                contract_digest: state.view.contract_digest.as_str().to_owned(),
                session_id: id.clone(),
            };
            let mut intents = self.cleanup.read()?;
            if let Some(existing) = intents.iter().find(|existing| existing.session_id == *id) {
                existing.verify(&state)?;
            } else {
                intents.push(intent.clone());
                self.cleanup.write(&intents)?;
            }
            self.with_manager(|manager| {
                // A failed previous save can leave an in-memory terminal outcome.
                // Reload the original owner before deciding whether to close again.
                manager
                    .load_from_store()
                    .map_err(|e| store_error(e.to_string()))?;
                self.verify_session(manager, &state, &session, false)?;
                let before = manager
                    .get(&session)
                    .ok_or_else(|| disk::corrupt("cleanup Session is missing"))?;
                if before.outcome == TerminalOutcome::Unfinished {
                    if let Err(error) = manager.close(&session, "confirmed Task cancellation") {
                        // Preserve intent even when the KV write may already have succeeded.
                        manager
                            .load_from_store()
                            .map_err(|e| store_error(e.to_string()))?;
                        return Err(store_error(error.to_string()));
                    }
                }
                let n2 = nexus::n2_store::N2Store::open(&self.config_root).map_err(store_error)?;
                let record = n2
                    .sessions()
                    .load()
                    .map_err(store_error)?
                    .into_iter()
                    .find(|record| record.session == session)
                    .ok_or_else(|| disk::corrupt("cleanup Session durable record is missing"))?;
                if record.phase != LifecyclePhase::Disposed
                    || record.outcome == TerminalOutcome::Unfinished
                {
                    return Err(disk::corrupt(
                        "resource cleanup lacks durable Disposed evidence",
                    ));
                }
                // Existing Completed/Failed/Cancelled stays exactly as recorded.
                Ok(())
            })?;
            let mut intents = self.cleanup.read()?;
            intents.retain(|existing| existing != &intent);
            self.cleanup.write(&intents)?;
        }
        Ok(())
    }
}

fn confirmed_cancel(state: &RuntimeState) -> bool {
    state.view.cancellation.state == CancellationState::Confirmed
        && state.view.outcome == TaskOutcome::Cancelled
}
fn unavailable(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::UnsupportedCapability, reason, false)
}
fn store_error(reason: String) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, reason, true)
}

#[derive(Clone, PartialEq, Eq)]
struct CleanupIntent {
    task_id: TaskId,
    contract_digest: String,
    session_id: String,
}
impl CleanupIntent {
    fn verify(&self, state: &RuntimeState) -> Result<(), TaskError> {
        if self.task_id != state.view.task_id
            || self.contract_digest != state.view.contract_digest.as_str()
            || !state.view.session_ids.contains(&self.session_id)
            || !confirmed_cancel(state)
        {
            return Err(disk::corrupt(
                "Session cleanup intent differs from confirmed Task authority",
            ));
        }
        Ok(())
    }
}

struct CleanupStore {
    root: PathBuf,
    device: u64,
    inode: u64,
}
impl CleanupStore {
    fn open(task_root: &Path, allow_new: bool) -> Result<Self, TaskError> {
        disk::check_directory(task_root)?;
        let root = task_root.join("session-cleanup-v1");
        if !allow_new && !root.try_exists().map_err(disk::io)? {
            return Err(disk::corrupt("Session cleanup authority was lost"));
        }
        let created = match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) if allow_new => {
                disk::sync(task_root)?;
                true
            }
            Ok(()) => {
                return Err(disk::corrupt("Session cleanup authority was lost"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(disk::io(error)),
        };
        disk::check_directory(&root)?;
        if created {
            let mut lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("lock"))
                .map_err(disk::io)?;
            if !crate::task_store::lock_fd(&lock, false)? {
                return Err(disk::corrupt(
                    "Session cleanup initialization lock unavailable",
                ));
            }
            lock.write_all(RECEIPT).map_err(disk::io)?;
            lock.sync_all().map_err(disk::io)?;
            disk::save(&root, INTENTS, &json!({"schema_version":1,"intents":[]}))?;
        }
        let metadata = fs::symlink_metadata(&root).map_err(disk::io)?;
        let store = Self {
            root,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let _lease = store.lock()?;
        store.read()?;
        Ok(store)
    }
    fn lock(&self) -> Result<File, TaskError> {
        let lock = disk::file(&self.root.join("lock"), true)?;
        if !crate::task_store::lock_fd(&lock, false)? {
            return Err(disk::corrupt("Session cleanup lock unavailable"));
        }
        disk::check_directory(&self.root)?;
        let root = fs::symlink_metadata(&self.root).map_err(disk::io)?;
        let actual = disk::file(&self.root.join("lock"), false)?
            .metadata()
            .map_err(disk::io)?;
        let held = lock.metadata().map_err(disk::io)?;
        if root.dev() != self.device
            || root.ino() != self.inode
            || actual.dev() != held.dev()
            || actual.ino() != held.ino()
            || disk::read(&self.root.join("lock"), 128)? != RECEIPT
        {
            return Err(disk::corrupt(
                "Session cleanup authority or stable lock changed",
            ));
        }
        Ok(lock)
    }
    fn read(&self) -> Result<Vec<CleanupIntent>, TaskError> {
        let value = disk::load(&self.root.join(INTENTS))?;
        if value.as_object().map(|fields| fields.len()) != Some(2) || value["schema_version"] != 1 {
            return Err(disk::corrupt("unknown Session cleanup authority schema"));
        }
        let mut identities = BTreeMap::new();
        value["intents"]
            .as_array()
            .ok_or_else(|| disk::corrupt("Session cleanup intents missing"))?
            .iter()
            .map(|value| {
                if value.as_object().map(|fields| fields.len()) != Some(3) {
                    return Err(disk::corrupt("unknown Session cleanup intent field"));
                }
                let text = |key: &str| {
                    value[key]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| disk::corrupt("Session cleanup intent field missing"))
                };
                let intent = CleanupIntent {
                    task_id: TaskId::new(text("task_id")?)
                        .map_err(|e| disk::corrupt(e.to_string()))?,
                    contract_digest: text("contract_digest")?,
                    session_id: text("session_id")?,
                };
                nexus_domain::task::Sha256Digest::parse(intent.contract_digest.clone())
                    .map_err(|e| disk::corrupt(e.to_string()))?;
                TaskId::new(intent.session_id.clone()).map_err(|e| disk::corrupt(e.to_string()))?;
                if identities.insert(intent.session_id.clone(), ()).is_some() {
                    return Err(disk::corrupt("duplicate Session cleanup intent"));
                }
                Ok(intent)
            })
            .collect()
    }
    fn write(&self, intents: &[CleanupIntent]) -> Result<(), TaskError> {
        let values: Vec<Value> = intents.iter().map(|intent| json!({"task_id":intent.task_id.as_str(),"contract_digest":intent.contract_digest,"session_id":intent.session_id})).collect();
        disk::save(
            &self.root,
            INTENTS,
            &json!({"schema_version":1,"intents":values}),
        )
    }
}
use std::os::unix::fs::DirBuilderExt;

#[cfg(test)]
#[path = "task_sessions_tests.rs"]
mod tests;
