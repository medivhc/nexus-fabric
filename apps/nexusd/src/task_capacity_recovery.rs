//! Private capacity proofs. Only verified original executor and Snapshot
//! authority can turn a fresh owner epoch Ready or release runtime charges.
pub(crate) use crate::task_capacity::CapacityOwnerGuard;
use crate::{
    snapshot_store::FileSnapshotStore, task_capacity::CapacityAuthorityFingerprint,
    task_executor::LinuxTaskExecutor, task_store::FileTaskAcceptanceStore,
};
use nexus_domain::task::{Sha256Digest, TaskError, TaskErrorCode, TaskId};
use std::fs::File;

#[derive(Debug)]
pub(crate) struct CapacityReconcileProof {
    fingerprint: CapacityAuthorityFingerprint,
    // Hold every original execution lease through the Ready publication.
    _leases: Vec<File>,
}
impl CapacityReconcileProof {
    pub(crate) fn fingerprint(&self) -> &CapacityAuthorityFingerprint {
        &self.fingerprint
    }
}

#[derive(Debug)]
pub(crate) struct CapacityRuntimeReleaseProof {
    fingerprint: CapacityAuthorityFingerprint,
    task_id: TaskId,
    contract_digest: Sha256Digest,
    event_sequence: u64,
    preparation_reaped: bool,
    // A dup retains the very same open-file-description lease. No new owner
    // can alter original execution evidence before the transaction consumes it.
    _lease: Option<File>,
}
impl CapacityRuntimeReleaseProof {
    pub(crate) fn fingerprint(&self) -> &CapacityAuthorityFingerprint {
        &self.fingerprint
    }
    pub(crate) fn task_id(&self) -> &TaskId {
        &self.task_id
    }
    pub(crate) fn contract_digest(&self) -> &Sha256Digest {
        &self.contract_digest
    }
    pub(crate) fn event_sequence(&self) -> u64 {
        self.event_sequence
    }
    pub(crate) fn preparation_reaped(&self) -> bool {
        self.preparation_reaped
    }
}

pub(crate) fn begin_capacity_owner_recovery(
    store: &FileTaskAcceptanceStore,
) -> Result<Option<CapacityOwnerGuard>, TaskError> {
    if !has_capacity_policy(store)? {
        return Ok(None);
    }
    store.begin_capacity_reconciliation().map(Some)
}

/// Unknown execution retains its charges and Pending epoch. Read-only service
/// queries can still use intact records; admission, preparation and GC refuse.
pub(crate) fn finish_capacity_owner_recovery(
    store: &FileTaskAcceptanceStore,
    executor: &LinuxTaskExecutor,
    guard: Option<&CapacityOwnerGuard>,
) -> Result<(), TaskError> {
    let Some(guard) = guard else { return Ok(()) };
    if executor.capacity_store()?.capacity_root() != guard.root()
        || store.capacity_root() != guard.root()
    {
        return Err(TaskError::new(
            TaskErrorCode::StateCorrupt,
            "capacity recovery executor belongs to another authority root",
            false,
        ));
    }
    let snapshots = FileSnapshotStore::open(guard.root())?;
    let initial = store.capacity_authority_fingerprint()?;
    snapshots.verify_recovery_roots()?;
    let witnesses = match executor.capacity_recovery_witnesses() {
        Ok(witnesses) => witnesses,
        Err(error) if error.code == TaskErrorCode::CapacityUnavailable => return Ok(()),
        Err(error) => return Err(error),
    };
    if store.capacity_authority_fingerprint()? != initial {
        return Ok(());
    }
    let mut leases = Vec::new();
    for witness in witnesses {
        let preparation_reaped = witness.preparation_reaped();
        let (state, lease, releasable) = witness.into_parts();
        if releasable {
            let proof = CapacityRuntimeReleaseProof {
                fingerprint: store.capacity_authority_fingerprint()?,
                task_id: state.view.task_id,
                contract_digest: state.view.contract_digest,
                event_sequence: state.view.last_event_seq,
                preparation_reaped,
                _lease: lease
                    .as_ref()
                    .map(File::try_clone)
                    .transpose()
                    .map_err(io)?,
            };
            store.release_capacity_runtime(&proof)?;
        }
        if let Some(lease) = lease {
            leases.push(lease);
        }
    }
    // Recheck every retained/staged/accepted root after our own release writes.
    // Any concurrent authority mutation requires another reconciliation pass.
    let fingerprint = store.capacity_authority_fingerprint()?;
    snapshots.verify_recovery_roots()?;
    if store.capacity_authority_fingerprint()? != fingerprint {
        return Ok(());
    }
    store.finish_capacity_reconciliation(
        guard,
        &CapacityReconcileProof {
            fingerprint,
            _leases: leases,
        },
    )
}

/// The executor's synchronous owner has already stopped/reaped; re-read and
/// bind its durable proofs while keeping its original lease through release.
pub(crate) fn release_capacity_from_executor(
    executor: &LinuxTaskExecutor,
    task_id: &TaskId,
    lease: Option<&File>,
) -> Result<(), TaskError> {
    let store = executor.capacity_store()?;
    if !has_capacity_policy(&store)? {
        return Ok(());
    }
    let fingerprint = store.capacity_authority_fingerprint()?;
    let witness = executor.capacity_release_witness(task_id, lease)?;
    let preparation_reaped = witness.preparation_reaped();
    let (state, lease, releasable) = witness.into_parts();
    if !releasable {
        return Err(TaskError::new(
            TaskErrorCode::CapacityUnavailable,
            "original execution has no verified release evidence",
            true,
        ));
    }
    store.release_capacity_runtime(&CapacityRuntimeReleaseProof {
        fingerprint,
        task_id: state.view.task_id,
        contract_digest: state.view.contract_digest,
        event_sequence: state.view.last_event_seq,
        preparation_reaped,
        _lease: lease,
    })
}

fn io(error: std::io::Error) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}

fn has_capacity_policy(store: &FileTaskAcceptanceStore) -> Result<bool, TaskError> {
    match store.capacity_policy() {
        Ok(_) => Ok(true),
        Err(error) if error.code == TaskErrorCode::UnsupportedCapability => Ok(false),
        Err(error) => Err(error),
    }
}
