//! Provider allocation accounting. These budgets are operator policy, not host statistics.
pub(crate) use crate::task_capacity_recovery::{
    CapacityReconcileProof, CapacityRuntimeReleaseProof,
};
use crate::task_store::FileTaskAcceptanceStore;
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_compute::task::{AcceptanceLedger, AcceptedTask};
use nexus_domain::task::{
    codec::{CanonicalDto, Value},
    *,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(crate) const CAPACITY_AUTHORITY_RECEIPT: &[u8] =
    b"n3-acceptance-initialized-v1\nruntime-v1-required\ncapacity-v1-required\n";
pub(crate) const CAPACITY_ARTIFACT_AUTHORITY_RECEIPT: &[u8] = b"n3-acceptance-initialized-v1\nruntime-v1-required\nartifacts-v1-required\ncapacity-v1-required\n";
const RECEIPT: &str = "capacity-initialized-v1";
const RECEIPT_BYTES: &[u8] = b"n3-capacity-initialized-v1\n";
const OWNER: &str = "capacity-owner.lock";
const ARCHIVE_BYTES: u64 = 80 * 1024 * 1024;

macro_rules! codec {
    ($t:ident {$($f:ident:$ty:ty),+}) => {
        impl CanonicalDto for $t {
            fn to_value(&self)->Value { Value::Object(BTreeMap::from([$( (stringify!($f).into(),self.$f.to_value()) ),+])) }
            fn from_value(v:Value)->Result<Self,TaskError> { let Value::Object(mut fields)=v else { return Err(corrupt("invalid capacity object")); }; let result=Self { $( $f:<$ty>::from_value(fields.remove(stringify!($f)).ok_or_else(||corrupt(concat!("missing capacity ",stringify!($f))))?)? ),+ }; if !fields.is_empty() { return Err(corrupt("unknown capacity field")); } Ok(result) }
        }
    }
}

/// Configured allocation dimensions. Runtime storage is tmpfs; backend disk is retained IO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityBudget {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub runtime_storage_bytes: u64,
    pub backend_disk_bytes: u64,
    pub slots: u64,
}
codec!(CapacityBudget {
    cpu_millis: u64,
    memory_bytes: u64,
    pids: u64,
    runtime_storage_bytes: u64,
    backend_disk_bytes: u64,
    slots: u64
});
/// Additional bounded per-task executor costs, beyond the accounted archive and copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorBackendOverhead {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub backend_disk_bytes: u64,
}
codec!(ExecutorBackendOverhead {
    cpu_millis: u64,
    memory_bytes: u64,
    pids: u64,
    backend_disk_bytes: u64
});
/// Explicit operator allocation; immutable for the lifetime of a provisioned pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCapacityPolicy {
    pub total: CapacityBudget,
    pub fixed: CapacityBudget,
    pub overhead: ExecutorBackendOverhead,
}
codec!(ProviderCapacityPolicy {
    total: CapacityBudget,
    fixed: CapacityBudget,
    overhead: ExecutorBackendOverhead
});
impl CapacityBudget {
    fn values(&self) -> [u64; 6] {
        [
            self.cpu_millis,
            self.memory_bytes,
            self.pids,
            self.runtime_storage_bytes,
            self.backend_disk_bytes,
            self.slots,
        ]
    }
    fn add(&self, other: &Self) -> Result<Self, TaskError> {
        Ok(Self {
            cpu_millis: sum(&[self.cpu_millis, other.cpu_millis])?,
            memory_bytes: sum(&[self.memory_bytes, other.memory_bytes])?,
            pids: sum(&[self.pids, other.pids])?,
            runtime_storage_bytes: sum(&[self.runtime_storage_bytes, other.runtime_storage_bytes])?,
            backend_disk_bytes: sum(&[self.backend_disk_bytes, other.backend_disk_bytes])?,
            slots: sum(&[self.slots, other.slots])?,
        })
    }
    fn fits(&self, total: &Self) -> bool {
        self.values()
            .iter()
            .zip(total.values())
            .all(|(a, b)| *a <= b)
    }
}
impl ProviderCapacityPolicy {
    pub fn validate(&self) -> Result<(), TaskError> {
        if self
            .total
            .values()
            .into_iter()
            .chain(self.fixed.values())
            .chain([
                self.overhead.cpu_millis,
                self.overhead.memory_bytes,
                self.overhead.pids,
                self.overhead.backend_disk_bytes,
            ])
            .any(|v| v == 0 || v > MAX_INTEGER)
            || !self.fixed.fits(&self.total)
        {
            return Err(TaskError::invalid(
                "capacity allocations, fixed reserve and executor overhead must be positive exact integers within total budget",
            ));
        }
        Ok(())
    }
    fn demand(&self, contract: &AcceptedContract) -> Result<CapacityBudget, TaskError> {
        let request = &contract.request;
        let input = request.input_snapshot.total_bytes;
        if request.input_snapshot.file_count > 65536
            || input > request.limits.storage_bytes
            || request.limits.storage_bytes > 64 * 1024 * 1024
        {
            return Err(TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "input or writable storage exceeds bounded executor capacity",
                false,
            ));
        }
        let metadata = sum(&[
            // Paths allow 4096 Unicode scalars (up to 16 KiB UTF-8), plus
            // inventories/manifests and allocator growth. Do not count characters as bytes.
            mul(request.input_snapshot.file_count, 64 * 1024)?,
            mul(request.outputs.len() as u64, 64 * 1024)?,
            mul(request.to_value().canonical_bytes().len() as u64, 4)?,
            256 * 1024,
        ])?;
        Ok(CapacityBudget {
            cpu_millis: sum(&[request.limits.cpu_millis, self.overhead.cpu_millis])?,
            memory_bytes: sum(&[
                request.limits.memory_bytes,
                self.overhead.memory_bytes,
                mul(ARCHIVE_BYTES, 2)?,
                mul(input, 2)?,
                metadata,
                4 * 1024 * 1024,
            ])?,
            pids: sum(&[256, self.overhead.pids])?,
            runtime_storage_bytes: request.limits.storage_bytes,
            backend_disk_bytes: sum(&[
                self.overhead.backend_disk_bytes,
                mul(input, 3)?,
                mul(ARCHIVE_BYTES, 2)?,
                mul(request.limits.storage_bytes, 2)?,
                mul(request.limits.log_bytes, 2)?,
                mul(metadata, 2)?,
            ])?,
            slots: 1,
        })
    }
}
fn sum(values: &[u64]) -> Result<u64, TaskError> {
    values.iter().try_fold(0u64, |n, v| {
        n.checked_add(*v)
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or_else(|| TaskError::invalid("capacity arithmetic exceeds exact integer range"))
    })
}
fn mul(a: u64, b: u64) -> Result<u64, TaskError> {
    a.checked_mul(b)
        .filter(|n| *n <= MAX_INTEGER)
        .ok_or_else(|| TaskError::invalid("capacity multiplication exceeds exact integer range"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerBinding {
    epoch: u64,
    device: u64,
    inode: u64,
}
codec!(OwnerBinding {
    epoch: u64,
    device: u64,
    inode: u64
});
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reservation {
    id: String,
    task_id: TaskId,
    contract_digest: Sha256Digest,
    demand: CapacityBudget,
    runtime_held: bool,
}
codec!(Reservation {
    id: String,
    task_id: TaskId,
    contract_digest: Sha256Digest,
    demand: CapacityBudget,
    runtime_held: bool
});
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapacityImage {
    schema_version: u64,
    policy: ProviderCapacityPolicy,
    policy_digest: Sha256Digest,
    epoch: u64,
    ready: bool,
    owner: Option<OwnerBinding>,
    reservations: Vec<Reservation>,
}
codec!(CapacityImage {schema_version:u64,policy:ProviderCapacityPolicy,policy_digest:Sha256Digest,epoch:u64,ready:bool,owner:Option<OwnerBinding>,reservations:Vec<Reservation>});
impl CapacityImage {
    pub(crate) fn validate(&self, ledger: &AcceptanceLedger) -> Result<(), TaskError> {
        let check = || {
            self.policy.validate()?;
            if self.schema_version != 1
                || self.epoch > MAX_INTEGER
                || self.policy_digest != sha256(&self.policy.to_value().canonical_bytes())
                || self.reservations.len() != ledger.tasks.len()
                || self.owner.is_none()
                || (self.ready && self.epoch == 0)
                || self.owner.as_ref().is_some_and(|o| {
                    o.epoch != self.epoch || o.device > MAX_INTEGER || o.inode > MAX_INTEGER
                })
            {
                return Err(corrupt("invalid capacity policy/version/owner/task count"));
            }
            let mut ids = BTreeSet::new();
            let mut tasks = BTreeSet::new();
            for reservation in &self.reservations {
                let task = ledger
                    .tasks
                    .iter()
                    .find(|t| t.view.task_id == reservation.task_id)
                    .ok_or_else(|| corrupt("capacity reservation has no Task"))?;
                if !ids.insert(&reservation.id)
                    || !tasks.insert(&reservation.task_id)
                    || reservation.id != task.view.accepted_contract.capacity_reservation_id
                    || reservation.contract_digest != task.view.contract_digest
                    || reservation.demand != self.policy.demand(&task.view.accepted_contract)?
                {
                    return Err(corrupt("capacity reservation identity/demand mismatch"));
                }
            }
            if !self.used()?.fits(&self.policy.total) {
                return Err(corrupt("retained capacity claims exceed policy"));
            }
            Ok(())
        };
        check().map_err(|e: TaskError| corrupt(e.to_string()))
    }
    fn used(&self) -> Result<CapacityBudget, TaskError> {
        self.reservations
            .iter()
            .try_fold(self.policy.fixed.clone(), |used, r| {
                let mut demand = r.demand.clone();
                if !r.runtime_held {
                    demand.cpu_millis = 0;
                    demand.memory_bytes = 0;
                    demand.pids = 0;
                    demand.runtime_storage_bytes = 0;
                    demand.slots = 0;
                }
                used.add(&demand)
            })
    }
    pub(crate) fn attach(
        &mut self,
        root: &Path,
        ledger: &AcceptanceLedger,
        task: &AcceptedTask,
    ) -> Result<(), TaskError> {
        self.require_ready(root, ledger)?;
        let contract = &task.view.accepted_contract;
        if self
            .reservations
            .iter()
            .any(|r| r.id == contract.capacity_reservation_id || r.task_id == task.view.task_id)
        {
            return Err(corrupt("capacity reservation ID cannot be reused"));
        }
        let demand = self.policy.demand(contract)?;
        if !self.used()?.add(&demand)?.fits(&self.policy.total) {
            return Err(unavailable("configured provider capacity exhausted"));
        }
        self.reservations.push(Reservation {
            id: contract.capacity_reservation_id.clone(),
            task_id: task.view.task_id.clone(),
            contract_digest: task.view.contract_digest.clone(),
            demand,
            runtime_held: true,
        });
        Ok(())
    }
    pub(crate) fn require_ready(
        &self,
        root: &Path,
        ledger: &AcceptanceLedger,
    ) -> Result<(), TaskError> {
        if !self.ready {
            return Err(unavailable("capacity reconciliation is Pending"));
        }
        let owner = self
            .owner
            .as_ref()
            .ok_or_else(|| corrupt("Ready capacity has no owner binding"))?;
        let file = owner_file(root, false)?;
        check_binding(root, &file, owner)?;
        match try_exclusive(&file)? {
            true => Err(unavailable("capacity owner lease is no longer live")),
            false => self.require_known_runtime(root, ledger),
        }
    }
    pub(crate) fn verify_start(
        &self,
        root: &Path,
        ledger: &AcceptanceLedger,
        contract: &AcceptedContract,
    ) -> Result<(), TaskError> {
        self.require_ready(root, ledger)?;
        let reservation = self
            .reservations
            .iter()
            .find(|r| r.id == contract.capacity_reservation_id)
            .ok_or_else(|| corrupt("accepted capacity reservation is missing"))?;
        if reservation.contract_digest != contract.contract_digest(sha256)?
            || reservation.demand != self.policy.demand(contract)?
        {
            return Err(corrupt("start reservation differs from accepted contract"));
        }
        if !reservation.runtime_held {
            return Err(unavailable("runtime capacity was released"));
        }
        Ok(())
    }
    fn require_known_runtime(
        &self,
        root: &Path,
        ledger: &AcceptanceLedger,
    ) -> Result<(), TaskError> {
        let runtime = crate::task_runtime_store::load_and_validate(root, ledger)?;
        for task in &ledger.tasks {
            let journal = runtime
                .journals
                .iter()
                .find(|j| j.task_id == task.view.task_id)
                .cloned()
                .unwrap_or_else(|| nexus_compute::task_runtime::RuntimeJournal::initial(task));
            let state = journal.replay(task, sha256)?;
            if state.view.observation == Observation::PendingVerification {
                return Err(unavailable(
                    "unknown original execution blocks capacity admission",
                ));
            }
            let held = self
                .reservations
                .iter()
                .any(|r| r.task_id == task.view.task_id && r.runtime_held);
            if !held {
                continue;
            }
            let parent = root.join("executions-v1");
            let directory =
                parent.join(&sha256(task.view.task_id.as_str().as_bytes()).as_str()[7..]);
            match fs::symlink_metadata(&directory) {
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && state.execution_handle.is_none()
                        && state.view.execution.state == ExecutionState::NotStarted =>
                {
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(corrupt("original execution authority is missing"));
                }
                Err(e) => return Err(io(e)),
                Ok(_) => {}
            }
            check_private_directory(&parent)?;
            check_private_directory(&directory)?;
            let path = directory.join("owner.lock");
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(0x20000 | 0x800)
                .open(&path)
                .map_err(|_| corrupt("original execution owner lock missing"))?;
            let owned = file.metadata().map_err(io)?;
            let current = fs::symlink_metadata(&path).map_err(io)?;
            if !owned.is_file()
                || owned.nlink() != 1
                || owned.permissions().mode() & 0o077 != 0
                || current.file_type().is_symlink()
                || current.dev() != owned.dev()
                || current.ino() != owned.ino()
            {
                return Err(corrupt("original execution owner lock was replaced"));
            }
            let binding = crate::artifact_fs::load(&directory.join("owner-lease-v1.json"))?;
            if binding.as_object().map(|m| m.len()) != Some(5)
                || binding["schema_version"] != 1
                || binding["task_id"] != task.view.task_id.as_str()
                || binding["contract_digest"] != task.view.contract_digest.as_str()
                || binding["device"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    != Some(owned.dev())
                || binding["inode"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    != Some(owned.ino())
            {
                return Err(corrupt(
                    "original execution lease binding differs from capacity Task",
                ));
            }
            if try_exclusive(&file)? {
                return Err(unavailable(
                    "orphan original execution must reconcile before capacity admission",
                ));
            }
        }
        Ok(())
    }
}

fn check_private_directory(path: &Path) -> Result<(), TaskError> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
        return Err(corrupt(
            "original execution directory must be private and real",
        ));
    }
    Ok(())
}

/// Process-owned capacity coordinator. Dropping this guard makes durable Ready unusable.
#[derive(Debug)]
pub(crate) struct CapacityOwnerGuard {
    root: PathBuf,
    file: File,
    binding: OwnerBinding,
}
impl CapacityOwnerGuard {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapacityAuthorityFingerprint {
    root: PathBuf,
    epoch: u64,
    acceptance: Sha256Digest,
    runtime: Sha256Digest,
    pins: Sha256Digest,
    capacity: Sha256Digest,
}

impl FileTaskAcceptanceStore {
    /// Explicit fresh-empty provisioning only. Query and legacy open never provision capacity.
    pub fn provision_capacity(
        root: &Path,
        policy: &ProviderCapacityPolicy,
    ) -> Result<Self, TaskError> {
        policy.validate()?;
        let store = Self::open_for_capacity_provision(root)?;
        let _lock = store.capacity_acceptance_lock()?;
        let (ledger, existing) = store.load_authority_for_provision()?;
        let runtime = crate::task_runtime_store::load_and_validate(store.capacity_root(), &ledger)?;
        if !ledger.tasks.is_empty()
            || !ledger.idempotency.is_empty()
            || !runtime.journals.is_empty()
        {
            return Err(corrupt(
                "capacity may only provision a fresh-empty provider",
            ));
        }
        for name in [
            "executions-v1",
            "content-sha256-v1",
            "artifact-content-sha256-v1",
            "artifacts-v1.json",
            "snapshot-roots-v1.json",
        ] {
            if fs::symlink_metadata(store.capacity_root().join(name)).is_ok() {
                return Err(corrupt(
                    "capacity provisioning refuses preexisting task content or Artifact authority",
                ));
            }
        }
        let owner = owner_file(store.capacity_root(), true)?;
        owner.sync_all().map_err(io)?;
        let metadata = owner.metadata().map_err(io)?;
        let image = match existing {
            Some(image)
                if image.policy == *policy
                    && image.reservations.is_empty()
                    && image.epoch == 0
                    && !image.ready =>
            {
                check_binding(
                    store.capacity_root(),
                    &owner,
                    image
                        .owner
                        .as_ref()
                        .ok_or_else(|| corrupt("initial owner binding missing"))?,
                )?;
                image
            }
            Some(_) => {
                return Err(corrupt(
                    "capacity policy cannot be replaced or pool reenrolled",
                ));
            }
            None => CapacityImage {
                schema_version: 1,
                policy: policy.clone(),
                policy_digest: sha256(&policy.to_value().canonical_bytes()),
                epoch: 0,
                ready: false,
                owner: Some(OwnerBinding {
                    epoch: 0,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                }),
                reservations: Vec::new(),
            },
        };
        store.publish_capacity_authority(&ledger, &image)?;
        atomic(store.capacity_root(), RECEIPT, RECEIPT_BYTES)?;
        atomic(
            store.capacity_root(),
            "acceptance-initialized-v1",
            CAPACITY_AUTHORITY_RECEIPT,
        )?;
        Ok(store)
    }
    /// This is concrete durable validation; an external callback cannot substitute an ID string.
    pub fn verify_capacity_for_start(&self, contract: &AcceptedContract) -> Result<(), TaskError> {
        self.with_capacity_start(contract, || Ok(()))
    }
    pub(crate) fn with_capacity_start<R>(
        &self,
        contract: &AcceptedContract,
        operation: impl FnOnce() -> Result<R, TaskError>,
    ) -> Result<R, TaskError> {
        let _lock = self.capacity_acceptance_lock()?;
        let (ledger, capacity) = self.load_capacity_authority()?;
        crate::task_runtime_store::load_and_validate(self.capacity_root(), &ledger)?;
        let image = capacity.ok_or_else(|| {
            unavailable("real execution requires explicitly provisioned capacity")
        })?;
        image.verify_start(self.capacity_root(), &ledger, contract)?;
        operation()
    }
    pub(crate) fn capacity_policy(&self) -> Result<ProviderCapacityPolicy, TaskError> {
        let _lock = self.capacity_acceptance_lock()?;
        let (_, capacity) = self.load_capacity_authority()?;
        Ok(capacity
            .ok_or_else(|| unsupported("provider capacity policy absent"))?
            .policy)
    }
    pub(crate) fn capacity_authority_fingerprint(
        &self,
    ) -> Result<CapacityAuthorityFingerprint, TaskError> {
        let _lock = self.capacity_acceptance_lock()?;
        fingerprint(self)
    }
    pub(crate) fn begin_capacity_reconciliation(&self) -> Result<CapacityOwnerGuard, TaskError> {
        let file = owner_file(self.capacity_root(), false)?;
        if !try_exclusive(&file)? {
            return Err(unavailable("capacity owner is already live"));
        }
        let _lock = self.capacity_acceptance_lock()?;
        let (ledger, capacity) = self.load_capacity_authority()?;
        let mut image = capacity.ok_or_else(|| unsupported("provider capacity policy absent"))?;
        // The prior binding remains authoritative even when its lease has died.
        if let Some(previous) = &image.owner {
            check_binding(self.capacity_root(), &file, previous)?;
        }
        let meta = file.metadata().map_err(io)?;
        image.epoch = sum(&[image.epoch, 1])?;
        image.ready = false;
        let binding = OwnerBinding {
            epoch: image.epoch,
            device: meta.dev(),
            inode: meta.ino(),
        };
        image.owner = Some(binding.clone());
        self.publish_capacity_authority(&ledger, &image)?;
        Ok(CapacityOwnerGuard {
            root: self.capacity_root().to_owned(),
            file,
            binding,
        })
    }
    pub(crate) fn finish_capacity_reconciliation(
        &self,
        guard: &CapacityOwnerGuard,
        proof: &CapacityReconcileProof,
    ) -> Result<(), TaskError> {
        let _lock = self.capacity_acceptance_lock()?;
        if fingerprint(self)? != *proof.fingerprint() {
            return Err(unavailable(
                "capacity authority changed during reconciliation",
            ));
        }
        let (ledger, capacity) = self.load_capacity_authority()?;
        let mut image = capacity.ok_or_else(|| unsupported("provider capacity policy absent"))?;
        if guard.root != self.capacity_root()
            || image.owner.as_ref() != Some(&guard.binding)
            || image.epoch != guard.binding.epoch
        {
            return Err(corrupt("capacity proof/owner epoch mismatch"));
        }
        check_binding(self.capacity_root(), &guard.file, &guard.binding)?;
        image.ready = true;
        self.publish_capacity_authority(&ledger, &image)
    }
    pub(crate) fn release_capacity_runtime(
        &self,
        proof: &CapacityRuntimeReleaseProof,
    ) -> Result<(), TaskError> {
        let _lock = self.capacity_acceptance_lock()?;
        let (ledger, capacity) = self.load_capacity_authority()?;
        let mut image = capacity.ok_or_else(|| unsupported("provider capacity policy absent"))?;
        let index = image
            .reservations
            .iter()
            .position(|r| &r.task_id == proof.task_id())
            .ok_or_else(|| corrupt("release Task reservation is absent"))?;
        if image.reservations[index].contract_digest != *proof.contract_digest() {
            return Err(corrupt("release proof contract mismatch"));
        }
        // A second release is a no-op, but never accepts a different Task/contract.
        if !image.reservations[index].runtime_held {
            return Ok(());
        }
        if fingerprint(self)? != *proof.fingerprint() {
            return Err(unavailable("capacity authority changed before release"));
        }
        let runtime = crate::task_runtime_store::load_and_validate(self.capacity_root(), &ledger)?;
        let task = ledger
            .tasks
            .iter()
            .find(|t| &t.view.task_id == proof.task_id())
            .ok_or_else(|| corrupt("release Task absent"))?;
        let journal = runtime
            .journals
            .iter()
            .find(|j| &j.task_id == proof.task_id())
            .cloned()
            .unwrap_or_else(|| nexus_compute::task_runtime::RuntimeJournal::initial(task));
        let state = journal.replay(task, sha256)?;
        if state.view.last_event_seq != proof.event_sequence()
            || state.view.observation != Observation::Confirmed
        {
            return Err(corrupt("release proof runtime changed or unverified"));
        }
        match state.view.execution.state {
            ExecutionState::NotStarted
                if state.view.phase == TaskPhase::Finished && state.execution_handle.is_none() =>
            {
                let directory = self
                    .capacity_root()
                    .join("executions-v1")
                    .join(&sha256(proof.task_id().as_str().as_bytes()).as_str()[7..]);
                match fs::symlink_metadata(&directory) {
                    Err(e)
                        if e.kind() == std::io::ErrorKind::NotFound
                            && !proof.preparation_reaped() => {}
                    Ok(_) if proof.preparation_reaped() => {}
                    Ok(_) => {
                        return Err(unavailable(
                            "preparation execution authority exists; capacity remains held",
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(corrupt("reaped preparation authority is missing"));
                    }
                    Err(e) => return Err(io(e)),
                }
            }
            ExecutionState::Exited | ExecutionState::Stopped => {}
            _ => {
                return Err(unavailable(
                    "unconfirmed execution cannot release runtime capacity",
                ));
            }
        }
        image.reservations[index].runtime_held = false;
        self.publish_capacity_authority(&ledger, &image)
    }
    pub(crate) fn with_gc_locked_ledger<R>(
        &self,
        operation: impl FnOnce(&Path, &AcceptanceLedger) -> Result<R, TaskError>,
    ) -> Result<R, TaskError> {
        let _lock = self.capacity_acceptance_lock()?;
        let (ledger, capacity) = self.load_capacity_authority()?;
        crate::task_runtime_store::load_and_validate(self.capacity_root(), &ledger)?;
        if let Some(image) = capacity {
            image.require_ready(self.capacity_root(), &ledger)?;
        }
        operation(self.capacity_root(), &ledger)
    }
}
fn fingerprint(store: &FileTaskAcceptanceStore) -> Result<CapacityAuthorityFingerprint, TaskError> {
    let (ledger, capacity) = store.load_capacity_authority()?;
    let image = capacity.ok_or_else(|| unsupported("provider capacity policy absent"))?;
    let runtime = crate::task_runtime_store::load_and_validate(store.capacity_root(), &ledger)?;
    // Pin intent is immutable in the acceptance ledger. Actual roots/content are independently verified by recovery.
    let catalog = private_read(&store.capacity_root().join("snapshot-roots-v1.json"))?;
    let pins = Value::Array(vec![
        Value::Array(
            ledger
                .tasks
                .iter()
                .map(|t| t.input_pin_intent.to_value())
                .collect(),
        ),
        catalog.map(|bytes| sha256(&bytes)).to_value(),
    ]);
    Ok(CapacityAuthorityFingerprint {
        root: store.capacity_root().to_owned(),
        epoch: image.epoch,
        acceptance: sha256(&ledger.to_value().canonical_bytes()),
        runtime: sha256(&runtime.to_value().canonical_bytes()),
        pins: sha256(&pins.canonical_bytes()),
        capacity: sha256(&image.to_value().canonical_bytes()),
    })
}
pub(crate) fn check_receipt(
    root: &Path,
    capacity: bool,
    allow_incomplete: bool,
) -> Result<(), TaskError> {
    let authority = private_read(&root.join("acceptance-initialized-v1"))?;
    let required = authority.as_deref() == Some(CAPACITY_AUTHORITY_RECEIPT)
        || authority.as_deref() == Some(CAPACITY_ARTIFACT_AUTHORITY_RECEIPT);
    let receipt = private_read(&root.join(RECEIPT))?;
    let owner_exists = fs::symlink_metadata(root.join(OWNER)).is_ok();
    if receipt.as_deref().is_some_and(|r| r != RECEIPT_BYTES)
        || (!capacity && (required || receipt.is_some() || (!allow_incomplete && owner_exists)))
        || (capacity && !allow_incomplete && (!required || receipt.is_none()))
    {
        return Err(corrupt(
            "capacity required receipt/image missing or downgraded",
        ));
    }
    Ok(())
}
pub(crate) fn is_capacity_receipt(bytes: &[u8]) -> bool {
    bytes == CAPACITY_AUTHORITY_RECEIPT || bytes == CAPACITY_ARTIFACT_AUTHORITY_RECEIPT
}
pub(crate) fn verify_action(
    root: &Path,
    ledger: &AcceptanceLedger,
    id: &TaskId,
) -> Result<(), TaskError> {
    // Caller already owns acceptance.lock; this helper must never relock.
    let store = FileTaskAcceptanceStore::capacity_handle(root);
    let (_, capacity) = store.load_capacity_authority()?;
    if let Some(image) = capacity {
        let task = ledger
            .tasks
            .iter()
            .find(|t| &t.view.task_id == id)
            .ok_or_else(|| corrupt("start Task missing"))?;
        image.verify_start(root, ledger, &task.view.accepted_contract)?;
    }
    Ok(())
}
fn owner_file(root: &Path, create: bool) -> Result<File, TaskError> {
    let path = root.join(OWNER);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(0x20000 | 0x800)
        .open(&path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                corrupt("capacity owner lock missing")
            } else {
                io(e)
            }
        })?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(corrupt(
            "capacity owner lock must be private regular fixed inode",
        ));
    }
    Ok(file)
}
fn check_binding(root: &Path, file: &File, binding: &OwnerBinding) -> Result<(), TaskError> {
    let meta = file.metadata().map_err(io)?;
    let path = fs::symlink_metadata(root.join(OWNER)).map_err(io)?;
    if !path.is_file()
        || path.file_type().is_symlink()
        || path.nlink() != 1
        || meta.nlink() != 1
        || path.permissions().mode() & 0o077 != 0
        || path.dev() != meta.dev()
        || path.ino() != meta.ino()
        || meta.dev() != binding.device
        || meta.ino() != binding.inode
    {
        return Err(corrupt("capacity owner lock identity was replaced"));
    }
    Ok(())
}
fn try_exclusive(file: &File) -> Result<bool, TaskError> {
    crate::task_store::lock_fd(file, true)
}
fn private_read(path: &Path) -> Result<Option<Vec<u8>>, TaskError> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(corrupt("capacity receipt must be private regular file"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(Some(bytes))
}
fn atomic(root: &Path, name: &str, bytes: &[u8]) -> Result<(), TaskError> {
    let tmp = root.join(format!(".capacity-{}.tmp", new_task_id()?.as_str()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    fs::rename(&tmp, root.join(name)).map_err(io)?;
    File::open(root).and_then(|f| f.sync_all()).map_err(io)
}
fn corrupt(message: impl Into<String>) -> TaskError {
    TaskError::new(TaskErrorCode::StateCorrupt, message, false)
}
fn unavailable(message: impl Into<String>) -> TaskError {
    TaskError::new(TaskErrorCode::CapacityUnavailable, message, true)
}
fn unsupported(message: impl Into<String>) -> TaskError {
    TaskError::new(TaskErrorCode::UnsupportedCapability, message, false)
}
fn io(error: std::io::Error) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}

#[cfg(test)]
#[path = "task_capacity_tests.rs"]
mod tests;
