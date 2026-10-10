use super::*;
use crate::{
    snapshot_store::FileSnapshotStore, task_capacity_recovery::finish_capacity_owner_recovery,
    task_executor::LinuxTaskExecutor,
};
use nexus_compute::{
    task::{AcceptanceContext, AcceptanceResult, TaskAcceptanceStore, TaskOwner},
    task_runtime::RuntimeAction,
};
use nexus_storage::InMemoryContentStore;
use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId, snapshot::SnapshotSelection};
use std::{
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nexus-capacity-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn policy() -> ProviderCapacityPolicy {
    ProviderCapacityPolicy {
        total: CapacityBudget {
            cpu_millis: 10000,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            pids: 2000,
            runtime_storage_bytes: 256 * 1024 * 1024,
            backend_disk_bytes: 2 * 1024 * 1024 * 1024,
            slots: 10,
        },
        fixed: CapacityBudget {
            cpu_millis: 100,
            memory_bytes: 16 * 1024 * 1024,
            pids: 4,
            runtime_storage_bytes: 4096,
            backend_disk_bytes: 16 * 1024 * 1024,
            slots: 1,
        },
        overhead: ExecutorBackendOverhead {
            cpu_millis: 10,
            memory_bytes: 8 * 1024 * 1024,
            pids: 2,
            backend_disk_bytes: 1024 * 1024,
        },
    }
}
struct Fixture {
    _dir: Dir,
    root: PathBuf,
    store: FileTaskAcceptanceStore,
    request: SubmitTaskRequest,
    guard: CapacityOwnerGuard,
}
impl Fixture {
    fn new(policy: ProviderCapacityPolicy) -> Self {
        let dir = Dir::new();
        let root = dir.0.join("provider");
        let store = FileTaskAcceptanceStore::provision_capacity(&root, &policy).unwrap();
        let snapshots = FileSnapshotStore::open(&root).unwrap();
        let mut workspace = Workspace::init(
            WorkspaceId("capacity-workspace".into()),
            InMemoryContentStore::new(),
            AuthorId("capacity-test".into()),
        )
        .unwrap();
        let base = workspace.heads().heads[0].clone();
        let commit = workspace
            .commit_changes(
                &base,
                &[Change {
                    path: "input.txt".into(),
                    content: b"fixed\n".to_vec(),
                }],
            )
            .unwrap();
        let frozen = snapshots
            .stage_snapshot(
                &workspace,
                &commit,
                &SnapshotSelection {
                    include: vec!["input.txt".into()],
                    exclude: vec![],
                    executable: vec![],
                },
            )
            .unwrap();
        let mut request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
            "../../../docs/contracts/n3-submit.example.json"
        ))
        .unwrap();
        request.workspace = frozen.reference.workspace.clone();
        request.input_snapshot = frozen.reference;
        request.idempotency_ttl_seconds = 10;
        request.limits = TaskLimits {
            timeout_seconds: 60,
            cpu_millis: 1000,
            memory_bytes: 64 * 1024 * 1024,
            storage_bytes: 1024 * 1024,
            log_bytes: 16384,
        };
        let guard = store.begin_capacity_reconciliation().unwrap();
        let executor = LinuxTaskExecutor::open(&root, Vec::new()).unwrap();
        finish_capacity_owner_recovery(&store, &executor, Some(&guard)).unwrap();
        store.with_gc_locked_ledger(|_, _| Ok(())).unwrap();
        Self {
            _dir: dir,
            root,
            store,
            request,
            guard,
        }
    }
    fn accept(
        &self,
        key: &str,
        reservation: &str,
        now: u64,
    ) -> Result<AcceptanceResult, TaskError> {
        accept(&self.root, self.request.clone(), key, reservation, now)
    }
    fn image(&self) -> CapacityImage {
        let _lock = self.store.capacity_acceptance_lock().unwrap();
        self.store.load_capacity_authority().unwrap().1.unwrap()
    }
}
fn accept(
    root: &Path,
    mut request: SubmitTaskRequest,
    key: &str,
    reservation: &str,
    now: u64,
) -> Result<AcceptanceResult, TaskError> {
    request.idempotency_key = key.into();
    let context = AcceptanceContext {
        authenticated_principal: "capacity-principal".into(),
        provider: request.provider.clone(),
        environment_evidence: request.environment.clone(),
        capacity_reservation_id: reservation.into(),
        now_unix: now,
        prepare_deadline_unix: now + 10,
        delivery_deadline_unix: now + 100,
    };
    TaskOwner::new(FileTaskAcceptanceStore::open(root)?, sha256, new_task_id)
        .accept_verified(request, context)
}

#[test]
fn exact_slot_budget_replay_pending_conflict_and_key_expiry() {
    let mut p = policy();
    p.total.slots = p.fixed.slots + 1;
    let f = Fixture::new(p);
    let first = f.accept("same", "reserved-once", 100).unwrap();
    let bytes = fs::read(f.root.join("acceptance-v1.json")).unwrap();
    assert_eq!(
        f.accept("other", "second", 101).unwrap_err().code,
        TaskErrorCode::CapacityUnavailable
    );
    let replay = f.accept("same", "unused-proposal", 101).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.task, first.task);
    assert_eq!(bytes, fs::read(f.root.join("acceptance-v1.json")).unwrap());
    let mut changed = f.request.clone();
    changed.command.push("changed".into());
    assert_eq!(
        accept(&f.root, changed, "same", "not-allocated", 101)
            .unwrap_err()
            .code,
        TaskErrorCode::IdempotencyConflict
    );
    assert_eq!(
        f.accept("same", "after-expiry", 110).unwrap_err().code,
        TaskErrorCode::CapacityUnavailable
    );
    drop(f.guard);
    let store = FileTaskAcceptanceStore::open(&f.root).unwrap();
    let next = store.begin_capacity_reconciliation().unwrap();
    assert!(
        accept(&f.root, f.request.clone(), "same", "unused", 102)
            .unwrap()
            .replayed
    );
    assert_eq!(
        accept(&f.root, f.request.clone(), "new", "new", 102)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    drop(next);
}

#[test]
fn each_policy_dimension_and_backend_overhead_is_enforced() {
    for dimension in 0..6 {
        let mut p = policy();
        match dimension {
            0 => p.total.cpu_millis = p.fixed.cpu_millis + p.overhead.cpu_millis,
            1 => p.total.memory_bytes = p.fixed.memory_bytes + 64 * 1024 * 1024,
            2 => p.total.pids = p.fixed.pids + 256,
            3 => p.total.runtime_storage_bytes = p.fixed.runtime_storage_bytes + 4096,
            4 => p.total.backend_disk_bytes = p.fixed.backend_disk_bytes + 80 * 1024 * 1024,
            _ => p.total.slots = p.fixed.slots,
        }
        let f = Fixture::new(p);
        let before = fs::read(f.root.join("acceptance-v1.json")).unwrap();
        assert_eq!(
            f.accept("exhausted", "no-allocation", 100)
                .unwrap_err()
                .code,
            TaskErrorCode::CapacityUnavailable,
            "dimension {dimension}"
        );
        assert_eq!(before, fs::read(f.root.join("acceptance-v1.json")).unwrap());
        assert!(f.image().reservations.is_empty());
    }
    let mut p = policy();
    p.fixed.memory_bytes = 0;
    assert!(p.validate().is_err());
    assert!(sum(&[MAX_INTEGER, 1]).is_err());
    assert!(mul(MAX_INTEGER, 2).is_err());
}

#[test]
fn reused_reservation_and_preexisting_tasks_cannot_join_a_pool() {
    let f = Fixture::new(policy());
    f.accept("first", "unique", 100).unwrap();
    assert_eq!(
        f.accept("second", "unique", 100).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(f.image().reservations.len(), 1);
    assert_eq!(
        FileTaskAcceptanceStore::provision_capacity(&f.root, &policy())
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    let dir = Dir::new();
    let root = dir.0.join("legacy");
    accept(&root, f.request.clone(), "legacy", "fixture-only", 100).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::provision_capacity(&root, &policy())
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    let task = FileTaskAcceptanceStore::open(&root)
        .unwrap()
        .read()
        .unwrap()
        .tasks[0]
        .clone();
    assert_eq!(
        FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .verify_capacity_for_start(&task.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
}

#[test]
fn owner_loss_path_replacement_and_runtime_start_gate_fail_closed() {
    let f = Fixture::new(policy());
    let accepted = f.accept("first", "one", 100).unwrap();
    f.store
        .verify_capacity_for_start(&accepted.task.view.accepted_contract)
        .unwrap();
    let owner = TaskOwner::new(f.store.clone(), sha256, new_task_id);
    drop(f.guard);
    assert_eq!(
        f.store
            .verify_capacity_for_start(&accepted.task.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        owner
            .record_event(
                &accepted.task.view.task_id,
                nexus_compute::task_runtime::RuntimeEvent {
                    sequence: 1,
                    action: RuntimeAction::Prepare
                }
            )
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        f.store
            .with_gc_locked_ledger(|_, _| Ok(()))
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert!(
        accept(&f.root, f.request.clone(), "first", "unused", 101)
            .unwrap()
            .replayed
    );
    let path = f.root.join(OWNER);
    fs::rename(&path, f.root.join("old-owner.lock")).unwrap();
    owner_file(&f.root, true).unwrap();
    assert_eq!(
        f.store.begin_capacity_reconciliation().unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
}

#[test]
fn capacity_receipt_loss_and_schema_downgrade_never_reset_authority() {
    let f = Fixture::new(policy());
    f.accept("accepted", "reserved", 100).unwrap();
    let authority = fs::read(f.root.join("acceptance-v1.json")).unwrap();
    fs::remove_file(f.root.join(RECEIPT)).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&f.root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        authority,
        fs::read(f.root.join("acceptance-v1.json")).unwrap()
    );
    atomic(&f.root, RECEIPT, RECEIPT_BYTES).unwrap();
    let _lock = f.store.capacity_acceptance_lock().unwrap();
    let (ledger, _) = f.store.load_capacity_authority().unwrap();
    f.store
        .publish_capacity_authority(&ledger, &f.image_unlocked())
        .unwrap();
    // A syntactically valid v1 image cannot bypass the durable required receipt.
    let payload = ledger.to_value();
    let envelope = Value::Object(BTreeMap::from([
        ("schema_version".into(), 1u64.to_value()),
        (
            "payload_sha256".into(),
            sha256(&payload.canonical_bytes()).to_value(),
        ),
        ("ledger".into(), payload),
    ]));
    atomic(&f.root, "acceptance-v1.json", &envelope.canonical_bytes()).unwrap();
    drop(_lock);
    assert_eq!(
        FileTaskAcceptanceStore::open(&f.root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
}

#[test]
fn original_execution_lease_loss_blocks_admission_even_before_observation_event() {
    let f = Fixture::new(policy());
    let accepted = f.accept("first", "original", 100).unwrap();
    let parent = f.root.join("executions-v1");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let directory =
        parent.join(&sha256(accepted.task.view.task_id.as_str().as_bytes()).as_str()[7..]);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("owner.lock"))
        .unwrap();
    let metadata = file.metadata().unwrap();
    crate::artifact_fs::save(&directory,"owner-lease-v1.json",&serde_json::json!({"schema_version":1,"task_id":accepted.task.view.task_id.as_str(),"contract_digest":accepted.task.view.contract_digest.as_str(),"device":metadata.dev().to_string(),"inode":metadata.ino().to_string()})).unwrap();
    assert!(crate::task_store::lock_fd(&file, true).unwrap());
    f.store
        .verify_capacity_for_start(&accepted.task.view.accepted_contract)
        .unwrap();
    drop(file);
    assert_eq!(
        f.store
            .verify_capacity_for_start(&accepted.task.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        f.accept("second", "second", 101).unwrap_err().code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        f.store
            .with_gc_locked_ledger(|_, _| Ok(()))
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        f.store.read().unwrap().tasks[0].view.observation,
        Observation::Confirmed,
        "loss gate must not fabricate Task events"
    );
    assert!(f.accept("first", "ignored-replay", 101).unwrap().replayed);
}

#[test]
fn interrupted_fresh_provision_only_repairs_via_explicit_matching_policy() {
    let dir = Dir::new();
    let root = dir.0.join("provider");
    let p = policy();
    FileTaskAcceptanceStore::provision_capacity(&root, &p).unwrap();
    let original = fs::read(root.join("acceptance-v1.json")).unwrap();
    fs::remove_file(root.join(RECEIPT)).unwrap();
    atomic(
        &root,
        "acceptance-initialized-v1",
        crate::task_store::RUNTIME_AUTHORITY_RECEIPT,
    )
    .unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    let mut changed = p.clone();
    changed.total.cpu_millis += 1;
    assert_eq!(
        FileTaskAcceptanceStore::provision_capacity(&root, &changed)
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(original, fs::read(root.join("acceptance-v1.json")).unwrap());
    FileTaskAcceptanceStore::provision_capacity(&root, &p).unwrap();
    assert_eq!(original, fs::read(root.join("acceptance-v1.json")).unwrap());
    assert!(
        FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .is_empty()
    );
}

#[test]
fn capacity_checksum_and_link_corruption_preserve_authority() {
    let f = Fixture::new(policy());
    f.accept("first", "original", 100).unwrap();
    let path = f.root.join("acceptance-v1.json");
    let original = fs::read(&path).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&original).unwrap();
    envelope["capacity"]["reservations"][0]["id"] = serde_json::json!("another-id");
    let raw = serde_json::to_vec(&envelope).unwrap();
    let value = nexus::n3_acceptance::parse_canonical_json(&raw).unwrap();
    atomic(&f.root, "acceptance-v1.json", &value.canonical_bytes()).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&f.root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    let payload = Value::Object(BTreeMap::from([
        (
            "ledger".into(),
            nexus::n3_acceptance::parse_canonical_json(
                &serde_json::to_vec(&envelope["ledger"]).unwrap(),
            )
            .unwrap(),
        ),
        (
            "capacity".into(),
            nexus::n3_acceptance::parse_canonical_json(
                &serde_json::to_vec(&envelope["capacity"]).unwrap(),
            )
            .unwrap(),
        ),
    ]));
    envelope["payload_sha256"] = serde_json::json!(sha256(&payload.canonical_bytes()).as_str());
    let invalid =
        nexus::n3_acceptance::parse_canonical_json(&serde_json::to_vec(&envelope).unwrap())
            .unwrap()
            .canonical_bytes();
    atomic(&f.root, "acceptance-v1.json", &invalid).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&f.root).unwrap_err().code,
        TaskErrorCode::StateCorrupt,
        "valid checksum cannot repair wrong reservation link"
    );
    assert_eq!(invalid, fs::read(&path).unwrap());
}
impl Fixture {
    fn image_unlocked(&self) -> CapacityImage {
        self.store.load_capacity_authority().unwrap().1.unwrap()
    }
}

#[test]
fn independent_process_acceptance_serializes_one_budget_and_replay() {
    let mut p = policy();
    p.total.slots = p.fixed.slots + 1;
    let f = Fixture::new(p);
    let request = f.root.join("capacity-test-request.json");
    atomic(
        &f.root,
        "capacity-test-request.json",
        &f.request.to_value().canonical_bytes(),
    )
    .unwrap();
    let child = |key: &str| {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "task_capacity::tests::capacity_child_process",
                "--ignored",
                "--nocapture",
            ])
            .env("NEXUS_CAPACITY_CHILD_ROOT", &f.root)
            .env("NEXUS_CAPACITY_CHILD_REQUEST", &request)
            .env("NEXUS_CAPACITY_CHILD_KEY", key)
            .spawn()
            .unwrap()
    };
    let mut one = child("first");
    let mut two = child("second");
    assert!(one.wait().unwrap().success());
    assert!(two.wait().unwrap().success());
    let results = [
        fs::read(f.root.join("result-first")).unwrap(),
        fs::read(f.root.join("result-second")).unwrap(),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_slice() == b"accepted")
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_slice() == b"CAPACITY_UNAVAILABLE")
            .count(),
        1
    );
    let image = f.image();
    assert_eq!(image.reservations.len(), 1);
    let ledger = f.store.read().unwrap();
    assert_eq!(ledger.tasks.len(), 1);
    assert_eq!(ledger.idempotency.len(), 1);
    let winning = ledger.idempotency[0].scope.key.clone();
    let mut replay = child(&winning);
    assert!(replay.wait().unwrap().success());
    assert_eq!(f.image(), image);
}

struct BoundaryStore {
    store: FileTaskAcceptanceStore,
    boundary: fn(&str) -> Result<(), TaskError>,
}
impl TaskAcceptanceStore for BoundaryStore {
    fn read(&self) -> Result<AcceptanceLedger, TaskError> {
        self.store.read()
    }
    fn transact(
        &self,
        update: &mut dyn FnMut(&mut AcceptanceLedger) -> Result<AcceptanceResult, TaskError>,
    ) -> Result<AcceptanceResult, TaskError> {
        let mut boundary = self.boundary;
        self.store.transact_with_boundary(update, &mut boundary)
    }
}

#[test]
fn crashed_coupled_publication_has_all_or_none_and_same_key_recovery() {
    for boundary in [
        "after-write",
        "after-file-sync",
        "after-rename",
        "after-directory-sync",
    ] {
        let f = Fixture::new(policy());
        atomic(
            &f.root,
            "capacity-test-request.json",
            &f.request.to_value().canonical_bytes(),
        )
        .unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "task_capacity::tests::capacity_publication_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("NEXUS_CAPACITY_CHILD_ROOT", &f.root)
            .env("NEXUS_CAPACITY_CRASH_BOUNDARY", boundary)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        let committed = matches!(boundary, "after-rename" | "after-directory-sync");
        let ledger = f.store.read().unwrap();
        let image = f.image();
        assert_eq!(ledger.tasks.len(), usize::from(committed));
        assert_eq!(ledger.idempotency.len(), usize::from(committed));
        assert_eq!(image.reservations.len(), usize::from(committed));
        if committed {
            assert_eq!(ledger.tasks[0].input_pin_intent, f.request.input_snapshot);
            assert_eq!(
                image.reservations[0].id,
                ledger.tasks[0]
                    .view
                    .accepted_contract
                    .capacity_reservation_id
            );
        }
        let accepted = f.accept("crash-key", "crash-reservation", 100).unwrap();
        assert_eq!(accepted.replayed, committed);
        let replay = f.accept("crash-key", "ignored-new-proposal", 101).unwrap();
        assert!(replay.replayed);
        assert_eq!(accepted.task, replay.task);
        assert_eq!(f.store.read().unwrap().tasks.len(), 1);
        assert_eq!(f.image().reservations.len(), 1);
    }
}

#[ignore = "crashing process fixture invoked only by crashed_coupled_publication_has_all_or_none_and_same_key_recovery"]
#[test]
fn capacity_publication_crash_child() {
    let root = PathBuf::from(std::env::var("NEXUS_CAPACITY_CHILD_ROOT").unwrap());
    let mut request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(
        &fs::read(root.join("capacity-test-request.json")).unwrap(),
    )
    .unwrap();
    request.idempotency_key = "crash-key".into();
    let context = AcceptanceContext {
        authenticated_principal: "capacity-principal".into(),
        provider: request.provider.clone(),
        environment_evidence: request.environment.clone(),
        capacity_reservation_id: "crash-reservation".into(),
        now_unix: 100,
        prepare_deadline_unix: 110,
        delivery_deadline_unix: 200,
    };
    fn exit_boundary(boundary: &str) -> Result<(), TaskError> {
        if std::env::var("NEXUS_CAPACITY_CRASH_BOUNDARY").unwrap() == boundary {
            std::process::exit(73)
        }
        Ok(())
    }
    let owner = TaskOwner::new(
        BoundaryStore {
            store: FileTaskAcceptanceStore::open(&root).unwrap(),
            boundary: exit_boundary,
        },
        sha256,
        new_task_id,
    );
    owner.accept_verified(request, context).unwrap();
    panic!("crash boundary was not reached");
}

#[ignore = "child-process fixture invoked only by independent_process_acceptance_serializes_one_budget_and_replay"]
#[test]
fn capacity_child_process() {
    let root = PathBuf::from(std::env::var("NEXUS_CAPACITY_CHILD_ROOT").unwrap());
    let request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(
        &fs::read(std::env::var("NEXUS_CAPACITY_CHILD_REQUEST").unwrap()).unwrap(),
    )
    .unwrap();
    let key = std::env::var("NEXUS_CAPACITY_CHILD_KEY").unwrap();
    let result = accept(&root, request, &key, &format!("reservation-{key}"), 100);
    let bytes = match result {
        Ok(_) => b"accepted".as_slice(),
        Err(ref e) => {
            assert_eq!(e.code, TaskErrorCode::CapacityUnavailable);
            b"CAPACITY_UNAVAILABLE".as_slice()
        }
    };
    atomic(&root, &format!("result-{key}"), bytes).unwrap();
}
