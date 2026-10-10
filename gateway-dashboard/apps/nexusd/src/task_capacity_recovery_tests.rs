use super::*;
use crate::task_capacity::{CapacityBudget, ExecutorBackendOverhead, ProviderCapacityPolicy};
use crate::task_capacity_recovery::{
    CapacityOwnerGuard, begin_capacity_owner_recovery, finish_capacity_owner_recovery,
};
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_compute::task::{AcceptanceContext, AcceptedTask, TaskAcceptanceStore, TaskOwner};
use nexus_storage::InMemoryContentStore;
use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId, snapshot::SnapshotSelection};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    store: FileTaskAcceptanceStore,
    executor: LinuxTaskExecutor,
    guard: Option<CapacityOwnerGuard>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "n3-capacity-recovery-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let store = FileTaskAcceptanceStore::provision_capacity(
            &root,
            &ProviderCapacityPolicy {
                total: CapacityBudget {
                    cpu_millis: 100_000,
                    memory_bytes: 1 << 34,
                    pids: 4096,
                    runtime_storage_bytes: 1 << 34,
                    backend_disk_bytes: 1 << 36,
                    slots: 16,
                },
                fixed: CapacityBudget {
                    cpu_millis: 1,
                    memory_bytes: 4096,
                    pids: 1,
                    runtime_storage_bytes: 4096,
                    backend_disk_bytes: 4096,
                    slots: 1,
                },
                overhead: ExecutorBackendOverhead {
                    cpu_millis: 1,
                    memory_bytes: 4096,
                    pids: 1,
                    backend_disk_bytes: 4096,
                },
            },
        )
        .unwrap();
        let guard = begin_capacity_owner_recovery(&store).unwrap();
        let executor = LinuxTaskExecutor::open(&root, vec![]).unwrap();
        finish_capacity_owner_recovery(&store, &executor, guard.as_ref()).unwrap();
        Self {
            root,
            store,
            executor,
            guard,
        }
    }
    fn accept(&self) -> AcceptedTask {
        let snapshots = FileSnapshotStore::open(&self.root).unwrap();
        let mut workspace = Workspace::init(
            WorkspaceId("capacity-recovery".into()),
            InMemoryContentStore::new(),
            AuthorId("test".into()),
        )
        .unwrap();
        let base = workspace.heads().heads[0].clone();
        let commit = workspace
            .commit_changes(
                &base,
                &[Change {
                    path: "input".into(),
                    content: b"immutable recovery input".to_vec(),
                }],
            )
            .unwrap();
        let frozen = snapshots
            .stage_snapshot(
                &workspace,
                &commit,
                &SnapshotSelection {
                    include: vec!["input".into()],
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
        request.limits = TaskLimits {
            timeout_seconds: 10,
            cpu_millis: 1000,
            memory_bytes: 64 * 1024 * 1024,
            storage_bytes: 1024 * 1024,
            log_bytes: 4096,
        };
        let context = AcceptanceContext {
            authenticated_principal: "recovery-test".into(),
            provider: request.provider.clone(),
            environment_evidence: request.environment.clone(),
            capacity_reservation_id: "recovery-reservation".into(),
            now_unix: 100,
            prepare_deadline_unix: 110,
            delivery_deadline_unix: 200,
        };
        TaskOwner::new(self.store.clone(), sha256, new_task_id)
            .accept_verified(request, context)
            .unwrap()
            .task
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.guard.take();
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn capacity_owner_recovery_revalidates_all_inputs_before_ready() {
    let mut fixture = Fixture::new();
    let accepted = fixture.accept();
    fixture
        .store
        .verify_capacity_for_start(&accepted.view.accepted_contract)
        .unwrap();
    fixture.guard.take();
    fixture.guard = begin_capacity_owner_recovery(&fixture.store).unwrap();
    assert_eq!(
        fixture
            .store
            .verify_capacity_for_start(&accepted.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    // A real frozen input manifest disappears; a Task pin still exists and no
    // terminal/runtime fact grants permission to rebuild it as an empty root.
    let content = fixture.root.join("content-sha256-v1");
    let paths: Vec<_> = fs::read_dir(&content)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let originals: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
    fs::remove_file(&paths[0]).unwrap();
    assert!(
        finish_capacity_owner_recovery(&fixture.store, &fixture.executor, fixture.guard.as_ref())
            .is_err()
    );
    assert!(
        fixture
            .store
            .verify_capacity_for_start(&accepted.view.accepted_contract)
            .is_err()
    );
    // Restore the exact private bytes, then a fresh verification can complete.
    use std::os::unix::fs::PermissionsExt;
    fs::write(&paths[0], &originals[0]).unwrap();
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o600)).unwrap();
    finish_capacity_owner_recovery(&fixture.store, &fixture.executor, fixture.guard.as_ref())
        .unwrap();
    fixture
        .store
        .verify_capacity_for_start(&accepted.view.accepted_contract)
        .unwrap();
}

#[test]
fn recovery_refuses_unowned_execution_directory_and_keeps_pending() {
    let mut fixture = Fixture::new();
    let accepted = fixture.accept();
    fixture.guard.take();
    fixture.guard = begin_capacity_owner_recovery(&fixture.store).unwrap();
    let parent = fixture.root.join("executions-v1");
    fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(parent.join("unknown-task"))
        .unwrap();
    assert_eq!(
        finish_capacity_owner_recovery(&fixture.store, &fixture.executor, fixture.guard.as_ref())
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert!(parent.join("unknown-task").exists());
    assert_eq!(fixture.store.read().unwrap().tasks[0], accepted);
    assert_eq!(
        fixture
            .store
            .verify_capacity_for_start(&accepted.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
}

#[test]
fn original_never_executed_cancellation_release_is_repeatable() {
    let fixture = Fixture::new();
    let accepted = fixture.accept();
    let state = fixture
        .executor
        .cancel(&accepted.view.task_id, "User")
        .unwrap();
    assert_eq!(state.view.cancellation.state, CancellationState::Confirmed);
    assert!(!fixture.root.join("executions-v1").exists());
    let before_release: Json =
        serde_json::from_slice(&fs::read(fixture.root.join("acceptance-v1.json")).unwrap())
            .unwrap();
    fixture
        .executor
        .release_verified_capacity(&accepted.view.task_id)
        .unwrap();
    let before = fs::read(fixture.root.join("acceptance-v1.json")).unwrap();
    let after_release: Json = serde_json::from_slice(&before).unwrap();
    assert!(
        after_release["capacity"]["reservations"][0]["demand"]["backend_disk_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert_eq!(
        before_release["capacity"]["reservations"][0]["demand"]["backend_disk_bytes"],
        after_release["capacity"]["reservations"][0]["demand"]["backend_disk_bytes"]
    );
    assert_eq!(
        after_release["capacity"]["reservations"][0]["runtime_held"],
        false
    );
    fixture
        .executor
        .release_verified_capacity(&accepted.view.task_id)
        .unwrap();
    assert_eq!(
        before,
        fs::read(fixture.root.join("acceptance-v1.json")).unwrap()
    );
    assert_eq!(fixture.store.read().unwrap().tasks[0], accepted);
}

#[test]
fn ready_without_original_capacity_owner_cannot_authorize_start() {
    let mut fixture = Fixture::new();
    let accepted = fixture.accept();
    fixture
        .store
        .verify_capacity_for_start(&accepted.view.accepted_contract)
        .unwrap();
    fixture.guard.take();
    assert_eq!(
        fixture
            .store
            .verify_capacity_for_start(&accepted.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(fixture.store.read().unwrap().tasks[0], accepted);
}

#[test]
fn unknown_real_preparation_authority_remains_pending_without_release() {
    let mut fixture = Fixture::new();
    let accepted = fixture.accept();
    fixture.guard.take();
    fixture.guard = begin_capacity_owner_recovery(&fixture.store).unwrap();
    // Use the original executor's durable Logs authority factory. No fake
    // running/stopped outcome or Engine response makes this preparation known.
    let logs = Logs::create(
        &fixture.root,
        &accepted.view.task_id,
        &accepted.view.contract_digest,
        accepted.view.accepted_contract.request.limits.log_bytes,
    )
    .unwrap();
    let before = fs::read(fixture.root.join("acceptance-v1.json")).unwrap();
    finish_capacity_owner_recovery(&fixture.store, &fixture.executor, fixture.guard.as_ref())
        .unwrap();
    assert_eq!(
        before,
        fs::read(fixture.root.join("acceptance-v1.json")).unwrap()
    );
    assert!(logs.directory.join("owner-lease-v1.json").exists());
    assert_eq!(
        fixture
            .store
            .verify_capacity_for_start(&accepted.view.accepted_contract)
            .unwrap_err()
            .code,
        TaskErrorCode::CapacityUnavailable
    );
}

#[test]
fn recovery_cannot_use_executor_witness_from_another_root() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    assert_eq!(
        finish_capacity_owner_recovery(&fixture.store, &other.executor, fixture.guard.as_ref())
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
}
