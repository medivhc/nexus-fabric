use super::*;
use nexus_compute::task::{AcceptanceContext, TaskOwner};
use nexus_domain::task::*;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "nexus-n3-1-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn request() -> SubmitTaskRequest {
    nexus::n3_acceptance::decode_dto(include_bytes!(
        "../../../docs/contracts/n3-submit.example.json"
    ))
    .unwrap()
}
fn context(r: &SubmitTaskRequest, now: u64) -> AcceptanceContext {
    AcceptanceContext {
        authenticated_principal: "verified-test-principal".into(),
        provider: r.provider.clone(),
        environment_evidence: r.environment.clone(),
        capacity_reservation_id: "test-reservation".into(),
        now_unix: now,
        prepare_deadline_unix: now + 10,
        delivery_deadline_unix: now + 100,
    }
}
fn owner(root: &Path) -> TaskOwner<FileTaskAcceptanceStore> {
    TaskOwner::new(
        FileTaskAcceptanceStore::open(root).unwrap(),
        sha256,
        new_task_id,
    )
}

#[test]
fn cold_restart_replay_conflict_scope_and_exact_expiry() {
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let r = request();
    let first = owner(&root)
        .accept_verified(r.clone(), context(&r, 100))
        .unwrap();
    assert!(!first.replayed);
    let bytes = std::fs::read(root.join("acceptance-v1.json")).unwrap();
    let mut replay = r.clone();
    replay.idempotency_ttl_seconds = 1;
    let second = owner(&root)
        .accept_verified(replay, context(&r, 200))
        .unwrap();
    assert!(second.replayed);
    assert_eq!(first.task, second.task);
    assert_eq!(
        bytes,
        std::fs::read(root.join("acceptance-v1.json")).unwrap()
    );
    let mut conflict = r.clone();
    conflict.command.push("different".into());
    assert_eq!(
        owner(&root)
            .accept_verified(conflict.clone(), context(&r, 201))
            .unwrap_err()
            .code,
        TaskErrorCode::IdempotencyConflict
    );
    let mut other = context(&r, 201);
    other.authenticated_principal = "second-principal".into();
    assert_ne!(
        owner(&root)
            .accept_verified(r.clone(), other)
            .unwrap()
            .task
            .view
            .task_id,
        first.task.view.task_id
    );
    let mut provider = r.clone();
    provider.provider = "another-provider".into();
    owner(&root)
        .accept_verified(provider.clone(), context(&provider, 201))
        .unwrap();
    let mut workspace = r.clone();
    workspace.workspace = "other-ws".into();
    workspace.input_snapshot.workspace = workspace.workspace.clone();
    let Value::Object(mut fields) = workspace.input_snapshot.to_value() else {
        panic!()
    };
    fields.remove("snapshot_id");
    workspace.input_snapshot.snapshot_id = sha256(&Value::Object(fields).canonical_bytes());
    owner(&root)
        .accept_verified(workspace.clone(), context(&workspace, 201))
        .unwrap();
    assert!(
        owner(&root)
            .accept_verified(r.clone(), context(&r, 3699))
            .unwrap()
            .replayed
    );
    let new = owner(&root)
        .accept_verified(conflict.clone(), context(&r, 3700))
        .unwrap();
    assert!(!new.replayed);
    assert_ne!(new.task.view.task_id, first.task.view.task_id);
    assert_eq!(
        owner(&root).accepted(&first.task.view.task_id).unwrap(),
        Some(first.task)
    );
    let ledger = FileTaskAcceptanceStore::open(&root)
        .unwrap()
        .read()
        .unwrap();
    assert_eq!(ledger.tasks.len(), 5);
    assert_eq!(ledger.idempotency.len(), 4);
    ledger.validate(sha256).unwrap();
}
#[test]
fn corrupt_or_torn_images_fail_closed_and_remain_available_for_evidence() {
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let r = request();
    owner(&root)
        .accept_verified(r.clone(), context(&r, 100))
        .unwrap();
    let path = root.join("acceptance-v1.json");
    let bytes = std::fs::read(&path).unwrap();
    for bad in [
        bytes[..bytes.len() / 2].to_vec(),
        b"".to_vec(),
        bytes
            .iter()
            .map(|&b| if b == b'W' { b'X' } else { b })
            .collect(),
    ] {
        std::fs::write(&path, &bad).unwrap();
        assert_eq!(
            FileTaskAcceptanceStore::open(&root).unwrap_err().code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(std::fs::read(&path).unwrap(), bad);
    }
    std::fs::write(&path, bytes).unwrap();
    let mut ledger = FileTaskAcceptanceStore::open(&root)
        .unwrap()
        .read()
        .unwrap();
    ledger.idempotency.clear();
    assert_eq!(
        ledger.validate(sha256).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    // A valid outer checksum does not override broken domain/index relationships.
    let value = ledger.to_value();
    let envelope = Value::Object(BTreeMap::from([
        ("schema_version".into(), Value::Integer(1)),
        (
            "payload_sha256".into(),
            sha256(&value.canonical_bytes()).to_value(),
        ),
        ("ledger".into(), value),
    ]));
    std::fs::write(&path, envelope.canonical_bytes()).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
}
#[test]
fn interrupted_publication_never_acknowledges_partial_acceptance() {
    for boundary in [
        "after-write",
        "after-file-sync",
        "after-rename",
        "after-directory-sync",
    ] {
        let dir = TestDir::new();
        let root = dir.0.join("store");
        let store = FileTaskAcceptanceStore::open(&root).unwrap();
        let scratch = dir.0.join("scratch");
        let r = request();
        let accepted = owner(&scratch)
            .accept_verified(r.clone(), context(&r, 100))
            .unwrap();
        let ledger = FileTaskAcceptanceStore::open(&scratch)
            .unwrap()
            .read()
            .unwrap();
        let _lock = store.lock().unwrap();
        let result = store.publish_with(&ledger, |at| {
            if at == boundary {
                Err(TaskError::new(
                    TaskErrorCode::PersistenceFailed,
                    "injected interruption",
                    true,
                ))
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err().code, TaskErrorCode::PersistenceFailed);
        drop(_lock);
        let after = FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap();
        let committed = matches!(boundary, "after-rename" | "after-directory-sync");
        assert_eq!(after.tasks.len(), usize::from(committed));
        assert_eq!(after.idempotency.len(), usize::from(committed));
        let retry = owner(&root)
            .accept_verified(r.clone(), context(&r, 101))
            .unwrap();
        assert_eq!(retry.replayed, committed);
        if committed {
            assert_eq!(retry.task, accepted.task);
        }
        assert_eq!(
            FileTaskAcceptanceStore::open(&root)
                .unwrap()
                .read()
                .unwrap()
                .tasks
                .len(),
            1
        );
    }
}
#[test]
fn auth_environment_deadlines_and_failed_store_do_not_accept() {
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let r = request();
    let o = owner(&root);
    for mutate in [
        |c: &mut AcceptanceContext| c.authenticated_principal.clear(),
        |c: &mut AcceptanceContext| c.provider = "wrong".into(),
        |c: &mut AcceptanceContext| c.environment_evidence.architecture = "aarch64".into(),
        |c: &mut AcceptanceContext| c.prepare_deadline_unix = 100,
        |c: &mut AcceptanceContext| c.delivery_deadline_unix = 110,
        |c: &mut AcceptanceContext| c.now_unix = MAX_INTEGER,
    ] {
        let mut c = context(&r, 100);
        mutate(&mut c);
        assert!(o.accept_verified(r.clone(), c).is_err());
    }
    assert!(
        FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .is_empty()
    );
    struct BrokenStore;
    impl TaskAcceptanceStore for BrokenStore {
        fn read(&self) -> Result<AcceptanceLedger, TaskError> {
            Ok(AcceptanceLedger::default())
        }
        fn transact(
            &self,
            update: &mut dyn FnMut(&mut AcceptanceLedger) -> Result<AcceptanceResult, TaskError>,
        ) -> Result<AcceptanceResult, TaskError> {
            let mut ledger = AcceptanceLedger::default();
            let _would_accept = update(&mut ledger)?;
            Err(TaskError::new(
                TaskErrorCode::PersistenceFailed,
                "commit failed",
                true,
            ))
        }
    }
    let broken = TaskOwner::new(BrokenStore, sha256, new_task_id);
    assert_eq!(
        broken
            .accept_verified(r.clone(), context(&r, 100))
            .unwrap_err()
            .code,
        TaskErrorCode::PersistenceFailed
    );
}

#[test]
fn independent_store_handles_serialize_parallel_duplicate_submissions() {
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let _store = FileTaskAcceptanceStore::open(&root).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
    let handles = (0..12)
        .map(|_| {
            let root = root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let o = owner(&root);
                let r = request();
                barrier.wait();
                o.accept_verified(r.clone(), context(&r, 100)).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| !r.replayed).count(), 1);
    assert!(
        results
            .iter()
            .all(|r| r.task.view.task_id == results[0].task.view.task_id)
    );
    assert_eq!(
        FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .len(),
        1
    );
}

// This ignored entry is a child-process fixture, explicitly invoked below. It
// does not skip a failing capability or represent an independently passing test.
#[test]
#[ignore = "child-process fixture; invoked by cross_process_recovery_and_racing_acceptance"]
fn subprocess_worker() {
    let root = PathBuf::from(std::env::var("NEXUS_N3_TEST_ROOT").expect("child root"));
    let mode = std::env::var("NEXUS_N3_TEST_MODE").expect("child mode");
    let r = request();
    if mode == "create-root-before-parent-sync" {
        FileTaskAcceptanceStore::open_with_parent_sync(&root, |_| std::process::exit(73)).unwrap();
        panic!("crash fixture returned");
    }
    if mode == "accept" {
        owner(&root)
            .accept_verified(r.clone(), context(&r, 100))
            .unwrap();
        return;
    }
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let scratch = root.parent().unwrap().join("candidate");
    owner(&scratch)
        .accept_verified(r.clone(), context(&r, 100))
        .unwrap();
    let ledger = FileTaskAcceptanceStore::open(&scratch)
        .unwrap()
        .read()
        .unwrap();
    let _lock = store.lock().unwrap();
    store
        .publish_with(&ledger, |at| {
            if at == mode {
                std::process::exit(73);
            }
            Ok(())
        })
        .unwrap();
    panic!("unknown child crash boundary");
}
fn child(root: &Path, mode: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "task_store::tests::subprocess_worker",
            "--exact",
            "--ignored",
        ])
        .env("NEXUS_N3_TEST_ROOT", root)
        .env("NEXUS_N3_TEST_MODE", mode)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}
#[test]
fn cross_process_recovery_and_racing_acceptance() {
    for boundary in [
        "after-write",
        "after-file-sync",
        "after-rename",
        "after-directory-sync",
    ] {
        let dir = TestDir::new();
        let root = dir.0.join("store");
        assert_eq!(child(&root, boundary).wait().unwrap().code(), Some(73));
        let store = FileTaskAcceptanceStore::open(&root).unwrap();
        let ledger = store.read().unwrap();
        let committed = matches!(boundary, "after-rename" | "after-directory-sync");
        assert_eq!(ledger.tasks.len(), usize::from(committed));
        let r = request();
        let retry = owner(&root)
            .accept_verified(r.clone(), context(&r, 101))
            .unwrap();
        assert_eq!(retry.replayed, committed);
        assert_eq!(store.read().unwrap().tasks.len(), 1);
    }
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let mut children = (0..8).map(|_| child(&root, "accept")).collect::<Vec<_>>();
    for process in &mut children {
        assert!(process.wait().unwrap().success());
    }
    let ledger = FileTaskAcceptanceStore::open(&root)
        .unwrap()
        .read()
        .unwrap();
    assert_eq!(ledger.tasks.len(), 1);
    assert_eq!(ledger.idempotency.len(), 1);
    ledger.validate(sha256).unwrap();
}

#[test]
fn task_id_collision_keeps_original_image_and_concurrent_conflicts_accept_once() {
    fn fixed_id() -> Result<TaskId, TaskError> {
        TaskId::new("provider-fixed-test-id".into())
    }
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let r = request();
    let o = TaskOwner::new(
        FileTaskAcceptanceStore::open(&root).unwrap(),
        sha256,
        fixed_id,
    );
    o.accept_verified(r.clone(), context(&r, 100)).unwrap();
    let mut next = r.clone();
    next.idempotency_key = "different-key".into();
    assert_eq!(
        o.accept_verified(next, context(&r, 100)).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .len(),
        1
    );
    let other_root = dir.0.join("race");
    let _store = FileTaskAcceptanceStore::open(&other_root).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
    let handles = (0..12)
        .map(|i| {
            let root = other_root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut r = request();
                if i % 2 == 1 {
                    r.command.push("different".into());
                }
                let o = owner(&root);
                barrier.wait();
                o.accept_verified(r.clone(), context(&r, 100))
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 6);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|v| !v.replayed))
            .count(),
        1
    );
    for e in results.into_iter().filter_map(Result::err) {
        assert_eq!(e.code, TaskErrorCode::IdempotencyConflict);
    }
    assert_eq!(
        FileTaskAcceptanceStore::open(&other_root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .len(),
        1
    );
}
#[test]
fn provider_state_directory_and_files_do_not_follow_links_or_expose_records() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let link = dir.0.join("linked-store");
    symlink(&root, &link).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&link).unwrap_err().code,
        TaskErrorCode::PersistenceFailed
    );
    let r = request();
    owner(&root)
        .accept_verified(r.clone(), context(&r, 100))
        .unwrap();
    let path = root.join("acceptance-v1.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved = root.join("saved.json");
    std::fs::rename(&path, &saved).unwrap();
    symlink(&saved, &path).unwrap();
    assert_eq!(
        store.read().unwrap_err().code,
        TaskErrorCode::PersistenceFailed
    );
}

#[test]
fn every_open_syncs_the_parent_after_failure_and_concurrent_initialization() {
    let dir = TestDir::new();
    let root = dir.0.join("store");
    let failure = || {
        TaskError::new(
            TaskErrorCode::PersistenceFailed,
            "injected parent sync failure",
            true,
        )
    };
    assert_eq!(
        FileTaskAcceptanceStore::open_with_parent_sync(&root, |_| Err(failure()))
            .unwrap_err()
            .code,
        TaskErrorCode::PersistenceFailed
    );
    assert!(root.is_dir());
    // Existing directory path must still report a parent-sync failure.
    assert_eq!(
        FileTaskAcceptanceStore::open_with_parent_sync(&root, |_| Err(failure()))
            .unwrap_err()
            .code,
        TaskErrorCode::PersistenceFailed
    );
    let mut parents = Vec::new();
    FileTaskAcceptanceStore::open_with_parent_sync(&root, |p| {
        parents.push(p.to_path_buf());
        sync_directory(p)
    })
    .unwrap();
    assert_eq!(parents[0], dir.0);
    assert!(parents.contains(&PathBuf::from("/")));
    let fresh = dir.0.join("race-init");
    let (created_tx, created_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let a_root = fresh.clone();
    let creator = std::thread::spawn(move || {
        FileTaskAcceptanceStore::open_with_parent_sync(&a_root, |_| {
            created_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Err(TaskError::new(
                TaskErrorCode::PersistenceFailed,
                "creator interrupted",
                true,
            ))
        })
    });
    created_rx.recv().unwrap();
    let mut synced = Vec::new();
    let other = FileTaskAcceptanceStore::open_with_parent_sync(&fresh, |p| {
        synced.push(p.to_path_buf());
        sync_directory(p)
    })
    .unwrap();
    assert_eq!(synced[0], dir.0);
    let r = request();
    TaskOwner::new(other, sha256, new_task_id)
        .accept_verified(r.clone(), context(&r, 100))
        .unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        creator.join().unwrap().unwrap_err().code,
        TaskErrorCode::PersistenceFailed
    );
    assert_eq!(
        FileTaskAcceptanceStore::open(&fresh)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .len(),
        1
    );
    let crashed = dir.0.join("crashed-init");
    assert_eq!(
        child(&crashed, "create-root-before-parent-sync")
            .wait()
            .unwrap()
            .code(),
        Some(73)
    );
    assert!(crashed.is_dir());
    let mut count = 0;
    let store = FileTaskAcceptanceStore::open_with_parent_sync(&crashed, |p| {
        count += 1;
        sync_directory(p)
    })
    .unwrap();
    assert!(count > 0);
    let r = request();
    let accepted = TaskOwner::new(store, sha256, new_task_id)
        .accept_verified(r.clone(), context(&r, 100))
        .unwrap();
    assert!(!accepted.replayed);
}
