use super::*;
use nexus_compute::task::{AcceptanceContext, TaskAcceptanceStore, TaskOwner};
use nexus_domain::task::SubmitTaskRequest;
use nexus_storage::{InMemoryContentStore, ObjectId};
use nexus_workspace::{AuthorId, Change, WorkspaceId};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

#[test]
fn review_regression_missing_acceptance_image_blocks_live_handle_gc() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    accept(&root, &s.reference, 100);
    store.release_preview(&s.reference.snapshot_id).unwrap();
    let content = root.join("content-sha256-v1");
    let count = fs::read_dir(&content).unwrap().count();
    let acceptance = FileTaskAcceptanceStore::open(&root).unwrap();
    fs::remove_file(root.join("acceptance-v1.json")).unwrap();
    assert_eq!(
        store.collect_garbage(10000, 0).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(count, fs::read_dir(content).unwrap().count());
    assert!(!root.join("acceptance-v1.json").exists());
    assert_eq!(
        acceptance.read().unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    let r = request(&s.reference);
    let error = TaskOwner::new(acceptance, sha256, new_task_id)
        .accept_verified(
            r.clone(),
            AcceptanceContext {
                authenticated_principal: "verified-principal".into(),
                provider: r.provider.clone(),
                environment_evidence: r.environment.clone(),
                capacity_reservation_id: "reserved".into(),
                now_unix: 200,
                prepare_deadline_unix: 210,
                delivery_deadline_unix: 300,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, TaskErrorCode::StateCorrupt);
    assert!(!root.join("acceptance-v1.json").exists());
}

#[test]
fn fresh_provider_persists_empty_acceptance_and_rejects_loss_before_first_task() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    assert!(store.read().unwrap().tasks.is_empty());
    assert!(root.join("acceptance-initialized-v1").is_file());
    assert!(root.join("acceptance-v1.json").is_file());
    fs::remove_file(root.join("acceptance-v1.json")).unwrap();
    assert_eq!(store.read().unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
}

#[test]
fn old_acceptance_image_migrates_receipt_without_rewriting_authority() {
    let dir = TestDir::new();
    let root = dir.root();
    let snapshots = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&snapshots);
    let first = accept(&root, &s.reference, 100);
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    fs::remove_file(root.join("acceptance-initialized-v1")).unwrap();
    let reopened = FileTaskAcceptanceStore::open(&root).unwrap();
    assert_eq!(reopened.read().unwrap().tasks[0], first.task);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
    assert!(root.join("acceptance-initialized-v1").is_file());
    assert!(accept(&root, &s.reference, 105).replayed);
}

#[test]
fn corrupt_initialization_receipt_blocks_open_and_preserves_acceptance_image() {
    let dir = TestDir::new();
    let root = dir.root();
    FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    fs::write(root.join("acceptance-initialized-v1"), b"torn").unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
    assert_eq!(
        fs::read(root.join("acceptance-initialized-v1")).unwrap(),
        b"torn"
    );
}

#[test]
fn review_regression_missing_acceptance_image_blocks_cold_restart() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    accept(&root, &s.reference, 100);
    store.release_preview(&s.reference.snapshot_id).unwrap();
    drop(store);
    let content = root.join("content-sha256-v1");
    let count = fs::read_dir(&content).unwrap().count();
    fs::remove_file(root.join("acceptance-v1.json")).unwrap();
    assert_eq!(
        FileSnapshotStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(count, fs::read_dir(content).unwrap().count());
    assert!(!root.join("acceptance-v1.json").exists());
}

#[test]
fn review_regression_restage_release_restarts_full_gc_retention() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    // 两次 stage 必须使用同一 (workspace, commit) 输入：CommitId 含 created_at_unix
    // （crates/nexus-workspace/src/lib.rs now_unix），重新构造 workspace 会跨秒产生
    // 不同 commit_id，使幂等断言退化为依赖挂钟巧合。与 fixed_commit_selection_* 同法。
    let (ws, c) = workspace();
    let s = store.stage_snapshot(&ws, &c, &selection()).unwrap();
    store.release_preview(&s.reference.snapshot_id).unwrap();
    assert_eq!(store.collect_garbage(100, 10).unwrap().marked, 3);
    assert_eq!(store.stage_snapshot(&ws, &c, &selection()).unwrap(), s);
    drop(store);
    let reopened = FileSnapshotStore::open(&root).unwrap();
    reopened.release_preview(&s.reference.snapshot_id).unwrap();
    let fresh = reopened.collect_garbage(200, 10).unwrap();
    assert_eq!(fresh.deleted, 0);
    assert_eq!(fresh.marked, 3);
    assert_eq!(reopened.collect_garbage(209, 10).unwrap().deleted, 0);
    assert_eq!(reopened.collect_garbage(210, 10).unwrap().deleted, 3);
}

#[test]
fn review_regression_prepare_release_restarts_full_gc_retention() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    store.release_preview(&s.reference.snapshot_id).unwrap();
    assert_eq!(store.collect_garbage(100, 10).unwrap().marked, 3);
    store.prepare_inputs(&s.reference, ".").unwrap();
    drop(store);
    let reopened = FileSnapshotStore::open(&root).unwrap();
    reopened.release_preview(&s.reference.snapshot_id).unwrap();
    let fresh = reopened.collect_garbage(200, 10).unwrap();
    assert_eq!(fresh.deleted, 0);
    assert_eq!(fresh.marked, 3);
    assert_eq!(reopened.collect_garbage(209, 10).unwrap().deleted, 0);
    assert_eq!(reopened.collect_garbage(210, 10).unwrap().deleted, 3);
}
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "nexus-n3-2-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn root(&self) -> PathBuf {
        self.0.join("provider")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn workspace() -> (Workspace<InMemoryContentStore>, CommitId) {
    let mut ws = Workspace::init(
        WorkspaceId("ws-n3-example".into()),
        InMemoryContentStore::new(),
        AuthorId("author".into()),
    )
    .unwrap();
    let base = ws.heads().heads[0].clone();
    let commit = ws
        .commit_changes(
            &base,
            &[
                Change {
                    path: "src/input.txt".into(),
                    content: b"original".to_vec(),
                },
                Change {
                    path: "bin/build".into(),
                    content: b"tool".to_vec(),
                },
                Change {
                    path: ".env".into(),
                    content: b"do-not-upload".to_vec(),
                },
            ],
        )
        .unwrap();
    (ws, commit)
}
fn selection() -> SnapshotSelection {
    SnapshotSelection {
        include: vec!["src".into(), "bin".into()],
        exclude: vec![],
        executable: vec!["bin/build".into()],
    }
}
fn request(snapshot: &SnapshotRef) -> SubmitTaskRequest {
    let mut r: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
        "../../../docs/contracts/n3-submit.example.json"
    ))
    .unwrap();
    r.workspace = snapshot.workspace.clone();
    r.input_snapshot = snapshot.clone();
    r.idempotency_ttl_seconds = 10;
    r
}
fn accept(root: &Path, snapshot: &SnapshotRef, now: u64) -> nexus_compute::task::AcceptanceResult {
    let r = request(snapshot);
    TaskOwner::new(
        FileTaskAcceptanceStore::open(root).unwrap(),
        sha256,
        new_task_id,
    )
    .accept_verified(
        r.clone(),
        AcceptanceContext {
            authenticated_principal: "verified-principal".into(),
            provider: r.provider.clone(),
            environment_evidence: r.environment.clone(),
            capacity_reservation_id: "reserved".into(),
            now_unix: now,
            prepare_deadline_unix: now + 10,
            delivery_deadline_unix: now + 100,
        },
    )
    .unwrap()
}
fn stage(store: &FileSnapshotStore) -> FrozenSnapshot {
    let (ws, c) = workspace();
    store.stage_snapshot(&ws, &c, &selection()).unwrap()
}

#[test]
fn fixed_commit_selection_preview_and_private_materialization() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let (mut ws, commit) = workspace();
    let frozen = store.stage_snapshot(&ws, &commit, &selection()).unwrap();
    ws.commit_changes(
        &commit,
        &[Change {
            path: "src/input.txt".into(),
            content: b"changed".to_vec(),
        }],
    )
    .unwrap();
    let repeated = store.stage_snapshot(&ws, &commit, &selection()).unwrap();
    assert_eq!(frozen, repeated);
    assert_eq!(frozen.reference.file_count, 2);
    assert_eq!(frozen.reference.total_bytes, 12);
    assert_eq!(
        frozen
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect::<Vec<_>>(),
        ["bin/build", "src/input.txt"]
    );
    assert_eq!(
        store.verify_inputs(&frozen.reference, "src").unwrap(),
        frozen
    );
    let prepared = store.prepare_inputs(&frozen.reference, "src").unwrap();
    assert_eq!(
        fs::read(prepared.directory.join("src/input.txt")).unwrap(),
        b"original"
    );
    assert!(!prepared.directory.join(".env").exists());
    assert_eq!(prepared.snapshot_id, frozen.reference.snapshot_id);
    assert_eq!(
        fs::metadata(prepared.directory.join("bin/build"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(prepared.directory.join("src/input.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        ws.read_from_head("src/input.txt").unwrap().unwrap(),
        b"changed"
    );
    let second = store.prepare_inputs(&frozen.reference, ".").unwrap();
    assert_ne!(prepared.directory, second.directory);
}

#[test]
fn canonical_manifest_matches_independent_sha256_vector() {
    // SHA-256("abc") is the published standard vector, independent of ring.
    let digest = Sha256Digest::parse(
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    )
    .unwrap();
    let file = SnapshotFile {
        path: "a.txt".into(),
        sha256: digest.clone(),
        size_bytes: 3,
        executable: false,
    };
    let expected=b"[{\"executable\":false,\"path\":\"a.txt\",\"sha256\":\"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"size_bytes\":3}]";
    assert_eq!(vec![file].to_value().canonical_bytes(), expected);
    let dir = TestDir::new();
    let store = FileSnapshotStore::open(&dir.root()).unwrap();
    store
        .acceptance
        .with_locked_ledger(|root, _| {
            let mut content = Content::open(root)?;
            content.put_verified(&digest, b"abc")?;
            assert_eq!(content.get_verified(&digest, 3)?, b"abc");
            assert_eq!(
                content.get_verified(&digest, 4).unwrap_err().code,
                TaskErrorCode::InputIntegrityFailed
            );
            assert_eq!(
                content.put_verified(&digest, b"abd").unwrap_err().code,
                TaskErrorCode::InputIntegrityFailed
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn invalid_paths_collisions_and_cwd_fail_before_creating_tree() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    for paths in [
        vec!["../escape"],
        vec!["/absolute"],
        vec!["a\\b"],
        vec!["dir", "dir/file"],
    ] {
        let mut ws = Workspace::init(
            WorkspaceId("ws-n3-example".into()),
            InMemoryContentStore::new(),
            AuthorId("author".into()),
        )
        .unwrap();
        let base = ws.heads().heads[0].clone();
        let commit = ws
            .commit_changes(
                &base,
                &paths
                    .iter()
                    .map(|p| Change {
                        path: p.to_string(),
                        content: b"x".to_vec(),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert!(
            store
                .stage_snapshot(
                    &ws,
                    &commit,
                    &SnapshotSelection {
                        include: vec![".".into()],
                        exclude: vec![],
                        executable: vec![]
                    }
                )
                .is_err()
        );
    }
    let snapshot = stage(&store);
    for cwd in ["missing", "src/input.txt", "../src"] {
        assert_eq!(
            store
                .prepare_inputs(&snapshot.reference, cwd)
                .unwrap_err()
                .code,
            TaskErrorCode::InvalidPath
        );
    }
    assert!(!fs::read_dir(root).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("input-")
    }));
}

#[test]
fn selection_version_digest_missing_commit_and_rules_are_explicit() {
    let dir = TestDir::new();
    let store = FileSnapshotStore::open(&dir.root()).unwrap();
    let (ws, c) = workspace();
    assert_eq!(
        store
            .stage_snapshot(&ws, &CommitId("missing".into()), &selection())
            .unwrap_err()
            .code,
        TaskErrorCode::InputUnavailable
    );
    for rules in [
        SnapshotSelection {
            include: vec![],
            exclude: vec![],
            executable: vec![],
        },
        SnapshotSelection {
            include: vec!["src".into(), "src".into()],
            exclude: vec![],
            executable: vec![],
        },
        SnapshotSelection {
            include: vec!["src".into()],
            exclude: vec![],
            executable: vec!["bin/build".into()],
        },
    ] {
        assert!(store.stage_snapshot(&ws, &c, &rules).is_err());
    }
    let mut missing = selection();
    missing.include.push("not-present".into());
    assert_eq!(
        store.stage_snapshot(&ws, &c, &missing).unwrap_err().code,
        TaskErrorCode::InputUnavailable
    );
    let original = selection();
    let mut reordered = original.clone();
    reordered.include.reverse();
    assert_eq!(
        original.digest(sha256).unwrap(),
        reordered.digest(sha256).unwrap()
    );
    reordered.exclude.push("src".into());
    assert_ne!(
        original.digest(sha256).unwrap(),
        reordered.digest(sha256).unwrap()
    );
    let selected = store.stage_snapshot(&ws, &c, &reordered).unwrap();
    assert_eq!(selected.reference.total_bytes, 4);
}

#[test]
fn corrupted_and_missing_inputs_block_prepare_and_gc_without_rewriting() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let snapshot = stage(&store);
    let path = root
        .join("content-sha256-v1")
        .join(&snapshot.files[0].sha256.as_str()[7..]);
    fs::write(&path, b"corrupt").unwrap();
    assert_eq!(
        store
            .prepare_inputs(&snapshot.reference, ".")
            .unwrap_err()
            .code,
        TaskErrorCode::InputIntegrityFailed
    );
    assert_eq!(
        store.collect_garbage(1000, 0).unwrap_err().code,
        TaskErrorCode::InputIntegrityFailed
    );
    assert_eq!(fs::read(&path).unwrap(), b"corrupt");
    fs::remove_file(path).unwrap();
    assert_eq!(
        store
            .verify_inputs(&snapshot.reference, ".")
            .unwrap_err()
            .code,
        TaskErrorCode::InputUnavailable
    );
    assert!(!fs::read_dir(root).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("input-")
    }));
}

#[test]
fn authenticated_snapshot_manifest_and_lengths_cannot_be_replaced() {
    let dir = TestDir::new();
    let store = FileSnapshotStore::open(&dir.root()).unwrap();
    let s = stage(&store);
    let mut reference = s.reference.clone();
    reference.commit_id = "attacker-commit".into();
    assert_eq!(
        store.verify_inputs(&reference, ".").unwrap_err().code,
        TaskErrorCode::InputIntegrityFailed
    );
    let mut bad = s.clone();
    bad.files[0].size_bytes += 1;
    assert_eq!(
        bad.validate(sha256).unwrap_err().code,
        TaskErrorCode::InputIntegrityFailed
    );
    let mut unsorted = s.clone();
    unsorted.files.reverse();
    assert!(unsorted.validate(sha256).is_err());
    let mut duplicate = s.clone();
    duplicate.files.push(s.files[0].clone());
    assert!(duplicate.validate(sha256).is_err());
}

#[test]
fn legacy_locators_never_name_strong_objects_or_override_different_content() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    assert!(
        !root
            .join("content-sha256-v1")
            .join(&s.reference.root_manifest_id)
            .exists()
    );
    assert!(
        root.join("content-sha256-v1")
            .join(&s.files[0].sha256.as_str()[7..])
            .exists()
    );
    let old_id = nexus_storage::object_id_of(b"tool");
    assert_ne!(old_id, ObjectId(s.files[0].sha256.as_str().into()));
    let mut ws = Workspace::init(
        WorkspaceId("ws-n3-example".into()),
        InMemoryContentStore::new(),
        AuthorId("author".into()),
    )
    .unwrap();
    let base = ws.heads().heads[0].clone();
    let c = ws
        .commit_changes(
            &base,
            &[Change {
                path: "bin/build".into(),
                content: b"other".to_vec(),
            }],
        )
        .unwrap();
    let changed = store
        .stage_snapshot(
            &ws,
            &c,
            &SnapshotSelection {
                include: vec!["bin".into()],
                exclude: vec![],
                executable: vec![],
            },
        )
        .unwrap();
    assert_ne!(s.files[0].sha256, changed.files[0].sha256);
    assert!(store.verify_inputs(&s.reference, ".").is_ok());
}

#[test]
fn cold_restart_expired_key_and_preview_release_preserve_all_accepted_pins() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let first = stage(&store);
    let a = accept(&root, &first.reference, 100);
    store.release_preview(&first.reference.snapshot_id).unwrap();
    let (mut ws, c) = workspace();
    let c2 = ws
        .commit_changes(
            &c,
            &[Change {
                path: "src/input.txt".into(),
                content: b"new".to_vec(),
            }],
        )
        .unwrap();
    let second = store.stage_snapshot(&ws, &c2, &selection()).unwrap();
    let b = accept(&root, &second.reference, 110);
    assert_ne!(a.task.view.task_id, b.task.view.task_id);
    store
        .release_preview(&second.reference.snapshot_id)
        .unwrap();
    drop(store);
    let reopened = FileSnapshotStore::open(&root).unwrap();
    let report = reopened.collect_garbage(10000, 0).unwrap();
    assert_eq!(report.deleted, 0);
    assert!(reopened.verify_inputs(&first.reference, ".").is_ok());
    assert!(reopened.verify_inputs(&second.reference, ".").is_ok());
    assert_eq!(
        FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .len(),
        2
    );
}

#[test]
fn two_phase_gc_respects_retention_and_independent_explicit_roots() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let frozen = stage(&store);
    store.retain_snapshot(&frozen.reference).unwrap();
    store
        .release_preview(&frozen.reference.snapshot_id)
        .unwrap();
    store
        .acceptance
        .with_locked_ledger(|root, _| {
            Content::open(root)?.put_verified(&sha256(b"orphan"), b"orphan")
        })
        .unwrap();
    let first = store.collect_garbage(100, 10).unwrap();
    assert_eq!(first.marked, 1);
    assert_eq!(first.deleted, 0);
    assert_eq!(store.collect_garbage(109, 10).unwrap().deleted, 0);
    assert_eq!(store.collect_garbage(110, 10).unwrap().deleted, 1);
    assert!(
        FileSnapshotStore::open(&root)
            .unwrap()
            .verify_inputs(&frozen.reference, ".")
            .is_ok()
    );
    // Unreferenced staging roots can be reclaimed independently of explicit roots.
    let (mut ws, c) = workspace();
    let c2 = ws
        .commit_changes(
            &c,
            &[Change {
                path: "src/input.txt".into(),
                content: b"unretained".to_vec(),
            }],
        )
        .unwrap();
    let old = store.stage_snapshot(&ws, &c2, &selection()).unwrap();
    store.release_preview(&old.reference.snapshot_id).unwrap();
    assert!(store.collect_garbage(200, 0).unwrap().deleted >= 2);
    assert_eq!(
        store.verify_inputs(&old.reference, ".").unwrap_err().code,
        TaskErrorCode::InputUnavailable
    );
    assert!(store.verify_inputs(&frozen.reference, ".").is_ok());
}

#[test]
fn missing_accepted_manifest_blocks_gc_instead_of_forgetting_pin() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    accept(&root, &s.reference, 100);
    store.release_preview(&s.reference.snapshot_id).unwrap();
    fs::remove_file(
        root.join("content-sha256-v1")
            .join(&s.reference.manifest_sha256.as_str()[7..]),
    )
    .unwrap();
    let before = fs::read_dir(root.join("content-sha256-v1"))
        .unwrap()
        .count();
    assert_eq!(
        FileSnapshotStore::open(&root)
            .unwrap()
            .collect_garbage(10000, 0)
            .unwrap_err()
            .code,
        TaskErrorCode::InputUnavailable
    );
    assert_eq!(
        before,
        fs::read_dir(root.join("content-sha256-v1"))
            .unwrap()
            .count()
    );
}

#[test]
fn symlink_device_fifo_and_escaping_roots_are_never_followed() {
    use std::os::unix::fs::symlink;
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    let path = root
        .join("content-sha256-v1")
        .join(&s.files[0].sha256.as_str()[7..]);
    fs::remove_file(&path).unwrap();
    let outside = dir.0.join("outside");
    fs::write(&outside, b"tool").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.prepare_inputs(&s.reference, ".").is_err());
    assert_eq!(fs::read(outside).unwrap(), b"tool");
    fs::remove_file(&path).unwrap();
    symlink("/dev/null", &path).unwrap();
    assert!(store.verify_inputs(&s.reference, ".").is_err());
    fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        store.verify_inputs(&s.reference, ".").unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    let linked = dir.0.join("linked-provider");
    symlink(&root, &linked).unwrap();
    assert!(FileSnapshotStore::open(&linked).is_err());
}

#[test]
fn corrupt_root_catalog_preserves_original_and_blocks_staging_and_gc() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let _ = stage(&store);
    let path = root.join("snapshot-roots-v1.json");
    fs::write(&path, b"{\"roots\":{}}").unwrap();
    assert_eq!(
        FileSnapshotStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        store.collect_garbage(1000, 0).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    let (ws, c) = workspace();
    assert_eq!(
        store
            .stage_snapshot(&ws, &c, &selection())
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(fs::read(path).unwrap(), b"{\"roots\":{}}");
}

#[test]
fn missing_initialized_root_catalog_is_corruption_not_an_empty_root_set() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    fs::remove_file(root.join("snapshot-roots-v1.json")).unwrap();
    assert_eq!(
        FileSnapshotStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        store.collect_garbage(10000, 0).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert!(
        root.join("content-sha256-v1")
            .join(&s.reference.manifest_sha256.as_str()[7..])
            .exists()
    );
}

#[test]
fn tombstoned_content_is_revalidated_and_resurrected_by_a_new_root() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    store.release_preview(&s.reference.snapshot_id).unwrap();
    assert!(store.collect_garbage(100, 10).unwrap().marked >= 3);
    store.retain_snapshot(&s.reference).unwrap();
    assert_eq!(store.collect_garbage(200, 10).unwrap().deleted, 0);
    assert!(load_catalog(&root).unwrap().tombstones.is_empty());
    assert!(store.verify_inputs(&s.reference, ".").is_ok());
}

fn child(root: &Path, action: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "snapshot_store::linux::tests::child_fixture",
            "--nocapture",
        ])
        .env("NEXUS_N3_2_CHILD_ROOT", root)
        .env("NEXUS_N3_2_CHILD_ACTION", action)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn process_crashes_at_root_publication_boundaries_recover_complete_pins() {
    for boundary in [
        "after-write",
        "after-file-sync",
        "after-rename",
        "after-directory-sync",
    ] {
        let dir = TestDir::new();
        let root = dir.root();
        let store = FileSnapshotStore::open(&root).unwrap();
        let s = stage(&store);
        let code = child(&root, boundary).wait().unwrap().code();
        assert_eq!(code, Some(91), "{boundary}");
        let reopened = FileSnapshotStore::open(&root).unwrap();
        assert!(reopened.verify_inputs(&s.reference, ".").is_ok());
        assert_eq!(reopened.collect_garbage(10000, 0).unwrap().deleted, 0);
        assert_eq!(
            load_catalog(&root).unwrap().retained.is_empty(),
            boundary == "after-write" || boundary == "after-file-sync"
        );
    }
}

#[test]
fn eight_processes_stage_materialize_and_collect_without_losing_accepted_roots() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    accept(&root, &s.reference, 100);
    let children = (0..8).map(|_| child(&root, "stage")).collect::<Vec<_>>();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    assert!(
        FileSnapshotStore::open(&root)
            .unwrap()
            .verify_inputs(&s.reference, ".")
            .is_ok()
    );
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("input-"))
            .count(),
        8
    );
}

// Parent tests explicitly execute this fixture in 12 independent processes.
#[test]
#[ignore = "subprocess fixture invoked by parent tests, not a skipped capability"]
fn child_fixture() {
    let root = PathBuf::from(std::env::var_os("NEXUS_N3_2_CHILD_ROOT").unwrap());
    let action = std::env::var("NEXUS_N3_2_CHILD_ACTION").unwrap();
    let store = FileSnapshotStore::open(&root).unwrap();
    if action == "stage" {
        let s = stage(&store);
        store.prepare_inputs(&s.reference, ".").unwrap();
        assert_eq!(store.collect_garbage(10000, 0).unwrap().deleted, 0);
        return;
    }
    store
        .acceptance
        .with_locked_ledger(|root, _| {
            let mut catalog = load_catalog(root)?;
            let snapshot = catalog.staged[0].clone();
            add_root(&mut catalog.retained, &snapshot)?;
            let payload = catalog.value();
            let bytes = Value::Object(BTreeMap::from([
                (
                    "payload_sha256".into(),
                    sha256(&payload.canonical_bytes()).to_value(),
                ),
                ("roots".into(), payload),
            ]))
            .canonical_bytes();
            atomic_publish_with(root, &root.join("snapshot-roots-v1.json"), &bytes, |at| {
                if at == action {
                    std::process::exit(91);
                }
                Ok(())
            })
        })
        .unwrap();
    panic!("requested crash boundary was not reached");
}

#[test]
fn independent_handles_stage_and_gc_share_one_acceptance_lock() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    // Compare the same frozen Commit, whose identity includes its timestamp.
    let (ws, commit) = workspace();
    let ws = std::sync::Arc::new(ws);
    let s = store.stage_snapshot(ws.as_ref(), &commit, &selection()).unwrap();
    accept(&root, &s.reference, 100);
    let threads = (0..8)
        .map(|i| {
            let root = root.clone();
            let ws = std::sync::Arc::clone(&ws);
            let commit = commit.clone();
            std::thread::spawn(move || {
                let store = FileSnapshotStore::open(&root).unwrap();
                let s = store.stage_snapshot(ws.as_ref(), &commit, &selection()).unwrap();
                assert_eq!(store.collect_garbage(1000 + i, 0).unwrap().deleted, 0);
                store.release_preview(&s.reference.snapshot_id).unwrap();
                store
                    .verify_inputs(&s.reference, ".")
                    .unwrap()
                    .reference
                    .snapshot_id
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), s.reference.snapshot_id);
    }
}

#[test]
fn root_publication_failures_preserve_last_complete_image_or_new_complete_image() {
    let dir = TestDir::new();
    let root = dir.root();
    let store = FileSnapshotStore::open(&root).unwrap();
    let s = stage(&store);
    let path = root.join("snapshot-roots-v1.json");
    let original = fs::read(&path).unwrap();
    for boundary in [
        "after-write",
        "after-file-sync",
        "after-rename",
        "after-directory-sync",
    ] {
        store
            .acceptance
            .with_locked_ledger(|root, _| {
                let mut catalog = load_catalog(root)?;
                add_root(&mut catalog.retained, &s.reference)?;
                let payload = catalog.value();
                let bytes = Value::Object(BTreeMap::from([
                    (
                        "payload_sha256".into(),
                        sha256(&payload.canonical_bytes()).to_value(),
                    ),
                    ("roots".into(), payload),
                ]))
                .canonical_bytes();
                let result = atomic_publish_with(root, &path, &bytes, |at| {
                    if at == boundary {
                        Err(TaskError::new(
                            TaskErrorCode::PersistenceFailed,
                            "injected sync/publication error",
                            true,
                        ))
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(result.unwrap_err().code, TaskErrorCode::PersistenceFailed);
                let loaded = load_catalog(root)?;
                assert_eq!(
                    loaded.retained.is_empty(),
                    boundary == "after-write" || boundary == "after-file-sync"
                );
                assert!(read_snapshot(root, &s.reference).is_ok());
                Ok(())
            })
            .unwrap();
        // Restore the previous durable fixture before testing another boundary.
        atomic_publish(&root, &path, &original).unwrap();
    }
}
