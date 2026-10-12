use super::*;
use crate::task_capacity::{CapacityBudget, ExecutorBackendOverhead};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    sync::{Arc, Mutex},
};

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    policy: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("n311-{}", new_task_id().unwrap().as_str()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let root = base.join("provider");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let policy = base.join("policy.json");
        let allocation = ProviderCapacityPolicy {
            total: CapacityBudget {
                cpu_millis: 10000,
                memory_bytes: 1024 * 1024 * 1024,
                pids: 1024,
                runtime_storage_bytes: 256 * 1024 * 1024,
                backend_disk_bytes: 1024 * 1024 * 1024,
                slots: 8,
            },
            fixed: CapacityBudget {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
                runtime_storage_bytes: 1,
                backend_disk_bytes: 1,
                slots: 1,
            },
            overhead: ExecutorBackendOverhead {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
                backend_disk_bytes: 1,
            },
        };
        fs::write(&policy, allocation.to_value().canonical_bytes()).unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        Self { base, root, policy }
    }
    fn init(&self) -> Result<ProviderStatus> {
        init(&self.root, "provider/a", "workspace/a", &self.policy)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    digest: Option<String>,
}
fn inventory(root: &Path) -> Vec<Entry> {
    fn scan(path: &Path, entries: &mut Vec<Entry>) {
        let meta = fs::symlink_metadata(path).unwrap();
        entries.push(Entry {
            path: path.to_owned(),
            device: meta.dev(),
            inode: meta.ino(),
            mode: meta.permissions().mode(),
            links: meta.nlink(),
            digest: meta
                .is_file()
                .then(|| sha256(&fs::read(path).unwrap()).as_str().to_owned()),
        });
        if meta.is_dir() {
            let mut children: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            children.sort();
            for child in children {
                scan(&child, entries);
            }
        }
    }
    let mut entries = Vec::new();
    scan(root, &mut entries);
    entries
}

#[test]
fn init_real_identity_and_capacity_then_readonly_and_duplicate_preserve_all_files() {
    let f = Fixture::new();
    assert!(!validate_managed_root(&f.root).unwrap());
    assert_eq!(
        check(&f.root).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    let status = f.init().unwrap();
    assert!(status.changed);
    assert_eq!(status.provider, "provider/a");
    let root = io::Root::open(&f.root).unwrap();
    let identity = io::read(&identity_path(&root).unwrap(), io::SMALL, true).unwrap();
    assert_eq!(
        nexus::n2_identity::principal_from_existing_bytes(&identity.bytes)
            .unwrap()
            .0,
        status.principal
    );
    assert_eq!(fs::read(task_root(&root).join(OWNER)).unwrap(), SENTINEL);
    let before = inventory(&f.root);
    assert!(validate_managed_root(&f.root).unwrap());
    assert_eq!(check(&f.root).unwrap().principal, status.principal);
    assert!(!f.init().unwrap().changed);
    assert_eq!(inventory(&f.root), before);
}

#[test]
fn duplicate_after_normal_service_recovery_keeps_live_epoch_and_owner() {
    let f = Fixture::new();
    f.init().unwrap();
    let n2 = nexus::n2_store::N2Store::open(&f.root).unwrap();
    let manager = nexus_session::SessionManager::new(
        Box::new(n2.sessions()),
        nexus_session::DEFAULT_ATTACH_WINDOW_SECS,
    );
    let service = crate::task_service::LocalTaskService::open_with_sessions(
        &f.root,
        Arc::new(Mutex::new(Some(manager))),
    );
    let path = f.root.join("data/n3/tasks/acceptance-v1.json");
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(json["capacity"]["epoch"].as_u64().unwrap() > 0);
    assert_eq!(json["capacity"]["ready"], true);
    let before = inventory(&f.root);
    check(&f.root).unwrap();
    assert!(!f.init().unwrap().changed);
    assert_eq!(inventory(&f.root), before);
    drop(service);
    assert!(!f.init().unwrap().changed);
    assert_eq!(inventory(&f.root), before);
}

#[test]
fn scope_and_policy_conflicts_are_zero_write() {
    let f = Fixture::new();
    f.init().unwrap();
    let before = inventory(&f.root);
    for (provider, workspace) in [("other", "workspace/a"), ("provider/a", "other")] {
        assert_eq!(
            init(&f.root, provider, workspace, &f.policy)
                .unwrap_err()
                .error
                .code,
            TaskErrorCode::StateCorrupt
        );
    }
    let (mut changed, _) = policy(&f.policy).unwrap();
    changed.total.cpu_millis += 1;
    fs::write(&f.policy, changed.to_value().canonical_bytes()).unwrap();
    assert_eq!(
        f.init().unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.root), before);
}

#[test]
fn every_required_authority_loss_refuses_without_rebuilding() {
    for name in [
        JOURNAL,
        RECEIPT,
        LOCK,
        "n2/n2%2Fauth-identity",
        "data/n3/tasks/acceptance-v1.json",
        "data/n3/tasks/capacity-initialized-v1",
        "data/n3/tasks/capacity-owner.lock",
    ] {
        let f = Fixture::new();
        f.init().unwrap();
        fs::remove_file(f.root.join(name)).unwrap();
        let before = inventory(&f.root);
        assert_eq!(
            check(&f.root).unwrap_err().error.code,
            TaskErrorCode::StateCorrupt,
            "{name}"
        );
        assert_eq!(
            f.init().unwrap_err().error.code,
            TaskErrorCode::StateCorrupt,
            "{name}"
        );
        assert_eq!(
            validate_managed_root(&f.root).unwrap_err().code,
            TaskErrorCode::StateCorrupt,
            "{name}"
        );
        assert_eq!(inventory(&f.root), before, "{name}");
    }
}

#[test]
fn retained_owner_sentinel_prevents_top_level_marker_downgrade() {
    let f = Fixture::new();
    f.init().unwrap();
    for name in [JOURNAL, RECEIPT, LOCK] {
        fs::remove_file(f.root.join(name)).unwrap();
    }
    let before = inventory(&f.root);
    assert_eq!(
        check(&f.root).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        f.init().unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        validate_managed_root(&f.root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.root), before);
}

#[test]
fn same_bytes_replaced_identity_owner_and_child_directory_are_rejected() {
    for name in [
        "n2/n2%2Fauth-identity",
        "data/n3/tasks/capacity-owner.lock",
        "task-api.toml",
    ] {
        let f = Fixture::new();
        f.init().unwrap();
        let path = f.root.join(name);
        let tmp = f.base.join("replacement");
        fs::write(&tmp, fs::read(&path).unwrap()).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&tmp, &path).unwrap();
        let before = inventory(&f.root);
        assert_eq!(
            check(&f.root).unwrap_err().error.code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(
            f.init().unwrap_err().error.code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(inventory(&f.root), before);
    }
    let f = Fixture::new();
    f.init().unwrap();
    fs::rename(f.root.join("n2"), f.base.join("old-n2")).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(f.root.join("n2"))
        .unwrap();
    let before = inventory(&f.root);
    assert_eq!(
        f.init().unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.root), before);
}

#[test]
fn malformed_policy_nonfresh_and_bad_daemon_fail_before_lease_creation() {
    for raw in [
        b"{}".as_slice(),
        b"{\"total\":1e3}",
        b"{\"total\":1.5}",
        b"{\"a\":1,\"a\":2}",
    ] {
        let f = Fixture::new();
        fs::write(&f.policy, raw).unwrap();
        let before = inventory(&f.root);
        assert_eq!(
            f.init().unwrap_err().error.code,
            TaskErrorCode::InvalidRequest
        );
        assert_eq!(inventory(&f.root), before);
    }
    for (name, bytes) in [
        ("old-state", b"keep".as_slice()),
        ("daemon.toml", b"[tun]\nenabled=true\n"),
    ] {
        let f = Fixture::new();
        fs::write(f.root.join(name), bytes).unwrap();
        let before = inventory(&f.root);
        assert_eq!(
            f.init().unwrap_err().error.code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(inventory(&f.root), before);
    }
}

#[test]
fn invalid_policy_file_constraints_do_not_create_authority() {
    for kind in ["oversize", "directory", "hardlink", "symlink", "writable"] {
        let f = Fixture::new();
        match kind {
            "oversize" => fs::write(&f.policy, vec![b' '; io::SMALL as usize + 1]).unwrap(),
            "directory" => {
                fs::remove_file(&f.policy).unwrap();
                fs::create_dir(&f.policy).unwrap();
            }
            "hardlink" => fs::hard_link(&f.policy, f.base.join("linked")).unwrap(),
            "symlink" => {
                fs::rename(&f.policy, f.base.join("original")).unwrap();
                std::os::unix::fs::symlink(f.base.join("original"), &f.policy).unwrap();
            }
            "writable" => {
                fs::set_permissions(&f.policy, fs::Permissions::from_mode(0o622)).unwrap();
            }
            _ => unreachable!(),
        }
        let before = inventory(&f.root);
        let failure = f.init().unwrap_err();
        assert_eq!(failure.error.code, TaskErrorCode::InvalidRequest, "{kind}");
        assert!(!failure.error.retryable, "{kind}");
        assert!(!failure.mutation_may_have_applied, "{kind}");
        assert_eq!(inventory(&f.root), before, "{kind}");
    }
    let f = Fixture::new();
    let before = inventory(&f.root);
    let missing_parent = f.base.join("absent/policy.json");
    assert_eq!(
        init(&f.root, "provider/a", "workspace/a", &missing_parent)
            .unwrap_err()
            .error
            .code,
        TaskErrorCode::PersistenceFailed
    );
    assert_eq!(inventory(&f.root), before);

    let (_, record) = policy(&f.policy).unwrap();
    fs::write(f.base.join("replacement-policy"), &record.bytes).unwrap();
    fs::set_permissions(
        f.base.join("replacement-policy"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::rename(f.base.join("replacement-policy"), &f.policy).unwrap();
    assert_eq!(
        check_policy(&record).unwrap_err().error.code,
        TaskErrorCode::InvalidRequest
    );
}

#[test]
fn completed_init_serializes_on_original_lease_but_check_does_not_acquire_it() {
    let f = Fixture::new();
    f.init().unwrap();
    let root = io::Root::open(&f.root).unwrap();
    let lease = io::Lease::acquire(&root, &f.root.join(LOCK), false).unwrap();
    let before = inventory(&f.root);
    let failure = f.init().unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::CapacityUnavailable);
    assert!(failure.error.retryable);
    assert!(!failure.mutation_may_have_applied);
    check(&f.root).unwrap();
    assert_eq!(inventory(&f.root), before);
    drop(lease);
    assert!(!f.init().unwrap().changed);
    assert_eq!(inventory(&f.root), before);
}

#[test]
fn pending_identity_capacity_losses_and_unknown_remnants_are_zero_write() {
    for name in [
        "acceptance.lock",
        OWNER,
        "acceptance-v1.json",
        "acceptance-initialized-v1",
        "task-runtime-v1.json",
        "task-runtime-initialized-v1",
        "capacity-initialized-v1",
        "unknown-remnant",
    ] {
        let f = Fixture::new();
        f.init().unwrap();
        identity_checkpoint(&f);
        let tasks = f.root.join("data/n3/tasks");
        if name == "unknown-remnant" {
            fs::write(tasks.join(name), b"preserve evidence").unwrap();
        } else {
            fs::remove_file(tasks.join(name)).unwrap();
        }
        let before = inventory(&f.root);
        let failure = f.init().unwrap_err();
        assert_eq!(failure.error.code, TaskErrorCode::StateCorrupt, "{name}");
        assert!(!failure.mutation_may_have_applied, "{name}");
        assert_eq!(inventory(&f.root), before, "{name}");
    }
}

fn identity_checkpoint(f: &Fixture) {
    let root = io::Root::open(&f.root).unwrap();
    let (mut state, _, _) = complete(&root).unwrap();
    state.phase = "identity".into();
    state.owner = None;
    state.acceptance_lock = None;
    state.scope = None;
    fs::write(f.root.join(JOURNAL), state.bytes()).unwrap();
    fs::remove_file(f.root.join(RECEIPT)).unwrap();
    fs::remove_file(f.root.join("task-api.toml")).unwrap();
}

#[test]
fn original_complete_capacity_checkpoint_resumes_without_republishing_authority() {
    for empty_owner in [false, true] {
        let f = Fixture::new();
        let original = f.init().unwrap();
        identity_checkpoint(&f);
        let tasks = f.root.join("data/n3/tasks");
        if empty_owner {
            fs::write(tasks.join(OWNER), b"").unwrap();
        }
        let mut before = inventory(&tasks);
        let owner_before = before
            .iter()
            .find(|entry| entry.path == tasks.join(OWNER))
            .unwrap();
        let owner_binding = (owner_before.device, owner_before.inode);
        before.retain(|entry| entry.path != tasks.join(OWNER));
        let recovered = f.init().unwrap();
        assert!(recovered.changed);
        assert_eq!(recovered.principal, original.principal);
        let mut after = inventory(&tasks);
        let owner_after = after
            .iter()
            .find(|entry| entry.path == tasks.join(OWNER))
            .unwrap();
        assert_eq!((owner_after.device, owner_after.inode), owner_binding);
        after.retain(|entry| entry.path != tasks.join(OWNER));
        assert_eq!(before, after);
        assert_eq!(fs::read(tasks.join(OWNER)).unwrap(), SENTINEL);
        check(&f.root).unwrap();
    }
}

#[test]
fn checks_use_original_acceptance_nonblocking_lease_without_writes() {
    let f = Fixture::new();
    f.init().unwrap();
    let root = io::Root::open(&f.root).unwrap();
    let lease =
        io::Lease::acquire(&root, &task_root(&root).join("acceptance.lock"), false).unwrap();
    let before = inventory(&f.root);
    let failure = check(&f.root).unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::CapacityUnavailable);
    assert!(failure.error.retryable);
    assert!(!failure.mutation_may_have_applied);
    assert_eq!(inventory(&f.root), before);
    drop(lease);
    check(&f.root).unwrap();
}

#[test]
fn original_record_and_root_fd_bindings_detect_replacement() {
    let f = Fixture::new();
    let root = io::Root::open(&f.root).unwrap();
    let record = io::create_file(&root, &f.root.join("record"), b"same").unwrap();
    fs::write(f.base.join("new"), b"same").unwrap();
    fs::set_permissions(f.base.join("new"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(f.base.join("new"), &record.path).unwrap();
    assert_eq!(
        record.check().unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    fs::rename(&f.root, f.base.join("old-root")).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&f.root).unwrap();
    assert_eq!(
        root.check().unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
}
