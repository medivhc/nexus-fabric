//! Persistence and ownership boundaries of the real private adapter.
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

struct Fixture {
    root: PathBuf,
    principal: Principal,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "n310-grant-{}",
            crate::n3_acceptance::new_task_id().unwrap().as_str()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("n2"))
            .unwrap();
        fs::write(
            root.join("task-api.toml"),
            "provider = 'actual-provider'\nworkspace = 'scoped-workspace'\n",
        )
        .unwrap();
        fs::set_permissions(
            root.join("task-api.toml"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let mut public = [0; 32];
        public.copy_from_slice(pair.public_key().as_ref());
        let principal = Principal::from_ed25519_public_key(&public);
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let identity = json!({"version":1,"seed_hex":hex(&[7;32]),"public_key_hex":hex(&public),"created_at_unix":1});
        let path = root
            .join("n2")
            .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap());
        fs::write(&path, serde_json::to_vec(&identity).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        Self { root, principal }
    }
    fn command(&self, operation: &str, extra: &[&str]) -> Command {
        let mut args = vec![
            "grant".into(),
            operation.into(),
            "--config".into(),
            self.root.display().to_string(),
        ];
        if operation != "list" {
            args.extend([
                "--resource".into(),
                "compute-resource".into(),
                "--self".into(),
            ]);
        }
        args.extend(extra.iter().map(|value| value.to_string()));
        super::super::parse(&args).unwrap()
    }
    fn path(&self) -> PathBuf {
        let reference = ResourceRef::new(
            WorkspaceId::new("scoped-workspace"),
            ResourceName::new("compute-resource").unwrap(),
        );
        self.root
            .join("n2")
            .join(grant_filename(&reference, &self.principal).unwrap())
    }
    fn audit(&self) -> PathBuf {
        self.root.join("n2/task-provider-grant-audit-v1.jsonl")
    }
    fn write_grant(&self, operations: Vec<ResourceOperation>) -> Vec<u8> {
        let grant = Grant::new(
            ResourceRef::new(
                WorkspaceId::new("scoped-workspace"),
                ResourceName::new("compute-resource").unwrap(),
            ),
            self.principal.clone(),
            operations,
            None,
        );
        let bytes = serde_json::to_vec_pretty(&crate::n2_store::encode_grant(&grant)).unwrap();
        fs::write(self.path(), &bytes).unwrap();
        fs::set_permissions(self.path(), fs::Permissions::from_mode(0o644)).unwrap();
        bytes
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn explicit_scoped_mutations_feed_existing_n2_decoder_and_preserve_noops() {
    let fixture = Fixture::new();
    let original = fixture.write_grant(vec![ResourceOperation::Use]);
    let noop = execute(&fixture.command("add", &[])).unwrap();
    assert_eq!(noop["changed"], false);
    assert_eq!(fs::read(fixture.path()).unwrap(), original);
    assert!(!fixture.audit().exists());
    assert_eq!(
        execute(&fixture.command("revoke", &[])).unwrap()["changed"],
        true
    );
    let store = crate::n2_store::N2Store::open(&fixture.root).unwrap();
    let decoded = store.load_grants().unwrap();
    assert_eq!(decoded.len(), 1);
    assert!(decoded[0].revoked);
    assert_eq!(decoded[0].resource.workspace.0, "scoped-workspace");
    let audit_before = fs::read(fixture.audit()).unwrap();
    assert_eq!(
        execute(&fixture.command("revoke", &[])).unwrap()["changed"],
        false
    );
    assert_eq!(fs::read(fixture.audit()).unwrap(), audit_before);
    assert_eq!(
        execute(&fixture.command("add", &["--not-after", "0"])).unwrap()["changed"],
        true
    );
    assert_eq!(
        execute(&fixture.command("list", &[])).unwrap()["grants"][0]["not_after"],
        0
    );
    let roots = io::Roots::open(&fixture.root).unwrap();
    assert!(
        audit::Journal::load(
            &roots,
            &json!({"provider":"actual-provider","workspace":"scoped-workspace"})
        )
        .is_ok()
    );
    assert_eq!(
        fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn non_use_operations_cannot_be_lost_but_remain_listable() {
    let fixture = Fixture::new();
    for operations in [
        vec![ResourceOperation::Manage],
        vec![ResourceOperation::Use, ResourceOperation::Manage],
        vec![],
        vec![ResourceOperation::Use, ResourceOperation::Use],
    ] {
        let bytes = fixture.write_grant(operations.clone());
        for operation in ["add", "revoke"] {
            assert_eq!(
                execute(&fixture.command(operation, &[]))
                    .unwrap_err()
                    .error
                    .code,
                TaskErrorCode::AuthDenied
            );
            assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
        }
        let listed = execute(&fixture.command("list", &[])).unwrap();
        assert_eq!(
            listed["grants"][0]["operations"].as_array().unwrap().len(),
            operations.len()
        );
        assert!(!fixture.audit().exists());
    }
}

#[test]
fn missing_revoke_is_a_true_noop_without_creating_grant_or_audit() {
    let fixture = Fixture::new();
    let result = execute(&fixture.command("revoke", &[])).unwrap();
    assert_eq!(result["changed"], false);
    assert!(result["grant"].is_null());
    assert!(!fixture.path().exists());
    assert!(!fixture.audit().exists());
}

#[test]
fn rename_followed_by_sync_failure_is_unknown_and_blocks_even_noop_mutations() {
    let fixture = Fixture::new();
    io::set_test_fault("after_grant_rename");
    let failure = execute(&fixture.command("add", &[])).unwrap_err();
    assert_eq!(failure.phase, "grant_sync");
    assert!(failure.may_have_applied);
    assert!(fixture.path().is_file());
    let bytes = fs::read(fixture.path()).unwrap();
    let audit = fs::read(fixture.audit()).unwrap();
    assert_eq!(audit.iter().filter(|b| **b == b'\n').count(), 1);
    assert_eq!(
        execute(&fixture.command("add", &[]))
            .unwrap_err()
            .error
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    assert_eq!(fs::read(fixture.audit()).unwrap(), audit);
    assert_eq!(
        execute(&fixture.command("list", &[])).unwrap()["grants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn actual_busy_lease_and_replaced_inode_are_rejected() {
    let fixture = Fixture::new();
    let roots = io::Roots::open(&fixture.root).unwrap();
    let lease = io::Lease::acquire(&roots).unwrap();
    let failure = execute(&fixture.command("add", &[])).unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::CapacityUnavailable);
    assert!(failure.error.retryable);
    let path = roots.n2.join("task-provider-grants.lock");
    fs::rename(&path, roots.n2.join("retained-original-lease")).unwrap();
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(lease.check(&roots).is_err());
    assert!(!fixture.path().exists());
}

#[test]
fn list_does_not_require_identity_or_touch_audit_lock_or_orphan_tmp() {
    let fixture = Fixture::new();
    fixture.write_grant(vec![ResourceOperation::Use]);
    let identity = fixture
        .root
        .join("n2")
        .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap());
    fs::remove_file(identity).unwrap();
    fs::write(fixture.audit(), b"broken audit\n").unwrap();
    let temporary = fixture.root.join("n2/.tmp-deliberately-retained");
    fs::write(&temporary, b"forensic temporary bytes").unwrap();
    let listed = execute(&fixture.command("list", &[])).unwrap();
    assert_eq!(listed["grants"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&temporary).unwrap(), b"forensic temporary bytes");
    assert_eq!(fs::read(fixture.audit()).unwrap(), b"broken audit\n");
    assert!(!fixture.root.join("n2/task-provider-grants.lock").exists());
}

#[test]
fn record_hardlinks_symlinks_and_content_filename_mismatch_fail_without_repair() {
    let fixture = Fixture::new();
    let bytes = fixture.write_grant(vec![ResourceOperation::Use]);
    let retained = fixture.root.join("n2/retained-grant");
    fs::hard_link(fixture.path(), &retained).unwrap();
    assert!(execute(&fixture.command("list", &[])).is_err());
    assert!(execute(&fixture.command("add", &[])).is_err());
    fs::remove_file(fixture.path()).unwrap();
    std::os::unix::fs::symlink(&retained, fixture.path()).unwrap();
    assert!(execute(&fixture.command("list", &[])).is_err());
    assert_eq!(fs::read(&retained).unwrap(), bytes);
    fs::remove_file(fixture.path()).unwrap();
    fs::remove_file(retained).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["workspace"] = json!("other-workspace");
    fs::write(fixture.path(), serde_json::to_vec(&value).unwrap()).unwrap();
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(execute(&fixture.command("list", &[])).is_err());
}

#[test]
fn existing_identity_decoder_rejects_changed_public_unknown_fields_and_duplicates() {
    let fixture = Fixture::new();
    let path = fixture
        .root
        .join("n2")
        .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap());
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        crate::n2_identity::principal_from_existing_bytes(&bytes).unwrap(),
        fixture.principal
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let mut changed = value.clone();
    changed["public_key_hex"] = json!("00".repeat(32));
    assert!(
        crate::n2_identity::principal_from_existing_bytes(&serde_json::to_vec(&changed).unwrap())
            .is_err()
    );
    let mut changed = value;
    changed["unexpected"] = json!(true);
    assert!(
        crate::n2_identity::principal_from_existing_bytes(&serde_json::to_vec(&changed).unwrap())
            .is_err()
    );
    assert!(
        crate::n2_identity::principal_from_existing_bytes(b"{\"version\":1,\"version\":1}")
            .is_err()
    );
}

#[test]
fn slash_workspace_prefixes_are_distinct_before_any_record_io() {
    let fixture = Fixture::new();
    let records = ["a", "a/b"].map(|workspace| {
        let grant = Grant::new(
            ResourceRef::new(
                WorkspaceId::new(workspace),
                ResourceName::new("compute-resource").unwrap(),
            ),
            fixture.principal.clone(),
            vec![ResourceOperation::Use],
            None,
        );
        let path = fixture
            .root
            .join("n2")
            .join(grant_filename(&grant.resource, &grant.principal).unwrap());
        let bytes = canonical(&crate::n2_store::encode_grant(&grant)).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (path, bytes)
    });
    for (index, workspace) in ["a", "a/b"].into_iter().enumerate() {
        fs::write(
            fixture.root.join("task-api.toml"),
            format!("provider = 'actual-provider'\nworkspace = '{workspace}'\n"),
        )
        .unwrap();
        let other = &records[1 - index];
        let current = &records[index];
        for extra in [vec![], vec!["--resource", "compute-resource"]] {
            let listed = execute(&fixture.command("list", &extra)).unwrap();
            assert_eq!(listed["scope"]["workspace"], workspace);
            assert_eq!(listed["grants"].as_array().unwrap().len(), 1);
        }
        // An unreadable other-scope entry must never be followed or opened.
        fs::remove_file(&other.0).unwrap();
        std::os::unix::fs::symlink("/nonexistent/n310-other-scope", &other.0).unwrap();
        assert_eq!(
            execute(&fixture.command("list", &[])).unwrap()["grants"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // Scope selection does not weaken strict parsing of the current file.
        fs::write(&current.0, b"invalid current grant\n").unwrap();
        assert_eq!(
            execute(&fixture.command("list", &[]))
                .unwrap_err()
                .error
                .code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(fs::read(&current.0).unwrap(), b"invalid current grant\n");
        fs::write(&current.0, &current.1).unwrap();
        fs::remove_file(&other.0).unwrap();
        fs::write(&other.0, &other.1).unwrap();
        fs::set_permissions(&other.0, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn replacing_a_held_grant_with_identical_private_bytes_cannot_authorize_publish() {
    let fixture = Fixture::new();
    let original = fixture.write_grant(vec![ResourceOperation::Use]);
    let roots = io::Roots::open(&fixture.root).unwrap();
    let lease = io::Lease::acquire(&roots).unwrap();
    let before = io::read(&fixture.path(), false).unwrap();
    let replacement = roots.n2.join("private-identical-replacement");
    fs::write(&replacement, &original).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    let retained = roots.n2.join("original-grant-inode");
    fs::rename(fixture.path(), &retained).unwrap();
    fs::rename(&replacement, fixture.path()).unwrap();
    assert_ne!(
        io::identity(&before.file.metadata().unwrap()),
        io::identity(&fs::metadata(fixture.path()).unwrap())
    );
    let replacement_identity = io::identity(&fs::metadata(fixture.path()).unwrap());
    let failure = io::atomic_grant(
        &roots,
        &lease,
        &fixture.path(),
        Some(&before),
        b"must not be published",
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::StateCorrupt);
    assert!(!failure.may_have_applied);
    assert_eq!(fs::read(fixture.path()).unwrap(), original);
    assert_eq!(
        io::identity(&fs::metadata(fixture.path()).unwrap()),
        replacement_identity
    );
    assert_eq!(fs::read(retained).unwrap(), original);
    assert!(!fixture.audit().exists());
}

#[test]
fn original_grant_content_and_scope_are_rechecked_after_temporary_write() {
    let fixture = Fixture::new();
    fixture.write_grant(vec![ResourceOperation::Use]);
    let roots = io::Roots::open(&fixture.root).unwrap();
    let lease = io::Lease::acquire(&roots).unwrap();
    let before = io::read(&fixture.path(), false).unwrap();
    let original_identity = io::identity(&before.file.metadata().unwrap());
    let failure = io::atomic_grant(
        &roots,
        &lease,
        &fixture.path(),
        Some(&before),
        b"must not be published",
        || {
            fs::write(fixture.path(), b"changed in-place while preparing").unwrap();
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::StateCorrupt);
    assert!(!failure.may_have_applied);
    assert_eq!(
        io::identity(&fs::metadata(fixture.path()).unwrap()),
        original_identity
    );
    assert_eq!(
        fs::read(fixture.path()).unwrap(),
        b"changed in-place while preparing"
    );
    // The final caller-bound check can refuse publication after temporary IO.
    let updated = io::read(&fixture.path(), false).unwrap();
    let scope = Scope::open(&roots).unwrap();
    let failure = io::atomic_grant(
        &roots,
        &lease,
        &fixture.path(),
        Some(&updated),
        b"must not be published",
        || {
            fs::write(
                roots.config.join("task-api.toml"),
                "provider = 'changed-provider'\nworkspace = 'scoped-workspace'\n",
            )
            .unwrap();
            scope.check(&roots)
        },
    )
    .unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::StateCorrupt);
    assert!(!failure.may_have_applied);
    assert_eq!(
        fs::read(fixture.path()).unwrap(),
        b"changed in-place while preparing"
    );
}

#[test]
fn noop_rejects_same_bytes_on_a_replaced_grant_and_newly_appeared_authority() {
    for missing in [false, true] {
        let fixture = Fixture::new();
        let bytes = fixture.write_grant(vec![ResourceOperation::Use]);
        if missing {
            fs::remove_file(fixture.path()).unwrap();
        }
        let path = fixture.path();
        let replacement = fixture.root.join("n2/noop-replacement");
        let retained = fixture.root.join("n2/noop-original");
        let original = bytes.clone();
        AUTHORITY_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some((
                "noop",
                Box::new(move || {
                    fs::write(&replacement, &original).unwrap();
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                    if !missing {
                        fs::rename(&path, &retained).unwrap();
                    }
                    fs::rename(&replacement, &path).unwrap();
                }),
            ))
        });
        let failure =
            execute(&fixture.command(if missing { "revoke" } else { "add" }, &[])).unwrap_err();
        assert_eq!(failure.error.code, TaskErrorCode::StateCorrupt);
        assert!(!failure.may_have_applied);
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
        assert!(!fixture.audit().exists());
        assert!(AUTHORITY_TEST_HOOK.with(|slot| slot.borrow().is_none()));
    }
}

#[test]
fn late_grant_or_audit_replacement_preserves_grant_and_dangling_intent() {
    for replace_audit in [false, true] {
        let fixture = Fixture::new();
        let original = fixture.write_grant(vec![ResourceOperation::Use]);
        let path = if replace_audit {
            fixture.audit()
        } else {
            fixture.path()
        };
        let replacement = fixture.root.join("n2/publish-replacement");
        let retained = fixture.root.join("n2/publish-original");
        AUTHORITY_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some((
                "publish",
                Box::new(move || {
                    let bytes = fs::read(&path).unwrap();
                    let identity = io::identity(&fs::metadata(&path).unwrap());
                    fs::write(&replacement, bytes).unwrap();
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::rename(&path, &retained).unwrap();
                    fs::rename(&replacement, &path).unwrap();
                    assert_ne!(identity, io::identity(&fs::metadata(&path).unwrap()));
                }),
            ))
        });
        let failure = execute(&fixture.command("revoke", &[])).unwrap_err();
        assert_eq!(failure.error.code, TaskErrorCode::StateCorrupt);
        assert_eq!(failure.phase, "grant_write");
        assert!(!failure.may_have_applied);
        assert_eq!(fs::read(fixture.path()).unwrap(), original);
        let audit = fs::read_to_string(fixture.audit()).unwrap();
        let records: Vec<serde_json::Value> = audit
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["phase"], "intent");
        if replace_audit {
            assert_eq!(
                fs::read_to_string(fixture.root.join("n2/publish-original")).unwrap(),
                audit
            );
        }
        assert_eq!(
            execute(&fixture.command("revoke", &[]))
                .unwrap_err()
                .error
                .code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(
            execute(&fixture.command("list", &[])).unwrap()["grants"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(AUTHORITY_TEST_HOOK.with(|slot| slot.borrow().is_none()));
    }
}
