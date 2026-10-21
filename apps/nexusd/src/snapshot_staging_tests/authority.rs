use super::*;

#[test]
fn policy_exact_integer_limits_strict_fields_and_conflicts_are_zero_write() {
    for bytes in [
        "{\"schema_version\":1,\"max_reserved_bytes\":16777215,\"max_active_uploads\":1}",
        "{\"schema_version\":1,\"max_reserved_bytes\":0,\"max_active_uploads\":1}",
        "{\"schema_version\":1,\"max_reserved_bytes\":9007199254740992,\"max_active_uploads\":1}",
        "{\"schema_version\":1,\"max_reserved_bytes\":1e8,\"max_active_uploads\":1}",
        "{\"schema_version\":1,\"max_reserved_bytes\":16777216,\"max_active_uploads\":0}",
        "{\"schema_version\":1,\"max_reserved_bytes\":16777216,\"max_active_uploads\":9}",
        "{\"schema_version\":2,\"max_reserved_bytes\":16777216,\"max_active_uploads\":1}",
        "{\"schema_version\":1,\"max_reserved_bytes\":16777216,\"max_active_uploads\":1,\"extra\":0}",
        "{\"schema_version\":1,\"max_reserved_bytes\":16777216,\"max_reserved_bytes\":16777217,\"max_active_uploads\":1}",
    ] {
        let f = Fixture::standard();
        private_file(&f.budget, bytes.as_bytes());
        let before = inventory(&f.root);
        assert!(
            initialize(&f.root, &f.budget).is_err(),
            "strict invalid budget {bytes}"
        );
        assert_eq!(inventory(&f.root), before);
    }
    let f = Fixture::new(GLOBAL, 1);
    f.initialize();
    let before = inventory(&f.namespace());
    private_file(
        &f.budget,
        b"{\"schema_version\":1,\"max_reserved_bytes\":16777217,\"max_active_uploads\":1}",
    );
    assert_eq!(
        initialize(&f.root, &f.budget).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.namespace()), before);
}
#[test]
fn staging_init_rejects_unmanaged_provider_before_writes() {
    let f = Fixture::standard();
    let empty = f.base.join("unmanaged");
    private_dir(&empty);
    let before = inventory(&empty);
    assert!(initialize(&empty, &f.budget).is_err());
    assert_eq!(inventory(&empty), before);
}
#[test]
fn legal_64k_chunk_works_and_file_total_manifest_caps_reject_before_writes() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    // At 1024 distinct entries the manifest cap may bind first; both are hard caps.
    let large = vec![7u8; 65_536];
    let i = Input::new(&[("blob", &large)]);
    let v = s.execute(&c, i.begin("chunk-boundary")).unwrap();
    assert_eq!(
        s.execute(&c, i.chunk(&v.upload_id, 0, &large))
            .unwrap()
            .blobs[0]
            .durable_offset,
        65_536
    );
    let before = inventory(&f.namespace());
    for mutation in ["files", "total", "manifest"] {
        let mut req = Input::small().begin(mutation);
        if let SnapshotRequest::Begin {
            snapshot,
            manifest_json,
            ..
        } = &mut req
        {
            match mutation {
                "files" => snapshot.file_count = 1025,
                "total" => snapshot.total_bytes = 67_108_865,
                _ => *manifest_json = " ".repeat(65_537),
            }
        }
        assert!(s.execute(&c, req).is_err());
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn invalid_manifests_and_snapshot_bindings_fail_without_reservation() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    // A real accepted control rules out a fixture rejected for an unrelated
    // scope or manifest-binding error before the isolated semantic negatives.
    assert_eq!(
        s.execute(&c, i.begin("valid-control")).unwrap().snapshot,
        i.snapshot
    );
    let before = inventory(&f.namespace());
    for mutation in [
        "noncanonical",
        "duplicatepath",
        "unknownfield",
        "manifestdigest",
        "snapshotdigest",
        "filecount",
        "totalbytes",
        "workspace",
        "duplicate-digest-size",
    ] {
        let mut req = i.begin(mutation);
        if let SnapshotRequest::Begin {
            snapshot,
            manifest_json,
            ..
        } = &mut req
        {
            match mutation {
                "noncanonical" => *manifest_json = format!(" {manifest_json}"),
                "duplicatepath" => {
                    let file = String::from_utf8(i.files[0].to_value().canonical_bytes()).unwrap();
                    *manifest_json = format!("[{file},{file}]");
                }
                "unknownfield" => {
                    let Value::Object(mut fields) = i.files[0].to_value() else {
                        unreachable!()
                    };
                    fields.insert("extra".into(), Value::Integer(0));
                    *manifest_json = String::from_utf8(
                        Value::Array(vec![Value::Object(fields)]).canonical_bytes(),
                    )
                    .unwrap();
                }
                "manifestdigest" => snapshot.manifest_sha256 = sha256(b"wrong"),
                "snapshotdigest" => snapshot.snapshot_id = sha256(b"wrong"),
                "filecount" => snapshot.file_count += 1,
                "totalbytes" => snapshot.total_bytes += 1,
                "workspace" => snapshot.workspace = "foreign".into(),
                _ => {
                    let mut changed = i.files[0].clone();
                    changed.path = "other".into();
                    changed.size_bytes += 1;
                    *manifest_json = String::from_utf8(
                        vec![i.files[0].clone(), changed]
                            .to_value()
                            .canonical_bytes(),
                    )
                    .unwrap();
                }
            }
        }
        if let SnapshotRequest::Begin {
            snapshot,
            manifest_json,
            ..
        } = &mut req
        {
            if matches!(
                mutation,
                "noncanonical" | "duplicatepath" | "unknownfield" | "duplicate-digest-size"
            ) {
                // Isolate the semantic defect from unrelated integrity mismatches.
                snapshot.manifest_sha256 = sha256(manifest_json.as_bytes());
                if matches!(mutation, "duplicatepath" | "duplicate-digest-size") {
                    snapshot.file_count = 2;
                    snapshot.total_bytes = if mutation == "duplicatepath" { 12 } else { 13 };
                }
            }
            if mutation != "snapshotdigest" {
                let Value::Object(mut fields) = snapshot.to_value() else {
                    unreachable!()
                };
                fields.remove("snapshot_id");
                snapshot.snapshot_id = sha256(&Value::Object(fields).canonical_bytes());
            }
        }
        assert!(s.execute(&c, req).is_err(), "invalid input {mutation}");
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn lost_fixed_authority_never_rebuilds_and_retained_marker_detects_namespace_loss() {
    for name in [
        "ledger-v1.json",
        "staging.lock",
        "policy-v1.json",
        "uploads",
    ] {
        let f = Fixture::standard();
        f.initialize();
        let path = f.namespace().join(name);
        if path.is_dir() {
            fs::remove_dir_all(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        let before = inventory(&f.root);
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(inventory(&f.root), before);
        assert_eq!(
            initialize(&f.root, &f.budget).unwrap_err().error.code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(inventory(&f.root), before);
    }
    let f = Fixture::standard();
    f.initialize();
    fs::remove_dir_all(f.namespace()).unwrap();
    let before = inventory(&f.root);
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    assert_eq!(inventory(&f.root), before);
    assert_eq!(
        initialize(&f.root, &f.budget).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.root), before);
}
#[test]
fn replaced_lock_inode_and_corrupt_ledger_reject_cold_and_live_operations() {
    for what in ["lock", "ledger"] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let v = s.execute(&c, i.begin("x")).unwrap();
        let p = f.namespace().join(if what == "lock" {
            "staging.lock"
        } else {
            "ledger-v1.json"
        });
        let bytes = fs::read(&p).unwrap();
        if what == "lock" {
            fs::rename(&p, f.base.join("old-lock")).unwrap();
            private_file(&p, &bytes);
        } else {
            private_file(&p, b"{broken}");
        }
        let before = inventory(&f.root);
        assert_code(
            s.execute(
                &c,
                SnapshotRequest::Get {
                    upload_id: v.upload_id,
                },
            ),
            TaskErrorCode::StateCorrupt,
        );
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        // Authentication is permitted to append audit; staging authority is immutable on rejection.
        let staging_before = before
            .into_iter()
            .filter(|e| e.relative.starts_with("data/n3/snapshot-staging-v1"))
            .collect::<Vec<_>>();
        let staging_after = inventory(&f.root)
            .into_iter()
            .filter(|e| e.relative.starts_with("data/n3/snapshot-staging-v1"))
            .collect::<Vec<_>>();
        assert_eq!(staging_after, staging_before);
        let unchanged = inventory(&f.root);
        assert_eq!(
            initialize(&f.root, &f.budget).unwrap_err().error.code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(inventory(&f.root), unchanged);
    }
}
#[test]
fn confirmed_prefix_missing_changed_and_unexplained_tail_preserve_evidence_and_charge() {
    for corruption in ["missing", "changed", "tail"] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let v = s.execute(&c, i.begin("x")).unwrap();
        s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
        drop(s);
        let p = f.payload(&v.upload_id, &i.files[0].sha256);
        match corruption {
            "missing" => fs::remove_file(&p).unwrap(),
            "changed" => fs::write(&p, b"xyz").unwrap(),
            _ => fs::write(&p, b"abcd").unwrap(),
        };
        let before = inventory(&f.namespace());
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn unknown_namespace_file_and_unowned_temp_fail_closed_without_cleanup() {
    for name in ["unknown", ".ledger-v1.tmp"] {
        let f = Fixture::standard();
        f.initialize();
        private_file(&f.namespace().join(name), b"forensic-decoy");
        let before = inventory(&f.namespace());
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn symlink_hardlink_and_nonprivate_authority_are_rejected_without_touching_decoy() {
    for kind in ["symlink", "hardlink", "mode"] {
        let f = Fixture::standard();
        f.initialize();
        let p = f.namespace().join("ledger-v1.json");
        let bytes = fs::read(&p).unwrap();
        let decoy = f.base.join("decoy");
        private_file(&decoy, &bytes);
        match kind {
            "symlink" => {
                fs::remove_file(&p).unwrap();
                symlink(&decoy, &p).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&p).unwrap();
                fs::hard_link(&decoy, &p).unwrap();
            }
            _ => fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap(),
        };
        let before = inventory(&f.namespace());
        let decoy_before = inventory(&decoy);
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(inventory(&decoy), decoy_before);
    }
}
#[test]
fn same_bytes_provider_identity_inode_replacement_does_not_rebind_staging() {
    let f = Fixture::standard();
    f.initialize();
    let identity = f
        .root
        .join("n2")
        .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap());
    let bytes = fs::read(&identity).unwrap();
    fs::rename(&identity, f.base.join("old-identity")).unwrap();
    private_file(&identity, &bytes);
    let before = inventory(&f.namespace());
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    assert_eq!(inventory(&f.namespace()), before);
    let whole = inventory(&f.root);
    assert_eq!(
        initialize(&f.root, &f.budget).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.root), whole);
}

#[test]
fn chunk_hard_limit_is_independent_of_declared_blob_range() {
    let bytes = vec![7u8; 65_537];
    let i = Input::new(&[("large", &bytes)]);
    let f = Fixture::new(GLOBAL + 3 * i.charge(), 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("over-limit")).unwrap();
    assert_eq!(v.snapshot, i.snapshot);
    assert_eq!(v.blobs[0].size_bytes, 65_537);
    assert_eq!(v.blobs[0].durable_offset, 0);
    assert_eq!(v.reserved_bytes, i.charge());
    let durable = s.test_observe(&v.upload_id).unwrap();
    let before = inventory(&f.namespace());
    let request = i.chunk(&v.upload_id, 0, &bytes);
    let SnapshotRequest::PutChunk {
        offset,
        bytes: chunk,
        chunk_sha256,
        ..
    } = &request
    else {
        unreachable!()
    };
    assert_eq!(*offset + chunk.len() as u64, v.blobs[0].size_bytes);
    assert_eq!(*chunk_sha256, sha256(chunk));
    // Only the chunk hard limit is violated: no range, manifest, binding,
    // hash, authorization, active-count, or reservation failure can mask it.
    assert_code(s.execute(&c, request), TaskErrorCode::InvalidRequest);
    assert_eq!(inventory(&f.namespace()), before);
    assert_eq!(s.test_observe(&v.upload_id).unwrap(), durable);
    for (key, prefix) in [("below-limit", 65_535), ("at-limit", 65_536)] {
        let admitted = s.execute(&c, i.begin(key)).unwrap();
        let progressed = s
            .execute(&c, i.chunk(&admitted.upload_id, 0, &bytes[..prefix]))
            .unwrap();
        assert_eq!(progressed.blobs[0].durable_offset, prefix as u64);
        assert_eq!(progressed.reserved_bytes, i.charge());
        assert_eq!(
            fs::read(f.payload(&admitted.upload_id, &i.files[0].sha256)).unwrap(),
            bytes[..prefix]
        );
        s.execute(
            &c,
            i.chunk(&admitted.upload_id, prefix as u64, &bytes[prefix..]),
        )
        .unwrap();
        let staged = s
            .execute(
                &c,
                SnapshotRequest::Seal {
                    upload_id: admitted.upload_id,
                },
            )
            .unwrap();
        assert_eq!(staged.state, UploadState::Staged);
    }
}

// Corrupt one scalar at a time in a real canonical Complete marker. No private
// field names or envelope layout is frozen: this visits every scalar, including
// the checksum itself. A checksum-only mutation therefore has no unrelated
// scope/type/JSON failure to hide a skipped checksum validation.
fn authority_scalar_corruptions(value: &Value) -> Vec<Value> {
    match value {
        Value::Object(fields) => fields
            .iter()
            .flat_map(|(key, child)| {
                authority_scalar_corruptions(child)
                    .into_iter()
                    .map(|bad| {
                        let mut altered = fields.clone();
                        altered.insert(key.clone(), bad);
                        Value::Object(altered)
                    })
                    .collect::<Vec<_>>()
            })
            .collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(index, child)| {
                authority_scalar_corruptions(child)
                    .into_iter()
                    .map(|bad| {
                        let mut altered = items.clone();
                        altered[index] = bad;
                        Value::Array(altered)
                    })
                    .collect::<Vec<_>>()
            })
            .collect(),
        Value::String(text) => {
            let mut chars = text.chars();
            let bad = match chars.next() {
                Some('s') if text.starts_with("sha256:") => {
                    let mut changed = text.clone().into_bytes();
                    changed[7] = if changed[7] == b'0' { b'1' } else { b'0' };
                    String::from_utf8(changed).unwrap()
                }
                Some(first) => {
                    format!("{}{}", if first == '0' { '1' } else { '0' }, chars.as_str())
                }
                None => "0".into(),
            };
            vec![Value::String(bad)]
        }
        Value::Integer(number) => vec![Value::Integer(if *number == 0 { 1 } else { 0 })],
        Value::Bool(flag) => vec![Value::Bool(!flag)],
        Value::Null => vec![Value::Bool(false)],
    }
}

fn assert_authority_rejected_without_rebuilding(f: &Fixture) {
    let before = inventory(&f.base);
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    assert_eq!(
        inventory(&f.base),
        before,
        "open must retain damaged authority and original charge"
    );
    assert_eq!(
        initialize(&f.root, &f.budget).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        inventory(&f.base),
        before,
        "repeat initialize must not rebuild authority or refund"
    );
}

#[test]
fn retained_complete_marker_missing_corrupt_or_foreign_binding_is_fail_closed() {
    const MARKER: &str = "snapshot-staging-required-v1.json";
    for damage in [
        "missing",
        "malformed",
        "foreign-complete",
        "directory",
        "symlink",
        "hardlink",
        "mode",
    ] {
        let f = Fixture::standard();
        let s = f.service();
        let i = Input::small();
        let v = s.execute(&f.context(), i.begin("original")).unwrap();
        s.execute(&f.context(), i.chunk(&v.upload_id, 0, b"abc"))
            .unwrap();
        let durable = s.test_observe(&v.upload_id).unwrap();
        assert_eq!(durable.view.reserved_bytes, i.charge());
        let marker = f.root.join(MARKER);
        let original = fs::read(&marker).unwrap();
        let positive = inventory(&f.root);
        drop(s);
        drop(f.open());
        assert!(!f.initialize().changed);
        assert_eq!(
            inventory(&f.root),
            positive,
            "valid original Complete marker is a read-only positive control"
        );
        match damage {
            "missing" => fs::remove_file(&marker).unwrap(),
            "malformed" => fs::write(&marker, b"{broken}").unwrap(),
            "foreign-complete" => {
                // This is a genuinely initialized and validated Complete
                // marker, with a valid checksum but another authority binding.
                let donor = Fixture::standard();
                donor.initialize();
                drop(donor.open());
                let foreign = fs::read(donor.root.join(MARKER)).unwrap();
                assert_ne!(foreign, original);
                fs::write(&marker, &foreign).unwrap();
            }
            "directory" => {
                fs::remove_file(&marker).unwrap();
                private_dir(&marker);
            }
            "symlink" | "hardlink" => {
                let decoy = f.base.join("original-marker");
                private_file(&decoy, &original);
                fs::remove_file(&marker).unwrap();
                if damage == "symlink" {
                    symlink(&decoy, &marker).unwrap();
                } else {
                    fs::hard_link(&decoy, &marker).unwrap();
                }
            }
            _ => fs::set_permissions(&marker, fs::Permissions::from_mode(0o666)).unwrap(),
        }
        let namespace = inventory(&f.namespace());
        assert_authority_rejected_without_rebuilding(&f);
        assert_eq!(
            inventory(&f.namespace()),
            namespace,
            "must preserve payload, ledger charge, and inodes: {damage}"
        );
    }
    let f = Fixture::standard();
    let s = f.service();
    let i = Input::small();
    let v = s.execute(&f.context(), i.begin("checksum-matrix")).unwrap();
    let durable = s.test_observe(&v.upload_id).unwrap();
    assert_eq!(durable.view.reserved_bytes, i.charge());
    drop(s);
    for authority in [f.root.join(MARKER), f.namespace().join("ledger-v1.json")] {
        let original = fs::read(&authority).unwrap();
        let value = nexus::n3_acceptance::parse_canonical_json(&original).unwrap();
        let corruptions = authority_scalar_corruptions(&value);
        assert!(
            !corruptions.is_empty(),
            "checksummed authority must contain binding/checksum scalars"
        );
        for (index, bad) in corruptions.into_iter().enumerate() {
            let bytes = bad.canonical_bytes();
            assert_ne!(bytes, original);
            fs::write(&authority, bytes).unwrap();
            let damaged = inventory(&f.namespace());
            assert_authority_rejected_without_rebuilding(&f);
            assert_eq!(
                inventory(&f.namespace()),
                damaged,
                "single authority scalar mutation {index} cannot rebuild payload/charge"
            );
            fs::write(&authority, &original).unwrap();
            let recovered = f.open();
            assert_eq!(recovered.test_observe(&v.upload_id).unwrap(), durable);
            assert!(!f.initialize().changed);
        }
    }
}

#[test]
fn replaced_original_root_and_namespace_directory_inodes_cannot_rebind_authority() {
    for replace_root in [false, true] {
        let f = Fixture::standard();
        let s = f.service();
        let i = Input::small();
        let v = s
            .execute(&f.context(), i.begin("directory-binding"))
            .unwrap();
        assert_eq!(
            s.test_observe(&v.upload_id).unwrap().view.reserved_bytes,
            i.charge()
        );
        drop(s);
        let directory = if replace_root {
            f.root.clone()
        } else {
            f.namespace()
        };
        let old = f.base.join("original-directory");
        let original = fs::metadata(&directory).unwrap();
        fs::rename(&directory, &old).unwrap();
        private_dir(&directory);
        for entry in fs::read_dir(&old).unwrap() {
            let entry = entry.unwrap();
            fs::rename(entry.path(), directory.join(entry.file_name())).unwrap();
        }
        let replacement = fs::metadata(&directory).unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (replacement.dev(), replacement.ino())
        );
        assert_authority_rejected_without_rebuilding(&f);
    }
}

#[test]
fn complete_policy_binding_rejects_another_valid_policy_without_resetting_charge() {
    let f = Fixture::standard();
    let s = f.service();
    let i = Input::small();
    let v = s.execute(&f.context(), i.begin("policy-binding")).unwrap();
    assert_eq!(
        s.test_observe(&v.upload_id).unwrap().view.reserved_bytes,
        i.charge()
    );
    drop(s);
    let donor = Fixture::new(128 << 20, 8);
    donor.initialize();
    drop(donor.open());
    let original = f.namespace().join("policy-v1.json");
    let foreign = fs::read(donor.namespace().join("policy-v1.json")).unwrap();
    assert_ne!(foreign, fs::read(&original).unwrap());
    // The policy is syntactically/canonically valid and was admitted by a real
    // initialization. Its mismatch with the original Complete binding alone
    // must prevent substituting a new capacity authority.
    fs::write(&original, foreign).unwrap();
    assert_authority_rejected_without_rebuilding(&f);
}

// These are new N3-12 nodes only. Existing requester source files retain their
// separate 0600/0644 compatibility contract and are never inspected here.
fn assert_private_staging_tree(f: &Fixture) {
    for entry in inventory(&f.namespace())
        .into_iter()
        .chain(inventory(&f.root.join("snapshot-staging-required-v1.json")))
    {
        let kind = entry.mode & 0o170000;
        let expected = match kind {
            0o040000 => 0o700,
            0o100000 => {
                assert_eq!(
                    entry.nlink, 1,
                    "new private file must be single-link: {:?}",
                    entry.relative
                );
                0o600
            }
            _ => panic!(
                "new staging node must be a real directory/file, not a followed link: {:?}",
                entry.relative
            ),
        };
        assert_eq!(
            entry.mode & 0o7777,
            expected,
            "exact private permission on {:?}",
            entry.relative
        );
    }
}

#[test]
fn newly_created_staging_nodes_are_exactly_private_through_chunk_and_seal() {
    let f = Fixture::standard();
    f.initialize();
    assert_private_staging_tree(&f);
    let s = f.open();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("private-creation")).unwrap();
    assert_private_staging_tree(&f);
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    assert_private_staging_tree(&f);
    s.set_fault("chunk_scratch_ready_durable");
    assert_code(
        s.execute(&c, i.chunk(&v.upload_id, 3, b"def")),
        TaskErrorCode::PersistenceFailed,
    );
    s.set_fault("");
    let scratch = f
        .namespace()
        .join("uploads")
        .join(v.upload_id.as_str())
        .join("chunk.tmp");
    assert_eq!(fs::read(&scratch).unwrap(), b"def");
    assert_eq!(
        fs::symlink_metadata(&scratch).unwrap().mode() & 0o7777,
        0o600
    );
    assert_private_staging_tree(&f);
    drop(s);
    let s = f.open();
    assert!(!scratch.exists());
    assert_eq!(get(&s, &c, &v.upload_id).blobs[0].durable_offset, 6);
    assert_private_staging_tree(&f);
    let staged = s
        .execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(staged.state, UploadState::Staged);
    assert_eq!(staged.reserved_bytes, i.charge());
    assert_private_staging_tree(&f);
}

// Return a genuine normal state and a single actual node. Scratch cases stop
// after the real durable ScratchReady transition; no private state is seeded.
fn private_boundary_fixture(
    target: &str,
) -> (
    Fixture,
    FileSnapshotStaging,
    TaskCallContext,
    Input,
    UploadId,
    PathBuf,
    bool,
) {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("private-boundary")).unwrap();
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    if target == "scratch" {
        s.set_fault("chunk_scratch_ready_durable");
        assert_code(
            s.execute(&c, i.chunk(&v.upload_id, 3, b"def")),
            TaskErrorCode::PersistenceFailed,
        );
        s.set_fault("");
    }
    if target == "ledger-tmp" {
        s.set_fault("ledger_tmp_durable");
        assert_code(
            s.execute(&c, i.begin("next-private-ledger-transition")),
            TaskErrorCode::PersistenceFailed,
        );
        s.set_fault("");
    }
    let upload = f.namespace().join("uploads").join(v.upload_id.as_str());
    let (path, initialization_authority) = match target {
        "marker" => (f.root.join("snapshot-staging-required-v1.json"), true),
        "namespace" => (f.namespace(), true),
        "policy" => (f.namespace().join("policy-v1.json"), true),
        "ledger" => (f.namespace().join("ledger-v1.json"), true),
        "ledger-tmp" => (f.namespace().join(".ledger-v1.tmp"), true),
        "lock" => (f.namespace().join("staging.lock"), true),
        "uploads" => (f.namespace().join("uploads"), true),
        "upload" => (upload.clone(), false),
        "manifest" => (upload.join("manifest-v1.json"), false),
        "blobs" => (upload.join("blobs"), false),
        "payload" => (f.payload(&v.upload_id, &i.files[0].sha256), false),
        "scratch" => (upload.join("chunk.tmp"), false),
        _ => panic!("unknown private-boundary test target"),
    };
    assert_private_staging_tree(&f);
    let durable = s.test_observe(&v.upload_id).unwrap();
    assert_eq!(durable.view.reserved_bytes, i.charge());
    assert_eq!(durable.view.blobs[0].durable_offset, 3);
    assert_eq!(get(&s, &c, &v.upload_id), durable.view);
    (f, s, c, i, v.upload_id, path, initialization_authority)
}

// Queries may append the required authorization audit, but must not modify any
// damaged staging node, its marker, or an external forensic original/decoy.
fn assert_private_boundary_rejection(
    f: &Fixture,
    s: &FileSnapshotStaging,
    c: &TaskCallContext,
    id: &UploadId,
    initialization_authority: bool,
    forensic: Option<&Path>,
) {
    let before = inventory(&f.namespace());
    let marker = inventory(&f.root.join("snapshot-staging-required-v1.json"));
    let original = forensic.map(inventory);
    let unchanged = || {
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(
            inventory(&f.root.join("snapshot-staging-required-v1.json")),
            marker
        );
        if let Some(path) = forensic {
            assert_eq!(inventory(path), *original.as_ref().unwrap());
        }
    };
    assert_code(
        s.execute(
            c,
            SnapshotRequest::Get {
                upload_id: id.clone(),
            },
        ),
        TaskErrorCode::StateCorrupt,
    );
    unchanged();
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    unchanged();
    if initialization_authority {
        // Completed init must recheck its own authority. Payload/scratch are
        // checked at open/live consumption; do not add an undocumented full
        // payload scan requirement to the operational init command.
        assert_eq!(
            initialize(&f.root, &f.budget).unwrap_err().error.code,
            TaskErrorCode::StateCorrupt
        );
        unchanged();
    }
}

#[test]
fn group_or_other_read_and_execute_expansion_is_rejected_on_each_private_node() {
    for target in [
        "marker",
        "namespace",
        "policy",
        "ledger",
        "ledger-tmp",
        "lock",
        "uploads",
        "upload",
        "manifest",
        "blobs",
        "payload",
        "scratch",
    ] {
        for added_bit in [0o040, 0o004, 0o010, 0o001] {
            let (f, s, c, i, id, path, init_authority) = private_boundary_fixture(target);
            let durable = s.test_observe(&id).unwrap();
            let original = fs::symlink_metadata(&path).unwrap();
            let mode = original.mode() & 0o7777;
            assert_eq!(mode, if original.is_dir() { 0o700 } else { 0o600 });
            let bytes = original.is_file().then(|| fs::read(&path).unwrap());
            // Exactly one group/other read or execute bit changes. In
            // particular, no group/other write bit can mask this boundary.
            let expanded = mode | added_bit;
            assert_eq!(expanded & 0o022, 0);
            fs::set_permissions(&path, fs::Permissions::from_mode(expanded)).unwrap();
            let bad = fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (bad.dev(), bad.ino(), bad.nlink(), bad.len()),
                (
                    original.dev(),
                    original.ino(),
                    original.nlink(),
                    original.len()
                )
            );
            if let Some(bytes) = &bytes {
                assert_eq!(fs::read(&path).unwrap(), *bytes);
            }
            assert_private_boundary_rejection(&f, &s, &c, &id, init_authority, None);
            assert_eq!(
                fs::symlink_metadata(&path).unwrap().mode() & 0o7777,
                expanded,
                "refusal must not chmod {target} / added bit {added_bit:o}"
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(s.test_observe(&id).unwrap(), durable);
            let before_get = inventory(&f.namespace());
            assert_eq!(get(&s, &c, &id), durable.view);
            assert_eq!(inventory(&f.namespace()), before_get);
            assert_eq!(durable.view.reserved_bytes, i.charge());
            assert_private_staging_tree(&f);
        }
    }
}

#[test]
fn private_files_and_directories_reject_links_and_wrong_node_types_without_cleanup() {
    for target in [
        "marker",
        "namespace",
        "policy",
        "ledger",
        "ledger-tmp",
        "lock",
        "uploads",
        "upload",
        "manifest",
        "blobs",
        "payload",
        "scratch",
    ] {
        let damages: &[&str] = if matches!(target, "namespace" | "uploads" | "upload" | "blobs") {
            &["symlink", "wrong-type"]
        } else {
            &["symlink", "wrong-type", "hardlink"]
        };
        for damage in damages {
            let (f, s, c, _i, id, path, init_authority) = private_boundary_fixture(target);
            let durable = s.test_observe(&id).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let original = f.base.join("original-private-node");
            fs::rename(&path, &original).unwrap();
            match *damage {
                "symlink" => symlink(&original, &path).unwrap(),
                "hardlink" => fs::hard_link(&original, &path).unwrap(),
                _ if metadata.is_dir() => {
                    private_file(&path, b"same private owner, wrong node type")
                }
                _ => private_dir(&path),
            }
            if *damage == "hardlink" {
                let bad = fs::symlink_metadata(&path).unwrap();
                assert_eq!((bad.dev(), bad.ino()), (metadata.dev(), metadata.ino()));
                assert_eq!(bad.nlink(), 2, "single invalid dimension is the link count");
            }
            assert_private_boundary_rejection(&f, &s, &c, &id, init_authority, Some(&original));
            let replacement = fs::symlink_metadata(&path).unwrap();
            if replacement.is_dir() {
                fs::remove_dir(&path).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            fs::rename(&original, &path).unwrap();
            assert_eq!(s.test_observe(&id).unwrap(), durable);
            assert_eq!(get(&s, &c, &id), durable.view);
            assert_private_staging_tree(&f);
        }
    }
}

#[test]
fn pending_init_and_atomic_ledger_temporary_authorities_are_created_private() {
    for cutpoint in ["init_pending_durable", "init_complete_durable"] {
        let f = Fixture::standard();
        let failed = initialize_with_test_fault(&f.root, &f.budget, cutpoint).unwrap_err();
        assert_eq!(failed.error.code, TaskErrorCode::PersistenceFailed);
        let marker =
            fs::symlink_metadata(f.root.join("snapshot-staging-required-v1.json")).unwrap();
        assert!(marker.is_file() && !marker.file_type().is_symlink());
        assert_eq!(marker.nlink(), 1);
        assert_eq!(marker.mode() & 0o7777, 0o600);
        assert_private_staging_tree(&f);
    }
    let (f, _s, _c, _i, _id, temporary, _init_authority) = private_boundary_fixture("ledger-tmp");
    assert_eq!(temporary, f.namespace().join(".ledger-v1.tmp"));
    let metadata = fs::symlink_metadata(&temporary).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_private_staging_tree(&f);
}

fn assert_external_budget_refused_without_authority(f: &Fixture, code: TaskErrorCode) {
    assert!(
        !crate::task_provider_init::check(&f.root).unwrap().changed,
        "the real N3-11 provider is valid before the isolated budget rejection"
    );
    assert!(!f.namespace().exists());
    assert!(!f.root.join("snapshot-staging-required-v1.json").exists());
    let before = inventory(&f.base);
    let failure = initialize(&f.root, &f.budget).unwrap_err();
    assert_eq!(failure.error.code, code);
    assert!(!failure.mutation_may_have_applied);
    assert_eq!(
        inventory(&f.base),
        before,
        "invalid external input cannot create authority or modify its target"
    );
    assert!(!f.namespace().exists());
    assert!(!f.root.join("snapshot-staging-required-v1.json").exists());
}

#[test]
fn external_budget_accepts_readonly_0644_and_16k_json_whitespace_but_not_unsafe_inputs() {
    // Input policy inherits N3-11's non-writable regular-file boundary, not
    // the stricter 0600 mode required of newly published authority files.
    for mode in [0o600, 0o644] {
        let f = Fixture::standard();
        let original = fs::read(&f.budget).unwrap();
        let mut padded = original.clone();
        padded.resize(16_384, b' ');
        assert!(serde_json::from_slice::<serde_json::Value>(&padded).is_ok());
        fs::write(&f.budget, &padded).unwrap();
        fs::set_permissions(&f.budget, fs::Permissions::from_mode(mode)).unwrap();
        let external = inventory(&f.budget);
        let status = f.initialize();
        assert!(status.changed);
        assert_eq!(inventory(&f.budget), external);
        assert!(!f.initialize().changed);
        assert_eq!(inventory(&f.budget), external);
        assert_private_staging_tree(&f);
    }
    for damage in [
        "symlink",
        "hardlink",
        "directory",
        "group-write",
        "other-write",
        "missing",
        "over-size",
        "invalid-utf8",
    ] {
        let f = Fixture::standard();
        let original = fs::read(&f.budget).unwrap();
        let saved = f.base.join("original-valid-external-budget");
        match damage {
            "symlink" => {
                fs::rename(&f.budget, &saved).unwrap();
                symlink(&saved, &f.budget).unwrap();
            }
            "hardlink" => {
                fs::rename(&f.budget, &saved).unwrap();
                fs::hard_link(&saved, &f.budget).unwrap();
            }
            "directory" => {
                fs::rename(&f.budget, &saved).unwrap();
                private_dir(&f.budget);
            }
            "missing" => {
                fs::rename(&f.budget, &saved).unwrap();
            }
            "group-write" => {
                fs::set_permissions(&f.budget, fs::Permissions::from_mode(0o620)).unwrap()
            }
            "other-write" => {
                fs::set_permissions(&f.budget, fs::Permissions::from_mode(0o602)).unwrap()
            }
            "over-size" => {
                let mut bytes = original.clone();
                bytes.resize(16_385, b' ');
                assert!(
                    serde_json::from_slice::<serde_json::Value>(&bytes).is_ok(),
                    "only the inherited byte cap is violated"
                );
                fs::write(&f.budget, bytes).unwrap();
            }
            _ => {
                let mut bytes = original.clone();
                bytes.push(0xff);
                fs::write(&f.budget, bytes).unwrap();
            }
        }
        let code = if damage == "missing" {
            // N3-11 §6 distinguishes actual input IO from malformed policy.
            TaskErrorCode::PersistenceFailed
        } else {
            TaskErrorCode::InvalidRequest
        };
        assert_external_budget_refused_without_authority(&f, code);
        if saved.exists() {
            if let Ok(meta) = fs::symlink_metadata(&f.budget) {
                if meta.is_dir() {
                    fs::remove_dir(&f.budget).unwrap();
                } else {
                    fs::remove_file(&f.budget).unwrap();
                }
            }
            fs::rename(&saved, &f.budget).unwrap();
        } else {
            fs::write(&f.budget, &original).unwrap();
            fs::set_permissions(&f.budget, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(
            f.initialize().changed,
            "same provider and policy are valid after only repairing {damage}"
        );
        assert_private_staging_tree(&f);
    }
}

#[test]
fn external_budget_schema_requires_each_field_and_lossless_exact_types() {
    let fields = ["schema_version", "max_reserved_bytes", "max_active_uploads"];
    for field in fields {
        for damage in [
            "missing",
            "string",
            "null",
            "boolean",
            "array",
            "object",
            "negative",
            "float",
            "exponent",
            "duplicate",
        ] {
            let f = Fixture::standard();
            let original = fs::read_to_string(&f.budget).unwrap();
            let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
            let object = value.as_object_mut().unwrap();
            let number = object[field].as_u64().unwrap();
            let raw = match damage {
                "missing" => {
                    object.remove(field);
                    serde_json::to_string(&value).unwrap()
                }
                "string" => {
                    object.insert(field.into(), serde_json::Value::String(number.to_string()));
                    serde_json::to_string(&value).unwrap()
                }
                "null" => {
                    object.insert(field.into(), serde_json::Value::Null);
                    serde_json::to_string(&value).unwrap()
                }
                "boolean" => {
                    object.insert(field.into(), serde_json::Value::Bool(true));
                    serde_json::to_string(&value).unwrap()
                }
                "array" => {
                    object.insert(field.into(), serde_json::json!([number]));
                    serde_json::to_string(&value).unwrap()
                }
                "object" => {
                    object.insert(field.into(), serde_json::json!({"value": number}));
                    serde_json::to_string(&value).unwrap()
                }
                "negative" => {
                    original.replace(&format!("\"{field}\":{number}"), &format!("\"{field}\":-1"))
                }
                "float" => original.replace(
                    &format!("\"{field}\":{number}"),
                    &format!("\"{field}\":{number}.0"),
                ),
                "exponent" => original.replace(
                    &format!("\"{field}\":{number}"),
                    &format!("\"{field}\":{number}e0"),
                ),
                _ => format!("{{\"{field}\":{number},{}", &original[1..]),
            };
            assert_ne!(raw, original);
            fs::write(&f.budget, raw).unwrap();
            assert_external_budget_refused_without_authority(&f, TaskErrorCode::InvalidRequest);
            fs::write(&f.budget, original).unwrap();
            assert!(f.initialize().changed);
        }
    }
    let f = Fixture::standard();
    let original = fs::read(&f.budget).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), serde_json::json!(0));
    fs::write(&f.budget, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_external_budget_refused_without_authority(&f, TaskErrorCode::InvalidRequest);
    fs::write(&f.budget, original).unwrap();
    assert!(f.initialize().changed);

    for raw in ["[]", "null", "true", "1", "1.0", "1e0", "\"policy\""] {
        let f = Fixture::standard();
        let original = fs::read(&f.budget).unwrap();
        fs::write(&f.budget, raw).unwrap();
        assert_external_budget_refused_without_authority(&f, TaskErrorCode::InvalidRequest);
        fs::write(&f.budget, original).unwrap();
        assert!(f.initialize().changed);
    }
}

#[test]
fn external_budget_fifo_is_rejected_by_a_bounded_owned_process() {
    let result = std::process::Command::new("timeout")
        .arg("10s")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "snapshot_staging::tests::authority::external_budget_fifo_probe_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "bounded external-budget FIFO probe failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "owned bounded subprocess invoked by external_budget_fifo_is_rejected_by_a_bounded_owned_process"]
fn external_budget_fifo_probe_child() {
    let f = Fixture::standard();
    let saved = f.base.join("valid-original-budget");
    fs::rename(&f.budget, &saved).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&f.budget)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        fs::symlink_metadata(&f.budget)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert_external_budget_refused_without_authority(&f, TaskErrorCode::InvalidRequest);
    fs::remove_file(&f.budget).unwrap();
    fs::rename(&saved, &f.budget).unwrap();
    assert!(f.initialize().changed);
}

#[test]
fn config_parameter_cannot_follow_root_or_ancestor_symlinks_or_relax_private_mode() {
    for damage in ["root-symlink", "ancestor-symlink", "root-read-exec"] {
        let f = Fixture::standard();
        let s = f.service();
        let i = Input::small();
        let v = s
            .execute(&f.context(), i.begin("config-parameter"))
            .unwrap();
        let durable = s.test_observe(&v.upload_id).unwrap();
        let path = match damage {
            "root-symlink" => {
                let alias = f.base.join("root-link");
                symlink(&f.root, &alias).unwrap();
                alias
            }
            "ancestor-symlink" => {
                let alias = f.base.join("parent-link");
                symlink(&f.base, &alias).unwrap();
                alias.join("provider")
            }
            _ => {
                fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap();
                f.root.clone()
            }
        };
        let before = inventory(&f.base);
        let failure = initialize(&path, &f.budget).unwrap_err();
        assert!(matches!(
            failure.error.code,
            TaskErrorCode::InvalidRequest | TaskErrorCode::StateCorrupt
        ));
        assert!(!failure.mutation_may_have_applied);
        assert_eq!(inventory(&f.base), before);
        let error = FileSnapshotStaging::open(&path).unwrap_err();
        assert!(matches!(
            error.code,
            TaskErrorCode::InvalidRequest | TaskErrorCode::StateCorrupt
        ));
        assert_eq!(inventory(&f.base), before);
        if damage == "root-read-exec" {
            fs::set_permissions(&f.root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(f.open().test_observe(&v.upload_id).unwrap(), durable);
        assert!(!f.initialize().changed);
    }
}

#[test]
fn canonical_self_consistent_manifest_rejects_only_unsorted_unique_paths() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let mut i = Input::new(&[("a.txt", b"first"), ("b.txt", b"second")]);
    let sorted = i.snapshot.clone();
    assert_eq!(
        s.execute(&c, i.begin("sorted-positive")).unwrap().snapshot,
        sorted
    );
    i.files.swap(0, 1);
    i.redeclare();
    assert_eq!(i.files[0].path, "b.txt");
    assert_eq!(i.files[1].path, "a.txt");
    assert_eq!(i.snapshot.file_count, 2);
    assert_eq!(i.snapshot.total_bytes, 11);
    assert_eq!(i.snapshot.manifest_sha256, sha256(i.manifest.as_bytes()));
    i.snapshot.verify_digest(sha256).unwrap();
    assert_eq!(
        nexus::n3_acceptance::parse_canonical_json(i.manifest.as_bytes())
            .unwrap()
            .canonical_bytes(),
        i.manifest.as_bytes()
    );
    let before = inventory(&f.namespace());
    assert!(s.execute(&c, i.begin("only-order-is-invalid")).is_err());
    assert_eq!(
        inventory(&f.namespace()),
        before,
        "no new reservation/payload for unsorted paths"
    );
    i.files.swap(0, 1);
    i.redeclare();
    assert_eq!(i.snapshot, sorted);
    assert_eq!(
        s.execute(&c, i.begin("only-order-is-invalid"))
            .unwrap()
            .snapshot,
        sorted
    );
}

#[test]
fn manifest_path_grammar_rejects_self_consistent_unsafe_relative_names() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let valid = Input::small();
    s.execute(&c, valid.begin("valid-path-control")).unwrap();
    for (index, path) in [
        "",
        ".",
        "..",
        "../escape",
        "dir/../escape",
        "./input",
        "dir/./file",
        "/absolute",
        "dir//file",
        "dir/",
        "back\\slash",
        "bad\0name",
        "C:/drive",
    ]
    .iter()
    .enumerate()
    {
        let mut i = Input::small();
        i.files[0].path = (*path).into();
        i.redeclare();
        assert_eq!(i.snapshot.file_count, 1);
        assert_eq!(i.snapshot.total_bytes, 6);
        assert_eq!(i.snapshot.manifest_sha256, sha256(i.manifest.as_bytes()));
        let before = inventory(&f.namespace());
        assert!(
            s.execute(&c, i.begin(&format!("unsafe-path-{index}")))
                .is_err()
        );
        assert_eq!(
            inventory(&f.namespace()),
            before,
            "path semantic defect cannot create reservation: {path:?}"
        );
    }
}

#[test]
fn utf8_case_distinct_names_and_executable_manifest_survive_upload_and_seal() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let mut i = Input::new(&[
        ("Case/same.txt", b"upper"),
        ("case/same.txt", b"lower"),
        ("unicode/e\u{301}.txt", b"decomposed"),
        ("unicode/é.txt", b"composed"),
        ("scripts/run.sh", b"#!/bin/sh\nexit 0\n"),
    ]);
    i.files
        .iter_mut()
        .find(|file| file.path == "scripts/run.sh")
        .unwrap()
        .executable = true;
    i.snapshot.selection_digest = SnapshotSelection {
        include: vec![".".into()],
        exclude: vec![],
        executable: vec!["scripts/run.sh".into()],
    }
    .digest(sha256)
    .unwrap();
    i.redeclare();
    let v = s.execute(&c, i.begin("utf8-executable")).unwrap();
    assert_eq!(v.snapshot, i.snapshot);
    assert_eq!(v.reserved_bytes, i.charge());
    assert_eq!(
        v.blobs
            .iter()
            .map(|blob| blob.sha256.clone())
            .collect::<Vec<_>>(),
        i.payloads.keys().cloned().collect::<Vec<_>>()
    );
    i.upload_all(&s, &c, &v.upload_id);
    let sealed = s
        .execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(sealed.state, UploadState::Staged);
    assert_eq!(sealed.snapshot, i.snapshot);
    let manifest = f
        .namespace()
        .join("uploads")
        .join(v.upload_id.as_str())
        .join("manifest-v1.json");
    assert_eq!(fs::read(manifest).unwrap(), i.manifest.as_bytes());
}

#[test]
fn execute_local_never_ensures_replacement_identity_or_repairs_changed_scope() {
    for damage in ["missing-identity", "same-bytes-new-identity-inode", "scope"] {
        let f = Fixture::standard();
        let s = f.service();
        let i = Input::small();
        let request = i.begin("local-pure-existing-identity");
        if damage == "scope" {
            private_file(
                &f.root.join("task-api.toml"),
                b"provider=\"foreign\"\nworkspace=\"n312-source\"\n",
            );
        } else {
            let identity = f
                .root
                .join("n2")
                .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap());
            let bytes = fs::read(&identity).unwrap();
            fs::rename(&identity, f.base.join("original-fixed-identity")).unwrap();
            if damage == "same-bytes-new-identity-inode" {
                private_file(&identity, &bytes);
            }
        }
        let before = inventory(&f.base);
        let result = s.execute_local(request);
        let SnapshotEnvelope::Error { error, .. } = result else {
            panic!("changed fixed identity/scope cannot upload")
        };
        assert_eq!(error.code, TaskErrorCode::StateCorrupt);
        assert_eq!(
            inventory(&f.base),
            before,
            "no ensure identity or scope repair after {damage}"
        );
    }
}

#[test]
fn canonical_real_ledger_at_stale_or_equal_generation_is_not_a_recoverable_next_tmp() {
    for generation in ["stale", "equal"] {
        let i = Input::small();
        let f = Fixture::new(GLOBAL + 3 * i.charge(), 8);
        let s = f.service();
        let c = f.context();
        let original = s.execute(&c, i.begin("original-active")).unwrap();
        s.execute(&c, i.chunk(&original.upload_id, 0, b"abc"))
            .unwrap();
        let ledger = f.namespace().join("ledger-v1.json");
        let tmp = f.namespace().join(".ledger-v1.tmp");
        // These bytes were actually accepted on THIS root/scope, with this
        // original upload, payload inode and prefix. No checksum is invented.
        drop(f.open());
        let stale = fs::read(&ledger).unwrap();
        let stale_tree = inventory(&f.namespace().join("uploads"));
        let retired = s.execute(&c, i.begin("advance-generation")).unwrap();
        s.execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: retired.upload_id.clone(),
            },
        )
        .unwrap();
        assert!(
            !f.namespace()
                .join("uploads")
                .join(retired.upload_id.as_str())
                .exists()
        );
        drop(f.open());
        let current = fs::read(&ledger).unwrap();
        assert_ne!(stale, current);
        assert_eq!(inventory(&f.namespace().join("uploads")), stale_tree);
        // Begin+Cancel advances the real ledger, but leaves exactly the same
        // physical original upload tree. The stale image is not masked by a
        // prefix mismatch or an unknown extra upload directory.
        let durable = s.test_observe(&original.upload_id).unwrap();
        assert_eq!(durable.view.reserved_bytes, i.charge());
        assert_eq!(durable.view.blobs[0].durable_offset, 3);
        let original_tree = inventory(&f.namespace().join("uploads"));
        let original_upload_tree = inventory(
            &f.namespace()
                .join("uploads")
                .join(original.upload_id.as_str()),
        );
        let candidate_key = format!("genuine-next-{generation}");
        s.set_fault("ledger_tmp_durable");
        assert_code(
            s.execute(&c, i.begin(&candidate_key)),
            TaskErrorCode::PersistenceFailed,
        );
        s.set_fault("");
        assert_eq!(fs::read(&ledger).unwrap(), current);
        assert_eq!(inventory(&f.namespace().join("uploads")), original_tree);
        let candidate = fs::read(&tmp).unwrap();
        assert_ne!(candidate, current);
        let original_tmp = fs::symlink_metadata(&tmp).unwrap();
        assert!(original_tmp.is_file() && !original_tmp.file_type().is_symlink());
        assert_eq!(original_tmp.mode() & 0o7777, 0o600);
        assert_eq!(original_tmp.nlink(), 1);
        let invalid_next = if generation == "stale" {
            &stale
        } else {
            &current
        };
        assert_eq!(
            nexus::n3_acceptance::parse_canonical_json(invalid_next)
                .unwrap()
                .canonical_bytes(),
            *invalid_next,
            "canonical, genuine checksummed bytes; only next-transition proof is invalid"
        );
        fs::write(&tmp, invalid_next).unwrap();
        let copied = fs::symlink_metadata(&tmp).unwrap();
        assert_eq!(
            (copied.dev(), copied.ino(), copied.mode(), copied.nlink()),
            (
                original_tmp.dev(),
                original_tmp.ino(),
                original_tmp.mode(),
                original_tmp.nlink()
            ),
            "the genuine fixed temporary inode and safe metadata stay unchanged"
        );
        drop(s);
        let before = inventory(&f.namespace());
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(fs::read(&ledger).unwrap(), current);
        assert_eq!(fs::read(&tmp).unwrap(), *invalid_next);
        assert_eq!(inventory(&f.namespace().join("uploads")), original_tree);
        // Restore ONLY the genuine next bytes on the same temporary inode.
        // Successful recovery proves neither inode/type/mode nor the original
        // root/scope/checksum was an unrelated reason for rejection.
        fs::write(&tmp, &candidate).unwrap();
        let recovered = f.open();
        assert!(!tmp.exists());
        assert_eq!(
            recovered.test_observe(&original.upload_id).unwrap(),
            durable
        );
        assert_eq!(
            inventory(
                &f.namespace()
                    .join("uploads")
                    .join(original.upload_id.as_str())
            ),
            original_upload_tree
        );
        let next = recovered.execute(&c, i.begin(&candidate_key)).unwrap();
        assert_ne!(next.upload_id, original.upload_id);
        assert_eq!(next.reserved_bytes, i.charge());
        assert_eq!(next.snapshot, i.snapshot);
        assert_eq!(
            get(&recovered, &c, &original.upload_id).blobs[0].durable_offset,
            3
        );
    }
}

#[test]
fn raw_manifest_duplicate_fields_numbers_escapes_and_order_fail_with_self_consistent_identity() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let control = s.execute(&c, i.begin("canonical-positive")).unwrap();
    let original = s.test_observe(&control.upload_id).unwrap();
    let Value::Object(fields) = i.files[0].to_value() else {
        unreachable!()
    };
    let file = String::from_utf8(i.files[0].to_value().canonical_bytes()).unwrap();
    let mut cases = vec![];
    for (field, value) in &fields {
        let raw_value = String::from_utf8(value.canonical_bytes()).unwrap();
        cases.push((
            format!("duplicate-{field}"),
            format!("[{{\"{field}\":{raw_value},{}]", &file[1..]),
        ));
    }
    cases.extend([
        (
            "float".into(),
            i.manifest.replace("\"size_bytes\":6", "\"size_bytes\":6.0"),
        ),
        (
            "exponent".into(),
            i.manifest.replace("\"size_bytes\":6", "\"size_bytes\":6e0"),
        ),
        (
            "escape".into(),
            i.manifest.replace("input.txt", "\\u0069nput.txt"),
        ),
    ]);
    let reverse_fields = fields
        .iter()
        .rev()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                String::from_utf8(key.to_value().canonical_bytes()).unwrap(),
                String::from_utf8(value.canonical_bytes()).unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    cases.push(("field-order".into(), format!("[{{{reverse_fields}}}]")));
    for (damage, raw) in cases {
        assert_ne!(raw, i.manifest);
        assert!(raw.len() <= 65_536);
        // A deliberately ordinary JSON decoder sees the same logical file in
        // every case. It is NOT the backend parser or the rejection oracle.
        let logical: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(logical.as_array().unwrap().len(), 1);
        assert_eq!(logical[0]["path"].as_str(), Some("input.txt"));
        assert_eq!(logical[0]["size_bytes"].as_f64(), Some(6.0));
        assert_eq!(
            logical[0]["sha256"].as_str(),
            Some(i.files[0].sha256.as_str())
        );
        assert_eq!(logical[0]["executable"].as_bool(), Some(false));
        let mut changed = Input::small();
        changed.manifest = raw;
        changed.snapshot.manifest_sha256 = sha256(changed.manifest.as_bytes());
        let Value::Object(mut identity) = changed.snapshot.to_value() else {
            unreachable!()
        };
        identity.remove("snapshot_id");
        changed.snapshot.snapshot_id = sha256(&Value::Object(identity).canonical_bytes());
        changed.snapshot.verify_digest(sha256).unwrap();
        assert_eq!(changed.snapshot.file_count, 1);
        assert_eq!(changed.snapshot.total_bytes, 6);
        let key = format!("raw-{damage}");
        let before = inventory(&f.namespace());
        assert!(
            s.execute(&c, changed.begin(&key)).is_err(),
            "raw manifest {damage}"
        );
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(s.test_observe(&control.upload_id).unwrap(), original);
        // Same key/scope/declaration with only canonical text restored works.
        let repaired = s.execute(&c, i.begin(&key)).unwrap();
        assert_eq!(repaired.snapshot, i.snapshot);
        assert_eq!(repaired.reserved_bytes, i.charge());
        s.execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: repaired.upload_id,
            },
        )
        .unwrap();
    }
}

#[test]
fn nested_unknown_entries_preserve_original_prefix_and_cancel_charge_until_manual_repair() {
    for damage in [
        "unregistered-upload",
        "upload-file",
        "upload-directory",
        "blob-bad-basename",
        "blob-undeclared-digest",
    ] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let begun = s.execute(&c, i.begin("nested-boundary")).unwrap();
        let partial = s.execute(&c, i.chunk(&begun.upload_id, 0, b"abc")).unwrap();
        assert_eq!(partial.state, UploadState::Receiving);
        assert_eq!(partial.blobs[0].durable_offset, 3);
        assert_eq!(partial.reserved_bytes, i.charge());
        let original = s.test_observe(&begun.upload_id).unwrap();
        assert_eq!(original.view, partial);
        let uploads = f.namespace().join("uploads");
        let upload = uploads.join(begun.upload_id.as_str());
        let payload = f.payload(&begun.upload_id, &i.files[0].sha256);
        let original_inode = fs::symlink_metadata(&payload).unwrap();
        assert_eq!(fs::read(&payload).unwrap(), b"abc");
        let original_tree = inventory(&upload);
        let original_manifest = inventory(&upload.join("manifest-v1.json"));
        let extra_bytes = b"unowned-extra-bytes";
        let unlisted = sha256(extra_bytes);
        assert_ne!(unlisted, i.files[0].sha256);
        let extra = match damage {
            "unregistered-upload" => {
                uploads.join(if begun.upload_id.as_str() == "unregistered-upload" {
                    "another-unregistered-upload"
                } else {
                    "unregistered-upload"
                })
            }
            "upload-file" => upload.join("unowned-file"),
            "upload-directory" => upload.join("unowned-directory"),
            "blob-bad-basename" => upload.join("blobs/not-a-digest"),
            _ => upload
                .join("blobs")
                .join(unlisted.as_str().trim_start_matches("sha256:")),
        };
        assert!(!extra.exists());
        let directory = matches!(damage, "unregistered-upload" | "upload-directory");
        if directory {
            private_dir(&extra);
            if damage == "upload-directory" {
                private_file(&extra.join("sentinel"), extra_bytes);
            }
        } else {
            private_file(&extra, extra_bytes);
        }
        // Only one extra entry/subtree is introduced. All original authority,
        // file contents, bindings, ownership, grants and permissions are valid.
        let extra_before = inventory(&extra);
        let before_cold = inventory(&f.base);
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(
            inventory(&f.base),
            before_cold,
            "cold open cannot clean {damage}"
        );
        assert_eq!(s.test_observe(&begun.upload_id).unwrap(), original);
        let mut cleanup_started = false;
        if damage != "unregistered-upload" {
            let physical_before_cancel = inventory(&upload);
            assert_code(
                s.execute(
                    &c,
                    SnapshotRequest::Cancel {
                        upload_id: begun.upload_id.clone(),
                    },
                ),
                TaskErrorCode::StateCorrupt,
            );
            // Cancel may have durably entered Cancelling before detecting the
            // unknown entry. Do not demand zero ledger changes or revive it.
            let retained = s.test_observe(&begun.upload_id).unwrap();
            assert!(matches!(
                retained.view.state,
                UploadState::Receiving | UploadState::Cancelling
            ));
            cleanup_started = retained.view.state == UploadState::Cancelling;
            let mut expected = original.view.clone();
            expected.state = retained.view.state;
            assert_eq!(
                retained.view, expected,
                "original bindings/prefix/charge survive {damage}"
            );
            assert_eq!(retained.chunk, original.chunk);
            assert_eq!(retained.future_ceiling_bytes, original.future_ceiling_bytes);
            assert!(retained.actual_record_bytes <= retained.future_ceiling_bytes);
            assert_eq!(
                inventory(&upload),
                physical_before_cancel,
                "live Cancel must not delete owned or unknown input: {damage}"
            );
            assert_eq!(inventory(&extra), extra_before);
            assert_eq!(fs::read(&payload).unwrap(), b"abc");
            assert_eq!(
                inventory(&upload.join("manifest-v1.json")),
                original_manifest
            );
            if damage == "upload-directory" {
                assert_eq!(fs::read(extra.join("sentinel")).unwrap(), extra_bytes);
            }
            let before_retry_open = inventory(&f.base);
            assert_code(
                FileSnapshotStaging::open(&f.root),
                TaskErrorCode::StateCorrupt,
            );
            assert_eq!(inventory(&f.base), before_retry_open);
            assert_eq!(s.test_observe(&begun.upload_id).unwrap(), retained);
        }
        assert_eq!(inventory(&extra), extra_before);
        // Observer-only manual repair removes exactly the test-added entry.
        // In particular the product must have preserved this nonempty dir's
        // sentinel; no product Cancel/recursive cleanup is used for repair.
        if damage == "upload-directory" {
            assert_eq!(fs::read(extra.join("sentinel")).unwrap(), extra_bytes);
            fs::remove_file(extra.join("sentinel")).unwrap();
        }
        if directory {
            fs::remove_dir(&extra).unwrap();
        } else {
            fs::remove_file(&extra).unwrap();
        }
        assert_eq!(inventory(&upload), original_tree);
        drop(s);
        let cold = f.open();
        let repaired = cold.test_observe(&begun.upload_id).unwrap();
        if cleanup_started {
            let mut cancelled = original.view.clone();
            cancelled.state = UploadState::Cancelled;
            cancelled.reserved_bytes = 0;
            cancelled.blobs.clear();
            assert_eq!(repaired.view, cancelled);
            assert!(!upload.exists());
            assert_eq!(
                cold.execute(
                    &c,
                    SnapshotRequest::Cancel {
                        upload_id: begun.upload_id.clone()
                    }
                )
                .unwrap(),
                cancelled
            );
            assert_eq!(
                cold.execute(&c, i.begin("nested-boundary")).unwrap(),
                cancelled
            );
        } else {
            assert_eq!(repaired.view, original.view);
            assert_eq!(inventory(&upload), original_tree);
            let completed = cold
                .execute(&c, i.chunk(&begun.upload_id, 3, b"def"))
                .unwrap();
            assert_eq!(completed.blobs[0].durable_offset, 6);
            assert_eq!(completed.reserved_bytes, i.charge());
            let staged = cold
                .execute(
                    &c,
                    SnapshotRequest::Seal {
                        upload_id: begun.upload_id.clone(),
                    },
                )
                .unwrap();
            assert_eq!(staged.state, UploadState::Staged);
            assert_eq!(staged.snapshot, i.snapshot);
            assert_eq!(staged.reserved_bytes, i.charge());
            assert_eq!(fs::read(&payload).unwrap(), b"abcdef");
            let after = fs::symlink_metadata(&payload).unwrap();
            assert_eq!(
                (after.dev(), after.ino()),
                (original_inode.dev(), original_inode.ino())
            );
            assert_eq!(
                inventory(&upload.join("manifest-v1.json")),
                original_manifest
            );
        }
    }
}
