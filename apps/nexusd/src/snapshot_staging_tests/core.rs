use super::*;

#[test]
fn absent_staging_is_read_only_disabled_not_implicit_provision() {
    let f = Fixture::standard();
    let before = inventory(&f.root);
    assert!(FileSnapshotStaging::open(&f.root).unwrap().is_none());
    assert_eq!(inventory(&f.root), before);
}
#[test]
fn explicit_initialize_is_idempotent_bound_and_keeps_original_task_authority() {
    let f = Fixture::standard();
    let tasks = inventory(&f.tasks());
    let first = f.initialize();
    assert!(first.changed);
    assert_eq!(
        (
            first.provider.as_str(),
            first.workspace.as_str(),
            first.principal.as_str()
        ),
        (PROVIDER, WORKSPACE, f.principal.as_str())
    );
    let before = inventory(&f.namespace());
    let second = f.initialize();
    assert!(!second.changed);
    assert_eq!(first.policy_digest, second.policy_digest);
    assert_eq!(inventory(&f.namespace()), before);
    assert_eq!(inventory(&f.tasks()), tasks);
    assert!(!crate::task_provider_init::check(&f.root).unwrap().changed);
}
#[test]
fn exact_budget_admits_one_charge_and_cancel_returns_it_after_physical_cleanup() {
    let input = Input::small();
    let f = Fixture::new(GLOBAL + input.charge(), 8);
    let s = f.service();
    let c = f.context();
    let first = s.execute(&c, input.begin("one")).unwrap();
    assert_eq!(first.reserved_bytes, input.charge());
    assert_code(
        s.execute(&c, input.begin("two")),
        TaskErrorCode::CapacityUnavailable,
    );
    let ended = s
        .execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: first.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(ended.state, UploadState::Cancelled);
    assert_eq!(ended.reserved_bytes, 0);
    assert!(ended.blobs.is_empty());
    assert!(
        !f.namespace()
            .join("uploads")
            .join(first.upload_id.as_str())
            .exists()
    );
    assert_eq!(
        s.execute(&c, input.begin("two")).unwrap().reserved_bytes,
        input.charge()
    );
}
#[test]
fn one_byte_under_charge_rejects_without_staging_changes() {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge() - 1, 8);
    let s = f.service();
    let before = inventory(&f.namespace());
    assert_code(
        s.execute(&f.context(), i.begin("x")),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_eq!(inventory(&f.namespace()), before);
}
#[test]
fn empty_manifest_and_empty_blob_have_metadata_charge_and_seal_without_empty_chunk() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    for (key, input) in [
        ("manifest", Input::empty()),
        ("file", Input::new(&[("empty", b"")])),
    ] {
        let v = s.execute(&c, input.begin(key)).unwrap();
        assert_eq!(v.reserved_bytes, input.charge());
        assert!(v.reserved_bytes > 0);
        let sealed = s
            .execute(
                &c,
                SnapshotRequest::Seal {
                    upload_id: v.upload_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(sealed.state, UploadState::Staged);
        assert_eq!(sealed.snapshot, input.snapshot);
    }
}
#[test]
fn intra_upload_dedup_charges_unique_blobs_but_other_owner_pays_full_charge() {
    let i = Input::new(&[("a", b"abc"), ("b", b"abc")]);
    let f = Fixture::standard();
    f.grant("add", OTHER, None);
    let s = f.service();
    let a = s.execute(&f.context(), i.begin("same")).unwrap();
    let b = s.execute(&f.context_for(OTHER), i.begin("same")).unwrap();
    assert_eq!(a.blobs.len(), 1);
    assert_eq!(a.reserved_bytes, i.charge());
    assert_eq!(b.reserved_bytes, a.reserved_bytes);
    assert_ne!(a.upload_id, b.upload_id);
    assert_code(
        s.execute(
            &f.context_for(OTHER),
            SnapshotRequest::Get {
                upload_id: a.upload_id.clone(),
            },
        ),
        TaskErrorCode::AuthDenied,
    );
    s.execute(
        &f.context(),
        SnapshotRequest::Cancel {
            upload_id: a.upload_id,
        },
    )
    .unwrap();
    assert_eq!(get(&s, &f.context_for(OTHER), &b.upload_id), b);
}
#[test]
fn active_upload_limit_rejects_ninth_and_cancel_frees_slot() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::empty();
    let mut ids = vec![];
    for n in 0..8 {
        ids.push(
            s.execute(&c, i.begin(&format!("key{n}")))
                .unwrap()
                .upload_id,
        );
    }
    assert_code(
        s.execute(&c, i.begin("ninth")),
        TaskErrorCode::CapacityUnavailable,
    );
    s.execute(
        &c,
        SnapshotRequest::Cancel {
            upload_id: ids[0].clone(),
        },
    )
    .unwrap();
    assert_eq!(
        s.execute(&c, i.begin("ninth")).unwrap().state,
        UploadState::Receiving
    );
}
#[test]
fn same_key_is_durable_same_id_and_changed_snapshot_is_conflict() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let first = s.execute(&c, i.begin("key")).unwrap();
    s.execute(&c, i.chunk(&first.upload_id, 0, b"abc")).unwrap();
    drop(s);
    let s = f.open();
    let again = s.execute(&c, i.begin("key")).unwrap();
    assert_eq!(again.upload_id, first.upload_id);
    assert_eq!(again.snapshot, first.snapshot);
    assert_eq!(again.blobs[0].durable_offset, 3);
    assert_eq!(again.reserved_bytes, first.reserved_bytes);
    assert_code(
        s.execute(&c, Input::new(&[("input.txt", b"different")]).begin("key")),
        TaskErrorCode::IdempotencyConflict,
    );
}
#[test]
fn chunk_retry_keeps_inode_bytes_and_offsets_and_mixed_or_gap_ranges_fail() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("x")).unwrap();
    let a = s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    assert_eq!(a.blobs[0].durable_offset, 3);
    let path = f.payload(&v.upload_id, &i.files[0].sha256);
    let before = inventory(&path);
    assert_eq!(s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap(), a);
    assert_eq!(inventory(&path), before);
    for (offset, bytes) in [(1, b"bcde".as_slice()), (4, b"ef"), (0, b"xyz"), (5, b"zz")] {
        assert!(
            s.execute(&c, i.chunk(&v.upload_id, offset, bytes)).is_err(),
            "invalid prefix/gap/bytes must fail"
        );
        assert_eq!(inventory(&path), before);
    }
    let completed = s.execute(&c, i.chunk(&v.upload_id, 3, b"def")).unwrap();
    assert_eq!(completed.blobs[0].durable_offset, 6);
    assert_eq!(fs::read(path).unwrap(), b"abcdef");
}
#[test]
fn full_upload_seal_is_idempotent_and_get_never_mutates_staging_or_task_gc() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::fixture_blob();
    let original_tasks = inventory(&f.tasks());
    let v = s.execute(&c, i.begin("full")).unwrap();
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
    assert!(
        sealed
            .blobs
            .iter()
            .all(|b| b.durable_offset == b.size_bytes)
    );
    let before = inventory(&f.namespace());
    assert_eq!(get(&s, &c, &v.upload_id), sealed);
    assert_eq!(inventory(&f.namespace()), before);
    assert_eq!(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone()
            }
        )
        .unwrap(),
        sealed
    );
    assert_eq!(s.execute(&c, i.begin("full")).unwrap(), sealed);
    assert_eq!(inventory(&f.tasks()), original_tasks);
    assert!(!f.root.join("data/n3/snapshot-roots-v1.json").exists());
}
#[test]
fn partial_or_wrong_hash_chunks_cannot_seal_or_mutate_confirmed_bytes() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("x")).unwrap();
    assert!(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone()
            }
        )
        .is_err()
    );
    let mut bad = i.chunk(&v.upload_id, 0, b"abc");
    if let SnapshotRequest::PutChunk { chunk_sha256, .. } = &mut bad {
        *chunk_sha256 = sha256(b"bad");
    }
    let before = inventory(&f.namespace());
    assert_code(s.execute(&c, bad), TaskErrorCode::InputIntegrityFailed);
    assert_eq!(inventory(&f.namespace()), before);
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    assert!(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id
            }
        )
        .is_err()
    );
}
#[test]
fn chunk_lengths_and_exact_integer_bounds_reject_before_writes() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("x")).unwrap();
    let before = inventory(&f.namespace());
    // Empty length, checked-add overflow, and declared range are distinct
    // guards. The independent >64KiB case uses a large legal declaration in
    // authority::chunk_hard_limit_is_independent_of_declared_blob_range.
    for request in [
        i.chunk(&v.upload_id, 0, b""),
        i.chunk(&v.upload_id, 0, &vec![0; 65_537]),
        i.chunk(&v.upload_id, MAX_INTEGER, b"aa"),
        i.chunk(&v.upload_id, 0, b"abcdefg"),
    ] {
        assert!(s.execute(&c, request).is_err());
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn every_operation_checks_current_grant_and_restored_grant_preserves_upload() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("x")).unwrap();
    f.grant("revoke", &f.principal, None);
    let before = inventory(&f.namespace());
    for request in [
        i.begin("x"),
        i.chunk(&v.upload_id, 0, b"abc"),
        SnapshotRequest::Get {
            upload_id: v.upload_id.clone(),
        },
        SnapshotRequest::Seal {
            upload_id: v.upload_id.clone(),
        },
        SnapshotRequest::Cancel {
            upload_id: v.upload_id.clone(),
        },
    ] {
        assert_code(s.execute(&c, request), TaskErrorCode::AuthDenied);
        assert_eq!(inventory(&f.namespace()), before);
    }
    f.grant("add", &f.principal, None);
    assert_eq!(get(&s, &c, &v.upload_id), v);
    s.execute(
        &c,
        SnapshotRequest::Cancel {
            upload_id: v.upload_id,
        },
    )
    .unwrap();
}
#[test]
fn expired_and_absent_grants_deny_even_with_valid_authenticated_context() {
    let f = Fixture::standard();
    let s = f.service();
    let i = Input::small();
    let before = inventory(&f.namespace());
    assert_code(
        s.execute(&f.context_for(OTHER), i.begin("x")),
        TaskErrorCode::AuthDenied,
    );
    assert_eq!(inventory(&f.namespace()), before);
    f.grant("add", &f.principal, Some(1));
    assert_code(
        s.execute(&f.context(), i.begin("x")),
        TaskErrorCode::AuthDenied,
    );
    assert_eq!(inventory(&f.namespace()), before);
}
#[test]
fn foreign_context_scope_and_begin_scope_resource_do_not_change_staging() {
    let f = Fixture::standard();
    let s = f.service();
    let i = Input::small();
    let before = inventory(&f.namespace());
    let foreign =
        TaskCallContext::from_authenticated(f.principal.clone(), "foreign".into()).unwrap();
    assert_code(s.execute(&foreign, i.begin("x")), TaskErrorCode::AuthDenied);
    for field in ["provider", "workspace", "resource"] {
        let mut request = i.begin("x");
        if let SnapshotRequest::Begin {
            provider,
            workspace,
            resource,
            ..
        } = &mut request
        {
            match field {
                "provider" => *provider = "foreign".into(),
                "workspace" => *workspace = "foreign".into(),
                _ => *resource = "foreign".into(),
            }
        }
        assert!(s.execute(&f.context(), request).is_err());
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn audit_failure_never_returns_pass_or_writes_payload() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let before = inventory(&f.namespace());
    let journal = f.root.join("n2/journal.log");
    fs::remove_file(&journal).unwrap();
    private_dir(&journal);
    assert_code(
        s.execute(&c, i.begin("x")),
        TaskErrorCode::PersistenceFailed,
    );
    assert_eq!(inventory(&f.namespace()), before);
}
#[test]
fn owner_rejects_all_foreign_upload_operations_including_path_like_ids() {
    let f = Fixture::standard();
    f.grant("add", OTHER, None);
    let s = f.service();
    let i = Input::small();
    let v = s.execute(&f.context(), i.begin("x")).unwrap();
    let before = inventory(&f.namespace());
    for request in [
        i.chunk(&v.upload_id, 0, b"abc"),
        SnapshotRequest::Get {
            upload_id: v.upload_id.clone(),
        },
        SnapshotRequest::Seal {
            upload_id: v.upload_id.clone(),
        },
        SnapshotRequest::Cancel {
            upload_id: v.upload_id.clone(),
        },
        SnapshotRequest::Get {
            upload_id: UploadId::new("../../decoy".into()).unwrap(),
        },
    ] {
        assert!(s.execute(&f.context_for(OTHER), request).is_err());
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn local_execution_uses_existing_identity_and_correlated_envelope() {
    let f = Fixture::standard();
    let s = f.service();
    let i = Input::small();
    let req = i.begin("local");
    let result = s.execute_local(req.clone());
    result.validate_for(&req).unwrap();
    let SnapshotEnvelope::Upload(v) = result else {
        panic!("local owned upload must succeed")
    };
    assert_eq!(v.provider, PROVIDER);
    assert_eq!(v.snapshot, i.snapshot);
}
#[test]
fn cancelled_tombstone_is_terminal_until_ttl_and_backward_clock_never_expires_it() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    s.set_time(1_000_000);
    let v = s.execute(&c, i.begin("x")).unwrap();
    let ended = s
        .execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    s.set_time(1_000_000 - 1);
    assert_eq!(s.execute(&c, i.begin("x")).unwrap(), ended);
    s.set_time(1_000_000 + 86_399);
    assert_eq!(s.execute(&c, i.begin("x")).unwrap(), ended);
    let before = inventory(&f.namespace());
    s.set_time(1_000_000 + 86_400);
    assert_eq!(get(&s, &c, &v.upload_id), ended);
    assert_eq!(inventory(&f.namespace()), before);
    let new = s.execute(&c, i.begin("x")).unwrap();
    assert_ne!(new.upload_id, v.upload_id);
    assert_eq!(new.state, UploadState::Receiving);
}

#[test]
fn two_legitimately_granted_resources_are_distinct_idempotency_namespaces() {
    let f = Fixture::standard();
    f.grant_resource("add", &f.principal, "compute-other", None);
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let a = s.execute(&c, i.begin("same-key")).unwrap();
    let mut other = i.begin("same-key");
    if let SnapshotRequest::Begin { resource, .. } = &mut other {
        *resource = "compute-other".into();
    }
    let b = s.execute(&c, other.clone()).unwrap();
    assert_ne!(a.upload_id, b.upload_id);
    assert_eq!(a.resource, RESOURCE);
    assert_eq!(b.resource, "compute-other");
    assert_eq!(a.reserved_bytes, i.charge());
    assert_eq!(b.reserved_bytes, i.charge());
    assert_eq!(s.execute(&c, i.begin("same-key")).unwrap(), a);
    assert_eq!(s.execute(&c, other).unwrap(), b);
    s.execute(
        &c,
        SnapshotRequest::Cancel {
            upload_id: a.upload_id,
        },
    )
    .unwrap();
    assert_eq!(get(&s, &c, &b.upload_id), b);
}

#[test]
fn each_operation_authorizes_original_record_resource_with_independent_revocation() {
    // Both resources are real grant entries. Each operation has an isolated
    // successful precondition and restores only the revoked original resource.
    // Testing both directions catches either fixed-resource substitution.
    for revoked_resource in [RESOURCE, "compute-other"] {
        let still_granted = if revoked_resource == RESOURCE {
            "compute-other"
        } else {
            RESOURCE
        };
        for operation in ["get", "confirmed-chunk", "seal", "cancel"] {
            let f = Fixture::standard();
            f.grant_resource("add", &f.principal, "compute-other", None);
            let s = f.service();
            let c = f.context();
            let i = Input::small();
            let begin_on = |resource: &str| {
                let mut request = i.begin("same-key");
                if let SnapshotRequest::Begin {
                    resource: field, ..
                } = &mut request
                {
                    *field = resource.into();
                }
                request
            };
            let other = s.execute(&c, begin_on(still_granted)).unwrap();
            let original = s.execute(&c, begin_on(revoked_resource)).unwrap();
            assert_ne!(original.upload_id, other.upload_id);
            assert_eq!(original.resource, revoked_resource);
            s.execute(&c, i.chunk(&original.upload_id, 0, b"abc"))
                .unwrap();
            if matches!(operation, "seal" | "cancel") {
                s.execute(&c, i.chunk(&original.upload_id, 3, b"def"))
                    .unwrap();
                let staged = s
                    .execute(
                        &c,
                        SnapshotRequest::Seal {
                            upload_id: original.upload_id.clone(),
                        },
                    )
                    .unwrap();
                assert_eq!(staged.state, UploadState::Staged);
            }
            let original_view = get(&s, &c, &original.upload_id);
            let request = match operation {
                "get" => SnapshotRequest::Get {
                    upload_id: original.upload_id.clone(),
                },
                "confirmed-chunk" => i.chunk(&original.upload_id, 0, b"abc"),
                "seal" => SnapshotRequest::Seal {
                    upload_id: original.upload_id.clone(),
                },
                _ => SnapshotRequest::Cancel {
                    upload_id: original.upload_id.clone(),
                },
            };
            f.grant_resource("revoke", &f.principal, revoked_resource, None);
            nexus::task_authorization::authorize_use(
                &f.root,
                &f.principal,
                WORKSPACE,
                still_granted,
            )
            .expect("the other resource really remains granted");
            assert_eq!(get(&s, &c, &other.upload_id), other);
            let before = inventory(&f.namespace());
            let durable = s.test_observe(&original.upload_id).unwrap();
            let store = nexus::n2_store::N2Store::open(&f.root).unwrap();
            let audits_before = nexus::n2_store::replay_audit_entries(store.kv()).unwrap();
            assert_code(s.execute(&c, request.clone()), TaskErrorCode::AuthDenied);
            assert_eq!(
                inventory(&f.namespace()),
                before,
                "denied {operation} must preserve all staging files for {revoked_resource}"
            );
            assert_eq!(s.test_observe(&original.upload_id).unwrap(), durable);
            let audits_after = nexus::n2_store::replay_audit_entries(store.kv()).unwrap();
            assert_eq!(
                &audits_after[..audits_before.len()],
                audits_before.as_slice()
            );
            let expected_resource = nexus_domain::ResourceRef::new(
                nexus_domain::WorkspaceId::new(WORKSPACE),
                nexus_domain::ResourceName::new(revoked_resource).unwrap(),
            )
            .to_string();
            assert!(
                audits_after[audits_before.len()..]
                    .iter()
                    .any(|(tag, json)| {
                        let entry: serde_json::Value = serde_json::from_str(json).unwrap();
                        tag == "auth"
                            && entry["workspace"] == WORKSPACE
                            && entry["principal"] == f.principal
                            && entry["resource"] == expected_resource
                            && entry["operation"] == "use"
                            && entry["decision"] == "deny"
                    }),
                "denied {operation} requires a current Use audit for the original {revoked_resource}"
            );
            // Restoring the original resource makes precisely the same request
            // valid; no malformed input/incomplete Seal can mask authorization.
            f.grant_resource("add", &f.principal, revoked_resource, None);
            assert_eq!(get(&s, &c, &original.upload_id), original_view);
            let restored = s.execute(&c, request).unwrap();
            assert_eq!(restored.upload_id, original.upload_id);
            assert_eq!(restored.resource, revoked_resource);
            assert_eq!(restored.snapshot, i.snapshot);
            if operation == "cancel" {
                assert_eq!(restored.state, UploadState::Cancelled);
                assert_eq!(restored.reserved_bytes, 0);
                assert!(restored.blobs.is_empty());
            } else {
                assert_eq!(restored, original_view);
            }
            assert_eq!(get(&s, &c, &other.upload_id), other);
        }
    }
}

#[test]
fn receiving_staged_and_cancelled_keys_keep_original_snapshot_binding() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let changed = Input::new(&[("input.txt", b"different")]);
    let v = s.execute(&c, i.begin("original")).unwrap();
    for state in [
        UploadState::Receiving,
        UploadState::Staged,
        UploadState::Cancelled,
    ] {
        if state == UploadState::Staged {
            i.upload_all(&s, &c, &v.upload_id);
            s.execute(
                &c,
                SnapshotRequest::Seal {
                    upload_id: v.upload_id.clone(),
                },
            )
            .unwrap();
        } else if state == UploadState::Cancelled {
            s.execute(
                &c,
                SnapshotRequest::Cancel {
                    upload_id: v.upload_id.clone(),
                },
            )
            .unwrap();
        }
        let original = get(&s, &c, &v.upload_id);
        assert_eq!(original.state, state);
        let before = inventory(&f.namespace());
        assert_code(
            s.execute(&c, changed.begin("original")),
            TaskErrorCode::IdempotencyConflict,
        );
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(s.execute(&c, i.begin("original")).unwrap(), original);
    }
}

#[test]
fn valid_chunk_hashes_never_allow_full_blob_digest_mismatch_to_be_staged() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small(); // declared SHA is SHA256(abcdef), not SHA256(uvwxyz).
    let v = s.execute(&c, i.begin("wrong-full-hash")).unwrap();
    let chunk = i.chunk(&v.upload_id, 0, b"uvwxyz");
    // The independent chunk hash is valid, and any acknowledged prefix hash
    // must describe uvwxyz. Thus prefix validation cannot mask the full-SHA oracle.
    match s.execute(&c, chunk) {
        Err(error) => assert_eq!(error.code, TaskErrorCode::InputIntegrityFailed),
        Ok(view) => {
            assert_eq!(view.blobs[0].durable_offset, 6);
            assert_ne!(view.state, UploadState::Staged);
            assert_eq!(
                fs::read(f.payload(&v.upload_id, &i.files[0].sha256)).unwrap(),
                b"uvwxyz"
            );
            let before = inventory(&f.namespace());
            assert_code(
                s.execute(
                    &c,
                    SnapshotRequest::Seal {
                        upload_id: v.upload_id.clone(),
                    },
                ),
                TaskErrorCode::InputIntegrityFailed,
            );
            assert_eq!(inventory(&f.namespace()), before);
        }
    }
    let durable = s.test_observe(&v.upload_id).unwrap();
    assert_ne!(durable.view.state, UploadState::Staged);
    assert_eq!(durable.view.reserved_bytes, i.charge());
}

#[test]
fn externally_changed_complete_blob_or_manifest_cannot_be_sealed_and_preserves_charge() {
    // The independent full-SHA oracle is the test above: its chunk prefix SHA
    // is correct for the wrong full bytes. These additional corruption cases
    // intentionally accept earlier owned-file integrity rejection.
    for damage in ["blob", "manifest"] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let v = s.execute(&c, i.begin("pre-seal-damage")).unwrap();
        i.upload_all(&s, &c, &v.upload_id);
        let original = s.test_observe(&v.upload_id).unwrap();
        assert_eq!(original.view.state, UploadState::Receiving);
        assert_eq!(original.view.blobs[0].durable_offset, 6);
        let path = if damage == "blob" {
            f.payload(&v.upload_id, &i.files[0].sha256)
        } else {
            f.namespace()
                .join("uploads")
                .join(v.upload_id.as_str())
                .join("manifest-v1.json")
        };
        let inode = fs::metadata(&path).unwrap();
        let bytes = if damage == "blob" {
            b"abcDex".to_vec()
        } else {
            // A well-formed canonical manifest with a changed executable bit;
            // its immutable original SnapshotRef binding is deliberately kept.
            let mut changed = i.files.clone();
            changed[0].executable = true;
            changed.to_value().canonical_bytes()
        };
        fs::write(&path, bytes).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode.ino());
        let evidence = inventory(&f.namespace());
        let error = s
            .execute(
                &c,
                SnapshotRequest::Seal {
                    upload_id: v.upload_id.clone(),
                },
            )
            .unwrap_err();
        assert!(
            matches!(
                error.code,
                TaskErrorCode::InputIntegrityFailed | TaskErrorCode::StateCorrupt
            ),
            "{damage}: {error:?}"
        );
        assert_eq!(inventory(&f.namespace()), evidence);
        assert_eq!(s.test_observe(&v.upload_id).unwrap(), original);
        drop(s);
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(inventory(&f.namespace()), evidence);
    }
}

#[test]
fn every_operation_requires_successful_real_audit_before_any_staging_write() {
    for operation in ["begin", "chunk", "get", "seal", "cancel"] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let v = s.execute(&c, i.begin("original")).unwrap();
        if operation == "seal" {
            i.upload_all(&s, &c, &v.upload_id);
        }
        let request = match operation {
            "begin" => i.begin("next"),
            "chunk" => i.chunk(&v.upload_id, 0, b"abc"),
            "get" => SnapshotRequest::Get {
                upload_id: v.upload_id.clone(),
            },
            "seal" => SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            },
            _ => SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        };
        let before = inventory(&f.namespace());
        // Actual journal IO failure; no mocked authorization or fake grant.
        let journal = f.root.join("n2/journal.log");
        fs::remove_file(&journal).unwrap();
        private_dir(&journal);
        assert_code(s.execute(&c, request), TaskErrorCode::PersistenceFailed);
        assert_eq!(
            inventory(&f.namespace()),
            before,
            "audit failure: {operation}"
        );
    }
}

#[test]
fn provider_generated_namespace_and_fixed_files_do_not_grow_with_confirmed_chunks() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("safe-name")).unwrap();
    let name = v.upload_id.as_str();
    assert!(!name.is_empty() && name.len() <= 256);
    assert!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    );
    let names = |path: &Path| {
        let mut names = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let mut root_names = [
        "policy-v1.json",
        "staging.lock",
        "ledger-v1.json",
        "uploads",
    ]
    .map(std::ffi::OsString::from)
    .to_vec();
    root_names.sort();
    assert_eq!(names(&f.namespace()), root_names);
    let upload = f.namespace().join("uploads").join(name);
    assert_eq!(
        names(&upload),
        ["blobs", "manifest-v1.json"].map(std::ffi::OsString::from)
    );
    let digest_basename = i.files[0].sha256.as_str().strip_prefix("sha256:").unwrap();
    assert_eq!(
        names(&upload.join("blobs")),
        [std::ffi::OsString::from(digest_basename)]
    );
    let entries = inventory(&upload);
    let original_names = entries
        .iter()
        .map(|entry| entry.relative.clone())
        .collect::<Vec<_>>();
    for (offset, byte) in b"abcdef".iter().enumerate() {
        s.execute(&c, i.chunk(&v.upload_id, offset as u64, &[*byte]))
            .unwrap();
        assert_eq!(
            inventory(&upload)
                .iter()
                .map(|entry| entry.relative.clone())
                .collect::<Vec<_>>(),
            original_names
        );
        assert_eq!(names(&f.namespace()), root_names);
        let observed = s.test_observe(&v.upload_id).unwrap();
        assert!(observed.chunk.is_none());
        assert!(observed.actual_record_bytes <= observed.future_ceiling_bytes);
        assert!(observed.future_ceiling_bytes <= 524_288);
    }
}

#[test]
fn confirmed_prefix_accepts_same_bytes_subranges_and_cross_chunk_boundary_retries() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::new(&[("input.txt", b"abcdefghijkl")]);
    let original = s.execute(&c, i.begin("subranges")).unwrap();
    let first = s
        .execute(&c, i.chunk(&original.upload_id, 0, b"abc"))
        .unwrap();
    assert_eq!(first.blobs[0].durable_offset, 3);
    let confirmed = s
        .execute(&c, i.chunk(&original.upload_id, 3, b"defghi"))
        .unwrap();
    assert_eq!(confirmed.state, UploadState::Receiving);
    assert_eq!(confirmed.blobs[0].durable_offset, 9);
    assert_eq!(confirmed.reserved_bytes, i.charge());
    let path = f.payload(&original.upload_id, &i.files[0].sha256);
    assert_eq!(fs::read(&path).unwrap(), b"abcdefghi");
    let payload = inventory(&path);
    for (offset, bytes) in [
        (1, b"bc".as_slice()), // Different start, ends exactly at the first boundary.
        (0, b"ab"),            // Original start, different length.
        (2, b"cdef"),          // Crosses the original boundary at offset 3.
        (3, b"def"),           // Original second start, different length.
        (7, b"hi"),            // Ends exactly at the confirmed-prefix boundary.
    ] {
        let retry = s
            .execute(&c, i.chunk(&original.upload_id, offset, bytes))
            .unwrap();
        assert_eq!(
            retry,
            confirmed,
            "legal confirmed subrange {offset}+{}",
            bytes.len()
        );
        assert_eq!(
            inventory(&path),
            payload,
            "retry must not rewrite or replace payload"
        );
        let before_get = inventory(&f.namespace());
        assert_eq!(get(&s, &c, &original.upload_id), confirmed);
        assert_eq!(inventory(&f.namespace()), before_get);
    }
    let completed = s
        .execute(&c, i.chunk(&original.upload_id, 9, b"jkl"))
        .unwrap();
    assert_eq!(completed.blobs[0].durable_offset, 12);
    assert_eq!(completed.reserved_bytes, i.charge());
    assert_eq!(fs::read(path).unwrap(), b"abcdefghijkl");
}

// Use only instance-local test time: no sleep and no wall-clock-dependent expiry.
fn active_upload_survives_tombstone_ttl(staged: bool) {
    const CREATED: u64 = 1_000_000;
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let s = f.service();
    s.set_time(CREATED);
    let c = f.context();
    let v = s.execute(&c, i.begin("retained-active")).unwrap();
    let prefixed = s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    assert_eq!(prefixed.blobs[0].durable_offset, 3);
    if staged {
        s.execute(&c, i.chunk(&v.upload_id, 3, b"def")).unwrap();
        let sealed = s
            .execute(
                &c,
                SnapshotRequest::Seal {
                    upload_id: v.upload_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(sealed.state, UploadState::Staged);
    }
    let original = get(&s, &c, &v.upload_id);
    assert_eq!(original.snapshot, i.snapshot);
    assert_eq!(original.reserved_bytes, i.charge());
    assert_eq!(
        original.state,
        if staged {
            UploadState::Staged
        } else {
            UploadState::Receiving
        }
    );
    assert_eq!(original.blobs[0].durable_offset, if staged { 6 } else { 3 });
    let upload_dir = f.namespace().join("uploads").join(v.upload_id.as_str());
    let payload = inventory(&upload_dir);
    let manifest = fs::read(upload_dir.join("manifest-v1.json")).unwrap();
    assert_eq!(manifest, i.manifest.as_bytes());
    let expected_bytes: &[u8] = if staged { b"abcdef" } else { b"abc" };
    assert_eq!(
        fs::read(f.payload(&v.upload_id, &i.files[0].sha256)).unwrap(),
        expected_bytes
    );
    for now in [CREATED + 86_399, CREATED + 86_401] {
        s.set_time(now);
        let before_get = inventory(&f.namespace());
        assert_eq!(get(&s, &c, &v.upload_id), original);
        assert_eq!(inventory(&f.namespace()), before_get);
        // An authorized, valid mutating request reaches TTL cleanup. Same-key
        // Begin and legal repeat Seal/chunk must preserve this active record.
        assert_eq!(s.execute(&c, i.begin("retained-active")).unwrap(), original);
        let request = if staged {
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            }
        } else {
            i.chunk(&v.upload_id, 0, b"abc")
        };
        assert_eq!(s.execute(&c, request).unwrap(), original);
        assert_eq!(inventory(&upload_dir), payload);
        let before_reject = inventory(&f.namespace());
        assert_code(
            s.execute(&c, i.begin("new-key")),
            TaskErrorCode::CapacityUnavailable,
        );
        assert_eq!(inventory(&f.namespace()), before_reject);
        assert_eq!(s.test_observe(&v.upload_id).unwrap().view, original);
    }
    drop(s);
    let s = FileSnapshotStaging::open_with_test_time(&f.root, CREATED + 2 * 86_400 + 1)
        .expect("cold open long-lived active record")
        .expect("staging remains provisioned");
    assert_eq!(s.test_observe(&v.upload_id).unwrap().view, original);
    assert_eq!(
        inventory(&upload_dir),
        payload,
        "cold TTL cleanup cannot replace or remove active input"
    );
    let before_get = inventory(&f.namespace());
    assert_eq!(get(&s, &c, &v.upload_id), original);
    assert_eq!(inventory(&f.namespace()), before_get);
    assert_eq!(s.execute(&c, i.begin("retained-active")).unwrap(), original);
    let request = if staged {
        SnapshotRequest::Seal {
            upload_id: v.upload_id.clone(),
        }
    } else {
        i.chunk(&v.upload_id, 0, b"abc")
    };
    assert_eq!(s.execute(&c, request).unwrap(), original);
    let before_reject = inventory(&f.namespace());
    assert_code(
        s.execute(&c, i.begin("new-key")),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_eq!(inventory(&f.namespace()), before_reject);
    assert_eq!(inventory(&upload_dir), payload);
    assert_eq!(s.test_observe(&v.upload_id).unwrap().view, original);
}

#[test]
fn receiving_nonzero_prefix_never_expires_at_tombstone_ttl_or_cold_open() {
    active_upload_survives_tombstone_ttl(false);
}

#[test]
fn staged_input_never_expires_at_tombstone_ttl_or_cold_open() {
    active_upload_survives_tombstone_ttl(true);
}

#[test]
fn cancelled_tombstone_rejects_original_owner_chunk_and_seal_without_revival() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("terminal-no-revival")).unwrap();
    // Both requests have a positive control on this exact original upload:
    // the chunk is genuinely confirmed and Seal has accepted the full input.
    let original_chunk = i.chunk(&v.upload_id, 0, b"abc");
    s.execute(&c, original_chunk.clone()).unwrap();
    s.execute(&c, i.chunk(&v.upload_id, 3, b"def")).unwrap();
    let seal = SnapshotRequest::Seal {
        upload_id: v.upload_id.clone(),
    };
    let staged = s.execute(&c, seal.clone()).unwrap();
    assert_eq!(staged.state, UploadState::Staged);
    let ended = s
        .execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(ended.state, UploadState::Cancelled);
    assert_eq!(ended.reserved_bytes, 0);
    assert!(ended.blobs.is_empty());
    assert_eq!(ended.snapshot, i.snapshot);
    let upload_dir = f.namespace().join("uploads").join(v.upload_id.as_str());
    assert!(!upload_dir.exists());
    let durable = s.test_observe(&v.upload_id).unwrap();
    assert_eq!(durable.view, ended);
    let before = inventory(&f.namespace());
    for request in [original_chunk, seal] {
        nexus::task_authorization::authorize_use(&f.root, &f.principal, WORKSPACE, RESOURCE)
            .expect("the original owner still has a current real Use grant");
        assert!(
            s.execute(&c, request).is_err(),
            "Cancelled must reject PutChunk and Seal"
        );
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(s.test_observe(&v.upload_id).unwrap(), durable);
        assert_eq!(get(&s, &c, &v.upload_id), ended);
        assert_eq!(inventory(&f.namespace()), before);
        assert!(
            !upload_dir.exists(),
            "terminal rejection cannot rebuild payload"
        );
    }
}

#[test]
fn chunk_target_must_be_declared_by_this_upload_even_when_another_upload_owns_it() {
    for progress in ["partial", "full-receiving"] {
        for target in ["fresh-unlisted", "other-own-upload", "other-owner-upload"] {
            let f = Fixture::standard();
            if target == "other-owner-upload" {
                f.grant("add", OTHER, None);
            }
            let s = f.service();
            let c = f.context();
            let i = Input::small(); // declared full hash is SHA256(abcdef).
            let original = s.execute(&c, i.begin("membership-original")).unwrap();
            let prefixed = s
                .execute(&c, i.chunk(&original.upload_id, 0, b"abc"))
                .unwrap();
            assert_eq!(prefixed.blobs[0].durable_offset, 3);
            if progress == "full-receiving" {
                s.execute(&c, i.chunk(&original.upload_id, 3, b"def"))
                    .unwrap();
            }
            // SHA256(abc) differs from the original declared SHA256(abcdef),
            // but is the correct full SHA for the test chunk's exact bytes.
            // A wrongly-created empty target cannot reject a gap/full hash.
            let unlisted = sha256(b"abc");
            assert_ne!(unlisted, i.files[0].sha256);
            let other = Input::new(&[("other.txt", b"abc")]);
            let donor = if target == "fresh-unlisted" {
                None
            } else {
                let owner = if target == "other-owner-upload" {
                    f.context_for(OTHER)
                } else {
                    f.context()
                };
                let donor = s.execute(&owner, other.begin("membership-donor")).unwrap();
                other.upload_all(&s, &owner, &donor.upload_id);
                assert_eq!(
                    fs::read(f.payload(&donor.upload_id, &unlisted)).unwrap(),
                    b"abc"
                );
                assert_eq!(get(&s, &owner, &donor.upload_id).blobs[0].durable_offset, 3);
                Some(donor.upload_id)
            };
            let durable = s.test_observe(&original.upload_id).unwrap();
            assert_eq!(durable.view.state, UploadState::Receiving);
            assert_eq!(durable.view.reserved_bytes, i.charge());
            assert_eq!(
                durable.view.blobs[0].durable_offset,
                if progress == "partial" { 3 } else { 6 }
            );
            let donor_before = donor.as_ref().map(|id| s.test_observe(id).unwrap());
            let before = inventory(&f.namespace());
            let legitimate = i.chunk(&original.upload_id, 0, b"abc");
            let mut unlisted_request = legitimate.clone();
            if let SnapshotRequest::PutChunk { blob_sha256, .. } = &mut unlisted_request {
                *blob_sha256 = unlisted.clone();
            }
            // Only membership differs. Owner, current Use, Receiving state,
            // nonzero original prefix, offset zero, size and both hashes are
            // otherwise valid; no path for the undeclared digest may appear.
            assert!(
                s.execute(&c, unlisted_request).is_err(),
                "unlisted target: {progress}/{target}"
            );
            assert_eq!(inventory(&f.namespace()), before);
            assert_eq!(s.test_observe(&original.upload_id).unwrap(), durable);
            assert!(!f.payload(&original.upload_id, &unlisted).exists());
            if let Some(id) = &donor {
                assert_eq!(s.test_observe(id).unwrap(), donor_before.unwrap());
            }
            assert_eq!(s.execute(&c, legitimate).unwrap(), durable.view);
            assert_eq!(
                s.test_observe(&original.upload_id).unwrap().view,
                durable.view,
                "a declared confirmed-prefix retry is a real positive control"
            );
            if progress == "partial" {
                let completed = s
                    .execute(&c, i.chunk(&original.upload_id, 3, b"def"))
                    .unwrap();
                assert_eq!(completed.blobs[0].durable_offset, 6);
                assert_eq!(completed.reserved_bytes, i.charge());
            }
        }
    }
}

fn state_authorization_fixture(
    state: &str,
) -> (
    Fixture,
    FileSnapshotStaging,
    TaskCallContext,
    Input,
    UploadView,
) {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("state-control")).unwrap();
    i.upload_all(&s, &c, &v.upload_id);
    match state {
        "staged" => {
            assert_eq!(
                s.execute(
                    &c,
                    SnapshotRequest::Seal {
                        upload_id: v.upload_id.clone()
                    }
                )
                .unwrap()
                .state,
                UploadState::Staged
            );
        }
        "cancelling" => {
            s.set_fault("cancel_intent_durable");
            assert_code(
                s.execute(
                    &c,
                    SnapshotRequest::Cancel {
                        upload_id: v.upload_id.clone(),
                    },
                ),
                TaskErrorCode::PersistenceFailed,
            );
            s.set_fault("");
        }
        "cancelled" => {
            assert_eq!(
                s.execute(
                    &c,
                    SnapshotRequest::Cancel {
                        upload_id: v.upload_id.clone()
                    }
                )
                .unwrap()
                .state,
                UploadState::Cancelled
            );
        }
        "receiving" => {}
        _ => panic!("unknown test state"),
    }
    let original = s.test_observe(&v.upload_id).unwrap().view;
    assert_eq!(
        original.state,
        match state {
            "receiving" => UploadState::Receiving,
            "staged" => UploadState::Staged,
            "cancelling" => UploadState::Cancelling,
            _ => UploadState::Cancelled,
        }
    );
    assert_eq!(original.snapshot, i.snapshot);
    assert_eq!(
        original.reserved_bytes,
        if state == "cancelled" { 0 } else { i.charge() }
    );
    (f, s, c, i, original)
}

fn state_operation(state: &str, operation: &str, i: &Input, v: &UploadView) -> SnapshotRequest {
    match operation {
        "same-begin" => i.begin("state-control"),
        "new-begin" => i.begin("new-authorized-key"),
        "get" => SnapshotRequest::Get {
            upload_id: v.upload_id.clone(),
        },
        "chunk" if state == "receiving" => i.chunk(&v.upload_id, 0, b"abc"),
        "seal" if matches!(state, "receiving" | "staged") => SnapshotRequest::Seal {
            upload_id: v.upload_id.clone(),
        },
        "cancel" => SnapshotRequest::Cancel {
            upload_id: v.upload_id.clone(),
        },
        _ => panic!("operation is not a legal positive control for this state"),
    }
}

fn current_authorization_is_required_before_state_shortcuts(state: &str, denial: &str) {
    let operations: &[&str] = match state {
        "receiving" => &["same-begin", "new-begin", "get", "chunk", "seal", "cancel"],
        "staged" => &["same-begin", "new-begin", "get", "seal", "cancel"],
        // The state table explicitly permits Get/Cancel for Cancelling.
        // New-key Begin exercises admission authorization independently; do
        // not invent a stronger same-key Begin success rule for this state.
        "cancelling" => &["new-begin", "get", "cancel"],
        _ => &["same-begin", "new-begin", "get", "cancel"],
    };
    for operation in operations {
        let (f, s, c, i, original) = state_authorization_fixture(state);
        let request = state_operation(state, operation, &i, &original);
        nexus::task_authorization::authorize_use(&f.root, &f.principal, WORKSPACE, RESOURCE)
            .expect("current valid grant before the isolated denial");
        let durable = s.test_observe(&original.upload_id).unwrap();
        let journal = f.root.join("n2/journal.log");
        let saved_journal = f.base.join("saved-original-audit-journal");
        match denial {
            "revoked" => f.grant("revoke", &f.principal, None),
            "expired" => f.grant("add", &f.principal, Some(1)),
            "audit-failure" => {
                fs::rename(&journal, &saved_journal).unwrap();
                private_dir(&journal);
            }
            _ => panic!("unknown denial"),
        }
        if denial != "audit-failure" {
            assert_code(
                nexus::task_authorization::authorize_use(
                    &f.root,
                    &f.principal,
                    WORKSPACE,
                    RESOURCE,
                ),
                TaskErrorCode::AuthDenied,
            );
        }
        let before = inventory(&f.namespace());
        assert_code(
            s.execute(&c, request.clone()),
            if denial == "audit-failure" {
                TaskErrorCode::PersistenceFailed
            } else {
                TaskErrorCode::AuthDenied
            },
        );
        assert_eq!(
            inventory(&f.namespace()),
            before,
            "{state}/{operation}/{denial}: no staging side effect"
        );
        assert_eq!(
            s.test_observe(&original.upload_id).unwrap(),
            durable,
            "{state}/{operation}/{denial}: retain original intent/offset/terminal/charge"
        );
        if denial == "audit-failure" {
            fs::remove_dir(&journal).unwrap();
            fs::rename(&saved_journal, &journal).unwrap();
        } else {
            f.grant("add", &f.principal, None);
        }
        let restored = s.execute(&c, request).unwrap();
        assert_eq!(restored.snapshot, i.snapshot);
        if *operation == "new-begin" {
            assert_ne!(restored.upload_id, original.upload_id);
            assert_eq!(restored.state, UploadState::Receiving);
            assert_eq!(restored.reserved_bytes, i.charge());
        } else {
            assert_eq!(restored.upload_id, original.upload_id);
            match *operation {
                "cancel" => {
                    assert_eq!(restored.state, UploadState::Cancelled);
                    assert_eq!(restored.reserved_bytes, 0);
                    assert!(restored.blobs.is_empty());
                }
                "seal" => {
                    assert_eq!(restored.state, UploadState::Staged);
                    assert_eq!(restored.reserved_bytes, i.charge());
                }
                _ => {
                    assert_eq!(restored, original);
                    if *operation == "get" {
                        assert_eq!(
                            inventory(&f.namespace()),
                            before,
                            "Get must preserve all original durable staging files"
                        );
                    }
                }
            }
        }
    }
}

macro_rules! state_authorization_matrix {
    ($name:ident, $state:literal, $denial:literal) => {
        #[test]
        fn $name() {
            current_authorization_is_required_before_state_shortcuts($state, $denial);
        }
    };
}
state_authorization_matrix!(
    receiving_shortcuts_require_unrevoked_current_use,
    "receiving",
    "revoked"
);
state_authorization_matrix!(
    receiving_shortcuts_require_unexpired_current_use,
    "receiving",
    "expired"
);
state_authorization_matrix!(
    receiving_shortcuts_require_successful_current_audit,
    "receiving",
    "audit-failure"
);
state_authorization_matrix!(
    staged_shortcuts_require_unrevoked_current_use,
    "staged",
    "revoked"
);
state_authorization_matrix!(
    staged_shortcuts_require_unexpired_current_use,
    "staged",
    "expired"
);
state_authorization_matrix!(
    staged_shortcuts_require_successful_current_audit,
    "staged",
    "audit-failure"
);
state_authorization_matrix!(
    cancelling_shortcuts_require_unrevoked_current_use,
    "cancelling",
    "revoked"
);
state_authorization_matrix!(
    cancelling_shortcuts_require_unexpired_current_use,
    "cancelling",
    "expired"
);
state_authorization_matrix!(
    cancelling_shortcuts_require_successful_current_audit,
    "cancelling",
    "audit-failure"
);
state_authorization_matrix!(
    cancelled_shortcuts_require_unrevoked_current_use,
    "cancelled",
    "revoked"
);
state_authorization_matrix!(
    cancelled_shortcuts_require_unexpired_current_use,
    "cancelled",
    "expired"
);
state_authorization_matrix!(
    cancelled_shortcuts_require_successful_current_audit,
    "cancelled",
    "audit-failure"
);

#[test]
fn cancelled_shortcuts_never_expose_or_reuse_another_currently_authorized_owners_record() {
    let (f, s, owner, i, ended) = state_authorization_fixture("cancelled");
    f.grant("add", OTHER, None);
    let foreign = f.context_for(OTHER);
    nexus::task_authorization::authorize_use(&f.root, OTHER, WORKSPACE, RESOURCE)
        .expect("foreign trusted context independently has a current real Use grant");
    let other_input = Input::new(&[("other-owner.txt", b"other-owner-input")]);
    let own = s
        .execute(&foreign, other_input.begin("state-control"))
        .unwrap();
    assert_ne!(own.upload_id, ended.upload_id);
    assert_eq!(own.snapshot, other_input.snapshot);
    let foreign_ended = s
        .execute(
            &foreign,
            SnapshotRequest::Cancel {
                upload_id: own.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(foreign_ended.state, UploadState::Cancelled);
    let original = s.test_observe(&ended.upload_id).unwrap();
    for request in [
        SnapshotRequest::Get {
            upload_id: ended.upload_id.clone(),
        },
        SnapshotRequest::Cancel {
            upload_id: ended.upload_id.clone(),
        },
    ] {
        let before = inventory(&f.namespace());
        assert_code(s.execute(&foreign, request), TaskErrorCode::AuthDenied);
        assert_eq!(inventory(&f.namespace()), before);
        assert_eq!(s.test_observe(&ended.upload_id).unwrap(), original);
        assert_eq!(get(&s, &owner, &ended.upload_id), ended);
        assert_eq!(inventory(&f.namespace()), before);
    }
    // Same key is scoped by authenticated principal: the other owner gets
    // their own cancelled binding, even though both principals remain granted.
    assert_eq!(
        s.execute(&foreign, other_input.begin("state-control"))
            .unwrap(),
        foreign_ended
    );
    assert_eq!(s.execute(&owner, i.begin("state-control")).unwrap(), ended);
    assert_eq!(get(&s, &foreign, &own.upload_id), foreign_ended);
    assert_eq!(s.test_observe(&ended.upload_id).unwrap(), original);
}

#[test]
fn foreign_seal_of_complete_receiving_and_staged_upload_is_auth_denied_without_changes() {
    let f = Fixture::standard();
    f.grant("add", OTHER, None);
    let s = f.service();
    let owner = f.context();
    let foreign = f.context_for(OTHER);
    let i = Input::small();
    let begun = s.execute(&owner, i.begin("complete-owned-seal")).unwrap();
    i.upload_all(&s, &owner, &begun.upload_id);
    let receiving = s.test_observe(&begun.upload_id).unwrap();
    assert_eq!(receiving.view.state, UploadState::Receiving);
    assert_eq!(receiving.view.snapshot, i.snapshot);
    assert_eq!(receiving.view.reserved_bytes, i.charge());
    assert_eq!(receiving.view.blobs.len(), i.payloads.len());
    assert!(!receiving.view.blobs.is_empty());
    assert!(
        receiving
            .view
            .blobs
            .iter()
            .all(|blob| blob.durable_offset == blob.size_bytes)
    );
    assert_eq!(
        fs::read(f.payload(&begun.upload_id, &i.files[0].sha256)).unwrap(),
        b"abcdef"
    );
    nexus::task_authorization::authorize_use(&f.root, OTHER, WORKSPACE, RESOURCE)
        .expect("foreign principal independently has the same current real Use grant");
    let seal = SnapshotRequest::Seal {
        upload_id: begun.upload_id.clone(),
    };
    let before = inventory(&f.namespace());
    let upload = f.namespace().join("uploads").join(begun.upload_id.as_str());
    let original_payload_and_manifest = inventory(&upload);
    // This exact request is otherwise fully sealable. Owner is the single
    // invalid condition; incomplete blobs cannot mask a missing owner check.
    assert_code(s.execute(&foreign, seal.clone()), TaskErrorCode::AuthDenied);
    assert_eq!(inventory(&f.namespace()), before);
    assert_eq!(s.test_observe(&begun.upload_id).unwrap(), receiving);
    assert_eq!(get(&s, &owner, &begun.upload_id), receiving.view);
    assert_eq!(inventory(&f.namespace()), before);
    let staged = s.execute(&owner, seal.clone()).unwrap();
    assert_eq!(staged.state, UploadState::Staged);
    assert_eq!(staged.snapshot, i.snapshot);
    assert_eq!(staged.reserved_bytes, i.charge());
    assert_eq!(staged.blobs, receiving.view.blobs);
    assert_eq!(inventory(&upload), original_payload_and_manifest);
    let durable_staged = s.test_observe(&begun.upload_id).unwrap();
    assert_eq!(durable_staged.view, staged);
    let before_repeat = inventory(&f.namespace());
    // The repeated Seal shortcut must still check original upload ownership.
    assert_code(s.execute(&foreign, seal.clone()), TaskErrorCode::AuthDenied);
    assert_eq!(inventory(&f.namespace()), before_repeat);
    assert_eq!(s.test_observe(&begun.upload_id).unwrap(), durable_staged);
    assert_eq!(get(&s, &owner, &begun.upload_id), staged);
    assert_eq!(s.execute(&owner, seal).unwrap(), staged);
    assert_eq!(inventory(&f.namespace()), before_repeat);
    assert_eq!(inventory(&upload), original_payload_and_manifest);
}
