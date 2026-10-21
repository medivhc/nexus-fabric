use super::*;

// Get is allowed to append the required authorization audit, but it must not
// advance, recover, or clean a genuine pending staging transaction (§§4,5,7).
// Read the actual durable record before and after, not an in-memory projection.
fn pending_get_is_read_only(
    f: &Fixture,
    s: &FileSnapshotStaging,
    c: &TaskCallContext,
    id: &UploadId,
    cutpoint: &str,
) {
    s.set_fault("");
    let durable = s.test_observe(id).unwrap();
    let before = inventory(&f.namespace());
    assert_eq!(
        get(s, c, id),
        durable.view,
        "Get must return the original authoritative view without recovery: {cutpoint}"
    );
    assert_eq!(
        inventory(&f.namespace()),
        before,
        "Get must not append, publish ledger, unlink scratch, or clean payload: {cutpoint}"
    );
    assert_eq!(
        s.test_observe(id).unwrap(),
        durable,
        "Get must preserve intent, offsets, and charge: {cutpoint}"
    );
}

fn interrupted_chunk(cutpoint: &'static str, expected_offset: u64) {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("x")).unwrap();
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    let path = f.payload(&v.upload_id, &i.files[0].sha256);
    let original = fs::metadata(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"abc");
    s.set_fault(cutpoint);
    assert_code(
        s.execute(&c, i.chunk(&v.upload_id, 3, b"def")),
        TaskErrorCode::PersistenceFailed,
    );
    let interrupted = s.test_observe(&v.upload_id).unwrap();
    assert_eq!(interrupted.view.upload_id, v.upload_id);
    assert_eq!(interrupted.view.snapshot, i.snapshot);
    assert_eq!(interrupted.view.state, UploadState::Receiving);
    assert_eq!(interrupted.view.reserved_bytes, i.charge());
    let committed = matches!(
        cutpoint,
        "chunk_committed_cleanup_durable" | "chunk_scratch_deleted" | "chunk_cleared_durable"
    );
    assert_eq!(
        interrupted.view.blobs[0].durable_offset,
        if committed { 6 } else { 3 }
    );
    if let Some(intent) = &interrupted.chunk {
        assert_eq!(intent.old_offset, 3);
        assert_eq!(intent.next_offset, 6);
        assert_eq!(intent.chunk_sha256, sha256(b"def"));
    } else {
        assert_eq!(cutpoint, "chunk_cleared_durable");
    }
    assert!(fs::read(&path).unwrap().starts_with(b"abc"));
    // These are healthy, owned transactions made by the real API. A denied
    // grant or corrupted scratch/prefix must not mask the zero-write oracle.
    pending_get_is_read_only(&f, &s, &c, &v.upload_id, cutpoint);
    drop(s);
    let s = f.open();
    let recovered = get(&s, &c, &v.upload_id);
    assert_eq!(recovered.upload_id, v.upload_id);
    assert_eq!(recovered.snapshot, i.snapshot);
    assert_eq!(recovered.reserved_bytes, i.charge());
    assert_eq!(
        recovered.blobs[0].durable_offset, expected_offset,
        "cutpoint {cutpoint}"
    );
    let after = fs::metadata(&path).unwrap();
    assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
    assert_eq!(
        fs::read(&path).unwrap(),
        &b"abcdef"[..expected_offset as usize]
    );
    assert_code(
        s.execute(&c, i.begin("competitor")),
        TaskErrorCode::CapacityUnavailable,
    );
    if expected_offset == 3 {
        s.execute(&c, i.chunk(&v.upload_id, 3, b"def")).unwrap();
    }
    assert_eq!(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id
            }
        )
        .unwrap()
        .state,
        UploadState::Staged
    );
}
macro_rules! chunk_cutpoint {
    ($name:ident,$point:literal,$offset:expr) => {
        #[test]
        fn $name() {
            interrupted_chunk($point, $offset);
        }
    };
}
chunk_cutpoint!(
    cold_chunk_intent_before_scratch_keeps_old_offset,
    "chunk_intent_durable",
    3
);
chunk_cutpoint!(
    cold_chunk_unconfirmed_scratch_does_not_advance_offset,
    "chunk_scratch_written",
    3
);
chunk_cutpoint!(
    cold_chunk_scratch_ready_replays_exact_original_bytes,
    "chunk_scratch_ready_durable",
    6
);
chunk_cutpoint!(
    cold_chunk_appended_tail_is_verified_and_completed,
    "chunk_blob_appended",
    6
);
chunk_cutpoint!(
    cold_chunk_blob_durable_does_not_lose_confirmed_bytes,
    "chunk_blob_durable",
    6
);
chunk_cutpoint!(
    cold_chunk_committed_cleanup_keeps_new_offset,
    "chunk_committed_cleanup_durable",
    6
);
chunk_cutpoint!(
    cold_chunk_scratch_deleted_keeps_new_offset,
    "chunk_scratch_deleted",
    6
);
chunk_cutpoint!(
    cold_chunk_clear_durable_keeps_new_offset,
    "chunk_cleared_durable",
    6
);

fn interrupted_begin(cutpoint: &'static str) {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let s = f.service();
    let c = f.context();
    s.set_fault(cutpoint);
    assert_code(
        s.execute(&c, i.begin("x")),
        TaskErrorCode::PersistenceFailed,
    );
    let original_id = s.test_last_generated_upload_id().unwrap();
    let durable = s.test_observe(&original_id).unwrap();
    assert_eq!(durable.view.upload_id, original_id);
    assert_eq!(durable.view.reserved_bytes, i.charge());
    assert_eq!(durable.view.snapshot, i.snapshot);
    let published = inventory(&f.namespace().join("uploads").join(original_id.as_str()));
    if cutpoint == "begin_manifest_durable" {
        assert!(published.iter().any(|entry| entry.relative
            == std::path::Path::new("manifest-v1.json")
            && entry.bytes.as_deref() == Some(i.manifest.as_bytes())));
    }
    drop(s);
    let s = f.open();
    let recovered = s.test_observe(&original_id).unwrap();
    assert_eq!(recovered.view.upload_id, original_id);
    assert_eq!(recovered.view.reserved_bytes, i.charge());
    assert_code(
        s.execute(&c, i.begin("competitor")),
        TaskErrorCode::CapacityUnavailable,
    );
    let v = s.execute(&c, i.begin("x")).unwrap();
    assert_eq!(
        v.upload_id, original_id,
        "cold recovery cannot discard the original Begin transaction"
    );
    assert_eq!(v.snapshot, i.snapshot);
    assert_eq!(v.state, UploadState::Receiving);
    assert_eq!(v.reserved_bytes, i.charge());
    assert_eq!(v.blobs[0].durable_offset, 0);
    let after = inventory(&f.namespace().join("uploads").join(original_id.as_str()));
    for entry in &published {
        let kept = after.iter().find(|e| e.relative == entry.relative).unwrap();
        assert_eq!(
            kept, entry,
            "published manifest/payload cannot be recreated"
        );
    }
    let exact = inventory(&f.namespace());
    assert_eq!(s.execute(&c, i.begin("x")).unwrap(), v);
    assert_eq!(inventory(&f.namespace()), exact);
}
macro_rules! begin_cutpoint {
    ($name:ident,$point:literal) => {
        #[test]
        fn $name() {
            interrupted_begin($point);
        }
    };
}
begin_cutpoint!(
    cold_begin_reserved_record_reuses_original_key,
    "begin_reservation_durable"
);
begin_cutpoint!(
    cold_begin_manifest_durable_keeps_reservation,
    "begin_manifest_durable"
);
begin_cutpoint!(
    cold_atomic_tmp_recovers_single_known_transition,
    "ledger_tmp_durable"
);
begin_cutpoint!(
    cold_atomic_replace_recovers_original_request,
    "ledger_replaced"
);
begin_cutpoint!(
    cold_atomic_directory_fsync_keeps_original_request,
    "ledger_directory_durable"
);

fn interrupted_seal(cutpoint: &'static str) {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("x")).unwrap();
    i.upload_all(&s, &c, &v.upload_id);
    let payload = f.payload(&v.upload_id, &i.files[0].sha256);
    let original_payload = fs::metadata(&payload).unwrap();
    let original_bytes = fs::read(&payload).unwrap();
    let full_view = get(&s, &c, &v.upload_id);
    assert_eq!(full_view.blobs[0].durable_offset, 6);
    s.set_fault(cutpoint);
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            },
        ),
        TaskErrorCode::PersistenceFailed,
    );
    let pending = s.test_observe(&v.upload_id).unwrap();
    assert_eq!(
        pending.view.state,
        if cutpoint == "seal_intent_durable" {
            UploadState::Receiving
        } else {
            UploadState::Staged
        }
    );
    assert_eq!(pending.view.reserved_bytes, i.charge());
    assert_eq!(pending.view.blobs, full_view.blobs);
    pending_get_is_read_only(&f, &s, &c, &v.upload_id, cutpoint);
    drop(s);
    let s = f.open();
    // Observe cold recovery before any retry can re-create the transition.
    let durable = s.test_observe(&v.upload_id).unwrap();
    let mut expected = full_view;
    expected.state = UploadState::Staged;
    assert_eq!(
        durable.view, expected,
        "boot must finish/retain Seal: {cutpoint}"
    );
    let before_get = inventory(&f.namespace());
    let recovered = get(&s, &c, &v.upload_id);
    assert_eq!(recovered, expected);
    assert_eq!(inventory(&f.namespace()), before_get);
    assert_eq!(s.test_observe(&v.upload_id).unwrap(), durable);
    assert_eq!(fs::read(&payload).unwrap(), original_bytes);
    let after = fs::metadata(&payload).unwrap();
    assert_eq!(
        (after.dev(), after.ino()),
        (original_payload.dev(), original_payload.ino())
    );
    let sealed = s
        .execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(sealed, recovered);
    assert_eq!(fs::read(&payload).unwrap(), original_bytes);
    let after_retry = fs::metadata(&payload).unwrap();
    assert_eq!(
        (after_retry.dev(), after_retry.ino()),
        (original_payload.dev(), original_payload.ino())
    );
}
#[test]
fn cold_seal_intent_finishes_same_snapshot() {
    interrupted_seal("seal_intent_durable");
}
#[test]
fn cold_staged_lost_reply_keeps_same_snapshot() {
    interrupted_seal("seal_staged_durable");
}

fn interrupted_cancel(cutpoint: &'static str) {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("x")).unwrap();
    i.upload_all(&s, &c, &v.upload_id);
    s.set_fault(cutpoint);
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        ),
        TaskErrorCode::PersistenceFailed,
    );
    let observed = s.test_observe(&v.upload_id).unwrap();
    assert_eq!(observed.view.upload_id, v.upload_id);
    assert_eq!(observed.view.snapshot, i.snapshot);
    // Cover CleanupIntent both before and after physical deletion, and the
    // committed tombstone, while this original instance is still open.
    pending_get_is_read_only(&f, &s, &c, &v.upload_id, cutpoint);
    let payload = f.payload(&v.upload_id, &i.files[0].sha256);
    if matches!(
        cutpoint,
        "cancel_intent_durable" | "cancel_before_payload_delete"
    ) {
        assert_eq!(fs::read(&payload).unwrap(), b"abcdef");
    } else {
        assert!(
            !payload.exists(),
            "post-delete cutpoint must really follow unlink"
        );
    }
    if cutpoint != "cancel_release_durable" {
        assert_eq!(observed.view.state, UploadState::Cancelling);
        assert_eq!(observed.view.reserved_bytes, i.charge());
        if cutpoint != "cancel_directory_durable_before_release" {
            // If Begin attempts to recover cleanup, a real directory-fsync
            // failure prevents durable deletion proof. Otherwise it can simply
            // deny capacity. Either way no unconfirmed refund is spendable.
            s.set_fault("cancel_directory_sync_failed");
            assert!(
                s.execute(&c, i.begin("next")).is_err(),
                "cannot spend an unconfirmed deletion refund"
            );
            let still = s.test_observe(&v.upload_id).unwrap();
            assert_eq!(still.view.reserved_bytes, i.charge());
            assert_eq!(still.view.state, UploadState::Cancelling);
        }
    } else {
        assert_eq!(observed.view.state, UploadState::Cancelled);
        assert_eq!(observed.view.reserved_bytes, 0);
        assert!(
            !f.namespace()
                .join("uploads")
                .join(v.upload_id.as_str())
                .exists()
        );
    }
    s.set_fault("");
    drop(s);
    let s = f.open();
    // Cold open must finish CleanupIntent before a retry can do the work.
    // This is the checksummed durable record, observed without mutation.
    let durable = s.test_observe(&v.upload_id).unwrap();
    let mut expected = v.clone();
    expected.state = UploadState::Cancelled;
    expected.reserved_bytes = 0;
    expected.blobs.clear();
    assert_eq!(
        durable.view, expected,
        "boot must finish Cancel: {cutpoint}"
    );
    assert!(
        !f.namespace()
            .join("uploads")
            .join(v.upload_id.as_str())
            .exists(),
        "boot must physically remove the original upload: {cutpoint}"
    );
    let before_get = inventory(&f.namespace());
    assert_eq!(get(&s, &c, &v.upload_id), expected);
    assert_eq!(inventory(&f.namespace()), before_get);
    assert_eq!(s.test_observe(&v.upload_id).unwrap(), durable);
    // Only after the cold-recovery oracle, test the explicit retry separately.
    let ended = s
        .execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(ended, expected);
    assert_eq!(ended.state, UploadState::Cancelled);
    assert_eq!(ended.reserved_bytes, 0);
    assert!(ended.blobs.is_empty());
    assert_eq!(ended.upload_id, v.upload_id);
    assert_eq!(ended.snapshot, i.snapshot);
    assert_eq!(s.execute(&c, i.begin("x")).unwrap(), ended);
    assert!(
        !f.namespace()
            .join("uploads")
            .join(v.upload_id.as_str())
            .exists()
    );
    assert_eq!(
        s.execute(&c, i.begin("next")).unwrap().reserved_bytes,
        i.charge()
    );
}
#[test]
fn cold_cancelling_intent_cleans_before_releasing() {
    interrupted_cancel("cancel_intent_durable");
}
#[test]
fn cold_cancel_deleted_payload_completes_release() {
    interrupted_cancel("cancel_payload_deleted");
}
#[test]
fn cold_cancel_before_delete_retains_charge() {
    interrupted_cancel("cancel_before_payload_delete");
}
#[test]
fn cold_cancel_directory_fsync_failure_retains_charge() {
    interrupted_cancel("cancel_directory_sync_failed");
}
#[test]
fn cold_cancel_directory_fsync_durable_still_precedes_refund() {
    interrupted_cancel("cancel_directory_durable_before_release");
}
#[test]
fn cold_cancel_release_lost_reply_keeps_terminal_tombstone() {
    interrupted_cancel("cancel_release_durable");
}

#[test]
fn pending_initialize_crash_is_fail_closed_without_reset() {
    let f = Fixture::standard();
    let failure =
        initialize_with_test_fault(&f.root, &f.budget, "init_pending_durable").unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::PersistenceFailed);
    assert!(failure.mutation_may_have_applied);
    let before = inventory(&f.root);
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    assert_eq!(
        initialize(&f.root, &f.budget).unwrap_err().error.code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(inventory(&f.root), before);
}
#[test]
fn completed_initialize_lost_reply_is_idempotent_same_inodes() {
    let f = Fixture::standard();
    let failure =
        initialize_with_test_fault(&f.root, &f.budget, "init_complete_durable").unwrap_err();
    assert_eq!(failure.error.code, TaskErrorCode::PersistenceFailed);
    assert!(failure.mutation_may_have_applied);
    let before = inventory(&f.namespace());
    assert!(!f.initialize().changed);
    assert_eq!(inventory(&f.namespace()), before);
    f.open();
}

#[test]
fn scratch_ready_consistent_partial_tail_recovers_without_touching_confirmed_prefix() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("partial-tail")).unwrap();
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    let path = f.payload(&v.upload_id, &i.files[0].sha256);
    let m = fs::metadata(&path).unwrap();
    s.set_fault("chunk_scratch_ready_durable");
    assert_code(
        s.execute(&c, i.chunk(&v.upload_id, 3, b"def")),
        TaskErrorCode::PersistenceFailed,
    );
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"d")
        .unwrap();
    drop(s);
    let s = f.open();
    let recovered = get(&s, &c, &v.upload_id);
    assert_eq!(recovered.blobs[0].durable_offset, 6);
    assert_eq!(recovered.reserved_bytes, i.charge());
    assert_eq!(fs::read(&path).unwrap(), b"abcdef");
    let after = fs::metadata(path).unwrap();
    assert_eq!((after.dev(), after.ino()), (m.dev(), m.ino()));
}

#[test]
fn before_scratch_ready_owned_partial_scratch_keeps_nonzero_confirmed_prefix() {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("partial-scratch")).unwrap();
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    let path = f.payload(&v.upload_id, &i.files[0].sha256);
    let original = fs::metadata(&path).unwrap();
    s.set_fault("chunk_scratch_written");
    assert_code(
        s.execute(&c, i.chunk(&v.upload_id, 3, b"def")),
        TaskErrorCode::PersistenceFailed,
    );
    let scratch = f
        .namespace()
        .join("uploads")
        .join(v.upload_id.as_str())
        .join("chunk.tmp");
    // Preserve the genuinely owned inode, emulating a short write before the
    // durable ScratchReady transition. No receipt or authority is fabricated.
    fs::OpenOptions::new()
        .write(true)
        .open(&scratch)
        .unwrap()
        .set_len(1)
        .unwrap();
    assert_eq!(fs::read(&scratch).unwrap(), b"d");
    assert_eq!(fs::read(&path).unwrap(), b"abc");
    drop(s);
    let s = f.open();
    let recovered = get(&s, &c, &v.upload_id);
    assert_eq!(recovered.blobs[0].durable_offset, 3);
    assert_eq!(recovered.reserved_bytes, i.charge());
    assert_eq!(recovered.upload_id, v.upload_id);
    assert_eq!(fs::read(&path).unwrap(), b"abc");
    let after = fs::metadata(&path).unwrap();
    assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
    assert!(!scratch.exists());
    s.execute(&c, i.chunk(&v.upload_id, 3, b"def")).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"abcdef");
}

#[test]
fn pending_chunk_unprovable_scratch_tail_or_confirmed_prefix_is_preserved_fail_closed() {
    for damage in [
        "scratch-missing",
        "scratch-changed",
        "scratch-replaced",
        "before-ready-tail",
        "ready-inconsistent-tail",
        "prefix-changed",
        "prefix-short",
        "committed-range-changed",
        "committed-prefix-changed",
    ] {
        let i = Input::small();
        let f = Fixture::new(GLOBAL + i.charge(), 8);
        let s = f.service();
        let c = f.context();
        let v = s.execute(&c, i.begin("pending")).unwrap();
        s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
        let point = match damage {
            "before-ready-tail" => "chunk_intent_durable",
            "committed-range-changed" | "committed-prefix-changed" => {
                "chunk_committed_cleanup_durable"
            }
            _ => "chunk_scratch_ready_durable",
        };
        s.set_fault(point);
        assert_code(
            s.execute(&c, i.chunk(&v.upload_id, 3, b"def")),
            TaskErrorCode::PersistenceFailed,
        );
        let durable = s.test_observe(&v.upload_id).unwrap();
        assert_eq!(durable.view.reserved_bytes, i.charge());
        let intent = durable.chunk.as_ref().unwrap();
        assert_eq!((intent.old_offset, intent.next_offset), (3, 6));
        assert_eq!(intent.chunk_sha256, sha256(b"def"));
        let path = f.payload(&v.upload_id, &i.files[0].sha256);
        let scratch = f
            .namespace()
            .join("uploads")
            .join(v.upload_id.as_str())
            .join("chunk.tmp");
        match damage {
            "scratch-missing" => fs::remove_file(&scratch).unwrap(),
            "scratch-changed" => fs::write(&scratch, b"XYZ").unwrap(),
            "scratch-replaced" => {
                let bytes = fs::read(&scratch).unwrap();
                fs::rename(&scratch, f.base.join("original-scratch")).unwrap();
                private_file(&scratch, &bytes);
            }
            "before-ready-tail" | "ready-inconsistent-tail" => {
                use std::io::Write;
                let byte = if damage == "before-ready-tail" {
                    b"d"
                } else {
                    b"X"
                };
                fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(byte)
                    .unwrap();
            }
            "prefix-changed" => fs::write(&path, b"zbc").unwrap(),
            "prefix-short" => fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(2)
                .unwrap(),
            "committed-range-changed" => fs::write(&path, b"abcDex").unwrap(),
            _ => fs::write(&path, b"zbcdef").unwrap(),
        }
        let evidence = inventory(&f.namespace());
        assert_code(
            s.execute(
                &c,
                SnapshotRequest::Get {
                    upload_id: v.upload_id.clone(),
                },
            ),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(
            inventory(&f.namespace()),
            evidence,
            "live must retain evidence: {damage}"
        );
        assert_eq!(
            s.test_observe(&v.upload_id).unwrap(),
            durable,
            "read-only ledger projection must preserve original reservation: {damage}"
        );
        drop(s);
        assert_code(
            FileSnapshotStaging::open(&f.root),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(
            inventory(&f.namespace()),
            evidence,
            "cold must not reset/refund: {damage}"
        );
    }
}
