//! N3-12 §5 "每请求校验时机" / nexusd MODULE Performance Budget.
//!
//! Every request fully re-hashes every record's confirmed prefix at entry,
//! before any state change. PutChunk and Get must not read confirmed prefix
//! bytes again; the committed SHA-256(prefix) continues the entry digest.
//! Tampering after entry inside one request is detected by the next request,
//! Seal or cold open, never reaching Staged.
use super::*;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const CHUNK: usize = 65_536;

/// (blob `hash_prefix` bytes, all blob payload bytes read) during `f`.
fn blob_bytes(f: impl FnOnce()) -> (u64, u64) {
    super::super::backend::test_take_blob_bytes();
    f();
    super::super::backend::test_take_blob_bytes()
}

fn put_request(
    id: &UploadId,
    digest: &nexus_domain::task::Sha256Digest,
    payload: &[u8],
    n: usize,
) -> SnapshotRequest {
    let bytes = &payload[n * CHUNK..(n + 1) * CHUNK];
    SnapshotRequest::PutChunk {
        upload_id: id.clone(),
        blob_sha256: digest.clone(),
        offset: (n * CHUNK) as u64,
        bytes: bytes.to_vec(),
        chunk_sha256: sha256(bytes),
    }
}

fn payload(len: usize, salt: usize) -> Vec<u8> {
    (0..len).map(|n| ((n + salt) % 251) as u8).collect()
}

fn flip_byte(path: &Path, at: u64) {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut b = [0u8; 1];
    f.read_exact_at(&mut b, at).unwrap();
    f.write_all_at(&[b[0] ^ 0xff], at).unwrap();
}

#[test]
fn put_chunk_reads_confirmed_prefix_exactly_once() {
    let a_payload = payload(32 * CHUNK, 0);
    let b_payload = payload(8 * CHUNK, 7);
    let a = Input::new(&[("a.bin", a_payload.as_slice())]);
    let b = Input::new(&[("b.bin", b_payload.as_slice())]);
    let f = Fixture::new(MAX_INTEGER, 8);
    let s = f.service();
    let c = f.context();
    let va = s.execute(&c, a.begin("budget-a")).unwrap();
    let vb = s.execute(&c, b.begin("budget-b")).unwrap();
    let (da, db) = (&a.files[0].sha256, &b.files[0].sha256);
    // A second, partially uploaded record: the exact equality below fails if
    // entry validation skips records other than the one being written.
    for n in 0..3 {
        s.execute(&c, put_request(&vb.upload_id, db, &b_payload, n))
            .unwrap();
    }
    let other = (3 * CHUNK) as u64;

    for n in 0..32 {
        let confirmed = (n * CHUNK) as u64 + other;
        let (hashed, read) = blob_bytes(|| {
            s.execute(&c, put_request(&va.upload_id, da, &a_payload, n))
                .unwrap();
        });
        assert_eq!(
            hashed, confirmed,
            "chunk {n}: every confirmed prefix must be hashed exactly once (entry)"
        );
        assert!(
            read >= confirmed && read <= confirmed + CHUNK as u64,
            "chunk {n}: blob payload bytes read {read} outside [{confirmed}, {confirmed} + 1 chunk]"
        );
    }

    let confirmed = (32 * CHUNK) as u64 + other;
    let (hashed, read) = blob_bytes(|| {
        get(&s, &c, &va.upload_id);
    });
    assert_eq!(
        (hashed, read),
        (confirmed, confirmed),
        "Get reads each confirmed prefix once"
    );
}

/// Uploads `before` of 8 chunks, then tampers a confirmed byte after entry
/// validation of PutChunk `before` and before it commits.
fn tamper_inside_put_chunk(
    before: usize,
) -> (
    Fixture,
    FileSnapshotStaging,
    TaskCallContext,
    Input,
    UploadId,
    Vec<u8>,
    PathBuf,
) {
    let data = payload(8 * CHUNK, 3);
    let i = Input::new(&[("t.bin", data.as_slice())]);
    let f = Fixture::new(MAX_INTEGER, 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("tamper")).unwrap();
    let digest = i.files[0].sha256.clone();
    for n in 0..before {
        s.execute(&c, put_request(&v.upload_id, &digest, &data, n))
            .unwrap();
    }
    let path = f.payload(&v.upload_id, &digest);
    let target = path.clone();
    let fired = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fired);
    s.set_tamper("chunk_scratch_ready_durable", move || {
        flip_byte(&target, 10);
        flag.store(true, Ordering::SeqCst);
    });
    // Detection inside this request is allowed but not required (§5).
    let _ = s.execute(&c, put_request(&v.upload_id, &digest, &data, before));
    assert!(
        fired.load(Ordering::SeqCst),
        "tamper hook point was not reached"
    );
    (f, s, c, i, v.upload_id, data, path)
}

#[test]
fn tamper_after_entry_fails_closed_later() {
    let (f, s, c, _i, id, data, _path) = tamper_inside_put_chunk(4);
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Get {
                upload_id: id.clone(),
            },
        ),
        TaskErrorCode::StateCorrupt,
    );
    let digest = sha256(&data);
    assert_code(
        s.execute(&c, put_request(&id, &digest, &data, 5)),
        TaskErrorCode::StateCorrupt,
    );
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: id.clone(),
            },
        ),
        TaskErrorCode::StateCorrupt,
    );
    assert_ne!(
        s.test_observe(&id).unwrap().view.state,
        UploadState::Staged,
        "tampered upload must never reach Staged"
    );
    drop(s);
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
}

#[test]
fn tamper_restored_before_next_request_continues() {
    let (_f, s, c, i, id, data, path) = tamper_inside_put_chunk(4);
    // Undo the damage before the next request: the committed prefix digest
    // must describe the original bytes, so the upload continues to Staged.
    flip_byte(&path, 10);
    let digest = i.files[0].sha256.clone();
    let start = get(&s, &c, &id).blobs[0].durable_offset as usize / CHUNK;
    for n in start..8 {
        s.execute(&c, put_request(&id, &digest, &data, n)).unwrap();
    }
    let sealed = s
        .execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: id.clone(),
            },
        )
        .unwrap();
    assert_eq!(sealed.state, UploadState::Staged);
}

#[test]
fn tamper_inside_final_put_chunk_never_seals() {
    // Every chunk may be durable after this request; Seal must still refuse.
    let (f, s, c, _i, id, _data, _path) = tamper_inside_put_chunk(7);
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: id.clone(),
            },
        ),
        TaskErrorCode::StateCorrupt,
    );
    assert_ne!(
        s.test_observe(&id).unwrap().view.state,
        UploadState::Staged,
        "tampered upload must never reach Staged"
    );
    drop(s);
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
}

#[test]
fn entry_verification_precedes_any_state_change() {
    let a_payload = payload(4 * CHUNK, 1);
    let b_payload = payload(2 * CHUNK, 9);
    let a = Input::new(&[("a.bin", a_payload.as_slice())]);
    let b = Input::new(&[("b.bin", b_payload.as_slice())]);
    let complete = Input::new(&[("c.bin", b"complete-upload")]);
    let fresh = Input::new(&[("d.bin", b"fresh-upload")]);
    let f = Fixture::new(MAX_INTEGER, 8);
    let s = f.service();
    let c = f.context();
    let va = s.execute(&c, a.begin("entry-a")).unwrap();
    let vb = s.execute(&c, b.begin("entry-b")).unwrap();
    let vc = s.execute(&c, complete.begin("entry-c")).unwrap();
    let (da, db) = (&a.files[0].sha256, &b.files[0].sha256);
    for n in 0..2 {
        s.execute(&c, put_request(&va.upload_id, da, &a_payload, n))
            .unwrap();
    }
    // C is fully uploaded and ready to Seal.
    complete.upload_all(&s, &c, &vc.upload_id);
    // Damage a confirmed byte of A between requests.
    flip_byte(&f.payload(&va.upload_id, da), 3);
    let evidence = inventory(&f.namespace());
    let (obs_a, obs_b, obs_c) = (
        s.test_observe(&va.upload_id).unwrap(),
        s.test_observe(&vb.upload_id).unwrap(),
        s.test_observe(&vc.upload_id).unwrap(),
    );
    let requests = [
        (
            "PutChunk on the damaged upload",
            put_request(&va.upload_id, da, &a_payload, 2),
        ),
        (
            "PutChunk on another upload",
            put_request(&vb.upload_id, db, &b_payload, 0),
        ),
        (
            "Cancel",
            SnapshotRequest::Cancel {
                upload_id: vb.upload_id.clone(),
            },
        ),
        (
            "Seal of another, complete upload",
            SnapshotRequest::Seal {
                upload_id: vc.upload_id.clone(),
            },
        ),
        ("Begin with a new key", fresh.begin("entry-fresh")),
    ];
    for (what, request) in requests {
        assert_code(s.execute(&c, request), TaskErrorCode::StateCorrupt);
        assert_eq!(
            inventory(&f.namespace()),
            evidence,
            "{what}: no tree change"
        );
        assert_eq!(
            s.test_observe(&va.upload_id).unwrap(),
            obs_a,
            "{what}: A unchanged"
        );
        assert_eq!(
            s.test_observe(&vb.upload_id).unwrap(),
            obs_b,
            "{what}: B unchanged"
        );
        assert_eq!(
            s.test_observe(&vc.upload_id).unwrap(),
            obs_c,
            "{what}: C unchanged (not Staged)"
        );
    }
}
