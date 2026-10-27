//! N3-12 §5 "每请求校验时机" / nexusd MODULE Performance Budget: every request
//! fully re-hashes every record's confirmed prefix exactly once at entry; later
//! checkpoints in the same request must not stream it again.
use super::*;

const CHUNK: usize = 65_536;

fn hashed_by(f: impl FnOnce()) -> u64 {
    super::super::backend::test_take_hashed_bytes();
    f();
    super::super::backend::test_take_hashed_bytes()
}

fn put(
    s: &FileSnapshotStaging,
    c: &TaskCallContext,
    id: &UploadId,
    digest: &nexus_domain::task::Sha256Digest,
    payload: &[u8],
    n: usize,
) {
    let bytes = &payload[n * CHUNK..(n + 1) * CHUNK];
    s.execute(
        c,
        SnapshotRequest::PutChunk {
            upload_id: id.clone(),
            blob_sha256: digest.clone(),
            offset: (n * CHUNK) as u64,
            bytes: bytes.to_vec(),
            chunk_sha256: sha256(bytes),
        },
    )
    .unwrap();
}

#[test]
fn put_chunk_hashes_confirmed_prefix_exactly_once() {
    let a_payload = (0..32 * CHUNK).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    let b_payload = (0..8 * CHUNK).map(|n| (n % 241) as u8).collect::<Vec<_>>();
    let a = Input::new(&[("a.bin", a_payload.as_slice())]);
    let b = Input::new(&[("b.bin", b_payload.as_slice())]);
    let f = Fixture::new(MAX_INTEGER, 8);
    let s = f.service();
    let c = f.context();
    let va = s.execute(&c, a.begin("budget-a")).unwrap();
    let vb = s.execute(&c, b.begin("budget-b")).unwrap();
    let (da, db) = (&a.files[0].sha256, &b.files[0].sha256);
    // A second, partially uploaded record: entry validation covers every record.
    for n in 0..3 {
        put(&s, &c, &vb.upload_id, db, &b_payload, n);
    }
    let other = (3 * CHUNK) as u64;

    for n in 0..32 {
        let confirmed = (n * CHUNK) as u64 + other;
        let hashed = hashed_by(|| put(&s, &c, &va.upload_id, da, &a_payload, n));
        assert!(
            hashed >= confirmed,
            "chunk {n}: entry must fully verify all confirmed prefixes ({hashed} < {confirmed})"
        );
        assert!(
            hashed <= confirmed + 2 * CHUNK as u64,
            "chunk {n}: confirmed prefixes re-streamed within one request ({hashed} > {confirmed} + 2 chunks)"
        );
    }

    let confirmed = (32 * CHUNK) as u64 + other;
    let hashed = hashed_by(|| {
        get(&s, &c, &va.upload_id);
    });
    assert_eq!(
        hashed, confirmed,
        "Get verifies every confirmed prefix once"
    );
}
