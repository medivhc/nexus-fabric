//! Upload-cost baseline (AGENTS.md §21). Not a gate: run explicitly with
//! `cargo test --release -p nexusd --lib snapshot_staging::tests::baseline -- --ignored --nocapture`.
use super::*;
use std::time::Instant;

const CHUNK: usize = 65_536;

/// Uploads one blob of `mib` MiB in 64 KiB chunks and reports wall time for the
/// whole upload plus the first/last 16 chunks, so per-chunk growth is visible.
fn upload_cost(mib: usize) -> (u128, u128, u128) {
    let payload = (0..mib * 1024 * 1024)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let i = Input::new(&[("blob.bin", payload.as_slice())]);
    let f = Fixture::new(MAX_INTEGER, 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("baseline")).unwrap();
    let digest = &i.files[0].sha256;
    let chunks = payload.chunks(CHUNK).collect::<Vec<_>>();
    let mut per_chunk = Vec::with_capacity(chunks.len());
    let start = Instant::now();
    for (n, chunk) in chunks.iter().enumerate() {
        let t = Instant::now();
        s.execute(
            &c,
            SnapshotRequest::PutChunk {
                upload_id: v.upload_id.clone(),
                blob_sha256: digest.clone(),
                offset: (n * CHUNK) as u64,
                bytes: chunk.to_vec(),
                chunk_sha256: sha256(chunk),
            },
        )
        .unwrap();
        per_chunk.push(t.elapsed().as_micros());
    }
    let total = start.elapsed().as_millis();
    let k = per_chunk.len().min(16);
    let first = per_chunk[..k].iter().sum::<u128>() / k as u128;
    let last = per_chunk[per_chunk.len() - k..].iter().sum::<u128>() / k as u128;
    (total, first, last)
}

#[test]
#[ignore = "performance baseline; run explicitly with --release --ignored"]
fn put_chunk_cost_by_upload_size() {
    for mib in [4, 8, 16, 32, 64] {
        let (total_ms, first_us, last_us) = upload_cost(mib);
        println!(
            "{{\"bench\":\"snapshot_staging.put_chunk\",\"upload_mib\":{mib},\"chunks\":{},\"total_ms\":{total_ms},\"first16_avg_us\":{first_us},\"last16_avg_us\":{last_us}}}",
            mib * 1024 * 1024 / CHUNK
        );
    }
}
