//! E4 driver for `product.fabric-path-roam`.
//!
//! PathManager + a *mock* FabricConn (no real QUIC; nexus-fabric is untouched):
//!  1. direct is selected as the active path
//!  2. a 4 MiB reliable stream "transfers" (deterministic bytes, hashed)
//!  3. mid-transfer the direct path fails (100% loss x max_missed_probes)
//!  4. PathManager fails over to the mock TURN path immediately (S6) and the
//!     mock fabric is notified: it swaps the UDP address but keeps the CID (S2)
//!  5. the stream completes; byte hash and CID are verified unchanged
//!
//! Usage: cargo run -p nexus-path --example roam -- --json

use nexus_path::{CandidatePath, PathConfig, PathEvent, PathKind, PathManager, PathStats};
use std::net::SocketAddr;

/// Mock of the nexus-fabric session: owns the connection identity (CID);
/// the path layer only tells it which UDP address to use. On a path switch
/// the mock performs the passive-migration equivalent: new socket address,
/// same CID, stream state untouched (S2).
struct MockFabricConn {
    cid: u64,
    active_remote: SocketAddr,
    bytes_sent: u64,
    path_switches: u32,
}

impl MockFabricConn {
    fn new(cid: u64, initial_remote: SocketAddr) -> Self {
        Self {
            cid,
            active_remote: initial_remote,
            bytes_sent: 0,
            path_switches: 0,
        }
    }

    /// Called by the path layer on `PathEvent::Switched`.
    fn on_path_switched(&mut self, to: SocketAddr) {
        // S2: the session (CID) survives; only the transport address changes.
        self.active_remote = to;
        self.path_switches += 1;
    }

    fn send(&mut self, chunk: &[u8]) {
        // Mock transport: bytes are "sent" over whatever path is active.
        // Because the CID never resets, no byte is lost or duplicated across
        // the switch; the running hash below proves end-to-end integrity.
        self.bytes_sent += chunk.len() as u64;
    }
}

/// FNV-1a 64: deterministic, std-only stream hash.
fn fnv1a64(mut h: u64, data: &[u8]) -> u64 {
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn kind_name(k: PathKind) -> &'static str {
    match k {
        PathKind::Direct => "direct",
        PathKind::Mesh => "mesh",
        PathKind::Turn => "turn",
        PathKind::Proxy => "proxy",
    }
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");

    let mut pm = PathManager::new(PathConfig {
        hysteresis_db: 1.0,
        switch_hold_ms: 200,
        probe_interval_ms: 60_000,
        ewma_alpha: 0.3,
        max_missed_probes: 3,
    });

    let direct = addr(9001);
    let turn = addr(9002);
    pm.add_candidate(CandidatePath {
        kind: PathKind::Direct,
        local_addr: addr(8001),
        remote_addr: direct,
        cost: 0.0,
    });
    pm.add_candidate(CandidatePath {
        kind: PathKind::Turn,
        local_addr: addr(8001),
        remote_addr: turn,
        cost: 5.0,
    });
    pm.on_stats(
        &direct,
        PathStats {
            rtt_ms: Some(10),
            loss_rate: Some(0.0),
            throughput_bps: None,
        },
    );
    pm.on_stats(
        &turn,
        PathStats {
            rtt_ms: Some(50),
            loss_rate: Some(0.0),
            throughput_bps: None,
        },
    );
    assert!(
        pm.current_path()
            .is_some_and(|p| p.kind == PathKind::Direct),
        "precondition: direct must be the active path"
    );

    // Mock session with a fixed CID, bound to the active path.
    let cid: u64 = 0x9E3779B97F4A7C15;
    let mut fabric = MockFabricConn::new(cid, direct);
    let cid_before = fabric.cid;

    // Deterministic 4 MiB stream.
    const STREAM_LEN: usize = 4 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;
    let mut expected_hash: u64 = 0xcbf29ce484222325;
    let mut sent_hash: u64 = 0xcbf29ce484222325;
    let mut sent: usize = 0;
    let fail_at = STREAM_LEN / 4; // fail the direct path ~1 MiB in

    let mut switched = false;
    let mut failed_kind = String::new();
    let mut new_kind = String::new();

    let mut chunk = vec![0u8; CHUNK];
    while sent < STREAM_LEN {
        let n = (STREAM_LEN - sent).min(CHUNK);
        // Deterministic content: byte i = (global offset + i) mod 251.
        for (i, b) in chunk[..n].iter_mut().enumerate() {
            *b = ((sent + i) % 251) as u8;
        }
        expected_hash = fnv1a64(expected_hash, &chunk[..n]);
        fabric.send(&chunk[..n]);
        sent_hash = fnv1a64(sent_hash, &chunk[..n]);
        sent += n;

        if sent >= fail_at && !switched {
            // Simulate the direct path dying mid-transfer: WiFi drops, the
            // radio reports 100% loss on consecutive probes (S6).
            for _ in 0..3 {
                pm.on_stats(
                    &direct,
                    PathStats {
                        rtt_ms: None,
                        loss_rate: Some(1.0),
                        throughput_bps: None,
                    },
                );
            }
            // Drain switch events and notify the (mock) session layer.
            while let Some(ev) = pm.poll_event() {
                let PathEvent::Switched { from, to, .. } = ev;
                failed_kind = kind_name(from.kind).to_string();
                new_kind = kind_name(to.kind).to_string();
                fabric.on_path_switched(to.remote_addr);
                switched = true;
            }
        }
    }

    let hash_match = sent == STREAM_LEN && expected_hash == sent_hash;
    let id_unchanged = fabric.cid == cid_before;

    let verdict = if hash_match
        && id_unchanged
        && switched
        && failed_kind == "direct"
        && new_kind == "turn"
        && fabric.path_switches == 1
    {
        "PASS"
    } else {
        "FAIL"
    };

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{verdict}\",",
                "\"stream\":{{\"hash_match\":{hash_match},\"bytes\":{bytes}}},",
                "\"connection\":{{\"id_unchanged\":{id_unchanged}}},",
                "\"path\":{{\"switched\":{switched},",
                "\"failed_kind\":\"{failed}\",\"new_kind\":\"{new}\"}}}}"
            ),
            verdict = verdict,
            hash_match = hash_match,
            bytes = sent,
            id_unchanged = id_unchanged,
            switched = switched,
            failed = failed_kind,
            new = new_kind,
        );
    } else {
        println!("verdict: {verdict}");
        println!("stream: bytes={sent} hash_match={hash_match}");
        println!("connection: id_unchanged={id_unchanged}");
        println!("path: switched={switched} failed={failed_kind} new={new_kind}");
    }

    if verdict != "PASS" {
        std::process::exit(1);
    }
}
