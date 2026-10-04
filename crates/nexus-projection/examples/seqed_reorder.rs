//! E4: product.multipath-quic-seq (GAP-2)
//!
//! Two FabricConn endpoints over loopback UDP in one process:
//! - Sender uses `send_datagram_seqed` (QSEQ): verifies assigned seqes are
//!   strictly monotonic.
//! - Receiver uses `recv_datagram_seqed`: verifies the 8-byte BE header
//!   round-trips (received seq == assigned seq).
//! - Received datagrams are shuffled (simulating per-packet multipath
//!   reordering), fed into `ReorderBuffer`, and verified to come out in
//!   order with intact payloads.
//! - A wraparound sub-test drives `ReorderBuffer` across `u64::MAX -> 0`
//!   (the fabric counter itself starts at 0; wraparound of the *reorder*
//!   logic is what GAP-2 P1/P2 covers).
//!
//! Prints exactly one JSON line to stdout.

use nexus_fabric::{ConnConfig, FabricConn, FabricListener};
use nexus_projection::multipath::ReorderBuffer;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

const DATAGRAMS: usize = 50;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn main() {
    let (json, pass) = match run() {
        Ok(x) => x,
        Err(e) => (
            format!("{{\"verdict\":\"FAIL\",\"detail\":\"{}\"}}", esc(&e)),
            false,
        ),
    };
    println!("{json}");
    if !pass {
        std::process::exit(1);
    }
}

fn run() -> Result<(String, bool), String> {
    let listener =
        FabricListener::bind("127.0.0.1:0".parse().unwrap()).map_err(|e| format!("bind: {e}"))?;
    let server_peer = listener.peer_id();
    let server_addr: SocketAddr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    // Server: accept, receive DATAGRAMS seqed datagrams, return them.
    let server = thread::spawn(move || -> Result<Vec<(u64, Vec<u8>)>, String> {
        let conn = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let mut out = Vec::new();
        for _ in 0..DATAGRAMS {
            let (seq, payload) = conn
                .recv_datagram_seqed()
                .map_err(|e| format!("recv_datagram_seqed: {e}"))?;
            out.push((seq, payload));
        }
        Ok(out)
    });

    // Client: connect, send DATAGRAMS seqed datagrams, record assigned seqes.
    let cfg = ConnConfig {
        addrs: vec![server_addr],
        handshake_timeout: Duration::from_secs(10),
    };
    let conn = FabricConn::connect(server_peer, &cfg).map_err(|e| format!("connect: {e}"))?;

    let mut assigned = Vec::with_capacity(DATAGRAMS);
    for i in 0..DATAGRAMS {
        // Deterministic payload: seq index encoded in bytes.
        let payload = vec![(i & 0xFF) as u8; 64];
        let seq = conn
            .send_datagram_seqed(&payload)
            .map_err(|e| format!("send_datagram_seqed: {e}"))?;
        assigned.push((seq, payload));
    }

    let received = server
        .join()
        .map_err(|_| "server thread panicked".to_string())??;

    // Q2: assigned seqes strictly monotonic (mod 2^64; here far from wrap).
    let mut seq_monotonic = true;
    for w in assigned.windows(2) {
        if w[1].0 != w[0].0.wrapping_add(1) {
            seq_monotonic = false;
            break;
        }
    }
    // First assigned seq is 0 (fresh connection, Q1).
    if assigned.first().map(|(s, _)| *s) != Some(0) {
        seq_monotonic = false;
    }

    // Q3: header roundtrip — received seqes match assigned seqes (as sets;
    // QUIC datagrams are unreliable but loopback should deliver all).
    let mut assigned_sorted: Vec<u64> = assigned.iter().map(|(s, _)| *s).collect();
    let mut received_sorted: Vec<u64> = received.iter().map(|(s, _)| *s).collect();
    assigned_sorted.sort_unstable();
    received_sorted.sort_unstable();
    let seq_header_roundtrip = assigned_sorted == received_sorted
        && received.len() == DATAGRAMS
        && received
            .iter()
            .all(|(s, p)| p.len() == 64 && p[0] == (*s as usize & 0xFF) as u8);

    // Simulate per-packet multipath reordering: reverse the arrival order,
    // feed into ReorderBuffer, verify in-order emission with intact payloads.
    let mut shuffled = received.clone();
    shuffled.reverse();
    // Also swap a couple to break the pure reversal pattern.
    if shuffled.len() >= 4 {
        shuffled.swap(1, 3);
    }
    let mut rb = ReorderBuffer::new(64);
    for (seq, payload) in &shuffled {
        rb.push(*seq, payload.clone());
    }
    let out = rb.pop_in_order();
    let reorder_in_order =
        out.len() == DATAGRAMS && out.iter().enumerate().all(|(i, (s, _))| *s == i as u64);
    let reorder_payload_match = out
        .iter()
        .enumerate()
        .all(|(i, (_, p))| p.len() == 64 && p[0] == (i & 0xFF) as u8);

    // Wraparound sub-test (P1/P2): drive ReorderBuffer across u64::MAX -> 0.
    let mut rb2 = ReorderBuffer::new(64);
    rb2.reset(u64::MAX - 1);
    for seq in [0u64, u64::MAX, 2, u64::MAX - 1, 1] {
        rb2.push(seq, vec![(seq & 0xFF) as u8]);
    }
    let out2 = rb2.pop_in_order();
    let wraparound_covered = out2.len() == 5
        && out2.iter().map(|(s, _)| *s).collect::<Vec<u64>>()
            == vec![u64::MAX - 1, u64::MAX, 0, 1, 2]
        && rb2.dropped_duplicate() == 0;

    let pass = seq_monotonic
        && seq_header_roundtrip
        && reorder_in_order
        && reorder_payload_match
        && wraparound_covered;

    let json = format!(
        "{{\
            \"verdict\":\"{}\",\
            \"sender\":{{\"seq_monotonic\":{},\"wraparound_covered\":{}}},\
            \"seq_header\":{{\"roundtrip\":{}}},\
            \"reorder\":{{\"in_order\":{},\"payload_match\":{}}}\
        }}",
        if pass { "PASS" } else { "FAIL" },
        seq_monotonic,
        wraparound_covered,
        seq_header_roundtrip,
        reorder_in_order,
        reorder_payload_match,
    );
    Ok((json, pass))
}
