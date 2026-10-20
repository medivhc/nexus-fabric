//! AC12: upper-layer file transfer demo over `FlowSessionHub`.
//!
//! Two Hub instances on 127.0.0.1 UDP loopback. A dials B, opens a reliable
//! stream, and sends a file in chunks of at most [`MAX_STREAM_WRITE`]
//! (256 KiB, AC11). B's registered stream service (type byte `0x10`) reads
//! every byte, writes it to the destination path, finishes the send half
//! (so A observes EOF), and prints the SHA-256 of the received bytes.
//!
//! Usage:
//!   cargo run -p nexus-projection --example flow_file_demo \
//!     -- <source> <dest>
//!
//! Without arguments, a deterministic 2 MiB payload is generated in memory
//! and written to `/tmp/flow_file_demo.out` (SHA-256 printed on both
//! sides must match).
//!
//! This example uses only the Hub API (`nexus_projection::flow_session`),
//! no QUIC protocol internals or fabric driver internals (AC1 API-surface
//! discipline).

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_fabric::{Driver, FabricListener, PeerId};
use nexus_nat_wireup::PunchManager;
use nexus_path::{PathConfig, PathManager, RaceBudget};
use nexus_projection::PathLink;
use nexus_projection::flow_session::{
    FlowSessionHub, MAX_STREAM_WRITE, RecvStream, SendStream, StreamHandler,
};
use sha2::{Digest, Sha256};

const SERVICE_FILE: u8 = 0x10;

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn peer_hex(peer: &PeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn fast_config() -> PathConfig {
    PathConfig {
        hysteresis_pct: 0.0,
        switch_hold_ms: 0,
        probe_interval_ms: 60_000,
        ewma_alpha: 1.0,
        max_missed_probes: 1000,
        race_budget: RaceBudget::default(),
    }
}

fn make_hub() -> Option<(FlowSessionHub, PeerId, SocketAddr)> {
    let listener = FabricListener::bind(addr(0)).ok()?;
    let peer = listener.peer_id();
    let local = listener.local_addr().ok()?;
    let pm = Arc::new(Mutex::new(PathManager::new(fast_config())));
    let link = PathLink::new(pm);
    let punch = PunchManager::new(Driver::new_client().ok()?, PeerId([9u8; 32]));
    let hub = FlowSessionHub::new(listener, link, punch);
    Some((hub, peer, local))
}

/// Read a whole file/stream into memory and print its SHA-256.
fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (src, dest): (PathBuf, PathBuf) = match args.as_slice() {
        [] => {
            let mut payload = Vec::with_capacity(2 * 1024 * 1024);
            for i in 0..payload.capacity() {
                payload.push((i % 251) as u8);
            }
            let p = std::env::temp_dir().join("flow_file_demo.src");
            std::fs::write(&p, &payload).expect("write source");
            (p, std::env::temp_dir().join("flow_file_demo.out"))
        }
        [s, d] => (PathBuf::from(s), PathBuf::from(d)),
        _ => {
            eprintln!("usage: flow_file_demo [<source> <dest>]");
            std::process::exit(2);
        }
    };

    let Some((hub_a, _pa, _la)) = make_hub() else {
        eprintln!("UDP loopback unavailable");
        std::process::exit(1);
    };
    let Some((hub_b, peer_b, addr_b)) = make_hub() else {
        eprintln!("UDP loopback unavailable");
        std::process::exit(1);
    };

    // B: receive the file stream and write it to `dest`.
    let dest_path = dest.clone();
    let handler: StreamHandler = Arc::new(
        move |_peer: PeerId, mut send: SendStream, mut recv: RecvStream| {
            let mut file = match std::fs::File::create(&dest_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[B] create dest failed: {e}");
                    return;
                }
            };
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = file.write_all(&buf[..n]);
                        hasher.update(&buf[..n]);
                    }
                    Err(e) => {
                        eprintln!("[B] read error: {e}");
                        return;
                    }
                }
            }
            let digest: [u8; 32] = hasher.finalize().into();
            eprintln!(
                "[B] received {} bytes -> {} (sha256 {})",
                file_len(&dest_path),
                dest_path.display(),
                sha256_hex(&digest)
            );
            let _ = send.finish();
        },
    );
    hub_b.register_stream_service(SERVICE_FILE, handler);

    hub_a.dial(peer_b, &[addr_b]).expect("dial B");
    eprintln!("[A] dialed {} at {addr_b}", peer_hex(&peer_b));

    let (mut send, mut recv) = hub_a.open_stream(peer_b).expect("open stream");
    send.write(&[SERVICE_FILE]).expect("write service type");

    let mut file = std::fs::File::open(&src).expect("open source");
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; MAX_STREAM_WRITE];
    let mut total = 0usize;
    loop {
        let n = file.read(&mut chunk).expect("read source");
        if n == 0 {
            break;
        }
        send.write(&chunk[..n]).expect("write chunk");
        hasher.update(&chunk[..n]);
        total += n;
    }
    send.finish().expect("finish send");
    eprintln!(
        "[A] sent {total} bytes from {} (sha256 {})",
        src.display(),
        sha256_hex(&hasher.finalize())
    );

    // A reads EOF once B's handler finishes the send half.
    let mut eof = false;
    let mut buf = [0u8; 8192];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match recv.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(_) => continue,
            Err(e) => {
                eprintln!("[A] read error: {e}");
                break;
            }
        }
    }
    if eof {
        eprintln!("[A] observed EOF from B");
    } else {
        eprintln!("[A] timed out waiting for EOF");
        std::process::exit(1);
    }

    hub_a.close_peer(peer_b);
    eprintln!("flow_file_demo done");
}

fn file_len(p: &PathBuf) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}
