//! E4: product.fabric-conn-roam
//!
//! 4 MiB reliable stream; once the server has read 1 MiB it signals the
//! client via datagram and the client rebinds its UDP socket mid-transfer
//! (active migration). Verifies: hash integrity (S3), CID stability (S2),
//! app-visible stall within budget, and that stats report the path change.
//! Prints exactly one JSON line to stdout.

use nexus_fabric::{ConnConfig, FabricConn, FabricListener};
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

const TOTAL: usize = 4 * 1024 * 1024;
const SIGNAL_AT: usize = 1024 * 1024;
const STALL_BUDGET_MS: u64 = 5000;

/// FNV-1a 64 (deterministic, no new deps).
struct Fnv64(u64);

impl Fnv64 {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }
    fn update(&mut self, b: &[u8]) {
        for &x in b {
            self.0 ^= x as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    fn digest(&self) -> u64 {
        self.0
    }
}

fn chunk(off: usize, end: usize) -> Vec<u8> {
    (off..end).map(|i| (i % 251) as u8).collect()
}

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

    // Server: read the stream, hash it, signal rebind at 1 MiB, track the
    // maximum gap between consecutive reads (app-visible stall).
    let server = thread::spawn(move || -> Result<(u64, usize, u64), String> {
        let conn = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let (_send, mut recv) = conn.accept_bi().map_err(|e| format!("accept_bi: {e}"))?;
        let mut hash = Fnv64::new();
        let mut total = 0usize;
        let mut signaled = false;
        let mut buf = [0u8; 65536];
        let mut last: Option<Instant> = None;
        let mut max_gap = Duration::ZERO;
        loop {
            let n = recv.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            let now = Instant::now();
            if n == 0 {
                break;
            }
            if let Some(prev) = last {
                let gap = now.saturating_duration_since(prev);
                if gap > max_gap {
                    max_gap = gap;
                }
            }
            last = Some(now);
            hash.update(&buf[..n]);
            total += n;
            if !signaled && total >= SIGNAL_AT {
                conn.send_datagram(b"rebind-now")
                    .map_err(|e| format!("signal: {e}"))?;
                signaled = true;
            }
        }
        Ok((hash.digest(), total, max_gap.as_millis() as u64))
    });

    // Client.
    let config = ConnConfig {
        addrs: vec![server_addr],
        handshake_timeout: Duration::from_secs(10),
    };
    let conn = FabricConn::connect(server_peer, &config).map_err(|e| format!("connect: {e}"))?;
    let id_before = conn.id();
    let path_before = conn.stats().active_path;
    let (mut send, _recv) = conn.open_bi().map_err(|e| format!("open_bi: {e}"))?;

    let writer = thread::spawn(move || -> Result<(), String> {
        let mut off = 0;
        while off < TOTAL {
            let end = (off + 65536).min(TOTAL);
            let c = chunk(off, end);
            let mut woff = 0;
            while woff < c.len() {
                woff += send.write(&c[woff..]).map_err(|e| format!("write: {e}"))?;
            }
            off = end;
        }
        send.finish().map_err(|e| format!("finish: {e}"))?;
        Ok(())
    });

    // Wait for the server's signal, then migrate mid-transfer.
    let sig = conn
        .recv_datagram()
        .map_err(|e| format!("signal recv: {e}"))?;
    if sig != b"rebind-now" {
        return Err(format!("unexpected signal ({} bytes)", sig.len()));
    }
    conn.rebind().map_err(|e| format!("rebind: {e}"))?;
    let path_after = conn.stats().active_path;

    writer
        .join()
        .map_err(|_| "writer thread panicked".to_string())?
        .map_err(|e| format!("writer: {e}"))?;
    let (digest, total, stalled_ms) = server
        .join()
        .map_err(|_| "server thread panicked".to_string())?
        .map_err(|e| format!("server: {e}"))?;

    // Expected hash, computed independently.
    let mut expect = Fnv64::new();
    let mut off = 0;
    while off < TOTAL {
        let end = (off + 65536).min(TOTAL);
        expect.update(&chunk(off, end));
        off = end;
    }

    let hash_match = digest == expect.digest() && total == TOTAL;
    let id_unchanged = conn.id() == id_before;
    let active_path_changed = path_after.is_some() && path_before != path_after;
    let stalled_within_budget = stalled_ms <= STALL_BUDGET_MS;
    let pass = hash_match && id_unchanged && active_path_changed && stalled_within_budget;
    let verdict = if pass { "PASS" } else { "FAIL" };
    let detail = if pass {
        String::new()
    } else {
        format!(
            ",\"detail\":\"hash_match={hash_match} total={total} id_unchanged={id_unchanged} path {path_before:?}->{path_after:?} stalled_ms={stalled_ms}\""
        )
    };
    Ok((
        format!(
            "{{\"verdict\":\"{verdict}\",\"stream\":{{\"hash_match\":{hash_match},\"stalled_ms\":{stalled_ms},\"stalled_within_budget\":{stalled_within_budget}}},\"connection\":{{\"id_unchanged\":{id_unchanged}}},\"stats\":{{\"active_path_changed\":{active_path_changed}}}{detail}}}"
        ),
        pass,
    ))
}
