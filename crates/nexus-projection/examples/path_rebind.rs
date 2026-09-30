//! E4 product scenario: `product.fabric-path-rebind`.
//!
//! A (originator) opens a real QUIC `FabricConn` to B over UDP loopback,
//! streams 256KB over a bidirectional stream while B echoes, and triggers
//! a path switch mid-transfer via `PathManager::remove_candidate` +
//! production `PathLink::pump()` -> `FabricConn::rebind()`.
//!
//! Asserts: all bytes echoed (transfer uninterrupted), CID unchanged,
//! and A's UDP source port changed (real socket rebind, not a purely
//! logical switch; the peer observes this as a remote-port change).
//! Note: `ConnStats.active_path` is the endpoint's OWN local address
//! (driver source), so the port change is observed A-side.
//!
//! Sandbox (UDP EPERM) -> {"verdict":"SKIP"}; any other failure -> FAIL.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_fabric::{ConnConfig, FabricConn, FabricError, FabricListener};
use nexus_path::{CandidatePath, PathConfig, PathKind, PathManager, PathStats, RaceBudget};
use nexus_projection::PathLink;

const N: usize = 262_144; // 256KB total
const CHUNK: usize = 16_384; // 16KB per chunk
const SWITCH_AT: usize = N / 2; // trigger switch after 128KB sent

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn candidate(port: u16) -> CandidatePath {
    CandidatePath {
        kind: PathKind::Direct,
        local_addr: addr(8000),
        remote_addr: addr(port),
        cost: 0.0,
    }
}

fn is_udp_blocked(e: &FabricError) -> bool {
    let s = format!("{e}").to_lowercase();
    s.contains("permission")
        || s.contains("not permitted")
        || s.contains("eperm")
        || s.contains("operation not allowed")
}

/// Direct capability probe: can this host actually send UDP loopback?
/// The sandbox blocks it at OS level (EPERM on sendto); QUIC would then
/// just time out, which must not be misreported as a product failure.
fn udp_loopback_available() -> bool {
    use std::net::UdpSocket;
    let a = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let b = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bp = match b.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => return false,
    };
    a.send_to(b"probe", format!("127.0.0.1:{bp}")).is_ok()
}

fn skip(reason: &str) -> ! {
    println!(
        "{{\"verdict\":\"SKIP\",\"reason\":{}}}",
        serde_json_string(reason)
    );
    std::process::exit(0);
}

fn fail(reason: &str) -> ! {
    println!(
        "{{\"verdict\":\"FAIL\",\"reason\":{}}}",
        serde_json_string(reason)
    );
    std::process::exit(1);
}

/// Minimal JSON string escaping (no extra deps in examples).
fn serde_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_all(tx: &mut nexus_fabric::SendStream, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        let n = tx.write(buf).map_err(|e| format!("stream write: {e}"))?;
        buf = &buf[n..];
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(report) => {
            println!("{report}");
        }
        Err(e) => fail(&e),
    }
}

struct BState {
    received: usize,
}

fn run() -> Result<String, String> {
    // Capability probe first: without UDP loopback, QUIC can never
    // complete a handshake (it would just time out).
    if !udp_loopback_available() {
        skip("udp loopback unavailable (sandbox EPERM)");
    }

    // --- B: real QUIC listener over loopback ---
    let listener = match FabricListener::bind(addr(0)) {
        Ok(l) => l,
        Err(e) if is_udp_blocked(&e) => skip(&format!("udp unavailable: {e}")),
        Err(e) => return Err(format!("bind: {e}")),
    };
    let server_peer = listener.peer_id();
    let server_addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    let b_state = Arc::new(Mutex::new(BState { received: 0 }));
    let b_done = Arc::new(AtomicBool::new(false));
    {
        let b_state = b_state.clone();
        let b_done = b_done.clone();
        std::thread::spawn(move || {
            let conn = match listener.accept() {
                Ok(c) => c,
                Err(_) => return,
            };
            // Echo exactly one bi stream until N bytes received.
            let (mut tx, mut rx) = match conn.accept_bi() {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut buf = [0u8; 16384];
            while b_state.lock().unwrap().received < N && !b_done.load(Ordering::SeqCst) {
                let n = match rx.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if write_all(&mut tx, &buf[..n]).is_err() {
                    break;
                }
                b_state.lock().unwrap().received += n;
            }
        });
    }

    // --- A: real QUIC connect ---
    let conn_a = match FabricConn::connect(
        server_peer,
        &ConnConfig {
            addrs: vec![server_addr],
            handshake_timeout: Duration::from_secs(10),
        },
    ) {
        Ok(c) => c,
        Err(e) if is_udp_blocked(&e) => skip(&format!("udp unavailable: {e}")),
        Err(e) => return Err(format!("connect: {e}")),
    };
    let cid_before = conn_a.id();
    // A's own UDP source port before the switch (active_path = own local addr).
    let a_port_before = conn_a
        .stats()
        .active_path
        .map(|a| a.port())
        .ok_or("no active_path after connect")?;

    // --- PathManager with two logical candidates ---
    let mut pm = PathManager::new(PathConfig {
        hysteresis_pct: 0.0,
        switch_hold_ms: 0,
        probe_interval_ms: 60_000,
        ewma_alpha: 1.0,
        max_missed_probes: 1000,
        race_budget: RaceBudget::default(),
    });
    pm.add_candidate(candidate(9001));
    pm.add_candidate(candidate(9002));
    for port in [9001u16, 9002] {
        pm.on_stats(
            &addr(port),
            PathStats {
                rtt_ms: Some(if port == 9001 { 10 } else { 20 }),
                loss_rate: Some(0.0),
                ..Default::default()
            },
        );
    }
    // Drain setup events so only the switch under test remains.
    while pm.poll_event().is_some() {}
    let active_addr = pm
        .current_path()
        .ok_or("no active path after setup")?
        .remote_addr;

    // --- PathLink: production linkage under test ---
    let mut link = PathLink::new(pm);
    link.add_conn("b", conn_a.clone());
    link.map_peer_addr("b", addr(9001));
    link.map_peer_addr("b", addr(9002));

    // --- Bi stream: A sends, B echoes ---
    let (mut tx, mut rx) = conn_a.open_bi().map_err(|e| format!("open_bi: {e}"))?;
    let echoed = Arc::new(AtomicUsize::new(0));
    let reader_done = Arc::new(AtomicBool::new(false));
    {
        let echoed = echoed.clone();
        let reader_done = reader_done.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 16384];
            let mut total = 0usize;
            while total < N {
                match rx.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        echoed.store(total, Ordering::SeqCst);
                    }
                    Err(_) => break,
                }
            }
            reader_done.store(true, Ordering::SeqCst);
        });
    }

    // --- Send in paced chunks; trigger the switch mid-transfer ---
    let payload = vec![0xABu8; CHUNK];
    let mut sent = 0usize;
    let mut switched = false;
    let mut received_at_switch = 0usize;
    while sent < N {
        let n = CHUNK.min(N - sent);
        write_all(&mut tx, &payload[..n])?;
        sent += n;
        if !switched && sent >= SWITCH_AT {
            // Production path only: remove_candidate -> Switched -> pump() -> rebind().
            // (E4 must-use-production-path: no manual rebind() here.)
            received_at_switch = b_state.lock().unwrap().received;
            link.manager_mut().remove_candidate(&active_addr);
            link.pump();
            switched = true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Genuinely mid-transfer: B had not yet received everything at switch time.
    if received_at_switch >= N {
        return Err(format!(
            "switch happened after transfer completed (received_at_switch={received_at_switch})"
        ));
    }

    // --- Drain the echo ---
    let deadline = Instant::now() + Duration::from_secs(30);
    while echoed.load(Ordering::SeqCst) < N {
        if Instant::now() > deadline {
            return Err(format!(
                "echo incomplete: {}/{}",
                echoed.load(Ordering::SeqCst),
                N
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    b_done.store(true, Ordering::SeqCst);

    // --- Assertions ---
    let bytes_relayed = echoed.load(Ordering::SeqCst);
    if bytes_relayed != N {
        return Err(format!("bytes_relayed={bytes_relayed}, want {N}"));
    }
    let cid_unchanged = conn_a.id() == cid_before;
    if !cid_unchanged {
        return Err("CID changed across rebind".to_string());
    }
    if link.stats().path_rebinds != 1 {
        return Err(format!(
            "path_rebinds={}, want 1",
            link.stats().path_rebinds
        ));
    }

    // A's UDP source port must have changed: cmd_rebind swaps the socket
    // synchronously and refreshes stats (the peer observes this as a
    // remote-port change). This proves a real rebind, not a logical flip.
    let remote_port_changed = {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut changed = false;
        while Instant::now() < deadline {
            let port_now = conn_a.stats().active_path.map(|a| a.port());
            if let Some(p) = port_now {
                if p != a_port_before {
                    changed = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        changed
    };
    if !remote_port_changed {
        return Err(format!(
            "A's source port never changed (still {a_port_before})"
        ));
    }

    Ok(format!(
        "{{\"verdict\":\"PASS\",\"bytes_relayed\":{bytes_relayed},\
         \"cid_unchanged\":{cid_unchanged},\
         \"remote_port_changed\":{remote_port_changed},\
         \"path_rebinds\":{}}}",
        link.stats().path_rebinds
    ))
}
