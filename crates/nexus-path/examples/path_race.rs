//! E4 for `product.path-race`: staggered connection racing (R1).
//!
//! Uses a fake `PathConnector` with injected latency:
//! - direct (preferred by stagger order) sleeps 800ms
//! - turn sleeps 50ms
//! With stagger_delay 200ms, turn starts 200ms after direct but finishes
//! first (at ~250ms vs ~800ms), so turn must win.
//!
//! Outputs JSON; `--json` flag required (harness convention).

use nexus_path::{race_connect, CandidatePath, PathConnector, PathKind, RaceBudget};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn candidate(kind: PathKind, port: u16, cost: f64) -> CandidatePath {
    CandidatePath {
        kind,
        local_addr: addr(1),
        remote_addr: addr(port),
        cost,
    }
}

/// Fake connector: latency depends on the remote port.
struct LatencyInjector {
    slow_port: u16,
    fast_port: u16,
}

impl PathConnector for LatencyInjector {
    fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> io::Result<u64> {
        let delay_ms = if path.remote_addr.port() == self.slow_port {
            800
        } else if path.remote_addr.port() == self.fast_port {
            50
        } else {
            100
        };
        let deadline = Instant::now() + Duration::from_millis(delay_ms);
        while Instant::now() < deadline {
            if cancel.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            thread::sleep(Duration::from_millis(5));
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        // Simulate bytes sent during a successful handshake.
        Ok(1200)
    }
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
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");

    // Direct is preferred (stagger order) but slow; turn is fast.
    let candidates = vec![
        candidate(PathKind::Direct, 9001, 0.0),
        candidate(PathKind::Turn, 9002, 5.0),
    ];
    let connector = LatencyInjector {
        slow_port: 9001,
        fast_port: 9002,
    };
    let budget = RaceBudget {
        stagger_delay_ms: 200,
        max_parallel: 2,
        total_timeout_ms: 5000,
    };

    let start = Instant::now();
    let result = race_connect(&candidates, &connector, &budget);
    let elapsed = start.elapsed().as_millis();

    match result {
        Ok(outcome) => {
            let winner_kind = kind_name(outcome.winner.kind);
            let within_budget = outcome.attempts <= budget.max_parallel as u32;
            let verdict = if winner_kind == "turn" && within_budget {
                "PASS"
            } else {
                "FAIL"
            };
            if json {
                println!(
                    concat!(
                        "{{\"verdict\":\"{verdict}\",",
                        "\"race\":{{\"winner_kind\":\"{winner}\",",
                        "\"attempts\":{attempts},",
                        "\"attempts_within_budget\":{within},",
                        "\"wasted_bytes\":{wasted},",
                        "\"elapsed_ms\":{elapsed}}},",
                        "\"budget\":{{\"max_parallel\":{maxp}}}}}"
                    ),
                    verdict = verdict,
                    winner = winner_kind,
                    attempts = outcome.attempts,
                    within = within_budget,
                    wasted = outcome.wasted_bytes,
                    elapsed = elapsed,
                    maxp = budget.max_parallel,
                );
            } else {
                println!(
                    "winner: {winner_kind} (attempts={}, wasted={}B, {elapsed}ms)",
                    outcome.attempts, outcome.wasted_bytes,
                );
            }
            if verdict == "FAIL" {
                std::process::exit(1);
            }
        }
        Err(e) => {
            if json {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":\"{e}\"}}",
                    e = e.to_string().replace('"', "'")
                );
            } else {
                eprintln!("race failed: {e}");
            }
            std::process::exit(1);
        }
    }
}
