//! E4 for `product.path-fallback-skip`: honest skip with no proxy/TURN config.
//!
//! `FallbackConfig::default()` (no proxy, no TURN) expands to `[Direct]`;
//! proxy/turn are skipped and counted (F4). The Direct candidate dials a
//! loopback TCP echo server; the roundtrip must verify (F6: empty config ≡
//! pure direct, zero regression).
//!
//! PASS requires: candidate list is exactly [direct], skipped kinds are
//! exactly [proxy, turn], and the echo roundtrip verifies.
//!
//! Outputs JSON; `--json` flag required (harness convention).

use nexus_path::{
    CandidatePath, FallbackChain, FallbackConfig, PathConnector, PathKind, RaceBudget,
    connect_with_fallback,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const N: usize = 65536;

fn payload() -> Vec<u8> {
    (0..N as u32).map(|i| (i % 251) as u8).collect()
}

fn serve_echo(listener: TcpListener) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let mut received = vec![0u8; N];
    stream.read_exact(&mut received)?;
    stream.write_all(&received)?;
    // Wait for the 1-byte "done" so we don't drop early (4b lesson).
    let mut done = [0u8; 1];
    stream.read_exact(&mut done)?;
    Ok(())
}

/// Direct-only dialer.
struct DirectDialer;

impl PathConnector for DirectDialer {
    fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> std::io::Result<u64> {
        if path.kind != PathKind::Direct {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "only direct expected",
            ));
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        let mut stream = TcpStream::connect_timeout(&path.remote_addr, Duration::from_secs(5))?;
        let out = payload();
        stream.write_all(&out)?;
        let mut back = vec![0u8; N];
        stream.read_exact(&mut back)?;
        if back != out {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "echo mismatch",
            ));
        }
        stream.write_all(&[1])?;
        Ok((2 * N) as u64)
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
    let json = std::env::args().any(|a| a == "--json");

    let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer: SocketAddr = echo_listener.local_addr().unwrap();
    let echo_handle = thread::spawn(move || serve_echo(echo_listener));

    // No proxy, no TURN: chain degrades to pure direct (F6).
    let config = FallbackConfig::default();
    let mut chain = FallbackChain::expand(&config, "127.0.0.1:0".parse().unwrap(), peer);

    let candidate_kinds: Vec<&str> = chain
        .candidates()
        .iter()
        .map(|c| kind_name(c.kind))
        .collect();
    let skipped_kinds: Vec<&str> = chain.skipped().iter().map(|k| kind_name(*k)).collect();

    let budget = RaceBudget {
        stagger_delay_ms: 200,
        max_parallel: 2,
        total_timeout_ms: 8000,
    };

    let mut verdict = "FAIL";
    let mut roundtrip_ok = false;
    match connect_with_fallback(&mut chain, &DirectDialer, &budget) {
        Ok(outcome) => {
            // connect() only returns Ok after a verified echo roundtrip.
            roundtrip_ok = outcome.winner.kind == PathKind::Direct;
            if roundtrip_ok {
                verdict = "PASS";
            }
        }
        Err(e) => {
            if !json {
                eprintln!("fallback race failed: {e}");
            }
        }
    }

    let _ = echo_handle.join();

    // F4/F6 assertions folded into the verdict.
    if verdict == "PASS" && !(candidate_kinds == ["direct"] && skipped_kinds == ["proxy", "turn"]) {
        verdict = "FAIL";
    }

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{verdict}\",",
                "\"fallback\":{{\"candidate_kinds\":\"{cands}\",",
                "\"skipped_kinds\":\"{skipped}\",",
                "\"roundtrip_ok\":{rt}}}}}"
            ),
            verdict = verdict,
            cands = candidate_kinds.join(","),
            skipped = skipped_kinds.join(","),
            rt = roundtrip_ok,
        );
    } else {
        println!("verdict={verdict} candidates={candidate_kinds:?} skipped={skipped_kinds:?}");
    }
    if verdict == "FAIL" {
        std::process::exit(1);
    }
}
