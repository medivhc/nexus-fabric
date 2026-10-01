//! E4 for `product.boost-v1`: Network Boost v1.
//!
//! Walks the production path end to end:
//! 1. `N1Config::parse_toml` parses a `network.toml` with `[boost]` → `BoostConfig`.
//! 2. `BoostConfig::path_params()` → `nexus_projection::boost::path_config_for_boost`
//!    → `PathConfig`; asserts aggressive params (0.10 / 1000ms).
//! 3. `PathManager` + 2 candidates + stats → `select_best` (read-only);
//!    asserts the good path (direct) wins by EWMA score.
//! 4. `boost_connect(race_on_connect=true)` → `connect_with_fallback` → `race_connect`;
//!    asserts racing was used and the fast path won.
//! 5. Control: `network.toml` without `[boost]` → params fall back to 0.20 / 3000ms.
//!
//! Outputs JSON; `--json` flag required (harness convention).

use nexus_network::n1::config::N1Config;
use nexus_path::{
    CandidatePath, FallbackChain, FallbackConfig, PathConnector, PathKind, PathManager, PathStats,
    ProxyEndpoint, RaceBudget,
};
use nexus_projection::boost::{boost_connect, path_config_for_boost, select_best};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn candidate(kind: PathKind, port: u16) -> CandidatePath {
    CandidatePath {
        kind,
        local_addr: addr(8000),
        remote_addr: addr(port),
        cost: 0.0,
    }
}

fn stats(rtt_ms: u64) -> PathStats {
    PathStats {
        rtt_ms: Some(rtt_ms),
        loss_rate: Some(0.0),
        ..Default::default()
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

/// Fake connector with injected latency per remote port.
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
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(1200)
    }
}

const NETWORK_TOML_BOOST: &str = r#"
peer_id = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

[vpi]
interface = "nxtun0"
address = "10.144.0.1"

[boost]
enabled = true
hysteresis_pct = 0.10
switch_hold_ms = 1000
race_on_connect = true
"#;

const NETWORK_TOML_PLAIN: &str = r#"
peer_id = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

[vpi]
interface = "nxtun0"
address = "10.144.0.1"
"#;

fn fail_json(msg: &str) -> ! {
    println!(
        "{{\"verdict\":\"FAIL\",\"error\":\"{}\"}}",
        msg.replace('"', "'")
    );
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }

    // --- 1+2. Parse [boost] → BoostConfig → PathConfig (production path). ---
    let n1 = N1Config::parse_toml(NETWORK_TOML_BOOST)
        .unwrap_or_else(|e| fail_json(&format!("parse boost toml: {e}")));
    let params = n1.boost.path_params();
    let pcfg = path_config_for_boost(params.hysteresis_pct, params.switch_hold_ms);

    // --- 3. EWMA-driven selection (read-only). ---
    let mut pm = PathManager::new(pcfg);
    let good = candidate(PathKind::Direct, 9001);
    let bad = candidate(PathKind::Proxy, 9002);
    pm.add_candidate(good.clone());
    pm.add_candidate(bad.clone());
    pm.on_stats(&good.remote_addr, stats(20));
    pm.on_stats(&bad.remote_addr, stats(200));
    let arr = [good.clone(), bad.clone()];
    let sel = select_best(&pm, &arr, 1.0)
        .unwrap_or_else(|| fail_json("select_best returned None (all scores unknown)"));
    let best_kind = sel.best.map(|c| kind_name(c.kind)).unwrap_or("none");

    // --- 4. Racing connect (production path: boost_connect → connect_with_fallback). ---
    let mut chain = FallbackChain::expand(
        &FallbackConfig {
            proxy: Some(ProxyEndpoint { server: addr(9002) }),
            turn: None,
        },
        addr(8000),
        addr(9001),
    );
    let connector = LatencyInjector {
        slow_port: 9001,
        fast_port: 9002,
    };
    let budget = RaceBudget {
        stagger_delay_ms: 200,
        max_parallel: 2,
        total_timeout_ms: 5000,
    };
    let outcome = boost_connect(&mut chain, &connector, &budget, params.race_on_connect)
        .unwrap_or_else(|e| fail_json(&format!("boost_connect: {e}")));
    let race_winner = kind_name(outcome.winner.kind);
    let within_budget = outcome.attempts <= budget.max_parallel as u32;

    // --- 5. Control: no [boost] → defaults 0.20 / 3000 (B4 zero-regression). ---
    let n1_plain = N1Config::parse_toml(NETWORK_TOML_PLAIN)
        .unwrap_or_else(|e| fail_json(&format!("parse plain toml: {e}")));
    let plain_params = n1_plain.boost.path_params();

    // --- Verdict. ---
    let verdict = if n1.boost.enabled
        && (params.hysteresis_pct - 0.10).abs() < f64::EPSILON
        && params.switch_hold_ms == 1000
        && params.race_on_connect
        && best_kind == "direct"
        && !sel.degraded
        && race_winner == "proxy" // fast path wins the race (stagger order: direct first, slow)
        && within_budget
        && (plain_params.hysteresis_pct - 0.20).abs() < f64::EPSILON
        && plain_params.switch_hold_ms == 3000
    {
        "PASS"
    } else {
        "FAIL"
    };

    println!(
        concat!(
            "{{\"verdict\":\"{verdict}\",",
            "\"boost\":{{\"enabled\":{enabled},\"hysteresis_pct\":{hyst},",
            "\"switch_hold_ms\":{hold},\"race_on_connect\":{race}}},",
            "\"selection\":{{\"best_kind\":\"{best}\",\"degraded\":{degraded}}},",
            "\"race\":{{\"used\":{used},\"winner_kind\":\"{rw}\",",
            "\"attempts_within_budget\":{within}}},",
            "\"noboost\":{{\"hysteresis_pct\":{nhyst},\"switch_hold_ms\":{nhold}}}}}"
        ),
        verdict = verdict,
        enabled = n1.boost.enabled,
        hyst = params.hysteresis_pct,
        hold = params.switch_hold_ms,
        race = params.race_on_connect,
        best = best_kind,
        degraded = sel.degraded,
        used = params.race_on_connect,
        rw = race_winner,
        within = within_budget,
        nhyst = plain_params.hysteresis_pct,
        nhold = plain_params.switch_hold_ms,
    );
    if verdict == "FAIL" {
        std::process::exit(1);
    }
}
