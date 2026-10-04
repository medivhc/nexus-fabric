//! E4 driver for `product.fabric-path-basic`.
//!
//! PathManager with direct + mock TURN candidates:
//!  1. feed initial stats -> direct (cheaper, equal quality) is selected (S3)
//!  2. severely degrade direct (RTT spike to 500ms + 30% loss) -> after
//!     relative hysteresis (20%) + hold, switch to TURN (S4, R3)
//!  3. emit JSON covering every frozen expect field.
//!
//! Usage: cargo run -p nexus-path --example basic -- --json

use nexus_path::{
    CandidatePath, PathConfig, PathEvent, PathKind, PathManager, PathStats, RaceBudget,
    SwitchReason,
};
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

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

fn reason_name(r: &SwitchReason) -> &'static str {
    match r {
        SwitchReason::BetterScore => "BetterScore",
        SwitchReason::PathFailed => "PathFailed",
        SwitchReason::PathAdded => "PathAdded",
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");

    let mut pm = PathManager::new(PathConfig {
        hysteresis_pct: 0.20,
        switch_hold_ms: 200,
        probe_interval_ms: 60_000,
        ewma_alpha: 0.3,
        max_missed_probes: 3,
        race_budget: RaceBudget::default(),
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

    // Phase 1: healthy stats on both. Direct must win (S3: equal quality,
    // lower cost -> higher score).
    let healthy_direct = || PathStats {
        rtt_ms: Some(10),
        loss_rate: Some(0.0),
        throughput_bps: None,
    };
    let healthy_turn = || PathStats {
        rtt_ms: Some(50),
        loss_rate: Some(0.0),
        throughput_bps: None,
    };
    pm.on_stats(&direct, healthy_direct());
    pm.on_stats(&turn, healthy_turn());

    let initial_kind = pm
        .current_path()
        .map(|p| kind_name(p.kind).to_string())
        .unwrap_or_default();
    let score_direct = pm.score(&direct);
    let score_turn = pm.score(&turn);

    // Phase 2: severely degrade direct (RTT 10ms -> 500ms + 30% loss).
    // 2026-09-30 requirement-change: loss added so TURN beats the 20%
    // relative hysteresis (pure RTT degradation only gives ~7.5% margin).
    // EWMA decays; once TURN leads by hysteresis_pct for switch_hold_ms,
    // we switch.
    let degraded_direct = || PathStats {
        rtt_ms: Some(500),
        loss_rate: Some(0.3),
        throughput_bps: None,
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut switched = false;
    let mut reason = String::new();
    while Instant::now() < deadline {
        pm.on_stats(&direct, degraded_direct());
        pm.on_stats(&turn, healthy_turn());
        while let Some(ev) = pm.poll_event() {
            // T1 (2026-10-03): `PathEvent::Adopted` (nexus-path D4) added;
            // this E4 only cares about switches to Turn.
            let (to, r) = match ev {
                PathEvent::Switched { to, reason: r, .. } => (to, r),
                PathEvent::Adopted { .. } => continue,
            };
            if to.kind == PathKind::Turn {
                switched = true;
                reason = reason_name(&r).to_string();
            }
        }
        if pm.current_path().is_some_and(|p| p.kind == PathKind::Turn) {
            switched = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    // Drain any straggler events for the reason field.
    while let Some(ev) = pm.poll_event() {
        // T1 (2026-10-03): `PathEvent::Adopted` (nexus-path D4) added;
        // adoptions carry no switch reason.
        let PathEvent::Switched { reason: r, .. } = ev else {
            continue;
        };
        if reason.is_empty() {
            reason = reason_name(&r).to_string();
        }
    }
    let after_kind = pm
        .current_path()
        .map(|p| kind_name(p.kind).to_string())
        .unwrap_or_default();

    let verdict = if initial_kind == "direct"
        && after_kind == "turn"
        && switched
        && (reason == "BetterScore" || reason == "PathFailed")
        && score_direct.is_some()
        && score_turn.is_some()
    {
        "PASS"
    } else {
        "FAIL"
    };

    if json {
        let sd = score_direct
            .map(|s| format!("{s:.3}"))
            .unwrap_or_else(|| "null".to_string());
        let st = score_turn
            .map(|s| format!("{s:.3}"))
            .unwrap_or_else(|| "null".to_string());
        println!(
            concat!(
                "{{\"verdict\":\"{verdict}\",",
                "\"selection\":{{\"initial_kind\":\"{initial}\",",
                "\"after_degrade_kind\":\"{after}\",",
                "\"switched\":{switched},\"reason\":\"{reason}\"}},",
                "\"scores\":{{\"direct\":{sd},\"turn\":{st}}}}}"
            ),
            verdict = verdict,
            initial = json_escape(&initial_kind),
            after = json_escape(&after_kind),
            switched = switched,
            reason = json_escape(&reason),
            sd = sd,
            st = st,
        );
    } else {
        println!("verdict: {verdict}");
        println!("initial_kind: {initial_kind} (score direct={score_direct:?})");
        println!("after_degrade_kind: {after_kind} (score turn={score_turn:?})");
        println!("switched: {switched}, reason: {reason}");
    }

    if verdict != "PASS" {
        std::process::exit(1);
    }
}
