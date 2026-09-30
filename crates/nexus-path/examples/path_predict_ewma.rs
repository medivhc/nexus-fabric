//! E4 for `product.path-predict-ewma`: EWMA realtime prediction, layer 1 (R2).
//!
//! Feeds an RTT climbing sequence (10ms -> 500ms, 0% loss) into:
//! 1. a bare `Ewma` (alpha 0.3) — asserts the smoothed value decreases
//!    monotonically (the minimal verifiable "trend following" behavior);
//! 2. a `PathManager` via `on_stats` — asserts `score()` follows downward;
//! 3. an unscored path — asserts `score()` is `None` (S7 unknown honesty).
//!
//! Outputs JSON; `--json` flag required (harness convention).

use nexus_path::{CandidatePath, Ewma, PathConfig, PathKind, PathManager, PathStats};
use std::net::SocketAddr;

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");

    // RTT climbing sequence: 10 -> 50 -> 100 -> 200 -> 500 ms, 0% loss.
    let rtts = [10u64, 50, 100, 200, 500];

    // 1. Bare Ewma must follow the climb downward, monotonically.
    let mut ewma = Ewma::new(0.3);
    let mut prev = f64::INFINITY;
    let mut monotonic = true;
    let mut first = 0.0;
    let mut last = 0.0;
    for (i, rtt) in rtts.iter().enumerate() {
        // Instantaneous score for (rtt, 0% loss, cost 0), mirroring
        // PathManager's instant_score weights (W_RTT=1, W_LOSS=1).
        let sample = 1000.0 / (1.0 + *rtt as f64) + 100.0;
        let v = ewma.update(sample);
        if i == 0 {
            first = v;
        }
        last = v;
        if v >= prev {
            monotonic = false;
        }
        prev = v;
    }

    // 2. PathManager::score() must follow downward as well.
    let mut pm = PathManager::new(PathConfig::default());
    let direct = addr(9001);
    pm.add_candidate(CandidatePath {
        kind: PathKind::Direct,
        local_addr: addr(1),
        remote_addr: direct,
        cost: 0.0,
    });
    let mut pm_prev = f64::INFINITY;
    let mut pm_decreased = true;
    let mut pm_first = 0.0;
    let mut pm_last = 0.0;
    for (i, rtt) in rtts.iter().enumerate() {
        pm.on_stats(
            &direct,
            PathStats {
                rtt_ms: Some(*rtt),
                loss_rate: Some(0.0),
                throughput_bps: None,
            },
        );
        if let Some(s) = pm.score(&direct) {
            if i == 0 {
                pm_first = s;
            }
            pm_last = s;
            if s >= pm_prev {
                pm_decreased = false;
            }
            pm_prev = s;
        } else {
            pm_decreased = false;
        }
    }
    let score_decreased = pm_decreased && pm_last < pm_first;

    // 3. Unknown path => None (S7).
    let unknown = addr(9999);
    pm.add_candidate(CandidatePath {
        kind: PathKind::Turn,
        local_addr: addr(1),
        remote_addr: unknown,
        cost: 5.0,
    });
    let unknown_is_none = pm.score(&unknown).is_none();

    let verdict = if monotonic && score_decreased && unknown_is_none {
        "PASS"
    } else {
        "FAIL"
    };

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{verdict}\",",
                "\"ewma\":{{\"monotonic_decreasing\":{mono},",
                "\"first\":{first:.3},\"last\":{last:.3}}},",
                "\"score\":{{\"decreased\":{dec},",
                "\"first\":{pfirst:.3},\"last\":{plast:.3},",
                "\"unknown_is_none\":{unk}}}}}",
            ),
            verdict = verdict,
            mono = monotonic,
            first = first,
            last = last,
            dec = score_decreased,
            pfirst = pm_first,
            plast = pm_last,
            unk = unknown_is_none,
        );
    } else {
        println!("ewma: {first:.1} -> {last:.1} (monotonic={monotonic})");
        println!("score: {pm_first:.1} -> {pm_last:.1} (decreased={score_decreased})");
        println!("unknown_is_none: {unknown_is_none}");
    }

    if verdict == "FAIL" {
        std::process::exit(1);
    }
}
