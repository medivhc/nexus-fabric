//! E4 产品场景 `product.strategy-watcher` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/strategy_watcher.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example strategy_watcher -- --json
//! ```
//!
//! 真实临时 TOML 文件 → `StrategyWatcher` 检测 `[routing]` 变更 →
//! FIB 重算 → 非法内容保持旧策略 → `stop()` join 回收验证。
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::strategy_watcher::{ReloadEventKind, StrategyWatcher, WatcherConfig};
use nexus_discovery::PeerId;
use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
use nexus_discovery::routing::{RoutingStrategy, SharedFibManager};
use serde_json::json;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

fn peer(id: &str) -> PeerId {
    PeerId(id.to_string())
}

fn link(to: &str, latency_ms: u32) -> LinkAdvert {
    LinkAdvert {
        neighbor: peer(to),
        metrics: LinkMetrics {
            latency_ms,
            loss_pct: 0,
            bandwidth_kbps: 100_000,
        },
    }
}

fn write_strategy(path: &std::path::Path, strategy: &str) -> std::io::Result<()> {
    std::fs::write(
        path,
        format!(
            "[subnet]\ncidr = \"10.99.0.0/24\"\n[routing]\nstrategy = \"{}\"\n",
            strategy
        ),
    )
}

fn next_hop_count(fib: &SharedFibManager<RoutingStrategy>) -> usize {
    fib.read()
        .fib()
        .lookup("10.99.0.4")
        .map(|hops| hops.len())
        .unwrap_or(0)
}

fn wait_for_applied(watcher: &StrategyWatcher, strategy: &str, timeout: Duration) -> Option<u64> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        for e in watcher.events() {
            if let ReloadEventKind::Applied {
                strategy: s,
                generation,
            } = &e.kind
            {
                if s == strategy {
                    return Some(*generation);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn wait_for_kind(
    watcher: &StrategyWatcher,
    want: fn(&ReloadEventKind) -> bool,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if watcher.events().iter().any(|e| want(&e.kind)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    watcher.events().iter().any(|e| want(&e.kind))
}

fn run() -> Result<serde_json::Value, String> {
    let fail = |m: &str| m.to_string();
    let mut events: Vec<&str> = Vec::new();

    // Diamond 拓扑
    let (id_a, id_b, id_c, id_d) = (peer("a"), peer("b"), peer("c"), peer("d"));
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link("b", 10), link("c", 10)],
    });
    for (id, vip, nbrs) in [
        (
            id_b.clone(),
            "10.99.0.2",
            vec![link("a", 10), link("d", 10)],
        ),
        (
            id_c.clone(),
            "10.99.0.3",
            vec![link("a", 10), link("d", 10)],
        ),
        (
            id_d.clone(),
            "10.99.0.4",
            vec![link("b", 10), link("c", 10)],
        ),
    ] {
        lsdb.update(Lsa {
            node_id: id,
            vip: vip.to_string(),
            incarnation: 1,
            seq: 1,
            capabilities: 0,
            locator: None,
            neighbors: nbrs,
        });
    }

    let fib = SharedFibManager::new(id_a.clone(), RoutingStrategy::Shortest, &lsdb);
    let lsdb = Arc::new(RwLock::new(lsdb));
    if next_hop_count(&fib) != 1 {
        return Err(fail("initial shortest should give 1 next-hop"));
    }
    events.push("initial_shortest");

    // 真实临时 TOML 文件
    let path = std::env::temp_dir().join(format!(
        "nexus-strategy-watcher-e4-{}.toml",
        std::process::id()
    ));
    write_strategy(&path, "shortest").map_err(|e| fail(&format!("write config: {e}")))?;

    // 启动 watcher
    let config = WatcherConfig {
        config_path: path.clone(),
        poll_interval: Duration::from_millis(50),
        max_events: 64,
    };
    let mut watcher = StrategyWatcher::start(config, fib.clone(), Arc::clone(&lsdb))
        .map_err(|e| fail(&format!("watcher start: {e}")))?;
    if !watcher.is_running() {
        return Err(fail("watcher should be running after start"));
    }
    events.push("watcher_started");

    // 变更文件：shortest -> ecmp，等待 watcher 热应用
    write_strategy(&path, "ecmp").map_err(|e| fail(&format!("write ecmp: {e}")))?;
    let generation = wait_for_applied(&watcher, "ecmp", Duration::from_secs(10))
        .ok_or_else(|| fail("watcher did not apply ecmp within 10s"))?;
    if generation != 2 {
        return Err(fail(&format!("expected generation 2, got {generation}")));
    }
    if next_hop_count(&fib) != 2 {
        return Err(fail("after watcher reload: ecmp should give 2 next-hops"));
    }
    events.push("watcher_reloaded_to_ecmp");

    // 非法内容：旧策略与旧 FIB 必须原样保留
    let gen_before = fib.read().generation();
    write_strategy(&path, "bogus-strategy").map_err(|e| fail(&format!("write bogus: {e}")))?;
    if !wait_for_kind(
        &watcher,
        |k| matches!(k, ReloadEventKind::ParseFailed { .. }),
        Duration::from_secs(10),
    ) {
        return Err(fail("watcher did not record ParseFailed within 10s"));
    }
    if next_hop_count(&fib) != 2 {
        return Err(fail("FIB must remain ecmp after invalid config"));
    }
    if fib.read().generation() != gen_before {
        return Err(fail("generation must not advance on parse failure"));
    }
    events.push("invalid_kept_old_strategy");

    // stop()：join 回收验证
    watcher.stop();
    if watcher.is_running() {
        return Err(fail("watcher should not be running after stop()"));
    }
    // 事件缓冲在 stop 后仍可查询
    if watcher.events().is_empty() {
        return Err(fail("event log should survive stop()"));
    }
    events.push("stopped_clean");

    std::fs::remove_file(&path).ok();

    Ok(json!({
        "verdict": "PASS",
        "events": events,
        "watcher": {
            "generation": fib.read().generation(),
            "next_hops": next_hop_count(&fib),
            "event_count": watcher.event_count(),
        },
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("strategy_watcher OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("strategy_watcher failed: {err}");
            std::process::exit(1);
        }
    }
}
