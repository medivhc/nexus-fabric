//! E4 产品场景 `product.discovery-enhanced` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/discovery_enhanced.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example discovery_enhanced -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//!
//! 本 example 自包含：直接使用 `nexus_connectivity::discovery_enhanced`，
//! 不依赖 `nexus` 库中的 flow 函数。

#![forbid(unsafe_code)]

use nexus_connectivity::discovery_enhanced::{
    DiscoveryConfig, DiscoveryStrategy, EnhancedDiscovery,
};
use serde_json::json;

/// 跑一遍节点发现决策矩阵，返回单个 JSON 对象。
fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let cfg = DiscoveryConfig::new(1000, 5000, 3)?;

    // upsert：同 node_id 已存在则刷新，不新增重复项。
    let mut d = EnhancedDiscovery::new(cfg);
    d.advertise(DiscoveryStrategy::Manual, "n1", "10.0.0.1:1", 1000)?;
    d.advertise(DiscoveryStrategy::Manual, "n1", "10.0.0.2:2", 2000)?;
    let upsert_count = d.peer_count();
    let upsert_endpoint = d
        .get_peer("n1")
        .map(|p| p.endpoint.clone())
        .unwrap_or_default();

    // 停用 Manual 策略后再 advertise：静默忽略（未记录）。
    d.disable_strategy(DiscoveryStrategy::Manual);
    let disabled_strategy_recorded =
        d.advertise(DiscoveryStrategy::Manual, "n2", "10.0.0.9:9", 3000)?;

    // 超时清理。
    let mut d2 = EnhancedDiscovery::new(cfg);
    d2.advertise(DiscoveryStrategy::Manual, "fresh", "e1", 9000)?;
    d2.advertise(DiscoveryStrategy::Manual, "stale", "e2", 1000)?;
    let pruned = d2.prune_expired(9000);
    let after_prune_count = d2.peer_count();

    // 表满驱逐最旧（max_peers=3）。
    let mut d3 = EnhancedDiscovery::new(cfg);
    d3.advertise(DiscoveryStrategy::Manual, "old", "e-old", 1000)?;
    d3.advertise(DiscoveryStrategy::Manual, "mid", "e-mid", 2000)?;
    d3.advertise(DiscoveryStrategy::Manual, "new", "e-new", 3000)?;
    d3.advertise(DiscoveryStrategy::Manual, "fourth", "e-4", 4000)?;
    let evicted_old_present = d3.get_peer("old").is_some();
    let new_peer_present = d3.get_peer("fourth").is_some();

    // 快照按 node_id 升序确定性输出。
    let mut d4 = EnhancedDiscovery::new(cfg);
    d4.advertise(DiscoveryStrategy::Manual, "zeta", "e1", 1000)?;
    d4.advertise(DiscoveryStrategy::Manual, "alpha", "e2", 2000)?;
    d4.advertise(DiscoveryStrategy::Manual, "mid", "e3", 3000)?;
    let snap = d4.peers_snapshot();
    let snapshot_first = snap.first().map(|p| p.node_id.clone()).unwrap_or_default();

    // FromStr：大小写不敏感解析 + 非法拒绝。
    let parsed: DiscoveryStrategy = "MULTICAST".parse()?;
    let parsed_strategy = parsed.as_str().to_string();
    let invalid_strategy_rejected = "udp".parse::<DiscoveryStrategy>().is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "discovery-enhanced",
        "upsert_count": upsert_count,
        "upsert_endpoint": upsert_endpoint,
        "disabled_strategy_recorded": disabled_strategy_recorded,
        "pruned": pruned,
        "after_prune_count": after_prune_count,
        "evicted_old_present": evicted_old_present,
        "new_peer_present": new_peer_present,
        "snapshot_first": snapshot_first,
        "parsed_strategy": parsed_strategy,
        "invalid_strategy_rejected": invalid_strategy_rejected,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let cnt = value["upsert_count"].as_i64().unwrap_or(0);
                println!("discovery-enhanced OK: upsert_count={cnt}");
            }
        }
        Err(err) => {
            eprintln!("discovery_enhanced example failed: {err}");
            std::process::exit(1);
        }
    }
}
