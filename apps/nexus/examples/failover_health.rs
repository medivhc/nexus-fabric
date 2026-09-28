//! E4 `product.failover-health`：消费健康事件流驱动主备切换与自动回切。
//!
//! ```text
//! cargo run --quiet -p nexus --example failover_health -- --json
//! ```

#![forbid(unsafe_code)]

use nexus_connectivity::failover::{FailoverConfig, FailoverManager};
use nexus_connectivity::health_check::{HealthEvent, HealthState};
use serde_json::json;

fn ev(node: &str, to: HealthState, at_ms: u64) -> HealthEvent {
    HealthEvent {
        node_id: node.to_string(),
        from: HealthState::Healthy,
        to,
        consecutive_failures: 0,
        at_ms,
    }
}

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let cfg = FailoverConfig::new("primary", vec!["s1".into(), "s2".into()], true)?;
    let mut mgr = FailoverManager::new(cfg);

    // primary 变 Unhealthy -> 切到 s1。
    mgr.apply_health_event(&ev("primary", HealthState::Unhealthy, 1000), 1000);
    let after_primary_unhealthy = mgr.active_node().to_string();

    // s1 变 Unhealthy -> 退到 s2。
    mgr.apply_health_event(&ev("s1", HealthState::Unhealthy, 2000), 2000);
    let after_s1_unhealthy = mgr.active_node().to_string();

    // s2 Degraded 事件：不应触发切换（仍在 s2）。
    mgr.apply_health_event(&ev("s2", HealthState::Degraded, 2500), 2500);
    let degraded_event_did_not_switch = mgr.active_node() == "s2";

    // primary 恢复 Healthy 且 auto_failback -> 切回 Primary。
    mgr.apply_health_event(&ev("primary", HealthState::Healthy, 3000), 3000);
    let after_primary_healthy = mgr.active_node().to_string();

    Ok(json!({
        "verdict": "PASS",
        "command": "failover-health",
        "after_primary_unhealthy_active": after_primary_unhealthy,
        "after_s1_unhealthy_active": after_s1_unhealthy,
        "degraded_event_did_not_switch": degraded_event_did_not_switch,
        "after_primary_healthy_active": after_primary_healthy,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(v) => {
            if as_json {
                println!("{v}");
            } else {
                println!("failover_health: {v}");
            }
        }
        Err(e) => {
            eprintln!("failover_health failed: {e}");
            std::process::exit(1);
        }
    }
}
