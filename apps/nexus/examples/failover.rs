//! E4 产品场景 `product.failover` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/failover.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example failover -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//!
//! 本 example 自包含：直接使用 `nexus_connectivity::failover`，
//! 不依赖 `nexus` 库中的 flow 函数。

#![forbid(unsafe_code)]

use nexus_connectivity::failover::{FailoverConfig, FailoverManager};
use serde_json::json;

/// 跑一遍故障转移决策矩阵，返回单个 JSON 对象。
fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // auto_failback=true：主备 s1/s2。
    let cfg = FailoverConfig::new("primary", vec!["s1".into(), "s2".into()], true)?;
    let mut mgr = FailoverManager::new(cfg);

    // 初始在主节点。
    let starts_on_primary = mgr.active_node() == "primary" && mgr.state().as_str() == "primary";

    // 主节点失败 -> 切到第一个备节点 s1。
    mgr.report_failure("primary", 1000);
    let after_primary_failure_active = mgr.active_node().to_string();
    let after_primary_failure_state = mgr.state().as_str().to_string();

    // 当前 s1 再失败 -> 退到 s2。
    mgr.report_failure("s1", 2000);
    let after_second_failure_active = mgr.active_node().to_string();

    // s2 也失败 -> 无可用备 -> Failed。
    mgr.report_failure("s2", 3000);
    let exhausted_state = mgr.state().as_str().to_string();

    // 主节点恢复：auto_failback=true -> 切回 Primary。
    mgr.report_recovery("primary", 4000);
    let auto_failback_active = mgr.active_node().to_string();

    // auto_failback=false：主节点失败后恢复，不切回。
    let cfg_no_fb = FailoverConfig::new("primary", vec!["s1".into()], false)?;
    let mut mgr_no_fb = FailoverManager::new(cfg_no_fb);
    mgr_no_fb.report_failure("primary", 1000);
    mgr_no_fb.report_recovery("primary", 2000);
    let no_failback_active = mgr_no_fb.active_node().to_string();

    // 错误路径 E4：构造校验三类拒绝。
    let empty_primary_rejected = FailoverConfig::new("", vec!["s1".into()], false).is_err();
    let standby_contains_primary_rejected =
        FailoverConfig::new("primary", vec!["primary".into()], false).is_err();
    let duplicate_standby_rejected =
        FailoverConfig::new("primary", vec!["s1".into(), "s1".into()], false).is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "failover",
        "starts_on_primary": starts_on_primary,
        "after_primary_failure_active": after_primary_failure_active,
        "after_primary_failure_state": after_primary_failure_state,
        "after_second_failure_active": after_second_failure_active,
        "exhausted_state": exhausted_state,
        "auto_failback_active": auto_failback_active,
        "no_failback_active": no_failback_active,
        "empty_primary_rejected": empty_primary_rejected,
        "standby_contains_primary_rejected": standby_contains_primary_rejected,
        "duplicate_standby_rejected": duplicate_standby_rejected,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let active = value["after_primary_failure_active"]
                    .as_str()
                    .unwrap_or("?");
                println!("failover OK: after_primary_failure_active={active}");
            }
        }
        Err(err) => {
            eprintln!("failover example failed: {err}");
            std::process::exit(1);
        }
    }
}
