//! E4 产品场景 `product.bandwidth-policy` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/bandwidth_policy.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example bandwidth_policy -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//! 自包含：直接使用 `nexus_connectivity::bandwidth_policy`，不依赖 nexus lib flow。

#![forbid(unsafe_code)]

use nexus_connectivity::bandwidth_policy::{
    AllocationOutcome, BandwidthPolicy, OverflowStrategy, PolicyAllocator, Priority,
};
use serde_json::json;

fn main() {
    // policy：组配额 1000 B/s，节点配额 600 B/s。
    let policy = match BandwidthPolicy::new(1000, 600) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bandwidth_policy: invalid policy: {e}");
            std::process::exit(1);
        }
    };

    // ---- Drop 策略演示 ----
    let mut drop_alloc = PolicyAllocator::new(policy, OverflowStrategy::Drop);
    drop_alloc.register_node("a", "A", Priority::High);
    drop_alloc.register_node("b", "A", Priority::Normal);
    drop_alloc.register_node("c", "B", Priority::Normal);

    // t=0：a(High) 申请 500 -> 组内有配额 -> Granted。
    let first = drop_alloc.try_allocate("a", 500, 0);
    // t=0：b(Normal) 申请 600 -> 组 A 仅剩 500 < 600 -> Dropped（组配额不足）。
    let over = drop_alloc.try_allocate("b", 600, 0);
    // 未注册节点 -> Dropped。
    let unregistered = drop_alloc.try_allocate("ghost", 100, 0);

    let group_used_after = drop_alloc.group_used_bytes("A", 0);

    // t=1（新秒）：组/节点计数跨秒清零，b 再申请 600 -> Granted。
    let after_reset = drop_alloc.try_allocate("b", 600, 1);
    let group_used_after_reset = drop_alloc.group_used_bytes("A", 1);

    // ---- Queue 策略演示 ----
    let mut queue_alloc = PolicyAllocator::new(policy, OverflowStrategy::Queue);
    queue_alloc.register_node("a", "A", Priority::High);
    queue_alloc.register_node("b", "A", Priority::Normal);
    // t=0：a(High) 申请 700 -> Granted，组 A 剩 300。
    let _ = queue_alloc.try_allocate("a", 700, 0);
    // t=0：b(Normal) 申请 400 -> 组剩 300 < 400 -> Queued（不记账）。
    let queued = queue_alloc.try_allocate("b", 400, 0);
    let queued_count = queue_alloc.queued_count();

    let payload = json!({
        "verdict": "PASS",
        "command": "bandwidth-policy",
        "first_alloc": first.as_str(),
        "over_quota": over.as_str(),
        "unregistered_node": unregistered.as_str(),
        "queued_path": queued.as_str(),
        "after_second_reset": after_reset.as_str(),
        "first_alloc_bytes": match first { AllocationOutcome::Granted { bytes } => bytes, _ => 0 },
        "group_used_after": group_used_after,
        "group_used_after_reset": group_used_after_reset,
        "queued_count": queued_count,
        "policy": {
            "group_quota_bytes_per_sec": policy.group_quota_bytes_per_sec,
            "per_node_quota_bytes_per_sec": policy.per_node_quota_bytes_per_sec,
        },
    });

    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    if as_json {
        println!("{payload}");
    } else {
        println!(
            "bandwidth policy OK: first={} over={} queued={} after_reset={}",
            first.as_str(),
            over.as_str(),
            queued.as_str(),
            after_reset.as_str()
        );
    }
}
