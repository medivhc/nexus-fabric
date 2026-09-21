//! E4 产品场景 `product.smart-retry` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/smart_retry.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example smart_retry -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//!
//! 本 example 自包含：直接使用 `nexus_connectivity::smart_retry`，
//! 不依赖 `nexus` 库中的 flow 函数。

#![forbid(unsafe_code)]

use nexus_connectivity::smart_retry::{RetryConfig, RetryExecutor, RetryableClass};
use serde_json::json;

/// 跑一遍智能重试决策矩阵，返回单个 JSON 对象。
fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let cfg = RetryConfig::new(3, 100, 2, 2, 1000)?;
    let ex = RetryExecutor::new(cfg);

    // 指数退避序列：attempt 1/2/3。
    let backoff_1 = ex.compute_backoff(1);
    let backoff_2 = ex.compute_backoff(2);
    let backoff_3 = ex.compute_backoff(3);

    // 超过 max_attempts -> StopRetry。
    let stop = ex.decide(4, 0);
    let stop_reason = match stop {
        nexus_connectivity::smart_retry::RetryDecision::StopRetry { reason } => reason,
        _ => "unexpected",
    };

    // 连续失败达阈值 -> 熔断 Open。
    let mut ex2 = RetryExecutor::new(cfg);
    ex2.record_failure(1000, RetryableClass::Retryable);
    ex2.record_failure(2000, RetryableClass::Retryable);
    let circuit_after_threshold = ex2.circuit_state().as_str().to_string();

    // 冷却期内（opened_at=2000, open_ms=1000, now=2500）-> CircuitOpen retry_after=500。
    let circuit_open = ex2.decide(1, 2500);
    let circuit_retry_after = match circuit_open {
        nexus_connectivity::smart_retry::RetryDecision::CircuitOpen { retry_after_ms } => {
            retry_after_ms
        }
        _ => 0,
    };

    // 冷却期过（now=3000）-> 放行一次 AllowAttempt。
    let after_cooldown = ex2.decide(1, 3000);
    let after_cooldown_decision = after_cooldown.as_str().to_string();

    // record_success -> 熔断回 Closed。
    ex2.record_success(4000);
    let success_resets_circuit = ex2.circuit_state().as_str().to_string();

    Ok(json!({
        "verdict": "PASS",
        "command": "smart-retry",
        "backoff_1": backoff_1,
        "backoff_2": backoff_2,
        "backoff_3": backoff_3,
        "stop_reason": stop_reason,
        "circuit_after_threshold": circuit_after_threshold,
        "circuit_retry_after": circuit_retry_after,
        "after_cooldown_decision": after_cooldown_decision,
        "success_resets_circuit": success_resets_circuit,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let b1 = value["backoff_1"].as_u64().unwrap_or(0);
                println!("smart-retry OK: backoff_1={b1}");
            }
        }
        Err(err) => {
            eprintln!("smart_retry example failed: {err}");
            std::process::exit(1);
        }
    }
}
