//! E4 `product.smart-retry-real`：真实指数退避循环，2 次可重试失败后第 3 次成功。
//!
//! ```text
//! cargo run --quiet -p nexus --example smart_retry_real -- --json
//! ```

#![forbid(unsafe_code)]

use std::cell::Cell;

use nexus_connectivity::smart_retry::{RetryConfig, RetryExecutor, RetryableClass};
use serde_json::json;

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let cfg = RetryConfig::new(5, 20, 2, 2, 200)?;
    let mut ex = RetryExecutor::new(cfg);
    let attempts = Cell::new(0u32);

    // op：前 2 次返回可重试失败，第 3 次成功返回 42。
    let result: Result<i32, _> = ex.execute(|_attempt| {
        let n = attempts.get() + 1;
        attempts.set(n);
        if n < 3 {
            Err(((), RetryableClass::Retryable))
        } else {
            Ok(42)
        }
    });

    let value = result?;
    let circuit = ex.circuit_state().as_str().to_string();

    Ok(json!({
        "verdict": "PASS",
        "command": "smart-retry-real",
        "result": value,
        "attempts": attempts.get(),
        "circuit_state": circuit,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(v) => {
            if as_json {
                println!("{v}");
            } else {
                println!("smart_retry_real: {v}");
            }
        }
        Err(e) => {
            eprintln!("smart_retry_real failed: {e}");
            std::process::exit(1);
        }
    }
}
