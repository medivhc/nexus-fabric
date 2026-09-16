//! E4 产品场景 product.connectivity-failure-rollback 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/connectivity_failure_rollback.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example connectivity_failure_rollback -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    match nexus::connectivity_failure_rollback("https://relay.example.invalid/", "Balanced") {
        Ok(report) => {
            if as_json {
                println!("{report}");
            } else {
                println!("Connectivity rollback OK: {report}");
            }
        }
        Err(err) => {
            eprintln!("connectivity_failure_rollback failed: {err}");
            std::process::exit(1);
        }
    }
}
