//! E4 产品场景 `product.strategy-extended` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/strategy_extended.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example strategy_extended -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要.

#![forbid(unsafe_code)]

use nexus::strategy_extended_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match strategy_extended_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("strategy_extended OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("strategy_extended_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
