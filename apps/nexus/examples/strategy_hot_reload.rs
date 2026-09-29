//! E4 产品场景 `product.strategy-hot-reload` 的可执行驱动（Composition Root）.
//!
//! 由 `scenarios/product/strategy_hot_reload.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example strategy_hot_reload -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要.

#![forbid(unsafe_code)]

use nexus::strategy_hot_reload_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match strategy_hot_reload_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("strategy_hot_reload OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("strategy_hot_reload_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
