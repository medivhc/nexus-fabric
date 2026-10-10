//! E4 产品场景 `product.k-shortest` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/k_shortest.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example k_shortest -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要.

#![forbid(unsafe_code)]

use nexus::k_shortest_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match k_shortest_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("k_shortest OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("k_shortest_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
