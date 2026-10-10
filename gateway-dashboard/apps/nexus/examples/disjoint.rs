//! E4 产品场景 `product.disjoint` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/disjoint.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example disjoint -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要.

#![forbid(unsafe_code)]

use nexus::disjoint_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match disjoint_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("disjoint OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("disjoint_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
