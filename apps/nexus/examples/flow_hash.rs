//! E4 产品场景 `product.flow-hash` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/flow_hash.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example flow_hash -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::flow_hash_selection;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match flow_hash_selection() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("flow_hash selection OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("flow_hash_selection failed: {err}");
            std::process::exit(1);
        }
    }
}
