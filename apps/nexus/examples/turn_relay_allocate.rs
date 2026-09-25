//! E4 产品场景 `product.turn-relay-allocate` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/turn_relay_allocate.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example turn_relay_allocate -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::turn_relay_allocate_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match turn_relay_allocate_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("turn relay allocate flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("turn_relay_allocate_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
