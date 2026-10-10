//! E4 产品场景 `product.remote-nat-relay-fallback-flow` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/remote_nat_relay_fallback_flow.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example remote_nat_relay_fallback_flow -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::remote_nat_relay_fallback_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match remote_nat_relay_fallback_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("remote nat relay fallback flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("remote_nat_relay_fallback_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
