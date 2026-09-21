//! E4 产品场景 `product.traffic-stats` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/traffic_stats.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example traffic_stats -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::traffic_stats_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match traffic_stats_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("traffic stats flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("traffic_stats_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
