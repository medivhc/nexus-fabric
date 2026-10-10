//! E5 产品场景 `product.coord-join-loopback` 的可执行驱动。
//!
//! 由 `scenarios/product/coord_join_loopback.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example coord_join_loopback -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::coord_join_loopback_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match coord_join_loopback_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("coord join loopback flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("coord_join_loopback_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
