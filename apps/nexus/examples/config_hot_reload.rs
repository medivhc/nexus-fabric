//! E4 产品场景 `product.config-hot-reload` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/config_hot_reload.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example config_hot_reload -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::config_hot_reload_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match config_hot_reload_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("config hot reload flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("config_hot_reload_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
