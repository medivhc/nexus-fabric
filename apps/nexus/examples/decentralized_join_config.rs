//! E4 产品场景 `product.decentralized-join-config` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/decentralized_join_config.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example decentralized_join_config -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::decentralized_join_config_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match decentralized_join_config_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("decentralized join config flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("decentralized_join_config_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
