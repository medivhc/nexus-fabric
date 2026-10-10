//! E4 产品场景 `product.schedule-cli` 的可执行驱动。
//!
//! 由 `scenarios/product/schedule_cli_flow.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example schedule_cli_flow -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::schedule_cli_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match schedule_cli_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("schedule cli flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("schedule_cli_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
