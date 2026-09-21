//! E4 产品场景 `product.coord-core` 的可执行驱动（纯函数，显式 now）。
//!
//! 由 `scenarios/product/coord_core.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example coord_core -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::coord_core_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match coord_core_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("coord core flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("coord_core_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
