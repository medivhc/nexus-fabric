//! E4 产品场景 `product.cross-subnet` 的可执行驱动。
//!
//! 由 `scenarios/product/cross_subnet.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example cross_subnet -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::cross_subnet_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match cross_subnet_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("cross subnet flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("cross_subnet_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
