//! E4 产品场景 `product.cli-subnet` 的可执行驱动。
//!
//! 由 `scenarios/product/cli_subnet.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example subnet_cli -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::subnet_cli_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match subnet_cli_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("subnet cli flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("subnet_cli_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
