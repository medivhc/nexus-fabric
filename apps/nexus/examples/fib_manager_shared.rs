//! E4 产品场景 `product.fib-manager-shared` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/fib_manager_shared.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example fib_manager_shared -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要.

#![forbid(unsafe_code)]

use nexus::fib_manager_shared_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match fib_manager_shared_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("fib_manager_shared OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("fib_manager_shared_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
