//! E4 产品场景 `product.virtual-subnet-nat-probe` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/virtual_subnet_nat_probe.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example virtual_subnet_nat_probe -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::virtual_subnet_nat_probe_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match virtual_subnet_nat_probe_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("virtual subnet nat probe flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("virtual_subnet_nat_probe_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
