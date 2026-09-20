//! E4 产品场景 `product.mesh-dns` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/mesh_dns.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example mesh_dns -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::mesh_dns_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match mesh_dns_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("mesh dns flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("mesh_dns_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
