//! E4 产品场景 `product.remote-relay-unavailable-rollback` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/remote_relay_unavailable_rollback.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example remote_relay_unavailable_rollback -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。

#![forbid(unsafe_code)]

use nexus::remote_relay_unavailable_rollback;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match remote_relay_unavailable_rollback() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("remote relay unavailable rollback OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("remote_relay_unavailable_rollback failed: {err}");
            std::process::exit(1);
        }
    }
}
