//! P4 产品场景 `bootstrap-udp-loopback` 的可执行驱动（真实 UDP，无 root/TUN）。
//!
//! ```text
//! cargo run --quiet -p nexus --example bootstrap_udp_loopback -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）。

#![forbid(unsafe_code)]

use nexus::bootstrap_udp_loopback_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match bootstrap_udp_loopback_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("bootstrap udp loopback flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("bootstrap_udp_loopback_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
