//! E4 产品场景 product.internet-access-flow 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/internet_access_flow.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example internet_access_flow -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let mut destination = "https://example.invalid/".to_string();
    let mut profile = "Balanced".to_string();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--destination" => {
                if let Some(v) = iter.next() {
                    destination.clone_from(v);
                }
            }
            "--profile" => {
                if let Some(v) = iter.next() {
                    profile.clone_from(v);
                }
            }
            _ => {}
        }
    }

    match nexus::internet_access_flow(&destination, &profile) {
        Ok(report) => {
            if as_json {
                println!("{report}");
            } else {
                println!("InternetAccess flow OK: {report}");
            }
        }
        Err(err) => {
            eprintln!("internet_access_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
