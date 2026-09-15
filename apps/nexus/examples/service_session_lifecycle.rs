//! E4 产品场景 product.resource-session-lifecycle 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/resource_session_lifecycle.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example service_session_lifecycle -- --json
//! ```

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let mut resource = "service://example".to_string();
    let mut profile = "Default".to_string();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--resource" => {
                if let Some(v) = iter.next() {
                    resource.clone_from(v);
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

    match nexus::service_session_lifecycle(&resource, &profile) {
        Ok(report) => {
            if as_json {
                println!("{report}");
            } else {
                println!("Service session lifecycle OK: {report}");
            }
        }
        Err(err) => {
            eprintln!("service_session_lifecycle failed: {err}");
            std::process::exit(1);
        }
    }
}
