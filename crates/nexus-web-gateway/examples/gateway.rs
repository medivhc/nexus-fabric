//! Run a Nexus Web Gateway node from a JSON configuration file.
//!
//! Usage:
//! ```text
//! cargo run -p nexus-web-gateway --example gateway -- ./gateway.json
//! ```
//!
//! The process binds the configured `listen_addr`, serves the page over HTTPS
//! and stays alive until killed.

use nexus_web_gateway::{Gateway, GatewayConfig};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: gateway <config.json>");
            std::process::exit(2);
        });

    let cfg = match GatewayConfig::from_json_file(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    match Gateway::start(cfg.clone()) {
        Ok(handle) => {
            println!(
                "Nexus Web Gateway '{}' listening on https://{}",
                cfg.node_name, handle.local_addr
            );
            println!(
                "Page: https://{}/  (install the local CA certificate on first visit)",
                handle.local_addr
            );
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Err(e) => {
            eprintln!("gateway failed to start: {e}");
            std::process::exit(1);
        }
    }
}