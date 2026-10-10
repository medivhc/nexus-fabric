//! Run a Nexus Web Gateway node from a JSON configuration file.
//!
//! Usage:
//! ```text
//! cargo run -p nexus-web-gateway --example gateway -- ./examples/gateway.example.json
//! ```
//!
//! The process binds the configured `listen_addr`, serves the page over HTTPS
//! and stays alive until killed.

use nexus_web_gateway::{Gateway, GatewayConfig};

fn main() {
    let path = std::env::args().nth(1);
    match path.as_deref() {
        None | Some("--help" | "-h") => {
            println!("usage: gateway <config.json>");
        }
        Some(p) => {
            let cfg = match GatewayConfig::from_json_file(p) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };

            match Gateway::start(cfg.clone()) {
                Ok(handle) => {
                    println!(
                        "Nexus Web Gateway '{}' listening on https://{}",
                        cfg.node_name, handle.page_addr
                    );
                    println!(
                        "Page: https://{}/  (download the local CA at https://{}/cert \
                         and install it once; the certificate persists across restarts)",
                        handle.page_addr, handle.page_addr
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
    }
}
