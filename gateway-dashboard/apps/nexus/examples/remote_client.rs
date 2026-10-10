//! 真机演示（Node A 请求方客户端）：经网络发现协议从远端 Node B 拉取动态
//! Presence 并完成远程 Service 访问闭环。
//!
//! 用法：
//!
//! ```text
//! cargo run --release -p nexus --example remote_client -- \
//!     --discovery-endpoint 192.168.1.10:25000 [--json]
//! ```
//!
//! `--discovery-endpoint` 为 Node B 的发现服务地址（`node_b_service` 启动时打印）。

#![forbid(unsafe_code)]

use std::net::SocketAddr;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut discovery_endpoint: Option<SocketAddr> = None;
    let mut as_json = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--discovery-endpoint" => {
                let val = it.next().expect("missing value for --discovery-endpoint");
                discovery_endpoint = Some(val.parse().expect("invalid endpoint"));
            }
            "--json" => as_json = true,
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(endpoint) = discovery_endpoint else {
        eprintln!("usage: remote_client --discovery-endpoint <ip:port> [--json]");
        std::process::exit(2);
    };

    match nexus::remote_client_flow(endpoint) {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("remote client flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("remote_client_flow failed: {err}");
            std::process::exit(1);
        }
    }
}
