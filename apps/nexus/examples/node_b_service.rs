//! 真机演示（Node B 提供方常驻服务）：发布动态 Presence 并循环处理发现请求与
//! 资源会话。
//!
//! 用法：
//!
//! ```text
//! cargo run --release -p nexus --example node_b_service -- \
//!     --bind 0.0.0.0 --discovery-port 25000 --resource-port 25001 --announce-ip 192.168.1.10
//! ```
//!
//! `--bind` 默认 `0.0.0.0`（真机需对外可达）；`--announce-ip` 为 Node B 对外可
//! 达地址（公告进 Presence 的 Endpoint，默认取本机回环地址）。启动后打印一行
//! JSON 公告（discovery_addr / resource_addr / peer），Node A 用
//! `remote_client --discovery-endpoint <discovery_addr>` 连接。

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;

use nexus_discovery::{PeerId, PresenceRegistry, PresenceServer};

fn parse_ip(s: &str) -> IpAddr {
    s.parse().expect("invalid IP")
}

fn parse_port(s: &str) -> u16 {
    s.parse().expect("invalid port")
}

fn main() {
    let mut bind_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut announce_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut discovery_port = 25_000u16;
    let mut resource_port = 25_001u16;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().expect("missing value");
        match arg.as_str() {
            "--bind" => bind_ip = parse_ip(&val()),
            "--announce-ip" => announce_ip = parse_ip(&val()),
            "--discovery-port" => discovery_port = parse_port(&val()),
            "--resource-port" => resource_port = parse_port(&val()),
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }

    // 发现端点 + 资源端点（对外监听）。
    let discovery_listener = std::net::TcpListener::bind(SocketAddr::new(bind_ip, discovery_port))
        .expect("bind discovery");
    let discovery_addr = discovery_listener.local_addr().expect("discovery addr");
    let resource_listener = std::net::TcpListener::bind(SocketAddr::new(bind_ip, resource_port))
        .expect("bind resource");
    let resource_addr = resource_listener.local_addr().expect("resource addr");

    // Node B 注册中心：公告真实可达资源端点（announce-ip 需为 Node A 可达地址）。
    let mut registry = PresenceRegistry::default();
    let announced_endpoint = SocketAddr::new(announce_ip, resource_addr.port());
    registry
        .announce(PeerId("node-b".into()), announced_endpoint, 60)
        .expect("announce");

    // 公告（Node A 据此配置 discovery-endpoint）。
    println!(
        "{{ \"peer\": \"node-b\", \"discovery_addr\": \"{}\", \"resource_addr\": \"{}\", \"announced_endpoint\": \"{}\" }}",
        discovery_addr, resource_addr, announced_endpoint
    );

    // 发现服务线程：常驻循环 accept -> 请求帧 -> PresenceServer::handle -> 响应帧。
    let server = PresenceServer;
    let discovery_thread = thread::spawn(move || {
        loop {
            let Ok(mut fs) = nexus_transport::accept(&discovery_listener) else {
                break;
            };
            if let Ok(request) = fs.recv_frame() {
                let response = server.handle(&registry, &request);
                if !response.is_empty() {
                    let _ = fs.send_frame(&response);
                }
            }
        }
    });

    // 资源服务线程：常驻循环 accept -> CONNECT/READY（可重复服务多个会话）。
    let resource_thread = thread::spawn(move || {
        loop {
            let Ok(mut fs) = nexus_transport::accept(&resource_listener) else {
                break;
            };
            if let Ok(frame) = fs.recv_frame() {
                if frame == b"CONNECT" {
                    let _ = fs.send_frame(b"READY");
                }
            }
        }
    });

    // 常驻运行；线程 panic 视为服务故障退出。
    let _ = discovery_thread.join();
    let _ = resource_thread.join();
}
