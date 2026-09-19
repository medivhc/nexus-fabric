//! Run specific E4 scenarios directly.

use super::Outcome;
use serde_json::json;

/// Run a specific scenario directly (for E4 product-level tests).
pub fn run_scenario(args: &[String]) -> Outcome {
    let subcommand = args.first().map(String::as_str).unwrap_or("");
    match subcommand {
        "virtual-subnet-tunnel" => run_virtual_subnet_tunnel(),
        _ => (
            "BLOCKED".to_string(),
            format!("unknown run subcommand: {subcommand}"),
            Vec::new(),
        ),
    }
}

/// E4 test: two nodes connected via virtual subnet tunnel (offline, deterministic).
///
/// P1: 完整双向包往返验证（A → B → A）。
fn run_virtual_subnet_tunnel() -> Outcome {
    use nexus_connectivity::virtual_subnet::*;

    // 创建一对真正互连的 MemoryCarrier
    let (carrier_a, carrier_b) = MemoryCarrier::connected_pair();

    // Node A
    let config_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let vpi_a = Box::new(MemoryVpi::new());
    let mut tunnel_a = VirtualSubnetTunnel::new(config_a, vpi_a, Box::new(carrier_a));

    // Node B
    let config_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
    let vpi_b = Box::new(MemoryVpi::new());
    let mut tunnel_b = VirtualSubnetTunnel::new(config_b, vpi_b, Box::new(carrier_b));

    // Register peers on both sides
    tunnel_a
        .add_peer(TunnelPeer::new("10.0.0.2", "node-b:10000"))
        .expect("add peer B");
    tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);

    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.1", "node-a:10000"))
        .expect("add peer A");
    tunnel_b.set_peer_state("10.0.0.1", TunnelState::Connected);

    // 1. A 发送包到 B
    let mut ip_packet_a = vec![0u8; 20];
    ip_packet_a[16] = 10; // dst IP: 10.0.0.2
    ip_packet_a[17] = 0;
    ip_packet_a[18] = 0;
    ip_packet_a[19] = 2;
    ip_packet_a.extend_from_slice(b"hello from A");

    tunnel_a
        .send_ip_packet("10.0.0.2", &ip_packet_a)
        .expect("send from A");

    // 2. B 从 carrier 接收并解封装
    let mut recv_buf = [0u8; 2048];
    let recv_result = tunnel_b
        .recv_and_deliver(&mut recv_buf)
        .expect("B receive and deliver");

    let b_received = recv_result.is_some();

    // 3. B 回包到 A
    let mut reply_packet = vec![0u8; 20];
    reply_packet[16] = 10; // dst IP: 10.0.0.1
    reply_packet[17] = 0;
    reply_packet[18] = 0;
    reply_packet[19] = 1;
    reply_packet.extend_from_slice(b"hello from B");

    tunnel_b
        .send_ip_packet("10.0.0.1", &reply_packet)
        .expect("B reply");

    // 4. A 从 carrier 接收回包
    let recv_result = tunnel_a
        .recv_and_deliver(&mut recv_buf)
        .expect("A receive reply");

    let a_received_reply = recv_result.is_some();

    // 收集统计
    let stats_a = tunnel_a.peer_stats("10.0.0.2").unwrap();
    let stats_b = tunnel_b.peer_stats("10.0.0.1").unwrap();

    let roundtrip_ok = b_received
        && a_received_reply
        && stats_a.bytes_sent > 0
        && stats_a.bytes_received > 0
        && stats_b.bytes_sent > 0
        && stats_b.bytes_received > 0;

    let extra = vec![
        ("subnet".to_string(), json!({"cidr": "10.0.0.0/24"})),
        ("node_a".to_string(), json!({"virtual_ip": "10.0.0.1"})),
        ("node_b".to_string(), json!({"virtual_ip": "10.0.0.2"})),
        (
            "tunnel".to_string(),
            json!({"status": if roundtrip_ok { "Connected" } else { "Failed" }}),
        ),
        (
            "packet_roundtrip".to_string(),
            json!({
                "ok": roundtrip_ok,
                "bytes_sent": stats_a.bytes_sent,
                "bytes_received": stats_a.bytes_received,
                "b_received_packet": b_received,
                "a_received_reply": a_received_reply
            }),
        ),
    ];

    if roundtrip_ok {
        (
            "PASS".to_string(),
            "virtual-subnet-tunnel: bidirectional roundtrip verified".to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            "virtual-subnet-tunnel: bidirectional roundtrip failed".to_string(),
            extra,
        )
    }
}
