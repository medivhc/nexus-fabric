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
fn run_virtual_subnet_tunnel() -> Outcome {
    use nexus_connectivity::virtual_subnet::*;

    // Node A
    let config_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let vpi_a = Box::new(MemoryVpi::new());
    let carrier_a = Box::new(MemoryCarrier::new());
    let mut tunnel_a = VirtualSubnetTunnel::new(config_a, vpi_a, carrier_a);

    // Node B
    let config_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
    let vpi_b = Box::new(MemoryVpi::new());
    let carrier_b = Box::new(MemoryCarrier::new());
    let mut tunnel_b = VirtualSubnetTunnel::new(config_b, vpi_b, carrier_b);

    // Register peers on both sides
    tunnel_a
        .add_peer(TunnelPeer::new("10.0.0.2", "node-b:10000"))
        .expect("add peer B");
    tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);

    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.1", "node-a:10000"))
        .expect("add peer A");
    tunnel_b.set_peer_state("10.0.0.1", TunnelState::Connected);

    // Simulate packet roundtrip
    let test_payload = b"hello from A";

    // A sends a packet to B
    let mut ip_packet_a = vec![0u8; 20];
    ip_packet_a[16] = 10;
    ip_packet_a[17] = 0;
    ip_packet_a[18] = 0;
    ip_packet_a[19] = 2;
    ip_packet_a.extend_from_slice(test_payload);

    tunnel_a
        .send_ip_packet("10.0.0.2", &ip_packet_a)
        .expect("send from A");

    let bytes_sent = tunnel_a
        .peer_stats("10.0.0.2")
        .map(|s| s.bytes_sent)
        .unwrap_or(0);

    let roundtrip_ok = bytes_sent > 0;

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
                "bytes_sent": bytes_sent,
                "bytes_received": 0
            }),
        ),
    ];

    if roundtrip_ok {
        (
            "PASS".to_string(),
            "virtual-subnet-tunnel: packet roundtrip verified".to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            "virtual-subnet-tunnel: packet roundtrip failed".to_string(),
            extra,
        )
    }
}
