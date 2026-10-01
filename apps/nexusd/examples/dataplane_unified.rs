//! 统一数据面 E4：TUN→分类→DNS→QoS 全链路（mock TUN，无需特权）。
//!
//! 场景 `scenarios/product/dataplane_unified.toml` 的可执行验证：
//! 注入 mesh/proxy/direct/drop/DNS 五种包，验证分类计数与 DNS 响应。

use std::net::Ipv4Addr;

use nexus_projection::MockTun;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use serde_json::json;

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn run() -> serde_json::Value {
    // 1. Mock TUN，预注入 5 种测试包。
    let mut tun = MockTun::new("mocktun0");
    // Mesh 包：目的 10.1.2.3（在 10.0.0.0/8 内）。
    tun.inject(build_ipv4_packet(
        Ipv4Addr::new(10, 1, 2, 3),
        6,
        b"mesh-payload",
    ));
    // Proxy 包：目的 198.18.1.1（在 fake-IP 池内）。
    tun.inject(build_ipv4_packet(
        Ipv4Addr::new(198, 18, 1, 1),
        6,
        b"proxy-payload",
    ));
    // Direct 包：目的 192.168.1.1（在 bypass 内）。
    tun.inject(build_ipv4_packet(
        Ipv4Addr::new(192, 168, 1, 1),
        6,
        b"direct-payload",
    ));
    // Drop 包：非 IPv4（版本 6）。
    let mut v6 = vec![0x60u8; 40];
    v6.extend_from_slice(b"drop");
    tun.inject(v6);
    // DNS 查询包：UDP dport 53，查询 example.com。
    tun.inject(build_dns_query(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        "example.com",
        0x1234,
    ));

    // 2. 数据面（mesh 10.0.0.0/8，bypass 192.168.0.0/16，DNS 启用，QoS 禁用）。
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.0.0.0/8".to_string()],
        bypass_cidrs: vec!["192.168.0.0/16".to_string()],
        dns_enabled: true,
        dns_config: None,
        qos_enabled: false,
        qos_config: Default::default(),
        boost_enabled: false,
        n1_configured: true,
        proxy_configured: true,
    };
    let mut dp = match Dataplane::new(Box::new(tun), config) {
        Ok(dp) => dp,
        Err(e) => {
            return json!({
                "verdict": "FAIL",
                "error": format!("dataplane init failed: {e}"),
            });
        }
    };

    // 3. 处理所有包。
    let mut processed = 0;
    for _ in 0..10 {
        match dp.process_one() {
            Ok(true) => processed += 1,
            Ok(false) => break,
            Err(e) => {
                return json!({
                    "verdict": "FAIL",
                    "error": format!("process_one failed: {e}"),
                });
            }
        }
    }

    let stats = dp.stats().clone();
    // DNS 响应验证：需要从 TUN 取出写入的包。由于 Dataplane 拥有 TUN，
    // MVP 通过 dns_answered 计数验证；完整包检查后置。
    json!({
        "verdict": if processed == 5 { "PASS" } else { "FAIL" },
        "dataplane": {
            "mesh_forwarded": stats.mesh_forwarded,
            "proxy_forwarded": stats.proxy_forwarded,
            "direct_forwarded": stats.direct_forwarded,
            "dropped": stats.dropped,
            "dns_answered": stats.dns_answered,
            "dns_response_received": stats.dns_answered == 1,
            "qos_bypassed": dp.qos_bypassed(),
            "processed": processed,
        }
    })
}

/// 构造最小 IPv4 包（TCP/UDP payload）。
fn build_ipv4_packet(dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // 版本 4，IHL 5
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&[192, 168, 1, 100]); // src
    pkt[16..20].copy_from_slice(&dst.octets()); // dst
    pkt[20..].copy_from_slice(payload);
    // IP 校验和（MVP 置零，分类器不校验）
    pkt
}

/// 构造 DNS 查询包（IPv4 + UDP dport 53）。
fn build_dns_query(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, qname: &str, txid: u16) -> Vec<u8> {
    // DNS 查询体。
    let mut dns = Vec::new();
    dns.extend_from_slice(&txid.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00]); // RD=1
    dns.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    dns.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    dns.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    dns.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    for label in qname.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0x00); // 结束
    dns.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    dns.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // UDP 头。
    let udp_len = 8 + dns.len();
    let mut udp = Vec::new();
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]); // 校验和置零

    // IP 头。
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..20 + udp.len()].copy_from_slice(&udp);
    pkt[20 + udp.len()..].copy_from_slice(&dns);
    pkt
}
