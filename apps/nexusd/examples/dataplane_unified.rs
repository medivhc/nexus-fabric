//! 统一数据面 E4：TUN→分类→DNS→QoS 全链路（mock TUN，无需特权）。
//!
//! 场景 `scenarios/product/dataplane_unified.toml` 的可执行验证：
//! 注入 mesh/proxy/direct/drop/DNS 五种包，验证分类计数与 DNS 响应。
//! 转发类包用 UDP 数据报（S1 终结 TCP，TCP 包不走转发计数路径）。

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nexus_network::n1::N1Error;
use nexus_network::n1::bridge::N1Sender;
use nexus_projection::MockTun;
use nexus_proxy::domain_engine::DomainRuleEngine;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use serde_json::json;

/// 测试用 N1 发送器：全部接受（W1 语义：mesh_forwarded 只计 N1 真发成功）。
struct AcceptAllN1Sender;

impl N1Sender for AcceptAllN1Sender {
    fn send_to_mesh(&self, _dst: Ipv4Addr, _packet: &[u8]) -> Result<(), N1Error> {
        Ok(())
    }
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn run() -> serde_json::Value {
    // 1. Mock TUN，预注入 5 种测试包（UDP 数据报）。
    let mut tun = MockTun::new("mocktun0");
    // Mesh 包：目的 10.1.2.3（在 10.0.0.0/8 内）。
    tun.inject(build_udp_packet(
        Ipv4Addr::new(10, 1, 2, 3),
        9999,
        12345,
        b"mesh-payload",
    ));
    // Proxy 包：目的 198.18.1.1（在 fake-IP 池内）。
    tun.inject(build_udp_packet(
        Ipv4Addr::new(198, 18, 1, 1),
        9999,
        12345,
        b"proxy-payload",
    ));
    // Direct 包：目的 192.168.1.1（在 bypass 内）。
    tun.inject(build_udp_packet(
        Ipv4Addr::new(192, 168, 1, 1),
        9999,
        12345,
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
        ..Default::default()
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

    // 2b. 注入 Mock N1 发送器（W1：无 sender 时 Mesh 包计
    // mesh_dropped_no_n1，不计 mesh_forwarded）。
    dp.set_n1_sender(Arc::new(AcceptAllN1Sender));

    // 2c. 注入 Proxy 引擎（P1/P3：proxy_forwarded 只计真实转发；
    // 无 engine 时 Proxy 包计 proxy_dropped_no_proxy）。桩 SOCKS5 只做
    // UDP ASSOCIATE + 收包丢弃，足以让 UdpForwarder::send 成功。
    let socks_addr = start_socks5_udp_stub();
    let proxy_yaml = format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: proxy\noutbounds:\n  - tag: proxy\n    kind: socks5\n    locator: {}\n",
        socks_addr
    );
    let proxy_engine = nexusd::proxy_fwd::ProxyEngine::new(Some(&proxy_yaml))
        .expect("proxy engine from stub socks5")
        .expect("engine constructed");
    dp.set_proxy_engine(proxy_engine);
    // P3：`Dataplane::new` 初始规则为空（fail-closed），须显式注入与
    // ProxyEngine 同源的规则引擎，否则 198.18.1.1 会被判 Drop。
    dp.set_rule_engine(Box::new(
        DomainRuleEngine::from_yaml(&proxy_yaml).expect("dataplane rule engine from stub socks5"),
    ));

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

    let stats = dp.stats();
    // DNS 响应验证：tun_written 证明响应包确实写入了 TUN（非同义反复）。
    json!({
        "verdict": if processed == 5 { "PASS" } else { "FAIL" },
        "dataplane": {
            "mesh_forwarded": stats.mesh_forwarded,
            "proxy_forwarded": stats.proxy_forwarded,
            "direct_forwarded": stats.direct_forwarded,
            "dropped": stats.dropped,
            "dns_answered": stats.dns_answered,
            "dns_response_received": stats.tun_written == 1,
            "qos_bypassed": dp.qos_bypassed(),
            "processed": processed,
        }
    })
}

/// 构造最小 IPv4/UDP 包（含合法 UDP 头；代理路径的 parse_udp_packet 需要）。
fn build_udp_packet(dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // 版本 4，IHL 5
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[192, 168, 1, 100]); // src
    pkt[16..20].copy_from_slice(&dst.octets()); // dst
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // UDP 校验和置零：测试桩不校验
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// 最小 SOCKS5 UDP 桩：NO-AUTH 握手 + UDP ASSOCIATE，收到的 UDP 包直接丢弃。
/// 只为让 UdpForwarder::establish()/send() 成功（proxy_forwarded 真实计数）。
fn start_socks5_udp_stub() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || handle_socks5_udp_assoc(stream));
        }
    });
    addr
}

fn handle_socks5_udp_assoc(mut s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    // 握手：[VER, NMETHODS, METHODS...] → [VER, NO-AUTH]。
    let mut hdr = [0u8; 2];
    if s.read_exact(&mut hdr).is_err() {
        return;
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    if s.read_exact(&mut methods).is_err() {
        return;
    }
    if s.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    // UDP ASSOCIATE 请求（10 字节，ATYP=IPv4）。
    let mut req = [0u8; 10];
    if s.read_exact(&mut req).is_err() || req[1] != 0x03 {
        return;
    }
    let udp = match UdpSocket::bind("127.0.0.1:0") {
        Ok(u) => u,
        Err(_) => return,
    };
    let relay = udp.local_addr().unwrap();
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    match relay.ip() {
        IpAddr::V4(v4) => reply.extend_from_slice(&v4.octets()),
        _ => return,
    }
    reply.extend_from_slice(&relay.port().to_be_bytes());
    if s.write_all(&reply).is_err() {
        return;
    }
    // 排空 UDP（保持中继地址有效；测试只发一个包）。
    let mut buf = [0u8; 65535];
    while udp.recv_from(&mut buf).is_ok() {}
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
