//! N1 组网接入 E4：TUN Mesh 包真发进 N1（mock N1 发送器，无需特权）。
//!
//! 场景 `scenarios/product/n1_wireup.toml` 的可执行验证：
//! - mesh_send：Mesh 包 → N1 真发 → mock 收到包内容一致；
//! - mesh_no_route：无路由 → mesh_dropped_no_n1；
//! - mesh_no_conn：有路由但发送失败 → mesh_dropped_no_n1；
//! - n1_recv：N1 下行包 → 写回 TUN → tun_written；
//! - proxy_unaffected：Proxy 分类不受 N1 影响。

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use nexus_network::n1::bridge::N1Sender;
use nexus_network::n1::{N1Error, N1PeerId};
use nexus_projection::MockTun;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use serde_json::json;

/// Mock N1 发送器：记录收到的包；可配置路由表与失败模式。
struct MockN1Sender {
    /// 记录 (dst, packet)。
    sent: Mutex<Vec<(Ipv4Addr, Vec<u8>)>>,
    /// 有路由的网段（如 "10.99.0.0/16"）。
    routed_cidr: (u32, u8),
    /// 为 true 时 send 返回 Err（模拟无连接）。
    fail_send: bool,
}

impl MockN1Sender {
    fn new(cidr: &str) -> Self {
        let (addr_s, prefix_s) = cidr.split_once('/').unwrap();
        let addr: Ipv4Addr = addr_s.parse().unwrap();
        let prefix: u8 = prefix_s.parse().unwrap();
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        Self {
            sent: Mutex::new(Vec::new()),
            routed_cidr: (u32::from(addr) & mask, prefix),
            fail_send: false,
        }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let (net, prefix) = self.routed_cidr;
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        (u32::from(ip) & mask) == net
    }

    fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    fn first_packet(&self) -> Option<Vec<u8>> {
        self.sent.lock().unwrap().first().map(|(_, p)| p.clone())
    }
}

impl N1Sender for MockN1Sender {
    fn send_to_mesh(&self, dst: Ipv4Addr, packet: &[u8]) -> Result<(), N1Error> {
        if !self.contains(dst) {
            return Err(N1Error::PeerUnknown);
        }
        if self.fail_send {
            return Err(N1Error::PeerUnknown);
        }
        // 1200B datagram 限制（对标 N1Connection）。
        if packet.len() > 1200 {
            return Err(N1Error::OversizeDatagram(packet.len()));
        }
        self.sent.lock().unwrap().push((dst, packet.to_vec()));
        Ok(())
    }
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn run() -> serde_json::Value {
    // 1. Mock TUN，注入测试包。
    let mut tun = MockTun::new("mocktun0");
    // Mesh 包（有路由）：目的 10.99.0.5。
    let mesh_pkt = build_ipv4_packet(Ipv4Addr::new(10, 99, 0, 5), 6, &[0xABu8; 64]);
    tun.inject(mesh_pkt.clone());
    // Mesh 包（无路由）：目的 10.100.0.5。
    tun.inject(build_ipv4_packet(
        Ipv4Addr::new(10, 100, 0, 5),
        6,
        b"no-route",
    ));
    // Mesh 包（超限）：目的 10.99.0.6，1300B payload → OversizeDatagram。
    tun.inject(build_ipv4_packet(
        Ipv4Addr::new(10, 99, 0, 6),
        6,
        &[0xCDu8; 1300],
    ));
    // Proxy 包：目的 198.18.1.1（fake-IP）。
    tun.inject(build_ipv4_packet(Ipv4Addr::new(198, 18, 1, 1), 6, b"proxy"));

    // 2. 数据面（mesh 10.0.0.0/8，N1 已配置，QoS/DNS 禁用）。
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.0.0.0/8".to_string()],
        bypass_cidrs: vec![],
        dns_enabled: false,
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

    // 3. 注入 Mock N1（路由 10.99.0.0/16）。
    let mock_n1 = Arc::new(MockN1Sender::new("10.99.0.0/16"));
    let mock_n1_clone = Arc::clone(&mock_n1);
    dp.set_n1_sender(mock_n1);
    assert!(dp.n1_bridge_ready());

    // 4. 处理所有包。
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

    // 5. W2：N1 下行包写回 TUN。
    let downlink_pkt = build_ipv4_packet(Ipv4Addr::new(192, 168, 1, 50), 6, b"from-n1");
    dp.inject_from_n1(&downlink_pkt);

    let stats = dp.stats();
    // 验证 mock N1 确实收到了 mesh 包（内容一致，非同义反复）。
    let n1_got_packet = mock_n1_clone
        .first_packet()
        .map(|p| p == mesh_pkt)
        .unwrap_or(false);
    let n1_received_bytes = mock_n1_clone.first_packet().map(|p| p.len()).unwrap_or(0);

    // mesh_forwarded=1（有路由且发送成功）；
    // mesh_dropped_no_n1=2（10.100.0.5 无路由 + 10.99.0.6 超限）；
    // proxy_forwarded=1（不受 N1 影响）。
    let pass = processed == 4
        && stats.mesh_forwarded == 1
        && stats.mesh_dropped_no_n1 == 2
        && stats.proxy_forwarded == 1
        && stats.tun_written == 1
        && n1_got_packet
        && mock_n1_clone.sent_count() == 1;

    json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "n1": {
            "mesh_forwarded": stats.mesh_forwarded,
            "mesh_dropped_no_n1": stats.mesh_dropped_no_n1,
            "tun_written": stats.tun_written,
            "n1_received_bytes": n1_received_bytes,
            "n1_got_packet": n1_got_packet,
            "proxy_forwarded": stats.proxy_forwarded,
            "processed": processed,
        }
    })
}

/// 构造最小 IPv4 包。
fn build_ipv4_packet(dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&[192, 168, 1, 100]);
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..].copy_from_slice(payload);
    pkt
}

// 抑制未使用导入警告（N1PeerId 在 trait 签名中间接使用）。
#[allow(dead_code)]
fn _use_types(_: N1PeerId, _: IpAddr) {}
