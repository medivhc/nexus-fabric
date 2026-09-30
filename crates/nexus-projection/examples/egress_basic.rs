//! E4 driver for `product.fabric-egress-basic`.
//!
//! Single Projection with MockTun + UnifiedRouter + EgressNat:
//!  1. 50 UDP packets to 8.8.8.8:53 → Egress{self} → NAT records
//!  2. 10 packets to 10.1.2.3 → MeshPeer via 10/8 fast path (S10)
//!  3. 5 packets to 1.2.3.4 → Drop via REJECT rule (S12)
//!  4. Mock "internet" replies for the 50 egress packets → NAT matches →
//!     written to TUN; verify byte integrity.
//!
//! Usage: cargo run -p nexus-projection --example egress_basic -- --json

use nexus_projection::{
    MockTun, Projection, ProjectionConfig, RouteTarget, Rule, SimpleRuleEngine, TunDevice,
    UnifiedRouter,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shared MockTun so the example can inject and drain around the threads.
struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "shared-mocktun"
    }
}

/// Deterministic UDP packet: 20B IPv4 + 8B UDP + 8B payload.
fn udp_packet(dst: [u8; 4], sport: u16, dport: u16, seed: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 36];
    pkt[0] = 0x45; // IPv4, IHL 5
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src: our virtual IP
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + 8) as u16).to_be_bytes()); // UDP len
    for (j, b) in pkt[28..].iter_mut().enumerate() {
        *b = ((seed as usize * 31 + j * 7) % 256) as u8;
    }
    pkt
}

/// Mock internet reply: swap src/dst IPs and ports, keep payload.
fn make_reply(out: &[u8]) -> Vec<u8> {
    let mut r = out.to_vec();
    let mut src_ip = [0u8; 4];
    let mut dst_ip = [0u8; 4];
    src_ip.copy_from_slice(&out[12..16]);
    dst_ip.copy_from_slice(&out[16..20]);
    r[12..16].copy_from_slice(&dst_ip);
    r[16..20].copy_from_slice(&src_ip);
    let mut sport = [0u8; 2];
    let mut dport = [0u8; 2];
    sport.copy_from_slice(&out[20..22]);
    dport.copy_from_slice(&out[22..24]);
    r[20..22].copy_from_slice(&dport);
    r[22..24].copy_from_slice(&sport);
    r
}

fn wait_for<F>(mut cond: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    cond()
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");

    // Router: 10/8 fast path → MeshPeer; 1.2.3.0/24 → Drop; rest → Egress{self}.
    let router = UnifiedRouter::new(
        vec!["10.0.0.0/8".parse().unwrap()],
        Box::new(SimpleRuleEngine::new(vec![
            Rule {
                cidr: "1.2.3.0/24".parse().unwrap(),
                target: RouteTarget::Drop,
            },
            Rule {
                cidr: "0.0.0.0/0".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "self".to_string(),
                },
            },
        ])),
    );

    let tun = Arc::new(Mutex::new(MockTun::new("tun-egress")));
    let p = Projection::new(
        Box::new(SharedTun(tun.clone())),
        ProjectionConfig::default(),
    )
    .with_router(Box::new(router));

    // 1. 50 UDP packets to the internet → Egress{self}.
    let egress_pkts: Vec<Vec<u8>> = (0..50)
        .map(|i| udp_packet([8, 8, 8, 8], 10000 + i as u16, 53, i))
        .collect();
    // 2. 10 packets to the virtual subnet → MeshPeer (S10).
    let mesh_pkts: Vec<Vec<u8>> = (0..10)
        .map(|i| udp_packet([10, 1, 2, 3], 20000 + i as u16, 80, 1000 + i))
        .collect();
    // 3. 5 packets → Drop (S12).
    let drop_pkts: Vec<Vec<u8>> = (0..5)
        .map(|i| udp_packet([1, 2, 3, 4], 30000 + i as u16, 80, 2000 + i))
        .collect();

    {
        let mut t = tun.lock().unwrap();
        for pkt in egress_pkts
            .iter()
            .chain(mesh_pkts.iter())
            .chain(drop_pkts.iter())
        {
            t.inject(pkt.clone());
        }
    }

    // Wait until the uplink thread has routed all 65 packets.
    let routed = wait_for(
        || {
            let rs = p.route_stats();
            rs.egress_self + rs.mesh_peer + rs.dropped == 65
        },
        Duration::from_secs(10),
    );

    let rs = p.route_stats();
    let route_ok = routed && rs.egress_self == 50 && rs.mesh_peer == 10 && rs.dropped == 5;

    // 4. Mock internet replies for the 50 egress packets.
    let mut replies_ok = 0u32;
    for pkt in &egress_pkts {
        let reply = make_reply(pkt);
        if p.handle_egress_reply(&reply) {
            replies_ok += 1;
        }
    }

    // Wait for all replies + mesh packets to land in the TUN.
    // 50 replies (via handle_egress_reply) + 10 mesh (via downlink loopback).
    let delivered = wait_for(|| p.stats().packets_in == 60, Duration::from_secs(10));
    let written = tun.lock().unwrap().take_written();

    // Verify every reply is byte-identical to what the mock internet sent.
    let expected_replies: Vec<Vec<u8>> = egress_pkts.iter().map(|p| make_reply(p)).collect();
    let mut reply_bytes_match = delivered && written.len() == 60;
    if reply_bytes_match {
        for er in &expected_replies {
            if !written.contains(er) {
                reply_bytes_match = false;
                break;
            }
        }
    }

    let nat = p.nat_stats();
    let verdict = route_ok && replies_ok == 50 && nat.reply_received == 50 && reply_bytes_match;

    p.close();

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"route\":{{\"egress_self\":{},\"mesh_peer\":{},\"dropped\":{}}},",
                "\"nat\":{{\"reply_received\":{},\"reply_bytes_match\":{}}}}}",
            ),
            if verdict { "PASS" } else { "FAIL" },
            rs.egress_self,
            rs.mesh_peer,
            rs.dropped,
            nat.reply_received,
            reply_bytes_match,
        );
    } else {
        println!(
            "route={:?} replies_ok={} nat={:?} bytes_match={} verdict={}",
            rs,
            replies_ok,
            nat,
            reply_bytes_match,
            if verdict { "PASS" } else { "FAIL" },
        );
    }
}
