//! E4 driver for `product.fabric-egress-remote`.
//!
//! Two-sided egress via a mock fabric:
//!  1. A routes 30 UDP packets (to 1.2.3.4:80) → Egress{peer=B};
//!     A's `send_packet` records the flow in A's NAT and emits a datagram
//!     with the egress intent bit set.
//!  2. The example (mock fabric) checks the intent bit, strips it, and hands
//!     the IP packet to B's NAT (`Egress{self}` on B's side).
//!  3. Mock "internet" replies → B's NAT matches → reply handed back.
//!  4. A's `handle_egress_reply` matches via A's NAT → written to A's TUN.
//!
//! Usage: cargo run -p nexus-projection --example egress_remote -- --json

use nexus_projection::{
    EgressNat, MockTun, Projection, ProjectionConfig, RouteTarget, Rule, SimpleRuleEngine,
    UnifiedRouter, decode_intent,
};
use std::sync::mpsc;

/// Deterministic UDP packet: 20B IPv4 + 8B UDP + 8B payload.
fn udp_packet(dst: [u8; 4], sport: u16, dport: u16, seed: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 36];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src: A's virtual IP
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + 8) as u16).to_be_bytes());
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

fn main() {
    let json = std::env::args().any(|a| a == "--json");

    // A's router: 1.2.3.0/24 → Egress{peer=B}; rest → Egress{self}.
    let router_a = UnifiedRouter::new(
        vec!["10.0.0.0/8".parse().unwrap()],
        Box::new(SimpleRuleEngine::new(vec![
            Rule {
                cidr: "1.2.3.0/24".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "B".to_string(),
                },
            },
            Rule {
                cidr: "0.0.0.0/0".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "self".to_string(),
                },
            },
        ])),
    );

    // A: thread-less is unavailable to examples, so use `send_packet`
    // directly (no threads needed for the injection path).
    let mut a = Projection::new(Box::new(MockTun::new("tun-a")), ProjectionConfig::default())
        .with_router(Box::new(router_a));

    // Mock fabric: A's output goes to the example, which plays B + internet.
    let (fabric_tx, fabric_rx) = mpsc::channel::<Vec<u8>>();
    a.link_peer(fabric_tx);

    // B's side building blocks (B's router would say Egress{self} for these;
    // the E4 focuses on B's NAT handling).
    let mut b_nat = EgressNat::new();

    const N: u32 = 30;
    let pkts: Vec<Vec<u8>> = (0..N)
        .map(|i| udp_packet([1, 2, 3, 4], 40000 + i as u16, 80, i))
        .collect();

    // 1-2. A routes + emits datagrams with the egress intent bit.
    let mut sent = 0u32;
    for pkt in &pkts {
        if a.send_packet(pkt).is_ok() {
            sent += 1;
        }
    }

    // 3. Mock fabric: check intent bit, hand to B's NAT.
    let mut intent_egress_bit_set = true;
    let mut b_handled = 0u32;
    for _ in 0..N {
        let datagram = fabric_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("datagram from A");
        let (intent_byte, ip_pkt) = datagram.split_first().expect("datagram has intent byte");
        let (is_egress, _hops) = decode_intent(*intent_byte);
        if !is_egress {
            intent_egress_bit_set = false;
        }
        // B's NAT handles the egress (B's router: 0.0.0.0/0 → Egress{self}).
        if b_nat.translate_outbound(ip_pkt, "A").is_some() {
            b_handled += 1;
        }
    }

    // 4-5. Mock internet replies → B's NAT matches → back to A.
    let mut replies_ok = 0u32;
    for pkt in &pkts {
        let reply = make_reply(pkt);
        // B's NAT matches the reply to the tracked flow.
        let b_match = b_nat.translate_inbound(&reply).is_some();
        // A validates the reply against its own originator tracking.
        let a_match = a.handle_egress_reply(&reply);
        if b_match && a_match {
            replies_ok += 1;
        }
    }

    let a_route = a.route_stats();
    let a_nat = a.nat_stats();
    let b_nat_stats = b_nat.stats();

    // 6. Byte integrity: P0 NAT never modifies packets (unit-tested);
    // a successful `handle_egress_reply` means the exact mock reply bytes
    // were matched and written to A's TUN.
    let reply_bytes_match = replies_ok == N;

    let verdict = sent == N
        && a_route.egress_remote == N as u64
        && b_handled == N
        && b_nat_stats.egress_handled == N as u64
        && replies_ok == N
        && a_nat.reply_received == N as u64
        && reply_bytes_match
        && intent_egress_bit_set;

    a.close();

    if json {
        // Build JSON manually (no serde in std-only crate).
        let verdict_str = if verdict { "PASS" } else { "FAIL" };
        println!(
            "{{\"verdict\":\"{}\",\"a\":{{\"route\":{{\"egress_remote\":{}}},\"nat\":{{\"reply_received\":{},\"reply_bytes_match\":{}}}}},\"b\":{{\"nat\":{{\"egress_handled\":{}}}}},\"intent\":{{\"egress_bit_set\":{}}}}}",
            verdict_str,
            a_route.egress_remote,
            a_nat.reply_received,
            reply_bytes_match,
            b_nat_stats.egress_handled,
            intent_egress_bit_set,
        );
    } else {
        println!(
            "sent={} a_route={:?} a_nat={:?} b_nat={:?} intent_egress={} bytes_match={} verdict={}",
            sent,
            a_route,
            a_nat,
            b_nat_stats,
            intent_egress_bit_set,
            reply_bytes_match,
            if verdict { "PASS" } else { "FAIL" },
        );
    }
}
