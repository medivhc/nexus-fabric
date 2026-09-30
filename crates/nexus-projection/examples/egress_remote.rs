//! E4 driver for `product.fabric-egress-remote` (3b-2: real fabric).
//!
//! Two-sided egress via real `FabricConn` datagrams over loopback UDP:
//!  1. A routes 30 UDP packets (to 1.2.3.4:80) → Egress{peer=B};
//!     A's `send_packet` records the flow in A's NAT and emits a datagram
//!     with the egress intent bit (hops=0) via `FabricTransport`.
//!  2. B's downlink (background thread) receives via its `FabricTransport`,
//!     validates the hop count (S13), and tracks the flow in B's NAT
//!     with origin peer "A".
//!  3. Mock "internet" replies → `b.handle_egress_reply` matches via B's NAT
//!     → forwarded back to A via fabric (mesh intent).
//!  4. A's downlink receives, NAT-validates the reply (S11), writes to A's TUN.
//!
//! Usage: cargo run -p nexus-projection --example egress_remote -- --json

use nexus_fabric::{ConnConfig, FabricConn, FabricListener};
use nexus_projection::{
    FabricTransport, MockTun, Projection, ProjectionConfig, RouteTarget, Rule, SimpleRuleEngine,
    TunDevice, UnifiedRouter,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Shared MockTun wrapper so the example can inspect what the downlink
/// thread wrote while the Projection owns the device.
struct SharedTun {
    inner: Arc<Mutex<MockTun>>,
}

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "shared"
    }
}

fn main() {
    let (report, pass) = match run() {
        Ok(r) => r,
        Err(e) => (format!("{{\"verdict\":\"FAIL\",\"detail\":\"{e}\"}}"), false),
    };
    println!("{report}");
    if !pass {
        std::process::exit(1);
    }
}

fn run() -> Result<(String, bool), String> {
    // --- Real fabric over loopback ---
    let listener =
        FabricListener::bind("127.0.0.1:0".parse().unwrap()).map_err(|e| format!("bind: {e}"))?;
    let server_peer = listener.peer_id();
    let server_addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    // B's side: accept in a thread (accept blocks).
    let accept_handle =
        std::thread::spawn(move || listener.accept().map_err(|e| format!("accept: {e}")));

    let conn_a = FabricConn::connect(
        server_peer,
        &ConnConfig {
            addrs: vec![server_addr],
            ..Default::default()
        },
    )
    .map_err(|e| format!("connect: {e}"))?;
    let conn_b = accept_handle
        .join()
        .map_err(|_| "accept thread panicked".to_string())??;

    let mut peers_a = HashMap::new();
    peers_a.insert("B".to_string(), conn_a);
    let transport_a = Arc::new(FabricTransport::new(peers_a));

    let mut peers_b = HashMap::new();
    peers_b.insert("A".to_string(), conn_b);
    let transport_b = Arc::new(FabricTransport::new(peers_b));

    // --- Projections ---
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
    // B's router: everything → Egress{self} (B is the egress node).
    let router_b = UnifiedRouter::new(
        vec![],
        Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().unwrap(),
            target: RouteTarget::Egress {
                peer: "self".to_string(),
            },
        }])),
    );

    let tun_a = Arc::new(Mutex::new(MockTun::new("tun-a")));
    let tun_b = Arc::new(Mutex::new(MockTun::new("tun-b")));

    let mut a = Projection::new(
        Box::new(SharedTun {
            inner: tun_a.clone(),
        }),
        ProjectionConfig::default(),
    )
    .with_router(Box::new(router_a))
    .with_transport(transport_a);

    let b = Projection::new(
        Box::new(SharedTun {
            inner: tun_b.clone(),
        }),
        ProjectionConfig::default(),
    )
    .with_router(Box::new(router_b))
    .with_transport(transport_b);

    const N: u32 = 30;
    let pkts: Vec<Vec<u8>> = (0..N)
        .map(|i| udp_packet([1, 2, 3, 4], 40000 + i as u16, 80, i))
        .collect();

    // 1. A routes + emits datagrams with egress intent via real fabric.
    let mut sent = 0u32;
    for pkt in &pkts {
        if a.send_packet(pkt).is_ok() {
            sent += 1;
        }
    }

    // 2. Wait for B's downlink to NAT-track all 30 (S11 on B's side).
    let deadline = Instant::now() + Duration::from_secs(10);
    while b.nat_stats().egress_handled < N as u64 {
        if Instant::now() > deadline {
            return Err(format!(
                "B NAT timeout: handled={}",
                b.nat_stats().egress_handled
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let b_handled = b.nat_stats().egress_handled;

    // 3. Mock internet replies → B's NAT matches → forwarded back to A.
    //    (handle_egress_reply sends via B's transport since peer="A".)
    let mut b_forwarded = 0u32;
    for pkt in &pkts {
        let reply = make_reply(pkt);
        if b.handle_egress_reply(&reply) {
            b_forwarded += 1;
        }
    }

    // 4. Wait for A's downlink to receive + NAT-validate + write to A's TUN.
    let deadline = Instant::now() + Duration::from_secs(10);
    while a.nat_stats().reply_received < N as u64 {
        if Instant::now() > deadline {
            return Err(format!(
                "A reply timeout: received={}",
                a.nat_stats().reply_received
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // 5. Validate A's TUN got the exact reply bytes.
    let written = tun_a.lock().unwrap().take_written();
    let mut replies_ok = 0u32;
    for pkt in &pkts {
        let expected = make_reply(pkt);
        if written.contains(&expected) {
            replies_ok += 1;
        }
    }
    let reply_bytes_match = replies_ok == N;

    let a_route = a.route_stats();
    let a_nat = a.nat_stats();
    let b_nat_stats = b.nat_stats();

    // Intent bit check: A's egress_remote datagrams must have egress intent.
    // (Validated implicitly: B's downlink only NAT-tracks egress-intent
    // packets; b_handled == N proves the bit was set.)
    let intent_egress_bit_set = b_handled == N as u64;

    let verdict = sent == N
        && a_route.egress_remote == N as u64
        && b_handled == N as u64
        && b_nat_stats.egress_handled == N as u64
        && b_forwarded == N
        && a_nat.reply_received == N as u64
        && reply_bytes_match
        && intent_egress_bit_set;

    let verdict_str = if verdict { "PASS" } else { "FAIL" };
    let report = format!(
        "{{\"verdict\":\"{}\",\"a\":{{\"route\":{{\"egress_remote\":{}}},\"nat\":{{\"reply_received\":{},\"reply_bytes_match\":{}}}}},\"b\":{{\"nat\":{{\"egress_handled\":{}}}}},\"intent\":{{\"egress_bit_set\":{}}}}}",
        verdict_str,
        a_route.egress_remote,
        a_nat.reply_received,
        reply_bytes_match,
        b_nat_stats.egress_handled,
        intent_egress_bit_set,
    );

    a.close();
    // B: drop (threads joined on Drop).

    Ok((report, verdict))
}
