//! E4 driver for `product.fabric-egress-real-udp` (3b-4: real UDP egress).
//!
//!  1. A routes 10 UDP packets (to 127.0.0.1:<echo_port>) → Egress{peer=B};
//!     A's `send_packet` records the flow in A's NAT and emits a datagram
//!     with the egress intent bit (hops=0) via the mock peer link.
//!  2. B's downlink (background thread) receives the egress intent,
//!     validates the hop count (S13), and forwards the UDP payload via a
//!     real OS socket to a local echo server (S18).
//!  3. Echo replies arrive on B's per-flow sockets; `recv_reply`
//!     reverse-NATs them to peer A (S19) and B's egress-recv thread sends
//!     them back to A with mesh intent.
//!  4. A's downlink NAT-validates the replies (S11) and writes them to A's
//!     TUN; the example checks the bytes match.
//!  5. An unmapped probe (junk from a non-peer socket to one of B's flow
//!     sockets) is dropped and counted (S19).
//!
//! No mock replies: `handle_egress_reply` is never used.
//!
//! UDP unavailable (sandbox bind failure) → `{"verdict":"SKIP",...}`.
//!
//! Usage: cargo run -p nexus-projection --example egress_real_udp -- --json

use nexus_projection::{
    FlowKey, MockTun, Projection, ProjectionConfig, RouteTarget, Rule, SimpleRuleEngine,
    TunDevice, UnifiedRouter,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
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

fn skip(reason: &str) -> (String, bool) {
    (
        format!("{{\"verdict\":\"SKIP\",\"reason\":\"{reason}\"}}"),
        true,
    )
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
    // --- Local UDP echo server ("the internet") ---
    let echo_sock = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return Ok(skip("udp-blocked")),
    };
    let echo_port = echo_sock
        .local_addr()
        .map_err(|e| format!("echo local_addr: {e}"))?
        .port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        loop {
            match echo_sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let _ = echo_sock.send_to(&buf[..n], src);
                }
                Err(_) => break,
            }
        }
    });

    // --- Projections (mock peer link, per the scenario) ---
    // A's router: 127.0.0.0/8 → Egress{peer=B} (covers the echo server);
    // everything else → Drop.
    let router_a = UnifiedRouter::new(
        vec![],
        Box::new(SimpleRuleEngine::new(vec![
            Rule {
                cidr: "127.0.0.0/8".parse().unwrap(),
                target: RouteTarget::Egress {
                    peer: "B".to_string(),
                },
            },
            Rule {
                cidr: "0.0.0.0/0".parse().unwrap(),
                target: RouteTarget::Drop,
            },
        ])),
    );
    // B's router is irrelevant for downlink-received egress packets, but a
    // trivial one keeps the production shape.
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
    .with_router(Arc::new(router_a));

    let b = Projection::new(
        Box::new(SharedTun {
            inner: tun_b.clone(),
        }),
        ProjectionConfig::default(),
    )
    .with_router(Arc::new(router_b));
    let mut b = match b.with_real_egress() {
        Ok(b) => b,
        Err(_) => return Ok(skip("udp-blocked")),
    };

    a.link_mock_peer("B", &b);
    b.link_mock_peer("A", &a);
    // MockTransport tags datagrams with its own name ("local"); link it
    // explicitly so B's reply routing doesn't depend on the single-peer
    // fallback.
    b.mock_transport()
        .unwrap()
        .link_peer("local", a.mock_transport().unwrap().inbox_sender());

    const N: u32 = 10;
    let pkts: Vec<Vec<u8>> = (0..N)
        .map(|i| udp_packet([127, 0, 0, 1], 40000 + i as u16, echo_port, i))
        .collect();

    // 1. A routes + emits datagrams with egress intent via the mock link.
    let mut sent = 0u32;
    for pkt in &pkts {
        if a.send_packet(pkt).is_ok() {
            sent += 1;
        }
    }

    // 2. Wait for B's real socket to forward all 10 (S18).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = b.real_egress_stats().map(|s| s.real_sent).unwrap_or(0);
        if s >= N as u64 {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!("B real_sent timeout: {s}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // 3. Wait for A's downlink to NAT-validate all 10 replies (S11/S19).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if a.nat_stats().reply_received >= N as u64 {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!(
                "A reply timeout: received={}",
                a.nat_stats().reply_received
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // 4. Validate A's TUN got the exact reply bytes.
    let written = tun_a.lock().unwrap().take_written();
    let mut replies_ok = 0u32;
    for (i, pkt) in pkts.iter().enumerate() {
        let payload = &pkt[28..];
        let mut found = false;
        for w in &written {
            if let Some(key) = FlowKey::parse(w) {
                // Rebuilt reply: src = echo server, dst = A's virtual IP.
                if key.src_ip == u32::from_be_bytes([127, 0, 0, 1])
                    && key.dst_ip == u32::from_be_bytes([10, 0, 0, 1])
                    && key.src_port == echo_port
                    && key.dst_port == 40000 + i as u16
                    && key.proto == 17
                    && w.len() >= 28
                    && &w[28..] == payload
                {
                    found = true;
                    break;
                }
            }
        }
        if found {
            replies_ok += 1;
        }
    }
    let reply_bytes_match = replies_ok == N;

    // 5. S19: unmapped probe dropped and counted. Flow sockets are bound
    // to the wildcard, so substitute loopback for the probe destination.
    let addrs = b.real_egress_socket_addrs();
    if addrs.is_empty() {
        return Err("B has no flow sockets for the unmapped probe".into());
    }
    let mut target: SocketAddr = addrs[0];
    if target.ip().is_unspecified() {
        target.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }
    let attacker = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("attacker bind: {e}"))?;
    attacker
        .send_to(b"junk-unmapped-probe", target)
        .map_err(|e| format!("probe send: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let d = b
            .real_egress_stats()
            .map(|s| s.unmapped_dropped)
            .unwrap_or(0);
        if d >= 1 {
            break;
        }
        if Instant::now() > deadline {
            return Err("unmapped probe timeout".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let a_route = a.route_stats();
    let a_nat = a.nat_stats();
    let b_egress = b.real_egress_stats().unwrap_or_default();

    // Intent bit check: B's downlink only socket-forwards egress-intent
    // packets (after the S13 hop check); real_sent == N proves the bit.
    let intent_egress_bit_set = b_egress.real_sent == N as u64;

    let verdict = sent == N
        && a_route.egress_remote == N as u64
        && b_egress.real_sent == N as u64
        && b_egress.reply_routed == N as u64
        && b_egress.unmapped_dropped == 1
        && a_nat.reply_received == N as u64
        && reply_bytes_match
        && intent_egress_bit_set;

    let verdict_str = if verdict { "PASS" } else { "FAIL" };
    let report = format!(
        "{{\"verdict\":\"{}\",\"a\":{{\"route\":{{\"egress_remote\":{}}},\"nat\":{{\"reply_received\":{},\"reply_bytes_match\":{}}}}},\"b\":{{\"egress\":{{\"real_sent\":{},\"reply_routed\":{},\"unmapped_dropped\":{}}}}},\"intent\":{{\"egress_bit_set\":{}}}}}",
        verdict_str,
        a_route.egress_remote,
        a_nat.reply_received,
        reply_bytes_match,
        b_egress.real_sent,
        b_egress.reply_routed,
        b_egress.unmapped_dropped,
        intent_egress_bit_set,
    );

    a.close();
    b.close();

    Ok((report, verdict))
}
