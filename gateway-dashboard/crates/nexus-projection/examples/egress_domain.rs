//! E4 driver for `product.fabric-egress-domain` (3b-3: domain rules).
//!
//! Deterministic two-projection flow (mock peer link, background threads
//! driven via stats polling):
//!  1. A routes a DNS query for `www.blocked.example` → sniffed QNAME →
//!     DOMAIN-SUFFIX rule → `Egress{peer=B}` (S16).
//!  2. B's downlink receives the egress-intent datagram (S13 validated) and
//!     NAT-tracks it — this proves the egress intent bit was set.
//!  3. Mock "internet" DNS response (A 1.2.3.4) → `b.handle_egress_reply`
//!     matches B's NAT → forwarded back to A (S11).
//!  4. A's downlink NAT-validates the response and writes it to A's TUN.
//!  5. A's router sniffs the response (sport 53) → learns
//!     1.2.3.4 → www.blocked.example into the DNS cache (S17); the response
//!     itself is decided by the queried domain.
//!  6. A UDP packet to 1.2.3.4:80 inherits the cached domain → `Egress{B}`
//!     (S17; the IP rule alone would Drop it).
//!  7. DNS query for `www.allowed.example` → no domain hit → falls back to
//!     IP rules → `Egress{self}` (S16).
//!  8. Malformed DNS packet (garbage to port 53) → sniff fails → ordinary
//!     IP routing, not dropped (S15).
//!
//! Usage: cargo run -p nexus-projection --example egress_domain -- --json

use nexus_projection::{
    MockTun, Projection, ProjectionConfig, RouteTarget, Rule, SimpleRuleEngine, TunDevice,
    UnifiedRouter,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// IPv4/UDP packet with a raw payload.
fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// Minimal DNS query message for `qname` (QTYPE=A).
fn dns_query(txid: u16, qname: &str) -> Vec<u8> {
    let mut m = vec![0u8; 12];
    m[0..2].copy_from_slice(&txid.to_be_bytes());
    m[2..4].copy_from_slice(&[0x01, 0x00]); // standard query, RD
    m[4..6].copy_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    for label in qname.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0x00);
    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    m
}

/// Minimal DNS response: `qname` → A `ip`, compression pointer for the name.
fn dns_response(txid: u16, qname: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut m = vec![0u8; 12];
    m[0..2].copy_from_slice(&txid.to_be_bytes());
    m[2..4].copy_from_slice(&[0x81, 0x80]); // response, RD+RA
    m[4..6].copy_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    m[6..8].copy_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    for label in qname.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0x00);
    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    m.extend_from_slice(&[0xC0, 0x0C]); // NAME → pointer to QNAME
    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
    m.extend_from_slice(&ip);
    m
}

/// Shared MockTun wrapper so the example can inspect downlink writes while
/// the Projection owns the device.
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

fn wait_for(ok: impl Fn() -> bool, what: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ok() {
        if Instant::now() > deadline {
            return Err(format!("timeout waiting for {what}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn main() {
    let (report, pass) = match run() {
        Ok(r) => r,
        Err(e) => (
            format!("{{\"verdict\":\"FAIL\",\"detail\":\"{e}\"}}"),
            false,
        ),
    };
    println!("{report}");
    if !pass {
        std::process::exit(1);
    }
}

fn run() -> Result<(String, bool), String> {
    // --- A's rules (per scenario [given]): DOMAIN-SUFFIX blocked.example
    // → Egress{B}; IP 1.2.3.0/24 → Egress{B}; default → Egress{self}.
    let mut engine_a = SimpleRuleEngine::new(vec![
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
    ]);
    engine_a.add_domain_suffix_rule(
        "blocked.example",
        RouteTarget::Egress {
            peer: "B".to_string(),
        },
    );
    // B's rules: everything → Egress{self} (B is the egress node).
    let engine_b = SimpleRuleEngine::new(vec![Rule {
        cidr: "0.0.0.0/0".parse().unwrap(),
        target: RouteTarget::Egress {
            peer: "self".to_string(),
        },
    }]);

    let router_a = Arc::new(UnifiedRouter::new(vec![], Box::new(engine_a)));
    let router_b = Arc::new(UnifiedRouter::new(vec![], Box::new(engine_b)));

    let tun_a = Arc::new(Mutex::new(MockTun::new("tun-a")));
    let tun_b = Arc::new(Mutex::new(MockTun::new("tun-b")));

    let mut a = Projection::new(
        Box::new(SharedTun {
            inner: tun_a.clone(),
        }),
        ProjectionConfig::default(),
    )
    .with_router(router_a.clone());
    let mut b = Projection::new(
        Box::new(SharedTun {
            inner: tun_b.clone(),
        }),
        ProjectionConfig::default(),
    )
    .with_router(router_b);
    a.link_mock_peer("B", &b);
    b.link_mock_peer("A", &a);

    // --- 1. DNS query for www.blocked.example → Egress{B} (S16).
    let query = ipv4_udp(
        [10, 0, 0, 1],
        [8, 8, 8, 8],
        40000,
        53,
        &dns_query(0x1234, "www.blocked.example"),
    );
    a.send_packet(&query)
        .map_err(|e| format!("send query: {e}"))?;
    let dns_query_egress_remote = a.route_stats().egress_remote;

    // --- 2. B's downlink receives the egress-intent datagram (S13) and
    // NAT-tracks it. Only egress-intent packets bump egress_handled, so
    // this proves the intent bit was set.
    wait_for(|| b.nat_stats().egress_handled == 1, "B NAT track query")?;
    let intent_egress_bit_set = b.nat_stats().egress_handled == 1;

    // --- 3. Mock internet DNS response → B's NAT → forwarded back to A.
    // 5-tuple is the exact reverse of the query (S11).
    let response = ipv4_udp(
        [8, 8, 8, 8],
        [10, 0, 0, 1],
        53,
        40000,
        &dns_response(0x1234, "www.blocked.example", [1, 2, 3, 4], 60),
    );
    if !b.handle_egress_reply(&response) {
        return Err("B handle_egress_reply failed".to_string());
    }

    // --- 4. A's downlink NAT-validates the response, writes to A's TUN.
    wait_for(|| a.nat_stats().reply_received == 1, "A reply received")?;

    // --- 5. F1 fix: the downlink thread now runs the response through
    // router_a.route_packet for DNS learning (S17) — no manual call.
    // Wait for the cache to be learned via the real production path.
    wait_for(
        || router_a.dns_stats().cache_inserted == 1,
        "cache learned via downlink",
    )?;
    let cache_inserted = router_a.dns_stats().cache_inserted;

    // --- 6. Packet to the resolved IP inherits the cached domain (S17):
    // cache hit → DOMAIN-SUFFIX rule → Egress{B} (checked before IP rules).
    let er_before = a.route_stats().egress_remote;
    let to_resolved = ipv4_udp([10, 0, 0, 1], [1, 2, 3, 4], 40001, 80, b"hello");
    a.send_packet(&to_resolved)
        .map_err(|e| format!("send to resolved ip: {e}"))?;
    let cached_ip_egress_remote = a.route_stats().egress_remote - er_before;

    // --- 7. Query for an unlisted domain → IP fallback → Egress{self} (S16).
    let es_before = a.route_stats().egress_self;
    let query_allowed = ipv4_udp(
        [10, 0, 0, 1],
        [8, 8, 8, 8],
        40002,
        53,
        &dns_query(0x5678, "www.allowed.example"),
    );
    a.send_packet(&query_allowed)
        .map_err(|e| format!("send allowed query: {e}"))?;
    let dns_query_fallback_egress_self = a.route_stats().egress_self - es_before;

    // --- 8. Malformed DNS packet → sniff fails → ordinary routing, kept (S15).
    let dropped_before = a.route_stats().dropped;
    let malformed = ipv4_udp([10, 0, 0, 1], [8, 8, 8, 8], 40003, 53, b"\xff\x00garbage");
    a.send_packet(&malformed)
        .map_err(|e| format!("send malformed: {e}"))?;
    let malformed_not_dropped = a.route_stats().dropped == dropped_before;
    let sniff_failed = router_a.dns_stats().sniff_failed;

    let verdict = dns_query_egress_remote == 1
        && intent_egress_bit_set
        && cache_inserted == 1
        && cached_ip_egress_remote == 1
        && dns_query_fallback_egress_self == 1
        && malformed_not_dropped
        && sniff_failed >= 1;
    let verdict_str = if verdict { "PASS" } else { "FAIL" };

    let report = format!(
        "{{\"verdict\":\"{verdict_str}\",\
         \"a\":{{\"route\":{{\
           \"dns_query_egress_remote\":{dns_query_egress_remote},\
           \"cached_ip_egress_remote\":{cached_ip_egress_remote},\
           \"dns_query_fallback_egress_self\":{dns_query_fallback_egress_self}}},\
         \"dns\":{{\"cache_inserted\":{cache_inserted},\
           \"malformed_not_dropped\":{malformed_not_dropped},\
           \"sniff_failed\":{sniff_failed}}}}},\
         \"intent\":{{\"egress_bit_set\":{intent_egress_bit_set}}}}}",
    );

    a.close();
    // B: Drop joins threads.

    Ok((report, verdict))
}
