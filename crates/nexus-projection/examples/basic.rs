//! E4 driver for `product.fabric-projection-basic`.
//!
//! Two Projection instances with MockTun, linked via mock fabric:
//!  1. A sends 100 deterministic IPv4 packets -> B's TUN (S1)
//!  2. B sends 100 packets -> A's TUN (S4 bidirectional)
//!  3. Verify byte-level integrity both ways, emit JSON.
//!
//! Usage: cargo run -p nexus-projection --example basic -- --json

use nexus_projection::{MockTun, Projection, ProjectionConfig, TunDevice};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shared MockTun so the example can drain what the downlink thread wrote.
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

/// Deterministic IPv4 packet: 20B header + variable payload.
fn make_packet(i: u32) -> Vec<u8> {
    let payload_len = 20 + (i % 100) as usize;
    let total_len = 20 + payload_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0x00; // DSCP
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    pkt[4] = (i >> 8) as u8; // ID
    pkt[5] = i as u8;
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    for (j, b) in pkt[20..].iter_mut().enumerate() {
        *b = ((i as usize * 31 + j * 7) % 256) as u8;
    }
    pkt
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
    let config = ProjectionConfig::default();

    let tun_a = Arc::new(Mutex::new(MockTun::new("tun-a")));
    let tun_b = Arc::new(Mutex::new(MockTun::new("tun-b")));
    let mut a = Projection::new(Box::new(SharedTun(tun_a.clone())), config.clone());
    let mut b = Projection::new(Box::new(SharedTun(tun_b.clone())), config);

    // Wire mock fabric: A -> B, B -> A.
    let a_inbox = a.inbox_sender();
    let b_inbox = b.inbox_sender();
    a.link_peer(b_inbox);
    b.link_peer(a_inbox);

    const N: u32 = 100;
    let packets: Vec<Vec<u8>> = (0..N).map(make_packet).collect();

    // Forward: A -> B.
    let mut sent = 0u32;
    for pkt in &packets {
        if a.send_packet(pkt).is_ok() {
            sent += 1;
        }
    }
    let ok = wait_for(|| b.stats().packets_in == N as u64, Duration::from_secs(10));
    let received_b = tun_b.lock().unwrap().take_written();
    let bytes_match = ok && received_b.len() == N as usize && received_b == packets;

    // Reverse: B -> A (S4 bidirectional).
    let rev_packets: Vec<Vec<u8>> = (1000..1000 + N).map(make_packet).collect();
    let mut rev_sent = 0u32;
    for pkt in &rev_packets {
        if b.send_packet(pkt).is_ok() {
            rev_sent += 1;
        }
    }
    let ok_rev = wait_for(|| a.stats().packets_in == N as u64, Duration::from_secs(10));
    let received_a = tun_a.lock().unwrap().take_written();
    let rev_match = ok_rev && received_a.len() == N as usize && received_a == rev_packets;

    let stats_a = a.stats();
    let verdict = sent == N
        && rev_sent == N
        && bytes_match
        && rev_match
        && stats_a.packets_out == N as u64
        && stats_a.packets_in == N as u64;

    // Explicit close (joins threads); also covered by Drop.
    a.close();
    b.close();

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"packets\":{{\"sent\":{},\"received\":{},\"bytes_match\":{}}},",
                "\"reverse\":{{\"bytes_match\":{}}},",
                "\"stats\":{{\"packets_out\":{},\"packets_in\":{}}}}}",
            ),
            if verdict { "PASS" } else { "FAIL" },
            sent,
            received_b.len(),
            bytes_match,
            rev_match,
            stats_a.packets_out,
            stats_a.packets_in,
        );
    } else {
        println!(
            "sent={} received_b={} bytes_match={} rev_match={} stats_a={:?} verdict={}",
            sent,
            received_b.len(),
            bytes_match,
            rev_match,
            stats_a,
            if verdict { "PASS" } else { "FAIL" },
        );
    }

    std::process::exit(if verdict { 0 } else { 1 });
}
