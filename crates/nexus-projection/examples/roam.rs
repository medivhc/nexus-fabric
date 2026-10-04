//! E4 driver for `product.fabric-projection-roam`.
//!
//! Projection pair with mock fabric; mid-stream, simulate a path-switch
//! event on both ends (as `nexus-path` would deliver). Packet flow must
//! continue uninterrupted: 1000 sent == 1000 received, bytes intact.
//!
//! Usage: cargo run -p nexus-projection --example roam -- --json

use nexus_projection::{MockTun, Projection, ProjectionConfig, TunDevice};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

fn make_packet(i: u32) -> Vec<u8> {
    let payload_len = 20 + (i % 100) as usize;
    let total_len = 20 + payload_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = total_len as u8;
    pkt[4] = (i >> 8) as u8;
    pkt[5] = i as u8;
    pkt[8] = 64;
    pkt[9] = 17; // UDP
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

    a.link_mock_peer("B", &b);
    b.link_mock_peer("A", &a);

    const N: u32 = 1000;
    const HALF: u32 = N / 2;

    let mut sent = 0u32;
    for i in 0..HALF {
        if a.send_packet(&make_packet(i)).is_ok() {
            sent += 1;
        }
    }

    // Simulate path switch mid-stream (as nexus-path PathEvent::Switched).
    a.on_path_event();
    b.on_path_event();
    let switched = a.path_switch_count() == 1 && b.path_switch_count() == 1;

    for i in HALF..N {
        if a.send_packet(&make_packet(i)).is_ok() {
            sent += 1;
        }
    }

    let ok = wait_for(|| b.stats().packets_in == N as u64, Duration::from_secs(15));
    let received = tun_b.lock().unwrap().take_written();
    let expected: Vec<Vec<u8>> = (0..N).map(make_packet).collect();
    let bytes_match = ok && received.len() == N as usize && received == expected;

    let verdict = sent == N && bytes_match && switched;

    a.close();
    b.close();

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"packets\":{{\"sent\":{},\"received\":{},\"bytes_match\":{}}},",
                "\"path\":{{\"switched\":{}}}}}",
            ),
            if verdict { "PASS" } else { "FAIL" },
            sent,
            received.len(),
            bytes_match,
            switched,
        );
    } else {
        println!(
            "sent={} received={} bytes_match={} switched={} verdict={}",
            sent,
            received.len(),
            bytes_match,
            switched,
            if verdict { "PASS" } else { "FAIL" },
        );
    }

    std::process::exit(if verdict { 0 } else { 1 });
}
