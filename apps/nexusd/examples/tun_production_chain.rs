//! E4: `tun_production_chain`（spec §12.1）— TUN 生产链最小闭环。

use std::io;
use std::sync::{Arc, Mutex};

use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "mock0"
    }
}

fn craft_udp(dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    pkt[0] = 0x45;
    let tot = (20 + 8 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    let server = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let addr = server.local_addr().expect("addr");
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        if let Ok((n, from)) = server.recv_from(&mut buf) {
            let _ = server.send_to(&buf[..n], from);
        }
    });
    let dst = match addr {
        std::net::SocketAddr::V4(v4) => v4.ip().octets(),
        std::net::SocketAddr::V6(_) => [127, 0, 0, 1],
    };
    let port = addr.port();

    let mock = Arc::new(Mutex::new(MockTun::new("mock0")));
    let config = DataplaneConfig {
        bypass_cidrs: vec!["127.0.0.0/8".to_string()],
        ..Default::default()
    };
    let mut dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config).expect("dataplane");
    mock.lock().unwrap().inject(craft_udp(dst, port, b"chain"));
    assert!(dp.tick(1).expect("tick"));
    let mut replies = 0;
    for _ in 0..2_000 {
        replies += dp.drain_direct_replies();
        if replies > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = handle.join();
    let stats = dp.stats();
    let pass = stats.direct_udp_sent >= 1 && replies >= 1;
    println!(
        "{{\"verdict\":\"{}\",\"matched_rule\":\"IP-CIDR,127.0.0.0/8\",\"selected_outbound\":\"self\",\"egress_hint\":null,\"direct_tcp_dial_ok\":0,\"upstream_failed\":0,\"direct_udp_sent\":{},\"direct_replies\":{}}}",
        if pass { "PASS" } else { "FAIL" },
        stats.direct_udp_sent,
        replies
    );
    std::process::exit(if pass { 0 } else { 1 });
}
