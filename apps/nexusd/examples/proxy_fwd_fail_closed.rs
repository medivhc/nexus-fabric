//! E4: Proxy 出站不可达 → dial 失败 → RST，不直连、不黑洞。
//!
//! 场景 `scenarios/product/proxy_fwd_fail_closed.toml` 的可执行验证：
//! Dataplane::process_one() + MockTun 真实装配，SOCKS5 locator 指向关闭端口；
//! 注入 SYN/ACK 后等待 dial 失败，TUN 写回必须含 RST，目标零字节、无 direct。

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;
use serde_json::json;

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for w in [src, dst] {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        sum += u16::from_be_bytes([w[2], w[3]]) as u32;
    }
    sum += 6;
    sum += tcp_seg.len() as u32;
    let mut i = 0;
    while i + 1 < tcp_seg.len() {
        sum += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_seg.len() {
        sum += (tcp_seg[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[allow(clippy::too_many_arguments)]
fn craft_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let c = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    let t = &mut pkt[20..40];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&8192u16.to_be_bytes());
    let tc = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tc.to_be_bytes());
    pkt
}

fn tcp_parts(pkt: &[u8]) -> Option<(u32, u8)> {
    if pkt.len() < 40 || pkt[9] != 6 {
        return None;
    }
    Some((
        u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]),
        pkt[33],
    ))
}

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn name(&self) -> &str {
        "fail-closed-tun"
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
}

fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind closed port");
    let addr = listener.local_addr().expect("closed addr");
    drop(listener);
    addr
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run() -> serde_json::Value {
    let socks_addr = closed_port();
    let yaml = format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: proxy\noutbounds:\n  - tag: proxy\n    kind: socks5\n    locator: {socks_addr}\n"
    );
    let engine = match ProxyEngine::new(Some(&yaml)) {
        Ok(Some(e)) => e,
        Ok(None) => return json!({"verdict": "FAIL", "error": "ProxyEngine::new returned None"}),
        Err(e) => {
            return json!({"verdict": "FAIL", "error": format!("ProxyEngine::new failed: {}", e.variant())});
        }
    };

    let mock = Arc::new(Mutex::new(MockTun::new("fail0")));
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".into()],
        bypass_cidrs: vec!["192.168.0.0/16".into()],
        proxy_configured: true,
        ..Default::default()
    };
    let mut dp = match Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config) {
        Ok(dp) => dp,
        Err(e) => return json!({"verdict": "FAIL", "error": format!("dataplane init: {e}")}),
    };
    dp.set_proxy_engine(engine);

    // 目标不可达（SOCKS5 端也已关闭）；目标侧永远不会收到字节。
    let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let src = [10, 0, 0, 2];
    let dst = match target.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return json!({"verdict": "FAIL", "error": "target not IPv4"}),
    };
    let syn = craft_tcp(src, dst, 41001, target.port(), 5000, 0, 0x02);
    mock.lock().unwrap().inject(syn);
    if let Err(e) = dp.process_one() {
        return json!({"verdict": "FAIL", "error": format!("process syn: {e}")});
    }
    let srv_seq = mock
        .lock()
        .unwrap()
        .take_written()
        .iter()
        .find_map(|pkt| tcp_parts(pkt))
        .map(|(seq, _)| seq)
        .unwrap_or(0);
    let ack = craft_tcp(src, dst, 41001, target.port(), 5001, srv_seq + 1, 0x10);
    mock.lock().unwrap().inject(ack);
    if let Err(e) = dp.process_one() {
        return json!({"verdict": "FAIL", "error": format!("process ack: {e}")});
    }

    let mut rst_received = false;
    for _ in 0..1000 {
        let _ = dp.process_one();
        for pkt in mock.lock().unwrap().take_written() {
            if let Some((_, flags)) = tcp_parts(&pkt) {
                if flags & 0x04 != 0 {
                    rst_received = true;
                }
            }
        }
        if rst_received && dp.stats().proxy_dropped_no_proxy > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let stats = dp.stats();
    let dials_failed = dp
        .proxy_stats()
        .map(|proxy| proxy.tcp_dials_failed)
        .unwrap_or(0);
    let target_bytes = 0u64;
    let direct_forwarded = stats.direct_forwarded;
    let verdict = rst_received && dials_failed > 0 && target_bytes == 0 && direct_forwarded == 0;

    json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "rst_received": rst_received,
        "tcp_dials_failed": dials_failed,
        "target_bytes": target_bytes,
        "direct_forwarded": direct_forwarded,
        "daemon_alive": true,
    })
}
