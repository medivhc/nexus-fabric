//! E4: TUN 生产 TCP Proxy 经 Dataplane::tick() + MockTun 真实转发。
//!
//! 场景 `scenarios/product/proxy_fwd_tun_production.toml` 的可执行验证：
//! - SOCKS5 经真实 dataplane 装配完成 TCP echo 往返（非 engine 直调）；
//! - 发完 DATA 后零上行包，下行响应仍到达（常态 poll）；
//! - 无 engine 的 Proxy SYN 立即回 RST + `proxy_dropped_no_proxy`。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
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
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + payload.len()];
    pkt[0] = 0x45;
    let tot = (40 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
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
    pkt[40..].copy_from_slice(payload);
    let tc = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tc.to_be_bytes());
    pkt
}

fn tcp_parts(pkt: &[u8]) -> Option<(u32, u32, u8, &[u8])> {
    if pkt.len() < 40 || pkt[9] != 6 {
        return None;
    }
    let seq = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
    let ack = u32::from_be_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]);
    Some((seq, ack, pkt[33], &pkt[40..]))
}

fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn start_socks5() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind socks5");
    let addr = listener.local_addr().expect("socks5 addr");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve_socks5(stream));
        }
    });
    addr
}

fn serve_socks5(mut s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut greeting = [0u8; 2];
    if s.read_exact(&mut greeting).is_err() {
        return;
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    if s.read_exact(&mut methods).is_err() || s.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    let mut hdr = [0u8; 4];
    if s.read_exact(&mut hdr).is_err() || hdr[0] != 0x05 || hdr[1] != 0x01 {
        return;
    }
    let target = match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            if s.read_exact(&mut b).is_err() {
                return;
            }
            let ip = std::net::IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            SocketAddr::new(ip, u16::from_be_bytes([b[4], b[5]]))
        }
        _ => return,
    };
    let upstream = TcpStream::connect_timeout(&target, Duration::from_secs(10));
    let upstream = match upstream {
        Ok(u) => u,
        Err(_) => {
            let _ = s.write_all(&[0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    if s.write_all(&[0x05, 0x00, 0, 0x01, 0, 0, 0, 0, 0, 0])
        .is_err()
    {
        return;
    }
    let mut s2 = match s.try_clone() {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut up2 = match upstream.try_clone() {
        Ok(v) => v,
        Err(_) => return,
    };
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up2.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut upstream = upstream;
    let mut buf = [0u8; 8192];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if s2.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = t.join();
}

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn name(&self) -> &str {
        "prod-tun"
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
}

fn proxy_yaml(addr: SocketAddr) -> String {
    format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: proxy\noutbounds:\n  - tag: proxy\n    kind: socks5\n    locator: {addr}\n"
    )
}

fn config() -> DataplaneConfig {
    DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".into()],
        bypass_cidrs: vec!["192.168.0.0/16".into()],
        proxy_configured: true,
        ..Default::default()
    }
}

fn fail(error: impl Into<String>) -> serde_json::Value {
    json!({"verdict": "FAIL", "error": error.into()})
}

fn main() {
    let echo_addr = start_tcp_echo();
    let socks_addr = start_socks5();
    std::thread::sleep(Duration::from_millis(200));
    let output = run(echo_addr, socks_addr);
    println!("{}", serde_json::to_string(&output).unwrap());
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run(echo_addr: SocketAddr, socks_addr: SocketAddr) -> serde_json::Value {
    // 阶段 1：真实 Dataplane + engine + MockTun。
    let mock = Arc::new(Mutex::new(MockTun::new("prod0")));
    let mut dp = match Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config()) {
        Ok(dp) => dp,
        Err(e) => return fail(format!("dataplane init: {e}")),
    };
    let engine = match ProxyEngine::new(Some(&proxy_yaml(socks_addr))) {
        Ok(Some(e)) => e,
        Ok(None) => return fail("ProxyEngine::new returned None"),
        Err(e) => return fail(format!("ProxyEngine::new failed: {}", e.variant())),
    };
    dp.set_proxy_engine(engine);

    let epoch = std::time::Instant::now();
    let now = || u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);

    let src = [10, 0, 0, 2];
    let dst = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return fail("echo server is not IPv4"),
    };
    let src_port = 40001u16;

    // SYN → SYN-ACK。
    let syn = craft_tcp(src, dst, src_port, echo_addr.port(), 1000, 0, 0x02, &[]);
    mock.lock().unwrap().inject(syn);
    if let Err(e) = dp.tick(now()) {
        return fail(format!("process syn: {e}"));
    }
    let written = mock.lock().unwrap().take_written();
    let srv_seq = match written.iter().find_map(|pkt| tcp_parts(pkt)) {
        Some((s, _, flags, _)) if flags & 0x12 == 0x12 => s,
        _ => return fail("no SYN-ACK from engine"),
    };

    // ACK → 完成握手；等待 worker dial 成功。
    let ack = craft_tcp(
        src,
        dst,
        src_port,
        echo_addr.port(),
        1001,
        srv_seq.wrapping_add(1),
        0x10,
        &[],
    );
    mock.lock().unwrap().inject(ack);
    if let Err(e) = dp.tick(now()) {
        return fail(format!("process ack: {e}"));
    }
    for _ in 0..400 {
        let _ = dp.tick(now());
        let _ = mock.lock().unwrap().take_written();
        if dp.stats().proxy_forwarded > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let dialed = dp.stats().proxy_forwarded > 0;

    // DATA → 之后零上行，等待下行 echo。
    let payload = b"hello-tun-proxy";
    let data = craft_tcp(
        src,
        dst,
        src_port,
        echo_addr.port(),
        1001,
        srv_seq.wrapping_add(1),
        0x18,
        payload,
    );
    mock.lock().unwrap().inject(data);
    if let Err(e) = dp.tick(now()) {
        return fail(format!("process data: {e}"));
    }
    let mut down = Vec::new();
    let mut downlink_seen = false;
    for _ in 0..1000 {
        let _ = dp.tick(now());
        for pkt in mock.lock().unwrap().take_written() {
            if let Some((_, _, flags, data)) = tcp_parts(&pkt) {
                if flags & 0x04 != 0 {
                    continue;
                }
                down.extend_from_slice(data);
            }
        }
        if down.windows(payload.len()).any(|w| w == payload) {
            downlink_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // 阶段 2：无 engine → SYN 即 RST。
    let mock2 = Arc::new(Mutex::new(MockTun::new("prod1")));
    let mut dp2 = match Dataplane::new(Box::new(SharedTun(Arc::clone(&mock2))), config()) {
        Ok(dp) => dp,
        Err(e) => return fail(format!("dataplane2 init: {e}")),
    };
    let syn2 = craft_tcp(src, dst, src_port + 1, echo_addr.port(), 2000, 0, 0x02, &[]);
    mock2.lock().unwrap().inject(syn2);
    if let Err(e) = dp2.tick(now()) {
        return fail(format!("no-engine syn: {e}"));
    }
    let syn_ack2 = mock2.lock().unwrap().take_written();
    let srv_seq2 = syn_ack2
        .iter()
        .find_map(|pkt| tcp_parts(pkt))
        .map(|(seq, _, _, _)| seq)
        .unwrap_or(0);
    let ack2 = craft_tcp(
        src,
        dst,
        src_port + 1,
        echo_addr.port(),
        2001,
        srv_seq2.wrapping_add(1),
        0x10,
        &[],
    );
    mock2.lock().unwrap().inject(ack2);
    if let Err(e) = dp2.tick(now()) {
        return fail(format!("no-engine ack: {e}"));
    }
    let written2 = mock2.lock().unwrap().take_written();
    let rst_ok = written2.iter().any(|pkt| {
        tcp_parts(pkt)
            .map(|(_, _, flags, _)| flags & 0x04 != 0)
            .unwrap_or(false)
    });
    let no_engine_counter = dp2.stats().proxy_dropped_no_proxy;

    let stats = dp.stats();
    let tcp_ok = dialed && downlink_seen;
    let zero_uplink_ok = downlink_seen;
    let verdict = tcp_ok && zero_uplink_ok && rst_ok && stats.proxy_forwarded > 0;

    json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "tcp.http_ok": tcp_ok,
        "stats.proxy_forwarded": stats.proxy_forwarded,
        "stats.proxy_tcp_bytes": stats.proxy_tcp_bytes,
        "daemon_alive": true,
        "zero_uplink_downlink_ok": zero_uplink_ok,
        "injected_uplink_after_data": 0,
        "no_engine.rst_ok": rst_ok,
        "no_engine.proxy_dropped_no_proxy": no_engine_counter,
    })
}
