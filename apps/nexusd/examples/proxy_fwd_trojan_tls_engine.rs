//! E4（MAJOR-5）：TLS Trojan 经 **nexusd 引擎**（`Dataplane::tick()` + `ProxyEngine`
//! + MockTun）真实完成 TCP 中继。
//!
//! 拓扑（全 loopback、离线）：
//! - TCP echo 目标（真实 `TcpListener`）；
//! - 本地 Trojan **TLS** 节点：`nexus_outbound_trojan::server_config(自签)`，
//!   解析 trojan 请求头 → 连到目标 → 双向中继（与 `proxy_outbound_trojan_flow`
//!   同一套 loopback TLS 材料，不新增依赖）；
//! - `Dataplane` + `ProxyEngine`：trojan 出站以 `skip_cert_verify: true` 声明 TLS
//!   （字段出现即声明），规则选中该 tag。
//!
//! 断言（引擎面，不是 `nexus proxy` 前端）：SYN → SYN-ACK、DATA 经隧道到达 echo、
//! 下行 echo 经隧道回写 TUN，且引擎 stats 佐证（`proxy_tcp_streams_ok` /
//! `proxy_tcp_bytes` / `proxy_forwarded`）。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_outbound_trojan::{generate_loopback_identity, parse_request, server_config};
use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;
use serde_json::json;

const PASSWORD: &str = "e4-trojan-tls";
const PAYLOAD: &[u8] = b"hello-via-nexusd-trojan-tls";

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

/// 从 TLS stream 读到第二个 CRLF（trojan 请求头结束）。
fn read_trojan_header<S: Read>(tls: &mut S) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(128);
    let mut one = [0u8; 1];
    loop {
        tls.read_exact(&mut one)
            .map_err(|e| format!("trojan header read: {e}"))?;
        buf.push(one[0]);
        if buf.windows(2).filter(|w| **w == *b"\r\n").count() >= 2 {
            return Ok(buf);
        }
        if buf.len() > 4096 {
            return Err("trojan header too large".to_string());
        }
    }
}

fn fail(error: impl Into<String>) -> serde_json::Value {
    json!({"verdict": "FAIL", "error": error.into()})
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run() -> serde_json::Value {
    let echo_addr = start_tcp_echo();

    // --- 本地 Trojan TLS 节点（自签，离线） ---
    let identity = match generate_loopback_identity() {
        Ok(identity) => identity,
        Err(error) => return fail(format!("loopback identity: {error:?}")),
    };
    let srv_cfg = match server_config(&identity) {
        Ok(cfg) => Arc::new(cfg),
        Err(error) => return fail(format!("server config: {error:?}")),
    };
    let node_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) => return fail(format!("bind trojan node: {error}")),
    };
    let node_addr = match node_listener.local_addr() {
        Ok(addr) => addr,
        Err(error) => return fail(format!("node addr: {error}")),
    };
    let connected = Arc::new(AtomicBool::new(false));
    let connected_clone = Arc::clone(&connected);
    let node_thread = std::thread::spawn(move || -> Result<(String, u16), String> {
        node_listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        // §11.9.5：nexusd 先发凭据探测连接（目标为保留域）；真实节点解析失败即关闭，
        // 这里同样关闭并继续等流连接。
        let mut probes_skipped = 0u32;
        let (mut tcp, mut conn, header) = loop {
            let mut accepted = None;
            for _ in 0..50 {
                match node_listener.accept() {
                    Ok((stream, _)) => {
                        accepted = Some(stream);
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(format!("trojan node accept: {e}")),
                }
            }
            let mut tcp = accepted.ok_or("no trojan node connection within window")?;
            tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
            tcp.set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| e.to_string())?;
            tcp.set_write_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| e.to_string())?;
            let mut conn = rustls::ServerConnection::new(Arc::clone(&srv_cfg))
                .map_err(|e| format!("tls server conn: {e}"))?;
            let header = read_trojan_header(&mut rustls::Stream::new(&mut conn, &mut tcp))?;
            let target = parse_request(PASSWORD, &header).map_err(|e| format!("{e:?}"))?;
            let is_probe =
                target.host_label() == "credential-probe.nexus.invalid" && target.port() == 9;
            if !is_probe {
                break (tcp, conn, header);
            }
            probes_skipped += 1;
            if probes_skipped > 1 {
                return Err("more than one credential probe for a single flow".into());
            }
        };
        connected_clone.store(true, Ordering::SeqCst);
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let target = parse_request(PASSWORD, &header).map_err(|e| format!("{e:?}"))?;
        let target_ip: Ipv4Addr = target
            .host_label()
            .parse()
            .map_err(|_| format!("trojan target is not IPv4: {}", target.host_label()))?;
        let target_addr = SocketAddr::new(std::net::IpAddr::V4(target_ip), target.port());

        let mut upstream = TcpStream::connect(target_addr).map_err(|e| e.to_string())?;
        upstream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;

        // 引擎 → 隧道 → 目标。
        let mut payload = vec![0u8; PAYLOAD.len()];
        tls.read_exact(&mut payload)
            .map_err(|e| format!("payload read: {e}"))?;
        upstream
            .write_all(&payload)
            .map_err(|e| format!("target write: {e}"))?;

        // 目标 echo → 隧道 → 引擎。
        let mut back = vec![0u8; PAYLOAD.len()];
        upstream
            .read_exact(&mut back)
            .map_err(|e| format!("target read: {e}"))?;
        tls.write_all(&back)
            .map_err(|e| format!("tls write: {e}"))?;
        tls.flush().map_err(|e| format!("tls flush: {e}"))?;
        // 保持隧道存活一小段时间：若服务端立即关闭，引擎可能先处理 Closed 再泵下行，
        // 导致下行包被丢弃（本 example 要证明的是「TCP 真经隧道中继」）。
        std::thread::sleep(Duration::from_millis(400));

        Ok((target.host_label(), target.port()))
    });

    // --- 生产装配：Dataplane + 规则引擎 + ProxyEngine（trojan 出站） ---
    let proxy_yaml = format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: trojan-node\noutbounds:\n  - tag: trojan-node\n    kind: trojan\n    locator: {node_addr}\n    password: {PASSWORD}\n    skip_cert_verify: true\n    header_format: standard\n"
    );
    let mock = Arc::new(Mutex::new(MockTun::new("trojan-tls0")));
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".into()],
        proxy_configured: true,
        ..Default::default()
    };
    let mut dp = match Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None) {
        Ok(dp) => dp,
        Err(error) => return fail(format!("dataplane init: {error}")),
    };
    let rule_engine = match nexus_proxy::domain_engine::DomainRuleEngine::from_yaml(&proxy_yaml) {
        Ok(engine) => engine,
        Err(error) => return fail(format!("rule engine: {error}")),
    };
    let engine = match ProxyEngine::new(Some(&proxy_yaml)) {
        Ok(Some(engine)) => engine,
        Ok(None) => return fail("ProxyEngine::new returned None"),
        Err(error) => return fail(format!("engine init: {}", error.variant())),
    };
    let selected_tag = engine.registry().selected_tag().map(str::to_string);
    dp.set_proxy_engine(engine);
    dp.set_rule_engine(Box::new(rule_engine));

    let epoch = std::time::Instant::now();
    let now = || u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);

    let src = [10, 0, 0, 2];
    let dst = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return fail("echo server is not IPv4"),
    };
    let src_port = 41001u16;

    // SYN → SYN-ACK（引擎接管，不直连）。
    mock.lock().unwrap().inject(craft_tcp(
        src,
        dst,
        src_port,
        echo_addr.port(),
        1000,
        0,
        0x02,
        &[],
    ));
    if let Err(e) = dp.tick(now()) {
        return fail(format!("process syn: {e}"));
    }
    let written = mock.lock().unwrap().take_written();
    let srv_seq = match written.iter().find_map(|pkt| tcp_parts(pkt)) {
        Some((seq, _, flags, _)) if flags & 0x12 == 0x12 => seq,
        _ => return fail("no SYN-ACK from engine"),
    };

    // ACK → 完成握手（worker 在此之后 dial trojan TLS 节点）。
    mock.lock().unwrap().inject(craft_tcp(
        src,
        dst,
        src_port,
        echo_addr.port(),
        1001,
        srv_seq.wrapping_add(1),
        0x10,
        &[],
    ));
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

    // DATA → 之后零上行包，下行 echo 仍须到达（常态 poll）。
    mock.lock().unwrap().inject(craft_tcp(
        src,
        dst,
        src_port,
        echo_addr.port(),
        1001,
        srv_seq.wrapping_add(1),
        0x18,
        PAYLOAD,
    ));
    if let Err(e) = dp.tick(now()) {
        return fail(format!("process data: {e}"));
    }
    let mut down = Vec::new();
    let mut downlink_seen = false;
    for _ in 0..2000 {
        let _ = dp.tick(now());
        for pkt in mock.lock().unwrap().take_written() {
            if let Some((_, _, flags, data)) = tcp_parts(&pkt) {
                if flags & 0x04 != 0 {
                    continue;
                }
                down.extend_from_slice(data);
            }
        }
        if down.windows(PAYLOAD.len()).any(|w| w == PAYLOAD) {
            downlink_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let node_result = node_thread
        .join()
        .unwrap_or_else(|_| Err("node thread panicked".into()));
    let (target_host, target_port) = match node_result {
        Ok((host, port)) => (host, port),
        Err(_) => (String::new(), 0),
    };
    let target_delivered_ok = target_host == "127.0.0.1" && target_port == echo_addr.port();
    let node_connected = connected.load(Ordering::SeqCst);

    let stats = dp.stats();
    let proxy_stats = dp.proxy_stats().unwrap_or_default();
    let tcp_ok = dialed && downlink_seen && node_connected && target_delivered_ok;
    let verdict = tcp_ok && stats.proxy_tcp_bytes > 0 && proxy_stats.tcp_streams_ok > 0;

    json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "selected_tag": selected_tag,
        "outbound.kind": "trojan",
        "trojan_server.connected": node_connected,
        "trojan_server.target_delivered_ok": target_delivered_ok,
        "tcp.roundtrip_ok": tcp_ok,
        "tcp.downlink_bytes": down.len(),
        "stats.proxy_tcp_bytes": stats.proxy_tcp_bytes,
        "stats.proxy_forwarded": stats.proxy_forwarded,
        "stats.proxy_tcp_streams_ok": proxy_stats.tcp_streams_ok,
        "direct_forwarded": stats.direct_forwarded,
    })
}

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn name(&self) -> &str {
        "trojan-tls0"
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
}
