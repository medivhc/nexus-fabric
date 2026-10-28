//! E4: `tun_production_chain`（spec §12.1）— TUN 生产链闭环。
//!
//! 真实驱动：Direct UDP 真发送/回显、Direct TCP 真拨号/回程、
//! Proxy TCP 经本地 SOCKS5 真中继/回程、ICMP 丢弃计数、Proxy dial 失败注入。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus::n3_acceptance::sha256;
use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
use nexus_projection::{MockTun, TunDevice};
use nexus_proxy::domain_engine::DomainRuleEngine;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "mock0"
    }
}

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
    sum += ((src[0] as u32) << 8) | src[1] as u32;
    sum += ((src[2] as u32) << 8) | src[3] as u32;
    sum += ((dst[0] as u32) << 8) | dst[1] as u32;
    sum += ((dst[2] as u32) << 8) | dst[3] as u32;
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
    let mut pkt = vec![0u8; 20 + 20 + payload.len()];
    pkt[0] = 0x45;
    let tot = (20 + 20 + payload.len()) as u16;
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

fn craft_udp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    pkt[0] = 0x45;
    let tot = (20 + 8 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let c = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

fn parse_tcp_seq_ack(pkt: &[u8]) -> Option<(u32, u32, u8)> {
    if pkt.len() < 40 || pkt[9] != 6 {
        return None;
    }
    let seq = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
    let ack = u32::from_be_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]);
    Some((seq, ack, pkt[33]))
}

fn tcp_payload(pkt: &[u8]) -> &[u8] {
    if pkt.len() < 40 || pkt[9] != 6 {
        return &[];
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let doff = usize::from(pkt[ihl + 12] >> 4) * 4;
    let start = ihl + doff;
    if pkt.len() <= start {
        return &[];
    }
    &pkt[start..]
}

fn start_tcp_echo() -> u16 {
    let listener = TcpListener::bind(("0.0.0.0", 0)).expect("bind tcp echo");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

fn start_udp_echo() -> u16 {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).expect("bind udp echo");
    let port = sock.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, src)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], src);
        }
    });
    port
}

fn start_socks5() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind socks5");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || handle_socks5(stream));
        }
    });
    port
}

fn handle_socks5(mut s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut head = [0u8; 2];
    if s.read_exact(&mut head).is_err() {
        return;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    if s.read_exact(&mut methods).is_err() || s.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    let mut hdr = [0u8; 4];
    if s.read_exact(&mut hdr).is_err() || hdr[3] != 0x01 {
        return;
    }
    let mut addr = [0u8; 6];
    if s.read_exact(&mut addr).is_err() {
        return;
    }
    let target = SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
        u16::from_be_bytes([addr[4], addr[5]]),
    );
    let upstream = match TcpStream::connect_timeout(&target, Duration::from_secs(10)) {
        Ok(up) => up,
        Err(_) => {
            let _ = s.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };
    if s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .is_err()
    {
        return;
    }
    let mut s2 = s.try_clone().unwrap();
    let mut up2 = upstream.try_clone().unwrap();
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

fn yaml_for(socks_port: u16) -> String {
    format!(
        r#"schema_version: 1
rules:
  - tag: proxy-target
    kind: ip_cidr
    match: 127.0.0.2/32
    action:
      - kind: select_outbound
        tag: p1
  - tag: direct-target
    kind: ip_cidr
    match: 127.0.0.1/32
    action:
      - kind: select_outbound
        tag: direct
  - tag: match-all
    kind: match
    action:
      - kind: select_outbound
        tag: direct
groups: []
outbounds:
  - tag: direct
    kind: direct
    locator: ""
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:{socks_port}
"#
    )
}

fn make_dataplane(config: DataplaneConfig) -> (Dataplane, Arc<Mutex<MockTun>>) {
    let mock = Arc::new(Mutex::new(MockTun::new("mock0")));
    let dp =
        Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None).expect("dataplane");
    (dp, mock)
}

fn drive_proxy_tcp(
    dp: &mut Dataplane,
    mock: &Arc<Mutex<MockTun>>,
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let syn = craft_tcp(
        [10, 0, 0, 2],
        dst_ip,
        src_port,
        dst_port,
        1000,
        0,
        0x02,
        &[],
    );
    mock.lock().unwrap().inject(syn);
    dp.tick(now_ticks()).ok()?;
    let written = mock.lock().unwrap().take_written();
    let srv_seq = written
        .iter()
        .find_map(|p| parse_tcp_seq_ack(p).filter(|(_, _, flags)| flags & 0x12 == 0x12))
        .map(|(seq, _, _)| seq)?;
    let ack = craft_tcp(
        [10, 0, 0, 2],
        dst_ip,
        src_port,
        dst_port,
        1001,
        srv_seq + 1,
        0x10,
        &[],
    );
    mock.lock().unwrap().inject(ack.clone());
    dp.tick(now_ticks()).ok()?;
    let dial_before = dp.stats().proxy_forwarded;
    let deadline = Instant::now() + Duration::from_secs(5);
    while dp.stats().proxy_forwarded == dial_before && Instant::now() < deadline {
        mock.lock().unwrap().inject(ack.clone());
        dp.tick(now_ticks()).ok()?;
        std::thread::sleep(Duration::from_millis(5));
    }
    if dp.stats().proxy_forwarded == dial_before {
        return None;
    }
    let data = craft_tcp(
        [10, 0, 0, 2],
        dst_ip,
        src_port,
        dst_port,
        1001,
        srv_seq + 1,
        0x18,
        payload,
    );
    mock.lock().unwrap().inject(data);
    dp.tick(now_ticks()).ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        mock.lock().unwrap().inject(ack.clone());
        dp.tick(now_ticks()).ok()?;
        let written = mock.lock().unwrap().take_written();
        for pkt in written {
            let got = tcp_payload(&pkt);
            if got.len() == payload.len() {
                return Some(got.to_vec());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

fn drive_direct_tcp(
    dp: &mut Dataplane,
    mock: &Arc<Mutex<MockTun>>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let dst_ip = [127, 0, 0, 1];
    let syn = craft_tcp(
        [10, 0, 0, 2],
        dst_ip,
        src_port,
        dst_port,
        2000,
        0,
        0x02,
        &[],
    );
    mock.lock().unwrap().inject(syn);
    dp.tick(now_ticks()).ok()?;
    let written = mock.lock().unwrap().take_written();
    let srv_seq = written
        .iter()
        .find_map(|p| parse_tcp_seq_ack(p).filter(|(_, _, flags)| flags & 0x12 == 0x12))
        .map(|(seq, _, _)| seq)?;
    let ack = craft_tcp(
        [10, 0, 0, 2],
        dst_ip,
        src_port,
        dst_port,
        2001,
        srv_seq + 1,
        0x10,
        &[],
    );
    mock.lock().unwrap().inject(ack.clone());
    dp.tick(now_ticks()).ok()?;
    let data = craft_tcp(
        [10, 0, 0, 2],
        dst_ip,
        src_port,
        dst_port,
        2001,
        srv_seq + 1,
        0x18,
        payload,
    );
    mock.lock().unwrap().inject(data);
    dp.tick(now_ticks()).ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        mock.lock().unwrap().inject(ack.clone());
        dp.tick(now_ticks()).ok()?;
        let written = mock.lock().unwrap().take_written();
        for pkt in written {
            let got = tcp_payload(&pkt);
            if got.len() == payload.len() {
                return Some(got.to_vec());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }

    let tcp_port = start_tcp_echo();
    let udp_port = start_udp_echo();
    let socks_port = start_socks5();
    std::thread::sleep(Duration::from_millis(100));

    let yaml = yaml_for(socks_port);
    let explain_engine = DomainRuleEngine::from_yaml(&yaml).expect("rule engine");
    let proxy_probe = craft_tcp(
        [10, 0, 0, 2],
        [127, 0, 0, 2],
        40_020,
        tcp_port,
        1000,
        0,
        0x02,
        &[],
    );
    let req = RouteRequest {
        packet: &proxy_probe,
        domain: None,
        src_port: Some(40_020),
        dst_port: Some(tcp_port),
        process_name: None,
    };
    let (target, explanation) = explain_engine.explain(&req);
    let selected_outbound = match target {
        RouteTarget::Egress { ref peer } => peer.clone(),
        RouteTarget::MeshPeer { ref peer } => peer.clone(),
        RouteTarget::Drop => "drop".to_string(),
    };
    let matched_rule = explanation.map(|e| e.matched_rule).unwrap_or_default();
    let egress_hint = (selected_outbound != "self").then(|| selected_outbound.clone());

    let config = DataplaneConfig::default();
    let (mut dp, mock) = make_dataplane(config);
    dp.set_rule_engine(Box::new(
        DomainRuleEngine::from_yaml(&yaml).expect("dataplane rule engine"),
    ));
    dp.set_proxy_engine(
        ProxyEngine::new(Some(&yaml))
            .expect("proxy engine")
            .expect("engine constructed"),
    );

    for src_port in [40_001u16, 40_002] {
        let pkt = craft_udp(
            [10, 0, 0, 2],
            [127, 0, 0, 1],
            src_port,
            udp_port,
            b"chain-udp",
        );
        mock.lock().unwrap().inject(pkt);
        dp.tick(now_ticks()).expect("udp");
    }
    let mut udp_replies = 0usize;
    let deadline = Instant::now() + Duration::from_secs(2);
    while udp_replies < 2 && Instant::now() < deadline {
        udp_replies += dp.drain_direct_replies();
        std::thread::sleep(Duration::from_millis(5));
    }

    let icmp = {
        let mut pkt = craft_udp([10, 0, 0, 2], [127, 0, 0, 1], 40_003, 0, &[]);
        pkt[9] = 1;
        pkt
    };
    mock.lock().unwrap().inject(icmp);
    dp.tick(now_ticks()).expect("icmp");

    let direct_payload = b"direct-tcp-payload";
    let direct_reply = drive_direct_tcp(&mut dp, &mock, 40_010, tcp_port, direct_payload);

    let proxy_payload = b"proxy-tcp-payload";
    let proxy_reply = drive_proxy_tcp(
        &mut dp,
        &mock,
        40_020,
        [127, 0, 0, 2],
        tcp_port,
        proxy_payload,
    );

    let proxy_sent_sha = sha256(proxy_payload).as_str().to_string();
    let proxy_recv_sha = proxy_reply
        .as_deref()
        .map(|bytes| sha256(bytes).as_str().to_string())
        .unwrap_or_default();
    let proxy_sha_match = proxy_sent_sha == proxy_recv_sha;
    let direct_sha_match = direct_reply.as_deref() == Some(&direct_payload[..]);

    let cached_outbound = dp.cached_outbound(&proxy_probe);

    let fail_yaml = yaml_for(1);
    let (mut fail_dp, fail_mock) = make_dataplane(DataplaneConfig::default());
    fail_dp.set_rule_engine(Box::new(
        DomainRuleEngine::from_yaml(&fail_yaml).expect("failure rule engine"),
    ));
    fail_dp.set_proxy_engine(
        ProxyEngine::new(Some(&fail_yaml))
            .expect("failure proxy engine")
            .expect("engine constructed"),
    );
    let fail_syn = craft_tcp(
        [10, 0, 0, 2],
        [127, 0, 0, 2],
        40_030,
        tcp_port,
        3000,
        0,
        0x02,
        &[],
    );
    fail_mock.lock().unwrap().inject(fail_syn);
    fail_dp.tick(now_ticks()).expect("fail syn");
    let fail_written = fail_mock.lock().unwrap().take_written();
    let fail_srv_seq = fail_written
        .iter()
        .find_map(|p| parse_tcp_seq_ack(p).filter(|(_, _, flags)| flags & 0x12 == 0x12))
        .map(|(seq, _, _)| seq)
        .unwrap_or(0);
    let fail_ack = craft_tcp(
        [10, 0, 0, 2],
        [127, 0, 0, 2],
        40_030,
        tcp_port,
        3001,
        fail_srv_seq + 1,
        0x10,
        &[],
    );
    fail_mock.lock().unwrap().inject(fail_ack.clone());
    fail_dp.tick(now_ticks()).expect("fail ack");
    let deadline = Instant::now() + Duration::from_secs(3);
    while fail_dp.stats().upstream_failed == 0 && Instant::now() < deadline {
        fail_mock.lock().unwrap().inject(fail_ack.clone());
        fail_dp.tick(now_ticks()).expect("fail poll");
        std::thread::sleep(Duration::from_millis(5));
    }
    let failure_rst = fail_mock
        .lock()
        .unwrap()
        .take_written()
        .iter()
        .any(|p| p.len() >= 34 && p[33] & 0x04 != 0);

    let stats = dp.stats();
    let pass = matched_rule == "proxy-target"
        && selected_outbound == "p1"
        && egress_hint.as_deref() == Some("p1")
        && cached_outbound.as_deref() == Some("p1")
        && stats.direct_udp_sent >= 2
        && udp_replies >= 2
        && direct_reply.is_some()
        && direct_sha_match
        && direct_reply.as_deref() == Some(&direct_payload[..])
        && stats.direct_tcp_dial_ok >= 1
        && stats.proxy_tcp_streams >= 1
        && stats.proxy_forwarded >= 1
        && proxy_reply.is_some()
        && proxy_sha_match
        && stats.direct_dropped_unsupported >= 1
        && fail_dp.stats().upstream_failed >= 1;

    let out = serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "matched_rule": matched_rule,
        "selected_outbound": selected_outbound,
        "egress_hint": egress_hint,
        "dataplane_cached_outbound": cached_outbound,
        "direct_tcp_dial_ok": stats.direct_tcp_dial_ok,
        "direct_tcp_sha_match": direct_sha_match,
        "proxy_tcp_streams": stats.proxy_tcp_streams,
        "proxy_forwarded": stats.proxy_forwarded,
        "proxy_sent_sha256": proxy_sent_sha,
        "proxy_recv_sha256": proxy_recv_sha,
        "proxy_sha_match": proxy_sha_match,
        "direct_dropped_unsupported": stats.direct_dropped_unsupported,
        "upstream_failed": fail_dp.stats().upstream_failed,
        "failure_rst": failure_rst,
        "direct_udp_sent": stats.direct_udp_sent,
        "direct_replies": udp_replies,
    });
    println!("{out}");
    std::process::exit(if pass { 0 } else { 1 });
}

/// 单调毫秒时间源（example 内允许直接用 std；协议 core 不得取系统时间）。
fn now_ticks() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}
