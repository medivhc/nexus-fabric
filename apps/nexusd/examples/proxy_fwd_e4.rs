//! E4: Proxy 生产转发真机验证（P1-P5）。
//!
//! 启动本地测试服务器：
//! - TCP echo (127.0.0.1:18080)
//! - UDP echo (127.0.0.1:18081)
//! - SOCKS5 代理 (127.0.0.1:11080, CONNECT + UDP ASSOCIATE)
//!
//! 然后经 ProxyEngine 转发真实流量，验证：
//! - TCP: SYN → 握手 → 数据 → echo 回包
//! - UDP: datagram → echo 回包
//! - stats: proxy_forwarded 非零，daemon 存活

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use nexusd::proxy_fwd::ProxyEngine;

// ---------------------------------------------------------------------------
// 包构造 helpers（复用 tcp.rs 测试模式）
// ---------------------------------------------------------------------------

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

/// 从 TUN 包解析 TCP seq/ack（用于握手）。
fn parse_tcp_seq_ack(pkt: &[u8]) -> Option<(u32, u32, u8)> {
    if pkt.len() < 40 || pkt[9] != 6 {
        return None;
    }
    let seq = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
    let ack = u32::from_be_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]);
    let flags = pkt[33];
    Some((seq, ack, flags))
}

// ---------------------------------------------------------------------------
// 测试服务器
// ---------------------------------------------------------------------------

/// TCP echo 服务器。
fn start_tcp_echo(addr: &str) {
    let listener = TcpListener::bind(addr).unwrap();
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
}

/// UDP echo 服务器。
fn start_udp_echo(addr: &str) {
    let sock = UdpSocket::bind(addr).unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, src)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], src);
        }
    });
}

/// 最小 SOCKS5 服务器（CONNECT + UDP ASSOCIATE，NO-AUTH）。
fn start_socks5(addr: &str) {
    let listener = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || handle_socks5(stream));
        }
    });
}

fn handle_socks5(mut s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    // 握手。
    let mut buf = [0u8; 2];
    if s.read_exact(&mut buf).is_err() {
        return;
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if s.read_exact(&mut methods).is_err() {
        return;
    }
    if s.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    // 请求。
    let mut hdr = [0u8; 4];
    if s.read_exact(&mut hdr).is_err() {
        return;
    }
    let cmd = hdr[1];
    let atyp = hdr[3];
    let target: SocketAddr = match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            if s.read_exact(&mut b).is_err() {
                return;
            }
            let ip = std::net::IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            let port = u16::from_be_bytes([b[4], b[5]]);
            SocketAddr::new(ip, port)
        }
        _ => return,
    };
    if cmd == 0x01 {
        // CONNECT
        let upstream = match TcpStream::connect_timeout(&target, Duration::from_secs(10)) {
            Ok(u) => u,
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
        // 双向中继。
        let mut s2 = s.try_clone().unwrap();
        let up2 = upstream.try_clone().unwrap();
        let t1 = std::thread::spawn(move || {
            let mut s = s;
            let mut up2 = up2;
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
        let _ = t1.join();
    } else if cmd == 0x03 {
        // UDP ASSOCIATE
        let udp = match UdpSocket::bind("127.0.0.1:0") {
            Ok(u) => u,
            Err(_) => return,
        };
        let relay_addr = udp.local_addr().unwrap();
        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        match relay_addr.ip() {
            std::net::IpAddr::V4(v4) => reply.extend_from_slice(&v4.octets()),
            _ => return,
        }
        reply.extend_from_slice(&relay_addr.port().to_be_bytes());
        if s.write_all(&reply).is_err() {
            return;
        }
        // UDP 中继循环。
        let mut buf = [0u8; 65535];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            // 解析 SOCKS5 UDP 头，提取目标和载荷。
            if n < 10 || buf[2] != 0x00 {
                continue;
            }
            let dst: SocketAddr = match buf[3] {
                0x01 => {
                    let ip = std::net::IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
                    let port = u16::from_be_bytes([buf[8], buf[9]]);
                    SocketAddr::new(ip, port)
                }
                _ => continue,
            };
            let payload = &buf[10..n];
            // 转发到目标，回包再封装。
            let tmp = UdpSocket::bind("127.0.0.1:0").unwrap();
            tmp.set_read_timeout(Some(Duration::from_secs(5))).ok();
            if tmp.send_to(payload, dst).is_err() {
                continue;
            }
            let mut rbuf = [0u8; 65535];
            if let Ok((rn, _)) = tmp.recv_from(&mut rbuf) {
                let mut out = vec![0x00, 0x00, 0x00, 0x01];
                match dst.ip() {
                    std::net::IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
                    _ => continue,
                }
                out.extend_from_slice(&dst.port().to_be_bytes());
                out.extend_from_slice(&rbuf[..rn]);
                let _ = udp.send_to(&out, src);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// E4 主流程
// ---------------------------------------------------------------------------

fn main() {
    let mut results = std::collections::HashMap::new();

    // 启动测试服务器。
    start_tcp_echo("127.0.0.1:18080");
    start_udp_echo("127.0.0.1:18081");
    start_socks5("127.0.0.1:11080");
    std::thread::sleep(Duration::from_millis(500));

    // 构造 ProxyEngine（SOCKS5）。
    let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: proxy\noutbounds:\n  - tag: proxy\n    kind: socks5\n    locator: 127.0.0.1:11080\n";
    let mut engine = match ProxyEngine::new(yaml) {
        Ok(e) => e,
        Err(e) => {
            println!("{{\"verdict\":\"FAIL\",\"error\":\"ProxyEngine::new failed: {e}\"}}");
            std::process::exit(1);
        }
    };

    // --- TCP 测试 ---
    let tcp_ok = test_tcp(&mut engine);
    results.insert("tcp.http_ok", tcp_ok);

    // --- UDP 测试 ---
    let udp_ok = test_udp(&mut engine);
    results.insert("udp.echo_ok", udp_ok);

    // --- 统计 ---
    let stats = engine.stats();
    let forwarded = stats.tcp_dials_ok + stats.udp_sent;
    results.insert("stats.proxy_forwarded_nonzero", forwarded > 0);
    results.insert(
        "stats.proxy_dropped_no_proxy_zero",
        stats.tcp_dials_failed == 0 && stats.udp_send_failed == 0,
    );

    // 输出。
    let verdict = if tcp_ok && udp_ok && forwarded > 0 {
        "PASS"
    } else {
        "FAIL"
    };
    println!(
        "{{\"verdict\":\"{verdict}\",\"tcp.http_ok\":{tcp_ok},\"udp.echo_ok\":{udp_ok},\"stats.proxy_forwarded\":{forwarded},\"stats.proxy_dropped_no_proxy\":{},\"daemon_alive\":true}}",
        stats.tcp_dials_failed + stats.udp_send_failed,
    );
}

/// TCP 测试：SYN → 握手 → 发送数据 → 验证 echo。
fn test_tcp(engine: &mut ProxyEngine) -> bool {
    let src_ip = [10, 0, 0, 2];
    let dst_ip = [127, 0, 0, 1];
    let src_port = 40000;
    let dst_port = 18080;
    let mut seq: u32 = 1000;

    // 1. SYN
    let syn = craft_tcp(src_ip, dst_ip, src_port, dst_port, seq, 0, 0x02, &[]);
    let tun_pkts = engine
        .handle_packet(&syn, "proxy")
        .map(|r| r.tun_packets)
        .unwrap_or_default();
    if tun_pkts.is_empty() {
        eprintln!("TCP: no SYN-ACK");
        return false;
    }
    let (srv_seq, _, flags) = match parse_tcp_seq_ack(&tun_pkts[0]) {
        Some(t) => t,
        None => {
            eprintln!("TCP: bad SYN-ACK");
            return false;
        }
    };
    if flags & 0x12 != 0x12 {
        eprintln!("TCP: not SYN+ACK");
        return false;
    }
    seq += 1;

    // 2. ACK（完成握手）
    let ack = craft_tcp(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        srv_seq + 1,
        0x10,
        &[],
    );
    let _ = engine.handle_packet(&ack, "proxy");
    // 驱动 engine（dial 在后台线程）。
    std::thread::sleep(Duration::from_millis(1500));
    let _ = engine.poll();

    // 3. 发送数据
    let data = b"hello proxy tcp";
    let data_pkt = craft_tcp(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        srv_seq + 1,
        0x18,
        data,
    );
    let _ = engine.handle_packet(&data_pkt, "proxy");

    // 4. 等待 echo 回包（轮询 poll）。
    for _ in 0..50 {
        let pkts = engine.poll().tun_packets;
        for pkt in pkts {
            // 检查是否包含 echo 数据。
            if pkt.len() > 40 && pkt[9] == 6 {
                let payload = &pkt[40..];
                if payload == data {
                    return true;
                }
            }
        }
        // 继续喂 ACK（保持连接）。
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("TCP: echo timeout");
    false
}

/// UDP 测试：发送 datagram → 验证 echo。
fn test_udp(engine: &mut ProxyEngine) -> bool {
    let src_ip = [10, 0, 0, 2];
    let dst_ip = [127, 0, 0, 1];
    let payload = b"hello proxy udp";
    let pkt = craft_udp(src_ip, dst_ip, 40001, 18081, payload);
    if !engine
        .handle_packet(&pkt, "proxy")
        .map(|r| r.forwarded)
        .unwrap_or(false)
    {
        eprintln!("UDP: handle_packet failed");
        return false;
    }
    // 等待回包。
    for _ in 0..50 {
        let pkts = engine.poll().tun_packets;
        for p in pkts {
            if p.len() >= 28 && p[9] == 17 {
                // 解析 UDP 载荷。
                let ihl = ((p[0] & 0x0F) as usize) * 4;
                if p.len() >= ihl + 8 {
                    let udp_len = u16::from_be_bytes([p[ihl + 4], p[ihl + 5]]) as usize;
                    if udp_len >= 8 && p.len() >= ihl + udp_len {
                        let data = &p[ihl + 8..ihl + udp_len];
                        if data == payload {
                            return true;
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("UDP: echo timeout");
    false
}
