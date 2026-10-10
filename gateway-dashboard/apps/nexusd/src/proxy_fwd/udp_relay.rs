//! UDP 转发：经代理协议转发 datagram（P2）。
//!
//! 设计：
//! - `UdpForwarder` 持有 per-protocol 中继会话（惰性初始化）；
//! - 出站：解析 IP/UDP 头 → 按协议封装 → 发送；
//! - 入站：后台线程收回包 → 解包 → 经 mpsc 发给 dataplane → 重构 IP 包写回 TUN；
//! - 流表 `(remote → (local, last_seen))`，60s 回收（P5）。
//!
//! 三种协议：
//! - SOCKS5：UDP ASSOCIATE（RFC 1928 §7）；
//! - ss：标准 AEAD UDP（`ss_std::SsUdp`）；
//! - trojan：TCP 上的 UDP（握手命令 0x03）。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use super::ss_std::SsUdp;
use super::{ProxyDialConfig, ProxyFwdStats};

/// UDP 流表回收超时（P5）。
const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(60);
/// UDP 流表上限（P5）。
const MAX_UDP_FLOWS: usize = 1024;

/// 入站 UDP 包（回包）→ dataplane。
/// `local` 由 dataplane 经 `lookup_local(remote)` 查流表得到，此处不携带。
#[derive(Debug)]
pub struct UdpInbound {
    /// 远端（回复方）。
    pub remote: SocketAddr,
    /// UDP 载荷。
    pub payload: Vec<u8>,
}

/// UDP 转发器（dataplane 线程拥有）。
pub struct UdpForwarder {
    dial_config: ProxyDialConfig,
    /// 惰性初始化的中继会话。
    relay: Option<UdpRelay>,
    inbound_rx: Receiver<UdpInbound>,
    inbound_tx: Sender<UdpInbound>,
    /// remote → (local, last_seen)。
    flows: HashMap<SocketAddr, (SocketAddr, Instant)>,
    stats: ProxyFwdStats,
}

/// 具体协议的中继会话。
enum UdpRelay {
    Socks5(Socks5UdpRelay),
    Ss(SsUdpRelay),
    Trojan(TrojanUdpRelay),
}

impl UdpForwarder {
    pub fn new(dial_config: ProxyDialConfig) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel();
        Self {
            dial_config,
            relay: None,
            inbound_rx,
            inbound_tx,
            flows: HashMap::new(),
            stats: ProxyFwdStats::default(),
        }
    }

    /// 处理一个 proxy 分类的 UDP 包（完整 IP 包）。
    /// 成功发送返回 true；失败返回 false（调用方计数）。
    pub fn handle_packet(&mut self, packet: &[u8]) -> bool {
        // 排空入站（实际写 TUN 由调用方通过 drain_inbound 完成）。
        self.reap();
        let (local, remote, payload) = match parse_udp_packet(packet) {
            Some(t) => t,
            None => return false,
        };
        // 确保中继已建立。
        if self.relay.is_none() {
            match self.establish() {
                Ok(r) => self.relay = Some(r),
                Err(e) => {
                    eprintln!("[proxy-fwd] udp relay establish failed: {e}");
                    return false;
                }
            }
        }
        let relay = match self.relay.as_mut() {
            Some(r) => r,
            None => return false,
        };
        let ok = match relay {
            UdpRelay::Socks5(r) => r.send(remote, &payload).is_ok(),
            UdpRelay::Ss(r) => r.send(remote, &payload).is_ok(),
            UdpRelay::Trojan(r) => r.send(remote, &payload).is_ok(),
        };
        if ok {
            // 记录流映射（last-write-wins）。
            if self.flows.len() >= MAX_UDP_FLOWS {
                //  evict 最旧的。
                if let Some((&k, _)) = self.flows.iter().min_by_key(|(_, (_, t))| *t) {
                    self.flows.remove(&k);
                }
            }
            self.flows.insert(remote, (local, Instant::now()));
            self.stats.udp_sent += 1;
            true
        } else {
            self.stats.udp_send_failed += 1;
            false
        }
    }

    /// 排空入站回包（调用方负责重构 IP 包写 TUN）。
    pub fn drain_inbound(&mut self) -> Vec<UdpInbound> {
        let mut out = Vec::new();
        while let Ok(pkt) = self.inbound_rx.try_recv() {
            // 更新流活跃时间。
            if let Some(entry) = self.flows.get_mut(&pkt.remote) {
                entry.1 = Instant::now();
            }
            out.push(pkt);
        }
        out
    }

    /// 查找回包对应的本地源。
    pub fn lookup_local(&self, remote: &SocketAddr) -> Option<SocketAddr> {
        self.flows.get(remote).map(|(local, _)| *local)
    }

    /// 回收超时流。
    fn reap(&mut self) {
        let now = Instant::now();
        self.flows
            .retain(|_, (_, t)| now.duration_since(*t) < UDP_FLOW_TIMEOUT);
    }

    /// 建立中继会话（惰性）。
    fn establish(&self) -> Result<UdpRelay, String> {
        let tx = self.inbound_tx.clone();
        match &self.dial_config {
            ProxyDialConfig::Socks5 { server } => Socks5UdpRelay::establish(*server, tx)
                .map(UdpRelay::Socks5)
                .map_err(|e| e.to_string()),
            ProxyDialConfig::Shadowsocks {
                server, password, ..
            } => SsUdpRelay::establish(*server, password.clone(), tx)
                .map(UdpRelay::Ss)
                .map_err(|e| e.to_string()),
            ProxyDialConfig::Trojan { server, password } => {
                TrojanUdpRelay::establish(*server, password.clone(), false, tx)
                    .map(UdpRelay::Trojan)
                    .map_err(|e| e.to_string())
            }
            ProxyDialConfig::TrojanTls {
                server: _,
                password: _,
                sni: _,
                skip_verify: _,
            } => {
                // trojan-tls 的 UDP：本期经明文 trojan UDP 逻辑走 TLS 流。
                // 诚实：P2 只实现明文 trojan UDP；TLS 变体返回错误走降级。
                Err("trojan-tls udp not in P2 scope (use plaintext trojan)".to_string())
            }
        }
    }

    pub fn stats(&self) -> ProxyFwdStats {
        self.stats.clone()
    }
}

/// 解析 IP/UDP 包；返回 (local_src, remote_dst, udp_payload)。
fn parse_udp_packet(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 8 {
        return None;
    }
    if packet[9] != 17 {
        // 非 UDP。
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp_off = ihl;
    let src_port = u16::from_be_bytes([packet[udp_off], packet[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([packet[udp_off + 2], packet[udp_off + 3]]);
    let udp_len = u16::from_be_bytes([packet[udp_off + 4], packet[udp_off + 5]]) as usize;
    if udp_len < 8 || packet.len() < udp_off + udp_len {
        return None;
    }
    let payload = packet[udp_off + 8..udp_off + udp_len].to_vec();
    let local = SocketAddr::new(IpAddr::V4(src_ip), src_port);
    let remote = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
    Some((local, remote, payload))
}

/// 重构回包的 IP/UDP 包（src/dst 互换）。
pub fn build_udp_reply(local: SocketAddr, remote: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let (local_ip, local_port) = match local {
        SocketAddr::V4(sa) => (*sa.ip(), sa.port()),
        _ => return None,
    };
    let (remote_ip, remote_port) = match remote {
        SocketAddr::V4(sa) => (*sa.ip(), sa.port()),
        _ => return None,
    };
    // IP 头（20B，无选项）。
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // version + IHL
    pkt[1] = 0x00; // DSCP
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&[0x00, 0x00]); // ID
    pkt[6..8].copy_from_slice(&[0x40, 0x00]); // flags + frag
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    // checksum 暂 0（本期由内核/对端宽容；诚实：TUN 写回通常不校验）。
    pkt[12..16].copy_from_slice(&remote_ip.octets());
    pkt[16..20].copy_from_slice(&local_ip.octets());
    // UDP 头。
    pkt[20..22].copy_from_slice(&remote_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&local_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[26..28].copy_from_slice(&[0x00, 0x00]); // UDP checksum 0（可选）
    pkt[28..].copy_from_slice(payload);
    // IP checksum。
    let csum = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    Some(pkt)
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

// ---------------------------------------------------------------------------
// SOCKS5 UDP ASSOCIATE
// ---------------------------------------------------------------------------

struct Socks5UdpRelay {
    udp: UdpSocket,
    relay_addr: SocketAddr,
}

impl Socks5UdpRelay {
    fn establish(server: SocketAddr, tx: Sender<UdpInbound>) -> io::Result<Self> {
        // 1. TCP 控制连接 + UDP ASSOCIATE。
        let mut tcp = TcpStream::connect_timeout(&server, Duration::from_secs(10))?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
        // 握手：NO-AUTH。
        tcp.write_all(&[0x05, 0x01, 0x00])?;
        let mut choice = [0u8; 2];
        tcp.read_exact(&mut choice)?;
        if choice != [0x05, 0x00] {
            return Err(io::Error::other("socks5: no acceptable auth"));
        }
        // UDP ASSOCIATE：ATYP=IPv4, ADDR=0.0.0.0, PORT=0。
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        let mut reply = [0u8; 10];
        tcp.read_exact(&mut reply)?;
        if reply[1] != 0x00 {
            return Err(io::Error::other(format!(
                "socks5: UDP ASSOCIATE rejected ({})",
                reply[1]
            )));
        }
        let relay_ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let relay_addr = SocketAddr::new(IpAddr::V4(relay_ip), relay_port);

        // 2. UDP socket（绑定本地任意端口）。
        let udp = UdpSocket::bind("0.0.0.0:0")?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        let udp2 = udp.try_clone()?;

        // 3. 后台接收线程（持有 TCP 控制连接保活）。
        std::thread::spawn(move || {
            let _tcp_keepalive = tcp; // 保持 ASSOCIATE 有效。
            let mut buf = [0u8; 65535];
            loop {
                match udp2.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        if let Some((src, payload)) = parse_socks5_udp(&buf[..n]) {
                            let _ = tx.send(UdpInbound {
                                remote: src,
                                payload,
                            });
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { udp, relay_addr })
    }

    fn send(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let mut pkt = vec![0x00, 0x00, 0x00]; // RSV + FRAG
        pkt.extend(encode_socks5_addr(target));
        pkt.extend_from_slice(payload);
        self.udp.send_to(&pkt, self.relay_addr)?;
        Ok(())
    }
}

/// SOCKS5 地址编码（IPv4）。
fn encode_socks5_addr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// 解析 SOCKS5 UDP 包；返回 (源地址, 载荷)。
fn parse_socks5_udp(buf: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    if buf.len() < 10 || buf[2] != 0x00 {
        return None; // FRAG != 0 不支持。
    }
    let atyp = buf[3];
    let (addr, off) = match atyp {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (SocketAddr::new(ip, port), 10)
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = IpAddr::V6(octets.into());
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (SocketAddr::new(ip, port), 22)
        }
        _ => return None,
    };
    Some((addr, buf[off..].to_vec()))
}

// ---------------------------------------------------------------------------
// 标准 ss UDP
// ---------------------------------------------------------------------------

struct SsUdpRelay {
    udp: UdpSocket,
    server: SocketAddr,
    password: String,
}

impl SsUdpRelay {
    fn establish(server: SocketAddr, password: String, tx: Sender<UdpInbound>) -> io::Result<Self> {
        let udp = UdpSocket::bind("0.0.0.0:0")?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        let udp2 = udp.try_clone()?;
        let pw2 = password.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            loop {
                match udp2.recv_from(&mut buf) {
                    Ok((n, _)) => match SsUdp::open_packet(&pw2, &buf[..n]) {
                        Ok((src, payload)) => {
                            let _ = tx.send(UdpInbound {
                                remote: src,
                                payload,
                            });
                        }
                        Err(_) => continue,
                    },
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            udp,
            server,
            password,
        })
    }

    fn send(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let pkt = SsUdp::seal_packet(&self.password, target, payload)?;
        self.udp.send_to(&pkt, self.server)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trojan UDP（TCP 上的 UDP，命令 0x03）
// ---------------------------------------------------------------------------

struct TrojanUdpRelay {
    /// 写锁（读由后台线程独占）。
    writer: std::sync::Mutex<TcpStream>,
}

impl TrojanUdpRelay {
    fn establish(
        server: SocketAddr,
        password: String,
        _tls: bool,
        tx: Sender<UdpInbound>,
    ) -> io::Result<Self> {
        let mut tcp = TcpStream::connect_timeout(&server, Duration::from_secs(10))?;
        tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))?;

        // trojan 握手（UDP 命令 0x03；复用 nexus-outbound-trojan 的 auth_hash）。
        let hash = nexus_outbound_trojan::auth_hash(&password);
        // 用 0.0.0.0:0 占位（UDP 模式地址在每包中携带）。
        let mut req = Vec::new();
        req.extend_from_slice(hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(0x03); // CMD = UDP ASSOCIATE
        req.push(0x01); // ATYP = IPv4
        req.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // 0.0.0.0:0
        req.extend_from_slice(b"\r\n");
        tcp.write_all(&req)?;
        tcp.flush()?;
        tcp.set_read_timeout(Some(Duration::from_millis(100)))?;

        let mut reader = tcp.try_clone()?;
        std::thread::spawn(move || {
            loop {
                match read_trojan_udp(&mut reader) {
                    Ok(Some((src, payload))) => {
                        let _ = tx.send(UdpInbound {
                            remote: src,
                            payload,
                        });
                    }
                    Ok(None) => break,  // EOF
                    Err(_) => continue, // 超时/分片，继续。
                }
            }
        });

        Ok(Self {
            writer: std::sync::Mutex::new(tcp),
        })
    }

    fn send(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        // trojan UDP 包：ATYP ADDR PORT LEN(2B) PAYLOAD CRLF。
        let mut pkt = encode_socks5_addr(target); // ATYP 格式与 trojan 兼容（IPv4）。
        pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt.extend_from_slice(b"\r\n");
        let mut w = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("trojan udp writer poisoned"))?;
        w.write_all(&pkt)?;
        w.flush()?;
        Ok(())
    }
}

/// 从 trojan TCP 流读一个 UDP 包；返回 (源地址, 载荷)。
/// Ok(None) = EOF；Err = 超时/可恢复（调用方继续）。
fn read_trojan_udp(reader: &mut TcpStream) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
    // 读 ATYP。
    let mut atyp = [0u8; 1];
    match reader.read_exact(&mut atyp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let (addr, addr_len) = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 6];
            reader.read_exact(&mut b)?;
            let ip = IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            let port = u16::from_be_bytes([b[4], b[5]]);
            (SocketAddr::new(ip, port), 7)
        }
        0x04 => {
            let mut b = [0u8; 18];
            reader.read_exact(&mut b)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            let ip = IpAddr::V6(octets.into());
            let port = u16::from_be_bytes([b[16], b[17]]);
            (SocketAddr::new(ip, port), 19)
        }
        _ => {
            return Err(io::Error::other("trojan udp: bad atyp"));
        }
    };
    let _ = addr_len;
    let mut len_b = [0u8; 2];
    reader.read_exact(&mut len_b)?;
    let len = u16::from_be_bytes(len_b) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf)?;
    Ok(Some((addr, payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_parse_and_build() {
        // 构造一个 UDP 包：20B IP + 8B UDP + payload。
        let payload = b"hello udp";
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);

        let (local, remote, data) = parse_udp_packet(&pkt).unwrap();
        assert_eq!(local.port(), 12345);
        assert_eq!(remote.port(), 53);
        assert_eq!(data, payload);

        // 回包重构。
        let reply = build_udp_reply(local, remote, b"reply").unwrap();
        let (l2, r2, d2) = parse_udp_packet(&reply).unwrap();
        assert_eq!(l2, remote); // src/dst 互换。
        assert_eq!(r2, local);
        assert_eq!(d2, b"reply");
    }

    #[test]
    fn socks5_udp_codec() {
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let payload = b"data";
        let mut pkt = vec![0x00, 0x00, 0x00];
        pkt.extend(encode_socks5_addr(addr));
        pkt.extend_from_slice(payload);
        let (a, p) = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(a, addr);
        assert_eq!(p, payload);
    }
}
