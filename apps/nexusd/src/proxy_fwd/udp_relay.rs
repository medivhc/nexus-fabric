//! UDP 转发：经代理协议转发 datagram（P2）。
//!
//! 设计：
//! - `UdpForwarder` 持有 per-protocol 中继会话（惰性初始化）；
//! - 出站：解析 IP/UDP 头 → 按 `dialer.udp_capability()` 分派 → 发送；
//! - 入站：后台线程收回包 → 解包 → 经 mpsc 发给 dataplane → 重构 IP 包写回 TUN；
//! - 数据报中继的流表 `(remote → (local, last_seen))`，60s 回收（P5）。
//!
//! 分派：
//! - SOCKS5：UDP ASSOCIATE（RFC 1928 §7）；
//! - ss：AEAD UDP（`ss_std::SsUdp`；派生非 SIP004，见步骤 1.5 证据
//!   `.evidence/outbound-adapter-wiring/ss-std-sip004/`）；
//! - VLESS / AnyTLS：每个（本地源，目的地址）一条代理流（`udp_stream::StreamTable`，
//!   PRODUCT §11.18.1），回包按流键回到本地源；
//! - Trojan：不建 relay，统一 `Unsupported { TlsVariantNotSupported }`（§3.5）。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use nexus_proxy_config::OutboundKind;

use super::ProxyFwdStats;
use super::adapter::{OutboundDialer, UdpCapability, UdpMode, UdpUnsupportedReason};
use super::udp_stream::StreamTable;
pub use super::udp_stream::UdpReply;
// TODO(deletion-gate: fixes-6): SS UDP 仍走 `ss_std::SsUdp`（crate 无标准 UDP
// 包 API，spec §3.3 / §4.5）。删除触发条件 = fixes-6 或 crate 提供标准 UDP API，
// 且同一 PR 内把 `UdpMode::ShadowsocksAead` 切换到 crate 实现。
use super::ss_std::SsUdp;

/// UDP 流表回收超时（P5）。
const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(60);
/// UDP 流表上限（P5）。
const MAX_UDP_FLOWS: usize = 1024;
/// UDP 未接线的限频日志间隔（spec §2.2）。
const UDP_UNSUPPORTED_LOG_INTERVAL: Duration = Duration::from_secs(10);

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
    dialer: Arc<dyn OutboundDialer>,
    /// 选中出站的 kind/tag（仅日志用；spec §6.5）。
    kind: OutboundKind,
    tag: String,
    /// 惰性初始化的中继会话（SOCKS5 / SS）。
    relay: Option<UdpRelay>,
    /// 惰性初始化的代理流表（VLESS / AnyTLS）。
    streams: Option<StreamTable>,
    inbound_rx: Receiver<UdpInbound>,
    inbound_tx: Sender<UdpInbound>,
    /// remote → (local, last_seen)。
    flows: HashMap<SocketAddr, (SocketAddr, Instant)>,
    stats: ProxyFwdStats,
    /// 上一次实际输出的 udp_unsupported 日志时间（限频用）。
    last_unsupported_log: Option<Instant>,
}

/// 具体协议的中继会话。
enum UdpRelay {
    Socks5(Socks5UdpRelay),
    Ss(SsUdpRelay),
}

impl UdpForwarder {
    pub fn new(dialer: Arc<dyn OutboundDialer>) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel();
        let kind = dialer.kind();
        let tag = dialer.tag().to_string();
        Self {
            dialer,
            kind,
            tag,
            relay: None,
            streams: None,
            inbound_rx,
            inbound_tx,
            flows: HashMap::new(),
            stats: ProxyFwdStats::default(),
            last_unsupported_log: None,
        }
    }

    /// 处理一个 proxy 分类的 UDP 包（完整 IP 包）。
    /// 写出或进入代理流队列返回 true；在本次调用内被丢弃返回 false。
    pub fn handle_packet(&mut self, packet: &[u8]) -> bool {
        self.handle_packet_at(packet, Instant::now())
    }

    fn handle_packet_at(&mut self, packet: &[u8], now: Instant) -> bool {
        // 排空入站（实际写 TUN 由调用方通过 drain_replies 完成）。
        self.reap();
        let (local, remote, payload) = match parse_udp_packet(packet) {
            Some(t) => t,
            None => return false,
        };
        if let Some(streams) = self.streams.as_mut() {
            return streams.send(local, remote, payload, now, &mut self.stats);
        }
        // 确保中继已建立。
        if self.relay.is_none() {
            match self.dialer.udp_capability() {
                UdpCapability::Supported(
                    UdpMode::VlessOverTcp { .. } | UdpMode::AnytlsUot { .. },
                ) => {
                    let streams = self
                        .streams
                        .insert(StreamTable::new(Arc::clone(&self.dialer)));
                    return streams.send(local, remote, payload, now, &mut self.stats);
                }
                UdpCapability::Supported(mode) => match self.establish(mode) {
                    Ok(r) => self.relay = Some(r),
                    Err(e) => {
                        eprintln!("[proxy-fwd] udp relay establish failed: {e}");
                        return false;
                    }
                },
                UdpCapability::Unsupported { reason } => {
                    // §2.6.2：该 UDP 包丢弃；udp_send_failed + udp_unsupported；
                    // 限频日志；绝不直连。
                    self.record_unsupported(reason);
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

    /// 排空回包（调用方负责重构 IP 包写 TUN / 交给 TPROXY 前端），并驱动代理流的
    /// 事件、空闲回收与 worker 回收（每个 dataplane / egress 周期调用）。
    pub fn drain_replies(&mut self) -> Vec<UdpReply> {
        self.drain_replies_at(Instant::now())
    }

    fn drain_replies_at(&mut self, now: Instant) -> Vec<UdpReply> {
        let mut replies: Vec<UdpReply> = self
            .drain_inbound()
            .into_iter()
            .filter_map(|inbound| {
                self.lookup_local(&inbound.remote).map(|local| UdpReply {
                    local,
                    remote: inbound.remote,
                    payload: inbound.payload,
                })
            })
            .collect();
        if let Some(streams) = self.streams.as_mut() {
            replies.extend(streams.poll(now, &mut self.stats));
        }
        replies
    }

    /// 排空数据报中继的入站回包。
    fn drain_inbound(&mut self) -> Vec<UdpInbound> {
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

    /// 查找数据报中继回包对应的本地源。
    fn lookup_local(&self, remote: &SocketAddr) -> Option<SocketAddr> {
        self.flows.get(remote).map(|(local, _)| *local)
    }

    /// 回收超时流。
    fn reap(&mut self) {
        let now = Instant::now();
        self.flows
            .retain(|_, (_, t)| now.duration_since(*t) < UDP_FLOW_TIMEOUT);
    }

    /// 建立中继会话（惰性）。UDP 实现不变，只按能力声明分派。
    fn establish(&self, mode: UdpMode) -> Result<UdpRelay, String> {
        let tx = self.inbound_tx.clone();
        match mode {
            UdpMode::Socks5Associate { server } => Socks5UdpRelay::establish(server, tx)
                .map(UdpRelay::Socks5)
                .map_err(|e| e.to_string()),
            UdpMode::ShadowsocksAead { server, password } => {
                SsUdpRelay::establish(server, password, tx)
                    .map(UdpRelay::Ss)
                    .map_err(|e| e.to_string())
            }
            other => Err(format!("udp mode not wired: {other:?}")),
        }
    }

    /// `UdpCapability::Unsupported`：计数 + 限频日志（spec §2.6.2 / §6.4）。
    fn record_unsupported(&mut self, reason: UdpUnsupportedReason) {
        self.stats.udp_unsupported += 1;
        self.stats.udp_send_failed += 1;
        match self.kind {
            OutboundKind::Vless => self.stats.udp_unsupported_vless += 1,
            OutboundKind::Anytls => self.stats.udp_unsupported_anytls += 1,
            _ => self.stats.udp_unsupported_other += 1,
        }
        let now = Instant::now();
        let due = self
            .last_unsupported_log
            .is_none_or(|last| now.duration_since(last) >= UDP_UNSUPPORTED_LOG_INTERVAL);
        if due {
            let suppressed = self.stats.udp_unsupported_log_suppressed;
            eprintln!(
                "[proxy-fwd] event=udp_unsupported kind={} tag={} reason={} suppressed={suppressed}",
                self.kind.as_str(),
                self.tag,
                unsupported_reason_str(reason)
            );
            self.last_unsupported_log = Some(now);
            self.stats.udp_unsupported_log_suppressed = 0;
        } else {
            self.stats.udp_unsupported_log_suppressed += 1;
        }
    }

    pub fn stats(&self) -> ProxyFwdStats {
        self.stats.clone()
    }
}

fn unsupported_reason_str(reason: UdpUnsupportedReason) -> &'static str {
    match reason {
        UdpUnsupportedReason::NotWired => "not_wired",
        UdpUnsupportedReason::TlsVariantNotSupported => "tls_variant_not_supported",
        UdpUnsupportedReason::NoDatagramMode => "no_datagram_mode",
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
// 标准 ss UDP（ss_std 保留面；TODO(deletion-gate: fixes-6) 见文件头 use 处）
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

#[cfg(test)]
mod tests {
    use super::super::adapter::{OutboundError, TunnelStream};
    use super::*;

    struct TrojanUnsupportedDialer;

    impl OutboundDialer for TrojanUnsupportedDialer {
        fn kind(&self) -> OutboundKind {
            OutboundKind::Trojan
        }

        fn tag(&self) -> &str {
            "trojan-a"
        }

        fn dial_tcp(&self, _target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
            Err(OutboundError::UdpUnsupported)
        }

        fn udp_capability(&self) -> UdpCapability {
            UdpCapability::Unsupported {
                reason: UdpUnsupportedReason::TlsVariantNotSupported,
            }
        }
    }

    fn udp_packet(payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn trojan_udp_is_unsupported_and_rate_limited() {
        let mut forwarder = UdpForwarder::new(Arc::new(TrojanUnsupportedDialer));
        let packet = udp_packet(b"dns-ish");
        assert!(!forwarder.handle_packet(&packet));
        assert!(!forwarder.handle_packet(&packet));
        let stats = forwarder.stats();
        assert_eq!(stats.udp_unsupported, 2);
        assert_eq!(stats.udp_send_failed, 2);
        assert_eq!(stats.udp_unsupported_other, 2);
        assert_eq!(stats.udp_unsupported_vless, 0);
        assert_eq!(stats.udp_unsupported_anytls, 0);
        assert_eq!(stats.udp_sent, 0);
        // 首条必打；第二条在 10s 窗口内被抑制。
        assert_eq!(stats.udp_unsupported_log_suppressed, 1);
    }

    #[test]
    fn not_wired_udp_capability_fails_closed_with_per_protocol_counters() {
        struct NotWiredDialer {
            kind: OutboundKind,
            tag: &'static str,
        }

        impl OutboundDialer for NotWiredDialer {
            fn kind(&self) -> OutboundKind {
                self.kind
            }

            fn tag(&self) -> &str {
                self.tag
            }

            fn dial_tcp(
                &self,
                _target: SocketAddr,
            ) -> Result<Box<dyn TunnelStream>, OutboundError> {
                Err(OutboundError::UdpUnsupported)
            }

            fn udp_capability(&self) -> UdpCapability {
                UdpCapability::Unsupported {
                    reason: UdpUnsupportedReason::NotWired,
                }
            }
        }

        for (kind, tag) in [
            (OutboundKind::Vless, "vless-a"),
            (OutboundKind::Anytls, "anytls-a"),
        ] {
            let mut forwarder = UdpForwarder::new(Arc::new(NotWiredDialer { kind, tag }));
            let packet = udp_packet(b"business-udp");
            assert!(!forwarder.handle_packet(&packet));
            assert!(!forwarder.handle_packet(&packet));
            let stats = forwarder.stats();
            assert_eq!(stats.udp_unsupported, 2, "{tag}");
            assert_eq!(stats.udp_send_failed, 2, "{tag}");
            assert_eq!(stats.udp_sent, 0, "{tag}");
            match kind {
                OutboundKind::Vless => {
                    assert_eq!(stats.udp_unsupported_vless, 2);
                    assert_eq!(stats.udp_unsupported_anytls, 0);
                }
                OutboundKind::Anytls => {
                    assert_eq!(stats.udp_unsupported_anytls, 2);
                    assert_eq!(stats.udp_unsupported_vless, 0);
                }
                other => panic!("unexpected kind {other:?}"),
            }
            assert_eq!(stats.udp_unsupported_other, 0, "{tag}");
            // 首条必打；第二条在 10s 窗口内被抑制。
            assert_eq!(stats.udp_unsupported_log_suppressed, 1, "{tag}");
        }
    }

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

    #[test]
    fn unsupported_reason_strings_match_log_enum() {
        assert_eq!(
            unsupported_reason_str(UdpUnsupportedReason::NotWired),
            "not_wired"
        );
        assert_eq!(
            unsupported_reason_str(UdpUnsupportedReason::TlsVariantNotSupported),
            "tls_variant_not_supported"
        );
        assert_eq!(
            unsupported_reason_str(UdpUnsupportedReason::NoDatagramMode),
            "no_datagram_mode"
        );
    }
}
