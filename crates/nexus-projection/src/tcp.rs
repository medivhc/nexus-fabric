//! TCP egress (3b-5, S21/S22/S23).
//!
//! Originator side: terminates TCP with smoltcp (local handshake), turns the
//! byte stream into STREAM-intent fabric frames. Egress side: relays the byte
//! stream through a real `TcpStream` to the internet destination.
//!
//! std-only + smoltcp; no Tokio.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

/// smoltcp interface address (packets are rewritten to this dst before
/// being fed to the stack; the real destination lives in the stream table).
pub const SMOLTCP_IFACE_IP: [u8; 4] = [10, 254, 0, 1];

/// Max concurrent terminated TCP connections (S22).
pub const MAX_TCP_CONNS: usize = 1024;

/// Half-open (SYN received, handshake not finished) expiry (S23).
pub const HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Blocking-connect timeout for the egress side (W2: connect runs on a
/// short-lived worker thread, never on the downlink thread).
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap for DATA buffered while a relay connect is in flight (W2).
pub const RELAY_PENDING_DATA_CAP: usize = 64 * 1024;

/// Cap for bytes buffered on a relay connection when the non-blocking
/// write cannot keep up (W2).
pub const RELAY_WRITE_PENDING_CAP: usize = 256 * 1024;

// STREAM frame flags (after the intent byte:
// stream_id u32be | flags u8 | payload).
pub const STREAM_SYN: u8 = 0x01;
pub const STREAM_FIN: u8 = 0x02;
pub const STREAM_RST: u8 = 0x04;

/// TTL for cancelled-connect keys (N-new-1): pruned in `drain_connects` so
/// a worker thread that never reports back cannot grow the set without bound.
const CANCELLED_TTL: Duration = Duration::from_secs(60);

/// F1-residual: seed `next_id` per instance so two nodes that start
/// initiating TCP at the same time almost surely allocate different
/// stream ids (collision ~2^-32). Combined with the (peer, stream_id)
/// dispatch guard, same-peer cross connections can no longer deterministically
/// collide. std-only entropy, no new dependencies.
/// SYN 载荷的目标地址形式（S25，S22 兼容扩展）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynTarget {
    /// IPv4 地址 + 端口。
    V4(std::net::SocketAddrV4),
    /// 域名 + 端口（egress 侧解析；originator 永不本地解析）。
    Domain(String, u16),
}

/// 编码 SYN 载荷（S25 typed 形式，originator 自 3d 起统一使用）。
///
/// 首字节 addr-type：`0x01` 后跟 4 字节 IPv4；`0x03` 后跟 1 字节域名长度 +
/// 域名；最后 2 字节 port（u16be）。host 为 IP 字面量时用 `0x01` 形式。
pub fn encode_syn_payload(host: &str, port: u16) -> Vec<u8> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let mut out = Vec::with_capacity(7);
        out.push(0x01);
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }
    let name = host.as_bytes();
    let len = name.len().min(255) as u8;
    let mut out = Vec::with_capacity(4 + len as usize);
    out.push(0x03);
    out.push(len);
    out.extend_from_slice(&name[..len as usize]);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// 解码 SYN 载荷。返回 `(目标, 消费字节数)`；消费字节之后的内容是首数据。
///
/// 兼容：载荷长恰为 6 字节时按 3b-5 旧格式（IPv4 + port）解析。
/// 格式非法（未知 addr-type、长度越界）时返回 `None`。
pub fn decode_syn_payload(payload: &[u8]) -> Option<(SynTarget, usize)> {
    if payload.len() == 6 {
        // 3b-5 legacy: IPv4(4) + port(2)。
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&payload[..4]);
        let port = u16::from_be_bytes([payload[4], payload[5]]);
        return Some((
            SynTarget::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(ip),
                port,
            )),
            6,
        ));
    }
    let (&atyp, rest) = payload.split_first()?;
    match atyp {
        0x01 => {
            if rest.len() < 6 {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&rest[..4]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Some((
                SynTarget::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(ip),
                    port,
                )),
                7,
            ))
        }
        0x03 => {
            let (&len, rest) = rest.split_first()?;
            let len = len as usize;
            if rest.len() < len + 2 {
                return None;
            }
            let name = std::str::from_utf8(&rest[..len]).ok()?;
            if name.is_empty() {
                return None;
            }
            let port = u16::from_be_bytes([rest[len], rest[len + 1]]);
            Some((SynTarget::Domain(name.to_string(), port), 1 + 1 + len + 2))
        }
        _ => None,
    }
}

/// Resolve `(host, port)` to a socket address, preferring IPv4.
///
/// P0 is IPv4-only (3b-4/3b-5); `ToSocketAddrs` may return `::1` first for
/// `localhost`, which would fail against IPv4-only targets.
pub(crate) fn resolve_target_v4(host: &str, port: u16) -> Option<SocketAddr> {
    let addrs = (host, port).to_socket_addrs().ok()?;
    let mut fallback = None;
    for a in addrs {
        if a.is_ipv4() {
            return Some(a);
        }
        if fallback.is_none() {
            fallback = Some(a);
        }
    }
    fallback
}

pub(crate) fn random_stream_id_seed() -> u32 {
    #[cfg(unix)]
    {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 4];
            if f.read_exact(&mut buf).is_ok() {
                let seed = u32::from_ne_bytes(buf);
                if seed != 0 {
                    return seed;
                }
            }
        }
    }
    // Fallback: fnv-1a over (time, pid, stack address).
    let probe = 0u64;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |x: u64| {
        for b in x.to_ne_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    mix(SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() ^ ((d.subsec_nanos() as u64) << 32))
        .unwrap_or(0x9e37_79b9));
    mix(std::process::id() as u64);
    mix(&probe as *const u64 as usize as u64);
    let seed = (h >> 32) as u32 ^ h as u32;
    if seed == 0 { 0x9e37_79b9 } else { seed }
}

/// Encode a STREAM frame body (without the intent byte).
pub fn encode_stream_frame(stream_id: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + payload.len());
    f.extend_from_slice(&stream_id.to_be_bytes());
    f.push(flags);
    f.extend_from_slice(payload);
    f
}

/// Decode a STREAM frame body. Returns (stream_id, flags, payload).
pub fn decode_stream_frame(frame: &[u8]) -> Option<(u32, u8, &[u8])> {
    if frame.len() < 5 {
        return None;
    }
    let id = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let flags = frame[4];
    Some((id, flags, &frame[5..]))
}

/// One's-complement checksum over `data`.
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum over the IPv4 pseudo-header + TCP segment.
/// `tcp_seg` must have its checksum field zeroed.
pub fn tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for w in [src, dst] {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        sum += u16::from_be_bytes([w[2], w[3]]) as u32;
    }
    sum += 6u32; // protocol = TCP
    sum += tcp_seg.len() as u32;
    let mut i = 0;
    while i + 1 < tcp_seg.len() {
        sum += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_seg.len() {
        sum += (tcp_seg[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parsed TCP header: (src_ip, dst_ip, src_port, dst_port, flags, payload_offset).
pub type TcpParsed = ([u8; 4], [u8; 4], u16, u16, u8, usize);

/// Minimal IPv4/TCP header parse.
pub fn parse_tcp(packet: &[u8]) -> Option<TcpParsed> {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 20 {
        return None;
    }
    let tcp = &packet[ihl..];
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() < data_off {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    dst.copy_from_slice(&packet[16..20]);
    Some((
        src,
        dst,
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
        tcp[13],
        ihl + data_off,
    ))
}

/// Rewrite the IPv4 destination and fix IP + TCP checksums.
pub fn rewrite_dst(packet: &[u8], new_dst: [u8; 4]) -> Option<Vec<u8>> {
    let mut p = packet.to_vec();
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((p[0] & 0x0F) as usize) * 4;
    p[16..20].copy_from_slice(&new_dst);
    p[10] = 0;
    p[11] = 0;
    let c = ip_checksum(&p[..ihl]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    if p[9] == 6 && p.len() >= ihl + 20 {
        // TCP checksum covers the pseudo-header; zero it first.
        p[ihl + 16] = 0;
        p[ihl + 17] = 0;
        let mut src = [0u8; 4];
        src.copy_from_slice(&p[12..16]);
        let tc = tcp_checksum(src, new_dst, &p[ihl..]);
        p[ihl + 16..ihl + 18].copy_from_slice(&tc.to_be_bytes());
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// QueueDevice: smoltcp Device backed by in-memory queues.
// ---------------------------------------------------------------------------

struct QueueRx(Vec<u8>);
impl RxToken for QueueRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct QueueTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for QueueTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl Device for QueueDevice {
    type RxToken<'a>
        = QueueRx
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTx<'a>
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1500;
        c
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // N.B.: borrow dance — pop first, then hand out the tx token.
        let pkt = self.rx.pop_front()?;
        Some((QueueRx(pkt), QueueTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx(&mut self.tx))
    }
}

// ---------------------------------------------------------------------------
// TcpTerminator: originator side (S21).
// ---------------------------------------------------------------------------

/// App-visible four-tuple (original addresses, before dst rewrite).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermState {
    /// SYN received, waiting for handshake to complete.
    SynReceived(SystemTime),
    /// Handshake done (or closing); socket state is authoritative.
    Active,
}

struct TermConn {
    stream_id: u32,
    sock: SocketHandle,
    peer: String,
    orig_dst: SocketAddrV4,
    state: TermState,
    /// Whether the SYN frame was already emitted over fabric.
    syn_sent: bool,
    /// Whether we already emitted Closed for this conn.
    close_sent: bool,
    /// W1: fabric bytes not yet accepted by the smoltcp send buffer
    /// (back-pressure). Retried on every poll; never silently dropped.
    pending: Vec<u8>,
}

/// Events produced by the terminator for the fabric / TUN layer.
#[derive(Debug)]
pub enum TcpEvent {
    /// New connection established: send a SYN frame (with real dst) first.
    Syn {
        stream_id: u32,
        dst: SocketAddrV4,
        peer: String,
    },
    /// Application bytes from the local socket: send as DATA frame.
    Data {
        stream_id: u32,
        peer: String,
        bytes: Vec<u8>,
    },
    /// Connection finished locally: send FIN (or RST) frame.
    Closed {
        stream_id: u32,
        peer: String,
        reset: bool,
    },
    /// Raw IP packet for the local TUN (SYN-ACK, ACKs, data...).
    TunPacket(Vec<u8>),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpTermStats {
    /// S21: first packet of unknown flow was not a SYN.
    pub no_conn_dropped: u64,
    /// S22: SYN rejected, table full.
    pub table_full: u64,
    /// S23: half-open connections expired.
    pub half_open_expired: u64,
    /// Handshakes completed locally.
    pub handshake_done: u64,
    /// W1: fabric bytes retained (not dropped) because the smoltcp send
    /// buffer was full.
    pub send_buffer_full: u64,
    /// W-new (F1-residual defense in depth): a STREAM SYN frame that
    /// resolved to our own terminator entry was dropped instead of being
    /// injected as application data.
    pub stream_syn_to_originator_dropped: u64,
}

pub struct TcpTerminator {
    device: QueueDevice,
    sockets: SocketSet<'static>,
    conns: HashMap<FourTuple, TermConn>,
    by_id: HashMap<u32, FourTuple>,
    next_id: AtomicU32,
    max_conns: usize,
    stats: TcpTermStats,
}

impl Default for TcpTerminator {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTerminator {
    pub fn new() -> Self {
        Self {
            device: QueueDevice {
                rx: VecDeque::new(),
                tx: VecDeque::new(),
            },
            sockets: SocketSet::new(vec![]),
            conns: HashMap::new(),
            by_id: HashMap::new(),
            // F1-residual: per-instance random seed, not a fixed 1.
            next_id: AtomicU32::new(random_stream_id_seed()),
            max_conns: MAX_TCP_CONNS,
            stats: TcpTermStats::default(),
        }
    }

    #[cfg(test)]
    fn set_max_conns(&mut self, max: usize) {
        self.max_conns = max;
    }

    pub fn stats(&self) -> TcpTermStats {
        self.stats
    }

    pub fn conn_count(&self) -> usize {
        self.conns.len()
    }

    /// Test-only: allocated stream ids (ids are random-seeded since
    /// F1-residual, so tests must never assume id 1).
    #[cfg(test)]
    pub fn stream_ids(&self) -> Vec<u32> {
        self.by_id.keys().copied().collect()
    }

    pub fn lookup_id(&self, stream_id: u32) -> Option<FourTuple> {
        self.by_id.get(&stream_id).copied()
    }

    /// F1: the peer this stream_id was originated for, if we are the
    /// originator. Dispatch must compare this against the frame's
    /// `from_peer` — a bare `lookup_id` is_some() check misroutes when
    /// this node is both originator and egress for the same peer (ids are
    /// allocated per originator, random-seeded since F1-residual).
    pub fn peer_for(&self, stream_id: u32) -> Option<String> {
        let key = self.by_id.get(&stream_id)?;
        self.conns.get(key).map(|c| c.peer.clone())
    }

    fn poll_iface(&mut self) {
        // smoltcp 0.12: Interface::new only reads device capabilities;
        // the device is passed to poll() separately, so we can recreate
        // the Interface per poll and keep sockets in `self.sockets`.
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut self.device,
            Instant::now(),
        );
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::v4(
                    SMOLTCP_IFACE_IP[0],
                    SMOLTCP_IFACE_IP[1],
                    SMOLTCP_IFACE_IP[2],
                    SMOLTCP_IFACE_IP[3],
                ),
                24,
            ));
        });
        iface.poll(Instant::now(), &mut self.device, &mut self.sockets);
    }

    /// Handle a TUN TCP packet routed to `Egress{peer}`.
    /// Returns raw IP packets to write back to the TUN.
    pub fn handle_uplink(&mut self, packet: &[u8], peer: &str) -> Vec<Vec<u8>> {
        let (src_ip, dst_ip, src_port, dst_port, flags, _off) = match parse_tcp(packet) {
            Some(t) => t,
            None => return vec![],
        };
        let key = FourTuple {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        let is_syn = flags & 0x02 != 0 && flags & 0x10 == 0;

        if !self.conns.contains_key(&key) {
            if !is_syn {
                // S21: no connection state and not a SYN — drop and count.
                self.stats.no_conn_dropped += 1;
                return vec![];
            }
            if self.conns.len() >= self.max_conns {
                self.stats.table_full += 1;
                return vec![];
            }
            let stream_id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; 16384]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; 16384]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            if sock.listen(dst_port).is_err() {
                return vec![];
            }
            let handle = self.sockets.add(sock);
            self.conns.insert(
                key,
                TermConn {
                    stream_id,
                    sock: handle,
                    peer: peer.to_string(),
                    orig_dst: SocketAddrV4::new(std::net::Ipv4Addr::from(dst_ip), dst_port),
                    state: TermState::SynReceived(SystemTime::now()),
                    syn_sent: false,
                    close_sent: false,
                    pending: Vec::new(),
                },
            );
            self.by_id.insert(stream_id, key);
        }

        // Rewrite dst to the smoltcp interface address and feed the stack.
        if let Some(rw) = rewrite_dst(packet, SMOLTCP_IFACE_IP) {
            self.device.rx.push_back(rw);
        }
        self.poll_iface();
        self.drain_tx()
    }

    /// Feed bytes arriving from the fabric (DATA frame) into the socket.
    /// W1: bytes the smoltcp send buffer cannot take are retained in
    /// `TermConn.pending` and retried on every `poll()` — never dropped.
    /// Returns TUN packets to write back.
    pub fn handle_fabric_data(&mut self, stream_id: u32, data: &[u8]) -> Vec<Vec<u8>> {
        let key = match self.by_id.get(&stream_id) {
            Some(k) => *k,
            None => return vec![],
        };
        if let Some(c) = self.conns.get_mut(&key) {
            c.pending.extend_from_slice(data);
        }
        self.flush_pending(key);
        self.poll_iface();
        self.drain_tx()
    }

    /// Dispatch an inbound STREAM frame for a connection we originated
    /// (S22). A SYN flag here means misrouting — an originator never
    /// receives SYN — so drop and count instead of injecting the 6-byte
    /// address payload as application data (F1-residual defense in depth,
    /// W-new). Consolidates the RST/FIN/DATA dispatch used by both the
    /// downlink path and the self-loopback path.
    pub fn handle_originator_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<Vec<u8>> {
        if flags & STREAM_SYN != 0 {
            self.stats.stream_syn_to_originator_dropped += 1;
            return vec![];
        }
        if flags & STREAM_RST != 0 {
            self.handle_fabric_rst(stream_id)
        } else if flags & STREAM_FIN != 0 {
            self.handle_fabric_fin(stream_id)
        } else {
            self.handle_fabric_data(stream_id, payload)
        }
    }

    /// Try to push retained bytes into the smoltcp send buffer.
    fn flush_pending(&mut self, key: FourTuple) {
        let handle = match self.conns.get(&key) {
            Some(c) => c.sock,
            None => return,
        };
        if self
            .conns
            .get(&key)
            .map(|c| c.pending.is_empty())
            .unwrap_or(true)
        {
            return;
        }
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        // N.B.: borrow dance — take the pending vec out, refill on partial.
        let mut pending = std::mem::take(&mut self.conns.get_mut(&key).unwrap().pending);
        let mut off = 0;
        while off < pending.len() {
            match sock.send_slice(&pending[off..]) {
                Ok(n) if n > 0 => off += n,
                _ => break,
            }
        }
        pending.drain(..off);
        let c = self.conns.get_mut(&key).unwrap();
        if !pending.is_empty() {
            self.stats.send_buffer_full += 1;
        }
        c.pending = pending;
    }

    #[cfg(test)]
    fn backdate_half_open(&mut self, age: Duration) {
        let t0 = SystemTime::now() - age;
        for c in self.conns.values_mut() {
            if matches!(c.state, TermState::SynReceived(_)) {
                c.state = TermState::SynReceived(t0);
            }
        }
    }

    /// Remote FIN: close the local socket (S23).
    pub fn handle_fabric_fin(&mut self, stream_id: u32) -> Vec<Vec<u8>> {
        let key = match self.by_id.get(&stream_id) {
            Some(k) => *k,
            None => return vec![],
        };
        if let Some(c) = self.conns.get(&key) {
            self.sockets.get_mut::<tcp::Socket>(c.sock).close();
        }
        self.poll_iface();
        self.drain_tx()
    }

    /// Remote RST: abort the local socket (S23).
    pub fn handle_fabric_rst(&mut self, stream_id: u32) -> Vec<Vec<u8>> {
        let key = match self.by_id.get(&stream_id) {
            Some(k) => *k,
            None => return vec![],
        };
        if let Some(c) = self.conns.remove(&key) {
            self.sockets.get_mut::<tcp::Socket>(c.sock).abort();
            self.sockets.remove(c.sock);
            self.by_id.remove(&stream_id);
        }
        self.poll_iface();
        self.drain_tx()
    }

    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.tx.drain(..).collect()
    }

    /// Drive timers / retransmissions; harvest socket events.
    /// Call regularly (~10ms) from the owner thread.
    pub fn poll(&mut self) -> Vec<TcpEvent> {
        self.poll_iface();
        let mut events = Vec::new();
        let now = SystemTime::now();

        // Snapshot keys to avoid borrow issues.
        let keys: Vec<FourTuple> = self.conns.keys().copied().collect();
        let mut remove: Vec<FourTuple> = Vec::new();

        for key in keys {
            let (stream_id, peer, orig_dst, state, handle) = {
                let c = match self.conns.get(&key) {
                    Some(c) => c,
                    None => continue,
                };
                (c.stream_id, c.peer.clone(), c.orig_dst, c.state, c.sock)
            };

            // S23: half-open expiry.
            if let TermState::SynReceived(t0) = state {
                if now.duration_since(t0).unwrap_or_default() > HALF_OPEN_TIMEOUT {
                    self.stats.half_open_expired += 1;
                    remove.push(key);
                    // Emit a RST so the egress side cleans up too.
                    events.push(TcpEvent::Closed {
                        stream_id,
                        peer,
                        reset: true,
                    });
                    continue;
                }
            }

            // W1: retry bytes the smoltcp send buffer could not take earlier.
            self.flush_pending(key);

            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            let sock_state = sock.state();

            // Handshake completed → emit Syn once.
            let established = sock_state == tcp::State::Established
                || sock_state == tcp::State::FinWait1
                || sock_state == tcp::State::FinWait2
                || sock_state == tcp::State::CloseWait
                || sock_state == tcp::State::Closing
                || sock_state == tcp::State::LastAck
                || sock_state == tcp::State::TimeWait;
            if established {
                let c = self.conns.get_mut(&key).unwrap();
                if matches!(c.state, TermState::SynReceived(_)) {
                    c.state = TermState::Active;
                    self.stats.handshake_done += 1;
                }
                if !c.syn_sent {
                    c.syn_sent = true;
                    events.push(TcpEvent::Syn {
                        stream_id,
                        dst: orig_dst,
                        peer: peer.clone(),
                    });
                }
            }

            // Application bytes.
            while sock.can_recv() {
                let mut buf = [0u8; 8192];
                match sock.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => events.push(TcpEvent::Data {
                        stream_id,
                        peer: peer.clone(),
                        bytes: buf[..n].to_vec(),
                    }),
                    _ => break,
                }
            }

            // Local close detection: app FIN → CloseWait → we close → FIN sent.
            // Socket fully closed → remove from the table (always checked,
            // independent of whether the Closed event was already emitted).
            if sock_state == tcp::State::Closed {
                let c = self.conns.get_mut(&key).unwrap();
                if !c.close_sent {
                    c.close_sent = true;
                    events.push(TcpEvent::Closed {
                        stream_id,
                        peer: peer.clone(),
                        reset: false,
                    });
                }
                remove.push(key);
                continue;
            }
            let c = self.conns.get_mut(&key).unwrap();
            if !c.close_sent && sock_state == tcp::State::CloseWait {
                // App sent FIN; send our FIN too (S23).
                sock.close();
                c.close_sent = true;
                events.push(TcpEvent::Closed {
                    stream_id,
                    peer: peer.clone(),
                    reset: false,
                });
            }
        }

        for key in remove {
            if let Some(c) = self.conns.remove(&key) {
                self.sockets.remove(c.sock);
                self.by_id.remove(&c.stream_id);
            }
        }

        // TUN-bound packets produced by this poll.
        for pkt in self.drain_tx() {
            events.push(TcpEvent::TunPacket(pkt));
        }
        events
    }
}

// ---------------------------------------------------------------------------
// TcpRelay: egress side (S22/S23).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TcpRelay: egress side (S22/S23).
// ---------------------------------------------------------------------------

/// Relay table key: stream_ids are allocated per originator (random-seeded
/// since F1-residual), so the table is keyed by (peer, stream_id) — F1.
type RelayKey = (String, u32);

struct RelayConn {
    stream: TcpStream,
    peer: String,
    /// EOF seen on the internet side; FIN frame already emitted.
    fin_sent: bool,
    /// W2: bytes the non-blocking write could not take yet.
    write_pending: Vec<u8>,
}

/// A SYN whose TCP connect is running on a worker thread (W2: the
/// downlink thread never blocks on connect).
struct PendingSyn {
    first_data: Vec<u8>,
    fin_pending: bool,
}

/// Result of a worker-thread connect, delivered back via channel.
struct ConnectResult {
    key: RelayKey,
    stream: Option<TcpStream>,
}

#[derive(Debug)]
pub enum RelayEvent {
    /// Bytes read from the internet side: send as DATA frame to `peer`.
    Data {
        stream_id: u32,
        peer: String,
        bytes: Vec<u8>,
    },
    /// Internet side EOF/error: send FIN (or RST) frame to `peer`.
    Closed {
        stream_id: u32,
        peer: String,
        reset: bool,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpRelayStats {
    pub relayed_bytes: u64,
    pub table_full: u64,
    pub connect_failed: u64,
    /// N3: SYN frames with a payload shorter than the 6-byte addr prefix.
    pub short_syn_dropped: u64,
}

pub struct TcpRelay {
    conns: HashMap<RelayKey, RelayConn>,
    /// SYNs with a connect in flight (W2).
    pending: HashMap<RelayKey, PendingSyn>,
    /// Keys whose in-flight connect was cancelled (RST arrived first);
    /// late worker results for these are dropped. Pruned by age in
    /// `drain_connects` (N-new-1).
    cancelled: HashMap<RelayKey, std::time::Instant>,
    connect_tx: mpsc::Sender<ConnectResult>,
    connect_rx: mpsc::Receiver<ConnectResult>,
    max_conns: usize,
    stats: TcpRelayStats,
}

impl Default for TcpRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpRelay {
    pub fn new() -> Self {
        let (connect_tx, connect_rx) = mpsc::channel();
        Self {
            conns: HashMap::new(),
            pending: HashMap::new(),
            cancelled: HashMap::new(),
            connect_tx,
            connect_rx,
            max_conns: MAX_TCP_CONNS,
            stats: TcpRelayStats::default(),
        }
    }

    #[cfg(test)]
    fn set_max_conns(&mut self, max: usize) {
        self.max_conns = max;
    }

    pub fn stats(&self) -> TcpRelayStats {
        self.stats
    }

    pub fn conn_count(&self) -> usize {
        self.conns.len() + self.pending.len()
    }

    pub fn has(&self, peer: &str, stream_id: u32) -> bool {
        let key = (peer.to_string(), stream_id);
        self.conns.contains_key(&key) || self.pending.contains_key(&key)
    }

    /// Non-blocking write helper shared by DATA handling and poll flush.
    /// Returns Err(()) on a fatal error (caller removes the conn + RST).
    /// WouldBlock remainder is appended to `pending_out`.
    fn write_nonblocking(
        stream: &mut TcpStream,
        pending_out: &mut Vec<u8>,
        data: &[u8],
    ) -> Result<(), ()> {
        let mut off = 0;
        while off < data.len() {
            match stream.write(&data[off..]) {
                Ok(n) => off += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            }
        }
        if off < data.len() {
            pending_out.extend_from_slice(&data[off..]);
            if pending_out.len() > RELAY_WRITE_PENDING_CAP {
                return Err(());
            }
        }
        Ok(())
    }

    /// Handle a STREAM frame from the originator. Returns events to send back
    /// (currently only used for connect-failure RST).
    ///
    /// W2: SYN never blocks the caller — the TCP connect runs on a
    /// short-lived worker thread and completes in `poll()`.
    pub fn handle_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: &[u8],
        from_peer: &str,
    ) -> Vec<RelayEvent> {
        let mut out = Vec::new();
        let key: RelayKey = (from_peer.to_string(), stream_id);
        if flags & STREAM_SYN != 0 {
            // S25: typed SYN 载荷（`decode_syn_payload` 兼容 3b-5 6 字节旧格式）。
            let (target, data_off) = match decode_syn_payload(payload) {
                Some(t) => t,
                None => {
                    self.stats.short_syn_dropped += 1;
                    return out;
                }
            };
            if self.conns.contains_key(&key) || self.pending.contains_key(&key) {
                return out; // duplicate SYN: ignore
            }
            if self.conns.len() + self.pending.len() >= self.max_conns {
                self.stats.table_full += 1;
                out.push(RelayEvent::Closed {
                    stream_id,
                    peer: from_peer.to_string(),
                    reset: true,
                });
                return out;
            }
            // S25: 域名形式在 egress 侧解析（ToSocketAddrs；originator 永不
            // 本地解析）。解析失败 → RST 回源并计数。
            let addr: SocketAddr = match target {
                SynTarget::V4(a) => SocketAddr::V4(a),
                SynTarget::Domain(host, port) => match resolve_target_v4(&host, port) {
                    Some(a) => a,
                    None => {
                        self.stats.connect_failed += 1;
                        out.push(RelayEvent::Closed {
                            stream_id,
                            peer: from_peer.to_string(),
                            reset: true,
                        });
                        return out;
                    }
                },
            };
            // 载荷中地址之后的内容是首数据（typed / legacy 均按消费偏移切分）。
            let mut first_data = Vec::new();
            if payload.len() > data_off {
                first_data.extend_from_slice(&payload[data_off..]);
            }
            self.pending.insert(
                key.clone(),
                PendingSyn {
                    first_data,
                    fin_pending: false,
                },
            );
            // W2: connect off the downlink thread.
            let tx = self.connect_tx.clone();
            std::thread::spawn(move || {
                let stream = TcpStream::connect_timeout(&addr, RELAY_CONNECT_TIMEOUT)
                    .ok()
                    .and_then(|s| s.set_nonblocking(true).ok().map(|_| s));
                let _ = tx.send(ConnectResult { key, stream });
            });
            return out;
        }
        if self.cancelled.contains_key(&key) {
            return out; // RST'd while connecting: drop late frames.
        }
        // DATA/FIN for a connect still in flight: buffer / record.
        if let Some(p) = self.pending.get_mut(&key) {
            if flags & STREAM_RST != 0 {
                self.pending.remove(&key);
                self.cancelled.insert(key, std::time::Instant::now());
                return out;
            }
            if flags & STREAM_FIN != 0 {
                p.fin_pending = true;
                return out;
            }
            if !payload.is_empty() {
                if p.first_data.len() + payload.len() > RELAY_PENDING_DATA_CAP {
                    self.pending.remove(&key);
                    self.cancelled
                        .insert(key.clone(), std::time::Instant::now());
                    out.push(RelayEvent::Closed {
                        stream_id,
                        peer: from_peer.to_string(),
                        reset: true,
                    });
                    return out;
                }
                p.first_data.extend_from_slice(payload);
            }
            return out;
        }
        let conn = match self.conns.get_mut(&key) {
            Some(c) => c,
            None => return out, // unknown stream: drop (S12-style)
        };
        if flags & STREAM_RST != 0 {
            self.conns.remove(&key);
            return out;
        }
        if flags & STREAM_FIN != 0 {
            let _ = conn.stream.shutdown(Shutdown::Write);
            // Keep reading remaining bytes until EOF, then FIN back.
            return out;
        }
        if !payload.is_empty() {
            // W2: non-blocking write; remainder buffered, never blocks.
            let r = Self::write_nonblocking(&mut conn.stream, &mut conn.write_pending, payload);
            if r.is_err() {
                self.conns.remove(&key);
                out.push(RelayEvent::Closed {
                    stream_id,
                    peer: from_peer.to_string(),
                    reset: true,
                });
            }
        }
        out
    }

    /// Drain finished worker connects into the table.
    fn drain_connects(&mut self, out: &mut Vec<RelayEvent>) {
        while let Ok(res) = self.connect_rx.try_recv() {
            if self.cancelled.remove(&res.key).is_some() {
                continue; // RST arrived while connecting: drop the stream.
            }
            let mut p = match self.pending.remove(&res.key) {
                Some(p) => p,
                None => continue,
            };
            let (stream_id, peer) = (res.key.1, res.key.0.clone());
            let mut stream = match res.stream {
                Some(s) => s,
                None => {
                    self.stats.connect_failed += 1;
                    out.push(RelayEvent::Closed {
                        stream_id,
                        peer,
                        reset: true,
                    });
                    continue;
                }
            };
            // Flush data buffered while connecting (W2).
            let mut write_pending = Vec::new();
            let first = std::mem::take(&mut p.first_data);
            let r = Self::write_nonblocking(&mut stream, &mut write_pending, &first);
            if r.is_err() {
                self.stats.connect_failed += 1;
                out.push(RelayEvent::Closed {
                    stream_id,
                    peer,
                    reset: true,
                });
                continue;
            }
            if p.fin_pending {
                let _ = stream.shutdown(Shutdown::Write);
            }
            self.conns.insert(
                res.key,
                RelayConn {
                    stream,
                    peer,
                    fin_sent: false,
                    write_pending,
                },
            );
        }
        // N-new-1: bound the cancelled set; a worker that panics (or whose
        // result arrives after the 60s TTL) must not grow it without bound.
        // Pruning is safe: `pending` was already removed when the key was
        // cancelled, so a late ConnectResult hits the pending-miss path and
        // is dropped regardless of whether the key is still cancelled.
        let now = std::time::Instant::now();
        self.cancelled
            .retain(|_, t| now.duration_since(*t) < CANCELLED_TTL);
    }

    /// Poll internet-side sockets; harvest bytes / EOF / errors.
    pub fn poll(&mut self) -> Vec<RelayEvent> {
        let mut out = Vec::new();
        self.drain_connects(&mut out);
        let mut remove = Vec::new();
        let ids: Vec<RelayKey> = self.conns.keys().cloned().collect();
        for id in ids {
            let conn = match self.conns.get_mut(&id) {
                Some(c) => c,
                None => continue,
            };
            // W2: flush bytes the non-blocking write could not take yet.
            if !conn.write_pending.is_empty() {
                let pending = std::mem::take(&mut conn.write_pending);
                let r =
                    Self::write_nonblocking(&mut conn.stream, &mut conn.write_pending, &pending);
                if r.is_err() {
                    remove.push(id.clone());
                    out.push(RelayEvent::Closed {
                        stream_id: id.1,
                        peer: conn.peer.clone(),
                        reset: true,
                    });
                    continue;
                }
            }
            let mut buf = [0u8; 8192];
            match conn.stream.read(&mut buf) {
                Ok(0) => {
                    // EOF: all remaining bytes delivered; FIN back (S23).
                    if !conn.fin_sent {
                        conn.fin_sent = true;
                        out.push(RelayEvent::Closed {
                            stream_id: id.1,
                            peer: conn.peer.clone(),
                            reset: false,
                        });
                    }
                    remove.push(id);
                }
                Ok(n) => {
                    self.stats.relayed_bytes += n as u64;
                    out.push(RelayEvent::Data {
                        stream_id: id.1,
                        peer: conn.peer.clone(),
                        bytes: buf[..n].to_vec(),
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    remove.push(id.clone());
                    out.push(RelayEvent::Closed {
                        stream_id: id.1,
                        peer: conn.peer.clone(),
                        reset: true,
                    });
                }
            }
        }
        for id in remove {
            self.conns.remove(&id);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// TcpEgress: combined owner (terminator + relay).
// ---------------------------------------------------------------------------

/// Combined TCP egress endpoint. A Projection owns one; it acts as
/// originator (terminator) for locally-originated flows and as relay for
/// STREAM frames arriving from other nodes. `Clone`-free; share via
/// `Arc<Mutex<..>>` like the other Projection state.
///
/// S25: `semantic_streams` registers originator-side STREAM flows owned by
/// `SemanticIngress` (byte-stream clients, not the smoltcp terminator).
/// Keyed by `(peer, stream_id)` (F1 lesson); the downlink and the
/// self-loopback path consult it before the terminator/relay dispatch.
/// S25: inbound channel for a semantic-ingress originator stream.
/// Payload is `(STREAM flags, frame payload)`.
pub type SemanticStreamTx = mpsc::SyncSender<(u8, Vec<u8>)>;

pub struct TcpEgress {
    pub terminator: TcpTerminator,
    pub relay: TcpRelay,
    pub semantic_streams: std::sync::Mutex<HashMap<(String, u32), SemanticStreamTx>>,
}

impl TcpEgress {
    pub fn new() -> Self {
        Self {
            terminator: TcpTerminator::new(),
            relay: TcpRelay::new(),
            semantic_streams: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Total live connections (terminator + relay).
    pub fn conn_count(&self) -> usize {
        self.terminator.conn_count() + self.relay.conn_count()
    }

    /// F1: true iff `stream_id` is a connection we originated *for*
    /// `from_peer`. A bare "id known to terminator" check misroutes when
    /// this node is both originator and egress, because ids are allocated
    /// per originator (random-seeded since F1-residual; the peer comparison
    /// is the deterministic guard).
    pub fn is_originator_frame(&self, stream_id: u32, from_peer: &str) -> bool {
        self.terminator.peer_for(stream_id).as_deref() == Some(from_peer)
    }

    /// S25: register a semantic-ingress originator stream.
    pub fn semantic_register(&self, peer: &str, stream_id: u32, tx: SemanticStreamTx) {
        self.semantic_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((peer.to_string(), stream_id), tx);
    }

    /// S25: remove a semantic-ingress originator stream.
    pub fn semantic_deregister(&self, peer: &str, stream_id: u32) {
        self.semantic_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(peer.to_string(), stream_id));
    }

    /// S25: look up a semantic-ingress originator stream by (peer, id).
    pub fn semantic_lookup(&self, peer: &str, stream_id: u32) -> Option<SemanticStreamTx> {
        self.semantic_streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(peer.to_string(), stream_id))
            .cloned()
    }
}

impl Default for TcpEgress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4/TCP packet with correct checksums.
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

    #[test]
    fn terminator_completes_handshake() {
        // S21: SYN -> SYN-ACK; ACK -> Established; Syn event emitted.
        let mut term = TcpTerminator::new();
        let syn = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40000, 8080, 1000, 0, 0x02, &[]);
        let tun_pkts = term.handle_uplink(&syn, "peer-B");
        assert_eq!(tun_pkts.len(), 1, "expected SYN-ACK");
        let (_, _, sp, dp, flags, _) = parse_tcp(&tun_pkts[0]).unwrap();
        assert_eq!((sp, dp), (8080, 40000));
        assert_eq!(flags & 0x12, 0x12, "SYN+ACK");

        // Complete the handshake with ACK (server seq from SYN-ACK).
        let srv_seq = u32::from_be_bytes([
            tun_pkts[0][24],
            tun_pkts[0][25],
            tun_pkts[0][26],
            tun_pkts[0][27],
        ]);
        let ack = craft_tcp(
            [10, 0, 0, 2],
            [1, 2, 3, 4],
            40000,
            8080,
            1001,
            srv_seq + 1,
            0x10,
            &[],
        );
        let tun_pkts = term.handle_uplink(&ack, "peer-B");
        // Pure ACK: no TUN reply expected (maybe none).
        let _ = tun_pkts;

        let events = term.poll();
        let syn_ev = events.iter().find_map(|e| match e {
            TcpEvent::Syn {
                stream_id,
                dst,
                peer,
            } => Some((*stream_id, *dst, peer.clone())),
            _ => None,
        });
        assert!(
            syn_ev.is_some(),
            "expected Syn event after handshake: {:?}",
            events.len()
        );
        let (sid, dst, peer) = syn_ev.unwrap();
        assert_eq!(dst.ip().octets(), [1, 2, 3, 4]);
        assert_eq!(dst.port(), 8080);
        assert_eq!(peer, "peer-B");
        assert_eq!(term.stats().handshake_done, 1);
        let _ = sid;
    }

    #[test]
    fn non_syn_first_packet_dropped() {
        // S21: first packet for unknown flow is not SYN -> drop + count.
        let mut term = TcpTerminator::new();
        let ack = craft_tcp(
            [10, 0, 0, 2],
            [1, 2, 3, 4],
            40000,
            8080,
            1001,
            777,
            0x10,
            &[],
        );
        let tun_pkts = term.handle_uplink(&ack, "peer-B");
        assert!(tun_pkts.is_empty());
        assert_eq!(term.stats().no_conn_dropped, 1);
        assert_eq!(term.conn_count(), 0);
    }

    #[test]
    fn stream_frame_roundtrip() {
        // S22: frame encode/decode incl. SYN addr prefix.
        let mut payload = vec![];
        payload.extend_from_slice(&[1, 2, 3, 4]);
        payload.extend_from_slice(&8080u16.to_be_bytes());
        payload.extend_from_slice(b"hello");
        let f = encode_stream_frame(42, STREAM_SYN, &payload);
        let (id, flags, p) = decode_stream_frame(&f).unwrap();
        assert_eq!(id, 42);
        assert_eq!(flags, STREAM_SYN);
        assert_eq!(&p[..4], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 8080);
        assert_eq!(&p[6..], b"hello");
        assert!(decode_stream_frame(&[1, 2, 3]).is_none());
    }

    #[test]
    fn relay_connects_and_relays() {
        // S22: SYN frame -> real TcpStream; DATA -> forwarded.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            s.write_all(&buf[..n]).unwrap(); // echo
        });

        let mut relay = TcpRelay::new();
        let sa = match addr {
            SocketAddr::V4(v4) => v4,
            _ => panic!("expected v4"),
        };
        let mut syn_payload = vec![];
        syn_payload.extend_from_slice(&sa.ip().octets());
        syn_payload.extend_from_slice(&sa.port().to_be_bytes());
        let evs = relay.handle_frame(7, STREAM_SYN, &syn_payload, "peer-A");
        assert!(evs.is_empty());
        // W2: connect completes asynchronously on the poll thread.
        let mut ok = false;
        for _ in 0..200 {
            let _ = relay.poll();
            if relay.has("peer-A", 7) {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ok, "relay connect did not complete");
        assert!(!relay.has("peer-B", 7));

        let evs = relay.handle_frame(7, 0, b"ping", "peer-A");
        assert!(evs.is_empty());
        // Poll until the echo comes back.
        let mut got: Vec<u8> = vec![];
        for _ in 0..200 {
            for e in relay.poll() {
                if let RelayEvent::Data { bytes, .. } = e {
                    got.extend_from_slice(&bytes);
                }
            }
            if got.len() >= 4 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(got, b"ping");
        assert!(relay.stats().relayed_bytes >= 4);
    }

    #[test]
    fn table_full_rejects_syn() {
        // S22: table cap enforced on both sides (test-only small cap).
        let mut term = TcpTerminator::new();
        term.set_max_conns(1);
        let syn1 = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40000, 8080, 1000, 0, 0x02, &[]);
        let _ = term.handle_uplink(&syn1, "peer-B");
        assert_eq!(term.conn_count(), 1);
        let syn2 = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40001, 8080, 1000, 0, 0x02, &[]);
        let _ = term.handle_uplink(&syn2, "peer-B");
        assert_eq!(term.stats().table_full, 1);
        assert_eq!(term.conn_count(), 1);

        // Relay side: SYN rejected with an RST event.
        let mut relay = TcpRelay::new();
        relay.set_max_conns(0);
        let mut p = vec![127, 0, 0, 1];
        p.extend_from_slice(&7u16.to_be_bytes());
        let evs = relay.handle_frame(9, STREAM_SYN, &p, "peer-A");
        assert!(
            evs.iter()
                .any(|e| matches!(e, RelayEvent::Closed { reset: true, .. })),
            "expected RST on table-full SYN"
        );
        assert_eq!(relay.stats().table_full, 1);
    }

    #[test]
    fn fin_propagates_and_cleans_up() {
        // S23: app FIN -> CloseWait -> we close -> Closed event + cleanup.
        let mut term = TcpTerminator::new();
        let syn = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40001, 8081, 2000, 0, 0x02, &[]);
        let tun_pkts = term.handle_uplink(&syn, "peer-B");
        assert_eq!(tun_pkts.len(), 1);
        let srv_seq = u32::from_be_bytes([
            tun_pkts[0][24],
            tun_pkts[0][25],
            tun_pkts[0][26],
            tun_pkts[0][27],
        ]);
        let ack = craft_tcp(
            [10, 0, 0, 2],
            [1, 2, 3, 4],
            40001,
            8081,
            2001,
            srv_seq + 1,
            0x10,
            &[],
        );
        term.handle_uplink(&ack, "peer-B");
        let _ = term.poll(); // establish

        // App FIN.
        let fin = craft_tcp(
            [10, 0, 0, 2],
            [1, 2, 3, 4],
            40001,
            8081,
            2001,
            srv_seq + 1,
            0x11,
            &[],
        );
        let tun_pkts = term.handle_uplink(&fin, "peer-B");
        assert!(!tun_pkts.is_empty(), "expected ACK of FIN");
        let events = term.poll();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TcpEvent::Closed { reset: false, .. })),
            "expected Closed event, got {:?}",
            events
                .iter()
                .map(std::mem::discriminant)
                .collect::<Vec<_>>()
        );

        // Our FIN must be emitted to the TUN (seq = srv_seq+1, one byte).
        let mut our_fin_seq = None;
        for _ in 0..3 {
            for e in term.poll() {
                if let TcpEvent::TunPacket(p) = e {
                    if let Some((_, _, sp, _, flags, _)) = parse_tcp(&p) {
                        if sp == 8081 && flags & 0x01 != 0 {
                            our_fin_seq = Some(u32::from_be_bytes([p[24], p[25], p[26], p[27]]));
                        }
                    }
                }
            }
            if our_fin_seq.is_some() {
                break;
            }
        }
        let our_fin_seq = our_fin_seq.expect("our FIN packet missing on TUN");

        // App ACKs our FIN -> smoltcp Closed -> table cleaned (S23).
        let final_ack = craft_tcp(
            [10, 0, 0, 2],
            [1, 2, 3, 4],
            40001,
            8081,
            2002,
            our_fin_seq + 1,
            0x10,
            &[],
        );
        term.handle_uplink(&final_ack, "peer-B");
        for _ in 0..3 {
            let _ = term.poll();
        }
        assert_eq!(
            term.conn_count(),
            0,
            "connection table must be empty after FIN handshake"
        );
    }

    #[test]
    fn half_open_expires() {
        // S23: SYN received but the handshake never completes → the
        // half-open connection is reaped after 30s and an RST goes out.
        let mut term = TcpTerminator::new();
        let syn = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40003, 8083, 6000, 0, 0x02, &[]);
        let _ = term.handle_uplink(&syn, "peer-B");
        assert_eq!(term.conn_count(), 1);
        term.backdate_half_open(Duration::from_secs(31));
        let events = term.poll();
        assert_eq!(term.stats().half_open_expired, 1);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TcpEvent::Closed { reset: true, .. })),
            "expected RST Closed event for expired half-open"
        );
        assert_eq!(term.conn_count(), 0);
    }

    #[test]
    fn checksum_helpers() {
        // ip_checksum of a header with correct checksum verifies to 0.
        let mut hdr = [
            0x45u8, 0, 0, 20, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
        ];
        let c = ip_checksum(&hdr);
        hdr[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(ip_checksum(&hdr), 0);
    }

    #[test]
    fn rewrite_dst_fixes_checksums() {
        let pkt = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40000, 8080, 1000, 0, 0x02, &[]);
        let rw = rewrite_dst(&pkt, SMOLTCP_IFACE_IP).unwrap();
        assert_eq!(&rw[16..20], &SMOLTCP_IFACE_IP);
        assert_eq!(ip_checksum(&rw[..20]), 0);
        // TCP checksum over new pseudo-header verifies to 0.
        assert_eq!(tcp_checksum([10, 0, 0, 2], SMOLTCP_IFACE_IP, &rw[20..]), 0);
    }

    #[test]
    fn dual_role_dispatches_by_peer() {
        // F1: one TcpEgress is originator for peer-C while a different
        // node (peer-A) may use the same stream_id against us as egress.
        // Dispatch must compare from_peer, not just id presence. The
        // allocated id is captured (never assumed: ids are random-seeded).
        let mut e = TcpEgress::new();
        let syn = craft_tcp([10, 0, 0, 2], [9, 9, 9, 9], 40010, 443, 5000, 0, 0x02, &[]);
        let _ = e.terminator.handle_uplink(&syn, "peer-C");
        let ids = e.terminator.stream_ids();
        assert_eq!(ids.len(), 1);
        let sid = ids[0];
        assert_eq!(e.terminator.peer_for(sid).as_deref(), Some("peer-C"));
        assert!(e.is_originator_frame(sid, "peer-C"));
        assert!(!e.is_originator_frame(sid, "peer-A")); // A's stream → egress
        assert!(!e.is_originator_frame(sid, "self"));
        assert!(!e.is_originator_frame(sid.wrapping_add(4242), "peer-C")); // unknown id → egress
    }

    /// Spawn a one-connection echo server; returns its address.
    fn echo_server() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).unwrap();
            }
        });
        addr
    }

    fn syn_payload_for(addr: SocketAddr) -> Vec<u8> {
        let sa = match addr {
            SocketAddr::V4(v4) => v4,
            _ => panic!("expected v4"),
        };
        let mut p = vec![];
        p.extend_from_slice(&sa.ip().octets());
        p.extend_from_slice(&sa.port().to_be_bytes());
        p
    }

    fn wait_relay_has(relay: &mut TcpRelay, peer: &str, sid: u32) {
        for _ in 0..300 {
            let _ = relay.poll();
            if relay.has(peer, sid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("relay connect for ({peer}, {sid}) did not complete");
    }

    #[test]
    fn relay_same_id_routes_by_peer() {
        // F1: two originators both allocate stream_id 1 against this
        // relay. Frames must be routed by (peer, stream_id); bytes must
        // never cross between the two connections.
        let addr_a = echo_server();
        let addr_c = echo_server();
        let mut relay = TcpRelay::new();
        relay.handle_frame(1, STREAM_SYN, &syn_payload_for(addr_a), "peer-A");
        relay.handle_frame(1, STREAM_SYN, &syn_payload_for(addr_c), "peer-C");
        wait_relay_has(&mut relay, "peer-A", 1);
        wait_relay_has(&mut relay, "peer-C", 1);
        assert_eq!(relay.conn_count(), 2);

        relay.handle_frame(1, 0, b"pingA", "peer-A");
        relay.handle_frame(1, 0, b"pingC", "peer-C");
        let mut got_a = vec![];
        let mut got_c = vec![];
        for _ in 0..300 {
            for e in relay.poll() {
                if let RelayEvent::Data { peer, bytes, .. } = e {
                    if peer == "peer-A" {
                        got_a.extend_from_slice(&bytes);
                    } else if peer == "peer-C" {
                        got_c.extend_from_slice(&bytes);
                    } else {
                        panic!("unexpected peer {peer}");
                    }
                }
            }
            if got_a == b"pingA" && got_c == b"pingC" {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(got_a, b"pingA", "peer-A's bytes misrouted");
        assert_eq!(got_c, b"pingC", "peer-C's bytes misrouted");
    }

    #[test]
    fn stream_id_seeds_differ() {
        // F1-residual: two terminators must not start their id counters at
        // the same value. Per-instance random seeding makes a collision
        // ~2^-32 (the deterministic guard is the (peer, id) dispatch).
        let mut a = TcpTerminator::new();
        let mut b = TcpTerminator::new();
        let syn_a = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40020, 8080, 7000, 0, 0x02, &[]);
        let syn_b = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40021, 8080, 7000, 0, 0x02, &[]);
        let _ = a.handle_uplink(&syn_a, "peer-B");
        let _ = b.handle_uplink(&syn_b, "peer-B");
        let id_a = a.stream_ids()[0];
        let id_b = b.stream_ids()[0];
        assert_ne!(
            id_a, id_b,
            "per-instance stream_id seeds must differ (2^-32 collision)"
        );
    }

    #[test]
    fn cross_peer_same_id_dispatch() {
        // F1-residual (deterministic): the same stream_id is used in both
        // directions against this node — we originated `sid` for peer-B,
        // and peer-C sends us a SYN frame with the same id. Dispatch must
        // be by (peer, stream_id): the colliding SYN opens a relay entry
        // keyed (peer-C, sid) and never touches our terminator connection.
        let mut e = TcpEgress::new();
        let syn = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40030, 8080, 8000, 0, 0x02, &[]);
        let _ = e.terminator.handle_uplink(&syn, "peer-B");
        let ids = e.terminator.stream_ids();
        assert_eq!(ids.len(), 1);
        let sid = ids[0];

        // Direction guard: our id for peer-B...
        assert!(e.is_originator_frame(sid, "peer-B"));
        // ...is NOT ours when it arrives from peer-C.
        assert!(!e.is_originator_frame(sid, "peer-C"));

        // Colliding SYN from peer-C opens a peer-namespaced relay entry.
        let addr = echo_server();
        e.relay
            .handle_frame(sid, STREAM_SYN, &syn_payload_for(addr), "peer-C");
        wait_relay_has(&mut e.relay, "peer-C", sid);
        assert!(e.relay.has("peer-C", sid));
        assert!(
            !e.relay.has("peer-B", sid),
            "relay must not shadow our own terminator id"
        );
        // Terminator's own connection is untouched.
        assert_eq!(e.terminator.peer_for(sid).as_deref(), Some("peer-B"));
        assert_eq!(e.terminator.conn_count(), 1);
    }

    #[test]
    fn originator_syn_frame_dropped_not_injected() {
        // W-new: a SYN frame that resolves to our own terminator entry must
        // be dropped and counted — the 6-byte address payload must never be
        // injected into the smoltcp socket as application data.
        let mut term = TcpTerminator::new();
        let syn = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40031, 8080, 9000, 0, 0x02, &[]);
        let _ = term.handle_uplink(&syn, "peer-B");
        let ids = term.stream_ids();
        assert_eq!(ids.len(), 1);
        let sid = ids[0];
        let payload = syn_payload_for("127.0.0.1:1".parse::<SocketAddr>().unwrap());
        let pkts = term.handle_originator_frame(sid, STREAM_SYN, &payload);
        assert!(pkts.is_empty(), "misrouted SYN must produce no TUN packets");
        assert_eq!(term.stats().stream_syn_to_originator_dropped, 1);
        // Connection state untouched: still one conn, no corruption.
        assert_eq!(term.conn_count(), 1);
        // DATA path still works afterwards.
        let _ = term.handle_originator_frame(sid, 0, b"");
        assert_eq!(term.stats().stream_syn_to_originator_dropped, 1);
    }

    /// Payload length of a TUN-bound IPv4/TCP packet.
    fn tun_payload_len(p: &[u8]) -> u64 {
        let tot = u16::from_be_bytes([p[2], p[3]]) as usize;
        let (_, _, _, _, _, off) = parse_tcp(p).unwrap();
        (tot - off) as u64
    }

    fn establish(term: &mut TcpTerminator) -> (u32, u32) {
        // SYN -> SYN-ACK, ACK -> Established. Returns (stream_id, srv_seq).
        // The stream_id is captured from the Syn event (ids are
        // random-seeded since F1-residual, never assume 1).
        let syn = craft_tcp([10, 0, 0, 2], [1, 2, 3, 4], 40002, 8082, 3000, 0, 0x02, &[]);
        let tun_pkts = term.handle_uplink(&syn, "peer-B");
        assert_eq!(tun_pkts.len(), 1);
        let srv_seq = u32::from_be_bytes([
            tun_pkts[0][24],
            tun_pkts[0][25],
            tun_pkts[0][26],
            tun_pkts[0][27],
        ]);
        let ack = craft_tcp(
            [10, 0, 0, 2],
            [1, 2, 3, 4],
            40002,
            8082,
            3001,
            srv_seq + 1,
            0x10,
            &[],
        );
        term.handle_uplink(&ack, "peer-B");
        let mut sid = 0;
        for e in term.poll() {
            if let TcpEvent::Syn { stream_id, .. } = e {
                sid = stream_id;
            }
        }
        assert_ne!(sid, 0, "expected Syn event after handshake");
        (sid, srv_seq)
    }

    #[test]
    fn fabric_data_backpressure_retained() {
        // W1: 64KB of fabric bytes into a 16KB smoltcp send buffer. The
        // excess must be retained (never dropped) and every byte must
        // eventually reach the TUN once the app ACKs.
        let mut term = TcpTerminator::new();
        let (sid, srv_seq) = establish(&mut term);

        let total = 64 * 1024usize;
        let data = vec![0xABu8; total];
        let mut delivered = 0u64;
        let pkts = term.handle_fabric_data(sid, &data);
        delivered += pkts.iter().map(|p| tun_payload_len(p)).sum::<u64>();
        assert!(
            term.stats().send_buffer_full >= 1,
            "expected send-buffer back-pressure"
        );
        let key = term.by_id.get(&sid).copied().unwrap();
        assert!(
            !term.conns.get(&key).unwrap().pending.is_empty(),
            "excess bytes must be retained, not dropped"
        );

        // App ACKs everything it received; retained bytes flush out.
        // (ack = srv_seq+1+delivered: cumulative, like a real TCP app.)
        let mut rounds = 0;
        loop {
            let (pending, sendq) = {
                let c = term.conns.get(&key).unwrap();
                let h = c.sock;
                (
                    c.pending.len(),
                    term.sockets.get::<tcp::Socket>(h).send_queue(),
                )
            };
            if pending == 0 && sendq == 0 {
                break;
            }
            let ack = craft_tcp(
                [10, 0, 0, 2],
                [1, 2, 3, 4],
                40002,
                8082,
                3001,
                srv_seq + 1 + delivered as u32,
                0x10,
                &[],
            );
            let pkts = term.handle_uplink(&ack, "peer-B");
            delivered += pkts.iter().map(|p| tun_payload_len(p)).sum::<u64>();
            for e in term.poll() {
                if let TcpEvent::TunPacket(p) = e {
                    delivered += tun_payload_len(&p);
                }
            }
            rounds += 1;
            assert!(rounds < 200, "drain did not converge");
        }
        assert_eq!(delivered, total as u64, "bytes lost under back-pressure");
    }
}
