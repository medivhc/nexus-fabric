//! Projection layer: L3 tunnel (TUN <-> fabric datagrams) + unified routing.
//!
//! Captures IP packets from a TUN device, classifies each via a [`Router`]
//! ([`RouteTarget`]: `MeshPeer` / `Egress` / `Drop`), and:
//! - `MeshPeer`: encapsulates into fabric datagrams (1-byte intent + raw IP
//!   packet, S2) for mesh forwarding;
//! - `Egress{self}`: records in the local UDP NAT ([`EgressNat`]);
//! - `Egress{peer}`: encapsulates with the egress intent bit for the peer;
//! - `Drop`: counted, not sent (S12).
//!
//! Transport: [`DatagramTransport`] abstracts peer datagram I/O.
//! [`MockTransport`] for tests/E4; [`FabricTransport`] wraps real
//! `nexus-fabric::FabricConn` peers (3b-2).

pub mod dns;
pub mod egress;
pub mod routing;
pub mod semantic;
pub mod tcp;
pub mod transport;
pub mod tun_rs_device;

pub use dns::{
    DEFAULT_DNS_CACHE_ENTRIES, DNS_CACHE_TTL_CAP, DnsCache, DnsSniffer, DnsStats, Sniffed,
    parse_dns_query, parse_dns_response,
};
pub use egress::{
    DEFAULT_MAX_NAT_ENTRIES, DomainMatch, DomainRule, EgressNat, FlowKey, NatStats,
    RealEgressStats, RealUdpEgress, Rule, SimpleRuleEngine,
};
/// Re-exported domain types for unified routing (defined in `nexus-domain`,
/// used — not modified — here).
pub use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
pub use routing::{Cidr, Router, UnifiedRouter, format_ipv4, parse_ipv4_dst};
pub use semantic::{SemanticDeps, SemanticIngress, SemanticStats};
pub use tcp::{TcpEgress, TcpRelayStats, TcpTermStats};
pub use transport::{DatagramTransport, FabricTransport, MockTransport, TransportError};

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::Duration;

/// Intent byte (fabric datagram payload, first byte — DESIGN.md §6.4):
/// bit 0-1 = type (00 = mesh forward, 01 = egress NAT, 10 = TCP byte stream),
/// bit 2-5 = egress hop count (loop protection), bit 6-7 = reserved.
pub const INTENT_MESH: u8 = 0x00;
pub const INTENT_EGRESS: u8 = 0x01;
/// 3b-5 (S22): TCP byte-stream frames (see `tcp::encode_stream_frame`).
pub const INTENT_STREAM: u8 = 0x02;

/// Encode the intent byte.
pub fn encode_intent(is_egress: bool, hops: u8) -> u8 {
    let mut b = if is_egress {
        INTENT_EGRESS
    } else {
        INTENT_MESH
    };
    b |= (hops & 0x0F) << 2;
    b
}

/// Decode the intent byte → (is_egress, hop_count).
pub fn decode_intent(b: u8) -> (bool, u8) {
    ((b & 0x03) == INTENT_EGRESS, (b >> 2) & 0x0F)
}

/// Encode the intent byte with an explicit kind
/// (`INTENT_MESH` / `INTENT_EGRESS` / `INTENT_STREAM`).
pub fn encode_intent_kind(kind: u8, hops: u8) -> u8 {
    (kind & 0x03) | ((hops & 0x0F) << 2)
}

/// Decode the intent byte → (kind, hop_count).
pub fn decode_intent_kind(b: u8) -> (u8, u8) {
    (b & 0x03, (b >> 2) & 0x0F)
}

/// Routing counters (S12: drops are visible, never silent).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RouteStats {
    pub mesh_peer: u64,
    pub egress_self: u64,
    pub egress_remote: u64,
    pub dropped: u64,
    /// S13: egress-intent packets dropped for exceeding `max_egress_hops`.
    pub hop_limit_exceeded: u64,
}

/// Abstraction over a TUN device. Implementations: `MockTun` (E4),
/// `tun_rs_device::TunRsDevice` (E5, real OS device via tun-rs v2).
pub trait TunDevice: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn name(&self) -> &str;
}

/// In-memory mock TUN for E4 (no privileges needed).
///
/// Separate queues model real TUN directionality:
/// - `inject` / `read`: OS -> us (packets the "network stack" gives us)
/// - `write` / `take_written`: us -> OS (packets we deliver to the "stack")
pub struct MockTun {
    read_queue: VecDeque<Vec<u8>>,
    write_queue: VecDeque<Vec<u8>>,
    name: String,
}

impl MockTun {
    pub fn new(name: &str) -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            name: name.to_string(),
        }
    }

    /// Inject a packet as if read from the OS (test helper).
    pub fn inject(&mut self, packet: Vec<u8>) {
        self.read_queue.push_back(packet);
    }

    /// Drain packets written to the (mock) OS. Test/E4 helper.
    pub fn take_written(&mut self) -> Vec<Vec<u8>> {
        self.write_queue.drain(..).collect()
    }
}

impl TunDevice for MockTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.read_queue.pop_front() {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet")),
        }
    }

    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.write_queue.push_back(packet.to_vec());
        Ok(packet.len())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Default for MockTun {
    fn default() -> Self {
        Self::new("mocktun0")
    }
}

/// Configuration for the projection.
#[derive(Debug, Clone)]
pub struct ProjectionConfig {
    /// Max fabric datagram payload. Packets larger than this are dropped (S5).
    pub mtu: usize,
    /// Max egress hops before a packet is dropped (S13, loop protection).
    pub max_egress_hops: u8,
    /// NAT table capacity (S14).
    pub max_nat_entries: usize,
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self {
            mtu: 1400,
            max_egress_hops: 2,
            max_nat_entries: DEFAULT_MAX_NAT_ENTRIES,
        }
    }
}

/// Packet counters (S8: honest, same code for mock and real devices).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub dropped_oversize: u64,
}

/// Error type for projection operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    Oversize { len: usize, mtu: usize },
    Io(String),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectionError::Oversize { len, mtu } => {
                write!(f, "packet too large: {len} > mtu {mtu}")
            }
            ProjectionError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// Lock helper that tolerates poisoning (a panicked thread must not
/// permanently break stats).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Classify a packet via the installed router, or default to mesh when
/// no router is set (legacy raw path). Uses the packet-level entry so
/// DNS-sniffing routers (3b-3, S15/S17) see every packet.
fn classify(router_slot: &Arc<Mutex<Option<Arc<dyn Router>>>>, packet: &[u8]) -> RouteTarget {
    let guard = lock(router_slot);
    match guard.as_ref() {
        Some(r) => r.route_packet(packet),
        None => RouteTarget::MeshPeer {
            peer: "legacy".to_string(),
        },
    }
}

/// Send a packet via the transport with the given intent byte prepended (S2).
///
/// S5: the full datagram (1 intent byte + packet) must fit in `mtu`;
/// oversize datagrams are dropped, counted, and reported — never truncated.
/// Returns `true` if accepted by the transport.
fn send_with_intent(
    transport: &Arc<dyn DatagramTransport>,
    stats: &Arc<Mutex<TunStats>>,
    peer: &str,
    packet: &[u8],
    mtu: usize,
    intent: u8,
) -> bool {
    if packet.len() + 1 > mtu {
        lock(stats).dropped_oversize += 1;
        return false;
    }
    let mut datagram = Vec::with_capacity(packet.len() + 1);
    datagram.push(intent);
    datagram.extend_from_slice(packet);
    // S3: best-effort. If the peer is gone, drop silently.
    if transport.send_to(peer, &datagram).is_ok() {
        let mut s = lock(stats);
        s.packets_out += 1;
        s.bytes_out += packet.len() as u64;
        true
    } else {
        false
    }
}

/// One tcp-poll iteration (3b-5, S21/S22/S23).
///
/// Drives the terminator (harvests `TcpEvent`s) and the relay (harvests
/// `RelayEvent`s), emitting STREAM-intent frames and writing TUN-bound
/// packets. `peer == "self"` loopbacks are delivered directly to the local
/// relay/terminator instead of going through the transport.
fn tcp_poll_once(
    tcp: &Arc<Mutex<TcpEgress>>,
    transport_slot: &Arc<Mutex<Arc<dyn DatagramTransport>>>,
    tun: &Arc<Mutex<Box<dyn TunDevice>>>,
    stats: &Arc<Mutex<TunStats>>,
    mtu: usize,
) {
    use tcp::{STREAM_FIN, STREAM_RST, STREAM_SYN, decode_stream_frame, encode_stream_frame};

    // Helper: emit a STREAM frame to `peer` ("self" = local loopback).
    let emit = |tcp: &Arc<Mutex<TcpEgress>>,
                transport_slot: &Arc<Mutex<Arc<dyn DatagramTransport>>>,
                stats: &Arc<Mutex<TunStats>>,
                peer: &str,
                stream_id: u32,
                flags: u8,
                payload: &[u8]| {
        if peer == "self" {
            // Local loopback: feed directly to the other side.
            let frame = encode_stream_frame(stream_id, flags, payload);
            let (sid, fl, pl) = match decode_stream_frame(&frame) {
                Some(t) => t,
                None => return,
            };
            let mut t = lock(tcp);
            // S25: semantic-ingress originator streams first — a frame from
            // our own relay for a semantic stream must reach the semantic
            // worker, never the terminator or the relay (which would treat
            // us as the stream's egress and corrupt it).
            if let Some(tx) = t.semantic_lookup("self", sid) {
                let _ = tx.try_send((fl, pl.to_vec()));
                return;
            }
            // F1: dispatch by (stream_id, from_peer), not by id alone.
            if t.is_originator_frame(sid, "self") {
                // Originator side (frame came from our own relay). SYN
                // frames are dropped+counted inside (W-new), never injected
                // as application data.
                let pkts = t.terminator.handle_originator_frame(sid, fl, pl);
                drop(t);
                let mut tun = lock(tun);
                for p in pkts {
                    if tun.write(&p).is_ok() {
                        let mut s = lock(stats);
                        s.packets_in += 1;
                        s.bytes_in += p.len() as u64;
                    }
                }
            } else {
                // Egress side.
                let evs = t.relay.handle_frame(sid, fl, pl, "self");
                drop(t);
                // Relay events loop back to the terminator directly.
                for e in evs {
                    handle_relay_event_loopback(tcp, tun, stats, e);
                }
            }
            return;
        }
        let frame = encode_stream_frame(stream_id, flags, payload);
        let transport = lock(transport_slot).clone();
        send_with_intent(
            &transport,
            stats,
            peer,
            &frame,
            mtu,
            encode_intent_kind(INTENT_STREAM, 0),
        );
    };

    // Terminator events.
    let term_events = { lock(tcp).terminator.poll() };
    for ev in term_events {
        match ev {
            tcp::TcpEvent::Syn {
                stream_id,
                dst,
                peer,
            } => {
                // S25: originator always uses the typed SYN form.
                let payload = tcp::encode_syn_payload(&dst.ip().to_string(), dst.port());
                emit(
                    tcp,
                    transport_slot,
                    stats,
                    &peer,
                    stream_id,
                    STREAM_SYN,
                    &payload,
                );
            }
            tcp::TcpEvent::Data {
                stream_id,
                peer,
                bytes,
            } => {
                emit(tcp, transport_slot, stats, &peer, stream_id, 0, &bytes);
            }
            tcp::TcpEvent::Closed {
                stream_id,
                peer,
                reset,
            } => {
                let flags = if reset { STREAM_RST } else { STREAM_FIN };
                emit(tcp, transport_slot, stats, &peer, stream_id, flags, &[]);
            }
            tcp::TcpEvent::TunPacket(pkt) => {
                let mut tun = lock(tun);
                if tun.write(&pkt).is_ok() {
                    let mut s = lock(stats);
                    s.packets_in += 1;
                    s.bytes_in += pkt.len() as u64;
                }
            }
        }
    }

    // Relay events.
    let relay_events = { lock(tcp).relay.poll() };
    for ev in relay_events {
        match ev {
            tcp::RelayEvent::Data {
                stream_id,
                peer,
                bytes,
            } => {
                emit(tcp, transport_slot, stats, &peer, stream_id, 0, &bytes);
            }
            tcp::RelayEvent::Closed {
                stream_id,
                peer,
                reset,
            } => {
                let flags = if reset { STREAM_RST } else { STREAM_FIN };
                emit(tcp, transport_slot, stats, &peer, stream_id, flags, &[]);
            }
        }
    }
}

/// Handle an inbound STREAM-intent datagram (3b-5, S22).
///
/// Dispatches by table lookup: stream_id known to the terminator → we are
/// the originator (feed bytes into smoltcp, write TUN packets); otherwise
/// we are the egress (relay the frame to the `TcpStream`). Immediate relay
/// events (e.g. connect-failure RST) are sent back via the transport.
fn handle_stream_datagram(
    tcp_egress_slot: &Arc<Mutex<Option<Arc<Mutex<TcpEgress>>>>>,
    transport_slot: &Arc<Mutex<Arc<dyn DatagramTransport>>>,
    tun: &Arc<Mutex<Box<dyn TunDevice>>>,
    stats: &Arc<Mutex<TunStats>>,
    from_peer: &str,
    frame: &[u8],
    mtu: usize,
) {
    use tcp::{STREAM_FIN, STREAM_RST};
    let tcp = match lock(tcp_egress_slot).clone() {
        Some(t) => t,
        None => return, // TCP egress not enabled: drop.
    };
    let (stream_id, flags, payload) = match tcp::decode_stream_frame(frame) {
        Some(t) => t,
        None => return,
    };
    // Originator? F1: compare the frame's from_peer against the peer the
    // stream was originated for — id-only lookup misroutes dual-role nodes.
    // SYN frames are dropped+counted inside handle_originator_frame (W-new).
    let is_originator = { lock(&tcp).is_originator_frame(stream_id, from_peer) };
    if is_originator {
        let pkts = {
            lock(&tcp)
                .terminator
                .handle_originator_frame(stream_id, flags, payload)
        };
        let mut tun = lock(tun);
        for p in pkts {
            if tun.write(&p).is_ok() {
                let mut s = lock(stats);
                s.packets_in += 1;
                s.bytes_in += p.len() as u64;
            }
        }
        return;
    }
    // Egress side.
    // S25: semantic-ingress originator streams (byte-stream clients, not the
    // smoltcp terminator). Keyed by (peer, stream_id) per the F1 lesson.
    // Checked before the relay: a semantic stream id must never be fed to
    // the relay as if we were its egress.
    let sem_tx = { lock(&tcp).semantic_lookup(from_peer, stream_id) };
    if let Some(tx) = sem_tx {
        // S3 best-effort: full or dead channel → drop the frame.
        let _ = tx.try_send((flags, payload.to_vec()));
        return;
    }
    let events = {
        lock(&tcp)
            .relay
            .handle_frame(stream_id, flags, payload, from_peer)
    };
    // Immediate events (connect failure → RST) go back over the transport.
    for ev in events {
        let (sid, peer, flags, payload) = match ev {
            tcp::RelayEvent::Data {
                stream_id,
                peer,
                bytes,
            } => (stream_id, peer, 0u8, bytes),
            tcp::RelayEvent::Closed {
                stream_id,
                peer,
                reset,
            } => (
                stream_id,
                peer,
                if reset { STREAM_RST } else { STREAM_FIN },
                vec![],
            ),
        };
        let frame = tcp::encode_stream_frame(sid, flags, &payload);
        let transport = lock(transport_slot).clone();
        send_with_intent(
            &transport,
            stats,
            &peer,
            &frame,
            mtu,
            encode_intent_kind(INTENT_STREAM, 0),
        );
    }
}

/// Feed a TUN TCP packet routed to egress into the smoltcp terminator
/// (3b-5, S21); write the stack's replies back to the TUN.
fn handle_tcp_uplink_packet(
    tcp_egress_slot: &Arc<Mutex<Option<Arc<Mutex<TcpEgress>>>>>,
    tun: &Arc<Mutex<Box<dyn TunDevice>>>,
    stats: &Arc<Mutex<TunStats>>,
    route_stats: &Arc<Mutex<RouteStats>>,
    pkt: &[u8],
    peer: &str,
    pkt_len: usize,
) {
    let tun_pkts = {
        let tcp = match lock(tcp_egress_slot).clone() {
            Some(t) => t,
            None => return,
        };
        lock(&tcp).terminator.handle_uplink(pkt, peer)
    };
    {
        let mut tun = lock(tun);
        for p in tun_pkts {
            if tun.write(&p).is_ok() {
                let mut s = lock(stats);
                s.packets_in += 1;
                s.bytes_in += p.len() as u64;
            }
        }
    }
    lock(route_stats).egress_remote += 1;
    let mut s = lock(stats);
    s.packets_out += 1;
    s.bytes_out += pkt_len as u64;
}

/// Deliver a relay-side event back to the local terminator ("self"
/// loopback path).
fn handle_relay_event_loopback(
    tcp: &Arc<Mutex<TcpEgress>>,
    tun: &Arc<Mutex<Box<dyn TunDevice>>>,
    stats: &Arc<Mutex<TunStats>>,
    ev: tcp::RelayEvent,
) {
    let mut t = lock(tcp);
    let pkts = match ev {
        tcp::RelayEvent::Data {
            stream_id, bytes, ..
        } => t.terminator.handle_fabric_data(stream_id, &bytes),
        tcp::RelayEvent::Closed {
            stream_id, reset, ..
        } => {
            if reset {
                t.terminator.handle_fabric_rst(stream_id)
            } else {
                t.terminator.handle_fabric_fin(stream_id)
            }
        }
    };
    drop(t);
    let mut tun = lock(tun);
    for p in pkts {
        if tun.write(&p).is_ok() {
            let mut s = lock(stats);
            s.packets_in += 1;
            s.bytes_in += p.len() as u64;
        }
    }
}
///
/// Four background threads (owner: this struct, joined on `close`/`Drop`):
/// - uplink: TUN.read -> route -> MTU check -> transport / local NAT / drop
/// - downlink: transport.recv -> hop validation (S13) -> TUN.write or NAT
///   (+ real socket egress when enabled, S18; + STREAM frames, S22)
/// - egress-recv: real socket replies -> reverse NAT -> transport back to
///   the origin peer with mesh intent (S19), or to the local TUN for
///   `Egress{self}`.
/// - tcp-poll: drives the smoltcp terminator and the TcpStream relay
///   (3b-5, S21/S22/S23): harvests byte-stream events and emits STREAM
///   frames, delivers TUN-bound packets.
///
/// `send_packet` is the test/E4 injection path (same routing + MTU check as
/// the uplink thread). `recv_packet` polls the transport directly and is
/// only available on thread-less instances (see `new_for_test`); with threads
/// running, the downlink thread owns the transport inbox.
pub struct Projection {
    config: ProjectionConfig,
    /// Datagram transport (shared slot; injected via `with_transport`,
    /// visible to already-spawned threads — same pattern as the router).
    transport_slot: Arc<Mutex<Arc<dyn DatagramTransport>>>,
    /// Concrete mock transport, when created via `new` (for `link_mock_peer`).
    mock_transport: Option<Arc<MockTransport>>,
    /// TUN device, shared with the background threads (also used by
    /// `handle_egress_reply` to deliver mock replies in E4).
    tun: Arc<Mutex<Box<dyn TunDevice>>>,
    /// Unified router (`None` = legacy raw path, everything is mesh).
    /// Shared slot so `with_router` (builder, runs after `new`) is visible
    /// to the already-spawned background threads.
    router_slot: Arc<Mutex<Option<Arc<dyn Router>>>>,
    route_stats: Arc<Mutex<RouteStats>>,
    /// Local egress NAT for `Egress{self}` (and inbound egress handling).
    egress_nat: Arc<Mutex<EgressNat>>,
    /// Real UDP egress (3b-4, S18/S19/S20). Shared slot so the downlink and
    /// egress-recv threads (spawned in `new`) see the builder-installed
    /// instance — same pattern as `router_slot` / `transport_slot`.
    real_egress_slot: Arc<Mutex<Option<Arc<RealUdpEgress>>>>,
    /// TCP egress (3b-5, S21/S22/S23): smoltcp terminator + TcpStream relay.
    /// Shared slot; the tcp-poll thread (spawned in `new`) sees the
    /// builder-installed instance. Inner `Mutex` because the uplink,
    /// downlink and tcp-poll threads all drive it.
    tcp_egress_slot: Arc<Mutex<Option<Arc<Mutex<TcpEgress>>>>>,
    stats: Arc<Mutex<TunStats>>,
    path_switches: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    uplink: Option<thread::JoinHandle<()>>,
    downlink: Option<thread::JoinHandle<()>>,
    egress_recv: Option<thread::JoinHandle<()>>,
    tcp_poll: Option<thread::JoinHandle<()>>,
}

impl Projection {
    pub fn new(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self {
        let transport = Arc::new(MockTransport::new("local"));
        // Self-link: single-projection E4 (e.g. egress_basic) expects mesh
        // packets to loop back, mirroring the 3b-1 mpsc loopback.
        transport.link_peer("self", transport.inbox_sender());
        Self::new_inner(tun, config, transport.clone(), Some(transport), true)
    }

    /// Build with an explicit transport (e.g. [`FabricTransport`] for real
    /// fabric). The already-spawned threads pick it up through the shared
    /// slot. No mock linking is available in this mode.
    pub fn with_transport(mut self, transport: Arc<dyn DatagramTransport>) -> Self {
        *lock(&self.transport_slot) = transport;
        self.mock_transport = None;
        self
    }

    fn new_inner(
        tun: Box<dyn TunDevice>,
        config: ProjectionConfig,
        transport: Arc<dyn DatagramTransport>,
        mock_transport: Option<Arc<MockTransport>>,
        spawn_threads: bool,
    ) -> Self {
        let stats = Arc::new(Mutex::new(TunStats::default()));
        let path_switches = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let tun = Arc::new(Mutex::new(tun));
        let mtu = config.mtu;
        let max_hops = config.max_egress_hops;
        let route_stats = Arc::new(Mutex::new(RouteStats::default()));
        let egress_nat = Arc::new(Mutex::new(EgressNat::new(config.max_nat_entries)));
        // Router is installed later via `with_router`; the threads read it
        // through this shared slot so the builder can run before or after
        // `new` (threads only start in `new`, builder runs before that).
        let router: Arc<Mutex<Option<Arc<dyn Router>>>> = Arc::new(Mutex::new(None));
        // Transport slot: same pattern — `with_transport` updates it and
        // the threads see the new transport.
        let transport_slot: Arc<Mutex<Arc<dyn DatagramTransport>>> =
            Arc::new(Mutex::new(transport));
        // Real-egress slot: `with_real_egress` (builder, runs after `new`)
        // installs the instance; the downlink and egress-recv threads read
        // it through this shared slot.
        let real_egress_slot: Arc<Mutex<Option<Arc<RealUdpEgress>>>> = Arc::new(Mutex::new(None));
        // TCP-egress slot: `with_tcp_egress` (builder) installs the
        // instance; the uplink, downlink and tcp-poll threads read it
        // through this shared slot.
        let tcp_egress_slot: Arc<Mutex<Option<Arc<Mutex<TcpEgress>>>>> = Arc::new(Mutex::new(None));

        let (uplink, downlink, egress_recv, tcp_poll) = if spawn_threads {
            // Uplink: TUN -> route -> transport / local NAT / drop.
            let up = {
                let tun = Arc::clone(&tun);
                let transport_slot = Arc::clone(&transport_slot);
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                let router = Arc::clone(&router);
                let route_stats = Arc::clone(&route_stats);
                let egress_nat = Arc::clone(&egress_nat);
                let real_egress_slot = Arc::clone(&real_egress_slot);
                let tcp_egress_slot = Arc::clone(&tcp_egress_slot);
                thread::Builder::new()
                    .name("projection-uplink".into())
                    .spawn(move || {
                        let mut buf = vec![0u8; mtu.max(1500) + 64];
                        while !shutdown.load(Ordering::Relaxed) {
                            let n = {
                                let mut tun = lock(&tun);
                                match tun.read(&mut buf) {
                                    Ok(n) => n,
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                        drop(tun);
                                        thread::sleep(Duration::from_millis(1));
                                        continue;
                                    }
                                    Err(_) => {
                                        drop(tun);
                                        thread::sleep(Duration::from_millis(10));
                                        continue;
                                    }
                                }
                            };
                            let pkt = &buf[..n];
                            // Route first (S9/S10/S12).
                            let target = classify(&router, pkt);
                            // 3b-5 (S21): TCP packets routed to egress go to
                            // the smoltcp terminator when enabled, not the
                            // UDP NAT / raw forward path.
                            let is_tcp_egress = matches!(target, RouteTarget::Egress { .. })
                                && tcp::parse_tcp(pkt).is_some()
                                && lock(&tcp_egress_slot).is_some();
                            if is_tcp_egress {
                                let peer = match target {
                                    RouteTarget::Egress { ref peer } => peer.clone(),
                                    _ => unreachable!(),
                                };
                                handle_tcp_uplink_packet(
                                    &tcp_egress_slot,
                                    &tun,
                                    &stats,
                                    &route_stats,
                                    pkt,
                                    &peer,
                                    n,
                                );
                                continue;
                            }
                            match target {
                                RouteTarget::Drop => {
                                    lock(&route_stats).dropped += 1;
                                    continue;
                                }
                                RouteTarget::Egress { ref peer } => {
                                    if peer == "self" {
                                        lock(&route_stats).egress_self += 1;
                                        // Local egress: real socket when
                                        // enabled (S18, records the flow
                                        // under the translated key),
                                        // otherwise the mock record-only
                                        // path (older E4s).
                                        match lock(&real_egress_slot).clone() {
                                            Some(re) => {
                                                re.send(pkt, "self");
                                            }
                                            None => {
                                                lock(&egress_nat).translate_outbound(pkt, peer);
                                            }
                                        }
                                        let mut s = lock(&stats);
                                        s.packets_out += 1;
                                        s.bytes_out += n as u64;
                                        continue;
                                    }
                                    lock(&route_stats).egress_remote += 1;
                                    // Originator tracks the flow for reply
                                    // validation (S11), regardless of where
                                    // the actual internet egress happens.
                                    lock(&egress_nat).translate_outbound(pkt, peer);
                                    // Remote egress: forward via transport.
                                    // Originator sets hops=0 (S13).
                                    let transport = lock(&transport_slot).clone();
                                    if !send_with_intent(
                                        &transport,
                                        &stats,
                                        peer,
                                        pkt,
                                        mtu,
                                        encode_intent(true, 0),
                                    ) {
                                        continue;
                                    }
                                }
                                RouteTarget::MeshPeer { ref peer } => {
                                    lock(&route_stats).mesh_peer += 1;
                                    let transport = lock(&transport_slot).clone();
                                    if !send_with_intent(
                                        &transport,
                                        &stats,
                                        peer,
                                        pkt,
                                        mtu,
                                        encode_intent(false, 0),
                                    ) {
                                        continue;
                                    }
                                }
                            }
                        }
                    })
                    .expect("spawn projection uplink")
            };
            // Downlink: transport -> hop validation (S13) -> TUN.write or NAT.
            let down = {
                let tun = Arc::clone(&tun);
                let transport_slot = Arc::clone(&transport_slot);
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                let route_stats = Arc::clone(&route_stats);
                let egress_nat = Arc::clone(&egress_nat);
                let real_egress_slot = Arc::clone(&real_egress_slot);
                let tcp_egress_slot = Arc::clone(&tcp_egress_slot);
                // F1 fix: the downlink must see the router so DNS responses
                // arriving via transport feed the DnsCache (S17). The routing
                // decision itself is discarded — the packet is already here,
                // we only want the sniffing/learning side effect.
                let router = Arc::clone(&router);
                thread::Builder::new()
                    .name("projection-downlink".into())
                    .spawn(move || {
                        while !shutdown.load(Ordering::Relaxed) {
                            let transport = lock(&transport_slot).clone();
                            match transport.recv() {
                                Some((from_peer, datagram)) => {
                                    // S2: strip the 1-byte intent; the rest is
                                    // the raw IP packet.
                                    let (intent_byte, pkt) = match datagram.split_first() {
                                        Some((b, rest)) => (*b, rest),
                                        None => continue, // empty datagram: drop
                                    };
                                    let (kind, hops) = decode_intent_kind(intent_byte);
                                    if kind == INTENT_STREAM {
                                        // 3b-5 (S22): TCP byte-stream frame.
                                        handle_stream_datagram(
                                            &tcp_egress_slot,
                                            &transport_slot,
                                            &tun,
                                            &stats,
                                            &from_peer,
                                            pkt,
                                            mtu,
                                        );
                                        let mut s = lock(&stats);
                                        s.packets_in += 1;
                                        s.bytes_in += pkt.len() as u64;
                                        continue;
                                    }
                                    let is_egress = kind == INTENT_EGRESS;
                                    if is_egress {
                                        // S13: validate hop count before
                                        // handling (loop protection).
                                        if hops > max_hops {
                                            lock(&route_stats).hop_limit_exceeded += 1;
                                            continue;
                                        }
                                        // We are the egress node. 3b-4
                                        // (S18): forward via the real socket
                                        // when enabled (records the flow
                                        // under the translated key);
                                        // otherwise the record-only mock
                                        // path — E4 drives replies via
                                        // `handle_egress_reply`.
                                        match lock(&real_egress_slot).clone() {
                                            Some(re) => {
                                                re.send(pkt, &from_peer);
                                            }
                                            None => {
                                                lock(&egress_nat)
                                                    .translate_outbound(pkt, &from_peer);
                                            }
                                        }
                                        let mut s = lock(&stats);
                                        s.packets_in += 1;
                                        s.bytes_in += pkt.len() as u64;
                                    } else {
                                        // Mesh forward, or an egress reply
                                        // returning: validate via NAT when
                                        // tracked, then deliver to TUN.
                                        // S17: run the packet through the
                                        // router for DNS learning (response
                                        // -> DnsCache). The decision is
                                        // discarded; delivery was already
                                        // determined by the sender.
                                        {
                                            let guard = lock(&router);
                                            if let Some(r) = guard.as_ref() {
                                                let _ = r.route_packet(pkt);
                                            }
                                        }
                                        let is_reply = lock(&egress_nat).peek_reply(pkt).is_some();
                                        if is_reply {
                                            lock(&egress_nat).translate_inbound(pkt);
                                        }
                                        let mut tun = lock(&tun);
                                        if tun.write(pkt).is_ok() {
                                            let mut s = lock(&stats);
                                            s.packets_in += 1;
                                            s.bytes_in += pkt.len() as u64;
                                        }
                                    }
                                }
                                None => {
                                    thread::sleep(Duration::from_millis(1));
                                    continue;
                                }
                            }
                        }
                    })
                    .expect("spawn projection downlink")
            };
            // Egress-recv (3b-4, S19/S20): real socket replies -> reverse
            // NAT -> back to the origin peer with mesh intent, or to the
            // local TUN for `Egress{self}`. Polls `recv_reply`; exits on
            // shutdown so `close` can join it (S20).
            let er = {
                let real_egress_slot = Arc::clone(&real_egress_slot);
                let transport_slot = Arc::clone(&transport_slot);
                let tun = Arc::clone(&tun);
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                let router = Arc::clone(&router);
                thread::Builder::new()
                    .name("projection-egress-recv".into())
                    .spawn(move || {
                        while !shutdown.load(Ordering::Relaxed) {
                            let re = lock(&real_egress_slot).clone();
                            match re {
                                None => {
                                    thread::sleep(Duration::from_millis(10));
                                    continue;
                                }
                                Some(re) => match re.recv_reply() {
                                    Some((ip_packet, peer)) => {
                                        // S17 (review WARN-3 fix): run the
                                        // reply through the router for DNS
                                        // learning (response -> DnsCache).
                                        // Decision discarded; delivery is
                                        // already determined by NAT lookup.
                                        {
                                            let guard = lock(&router);
                                            if let Some(r) = guard.as_ref() {
                                                let _ = r.route_packet(&ip_packet);
                                            }
                                        }
                                        if peer == "self" {
                                            // Local egress origin: deliver
                                            // to the TUN directly.
                                            let mut tun = lock(&tun);
                                            if tun.write(&ip_packet).is_ok() {
                                                let mut s = lock(&stats);
                                                s.packets_in += 1;
                                                s.bytes_in += ip_packet.len() as u64;
                                            }
                                        } else {
                                            // S19: mesh intent back to the
                                            // originator; its downlink
                                            // NAT-validates it (S11).
                                            let transport = lock(&transport_slot).clone();
                                            send_with_intent(
                                                &transport,
                                                &stats,
                                                &peer,
                                                &ip_packet,
                                                mtu,
                                                encode_intent(false, 0),
                                            );
                                        }
                                    }
                                    None => {
                                        thread::sleep(Duration::from_millis(1));
                                    }
                                },
                            }
                        }
                    })
                    .expect("spawn projection egress-recv")
            };
            // tcp-poll (3b-5, S21/S22/S23): drives the smoltcp terminator
            // and the TcpStream relay. Harvests byte-stream events and
            // emits STREAM frames; delivers TUN-bound packets. Exits on
            // shutdown so `close` can join it.
            let tp = {
                let tcp_egress_slot = Arc::clone(&tcp_egress_slot);
                let transport_slot = Arc::clone(&transport_slot);
                let tun = Arc::clone(&tun);
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);
                thread::Builder::new()
                    .name("projection-tcp-poll".into())
                    .spawn(move || {
                        while !shutdown.load(Ordering::Relaxed) {
                            let tcp = lock(&tcp_egress_slot).clone();
                            match tcp {
                                None => {
                                    thread::sleep(Duration::from_millis(10));
                                    continue;
                                }
                                Some(tcp) => {
                                    tcp_poll_once(&tcp, &transport_slot, &tun, &stats, mtu);
                                    thread::sleep(Duration::from_millis(10));
                                }
                            }
                        }
                    })
                    .expect("spawn projection tcp-poll")
            };
            (Some(up), Some(down), Some(er), Some(tp))
        } else {
            (None, None, None, None)
        };

        Self {
            config,
            transport_slot,
            mock_transport,
            tun,
            router_slot: router,
            route_stats,
            egress_nat,
            real_egress_slot,
            tcp_egress_slot,
            stats,
            path_switches,
            shutdown,
            uplink,
            downlink,
            egress_recv,
            tcp_poll,
        }
    }

    /// Test helper: create without background threads, so `send_packet` /
    /// `recv_packet` have exclusive access to the transport.
    #[cfg(test)]
    fn new_for_test(tun: Box<dyn TunDevice>, config: ProjectionConfig) -> Self {
        let transport = Arc::new(MockTransport::new("test"));
        // Self-link so `send_packet` loopback works (single-peer fallback).
        transport.link_peer("self", transport.inbox_sender());
        Self::new_inner(tun, config, transport.clone(), Some(transport), false)
    }

    /// Test/E4 helper: link this projection's mock transport to a peer's.
    /// Both projections must have been created via `new` (mock transport).
    /// Panics if a custom transport was injected via `with_transport`.
    /// Removes any "self" loopback link (from `new_for_test`) so the named
    /// peer takes precedence.
    pub fn link_mock_peer(&mut self, peer_name: &str, peer: &Projection) {
        let my_mock = self
            .mock_transport
            .as_ref()
            .expect("link_mock_peer requires mock transport");
        let peer_mock = peer
            .mock_transport
            .as_ref()
            .expect("link_mock_peer requires mock transport on peer");
        my_mock.unlink_peer("self");
        my_mock.link_peer(peer_name, peer_mock.inbox_sender());
    }

    /// This projection's mock transport (for `link_mock_peer`).
    pub fn mock_transport(&self) -> Option<&Arc<MockTransport>> {
        self.mock_transport.as_ref()
    }

    /// Build the [`SemanticDeps`] for a [`SemanticIngress`] owned alongside
    /// this projection (S25). Returns `None` when no router is installed.
    pub fn semantic_deps(&self) -> Option<SemanticDeps> {
        let router = lock(&self.router_slot).clone()?;
        Some(SemanticDeps {
            router,
            tcp_egress: Arc::clone(&self.tcp_egress_slot),
            transport: Arc::clone(&self.transport_slot),
            mtu: self.config.mtu,
        })
    }

    /// Handle a path-switch event from `nexus-path`.
    ///
    /// P0: records the event. The mock fabric channel is unaffected, so packet
    /// flow continues uninterrupted (S3 best-effort).
    /// Future: trigger `FabricConn` rebind / path migration here.
    pub fn on_path_event(&mut self) {
        self.path_switches.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of path-switch events handled.
    pub fn path_switch_count(&self) -> u64 {
        self.path_switches.load(Ordering::Relaxed)
    }

    /// Install the unified router (builder). The already-spawned uplink
    /// thread and `send_packet` pick it up through the shared slot.
    /// Takes `Arc` so drivers can keep a handle (e.g. for `dns_stats`).
    pub fn with_router(self, router: Arc<dyn Router>) -> Self {
        *lock(&self.router_slot) = Some(router);
        self
    }

    /// Enable real UDP egress (3b-4, S18/S19/S20). Builds the egress from
    /// this projection's shared NAT table and makes it visible to the
    /// downlink and egress-recv threads. Fails when UDP is unavailable
    /// (callers map this to SKIP, not FAIL).
    pub fn with_real_egress(self) -> io::Result<Self> {
        let re = RealUdpEgress::new(Arc::clone(&self.egress_nat))?;
        *lock(&self.real_egress_slot) = Some(Arc::new(re));
        Ok(self)
    }

    /// Real-egress counters (S18/S19), or `None` when not enabled.
    pub fn real_egress_stats(&self) -> Option<RealEgressStats> {
        lock(&self.real_egress_slot).as_ref().map(|re| re.stats())
    }

    /// Enable TCP egress (3b-5, S21/S22/S23). Installs the terminator+relay
    /// and makes it visible to the uplink, downlink and tcp-poll threads.
    pub fn with_tcp_egress(self) -> Self {
        *lock(&self.tcp_egress_slot) = Some(Arc::new(Mutex::new(TcpEgress::new())));
        self
    }

    /// TCP terminator counters (S21/S23), or `None` when not enabled.
    pub fn tcp_term_stats(&self) -> Option<TcpTermStats> {
        lock(&self.tcp_egress_slot)
            .as_ref()
            .map(|t| lock(t).terminator.stats())
    }

    /// TCP relay counters (S22), or `None` when not enabled.
    pub fn tcp_relay_stats(&self) -> Option<TcpRelayStats> {
        lock(&self.tcp_egress_slot)
            .as_ref()
            .map(|t| lock(t).relay.stats())
    }

    /// Live TCP connections (terminator + relay), or `None` when disabled.
    pub fn tcp_conn_count(&self) -> Option<usize> {
        lock(&self.tcp_egress_slot)
            .as_ref()
            .map(|t| lock(t).conn_count())
    }

    /// Bound addresses of live egress flow sockets (E4 probing, S19).
    pub fn real_egress_socket_addrs(&self) -> Vec<SocketAddr> {
        lock(&self.real_egress_slot)
            .as_ref()
            .map(|re| re.socket_addrs())
            .unwrap_or_default()
    }

    /// Routing counters (S12).
    pub fn route_stats(&self) -> RouteStats {
        *lock(&self.route_stats)
    }

    /// Local egress NAT counters (S11).
    pub fn nat_stats(&self) -> NatStats {
        lock(&self.egress_nat).stats()
    }

    /// Feed a mock "internet" reply through the egress NAT (E4/test helper).
    ///
    /// If the reply's 5-tuple matches a tracked outbound flow:
    /// - origin peer is "self": write to the TUN, return `true`;
    /// - origin peer is remote: forward back via the transport with mesh
    ///   intent (the originator's downlink validates it via NAT, S11).
    ///
    /// Returns `false` if the reply matches no tracked flow.
    /// Production uses real egress sockets instead of this method.
    pub fn handle_egress_reply(&self, reply: &[u8]) -> bool {
        let (packet, peer) = {
            let mut nat = lock(&self.egress_nat);
            match nat.translate_inbound(reply) {
                Some((p, peer)) => (p, peer),
                None => return false,
            }
        };
        if peer == "self" {
            let mut tun = lock(&self.tun);
            if tun.write(&packet).is_ok() {
                let mut s = lock(&self.stats);
                s.packets_in += 1;
                s.bytes_in += packet.len() as u64;
                true
            } else {
                false
            }
        } else {
            // Remote originator: send the reply back via the transport.
            // Mesh intent: the originator's downlink NAT-validates it (S11).
            let mut datagram = Vec::with_capacity(packet.len() + 1);
            datagram.push(encode_intent(false, 0));
            datagram.extend_from_slice(&packet);
            if datagram.len() > self.config.mtu {
                lock(&self.stats).dropped_oversize += 1;
                return false;
            }
            let transport = lock(&self.transport_slot).clone();
            if transport.send_to(&peer, &datagram).is_ok() {
                let mut s = lock(&self.stats);
                s.packets_out += 1;
                s.bytes_out += packet.len() as u64;
                true
            } else {
                false
            }
        }
    }

    /// Inject a packet to send (test/E4 path; production uses the TUN).
    ///
    /// Routes via the installed router (S9/S10/S12); S5 oversize datagrams
    /// are dropped, counted, and reported — never truncated or fragmented.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), ProjectionError> {
        let target = classify(&self.router_slot, packet);
        // 3b-5 (S21): mirror the uplink thread — TCP to egress goes to the
        // smoltcp terminator when enabled.
        if matches!(target, RouteTarget::Egress { .. })
            && tcp::parse_tcp(packet).is_some()
            && lock(&self.tcp_egress_slot).is_some()
        {
            let peer = match target {
                RouteTarget::Egress { ref peer } => peer.clone(),
                _ => unreachable!(),
            };
            handle_tcp_uplink_packet(
                &self.tcp_egress_slot,
                &self.tun,
                &self.stats,
                &self.route_stats,
                packet,
                &peer,
                packet.len(),
            );
            return Ok(());
        }
        match target {
            RouteTarget::Drop => {
                lock(&self.route_stats).dropped += 1;
                Ok(())
            }
            RouteTarget::Egress { ref peer } => {
                if peer == "self" {
                    lock(&self.route_stats).egress_self += 1;
                } else {
                    lock(&self.route_stats).egress_remote += 1;
                }
                // Originator tracks the flow for reply validation (S11).
                lock(&self.egress_nat).translate_outbound(packet, peer);
                if peer == "self" {
                    let mut s = lock(&self.stats);
                    s.packets_out += 1;
                    s.bytes_out += packet.len() as u64;
                    return Ok(());
                }
                let transport = lock(&self.transport_slot).clone();
                if send_with_intent(
                    &transport,
                    &self.stats,
                    peer,
                    packet,
                    self.config.mtu,
                    encode_intent(true, 0),
                ) {
                    Ok(())
                } else if packet.len() + 1 > self.config.mtu {
                    Err(ProjectionError::Oversize {
                        len: packet.len() + 1,
                        mtu: self.config.mtu,
                    })
                } else {
                    // S3: best-effort; peer gone.
                    Err(ProjectionError::Io("transport send failed".into()))
                }
            }
            RouteTarget::MeshPeer { ref peer } => {
                lock(&self.route_stats).mesh_peer += 1;
                let transport = lock(&self.transport_slot).clone();
                if send_with_intent(
                    &transport,
                    &self.stats,
                    peer,
                    packet,
                    self.config.mtu,
                    encode_intent(false, 0),
                ) {
                    Ok(())
                } else if packet.len() + 1 > self.config.mtu {
                    Err(ProjectionError::Oversize {
                        len: packet.len() + 1,
                        mtu: self.config.mtu,
                    })
                } else {
                    // S3: best-effort; peer gone.
                    Err(ProjectionError::Io("transport send failed".into()))
                }
            }
        }
    }

    /// Take a received packet (thread-less test instances only).
    ///
    /// Strips the 1-byte intent (S2); the returned bytes are the raw IP packet.
    /// Applies S13 hop validation for egress-intent packets.
    pub fn recv_packet(&mut self) -> Option<Vec<u8>> {
        let transport = lock(&self.transport_slot).clone();
        let (_from_peer, datagram) = transport.recv()?;
        let (intent_byte, pkt) = match datagram.split_first() {
            Some((b, rest)) => (*b, rest),
            None => return None, // empty datagram: drop
        };
        let (is_egress, hops) = decode_intent(intent_byte);
        if is_egress {
            // S13: hop validation (same as the downlink thread).
            if hops > self.config.max_egress_hops {
                lock(&self.route_stats).hop_limit_exceeded += 1;
                return None;
            }
            // Track for reply routing; the caller handles the packet.
            lock(&self.egress_nat).translate_outbound(pkt, &_from_peer);
        } else if lock(&self.egress_nat).peek_reply(pkt).is_some() {
            lock(&self.egress_nat).translate_inbound(pkt);
        }
        let mut s = lock(&self.stats);
        s.packets_in += 1;
        s.bytes_in += pkt.len() as u64;
        Some(pkt.to_vec())
    }

    pub fn stats(&self) -> TunStats {
        *lock(&self.stats)
    }

    /// Stop background threads and drop unsent packets (S7).
    pub fn close(mut self) {
        self.shutdown_threads();
    }

    fn shutdown_threads(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.uplink.take() {
            let _ = h.join();
        }
        if let Some(h) = self.downlink.take() {
            let _ = h.join();
        }
        if let Some(h) = self.egress_recv.take() {
            let _ = h.join();
        }
        if let Some(h) = self.tcp_poll.take() {
            let _ = h.join();
        }
        // S20: drop the real egress after the threads using it have joined,
        // closing all flow sockets.
        *lock(&self.real_egress_slot) = None;
        // S23: drop the TCP egress after the threads joined.
        *lock(&self.tcp_egress_slot) = None;
    }
}

impl Drop for Projection {
    fn drop(&mut self) {
        self.shutdown_threads();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_tun_separate_queues() {
        let mut tun = MockTun::new("test0");
        // inject -> read path
        let pkt = vec![0x45, 0x00, 0x00, 0x14];
        tun.inject(pkt.clone());
        let mut buf = [0u8; 1500];
        let n = tun.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &pkt[..]);
        // write -> take_written path (does NOT loop back to read)
        tun.write(&pkt).unwrap();
        assert!(tun.read(&mut buf).is_err());
        let written = tun.take_written();
        assert_eq!(written, vec![pkt]);
    }

    #[test]
    fn s1_packet_integrity_loopback() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        // Unlinked: to_net loops back to own from_net.
        let pkt: Vec<u8> = (0..100).map(|i| (i * 7 % 256) as u8).collect();
        p.send_packet(&pkt).unwrap();
        let got = p.recv_packet().expect("loopback packet");
        assert_eq!(got, pkt);
    }

    #[test]
    fn s5_oversize_dropped_and_counted() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(
            tun,
            ProjectionConfig {
                mtu: 100,
                ..Default::default()
            },
        );
        let big = vec![0u8; 101];
        // S2: datagram = 1 intent byte + packet = 102 > mtu 100.
        let err = p.send_packet(&big).unwrap_err();
        assert_eq!(err, ProjectionError::Oversize { len: 102, mtu: 100 });
        assert_eq!(p.stats().dropped_oversize, 1);
        assert_eq!(p.stats().packets_out, 0);
        // Largest fitting packet: 99 + 1 intent = 100 <= mtu.
        let exact = vec![0u8; 99];
        p.send_packet(&exact).unwrap();
        assert_eq!(p.stats().packets_out, 1);
    }

    #[test]
    fn s2_intent_byte_overhead() {
        // S2 (revised §6.4): datagram = 1-byte intent + raw IP packet.
        assert_eq!(encode_intent(false, 0), 0x00);
        assert_eq!(encode_intent(true, 0), 0x01);
        assert_eq!(encode_intent(true, 3), 0x01 | (3 << 2));
        assert_eq!(decode_intent(0x00), (false, 0));
        assert_eq!(decode_intent(0x01), (true, 0));
        assert_eq!(decode_intent(0x0D), (true, 3));

        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        // Minimal IPv4 header (20 bytes).
        let pkt = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        ];
        p.send_packet(&pkt).unwrap();
        let got = p.recv_packet().unwrap();
        // Intent stripped on receive: the IP packet is byte-identical.
        assert_eq!(got.len(), pkt.len());
        assert_eq!(got, pkt);
    }

    #[test]
    fn s8_stats_honest() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        assert_eq!(p.stats(), TunStats::default());
        p.send_packet(&[0x45; 20]).unwrap();
        p.send_packet(&[0x45; 40]).unwrap();
        let _ = p.recv_packet();
        let s = p.stats();
        assert_eq!(s.packets_out, 2);
        assert_eq!(s.bytes_out, 60);
        assert_eq!(s.packets_in, 1);
        assert_eq!(s.bytes_in, 20);
        assert_eq!(s.dropped_oversize, 0);
    }

    #[test]
    fn linked_pair_delivers() {
        let ta = Box::new(MockTun::default());
        let tb = Box::new(MockTun::default());
        let mut a = Projection::new_for_test(ta, ProjectionConfig::default());
        let mut b = Projection::new_for_test(tb, ProjectionConfig::default());
        a.link_mock_peer("B", &b);
        b.link_mock_peer("A", &a);
        let pkt = vec![0x45; 64];
        a.send_packet(&pkt).unwrap();
        let got = b.recv_packet().expect("peer delivery");
        assert_eq!(got, pkt);
        assert_eq!(a.stats().packets_out, 1);
        assert_eq!(b.stats().packets_in, 1);
    }

    #[test]
    fn on_path_event_counts() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());
        assert_eq!(p.path_switch_count(), 0);
        p.on_path_event();
        p.on_path_event();
        assert_eq!(p.path_switch_count(), 2);
    }

    #[test]
    fn close_joins_threads() {
        let tun = Box::new(MockTun::default());
        let p = Projection::new(tun, ProjectionConfig::default());
        // Threads started; close must join them without hanging.
        p.close();
    }

    /// Build a test router: 10/8 → MeshPeer (fast path), 1.2.3.0/24 → Drop,
    /// everything else → Egress{self}.
    fn test_router() -> UnifiedRouter {
        UnifiedRouter::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            Box::new(SimpleRuleEngine::new(vec![
                Rule {
                    cidr: "1.2.3.0/24".parse().unwrap(),
                    target: RouteTarget::Drop,
                },
                Rule {
                    cidr: "0.0.0.0/0".parse().unwrap(),
                    target: RouteTarget::Egress {
                        peer: "self".to_string(),
                    },
                },
            ])),
        )
    }

    fn udp_pkt(dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    #[test]
    fn s9_s12_with_router_send_packet_routes() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default())
            .with_router(Arc::new(test_router()));

        // Egress{self}
        p.send_packet(&udp_pkt([8, 8, 8, 8], 1000, 53)).unwrap();
        // MeshPeer via 10/8 fast path
        p.send_packet(&udp_pkt([10, 1, 2, 3], 1001, 80)).unwrap();
        // Drop via 1.2.3.0/24 rule
        p.send_packet(&udp_pkt([1, 2, 3, 4], 1002, 80)).unwrap();

        let rs = p.route_stats();
        assert_eq!(rs.egress_self, 1);
        assert_eq!(rs.mesh_peer, 1);
        assert_eq!(rs.dropped, 1);
        assert_eq!(rs.egress_remote, 0);
        // Egress{self} records in NAT; mesh sends via fabric.
        assert_eq!(p.nat_stats().egress_handled, 1);
    }

    #[test]
    fn s11_handle_egress_reply_matches() {
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default())
            .with_router(Arc::new(test_router()));

        let out = udp_pkt([8, 8, 8, 8], 2000, 53);
        p.send_packet(&out).unwrap();
        assert_eq!(p.nat_stats().egress_handled, 1);

        // Mock reply: reversed 5-tuple.
        let reply = udp_pkt([8, 8, 8, 8], 2000, 53); // placeholder, rebuild below
        let mut reply = reply;
        // src=8.8.8.8:53 dst=10.0.0.1:2000
        reply[12..16].copy_from_slice(&[8, 8, 8, 8]);
        reply[16..20].copy_from_slice(&[10, 0, 0, 1]);
        reply[20..22].copy_from_slice(&53u16.to_be_bytes());
        reply[22..24].copy_from_slice(&2000u16.to_be_bytes());

        assert!(p.handle_egress_reply(&reply));
        assert_eq!(p.nat_stats().reply_received, 1);

        // Unknown flow: no match.
        let mut bad = reply.clone();
        bad[22..24].copy_from_slice(&9999u16.to_be_bytes());
        assert!(!p.handle_egress_reply(&bad));
        assert_eq!(p.nat_stats().reply_dropped, 1);
    }

    #[test]
    fn s13_hop_limit_enforced_on_receive() {
        // Thread-less instance; drive recv_packet directly.
        let tun = Box::new(MockTun::default());
        let mut p = Projection::new_for_test(tun, ProjectionConfig::default());

        // Inject an egress datagram with hops=3 (> default max 2) into the
        // transport inbox, simulating a looping peer.
        let pkt = udp_pkt([1, 2, 3, 4], 3000, 80);
        let mut bad_dgram = vec![encode_intent(true, 3)];
        bad_dgram.extend_from_slice(&pkt);
        p.mock_transport()
            .unwrap()
            .inbox_sender()
            .send(("evil".to_string(), bad_dgram))
            .unwrap();
        assert!(p.recv_packet().is_none());
        assert_eq!(p.route_stats().hop_limit_exceeded, 1);

        // hops=2 (at the limit) passes.
        let mut ok_dgram = vec![encode_intent(true, 2)];
        ok_dgram.extend_from_slice(&pkt);
        p.mock_transport()
            .unwrap()
            .inbox_sender()
            .send(("ok".to_string(), ok_dgram))
            .unwrap();
        let got = p.recv_packet().expect("hops=2 passes");
        assert_eq!(got, pkt);
        assert_eq!(p.route_stats().hop_limit_exceeded, 1);
        // Egress packet was NAT-tracked with the origin peer.
        assert_eq!(p.nat_stats().egress_handled, 1);
    }

    #[test]
    fn s13_custom_max_hops() {
        let tun = Box::new(MockTun::default());
        let config = ProjectionConfig {
            max_egress_hops: 0,
            ..Default::default()
        };
        let mut p = Projection::new_for_test(tun, config);
        // Even hops=1 exceeds max 0.
        let pkt = udp_pkt([1, 2, 3, 4], 3001, 80);
        let mut dgram = vec![encode_intent(true, 1)];
        dgram.extend_from_slice(&pkt);
        p.mock_transport()
            .unwrap()
            .inbox_sender()
            .send(("x".to_string(), dgram))
            .unwrap();
        assert!(p.recv_packet().is_none());
        assert_eq!(p.route_stats().hop_limit_exceeded, 1);
    }
}
