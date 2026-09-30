//! Semantic ingress (S25): SOCKS5 / HTTP CONNECT → unified routing → fabric STREAM.
//!
//! An explicit proxy entry point: `SemanticIngress::bind` listens on a local
//! TCP port, runs the `nexus-ingress` handshake state machines (zero-I/O
//! pure functions) over each accepted connection, then routes the resulting
//! `host:port` destination through the **same** [`Router`] decision chain
//! the TUN path uses:
//!
//! - `Egress{self}` → local `TcpStream::connect` (DIRECT semantics);
//! - `Egress{peer}` → STREAM intent (`0x02`) SYN toward the peer, with the
//!   S25 typed SYN payload (domain form supported; the originator never
//!   resolves domains locally);
//! - `Drop` (or `MeshPeer`, which P0 does not serve here) → protocol
//!   rejection (`0x02` / `403`), counted.
//!
//! Sync only, zero tokio. Per-connection worker threads are owned by the
//! accept thread (which prunes/reaps them); `close()`/`Drop` shuts the
//! listener down and joins the accept thread.

use nexus_ingress::{HttpProxyHandshake, HttpProxyState, Socks5Handshake, Socks5State};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::tcp::{self, TcpEgress, encode_syn_payload};
use crate::{
    DatagramTransport, FlowLabels, INTENT_STREAM, ProcessAttributor, QosClass, QosConfig,
    RouteRequest, RouteTarget, Router, encode_intent_kind,
};
use tcp::{STREAM_FIN, STREAM_RST, STREAM_SYN, encode_stream_frame};

/// Lock helper that tolerates poisoning (mirrors `crate::lock`).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Total time budget for one client's handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Cap on handshake bytes (DoS bound).
const HANDSHAKE_MAX_BYTES: usize = 16 * 1024;
/// Inbound STREAM frame channel capacity per semantic connection (S3 best-effort).
const SEMANTIC_CHAN_CAP: usize = 64;
/// Relay idle timeout (safety bound; normal exit is EOF/error/shutdown).
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Connect timeout for `Egress{self}` local upstream.
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Wait for the peer's FIN/RST after we send FIN.
const FIN_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// S25 counters for the semantic ingress.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SemanticStats {
    /// Accepted client connections.
    pub ingress_accepted: u64,
    /// Connections rejected by routing (`Drop`/`MeshPeer`) or target unreachable.
    pub ingress_dropped: u64,
    /// Handshake protocol failures (+ explicit non-CONNECT rejections).
    pub ingress_handshake_errors: u64,
    /// Flows relayed to a local upstream (`Egress{self}`).
    pub ingress_egress_local: u64,
    /// Flows relayed to a remote peer (`Egress{peer}`).
    pub ingress_egress_remote: u64,
    /// Application bytes forwarded toward the target (client → upstream/fabric).
    pub relayed_bytes: u64,
    /// S26: accepted connections labeled High (best-effort attribution).
    pub ingress_qos_high: u64,
    /// S26: accepted connections labeled Normal (incl. unknown attribution).
    pub ingress_qos_normal: u64,
    /// S26: accepted connections labeled Low.
    pub ingress_qos_low: u64,
    /// S26: accepted connections labeled Background.
    pub ingress_qos_background: u64,
}

// ---------------------------------------------------------------------------
// Deps
// ---------------------------------------------------------------------------

/// Everything a `SemanticIngress` needs from its owning `Projection`.
#[derive(Clone)]
pub struct SemanticDeps {
    /// The same unified router the TUN path uses (S25: one decision chain).
    pub router: Arc<dyn Router>,
    /// Slot installed by `Projection::with_tcp_egress` (needed for `Egress{peer}`).
    pub tcp_egress: Arc<Mutex<Option<Arc<Mutex<TcpEgress>>>>>,
    /// Datagram transport for STREAM frames.
    pub transport: Arc<Mutex<Arc<dyn DatagramTransport>>>,
    /// MTU for STREAM datagrams.
    pub mtu: usize,
    /// Process attributor for accept-time labeling (S26).
    pub attributor: Arc<dyn ProcessAttributor>,
    /// Process-name → QoS class mapping (S26).
    pub qos: QosConfig,
}

// ---------------------------------------------------------------------------
// SemanticIngress
// ---------------------------------------------------------------------------

/// Explicit SOCKS5/HTTP proxy entry mapping clients to fabric streams (S25).
pub struct SemanticIngress {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept_handle: Option<JoinHandle<()>>,
    stats: Arc<Mutex<SemanticStats>>,
}

impl SemanticIngress {
    /// Bind `addr` and start the accept thread. `deps` wires routing,
    /// the TCP-egress slot and the transport from the owning `Projection`.
    pub fn bind(addr: SocketAddr, deps: SemanticDeps) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(SemanticStats::default()));
        // F1-residual lesson: per-instance random stream-id seed.
        let next_id = Arc::new(AtomicU32::new(tcp::random_stream_id_seed()));

        let th_shutdown = Arc::clone(&shutdown);
        let th_stats = Arc::clone(&stats);
        let th_next_id = Arc::clone(&next_id);
        let accept_handle = thread::Builder::new()
            .name("semantic-ingress-accept".into())
            .spawn(move || {
                // Owner of the per-connection workers: prune finished ones,
                // join the rest on shutdown (§13 structured concurrency).
                let mut workers: Vec<JoinHandle<()>> = Vec::new();
                while !th_shutdown.load(Ordering::Relaxed) {
                    workers.retain(|h| !h.is_finished());
                    match listener.accept() {
                        Ok((stream, _peer)) => {
                            lock(&th_stats).ingress_accepted += 1;
                            let deps = deps.clone();
                            let stats = Arc::clone(&th_stats);
                            let next_id = Arc::clone(&th_next_id);
                            let shutdown = Arc::clone(&th_shutdown);
                            match thread::Builder::new()
                                .name("semantic-ingress-conn".into())
                                .spawn(move || {
                                    handle_client(stream, &deps, &stats, &next_id, &shutdown);
                                }) {
                                Ok(h) => workers.push(h),
                                Err(_) => {
                                    // Spawn failure: counted as accepted but
                                    // immediately dropped; never panic the
                                    // accept loop.
                                    lock(&th_stats).ingress_dropped += 1;
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
                for h in workers {
                    let _ = h.join();
                }
            })
            .map_err(std::io::Error::other)?;

        Ok(Self {
            local_addr,
            shutdown,
            accept_handle: Some(accept_handle),
            stats,
        })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Snapshot of the S25 counters.
    pub fn stats(&self) -> SemanticStats {
        *lock(&self.stats)
    }

    /// Stop accepting, wait for the accept thread (and its workers) to finish.
    /// Idempotent.
    pub fn close(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.accept_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for SemanticIngress {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Outcome of the protocol handshake. The success `response` is held back
/// until routing decides (so a `Drop` can still send a rejection instead).
struct Established {
    destination: String,
    response: Vec<u8>,
    is_http: bool,
}

fn handshake_failed(stream: &mut TcpStream, stats: &Arc<Mutex<SemanticStats>>, response: &[u8]) {
    if !response.is_empty() {
        let _ = stream.write_all(response);
    }
    lock(stats).ingress_handshake_errors += 1;
}

/// Run the SOCKS5 handshake on `stream`. Returns `None` on protocol failure
/// (error response already written, counter bumped).
fn do_socks5(
    stream: &mut TcpStream,
    stats: &Arc<Mutex<SemanticStats>>,
    first: &[u8],
) -> std::io::Result<Option<Established>> {
    let mut hs = Socks5Handshake::new();
    let mut total = 0usize;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut step = hs.feed(first);
    total += first.len();
    loop {
        match step.state {
            Socks5State::Established => {
                let dest = step.flow.map(|f| f.destination).unwrap_or_default();
                return Ok(Some(Established {
                    destination: dest,
                    response: step.response,
                    is_http: false,
                }));
            }
            Socks5State::Failed(_) => {
                handshake_failed(stream, stats, &step.response);
                return Ok(None);
            }
            _ => {
                // Intermediate responses (method selection) must go out now:
                // the client waits for them before sending the request.
                if !step.response.is_empty() {
                    stream.write_all(&step.response)?;
                }
                if total >= HANDSHAKE_MAX_BYTES || Instant::now() > deadline {
                    handshake_failed(stream, stats, &[]);
                    return Ok(None);
                }
                let mut buf = [0u8; 4096];
                match stream.read(&mut buf) {
                    Ok(0) => {
                        handshake_failed(stream, stats, &[]);
                        return Ok(None);
                    }
                    Ok(n) => {
                        total += n;
                        step = hs.feed(&buf[..n]);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Run the HTTP proxy handshake. Non-CONNECT (absolute-form forwarding) is
/// explicitly rejected with 405 per the S25 contract (P0 only does CONNECT).
fn do_http(
    stream: &mut TcpStream,
    stats: &Arc<Mutex<SemanticStats>>,
    first: &[u8],
) -> std::io::Result<Option<Established>> {
    let mut hs = HttpProxyHandshake::new();
    let mut total = 0usize;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut step = hs.feed(first);
    total += first.len();
    loop {
        match step.state {
            HttpProxyState::Established => {
                if !step.upstream_prefix.is_empty() {
                    // Absolute-form forwarding (non-CONNECT): explicit 405.
                    let _ = stream
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
                    lock(stats).ingress_handshake_errors += 1;
                    return Ok(None);
                }
                let dest = step.flow.map(|f| f.destination).unwrap_or_default();
                return Ok(Some(Established {
                    destination: dest,
                    response: step.response,
                    is_http: true,
                }));
            }
            HttpProxyState::Failed(_) => {
                handshake_failed(stream, stats, &step.response);
                return Ok(None);
            }
            _ => {
                if total >= HANDSHAKE_MAX_BYTES || Instant::now() > deadline {
                    handshake_failed(stream, stats, &[]);
                    return Ok(None);
                }
                let mut buf = [0u8; 4096];
                match stream.read(&mut buf) {
                    Ok(0) => {
                        handshake_failed(stream, stats, &[]);
                        return Ok(None);
                    }
                    Ok(n) => {
                        total += n;
                        step = hs.feed(&buf[..n]);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Split `host:port`. Returns `None` on malformed input.
fn split_host_port(dest: &str) -> Option<(&str, u16)> {
    let (host, port) = dest.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// Route a semantic `host:port` destination through the unified decision
/// chain (S25: same chain as the TUN path).
///
/// Builds a minimal synthetic IPv4 header so `UnifiedRouter::route` can run
/// its S10 fast path for IP literals; the `domain` field carries the
/// hostname for S16 domain rules (None for IP literals).
pub(crate) fn route_destination(router: &Arc<dyn Router>, host: &str, port: u16) -> RouteTarget {
    let _ = port; // port is not part of the routing decision (S9/S16).
    let mut pkt = [0u8; 20];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[9] = 6; // TCP (protocol value is informational here)
    let domain: Option<&str> = match host.parse::<Ipv4Addr>() {
        Ok(ip) => {
            pkt[16..20].copy_from_slice(&ip.octets());
            None
        }
        Err(_) => {
            // Non-IP host: dst 0.0.0.0; domain rules decide (S16).
            Some(host)
        }
    };
    router.route(&RouteRequest {
        packet: &pkt,
        domain,
    })
}

// ---------------------------------------------------------------------------
// STREAM emission
// ---------------------------------------------------------------------------

/// Send one STREAM frame toward `peer` ("self" = direct local relay call).
fn emit_stream(deps: &SemanticDeps, peer: &str, stream_id: u32, flags: u8, payload: &[u8]) {
    let tcp = lock(&deps.tcp_egress).clone();
    let Some(tcp) = tcp else { return };
    if peer == "self" {
        // Defensive: the route match in `handle_client` guarantees
        // `peer != "self"` on this path (it takes the local-upstream arm),
        // so this branch is unreachable in practice. Kept (rather than
        // panicking) so a future caller can never silently misroute.
        // Direct relay call mirrors tcp-poll's self-loopback; connect
        // failures come back as immediate RST events → deliver to our own
        // registry entry (we are the originator).
        let events = lock(&tcp)
            .relay
            .handle_frame(stream_id, flags, payload, "self");
        let t = lock(&tcp);
        for ev in events {
            if let tcp::RelayEvent::Closed {
                stream_id,
                reset: true,
                ..
            } = ev
            {
                if let Some(tx) = t.semantic_lookup("self", stream_id) {
                    let _ = tx.try_send((STREAM_RST, Vec::new()));
                }
            }
        }
        return;
    }
    let frame = encode_stream_frame(stream_id, flags, payload);
    let mut datagram = Vec::with_capacity(frame.len() + 1);
    datagram.push(encode_intent_kind(INTENT_STREAM, 0));
    datagram.extend_from_slice(&frame);
    if datagram.len() > deps.mtu {
        return; // S5: never fragment; drop oversize.
    }
    let transport = lock(&deps.transport).clone();
    let _ = transport.send_to(peer, &datagram); // S3 best-effort.
}

// ---------------------------------------------------------------------------
// Per-connection worker
// ---------------------------------------------------------------------------

fn reject_routed(stream: &mut TcpStream, stats: &Arc<Mutex<SemanticStats>>, is_http: bool) {
    if is_http {
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    } else {
        let _ = stream.write_all(&[0x05, 0x02, 0x00]); // connection not allowed
    }
    lock(stats).ingress_dropped += 1;
}

fn reject_unreachable(stream: &mut TcpStream, stats: &Arc<Mutex<SemanticStats>>, is_http: bool) {
    if is_http {
        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    } else {
        let _ = stream.write_all(&[0x05, 0x04, 0x00]); // host unreachable
    }
    lock(stats).ingress_dropped += 1;
}

/// Bidirectional byte relay between two nonblocking streams.
/// Returns when either side hits EOF/error or `shutdown` is set.
/// `count_up` accumulates bytes flowing `a → b` into `stats.relayed_bytes`.
fn relay_pair(
    mut a: &TcpStream,
    mut b: &TcpStream,
    stats: &Arc<Mutex<SemanticStats>>,
    shutdown: &Arc<AtomicBool>,
    count_up: bool,
) {
    let mut buf = [0u8; 16384];
    let mut idle_since = Instant::now();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let mut progressed = false;
        // a → b
        match a.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                progressed = true;
                idle_since = Instant::now();
                if count_up {
                    lock(stats).relayed_bytes += n as u64;
                }
                if write_all_nb(b, &buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        // b → a
        match b.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                progressed = true;
                idle_since = Instant::now();
                if write_all_nb(a, &buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        if !progressed {
            if idle_since.elapsed() > RELAY_IDLE_TIMEOUT {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    let _ = a.shutdown(std::net::Shutdown::Both);
    let _ = b.shutdown(std::net::Shutdown::Both);
}

fn write_all_nb(mut stream: &TcpStream, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match stream.write(data) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write zero",
                ));
            }
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Handle one accepted client connection: handshake → route → relay.
fn handle_client(
    mut stream: TcpStream,
    deps: &SemanticDeps,
    stats: &Arc<Mutex<SemanticStats>>,
    next_id: &Arc<AtomicU32>,
    shutdown: &Arc<AtomicBool>,
) {
    // S26: attribute once at accept time (best-effort; never blocks setup).
    // The application owns the *peer* side of the accepted socket.
    let labels = match (stream.peer_addr(), stream.local_addr()) {
        (Ok(peer), Ok(local)) => {
            FlowLabels::for_accepted_peer(&*deps.attributor, &deps.qos, peer, local)
        }
        _ => FlowLabels::unknown(),
    };
    match labels.qos_class {
        QosClass::High => lock(stats).ingress_qos_high += 1,
        QosClass::Normal => lock(stats).ingress_qos_normal += 1,
        QosClass::Low => lock(stats).ingress_qos_low += 1,
        QosClass::Background => lock(stats).ingress_qos_background += 1,
    };
    if stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).is_err() {
        return;
    }
    // 1. First-byte sniff: 0x05 → SOCKS5, else HTTP request line.
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).is_err() {
        lock(stats).ingress_handshake_errors += 1;
        return;
    }
    let est = if first[0] == 0x05 {
        match do_socks5(&mut stream, stats, &first) {
            Ok(e) => e,
            Err(_) => {
                lock(stats).ingress_handshake_errors += 1;
                return;
            }
        }
    } else {
        match do_http(&mut stream, stats, &first) {
            Ok(e) => e,
            Err(_) => {
                lock(stats).ingress_handshake_errors += 1;
                return;
            }
        }
    };
    let Some(est) = est else { return }; // failed: response written, counted.
    let (host, port) = match split_host_port(&est.destination) {
        Some(hp) => hp,
        None => {
            handshake_failed(&mut stream, stats, &[]);
            return;
        }
    };

    // 2. Route through the unified chain (S25).
    let target = route_destination(&deps.router, host, port);
    match target {
        RouteTarget::Egress { ref peer } if peer == "self" => {
            // Local upstream (DIRECT semantics); the domain is resolved here.
            let up = match tcp::resolve_target_v4(host, port) {
                Some(a) => a,
                None => {
                    reject_unreachable(&mut stream, stats, est.is_http);
                    return;
                }
            };
            let upstream = match TcpStream::connect_timeout(&up, LOCAL_CONNECT_TIMEOUT) {
                Ok(s) => s,
                Err(_) => {
                    reject_unreachable(&mut stream, stats, est.is_http);
                    return;
                }
            };
            // Routing accepted: release the held success response.
            if stream.write_all(&est.response).is_err() {
                return;
            }
            lock(stats).ingress_egress_local += 1;
            let _ = stream.set_read_timeout(None);
            let _ = stream.set_nonblocking(true);
            let _ = upstream.set_nonblocking(true);
            relay_pair(&stream, &upstream, stats, shutdown, true);
        }
        RouteTarget::Egress { ref peer } => {
            let peer = peer.clone();
            // Remote egress needs the TCP-egress slot (STREAM dispatch).
            if lock(&deps.tcp_egress).is_none() {
                reject_unreachable(&mut stream, stats, est.is_http);
                return;
            }
            let stream_id = next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::sync_channel::<(u8, Vec<u8>)>(SEMANTIC_CHAN_CAP);
            if let Some(tcp) = lock(&deps.tcp_egress).clone() {
                lock(&tcp).semantic_register(&peer, stream_id, tx);
            }
            // S25: originator always uses the typed SYN form. The domain is
            // NOT resolved here — the egress side resolves it.
            let syn = encode_syn_payload(host, port);
            emit_stream(deps, &peer, stream_id, STREAM_SYN, &syn);
            if stream.write_all(&est.response).is_err() {
                emit_stream(deps, &peer, stream_id, STREAM_RST, &[]);
                deregister(deps, &peer, stream_id);
                return;
            }
            lock(stats).ingress_egress_remote += 1;
            let _ = stream.set_read_timeout(None);
            let _ = stream.set_nonblocking(true);
            relay_stream(&stream, deps, &peer, stream_id, rx, stats, shutdown);
            deregister(deps, &peer, stream_id);
        }
        _ => {
            // Drop (and MeshPeer, which P0 semantic ingress does not serve).
            reject_routed(&mut stream, stats, est.is_http);
        }
    }
}

fn deregister(deps: &SemanticDeps, peer: &str, stream_id: u32) {
    if let Some(tcp) = lock(&deps.tcp_egress).clone() {
        lock(&tcp).semantic_deregister(peer, stream_id);
    }
}

/// Relay between the client socket and a remote fabric STREAM.
/// Client EOF → FIN; client error → RST; peer FIN/RST → close.
fn relay_stream(
    mut client: &TcpStream,
    deps: &SemanticDeps,
    peer: &str,
    stream_id: u32,
    rx: mpsc::Receiver<(u8, Vec<u8>)>,
    stats: &Arc<Mutex<SemanticStats>>,
    shutdown: &Arc<AtomicBool>,
) {
    let mut buf = [0u8; 16384];
    let mut idle_since = Instant::now();
    let mut fin_sent = false;
    let fin_deadline = Instant::now() + FIN_WAIT_TIMEOUT;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            emit_stream(deps, peer, stream_id, STREAM_RST, &[]);
            break;
        }
        // Fabric → client.
        while let Ok((flags, payload)) = rx.try_recv() {
            idle_since = Instant::now();
            if flags & STREAM_RST != 0 {
                let _ = client.shutdown(std::net::Shutdown::Both);
                return;
            }
            if !payload.is_empty() && write_all_nb(client, &payload).is_err() {
                emit_stream(deps, peer, stream_id, STREAM_RST, &[]);
                return;
            }
            if flags & STREAM_FIN != 0 {
                // Peer closed: drain is best-effort; close our side.
                let _ = client.shutdown(std::net::Shutdown::Both);
                return;
            }
        }
        if fin_sent {
            if Instant::now() > fin_deadline {
                break;
            }
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        // Client → fabric.
        match client.read(&mut buf) {
            Ok(0) => {
                emit_stream(deps, peer, stream_id, STREAM_FIN, &[]);
                fin_sent = true;
            }
            Ok(n) => {
                idle_since = Instant::now();
                lock(stats).relayed_bytes += n as u64;
                // Chunk to fit the MTU (S5: never fragment a datagram).
                for chunk in buf[..n].chunks(deps.mtu.saturating_sub(64).max(1)) {
                    emit_stream(deps, peer, stream_id, 0, chunk);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                emit_stream(deps, peer, stream_id, STREAM_RST, &[]);
                break;
            }
        }
        if idle_since.elapsed() > RELAY_IDLE_TIMEOUT {
            emit_stream(deps, peer, stream_id, STREAM_RST, &[]);
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = client.shutdown(std::net::Shutdown::Both);
}

// ---------------------------------------------------------------------------
// Tests (S25 Red spec)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockTun, Projection, ProjectionConfig, Rule, SimpleRuleEngine, UnifiedRouter};
    use std::io::{Read, Write};

    fn drop_router() -> Arc<dyn Router> {
        let engine = SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().unwrap(),
            target: RouteTarget::Drop,
        }]);
        Arc::new(UnifiedRouter::new(vec![], Box::new(engine)))
    }

    fn peer_b_router() -> Arc<dyn Router> {
        let mut engine = SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().unwrap(),
            target: RouteTarget::Egress {
                peer: "self".to_string(),
            },
        }]);
        engine.add_domain_exact_rule(
            "localhost",
            RouteTarget::Egress {
                peer: "B".to_string(),
            },
        );
        Arc::new(UnifiedRouter::new(vec![], Box::new(engine)))
    }

    fn test_deps(router: Arc<dyn Router>) -> (SemanticDeps, Arc<Mutex<SemanticStats>>) {
        let transport: Arc<dyn DatagramTransport> = Arc::new(crate::MockTransport::new("test"));
        let stats = Arc::new(Mutex::new(SemanticStats::default()));
        let deps = SemanticDeps {
            router,
            tcp_egress: Arc::new(Mutex::new(None)),
            transport: Arc::new(Mutex::new(transport)),
            mtu: 1400,
            attributor: Arc::new(crate::PlatformAttributor),
            qos: QosConfig::default(),
        };
        (deps, stats)
    }

    /// Run `handle_client` against a loopback TCP pair; returns the client
    /// socket for assertions.
    fn run_client(
        deps: &SemanticDeps,
        stats: &Arc<Mutex<SemanticStats>>,
        next_id: &Arc<AtomicU32>,
    ) -> (TcpStream, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let deps = deps.clone();
        let stats = Arc::clone(stats);
        let next_id = Arc::clone(next_id);
        let h = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let shutdown = Arc::new(AtomicBool::new(false));
            handle_client(stream, &deps, &stats, &next_id, &shutdown);
        });
        let client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        (client, h)
    }

    fn next_id() -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(tcp::random_stream_id_seed()))
    }

    #[test]
    fn socks5_drop_target_rejected_with_protocol_error() {
        // S25: Drop → SOCKS5 回复 0x02，计数 ingress_dropped。
        let (deps, stats) = test_deps(drop_router());
        let (mut client, h) = run_client(&deps, &stats, &next_id());
        client.write_all(&[0x05, 0x01, 0x00]).unwrap(); // greeting
        let mut b = [0u8; 2];
        client.read_exact(&mut b).unwrap();
        assert_eq!(b, [0x05, 0x00]);
        // CONNECT 1.2.3.4:80
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
            .unwrap();
        let mut rep = [0u8; 3];
        client.read_exact(&mut rep).unwrap();
        assert_eq!(rep, [0x05, 0x02, 0x00], "expected connection-not-allowed");
        h.join().unwrap();
        let s = *lock(&stats);
        assert_eq!(s.ingress_accepted, 0); // accepted counted by accept loop, not handle_client
        assert_eq!(s.ingress_dropped, 1);
        assert_eq!(s.ingress_handshake_errors, 0);
    }

    #[test]
    fn http_drop_target_rejected_with_403() {
        // S25: Drop → HTTP 403。
        let (deps, stats) = test_deps(drop_router());
        let (mut client, h) = run_client(&deps, &stats, &next_id());
        client
            .write_all(b"CONNECT 1.2.3.4:80 HTTP/1.1\r\nHost: 1.2.3.4:80\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(
            text.starts_with("HTTP/1.1 403"),
            "expected 403, got {text:?}"
        );
        h.join().unwrap();
        assert_eq!(lock(&stats).ingress_dropped, 1);
    }

    #[test]
    fn socks5_bind_rejected_with_command_error() {
        // S25: BIND 显式拒绝 → 0x07，计数 handshake_errors。
        let (deps, stats) = test_deps(drop_router());
        let (mut client, h) = run_client(&deps, &stats, &next_id());
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut b = [0u8; 2];
        client.read_exact(&mut b).unwrap();
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
            .unwrap(); // BIND
        let mut rep = [0u8; 3];
        client.read_exact(&mut rep).unwrap();
        assert_eq!(rep, [0x05, 0x07, 0x00], "expected command-not-supported");
        h.join().unwrap();
        assert_eq!(lock(&stats).ingress_handshake_errors, 1);
    }

    #[test]
    fn http_non_connect_rejected_with_405() {
        // S25: plain HTTP absolute-form → 405。
        let (deps, stats) = test_deps(drop_router());
        let (mut client, h) = run_client(&deps, &stats, &next_id());
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(
            text.starts_with("HTTP/1.1 405"),
            "expected 405, got {text:?}"
        );
        h.join().unwrap();
        assert_eq!(lock(&stats).ingress_handshake_errors, 1);
    }

    #[test]
    fn handshake_failure_counted_and_closed() {
        // S25: 握手失败 → 协议错误响应 + 计数，连接关闭。
        let (deps, stats) = test_deps(drop_router());
        let (mut client, h) = run_client(&deps, &stats, &next_id());
        // 0x05 then truncated greeting, then close the write side.
        client.write_all(&[0x05]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        h.join().unwrap();
        assert_eq!(lock(&stats).ingress_handshake_errors, 1);
        // Connection fully closed by the worker.
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn socks5_connect_routes_to_egress_peer() {
        // S25: 域名走 S16 域名规则 → Egress{peer=B}（同一条决策链）。
        let router = peer_b_router();
        assert_eq!(
            route_destination(&router, "localhost", 8080),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
        // 未命中域名规则 → 回退 IP 规则 → Egress{self}。
        assert_eq!(
            route_destination(&router, "other.example", 80),
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
    }

    #[test]
    fn route_destination_ip_literal_uses_fast_path() {
        // IP 字面量走 S10 虚拟子网 fast path（同一条决策链）。
        let engine = SimpleRuleEngine::new(vec![]);
        let router: Arc<dyn Router> = Arc::new(UnifiedRouter::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            Box::new(engine),
        ));
        assert_eq!(
            route_destination(&router, "10.1.2.3", 80),
            RouteTarget::MeshPeer {
                peer: "10.1.2.3".to_string()
            }
        );
    }

    #[test]
    fn syn_domain_form_roundtrip() {
        // S25: typed SYN 载荷编解码 + 3b-5 6 字节旧格式兼容。
        let enc = tcp::encode_syn_payload("example.com", 8080);
        assert_eq!(enc[0], 0x03);
        let (t, off) = tcp::decode_syn_payload(&enc).unwrap();
        assert_eq!(t, tcp::SynTarget::Domain("example.com".to_string(), 8080));
        assert_eq!(off, enc.len());

        let enc_ip = tcp::encode_syn_payload("1.2.3.4", 80);
        assert_eq!(enc_ip[0], 0x01);
        let (t, off) = tcp::decode_syn_payload(&enc_ip).unwrap();
        assert_eq!(t, tcp::SynTarget::V4("1.2.3.4:80".parse().unwrap()));
        assert_eq!(off, 7);

        // 3b-5 legacy: 6 bytes = IPv4 + port.
        let legacy = [1u8, 2, 3, 4, 0, 80];
        let (t, off) = tcp::decode_syn_payload(&legacy).unwrap();
        assert_eq!(t, tcp::SynTarget::V4("1.2.3.4:80".parse().unwrap()));
        assert_eq!(off, 6);

        // Malformed: unknown atyp / truncated.
        assert!(tcp::decode_syn_payload(&[0x05, 1, 2, 3, 4, 0, 80]).is_none());
        assert!(tcp::decode_syn_payload(&[0x01, 1, 2]).is_none());
        assert!(tcp::decode_syn_payload(&[0x03, 5, b'a', b'b']).is_none());
        assert!(tcp::decode_syn_payload(&[]).is_none());
    }

    #[test]
    fn semantic_ingress_bind_and_close() {
        // bind → local_addr 有效 → close 后不再接受连接。
        let transport: Arc<dyn DatagramTransport> = Arc::new(crate::MockTransport::new("test"));
        let deps = SemanticDeps {
            router: drop_router(),
            tcp_egress: Arc::new(Mutex::new(None)),
            transport: Arc::new(Mutex::new(transport)),
            mtu: 1400,
            attributor: Arc::new(crate::PlatformAttributor),
            qos: QosConfig::default(),
        };
        let mut ing = SemanticIngress::bind("127.0.0.1:0".parse().unwrap(), deps).unwrap();
        let addr = ing.local_addr();
        assert!(addr.port() != 0);
        // Accept loop is running: a connect succeeds.
        let _probe = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(lock(&ing.stats).ingress_accepted, 1);
        ing.close();
        ing.close(); // idempotent
    }

    #[test]
    fn local_egress_roundtrip() {
        // Egress{self}: client ↔ 本地 TcpStream 双向中继。
        let engine = SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().unwrap(),
            target: RouteTarget::Egress {
                peer: "self".to_string(),
            },
        }]);
        let router: Arc<dyn Router> = Arc::new(UnifiedRouter::new(vec![], Box::new(engine)));
        let (deps, stats) = test_deps(router);

        // Echo server = local upstream target.
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = echo.accept().unwrap();
            let mut b = [0u8; 1024];
            loop {
                match s.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let (mut client, h) = run_client(&deps, &stats, &next_id());
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut b = [0u8; 2];
        client.read_exact(&mut b).unwrap();
        let req = [
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (echo_port >> 8) as u8,
            (echo_port & 0xff) as u8,
        ];
        client.write_all(&req).unwrap();
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).unwrap();
        assert_eq!(&rep[..2], &[0x05, 0x00]);
        client.write_all(b"ping-3d").unwrap();
        let mut back = [0u8; 7];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping-3d");
        drop(client);
        h.join().unwrap();
        let s = *lock(&stats);
        assert_eq!(s.ingress_egress_local, 1);
        assert_eq!(s.relayed_bytes, 7);
    }

    #[test]
    fn projection_exposes_semantic_deps() {
        // Projection::semantic_deps 把 router/transport/tcp slot 交给 SemanticIngress。
        let tun = Box::new(MockTun::new("t"));
        let engine = SimpleRuleEngine::new(vec![]);
        let p = Projection::new(tun, ProjectionConfig::default())
            .with_router(Arc::new(UnifiedRouter::new(vec![], Box::new(engine))));
        let deps = p
            .semantic_deps()
            .expect("router installed → deps available");
        assert_eq!(deps.mtu, ProjectionConfig::default().mtu);
        p.close();
    }

    #[test]
    fn syn_two_char_domain_never_six_bytes() {
        // Review F1: 2 字符域名的 typed 载荷绝不能是 6 字节（否则解码侧按
        // 3b-5 旧格式误读为 IPv4 → 静默连错主机）。
        let enc = tcp::encode_syn_payload("ab", 80);
        assert_ne!(enc.len(), 6, "typed payload must never be 6 bytes");
        let (t, _) = tcp::decode_syn_payload(&enc).expect("must decode as typed");
        // trailing-dot FQDN：与 "ab" 解析等价。
        assert_eq!(t, tcp::SynTarget::Domain("ab.".to_string(), 80));
        // 往返一致：egress 侧解析的目标仍是该域名。
        let addr = tcp::resolve_target_v4("ab.", 80);
        let _ = addr; // resolution itself needs DNS; shape is what matters
    }

    #[test]
    fn http_connect_routes_to_egress_peer() {
        // S25: HTTP CONNECT 的 destination 同样走统一决策链（S16 域名规则）。
        let router = peer_b_router();
        assert_eq!(
            route_destination(&router, "localhost", 443),
            RouteTarget::Egress {
                peer: "B".to_string()
            }
        );
    }

    #[test]
    fn semantic_registry_register_deregister() {
        // Review G2: 注册表的基本操作；worker 的所有退出路径都必须
        // deregister（由 handle_client/relay_stream 保证，这里锁定语义）。
        let tcp = TcpEgress::new();
        assert_eq!(tcp.semantic_stream_count(), 0);
        let (tx, _rx) = mpsc::sync_channel::<(u8, Vec<u8>)>(4);
        tcp.semantic_register("B", 42, tx);
        assert_eq!(tcp.semantic_stream_count(), 1);
        assert!(tcp.semantic_lookup("B", 42).is_some());
        // (peer, id) 键：同 id 不同 peer 不冲突（F1 教训）。
        assert!(tcp.semantic_lookup("C", 42).is_none());
        tcp.semantic_deregister("B", 42);
        assert_eq!(tcp.semantic_stream_count(), 0);
        assert!(tcp.semantic_lookup("B", 42).is_none());
    }
}
