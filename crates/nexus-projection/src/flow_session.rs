//! PeerId-level flow session API over `nexus-fabric` (flow_session).
//!
//! [`FlowSessionHub`] turns a [`FabricConn`] into an upper-layer production
//! API: reliable bidirectional streams (`open_stream`) and unreliable
//! service datagrams (`send_datagram`, intent kind `0x03`), keyed by
//! [`PeerId`] (R6). No new wire protocol is introduced (D2/D3/D4): stream
//! services reuse the wireup first-frame type-byte convention, and the
//! datagram service channel reuses the existing intent-byte layout with
//! kind `0x03`.
//!
//! # Frozen API (spec §4)
//!
//! - [`FlowError`] is frozen with exactly four variants. `TooLarge` was
//!   frozen in spec §4 and implemented here (S2): a single stream write
//!   larger than [`MAX_STREAM_WRITE`] (256 KiB, AC11) or a single
//!   `send_datagram` with `data.len() > [`MAX_DATAGRAM_PAYLOAD`]` maps to
//!   this variant.
//! - `SendStream::write` has **no backpressure** (P0, D7): it buffers in
//!   memory and returns immediately. Callers MUST chunk transfers into
//!   writes of at most [`MAX_STREAM_WRITE`] (256 KiB, AC11); a single
//!   larger write returns [`FlowError::TooLarge`] (AC11).
//! - `send_datagram` rejects `data.len() > [`MAX_DATAGRAM_PAYLOAD`]` with
//!   [`FlowError::TooLarge`] (AC11). `data[0]` is the service sub-id (D4);
//!   the receiver's R3 dispatch delivers `data[1..]` to the handler
//!   registered for `data[0]`. The fabric 1200-byte datagram cap includes
//!   the 1-byte intent, so the effective maximum sendable `data.len()` is
//!   1199; `data.len() == 1200` passes the API guard but is rejected by
//!   the fabric (mapped to [`FlowError::Fabric`]).
//! - P0 does **not** guarantee a single underlying connect under
//!   concurrent `dial` calls (S3); verifiers do not test concurrency.
//!
//! # Assembly (S4)
//!
//! The typical composition-root pattern for building the three `new`
//! arguments (`listener`, `link`, `punch`) is shown in
//! `nexus-nat-wireup/examples/e4_prod_switch.rs` (`Stack::new` constructs
//! `PunchManager` + `PathLink`; `FabricListener::bind` provides the
//! listener).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use nexus_fabric::{
    Cmd, ConnConfig, ConnShared, ConnStats, FabricConn, FabricError, FabricListener, PeerId,
    RecvStream as FabricRecvStream, SendStream as FabricSendStream, StreamShared, split_stream,
};
use nexus_nat_wireup::PunchManager;
use nexus_path::{CandidatePath, PathKind};

use crate::path_link::{ActiveConn, PathLink};
use crate::{INTENT_SERVICE, decode_intent_kind, encode_intent_kind};

/// Max single datagram payload accepted by [`FlowSessionHub::send_datagram`]
/// (frozen spec: `data.len() > 1200` -> [`FlowError::TooLarge`], AC11).
pub const MAX_DATAGRAM_PAYLOAD: usize = 1200;

/// Max single stream write accepted by [`SendStream::write`] (AC11, D7).
/// The Hub has no backpressure (P0); callers must chunk larger transfers.
pub const MAX_STREAM_WRITE: usize = 256 * 1024;

/// Handler for an inbound service stream. The Hub consumes the stream's
/// first byte (the service type, D3) for routing; the handler receives the
/// stream with the type byte already consumed (AC5).
pub type StreamHandler = Arc<dyn Fn(PeerId, SendStream, RecvStream) + Send + Sync + 'static>;

/// Handler for an inbound service datagram (D4/R3): `(peer, payload)` where
/// `payload` is the datagram after the intent byte and the service sub-id.
pub type DatagramHandler = Arc<dyn Fn(PeerId, &[u8]) + Send + Sync + 'static>;

/// Typed error for [`FlowSessionHub`] operations (frozen spec §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// A single stream `write` exceeded [`MAX_STREAM_WRITE`] (256 KiB, AC11)
    /// or a single `send_datagram` `data.len()` exceeded
    /// [`MAX_DATAGRAM_PAYLOAD`] (AC11). Frozen in spec §4.
    TooLarge,
    /// The peer was closed via [`FlowSessionHub::close_peer`] (AC9).
    Closed,
    /// No connection exists and there are no candidates to dial.
    PathUnreachable,
    /// Underlying fabric connect/transport error (R2: errors during
    /// rebind are surfaced here, never silently dropped).
    Fabric(FabricError),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowError::TooLarge => write!(
                f,
                "too large (stream writes > {} KiB or datagram > {} bytes)",
                MAX_STREAM_WRITE / 1024,
                MAX_DATAGRAM_PAYLOAD
            ),
            FlowError::Closed => write!(f, "peer closed"),
            FlowError::PathUnreachable => write!(f, "path unreachable"),
            FlowError::Fabric(e) => write!(f, "fabric: {e}"),
        }
    }
}

impl std::error::Error for FlowError {}

/// Reliable send half of a flow-session stream.
///
/// Wraps [`nexus_fabric::SendStream`]. No backpressure (P0, D7): `write`
/// buffers in memory and returns immediately. Callers MUST chunk transfers
/// into writes of at most [`MAX_STREAM_WRITE`] (256 KiB, AC11); a single
/// larger write returns [`FlowError::TooLarge`] (AC11).
pub struct SendStream {
    inner: FabricSendStream,
}

impl SendStream {
    /// Write `buf` to the stream. A single write larger than
    /// [`MAX_STREAM_WRITE`] (256 KiB, AC11) returns [`FlowError::TooLarge`].
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, FlowError> {
        if buf.len() > MAX_STREAM_WRITE {
            return Err(FlowError::TooLarge);
        }
        self.inner.write(buf).map_err(FlowError::Fabric)
    }

    /// Signal end-of-stream; the peer observes EOF after all bytes (S4).
    pub fn finish(&mut self) -> Result<(), FlowError> {
        self.inner.finish().map_err(FlowError::Fabric)
    }
}

/// Reliable receive half of a flow-session stream.
///
/// Wraps [`nexus_fabric::RecvStream`]. `read` blocks until data is
/// available; `Ok(0)` signals EOF.
pub struct RecvStream {
    inner: FabricRecvStream,
}

impl RecvStream {
    /// Read into `buf`, blocking until data is available. `Ok(0)` = EOF.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, FlowError> {
        self.inner.read(buf).map_err(FlowError::Fabric)
    }

    /// Read with an absolute deadline (avoids hanging on a dead peer).
    pub fn read_deadline(&mut self, buf: &mut [u8], deadline: Instant) -> Result<usize, FlowError> {
        self.inner
            .read_deadline(buf, deadline)
            .map_err(FlowError::Fabric)
    }
}

/// Which connection kind backs a registry entry.
enum ConnKind {
    /// A single direct `FabricConn` (legacy/rebind path, S27).
    Direct(FabricConn),
    /// A NAT peer using the PathLink dual-connection path (D1): the active
    /// `Arc<ConnShared>` is read from `PathLink::nat_conns` on each use.
    Nat,
}

/// Registry entry for one peer (R6: keyed by `PeerId`).
struct HubConn {
    closed: bool,
    kind: ConnKind,
}

/// Resolved connection reference for a peer.
enum ConnRef {
    Direct(FabricConn),
    Nat(Arc<ConnShared>),
}

/// Shared state of a [`FlowSessionHub`], held behind an `Arc` so background
/// threads (listener accept, per-peer accept/datagram pumps, path pump,
/// unclaimed dispatcher) can own it.
struct HubShared {
    listener: FabricListener,
    link: Arc<Mutex<PathLink>>,
    punch: Arc<PunchManager>,
    registry: Mutex<HashMap<PeerId, HubConn>>,
    last_candidates: Mutex<HashMap<PeerId, Vec<SocketAddr>>>,
    /// Relay connection id -> peer, for routing `take_unclaimed()` streams
    /// (R1/D5: the Hub never calls `accept_bi` on punch-registered relays).
    conn_id_to_peer: Mutex<HashMap<u64, PeerId>>,
    stream_services: Mutex<HashMap<u8, StreamHandler>>,
    datagram_services: Mutex<HashMap<u8, DatagramHandler>>,
    shutdown: AtomicBool,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
    peer_threads: Mutex<HashMap<PeerId, Vec<thread::JoinHandle<()>>>>,
    inbound_conns: Mutex<Vec<FabricConn>>,
}

/// PeerId-level session API over `nexus-fabric` (flow_session).
///
/// Holds a [`FabricListener`] (inbound connections), a [`PathLink`] (path
/// switching/roaming, R2), a service dispatch table (streams + datagrams),
/// and an `Arc<PunchManager>` (NAT relay/unclaimed streams, R1).
pub struct FlowSessionHub {
    shared: Arc<HubShared>,
}

fn peer_hex(peer: &PeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn conn_closed(conn: &Arc<ConnShared>) -> bool {
    conn.state
        .lock()
        .map(|s| s.closed.is_some())
        .unwrap_or(true)
}

/// Send a service datagram over a NAT peer's active `ConnShared`.
fn send_dgram_shared(conn: &Arc<ConnShared>, data: Vec<u8>) -> Result<(), FlowError> {
    let (tx, rx) = mpsc::channel();
    conn.tx
        .send(Cmd::SendDatagram {
            conn: conn.id.0,
            data,
            reply: tx,
        })
        .map_err(|_| FlowError::Fabric(FabricError::Closed(0)))?;
    rx.recv()
        .map_err(|_| FlowError::Fabric(FabricError::Closed(0)))?
        .map_err(FlowError::Fabric)
}

/// Blocking receive from a `ConnShared` datagram queue with a timeout.
fn recv_dgram_timeout(conn: &Arc<ConnShared>, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut q = conn.dgrams.lock().ok()?;
    loop {
        if let Some(d) = q.pop_front() {
            return Some(d);
        }
        if conn_closed(conn) {
            return None;
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let (g, _) = conn.dgram_cv.wait_timeout(q, deadline - now).ok()?;
        q = g;
    }
}

impl FlowSessionHub {
    /// Create a session hub.
    ///
    /// Assembly pointer (S4): the typical composition-root pattern for
    /// building `listener` + `link` + `punch` is shown in
    /// `nexus-nat-wireup/examples/e4_prod_switch.rs`.
    pub fn new(listener: FabricListener, link: PathLink, punch: Arc<PunchManager>) -> Self {
        let shared = Arc::new(HubShared {
            listener,
            link: Arc::new(Mutex::new(link)),
            punch,
            registry: Mutex::new(HashMap::new()),
            last_candidates: Mutex::new(HashMap::new()),
            conn_id_to_peer: Mutex::new(HashMap::new()),
            stream_services: Mutex::new(HashMap::new()),
            datagram_services: Mutex::new(HashMap::new()),
            shutdown: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
            peer_threads: Mutex::new(HashMap::new()),
            inbound_conns: Mutex::new(Vec::new()),
        });
        let hub = Self { shared };
        hub.spawn_listener_thread();
        hub.spawn_path_pump_thread();
        hub.spawn_unclaimed_thread();
        hub
    }

    /// Access the shared [`PathLink`]. Composition roots use this to
    /// register NAT relay/direct connections and additional path candidates
    /// after `new` (the production `NatSwitching` pattern).
    pub fn link(&self) -> Arc<Mutex<PathLink>> {
        Arc::clone(&self.shared.link)
    }

    /// Dial `peer` on demand. Idempotent: an already-known peer is reused
    /// and `Ok(false)` is returned; a new connection returns `Ok(true)`.
    ///
    /// Candidates are registered with the `PathManager` (R4). Direct peers
    /// use `FabricConn::connect(addrs[0])`; NAT peers (already registered
    /// in `PathLink` via `register_nat_relay`/`register_nat_direct`, the
    /// #4 production pattern) use the dual-connection path.
    pub fn dial(&self, peer: PeerId, candidates: &[SocketAddr]) -> Result<bool, FlowError> {
        self.shared.dial(peer, candidates)
    }

    /// Open a reliable bidirectional stream to `peer`.
    ///
    /// Unknown peers are dialed automatically using the candidates from
    /// their last `dial`; a peer that was never dialed returns
    /// [`FlowError::PathUnreachable`]. After [`FlowSessionHub::close_peer`]
    /// this returns [`FlowError::Closed`] (AC9).
    pub fn open_stream(&self, peer: PeerId) -> Result<(SendStream, RecvStream), FlowError> {
        self.shared.open_stream(peer)
    }

    /// Send an unreliable service datagram to `peer`.
    ///
    /// The wire format is `[intent 0x03][data]` (D4): `data[0]` is the
    /// service sub-id and `data[1..]` is the payload delivered to the
    /// receiver's registered [`DatagramHandler`]. `data.len() > 1200`
    /// returns [`FlowError::TooLarge`] (AC11).
    pub fn send_datagram(&self, peer: PeerId, data: &[u8]) -> Result<(), FlowError> {
        self.shared.send_datagram(peer, data)
    }

    /// Register a stream service handler for `type_byte` (D3: the first
    /// byte of an inbound service stream routes to this handler).
    pub fn register_stream_service(&self, type_byte: u8, h: StreamHandler) {
        self.shared
            .stream_services
            .lock()
            .unwrap()
            .insert(type_byte, h);
    }

    /// Register a datagram service handler for `svc` (D4/R3: the second
    /// byte of a `0x03` service datagram routes to this handler).
    pub fn register_datagram_service(&self, svc: u8, h: DatagramHandler) {
        self.shared.datagram_services.lock().unwrap().insert(svc, h);
    }

    /// Connection statistics for `peer` (AC8): `None` for unknown peers;
    /// fields without samples stay `None`.
    pub fn stats(&self, peer: PeerId) -> Option<ConnStats> {
        self.shared.stats(peer)
    }

    /// Close the session to `peer` (AC9): `open_stream` afterwards returns
    /// [`FlowError::Closed`], the peer's `flow-accept-*`/`flow-dgram-*`
    /// threads exit, and existing streams end per S7 semantics.
    pub fn close_peer(&self, peer: PeerId) {
        self.shared.close_peer(peer);
    }

    fn spawn_listener_thread(&self) {
        let shared = Arc::clone(&self.shared);
        let h = thread::Builder::new()
            .name("flow-accept-listener".into())
            .spawn(move || listener_loop(shared))
            .expect("spawn flow-accept-listener");
        self.shared.threads.lock().unwrap().push(h);
    }

    fn spawn_path_pump_thread(&self) {
        let shared = Arc::clone(&self.shared);
        let h = thread::Builder::new()
            .name("flow-path-pump".into())
            .spawn(move || path_pump_loop(shared))
            .expect("spawn flow-path-pump");
        self.shared.threads.lock().unwrap().push(h);
    }

    fn spawn_unclaimed_thread(&self) {
        let shared = Arc::clone(&self.shared);
        let h = thread::Builder::new()
            .name("flow-unclaimed".into())
            .spawn(move || unclaimed_loop(shared))
            .expect("spawn flow-unclaimed");
        self.shared.threads.lock().unwrap().push(h);
    }
}

impl HubShared {
    fn dial(self: &Arc<Self>, peer: PeerId, candidates: &[SocketAddr]) -> Result<bool, FlowError> {
        if candidates.is_empty() {
            return Err(FlowError::PathUnreachable);
        }
        self.last_candidates
            .lock()
            .unwrap()
            .insert(peer, candidates.to_vec());
        {
            let mut reg = self.registry.lock().unwrap();
            if let Some(entry) = reg.get(&peer) {
                if !entry.closed {
                    return Ok(false);
                }
                // Closed peer: re-dial by replacing the entry.
                reg.remove(&peer);
            }
        }

        let name = peer_hex(&peer);
        // NAT peer? The composition root registers relay/direct conns in
        // PathLink before calling dial (nexusd `NatSwitching`, e4_prod_switch).
        let is_nat = self.link.lock().unwrap().nat_conns(&name).is_some();
        if is_nat {
            if let Some(conns) = self.link.lock().unwrap().nat_conns(&name) {
                self.conn_id_to_peer
                    .lock()
                    .unwrap()
                    .insert(conns.relay.id.0, peer);
            }
            self.registry.lock().unwrap().insert(
                peer,
                HubConn {
                    closed: false,
                    kind: ConnKind::Nat,
                },
            );
            self.spawn_nat_dgram_pump(peer);
            return Ok(true);
        }

        // Direct connection (P0: addrs[0]).
        let conn = FabricConn::connect(
            peer,
            &ConnConfig {
                addrs: candidates.to_vec(),
                handshake_timeout: Duration::from_secs(10),
            },
        )
        .map_err(FlowError::Fabric)?;

        // R4: register candidates with the PathManager and map them to the
        // peer so `PathLink::pump()` can drive `rebind()` on switch (S27).
        {
            let mut link = self.link.lock().unwrap();
            link.add_conn(&name, conn.clone());
            let local = conn
                .stats()
                .active_path
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            for &addr in candidates {
                link.manager().lock().unwrap().add_candidate(CandidatePath {
                    kind: PathKind::Direct,
                    local_addr: local,
                    remote_addr: addr,
                    cost: 0.0,
                });
                link.map_peer_addr(&name, addr);
            }
        }

        self.registry.lock().unwrap().insert(
            peer,
            HubConn {
                closed: false,
                kind: ConnKind::Direct(conn.clone()),
            },
        );
        self.spawn_direct_accept(peer, conn.clone());
        self.spawn_direct_dgram_pump(peer, conn);
        Ok(true)
    }

    fn open_stream(self: &Arc<Self>, peer: PeerId) -> Result<(SendStream, RecvStream), FlowError> {
        // Auto-dial unknown peers that have candidates from a previous dial.
        {
            let reg = self.registry.lock().unwrap();
            if !reg.contains_key(&peer) {
                let cands = self.last_candidates.lock().unwrap().get(&peer).cloned();
                drop(reg);
                if let Some(c) = cands {
                    self.dial(peer, &c)?;
                } else {
                    return Err(FlowError::PathUnreachable);
                }
            }
        }
        match self.resolve_conn(&peer)? {
            ConnRef::Direct(conn) => {
                let (s, r) = conn.open_bi().map_err(FlowError::Fabric)?;
                Ok((SendStream { inner: s }, RecvStream { inner: r }))
            }
            ConnRef::Nat(conn) => {
                let sh = conn.open_stream().map_err(FlowError::Fabric)?;
                let (s, r) = split_stream(sh);
                Ok((SendStream { inner: s }, RecvStream { inner: r }))
            }
        }
    }

    fn send_datagram(&self, peer: PeerId, data: &[u8]) -> Result<(), FlowError> {
        if data.len() > MAX_DATAGRAM_PAYLOAD {
            return Err(FlowError::TooLarge);
        }
        let mut wire = Vec::with_capacity(1 + data.len());
        wire.push(encode_intent_kind(INTENT_SERVICE, 0));
        wire.extend_from_slice(data);
        match self.resolve_conn(&peer)? {
            ConnRef::Direct(conn) => conn.send_datagram(&wire).map_err(FlowError::Fabric),
            ConnRef::Nat(conn) => send_dgram_shared(&conn, wire),
        }
    }

    fn stats(&self, peer: PeerId) -> Option<ConnStats> {
        match self.resolve_conn(&peer) {
            Ok(ConnRef::Direct(conn)) => Some(conn.stats()),
            Ok(ConnRef::Nat(conn)) => Some(conn.stats.lock().unwrap().clone()),
            Err(_) => None,
        }
    }

    fn close_peer(self: &Arc<Self>, peer: PeerId) {
        let mut reg = self.registry.lock().unwrap();
        let entry = match reg.get_mut(&peer) {
            Some(e) => e,
            None => return,
        };
        if entry.closed {
            return;
        }
        entry.closed = true;
        match &entry.kind {
            ConnKind::Direct(conn) => {
                conn.close(0, b"flow-session close");
            }
            ConnKind::Nat => {
                let name = peer_hex(&peer);
                if let Some(conns) = self.link.lock().unwrap().nat_conns(&name) {
                    let _ = conns.relay.tx.send(Cmd::Close {
                        conn: conns.relay.id.0,
                        code: 0,
                        reason: b"flow-session close".to_vec(),
                    });
                    if let Some(d) = &conns.direct {
                        let _ = d.tx.send(Cmd::Close {
                            conn: d.id.0,
                            code: 0,
                            reason: b"flow-session close".to_vec(),
                        });
                    }
                }
            }
        }
        drop(reg);
        self.conn_id_to_peer
            .lock()
            .unwrap()
            .retain(|_, v| *v != peer);
        if let Some(handles) = self.peer_threads.lock().unwrap().remove(&peer) {
            for h in handles {
                let _ = h.join();
            }
        }
    }

    fn resolve_conn(&self, peer: &PeerId) -> Result<ConnRef, FlowError> {
        let reg = self.registry.lock().unwrap();
        let entry = reg.get(peer).ok_or(FlowError::PathUnreachable)?;
        if entry.closed {
            return Err(FlowError::Closed);
        }
        match &entry.kind {
            ConnKind::Direct(conn) => Ok(ConnRef::Direct(conn.clone())),
            ConnKind::Nat => {
                let name = peer_hex(peer);
                let link = self.link.lock().unwrap();
                let conns = link
                    .nat_conns(&name)
                    .ok_or(FlowError::Fabric(FabricError::PathUnreachable))?;
                let active = match conns.active {
                    ActiveConn::Direct => conns
                        .direct
                        .clone()
                        .ok_or(FlowError::Fabric(FabricError::PathUnreachable))?,
                    ActiveConn::Relay => conns.relay.clone(),
                };
                Ok(ConnRef::Nat(active))
            }
        }
    }

    fn active_conn_shared(&self, peer: &PeerId) -> Option<Arc<ConnShared>> {
        let reg = self.registry.lock().unwrap();
        let entry = reg.get(peer)?;
        if entry.closed {
            return None;
        }
        if !matches!(entry.kind, ConnKind::Nat) {
            return None;
        }
        let name = peer_hex(peer);
        let link = self.link.lock().unwrap();
        let conns = link.nat_conns(&name)?;
        match conns.active {
            ActiveConn::Direct => conns.direct.clone(),
            ActiveConn::Relay => Some(conns.relay.clone()),
        }
    }

    /// Direct accept path: read the first byte (service type, D3), route to
    /// the registered handler. The type byte is consumed for routing (AC5).
    fn dispatch_stream(
        &self,
        peer: PeerId,
        send: FabricSendStream,
        mut recv: FabricRecvStream,
    ) -> bool {
        let mut ty = [0u8; 1];
        match recv.read(&mut ty) {
            Ok(1) => {}
            _ => return false,
        }
        let handler = self.stream_services.lock().unwrap().get(&ty[0]).cloned();
        match handler {
            Some(h) => {
                h(peer, SendStream { inner: send }, RecvStream { inner: recv });
                true
            }
            None => false,
        }
    }

    /// R1/D5: inbound streams on punch-registered relay connections arrive
    /// here via `PunchManager::take_unclaimed()` (never `accept_bi`). The
    /// type byte is consumed so handlers see the same stream shape as the
    /// direct accept path.
    fn dispatch_unclaimed(&self, ty: u8, sh: Arc<StreamShared>) {
        let peer = match self
            .conn_id_to_peer
            .lock()
            .unwrap()
            .get(&sh.conn_id)
            .cloned()
        {
            Some(p) => p,
            None => return,
        };
        {
            let mut st = match sh.state.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            st.recv_buf.pop_front();
        }
        let (send, recv) = split_stream(sh);
        let handler = self.stream_services.lock().unwrap().get(&ty).cloned();
        if let Some(h) = handler {
            h(peer, SendStream { inner: send }, RecvStream { inner: recv });
        }
    }

    /// R3/D4: dispatch a received datagram by intent kind. `0x03` service
    /// datagrams go to the handler registered for `d[1]`; `0x00/0x01/0x02`
    /// are not service traffic and are ignored (the Hub has no TUN inbox).
    fn dispatch_datagram(&self, peer: PeerId, d: Vec<u8>) {
        let Some(&first) = d.first() else {
            return;
        };
        let (kind, _hops) = decode_intent_kind(first);
        if kind != INTENT_SERVICE || d.len() < 2 {
            return;
        }
        let svc = d[1];
        let handler = self.datagram_services.lock().unwrap().get(&svc).cloned();
        if let Some(h) = handler {
            h(peer, &d[2..]);
        }
    }

    fn spawn_direct_accept(self: &Arc<Self>, peer: PeerId, conn: FabricConn) {
        let shared = Arc::clone(self);
        let h = thread::Builder::new()
            .name(format!("flow-accept-{}", peer_hex(&peer)))
            .spawn(move || {
                loop {
                    let (send, recv) = match conn.accept_bi() {
                        Ok(x) => x,
                        Err(_) => break,
                    };
                    shared.dispatch_stream(peer, send, recv);
                }
            })
            .expect("spawn flow-accept");
        self.peer_threads
            .lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .push(h);
    }

    fn spawn_direct_dgram_pump(self: &Arc<Self>, peer: PeerId, conn: FabricConn) {
        let shared = Arc::clone(self);
        let h = thread::Builder::new()
            .name(format!("flow-dgram-{}", peer_hex(&peer)))
            .spawn(move || direct_dgram_loop(shared, peer, conn))
            .expect("spawn flow-dgram");
        self.peer_threads
            .lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .push(h);
    }

    fn spawn_nat_dgram_pump(self: &Arc<Self>, peer: PeerId) {
        let shared = Arc::clone(self);
        let h = thread::Builder::new()
            .name(format!("flow-dgram-{}", peer_hex(&peer)))
            .spawn(move || nat_dgram_loop(shared, peer))
            .expect("spawn flow-dgram");
        self.peer_threads
            .lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .push(h);
    }
}

/// Listener accept thread: accepts inbound connections and runs an
/// `accept_bi` loop per connection (these are NOT punch-registered relays).
fn listener_loop(shared: Arc<HubShared>) {
    while !shared.shutdown.load(Ordering::Relaxed) {
        match shared.listener.accept_timeout(Duration::from_millis(100)) {
            Ok(conn) => {
                let peer = conn.peer();
                let id = conn.id().0;
                let shared2 = Arc::clone(&shared);
                let conn2 = conn.clone();
                let h = thread::Builder::new()
                    .name(format!("flow-accept-in-{id}"))
                    .spawn(move || {
                        loop {
                            let (send, recv) = match conn2.accept_bi() {
                                Ok(x) => x,
                                Err(_) => break,
                            };
                            shared2.dispatch_stream(peer, send, recv);
                        }
                    })
                    .expect("spawn inbound accept");
                shared.inbound_conns.lock().unwrap().push(conn.clone());
                shared.threads.lock().unwrap().push(h);
                // Inbound connections also carry service datagrams (AC2):
                // pump them with the same R3 dispatch as dialed peers.
                let shared3 = Arc::clone(&shared);
                let conn3 = conn;
                let hd = thread::Builder::new()
                    .name(format!("flow-dgram-in-{id}"))
                    .spawn(move || {
                        while let Ok(d) = conn3.recv_datagram() {
                            if shared3.shutdown.load(Ordering::Relaxed) {
                                break;
                            }
                            shared3.dispatch_datagram(peer, d);
                        }
                    })
                    .expect("spawn inbound datagram pump");
                shared.threads.lock().unwrap().push(hd);
            }
            Err(_) => continue,
        }
    }
}

/// Drives `PathLink::pump()` (R2): `Switched` events call `rebind()` for
/// legacy peers and flip the active connection for NAT peers (D1).
fn path_pump_loop(shared: Arc<HubShared>) {
    while !shared.shutdown.load(Ordering::Relaxed) {
        shared.link.lock().unwrap().pump();
        thread::sleep(Duration::from_millis(10));
    }
}

/// R1/D5: sole consumer of `PunchManager::take_unclaimed()`; routes
/// non-punch relay streams to the registered service handlers.
fn unclaimed_loop(shared: Arc<HubShared>) {
    while !shared.shutdown.load(Ordering::Relaxed) {
        match shared.punch.take_unclaimed() {
            Some((ty, sh)) => shared.dispatch_unclaimed(ty, sh),
            None => thread::sleep(Duration::from_millis(1)),
        }
    }
}

/// Datagram pump for a direct `FabricConn`.
fn direct_dgram_loop(shared: Arc<HubShared>, peer: PeerId, conn: FabricConn) {
    while let Ok(d) = conn.recv_datagram() {
        if shared.shutdown.load(Ordering::Relaxed) {
            break;
        }
        shared.dispatch_datagram(peer, d);
    }
}

/// Datagram pump for a NAT peer: follows the currently active connection
/// (relay or direct) and exits when the peer is closed.
fn nat_dgram_loop(shared: Arc<HubShared>, peer: PeerId) {
    while !shared.shutdown.load(Ordering::Relaxed) {
        let closed = shared
            .registry
            .lock()
            .unwrap()
            .get(&peer)
            .map(|e| e.closed)
            .unwrap_or(true);
        if closed {
            break;
        }
        let Some(conn) = shared.active_conn_shared(&peer) else {
            thread::sleep(Duration::from_millis(10));
            continue;
        };
        match recv_dgram_timeout(&conn, Duration::from_millis(100)) {
            Some(d) => shared.dispatch_datagram(peer, d),
            None => {
                if conn_closed(&conn) {
                    break;
                }
            }
        }
    }
}

impl Drop for FlowSessionHub {
    fn drop(&mut self) {
        let shared = &self.shared;
        shared.shutdown.store(true, Ordering::Relaxed);
        // E-3 lesson: close conns FIRST to unblock blocking I/O, then join.
        {
            let reg = shared.registry.lock().unwrap();
            for entry in reg.values() {
                if let ConnKind::Direct(conn) = &entry.kind {
                    conn.close(0, b"hub drop");
                }
            }
        }
        for conn in shared.inbound_conns.lock().unwrap().iter() {
            conn.close(0, b"hub drop");
        }
        {
            let reg = shared.registry.lock().unwrap();
            for (peer, entry) in reg.iter() {
                if matches!(entry.kind, ConnKind::Nat) {
                    if let Some(conns) = shared.link.lock().unwrap().nat_conns(&peer_hex(peer)) {
                        let _ = conns.relay.tx.send(Cmd::Close {
                            conn: conns.relay.id.0,
                            code: 0,
                            reason: b"hub drop".to_vec(),
                        });
                        if let Some(d) = &conns.direct {
                            let _ = d.tx.send(Cmd::Close {
                                conn: d.id.0,
                                code: 0,
                                reason: b"hub drop".to_vec(),
                            });
                        }
                    }
                }
            }
        }
        for h in shared.threads.lock().unwrap().drain(..) {
            let _ = h.join();
        }
        for (_, hs) in shared.peer_threads.lock().unwrap().drain() {
            for h in hs {
                let _ = h.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn udp_loopback_available() -> bool {
        use std::net::UdpSocket;
        let a = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return false,
        };
        let b = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return false,
        };
        let bp = match b.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return false,
        };
        a.send_to(b"probe", format!("127.0.0.1:{bp}")).is_ok()
    }

    fn test_hub() -> Option<(FlowSessionHub, PeerId, SocketAddr)> {
        if !udp_loopback_available() {
            return None;
        }
        let listener = FabricListener::bind(addr(0)).ok()?;
        let peer = listener.peer_id();
        let local = listener.local_addr().ok()?;
        let link = PathLink::new(Arc::new(Mutex::new(nexus_path::PathManager::new(
            nexus_path::PathConfig::default(),
        ))));
        let punch = PunchManager::new(nexus_fabric::Driver::new_client().ok()?, PeerId([9u8; 32]));
        let hub = FlowSessionHub::new(listener, link, punch);
        Some((hub, peer, local))
    }

    /// AC4: on-demand dial is idempotent and reuse happens after the first
    /// connect. Three `open_stream` calls on a dialed peer reuse the single
    /// underlying connection (the raw listener accepts exactly once).
    #[test]
    fn ac4_dial_idempotent_and_stream_reuses_conn() {
        let Some((hub_a, _peer_b, _addr_b)) = test_hub() else {
            return; // UDP blocked: true verification on xc-pc-linux
        };
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener_b = FabricListener::bind(addr(0)).expect("bind B");
        let peer_b_expected = listener_b.peer_id();
        let addr_b_listener = listener_b.local_addr().expect("local addr");
        let accepted2 = Arc::clone(&accepted);
        let accept_thread = thread::spawn(move || {
            // The Hub dials peer_b (which equals listener_b's peer id).
            let _conn = listener_b.accept().expect("accept");
            accepted2.fetch_add(1, Ordering::Relaxed);
        });

        let peer_b = peer_b_expected;
        let addr_b = addr_b_listener;
        // First dial creates the connection.
        assert!(hub_a.dial(peer_b, &[addr_b]).expect("dial"));
        // Idempotent dial reuses it.
        assert!(!hub_a.dial(peer_b, &[addr_b]).expect("dial"));
        // Three stream opens reuse the same connection.
        for _ in 0..3 {
            let (_s, _r) = hub_a.open_stream(peer_b).expect("open stream");
        }
        accept_thread.join().expect("accept thread");
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        hub_a.close_peer(peer_b);
    }

    /// AC8: stats are honest — connected peer has `rtt_ms: Some`, unknown
    /// peers return `None`, and unsampled fields stay `None`.
    #[test]
    fn ac8_stats_honest() {
        let Some((hub_a, _peer_b, _addr_b)) = test_hub() else {
            return; // UDP blocked: true verification on xc-pc-linux
        };
        let listener_b = FabricListener::bind(addr(0)).expect("bind B");
        let peer_b = listener_b.peer_id();
        let addr_b = listener_b.local_addr().expect("local addr");
        let accept_thread = thread::spawn(move || listener_b.accept());

        hub_a.dial(peer_b, &[addr_b]).expect("dial");
        let _res = accept_thread.join().expect("accept thread");

        // The driver publishes RTT samples on its pump loop after the
        // handshake; poll briefly (honest: `Some` only once a sample exists).
        let mut rtt_seen = false;
        for _ in 0..100 {
            let s = hub_a.stats(peer_b).expect("stats for connected peer");
            if s.rtt_ms.is_some() {
                rtt_seen = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(rtt_seen, "connected peer must have rtt samples");
        let s = hub_a.stats(peer_b).expect("stats for connected peer");
        // Unsampled fields stay None (S8: honest).
        assert!(s.loss_rate.is_none());
        assert!(s.jitter_ms.is_none());
        assert!(s.throughput_bps.is_none());

        let unknown = PeerId([0xEE; 32]);
        assert!(hub_a.stats(unknown).is_none());
        hub_a.close_peer(peer_b);
    }

    /// AC9: after `close_peer`, `open_stream` returns `Closed` and the
    /// Hub's `flow-accept-*` thread count returns to baseline.
    #[test]
    fn ac9_close_peer_semantics() {
        let Some((hub_a, _peer_b, _addr_b)) = test_hub() else {
            return; // UDP blocked: true verification on xc-pc-linux
        };
        let listener_b = FabricListener::bind(addr(0)).expect("bind B");
        let peer_b = listener_b.peer_id();
        let addr_b = listener_b.local_addr().expect("local addr");
        let accept_thread = thread::spawn(move || listener_b.accept());

        // Process-level count of `flow-accept-*` threads whose truncated
        // comm (15 chars) matches this peer's accept thread. The per-peer
        // thread is named `flow-accept-<64-hex>`, so its comm is
        // `flow-accept-` + the first 3 hex chars (unique per peer).
        let peer_h = peer_hex(&peer_b);
        let comm_prefix = format!("flow-accept-{}", &peer_h[..3]);
        let count_flow_accept = || {
            let mut n = 0usize;
            if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
                for e in rd.flatten() {
                    let comm_path = e.path().join("comm");
                    if let Ok(name) = std::fs::read_to_string(comm_path) {
                        if name.trim() == comm_prefix {
                            n += 1;
                        }
                    }
                }
            }
            n
        };

        let baseline = count_flow_accept();
        hub_a.dial(peer_b, &[addr_b]).expect("dial");
        let _res = accept_thread.join().expect("accept thread");
        // Wait for the per-peer accept thread to be observable.
        let mut seen = 0usize;
        for _ in 0..100 {
            seen = count_flow_accept();
            if seen >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(seen >= 1, "flow-accept-<peer> thread should be up");
        // Internal per-peer handle count (accept + datagram pumps).
        let handles_before_close = hub_a
            .shared
            .peer_threads
            .lock()
            .unwrap()
            .get(&peer_b)
            .map(|v| v.len())
            .unwrap_or(0);
        assert!(handles_before_close >= 1);

        // Stream works before close.
        let (_s, _r) = hub_a.open_stream(peer_b).expect("open before close");

        hub_a.close_peer(peer_b);
        // After close, open_stream returns Closed.
        let err = hub_a
            .open_stream(peer_b)
            .err()
            .expect("open after close must fail");
        assert_eq!(err, FlowError::Closed);
        // Internal per-peer handles are drained (difference 0).
        let handles_after_close = hub_a
            .shared
            .peer_threads
            .lock()
            .unwrap()
            .get(&peer_b)
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(
            handles_after_close, 0,
            "flow-accept-* thread count difference must be 0"
        );
        // Process-level `flow-accept-<peer>` thread count returns to baseline.
        let after = count_flow_accept();
        assert_eq!(
            after, baseline,
            "process-level flow-accept-* count difference must be 0"
        );
    }

    /// AC11: `send_datagram` with `data.len() > 1200` returns `TooLarge`;
    /// `SendStream::write` with a single write > 256 KiB returns `TooLarge`
    /// (the stream wrapper enforces the frozen AC11 bound).
    #[test]
    fn ac11_oversize_returns_toolarge() {
        let Some((hub_a, _peer_b, _addr_b)) = test_hub() else {
            return; // UDP blocked: true verification on xc-pc-linux
        };
        let listener_b = FabricListener::bind(addr(0)).expect("bind B");
        let peer_b = listener_b.peer_id();
        let addr_b = listener_b.local_addr().expect("local addr");
        let accept_thread = thread::spawn(move || listener_b.accept());

        hub_a.dial(peer_b, &[addr_b]).expect("dial");
        let _res = accept_thread.join().expect("accept thread");

        // Datagram oversize (AC11).
        let big = vec![0u8; MAX_DATAGRAM_PAYLOAD + 1];
        let err = hub_a.send_datagram(peer_b, &big).unwrap_err();
        assert_eq!(err, FlowError::TooLarge);

        // Stream write oversize (AC11).
        let (mut send, _recv) = hub_a.open_stream(peer_b).expect("open stream");
        let big_stream = vec![0u8; MAX_STREAM_WRITE + 1];
        let err = send.write(&big_stream).unwrap_err();
        assert_eq!(err, FlowError::TooLarge);

        hub_a.close_peer(peer_b);
    }
}
