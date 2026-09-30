//! std-thread driver for quinn-proto (sans-IO).
//!
//! One OS thread owns the [`UdpTransport`](crate::transport::UdpTransport)
//! and the `quinn_proto::Endpoint`.
//! The public sync API talks to it through an mpsc command channel plus
//! shared `Mutex`/`Condvar` state. `quinn_proto::Connection` never leaves
//! the driver thread.
//!
//! Concurrency ownership (§13): the [`Driver`] (held via `Arc` by every
//! `FabricConn`/`FabricListener` created from it) owns the thread's
//! `JoinHandle`; `Drop` sends `Shutdown` and joins (reaper).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, ServerConfig,
    StreamId, VarInt, crypto::rustls::QuicClientConfig,
};

use crate::cert::{Identity, build_client_crypto, build_server_config, generate_identity};
use crate::transport::{StdUdpTransport, UdpTransport};
use crate::{ConnStats, ConnectionId, FabricError, PeerId};

/// Logical connection ids; process-wide unique (P0: one driver per connection
/// on the client side, one driver per listener on the server side).
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Lower bound for the UDP poll timeout in the driver drain loop.
///
/// `UdpSocket::set_read_timeout(Some(Duration::ZERO))` is rejected with
/// `InvalidInput`, leaving the socket in whatever mode it had. On a freshly
/// rebound socket that means blocking forever. A zero computed timeout means
/// a QUIC timer is already due; wait minimally instead of hanging.
fn min_poll_timeout(d: Duration) -> Duration {
    d.max(Duration::from_millis(1))
}

/// Upper bound for a command-channel wakeup while blocked in `recv_from`.
/// Bounds both command latency and QUIC timer granularity (P0: coarse pacing is fine).
const POLL_CAP: Duration = Duration::from_millis(5);

/// Largest UDP datagram the driver reads.
const RECV_BUF: usize = 65536;

// ---------------------------------------------------------------------------
// Shared state (public handles <-> driver thread)
// ---------------------------------------------------------------------------

/// Per-connection state shared with the public API.
pub struct ConnShared {
    pub id: ConnectionId,
    /// Remote peer. Client side: the expected peer. Server side: unknown in P0
    /// (no client auth yet) and stays zeroed; documented, not fabricated.
    pub peer: PeerId,
    pub tx: mpsc::Sender<Cmd>,
    pub state: Mutex<ConnState>,
    pub state_cv: Condvar,
    pub accepted: Mutex<VecDeque<Arc<StreamShared>>>,
    pub accepted_cv: Condvar,
    pub dgrams: Mutex<VecDeque<Vec<u8>>>,
    pub dgram_cv: Condvar,
    pub stats: Mutex<ConnStats>,
}

pub struct ConnState {
    pub connected: bool,
    pub closed: Option<FabricError>,
}

impl std::fmt::Debug for ConnShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnShared")
            .field("id", &self.id)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl ConnShared {
    fn new(id: ConnectionId, peer: PeerId, tx: mpsc::Sender<Cmd>) -> Self {
        Self {
            id,
            peer,
            tx,
            state: Mutex::new(ConnState {
                connected: false,
                closed: None,
            }),
            state_cv: Condvar::new(),
            accepted: Mutex::new(VecDeque::new()),
            accepted_cv: Condvar::new(),
            dgrams: Mutex::new(VecDeque::new()),
            dgram_cv: Condvar::new(),
            stats: Mutex::new(ConnStats::unknown()),
        }
    }
}

/// Per-stream state shared with the public API.
///
/// P0 buffering model: `SendStream::write` appends to an in-memory queue and
/// returns immediately; the driver moves bytes into QUIC. No backpressure yet
/// (documented limitation; the frozen API returns bytes-accepted).
pub struct StreamShared {
    pub conn_id: u64,
    pub tx: mpsc::Sender<Cmd>,
    pub state: Mutex<StreamState>,
    pub cv: Condvar,
}

pub struct StreamState {
    pub send_buf: VecDeque<u8>,
    pub send_fin: bool,
    pub fin_sent: bool,
    pub recv_buf: VecDeque<u8>,
    pub recv_eof: bool,
    pub error: Option<FabricError>,
}

impl StreamShared {
    fn new(conn_id: u64, tx: mpsc::Sender<Cmd>) -> Self {
        Self {
            conn_id,
            tx,
            state: Mutex::new(StreamState {
                send_buf: VecDeque::new(),
                send_fin: false,
                fin_sent: false,
                recv_buf: VecDeque::new(),
                recv_eof: false,
                error: None,
            }),
            cv: Condvar::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Commands from the public API to the driver thread.
pub enum Cmd {
    Connect {
        remote: SocketAddr,
        crypto: QuicClientConfig,
        peer: PeerId,
        server_name: String,
        reply: mpsc::Sender<Result<u64, FabricError>>,
    },
    OpenBi {
        conn: u64,
        reply: mpsc::Sender<Result<Arc<StreamShared>, FabricError>>,
    },
    SendDatagram {
        conn: u64,
        data: Vec<u8>,
        reply: mpsc::Sender<Result<(), FabricError>>,
    },
    /// State changed (write/finish/datagram queued): pump soon.
    Pump {
        conn: u64,
    },
    Rebind {
        conn: u64,
        reply: mpsc::Sender<Result<SocketAddr, FabricError>>,
    },
    Close {
        conn: u64,
        code: u32,
        reason: Vec<u8>,
    },
    Shutdown,
}

pub struct Driver {
    tx: mpsc::Sender<Cmd>,
    shared: Arc<DriverShared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver").finish_non_exhaustive()
    }
}

pub struct DriverShared {
    pub conns: Mutex<HashMap<u64, Arc<ConnShared>>>,
    pub accept_q: Mutex<VecDeque<u64>>,
    pub accept_cv: Condvar,
    pub local_addr: Mutex<SocketAddr>,
    pub peer_id: Option<PeerId>,
}

impl Driver {
    fn spawn(
        bind: SocketAddr,
        server: Option<(ServerConfig, Identity)>,
    ) -> Result<Arc<Self>, FabricError> {
        let transport: Box<dyn UdpTransport> = Box::new(
            StdUdpTransport::bind(bind).map_err(|e| FabricError::Transport(e.to_string()))?,
        );
        Self::spawn_with_transport(transport, server)
    }

    /// Spawn the driver on a caller-provided transport (S9).
    ///
    /// Used for relayed paths (e.g. `nexus-turn::TurnSocket`); the default
    /// [`Self::spawn`] wraps a direct `UdpSocket`.
    fn spawn_with_transport(
        transport: Box<dyn UdpTransport>,
        server: Option<(ServerConfig, Identity)>,
    ) -> Result<Arc<Self>, FabricError> {
        let local_addr = transport
            .local_addr()
            .map_err(|e| FabricError::Transport(e.to_string()))?;
        let (server_config, identity) = server
            .map(|(c, i)| (Some(Arc::new(c)), Some(i)))
            .unwrap_or((None, None));
        let peer_id = identity.as_ref().map(|i| i.peer_id);
        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            server_config.clone(),
            false,
            None,
        );
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(DriverShared {
            conns: Mutex::new(HashMap::new()),
            accept_q: Mutex::new(VecDeque::new()),
            accept_cv: Condvar::new(),
            local_addr: Mutex::new(local_addr),
            peer_id,
        });
        let lp = Loop {
            rx,
            tx: tx.clone(),
            shared: shared.clone(),
            socket: transport,
            endpoint,
            server_config,
            live: HashMap::new(),
            handle_map: HashMap::new(),
            buf: vec![0u8; RECV_BUF],
            out: Vec::new(),
        };
        let thread = thread::Builder::new()
            .name("nexus-fabric-drv".into())
            .spawn(move || lp.run())
            .map_err(|e| FabricError::Transport(format!("driver thread: {e}")))?;
        Ok(Arc::new(Self {
            tx,
            shared,
            thread: Mutex::new(Some(thread)),
        }))
    }

    /// Client endpoint: fresh UDP socket, no identity needed in P0.
    pub fn new_client() -> Result<Arc<Self>, FabricError> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Self::spawn(addr, None)
    }

    /// Client endpoint on a caller-provided transport (S9).
    pub fn new_client_with_transport(
        transport: Box<dyn UdpTransport>,
    ) -> Result<Arc<Self>, FabricError> {
        Self::spawn_with_transport(transport, None)
    }

    /// Server endpoint: generates an ed25519 identity, binds `addr`.
    pub fn new_server(addr: SocketAddr) -> Result<Arc<Self>, FabricError> {
        let id = generate_identity()?;
        let cfg = build_server_config(&id)?;
        Self::spawn(addr, Some((cfg, id)))
    }

    /// Server endpoint on a caller-provided transport (S9).
    pub fn new_server_with_transport(
        transport: Box<dyn UdpTransport>,
    ) -> Result<Arc<Self>, FabricError> {
        let id = generate_identity()?;
        let cfg = build_server_config(&id)?;
        Self::spawn_with_transport(transport, Some((cfg, id)))
    }

    pub fn shared(&self) -> &Arc<DriverShared> {
        &self.shared
    }

    pub fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }

    /// Establish a connection (blocks until QUIC handshake completes).
    pub fn connect(
        self: &Arc<Self>,
        peer: PeerId,
        remote: SocketAddr,
        handshake_timeout: Duration,
    ) -> Result<Arc<ConnShared>, FabricError> {
        let crypto = build_client_crypto(peer)?;
        let (tx, rx) = mpsc::channel();
        self.send(Cmd::Connect {
            remote,
            crypto,
            peer,
            server_name: "nexus-fabric".to_string(),
            reply: tx,
        });
        let conn_id = rx
            .recv_timeout(handshake_timeout)
            .map_err(|_| FabricError::Timeout)??;
        let shared = self
            .shared
            .conns
            .lock()
            .unwrap()
            .get(&conn_id)
            .cloned()
            .ok_or(FabricError::Closed(0))?;
        // Wait for handshake completion (or failure).
        let deadline = Instant::now() + handshake_timeout;
        let mut st = shared.state.lock().unwrap();
        loop {
            if st.connected {
                break;
            }
            if let Some(e) = st.closed.clone() {
                return Err(e);
            }
            let now = Instant::now();
            if now >= deadline {
                drop(st);
                self.send(Cmd::Close {
                    conn: conn_id,
                    code: 0,
                    reason: b"connect timeout".to_vec(),
                });
                return Err(FabricError::Timeout);
            }
            let (g, _) = shared
                .state_cv
                .wait_timeout(st, deadline - now)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
            st = g;
        }
        drop(st);
        Ok(shared)
    }

    /// Accept the next incoming connection (blocks).
    pub fn accept_conn(self: &Arc<Self>) -> Result<Arc<ConnShared>, FabricError> {
        let mut q = self.shared.accept_q.lock().unwrap();
        loop {
            if let Some(id) = q.pop_front() {
                return self
                    .shared
                    .conns
                    .lock()
                    .unwrap()
                    .get(&id)
                    .cloned()
                    .ok_or(FabricError::Closed(0));
            }
            q = self
                .shared
                .accept_cv
                .wait(q)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
        if let Some(h) = self.thread.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Driver loop (owns socket + endpoint + all quinn Connections)
// ---------------------------------------------------------------------------

struct LiveConn {
    handle: ConnectionHandle,
    quic: quinn_proto::Connection,
    shared: Arc<ConnShared>,
    streams: HashMap<StreamId, Arc<StreamShared>>,
    dgram_tx_q: VecDeque<Vec<u8>>,
    bytes_sent: u64,
    bytes_recv: u64,
}

struct Loop {
    rx: mpsc::Receiver<Cmd>,
    tx: mpsc::Sender<Cmd>,
    shared: Arc<DriverShared>,
    socket: Box<dyn UdpTransport>,
    endpoint: Endpoint,
    server_config: Option<Arc<ServerConfig>>,
    live: HashMap<u64, LiveConn>,
    handle_map: HashMap<ConnectionHandle, u64>,
    buf: Vec<u8>,
    out: Vec<u8>,
}

impl Loop {
    fn run(mut self) {
        loop {
            let now = Instant::now();
            // 1. Commands.
            let mut shutdown = false;
            while let Ok(cmd) = self.rx.try_recv() {
                if self.handle_cmd(cmd, now) {
                    shutdown = true;
                    break;
                }
            }
            if shutdown {
                break;
            }
            // 2. Pump (applies command effects + due timers).
            let now = Instant::now();
            let ids: Vec<u64> = self.live.keys().copied().collect();
            for id in ids {
                self.pump_one(id, now);
            }
            // 3. Incoming UDP: drain the socket fully (a single recv_from per
            // iteration lets bursts overflow the kernel buffer), then block
            // briefly for the next packet or timer.
            loop {
                let now = Instant::now();
                let deadline = self.next_deadline(now);
                let timeout = deadline.saturating_duration_since(now).min(POLL_CAP);
                // Never pass a zero timeout: `set_read_timeout(Some(ZERO))`
                // is rejected with InvalidInput, leaving the socket as-is.
                // On a freshly rebound socket that means blocking forever.
                // A zero timeout means a timer is already due, so use a
                // minimal wait and let the next pump handle it.
                let timeout = min_poll_timeout(timeout);
                if let Err(e) = self.socket.set_read_timeout(Some(timeout)) {
                    debug_assert!(false, "set_read_timeout failed: {e:?}");
                }
                match self.socket.recv_from(&mut self.buf) {
                    Ok((n, remote)) => self.on_udp(n, remote),
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            // 4. Pump again (applies incoming packets).
            let now = Instant::now();
            let ids: Vec<u64> = self.live.keys().copied().collect();
            for id in ids {
                self.pump_one(id, now);
            }
        }
    }

    /// Returns true on Shutdown.
    fn handle_cmd(&mut self, cmd: Cmd, now: Instant) -> bool {
        match cmd {
            Cmd::Shutdown => return true,
            Cmd::Connect {
                remote,
                crypto,
                peer,
                server_name,
                reply,
            } => {
                let r = self.cmd_connect(remote, crypto, peer, &server_name, now);
                let _ = reply.send(r);
            }
            Cmd::OpenBi { conn, reply } => {
                let r = self.cmd_open_bi(conn);
                let _ = reply.send(r);
            }
            Cmd::SendDatagram { conn, data, reply } => {
                let r = self.cmd_send_datagram(conn, data);
                let _ = reply.send(r);
            }
            Cmd::Pump { conn } => {
                self.pump_one(conn, Instant::now());
            }
            Cmd::Rebind { conn, reply } => {
                let r = self.cmd_rebind(conn);
                let _ = reply.send(r);
            }
            Cmd::Close { conn, code, reason } => {
                if let Some(lc) = self.live.get_mut(&conn) {
                    lc.quic
                        .close(Instant::now(), VarInt::from_u32(code), Bytes::from(reason));
                }
            }
        }
        false
    }

    fn cmd_connect(
        &mut self,
        remote: SocketAddr,
        crypto: QuicClientConfig,
        peer: PeerId,
        server_name: &str,
        now: Instant,
    ) -> Result<u64, FabricError> {
        let mut cc = ClientConfig::new(Arc::new(crypto));
        cc.transport_config(crate::cert::quic_transport_config());
        let (handle, quic) = self
            .endpoint
            .connect(now, cc, remote, server_name)
            .map_err(|e| FabricError::Transport(format!("quic connect: {e:?}")))?;
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(ConnShared::new(ConnectionId(id), peer, self.tx.clone()));
        self.handle_map.insert(handle, id);
        self.live.insert(
            id,
            LiveConn {
                handle,
                quic,
                shared: shared.clone(),
                streams: HashMap::new(),
                dgram_tx_q: VecDeque::new(),
                bytes_sent: 0,
                bytes_recv: 0,
            },
        );
        self.shared.conns.lock().unwrap().insert(id, shared);
        Ok(id)
    }

    fn cmd_open_bi(&mut self, conn: u64) -> Result<Arc<StreamShared>, FabricError> {
        let lc = self.live.get_mut(&conn).ok_or(FabricError::Closed(0))?;
        let qid = lc
            .quic
            .streams()
            .open(Dir::Bi)
            .ok_or_else(|| FabricError::Transport("stream limit reached".into()))?;
        let sh = Arc::new(StreamShared::new(conn, self.tx.clone()));
        lc.streams.insert(qid, sh.clone());
        Ok(sh)
    }

    fn cmd_send_datagram(&mut self, conn: u64, data: Vec<u8>) -> Result<(), FabricError> {
        let lc = self.live.get_mut(&conn).ok_or(FabricError::Closed(0))?;
        lc.dgram_tx_q.push_back(data);
        Ok(())
    }

    /// Active migration: swap the UDP socket so subsequent packets go out
    /// from a new local port. The peer migrates via QUIC path validation
    /// (S3, S6) when it sees the new source address (passive migration).
    ///
    /// Note: we deliberately do NOT call quinn-proto's
    /// `local_address_changed()` here: its `update_rem_cid` + `ping` path
    /// trips a `debug_assert!` in quinn-proto 0.11.18's `pto_time_and_space`
    /// when the connection goes idle post-migration. Passive migration
    /// (new source address observed by the peer) is RFC 9000 §9-compliant
    /// and sufficient.
    fn cmd_rebind(&mut self, conn: u64) -> Result<SocketAddr, FabricError> {
        if !self.live.contains_key(&conn) {
            return Err(FabricError::Closed(0));
        }
        // Rebind always reverts to a fresh direct UDP socket (S9): re-creating
        // a TURN allocation mid-connection is out of scope for 4b. The TURN
        // path is exercised without rebind (see product.fabric-turn-relay).
        //
        // D0 (N1 装配)：绑定 0.0.0.0 而非 127.0.0.1。回环绑定在真实拓扑
        // （双 netns + veth / 任何非回环 underlay）下无法到达对端，
        // rebind 后的连接会永久失联；wildcard 让内核按路由选源地址，
        // 在回环拓扑上的行为与原来一致（回归风险低）。
        //
        // N1 E4 修复：优先尝试绑定到原地址（保留端口）。Listener 重绑到
        // 随机端口会导致对端按旧端口发送的包丢失；若原 IP 已不存在
        // （如 roam 后旧 IP 被删除），则回退到 wildcard。
        // Server 必须保留端口（well-known），bind 失败则报错而非回退。
        let orig = *self.shared.local_addr.lock().unwrap();
        let is_server = self.server_config.is_some();
        let sock: Box<dyn UdpTransport> = match StdUdpTransport::bind(orig) {
            Ok(s) => Box::new(s),
            Err(e) => {
                if is_server {
                    return Err(FabricError::Transport(format!(
                        "server rebind must preserve {orig}, bind failed: {e}"
                    )));
                }
                // Client: 原 IP 已消失（如 roam），回退到 wildcard。
                Box::new(
                    StdUdpTransport::bind("0.0.0.0:0".parse().unwrap())
                        .map_err(|e| FabricError::Transport(e.to_string()))?,
                )
            }
        };
        let addr = sock
            .local_addr()
            .map_err(|e| FabricError::Transport(e.to_string()))?;
        self.socket = sock;
        *self.shared.local_addr.lock().unwrap() = addr;
        // Refresh stats immediately so the caller observes the new path.
        self.update_stats(conn);
        Ok(addr)
    }

    fn on_udp(&mut self, n: usize, remote: SocketAddr) {
        let now = Instant::now();
        let local_ip = self.socket.local_addr().ok().map(|a| a.ip());
        let data = BytesMut::from(&self.buf[..n]);
        let ev = self
            .endpoint
            .handle(now, remote, local_ip, None, data, &mut self.out);
        match ev {
            None => {}
            Some(DatagramEvent::Response(t)) => {
                let pkt = self.out[..t.size].to_vec();
                let _ = self.socket.send_to(&pkt, t.destination);
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                self.on_new_connection(incoming, now);
            }
            Some(DatagramEvent::ConnectionEvent(ch, cev)) => {
                if let Some(id) = self.handle_map.get(&ch).copied() {
                    if let Some(lc) = self.live.get_mut(&id) {
                        lc.quic.handle_event(cev);
                    }
                }
            }
        }
        self.out.clear();
    }

    fn on_new_connection(&mut self, incoming: quinn_proto::Incoming, now: Instant) {
        // Client-mode endpoints have no server config: drop stray handshakes.
        if self.server_config.is_none() {
            return;
        }
        match self
            .endpoint
            .accept(incoming, now, &mut self.out, self.server_config.clone())
        {
            Ok((handle, quic)) => {
                let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                // P0: no client auth, so the peer id is unknown (zeroed, documented).
                let shared = Arc::new(ConnShared::new(
                    ConnectionId(id),
                    PeerId([0u8; 32]),
                    self.tx.clone(),
                ));
                self.handle_map.insert(handle, id);
                self.live.insert(
                    id,
                    LiveConn {
                        handle,
                        quic,
                        shared: shared.clone(),
                        streams: HashMap::new(),
                        dgram_tx_q: VecDeque::new(),
                        bytes_sent: 0,
                        bytes_recv: 0,
                    },
                );
                self.shared.conns.lock().unwrap().insert(id, shared);
                self.shared.accept_q.lock().unwrap().push_back(id);
                self.shared.accept_cv.notify_one();
            }
            Err(e) => {
                if let Some(t) = e.response {
                    let pkt = self.out[..t.size].to_vec();
                    let _ = self.socket.send_to(&pkt, t.destination);
                }
            }
        }
    }

    fn next_deadline(&mut self, now: Instant) -> Instant {
        let mut dl = now + POLL_CAP;
        for lc in self.live.values_mut() {
            if let Some(t) = lc.quic.poll_timeout() {
                if t < dl {
                    dl = t;
                }
            }
        }
        dl
    }

    fn pump_one(&mut self, id: u64, now: Instant) {
        // Collect connection events first (avoids &mut self reborrow issues).
        let evs: Vec<quinn_proto::Event> = match self.live.get_mut(&id) {
            Some(lc) => {
                if matches!(lc.quic.poll_timeout(), Some(t) if t <= now) {
                    lc.quic.handle_timeout(now);
                }
                while let Some(ev) = lc.quic.poll_endpoint_events() {
                    if let Some(cev) = self.endpoint.handle_event(lc.handle, ev) {
                        lc.quic.handle_event(cev);
                    }
                }
                let mut evs = Vec::new();
                while let Some(ev) = lc.quic.poll() {
                    evs.push(ev);
                }
                evs
            }
            None => return,
        };
        for ev in evs {
            self.on_conn_event(id, ev);
        }
        // Streams.
        let qids: Vec<StreamId> = match self.live.get(&id) {
            Some(lc) => lc.streams.keys().copied().collect(),
            None => return,
        };
        for qid in qids {
            self.pump_stream(id, qid);
        }
        // Datagrams: flush queued sends, drain received.
        if let Some(lc) = self.live.get_mut(&id) {
            while let Some(d) = lc.dgram_tx_q.pop_front() {
                let len = d.len();
                match lc.quic.datagrams().send(Bytes::from(d), true) {
                    Ok(()) => {
                        lc.bytes_sent += len as u64;
                    }
                    Err(quinn_proto::SendDatagramError::Blocked(data)) => {
                        lc.dgram_tx_q.push_front(data.to_vec());
                        break;
                    }
                    // Best-effort drop (S5).
                    Err(_) => {}
                }
            }
            let shared = lc.shared.clone();
            let mut got = false;
            while let Some(b) = lc.quic.datagrams().recv() {
                lc.bytes_recv += b.len() as u64;
                shared.dgrams.lock().unwrap().push_back(b.to_vec());
                got = true;
            }
            if got {
                shared.dgram_cv.notify_all();
            }
        }
        // Transmit.
        if let Some(lc) = self.live.get_mut(&id) {
            while let Some(t) = lc.quic.poll_transmit(now, 1, &mut self.out) {
                let pkt = self.out[..t.size].to_vec();
                let _ = self.socket.send_to(&pkt, t.destination);
                self.out.clear();
            }
        }
        self.update_stats(id);
        // Reap fully-closed connections (keep shared state for late stats()).
        let reaped = match self.live.get_mut(&id) {
            Some(lc) => {
                lc.quic.poll_timeout().is_none() && lc.shared.state.lock().unwrap().closed.is_some()
            }
            None => false,
        };
        if reaped {
            if let Some(lc) = self.live.remove(&id) {
                self.handle_map.remove(&lc.handle);
            }
        }
    }

    fn pump_stream(&mut self, conn_id: u64, qid: StreamId) {
        let lc = match self.live.get_mut(&conn_id) {
            Some(lc) => lc,
            None => return,
        };
        let sh = match lc.streams.get(&qid) {
            Some(sh) => sh.clone(),
            None => return,
        };
        // SEND: app buffer -> QUIC.
        {
            let mut ss = sh.state.lock().unwrap();
            if ss.error.is_none() {
                while !ss.send_buf.is_empty() {
                    let n = ss.send_buf.len().min(65536);
                    let data: Vec<u8> = ss.send_buf.drain(..n).collect();
                    match lc.quic.send_stream(qid).write(&data) {
                        Ok(w) => {
                            lc.bytes_sent += w as u64;
                            if w < n {
                                for b in data[w..].iter().rev() {
                                    ss.send_buf.push_front(*b);
                                }
                                break;
                            }
                        }
                        Err(_) => {
                            for b in data.iter().rev() {
                                ss.send_buf.push_front(*b);
                            }
                            break;
                        }
                    }
                }
                if ss.send_fin
                    && !ss.fin_sent
                    && ss.send_buf.is_empty()
                    && lc.quic.send_stream(qid).finish().is_ok()
                {
                    ss.fin_sent = true;
                }
            }
        }
        // RECV: QUIC -> app buffer.
        // quinn-proto 0.11: Chunks::next() yields Ok(Some(chunk)) for data,
        // Ok(None) when the stream is finished AND fully read (= EOF),
        // Err(Blocked) when no data is available yet.
        {
            let mut ss = sh.state.lock().unwrap();
            if ss.error.is_none() && !ss.recv_eof {
                match lc.quic.recv_stream(qid).read(true) {
                    Ok(mut chunks) => {
                        let mut got = false;
                        loop {
                            match chunks.next(65536) {
                                Ok(Some(chunk)) => {
                                    got = true;
                                    lc.bytes_recv += chunk.bytes.len() as u64;
                                    ss.recv_buf.extend(chunk.bytes.iter().copied());
                                }
                                Ok(None) => {
                                    ss.recv_eof = true;
                                    break;
                                }
                                Err(quinn_proto::ReadError::Blocked) => break,
                                Err(quinn_proto::ReadError::Reset(code)) => {
                                    ss.error = Some(FabricError::Closed(code.into_inner() as u32));
                                    break;
                                }
                            }
                        }
                        let _ = chunks.finalize();
                        if got || ss.recv_eof {
                            sh.cv.notify_all();
                        }
                    }
                    Err(_) => { /* not readable right now */ }
                }
            }
        }
    }

    fn on_conn_event(&mut self, id: u64, ev: quinn_proto::Event) {
        match ev {
            quinn_proto::Event::HandshakeDataReady => {}
            quinn_proto::Event::Connected => {
                if let Some(lc) = self.live.get(&id) {
                    lc.shared.state.lock().unwrap().connected = true;
                    lc.shared.state_cv.notify_all();
                }
            }
            quinn_proto::Event::ConnectionLost { reason } => {
                let err = map_close_reason(&reason);
                if let Some(lc) = self.live.get(&id) {
                    lc.shared.state.lock().unwrap().closed = Some(err.clone());
                    lc.shared.state_cv.notify_all();
                    for sh in lc.streams.values() {
                        let mut ss = sh.state.lock().unwrap();
                        ss.error = Some(err.clone());
                        sh.cv.notify_all();
                    }
                    lc.shared.dgram_cv.notify_all();
                    lc.shared.accepted_cv.notify_all();
                }
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Opened { dir: Dir::Bi }) => {
                let sh = match self.live.get_mut(&id) {
                    Some(lc) => match lc.quic.streams().accept(Dir::Bi) {
                        Some(qid) => {
                            let sh = Arc::new(StreamShared::new(id, self.tx.clone()));
                            lc.streams.insert(qid, sh.clone());
                            sh
                        }
                        None => return,
                    },
                    None => return,
                };
                if let Some(lc) = self.live.get(&id) {
                    lc.shared.accepted.lock().unwrap().push_back(sh);
                    lc.shared.accepted_cv.notify_all();
                }
            }
            // Readable/Writable/Finished/Stopped/Available/Datagram*: the pump
            // loop picks these up directly; no extra bookkeeping needed here.
            _ => {}
        }
    }

    fn update_stats(&mut self, id: u64) {
        let lc = match self.live.get(&id) {
            Some(lc) => lc,
            None => return,
        };
        let connected = lc.shared.state.lock().unwrap().connected;
        let mut st = lc.shared.stats.lock().unwrap();
        // S8: only report RTT once the handshake produced real samples.
        st.rtt_ms = if connected {
            Some(lc.quic.rtt().as_millis() as u64)
        } else {
            None
        };
        st.active_path = Some(*self.shared.local_addr.lock().unwrap());
        st.bytes_sent = lc.bytes_sent;
        st.bytes_recv = lc.bytes_recv;
    }
}

fn map_close_reason(reason: &quinn_proto::ConnectionError) -> FabricError {
    use quinn_proto::ConnectionError as E;
    match reason {
        E::ApplicationClosed(f) => FabricError::Closed(f.error_code.into_inner() as u32),
        E::TimedOut => FabricError::Timeout,
        E::LocallyClosed => FabricError::Closed(0),
        E::TransportError(e) => FabricError::Transport(format!("transport: {e:?}")),
        E::ConnectionClosed(c) => FabricError::Transport(format!("closed: {:?}", c.error_code)),
        E::VersionMismatch => FabricError::Transport("version mismatch".into()),
        E::Reset => FabricError::Transport("stateless reset".into()),
        E::CidsExhausted => FabricError::Transport("connection ids exhausted".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn poll_timeout_never_zero() {
        // Regression: a zero poll timeout made `set_read_timeout` fail with
        // InvalidInput, leaving a freshly rebound socket blocking forever.
        assert_eq!(min_poll_timeout(Duration::ZERO), Duration::from_millis(1));
        assert_eq!(
            min_poll_timeout(Duration::from_millis(5)),
            Duration::from_millis(5)
        );
        assert_eq!(
            min_poll_timeout(Duration::from_secs(10)),
            Duration::from_secs(10)
        );
    }
}
