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
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, ServerConfig,
    StreamId, VarInt, crypto::rustls::QuicClientConfig,
};

use crate::cert::{
    FabricIdentity, Identity, build_client_crypto, build_mtls_server_config, build_server_config,
    generate_identity, verified_connection_peer,
};
use crate::transport::{StdUdpTransport, UdpTransport};
use crate::{ConnStats, ConnectionId, FabricError, PeerId};

/// Placeholder transport used during `cmd_rebind` between closing the old
/// socket and binding the new one (F-EDGE-1). All operations fail; it is
/// never observable outside the rebind window.
struct ClosedTransport;

impl UdpTransport for ClosedTransport {
    fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "socket closed for rebind",
        ))
    }
    fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "socket closed for rebind",
        ))
    }
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "socket closed for rebind",
        ))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "socket closed for rebind",
        ))
    }
}

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

/// datagram 丢弃日志的限频窗口（与 `apps/nexusd/src/log_throttle.rs` 的
/// `OUTBOUND_UNAVAILABLE_LOG_INTERVAL` 同值，保持运维口径一致）。
const DGRAM_DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// socket 发送失败日志的限频窗口（与 datagram 丢弃日志同值，保持运维口径一致）。
const SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 丢弃/逐出的分类（flush 期由 quinn 错误映射；纯数据，便于单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DgramDropKind {
    /// `SendDatagramError::TooLarge`（预检后被 cap 变化追上）。
    TooLarge,
    /// `SendDatagramError::Disabled | UnsupportedByPeer`。
    Unsupported,
    /// 发送缓冲不足，本次 `send` 迫使 quinn 逐出旧 datagram。
    Evicted,
}

impl DgramDropKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Unsupported => "unsupported",
            Self::Evicted => "evicted",
        }
    }
}

/// per-connection datagram 丢弃计数（纯数据；`LiveConn` 内持有）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DgramCounters {
    /// flush 期丢弃总数（`dropped_too_large + dropped_unsupported`）。
    dropped: u64,
    dropped_too_large: u64,
    dropped_unsupported: u64,
    /// 迫使 quinn 逐出的 send 次数（近似语义，不是被逐出的条数）。
    evicted: u64,
}

impl DgramCounters {
    /// 纯计数：无 I/O、无时钟。`Evicted` 不计入 `dropped`（不是丢弃）。
    fn record_drop(&mut self, kind: DgramDropKind) {
        match kind {
            DgramDropKind::TooLarge => {
                self.dropped += 1;
                self.dropped_too_large += 1;
            }
            DgramDropKind::Unsupported => {
                self.dropped += 1;
                self.dropped_unsupported += 1;
            }
            DgramDropKind::Evicted => self.evicted += 1,
        }
    }
}

/// 限频日志判定（datagram 丢弃与 socket 发送失败共用）：**不自取时钟**，
/// `now` 由 driver loop（时间注入方）传入
/// （AGENTS §22 / 既定决议：协议 core 不直接读系统时间）。
#[derive(Default)]
struct RateLimitedLog {
    last: Option<Instant>,
    suppressed: u64,
}

impl RateLimitedLog {
    /// `Some(suppressed)` = 本次应发射，并带出窗口内被抑制条数；`None` = 只累加。
    fn decide(&mut self, now: Instant, interval: Duration) -> Option<u64> {
        match self.last {
            None => {
                self.last = Some(now);
                self.suppressed = 0;
                Some(0)
            }
            Some(last) if now.saturating_duration_since(last) >= interval => {
                let suppressed = std::mem::take(&mut self.suppressed);
                self.last = Some(now);
                Some(suppressed)
            }
            Some(_) => {
                self.suppressed += 1;
                None
            }
        }
    }
}

/// `UdpTransport::send_to` 结果分类（纯数据）。
///
/// `WouldBlock` 是正常背压（socket 发送缓冲满），**不是发送失败**：单独计数、
/// 不触发错误日志。`NotConnected` 单列——rebind 窗口内的 `ClosedTransport`
/// 恒返该 kind，窗口内经它发出的 transmit 失败计入这里是诚实语义。其余 kind
/// 归入 `Other` 计数（原始 kind 只进日志，避免无界的计数维度）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendFailureKind {
    WouldBlock,
    NotConnected,
    Other,
}

impl SendFailureKind {
    fn classify(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            io::ErrorKind::NotConnected => Self::NotConnected,
            _ => Self::Other,
        }
    }

    fn is_failure(self) -> bool {
        !matches!(self, Self::WouldBlock)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::WouldBlock => "would_block",
            Self::NotConnected => "not_connected",
            Self::Other => "other",
        }
    }
}

/// socket 发送结果分类计数（纯数据；不含时钟/日志）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SendErrorCounters {
    /// 非 `WouldBlock` 的失败总数（= `failed_not_connected + failed_other`）。
    failed: u64,
    failed_not_connected: u64,
    failed_other: u64,
    /// 正常背压次数（不计入 `failed`）。
    would_block: u64,
}

impl SendErrorCounters {
    fn record(&mut self, kind: SendFailureKind) {
        match kind {
            SendFailureKind::WouldBlock => self.would_block += 1,
            SendFailureKind::NotConnected => {
                self.failed += 1;
                self.failed_not_connected += 1;
            }
            SendFailureKind::Other => {
                self.failed += 1;
                self.failed_other += 1;
            }
        }
    }
}

/// 一次发送错误的日志判定结果；连接/站点上下文由调用方补充。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendErrorEvent {
    kind: SendFailureKind,
    /// 原始 `io::ErrorKind`（`Other` 桶的细分信息只进日志，不进计数）。
    io_kind: io::ErrorKind,
    /// 本窗口内被限频吞掉的错误条数（首条恒为 0）。
    suppressed: u64,
}

/// `send_to` 结果观察器：成功**零副作用**；失败按 kind 分类计数，
/// 非 `WouldBlock` 再走 10s 限频日志判定。时间由调用方注入，本结构零时钟调用。
#[derive(Default)]
struct SendErrorTracker {
    counters: SendErrorCounters,
    log: RateLimitedLog,
}

impl SendErrorTracker {
    fn observe(&mut self, now: Instant, result: &io::Result<usize>) -> Option<SendErrorEvent> {
        let err = result.as_ref().err()?;
        let kind = SendFailureKind::classify(err);
        self.counters.record(kind);
        if !kind.is_failure() {
            return None;
        }
        self.log
            .decide(now, SEND_ERROR_LOG_INTERVAL)
            .map(|suppressed| SendErrorEvent {
                kind,
                io_kind: err.kind(),
                suppressed,
            })
    }
}

/// 端点级发送（`on_udp` / `on_new_connection`，无连接上下文）：失败按 kind
/// 计入 driver loop 内部计数并按 10s 限频打日志。
///
/// 该计数**暂无公共读面**（本 run 裁决：不新开 stats 端点），只经日志与单测观察；
/// 连接内的同一类失败则经 `ConnStats.send_*` 暴露。
fn send_endpoint_packet(
    socket: &dyn UdpTransport,
    tracker: &mut SendErrorTracker,
    now: Instant,
    pkt: &[u8],
    dest: SocketAddr,
    site: &'static str,
) {
    let result = socket.send_to(pkt, dest);
    let Some(ev) = tracker.observe(now, &result) else {
        return;
    };
    eprintln!(
        "[fabric] socket send failed site={} kind={} io_kind={:?} len={} dest={} total={} suppressed={}",
        site,
        ev.kind.as_str(),
        ev.io_kind,
        pkt.len(),
        dest,
        tracker.counters.failed,
        ev.suppressed
    );
}

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
    /// Additive: address of the live connection's remote end (accept side:
    /// the incoming source; connect side: the dialed target). Used by the
    /// NAT composition root so `DirectConn.addr` reflects reality.
    pub remote_addr: Mutex<Option<SocketAddr>>,
    pub tx: mpsc::Sender<Cmd>,
    pub state: Mutex<ConnState>,
    pub state_cv: Condvar,
    pub accepted: Mutex<VecDeque<Arc<StreamShared>>>,
    pub accepted_cv: Condvar,
    pub dgrams: Mutex<VecDeque<Vec<u8>>>,
    pub dgram_cv: Condvar,
    pub stats: Mutex<ConnStats>,
    /// QSEQ (GAP-2): per-connection datagram sequence counter for
    /// `send_datagram_seqed`. Monotonic `u64`, wraps via `fetch_add`.
    /// `send_datagram` (non-seqed) does not touch this counter (Q1).
    pub datagram_seq: AtomicU64,
    /// 有效 datagram 载荷上限采样值（quinn `datagrams().max_size()`）。
    /// `0` = 未知（握手未完成 / 连接已关闭 / 对端不支持 DATAGRAM）。
    /// 驱动线程每次 pump 刷新；API 侧只读。
    pub datagram_cap: AtomicUsize,
    /// 入队前被有效 datagram 上限拒绝的次数（API 快路径 + driver 权威判定，
    /// 共用 [`ConnShared::reject_datagram_too_large`]，合计只计一次）。
    pub datagram_rejected: AtomicU64,
    /// F-EDGE-3: serializes concurrent `rebind()` calls on this connection.
    /// The driver loop is single-threaded so `Cmd::Rebind` execution is already
    /// sequential, but that is incidental to the current implementation, not an
    /// API-level guarantee. This lock makes the ordering explicit at the
    /// portable-core boundary: rapid successive rebinds (e.g. link monitor
    /// backoff + path-switch event firing together) execute in call order,
    /// never interleaved. Deletion Test: without it, a future multi-threaded
    /// driver refactor would race the socket swap in `cmd_rebind`.
    pub rebind_lock: Mutex<()>,
}

pub struct ConnState {
    pub connected: bool,
    pub closed: Option<FabricError>,
    pub(crate) mutual_peer: Option<PeerId>,
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
            remote_addr: Mutex::new(None),
            tx,
            state: Mutex::new(ConnState {
                connected: false,
                closed: None,
                mutual_peer: None,
            }),
            state_cv: Condvar::new(),
            accepted: Mutex::new(VecDeque::new()),
            accepted_cv: Condvar::new(),
            dgrams: Mutex::new(VecDeque::new()),
            dgram_cv: Condvar::new(),
            stats: Mutex::new(ConnStats::unknown()),
            datagram_seq: AtomicU64::new(0),
            datagram_cap: AtomicUsize::new(0),
            datagram_rejected: AtomicU64::new(0),
            rebind_lock: Mutex::new(()),
        }
    }

    /// 当前连接的有效 datagram 载荷上限（同 `FabricConn::datagram_cap`）。
    ///
    /// `Arc<ConnShared>` 消费者（如 `nexus-nat-quality`）可直接查询；`None`
    /// 表示未知/已关闭，调用方退到 `CONSERVATIVE_DATAGRAM_CAP`。
    pub fn datagram_cap(&self) -> Option<usize> {
        if self.state.lock().unwrap().closed.is_some() {
            return None;
        }
        let cap = self.datagram_cap.load(Ordering::Relaxed);
        (cap != 0).then_some(cap)
    }

    /// 统一的"入队前拒绝"构造器：计数一次并返回 typed error
    /// （保证 API 快路径与 driver 权威判定不重不漏）。
    pub(crate) fn reject_datagram_too_large(&self, len: usize, cap: usize) -> FabricError {
        self.datagram_rejected.fetch_add(1, Ordering::Relaxed);
        FabricError::DatagramTooLarge { len, cap }
    }

    /// Open a bidirectional stream on this connection (C2 sync transport).
    ///
    /// Sends `Cmd::OpenBi` and waits for the driver's reply.
    /// Prefer the higher-level `FabricConn::open_bi` when you hold a `FabricConn`.
    pub fn open_stream(&self) -> Result<Arc<StreamShared>, FabricError> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Cmd::OpenBi {
                conn: self.id.0,
                reply: tx,
            })
            .map_err(|_| FabricError::Closed(0))?;
        rx.recv().map_err(|_| FabricError::Closed(0))?
    }

    /// Accept a remotely-initiated bidirectional stream (blocking, C2).
    ///
    /// Pops from the shared `accepted` queue. Prefer `FabricConn::accept_bi`
    /// when you hold a `FabricConn`.
    pub fn accept_stream(&self) -> Result<Arc<StreamShared>, FabricError> {
        let mut q = self.accepted.lock().unwrap();
        loop {
            if let Some(sh) = q.pop_front() {
                return Ok(sh);
            }
            if let Some(e) = self.state.lock().unwrap().closed.clone() {
                return Err(e);
            }
            q = self
                .accepted_cv
                .wait(q)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
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
        /// S11: set by `Driver::connect` if it stops waiting for the reply.
        /// The driver must not create an orphan connection from a
        /// cancelled command.
        cancel: Arc<AtomicBool>,
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
    InstallStunTap {
        sink: std::sync::Arc<dyn crate::stun::StunSink>,
        reply: mpsc::Sender<Result<(), crate::stun::StunTapError>>,
    },
    SendStunRequest {
        server: SocketAddr,
        bytes: Vec<u8>,
        reply: mpsc::Sender<Result<crate::stun::StunTransactionId, crate::stun::StunTapError>>,
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
    /// Additive (WP1b/spec §19): inbound mTLS handshakes this driver rejected
    /// (anonymous, unlisted, wrongly pinned, or protocol error). Monotonic and
    /// exactly once per inbound connection; see `Loop::publish_mutual_connection`
    /// and the `ConnectionLost` handler. No logging or callbacks here.
    pub rejected_handshakes: AtomicU64,
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
        Self::spawn_mode(transport, server, false)
    }

    fn spawn_mode(
        transport: Box<dyn UdpTransport>,
        server: Option<(ServerConfig, Identity)>,
        mutual_auth: bool,
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
            rejected_handshakes: AtomicU64::new(0),
        });
        let lp = Loop {
            rx,
            tx: tx.clone(),
            shared: shared.clone(),
            socket: transport,
            endpoint,
            server_config,
            mutual_auth,
            live: HashMap::new(),
            handle_map: HashMap::new(),
            buf: vec![0u8; RECV_BUF],
            out: Vec::new(),
            stun_sink: None,
            stun_pending: HashMap::new(),
            endpoint_send_errors: SendErrorTracker::default(),
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

    /// Server endpoint on a caller-provided transport with an **explicit
    /// identity**（#3 fabric-over-proxy：经代理的 QUIC 服务端必须 pin 配置中的
    /// PeerId，不能每次生成随机身份）。
    pub fn new_server_with_transport_identity(
        transport: Box<dyn UdpTransport>,
        identity: Identity,
    ) -> Result<Arc<Self>, FabricError> {
        let cfg = build_server_config(&identity)?;
        Self::spawn_with_transport(transport, Some((cfg, identity)))
    }

    pub(crate) fn new_mtls_client() -> Result<Arc<Self>, FabricError> {
        let transport = StdUdpTransport::bind("0.0.0.0:0".parse().unwrap())
            .map_err(|e| FabricError::Transport(e.to_string()))?;
        Self::new_mtls_client_with_transport(Box::new(transport))
    }

    /// mTLS client on a caller-provided transport (spec §7 additive support).
    pub(crate) fn new_mtls_client_with_transport(
        transport: Box<dyn UdpTransport>,
    ) -> Result<Arc<Self>, FabricError> {
        Self::spawn_mode(transport, None, true)
    }

    pub(crate) fn new_mtls_server(
        addr: SocketAddr,
        identity: &FabricIdentity,
        allowed: &[PeerId],
    ) -> Result<Arc<Self>, FabricError> {
        let config = build_mtls_server_config(identity, allowed)?;
        // Driver needs only the public endpoint identity after TLS config construction.
        let id = Identity {
            peer_id: identity.peer_id(),
            cert_der: Vec::new(),
            key_der: Vec::new(),
        };
        let transport =
            StdUdpTransport::bind(addr).map_err(|e| FabricError::Transport(e.to_string()))?;
        Self::spawn_mode(Box::new(transport), Some((config, id)), true)
    }

    pub fn shared(&self) -> &Arc<DriverShared> {
        &self.shared
    }

    /// Additive: install the single STUN sink (duplicate -> AlreadyInstalled).
    pub fn install_stun_tap(
        self: &Arc<Self>,
        sink: Arc<dyn crate::stun::StunSink>,
    ) -> Result<(), crate::stun::StunTapError> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Cmd::InstallStunTap { sink, reply: tx })
            .map_err(|_| crate::stun::StunTapError::DriverClosed)?;
        rx.recv()
            .map_err(|_| crate::stun::StunTapError::DriverClosed)?
    }

    /// Additive: send a pre-built STUN Binding request from the driver socket.
    pub fn send_stun_request(
        self: &Arc<Self>,
        server: SocketAddr,
        bytes: Vec<u8>,
    ) -> Result<crate::stun::StunTransactionId, crate::stun::StunTapError> {
        if crate::stun::parse_transaction(&bytes).is_none() {
            return Err(crate::stun::StunTapError::MalformedRequest);
        }
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Cmd::SendStunRequest {
                server,
                bytes,
                reply: tx,
            })
            .map_err(|_| crate::stun::StunTapError::DriverClosed)?;
        rx.recv()
            .map_err(|_| crate::stun::StunTapError::DriverClosed)?
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
        self.connect_with_crypto(peer, remote, handshake_timeout, crypto)
    }

    pub(crate) fn connect_with_crypto(
        self: &Arc<Self>,
        peer: PeerId,
        remote: SocketAddr,
        handshake_timeout: Duration,
        crypto: QuicClientConfig,
    ) -> Result<Arc<ConnShared>, FabricError> {
        // S11: a single total deadline spans both phases (command reply +
        // QUIC handshake) — the caller never observes ~2x the timeout.
        let start = Instant::now();
        let deadline = start
            .checked_add(handshake_timeout)
            .ok_or(FabricError::Timeout)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        self.send(Cmd::Connect {
            remote,
            crypto,
            peer,
            server_name: "nexus-fabric".to_string(),
            reply: tx,
            cancel: cancel.clone(),
        });
        let conn_id = match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(r) => r?,
            Err(_) => {
                // S11: phase-1 timeout. The driver may still run the
                // command later — cancel it so no orphan connection is
                // created, and drain a reply that raced the timeout.
                cancel.store(true, Ordering::Relaxed);
                if let Ok(Ok(id)) = rx.try_recv() {
                    self.send(Cmd::Close {
                        conn: id,
                        code: 0,
                        reason: b"connect timeout".to_vec(),
                    });
                }
                return Err(FabricError::Timeout);
            }
        };
        let shared = self
            .shared
            .conns
            .lock()
            .unwrap()
            .get(&conn_id)
            .cloned()
            .ok_or(FabricError::Closed(0))?;
        // Wait for handshake completion (or failure) — same total deadline.
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

    pub(crate) fn accept_conn_timeout(
        self: &Arc<Self>,
        timeout: Duration,
    ) -> Result<Arc<ConnShared>, FabricError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(FabricError::Timeout)?;
        let mut queue = self
            .shared
            .accept_q
            .lock()
            .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
        loop {
            while let Some(id) = queue.pop_front() {
                if let Some(conn) = self
                    .shared
                    .conns
                    .lock()
                    .map_err(|_| FabricError::Transport("lock poisoned".into()))?
                    .get(&id)
                    .cloned()
                {
                    if conn
                        .state
                        .lock()
                        .map_err(|_| FabricError::Transport("lock poisoned".into()))?
                        .closed
                        .is_none()
                    {
                        return Ok(conn);
                    }
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(FabricError::Timeout);
            }
            queue = self
                .shared
                .accept_cv
                .wait_timeout(queue, deadline - now)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?
                .0;
        }
    }

    /// Accept the next incoming connection (blocks).
    pub fn accept_conn(self: &Arc<Self>) -> Result<Arc<ConnShared>, FabricError> {
        let mut q = self.shared.accept_q.lock().unwrap();
        loop {
            if let Some(id) = q.pop_front() {
                // S10: the accept queue can hold ids whose connections were
                // already reaped — skip them instead of handing out (or
                // erroring on) dead connections.
                if let Some(shared) = self.shared.conns.lock().unwrap().get(&id).cloned() {
                    return Ok(shared);
                }
                continue;
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
    dgram: DgramCounters,
    dgram_drop_log: RateLimitedLog,
    send_errors: SendErrorTracker,
    bytes_sent: u64,
    bytes_recv: u64,
    /// WP1b/§19: set once the QUIC/TLS handshake completed (`Connected`).
    /// A connection that dies before this point never authenticated.
    handshake_authenticated: bool,
    /// WP1b/§19: exactly-once latch for `DriverShared::rejected_handshakes`.
    rejection_counted: bool,
}

impl LiveConn {
    /// 记录一次 flush 期丢弃/逐出，并按 10s 窗口限频打一行结构化日志。
    ///
    /// 时间来自 `pump_one(now)`（driver loop 注入），本函数零时钟调用。
    fn log_dgram_drop(&mut self, now: Instant, kind: DgramDropKind, len: usize, cap: usize) {
        let Some(suppressed) = self.dgram_drop_log.decide(now, DGRAM_DROP_LOG_INTERVAL) else {
            return;
        };
        let total = match kind {
            DgramDropKind::TooLarge => self.dgram.dropped_too_large,
            DgramDropKind::Unsupported => self.dgram.dropped_unsupported,
            DgramDropKind::Evicted => self.dgram.evicted,
        };
        eprintln!(
            "[fabric] datagram drop conn={} peer={} reason={} len={} cap={} total={} suppressed={}",
            self.shared.id.0,
            crate::hex_short(&self.shared.peer.0),
            kind.as_str(),
            len,
            cap,
            total,
            suppressed
        );
    }
}

struct Loop {
    rx: mpsc::Receiver<Cmd>,
    tx: mpsc::Sender<Cmd>,
    shared: Arc<DriverShared>,
    socket: Box<dyn UdpTransport>,
    endpoint: Endpoint,
    server_config: Option<Arc<ServerConfig>>,
    mutual_auth: bool,
    live: HashMap<u64, LiveConn>,
    handle_map: HashMap<ConnectionHandle, u64>,
    buf: Vec<u8>,
    out: Vec<u8>,
    stun_sink: Option<std::sync::Arc<dyn crate::stun::StunSink>>,
    stun_pending: HashMap<[u8; 12], Instant>,
    /// 端点级（无连接上下文）`send_to` 失败/背压计数。driver loop 内部状态，
    /// 暂无公共读面（本 run 裁决）。
    endpoint_send_errors: SendErrorTracker,
}

impl Loop {
    fn run(mut self) {
        loop {
            let now = Instant::now();
            self.stun_pending
                .retain(|_, at| now.duration_since(*at) <= Duration::from_millis(2000));
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
            Cmd::InstallStunTap { sink, reply } => {
                let result = if self.stun_sink.is_some() {
                    Err(crate::stun::StunTapError::AlreadyInstalled)
                } else {
                    self.stun_sink = Some(sink);
                    Ok(())
                };
                let _ = reply.send(result);
            }
            Cmd::SendStunRequest {
                server,
                bytes,
                reply,
            } => {
                let result = if self.stun_sink.is_none() {
                    Err(crate::stun::StunTapError::NotInstalled)
                } else if let Some(txn) = crate::stun::parse_transaction(&bytes) {
                    self.stun_pending.insert(txn.0, now);
                    match self.socket.send_to(&bytes, server) {
                        Ok(_) => Ok(txn),
                        Err(_) => Err(crate::stun::StunTapError::DriverClosed),
                    }
                } else {
                    Err(crate::stun::StunTapError::MalformedRequest)
                };
                let _ = reply.send(result);
            }
            Cmd::Connect {
                remote,
                crypto,
                peer,
                server_name,
                reply,
                cancel,
            } => {
                let r = self.cmd_connect(remote, crypto, peer, &server_name, now, &cancel);
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
                // E-3 lesson: local close must unblock blocked readers
                // (`accept_bi` / `recv_datagram` / `open_bi`) immediately,
                // otherwise a session layer that joins its pump threads
                // after `close()` deadlocks. The QUIC close frame alone
                // only emits `ConnectionLost` after the close timer, which
                // is too late for synchronous join-based shutdown.
                if let Some(sh) = self.shared.conns.lock().unwrap().get(&conn) {
                    let mut st = sh.state.lock().unwrap();
                    if st.closed.is_none() {
                        st.closed = Some(FabricError::Closed(code));
                    }
                    sh.accepted_cv.notify_all();
                    sh.dgram_cv.notify_all();
                    sh.state_cv.notify_all();
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
        cancel: &AtomicBool,
    ) -> Result<u64, FabricError> {
        // S11: connect() stopped waiting — don't create an orphan.
        if cancel.load(Ordering::Relaxed) {
            return Err(FabricError::Timeout);
        }
        let mut cc = ClientConfig::new(Arc::new(crypto));
        cc.transport_config(crate::cert::quic_transport_config());
        let (handle, quic) = self
            .endpoint
            .connect(now, cc, remote, server_name)
            .map_err(|e| FabricError::Transport(format!("quic connect: {e:?}")))?;
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(ConnShared::new(ConnectionId(id), peer, self.tx.clone()));
        *shared.remote_addr.lock().unwrap() = Some(remote);
        self.handle_map.insert(handle, id);
        self.live.insert(
            id,
            LiveConn {
                handle,
                quic,
                shared: shared.clone(),
                streams: HashMap::new(),
                dgram_tx_q: VecDeque::new(),
                dgram: DgramCounters::default(),
                dgram_drop_log: RateLimitedLog::default(),
                send_errors: SendErrorTracker::default(),
                bytes_sent: 0,
                bytes_recv: 0,
                handshake_authenticated: false,
                rejection_counted: false,
            },
        );
        self.shared.conns.lock().unwrap().insert(id, shared);
        // S11: cancelled while creating — close immediately instead of
        // leaving an orphan; the reaper removes it on the next pump.
        if cancel.load(Ordering::Relaxed) {
            if let Some(lc) = self.live.get_mut(&id) {
                lc.quic.close(
                    now,
                    VarInt::from_u32(0),
                    Bytes::from_static(b"connect cancelled"),
                );
            }
        }
        Ok(id)
    }

    fn cmd_open_bi(&mut self, conn: u64) -> Result<Arc<StreamShared>, FabricError> {
        let lc = self.live.get_mut(&conn).ok_or(FabricError::Closed(0))?;
        if self.mutual_auth {
            if lc.quic.is_closed() {
                return Err(FabricError::Closed(0));
            }
            let state = lc.shared.state.lock().unwrap();
            if let Some(error) = &state.closed {
                return Err(error.clone());
            }
            if state.mutual_peer.is_none() {
                return Err(FabricError::HandshakeFailed(
                    "mutual authentication incomplete".into(),
                ));
            }
        }
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
        if self.mutual_auth {
            if lc.quic.is_closed() {
                return Err(FabricError::Closed(0));
            }
            let state = lc.shared.state.lock().unwrap();
            if let Some(error) = &state.closed {
                return Err(error.clone());
            }
            if state.mutual_peer.is_none() {
                return Err(FabricError::HandshakeFailed(
                    "mutual authentication incomplete".into(),
                ));
            }
        }
        // **权威判定点**：用 quinn 现算的 `datagrams().max_size()`（载荷口径）。
        // API 侧的 `FabricConn::send_datagram` 只是缓存快路径；这里的数字刷新
        // 回 `ConnShared.datagram_cap` 供上层查询。
        let cap = lc.quic.datagrams().max_size();
        lc.shared
            .datagram_cap
            .store(cap.unwrap_or(0), Ordering::Relaxed);
        let connected = lc.shared.state.lock().unwrap().connected;
        match cap {
            Some(c) if data.len() > c => {
                return Err(lc.shared.reject_datagram_too_large(data.len(), c));
            }
            None if connected => {
                // 对端未通告 `max_datagram_frame_size`：quinn 的 `send` 会返回
                // `UnsupportedByPeer`。握手后即可同步判定，回归 typed error。
                return Err(FabricError::Transport(
                    "datagrams not supported by peer".into(),
                ));
            }
            _ => {}
        }
        lc.dgram_tx_q.push_back(data);
        Ok(())
    }

    /// Active migration: swap the UDP socket so subsequent packets go out
    /// from a new local port. The peer migrates via QUIC path validation
    /// (S3, S6) when it sees the new source address (passive migration).
    ///
    /// Note: we do NOT call quinn-proto's `local_address_changed()` here
    /// (F-EDGE-2). That call only resets this endpoint's path state; it does
    /// not help the peer migrate its send path — the peer migrates passively
    /// when it observes packets from the new source address (RFC 9000 §9).
    /// The old code deliberately avoided the call because quinn-proto 0.11.18's
    /// `pto_time_and_space` trips a `debug_assert!` when the connection goes
    /// idle post-migration. Migration trigger packets are driven by the caller
    /// (E4 burst / application data).
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
        //
        // F-EDGE-1 修复：必须先释放旧 socket 再 bind。旧 socket 在新 bind
        // 成功前仍持有端口（StdUdpTransport 无 SO_REUSEADDR），否则
        // bind(orig) 与 bind(0.0.0.0:port) 恒 EADDRINUSE，端口保留成死代码。
        // 若全部 bind 失败，连接失去 socket（不可恢复，返回 Err）。
        //
        // 注意：Client rebind 必须产生**不同**的本地地址，否则对端不会
        // 触发 QUIC 被动迁移。若原 IP 仍存在，直接 bind(orig) 会得到完全
        // 相同的地址，迁移无从发生。因此 Client 跳过 bind(orig)，直接用
        // wildcard（新 IP 由路由决定，端口随机），保证地址变化。
        let orig = *self.shared.local_addr.lock().unwrap();
        let is_server = self.server_config.is_some();
        drop(std::mem::replace(
            &mut self.socket,
            Box::new(ClosedTransport),
        ));
        let sock: Box<dyn UdpTransport> = if is_server {
            // Server：必须保留原地址/端口（well-known）。若原 IP 已不存在
            // （如本端 roam），bind 失败则报错，不回退（调用方处理）。
            Box::new(StdUdpTransport::bind(orig).map_err(|e| {
                FabricError::Transport(format!(
                    "server rebind must preserve {orig}, bind failed: {e}"
                ))
            })?)
        } else {
            // Client：直接 wildcard 随机端口，保证新地址与旧的不同，
            // 触发对端 QUIC 被动迁移。端口保留非必需（迁移不依赖端口）。
            Box::new(
                StdUdpTransport::bind("0.0.0.0:0".parse().unwrap())
                    .map_err(|e| FabricError::Transport(e.to_string()))?,
            )
        };
        let addr = sock
            .local_addr()
            .map_err(|e| FabricError::Transport(e.to_string()))?;
        self.socket = sock;
        *self.shared.local_addr.lock().unwrap() = addr;
        // F-EDGE-2：移除无条件 local_address_changed() 调用。
        // 该调用只影响本端（B）路径状态，不能帮助对端（A）迁移发送路径；
        // A 的迁移靠收到 B 新源地址包时的被动迁移（QUIC 标准行为）。
        // 旧代码刻意不调用（quinn-proto 0.11.18 pto_time_and_space 在
        // 迁移后 idle 时触发 debug_assert）；无条件调用重引入该风险。
        // B 的迁移触发包由调用方（E4 burst / 业务数据）驱动发出。
        // Refresh stats immediately so the caller observes the new path.
        self.update_stats(conn);
        Ok(addr)
    }

    fn on_udp(&mut self, n: usize, remote: SocketAddr) {
        let now = Instant::now();
        if let Some(txn) = crate::stun::parse_transaction(&self.buf[..n]) {
            if self.stun_pending.remove(&txn.0).is_some() {
                if let Some(sink) = &self.stun_sink {
                    sink.on_stun_response(crate::stun::StunResponse {
                        transaction_id: txn,
                        from: remote,
                        bytes: self.buf[..n].to_vec(),
                    });
                }
                return;
            }
        }
        let local_ip = self.socket.local_addr().ok().map(|a| a.ip());
        let data = BytesMut::from(&self.buf[..n]);
        let ev = self
            .endpoint
            .handle(now, remote, local_ip, None, data, &mut self.out);
        match ev {
            None => {}
            Some(DatagramEvent::Response(t)) => {
                let pkt = self.out[..t.size].to_vec();
                send_endpoint_packet(
                    &*self.socket,
                    &mut self.endpoint_send_errors,
                    now,
                    &pkt,
                    t.destination,
                    "datagram_response",
                );
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
        let remote_addr = incoming.remote_address();
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
                *shared.remote_addr.lock().unwrap() = Some(remote_addr);
                self.handle_map.insert(handle, id);
                self.live.insert(
                    id,
                    LiveConn {
                        handle,
                        quic,
                        shared: shared.clone(),
                        streams: HashMap::new(),
                        dgram_tx_q: VecDeque::new(),
                        dgram: DgramCounters::default(),
                        dgram_drop_log: RateLimitedLog::default(),
                        send_errors: SendErrorTracker::default(),
                        bytes_sent: 0,
                        bytes_recv: 0,
                        handshake_authenticated: false,
                        rejection_counted: false,
                    },
                );
                self.shared.conns.lock().unwrap().insert(id, shared);
                if !self.mutual_auth {
                    self.shared.accept_q.lock().unwrap().push_back(id);
                    self.shared.accept_cv.notify_one();
                }
            }
            Err(e) => {
                if let Some(t) = e.response {
                    let pkt = self.out[..t.size].to_vec();
                    send_endpoint_packet(
                        &*self.socket,
                        &mut self.endpoint_send_errors,
                        now,
                        &pkt,
                        t.destination,
                        "accept_response",
                    );
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
        self.publish_mutual_connection(id);
        // An Opened event can precede client handshake confirmation. Keep the
        // QUIC accept queue private until authenticated, then drain it here.
        if self.mutual_auth {
            if let Some(lc) = self.live.get_mut(&id) {
                if lc.shared.state.lock().unwrap().mutual_peer.is_some() {
                    while let Some(qid) = lc.quic.streams().accept(Dir::Bi) {
                        let sh = Arc::new(StreamShared::new(id, self.tx.clone()));
                        lc.streams.insert(qid, sh.clone());
                        lc.shared.accepted.lock().unwrap().push_back(sh);
                        lc.shared.accepted_cv.notify_all();
                    }
                }
            }
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
            // 每次 pump 刷新有效盖采样（握手完成 / MTU 变化 / 关闭都会反映到这里）。
            let cap = lc.quic.datagrams().max_size().unwrap_or(0);
            lc.shared.datagram_cap.store(cap, Ordering::Relaxed);
            while let Some(d) = lc.dgram_tx_q.pop_front() {
                let len = d.len();
                // `send(drop=true)` 在缓冲不足时会**静默逐出**旧 datagram，
                // quinn 不报告这件事；只能在调用前用剩余空间预判并计数。
                let evict = lc.quic.datagrams().send_buffer_space() < len;
                match lc.quic.datagrams().send(Bytes::from(d), true) {
                    Ok(()) => {
                        lc.bytes_sent += len as u64;
                        if evict {
                            lc.dgram.record_drop(DgramDropKind::Evicted);
                            lc.log_dgram_drop(now, DgramDropKind::Evicted, len, cap);
                        }
                    }
                    Err(quinn_proto::SendDatagramError::Blocked(data)) => {
                        lc.dgram_tx_q.push_front(data.to_vec());
                        break;
                    }
                    Err(quinn_proto::SendDatagramError::TooLarge) => {
                        lc.dgram.record_drop(DgramDropKind::TooLarge);
                        lc.log_dgram_drop(now, DgramDropKind::TooLarge, len, cap);
                    }
                    // Disabled | UnsupportedByPeer：对端不支持 DATAGRAM。
                    Err(_) => {
                        lc.dgram.record_drop(DgramDropKind::Unsupported);
                        lc.log_dgram_drop(now, DgramDropKind::Unsupported, len, cap);
                    }
                }
            }
            let shared = lc.shared.clone();
            let mut got = false;
            while let Some(b) = lc.quic.datagrams().recv() {
                lc.bytes_recv += b.len() as u64;
                if !self.mutual_auth || shared.state.lock().unwrap().mutual_peer.is_some() {
                    shared.dgrams.lock().unwrap().push_back(b.to_vec());
                    got = true;
                }
            }
            if got {
                shared.dgram_cv.notify_all();
            }
        }
        // Transmit.
        //
        // quinn sans-IO：`poll_transmit` 交出包即视为已发送。本层 send_to 失败时
        // 包按丢失处理（不归还、不重试、不自旋），由 QUIC 自身丢包检测/PTO 重传；
        // 这里只负责让它**可见**（计数 + 首条即出、其后 10s 限频的日志）。
        if let Some(lc) = self.live.get_mut(&id) {
            while let Some(t) = lc.quic.poll_transmit(now, 1, &mut self.out) {
                let pkt = self.out[..t.size].to_vec();
                let result = self.socket.send_to(&pkt, t.destination);
                if let Some(ev) = lc.send_errors.observe(now, &result) {
                    eprintln!(
                        "[fabric] socket send failed conn={} peer={} kind={} io_kind={:?} len={} dest={} total={} suppressed={}",
                        lc.shared.id.0,
                        crate::hex_short(&lc.shared.peer.0),
                        ev.kind.as_str(),
                        ev.io_kind,
                        pkt.len(),
                        t.destination,
                        lc.send_errors.counters.failed,
                        ev.suppressed
                    );
                }
                self.out.clear();
            }
        }
        self.update_stats(id);
        // Reap fully-closed connections. S10: also remove from
        // `shared.conns` — otherwise closed connections (and their
        // `accepted`/`dgrams` buffers) accumulate forever and `accept()`
        // can hand out dead connections.
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
            self.shared.conns.lock().unwrap().remove(&id);
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

    /// TLS client Connected precedes the server's client-certificate verdict.
    /// HANDSHAKE_DONE is authenticated confirmation from that server; wait for it
    /// before releasing the client handle. Server Connected already validates
    /// mandatory CertificateVerify and the allowlist.
    fn publish_mutual_connection(&mut self, id: u64) {
        if !self.mutual_auth {
            return;
        }
        let Some(lc) = self.live.get_mut(&id) else {
            return;
        };
        if lc.quic.is_handshaking()
            || lc.shared.state.lock().unwrap().closed.is_some()
            || lc.shared.state.lock().unwrap().mutual_peer.is_some()
        {
            return;
        }
        if lc.quic.side().is_client() && lc.quic.stats().frame_rx.handshake_done == 0 {
            return;
        }
        match verified_connection_peer(&lc.quic) {
            Ok(peer) => {
                let mut state = lc.shared.state.lock().unwrap();
                state.mutual_peer = Some(peer);
                state.connected = true;
                drop(state);
                lc.shared.state_cv.notify_all();
                if !lc.quic.side().is_client() {
                    self.shared.accept_q.lock().unwrap().push_back(id);
                    self.shared.accept_cv.notify_one();
                }
            }
            Err(error) => {
                lc.shared.state.lock().unwrap().closed = Some(error);
                lc.shared.state_cv.notify_all();
                // WP1b/§19 authoritative rejection point: the handshake got far
                // enough to verify a peer, but no mutually authenticated
                // identity could be established. Count once (the latch also
                // protects the later `ConnectionLost` path).
                if self.mutual_auth && !lc.quic.side().is_client() && !lc.rejection_counted {
                    lc.rejection_counted = true;
                    self.shared
                        .rejected_handshakes
                        .fetch_add(1, Ordering::Relaxed);
                }
                lc.quic.close(
                    Instant::now(),
                    VarInt::from_u32(1),
                    Bytes::from_static(b"mutual authentication failed"),
                );
            }
        }
    }

    fn on_conn_event(&mut self, id: u64, ev: quinn_proto::Event) {
        match ev {
            quinn_proto::Event::HandshakeDataReady => {}
            quinn_proto::Event::Connected => {
                if let Some(lc) = self.live.get_mut(&id) {
                    if !self.mutual_auth {
                        lc.shared.state.lock().unwrap().connected = true;
                        lc.shared.state_cv.notify_all();
                    } else {
                        // Server side: QUIC `Connected` already validated the
                        // mandatory client certificate and the allowlist.
                        lc.handshake_authenticated = true;
                    }
                }
            }
            quinn_proto::Event::ConnectionLost { reason } => {
                let err = map_close_reason(&reason);
                if let Some(lc) = self.live.get_mut(&id) {
                    lc.shared.state.lock().unwrap().closed = Some(err.clone());
                    lc.shared.state_cv.notify_all();
                    for sh in lc.streams.values() {
                        let mut ss = sh.state.lock().unwrap();
                        ss.error = Some(err.clone());
                        sh.cv.notify_all();
                    }
                    lc.shared.dgram_cv.notify_all();
                    lc.shared.accepted_cv.notify_all();
                    // WP1b/§19: an inbound mTLS connection that dies before the
                    // handshake completed never authenticated — count it as a
                    // rejected handshake (anonymous / unlisted / wrong pin /
                    // protocol error). Exactly once via the per-conn latch.
                    if self.mutual_auth
                        && !lc.quic.side().is_client()
                        && !lc.handshake_authenticated
                        && !lc.rejection_counted
                    {
                        lc.rejection_counted = true;
                        self.shared
                            .rejected_handshakes
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            quinn_proto::Event::Stream(quinn_proto::StreamEvent::Opened { dir: Dir::Bi }) => {
                if self.mutual_auth {
                    return;
                }
                // quinn-proto emits one `Opened` event per direction per poll
                // batch (a single flag), not one per stream. Drain the whole
                // accept queue so several streams opened in the same packet
                // all reach the `accepted` queue (flow-session AC5: 6 streams
                // in a tight loop must all be delivered).
                let mut notified = false;
                while let Some(lc) = self.live.get_mut(&id) {
                    let Some(qid) = lc.quic.streams().accept(Dir::Bi) else {
                        break;
                    };
                    let sh = Arc::new(StreamShared::new(id, self.tx.clone()));
                    lc.streams.insert(qid, sh.clone());
                    lc.shared.accepted.lock().unwrap().push_back(sh);
                    notified = true;
                }
                if notified {
                    if let Some(lc) = self.live.get(&id) {
                        lc.shared.accepted_cv.notify_all();
                    }
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
        st.datagram_rejected = lc.shared.datagram_rejected.load(Ordering::Relaxed);
        st.datagram_dropped = lc.dgram.dropped;
        st.datagram_dropped_too_large = lc.dgram.dropped_too_large;
        st.datagram_dropped_unsupported = lc.dgram.dropped_unsupported;
        st.datagram_evicted = lc.dgram.evicted;
        st.send_failed = lc.send_errors.counters.failed;
        st.send_failed_not_connected = lc.send_errors.counters.failed_not_connected;
        st.send_failed_other = lc.send_errors.counters.failed_other;
        st.send_would_block = lc.send_errors.counters.would_block;
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
    use std::sync::atomic::AtomicBool;
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

    /// 限频判定是纯函数：虚拟时刻推演，不 sleep、不在协议 core 取时钟。
    #[test]
    fn dgram_drop_log_throttles_with_injected_time() {
        let mut log = RateLimitedLog::default();
        let t0 = Instant::now();
        let interval = DGRAM_DROP_LOG_INTERVAL;
        assert_eq!(log.decide(t0, interval), Some(0), "first drop always emits");
        assert_eq!(
            log.decide(t0 + Duration::from_secs(9), interval),
            None,
            "inside the window: suppressed"
        );
        assert_eq!(
            log.decide(t0 + Duration::from_secs(9), interval),
            None,
            "still inside the window"
        );
        assert_eq!(
            log.decide(t0 + Duration::from_secs(10), interval),
            Some(2),
            "window elapsed: emit with the suppressed count"
        );
        assert_eq!(
            log.decide(t0 + Duration::from_secs(11), interval),
            None,
            "new window starts empty"
        );
        assert_eq!(log.decide(t0 + Duration::from_secs(20), interval), Some(1));
    }

    /// flush 期分类计数（纯函数，无 quinn 对象）。
    #[test]
    fn dgram_counters_classify_drops() {
        let mut c = DgramCounters::default();
        c.record_drop(DgramDropKind::TooLarge);
        assert_eq!(
            c,
            DgramCounters {
                dropped: 1,
                dropped_too_large: 1,
                dropped_unsupported: 0,
                evicted: 0,
            }
        );
        c.record_drop(DgramDropKind::Unsupported);
        assert_eq!(
            c,
            DgramCounters {
                dropped: 2,
                dropped_too_large: 1,
                dropped_unsupported: 1,
                evicted: 0,
            }
        );
        c.record_drop(DgramDropKind::Evicted);
        assert_eq!(
            c,
            DgramCounters {
                dropped: 2,
                dropped_too_large: 1,
                dropped_unsupported: 1,
                evicted: 1,
            },
            "evictions are not drops"
        );
    }

    /// `send_to` 分类：`WouldBlock` 是正常背压，不是失败；`NotConnected`
    /// 单列（rebind 窗口的 `ClosedTransport` 恒返该 kind），其余归 `Other`。
    #[test]
    fn send_failure_kind_classifies_io_errors() {
        let kind = |k| SendFailureKind::classify(&io::Error::from(k));
        assert_eq!(kind(io::ErrorKind::WouldBlock), SendFailureKind::WouldBlock);
        assert_eq!(
            kind(io::ErrorKind::NotConnected),
            SendFailureKind::NotConnected
        );
        assert_eq!(
            kind(io::ErrorKind::PermissionDenied),
            SendFailureKind::Other
        );
        assert_eq!(
            kind(io::ErrorKind::NetworkUnreachable),
            SendFailureKind::Other
        );
        assert!(
            !SendFailureKind::WouldBlock.is_failure(),
            "WouldBlock is backpressure, not a send failure"
        );
        assert!(SendFailureKind::NotConnected.is_failure());
        assert!(SendFailureKind::Other.is_failure());
    }

    /// Spec 5 第一项：注入 send_to 失败 → 计数增加；**首个错误立即出日志**
    /// （首条不被限频吞），其后同窗口只累加，窗口到期带 suppressed 再发。
    /// 时间由测试注入，观察器内部零时钟调用。
    #[test]
    fn send_failure_counts_and_first_error_is_never_throttled() {
        let mut tracker = SendErrorTracker::default();
        let t0 = Instant::now();
        let fail = || {
            Err::<usize, io::Error>(io::Error::new(
                io::ErrorKind::NotConnected,
                "socket closed for rebind",
            ))
        };

        let first = tracker
            .observe(t0, &fail())
            .expect("first failure emits immediately");
        assert_eq!(first.kind, SendFailureKind::NotConnected);
        assert_eq!(first.io_kind, io::ErrorKind::NotConnected);
        assert_eq!(first.suppressed, 0);
        assert_eq!(
            tracker.counters,
            SendErrorCounters {
                failed: 1,
                failed_not_connected: 1,
                failed_other: 0,
                would_block: 0,
            }
        );

        assert!(
            tracker
                .observe(t0 + Duration::from_secs(1), &fail())
                .is_none(),
            "inside the 10s window the log is suppressed"
        );
        assert_eq!(tracker.counters.failed, 2, "suppressed errors still count");

        let ev = tracker
            .observe(t0 + SEND_ERROR_LOG_INTERVAL, &fail())
            .expect("window elapsed: emit again");
        assert_eq!(ev.suppressed, 1);
        assert_eq!(tracker.counters.failed, 3);
    }

    /// Spec 5 第二项：WouldBlock → 不计失败、不触发错误日志，且**不消耗**
    /// 日志窗口（背压之后的首个真实错误仍然立即可见）。
    #[test]
    fn would_block_is_counted_separately_and_never_logs() {
        let mut tracker = SendErrorTracker::default();
        let t0 = Instant::now();
        let would_block = || {
            Err::<usize, io::Error>(io::Error::new(
                io::ErrorKind::WouldBlock,
                "send buffer full",
            ))
        };

        assert!(
            tracker.observe(t0, &would_block()).is_none(),
            "WouldBlock must not trigger the error log"
        );
        assert!(tracker.observe(t0, &would_block()).is_none());
        assert_eq!(
            tracker.counters,
            SendErrorCounters {
                failed: 0,
                failed_not_connected: 0,
                failed_other: 0,
                would_block: 2,
            },
            "backpressure is not a send failure"
        );

        let ev = tracker
            .observe(
                t0 + Duration::from_millis(1),
                &Err::<usize, io::Error>(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected failure",
                )),
            )
            .expect("WouldBlock must not consume the log window");
        assert_eq!(ev.kind, SendFailureKind::Other);
        assert_eq!(ev.io_kind, io::ErrorKind::PermissionDenied);
        assert_eq!(ev.suppressed, 0);
        assert_eq!(tracker.counters.failed, 1);
        assert_eq!(tracker.counters.failed_other, 1);
    }

    /// Spec 5 第三项：成功路径零副作用（计数不变、不产生日志判定）。
    #[test]
    fn successful_send_leaves_counters_untouched() {
        let mut tracker = SendErrorTracker::default();
        assert!(
            tracker
                .observe(Instant::now(), &Ok::<usize, io::Error>(1200))
                .is_none()
        );
        assert_eq!(tracker.counters, SendErrorCounters::default());
    }

    /// 端点级站点（无连接上下文）走同一个观察器：同样分类、同样限频，
    /// 计数挂在 driver loop 内部（无公共读面）。
    #[test]
    fn endpoint_send_failure_is_classified_and_counted() {
        let socket = SendErrorTransport::new(io::ErrorKind::NotConnected);
        let mut tracker = SendErrorTracker::default();
        let t0 = Instant::now();
        let dest: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        send_endpoint_packet(&socket, &mut tracker, t0, b"reply", dest, "test_site");
        assert_eq!(tracker.counters.failed, 1);
        assert_eq!(tracker.counters.failed_not_connected, 1);
        send_endpoint_packet(&socket, &mut tracker, t0, b"reply", dest, "test_site");
        assert_eq!(tracker.counters.failed, 2);

        let socket = SendErrorTransport::new(io::ErrorKind::WouldBlock);
        let mut tracker = SendErrorTracker::default();
        send_endpoint_packet(&socket, &mut tracker, t0, b"reply", dest, "test_site");
        assert_eq!(tracker.counters.failed, 0, "WouldBlock is not a failure");
        assert_eq!(tracker.counters.would_block, 1);
    }

    /// 主站点接线：真实 quinn 客户端 + 注入失败的 transport，断言 `pump_one`
    /// 的 send_to 失败经 `update_stats` 进入 `ConnStats`。
    #[test]
    fn pump_send_failure_reaches_conn_stats() {
        let driver = Driver::new_client_with_transport(Box::new(SendErrorTransport::new(
            io::ErrorKind::NotConnected,
        )))
        .expect("driver spawns");
        let conn = connect_for_send_error_test(&driver);
        let stats = wait_for_stats(&conn, |s| s.send_failed > 0);
        assert_eq!(
            stats.send_failed,
            stats.send_failed_not_connected + stats.send_failed_other,
            "failed is the sum of its kind buckets"
        );
        assert!(stats.send_failed_not_connected > 0);
        assert_eq!(stats.send_would_block, 0);
    }

    /// 主站点接线：WouldBlock 注入只进 `send_would_block`，失败计数保持 0。
    #[test]
    fn pump_would_block_never_counts_as_failure() {
        let driver = Driver::new_client_with_transport(Box::new(SendErrorTransport::new(
            io::ErrorKind::WouldBlock,
        )))
        .expect("driver spawns");
        let conn = connect_for_send_error_test(&driver);
        let stats = wait_for_stats(&conn, |s| s.send_would_block > 0);
        assert_eq!(stats.send_failed, 0, "backpressure is not a send failure");
        assert_eq!(stats.send_failed_not_connected, 0);
        assert_eq!(stats.send_failed_other, 0);
    }

    /// 测试替身：send_to 恒返指定 kind；recv_from 立即 WouldBlock（带 1ms
    /// 休眠避免忙等），driver 线程可正常处理命令与 pump。
    struct SendErrorTransport {
        kind: io::ErrorKind,
    }

    impl SendErrorTransport {
        fn new(kind: io::ErrorKind) -> Self {
            Self { kind }
        }
    }

    impl UdpTransport for SendErrorTransport {
        fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            thread::sleep(Duration::from_millis(1));
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no packets"))
        }
        fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
            Err(io::Error::new(self.kind, "injected send failure"))
        }
        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            "127.0.0.1:41000".parse().map_err(io::Error::other)
        }
    }

    fn connect_for_send_error_test(driver: &Arc<Driver>) -> Arc<ConnShared> {
        let peer = PeerId([9u8; 32]);
        let crypto = build_client_crypto(peer).expect("client crypto");
        let (tx, rx) = mpsc::channel();
        driver.send(Cmd::Connect {
            remote: "127.0.0.1:9".parse().unwrap(),
            crypto,
            peer,
            server_name: "nexus-fabric".to_string(),
            reply: tx,
            cancel: Arc::new(AtomicBool::new(false)),
        });
        let id = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("connect reply")
            .expect("connection id");
        driver
            .shared()
            .conns
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .expect("live connection is published")
    }

    fn wait_for_stats(conn: &Arc<ConnShared>, predicate: impl Fn(&ConnStats) -> bool) -> ConnStats {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let stats = conn.stats.lock().unwrap().clone();
            if predicate(&stats) {
                return stats;
            }
            assert!(
                Instant::now() < deadline,
                "send error was not surfaced in ConnStats within 5s: {stats:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// S11: a `Cmd::Connect` cancelled before the driver runs it must not
    /// create an orphan connection. This is what `Driver::connect` relies
    /// on when its phase-1 wait times out.
    #[test]
    fn s11_cancelled_connect_creates_no_orphan() {
        let driver = Driver::new_client().expect("driver spawns");
        let peer = PeerId([7u8; 32]);
        let crypto = build_client_crypto(peer).expect("client crypto");
        let (tx, rx) = mpsc::channel();
        // Pre-cancelled: simulates connect() timing out before the driver
        // thread picks the command up.
        let cancel = Arc::new(AtomicBool::new(true));
        driver.send(Cmd::Connect {
            remote: "127.0.0.1:9".parse().unwrap(),
            crypto,
            peer,
            server_name: "nexus-fabric".to_string(),
            reply: tx,
            cancel,
        });
        let r = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reply arrives");
        assert!(
            r.is_err(),
            "S11: cancelled connect must not produce a connection id"
        );
        thread::sleep(Duration::from_millis(300));
        assert!(
            driver.shared().conns.lock().unwrap().is_empty(),
            "S11: cancelled connect must not leave an orphan in shared.conns"
        );
    }
}
