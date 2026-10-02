//! Production wiring for NAT punch-through (`feature/nat-punch-wiring`).
//!
//! Connects the portable `nexus-nat-traversal` orchestration
//! (`PunchSession`) to a real `nexus-fabric` driver:
//!
//! ```text
//! relayed QUIC conn ──► FabricPunchChannel (bi-stream, P2 codec)
//! punch driver      ──► DriverPunchSocket  (Driver::connect fan-out)
//! PunchManager      ──► responder + dedup + tie-break + feed
//! ```
//!
//! Architecture (verified against quinn-proto 0.11.18): passive migration
//! only works server-side, and a punch changes *both* endpoints' UDP
//! addresses, so in-connection migration is impossible. Punching therefore
//! establishes a **new direct QUIC connection on the same UDP socket**
//! (bidirectional `Driver::connect` = simultaneous punch); the relayed
//! connection stays up as warm backup (D4).

pub mod channel;
pub mod responder;
pub mod socket;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nexus_connectivity::nat::NatType;
use nexus_fabric::{Cmd, ConnShared, Driver, PeerId as FabricPeerId, StreamShared};
use nexus_nat_traversal::{
    DefaultPredictor, LocalCandidates, PortSample, Predictability, PunchAnswer, PunchConfig,
    PunchPredictor, PunchRaceFeed, PunchResult, PunchSession, SIGNAL_VERSION, SprayPlan,
    decode_offer, encode_answer,
};

pub use channel::{
    FabricPunchChannel, STREAM_TYPE_BIND, STREAM_TYPE_PUNCH, decode_bind_response,
    encode_bind_response, frame_msg, peek_stream_type, verify_bind,
};
pub use responder::PreAnsweredChannel;
pub use socket::DriverPunchSocket;

/// Deterministic tie-break: the side with the larger `PeerId` keeps the
/// connection *it* initiated; the smaller side closes its own initiated
/// connection. Both sides compute this independently — no negotiation.
/// (PeerIds are distinct ed25519 keys; equality is impossible in practice.)
pub fn tie_break_keep_local(my_id: &[u8; 32], peer_id: &[u8; 32]) -> bool {
    my_id >= peer_id
}

/// `PunchPredictor` pre-loaded with STUN samples gathered by the composition
/// root. `PunchSession::run` calls `assess(&[])`, so the samples must be
/// seeded here (the frozen contract assigns sample collection to the root).
#[derive(Debug)]
pub struct SeededPredictor {
    samples: Vec<PortSample>,
    inner: DefaultPredictor,
}

impl SeededPredictor {
    pub fn new(samples: Vec<PortSample>) -> Self {
        Self {
            samples,
            inner: DefaultPredictor,
        }
    }
}

impl PunchPredictor for SeededPredictor {
    fn assess(&self, _samples: &[PortSample]) -> Predictability {
        self.inner.assess(&self.samples)
    }

    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan> {
        self.inner.plan(p, target_ip, k)
    }
}

/// `PunchRaceFeed`: P0 logs + counts direct candidates. Real PathManager
/// integration is a follow-up (see report); the relay stays the working path.
#[derive(Debug, Default)]
pub struct LoggingFeed {
    counts: Mutex<HashMap<[u8; 32], u64>>,
}

impl LoggingFeed {
    pub fn count_for(&self, peer: &[u8; 32]) -> u64 {
        self.counts
            .lock()
            .map(|g| g.get(peer).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

impl PunchRaceFeed for LoggingFeed {
    fn report_direct_candidate(
        &self,
        peer: nexus_nat_traversal::PeerId,
        addr: SocketAddr,
        rtt_ms: u64,
        loss_01: f64,
    ) {
        if let Ok(mut g) = self.counts.lock() {
            *g.entry(peer.0).or_insert(0) += 1;
        }
        eprintln!(
            "[wireup] direct candidate registered: peer={} addr={addr} rtt_ms={rtt_ms} loss={loss_01}",
            hex_id(&peer.0),
        );
    }
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// A surviving direct connection after tie-break.
#[derive(Clone)]
pub struct DirectConn {
    pub conn: Arc<ConnShared>,
    pub addr: SocketAddr,
    /// True if initiated by us (winner side), false if adopted from accept.
    pub initiated_locally: bool,
}

/// Orchestrator: responder loops, session dedup, tie-break, direct registry.
pub struct PunchManager {
    driver: Arc<Driver>,
    my_id: FabricPeerId,
    active: Mutex<HashSet<FabricPeerId>>,
    responders: Mutex<HashSet<u64>>,
    relay_peers: Mutex<HashMap<u64, FabricPeerId>>,
    local: Mutex<LocalCandidates>,
    samples: Mutex<Vec<PortSample>>,
    feed: Arc<LoggingFeed>,
    direct: Mutex<HashMap<FabricPeerId, DirectConn>>,
    sockets: Mutex<HashMap<FabricPeerId, Arc<DriverPunchSocket>>>,
    config: Mutex<PunchConfig>,
    /// All nonces seen in relay signaling with a peer (offer nonces we sent
    /// plus offer nonces we received). The bind challenge proves the far end
    /// of an accepted direct connection took part in that signaling: the
    /// responder must echo a nonce from this set. Per-peer sets make
    /// cross-peer misidentification impossible (D4).
    signaling_nonces: Mutex<HashMap<FabricPeerId, HashSet<u64>>>,
    /// Inbound relay streams whose type is not punch. The responder peeks
    /// the type WITHOUT consuming bytes, so stashed streams are intact and
    /// can be handed to their real owner later. Never mis-decoded as offers.
    /// (D5: "转交" — handoff. "放回" would spin on the same stream.)
    unclaimed: Mutex<VecDeque<(u8, Arc<StreamShared>)>>,
}

impl PunchManager {
    pub fn new(driver: Arc<Driver>, my_id: FabricPeerId) -> Arc<Self> {
        Arc::new(Self {
            driver,
            my_id,
            active: Mutex::new(HashSet::new()),
            responders: Mutex::new(HashSet::new()),
            relay_peers: Mutex::new(HashMap::new()),
            local: Mutex::new(LocalCandidates {
                host: Vec::new(),
                srflx: None,
                srflx_stun: None,
                nat_type: NatType::Unknown,
            }),
            samples: Mutex::new(Vec::new()),
            feed: Arc::new(LoggingFeed::default()),
            direct: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            config: Mutex::new(PunchConfig::default()),
            signaling_nonces: Mutex::new(HashMap::new()),
            unclaimed: Mutex::new(VecDeque::new()),
        })
    }

    /// Punch parameters shared by initiator and responder paths.
    pub fn set_config(&self, config: PunchConfig) {
        *self.config.lock().unwrap() = config;
    }

    /// Local candidates + STUN port samples (drives the predictor).
    pub fn set_local(&self, local: LocalCandidates, samples: Vec<PortSample>) {
        *self.local.lock().unwrap() = local;
        *self.samples.lock().unwrap() = samples;
    }

    pub fn feed(&self) -> &Arc<LoggingFeed> {
        &self.feed
    }

    pub fn direct_conn(&self, peer: &FabricPeerId) -> Option<DirectConn> {
        self.direct.lock().ok()?.get(peer).cloned()
    }

    /// Record a signaling nonce for bind identity (D4). Both sent and
    /// received offer nonces go here; the bind challenge accepts any of them.
    fn record_signaling_nonce(&self, peer: FabricPeerId, nonce: u64) {
        if let Ok(mut g) = self.signaling_nonces.lock() {
            g.entry(peer).or_default().insert(nonce);
        }
    }

    /// Take a stashed non-punch stream, if any: `(stream type, stream)`.
    /// Bytes are intact (the responder only peeked the type).
    pub fn take_unclaimed(&self) -> Option<(u8, Arc<StreamShared>)> {
        self.unclaimed.lock().ok()?.pop_front()
    }

    fn stash_unclaimed(&self, ty: u8, stream: Arc<StreamShared>) {
        if let Ok(mut q) = self.unclaimed.lock() {
            q.push_back((ty, stream));
        }
    }

    /// Punch attempts used by the last `punch_peer` for `peer`
    /// (observability; E4 asserts no spray storm on unpredictable NAT).
    pub fn punch_attempts(&self, peer: &FabricPeerId) -> Option<u64> {
        self.sockets
            .lock()
            .ok()?
            .get(peer)
            .map(|s| s.punch_attempts())
    }

    fn local_snapshot(&self) -> LocalCandidates {
        self.local.lock().unwrap().clone()
    }

    fn samples_snapshot(&self) -> Vec<PortSample> {
        self.samples.lock().unwrap().clone()
    }

    /// Register a relayed connection and ensure a responder loop serves it.
    /// Idempotent per connection id.
    pub fn register_relay(self: &Arc<Self>, relay_conn: &Arc<ConnShared>, peer: FabricPeerId) {
        let conn_id = relay_conn.id.0;
        self.relay_peers.lock().unwrap().insert(conn_id, peer);
        let mut responders = self.responders.lock().unwrap();
        if !responders.insert(conn_id) {
            return; // already running
        }
        drop(responders);
        let this = self.clone();
        let conn = relay_conn.clone();
        thread::spawn(move || this.responder_loop(conn));
    }

    /// Blocking punch orchestration (runs `PunchSession` on a worker thread).
    pub fn punch_peer(
        self: &Arc<Self>,
        relay_conn: &Arc<ConnShared>,
        peer: FabricPeerId,
        remote_nat: NatType,
        config: PunchConfig,
    ) -> PunchResult {
        // 发起方配置即 manager 配置：responder 路径（handle_offer）共用，保证两侧对称。
        self.set_config(config);
        let channel = match FabricPunchChannel::open(relay_conn) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                eprintln!("[wireup] signal channel open failed: {e}");
                return PunchResult::StayedOnRelay {
                    reason: nexus_nat_traversal::PunchFailReason::ChannelClosed,
                };
            }
        };
        let socket = Arc::new(DriverPunchSocket::new(
            self.driver.clone(),
            peer,
            config.punch_timeout,
        ));
        self.sockets
            .lock()
            .unwrap()
            .insert(peer, Arc::clone(&socket));
        let predictor = Arc::new(SeededPredictor::new(self.samples_snapshot()));
        let local = self.local_snapshot();

        self.active.lock().unwrap().insert(peer);
        let sock2 = socket.clone();
        let channel2 = channel.clone();
        let result = thread::spawn(move || {
            let mut session = PunchSession::new(
                nexus_nat_traversal::PeerId(peer.0),
                local,
                remote_nat,
                config,
                channel2,
                sock2,
                predictor,
            );
            session.run()
        })
        .join()
        .unwrap_or(PunchResult::StayedOnRelay {
            reason: nexus_nat_traversal::PunchFailReason::ChannelClosed,
        });
        self.active.lock().unwrap().remove(&peer);

        // Record our offer nonce for bind identity (D4): the far end must
        // echo a signaling nonce to prove it is this peer.
        if let Some(nonce) = channel.last_offer_nonce() {
            self.record_signaling_nonce(peer, nonce);
        }

        if let PunchResult::Migrated { addr } = &result {
            self.on_migrated(peer, *addr, &socket);
        }
        result
    }

    /// Tie-break + feed after a successful punch.
    fn on_migrated(
        self: &Arc<Self>,
        peer: FabricPeerId,
        addr: SocketAddr,
        socket: &DriverPunchSocket,
    ) {
        let Some((_, conn)) = socket.take_winner() else {
            eprintln!("[wireup] Migrated without winner conn; relay remains");
            return;
        };
        let direct = if tie_break_keep_local(&self.my_id.0, &peer.0) {
            eprintln!(
                "[wireup] tie-break: we win ({}), keeping initiated conn to {addr}",
                hex_id(&self.my_id.0)
            );
            // Serve bind challenges so the loser can verify this connection
            // is really us (D4). Bounded lifetime: the loser challenges
            // immediately after its own tie-break.
            self.spawn_bind_responder(peer, conn.clone());
            DirectConn {
                conn,
                addr,
                initiated_locally: true,
            }
        } else {
            eprintln!("[wireup] tie-break: peer wins, closing our initiated conn");
            self.driver.send(Cmd::Close {
                conn: conn.id.0,
                code: 0,
                reason: b"punch tie-break: peer wins".to_vec(),
            });
            match self.adopt_verified_direct(peer, Duration::from_secs(10)) {
                Some(c) => {
                    eprintln!("[wireup] adopted peer-initiated direct conn (nonce-verified)");
                    DirectConn {
                        conn: c,
                        addr,
                        initiated_locally: false,
                    }
                }
                None => {
                    eprintln!(
                        "[wireup] WARN: no verified direct conn found; relay remains the path"
                    );
                    return;
                }
            }
        };
        self.direct.lock().unwrap().insert(peer, direct);
        // P0: report with zeroed measurements (real scoring is follow-up).
        self.feed
            .report_direct_candidate(nexus_nat_traversal::PeerId(peer.0), addr, 0, 0.0);
    }

    /// Responder: accept punch offers on `relay_conn`, answer on the same
    /// stream, and punch back unless a session for this peer is active.
    ///
    /// Stream routing (D5): the first frame's type byte is PEEKED, never
    /// consumed for routing. Only `STREAM_TYPE_PUNCH` streams reach
    /// `handle_offer`; everything else is stashed in `unclaimed` with bytes
    /// intact, so transfer/data streams are never mis-decoded as offers.
    fn responder_loop(self: Arc<Self>, relay_conn: Arc<ConnShared>) {
        let conn_id = relay_conn.id.0;
        loop {
            let stream = match accept_stream_timeout(&relay_conn, Duration::from_secs(1)) {
                Ok(s) => s,
                Err(_) => {
                    if conn_closed(&relay_conn) {
                        break;
                    }
                    continue;
                }
            };
            match peek_stream_type(&stream, Instant::now() + Duration::from_secs(2)) {
                Ok(ty) if ty == STREAM_TYPE_PUNCH => {
                    if let Err(e) = Self::handle_offer(&self, conn_id, stream) {
                        eprintln!("[wireup] offer handling failed: {e}");
                    }
                }
                Ok(ty) => {
                    eprintln!(
                        "[wireup] non-punch stream (type {ty:#04x}) stashed unclaimed, not consumed"
                    );
                    self.stash_unclaimed(ty, stream);
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    // Idle stream, no bytes yet: put it back so a slow
                    // writer isn't killed. Peek consumed nothing; the 2s
                    // wait bounds the retry spin.
                    push_back_accepted(&relay_conn, stream);
                }
                Err(e) => {
                    // EOF / error: dead stream, drop it.
                    eprintln!("[wireup] dropping dead inbound stream: {e}");
                }
            }
        }
    }

    fn handle_offer(this: &Arc<Self>, conn_id: u64, stream: Arc<StreamShared>) -> io::Result<()> {
        let peer = *this
            .relay_peers
            .lock()
            .unwrap()
            .get(&conn_id)
            .ok_or_else(|| io::Error::other("unknown relay conn"))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let (ty, payload) = channel::read_msg(&stream, deadline)?;
        if ty != STREAM_TYPE_PUNCH {
            // Defense in depth: responder_loop already routes by type.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("handle_offer: expected punch stream, got type {ty:#04x}"),
            ));
        }
        let offer = decode_offer(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;

        // Record the peer's offer nonce for bind identity (D4).
        this.record_signaling_nonce(peer, offer.nonce);

        // Answer on the same stream.
        let local = this.local_snapshot();
        let answer = PunchAnswer {
            version: SIGNAL_VERSION,
            nonce: offer.nonce,
            candidates: local.ordered(),
            nat_type: local.nat_type,
        };
        channel::write_msg(&stream, STREAM_TYPE_PUNCH, &encode_answer(&answer))?;

        // Dedup (atomic insert): an active session for this peer already punches.
        if !this.active.lock().unwrap().insert(peer) {
            return Ok(());
        }

        // Punch back through the frozen state machine with a pre-answered
        // channel (the real answer went out on the accepted stream above).
        let preanswered = Arc::new(PreAnsweredChannel::new(
            offer.candidates.clone(),
            offer.nat_type,
        ));
        let socket = Arc::new(DriverPunchSocket::new(
            this.driver.clone(),
            peer,
            Duration::from_secs(5),
        ));
        this.sockets
            .lock()
            .unwrap()
            .insert(peer, Arc::clone(&socket));
        let predictor = Arc::new(SeededPredictor::new(this.samples_snapshot()));
        // 与发起方对称：用 manager 上最近一次配置（未配置则为 default）。
        let config = *this.config.lock().unwrap();
        let remote_nat = offer.nat_type;
        let sock2 = socket.clone();
        let this2 = this.clone();
        let preanswered2 = preanswered.clone();
        thread::spawn(move || {
            let mut session = PunchSession::new(
                nexus_nat_traversal::PeerId(peer.0),
                local,
                remote_nat,
                config,
                preanswered2,
                sock2,
                predictor,
            );
            let result = session.run();
            // Record our (responder-side) offer nonce for bind identity.
            if let Some(nonce) = preanswered.captured_nonce() {
                this2.record_signaling_nonce(peer, nonce);
            }
            this2.active.lock().unwrap().remove(&peer);
            if let PunchResult::Migrated { addr } = &result {
                this2.on_migrated(peer, *addr, &socket);
            }
        });
        Ok(())
    }

    /// Serve bind challenges on our kept direct connection so the tie-break
    /// loser can verify this connection is really us (D4).
    ///
    /// Bounded lifetime (30s): the loser challenges immediately after its own
    /// tie-break. Only `STREAM_TYPE_BIND` streams are answered; anything else
    /// is left alone (peeked, not consumed).
    fn spawn_bind_responder(self: &Arc<Self>, peer: FabricPeerId, conn: Arc<ConnShared>) {
        let nonces: Vec<u64> = self
            .signaling_nonces
            .lock()
            .map(|g| {
                g.get(&peer)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
        if nonces.is_empty() {
            eprintln!("[wireup] no signaling nonces for peer; bind responder not started");
            return;
        }
        let payload = encode_bind_response(&nonces);
        thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30) {
                if conn_closed(&conn) {
                    break;
                }
                let stream = match accept_stream_timeout(&conn, Duration::from_secs(1)) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                match peek_stream_type(&stream, Instant::now() + Duration::from_secs(5)) {
                    Ok(ty) if ty == STREAM_TYPE_BIND => {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        if let Ok((STREAM_TYPE_BIND, _)) = channel::read_msg(&stream, deadline) {
                            let _ = channel::write_msg(&stream, STREAM_TYPE_BIND, &payload);
                        }
                    }
                    _ => {
                        // Not a bind challenge (or dead stream): leave it.
                    }
                }
            }
        });
    }

    /// Adopt the peer-initiated direct connection after verifying, via a
    /// nonce challenge-response on the candidate connection itself, that the
    /// far end participated in this peer's relay signaling (D4).
    ///
    /// Replaces the old recency heuristic (`resolve_accepted_after`), which
    /// could misidentify the peer when several punches run concurrently.
    /// Returns `None` (relay remains the path) when no candidate proves
    /// knowledge of a signaling nonce within `timeout`.
    fn adopt_verified_direct(
        &self,
        peer: FabricPeerId,
        timeout: Duration,
    ) -> Option<Arc<ConnShared>> {
        let expected: HashSet<u64> = self
            .signaling_nonces
            .lock()
            .ok()?
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        if expected.is_empty() {
            eprintln!("[wireup] no signaling nonces for peer; cannot verify direct conn");
            return None;
        }
        let deadline = Instant::now() + timeout;
        let shared = self.driver.shared();
        // Connection ids already definitively rejected (wrong nonce).
        // Timeouts are retried: the winner's bind responder may not be up yet,
        // so retryable candidates are kept across rounds (accept_q is drained,
        // not peeked — popped ids would otherwise be lost).
        let mut pending: Vec<Arc<ConnShared>> = Vec::new();
        let mut rejected: HashSet<u64> = HashSet::new();
        while Instant::now() < deadline {
            // Drain new accepts into pending.
            {
                let mut q = shared.accept_q.lock().ok()?;
                while let Some(id) = q.pop_front() {
                    if rejected.contains(&id) || pending.iter().any(|c| c.id.0 == id) {
                        continue;
                    }
                    if let Some(c) = shared.conns.lock().ok()?.get(&id).cloned() {
                        let open = c
                            .state
                            .lock()
                            .map(|st| st.closed.is_none())
                            .unwrap_or(false);
                        if open {
                            pending.push(c);
                        }
                    }
                }
            }
            let mut still_pending = Vec::new();
            for conn in pending.drain(..) {
                // Drop closed conns instead of retrying them forever.
                let open = conn
                    .state
                    .lock()
                    .map(|st| st.closed.is_none())
                    .unwrap_or(false);
                if !open {
                    continue;
                }
                match self.try_bind_challenge(&conn, &expected, deadline) {
                    BindOutcome::Verified => return Some(conn),
                    BindOutcome::Rejected => {
                        rejected.insert(conn.id.0);
                    }
                    BindOutcome::Retryable => still_pending.push(conn),
                }
            }
            pending = still_pending;
            // Wait for new accepts (or deadline).
            if let Ok(q) = shared.accept_q.lock() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let _ = shared
                    .accept_cv
                    .wait_timeout(q, remaining.min(Duration::from_millis(200)));
            }
        }
        None
    }

    /// Challenge one candidate connection. Opens a bi-stream, sends a
    /// `STREAM_TYPE_BIND` challenge, and checks the response nonces against
    /// the signaling nonces for this peer.
    fn try_bind_challenge(
        &self,
        conn: &Arc<ConnShared>,
        expected: &HashSet<u64>,
        deadline: Instant,
    ) -> BindOutcome {
        let stream = match channel::open_bi_stream(conn, Duration::from_secs(2)) {
            Ok(s) => s,
            Err(_) => return BindOutcome::Retryable,
        };
        // Challenge payload: single version byte (non-empty; write_msg
        // rejects empty payloads).
        if channel::write_msg(&stream, STREAM_TYPE_BIND, &[1]).is_err() {
            return BindOutcome::Retryable;
        }
        let per_try = deadline.min(Instant::now() + Duration::from_secs(3));
        match channel::read_msg(&stream, per_try) {
            Ok((ty, payload)) if ty == STREAM_TYPE_BIND => match decode_bind_response(&payload) {
                Ok(nonces) if verify_bind(expected, &nonces) => BindOutcome::Verified,
                _ => BindOutcome::Rejected,
            },
            Ok(_) => BindOutcome::Rejected,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => BindOutcome::Retryable,
            Err(_) => BindOutcome::Retryable,
        }
    }
}

/// Outcome of one bind challenge against a candidate direct connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindOutcome {
    /// Far end proved knowledge of a signaling nonce: adopt it.
    Verified,
    /// Far end answered with a foreign nonce: never this peer, don't retry.
    Rejected,
    /// No answer yet (responder not up / stream failed): retry until deadline.
    Retryable,
}

/// Push a stream back onto the connection's accepted queue (for retry).
/// The stream's bytes are untouched.
fn push_back_accepted(conn: &Arc<ConnShared>, stream: Arc<StreamShared>) {
    if let Ok(mut q) = conn.accepted.lock() {
        q.push_back(stream);
        conn.accepted_cv.notify_one();
    }
}

/// Accept one bidirectional stream with timeout (P0: responder owns accept on
/// registered relay conns).
pub fn accept_stream_timeout(
    conn: &Arc<ConnShared>,
    timeout: Duration,
) -> io::Result<Arc<StreamShared>> {
    let deadline = Instant::now() + timeout;
    let mut q = conn
        .accepted
        .lock()
        .map_err(|_| io::Error::other("accept lock poisoned"))?;
    loop {
        if let Some(s) = q.pop_front() {
            return Ok(s);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "accept timeout"));
        }
        let (guard, _) = conn
            .accepted_cv
            .wait_timeout(q, Duration::from_millis(50))
            .map_err(|_| io::Error::other("accept lock poisoned"))?;
        q = guard;
    }
}

fn conn_closed(conn: &Arc<ConnShared>) -> bool {
    conn.state
        .lock()
        .map(|st| st.closed.is_some())
        .unwrap_or(true)
}

/// One-shot convenience: build an ephemeral manager, register the relay,
/// run the punch. (The responder thread outlives the call, which is
/// required for the both-initiate case.)
pub fn punch_peer(
    driver: &Arc<Driver>,
    my_id: FabricPeerId,
    relay_conn: &Arc<ConnShared>,
    peer: FabricPeerId,
    local: LocalCandidates,
    remote_nat: NatType,
    config: PunchConfig,
) -> PunchResult {
    let mgr = PunchManager::new(driver.clone(), my_id);
    mgr.set_local(local, Vec::new());
    mgr.register_relay(relay_conn, peer);
    mgr.punch_peer(relay_conn, peer, remote_nat, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> Option<Arc<PunchManager>> {
        let driver = Driver::new_client().ok()?;
        Some(PunchManager::new(driver, FabricPeerId([7u8; 32])))
    }

    /// D4: per-peer nonce sets — peer B's nonce never verifies as peer A.
    /// This is the multi-peer concurrent misidentification case.
    #[test]
    fn signaling_nonces_are_per_peer() {
        let mgr = test_manager().expect("driver must build in test");
        let peer_a = FabricPeerId([0xAA; 32]);
        let peer_b = FabricPeerId([0xBB; 32]);
        mgr.record_signaling_nonce(peer_a, 111);
        mgr.record_signaling_nonce(peer_b, 222);

        let nonces_a: HashSet<u64> = mgr
            .signaling_nonces
            .lock()
            .unwrap()
            .get(&peer_a)
            .cloned()
            .unwrap();
        let nonces_b: HashSet<u64> = mgr
            .signaling_nonces
            .lock()
            .unwrap()
            .get(&peer_b)
            .cloned()
            .unwrap();

        // A's set verifies A's nonce, rejects B's.
        assert!(verify_bind(&nonces_a, &[111]));
        assert!(!verify_bind(&nonces_a, &[222]));
        // B's set verifies B's nonce, rejects A's.
        assert!(verify_bind(&nonces_b, &[222]));
        assert!(!verify_bind(&nonces_b, &[111]));
        // Unknown peer has no nonces: never verifies.
        let unknown = FabricPeerId([0xCC; 32]);
        let empty: HashSet<u64> = mgr
            .signaling_nonces
            .lock()
            .unwrap()
            .get(&unknown)
            .cloned()
            .unwrap_or_default();
        assert!(!verify_bind(&empty, &[111]));
        assert!(!verify_bind(&empty, &[222]));
    }

    /// D4: bind response codec carries the nonce set.
    #[test]
    fn bind_challenge_response_codec() {
        let nonces = vec![111u64, 222u64];
        let payload = encode_bind_response(&nonces);
        // Frame it as a BIND-type stream frame.
        let framed = channel::frame_msg(STREAM_TYPE_BIND, &payload);
        let (ty, out, _) = channel::deframe(&framed).unwrap();
        assert_eq!(ty, STREAM_TYPE_BIND);
        let back = decode_bind_response(&out).unwrap();
        assert_eq!(back, nonces);
    }
}
