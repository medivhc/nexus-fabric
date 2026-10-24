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
pub mod clock;
pub mod repunch;
pub mod responder;
pub mod socket;
pub mod status;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nexus_connectivity::nat::NatType;
use nexus_fabric::{Cmd, ConnShared, Driver, PeerId as FabricPeerId, StreamShared};
use nexus_nat_traversal::{
    DefaultPredictor, LocalCandidates, PortSample, Predictability, PredictionHint, PunchAnswer,
    PunchClock, PunchConfig, PunchPredictor, PunchRaceFeed, PunchResult, PunchSession, PunchStats,
    SIGNAL_VERSION, SprayPlan, decode_offer, encode_answer,
};

pub use channel::{
    FabricPunchChannel, STREAM_TYPE_BIND, STREAM_TYPE_PUNCH, STREAM_TYPE_WORKSPACE_SYNC,
    decode_bind_response, encode_bind_response, frame_msg, peek_stream_type, verify_bind,
};
pub use clock::SystemPunchClock;
pub use repunch::Scheduler;
pub use responder::PreAnsweredChannel;
pub use socket::DriverPunchSocket;
pub use status::{PunchPeerStatus, PunchState, RelaySource, RepunchTrigger, TunnelProto};

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
    clock: Arc<dyn PunchClock>,
    status: Mutex<HashMap<[u8; 32], PunchPeerStatus>>,
    scheduler: Mutex<Scheduler>,
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

/// Routing decision for one inbound relay stream, from the responder's peek
/// outcome. Pure: this is the D5 demux table, directly unit-tested.
///
/// The responder is the SOLE stream acceptor on relay connections registered
/// via [`PunchManager::register_relay`]; the session layer must NOT call
/// `accept_bi` on those connections (it would race the responder on the
/// shared `accepted` queue). Non-punch streams are handed over via
/// [`PunchManager::take_unclaimed`] with bytes untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundRoute {
    /// Punch signaling: consumed by the offer handler.
    Punch,
    /// Anything else: stashed to `unclaimed` for the session layer.
    /// The first-frame type byte is preserved (peek never pops).
    StashUnclaimed(u8),
    /// Idle stream, no bytes yet: pushed back so a slow writer isn't killed.
    PushBack,
    /// Dead stream (EOF / error): dropped.
    Drop,
}

/// Classify an inbound relay stream from the responder's type peek.
/// See [`InboundRoute`] for the contract.
fn route_inbound(peek: &io::Result<u8>) -> InboundRoute {
    match peek {
        Ok(ty) if *ty == STREAM_TYPE_PUNCH => InboundRoute::Punch,
        Ok(ty) => InboundRoute::StashUnclaimed(*ty),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => InboundRoute::PushBack,
        Err(_) => InboundRoute::Drop,
    }
}

impl PunchManager {
    pub fn new(driver: Arc<Driver>, my_id: FabricPeerId, clock: Arc<dyn PunchClock>) -> Arc<Self> {
        let scheduler = Scheduler::new(&PunchConfig::default());
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
                srflx_turn: None,
                nat_type: NatType::Unknown,
            }),
            samples: Mutex::new(Vec::new()),
            feed: Arc::new(LoggingFeed::default()),
            direct: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            config: Mutex::new(PunchConfig::default()),
            clock,
            status: Mutex::new(HashMap::new()),
            scheduler: Mutex::new(scheduler),
            signaling_nonces: Mutex::new(HashMap::new()),
            unclaimed: Mutex::new(VecDeque::new()),
        })
    }

    /// Punch parameters shared by initiator and responder paths.
    pub fn set_config(&self, config: PunchConfig) {
        *self.config.lock().unwrap() = config;
        *self.scheduler.lock().unwrap() = Scheduler::new(&config);
    }

    /// Replace STUN samples (reflexive change path).
    pub fn set_samples(&self, samples: Vec<PortSample>) {
        *self.samples.lock().unwrap() = samples;
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
    ///
    /// Demux handoff contract (D5, WARN-2):
    /// - [`PunchManager::register_relay`] makes the wireup responder loop the
    ///   SOLE stream acceptor on that relay connection. The session layer
    ///   must NOT call `accept_bi` (or pop `ConnShared.accepted`) on a
    ///   punch-registered relay conn — it would race the responder on the
    ///   shared accept queue.
    /// - The responder routes by the first frame's type byte (see
    ///   [`route_inbound`]): punch streams are consumed as signaling; every
    ///   other stream is stashed here with bytes untouched.
    /// - The session layer takes non-punch streams from THIS queue. Bytes
    ///   are intact: the responder only PEEKED the type byte, never popped
    ///   it (`peek_stream_type` leaves `recv_buf` whole).
    /// - FIFO order; `None` when no unclaimed stream is waiting.
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

    fn with_status<R>(
        &self,
        peer: FabricPeerId,
        f: impl FnOnce(&mut PunchPeerStatus) -> R,
    ) -> Option<R> {
        let mut g = self.status.lock().ok()?;
        let entry = g
            .entry(peer.0)
            .or_insert_with(|| PunchPeerStatus::new(peer));
        Some(f(entry))
    }

    pub fn status(&self, peer: &FabricPeerId) -> Option<PunchPeerStatus> {
        self.status.lock().ok()?.get(&peer.0).cloned()
    }

    pub fn all_status(&self) -> Vec<PunchPeerStatus> {
        self.status
            .lock()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn set_tunnel_proto(&self, peer: FabricPeerId, proto: TunnelProto) {
        let _ = self.with_status(peer, |s| s.tunnel_proto = proto);
    }

    pub fn set_relay_source(&self, peer: FabricPeerId, source: Option<RelaySource>) {
        let _ = self.with_status(peer, |s| s.relay_source = source);
    }

    fn record_signal_decode_error(&self, peer: FabricPeerId, n: u64) {
        let _ = self.with_status(peer, |s| {
            s.signal_decode_errors_total = s.signal_decode_errors_total.saturating_add(n);
        });
    }

    fn aggregate_stats(&self, peer: FabricPeerId, stats: PunchStats, result: &PunchResult) {
        let now = self.clock.now_ms();
        let _ = self.with_status(peer, |s| {
            s.attempts_total = s.attempts_total.saturating_add(stats.attempts);
            s.migrated_total = s.migrated_total.saturating_add(stats.migrated);
            s.failed_timeout_total = s.failed_timeout_total.saturating_add(stats.failed_timeout);
            s.failed_unpredictable_total = s
                .failed_unpredictable_total
                .saturating_add(stats.failed_unpredictable);
            s.failed_no_candidates_total = s
                .failed_no_candidates_total
                .saturating_add(stats.failed_no_candidates);
            s.failed_channel_closed_total = s
                .failed_channel_closed_total
                .saturating_add(stats.failed_channel_closed);
            s.spray_sends_total = s.spray_sends_total.saturating_add(stats.spray_sends);
            s.spray_skipped_total = s.spray_skipped_total.saturating_add(stats.spray_skipped);
            s.mapping_probe_sends_total = s
                .mapping_probe_sends_total
                .saturating_add(stats.mapping_probe_sends);
            s.prediction_hints_sent_total = s
                .prediction_hints_sent_total
                .saturating_add(stats.prediction_hints_sent);
            s.prediction_hints_recv_total = s
                .prediction_hints_recv_total
                .saturating_add(stats.prediction_hints_recv);
            s.phase = stats.last_phase;
            s.last_attempt_ms = Some(now);
            match result {
                PunchResult::Migrated { addr } => {
                    s.state = PunchState::Succeeded;
                    s.last_result = Some(*result);
                    s.fail_reason = None;
                    s.last_success_ms = Some(now);
                    s.last_direct_addr = Some(*addr);
                    s.direct_conn_id = self
                        .direct
                        .lock()
                        .ok()
                        .and_then(|d| d.get(&peer).map(|c| c.conn.id.0));
                }
                PunchResult::StayedOnRelay { reason } => {
                    s.state = PunchState::Failed;
                    s.last_result = Some(*result);
                    s.fail_reason = Some(*reason);
                }
            }
        });
    }

    /// Prediction hint advertised by this manager (from current samples).
    fn prediction_for(&self) -> Option<PredictionHint> {
        let samples = self.samples_snapshot();
        let predictor = SeededPredictor::new(samples.clone());
        match predictor.assess(&samples) {
            Predictability::Predictable { base_port, delta } if samples.len() >= 3 => {
                Some(PredictionHint {
                    base_port,
                    delta,
                    samples: samples.len().min(8) as u8,
                })
            }
            _ => None,
        }
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
        let samples = self.samples_snapshot();
        let predictor = Arc::new(SeededPredictor::new(samples.clone()));
        let local = self.local_snapshot();
        let clock = self.clock.clone();

        self.active.lock().unwrap().insert(peer);
        let _ = self.with_status(peer, |s| {
            s.state = PunchState::InProgress;
            s.phase = nexus_nat_traversal::PunchPhase::Idle;
        });
        let sock2 = socket.clone();
        let channel2 = channel.clone();
        let (result, stats) = thread::spawn(move || {
            let mut session = PunchSession::new(
                nexus_nat_traversal::PeerId(peer.0),
                local,
                remote_nat,
                samples,
                config,
                channel2,
                sock2,
                predictor,
                clock,
            );
            let result = session.run();
            (result, session.stats())
        })
        .join()
        .unwrap_or((
            PunchResult::StayedOnRelay {
                reason: nexus_nat_traversal::PunchFailReason::ChannelClosed,
            },
            PunchStats::default(),
        ));
        self.active.lock().unwrap().remove(&peer);
        self.aggregate_stats(peer, stats, &result);

        // Record our offer nonce for bind identity (D4): the far end must
        // echo a signaling nonce to prove it is this peer.
        if let Some(nonce) = channel.last_offer_nonce() {
            self.record_signaling_nonce(peer, nonce);
        }
        let decode_errors = channel.decode_errors();
        if decode_errors > 0 {
            self.record_signal_decode_error(peer, decode_errors);
        }

        if let PunchResult::Migrated { addr } = &result {
            self.on_migrated(peer, *addr, &socket);
        }
        result
    }

    /// Automatic repunch (periodic / reflexive change / relay degradation).
    ///
    /// Any side Symmetric disables all automatic repunch (C-22): the call is
    /// refused with the relay kept as-is.
    pub fn repunch(
        self: &Arc<Self>,
        relay_conn: &Arc<ConnShared>,
        peer: FabricPeerId,
        trigger: RepunchTrigger,
    ) -> PunchResult {
        let local = self.local_snapshot();
        let remote_nat = self
            .status(&peer)
            .map(|s| s.nat_type_remote)
            .unwrap_or(NatType::Unknown);
        if local.nat_type == NatType::Symmetric || remote_nat == NatType::Symmetric {
            eprintln!(
                "[wireup] repunch skipped for peer {}: symmetric side disables auto repunch ({trigger:?})",
                hex_id(&peer.0)
            );
            return PunchResult::StayedOnRelay {
                reason: nexus_nat_traversal::PunchFailReason::UnpredictableSymmetric,
            };
        }
        let config = *self.config.lock().unwrap();
        self.punch_peer(relay_conn, peer, remote_nat, config)
    }

    /// Reflexive address changed: update local candidates/samples. Never
    /// starts a session while either side is Symmetric (C-22).
    pub fn on_reflexive_changed(&self, srflx: SocketAddr) {
        if let Ok(mut local) = self.local.lock() {
            local.srflx = Some(srflx);
        }
    }

    /// Relay degradation signal from the quality monitor.
    pub fn on_relay_degraded(&self, peer: FabricPeerId) {
        let _ = self.with_status(peer, |s| {
            s.fail_reason = Some(nexus_nat_traversal::PunchFailReason::Timeout);
        });
        eprintln!("[wireup] relay degraded for peer {}", hex_id(&peer.0));
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
            let peeked = peek_stream_type(&stream, Instant::now() + Duration::from_secs(2));
            match route_inbound(&peeked) {
                InboundRoute::Punch => {
                    if let Err(e) = Self::handle_offer(&self, conn_id, stream) {
                        eprintln!("[wireup] offer handling failed: {e}");
                    }
                }
                InboundRoute::StashUnclaimed(ty) => {
                    eprintln!(
                        "[wireup] non-punch stream (type {ty:#04x}) stashed unclaimed, not consumed"
                    );
                    self.stash_unclaimed(ty, stream);
                }
                InboundRoute::PushBack => {
                    // Idle stream, no bytes yet: put it back so a slow
                    // writer isn't killed. Peek consumed nothing; the 2s
                    // wait bounds the retry spin.
                    push_back_accepted(&relay_conn, stream);
                }
                InboundRoute::Drop => {
                    // EOF / error: dead stream, drop it.
                    eprintln!("[wireup] dropping dead inbound stream: {peeked:?}");
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
        let prediction = this.prediction_for();
        let answer = PunchAnswer {
            version: SIGNAL_VERSION,
            nonce: offer.nonce,
            candidates: local.ordered(),
            nat_type: local.nat_type,
            prediction,
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
            offer.prediction,
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
        let samples = this.samples_snapshot();
        let predictor = Arc::new(SeededPredictor::new(samples.clone()));
        // 与发起方对称：用 manager 上最近一次配置（未配置则为 default）。
        let config = *this.config.lock().unwrap();
        let remote_nat = offer.nat_type;
        let sock2 = socket.clone();
        let this2 = this.clone();
        let preanswered2 = preanswered.clone();
        let clock = this.clock.clone();
        thread::spawn(move || {
            let mut session = PunchSession::new(
                nexus_nat_traversal::PeerId(peer.0),
                local,
                remote_nat,
                samples,
                config,
                preanswered2,
                sock2,
                predictor,
                clock,
            );
            let result = session.run();
            let stats = session.stats();
            // Record our (responder-side) offer nonce for bind identity.
            if let Some(nonce) = preanswered.captured_nonce() {
                this2.record_signaling_nonce(peer, nonce);
            }
            this2.active.lock().unwrap().remove(&peer);
            this2.aggregate_stats(peer, stats, &result);
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
    ///
    /// Concurrency (WARN-1): several adopts may run at once (A punching B
    /// and C, losing both tie-breaks). Drained candidate ids are never
    /// silently dropped — rejected / unprocessed / retryable ids are
    /// requeued — so one adopt cannot swallow another peer's connection.
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
        // Timeouts are retried: the winner's bind responder may not be up yet.
        let mut pending: Vec<Arc<ConnShared>> = Vec::new();
        let mut rejected: HashSet<u64> = HashSet::new();
        while Instant::now() < deadline {
            drain_candidates(
                &shared.accept_q,
                &shared.accept_cv,
                &shared.conns,
                &rejected,
                &mut pending,
            );
            let mut still_pending = Vec::new();
            let mut verified: Option<Arc<ConnShared>> = None;
            for conn in pending.drain(..) {
                if verified.is_some() {
                    // Already adopted one; requeue the rest for other adopts.
                    requeue_accept_id(&shared.accept_q, &shared.accept_cv, conn.id.0);
                    continue;
                }
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
                    BindOutcome::Verified => verified = Some(conn),
                    BindOutcome::Rejected => {
                        // Not ours — but it may be another peer's concurrent
                        // punch. Requeue the id; the per-round `rejected`
                        // set keeps this adopt from challenging it again
                        // (no spin).
                        requeue_accept_id(&shared.accept_q, &shared.accept_cv, conn.id.0);
                        rejected.insert(conn.id.0);
                    }
                    BindOutcome::Retryable => still_pending.push(conn),
                }
            }
            if let Some(conn) = verified {
                return Some(conn);
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
        // Timeout: requeue retryable candidates instead of dropping them, so
        // a concurrent (or later) adopt for another peer can still find them.
        for conn in pending.drain(..) {
            requeue_accept_id(&shared.accept_q, &shared.accept_cv, conn.id.0);
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

/// Push a candidate connection id back onto the driver's accept-queue tail
/// and wake waiters.
///
/// Drained ids must never be silently dropped: `accept_q` is pop-only, so a
/// dropped id is invisible to every other in-flight adopt (WARN-1: A punching
/// B and C concurrently must not swallow C's direct connection).
fn requeue_accept_id(accept_q: &Mutex<VecDeque<u64>>, accept_cv: &Condvar, id: u64) {
    if let Ok(mut q) = accept_q.lock() {
        q.push_back(id);
    }
    accept_cv.notify_one();
}

/// Drain newly accepted connection ids into `pending`.
///
/// Ids this adopt already rejected (or already has pending) are REQUEUED,
/// never dropped, so a concurrent adopt for another peer can still find
/// them. Unknown or closed ids are consumed (dropped): they can never
/// verify for anyone.
fn drain_candidates(
    accept_q: &Mutex<VecDeque<u64>>,
    accept_cv: &Condvar,
    conns: &Mutex<HashMap<u64, Arc<ConnShared>>>,
    rejected: &HashSet<u64>,
    pending: &mut Vec<Arc<ConnShared>>,
) {
    let mut q = match accept_q.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let mut deferred = Vec::new();
    while let Some(id) = q.pop_front() {
        if rejected.contains(&id) || pending.iter().any(|c| c.id.0 == id) {
            // Seen this round already: put it back for other adopts
            // instead of swallowing it (WARN-1).
            deferred.push(id);
            continue;
        }
        let conn = conns.lock().ok().and_then(|m| m.get(&id).cloned());
        match conn {
            Some(c)
                if c.state
                    .lock()
                    .map(|st| st.closed.is_none())
                    .unwrap_or(false) =>
            {
                pending.push(c)
            }
            _ => {}
        }
    }
    let had_deferred = !deferred.is_empty();
    for id in deferred {
        q.push_back(id);
    }
    if had_deferred {
        accept_cv.notify_one();
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
    clock: Arc<dyn PunchClock>,
) -> PunchResult {
    let mgr = PunchManager::new(driver.clone(), my_id, clock);
    mgr.set_local(local, Vec::new());
    mgr.register_relay(relay_conn, peer);
    mgr.punch_peer(relay_conn, peer, remote_nat, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> Option<Arc<PunchManager>> {
        let driver = Driver::new_client().ok()?;
        Some(PunchManager::new(
            driver,
            FabricPeerId([7u8; 32]),
            Arc::new(SystemPunchClock::new()),
        ))
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

    /// WARN-1 Red: A punches B and C concurrently and loses both tie-breaks.
    /// B's adopt drains C's connection id (7) and rejects it (foreign nonce).
    /// The id must be REQUEUED — not dropped — so C's adopt can still find it.
    /// (Old code: the drain popped every id and silently dropped the ones it
    /// didn't adopt; C fell back to relay despite a healthy direct conn.)
    #[test]
    fn drain_requeues_rejected_ids_instead_of_dropping() {
        use std::sync::Condvar;
        let accept_q = Mutex::new(VecDeque::from([7u64, 9u64]));
        let accept_cv = Condvar::new();
        // No conns resolve: 9 is an unknown id (consumed); 7 was rejected
        // by this adopt round (foreign nonce) and must survive.
        let conns: Mutex<HashMap<u64, Arc<ConnShared>>> = Mutex::new(HashMap::new());
        let rejected = HashSet::from([7u64]);
        let mut pending = Vec::new();

        drain_candidates(&accept_q, &accept_cv, &conns, &rejected, &mut pending);

        let q = accept_q.lock().unwrap();
        assert!(
            q.contains(&7),
            "rejected candidate id must survive in accept_q for the other peer's adopt"
        );
        assert!(!q.contains(&9), "unknown ids are consumed");
        assert!(pending.is_empty());
    }

    /// WARN-1: requeueing wakes a waiter, so the other peer's adopt need not
    /// burn its whole deadline before noticing the returned candidate.
    #[test]
    fn requeue_accept_id_pushes_back_and_notifies() {
        use std::sync::Condvar;
        let accept_q = Mutex::new(VecDeque::new());
        let accept_cv = Condvar::new();
        requeue_accept_id(&accept_q, &accept_cv, 42);
        let q = accept_q.lock().unwrap();
        assert_eq!(q.iter().collect::<Vec<_>>(), [&42u64]);
    }

    /// WARN-2 Red: the D5 demux routing table. A non-punch stream must be
    /// stashed to unclaimed (bytes untouched) — never consumed as an offer;
    /// punch streams go to the offer handler; idle streams are pushed back
    /// so a slow writer isn't killed; dead streams are dropped.
    #[test]
    fn inbound_routing_table() {
        // Punch signaling -> offer handler.
        assert_eq!(route_inbound(&Ok(STREAM_TYPE_PUNCH)), InboundRoute::Punch);
        // Non-punch (e.g. transfer) -> stashed unclaimed, bytes intact.
        assert_eq!(route_inbound(&Ok(0x7F)), InboundRoute::StashUnclaimed(0x7F));
        assert_eq!(
            route_inbound(&Ok(STREAM_TYPE_BIND)),
            InboundRoute::StashUnclaimed(STREAM_TYPE_BIND)
        );
        // Idle stream (peek timed out, no bytes yet) -> push back.
        assert_eq!(
            route_inbound(&Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peek timeout"
            ))),
            InboundRoute::PushBack
        );
        // Dead stream (EOF / error) -> drop.
        assert_eq!(
            route_inbound(&Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed"))),
            InboundRoute::Drop
        );
        assert_eq!(
            route_inbound(&Err(io::Error::other("broken"))),
            InboundRoute::Drop
        );
    }
}
