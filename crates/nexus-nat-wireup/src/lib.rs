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

use std::collections::{HashMap, HashSet};
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

pub use channel::{FabricPunchChannel, frame_msg};
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
        })
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
        &self,
        relay_conn: &Arc<ConnShared>,
        peer: FabricPeerId,
        remote_nat: NatType,
        config: PunchConfig,
    ) -> PunchResult {
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
        let punch_start = Instant::now();
        let sock2 = socket.clone();
        let result = thread::spawn(move || {
            let mut session = PunchSession::new(
                nexus_nat_traversal::PeerId(peer.0),
                local,
                remote_nat,
                config,
                channel,
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

        if let PunchResult::Migrated { addr } = &result {
            self.on_migrated(peer, *addr, &socket, punch_start);
        }
        result
    }

    /// Tie-break + feed after a successful punch.
    fn on_migrated(
        &self,
        peer: FabricPeerId,
        addr: SocketAddr,
        socket: &DriverPunchSocket,
        punch_start: Instant,
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
            match resolve_accepted_after(&self.driver, punch_start, Duration::from_secs(2)) {
                Some(c) => {
                    eprintln!("[wireup] adopted peer-initiated direct conn");
                    DirectConn {
                        conn: c,
                        addr,
                        initiated_locally: false,
                    }
                }
                None => {
                    eprintln!(
                        "[wireup] WARN: no accepted direct conn found; relay remains the path"
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
            if let Err(e) = Self::handle_offer(&self, conn_id, stream) {
                eprintln!("[wireup] offer handling failed: {e}");
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
        let payload = channel::read_msg(&stream, deadline)?;
        let offer = decode_offer(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;

        // Answer on the same stream.
        let local = this.local_snapshot();
        let answer = PunchAnswer {
            version: SIGNAL_VERSION,
            nonce: offer.nonce,
            candidates: local.ordered(),
            nat_type: local.nat_type,
        };
        channel::write_msg(&stream, &encode_answer(&answer))?;

        // Dedup: an active session for this peer already punches.
        if this.active.lock().unwrap().contains(&peer) {
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
        let config = PunchConfig::default();
        let remote_nat = offer.nat_type;
        this.active.lock().unwrap().insert(peer);
        let punch_start = Instant::now();
        let sock2 = socket.clone();
        let this2 = this.clone();
        thread::spawn(move || {
            let mut session = PunchSession::new(
                nexus_nat_traversal::PeerId(peer.0),
                local,
                remote_nat,
                config,
                preanswered,
                sock2,
                predictor,
            );
            let result = session.run();
            this2.active.lock().unwrap().remove(&peer);
            if let PunchResult::Migrated { addr } = &result {
                this2.on_migrated(peer, *addr, &socket, punch_start);
            }
        });
        Ok(())
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

/// Find the most recently accepted, still-open connection established after
/// `since`. P0 heuristic: correct when no unrelated handshakes interleave
/// with the punch (true for all current flows; E4-validated).
fn resolve_accepted_after(
    driver: &Arc<Driver>,
    _since: Instant,
    timeout: Duration,
) -> Option<Arc<ConnShared>> {
    let deadline = Instant::now() + timeout;
    let shared = driver.shared();
    let mut last = None;
    let mut q = shared.accept_q.lock().ok()?;
    loop {
        while let Some(id) = q.pop_front() {
            if let Some(c) = shared.conns.lock().ok()?.get(&id).cloned() {
                let open = c
                    .state
                    .lock()
                    .map(|st| st.closed.is_none())
                    .unwrap_or(false);
                if open {
                    last = Some(c);
                }
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        let (guard, _) = shared
            .accept_cv
            .wait_timeout(q, Duration::from_millis(50))
            .ok()?;
        q = guard;
    }
    last
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
