//! Production peer sources for NAT relay triggering.
//!
//! The feed merges the three peer sources the node actually has — the static
//! `[[peers]]` table, discovery results (paired/LSA/mDNS through the single
//! [`DiscoveryHub`]) and the live N1 sessions — then keeps a per-peer relay
//! subscription and drives the relay trigger state machine.
//!
//! Design contract (spec §4.4):
//! - one owner, one calling thread: [`PeerSourceFeed`] is held **by value** by
//!   `NatSwitchRuntime` and `tick`/`shutdown` are only ever called from the NAT
//!   worker thread (the `&mut self` receiver plus non-`Arc` ownership makes a
//!   second caller impossible at compile time);
//! - no field locks: every mutable field below is worker-exclusive; only the
//!   published status snapshot is shared (its own `Mutex`) and is written once
//!   per tick, so readers never observe a torn combination;
//! - discovery returns `(PeerId, candidate addr)` only — the feed never dials a
//!   discovered address; triggers use the address book exclusively.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime};

use nexus_discovery::{DiscoverySource, hub::DiscoveryHub};
use nexus_fabric::PeerId as FabricPeerId;
use nexus_network::n1::N1PeerId;
use nexus_network::n1::session::N1SessionManager;

use crate::nat_relay::{RelayAddressBook, RelayError, RelaySubscriptionGuard, RelayTrigger};
use crate::nat_switch::NatSwitching;

/// `hex8`: first four bytes of the peer id (peer-source log correlation).
fn hex8(peer: &[u8; 32]) -> String {
    peer.iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn hex64(peer: &[u8; 32]) -> String {
    peer.iter().map(|b| format!("{b:02x}")).collect()
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Which sources currently know a peer (spec §4.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerSources {
    /// Present in the static `[[peers]]` table.
    pub static_cfg: bool,
    /// Present in the paired discovery source.
    pub paired: bool,
    /// Present in the LSA source (inside the freshness window).
    pub lsa: bool,
    /// Present in the mDNS cache.
    pub mdns: bool,
    /// Present in the live N1 session table.
    pub n1: bool,
}

impl PeerSources {
    /// A peer with no source left must be unsubscribed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !(self.static_cfg || self.paired || self.lsa || self.mdns || self.n1)
    }

    /// Source labels in the frozen order `paired,static,lsa,mdns,n1`
    /// (only true entries, comma separated).
    #[must_use]
    pub fn labels(&self) -> String {
        let mut out: Vec<&'static str> = Vec::new();
        if self.paired {
            out.push("paired");
        }
        if self.static_cfg {
            out.push("static");
        }
        if self.lsa {
            out.push("lsa");
        }
        if self.mdns {
            out.push("mdns");
        }
        if self.n1 {
            out.push("n1");
        }
        out.join(",")
    }
}

/// Strict discovery-id parse: exactly 64 chars, every char `0-9a-f`.
///
/// No trimming, no case folding, and none of the lenient parsers already in
/// the tree (`parse_hex32` accepts `A-F`; `N1PeerId::from_hex` accepts mixed
/// case). Static and N1 ids are `[u8; 32]` already and never take this path.
#[must_use]
pub fn parse_fabric_peer_hex(s: &str) -> Option<nexus_fabric::PeerId> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(nexus_fabric::PeerId(out))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Trigger timings and limits (spec §4.4.3, frozen values).
#[derive(Debug, Clone)]
pub struct PeerSourceConfig {
    /// Tick interval (worker calls `tick` at most this often).
    pub feed_interval: Duration,
    /// Address-book reload interval.
    pub book_poll_interval: Duration,
    /// Consecutive failures before `Parked{MaxFailures}`.
    pub trigger_max_failures: u32,
    /// Backoff after the 1st/2nd/3rd failure.
    pub trigger_backoff: [Duration; 3],
    /// In-flight trigger deadline.
    pub trigger_inflight_timeout: Duration,
}

impl Default for PeerSourceConfig {
    fn default() -> Self {
        Self {
            feed_interval: Duration::from_millis(1000),
            book_poll_interval: Duration::from_millis(5000),
            trigger_max_failures: 3,
            trigger_backoff: [
                Duration::from_millis(1000),
                Duration::from_millis(2000),
                Duration::from_millis(4000),
            ],
            trigger_inflight_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_frozen_order() {
        let mut s = PeerSources::default();
        assert!(s.is_empty());
        assert_eq!(s.labels(), "");
        s.mdns = true;
        s.static_cfg = true;
        s.paired = true;
        s.lsa = true;
        s.n1 = true;
        assert!(!s.is_empty());
        assert_eq!(s.labels(), "paired,static,lsa,mdns,n1");
    }

    #[test]
    fn parse_rejects_non_canonical_ids() {
        let good = "ab".repeat(32);
        let peer = parse_fabric_peer_hex(&good).expect("canonical id");
        assert_eq!(peer.0, [0xabu8; 32]);

        // Wrong length.
        assert!(parse_fabric_peer_hex(&"ab".repeat(31)).is_none());
        assert!(parse_fabric_peer_hex(&"ab".repeat(33)).is_none());
        // Uppercase is not canonical (no case folding).
        assert!(parse_fabric_peer_hex(&"AB".repeat(32)).is_none());
        // Mixed case.
        let mut mixed = "ab".repeat(32);
        mixed.replace_range(0..1, "A");
        assert!(parse_fabric_peer_hex(&mixed).is_none());
        // Non-hex.
        assert!(parse_fabric_peer_hex(&"zz".repeat(32)).is_none());
        // Whitespace is not trimmed.
        assert!(parse_fabric_peer_hex(&format!(" {} ", good)).is_none());
    }

    #[test]
    fn config_defaults_are_frozen() {
        let cfg = PeerSourceConfig::default();
        assert_eq!(cfg.feed_interval, Duration::from_millis(1000));
        assert_eq!(cfg.book_poll_interval, Duration::from_millis(5000));
        assert_eq!(cfg.trigger_max_failures, 3);
        assert_eq!(
            cfg.trigger_backoff,
            [
                Duration::from_millis(1000),
                Duration::from_millis(2000),
                Duration::from_millis(4000)
            ]
        );
        assert_eq!(cfg.trigger_inflight_timeout, Duration::from_secs(30));
    }
}

/// Published peer-source state (`peer_source` block of the NAT snapshot).
pub struct PeerSourceStatus {
    inner: std::sync::Mutex<PeerSourceStatusSnapshot>,
}

impl Default for PeerSourceStatus {
    fn default() -> Self {
        Self {
            inner: std::sync::Mutex::new(PeerSourceStatusSnapshot {
                state: "disabled:no-turn",
                ..PeerSourceStatusSnapshot::default()
            }),
        }
    }
}

impl PeerSourceStatus {
    /// Current snapshot (complete per-tick view).
    #[must_use]
    pub fn snapshot(&self) -> PeerSourceStatusSnapshot {
        self.inner
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    /// Publish the state string (one of the six frozen values).
    pub fn set_state(&self, state: &'static str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.state = state;
        g.enabled = state == "running";
    }

    /// Record a book reload failure. `last_error` is the frozen enum value
    /// `"book-reload-failed"`; `msg` is only logged (empty = already logged by
    /// the caller's throttle).
    pub fn note_book_error(&self, msg: String) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.last_error = Some("book-reload-failed".to_string());
        drop(g);
        if !msg.is_empty() {
            eprintln!("{msg}");
        }
    }

    /// Record a successful reload. Only the timestamp changes; `last_error`
    /// keeps the most recent failure code (spec §4.12.1).
    pub fn note_book_success(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.book_last_success_ms = wall_ms();
    }

    /// Replace the snapshot (worker is the only writer, once per tick).
    pub(crate) fn publish(&self, snapshot: PeerSourceStatusSnapshot) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = snapshot;
    }
}

/// Typed peer-source failures (spec §5.2; frozen variant set).
#[derive(Debug)]
pub enum PeerSourceError {
    InvalidPeerId {
        source: DiscoverySource,
        raw: String,
    },
    SubscribeRefused {
        peer: FabricPeerId,
    },
    Trigger(RelayError),
    TriggerTimeout {
        peer: FabricPeerId,
        elapsed_ms: u64,
    },
    Book(std::io::Error),
    Capacity {
        requested: FabricPeerId,
        holder: Option<FabricPeerId>,
    },
}

impl std::fmt::Display for PeerSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerSourceError::InvalidPeerId { source, raw } => write!(
                f,
                "invalid peer id source={} value={} (ignored)",
                source.as_str(),
                raw
            ),
            PeerSourceError::SubscribeRefused { peer } => write!(
                f,
                "subscribe refused peer={} reason=no-provider",
                hex8(&peer.0)
            ),
            PeerSourceError::Trigger(e) => write!(f, "trigger failed: {e}"),
            PeerSourceError::TriggerTimeout { peer, elapsed_ms } => write!(
                f,
                "trigger timed out peer={} after {elapsed_ms}ms",
                hex8(&peer.0)
            ),
            PeerSourceError::Book(e) => write!(f, "book: {e}"),
            PeerSourceError::Capacity { requested, holder } => write!(
                f,
                "capacity: requested={} holder={}",
                hex8(&requested.0),
                holder
                    .map(|h| hex8(&h.0))
                    .unwrap_or_else(|| "none".to_string())
            ),
        }
    }
}

impl std::error::Error for PeerSourceError {}

/// Published counters/gauges (spec §6.4, 19 fields).
#[derive(Debug, Clone, Default)]
pub struct PeerSourceStatusSnapshot {
    pub enabled: bool,
    pub state: &'static str,
    pub subscribed_peers: usize,
    pub sources_static: usize,
    pub sources_paired: usize,
    pub sources_lsa: usize,
    pub sources_mdns: usize,
    pub sources_n1: usize,
    pub invalid_peer_id_total: u64,
    pub subscribe_refused_total: u64,
    pub trigger_attempts_total: u64,
    pub trigger_ok_total: u64,
    pub trigger_fail_total: u64,
    pub trigger_capacity_parked_total: u64,
    pub trigger_parked_peers: usize,
    pub trigger_inflight_peers: usize,
    pub book_reloads_total: u64,
    pub book_errors_total: u64,
    pub book_last_success_ms: u64,
    pub last_error: Option<String>,
}

/// Inputs of the frozen six-row state table (§4.11.1).
///
/// Wiring helper shared by `main.rs` and the `nat_status` tests: the judgment
/// order lives in exactly one place (OQ-3 ruling (a)); this is not a product
/// API.
#[derive(Debug, Clone, Copy)]
pub struct PeerSourceStateInputs {
    /// `[network.discovery].enabled`.
    pub enabled: bool,
    /// `[network.discovery].feed`.
    pub feed: bool,
    /// A `NatSwitching` stack exists (turn section enabled).
    pub has_nat_switch: bool,
    /// A relay provider is attached.
    pub has_provider: bool,
    /// A discovery hub exists.
    pub has_hub: bool,
    /// N1 sessions exist.
    pub has_sessions: bool,
}

/// First matching row of §4.11.1 wins (CR-3).
#[must_use]
pub fn decide_state(inputs: PeerSourceStateInputs) -> &'static str {
    if !inputs.enabled || !inputs.feed {
        return "disabled:config";
    }
    if !inputs.has_nat_switch {
        return "disabled:no-turn";
    }
    if !inputs.has_provider {
        return "disabled:no-provider";
    }
    if !inputs.has_hub {
        return "disabled:no-discovery";
    }
    if !inputs.has_sessions {
        return "disabled:no-sessions";
    }
    "running"
}

/// Internal per-peer trigger state.
#[derive(Debug)]
struct PeerTrigger {
    /// Arbitration key: tick sequence at subscription time (shared by peers
    /// subscribed in the same tick).
    subscribed_tick: u64,
    /// Last observed source set (change detection for re-arming).
    sources: PeerSources,
    state: TriggerState,
}

#[derive(Debug)]
enum TriggerState {
    Idle {
        last_addr: Option<SocketAddr>,
        failures: u32,
        next_attempt_at: Instant,
    },
    InFlight {
        addr: SocketAddr,
        started_at: Instant,
        attempt: u32,
        failures_before: u32,
    },
    Parked {
        reason: ParkReason,
        failures: u32,
        last_addr: Option<SocketAddr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParkReason {
    MaxFailures,
    Capacity,
}

enum TriggerReport {
    Ok {
        peer: FabricPeerId,
        addr: SocketAddr,
        elapsed_ms: u64,
    },
    Err {
        peer: FabricPeerId,
        addr: SocketAddr,
        error: RelayError,
    },
}

/// Worker-private counters (published once per tick).
#[derive(Debug, Default)]
struct Counters {
    invalid_peer_id_total: u64,
    subscribe_refused_total: u64,
    trigger_attempts_total: u64,
    trigger_ok_total: u64,
    trigger_fail_total: u64,
    trigger_capacity_parked_total: u64,
    book_reloads_total: u64,
    book_errors_total: u64,
}

/// Peer-source feed: merge, subscribe, book poll, trigger state machine.
///
/// Ownership: held **by value** by `NatSwitchRuntime`; `tick`/`shutdown` run
/// only on the `nexusd-nat-switch` worker thread. Never put this in an `Arc`.
pub struct PeerSourceFeed {
    sw: Arc<NatSwitching>,
    provider: Arc<dyn RelayTrigger>,
    book: Arc<dyn RelayAddressBook>,
    sessions: Arc<N1SessionManager>,
    /// Static ids fixed at construction (add/remove needs a daemon restart).
    static_peers: Vec<N1PeerId>,
    hub: Arc<DiscoveryHub>,
    self_id: FabricPeerId,
    cfg: PeerSourceConfig,
    status: Arc<PeerSourceStatus>,
    stop: Arc<AtomicBool>,
    guards: HashMap<FabricPeerId, RelaySubscriptionGuard>,
    triggers: HashMap<FabricPeerId, PeerTrigger>,
    counters: Counters,
    tick_seq: u64,
    last_book_poll: Instant,
    /// Only discovery-layer string ids are validated here (static/N1 ids are
    /// `[u8; 32]` and cannot be non-canonical).
    invalid_seen: HashSet<(DiscoverySource, String)>,
    last_subscribe_warn: HashMap<FabricPeerId, Instant>,
    last_book_warn: Option<Instant>,
    trigger_tx: Sender<TriggerReport>,
    trigger_rx: Receiver<TriggerReport>,
}

impl PeerSourceFeed {
    /// Build the feed. Every dependency is non-optional by type: the runtime
    /// only constructs a feed after deciding the state is `"running"`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sw: Arc<NatSwitching>,
        provider: Arc<dyn RelayTrigger>,
        book: Arc<dyn RelayAddressBook>,
        sessions: Arc<N1SessionManager>,
        static_peers: Vec<N1PeerId>,
        hub: Arc<DiscoveryHub>,
        self_id: FabricPeerId,
        cfg: PeerSourceConfig,
        status: Arc<PeerSourceStatus>,
        stop: Arc<AtomicBool>,
    ) -> Self {
        let (trigger_tx, trigger_rx) = mpsc::channel();
        let last_book_poll = Instant::now()
            .checked_sub(cfg.book_poll_interval)
            .unwrap_or_else(Instant::now);
        Self {
            sw,
            provider,
            book,
            sessions,
            static_peers,
            hub,
            self_id,
            cfg,
            status,
            stop,
            guards: HashMap::new(),
            triggers: HashMap::new(),
            counters: Counters::default(),
            tick_seq: 0,
            last_book_poll,
            invalid_seen: HashSet::new(),
            last_subscribe_warn: HashMap::new(),
            last_book_warn: None,
            trigger_tx,
            trigger_rx,
        }
    }

    /// One feed tick (steps 1–9 of spec §4.4.2).
    pub fn tick(&mut self, now: Instant) {
        self.tick_seq += 1;
        if self.stop.load(Ordering::SeqCst) {
            return;
        }
        let sources = self.merge_sources(now);
        let changed = self.reconcile(&sources, now);
        self.poll_book(now);
        self.drain_reports(now);
        self.expire_inflight(now);
        self.arbitrate_and_trigger(now, &changed);
        self.publish_status();
    }

    /// Idempotent teardown: drop every guard (unsubscribe -> zero-sink slot
    /// release), forget the triggers and park the status on `disabled:config`.
    pub fn shutdown(&mut self) {
        self.guards.clear();
        self.triggers.clear();
        self.status.set_state("disabled:config");
    }

    // ---------- step 3: merge ----------

    fn merge_sources(&mut self, now: Instant) -> HashMap<FabricPeerId, PeerSources> {
        let mut sources: HashMap<FabricPeerId, PeerSources> = HashMap::new();
        let static_ids: HashSet<[u8; 32]> = self.static_peers.iter().map(|p| p.0).collect();
        for id in &self.static_peers {
            sources.entry(FabricPeerId(id.0)).or_default().static_cfg = true;
        }
        for (peer, found) in self.hub.peer_source_map(now) {
            // Static wins: a discovery duplicate of a static id stays a single
            // static label (spec §4.2).
            if let Some(id) = parse_fabric_peer_hex(&peer.0) {
                if static_ids.contains(&id.0) {
                    continue;
                }
                let entry = sources.entry(id).or_default();
                for source in found {
                    match source {
                        DiscoverySource::Paired => entry.paired = true,
                        DiscoverySource::Static => entry.static_cfg = true,
                        DiscoverySource::Lsa => entry.lsa = true,
                        DiscoverySource::Mdns => entry.mdns = true,
                    }
                }
            } else {
                for source in found {
                    self.note_invalid(source, &peer.0);
                }
            }
        }
        for id in self.sessions.peers() {
            sources.entry(FabricPeerId(id.0)).or_default().n1 = true;
        }
        sources.remove(&self.self_id);
        sources
    }

    fn note_invalid(&mut self, source: DiscoverySource, raw: &str) {
        if !self.invalid_seen.insert((source, raw.to_string())) {
            return;
        }
        self.counters.invalid_peer_id_total += 1;
        let err = PeerSourceError::InvalidPeerId {
            source,
            raw: raw.to_string(),
        };
        eprintln!("[peer-source] WARN: {err}");
    }

    // ---------- step 4: reconcile ----------

    fn reconcile(
        &mut self,
        sources: &HashMap<FabricPeerId, PeerSources>,
        now: Instant,
    ) -> HashSet<FabricPeerId> {
        let mut changed = HashSet::new();
        let mut all: Vec<FabricPeerId> = sources
            .keys()
            .copied()
            .chain(self.triggers.keys().copied())
            .collect();
        all.sort_by_key(|a| a.0);
        all.dedup();
        for peer in all {
            let new = sources.get(&peer).copied().unwrap_or_default();
            let known = self.triggers.contains_key(&peer);
            match (known, new.is_empty()) {
                (false, false) => self.subscribe(peer, new, now),
                (false, true) => {}
                (true, true) => {
                    // Dropping the guard unsubscribes; the provider releases the
                    // relay slot when the last sink is gone.
                    self.guards.remove(&peer);
                    self.triggers.remove(&peer);
                    eprintln!(
                        "[peer-source] unsubscribed peer={} reason=no-sources",
                        hex8(&peer.0)
                    );
                }
                (true, false) => {
                    let Some(trigger) = self.triggers.get_mut(&peer) else {
                        continue;
                    };
                    if trigger.sources != new {
                        trigger.sources = new;
                        changed.insert(peer);
                    }
                }
            }
        }
        changed
    }

    fn subscribe(&mut self, peer: FabricPeerId, sources: PeerSources, now: Instant) {
        match self.sw.subscribe_relay_peer(peer) {
            Some(guard) => {
                self.guards.insert(peer, guard);
                self.triggers.insert(
                    peer,
                    PeerTrigger {
                        subscribed_tick: self.tick_seq,
                        sources,
                        state: TriggerState::Idle {
                            last_addr: None,
                            failures: 0,
                            next_attempt_at: now,
                        },
                    },
                );
                let addrs = self
                    .hub
                    .resolve(&nexus_discovery::PeerId(hex64(&peer.0)), now)
                    .len();
                eprintln!(
                    "[peer-source] subscribed peer={} sources={} addrs={addrs}",
                    hex8(&peer.0),
                    sources.labels()
                );
            }
            None => {
                self.counters.subscribe_refused_total += 1;
                let due = self
                    .last_subscribe_warn
                    .get(&peer)
                    .map(|at| now.saturating_duration_since(*at) >= Duration::from_secs(60))
                    .unwrap_or(true);
                if due {
                    self.last_subscribe_warn.insert(peer, now);
                    let err = PeerSourceError::SubscribeRefused { peer };
                    eprintln!("[peer-source] WARN: {err}");
                }
            }
        }
    }

    // ---------- step 5: book poll ----------

    fn poll_book(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_book_poll) < self.cfg.book_poll_interval {
            return;
        }
        self.last_book_poll = now;
        match self.book.reload() {
            Ok(()) => {
                self.counters.book_reloads_total += 1;
                self.status.note_book_success();
            }
            Err(e) => {
                self.counters.book_errors_total += 1;
                // Keep the previous entries; log (60s throttled) and publish the
                // frozen `last_error` code.
                let due = self
                    .last_book_warn
                    .map(|at| now.saturating_duration_since(at) >= Duration::from_secs(60))
                    .unwrap_or(true);
                let msg = if due {
                    self.last_book_warn = Some(now);
                    format!(
                        "[peer-source] WARN: book reload failed: {e} (keeping previous entries)"
                    )
                } else {
                    String::new()
                };
                self.status.note_book_error(msg);
            }
        }
    }

    // ---------- step 6: drain reports ----------

    fn drain_reports(&mut self, now: Instant) {
        while let Ok(report) = self.trigger_rx.try_recv() {
            match report {
                TriggerReport::Ok {
                    peer,
                    addr,
                    elapsed_ms,
                } => {
                    if !self.inflight_matches(&peer, &addr) {
                        continue; // late report: count nothing, keep state
                    }
                    self.counters.trigger_ok_total += 1;
                    if let Some(t) = self.triggers.get_mut(&peer) {
                        t.state = TriggerState::Idle {
                            last_addr: Some(addr),
                            failures: 0,
                            next_attempt_at: now,
                        };
                    }
                    eprintln!(
                        "[peer-source] trigger ok peer={} relayed={addr} elapsed_ms={elapsed_ms}",
                        hex8(&peer.0)
                    );
                }
                TriggerReport::Err { peer, addr, error } => {
                    if !self.inflight_matches(&peer, &addr) {
                        continue;
                    }
                    self.counters.trigger_fail_total += 1;
                    let (failures_before, started_at) = self
                        .triggers
                        .get(&peer)
                        .and_then(|t| match &t.state {
                            TriggerState::InFlight {
                                started_at,
                                failures_before,
                                ..
                            } => Some((*failures_before, *started_at)),
                            _ => None,
                        })
                        .unwrap_or((0, now));
                    let elapsed_ms = now.saturating_duration_since(started_at).as_millis() as u64;
                    let attempt = failures_before + 1;
                    self.apply_failure(peer, addr, failures_before, now);
                    eprintln!(
                        "[peer-source] WARN: trigger failed peer={} relayed={addr} \
                         attempt={attempt} error={} detail={} elapsed_ms={elapsed_ms}",
                        hex8(&peer.0),
                        error.category(),
                        error
                    );
                }
            }
        }
    }

    fn inflight_matches(&self, peer: &FabricPeerId, addr: &SocketAddr) -> bool {
        matches!(
            self.triggers.get(peer).map(|t| &t.state),
            Some(TriggerState::InFlight { addr: current, .. }) if current == addr
        )
    }

    /// Failure transition shared by reports and the in-flight timeout.
    fn apply_failure(
        &mut self,
        peer: FabricPeerId,
        addr: SocketAddr,
        failures_before: u32,
        now: Instant,
    ) {
        let Some(trigger) = self.triggers.get_mut(&peer) else {
            return;
        };
        let failures = failures_before + 1;
        if failures >= self.cfg.trigger_max_failures {
            trigger.state = TriggerState::Parked {
                reason: ParkReason::MaxFailures,
                failures,
                last_addr: Some(addr),
            };
            eprintln!(
                "[peer-source] WARN: trigger parked peer={} failures={failures} reason=max-failures",
                hex8(&peer.0)
            );
        } else {
            let idx = (failures.saturating_sub(1) as usize).min(self.cfg.trigger_backoff.len() - 1);
            trigger.state = TriggerState::Idle {
                last_addr: Some(addr),
                failures,
                next_attempt_at: now + self.cfg.trigger_backoff[idx],
            };
        }
    }

    // ---------- step 7: in-flight timeout ----------

    fn expire_inflight(&mut self, now: Instant) {
        let expired: Vec<(FabricPeerId, SocketAddr, u32, u32, u64)> = self
            .triggers
            .iter()
            .filter_map(|(peer, t)| match &t.state {
                TriggerState::InFlight {
                    addr,
                    started_at,
                    attempt,
                    failures_before,
                } if now.saturating_duration_since(*started_at)
                    >= self.cfg.trigger_inflight_timeout =>
                {
                    Some((
                        *peer,
                        *addr,
                        *attempt,
                        *failures_before,
                        now.saturating_duration_since(*started_at).as_millis() as u64,
                    ))
                }
                _ => None,
            })
            .collect();
        for (peer, addr, attempt, failures_before, elapsed_ms) in expired {
            self.counters.trigger_fail_total += 1;
            self.apply_failure(peer, addr, failures_before, now);
            eprintln!(
                "[peer-source] WARN: trigger failed peer={} relayed={addr} attempt={attempt} \
                 error=timeout detail=inflight-timeout elapsed_ms={elapsed_ms}",
                hex8(&peer.0)
            );
        }
    }

    // ---------- step 8: arbitration + trigger ----------

    fn arbitrate_and_trigger(&mut self, now: Instant, changed: &HashSet<FabricPeerId>) {
        let ordered: Vec<FabricPeerId> = self.ordered_triggers();
        let established = self.provider.established_peer_ids();
        let mut any_inflight = self
            .triggers
            .values()
            .any(|t| matches!(t.state, TriggerState::InFlight { .. }));
        let mut spawned = false;
        for peer in ordered {
            let Some(trigger) = self.triggers.get_mut(&peer) else {
                continue;
            };
            let Some(desired) = self.book.relay_addr(&peer.0) else {
                continue;
            };
            if let Some(established_addr) = self.provider.established_relay_addr(&peer) {
                if established_addr == desired {
                    // Already established at the desired address: no trigger.
                    // Only normalise the state when it is not already synced.
                    let synced = matches!(
                        &trigger.state,
                        TriggerState::Idle {
                            last_addr: Some(prev),
                            failures: 0,
                            ..
                        } if *prev == desired
                    );
                    if !synced {
                        trigger.state = TriggerState::Idle {
                            last_addr: Some(desired),
                            failures: 0,
                            next_attempt_at: now,
                        };
                    }
                    continue;
                }
            }
            if matches!(trigger.state, TriggerState::InFlight { .. }) {
                continue;
            }
            let current_failures = match &trigger.state {
                TriggerState::Idle { failures, .. } | TriggerState::Parked { failures, .. } => {
                    *failures
                }
                TriggerState::InFlight { .. } => continue,
            };
            // Parked{MaxFailures} re-arms on exactly two conditions (the third,
            // capacity release, only applies to Parked{Capacity} below).
            if let TriggerState::Parked {
                reason: ParkReason::MaxFailures,
                last_addr,
                ..
            } = &trigger.state
            {
                let addr_changed = last_addr.map(|a| a != desired).unwrap_or(false);
                let sources_changed = changed.contains(&peer);
                if !addr_changed && !sources_changed {
                    continue;
                }
                let reason = if addr_changed {
                    "book-change"
                } else {
                    "peer-set-change"
                };
                eprintln!(
                    "[peer-source] trigger re-armed peer={} reason={reason}",
                    hex8(&peer.0)
                );
                trigger.state = TriggerState::Idle {
                    last_addr: Some(desired),
                    failures: 0,
                    next_attempt_at: now,
                };
            }
            if let TriggerState::Idle {
                next_attempt_at, ..
            } = &trigger.state
            {
                if now < *next_attempt_at {
                    continue;
                }
            }
            let slot_free = match established.as_slice() {
                [] => true,
                [holder] if *holder == peer => true,
                _ => false,
            };
            if !slot_free || any_inflight || spawned {
                if !matches!(
                    trigger.state,
                    TriggerState::Parked {
                        reason: ParkReason::Capacity,
                        ..
                    }
                ) {
                    trigger.state = TriggerState::Parked {
                        reason: ParkReason::Capacity,
                        failures: current_failures,
                        last_addr: Some(desired),
                    };
                    self.counters.trigger_capacity_parked_total += 1;
                    eprintln!(
                        "[peer-source] WARN: trigger parked peer={} failures={current_failures} reason=capacity",
                        hex8(&peer.0)
                    );
                }
                continue;
            }
            if matches!(
                trigger.state,
                TriggerState::Parked {
                    reason: ParkReason::Capacity,
                    ..
                }
            ) {
                eprintln!(
                    "[peer-source] trigger re-armed peer={} reason=capacity-free",
                    hex8(&peer.0)
                );
                trigger.state = TriggerState::Idle {
                    last_addr: Some(desired),
                    failures: 0,
                    next_attempt_at: now,
                };
            }
            let attempt = current_failures + 1;
            trigger.state = TriggerState::InFlight {
                addr: desired,
                started_at: now,
                attempt,
                failures_before: current_failures,
            };
            self.counters.trigger_attempts_total += 1;
            eprintln!(
                "[peer-source] trigger peer={} relayed={desired} attempt={attempt}",
                hex8(&peer.0)
            );
            self.spawn_trigger(peer, desired);
            any_inflight = true;
            spawned = true;
        }
    }

    /// Arbitration order: subscription tick first, then PeerId hex ascending.
    fn ordered_triggers(&self) -> Vec<FabricPeerId> {
        let mut peers: Vec<FabricPeerId> = self.triggers.keys().copied().collect();
        peers.sort_by(|a, b| {
            let ta = self.triggers.get(a).map(|t| t.subscribed_tick).unwrap_or(0);
            let tb = self.triggers.get(b).map(|t| t.subscribed_tick).unwrap_or(0);
            ta.cmp(&tb).then_with(|| a.0.cmp(&b.0))
        });
        peers
    }

    fn spawn_trigger(&self, peer: FabricPeerId, desired: SocketAddr) {
        let provider = Arc::clone(&self.provider);
        let tx = self.trigger_tx.clone();
        let name = format!("nat-trigger-{}", hex8(&peer.0));
        let spawned = std::thread::Builder::new().name(name).spawn(move || {
            let started = Instant::now();
            let report = match provider.trigger_relay(peer, desired) {
                Ok(addr) => TriggerReport::Ok {
                    peer,
                    addr,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                },
                Err(error) => TriggerReport::Err {
                    peer,
                    addr: desired,
                    error,
                },
            };
            // A closed channel means the feed is gone: end silently.
            let _ = tx.send(report);
        });
        if let Err(e) = spawned {
            // The state machine's in-flight timeout bounds the damage.
            eprintln!(
                "[peer-source] WARN: trigger thread spawn failed ({}); peer={} relayed={desired}",
                e,
                hex8(&peer.0)
            );
        }
    }

    // ---------- step 9: publish ----------

    fn publish_status(&self) {
        let mut snap = self.status.snapshot();
        snap.enabled = true;
        snap.subscribed_peers = self.guards.len();
        let mut stat = 0;
        let mut paired = 0;
        let mut lsa = 0;
        let mut mdns = 0;
        let mut n1 = 0;
        let mut parked = 0;
        let mut inflight = 0;
        for trigger in self.triggers.values() {
            if trigger.sources.static_cfg {
                stat += 1;
            }
            if trigger.sources.paired {
                paired += 1;
            }
            if trigger.sources.lsa {
                lsa += 1;
            }
            if trigger.sources.mdns {
                mdns += 1;
            }
            if trigger.sources.n1 {
                n1 += 1;
            }
            match trigger.state {
                TriggerState::Parked { .. } => parked += 1,
                TriggerState::InFlight { .. } => inflight += 1,
                TriggerState::Idle { .. } => {}
            }
        }
        snap.sources_static = stat;
        snap.sources_paired = paired;
        snap.sources_lsa = lsa;
        snap.sources_mdns = mdns;
        snap.sources_n1 = n1;
        snap.trigger_parked_peers = parked;
        snap.trigger_inflight_peers = inflight;
        snap.invalid_peer_id_total = self.counters.invalid_peer_id_total;
        snap.subscribe_refused_total = self.counters.subscribe_refused_total;
        snap.trigger_attempts_total = self.counters.trigger_attempts_total;
        snap.trigger_ok_total = self.counters.trigger_ok_total;
        snap.trigger_fail_total = self.counters.trigger_fail_total;
        snap.trigger_capacity_parked_total = self.counters.trigger_capacity_parked_total;
        snap.book_reloads_total = self.counters.book_reloads_total;
        snap.book_errors_total = self.counters.book_errors_total;
        self.status.publish(snap);
    }
}
