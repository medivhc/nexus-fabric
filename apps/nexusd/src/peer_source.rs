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
    /// Parked because the failure budget ran out (re-arms only on a book
    /// address or source-set change).
    pub trigger_parked_max_failures: usize,
    /// Parked because this provider already serves another peer.
    pub trigger_parked_capacity: usize,
    pub trigger_inflight_peers: usize,
    /// Entries visible in the relay address book (`None` = unknown/book double).
    pub book_entries: Option<usize>,
    /// Subscribed peers for which the book holds no relayed address yet. This
    /// is the observable reason a feed is silent while `trigger_attempts_total`
    /// stays 0 (product-review r1 MAJOR-2).
    pub subscribed_peers_without_book_addr: usize,
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
        // Poll immediately on the first tick: the provider already published
        // our address before the loop starts.
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
        let mut parked_max_failures = 0;
        let mut parked_capacity = 0;
        let mut inflight = 0;
        let mut without_book_addr = 0;
        for (peer, trigger) in &self.triggers {
            if self.book.relay_addr(&peer.0).is_none() {
                without_book_addr += 1;
            }
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
                TriggerState::Parked { reason, .. } => {
                    parked += 1;
                    match reason {
                        ParkReason::MaxFailures => parked_max_failures += 1,
                        ParkReason::Capacity => parked_capacity += 1,
                    }
                }
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
        snap.trigger_parked_max_failures = parked_max_failures;
        snap.trigger_parked_capacity = parked_capacity;
        snap.trigger_inflight_peers = inflight;
        snap.book_entries = self.book.entry_count();
        snap.subscribed_peers_without_book_addr = without_book_addr;
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

#[cfg(test)]
mod feed_tests {
    use super::*;
    use crate::nat_relay::RelayConnProvider;
    use nexus_discovery::PeerId as DiscoveryPeerId;
    use nexus_discovery::lsa::Lsa;
    use nexus_network::n1::{N1Connection, N1Error, N1KeepaliveStream};
    use std::sync::Mutex;

    fn hex_id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn peer(byte: u8) -> FabricPeerId {
        FabricPeerId([byte; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn now() -> Instant {
        Instant::now()
    }

    // ---------- fixtures ----------

    #[derive(Default)]
    struct FakeBook {
        entries: Mutex<HashMap<[u8; 32], SocketAddr>>,
        fail: AtomicBool,
        reloads: std::sync::atomic::AtomicU64,
    }

    impl FakeBook {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn set(&self, peer: FabricPeerId, addr: SocketAddr) {
            self.entries.lock().unwrap().insert(peer.0, addr);
        }
    }

    impl RelayAddressBook for FakeBook {
        fn relay_addr(&self, peer: &[u8; 32]) -> Option<SocketAddr> {
            self.entries.lock().unwrap().get(peer).copied()
        }

        fn entry_count(&self) -> Option<usize> {
            self.entries.lock().ok().map(|g| g.len())
        }

        fn reload(&self) -> std::io::Result<()> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fake book reload failure"));
            }
            self.reloads.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn publish(&self, peer: [u8; 32], addr: SocketAddr) -> std::io::Result<()> {
            self.entries.lock().unwrap().insert(peer, addr);
            Ok(())
        }
    }

    type SinkList = Vec<std::sync::Weak<dyn crate::nat_relay::RelayConnSink>>;
    type Gate = Arc<(Mutex<bool>, std::sync::Condvar)>;

    /// Fake relay that implements both faces the feed/runtime need.
    #[derive(Default)]
    struct FakeRelay {
        calls: Mutex<Vec<(FabricPeerId, SocketAddr)>>,
        established: Mutex<HashMap<[u8; 32], SocketAddr>>,
        sinks: Mutex<HashMap<[u8; 32], SinkList>>,
        fail: Mutex<Option<String>>,
        gate: Mutex<Option<Gate>>,
    }

    impl FakeRelay {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn calls(&self) -> Vec<(FabricPeerId, SocketAddr)> {
            self.calls.lock().unwrap().clone()
        }

        fn set_fail(&self, msg: Option<&str>) {
            *self.fail.lock().unwrap() = msg.map(str::to_string);
        }

        fn block(&self) -> Gate {
            let gate: Gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
            *self.gate.lock().unwrap() = Some(Arc::clone(&gate));
            gate
        }
    }

    impl RelayTrigger for FakeRelay {
        fn established_relay_addr(&self, peer: &FabricPeerId) -> Option<SocketAddr> {
            self.established.lock().unwrap().get(&peer.0).copied()
        }

        fn established_peer_ids(&self) -> Vec<FabricPeerId> {
            let mut out: Vec<FabricPeerId> = self
                .established
                .lock()
                .unwrap()
                .keys()
                .map(|k| FabricPeerId(*k))
                .collect();
            out.sort_by_key(|p| p.0);
            out
        }

        fn trigger_relay(
            &self,
            peer: FabricPeerId,
            peer_relayed: SocketAddr,
        ) -> Result<SocketAddr, RelayError> {
            self.calls.lock().unwrap().push((peer, peer_relayed));
            if let Some(gate) = self.gate.lock().unwrap().clone() {
                let (lock, cv) = &*gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = cv
                        .wait_timeout(released, Duration::from_millis(200))
                        .unwrap()
                        .0;
                }
            }
            if let Some(msg) = self.fail.lock().unwrap().clone() {
                return Err(RelayError::Turn(msg));
            }
            self.established
                .lock()
                .unwrap()
                .insert(peer.0, peer_relayed);
            Ok(peer_relayed)
        }
    }

    impl crate::nat_relay::RelayConnProvider for FakeRelay {
        fn subscribe(&self, peer: FabricPeerId, sink: Arc<dyn crate::nat_relay::RelayConnSink>) {
            self.sinks
                .lock()
                .unwrap()
                .entry(peer.0)
                .or_default()
                .push(Arc::downgrade(&sink));
        }

        fn unsubscribe(&self, peer: FabricPeerId, sink: &Arc<dyn crate::nat_relay::RelayConnSink>) {
            let live = {
                let mut g = self.sinks.lock().unwrap();
                let target = Arc::downgrade(sink);
                if let Some(list) = g.get_mut(&peer.0) {
                    list.retain(|w| !std::sync::Weak::ptr_eq(w, &target));
                }
                let live = g.get(&peer.0).map(|l| l.len()).unwrap_or(0);
                if live == 0 {
                    g.remove(&peer.0);
                }
                live
            };
            if live == 0 {
                // Simulate the provider's zero-sink teardown.
                self.established.lock().unwrap().remove(&peer.0);
            }
        }

        fn established_relay(&self, peer: &FabricPeerId) -> Option<crate::nat_relay::RelayConn> {
            let _ = peer;
            None
        }

        fn established_peers(&self) -> Vec<FabricPeerId> {
            Vec::new()
        }

        fn subscribed_peers(&self) -> Vec<FabricPeerId> {
            let mut out: Vec<FabricPeerId> = self
                .sinks
                .lock()
                .unwrap()
                .keys()
                .map(|k| FabricPeerId(*k))
                .collect();
            out.sort_by_key(|p| p.0);
            out
        }

        fn sink_count(&self, peer: &FabricPeerId) -> usize {
            self.sinks
                .lock()
                .unwrap()
                .get(&peer.0)
                .map(|l| l.iter().filter(|w| w.strong_count() > 0).count())
                .unwrap_or(0)
        }
    }

    struct MockConn(N1PeerId);

    impl N1Connection for MockConn {
        fn send_datagram(&self, _data: &[u8]) -> Result<(), N1Error> {
            Ok(())
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            Err(N1Error::Closed)
        }
        fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn rebind(&self) -> Result<(), N1Error> {
            Ok(())
        }
        fn connection_id(&self) -> u64 {
            1
        }
        fn peer(&self) -> N1PeerId {
            self.0
        }
        fn close(&self) {}
    }

    fn sessions_with(peers: &[N1PeerId]) -> Arc<N1SessionManager> {
        let text = format!(
            "peer_id = \"{}\"\n[vpi]\ninterface = \"nexus0\"\naddress = \"10.200.0.1\"\nmtu = 1200\n",
            hex_id(0xaa)
        );
        let (_cfg, mgr, _hub) = nexus::network::build_session_manager_with_discovery(
            &text,
            None,
            Arc::new(AtomicBool::new(false)),
            nexus::network::DiscoveryParams::static_only(),
        )
        .expect("session manager");
        for peer in peers {
            mgr.insert_accepted(*peer, Box::new(MockConn(*peer)));
        }
        mgr
    }

    struct Harness {
        feed: PeerSourceFeed,
        status: Arc<PeerSourceStatus>,
        book: Arc<FakeBook>,
        relay: Arc<FakeRelay>,
        hub: Arc<DiscoveryHub>,
        sw: Arc<NatSwitching>,
        clock: Instant,
    }

    impl Harness {
        fn new(static_peers: Vec<N1PeerId>, sessions: Arc<N1SessionManager>) -> Self {
            let self_id = peer(0x11);
            let hub = Arc::new(DiscoveryHub::new(
                DiscoveryPeerId(hex_id(0x11)),
                Vec::new(),
                None,
                Duration::from_secs(90),
            ));
            let book = FakeBook::new();
            let relay = FakeRelay::new();
            let sw = switch(self_id);
            sw.attach_relay_provider(relay.clone());
            let status = Arc::new(PeerSourceStatus::default());
            status.set_state("running");
            let clock = now();
            let feed = PeerSourceFeed::new(
                Arc::clone(&sw),
                relay.clone(),
                book.clone(),
                sessions,
                static_peers,
                Arc::clone(&hub),
                self_id,
                PeerSourceConfig {
                    book_poll_interval: Duration::from_millis(1000),
                    ..PeerSourceConfig::default()
                },
                Arc::clone(&status),
                Arc::new(AtomicBool::new(false)),
            );
            Self {
                feed,
                status,
                book,
                relay,
                hub,
                sw,
                clock,
            }
        }

        fn tick(&mut self) -> PeerSourceStatusSnapshot {
            // 300ms ticks advance the 1s/2s backoff in a bounded number of steps.
            self.clock += Duration::from_millis(300);
            self.feed.tick(self.clock);
            self.status.snapshot()
        }

        fn tick_at(&mut self, at: Instant) -> PeerSourceStatusSnapshot {
            self.clock = at;
            self.feed.tick(self.clock);
            self.status.snapshot()
        }

        fn drain(&mut self) {
            std::thread::sleep(Duration::from_millis(60));
        }

        /// Wait until the fake relay has recorded `n` trigger calls (the call is
        /// made on a spawned thread, so it is observable only after a yield).
        fn wait_calls(&self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.relay.calls().len() < n && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                self.relay.calls().len() >= n,
                "expected {n} trigger calls, saw {}",
                self.relay.calls().len()
            );
        }

        fn run_until(
            &mut self,
            mut pred: impl FnMut(&PeerSourceStatusSnapshot) -> bool,
            max_ticks: usize,
        ) -> PeerSourceStatusSnapshot {
            for _ in 0..max_ticks {
                self.drain();
                let snap = self.tick();
                if pred(&snap) {
                    return snap;
                }
            }
            panic!(
                "condition not reached within {max_ticks} ticks (state: {:?})",
                self.status.snapshot()
            );
        }

        fn inject_lsa(&self, byte: u8) {
            let id = hex_id(byte);
            self.hub.upsert_lsa(
                Lsa {
                    node_id: DiscoveryPeerId(id.clone()),
                    vip: "10.99.0.1".to_string(),
                    incarnation: 1,
                    seq: 1,
                    capabilities: 0,
                    locator: Some(format!("udp://10.0.0.{}:19010", byte.max(1))),
                    neighbors: Vec::new(),
                },
                self.clock,
            );
            self.hub.note_lsa_heard(&DiscoveryPeerId(id), self.clock);
        }

        fn finish(mut self) {
            self.sw.shutdown();
            self.feed.shutdown();
        }
    }

    fn switch(my_id: FabricPeerId) -> Arc<NatSwitching> {
        let driver =
            nexus_fabric::Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("driver");
        let local = nexus_nat_traversal::LocalCandidates {
            host: crate::nat_switch::gather_host_candidates(&driver),
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: nexus_domain::nat::NatType::Unknown,
        };
        NatSwitching::new(
            driver,
            my_id,
            local,
            Vec::new(),
            Arc::new(nexus_nat_wireup::SystemPunchClock::new()),
        )
    }

    // ---------- status ----------

    #[test]
    fn status_note_book_error_is_enum() {
        let status = PeerSourceStatus::default();
        assert_eq!(status.snapshot().state, "disabled:no-turn");
        status.set_state("running");
        assert!(status.snapshot().enabled);
        status.note_book_error(String::new());
        assert_eq!(
            status.snapshot().last_error.as_deref(),
            Some("book-reload-failed")
        );
        // Success does not clear the last failure code (spec §4.12.1).
        status.note_book_success();
        let snap = status.snapshot();
        assert_eq!(snap.last_error.as_deref(), Some("book-reload-failed"));
        assert!(snap.book_last_success_ms > 0);
    }

    #[test]
    fn decide_state_table_order() {
        let base = PeerSourceStateInputs {
            enabled: true,
            feed: true,
            has_nat_switch: true,
            has_provider: true,
            has_hub: true,
            has_sessions: true,
        };
        assert_eq!(decide_state(base), "running");
        assert_eq!(
            decide_state(PeerSourceStateInputs {
                enabled: false,
                ..base
            }),
            "disabled:config"
        );
        // `enabled=false` wins over a missing turn stack (judgment order).
        assert_eq!(
            decide_state(PeerSourceStateInputs {
                enabled: false,
                has_nat_switch: false,
                ..base
            }),
            "disabled:config"
        );
        assert_eq!(
            decide_state(PeerSourceStateInputs {
                has_nat_switch: false,
                ..base
            }),
            "disabled:no-turn"
        );
        assert_eq!(
            decide_state(PeerSourceStateInputs {
                has_provider: false,
                ..base
            }),
            "disabled:no-provider"
        );
        assert_eq!(
            decide_state(PeerSourceStateInputs {
                has_hub: false,
                ..base
            }),
            "disabled:no-discovery"
        );
        assert_eq!(
            decide_state(PeerSourceStateInputs {
                has_sessions: false,
                ..base
            }),
            "disabled:no-sessions"
        );
    }

    // ---------- AC8 ----------

    #[test]
    fn rejects_non_canonical_ids() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        // Uppercase / wrong length / non-hex ids injected as mDNS/LSA ids.
        let bad = ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)];
        for (i, id) in bad.iter().enumerate() {
            h.hub.upsert_lsa(
                Lsa {
                    node_id: DiscoveryPeerId(id.clone()),
                    vip: "10.99.0.1".into(),
                    incarnation: 1,
                    seq: 1,
                    capabilities: 0,
                    locator: Some(format!("udp://10.0.0.{}:19010", i + 1)),
                    neighbors: Vec::new(),
                },
                h.clock,
            );
            h.hub.note_lsa_heard(&DiscoveryPeerId(id.clone()), h.clock);
        }
        let snap = h.tick();
        assert_eq!(snap.subscribed_peers, 0);
        assert_eq!(snap.invalid_peer_id_total, 3);

        // Same (source, raw) over three ticks counts once.
        let snap = h.tick();
        assert_eq!(snap.invalid_peer_id_total, 3);
        let snap = h.tick();
        assert_eq!(snap.invalid_peer_id_total, 3);

        // Same raw id from a different source counts again (dedup key includes
        // the source).
        let raw = "zz".repeat(32);
        h.feed.note_invalid(DiscoverySource::Mdns, &raw);
        let snap = h.tick();
        assert_eq!(snap.invalid_peer_id_total, 4);
        h.finish();
    }

    #[test]
    fn static_and_n1_ids_bypass_string_validation() {
        let static_id = N1PeerId([0x22; 32]);
        let n1_id = N1PeerId([0x33; 32]);
        let mut h = Harness::new(vec![static_id], sessions_with(&[n1_id]));
        let snap = h.tick();
        assert_eq!(snap.subscribed_peers, 2);
        assert_eq!(snap.sources_static, 1);
        assert_eq!(snap.sources_n1, 1);
        assert_eq!(snap.invalid_peer_id_total, 0);
        h.finish();
    }

    // ---------- AC9 ----------

    #[test]
    fn static_source_subscribes_without_book() {
        let static_id = N1PeerId([0x22; 32]);
        let mut h = Harness::new(vec![static_id], sessions_with(&[]));
        let snap = h.tick();
        assert_eq!(snap.subscribed_peers, 1);
        assert_eq!(snap.sources_static, 1);
        // No book entry: the subscription must not fabricate a trigger.
        assert_eq!(snap.trigger_attempts_total, 0);
        assert!(h.relay.calls().is_empty());
        assert_eq!(snap.book_entries, Some(0));
        assert_eq!(
            snap.subscribed_peers_without_book_addr, 1,
            "the silent 'subscribed but book has no address' state must be visible"
        );
        h.finish();
    }

    #[test]
    fn book_coverage_status_tracks_entries_and_missing_addresses() {
        // Two static peers, one address in the book: the other stays counted.
        let mut h = Harness::new(
            vec![N1PeerId([0x22; 32]), N1PeerId([0x23; 32])],
            sessions_with(&[]),
        );
        h.book.set(peer(0x22), addr(5002));
        let snap = h.tick();
        assert_eq!(snap.book_entries, Some(1));
        assert_eq!(snap.subscribed_peers_without_book_addr, 1);
        // Publishing the second address closes the gap.
        h.book.set(peer(0x23), addr(5003));
        let snap = h.tick();
        assert_eq!(snap.book_entries, Some(2));
        assert_eq!(snap.subscribed_peers_without_book_addr, 0);
        h.finish();
    }

    #[test]
    fn static_label_wins_over_discovery_duplicate() {
        let static_id = N1PeerId([0x2a; 32]);
        let mut h = Harness::new(vec![static_id], sessions_with(&[]));
        // The same id is also visible through LSA.
        h.inject_lsa(0x2a);
        let snap = h.tick();
        assert_eq!(snap.subscribed_peers, 1);
        assert_eq!(snap.sources_static, 1);
        assert_eq!(snap.sources_lsa, 0);
        assert_eq!(h.relay.sink_count(&peer(0x2a)), 1);
        h.finish();
    }

    #[test]
    fn peer_stays_until_all_sources_drop() {
        // Discovery disappears but static remains -> still subscribed.
        let static_id = N1PeerId([0x2b; 32]);
        let mut h = Harness::new(vec![static_id], sessions_with(&[]));
        h.inject_lsa(0x2b);
        assert_eq!(h.tick().subscribed_peers, 1);
        // Age the LSA out (90s window) but keep the static entry.
        let stale = h.clock + Duration::from_secs(120);
        let snap = h.tick_at(stale);
        assert_eq!(snap.subscribed_peers, 1);
        assert_eq!(snap.sources_static, 1);
        assert_eq!(snap.sources_lsa, 0);

        // All sources gone -> unsubscribe (guard drop -> zero sinks).
        let mut h2 = Harness::new(Vec::new(), sessions_with(&[]));
        h2.inject_lsa(0x2c);
        assert_eq!(h2.tick().subscribed_peers, 1);
        assert_eq!(h2.relay.sink_count(&peer(0x2c)), 1);
        let stale = h2.clock + Duration::from_secs(120);
        let snap = h2.tick_at(stale);
        assert_eq!(snap.subscribed_peers, 0);
        assert_eq!(h2.relay.sink_count(&peer(0x2c)), 0);

        // N1 alone is a sufficient source.
        let n1_id = N1PeerId([0x2d; 32]);
        let mut h3 = Harness::new(Vec::new(), sessions_with(&[n1_id]));
        let snap = h3.tick();
        assert_eq!(snap.subscribed_peers, 1);
        assert_eq!(snap.sources_n1, 1);
        h.finish();
        h2.finish();
        h3.finish();
    }

    #[test]
    fn static_removal_requires_restart() {
        // (a) feed A with P static and also discoverable through LSA.
        let p = N1PeerId([0x2e; 32]);
        let mut a = Harness::new(vec![p], sessions_with(&[]));
        a.inject_lsa(0x2e);
        let snap = a.tick();
        assert_eq!(snap.subscribed_peers, 1);
        assert_eq!(snap.sources_static, 1);
        assert_eq!(snap.sources_lsa, 0, "static label absorbs the duplicate");
        assert_eq!(a.relay.sink_count(&peer(0x2e)), 1);

        // (b) shutdown is the daemon-restart path: guards drop, sinks go to 0.
        a.feed.shutdown();
        assert_eq!(a.relay.sink_count(&peer(0x2e)), 0);
        assert!(a.relay.established_peer_ids().is_empty());
        a.sw.shutdown();

        // (c) new config without the static entry, same hub still discovers P.
        let hub = Arc::clone(&a.hub);
        let book = FakeBook::new();
        let relay = FakeRelay::new();
        let sw = switch(peer(0x11));
        sw.attach_relay_provider(relay.clone());
        let status = Arc::new(PeerSourceStatus::default());
        let status_ro = Arc::clone(&status);
        let mut b = PeerSourceFeed::new(
            Arc::clone(&sw),
            relay.clone(),
            book,
            sessions_with(&[]),
            Vec::new(),
            hub,
            peer(0x11),
            PeerSourceConfig::default(),
            status,
            Arc::new(AtomicBool::new(false)),
        );
        let t0 = now();
        b.tick(t0);
        let snap = status_ro.snapshot();
        assert_eq!(snap.subscribed_peers, 1);
        assert_eq!(snap.sources_lsa, 1);
        assert_eq!(relay.sink_count(&peer(0x2e)), 1);
        sw.shutdown();
    }

    // ---------- AC10 ----------

    #[test]
    fn trigger_once_per_address() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x31);
        h.book.set(peer(0x31), addr(5001));
        assert_eq!(h.tick().trigger_attempts_total, 1);
        h.wait_calls(1);
        h.run_until(|s| s.trigger_ok_total == 1, 10);
        for _ in 0..10 {
            h.tick();
        }
        assert_eq!(h.status.snapshot().trigger_ok_total, 1);
        assert_eq!(h.relay.calls().len(), 1, "same address must not retrigger");
        h.finish();
    }

    #[test]
    fn retrigger_on_address_change() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x32);
        h.book.set(peer(0x32), addr(5002));
        h.tick();
        h.wait_calls(1);
        h.run_until(|s| s.trigger_ok_total == 1, 10);
        assert_eq!(h.relay.calls().len(), 1);
        h.book.set(peer(0x32), addr(6002));
        h.tick();
        h.wait_calls(2);
        h.run_until(|s| s.trigger_ok_total == 2, 10);
        let calls = h.relay.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].1, addr(6002));
        assert_eq!(h.status.snapshot().trigger_ok_total, 2);
        h.finish();
    }

    #[test]
    fn park_and_rearm_on_book_change() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x33);
        h.book.set(peer(0x33), addr(5003));
        h.relay.set_fail(Some("boom"));
        // Three failures with the frozen 1s/2s backoff -> Parked{MaxFailures}.
        h.run_until(|s| s.trigger_fail_total == 1, 20);
        h.run_until(|s| s.trigger_fail_total == 2, 20);
        let snap = h.run_until(|s| s.trigger_parked_peers == 1, 30);
        assert_eq!(snap.trigger_fail_total, 3);
        h.wait_calls(3);
        assert_eq!(h.relay.calls().len(), 3);
        // Parked and unchanged: no new attempts.
        for _ in 0..3 {
            h.tick();
        }
        assert_eq!(h.relay.calls().len(), 3);

        // Book address change re-arms and triggers again.
        h.book.set(peer(0x33), addr(6003));
        h.run_until(|s| s.trigger_attempts_total == 4, 30);
        h.wait_calls(4);
        assert_eq!(h.relay.calls().len(), 4);
        h.finish();
    }

    #[test]
    fn trigger_failure_backoff_and_park() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x34);
        h.book.set(peer(0x34), addr(5004));
        h.relay.set_fail(Some("boom"));
        h.tick();
        h.drain();
        // Backoff: an immediate retrigger is not attempted.
        let snap = h.tick_at(h.clock + Duration::from_millis(100));
        assert_eq!(snap.trigger_attempts_total, 1);
        // Keep ticking without changing the address: 3 attempts then parked.
        let snap = h.run_until(|s| s.trigger_parked_peers == 1, 40);
        assert_eq!(snap.trigger_fail_total, 3);
        assert_eq!(
            snap.trigger_parked_max_failures, 1,
            "MaxFailures must be distinguishable from capacity parking"
        );
        assert_eq!(snap.trigger_parked_capacity, 0);
        h.wait_calls(3);
        assert_eq!(h.relay.calls().len(), 3);
        for _ in 0..5 {
            h.tick();
        }
        assert_eq!(h.relay.calls().len(), 3, "parked peers do not retry");
        h.finish();
    }

    #[test]
    fn trigger_inflight_timeout_parks() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x35);
        h.book.set(peer(0x35), addr(5005));
        let gate = h.relay.block();
        let t0 = h.clock;
        h.tick();
        assert_eq!(h.status.snapshot().trigger_inflight_peers, 1);
        // Past the 30s in-flight deadline: one failure, no duplicate spawn.
        let snap = h.tick_at(t0 + Duration::from_secs(31));
        assert_eq!(snap.trigger_fail_total, 1);
        assert_eq!(snap.trigger_inflight_peers, 0);
        h.wait_calls(1);
        assert_eq!(h.relay.calls().len(), 1);
        // Release the blocked thread so the test does not leak a waiter.
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
        h.finish();
    }

    // ---------- AC15 ----------

    #[test]
    fn capacity_arbitration_deterministic() {
        // Same tick: the smaller hex wins, the other parks once.
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x0b); // H
        h.inject_lsa(0x0a); // L
        h.book.set(peer(0x0a), addr(5010));
        h.book.set(peer(0x0b), addr(5011));
        let snap = h.tick();
        assert_eq!(snap.trigger_attempts_total, 1);
        assert_eq!(snap.trigger_capacity_parked_total, 1);
        assert_eq!(snap.trigger_parked_peers, 1);
        assert_eq!(snap.trigger_parked_capacity, 1);
        assert_eq!(snap.trigger_parked_max_failures, 0);
        h.wait_calls(1);
        let calls = h.relay.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, peer(0x0a), "hex-smaller peer wins the tie");
        h.run_until(|s| s.trigger_ok_total == 1, 10);
        // The loser stays parked without re-counting.
        for _ in 0..5 {
            h.tick();
        }
        assert_eq!(h.status.snapshot().trigger_capacity_parked_total, 1);
        assert_eq!(h.relay.calls().len(), 1);

        // Slot release: L ages out of discovery -> unsubscribed -> the fake
        // provider clears its established entry -> H re-arms and triggers.
        // H is re-announced so only L expires.
        let stale = h.clock + Duration::from_secs(120);
        h.clock = stale;
        h.inject_lsa(0x0b);
        let snap = h.tick_at(stale);
        assert_eq!(snap.trigger_attempts_total, 2);
        assert_eq!(snap.trigger_capacity_parked_total, 1);
        h.wait_calls(2);
        let calls = h.relay.calls();
        assert_eq!(calls.last().unwrap().0, peer(0x0b));
        h.finish();

        // Different tick: the earlier subscription wins regardless of hex.
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.inject_lsa(0x0b); // H subscribes first
        h.book.set(peer(0x0a), addr(5020));
        h.book.set(peer(0x0b), addr(5021));
        h.tick();
        h.inject_lsa(0x0a); // L subscribes later
        h.tick();
        h.wait_calls(1);
        let calls = h.relay.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, peer(0x0b), "earlier subscription tick wins");
        h.finish();
    }

    // ---------- AC7 ----------

    #[test]
    fn degrade_no_provider() {
        // A stack without an attached provider refuses subscriptions.
        let h = Harness::new(Vec::new(), sessions_with(&[]));
        let no_provider = switch(peer(0x11));
        let status = Arc::new(PeerSourceStatus::default());
        let mut feed = PeerSourceFeed::new(
            Arc::clone(&no_provider),
            h.relay.clone(),
            h.book.clone(),
            sessions_with(&[]),
            Vec::new(),
            Arc::clone(&h.hub),
            peer(0x11),
            PeerSourceConfig::default(),
            Arc::clone(&status),
            Arc::new(AtomicBool::new(false)),
        );
        h.inject_lsa(0x41);
        let t0 = now();
        feed.tick(t0);
        feed.tick(t0 + Duration::from_millis(20));
        let snap = status.snapshot();
        assert_eq!(snap.subscribed_peers, 0);
        assert_eq!(snap.subscribe_refused_total, 2);
        no_provider.shutdown();
        h.finish();
    }

    #[test]
    fn degrade_book_reload() {
        let mut h = Harness::new(Vec::new(), sessions_with(&[]));
        h.book.fail.store(true, Ordering::SeqCst);
        let snap = h.tick();
        assert_eq!(snap.book_errors_total, 1);
        assert_eq!(snap.last_error.as_deref(), Some("book-reload-failed"));
        h.book.fail.store(false, Ordering::SeqCst);
        let snap = h.tick_at(h.clock + Duration::from_millis(1100));
        assert_eq!(snap.book_reloads_total, 1);
        // Success keeps the previous failure code.
        assert_eq!(snap.last_error.as_deref(), Some("book-reload-failed"));
        h.finish();
    }
}
