//! Production relay connections for NAT punch-through (AC-13).
//!
//! `TurnRelayProvider` allocates a TURN relay on the punch socket and feeds
//! `RelayConnSink`s with a `ConnShared` the punch manager can signal over.
//! Identity is **injected** (never random); seeding comes from the daemon's
//! `[network.identity].seed_file` (BLOCKED-1 ruling (a), see evidence).
//!
//! Operational contract = per-peer attach + the errata in spec §4.7
//! (O8-1..O8-12), not a literal §14.3 constructor subscription:
//! - `subscribe(peer, sink)` per peer, `unsubscribe` explicit or via the
//!   consumer's `RelaySubscriptionGuard`;
//! - sink edges are `Weak` (O9), so the provider never keeps a subscriber
//!   alive and no `NatSwitching -> provider -> NatSwitching` cycle exists;
//! - the established relay is a **single slot** (CR-BLOCKED-3) that owns its
//!   transport anchor (driver / listener) and is torn down outside locks;
//! - no replay of already-established relays (O8-10): the feed asks
//!   `established_relay_addr`, which avoids re-registering a path and dropping
//!   the direct hot standby.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use nexus_fabric::{ConnShared, Driver, FabricIdentity, FabricListener, PeerId as FabricPeerId};
use nexus_turn::socket::TurnSocket;

use crate::nat_turn::{RefreshOutcome, TurnManager, TurnState};

/// Relay connection kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayKind {
    Turn,
    Mesh,
}

/// A relayed connection handed to the punch manager.
#[derive(Clone)]
pub struct RelayConn {
    pub conn: Arc<ConnShared>,
    pub relayed: SocketAddr,
    pub kind: RelayKind,
}

/// Event delivered to a `RelayConnSink`.
#[derive(Clone)]
pub struct RelayInfo {
    pub peer: FabricPeerId,
    pub conn: Arc<ConnShared>,
    pub relayed: SocketAddr,
    pub kind: RelayKind,
}

pub trait RelayConnSink: Send + Sync {
    fn on_relay_available(&self, info: RelayInfo);
    fn on_relay_lost(&self, peer: FabricPeerId);
}

/// Provider of production relay connections.
///
/// Per-peer attach model (spec §4.7 errata O8-2/O8-3): one stack may subscribe
/// several peers, each subscription is revocable, and the provider never holds
/// a strong reference to its subscribers.
pub trait RelayConnProvider: Send + Sync {
    fn subscribe(&self, peer: FabricPeerId, sink: Arc<dyn RelayConnSink>);
    fn unsubscribe(&self, peer: FabricPeerId, sink: &Arc<dyn RelayConnSink>);
    fn established_relay(&self, peer: &FabricPeerId) -> Option<RelayConn>;
    fn established_peers(&self) -> Vec<FabricPeerId>;
    fn subscribed_peers(&self) -> Vec<FabricPeerId>;
    fn sink_count(&self, peer: &FabricPeerId) -> usize;
}

/// Minimal trigger surface the peer-source feed depends on.
///
/// `TurnRelayProvider` implements it in production and tests implement fakes,
/// so the feed never needs the concrete provider type (spec §1.5 item 8).
pub trait RelayTrigger: Send + Sync {
    /// Relayed address currently established for `peer`, if any.
    fn established_relay_addr(&self, peer: &FabricPeerId) -> Option<SocketAddr>;
    /// Peers currently holding the relay slot (<= 1 in this run).
    fn established_peer_ids(&self) -> Vec<FabricPeerId>;
    /// Establish a relay to `peer` at `peer_relayed`; returns our relayed
    /// address on success.
    fn trigger_relay(
        &self,
        peer: FabricPeerId,
        peer_relayed: SocketAddr,
    ) -> Result<SocketAddr, RelayError>;
}

#[derive(Debug)]
pub enum RelayError {
    Turn(String),
    Io(io::Error),
    Identity(String),
    AddressBook(String),
    /// The single relay slot is taken by another peer (CR-BLOCKED-3 guard).
    Capacity(String),
}

impl RelayError {
    /// Stable log category (spec §4.12.2: `turn|io|identity|book|capacity`).
    pub fn category(&self) -> &'static str {
        match self {
            RelayError::Turn(_) => "turn",
            RelayError::Io(_) => "io",
            RelayError::Identity(_) => "identity",
            RelayError::AddressBook(_) => "book",
            RelayError::Capacity(_) => "capacity",
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Turn(s) => write!(f, "turn: {s}"),
            RelayError::Io(e) => write!(f, "io: {e}"),
            RelayError::Identity(s) => write!(f, "identity: {s}"),
            RelayError::AddressBook(s) => write!(f, "address book: {s}"),
            RelayError::Capacity(s) => write!(f, "capacity: {s}"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<io::Error> for RelayError {
    fn from(e: io::Error) -> Self {
        RelayError::Io(e)
    }
}

/// Outcome of [`TurnRelayProvider::refresh`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefresh {
    /// Nothing to do (not due, inactive, or the turn lock was busy).
    NotDue,
    /// The allocation was refreshed (address unchanged or re-published).
    Refreshed,
    /// The allocation died; the slot was cleared and sinks were notified.
    Lost,
}

/// Read-only address book for peer relayed addresses.
pub trait RelayAddressBook: Send + Sync {
    fn relay_addr(&self, peer: &[u8; 32]) -> Option<SocketAddr>;
    fn reload(&self) -> io::Result<()>;
    fn publish(&self, peer: [u8; 32], addr: SocketAddr) -> io::Result<()>;
    /// Number of peer addresses currently visible in the book.
    ///
    /// `None` = the implementation cannot tell (test doubles). Production
    /// books report `Some`, so the status block can explain "subscribed but no
    /// book address" (product-review r1 MAJOR-2).
    fn entry_count(&self) -> Option<usize> {
        None
    }
}

/// File-backed address book (`peer_hex = "ip:port"` lines).
pub struct FileRelayAddressBook {
    path: PathBuf,
    entries: Mutex<HashMap<[u8; 32], SocketAddr>>,
}

impl FileRelayAddressBook {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let book = Self {
            path: path.into(),
            entries: Mutex::new(HashMap::new()),
        };
        book.reload()?;
        Ok(book)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RelayAddressBook for FileRelayAddressBook {
    fn relay_addr(&self, peer: &[u8; 32]) -> Option<SocketAddr> {
        self.entries.lock().ok()?.get(peer).copied()
    }

    fn entry_count(&self) -> Option<usize> {
        self.entries.lock().ok().map(|g| g.len())
    }

    fn reload(&self) -> io::Result<()> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = k.trim().trim_matches('"');
            let val = v.trim().trim_matches('"');
            if let (Ok(peer), Ok(addr)) = (parse_hex32(key), val.parse::<SocketAddr>()) {
                map.insert(peer, addr);
            }
        }
        *self.entries.lock().unwrap() = map;
        Ok(())
    }

    fn publish(&self, peer: [u8; 32], addr: SocketAddr) -> io::Result<()> {
        {
            let mut g = self.entries.lock().unwrap();
            g.insert(peer, addr);
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut out = String::from("# nexus relay address book (generated)\n");
        let g = self.entries.lock().unwrap();
        let mut rows: Vec<_> = g.iter().collect();
        rows.sort_by_key(|(k, _)| **k);
        for (k, v) in rows {
            out.push_str(&format!("{} = \"{}\"\n", hex32(k), v));
        }
        let mut f = fs::File::create(&self.path)?;
        f.write_all(out.as_bytes())?;
        Ok(())
    }
}

fn hex32(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

/// Per-peer sink lists.
///
/// O9: the provider must not own its subscribers. Strong `Arc`s here formed a
/// cycle (`NatSwitching -> provider -> NatSwitching`) that made teardown
/// impossible; a `Weak` edge plus the explicit unsubscribe guard breaks it.
type SinkMap = HashMap<[u8; 32], Vec<Weak<dyn RelayConnSink>>>;

/// Prune dead weak sinks for one peer; returns the live count.
fn prune_peer(sinks: &mut SinkMap, peer: &[u8; 32]) -> usize {
    if let Some(list) = sinks.get_mut(peer) {
        list.retain(|w| w.strong_count() > 0);
        let live = list.len();
        if live == 0 {
            sinks.remove(peer);
        }
        live
    } else {
        0
    }
}

/// One established relay plus its ownership anchor(s).
///
/// The anchor is what keeps the relay alive: `Driver::drop` shuts the transport
/// thread down and joins it, so dropping it as soon as `on_turn_allocated`
/// returns would kill the connection (shipped gap, spec §1.5 item 2).
///
/// Client side anchors on the `Driver` it dialed with. Server side accepts
/// through a `FabricListener`, which *owns* the equivalent driver but exposes no
/// accessor (`nexus-fabric` is a frozen boundary for this run), so the listener
/// itself is the anchor there. Exactly one of the two is set; both keep the
/// transport alive for the lifetime of the slot, and the slot is always torn
/// down outside every provider lock.
///
/// Single slot by design (CR-BLOCKED-3).
struct EstablishedRelay {
    conn: RelayConn,
    driver: Option<Arc<Driver>>,
    listener: Option<FabricListener>,
    /// Why this slot is being torn down. Set by whoever removes the entry;
    /// the default covers process shutdown.
    release_reason: std::cell::Cell<&'static str>,
}

impl EstablishedRelay {
    fn anchor_label(&self) -> &'static str {
        if self.listener.is_some() {
            "listener"
        } else if self.driver.is_some() {
            "driver"
        } else {
            "none"
        }
    }

    /// Tag the teardown cause so the release line is self-explanatory.
    fn released_because(self, reason: &'static str) -> Self {
        self.release_reason.set(reason);
        self
    }
}

impl Drop for EstablishedRelay {
    fn drop(&mut self) {
        // Observable teardown: the driver's Shutdown + join happens here, which
        // must never run while a provider lock is held. `hex64` matches the
        // `provider_up peer=<hex64>` correlation key, and `reason=` keeps a
        // normal replace from reading like a relay loss (spec §4.12.2).
        eprintln!(
            "[nat-relay] relay slot released peer={} anchor={} reason={}",
            hex32(&self.conn.conn.peer.0),
            self.anchor_label(),
            self.release_reason.get()
        );
    }
}

/// Project the provider's TURN manager onto the status row (spec §4.10.4).
///
/// Lock order is fixed `turn -> nat_status`; the status guard is taken and
/// released inside `update_turn_status`, never held across a TURN I/O call.
fn publish_provider_status(m: &TurnManager) {
    crate::nat_status::update_turn_status(
        crate::nat_status::TurnManagerKind::Provider,
        crate::nat_status::TurnManagerStatus {
            health: m.health().as_str(),
            bind_addr: m.bind_addr_text().map(str::to_string),
            last_error: m.last_failure().map(|f| f.as_str()),
        },
    );
}

/// Production TURN relay provider.
pub struct TurnRelayProvider {
    my_id: FabricPeerId,
    identity: FabricIdentity,
    turn: Mutex<TurnManager>,
    book: Arc<dyn RelayAddressBook>,
    sinks: Mutex<SinkMap>,
    /// Single relay slot (len <= 1); the value owns the driver anchor.
    established: Mutex<HashMap<[u8; 32], EstablishedRelay>>,
    up: AtomicBool,
}

impl TurnRelayProvider {
    pub fn new(
        my_id: FabricPeerId,
        identity: FabricIdentity,
        turn: TurnManager,
        book: Arc<dyn RelayAddressBook>,
    ) -> Arc<Self> {
        Arc::new(Self {
            my_id,
            identity,
            turn: Mutex::new(turn),
            book,
            sinks: Mutex::new(HashMap::new()),
            established: Mutex::new(HashMap::new()),
            up: AtomicBool::new(false),
        })
    }

    pub fn my_id(&self) -> FabricPeerId {
        self.my_id
    }

    pub fn identity_peer_id(&self) -> FabricPeerId {
        self.identity.peer_id()
    }

    /// Register our own allocated relayed address so peers can dial it.
    pub fn publish_self(&self, relayed: SocketAddr) -> Result<(), RelayError> {
        self.book
            .publish(self.my_id.0, relayed)
            .map_err(|e| RelayError::AddressBook(e.to_string()))
    }

    /// Allocate (if needed) and publish **this provider's** relayed address.
    ///
    /// Called once at start-up. The runtime's warm-backup allocation must never
    /// be published here: peers would dial an allocation nobody accepts (D-D).
    pub fn ensure_relay_ready(&self) -> Result<SocketAddr, RelayError> {
        let relayed = {
            let mut turn = self
                .turn
                .lock()
                .map_err(|_| RelayError::Turn("lock".into()))?;
            turn.ensure_allocated()
                .map_err(|e| RelayError::Turn(format!("{e:?}")))?
        };
        if self.book.relay_addr(&self.my_id.0) != Some(relayed) {
            self.book
                .publish(self.my_id.0, relayed)
                .map_err(|e| RelayError::AddressBook(e.to_string()))?;
        }
        eprintln!("[nat-relay] relay_ready relayed={relayed}");
        Ok(relayed)
    }

    /// Keep the provider's own allocation alive (called every 500ms).
    ///
    /// Never blocks the worker: a busy turn lock returns `NotDue` immediately.
    /// An `Active/Refreshing -> Expired/Disabled` transition clears the slot and
    /// notifies the sinks (`provider_lost`), and a refreshed relay address is
    /// re-published.
    pub fn refresh(&self) -> RelayRefresh {
        let (before, after, outcome, relayed) = {
            let Ok(mut turn) = self.turn.try_lock() else {
                return RelayRefresh::NotDue;
            };
            let before = turn.state();
            let outcome = turn.refresh_if_needed();
            let after = turn.state();
            (before, after, outcome, turn.relayed_addr())
        };
        let was_up = matches!(before, TurnState::Active | TurnState::Refreshing);
        let now_dead = matches!(after, TurnState::Expired | TurnState::Disabled);
        if was_up && now_dead {
            self.provider_lost();
            return RelayRefresh::Lost;
        }
        if after == TurnState::Active {
            if let Some(relayed) = relayed {
                if self.book.relay_addr(&self.my_id.0) != Some(relayed) {
                    if let Err(e) = self.publish_self(relayed) {
                        eprintln!("[nat-relay] WARN: re-publish after refresh failed: {e}");
                    }
                }
            }
        }
        match outcome {
            RefreshOutcome::Refreshed | RefreshOutcome::StaleNonceRetried => {
                RelayRefresh::Refreshed
            }
            _ => RelayRefresh::NotDue,
        }
    }

    /// Establish (or reuse) the relay to `peer` (spec §4.6.3, frozen steps).
    ///
    /// 1. TURN allocation (failure => `provider_lost()` + `RelayError::Turn`);
    /// 2. permission for the peer's relayed address;
    /// 3. single-slot bookkeeping: same peer+address is idempotent, same peer
    ///    with a new address replaces the old entry, another peer is rejected
    ///    with `RelayError::Capacity`;
    /// 4. identity-injected listener (larger id) or client (smaller id), 5s;
    /// 5. store the connection with its driver anchor;
    /// 6. first success logs `provider_up`;
    /// 7. notify this peer's live sinks; 8. return the connection.
    pub fn on_turn_allocated(
        &self,
        peer: FabricPeerId,
        peer_relayed: SocketAddr,
    ) -> Result<RelayConn, RelayError> {
        // 1. Allocation is the precondition for every new relay.
        let client = {
            let mut turn = self
                .turn
                .lock()
                .map_err(|_| RelayError::Turn("lock".into()))?;
            match turn.ensure_allocated() {
                Ok(_) => {
                    publish_provider_status(&turn);
                    turn.client()
                }
                Err(e) => {
                    publish_provider_status(&turn);
                    drop(turn);
                    self.provider_lost();
                    return Err(RelayError::Turn(format!("{e:?}")));
                }
            }
        };
        let client = client.ok_or_else(|| RelayError::Turn("no allocated client".into()))?;
        // 2. Relay permission for the peer's relayed address.
        client
            .create_permission(peer_relayed)
            .map_err(|e| RelayError::Turn(format!("create_permission: {e}")))?;

        // 3. Single-slot bookkeeping (idempotent / replace / capacity).
        let replaced = {
            let mut established = self
                .established
                .lock()
                .map_err(|_| RelayError::Turn("established lock".into()))?;
            if let Some(current) = established.get(&peer.0) {
                if current.conn.relayed == peer_relayed {
                    // Already established for this peer and address: do not
                    // rebuild the driver and do not notify again.
                    return Ok(current.conn.clone());
                }
            }
            if established.keys().any(|holder| *holder != peer.0) {
                return Err(RelayError::Capacity("relay slot busy".into()));
            }
            established
                .remove(&peer.0)
                .map(|old| old.released_because("replace"))
        };
        // Driver teardown (Shutdown + join) must happen outside every lock.
        drop(replaced);

        // 4. Larger id listens, smaller id connects; identity is injected.
        let (conn, driver_anchor, listener_anchor) = if self.my_id.0 > peer.0 {
            let listener = FabricListener::bind_with_transport_identity(
                Box::new(TurnSocket::new(client)),
                &self.identity,
            )
            .map_err(|e| RelayError::Identity(format!("listener: {e:?}")))?;
            let conn = listener
                .accept_timeout(Duration::from_secs(5))
                .map_err(|e| RelayError::Turn(format!("accept: {e:?}")))?
                .shared();
            (conn, None, Some(listener))
        } else {
            let driver = Driver::new_client_with_transport(Box::new(TurnSocket::new(client)))
                .map_err(|e| RelayError::Turn(format!("driver: {e:?}")))?;
            let conn = driver
                .connect(peer, peer_relayed, Duration::from_secs(5))
                .map_err(|e| RelayError::Turn(format!("connect: {e:?}")))?;
            (conn, Some(driver), None)
        };

        // 5. Store the connection together with its driver anchor.
        let relay_conn = RelayConn {
            conn,
            relayed: peer_relayed,
            kind: RelayKind::Turn,
        };
        {
            let mut established = self
                .established
                .lock()
                .map_err(|_| RelayError::Turn("established lock".into()))?;
            established.insert(
                peer.0,
                EstablishedRelay {
                    conn: relay_conn.clone(),
                    driver: driver_anchor,
                    listener: listener_anchor,
                    release_reason: std::cell::Cell::new("shutdown"),
                },
            );
        }

        // 6. First success in this provider lifetime.
        if !self.up.swap(true, Ordering::SeqCst) {
            eprintln!(
                "[nat-relay] provider_up peer={} relayed={peer_relayed}",
                hex32(&peer.0)
            );
        }
        // 7. Notify this peer's live sinks (locks `sinks` only; the sink must
        // not call back into the provider, spec §4.5).
        dispatch_available(&self.sinks, &peer, &relay_conn);
        // 8.
        Ok(relay_conn)
    }

    /// The provider's allocation is gone (spec §4.6.3, frozen five steps).
    ///
    /// Clears the single slot, tears the driver down outside every lock, and
    /// notifies each subscribed peer once. The feed re-arms from the next book
    /// poll.
    pub fn provider_lost(&self) {
        self.up.swap(false, Ordering::SeqCst);
        let cleared = {
            let mut established = match self.established.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let entries: Vec<EstablishedRelay> = established
                .drain()
                .map(|(_, v)| v.released_because("provider-lost"))
                .collect();
            entries.len()
        };
        // `EstablishedRelay` values were dropped when the drain result went out
        // of scope above — which is still inside this function but outside the
        // `established` lock. Driver Shutdown + join therefore never runs while
        // holding a provider lock.
        let peers = self.live_subscribed_peers();
        if !peers.is_empty() {
            if let Ok(mut sinks) = self.sinks.lock() {
                for peer in &peers {
                    if let Some(list) = sinks.get(&peer.0) {
                        for weak in list.iter() {
                            if let Some(sink) = weak.upgrade() {
                                sink.on_relay_lost(*peer);
                            }
                        }
                    }
                }
                for peer in &peers {
                    prune_peer(&mut sinks, &peer.0);
                }
            }
        }
        eprintln!("[nat-relay] provider_lost peers={cleared}");
    }

    /// Live subscribed peers (prunes dead weak entries).
    fn live_subscribed_peers(&self) -> Vec<FabricPeerId> {
        let mut out = Vec::new();
        if let Ok(mut g) = self.sinks.lock() {
            let peers: Vec<[u8; 32]> = g.keys().copied().collect();
            for peer in peers {
                if prune_peer(&mut g, &peer) > 0 {
                    out.push(FabricPeerId(peer));
                }
            }
        }
        out.sort_by_key(|a| a.0);
        out
    }
}

impl TurnRelayProvider {
    /// Clone of the established relay for `peer`, if any.
    pub fn established_relay(&self, peer: &FabricPeerId) -> Option<RelayConn> {
        match self.established.lock() {
            Ok(g) => g.get(&peer.0).map(|e| e.conn.clone()),
            Err(e) => e.into_inner().get(&peer.0).map(|e| e.conn.clone()),
        }
    }

    /// Peers holding the relay slot (always <= 1; ascending for determinism).
    pub fn established_peers(&self) -> Vec<FabricPeerId> {
        let mut out: Vec<FabricPeerId> = match self.established.lock() {
            Ok(g) => g.keys().map(|k| FabricPeerId(*k)).collect(),
            Err(e) => e.into_inner().keys().map(|k| FabricPeerId(*k)).collect(),
        };
        out.sort_by_key(|a| a.0);
        out
    }

    /// Live sink count for one peer (prunes dead entries first).
    pub fn sink_count(&self, peer: &FabricPeerId) -> usize {
        match self.sinks.lock() {
            Ok(mut g) => prune_peer(&mut g, &peer.0),
            Err(_) => 0,
        }
    }

    /// Peers with at least one live sink (prunes dead entries first).
    pub fn subscribed_peers(&self) -> Vec<FabricPeerId> {
        self.live_subscribed_peers()
    }
}

impl RelayConnProvider for TurnRelayProvider {
    fn subscribe(&self, peer: FabricPeerId, sink: Arc<dyn RelayConnSink>) {
        if let Ok(mut g) = self.sinks.lock() {
            let weak = Arc::downgrade(&sink);
            let list = g.entry(peer.0).or_default();
            // Same `Arc` subscribed twice for the same peer must not duplicate
            // deliveries.
            if list.iter().any(|existing| Weak::ptr_eq(existing, &weak)) {
                return;
            }
            list.push(weak);
        }
    }

    /// Explicit unsubscribe (spec §4.6.1).
    ///
    /// Lock order is `sinks` and then, only after releasing it, `established`.
    /// When the last sink for a peer goes away the relay slot is released: the
    /// `EstablishedRelay` is taken out and dropped **outside** both locks, so
    /// the driver teardown (Shutdown + join) never runs under a lock.
    fn unsubscribe(&self, peer: FabricPeerId, sink: &Arc<dyn RelayConnSink>) {
        let live = {
            let Ok(mut sinks) = self.sinks.lock() else {
                return;
            };
            if let Some(list) = sinks.get_mut(&peer.0) {
                let target = Arc::downgrade(sink);
                list.retain(|w| !Weak::ptr_eq(w, &target));
            }
            prune_peer(&mut sinks, &peer.0)
        };
        if live == 0 {
            let taken = match self.established.lock() {
                Ok(mut g) => g.remove(&peer.0),
                Err(e) => e.into_inner().remove(&peer.0),
            }
            .map(|old| old.released_because("unsubscribe"));
            drop(taken);
        }
    }

    fn established_relay(&self, peer: &FabricPeerId) -> Option<RelayConn> {
        TurnRelayProvider::established_relay(self, peer)
    }

    fn established_peers(&self) -> Vec<FabricPeerId> {
        TurnRelayProvider::established_peers(self)
    }

    fn subscribed_peers(&self) -> Vec<FabricPeerId> {
        TurnRelayProvider::subscribed_peers(self)
    }

    fn sink_count(&self, peer: &FabricPeerId) -> usize {
        TurnRelayProvider::sink_count(self, peer)
    }
}

impl RelayTrigger for TurnRelayProvider {
    fn established_relay_addr(&self, peer: &FabricPeerId) -> Option<SocketAddr> {
        self.established_relay(peer).map(|c| c.relayed)
    }

    fn established_peer_ids(&self) -> Vec<FabricPeerId> {
        self.established_peers()
    }

    fn trigger_relay(
        &self,
        peer: FabricPeerId,
        peer_relayed: SocketAddr,
    ) -> Result<SocketAddr, RelayError> {
        self.on_turn_allocated(peer, peer_relayed)
            .map(|conn| conn.relayed)
    }
}

/// Dispatch `on_relay_available` to one peer's live sinks while holding the
/// sink lock (spec §4.5 callback constraint: sink implementations must not call
/// back into the provider), then prune dead entries.
fn dispatch_available(sinks: &Mutex<SinkMap>, peer: &FabricPeerId, conn: &RelayConn) {
    let info = RelayInfo {
        peer: *peer,
        conn: conn.conn.clone(),
        relayed: conn.relayed,
        kind: conn.kind,
    };
    if let Ok(mut g) = sinks.lock() {
        if let Some(list) = g.get(&peer.0) {
            for weak in list.iter() {
                if let Some(sink) = weak.upgrade() {
                    sink.on_relay_available(info.clone());
                }
            }
        }
        prune_peer(&mut g, &peer.0);
    }
}

/// Subscription handle owned by the consumer (feed).
///
/// Both edges are weak: the guard never keeps the provider or the sink alive,
/// so it cannot create a cycle. Dropping it is the explicit unsubscribe path
/// (spec §4.6.2); if either side is already gone the drop is silent and the
/// provider's weak table prunes itself on the next dispatch.
pub struct RelaySubscriptionGuard {
    provider: Weak<dyn RelayConnProvider>,
    peer: FabricPeerId,
    sink: Weak<dyn RelayConnSink>,
}

impl RelaySubscriptionGuard {
    pub(crate) fn new(
        provider: Weak<dyn RelayConnProvider>,
        peer: FabricPeerId,
        sink: Weak<dyn RelayConnSink>,
    ) -> Self {
        Self {
            provider,
            peer,
            sink,
        }
    }

    /// The peer this subscription belongs to.
    pub fn peer(&self) -> FabricPeerId {
        self.peer
    }

    /// Whether both ends are still alive.
    pub fn is_active(&self) -> bool {
        self.provider.strong_count() > 0 && self.sink.strong_count() > 0
    }
}

impl Drop for RelaySubscriptionGuard {
    fn drop(&mut self) {
        let (Some(provider), Some(sink)) = (self.provider.upgrade(), self.sink.upgrade()) else {
            return;
        };
        provider.unsubscribe(self.peer, &sink);
    }
}

/// Directory-backed address book: one `<64 lowercase hex>.addr` file per node.
///
/// INTERIM cross-host channel (CR-BLOCKED-2 Option A): it requires a shared
/// file system between the nodes. `publish` writes a temp file in the same
/// directory and renames it, so readers never observe a half-written entry;
/// `reload` ignores malformed files (one WARN per file and process) instead of
/// failing the whole snapshot.
pub struct DirRelayAddressBook {
    dir: PathBuf,
    self_peer: [u8; 32],
    entries: Mutex<HashMap<[u8; 32], SocketAddr>>,
    /// Files already warned about (no per-poll log storm).
    warned: Mutex<std::collections::HashSet<PathBuf>>,
}

impl DirRelayAddressBook {
    pub fn new(dir: impl Into<PathBuf>, self_peer: [u8; 32]) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let book = Self {
            dir,
            self_peer,
            entries: Mutex::new(HashMap::new()),
            warned: Mutex::new(std::collections::HashSet::new()),
        };
        book.reload()?;
        Ok(book)
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    fn entry_path(&self, peer: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.addr", hex32(peer)))
    }

    /// Strict filename decode: 64 chars, lowercase hex only.
    fn parse_file_stem(stem: &str) -> Option<[u8; 32]> {
        if stem.len() != 64 {
            return None;
        }
        let bytes = stem.as_bytes();
        if !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return None;
        }
        parse_hex32(stem).ok()
    }

    fn warn_once(&self, path: &Path, reason: &str) {
        let first = match self.warned.lock() {
            Ok(mut set) => set.insert(path.to_path_buf()),
            Err(e) => e.into_inner().insert(path.to_path_buf()),
        };
        if first {
            eprintln!(
                "[nat-relay] WARN: ignoring relay book file {} ({reason})",
                path.display()
            );
        }
    }
}

impl RelayAddressBook for DirRelayAddressBook {
    fn relay_addr(&self, peer: &[u8; 32]) -> Option<SocketAddr> {
        self.entries.lock().ok()?.get(peer).copied()
    }

    fn entry_count(&self) -> Option<usize> {
        self.entries.lock().ok().map(|g| g.len())
    }

    fn reload(&self) -> io::Result<()> {
        let mut map = HashMap::new();
        let rd = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A missing directory is an empty book, not an error.
                *self.entries.lock().unwrap() = map;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("addr") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                self.warn_once(&path, "non-utf8 file name");
                continue;
            };
            let Some(peer) = Self::parse_file_stem(stem) else {
                self.warn_once(&path, "file name is not 64 lowercase hex");
                continue;
            };
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    self.warn_once(&path, &format!("read failed: {e}"));
                    continue;
                }
            };
            match text.trim().parse::<SocketAddr>() {
                Ok(addr) => {
                    map.insert(peer, addr);
                }
                Err(_) => self.warn_once(&path, "content is not a socket address"),
            }
        }
        *self.entries.lock().unwrap() = map;
        Ok(())
    }

    fn publish(&self, peer: [u8; 32], addr: SocketAddr) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let path = self.entry_path(&peer);
        let tmp = self
            .dir
            .join(format!("{}.addr.tmp.{}", hex32(&peer), std::process::id()));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(
                format!(
                    "{addr}
"
                )
                .as_bytes(),
            )?;
            f.sync_all()?;
        }
        // Atomic replace inside one directory: readers see old or new content.
        fs::rename(&tmp, &path)?;
        if peer == self.self_peer {
            // Keep our own entry visible even if this node never reloads.
            self.entries
                .lock()
                .map_err(|_| io::Error::other("book lock poisoned"))?
                .insert(peer, addr);
        }
        Ok(())
    }
}

/// Identity seed loading with explicit 0600 enforcement and PeerId assertion.
pub fn load_seed_file(path: &Path) -> Result<[u8; 32], RelayError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(RelayError::Io)?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(RelayError::Identity(format!(
                "seed file {} must be 0600 (found {mode:o})",
                path.display()
            )));
        }
    }
    let text = fs::read_to_string(path).map_err(RelayError::Io)?;
    let hex = text.trim();
    parse_hex32(hex).map_err(|_| {
        RelayError::Identity(format!("seed file {} is not 64 hex chars", path.display()))
    })
}

/// Derive a `FabricIdentity` from a seed and assert it matches `expected`.
pub fn identity_from_seed(
    seed: [u8; 32],
    expected: FabricPeerId,
) -> Result<FabricIdentity, RelayError> {
    let identity = FabricIdentity::from_ed25519_seed(seed)
        .map_err(|e| RelayError::Identity(format!("{e:?}")))?;
    if identity.peer_id() != expected {
        return Err(RelayError::Identity(format!(
            "identity mismatch: derived {} != configured {}",
            hex32(&identity.peer_id().0),
            hex32(&expected.0)
        )));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TurnSection;
    use crate::nat_switch::{NatSwitching, gather_host_candidates};
    use crate::nat_turn::TurnHandle;
    use nexus_domain::nat::NatType;
    use nexus_nat_traversal::LocalCandidates;
    use nexus_nat_wireup::SystemPunchClock;
    use nexus_turn::client::{TurnClient, TurnCredentials};
    use nexus_turn::server::TurnServer;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::mpsc;

    struct Sink(mpsc::Sender<RelayInfo>);
    impl RelayConnSink for Sink {
        fn on_relay_available(&self, info: RelayInfo) {
            let _ = self.0.send(info);
        }
        fn on_relay_lost(&self, _peer: FabricPeerId) {}
    }

    fn creds() -> TurnCredentials {
        TurnCredentials {
            username: "nexus".into(),
            password: "test-secret".into(),
            realm: "nexus".into(),
        }
    }

    #[test]
    fn g13_relay_provider_triggers_punch() {
        if std::net::UdpSocket::bind("127.0.0.2:0").is_err() {
            eprintln!("SKIP: 127.0.0.2 not bindable in this environment");
            return;
        }
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let section = TurnSection {
            server: server.main_addr().to_string(),
            realm: "nexus".into(),
            username: "nexus".into(),
            password: "test-secret".into(),
            refresh_interval_sec: 300,
            stun_server: None,
            stun_server2: None,
            bind_addr: "127.0.0.2:0".into(),
            relay_book_dir: None,
        };
        let id_a = FabricIdentity::from_ed25519_seed([1; 32]).unwrap();
        let id_b = FabricIdentity::from_ed25519_seed([2; 32]).unwrap();
        let a_id = id_a.peer_id();
        let b_id = id_b.peer_id();

        let book_path = std::env::temp_dir().join(format!(
            "nexus-relay-book-{}-{}.toml",
            std::process::id(),
            a_id.0[0]
        ));
        let book = Arc::new(FileRelayAddressBook::new(&book_path).unwrap());

        let mut ta = TurnManager::new(Some(section.clone()));
        let mut tb = TurnManager::new(Some(section));
        let relayed_a = ta.ensure_allocated().expect("allocate a");
        let relayed_b = tb.ensure_allocated().expect("allocate b");
        book.publish(a_id.0, relayed_a).unwrap();
        book.publish(b_id.0, relayed_b).unwrap();

        let pa = TurnRelayProvider::new(a_id, id_a, ta, book.clone());
        let pb = TurnRelayProvider::new(b_id, id_b, tb, book.clone());
        let (txa, rxa) = mpsc::channel();
        let (txb, rxb) = mpsc::channel();
        // O9: the sink map holds `Weak` edges, so the owner keeps the sink
        // alive for the duration of the subscription.
        let sink_a = Arc::new(Sink(txa));
        let sink_b = Arc::new(Sink(txb));
        pa.subscribe(b_id, sink_a.clone());
        pb.subscribe(a_id, sink_b.clone());

        let ha = {
            let pa = pa.clone();
            std::thread::spawn(move || pa.on_turn_allocated(b_id, relayed_b))
        };
        let hb = {
            let pb = pb.clone();
            std::thread::spawn(move || pb.on_turn_allocated(a_id, relayed_a))
        };
        let ra = hb.join().expect("join b");
        let rb = ha.join().expect("join a");
        assert!(ra.is_ok(), "provider side A failed: {:?}", ra.err());
        assert!(rb.is_ok(), "provider side B failed: {:?}", rb.err());
        let got_a = rxa.recv_timeout(Duration::from_secs(2));
        let got_b = rxb.recv_timeout(Duration::from_secs(2));
        assert!(got_a.is_ok(), "sink on A not fed");
        assert!(got_b.is_ok(), "sink on B not fed");
        assert_eq!(got_a.unwrap().kind, RelayKind::Turn);
        // P3-AC6(iii): both provider allocations used the configured loopback
        // bind and reached Active through the production ensure path.
        for (label, p) in [("a", &pa), ("b", &pb)] {
            let turn = p.turn.lock().unwrap();
            assert_eq!(
                turn.mapped_addr().expect("mapped addr").ip(),
                "127.0.0.2".parse::<std::net::IpAddr>().unwrap(),
                "provider {label} mapped ip"
            );
            assert_eq!(
                turn.health(),
                crate::nat_turn::TurnHealth::Active,
                "provider {label} health"
            );
        }
        drop(sink_a);
        drop(sink_b);
        let _ = std::fs::remove_file(&book_path);
    }

    #[test]
    fn identity_seed_mismatch_is_fail_closed() {
        let id = FabricIdentity::from_ed25519_seed([9; 32]).unwrap();
        let wrong = FabricPeerId([0xAA; 32]);
        let err = identity_from_seed([9; 32], wrong).unwrap_err();
        assert!(matches!(err, RelayError::Identity(_)));
        assert_eq!(
            identity_from_seed([9; 32], id.peer_id()).unwrap().peer_id(),
            id.peer_id()
        );
    }

    #[test]
    fn seed_file_requires_0600() {
        let path = std::env::temp_dir().join(format!("nexus-seed-test-{}", std::process::id()));
        std::fs::write(
            &path,
            [7u8; 32]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(matches!(
            load_seed_file(&path),
            Err(RelayError::Identity(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(load_seed_file(&path).unwrap(), [7u8; 32]);
        let _ = std::fs::remove_file(&path);
    }

    /// D5 loopback acceptance (O5): the PRODUCTION sink, not the g13 test
    /// Sink. Two switches + two providers over one loopback TURN server:
    /// provider event -> `NatSwitching::on_relay_available` ->
    /// `on_relay_connected(auto_punch: true)` must register the relay on
    /// both switches. `on_relay_lost` must leave the relay registered
    /// (state only, no close, no punch). This is the new wiring evidence
    /// for AC-13's `production_trigger_path` -- it replaces the g13 lib
    /// test as evidence, and it is NOT device evidence (row stays
    /// ENV_NOT_READY until the V-section runs).
    #[test]
    fn d5_production_sink_triggers_on_relay_connected() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let c = creds();
        let section = TurnSection {
            server: server.main_addr().to_string(),
            realm: c.realm,
            username: c.username,
            password: c.password,
            refresh_interval_sec: 300,
            stun_server: None,
            stun_server2: None,
            bind_addr: "0.0.0.0:0".into(),
            relay_book_dir: None,
        };
        let id_a = FabricIdentity::from_ed25519_seed([1; 32]).unwrap();
        let id_b = FabricIdentity::from_ed25519_seed([2; 32]).unwrap();
        let a_id = id_a.peer_id();
        let b_id = id_b.peer_id();

        let book_path = std::env::temp_dir().join(format!(
            "nexus-relay-book-d5-{}-{:02x}.toml",
            std::process::id(),
            a_id.0[0]
        ));
        let book = Arc::new(FileRelayAddressBook::new(&book_path).unwrap());

        let mut ta = TurnManager::new(Some(section.clone()));
        let mut tb = TurnManager::new(Some(section));
        let relayed_a = ta.ensure_allocated().expect("allocate a");
        let relayed_b = tb.ensure_allocated().expect("allocate b");
        book.publish(a_id.0, relayed_a).unwrap();
        book.publish(b_id.0, relayed_b).unwrap();

        let pa = TurnRelayProvider::new(a_id, id_a, ta, book.clone());
        let pb = TurnRelayProvider::new(b_id, id_b, tb, book.clone());

        let driver_a = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind a");
        let driver_b = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind b");
        let driver_c = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind c");
        let local_a = LocalCandidates {
            host: gather_host_candidates(&driver_a),
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: NatType::Unknown,
        };
        let local_b = LocalCandidates {
            host: gather_host_candidates(&driver_b),
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: NatType::Unknown,
        };
        let local_c = LocalCandidates {
            host: gather_host_candidates(&driver_c),
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: NatType::Unknown,
        };
        let swa = NatSwitching::new(
            driver_a,
            a_id,
            local_a,
            Vec::new(),
            Arc::new(SystemPunchClock::new()),
        );
        let swb = NatSwitching::new(
            driver_b,
            b_id,
            local_b,
            Vec::new(),
            Arc::new(SystemPunchClock::new()),
        );
        let swc = NatSwitching::new(
            driver_c,
            a_id,
            local_c,
            Vec::new(),
            Arc::new(SystemPunchClock::new()),
        );

        // Fail-closed: subscribing with no provider attached refuses.
        assert!(swc.subscribe_relay_peer(a_id).is_none());

        swa.attach_relay_provider(pa.clone());
        swb.attach_relay_provider(pb.clone());
        let guard_a = swa.subscribe_relay_peer(b_id).expect("subscribe a");
        let guard_b = swb.subscribe_relay_peer(a_id).expect("subscribe b");

        let ha = {
            let pa = pa.clone();
            std::thread::spawn(move || pa.on_turn_allocated(b_id, relayed_b))
        };
        let hb = {
            let pb = pb.clone();
            std::thread::spawn(move || pb.on_turn_allocated(a_id, relayed_a))
        };
        let ra = hb.join().expect("join b");
        let rb = ha.join().expect("join a");
        assert!(ra.is_ok(), "provider side B failed: {:?}", ra.err());
        assert!(rb.is_ok(), "provider side A failed: {:?}", rb.err());

        // Production trigger delivered: each switch registered the peer's
        // relay (synchronous in on_relay_available, so no polling needed).
        let hex_a: String = a_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let hex_b: String = b_id.0.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            swa.active_conn(&hex_b).is_some(),
            "A's switch must have B's relay registered via production sink"
        );
        assert!(
            swb.active_conn(&hex_a).is_some(),
            "B's switch must have A's relay registered via production sink"
        );

        // on_relay_lost is state only: relay stays, no punch triggered.
        RelayConnSink::on_relay_lost(swa.as_ref(), b_id);
        assert!(
            swa.active_conn(&hex_b).is_some(),
            "lost must not close the relay"
        );
        assert!(
            swa.relay_lost_peers().contains(&b_id),
            "lost peer must be recorded"
        );

        drop(guard_a);
        drop(guard_b);
        swa.shutdown();
        swb.shutdown();
        swc.shutdown();
        let _ = std::fs::remove_file(&book_path);
    }

    // ---------- shared fixtures ----------

    /// In-memory address book (no file, no shared directory).
    #[derive(Default)]
    struct FakeBook {
        entries: Mutex<HashMap<[u8; 32], SocketAddr>>,
    }

    impl FakeBook {
        fn set(&self, peer: [u8; 32], addr: SocketAddr) {
            self.entries.lock().unwrap().insert(peer, addr);
        }
    }

    impl RelayAddressBook for FakeBook {
        fn relay_addr(&self, peer: &[u8; 32]) -> Option<SocketAddr> {
            self.entries.lock().unwrap().get(peer).copied()
        }
        fn reload(&self) -> io::Result<()> {
            Ok(())
        }
        fn publish(&self, peer: [u8; 32], addr: SocketAddr) -> io::Result<()> {
            self.set(peer, addr);
            Ok(())
        }
    }

    /// Sink that only counts deliveries (no channel, no blocking).
    #[derive(Default)]
    struct CountingSink {
        available: AtomicUsize,
        lost: AtomicUsize,
        lost_peers: Mutex<Vec<FabricPeerId>>,
    }

    impl CountingSink {
        fn available(&self) -> usize {
            self.available.load(AtomicOrdering::SeqCst)
        }
        fn lost(&self) -> usize {
            self.lost.load(AtomicOrdering::SeqCst)
        }
    }

    impl RelayConnSink for CountingSink {
        fn on_relay_available(&self, _info: RelayInfo) {
            self.available.fetch_add(1, AtomicOrdering::SeqCst);
        }
        fn on_relay_lost(&self, peer: FabricPeerId) {
            self.lost.fetch_add(1, AtomicOrdering::SeqCst);
            self.lost_peers.lock().unwrap().push(peer);
        }
    }

    fn provider_without_turn(identity_seed: u8, book: Arc<FakeBook>) -> Arc<TurnRelayProvider> {
        let identity = FabricIdentity::from_ed25519_seed([identity_seed; 32]).unwrap();
        let my_id = identity.peer_id();
        TurnRelayProvider::new(my_id, identity, TurnManager::new(None), book)
    }

    /// Datagram send on a bare `ConnShared` (the same command path
    /// `FabricConn::send_datagram` uses).
    fn send_dgram(conn: &Arc<ConnShared>, data: &[u8]) -> Result<(), nexus_fabric::FabricError> {
        let (tx, rx) = mpsc::channel();
        conn.tx
            .send(nexus_fabric::Cmd::SendDatagram {
                conn: conn.id.0,
                data: data.to_vec(),
                reply: tx,
            })
            .map_err(|_| nexus_fabric::FabricError::Closed(0))?;
        rx.recv()
            .map_err(|_| nexus_fabric::FabricError::Closed(0))?
    }

    /// Blocking datagram receive on a bare `ConnShared`.
    fn recv_dgram(conn: &Arc<ConnShared>) -> Result<Vec<u8>, nexus_fabric::FabricError> {
        let mut q = conn.dgrams.lock().unwrap();
        loop {
            if let Some(d) = q.pop_front() {
                return Ok(d);
            }
            if let Some(e) = conn.state.lock().unwrap().closed.clone() {
                return Err(e);
            }
            q = conn
                .dgram_cv
                .wait(q)
                .map_err(|_| nexus_fabric::FabricError::Transport("lock poisoned".into()))?;
        }
    }

    fn local_candidates(driver: &Arc<Driver>) -> LocalCandidates {
        LocalCandidates {
            host: gather_host_candidates(driver),
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: NatType::Unknown,
        }
    }

    fn switch(my_id: FabricPeerId) -> Arc<NatSwitching> {
        let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind");
        let local = local_candidates(&driver);
        NatSwitching::new(
            driver,
            my_id,
            local,
            Vec::new(),
            Arc::new(SystemPunchClock::new()),
        )
    }

    // ---------- AC5: O9 evidence ----------

    #[test]
    fn o9_weak_sink_pruned_after_drop() {
        let book = Arc::new(FakeBook::default());
        let provider = provider_without_turn(7, book);
        let peer = FabricPeerId([0x01; 32]);
        let sink = Arc::new(CountingSink::default());
        provider.subscribe(peer, sink.clone());
        assert_eq!(provider.sink_count(&peer), 1);
        assert_eq!(provider.subscribed_peers(), vec![peer]);
        drop(sink);
        // The weak edge is pruned on the next read.
        assert_eq!(provider.sink_count(&peer), 0);
        assert!(provider.subscribed_peers().is_empty());
    }

    #[test]
    fn o9_guard_drop_unsubscribes() {
        let book = Arc::new(FakeBook::default());
        let provider = provider_without_turn(8, book);
        let peer = provider.my_id();
        let sw = switch(FabricPeerId([0x02; 32]));
        sw.attach_relay_provider(provider.clone());
        let guard = sw.subscribe_relay_peer(peer).expect("guard");
        assert_eq!(provider.sink_count(&peer), 1);
        assert_eq!(guard.peer(), peer);
        assert!(guard.is_active());
        assert_eq!(sw.relay_subscribed_peers(), vec![peer]);
        drop(guard);
        assert_eq!(provider.sink_count(&peer), 0);
        assert!(sw.relay_subscribed_peers().is_empty());
        sw.shutdown();
    }

    #[test]
    fn o9_no_cycle_after_shutdown() {
        let book = Arc::new(FakeBook::default());
        let provider = provider_without_turn(9, book);
        let peer = provider.my_id();
        let sw = switch(FabricPeerId([0x03; 32]));
        sw.attach_relay_provider(provider.clone());
        let guard = sw.subscribe_relay_peer(peer).expect("guard");
        let weak = Arc::downgrade(&sw);
        sw.shutdown();
        drop(guard);
        drop(sw);
        // No NatSwitching -> provider -> NatSwitching cycle keeps the stack alive.
        assert!(weak.upgrade().is_none());
        // The provider is still usable after the subscriber disappeared.
        assert_eq!(provider.sink_count(&peer), 0);
    }

    // ---------- AC11: provider_lost ----------

    #[test]
    fn provider_lost_notifies_all_subscribed() {
        let book = Arc::new(FakeBook::default());
        let provider = provider_without_turn(10, book);
        let peer_a = FabricPeerId([0x0a; 32]);
        let peer_b = FabricPeerId([0x0b; 32]);
        let sink_a = Arc::new(CountingSink::default());
        let sink_b = Arc::new(CountingSink::default());
        provider.subscribe(peer_a, sink_a.clone());
        provider.subscribe(peer_b, sink_b.clone());
        provider.provider_lost();
        assert_eq!(sink_a.lost(), 1);
        assert_eq!(sink_b.lost(), 1);
        assert_eq!(sink_a.lost_peers.lock().unwrap().as_slice(), &[peer_a]);
        assert_eq!(sink_b.lost_peers.lock().unwrap().as_slice(), &[peer_b]);
    }

    #[test]
    fn ensure_failure_marks_lost() {
        let book = Arc::new(FakeBook::default());
        // No `[network.turn]`: ensure_allocated fails immediately.
        let provider = provider_without_turn(11, book);
        let peer = FabricPeerId([0x0c; 32]);
        let sink = Arc::new(CountingSink::default());
        provider.subscribe(peer, sink.clone());
        let err = match provider.on_turn_allocated(peer, "127.0.0.1:5000".parse().unwrap()) {
            Ok(_) => panic!("allocation must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, RelayError::Turn(_)));
        assert_eq!(sink.lost(), 1, "provider_lost must notify subscribers");
        assert!(provider.established_peers().is_empty());
    }

    struct StaleNonceHandle;

    impl TurnHandle for StaleNonceHandle {
        fn refresh(&self) -> io::Result<()> {
            Err(io::Error::other(
                "turn refresh: unexpected response 0x0438 438 Stale Nonce",
            ))
        }
        fn release(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn relayed_addr(&self) -> SocketAddr {
            "127.0.0.1:5002".parse().unwrap()
        }
        fn mapped_addr(&self) -> Option<SocketAddr> {
            None
        }
        fn is_expired(&self) -> bool {
            false
        }
        fn as_turn_client(&self) -> Option<TurnClient> {
            None
        }
    }

    #[test]
    fn refresh_expiry_marks_lost() {
        let book = Arc::new(FakeBook::default());
        let identity = FabricIdentity::from_ed25519_seed([12; 32]).unwrap();
        let my_id = identity.peer_id();
        // Active with a stale-nonce failure and a dead factory: the refresh
        // path degrades the manager to Disabled in one call (Active -> Disabled
        // is part of the frozen Lost transition).
        let turn = TurnManager::test_seam(
            TurnState::Active,
            Some(Box::new(StaleNonceHandle)),
            Some(std::time::Instant::now()),
        );
        let provider = TurnRelayProvider::new(my_id, identity, turn, book);
        let peer = FabricPeerId([0x0d; 32]);
        let sink = Arc::new(CountingSink::default());
        provider.subscribe(peer, sink.clone());
        assert_eq!(provider.refresh(), RelayRefresh::Lost);
        assert_eq!(sink.lost(), 1);
        // A busy/absent refresh never blocks: the second call is not due.
        assert_eq!(provider.refresh(), RelayRefresh::NotDue);
    }

    // ---------- AC12: self-publish + single slot ----------

    fn turn_section(server: SocketAddr) -> TurnSection {
        TurnSection {
            server: server.to_string(),
            realm: "nexus".into(),
            username: "nexus".into(),
            password: "test-secret".into(),
            refresh_interval_sec: 300,
            stun_server: None,
            stun_server2: None,
            bind_addr: "0.0.0.0:0".into(),
            relay_book_dir: None,
        }
    }

    #[test]
    fn self_publish_uses_provider_allocation() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let section = turn_section(server.main_addr());
        let id = FabricIdentity::from_ed25519_seed([1; 32]).unwrap();
        let my_id = id.peer_id();

        // Runtime's warm-backup allocation is published first (the shipped
        // double-publish bug); the provider must overwrite it with its own.
        let mut runtime = TurnManager::new(Some(section.clone()));
        let runtime_relayed = runtime.ensure_allocated().expect("runtime allocate");
        let book = Arc::new(FakeBook::default());
        book.publish(my_id.0, runtime_relayed).unwrap();

        let provider =
            TurnRelayProvider::new(my_id, id, TurnManager::new(Some(section)), book.clone());
        let relayed = provider.ensure_relay_ready().expect("provider allocate");
        assert_eq!(book.relay_addr(&my_id.0), Some(relayed));
        assert_ne!(
            relayed, runtime_relayed,
            "provider and runtime allocations are distinct sockets"
        );
    }

    #[test]
    fn single_relay_slot_and_driver_retention() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let section = turn_section(server.main_addr());
        let book = Arc::new(FakeBook::default());

        let id_a = FabricIdentity::from_ed25519_seed([1; 32]).unwrap();
        let id_b = FabricIdentity::from_ed25519_seed([2; 32]).unwrap();
        let id_c = FabricIdentity::from_ed25519_seed([3; 32]).unwrap();
        let a_id = id_a.peer_id();
        let b_id = id_b.peer_id();
        let c_id = id_c.peer_id();

        let mut ta = TurnManager::new(Some(section.clone()));
        let mut tb = TurnManager::new(Some(section.clone()));
        let relayed_a = ta.ensure_allocated().expect("allocate a");
        let relayed_b = tb.ensure_allocated().expect("allocate b");
        let pa = TurnRelayProvider::new(a_id, id_a, ta, book.clone());
        let pb = TurnRelayProvider::new(b_id, id_b, tb, book.clone());
        let sink_a = Arc::new(CountingSink::default());
        pa.subscribe(b_id, sink_a.clone());

        // --- item 2/3: establish one relay, keep the driver alive ---
        let ha = {
            let pa = pa.clone();
            std::thread::spawn(move || pa.on_turn_allocated(b_id, relayed_b))
        };
        let hb = {
            let pb = pb.clone();
            std::thread::spawn(move || pb.on_turn_allocated(a_id, relayed_a))
        };
        ha.join().expect("join a").expect("relay a");
        hb.join().expect("join b").expect("relay b");
        assert_eq!(pa.established_peers(), vec![b_id]);
        assert_eq!(sink_a.available(), 1);
        assert_eq!(
            pa.established_relay(&b_id).expect("established").relayed,
            relayed_b
        );

        // A datagram must cross the relay after `on_turn_allocated` returned:
        // this is the driver-retention proof.
        let a_conn = pa.established_relay(&b_id).unwrap().conn;
        let b_conn = pb.established_relay(&a_id).unwrap().conn;
        let (tx, rx) = mpsc::channel();
        let receiver = std::thread::spawn(move || {
            let _ = tx.send(recv_dgram(&b_conn));
        });
        send_dgram(&a_conn, b"relay-ping").expect("send datagram");
        let got = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("datagram must arrive over the retained driver");
        assert_eq!(got.expect("datagram payload"), b"relay-ping");
        receiver.join().expect("receiver thread");

        // --- item 2: another peer is rejected with Capacity ---
        let err = match pa.on_turn_allocated(c_id, relayed_b) {
            Ok(_) => panic!("slot is busy"),
            Err(e) => e,
        };
        assert!(matches!(err, RelayError::Capacity(_)));
        assert_eq!(pa.established_peers(), vec![b_id]);

        // --- item 4: same peer, new relayed address replaces the slot ---
        // The peer is staggered so our replacement listener is up before its
        // dial arrives; otherwise the outgoing listener can still accept the
        // newcomer and be torn down under it (the retry path the feed owns).
        let id_b2 = FabricIdentity::from_ed25519_seed([4; 32]).unwrap();
        let mut tb2 = TurnManager::new(Some(section.clone()));
        let relayed_b2 = tb2.ensure_allocated().expect("allocate b2");
        let pb2 = TurnRelayProvider::new(b_id, id_b2, tb2, book.clone());
        let h1 = {
            let pa = pa.clone();
            std::thread::spawn(move || pa.on_turn_allocated(b_id, relayed_b2))
        };
        std::thread::sleep(Duration::from_millis(150));
        let h2 = {
            let pb2 = pb2.clone();
            std::thread::spawn(move || pb2.on_turn_allocated(a_id, relayed_a))
        };
        let ra = h1.join().expect("join replace a");
        let rb = h2.join().expect("join replace b2");
        assert!(ra.is_ok(), "replace a failed: {:?}", ra.err());
        assert!(rb.is_ok(), "replace b2 failed: {:?}", rb.err());
        assert_eq!(pa.established_peers(), vec![b_id]);
        assert_eq!(
            pa.established_relay(&b_id).unwrap().relayed,
            relayed_b2,
            "the slot must carry the new peer address"
        );

        // --- item 5: zero sinks releases the slot for another peer ---
        assert_eq!(pa.sink_count(&b_id), 1);
        pb2.subscribe(a_id, Arc::new(CountingSink::default()));
        // Drop the last sink through the explicit unsubscribe path.
        {
            let sink: Arc<dyn RelayConnSink> = sink_a.clone();
            pa.unsubscribe(b_id, &sink);
        }
        assert_eq!(pa.sink_count(&b_id), 0);
        assert!(pa.established_peers().is_empty(), "slot released");

        let mut tc = TurnManager::new(Some(section));
        let relayed_c = tc.ensure_allocated().expect("allocate c");
        let pc = TurnRelayProvider::new(c_id, id_c, tc, book);
        let sink_c = Arc::new(CountingSink::default());
        pa.subscribe(c_id, sink_c.clone());
        let h3 = {
            let pa = pa.clone();
            std::thread::spawn(move || pa.on_turn_allocated(c_id, relayed_c))
        };
        let h4 = {
            let pc = pc.clone();
            std::thread::spawn(move || pc.on_turn_allocated(a_id, relayed_a))
        };
        h3.join().expect("join c a").expect("relay c a");
        h4.join().expect("join c").expect("relay c");
        assert_eq!(pa.established_peers(), vec![c_id]);
        assert_eq!(sink_c.available(), 1);
    }

    // ---------- dir book ----------

    fn temp_book_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nexusd-relay-book-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn dir_book_publish_reload_roundtrip() {
        let dir = temp_book_dir("roundtrip");
        let self_peer = [0x11u8; 32];
        let other_peer = [0x22u8; 32];
        let addr: SocketAddr = "10.0.0.7:19010".parse().unwrap();
        {
            let book = DirRelayAddressBook::new(&dir, self_peer).unwrap();
            book.publish(self_peer, addr).unwrap();
            assert_eq!(book.relay_addr(&self_peer), Some(addr));
        }
        // A different node opening the same directory sees our entry, and can
        // reload a later change written by yet another node.
        let book = DirRelayAddressBook::new(&dir, other_peer).unwrap();
        assert_eq!(book.relay_addr(&self_peer), Some(addr));
        std::fs::write(
            dir.join(format!("{}.addr", hex32(&other_peer))),
            "10.0.0.8:1
",
        )
        .unwrap();
        book.reload().unwrap();
        assert_eq!(
            book.relay_addr(&other_peer),
            Some("10.0.0.8:1".parse().unwrap())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_book_ignores_malformed_files() {
        let dir = temp_book_dir("malformed");
        std::fs::create_dir_all(&dir).unwrap();
        let good = [0x33u8; 32];
        let upper = "AA".repeat(32);
        std::fs::write(dir.join(format!("{}.addr", hex32(&good))), "10.0.0.9:19010").unwrap();
        std::fs::write(dir.join("nothex.addr"), "10.0.0.9:19010").unwrap();
        std::fs::write(dir.join(format!("{upper}.addr")), "10.0.0.9:19010").unwrap();
        let bad_content = [0x44u8; 32];
        std::fs::write(dir.join(format!("{}.addr", hex32(&bad_content))), "nope").unwrap();
        std::fs::write(dir.join("ignored.txt"), "10.0.0.9:19010").unwrap();

        let book = DirRelayAddressBook::new(&dir, [0u8; 32]).unwrap();
        assert_eq!(
            book.relay_addr(&good),
            Some("10.0.0.9:19010".parse().unwrap())
        );
        assert!(book.relay_addr(&bad_content).is_none());
        // Uppercase names are not canonical ids: ignored, not folded.
        assert!(book.relay_addr(&[0xAAu8; 32]).is_none());
        // Reloading again must not resurrect them.
        book.reload().unwrap();
        assert!(book.relay_addr(&bad_content).is_none());

        // A missing directory is an empty book, not an error.
        let gone = temp_book_dir("gone");
        let book = DirRelayAddressBook::new(&gone, [0u8; 32]).unwrap();
        std::fs::remove_dir_all(&gone).unwrap();
        book.reload().unwrap();
        assert!(book.relay_addr(&good).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
