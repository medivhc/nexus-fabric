//! Production relay connections for NAT punch-through (AC-13).
//!
//! `TurnRelayProvider` allocates a TURN relay on the punch socket and feeds
//! `RelayConnSink`s with a `ConnShared` the punch manager can signal over.
//! Identity is **injected** (never random); seeding comes from the daemon's
//! `[network.identity].seed_file` (BLOCKED-1 ruling (a), see evidence).

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
}

impl Drop for EstablishedRelay {
    fn drop(&mut self) {
        // Observable teardown: the driver's Shutdown + join happens here, which
        // must never run while a provider lock is held.
        eprintln!(
            "[nat-relay] relay slot released peer={} anchor={}",
            &hex32(&self.conn.conn.peer.0)[..8],
            self.anchor_label()
        );
    }
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
                Ok(_) => turn.client(),
                Err(e) => {
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
            established.remove(&peer.0)
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
            let entries: Vec<EstablishedRelay> = established.drain().map(|(_, v)| v).collect();
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
        out.sort_by(|a, b| a.0.cmp(&b.0));
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
        out.sort_by(|a, b| a.0.cmp(&b.0));
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
            };
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
    use nexus_connectivity::nat::NatType;
    use nexus_nat_traversal::LocalCandidates;
    use nexus_nat_wireup::SystemPunchClock;
    use nexus_turn::client::TurnCredentials;
    use nexus_turn::server::TurnServer;
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
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
        let section = TurnSection {
            server: server.main_addr().to_string(),
            realm: "nexus".into(),
            username: "nexus".into(),
            password: "test-secret".into(),
            refresh_interval_sec: 300,
            stun_server: None,
            stun_server2: None,
            bind_addr: "0.0.0.0:0".into(),
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
        assert!(!swc.subscribe_relay_peer(a_id));

        swa.attach_relay_provider(pa.clone());
        swb.attach_relay_provider(pb.clone());
        assert!(swa.subscribe_relay_peer(b_id));
        assert!(swb.subscribe_relay_peer(a_id));

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

        swa.shutdown();
        swb.shutdown();
        swc.shutdown();
        let _ = std::fs::remove_file(&book_path);
    }
}
