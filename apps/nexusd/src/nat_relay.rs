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
use nexus_turn::client::TurnClient;
use nexus_turn::socket::TurnSocket;

use crate::nat_turn::TurnManager;

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
pub trait RelayConnProvider: Send + Sync {
    fn subscribe(&self, peer: FabricPeerId, sink: Arc<dyn RelayConnSink>);
}

#[derive(Debug)]
pub enum RelayError {
    Turn(String),
    Io(io::Error),
    Identity(String),
    AddressBook(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Turn(s) => write!(f, "turn: {s}"),
            RelayError::Io(e) => write!(f, "io: {e}"),
            RelayError::Identity(s) => write!(f, "identity: {s}"),
            RelayError::AddressBook(s) => write!(f, "address book: {s}"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<io::Error> for RelayError {
    fn from(e: io::Error) -> Self {
        RelayError::Io(e)
    }
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

/// Production TURN relay provider.
pub struct TurnRelayProvider {
    my_id: FabricPeerId,
    identity: FabricIdentity,
    turn: Mutex<TurnManager>,
    book: Arc<dyn RelayAddressBook>,
    sinks: Mutex<SinkMap>,
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

    /// Frozen steps 1–6: allocate → address book → permission → bind/connect
    /// with the injected identity → notify every sink.
    pub fn on_turn_allocated(
        &self,
        peer: FabricPeerId,
        peer_relayed: SocketAddr,
    ) -> Result<RelayConn, RelayError> {
        let client: TurnClient = {
            let mut turn = self
                .turn
                .lock()
                .map_err(|_| RelayError::Turn("lock".into()))?;
            turn.ensure_allocated()
                .map_err(|e| RelayError::Turn(format!("{e:?}")))?;
            turn.client()
                .ok_or_else(|| RelayError::Turn("no allocated client".into()))?
        };
        client
            .create_permission(peer_relayed)
            .map_err(|e| RelayError::Turn(format!("create_permission: {e}")))?;

        let conn: Arc<ConnShared> = if self.my_id.0 > peer.0 {
            let listener = FabricListener::bind_with_transport_identity(
                Box::new(TurnSocket::new(client)),
                &self.identity,
            )
            .map_err(|e| RelayError::Identity(format!("listener: {e:?}")))?;
            listener
                .accept_timeout(Duration::from_secs(5))
                .map_err(|e| RelayError::Turn(format!("accept: {e:?}")))?
                .shared()
        } else {
            let driver = Driver::new_client_with_transport(Box::new(TurnSocket::new(client)))
                .map_err(|e| RelayError::Turn(format!("driver: {e:?}")))?;
            driver
                .connect(peer, peer_relayed, Duration::from_secs(5))
                .map_err(|e| RelayError::Turn(format!("connect: {e:?}")))?
        };

        if !self.up.swap(true, Ordering::SeqCst) {
            eprintln!(
                "[nat-relay] provider_up peer={} relayed={peer_relayed}",
                hex32(&peer.0)
            );
        }
        let info = RelayInfo {
            peer,
            conn: conn.clone(),
            relayed: peer_relayed,
            kind: RelayKind::Turn,
        };
        if let Ok(mut sinks) = self.sinks.lock() {
            if let Some(list) = sinks.get(&peer.0) {
                for weak in list.iter() {
                    if let Some(sink) = weak.upgrade() {
                        sink.on_relay_available(info.clone());
                    }
                }
            }
            // Drop entries whose owner went away (prune after dispatch).
            prune_peer(&mut sinks, &peer.0);
        }
        Ok(RelayConn {
            conn,
            relayed: peer_relayed,
            kind: RelayKind::Turn,
        })
    }

    pub fn provider_lost(&self) {
        if self.up.swap(false, Ordering::SeqCst) {
            eprintln!("[nat-relay] provider_lost");
        }
    }
}

impl TurnRelayProvider {
    /// Live sink count for one peer (prunes dead entries first).
    pub fn sink_count(&self, peer: &FabricPeerId) -> usize {
        match self.sinks.lock() {
            Ok(mut g) => prune_peer(&mut g, &peer.0),
            Err(_) => 0,
        }
    }

    /// Peers with at least one live sink (prunes dead entries first).
    pub fn subscribed_peers(&self) -> Vec<FabricPeerId> {
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
