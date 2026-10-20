//! Datagram transport abstraction (DESIGN.md §6.4, Phase 3b-2).
//!
//! [`Projection`](crate::Projection) sends/receives fabric datagrams through
//! a [`DatagramTransport`], never touching connection management directly.
//! The concrete transport is injected at assembly time:
//! - [`MockTransport`]: in-memory peer inboxes, for unit tests and E4.
//! - [`FabricTransport`]: wraps real `nexus-fabric::FabricConn` peers,
//!   each pumped by a background thread into a shared inbox.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// Error sending via a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No connection to the named peer.
    PeerNotFound(String),
    /// Underlying I/O failure (peer gone, fabric closed, ...).
    Io(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::PeerNotFound(p) => write!(f, "peer not found: {p}"),
            TransportError::Io(e) => write!(f, "transport io: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Lock helper that tolerates poisoning.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Datagram transport: send to a named peer, poll inbound datagrams.
///
/// `recv` is non-blocking and returns the origin peer name with each
/// datagram (needed for egress reply routing, S11).
pub trait DatagramTransport: Send + Sync {
    /// Send a datagram to `peer`. `Ok` means accepted by the transport
    /// (S3 best-effort: delivery itself is unreliable).
    fn send_to(&self, peer: &str, data: &[u8]) -> Result<(), TransportError>;
    /// Poll one inbound datagram: `(from_peer, data)`. `None` if empty.
    fn recv(&self) -> Option<(String, Vec<u8>)>;
}

/// In-memory transport for tests and E4 examples (no network).
///
/// Peers are wired via [`MockTransport::link_peer`]; each `send_to` tags
/// the datagram with this transport's name so the receiver knows the origin.
/// For E4 fidelity the name should match the routing-level peer identity
/// (production `FabricConn` stamps the real PeerId); use
/// [`MockTransport::set_name`] to align them.
pub struct MockTransport {
    name: Mutex<String>,
    peers: Mutex<PeerMap>,
    inbox_rx: Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
    inbox_tx: mpsc::Sender<(String, Vec<u8>)>,
}

/// Peer name → inbox sender for [`MockTransport`].
type PeerMap = HashMap<String, mpsc::Sender<(String, Vec<u8>)>>;

impl MockTransport {
    /// Create an unlinked transport named `name`.
    pub fn new(name: &str) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            name: Mutex::new(name.to_string()),
            peers: Mutex::new(HashMap::new()),
            inbox_rx: Mutex::new(rx),
            inbox_tx: tx,
        }
    }

    /// Rename this transport (E4 wiring: align the stamped `from_peer`
    /// with the routing-level peer identity).
    pub fn set_name(&self, name: &str) {
        *lock(&self.name) = name.to_string();
    }

    /// Register `peer_name`'s inbox (test/E4 wiring).
    pub fn link_peer(&self, peer_name: &str, peer_inbox: mpsc::Sender<(String, Vec<u8>)>) {
        lock(&self.peers).insert(peer_name.to_string(), peer_inbox);
    }

    /// Remove a peer link (e.g. the "self" loopback from `new_for_test`).
    pub fn unlink_peer(&self, peer_name: &str) {
        lock(&self.peers).remove(peer_name);
    }

    /// Our inbox sender, for a peer to `link_peer` to.
    pub fn inbox_sender(&self) -> mpsc::Sender<(String, Vec<u8>)> {
        self.inbox_tx.clone()
    }
}

impl DatagramTransport for MockTransport {
    fn send_to(&self, peer: &str, data: &[u8]) -> Result<(), TransportError> {
        let peers = lock(&self.peers);
        // Fallback: if the named peer isn't linked but exactly one peer is,
        // use it. Preserves the old single-peer `link_peer` behavior for
        // legacy (unrouted) traffic in tests.
        let tx = peers
            .get(peer)
            .or_else(|| {
                if peers.len() == 1 {
                    peers.values().next()
                } else {
                    None
                }
            })
            .ok_or_else(|| TransportError::PeerNotFound(peer.to_string()))?;
        tx.send((lock(&self.name).clone(), data.to_vec()))
            .map_err(|_| TransportError::Io("peer inbox closed".into()))
    }

    fn recv(&self) -> Option<(String, Vec<u8>)> {
        lock(&self.inbox_rx).try_recv().ok()
    }
}

/// Real fabric transport: wraps `nexus-fabric::FabricConn` peers.
///
/// Each peer connection is pumped by a background thread that blocks on
/// `FabricConn::recv_datagram` and forwards `(peer_name, datagram)` into a
/// shared inbox. `Drop` closes the connections (unblocking the pumps);
/// pump threads are detached and exit on close.
///
/// R3/D5: the pump splits datagrams by intent kind after `recv_datagram`.
/// `0x03` (SERVICE) datagrams are dispatched to the upper-layer handler
/// registered for the second byte (service sub-id); `0x00/0x01/0x02`
/// continue to the TUN inbox unchanged (wire compatibility, AC7).
pub struct FabricTransport {
    conns: HashMap<String, nexus_fabric::FabricConn>,
    inbox_rx: Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
    service_table: Arc<Mutex<HashMap<u8, crate::flow_session::DatagramHandler>>>,
}

impl FabricTransport {
    /// Build from a static peer-name → connection map (3b-2: static config;
    /// discovery integration is later).
    pub fn new(peers: HashMap<String, nexus_fabric::FabricConn>) -> Self {
        let (tx, rx) = mpsc::channel();
        let service_table: Arc<Mutex<HashMap<u8, crate::flow_session::DatagramHandler>>> =
            Arc::new(Mutex::new(HashMap::new()));
        for (name, conn) in &peers {
            let tx = tx.clone();
            let conn = conn.clone();
            let name = name.clone();
            let peer_id = conn.peer();
            let service_table = Arc::clone(&service_table);
            thread::Builder::new()
                .name(format!("fabric-pump-{name}"))
                .spawn(move || {
                    while let Ok(d) = conn.recv_datagram() {
                        // R3/D5: 0x03 service datagrams go to the upper-layer
                        // handler; 0x00/0x01/0x02 keep the TUN inbox path.
                        if d.len() >= 2
                            && crate::decode_intent_kind(d[0]).0 == crate::INTENT_SERVICE
                        {
                            let svc = d[1];
                            let handler = service_table.lock().unwrap().get(&svc).cloned();
                            if let Some(h) = handler {
                                h(peer_id, &d[2..]);
                                continue;
                            }
                        }
                        if tx.send((name.clone(), d)).is_err() {
                            break; // inbox gone
                        }
                    }
                })
                .expect("spawn fabric pump thread");
        }
        Self {
            conns: peers,
            inbox_rx: Mutex::new(rx),
            service_table,
        }
    }

    /// Register an upper-layer datagram service handler (R3/D5): a
    /// `0x03`-intent datagram whose second byte equals `svc` is delivered
    /// to `h` and never enters the TUN inbox (AC7).
    pub fn register_datagram_service(&self, svc: u8, h: crate::flow_session::DatagramHandler) {
        self.service_table.lock().unwrap().insert(svc, h);
    }
}

impl DatagramTransport for FabricTransport {
    fn send_to(&self, peer: &str, data: &[u8]) -> Result<(), TransportError> {
        let conn = self
            .conns
            .get(peer)
            .ok_or_else(|| TransportError::PeerNotFound(peer.to_string()))?;
        conn.send_datagram(data)
            .map_err(|e| TransportError::Io(e.to_string()))
    }

    fn recv(&self) -> Option<(String, Vec<u8>)> {
        lock(&self.inbox_rx).try_recv().ok()
    }
}

impl Drop for FabricTransport {
    fn drop(&mut self) {
        // Unblock pump threads; they exit when recv_datagram errors.
        // Threads are detached (not joined) to avoid Drop hanging if a
        // peer never closes cleanly; the process exit reaps them.
        for conn in self.conns.values() {
            conn.close(0, b"transport shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_transport_delivers_with_origin_tag() {
        let a = MockTransport::new("A");
        let b = MockTransport::new("B");
        a.link_peer("B", b.inbox_sender());
        b.link_peer("A", a.inbox_sender());

        a.send_to("B", &[1, 2, 3]).unwrap();
        let (from, data) = b.recv().expect("datagram");
        assert_eq!(from, "A");
        assert_eq!(data, vec![1, 2, 3]);
        assert!(b.recv().is_none());

        b.send_to("A", &[9]).unwrap();
        let (from, _) = a.recv().expect("datagram");
        assert_eq!(from, "B");
    }

    #[test]
    fn mock_transport_unknown_peer_errors() {
        let a = MockTransport::new("A");
        let err = a.send_to("ghost", &[1]).unwrap_err();
        assert_eq!(err, TransportError::PeerNotFound("ghost".to_string()));
    }

    #[test]
    fn mock_transport_closed_peer_io_error() {
        let a = MockTransport::new("A");
        let b = MockTransport::new("B");
        a.link_peer("B", b.inbox_sender());
        drop(b); // close B's inbox
        // Send may still succeed if the channel buffer accepts it; drop
        // the receiver side fully by ensuring no receiver exists.
        // (mpsc::Sender survives in `a.peers`; the receiver is gone with `b`.)
        let err = a.send_to("B", &[1]).unwrap_err();
        assert_eq!(err, TransportError::Io("peer inbox closed".into()));
    }
}
