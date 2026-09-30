//! Datagram transport abstraction (DESIGN.md §6.4, Phase 3b-2).
//!
//! [`Projection`](crate::Projection) sends/receives fabric datagrams through
//! a [`DatagramTransport`], never touching connection management directly.
//! The concrete transport is injected at assembly time:
//! - [`MockTransport`]: in-memory peer inboxes, for unit tests and E4.
//! - [`FabricTransport`]: wraps real `nexus-fabric::FabricConn` peers,
//!   each pumped by a background thread into a shared inbox.

use std::collections::HashMap;
use std::sync::{Mutex, mpsc};
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
pub struct MockTransport {
    name: String,
    peers: Mutex<HashMap<String, mpsc::Sender<(String, Vec<u8>)>>>,
    inbox_rx: Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
    inbox_tx: mpsc::Sender<(String, Vec<u8>)>,
}

impl MockTransport {
    /// Create an unlinked transport named `name`.
    pub fn new(name: &str) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            name: name.to_string(),
            peers: Mutex::new(HashMap::new()),
            inbox_rx: Mutex::new(rx),
            inbox_tx: tx,
        }
    }

    /// This transport's name (used as the origin tag on send).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Register `peer_name`'s inbox (test/E4 wiring).
    pub fn link_peer(&self, peer_name: &str, peer_inbox: mpsc::Sender<(String, Vec<u8>)>) {
        lock(&self.peers).insert(peer_name.to_string(), peer_inbox);
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
        let tx = peers.get(peer).or_else(|| {
            if peers.len() == 1 {
                peers.values().next()
            } else {
                None
            }
        }).ok_or_else(|| TransportError::PeerNotFound(peer.to_string()))?;
        tx.send((self.name.clone(), data.to_vec()))
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
pub struct FabricTransport {
    conns: HashMap<String, nexus_fabric::FabricConn>,
    inbox_rx: Mutex<mpsc::Receiver<(String, Vec<u8>)>>,
}

impl FabricTransport {
    /// Build from a static peer-name → connection map (3b-2: static config;
    /// discovery integration is later).
    pub fn new(peers: HashMap<String, nexus_fabric::FabricConn>) -> Self {
        let (tx, rx) = mpsc::channel();
        for (name, conn) in &peers {
            let tx = tx.clone();
            let conn = conn.clone();
            let name = name.clone();
            thread::Builder::new()
                .name(format!("fabric-pump-{name}"))
                .spawn(move || {
                    loop {
                        match conn.recv_datagram() {
                            Ok(d) => {
                                if tx.send((name.clone(), d)).is_err() {
                                    break; // inbox gone
                                }
                            }
                            Err(_) => break, // closed / poisoned
                        }
                    }
                })
                .expect("spawn fabric pump thread");
        }
        Self {
            conns: peers,
            inbox_rx: Mutex::new(rx),
        }
    }

    /// Number of peer connections.
    pub fn peer_count(&self) -> usize {
        self.conns.len()
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
