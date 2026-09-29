//! Nexus fabric session layer: `FabricConn`.
//!
//! Contract stage (Phase A): public API surface is frozen by `MODULE.md`.
//! All constructors currently return "not implemented"; the first E4 scenarios
//! (`product.fabric-conn-basic`, `product.fabric-conn-roam`) are expected to be
//! BLOCKED until the quinn-proto driver lands.
//!
//! Naming note: `FabricConn` is deliberately distinct from `nexus-session`'s
//! task-execution `Session`. Do not conflate the two.

use std::fmt;
use std::net::SocketAddr;

/// Node identity: ed25519 public key (cf. iroh's EndpointId).
///
/// Distinct from the X25519 link-encryption identity in `nexus-connectivity`:
/// X25519 can only do DH, while the QUIC/TLS handshake requires a signing key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", hex_short(&self.0))
    }
}

/// Logical connection identifier, decoupled from the UDP 5-tuple (S2).
///
/// Survives local address changes (roaming); the peer re-identifies the
/// connection by `(PeerId, ConnectionId)`, never by IP/port.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnectionId(pub u64);

/// Connection establishment parameters.
#[derive(Clone, Debug)]
pub struct ConnConfig {
    /// Candidate underlay addresses, in preference order (supplied by the path layer).
    pub addrs: Vec<SocketAddr>,
    /// Handshake timeout.
    pub handshake_timeout: std::time::Duration,
}

impl Default for ConnConfig {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            handshake_timeout: std::time::Duration::from_secs(10),
        }
    }
}

/// A QUIC-like connection to a peer: reliable streams, unreliable datagrams,
/// E2E encryption, statistics. Sync API (the driver runs on its own threads;
/// the repository is tokio-free).
///
/// Contract stage: not implemented.
pub struct FabricConn {
    peer: PeerId,
    id: ConnectionId,
}

impl FabricConn {
    /// Actively establish a connection (QUIC/TLS 1.3 handshake, peer authentication).
    pub fn connect(peer: PeerId, _config: &ConnConfig) -> Result<Self, FabricError> {
        let _ = peer;
        Err(FabricError::not_implemented("connect"))
    }

    pub fn peer(&self) -> PeerId {
        self.peer
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Open a reliable bidirectional stream (ordered, complete delivery, S4).
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), FabricError> {
        Err(FabricError::not_implemented("open_bi"))
    }

    /// Send an unreliable datagram (best-effort, S5). Max 1200 bytes pre-PMTUD.
    pub fn send_datagram(&self, _data: &[u8]) -> Result<(), FabricError> {
        Err(FabricError::not_implemented("send_datagram"))
    }

    /// Receive an unreliable datagram.
    pub fn recv_datagram(&self) -> Result<Vec<u8>, FabricError> {
        Err(FabricError::not_implemented("recv_datagram"))
    }

    /// Measured connection statistics (S8: honest, unknown marked as such).
    pub fn stats(&self) -> ConnStats {
        ConnStats::unknown()
    }

    /// Graceful close: sends a close frame (S7).
    pub fn close(&self, _code: u32, _reason: &[u8]) {}
}

/// Passive side: accept incoming connections.
pub struct FabricListener;

impl FabricListener {
    pub fn bind(_addr: SocketAddr) -> Result<Self, FabricError> {
        Err(FabricError::not_implemented("bind"))
    }

    pub fn accept(&self) -> Result<FabricConn, FabricError> {
        Err(FabricError::not_implemented("accept"))
    }
}

/// Reliable send half of a bidirectional stream.
pub struct SendStream;

impl SendStream {
    pub fn write(&mut self, _buf: &[u8]) -> Result<usize, FabricError> {
        Err(FabricError::not_implemented("SendStream::write"))
    }

    /// Signal end-of-stream; the peer observes EOF after all bytes (S4).
    pub fn finish(&mut self) -> Result<(), FabricError> {
        Err(FabricError::not_implemented("SendStream::finish"))
    }
}

/// Reliable receive half of a bidirectional stream.
pub struct RecvStream;

impl RecvStream {
    pub fn read(&mut self, _buf: &mut [u8]) -> Result<usize, FabricError> {
        Err(FabricError::not_implemented("RecvStream::read"))
    }
}

/// Measured statistics, shared by path-layer scoring (§4.3) and user diagnostics.
#[derive(Clone, Debug)]
pub struct ConnStats {
    /// Smoothed RTT in ms; `None` when no sample exists (S8).
    pub rtt_ms: Option<u64>,
    /// Estimated loss rate in [0.0, 1.0]; `None` when unknown.
    pub loss_rate: Option<f32>,
    /// Jitter in ms; `None` when unknown (feeds trend detection, §4.6).
    pub jitter_ms: Option<u64>,
    /// Measured throughput in bytes/s; `None` when unknown.
    pub throughput_bps: Option<u64>,
    /// Currently active underlay path (updated after migration, S3).
    pub active_path: Option<SocketAddr>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

impl ConnStats {
    pub fn unknown() -> Self {
        Self {
            rtt_ms: None,
            loss_rate: None,
            jitter_ms: None,
            throughput_bps: None,
            active_path: None,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }
}

/// Typed errors. Recoverability is explicit: `PathUnreachable` invites the path
/// layer to retry on another path; `HandshakeFailed` does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FabricError {
    /// Authentication/handshake failure: do NOT retry with the same identity.
    HandshakeFailed(String),
    /// Underlay path unreachable: the path layer should try another path.
    PathUnreachable,
    /// Peer closed the connection with the given code.
    Closed(u32),
    Timeout,
    /// Internal transport error (includes "not implemented" during contract stage).
    Transport(String),
}

impl FabricError {
    fn not_implemented(op: &str) -> Self {
        FabricError::Transport(format!("not implemented (contract stage): {op}"))
    }
}

impl fmt::Display for FabricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FabricError::HandshakeFailed(s) => write!(f, "handshake failed: {s}"),
            FabricError::PathUnreachable => write!(f, "path unreachable"),
            FabricError::Closed(c) => write!(f, "closed by peer (code {c})"),
            FabricError::Timeout => write!(f, "timeout"),
            FabricError::Transport(s) => write!(f, "transport error: {s}"),
        }
    }
}

impl std::error::Error for FabricError {}

fn hex_short(b: &[u8; 32]) -> String {
    b[..8].iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_stage_stubs_are_honest() {
        // Red Evidence anchor: every constructor fails loudly until the driver lands.
        let err = FabricConn::connect(PeerId([0u8; 32]), &ConnConfig::default()).unwrap_err();
        assert!(matches!(err, FabricError::Transport(_)));
    }
}
