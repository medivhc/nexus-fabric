//! Nexus fabric session layer: `FabricConn`.
//!
//! QUIC-like connections over UDP (quinn-proto sans-IO + a self-written std
//! driver thread; the repository is tokio-free): reliable bidirectional
//! streams, unreliable datagrams, E2E encryption (TLS 1.3), and connections
//! identified by `(PeerId, ConnectionId)` decoupled from the UDP 5-tuple so
//! they survive local address changes (roaming, S2/S3).
//!
//! Naming note: `FabricConn` is deliberately distinct from `nexus-session`'s
//! task-execution `Session`. Do not conflate the two.
//!
//! Phase B additions to the frozen API surface (all truly necessary for the
//! frozen E4 scenarios; no frozen expectation changed):
//! - `FabricConn::accept_bi`: the echo server must accept the peer's stream.
//! - `FabricConn::rebind`: the roam scenario rebinds the client mid-transfer.
//! - `FabricListener::peer_id` / `local_addr`: the dialing side needs both.

mod cert;
mod driver;
mod stun;
pub mod transport;

use crate::cert::Identity;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// Driver-level handles for NAT punch-through wiring (`nexus-nat-wireup`).
///
/// Additive re-export (no logic change): the punch orchestrator needs
/// `Driver::connect` on a shared punch driver (same UDP socket for all
/// candidates — a fresh `FabricConn::connect` per target would open a new
/// socket per candidate and break NAT mapping stability) and `Cmd::OpenBi`
/// / `StreamShared` for the signal channel on the relayed connection.
pub use cert::FabricIdentity;
pub use driver::{Cmd, ConnShared, Driver, StreamShared};
pub use stun::{StunRequest, StunResponse, StunSink, StunTapError, StunTransactionId};
pub use transport::{StdUdpTransport, UdpTransport};

/// QSEQ (GAP-2): length of the big-endian sequence header prepended by
/// `send_datagram_seqed`.
pub const SEQ_HEADER_LEN: usize = 8;
/// QSEQ (GAP-2): max user payload for `send_datagram_seqed`
/// (1200-byte datagram cap minus the 8-byte header).
pub const MAX_SEQED_PAYLOAD: usize = 1192;

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
    pub handshake_timeout: Duration,
}

impl Default for ConnConfig {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// A QUIC-like connection to a peer: reliable streams, unreliable datagrams,
/// E2E encryption, statistics. Sync API (the driver runs on its own std thread).
#[derive(Debug, Clone)]
pub struct FabricConn {
    inner: Arc<ConnShared>,
    // Ownership anchor: keeps the driver thread alive as long as any
    // connection (or the listener) exists. Never read directly.
    #[allow(dead_code)]
    driver: Arc<Driver>,
}

impl FabricConn {
    /// Actively establish a connection (QUIC/TLS 1.3 handshake with peer-key
    /// pinning, S1). Blocks until the handshake completes or `handshake_timeout`
    /// elapses. Uses `config.addrs[0]` (P0: no racing yet).
    pub fn connect(peer: PeerId, config: &ConnConfig) -> Result<Self, FabricError> {
        if config.addrs.is_empty() {
            return Err(FabricError::PathUnreachable);
        }
        let driver = Driver::new_client()?;
        let inner = driver.connect(peer, config.addrs[0], config.handshake_timeout)?;
        Ok(Self { inner, driver })
    }

    /// Actively establish a connection over a caller-provided transport (S9),
    /// e.g. a TURN-relayed socket. `config.addrs[0]` is the destination as
    /// seen by the transport (for TURN: the peer's relayed address).
    pub fn connect_with_transport(
        peer: PeerId,
        config: &ConnConfig,
        transport: Box<dyn UdpTransport>,
    ) -> Result<Self, FabricError> {
        if config.addrs.is_empty() {
            return Err(FabricError::PathUnreachable);
        }
        let driver = Driver::new_client_with_transport(transport)?;
        let inner = driver.connect(peer, config.addrs[0], config.handshake_timeout)?;
        Ok(Self { inner, driver })
    }

    /// Connect with mandatory TLS1.3 client authentication and server-key pinning.
    /// The single handshake budget includes peer acceptance (QUIC HANDSHAKE_DONE).
    pub fn connect_mtls(
        peer: PeerId,
        identity: &FabricIdentity,
        config: &ConnConfig,
    ) -> Result<Self, FabricError> {
        let remote = *config.addrs.first().ok_or(FabricError::PathUnreachable)?;
        let start = Instant::now();
        let crypto = cert::build_mtls_client_crypto(peer, identity)?;
        let driver = Driver::new_mtls_client()?;
        let budget = config.handshake_timeout.saturating_sub(start.elapsed());
        let inner = driver.connect_with_crypto(peer, remote, budget, crypto)?;
        Ok(Self { inner, driver })
    }

    /// Verified mutual-TLS identity, never a legacy anonymous/single-pin claim.
    pub fn mutually_authenticated_peer(&self) -> Option<PeerId> {
        self.inner.state.lock().ok()?.mutual_peer
    }

    /// Additive: shared handle for signaling/path registration (no semantic
    /// change; returns the same underlying handle).
    pub fn shared(&self) -> Arc<ConnShared> {
        self.inner.clone()
    }

    pub fn peer(&self) -> PeerId {
        self.mutually_authenticated_peer()
            .unwrap_or(self.inner.peer)
    }

    pub fn id(&self) -> ConnectionId {
        self.inner.id
    }

    /// Open a reliable bidirectional stream (ordered, complete delivery, S4).
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), FabricError> {
        let (tx, rx) = mpsc::channel();
        self.inner
            .tx
            .send(Cmd::OpenBi {
                conn: self.inner.id.0,
                reply: tx,
            })
            .map_err(|_| FabricError::Closed(0))?;
        let sh = rx.recv().map_err(|_| FabricError::Closed(0))??;
        Ok(split_stream(sh))
    }

    /// Accept a remotely-initiated bidirectional stream (blocking).
    ///
    /// Phase B addition: required by the echo side of the product scenarios.
    pub fn accept_bi(&self) -> Result<(SendStream, RecvStream), FabricError> {
        let mut q = self.inner.accepted.lock().unwrap();
        loop {
            if let Some(sh) = q.pop_front() {
                return Ok(split_stream(sh));
            }
            if let Some(e) = self.inner.state.lock().unwrap().closed.clone() {
                return Err(e);
            }
            q = self
                .inner
                .accepted_cv
                .wait(q)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
        }
    }

    /// Send an unreliable datagram (best-effort, S5). Max 1200 bytes pre-PMTUD.
    pub fn send_datagram(&self, data: &[u8]) -> Result<(), FabricError> {
        if data.len() > 1200 {
            return Err(FabricError::Transport(
                "datagram too large (S5: 1200 byte cap)".into(),
            ));
        }
        let (tx, rx) = mpsc::channel();
        self.inner
            .tx
            .send(Cmd::SendDatagram {
                conn: self.inner.id.0,
                data: data.to_vec(),
                reply: tx,
            })
            .map_err(|_| FabricError::Closed(0))?;
        rx.recv().map_err(|_| FabricError::Closed(0))?
    }

    /// QSEQ (GAP-2): send a datagram with a fabric-layer sequence number.
    ///
    /// Atomically assigns the next per-connection sequence number (Q1, Q4),
    /// prepends it as an 8-byte big-endian header, and sends via the normal
    /// datagram path. Returns the assigned sequence number.
    ///
    /// This is NOT the QUIC wire packet number (inaccessible via quinn-proto's
    /// public API; also semantically wrong for reordering due to retransmit
    /// renumbering — see MODULE.md QSEQ). It is a per-connection datagram
    /// identity sequence assigned at the QUIC send boundary.
    ///
    /// `data.len()` must be `<= 1192` (1200 cap minus 8-byte header).
    pub fn send_datagram_seqed(&self, data: &[u8]) -> Result<u64, FabricError> {
        if data.len() > MAX_SEQED_PAYLOAD {
            return Err(FabricError::Transport(
                "seqed datagram too large (1192 byte cap after 8-byte seq header)".into(),
            ));
        }
        // Q4: fetch_add is atomic; the header is prepended and handed to the
        // driver in the same call, so there is no "assigned but not sent" window
        // visible to the caller. (Transmission order may still differ from
        // assignment order under concurrency; the receiver's ReorderBuffer
        // handles out-of-order delivery — that is its job.)
        let seq = self
            .inner
            .datagram_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut buf = Vec::with_capacity(SEQ_HEADER_LEN + data.len());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(data);
        self.send_datagram(&buf)?;
        Ok(seq)
    }

    /// QSEQ (GAP-2): receive a datagram sent with [`FabricConn::send_datagram_seqed`].
    ///
    /// Strips the 8-byte big-endian sequence header and returns
    /// `(seq, payload)`. Datagrams shorter than 8 bytes are rejected with
    /// `FabricError::Transport` (Q3).
    pub fn recv_datagram_seqed(&self) -> Result<(u64, Vec<u8>), FabricError> {
        let raw = self.recv_datagram()?;
        if raw.len() < SEQ_HEADER_LEN {
            return Err(FabricError::Transport(
                "datagram too short for seq header".into(),
            ));
        }
        let mut hdr = [0u8; SEQ_HEADER_LEN];
        hdr.copy_from_slice(&raw[..SEQ_HEADER_LEN]);
        let seq = u64::from_be_bytes(hdr);
        Ok((seq, raw[SEQ_HEADER_LEN..].to_vec()))
    }

    /// Receive an unreliable datagram (blocking).
    pub fn recv_datagram(&self) -> Result<Vec<u8>, FabricError> {
        let mut q = self.inner.dgrams.lock().unwrap();
        loop {
            if let Some(d) = q.pop_front() {
                return Ok(d);
            }
            if let Some(e) = self.inner.state.lock().unwrap().closed.clone() {
                return Err(e);
            }
            q = self
                .inner
                .dgram_cv
                .wait(q)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
        }
    }

    /// Rebind the underlying UDP socket to a new local port (active migration).
    ///
    /// Phase B addition: the roam scenario's client rebinds mid-transfer (S3).
    /// Unacknowledged data is retransmitted on the new path; the peer migrates
    /// via QUIC path validation (S6). Blocks until the swap completes.
    ///
    /// F-EDGE-3: concurrent `rebind()` calls on this connection are serialized
    /// via `ConnShared::rebind_lock` (held for the whole call). Successive
    /// rebinds execute in call order; they are not coalesced.
    pub fn rebind(&self) -> Result<(), FabricError> {
        let _guard = self.inner.rebind_lock.lock().unwrap();
        let (tx, rx) = mpsc::channel();
        self.inner
            .tx
            .send(Cmd::Rebind {
                conn: self.inner.id.0,
                reply: tx,
            })
            .map_err(|_| FabricError::Closed(0))?;
        rx.recv().map_err(|_| FabricError::Closed(0))??;
        Ok(())
    }

    /// Measured connection statistics (S8: honest, unknown marked as such).
    pub fn stats(&self) -> ConnStats {
        self.inner.stats.lock().unwrap().clone()
    }

    /// Graceful close: queues a close frame (S7, best-effort delivery).
    pub fn close(&self, code: u32, reason: &[u8]) {
        let _ = self.inner.tx.send(Cmd::Close {
            conn: self.inner.id.0,
            code,
            reason: reason.to_vec(),
        });
    }
}

/// Split a shared stream into its send/recv halves (C2: lets the sync
/// transport adapter accept `Arc<StreamShared>` from `take_unclaimed`
/// and from `open_bi`/`accept_bi` uniformly).
pub fn split_stream(sh: Arc<StreamShared>) -> (SendStream, RecvStream) {
    (SendStream { shared: sh.clone() }, RecvStream { shared: sh })
}

/// Passive side: accept incoming connections.
#[derive(Debug, Clone)]
pub struct FabricListener {
    driver: Arc<Driver>,
}

impl FabricListener {
    pub fn bind(addr: SocketAddr) -> Result<Self, FabricError> {
        Ok(Self {
            driver: Driver::new_server(addr)?,
        })
    }

    /// Bind the listener on a caller-provided transport (S9), e.g. a
    /// TURN-relayed socket. Peers dial the transport's `local_addr()`
    /// (for TURN: the allocated relay address).
    pub fn bind_with_transport(transport: Box<dyn UdpTransport>) -> Result<Self, FabricError> {
        Ok(Self {
            driver: Driver::new_server_with_transport(transport)?,
        })
    }

    /// Bind the listener on a caller-provided transport with an **explicit
    /// identity**（#3 fabric-over-proxy）。`bind_with_transport` 每次生成随机
    /// 身份，无法与拨号方配置里的 PeerId 对齐；经代理建连时服务端身份必须可
    /// 预测，否则 `FabricConn::connect_with_transport` 的 PeerPin 校验失败。
    pub fn bind_with_transport_identity(
        transport: Box<dyn UdpTransport>,
        identity: &FabricIdentity,
    ) -> Result<Self, FabricError> {
        let id = Identity {
            peer_id: identity.inner.peer_id,
            cert_der: identity.inner.cert_der.clone(),
            key_der: identity.inner.key_der.clone(),
        };
        Ok(Self {
            driver: Driver::new_server_with_transport_identity(transport, id)?,
        })
    }

    /// TLS1.3 listener requiring a verified client key from the explicit allowlist.
    /// An empty allowlist rejects every client; no identity is learned implicitly.
    pub fn bind_mtls(
        addr: SocketAddr,
        identity: &FabricIdentity,
        allowed: &[PeerId],
    ) -> Result<Self, FabricError> {
        Ok(Self {
            driver: Driver::new_mtls_server(addr, identity, allowed)?,
        })
    }

    /// Bounded accept for connection owners and admission observers.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<FabricConn, FabricError> {
        let inner = self.driver.accept_conn_timeout(timeout)?;
        Ok(FabricConn {
            inner,
            driver: self.driver.clone(),
        })
    }

    pub fn accept(&self) -> Result<FabricConn, FabricError> {
        let inner = self.driver.accept_conn()?;
        Ok(FabricConn {
            inner,
            driver: self.driver.clone(),
        })
    }

    /// This endpoint's [`PeerId`], for the dialing side to pin.
    ///
    /// Phase B addition: the product scenarios dial with an expected peer.
    pub fn peer_id(&self) -> PeerId {
        self.driver
            .shared()
            .peer_id
            .expect("server driver always has an identity")
    }

    /// Local UDP address, for the dialing side's [`ConnConfig`].
    ///
    /// Phase B addition: the product scenarios bind port 0 and discover it.
    pub fn local_addr(&self) -> Result<SocketAddr, FabricError> {
        Ok(*self.driver.shared().local_addr.lock().unwrap())
    }
}

/// Reliable send half of a bidirectional stream.
///
/// P0: `write` buffers in memory and returns immediately; the driver moves
/// bytes into QUIC. There is no backpressure yet (documented limitation).
pub struct SendStream {
    shared: Arc<StreamShared>,
}

impl SendStream {
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, FabricError> {
        let mut ss = self.shared.state.lock().unwrap();
        if let Some(e) = ss.error.clone() {
            return Err(e);
        }
        ss.send_buf.extend(buf.iter().copied());
        let _ = self.shared.tx.send(Cmd::Pump {
            conn: self.shared.conn_id,
        });
        Ok(buf.len())
    }

    /// Signal end-of-stream; the peer observes EOF after all bytes (S4).
    pub fn finish(&mut self) -> Result<(), FabricError> {
        let mut ss = self.shared.state.lock().unwrap();
        if let Some(e) = ss.error.clone() {
            return Err(e);
        }
        ss.send_fin = true;
        let _ = self.shared.tx.send(Cmd::Pump {
            conn: self.shared.conn_id,
        });
        Ok(())
    }
}

/// Reliable receive half of a bidirectional stream.
///
/// `read` blocks until data is available; `Ok(0)` signals EOF (after `finish`).
pub struct RecvStream {
    shared: Arc<StreamShared>,
}

impl RecvStream {
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, FabricError> {
        let mut ss = self.shared.state.lock().unwrap();
        loop {
            if let Some(e) = ss.error.clone() {
                return Err(e);
            }
            if !ss.recv_buf.is_empty() {
                let n = ss.recv_buf.len().min(buf.len());
                for (i, b) in ss.recv_buf.drain(..n).enumerate() {
                    buf[i] = b;
                }
                return Ok(n);
            }
            if ss.recv_eof {
                return Ok(0);
            }
            ss = self
                .shared
                .cv
                .wait(ss)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
        }
    }

    /// Read with an absolute deadline (C2 sync transport requirement:
    /// `RecvStream::read` has no timeout; a hung peer would block the sync
    /// thread forever). Returns `FabricError::Timeout` on deadline expiry.
    pub fn read_deadline(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, FabricError> {
        let mut ss = self.shared.state.lock().unwrap();
        loop {
            if let Some(e) = ss.error.clone() {
                return Err(e);
            }
            if !ss.recv_buf.is_empty() {
                let n = ss.recv_buf.len().min(buf.len());
                for (i, b) in ss.recv_buf.drain(..n).enumerate() {
                    buf[i] = b;
                }
                return Ok(n);
            }
            if ss.recv_eof {
                return Ok(0);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(FabricError::Timeout);
            }
            let timeout = deadline - now;
            let (g, r) = self
                .shared
                .cv
                .wait_timeout(ss, timeout)
                .map_err(|_| FabricError::Transport("lock poisoned".into()))?;
            ss = g;
            if r.timed_out() {
                return Err(FabricError::Timeout);
            }
        }
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
    fn connect_without_candidates_is_path_unreachable() {
        // No underlay addresses: the path layer must supply another path.
        let err = FabricConn::connect(PeerId([0u8; 32]), &ConnConfig::default()).unwrap_err();
        assert_eq!(err, FabricError::PathUnreachable);
    }

    #[test]
    fn peer_id_debug_is_short() {
        let s = format!("{:?}", PeerId([0xabu8; 32]));
        assert!(s.starts_with("PeerId(abababab"));
    }

    #[test]
    fn bind_with_transport_identity_pins_peer_id() {
        // #3：经代理的服务端必须能用显式身份建 listener，使拨号方配置中的
        // PeerId 与握手校验目标一致（PeerPin）。
        let id = FabricIdentity::from_ed25519_seed([42; 32]).expect("identity");
        let expected = id.peer_id();

        // 最小 UdpTransport 替身：recv_from 立即返回错误，驱动线程快速退出，
        // 避免真实 TCP 阻塞导致测试挂起（身份在构造时已写入 DriverShared）。
        struct StubTransport;
        impl UdpTransport for StubTransport {
            fn recv_from(&mut self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "stub",
                ))
            }
            fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
                Ok(0)
            }
            fn set_read_timeout(&self, _timeout: Option<Duration>) -> std::io::Result<()> {
                Ok(())
            }
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                "127.0.0.1:0".parse().map_err(std::io::Error::other)
            }
        }

        let fl = FabricListener::bind_with_transport_identity(Box::new(StubTransport), &id)
            .expect("bind_with_transport_identity");
        assert_eq!(fl.peer_id(), expected);
        drop(fl);
    }
}
