//! QUIC over SOCKS5 CONNECT (DESIGN §3.5, P1).
//!
//! Per-link proxy transport: SOCKS5 handshake → connected `TcpStream` →
//! 2-byte big-endian length-prefix framing → [`ProxyTransport`] implements
//! [`nexus_fabric::UdpTransport`]. The QUIC driver needs zero changes;
//! plug a `ProxyTransport` into [`nexus_fabric::FabricConn::connect_with_transport`].
//!
//! This is the **transport** (per-link, path-layer decision), not the
//! **egress** (per-flow, rule-engine decision — already built in 3b).
//! Double encryption is intentional: the proxy layer provides obfuscation,
//! E2E encryption stays the trust boundary (fabric S1 — the proxy only
//! sees ciphertext).
//!
//! Contract: `MODULE.md` (X1–X6). Protected after freeze.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::Duration;

use nexus_fabric::UdpTransport;

/// SOCKS5 proxy server configuration.
///
/// Note: no existing SOCKS5 *outbound* structure was found in
/// `nexus-proxy-config` (`OutboundKind` has no `Socks5` variant; SOCKS5
/// there is inbound/ingress only). This crate therefore carries its own
/// minimal config; wiring it into the shared outbound config is deferred
/// to the PathManager fallback-linkage phase (explicitly postposed).
#[derive(Debug, Clone)]
pub struct Socks5ProxyConfig {
    /// `ip:port` of the SOCKS5 server.
    pub server: SocketAddr,
    /// Optional RFC 1929 username/password authentication.
    pub auth: Option<Socks5Auth>,
    /// TCP connect timeout for the proxy server. Defaults to 10s.
    pub connect_timeout: Duration,
    /// I/O timeout during the SOCKS5 handshake. Defaults to 10s.
    pub handshake_timeout: Duration,
}

/// RFC 1929 username/password credentials.
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

/// Typed errors for the SOCKS5 handshake and framing layer.
#[derive(Debug)]
pub enum ProxyError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// Server refused all offered auth methods (`05 FF`).
    NoAcceptableAuth,
    /// Username/password authentication rejected.
    AuthFailed,
    /// CONNECT rejected; carries the RFC 1928 REP byte.
    ConnectRejected(u8),
    /// Malformed server reply (bad version, truncated, unknown ATYP…).
    BadReply(&'static str),
    /// Frame length prefix exceeds [`MAX_DATAGRAM`] (X1).
    FrameTooLarge(u16),
    /// Received frame does not fit the caller's buffer.
    FrameOverflow { frame: usize, buf: usize },
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "proxy I/O: {e}"),
            Self::NoAcceptableAuth => write!(f, "proxy: no acceptable auth method"),
            Self::AuthFailed => write!(f, "proxy: username/password rejected"),
            Self::ConnectRejected(rep) => write!(f, "proxy: CONNECT rejected (REP={rep:#04x})"),
            Self::BadReply(what) => write!(f, "proxy: malformed reply ({what})"),
            Self::FrameTooLarge(n) => write!(f, "proxy: frame too large ({n} > {MAX_DATAGRAM})"),
            Self::FrameOverflow { frame, buf } => {
                write!(f, "proxy: frame ({frame}B) exceeds buffer ({buf}B)")
            }
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ProxyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ProxyError> for io::Error {
    fn from(e: ProxyError) -> Self {
        match e {
            ProxyError::Io(inner) => inner,
            other => io::Error::new(io::ErrorKind::Other, other.to_string()),
        }
    }
}

/// Maximum QUIC datagram carried in one frame (fabric S5, pre-PMTUD).
pub const MAX_DATAGRAM: usize = 1200;

/// Length-prefix width in bytes (big-endian u16).
pub const FRAME_HEADER_LEN: usize = 2;

/// Perform the SOCKS5 handshake (RFC 1928) and return a connected `TcpStream`.
///
/// 1. TCP-connect to `config.server`.
/// 2. Method negotiation (`00` no-auth, or `00`+`02` when `auth` is set).
/// 3. RFC 1929 username/password sub-negotiation when required.
/// 4. `CONNECT` to `target` (IPv4/IPv6).
///
/// The returned stream is positioned right after the server's CONNECT
/// reply; the caller owns subsequent framing.
pub fn socks5_connect(_config: &Socks5ProxyConfig, _target: SocketAddr) -> io::Result<TcpStream> {
    // Contract phase stub — real implementation in Phase B (P-S-1).
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "not implemented",
    ))
}

/// QUIC datagrams over a SOCKS5-established TCP stream (X1).
///
/// Implements [`UdpTransport`] by framing each datagram as
/// `len: u16be || payload` on the wire. Point-to-point: the transport is
/// bound to the single CONNECT `target`; [`UdpTransport::send_to`]'s
/// `target` parameter is ignored (documented, X1).
///
/// `TcpStream` is wrapped in a `Mutex` because `UdpTransport::send_to`
/// takes `&self` while `TcpStream::write` needs `&mut`.
// Contract phase: fields unused until Phase B implements the methods.
#[allow(dead_code)]
pub struct ProxyTransport {
    stream: Mutex<TcpStream>,
    /// The CONNECT target — the real peer as seen by this transport
    /// (reported as source address by `recv_from`, per `UdpTransport`).
    target: SocketAddr,
    handshake_ok: AtomicU64,
    handshake_err: AtomicU64,
    framed_bytes: AtomicU64,
}

impl ProxyTransport {
    /// Wrap an already SOCKS5-connected stream (X1–X6).
    pub fn new(stream: TcpStream, target: SocketAddr) -> Self {
        Self {
            stream: Mutex::new(stream),
            target,
            handshake_ok: AtomicU64::new(0),
            handshake_err: AtomicU64::new(0),
            framed_bytes: AtomicU64::new(0),
        }
    }

    /// One-step helper: handshake then wrap (X4).
    pub fn connect(_config: &Socks5ProxyConfig, _target: SocketAddr) -> io::Result<Self> {
        // Contract phase stub — real implementation in Phase B (P-F-1).
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not implemented",
        ))
    }

    /// The CONNECT target (real peer address).
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// X6 counters: `(handshake_ok, handshake_err, framed_bytes)`.
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.handshake_ok.load(Ordering::Relaxed),
            self.handshake_err.load(Ordering::Relaxed),
            self.framed_bytes.load(Ordering::Relaxed),
        )
    }
}

impl UdpTransport for ProxyTransport {
    fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Contract phase stub — real implementation in Phase B (P-F-1).
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not implemented",
        ))
    }

    fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
        // Contract phase stub — real implementation in Phase B (P-F-1).
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not implemented",
        ))
    }

    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        // Contract phase stub — real implementation in Phase B (P-F-1).
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not implemented",
        ))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Contract phase stub — real implementation in Phase B (P-F-1).
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not implemented",
        ))
    }
}
