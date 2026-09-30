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

mod framed;
mod socks5;

pub use framed::ProxyTransport;
pub use socks5::socks5_connect;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

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
    /// TCP connect timeout for the proxy server.
    pub connect_timeout: Duration,
    /// I/O timeout during the SOCKS5 handshake.
    pub handshake_timeout: Duration,
}

impl Socks5ProxyConfig {
    /// Config with 10s default timeouts.
    pub fn new(server: SocketAddr, auth: Option<Socks5Auth>) -> Self {
        Self {
            server,
            auth,
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }
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
    FrameTooLarge(usize),
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
            // X1: oversize send_to must be InvalidInput, not generic Other.
            ProxyError::FrameTooLarge(n) => io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("proxy: frame too large ({n} > {MAX_DATAGRAM})"),
            ),
            // Inbound protocol violation: peer sent a frame we cannot honor.
            ProxyError::FrameOverflow { frame, buf } => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("proxy: frame ({frame}B) exceeds buffer ({buf}B)"),
            ),
            other => io::Error::other(other.to_string()),
        }
    }
}

/// Maximum QUIC datagram carried in one frame (fabric S5, pre-PMTUD).
pub const MAX_DATAGRAM: usize = 1200;

/// Length-prefix width in bytes (big-endian u16).
pub const FRAME_HEADER_LEN: usize = 2;
