//! QUIC over proxy CONNECT transports (DESIGN §3.5).
//!
//! Per-link proxy transports: handshake → connected `TcpStream` → 2-byte
//! big-endian length-prefix framing → [`nexus_fabric::UdpTransport`].
//! The QUIC driver needs zero changes; plug a transport into
//! [`nexus_fabric::FabricConn::connect_with_transport`].
//!
//! Three handshakes share one framing core ([`FramedTransport`], T4):
//! - SOCKS5 CONNECT (RFC 1928) — [`ProxyTransport`] (X1–X6, frozen).
//! - Shadowsocks session (AEAD) — [`SsTransport`] (T1; crypto reused from
//!   `nexus-outbound-shadowsocks`, never reimplemented here).
//! - Trojan (plaintext handshake this phase) — [`TrojanTransport`] (T2;
//!   handshake reused from `nexus-outbound-trojan`; TLS postponed).
//!
//! This is the **transport** (per-link, path-layer decision), not the
//! **egress** (per-flow, rule-engine decision — already built in 3b).
//! Double encryption is intentional: the proxy layer provides obfuscation,
//! E2E encryption stays the trust boundary (fabric S1 — the proxy only
//! sees ciphertext payloads).
//!
//! Contract: `MODULE.md` (X1–X6 frozen; T1–T6 frozen). Protected after freeze.

mod framed;
mod shadowsocks;
mod socks5;
mod trojan;
mod trojan_tls;

pub use framed::{Counters, FramedTransport, ProxyTransport};
pub use nexus_outbound_shadowsocks::SsMethod; // T3: reuse, don't redefine
pub use shadowsocks::{SsProxyConfig, SsTransport};
pub use socks5::socks5_connect;
pub use trojan::{trojan_connect, TrojanProxyConfig, TrojanTransport};
pub use trojan_tls::{trojan_tls_connect, TlsTrojanTransport, TrojanTlsConfig};

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use nexus_outbound_shadowsocks::OutboundCipherError;

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

/// Typed errors for the proxy handshakes and framing layer.
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
    /// Frame length prefix exceeds the accepted wire bound (X1/T4).
    FrameTooLarge(usize),
    /// Received frame does not fit the caller's buffer.
    FrameOverflow { frame: usize, buf: usize },
    /// `TryFrom<&OutboundConfig>` failed (T4): kind/locator/method/password
    /// problem — fix the config and retry.
    BadConfig(String),
    /// Shadowsocks AEAD failure (T1/T3): wrong password, corrupt record…
    SsCrypto(OutboundCipherError),
    /// Dial target not representable in the protocol's ATYP subset
    /// (IPv6 this phase; postponed, not silently mapped).
    UnsupportedTarget(&'static str),
    /// TLS failure (T7): config build, handshake, or I/O inside TLS.
    Tls(String),
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
            Self::BadConfig(what) => write!(f, "proxy: bad config ({what})"),
            Self::SsCrypto(e) => write!(f, "proxy: ss crypto: {e}"),
            Self::UnsupportedTarget(what) => write!(f, "proxy: unsupported target ({what})"),
            Self::Tls(what) => write!(f, "proxy: TLS failure ({what})"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::SsCrypto(e) => Some(e),
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
/// Applies to the *plaintext* datagram for every transport (X1, T1).
pub const MAX_DATAGRAM: usize = 1200;

/// AEAD seal overhead per datagram on the ss data path:
/// 12B nonce || ciphertext+16B tag (must match `SsStream::seal`'s output
/// format in `nexus-outbound-shadowsocks`; guarded by unit test).
pub const SS_SEAL_OVERHEAD: usize = 12 + 16;

/// Largest accepted wire frame on the ss path (T4).
pub const MAX_SEALED_FRAME: usize = MAX_DATAGRAM + SS_SEAL_OVERHEAD;

/// Length-prefix width in bytes (big-endian u16).
pub const FRAME_HEADER_LEN: usize = 2;
