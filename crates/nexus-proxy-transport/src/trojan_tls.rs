//! Trojan over TLS proxy transport (T7).
//!
//! TCP → TLS handshake (rustls 0.23 + ring) → trojan handshake inside TLS →
//! 2-byte framing → [`UdpTransport`].
//!
//! The trojan handshake bytes are identical to the plaintext phase (T2):
//! `encode_request(password, target)` from `nexus-outbound-trojan` (T3).
//! What changes is the transport: TLS encrypts everything on the wire,
//! making this interoperable with real trojan servers.
//!
//! Certificate verification:
//! - `skip_cert_verify = false` (default): system root certificates.
//! - `skip_cert_verify = true`: skip chain/hostname verification (still
//!   verifies handshake signatures; reuses
//!   `nexus-outbound-trojan::client_config_dangerous_skip_verify`).
//!
//! This module is parallel to `trojan.rs` (T2 plaintext); the frozen T2
//! contract is untouched.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use nexus_fabric::UdpTransport;
use nexus_outbound_trojan::{client_config_dangerous_skip_verify, encode_request, TrojanTarget};
use nexus_proxy_config::{OutboundConfig, OutboundKind};
use rustls::pki_types::ServerName;

use crate::{Counters, ProxyError, FRAME_HEADER_LEN, MAX_DATAGRAM};

/// Trojan-over-TLS proxy server configuration (T7).
#[derive(Clone)]
pub struct TrojanTlsConfig {
    /// `ip:port` of the trojan server (IP only — no DNS in the transport).
    pub server: SocketAddr,
    /// Password (sent as `hex(SHA-224(password))` inside TLS; never logged).
    pub password: String,
    /// TLS SNI (usually the server domain; IP string also works).
    pub sni: String,
    /// Skip certificate chain/hostname verification (self-signed/intranet).
    pub skip_cert_verify: bool,
    /// ALPN protocols to offer (e.g. `[b"h2"]`; empty = none).
    pub alpn: Vec<Vec<u8>>,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// I/O timeout during TLS + trojan handshake.
    pub handshake_timeout: Duration,
}

/// 手动 `Debug`：`password` 只输出 `***`，永不落日志（#3 BLOCKER 硬性约束 5）。
impl std::fmt::Debug for TrojanTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanTlsConfig")
            .field("server", &self.server)
            .field("password", &"***")
            .field("sni", &self.sni)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("alpn", &self.alpn)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish()
    }
}

impl TrojanTlsConfig {
    /// Config with 10s default timeouts, strict cert verification, no ALPN.
    pub fn new(server: SocketAddr, password: String, sni: String) -> Self {
        Self {
            server,
            password,
            sni,
            skip_cert_verify: false,
            alpn: Vec::new(),
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl TryFrom<&OutboundConfig> for TrojanTlsConfig {
    type Error = ProxyError;

    fn try_from(o: &OutboundConfig) -> Result<Self, Self::Error> {
        if o.kind != OutboundKind::Trojan {
            return Err(ProxyError::BadConfig(format!(
                "expected trojan outbound, got '{}'",
                o.kind.as_str()
            )));
        }
        let locator = o
            .locator
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ProxyError::BadConfig("trojan outbound requires a locator (IP:port)".into())
            })?;
        let server: SocketAddr = locator.parse().map_err(|_| {
            ProxyError::BadConfig(format!(
                "bad locator '{locator}': expected IP:port (transport does no DNS)"
            ))
        })?;
        let password = o
            .password
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ProxyError::BadConfig("trojan outbound requires a non-empty password".into())
            })?;
        // SNI defaults to the server IP string; override via config when known.
        let sni = server.ip().to_string();
        Ok(Self::new(server, password, sni))
    }
}

/// Map a dial target onto the trojan ATYP subset (IPv4 only, T2 parity).
fn trojan_target(target: SocketAddr) -> Result<TrojanTarget, ProxyError> {
    match target.ip() {
        IpAddr::V4(v4) => Ok(TrojanTarget::Ipv4(v4.octets(), target.port())),
        IpAddr::V6(_) => Err(ProxyError::UnsupportedTarget(
            "trojan target must be IPv4 (ATYP subset)",
        )),
    }
}

/// Build a rustls `ClientConfig` for the given verification mode.
fn build_client_config(config: &TrojanTlsConfig) -> Result<rustls::ClientConfig, ProxyError> {
    if config.skip_cert_verify {
        client_config_dangerous_skip_verify(
            &config.alpn.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
        )
        .map_err(|_| ProxyError::Tls("failed to build skip-verify TLS config".into()))
    } else {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // Load native root certificates for strict verification.
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            return Err(ProxyError::Tls(
                "failed to load native root certificates".into(),
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in native.certs {
            roots
                .add(cert)
                .map_err(|_| ProxyError::Tls("bad native root certificate".into()))?;
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| ProxyError::Tls("TLS protocol versions unavailable".into()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        if !config.alpn.is_empty() {
            cfg.alpn_protocols = config.alpn.clone();
        }
        Ok(cfg)
    }
}

/// TLS stream type: owns both the rustls connection and the TCP socket.
/// Public for ProxyEngine relay (P1): the relay pumps bytes through it.
pub type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// Perform the TLS handshake then the trojan handshake inside it.
/// Returns the established TLS stream.
pub fn trojan_tls_connect(
    config: &TrojanTlsConfig,
    target: SocketAddr,
) -> Result<TlsStream, ProxyError> {
    // Validate the target before touching the network (fail fast, T2 parity).
    let tgt = trojan_target(target)?;

    let tcp = TcpStream::connect_timeout(&config.server, config.connect_timeout)
        .map_err(ProxyError::Io)?;
    tcp.set_read_timeout(Some(config.handshake_timeout))
        .map_err(ProxyError::Io)?;
    tcp.set_write_timeout(Some(config.handshake_timeout))
        .map_err(ProxyError::Io)?;

    let client_config = build_client_config(config)?;
    let server_name = ServerName::try_from(config.sni.clone())
        .map_err(|_| ProxyError::BadConfig(format!("bad SNI '{}'", config.sni)))?;
    let conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|_| ProxyError::Tls("failed to create TLS client connection".into()))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    // TLS handshake happens implicitly on first read/write. Write the
    // trojan request inside the TLS tunnel (T2 bytes, T7 transport).
    let req = encode_request(&config.password, &tgt);
    tls.write_all(&req).map_err(ProxyError::Io)?;
    tls.flush().map_err(ProxyError::Io)?;

    // Handshake done: clear timeouts; the transport sets its own later.
    // Note: StreamOwned DerefMut gives TcpStream access via .sock.
    tls.sock.set_read_timeout(None).map_err(ProxyError::Io)?;
    tls.sock.set_write_timeout(None).map_err(ProxyError::Io)?;

    Ok(tls)
}

/// QUIC datagrams over a TLS-trojan TCP stream (T7).
///
/// 2-byte framing inside TLS (same as T2 framing, now encrypted on the wire).
/// Parallel to [`FramedTransport`]; frozen T2/T4 code is untouched.
pub struct TlsTrojanTransport {
    stream: Mutex<TlsStream>,
    target: SocketAddr,
    read_buf: Vec<u8>,
    counters: Counters,
    tls_handshake_ok: Arc<AtomicU64>,
}

impl TlsTrojanTransport {
    /// One-step helper: TLS + trojan handshake then wrap (T7).
    pub fn connect(config: &TrojanTlsConfig, target: SocketAddr) -> Result<Self, ProxyError> {
        let stream = trojan_tls_connect(config, target)?;
        let t = Self {
            stream: Mutex::new(stream),
            target,
            read_buf: Vec::new(),
            counters: Counters::default(),
            tls_handshake_ok: Arc::new(AtomicU64::new(0)),
        };
        // Mark handshake counters (T6/T7).
        t.counters.set_handshake_ok();
        t.tls_handshake_ok.store(1, Ordering::Relaxed);
        Ok(t)
    }

    /// The trojan target — the real peer as seen by this transport.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// T6: `(handshake_ok, handshake_err, framed_bytes)`.
    pub fn counters(&self) -> (u64, u64, u64) {
        self.counters.get()
    }

    /// Cloneable handle to the T6 counters.
    pub fn counters_handle(&self) -> Counters {
        self.counters.clone()
    }

    /// T7: whether the TLS handshake completed (1) or not (0).
    pub fn tls_handshake_ok(&self) -> u64 {
        self.tls_handshake_ok.load(Ordering::Relaxed)
    }

    fn send_frame(&self, blob: &[u8]) -> std::io::Result<()> {
        if blob.len() > MAX_DATAGRAM {
            return Err(ProxyError::FrameTooLarge(blob.len()).into());
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("tls trojan transport mutex poisoned"))?;
        stream.write_all(&(blob.len() as u16).to_be_bytes())?;
        stream.write_all(blob)?;
        stream.flush()?;
        Ok(())
    }

    fn recv_frame(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.read_buf.len() >= FRAME_HEADER_LEN {
                let len = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
                if len > MAX_DATAGRAM {
                    return Err(ProxyError::FrameTooLarge(len).into());
                }
                if self.read_buf.len() >= FRAME_HEADER_LEN + len {
                    if len > out.len() {
                        self.read_buf.drain(..FRAME_HEADER_LEN + len);
                        return Err(ProxyError::FrameOverflow {
                            frame: len,
                            buf: out.len(),
                        }
                        .into());
                    }
                    out[..len]
                        .copy_from_slice(&self.read_buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len]);
                    self.read_buf.drain(..FRAME_HEADER_LEN + len);
                    return Ok(len);
                }
            }
            // Need more bytes: read from TLS stream (atomic — buffer untouched on error).
            let mut stream = self
                .stream
                .lock()
                .map_err(|_| std::io::Error::other("tls trojan transport mutex poisoned"))?;
            let mut tmp = [0u8; 4096];
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "tls trojan stream closed",
                ));
            }
            // Bound the buffer: FRAME_HEADER_LEN + MAX_DATAGRAM (T4 parity).
            if self.read_buf.len() + n > FRAME_HEADER_LEN + MAX_DATAGRAM {
                return Err(ProxyError::FrameTooLarge(self.read_buf.len() + n).into());
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}

impl UdpTransport for TlsTrojanTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let n = self.recv_frame(buf)?;
        Ok((n, self.target))
    }

    fn send_to(&self, buf: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
        if buf.len() > MAX_DATAGRAM {
            return Err(ProxyError::FrameTooLarge(buf.len()).into());
        }
        self.send_frame(buf)?;
        Ok(buf.len())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("tls trojan transport mutex poisoned"))?;
        stream.sock.set_read_timeout(timeout)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("tls trojan transport mutex poisoned"))?;
        stream.sock.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(server: SocketAddr) -> TrojanTlsConfig {
        TrojanTlsConfig {
            server,
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            skip_cert_verify: true,
            alpn: Vec::new(),
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn tls_config_defaults_strict() {
        let cfg = TrojanTlsConfig::new(
            "127.0.0.1:443".parse().unwrap(),
            "pw".to_string(),
            "example.com".to_string(),
        );
        assert!(!cfg.skip_cert_verify);
        assert!(cfg.alpn.is_empty());
        assert_eq!(cfg.sni, "example.com");
    }

    #[test]
    fn tls_config_debug_masks_password() {
        let cfg = TrojanTlsConfig::new(
            "127.0.0.1:443".parse().unwrap(),
            "supersecret".to_string(),
            "example.com".to_string(),
        );
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("\"***\""));
    }

    #[test]
    fn tls_config_rejects_wrong_kind() {
        let o = OutboundConfig {
            tag: "t".into(),
            kind: OutboundKind::Shadowsocks,
            locator: Some("127.0.0.1:443".into()),
            method: None,
            password: Some("pw".to_string()),
            alpn: None,
            skip_cert_verify: None,
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: None,
            flow: None,
            tls: None,
            servername: None,
            sni: None,
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
        };
        assert!(TrojanTlsConfig::try_from(&o).is_err());
    }

    #[test]
    fn tls_config_rejects_bad_locator() {
        let o = OutboundConfig {
            tag: "t".into(),
            kind: OutboundKind::Trojan,
            locator: Some("not-an-addr".to_string()),
            method: None,
            password: Some("pw".to_string()),
            alpn: None,
            skip_cert_verify: None,
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: None,
            flow: None,
            tls: None,
            servername: None,
            sni: None,
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
        };
        assert!(TrojanTlsConfig::try_from(&o).is_err());
    }

    #[test]
    fn tls_target_rejects_ipv6() {
        let cfg = test_config("127.0.0.1:443".parse().unwrap());
        let target: SocketAddr = "[::1]:8080".parse().unwrap();
        assert!(trojan_target(target).is_err());
        let _ = cfg;
    }

    #[test]
    fn tls_build_client_config_skip_verify() {
        let cfg = test_config("127.0.0.1:443".parse().unwrap());
        assert!(build_client_config(&cfg).is_ok());
    }
}
