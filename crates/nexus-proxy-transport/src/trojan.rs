//! Trojan proxy transport (T2).
//!
//! TCP → plaintext trojan handshake → 2-byte framing → [`UdpTransport`].
//! The handshake reuses `nexus-outbound-trojan::{encode_request, ...}`
//! (T3) — never reimplemented here.
//!
//! This phase is **plaintext trojan** (no TLS — postponed, see the T2
//! honesty boundary in MODULE.md). The QUIC payload stays E2E-encrypted
//! (fabric S1), so the proxy still only ever sees ciphertext payloads (X2);
//! what travels in the clear is the trojan request header and the 2-byte
//! length prefixes (same as the SOCKS5 phase).

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use nexus_fabric::UdpTransport;
use nexus_outbound_trojan::{encode_request, TrojanTarget};
use nexus_proxy_config::{OutboundConfig, OutboundKind};

use crate::framed::FramedTransport;
use crate::{Counters, ProxyError};

/// Trojan proxy server configuration (plaintext handshake this phase).
///
/// Prefer building from the shared outbound config
/// (`TryFrom<&OutboundConfig>`, T4); `new` is the explicit constructor.
#[derive(Debug, Clone)]
pub struct TrojanProxyConfig {
    /// `ip:port` of the trojan server (IP only — no DNS in the transport, T4).
    pub server: SocketAddr,
    /// Password (sent as `hex(SHA-224(password))`; never logged).
    pub password: String,
    /// TCP connect timeout for the trojan server.
    pub connect_timeout: Duration,
    /// I/O timeout during the trojan handshake.
    pub handshake_timeout: Duration,
}

impl TrojanProxyConfig {
    /// Config with 10s default timeouts.
    pub fn new(server: SocketAddr, password: String) -> Self {
        Self {
            server,
            password,
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl TryFrom<&OutboundConfig> for TrojanProxyConfig {
    type Error = ProxyError;

    /// Reuse the shared outbound config *structure* (T4). `header_format`
    /// is accepted but ignored: `standard` and `singbox` are byte-identical
    /// (PRODUCT §11.9.2). As with ss, this is config reuse, not a layer
    /// merge (X3).
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
        Ok(Self::new(server, password))
    }
}

/// Map a dial target onto the trojan ATYP subset (IPv4 only this phase).
fn trojan_target(target: SocketAddr) -> Result<TrojanTarget, ProxyError> {
    match target.ip() {
        IpAddr::V4(v4) => Ok(TrojanTarget::Ipv4(v4.octets(), target.port())),
        IpAddr::V6(_) => Err(ProxyError::UnsupportedTarget(
            "trojan target must be IPv4 (ATYP subset)",
        )),
    }
}

/// Perform the (plaintext) trojan handshake and return a connected
/// `TcpStream`: write `hex(SHA-224(password)) CRLF 0x01 ATYP ADDR PORT CRLF`.
///
/// There is **no ack** in the trojan protocol — by design, not by omission.
/// A wrong password surfaces as a server-side close on subsequent I/O.
pub fn trojan_connect(
    config: &TrojanProxyConfig,
    target: SocketAddr,
) -> Result<TcpStream, ProxyError> {
    // Validate the target before touching the network (fail fast).
    let tgt = trojan_target(target)?;
    let mut stream = TcpStream::connect_timeout(&config.server, config.connect_timeout)
        .map_err(ProxyError::Io)?;
    stream
        .set_read_timeout(Some(config.handshake_timeout))
        .map_err(ProxyError::Io)?;
    stream
        .set_write_timeout(Some(config.handshake_timeout))
        .map_err(ProxyError::Io)?;

    let req = encode_request(&config.password, &tgt);
    stream.write_all(&req).map_err(ProxyError::Io)?;

    // Handshake done: clear timeouts; the transport sets its own later.
    stream.set_read_timeout(None).map_err(ProxyError::Io)?;
    stream.set_write_timeout(None).map_err(ProxyError::Io)?;
    Ok(stream)
}

/// QUIC datagrams over a trojan-handshaked TCP stream (T2).
///
/// Plaintext 2-byte framing, like the SOCKS5 transport (the TLS upgrade is
/// postponed). Thin wrapper over [`FramedTransport`], mirroring
/// [`ProxyTransport`](crate::ProxyTransport).
pub struct TrojanTransport {
    inner: FramedTransport,
}

impl TrojanTransport {
    /// One-step helper: trojan handshake then wrap (T2).
    pub fn connect(config: &TrojanProxyConfig, target: SocketAddr) -> Result<Self, ProxyError> {
        let stream = trojan_connect(config, target)?;
        let inner = FramedTransport::new(stream, target);
        inner.set_handshake_ok();
        Ok(Self { inner })
    }

    /// The trojan target — the real peer as seen by this transport.
    pub fn target(&self) -> SocketAddr {
        self.inner.target()
    }

    /// T6: `(handshake_ok, handshake_err, framed_bytes)`.
    /// `handshake_ok` is 1 once the request header was fully written
    /// (no ack exists in the trojan protocol).
    pub fn counters(&self) -> (u64, u64, u64) {
        self.inner.counters()
    }

    /// Cloneable handle to the T6 counters.
    pub fn counters_handle(&self) -> Counters {
        self.inner.counters_handle()
    }
}

impl UdpTransport for TrojanTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    /// [`UdpTransport::send_to`]'s `target` parameter is ignored (the TCP
    /// connection *is* the target).
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, target)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    fn test_config(server: SocketAddr) -> TrojanProxyConfig {
        TrojanProxyConfig {
            server,
            password: "trojan-secret".into(),
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    fn outbound_config(kind: OutboundKind) -> OutboundConfig {
        OutboundConfig {
            tag: "t".into(),
            kind,
            locator: Some("127.0.0.1:443".into()),
            method: None,
            password: Some("pw".into()),
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
        }
    }

    /// Read exactly one trojan request header (bounded): 56 hex + CRLF,
    /// CMD, ATYP, addr, port, CRLF.
    fn read_header(s: &mut TcpStream) -> Vec<u8> {
        let mut buf = vec![0u8; 58]; // 56 hex + CRLF
        s.read_exact(&mut buf).unwrap();
        let mut cmd = [0u8; 1];
        s.read_exact(&mut cmd).unwrap();
        buf.extend_from_slice(&cmd);
        let mut atyp = [0u8; 1];
        s.read_exact(&mut atyp).unwrap();
        buf.extend_from_slice(&atyp);
        match atyp[0] {
            0x01 => {
                let mut rest = [0u8; 6];
                s.read_exact(&mut rest).unwrap();
                buf.extend_from_slice(&rest);
            }
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).unwrap();
                buf.push(l[0]);
                let mut rest = vec![0u8; l[0] as usize + 2];
                s.read_exact(&mut rest).unwrap();
                buf.extend_from_slice(&rest);
            }
            b => panic!("unexpected ATYP {b:#04x}"),
        }
        let mut crlf = [0u8; 2];
        s.read_exact(&mut crlf).unwrap();
        assert_eq!(crlf, *b"\r\n");
        buf.extend_from_slice(&crlf);
        buf
    }

    #[test]
    fn handshake_writes_valid_header() {
        use nexus_outbound_trojan::parse_request;
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let raw = read_header(&mut s);
            // The exact bytes must verify against the password (T3 reuse).
            let parsed = parse_request("trojan-secret", &raw).unwrap();
            assert_eq!(parsed, TrojanTarget::Ipv4([127, 0, 0, 1], 9000));
        });
        let stream = trojan_connect(&test_config(addr), target).unwrap();
        assert!(stream.local_addr().is_ok());
    }

    #[test]
    fn handshake_wrong_password_detected_by_server() {
        use nexus_outbound_trojan::{parse_request, TrojanError};
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let raw = read_header(&mut s);
            assert_eq!(
                parse_request("server-password", &raw),
                Err(TrojanError::AuthDenied)
            );
        });
        // Client-side connect still succeeds (no ack in trojan); the failure
        // is observable server-side. This test pins that semantic.
        trojan_connect(&test_config(addr), target).unwrap();
    }

    #[test]
    fn handshake_ipv6_target_unsupported() {
        let target: SocketAddr = "[::1]:9000".parse().unwrap();
        let cfg = test_config("127.0.0.1:1".parse().unwrap());
        let err = trojan_connect(&cfg, target).unwrap_err();
        assert!(
            matches!(err, ProxyError::UnsupportedTarget(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn try_from_outbound_ok() {
        let cfg = TrojanProxyConfig::try_from(&outbound_config(OutboundKind::Trojan)).unwrap();
        assert_eq!(cfg.server, "127.0.0.1:443".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.password, "pw");
    }

    #[test]
    fn try_from_outbound_rejects() {
        // Wrong kind.
        let err =
            TrojanProxyConfig::try_from(&outbound_config(OutboundKind::Shadowsocks)).unwrap_err();
        assert!(matches!(err, ProxyError::BadConfig(_)));

        // Empty password.
        let mut o = outbound_config(OutboundKind::Trojan);
        o.password = Some(String::new());
        assert!(matches!(
            TrojanProxyConfig::try_from(&o).unwrap_err(),
            ProxyError::BadConfig(_)
        ));

        // Domain locator.
        let mut o = outbound_config(OutboundKind::Trojan);
        o.locator = Some("trojan.example:443".into());
        assert!(matches!(
            TrojanProxyConfig::try_from(&o).unwrap_err(),
            ProxyError::BadConfig(_)
        ));
    }

    #[test]
    fn transport_is_send_and_counts_handshake() {
        fn assert_send<T: Send>() {}
        assert_send::<TrojanTransport>();

        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_header(&mut s);
        });
        let tx = TrojanTransport::connect(&test_config(addr), target).unwrap();
        assert_eq!(tx.target(), target);
        assert_eq!(tx.counters().0, 1); // T6 handshake_ok
    }
}
