//! Shadowsocks proxy transport (T1).
//!
//! TCP → ss session handshake → per-datagram AEAD seal → 2-byte framing →
//! [`UdpTransport`]. The QUIC driver needs zero changes.
//!
//! Crypto and handshake primitives are **reused** from
//! `nexus-outbound-shadowsocks` (T3) — never reimplemented here. The session
//! ([`SsStream`]) speaks the **SIP004** wire format on the TCP leg
//! (`salt(32) || chunk*`, streaming, random per-direction salt), so the
//! codec is no longer a private look-alike.
//!
//! Honest boundary: the *ack handshake* and the transport topology are still
//! Nexus-internal protocol (the far side is another Nexus node, not a public
//! shadowsocks server). Interop with public ss servers is **not** claimed by
//! this crate; only the product SOCKS5 carrier path is interop-tested.
//!
//! Topology (mirrors a real ss deployment): the ss server *terminates* the
//! AEAD session, parses the target address frame, and relays the decrypted
//! framed bytes to the target. The far side therefore speaks plain
//! [`FramedTransport`] framing.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use nexus_fabric::UdpTransport;
use nexus_outbound_shadowsocks::{encode_request, Role, SsMethod, SsStream, SsTarget};
use nexus_proxy_config::{OutboundConfig, OutboundKind};

use crate::framed::FramedTransport;
use crate::{Counters, ProxyError, MAX_DATAGRAM, MAX_SEALED_FRAME};

/// Server ack payload: proving it derived the same session keys is the
/// authentication (wrong password ⇒ [`OutboundCipherError::DecryptFailed`]).
const SS_ACK: &[u8] = b"ss-proxy-ok";

/// Shadowsocks proxy server configuration.
///
/// Prefer building from the shared outbound config
/// (`TryFrom<&OutboundConfig>`, T4); `new` is the explicit constructor.
#[derive(Debug, Clone)]
pub struct SsProxyConfig {
    /// `ip:port` of the ss server (IP only — no DNS in the transport, T4).
    pub server: SocketAddr,
    /// AEAD method (frozen to `chacha20-ietf-poly1305`, cf. `OutboundConfig` validation).
    pub method: SsMethod,
    /// Password (HKDF-derived session keys).
    pub password: String,
    /// TCP connect timeout for the ss server.
    pub connect_timeout: Duration,
    /// I/O timeout during the ss handshake.
    pub handshake_timeout: Duration,
}

impl SsProxyConfig {
    /// Config with 10s default timeouts.
    pub fn new(server: SocketAddr, method: SsMethod, password: String) -> Self {
        Self {
            server,
            method,
            password,
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl TryFrom<&OutboundConfig> for SsProxyConfig {
    type Error = ProxyError;

    /// Reuse the shared outbound config *structure* (T4). This is config
    /// reuse, not a layer merge: the `OutboundAdapter` trait (per-flow
    /// egress semantics) is still not used — this crate stays per-link
    /// transport (X3).
    fn try_from(o: &OutboundConfig) -> Result<Self, Self::Error> {
        if o.kind != OutboundKind::Shadowsocks {
            return Err(ProxyError::BadConfig(format!(
                "expected shadowsocks outbound, got '{}'",
                o.kind.as_str()
            )));
        }
        let locator = o
            .locator
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ProxyError::BadConfig("shadowsocks outbound requires a locator (IP:port)".into())
            })?;
        let server: SocketAddr = locator.parse().map_err(|_| {
            ProxyError::BadConfig(format!(
                "bad locator '{locator}': expected IP:port (transport does no DNS)"
            ))
        })?;
        let method_label = o.method.as_deref().unwrap_or("chacha20-ietf-poly1305");
        let method = SsMethod::parse(method_label).map_err(|_| {
            ProxyError::BadConfig(format!("unsupported ss method '{method_label}'"))
        })?;
        let password = o
            .password
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ProxyError::BadConfig("shadowsocks outbound requires a non-empty password".into())
            })?;
        Ok(Self::new(server, method, password))
    }
}

/// Map a dial target onto the ss ATYP subset (IPv4 only this phase —
/// matches the outbound crate's `SsTarget`; IPv6 is postponed).
fn ss_target(target: SocketAddr) -> Result<SsTarget, ProxyError> {
    match target.ip() {
        IpAddr::V4(v4) => Ok(SsTarget::Ipv4(v4.octets(), target.port())),
        IpAddr::V6(_) => Err(ProxyError::UnsupportedTarget(
            "shadowsocks target must be IPv4 (ATYP subset)",
        )),
    }
}

/// Read stream bytes until the session yields a non-empty plaintext chunk.
///
/// SIP004 is streaming: a single `read` may deliver only part of the salt or
/// part of a chunk, in which case `open` returns `Ok(empty)` and we keep
/// reading. Errors stay typed (`SsCrypto` for AEAD/framing, `Io` for sockets).
fn read_ack(stream: &mut TcpStream, session: &mut SsStream) -> Result<Vec<u8>, ProxyError> {
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).map_err(ProxyError::Io)?;
        if n == 0 {
            return Err(ProxyError::BadReply("ss handshake ack truncated (eof)"));
        }
        let plain = session.open(&buf[..n]).map_err(ProxyError::SsCrypto)?;
        if !plain.is_empty() {
            return Ok(plain);
        }
    }
}

/// Perform the ss handshake: TCP connect → `seal(encode_request(target))`
/// → await sealed `ss-proxy-ok` ack. Returns the stream and the established
/// session — the session must stay with the transport (per-datagram
/// seal/open on the data path), so this stays `pub(crate)`.
///
/// The handshake writes the SIP004 stream directly (no u32 record framing):
/// the first write carries the client salt.
fn ss_handshake(
    config: &SsProxyConfig,
    target: SocketAddr,
) -> Result<(TcpStream, SsStream), ProxyError> {
    // Validate the target before touching the network (fail fast).
    let ss_tgt = ss_target(target)?;
    let mut stream = TcpStream::connect_timeout(&config.server, config.connect_timeout)
        .map_err(ProxyError::Io)?;
    stream
        .set_read_timeout(Some(config.handshake_timeout))
        .map_err(ProxyError::Io)?;
    stream
        .set_write_timeout(Some(config.handshake_timeout))
        .map_err(ProxyError::Io)?;

    let mut session = SsStream::new(&config.password, config.method, Role::Client)
        .map_err(ProxyError::SsCrypto)?;
    let req = session
        .seal(&encode_request(&ss_tgt))
        .map_err(ProxyError::SsCrypto)?;
    stream.write_all(&req).map_err(ProxyError::Io)?;
    let ack = read_ack(&mut stream, &mut session)?;
    if ack != SS_ACK {
        return Err(ProxyError::BadReply("unexpected ss handshake ack"));
    }

    // Handshake done: clear timeouts; the transport sets its own later.
    stream.set_read_timeout(None).map_err(ProxyError::Io)?;
    stream.set_write_timeout(None).map_err(ProxyError::Io)?;
    Ok((stream, session))
}

/// QUIC datagrams over a shadowsocks session (T1).
///
/// Data path: each datagram is AEAD-sealed with the session (`SsStream`)
/// and then 2-byte framed (T4). `framed_bytes` counts plaintext datagram
/// bytes (same meaning as the SOCKS5 transport's counter).
pub struct SsTransport {
    inner: FramedTransport,
    ss: Mutex<SsStream>,
    target: SocketAddr,
}

impl SsTransport {
    /// One-step helper: ss handshake then wrap (T1).
    pub fn connect(config: &SsProxyConfig, target: SocketAddr) -> Result<Self, ProxyError> {
        let (stream, session) = ss_handshake(config, target)?;
        let inner = FramedTransport::with_max_wire(stream, target, MAX_SEALED_FRAME);
        inner.set_handshake_ok();
        Ok(Self {
            inner,
            ss: Mutex::new(session),
            target,
        })
    }

    /// The ss target — the real peer as seen by this transport.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// T6: `(handshake_ok, handshake_err, framed_bytes)`.
    /// `handshake_ok` is 1 only if the sealed ack verified.
    pub fn counters(&self) -> (u64, u64, u64) {
        self.inner.counters()
    }

    /// Cloneable handle to the T6 counters.
    pub fn counters_handle(&self) -> Counters {
        self.inner.counters_handle()
    }
}

impl UdpTransport for SsTransport {
    fn recv_from(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut sealed = [0u8; MAX_SEALED_FRAME];
        let n = self.inner.recv_frame(&mut sealed)?;
        // Decrypt with the RX (s2c) key; the frame nonce travels in the record.
        let open_result = self
            .ss
            .lock()
            .map_err(|_| std::io::Error::other("ss transport mutex poisoned"))?
            .open(&sealed[..n]);
        let plain = match open_result {
            Ok(p) => p,
            Err(e) => {
                self.inner.record_err();
                return Err(ProxyError::SsCrypto(e).into());
            }
        };
        if plain.len() > buf.len() {
            self.inner.record_err();
            return Err(ProxyError::FrameOverflow {
                frame: plain.len(),
                buf: buf.len(),
            }
            .into());
        }
        buf[..plain.len()].copy_from_slice(&plain);
        self.inner.add_framed_bytes(plain.len() as u64);
        // The "source address" is the real peer (decapsulated), per UdpTransport.
        Ok((plain.len(), self.target))
    }

    /// [`UdpTransport::send_to`]'s `target` parameter is ignored (the TCP
    /// connection *is* the target).
    fn send_to(&self, buf: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
        // X1: the *plaintext* datagram limit stays 1200; the sealed wire
        // frame may reach MAX_SEALED_FRAME (1266): the first chunk of a
        // direction carries the 32B salt, later chunks cost 34B. Later
        // frames here are single-chunk (1200 < 0x3FFF), so 1234B at most;
        // 1266 covers the salt-bearing case and remains the accept bound.
        if buf.len() > MAX_DATAGRAM {
            return Err(ProxyError::FrameTooLarge(buf.len()).into());
        }
        // Seal first, then touch the socket: the two mutexes are never
        // nested, so no lock ordering to get wrong.
        let sealed = self
            .ss
            .lock()
            .map_err(|_| std::io::Error::other("ss transport mutex poisoned"))?
            .seal(buf)
            .map_err(ProxyError::SsCrypto)?;
        debug_assert!(sealed.len() <= MAX_SEALED_FRAME);
        self.inner.send_frame(&sealed)?;
        self.inner.add_framed_bytes(buf.len() as u64);
        Ok(buf.len())
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
    use nexus_outbound_shadowsocks::{
        parse_request as ss_parse_request, OutboundCipherError, SsTarget as SsT,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn test_config(server: SocketAddr) -> SsProxyConfig {
        SsProxyConfig {
            server,
            method: SsMethod::Chacha20IetfPoly1305,
            password: "test-password".into(),
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    fn outbound_config(kind: OutboundKind) -> OutboundConfig {
        OutboundConfig {
            tag: "t".into(),
            kind,
            locator: Some("127.0.0.1:8388".into()),
            method: Some("chacha20-ietf-poly1305".into()),
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

    /// Fake ss server: one handshake against `script`, then exit.
    /// The script receives the accepted stream and the expected password.
    fn fake_server(
        password: &str,
        script: impl FnOnce(TcpStream, SsStream) + Send + 'static,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let pw = password.to_string();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let session = SsStream::new(&pw, SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap();
            script(stream, session);
        });
        addr
    }

    /// Stream-read until the session yields non-empty plaintext.
    fn read_plain(s: &mut TcpStream, sess: &mut SsStream) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).unwrap();
            assert_ne!(n, 0, "eof while waiting for plaintext");
            let plain = sess.open(&buf[..n]).unwrap();
            if !plain.is_empty() {
                return plain;
            }
        }
    }

    /// Stream-write one sealed chunk (first call carries the salt).
    fn write_plain(s: &mut TcpStream, sess: &mut SsStream, plain: &[u8]) {
        s.write_all(&sess.seal(plain).unwrap()).unwrap();
    }

    /// Data path keeps the 2-byte frame on top of the sealed bytes.
    fn read_frame(s: &mut TcpStream) -> Vec<u8> {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).unwrap();
        let len = u16::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).unwrap();
        body
    }

    fn write_frame(s: &mut TcpStream, body: &[u8]) {
        s.write_all(&(body.len() as u16).to_be_bytes()).unwrap();
        s.write_all(body).unwrap();
    }

    #[test]
    fn handshake_ok_with_ack() {
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let addr = fake_server("test-password", move |mut s, mut srv| {
            let plain = read_plain(&mut s, &mut srv);
            assert_eq!(
                ss_parse_request(&plain).unwrap(),
                SsT::Ipv4([127, 0, 0, 1], 9000)
            );
            write_plain(&mut s, &mut srv, SS_ACK);
        });
        let (stream, _session) = ss_handshake(&test_config(addr), target).unwrap();
        assert!(stream.local_addr().is_ok());
    }

    #[test]
    fn handshake_wrong_password_fails() {
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        // Server uses a different password: client's ack open fails.
        let addr = fake_server("other-password", move |mut s, mut srv| {
            // Server can't open the client's request either, but it still
            // seals *something* so the client gets bytes to fail on.
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            s.write_all(&srv.seal(b"nope").unwrap()).unwrap();
        });
        let err = ss_handshake(&test_config(addr), target)
            .err()
            .expect("handshake should fail");
        assert!(
            matches!(
                err,
                ProxyError::SsCrypto(OutboundCipherError::DecryptFailed)
            ),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn handshake_bad_ack_content_rejected() {
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let addr = fake_server("test-password", move |mut s, mut srv| {
            read_plain(&mut s, &mut srv);
            // Correct keys, wrong ack content.
            write_plain(&mut s, &mut srv, b"wrong-ack");
        });
        let err = ss_handshake(&test_config(addr), target)
            .err()
            .expect("handshake should fail");
        assert!(
            matches!(err, ProxyError::BadReply(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn handshake_ipv6_target_unsupported() {
        let target: SocketAddr = "[::1]:9000".parse().unwrap();
        // No server needed: the target check happens before TCP connect.
        let cfg = test_config("127.0.0.1:1".parse().unwrap());
        let err = ss_handshake(&cfg, target)
            .err()
            .expect("handshake should fail");
        assert!(
            matches!(err, ProxyError::UnsupportedTarget(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn seal_overhead_matches_const() {
        // SIP004: empty plaintext emits nothing (and no salt); one byte costs
        // 32(salt) + 18(len) + 1 + 16(tag) = 67 the first time and 18+1+16 = 35
        // afterwards. The per-chunk overhead is 34 and the first-chunk
        // overhead (with salt) is 66.
        assert_eq!(crate::SS_SEAL_OVERHEAD, 34);
        assert_eq!(crate::SS_SALT_LEN, 32);
        assert_eq!(crate::SS_FIRST_CHUNK_OVERHEAD, 66);
        assert_eq!(
            crate::MAX_SEALED_FRAME,
            crate::MAX_DATAGRAM + crate::SS_FIRST_CHUNK_OVERHEAD
        );

        let mut s = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Client).unwrap();
        assert!(s.seal(&[]).unwrap().is_empty());
        assert_eq!(s.seal(b"x").unwrap().len(), 67);
        assert_eq!(s.seal(b"y").unwrap().len(), 35);

        // One max-size datagram is exactly one chunk: first frame 1266
        // (salt-bearing), later frames 1234 — both inside MAX_SEALED_FRAME.
        let mut t = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Client).unwrap();
        assert_eq!(t.seal(&vec![0u8; crate::MAX_DATAGRAM]).unwrap().len(), 1266);
        assert_eq!(t.seal(&vec![0u8; crate::MAX_DATAGRAM]).unwrap().len(), 1234);
    }

    #[test]
    fn try_from_outbound_ok() {
        let cfg = SsProxyConfig::try_from(&outbound_config(OutboundKind::Shadowsocks)).unwrap();
        assert_eq!(cfg.server, "127.0.0.1:8388".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.method, SsMethod::Chacha20IetfPoly1305);
        assert_eq!(cfg.password, "pw");
    }

    #[test]
    fn try_from_outbound_rejects() {
        // Wrong kind.
        let err = SsProxyConfig::try_from(&outbound_config(OutboundKind::Trojan)).unwrap_err();
        assert!(matches!(err, ProxyError::BadConfig(_)));

        // Empty password.
        let mut o = outbound_config(OutboundKind::Shadowsocks);
        o.password = Some(String::new());
        assert!(matches!(
            SsProxyConfig::try_from(&o).unwrap_err(),
            ProxyError::BadConfig(_)
        ));

        // Bad method.
        let mut o = outbound_config(OutboundKind::Shadowsocks);
        o.method = Some("aes-256-gcm".into());
        assert!(matches!(
            SsProxyConfig::try_from(&o).unwrap_err(),
            ProxyError::BadConfig(_)
        ));

        // Domain locator (transport does no DNS).
        let mut o = outbound_config(OutboundKind::Shadowsocks);
        o.locator = Some("proxy.example:8388".into());
        assert!(matches!(
            SsProxyConfig::try_from(&o).unwrap_err(),
            ProxyError::BadConfig(_)
        ));

        // Missing locator.
        let mut o = outbound_config(OutboundKind::Shadowsocks);
        o.locator = None;
        assert!(matches!(
            SsProxyConfig::try_from(&o).unwrap_err(),
            ProxyError::BadConfig(_)
        ));
    }

    #[test]
    fn transport_send_recv_sealed_roundtrip() {
        // SsTransport data path against a loopback peer that speaks
        // sealed records: seal → frame → open must roundtrip.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let target: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut srv = SsStream::new(
                "test-password",
                SsMethod::Chacha20IetfPoly1305,
                Role::Server,
            )
            .unwrap();
            // handshake (streaming SIP004)
            let plain = read_plain(&mut s, &mut srv);
            assert_eq!(
                ss_parse_request(&plain).unwrap(),
                SsT::Ipv4([127, 0, 0, 1], 7777)
            );
            write_plain(&mut s, &mut srv, SS_ACK);
            // echo one sealed datagram back (still 2-byte framed on the data path)
            let sealed = read_frame(&mut s);
            let pt = srv.open(&sealed).unwrap();
            let back = srv.seal(&pt).unwrap();
            write_frame(&mut s, &back);
        });
        let mut tx = SsTransport::connect(&test_config(addr), target).unwrap();
        assert_eq!(tx.counters().0, 1); // T6 handshake_ok
        let msg = b"sealed-datagram";
        tx.send_to(msg, target).unwrap();
        let mut buf = [0u8; 1500];
        let (n, src) = tx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg);
        assert_eq!(src, target);
        // framed_bytes counts plaintext datagram bytes both ways.
        assert_eq!(tx.counters().2, (msg.len() * 2) as u64);
        fn assert_send<T: Send>() {}
        assert_send::<SsTransport>();
    }

    #[test]
    fn transport_send_to_rejects_oversize_plaintext() {
        // X1: the 1200B limit applies to the *plaintext* datagram, so a
        // 1201B payload is rejected even though the sealed frame would fit.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let target: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut srv = SsStream::new(
                "test-password",
                SsMethod::Chacha20IetfPoly1305,
                Role::Server,
            )
            .unwrap();
            read_plain(&mut s, &mut srv);
            write_plain(&mut s, &mut srv, SS_ACK);
        });
        let tx = SsTransport::connect(&test_config(addr), target).unwrap();
        let big = vec![0u8; MAX_DATAGRAM + 1];
        let err = tx.send_to(&big, target).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
