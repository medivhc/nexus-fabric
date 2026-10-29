//! 三个 legacy 出站 adapter（spec §2.3 / §3.5 / §3.6）。
//!
//! - `Socks5Dialer` → `nexus_proxy_transport::socks5_connect`（零行为变化）；
//! - `ShadowsocksCrateDialer` → `nexus-outbound-shadowsocks` 的 SIP004 TCP 会话
//!   （步骤 4 切换；`ss_std` 的 TCP 实现已删除）；
//! - `TrojanProxyTransportDialer` → `trojan_tls_connect`（**始终 TLS**，§3.5）；拨号前经
//!   凭据探测闸门（PRODUCT §11.9.5，`credential_probe: false` 时不探测）。
//!
//! UDP 只做能力声明：SOCKS5 = `Supported(Socks5Associate)`、SS =
//! `Supported(ShadowsocksAead)`、Trojan = `Unsupported(TlsVariantNotSupported)`。

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use nexus_outbound_shadowsocks::{
    OutboundCipherError, Role, SsMethod, SsStream, SsTarget, encode_request,
};
use nexus_proxy_config::OutboundKind;
use nexus_proxy_transport::{
    ProxyError, Socks5ProxyConfig, TlsStream, TrojanTlsConfig, socks5_connect, trojan_tls_connect,
};

use super::trojan_probe::{self, ProbeGate, Verdict};
use super::{
    DIAL_TIMEOUT, HandshakeFailure, OutboundConfigError, OutboundDialer, OutboundError, Protocol,
    TlsFailure, TunnelStream, UdpCapability, UdpMode, UdpUnsupportedReason,
};

/// SOCKS5 出站（RFC 1928 CONNECT）。
pub(crate) struct Socks5Dialer {
    tag: String,
    server: SocketAddr,
}

impl Socks5Dialer {
    pub(crate) fn new(tag: String, server: SocketAddr) -> Self {
        Self { tag, server }
    }
}

impl OutboundDialer for Socks5Dialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Socks5
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        let config = Socks5ProxyConfig::new(self.server, None);
        let stream = socks5_connect(&config, target)
            .map_err(|error| map_proxy_error(error, Protocol::Socks5, target))?;
        Ok(Box::new(TcpTunnel(stream)))
    }

    fn udp_capability(&self) -> UdpCapability {
        UdpCapability::Supported(UdpMode::Socks5Associate {
            server: self.server,
        })
    }
}

/// Shadowsocks 出站：`nexus-outbound-shadowsocks` 的 SIP004 TCP 会话。
///
/// 步骤 4 起生产 SS TCP 走 crate（spec §3.3「fixes-2 之后」）；daemon 内嵌
/// `ss_std` 只保留 UDP 一侧（spec §4.2 条件 5，`TODO(deletion-gate: fixes-6)`）。
pub(crate) struct ShadowsocksCrateDialer {
    tag: String,
    server: SocketAddr,
    password: String,
}

impl ShadowsocksCrateDialer {
    pub(crate) fn new(tag: String, server: SocketAddr, password: String) -> Self {
        // AC-3 字面要求：生产选路时输出 `kind=shadowsocks source=crate`（不含凭据）。
        eprintln!("[proxy-fwd] outbound kind=shadowsocks source=crate tag={tag}");
        Self {
            tag,
            server,
            password,
        }
    }
}

impl OutboundDialer for ShadowsocksCrateDialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Shadowsocks
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        let target = ss_target(target)?;
        // 建连错误沿用 spec §2.7 既有 SS 映射（`Io { kind }`），与切换前一致。
        let mut stream = TcpStream::connect_timeout(&self.server, DIAL_TIMEOUT)
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;
        stream
            .set_read_timeout(Some(DIAL_TIMEOUT))
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;
        stream
            .set_write_timeout(Some(DIAL_TIMEOUT))
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;

        let mut session =
            SsStream::new(&self.password, SsMethod::Chacha20IetfPoly1305, Role::Client)
                .map_err(map_cipher_error)?;
        // 首个 payload = SS request header；`seal` 同时发出本方向 32B salt。
        let header = session
            .seal(&encode_request(&target))
            .map_err(map_cipher_error)?;
        stream
            .write_all(&header)
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;
        stream
            .flush()
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;

        // 握手完成后清空超时；中继层按自身节奏重设（与切换前的内嵌 SS TCP 行为一致）。
        stream
            .set_read_timeout(None)
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;
        stream
            .set_write_timeout(None)
            .map_err(|error| OutboundError::Io { kind: error.kind() })?;

        Ok(Box::new(SsCrateTunnel {
            stream,
            session,
            plain: Vec::new(),
        }))
    }

    fn udp_capability(&self) -> UdpCapability {
        // UDP 本步不切换（crate 无 UDP API）：仍由 `ss_std::SsUdp` 承载。
        UdpCapability::Supported(UdpMode::ShadowsocksAead {
            server: self.server,
            password: self.password.clone(),
        })
    }
}

/// Trojan（proxy-transport，始终 TLS）出站。
pub(crate) struct TrojanProxyTransportDialer {
    tag: String,
    config: TrojanTlsConfig,
    /// 凭据探测状态（MODULE P6）；`credential_probe: false` 时为 `None`。
    probe: Option<ProbeGate>,
}

impl TrojanProxyTransportDialer {
    pub(crate) fn new(tag: String, config: TrojanTlsConfig, credential_probe: bool) -> Self {
        let probe = credential_probe.then(|| ProbeGate::new(tag.clone()));
        Self { tag, config, probe }
    }
}

impl OutboundDialer for TrojanProxyTransportDialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Trojan
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        if let Some(gate) = &self.probe
            && gate.verdict(|| trojan_probe::run_probe(&self.config)) == Verdict::Rejected
        {
            return Err(OutboundError::ProtocolHandshake(
                HandshakeFailure::AuthRejected {
                    protocol: Protocol::Trojan,
                },
            ));
        }
        let stream = trojan_tls_connect(&self.config, target)
            .map_err(|error| map_proxy_error(error, Protocol::Trojan, target))?;
        Ok(Box::new(TlsTunnel(stream)))
    }

    fn udp_capability(&self) -> UdpCapability {
        UdpCapability::Unsupported {
            reason: UdpUnsupportedReason::TlsVariantNotSupported,
        }
    }
}

/// 裸 TCP 隧道（SOCKS5 CONNECT 结果）。
struct TcpTunnel(TcpStream);

impl Read for TcpTunnel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TcpTunnel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl TunnelStream for TcpTunnel {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }
}

/// Trojan-over-TLS 隧道（rustls `StreamOwned`）。
struct TlsTunnel(TlsStream);

impl Read for TlsTunnel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TlsTunnel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl TunnelStream for TlsTunnel {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.sock.set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.sock.set_write_timeout(timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.0.sock.shutdown(Shutdown::Write)
    }
}

/// SS 隧道：`TcpStream` + crate 侧 SIP004 会话（`seal`/`open` + 明文读缓冲）。
struct SsCrateTunnel {
    stream: TcpStream,
    session: SsStream,
    /// 已解密、尚未交给中继的明文（一个 chunk 可能大于调用方 buffer）。
    plain: Vec<u8>,
}

/// 单次 socket 读的线字节缓冲（SIP004 chunk 上限 0x3FFF + 开销 < 16KiB）。
const SS_READ_BUF: usize = 16 * 1024;

impl Read for SsCrateTunnel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.plain.is_empty() {
            let mut wire = [0u8; SS_READ_BUF];
            match self.stream.read(&mut wire) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    // `open` 内部累积未成块的线字节；WouldBlock 不丢缓冲。
                    let plain = self.session.open(&wire[..n]).map_err(cipher_io_error)?;
                    self.plain.extend_from_slice(&plain);
                }
                Err(error) => return Err(error),
            }
        }
        let n = buf.len().min(self.plain.len());
        buf[..n].copy_from_slice(&self.plain[..n]);
        self.plain.drain(..n);
        Ok(n)
    }
}

impl Write for SsCrateTunnel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wire = self.session.seal(buf).map_err(cipher_io_error)?;
        self.stream.write_all(&wire)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl TunnelStream for SsCrateTunnel {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        // SIP004 无半关闭帧：写方向 FIN 由 TCP 层承担（spec §7.2）。
        self.stream.shutdown(Shutdown::Write)
    }
}

/// `ProxyError` → `OutboundError`（spec §2.7 冻结映射）。
fn map_proxy_error(error: ProxyError, protocol: Protocol, target: SocketAddr) -> OutboundError {
    match error {
        ProxyError::Io(error) => OutboundError::Io { kind: error.kind() },
        ProxyError::NoAcceptableAuth | ProxyError::AuthFailed => {
            OutboundError::ProtocolHandshake(HandshakeFailure::AuthRejected { protocol })
        }
        ProxyError::ConnectRejected(code) => {
            OutboundError::ProtocolHandshake(HandshakeFailure::ConnectRejected { protocol, code })
        }
        ProxyError::BadReply(_)
        | ProxyError::SsCrypto(_)
        | ProxyError::FrameTooLarge(_)
        | ProxyError::FrameOverflow { .. } => {
            OutboundError::ProtocolHandshake(HandshakeFailure::InvalidFrame { protocol })
        }
        ProxyError::BadConfig(_) => OutboundError::Config(OutboundConfigError::InvalidRequest {
            detail: "proxy transport rejected the configuration",
        }),
        ProxyError::UnsupportedTarget(_) => {
            OutboundError::Config(OutboundConfigError::UnsupportedTarget { target })
        }
        ProxyError::Tls(_) => OutboundError::TlsHandshake(TlsFailure::Handshake),
    }
}

/// TUN 目标 → SS `ATYP`。`SsTarget` 只编码 IPv4/domain，IPv6 目标按配置拒绝。
fn ss_target(target: SocketAddr) -> Result<SsTarget, OutboundError> {
    match target {
        SocketAddr::V4(addr) => Ok(SsTarget::Ipv4(addr.ip().octets(), addr.port())),
        SocketAddr::V6(_) => Err(OutboundError::Config(
            OutboundConfigError::UnsupportedTarget { target },
        )),
    }
}

/// `OutboundCipherError` → `OutboundError`（dial 阶段，沿用 spec §2.7 SS 行）。
fn map_cipher_error(error: OutboundCipherError) -> OutboundError {
    match error {
        OutboundCipherError::KeyDerivation
        | OutboundCipherError::InvalidFrame
        | OutboundCipherError::DecryptFailed => {
            OutboundError::ProtocolHandshake(HandshakeFailure::InvalidFrame {
                protocol: Protocol::Shadowsocks,
            })
        }
    }
}

/// `OutboundCipherError` → `io::Error`（中继读写阶段；不可恢复即 RST）。
fn cipher_io_error(error: OutboundCipherError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("shadowsocks: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    use nexus_outbound_shadowsocks::parse_request;

    const PAYLOAD: &[u8] = b"ss-crate-payload";
    const REPLY: &[u8] = b"ss-crate-reply";

    /// 进程内 SS 服务端（`SsStream` Role::Server）：证明 dialer 发出的
    /// request header 与 payload 能被对端按 SIP004 解出，且回包能流式读回。
    #[test]
    fn shadowsocks_crate_dialer_delivers_header_and_roundtrips_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut session =
                SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap();
            let mut plain = Vec::new();
            let mut raw = [0u8; 8192];
            while plain.len() < 7 + PAYLOAD.len() {
                let n = tcp.read(&mut raw).unwrap();
                assert!(n > 0, "client closed before request header + payload");
                plain.extend(session.open(&raw[..n]).unwrap());
            }
            let target = parse_request(&plain[..7]).unwrap();
            assert_eq!(target, SsTarget::Ipv4([127, 0, 0, 1], 9000));
            assert_eq!(&plain[7..7 + PAYLOAD.len()], PAYLOAD);
            let wire = session.seal(REPLY).unwrap();
            tcp.write_all(&wire).unwrap();
            tcp.flush().unwrap();
        });

        let dialer =
            ShadowsocksCrateDialer::new("ss-out".to_string(), server_addr, "pw".to_string());
        let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let mut tunnel = dialer.dial_tcp(target).expect("ss dial");
        tunnel.write_all(PAYLOAD).unwrap();
        tunnel.flush().unwrap();
        let mut reply = vec![0u8; REPLY.len()];
        tunnel.read_exact(&mut reply).unwrap();
        assert_eq!(reply, REPLY);
        tunnel.shutdown().unwrap();
        server.join().unwrap();
    }

    /// 大于单个 SIP004 chunk（0x3FFF）的载荷：验证多 chunk seal/open 与
    /// `plain` 余量（读 buffer 小于解出的明文时不得丢字节）。
    #[test]
    fn shadowsocks_crate_tunnel_chunks_large_payload_and_keeps_remainder() {
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let server_payload = payload.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut session =
                SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap();
            let mut plain = Vec::new();
            let mut raw = [0u8; 8192];
            while plain.len() < 7 + server_payload.len() {
                let n = tcp.read(&mut raw).unwrap();
                assert!(n > 0, "client closed before the full payload");
                plain.extend(session.open(&raw[..n]).unwrap());
            }
            assert_eq!(&plain[7..7 + server_payload.len()], &server_payload[..]);
            let wire = session.seal(&server_payload).unwrap();
            tcp.write_all(&wire).unwrap();
            tcp.flush().unwrap();
        });

        let dialer =
            ShadowsocksCrateDialer::new("ss-out".to_string(), server_addr, "pw".to_string());
        let mut tunnel = dialer
            .dial_tcp("127.0.0.1:9000".parse().unwrap())
            .expect("ss dial");
        tunnel.write_all(&payload).unwrap();
        let mut reply = vec![0u8; payload.len()];
        tunnel.read_exact(&mut reply).unwrap();
        assert_eq!(reply, payload);
        server.join().unwrap();
    }

    #[test]
    fn shadowsocks_crate_dialer_rejects_ipv6_target() {
        let dialer = ShadowsocksCrateDialer::new(
            "ss-out".to_string(),
            "127.0.0.1:8388".parse().unwrap(),
            "pw".to_string(),
        );
        match dialer.dial_tcp("[::1]:9000".parse().unwrap()) {
            Err(OutboundError::Config(OutboundConfigError::UnsupportedTarget { target })) => {
                assert_eq!(target, "[::1]:9000".parse().unwrap());
            }
            _ => panic!("expected UnsupportedTarget"),
        }
    }
}
