//! 三个 legacy 出站 adapter（spec §2.3 / §3.5 / §3.6）。
//!
//! - `Socks5Dialer` → `nexus_proxy_transport::socks5_connect`（零行为变化）；
//! - `ShadowsocksStdDialer` → daemon 内嵌 `ss_std::SsTcpClient`（行格式零变化）；
//! - `TrojanProxyTransportDialer` → `trojan_tls_connect`（**始终 TLS**，§3.5）。
//!
//! UDP 只做能力声明：SOCKS5 = `Supported(Socks5Associate)`、SS =
//! `Supported(ShadowsocksAead)`、Trojan = `Unsupported(TlsVariantNotSupported)`。

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use nexus_proxy_config::OutboundKind;
use nexus_proxy_transport::{
    ProxyError, Socks5ProxyConfig, TlsStream, TrojanTlsConfig, socks5_connect, trojan_tls_connect,
};

use super::{
    DIAL_TIMEOUT, HandshakeFailure, OutboundConfigError, OutboundDialer, OutboundError, Protocol,
    TlsFailure, TunnelStream, UdpCapability, UdpMode, UdpUnsupportedReason,
};
use crate::proxy_fwd::ss_std::{SsStdError, SsTcpClient};

/// SOCKS5 出站（RFC 1928 CONNECT）。
pub(super) struct Socks5Dialer {
    tag: String,
    server: SocketAddr,
}

impl Socks5Dialer {
    pub(super) fn new(tag: String, server: SocketAddr) -> Self {
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

/// 标准 Shadowsocks（`ss_std`）出站。
pub(super) struct ShadowsocksStdDialer {
    tag: String,
    server: SocketAddr,
    password: String,
}

impl ShadowsocksStdDialer {
    pub(super) fn new(tag: String, server: SocketAddr, password: String) -> Self {
        Self {
            tag,
            server,
            password,
        }
    }
}

impl OutboundDialer for ShadowsocksStdDialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Shadowsocks
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        let client = SsTcpClient::connect(self.server, &self.password, target, DIAL_TIMEOUT)
            .map_err(map_ss_error)?;
        Ok(Box::new(SsStdTunnel { client }))
    }

    fn udp_capability(&self) -> UdpCapability {
        UdpCapability::Supported(UdpMode::ShadowsocksAead {
            server: self.server,
            password: self.password.clone(),
        })
    }
}

/// Trojan（proxy-transport，始终 TLS）出站。
pub(super) struct TrojanProxyTransportDialer {
    tag: String,
    config: TrojanTlsConfig,
}

impl TrojanProxyTransportDialer {
    pub(super) fn new(tag: String, config: TrojanTlsConfig) -> Self {
        Self { tag, config }
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

/// 标准 ss 隧道（`SsTcpClient` 自带分块 AEAD）。
struct SsStdTunnel {
    client: SsTcpClient,
}

impl Read for SsStdTunnel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.client.read(buf).map_err(map_ss_io_error)
    }
}

impl Write for SsStdTunnel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.client.write_all(buf).map_err(map_ss_io_error)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TunnelStream for SsStdTunnel {
    fn set_read_timeout(&mut self, _timeout: Option<Duration>) -> io::Result<()> {
        // 零行为变化：`SsTcpClient` 内部管理超时；旧 relay 对该分支同样不做设置。
        Ok(())
    }

    fn set_write_timeout(&mut self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn shutdown(&mut self) -> io::Result<()> {
        // 标准 ss 无半关闭帧；关闭由 relay 线程 drop 完成（与旧实现一致）。
        Ok(())
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

/// `SsStdError` → `OutboundError`（spec §2.7；dial 阶段）。
fn map_ss_error(error: SsStdError) -> OutboundError {
    match error {
        SsStdError::Io(error) => OutboundError::Io { kind: error.kind() },
        SsStdError::DecryptFailed | SsStdError::BadAddress | SsStdError::TooLarge => {
            OutboundError::ProtocolHandshake(HandshakeFailure::InvalidFrame {
                protocol: Protocol::Shadowsocks,
            })
        }
    }
}

/// `SsStdError` → `io::Error`（中继读写阶段；`Io` 保留原始 kind）。
fn map_ss_io_error(error: SsStdError) -> io::Error {
    match error {
        SsStdError::Io(error) => error,
        other => io::Error::other(other.to_string()),
    }
}
