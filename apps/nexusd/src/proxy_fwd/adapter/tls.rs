//! TLS 装配（spec §2.1 / §3.1 / §3.2 / §3.5）。
//!
//! - `TrojanTlsConfig` 的字段映射（sni / skip_cert_verify / alpn / 握手超时）；
//! - VLESS / AnyTLS 共用的 rustls 客户端装配：`build_client_config` 只负责
//!   信任根与 ALPN，`connect_tls` 负责 TCP + TLS 握手（超时 `TLS_HANDSHAKE_TIMEOUT`）。
//!
//! 证书校验纪律（spec §3.1/§3.2）：`skip_verify = false` 时使用系统信任根 +
//! hostname 校验；系统根加载失败（`RootsUnavailable`）**不得**降级为跳过校验。

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use nexus_proxy_transport::TrojanTlsConfig;
use rustls::pki_types::ServerName;

use super::{DIAL_TIMEOUT, OutboundError, TLS_HANDSHAKE_TIMEOUT, TlsFailure};

/// rustls 客户端流（持有连接状态与 TCP socket）。
pub(super) type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// 装配 Trojan-over-TLS 配置（密码不落日志；`Debug` 由 crate 手写脱敏）。
pub(super) fn trojan_tls_config(
    server: SocketAddr,
    password: &str,
    sni: &str,
    skip_cert_verify: bool,
    alpn: &[String],
) -> TrojanTlsConfig {
    let mut config = TrojanTlsConfig::new(server, password.to_string(), sni.to_string());
    config.skip_cert_verify = skip_cert_verify;
    config.alpn = alpn.iter().map(|entry| entry.as_bytes().to_vec()).collect();
    config.handshake_timeout = TLS_HANDSHAKE_TIMEOUT;
    config
}

/// 构造 rustls 客户端配置（spec §3.1/§3.2）。
///
/// - `skip_verify = true` → `client_config_dangerous_skip_verify(alpn)`；
/// - `skip_verify = false` → 系统信任根（`rustls-native-certs`）+ 默认校验。
///
/// # Errors
/// 系统根证书不可用 → [`TlsFailure::RootsUnavailable`]（**不**降级为跳过校验）；
/// 跳过校验变体构造失败 → [`TlsFailure::Handshake`]。
pub(super) fn build_client_config(
    skip_verify: bool,
    alpn: &[Vec<u8>],
) -> Result<rustls::ClientConfig, TlsFailure> {
    if skip_verify {
        let alpn_refs: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
        return nexus_outbound_trojan::client_config_dangerous_skip_verify(&alpn_refs)
            .map_err(|_| TlsFailure::Handshake);
    }

    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        return Err(TlsFailure::RootsUnavailable);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in native.certs {
        roots.add(cert).map_err(|_| TlsFailure::RootsUnavailable)?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsFailure::Handshake)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.to_vec();
    Ok(config)
}

/// 一条已建立的出站字节流：明文 TCP 或 TLS。
///
/// VLESS 的 TLS 是可选的，AnyTLS 恒为 TLS；两种形态都需要在握手后按中继
/// 需要设置读写超时并支持半关闭，因此收敛成单一类型，避免两套 `TunnelStream`
/// 实现。
pub(super) enum Transport {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl Transport {
    /// 设置底层 socket 读超时。
    pub(super) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_read_timeout(timeout),
            Self::Tls(stream) => stream.sock.set_read_timeout(timeout),
        }
    }

    /// 设置底层 socket 写超时。
    pub(super) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_write_timeout(timeout),
            Self::Tls(stream) => stream.sock.set_write_timeout(timeout),
        }
    }

    /// 半关闭写方向（spec §3.1：VLESS `shutdown()` = 底层 `shutdown(Write)`）。
    pub(super) fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(Shutdown::Write),
            Self::Tls(stream) => stream.sock.shutdown(Shutdown::Write),
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// TCP 建连（`DIAL_TIMEOUT`）。
///
/// # Errors
/// 超时 → [`OutboundError::ConnectTimeout`]；其他 → [`OutboundError::TcpConnect`]。
pub(super) fn connect_plain(server: SocketAddr) -> Result<Transport, OutboundError> {
    let stream = connect_tcp(server)?;
    Ok(Transport::Plain(stream))
}

/// TCP 建连 + TLS 握手（`TLS_HANDSHAKE_TIMEOUT`）。
///
/// # Errors
/// TCP 失败映射同 [`connect_plain`]；SNI 非法 → [`TlsFailure::InvalidSni`]；
/// 证书/握手失败 → [`TlsFailure::CertificateVerification`] / [`TlsFailure::Handshake`]。
pub(super) fn connect_tls(
    server: SocketAddr,
    sni: &str,
    config: Arc<rustls::ClientConfig>,
) -> Result<Transport, OutboundError> {
    let stream = connect_tcp(server)?;
    stream
        .set_read_timeout(Some(TLS_HANDSHAKE_TIMEOUT))
        .map_err(tls_io_error)?;
    stream
        .set_write_timeout(Some(TLS_HANDSHAKE_TIMEOUT))
        .map_err(tls_io_error)?;

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| OutboundError::TlsHandshake(TlsFailure::InvalidSni))?;
    let connection = rustls::ClientConnection::new(config, server_name)
        .map_err(|_| OutboundError::TlsHandshake(TlsFailure::Handshake))?;
    let mut tls = Box::new(rustls::StreamOwned::new(connection, stream));
    // 显式完成握手：把证书/协议错误暴露在 dial 阶段，而不是首次中继读。
    tls.conn
        .complete_io(&mut tls.sock)
        .map_err(map_handshake_error)?;

    // 握手完成后清空超时；中继层按自身节奏重设（spec §2.2）。
    tls.sock.set_read_timeout(None).map_err(tls_io_error)?;
    tls.sock.set_write_timeout(None).map_err(tls_io_error)?;
    Ok(Transport::Tls(tls))
}

fn connect_tcp(server: SocketAddr) -> Result<TcpStream, OutboundError> {
    match TcpStream::connect_timeout(&server, DIAL_TIMEOUT) {
        Ok(stream) => Ok(stream),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Err(OutboundError::ConnectTimeout),
        Err(error) => Err(OutboundError::TcpConnect { kind: error.kind() }),
    }
}

fn tls_io_error(error: io::Error) -> OutboundError {
    OutboundError::TlsHandshake(TlsFailure::Io { kind: error.kind() })
}

/// 把 TLS 握手 I/O 错误分类为 §2.6.3 的 `TlsFailure`。
fn map_handshake_error(error: io::Error) -> OutboundError {
    if let Some(rustls::Error::InvalidCertificate(_)) =
        error.get_ref().and_then(|inner| inner.downcast_ref())
    {
        return OutboundError::TlsHandshake(TlsFailure::CertificateVerification);
    }
    match error.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::Other => {
            OutboundError::TlsHandshake(TlsFailure::Handshake)
        }
        kind => OutboundError::TlsHandshake(TlsFailure::Io { kind }),
    }
}
