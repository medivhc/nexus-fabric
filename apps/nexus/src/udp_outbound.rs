//! 出站 UDP 抽象（spec §4.6/§4.7；`apps/nexus` 内部，不扩大 crate 公共 API）。
//!
//! 只承载目标地址、能力声明、会话工厂与规则路由适配；C2 不接
//! `proxy_serve_once`（C4 接线）。三类型 `UdpCapability`/`UdpMode`/
//! `UdpUnsupportedReason` 直接 `use nexus_proxy_config`，不自建同名类型、不建映射层。

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use nexus_ingress::Socks5Address;
use nexus_outbound_vless::VlessFlow;
use nexus_proxy::{ProxyError, ProxyService, RoutingDecision};
use nexus_proxy_config::{
    OutboundConfig, OutboundKind, UdpCapability, UdpMode, UdpUnsupportedReason,
};

use crate::udp_session_anytls::{AnytlsUdpConfig, open_anytls_session};
use crate::udp_session_vless::{VlessUdpConfig, open_vless_session};

/// TCP/QUIC connect 超时（与既有 `udp_relay.rs` 同值）。
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// TLS 握手超时。
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 协议握手超时（VLESS 请求头 / AnyTLS session+stream）。
pub(crate) const PROTOCOL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 会话读轮询超时（100ms；超时/WouldBlock 不算错误）。
pub(crate) const READ_POLL_TIMEOUT: Duration = Duration::from_millis(100);
/// 写超时。
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// 目标地址（域名或 IP + 端口）。Hash 供 flow 表 key 使用。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TargetAddr {
    /// IP 字面量目标。
    Ip(SocketAddr),
    /// 域名目标（不做本地 DNS，原样交给出站协议）。
    Domain { host: String, port: u16 },
}

impl TargetAddr {
    /// 端口。
    pub(crate) fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    /// 转为 SOCKS5 地址（回包头 / 入口解码共用表示）。
    pub(crate) fn to_socks5(&self) -> Socks5Address {
        match self {
            Self::Ip(SocketAddr::V4(v4)) => Socks5Address::Ipv4 {
                addr: v4.ip().octets(),
                port: v4.port(),
            },
            Self::Ip(SocketAddr::V6(v6)) => Socks5Address::Ipv6 {
                addr: v6.ip().octets(),
                port: v6.port(),
            },
            Self::Domain { host, port } => Socks5Address::Domain {
                host: host.clone(),
                port: *port,
            },
        }
    }

    /// 从 SOCKS5 地址转换（入口数据报 → 路由/flow 表）。
    pub(crate) fn from_socks5(address: &Socks5Address) -> Self {
        match address {
            Socks5Address::Ipv4 { addr, port } => Self::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                *port,
            )),
            Socks5Address::Ipv6 { addr, port } => {
                Self::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*addr)), *port))
            }
            Socks5Address::Domain { host, port } => Self::Domain {
                host: host.clone(),
                port: *port,
            },
        }
    }

    /// 既有 `FlowContext` destination 格式（`ProxyService::route` 输入）。
    pub(crate) fn to_destination_string(&self) -> String {
        match self {
            Self::Ip(addr) => addr.to_string(),
            Self::Domain { host, port } => format!("{host}:{port}"),
        }
    }
}

/// 出站 UDP 错误（spec §4.7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpOutboundError {
    /// 协议未接线 / 无 datagram 模式 / 仅 TLS 变体。
    Unsupported {
        kind: OutboundKind,
        reason: UdpUnsupportedReason,
    },
    /// 防御性配置错误。
    Config {
        kind: OutboundKind,
        detail: &'static str,
    },
    /// TCP/QUIC connect 失败。
    Connect { kind: OutboundKind, io: ErrorKind },
    /// connect/TLS/协议握手/发送超时。
    Timeout { kind: OutboundKind, phase: UdpPhase },
    /// TLS 握手/证书/根证书失败。
    Tls {
        kind: OutboundKind,
        failure: UdpTlsFailure,
    },
    /// 协议握手/认证/帧非法。
    Handshake {
        kind: OutboundKind,
        failure: UdpHandshakeFailure,
    },
    /// 发送/接收期 I/O 错误。
    Io { kind: OutboundKind, io: ErrorKind },
    /// 对端关闭。
    Closed { kind: OutboundKind },
    /// 超过协议上限。
    DatagramTooLarge {
        kind: OutboundKind,
        len: usize,
        limit: usize,
    },
    /// 不应发生的不一致。
    Internal { what: &'static str },
}

/// 超时发生的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpPhase {
    /// 建立连接。
    Connect,
    /// TLS 握手。
    TlsHandshake,
    /// 协议握手。
    ProtocolHandshake,
    /// 发送。
    Send,
    /// 接收。
    Receive,
}

/// TLS 失败分类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpTlsFailure {
    /// SNI 无法构造。
    InvalidSni,
    /// 系统根加载失败（不降级 skip）。
    RootsUnavailable,
    /// 证书链/主机名校验失败（不降级 skip）。
    CertificateVerification,
    /// TLS 版本/套件/握手消息失败。
    Handshake,
    /// TLS 底层 I/O 失败/超时。
    Io { kind: ErrorKind },
}

/// 协议握手失败分类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpHandshakeFailure {
    /// 认证拒绝。
    AuthRejected,
    /// 帧头/长度/地址/解密失败。
    InvalidFrame,
    /// 非预期命令/错流。
    UnexpectedFrame,
    /// 服务端拒绝流（reason 已截断去控制字符）。
    StreamRejected { reason: String },
    /// 响应头/Settings 非法。
    ResponseInvalid,
    /// EOF 前不完整。
    Truncated,
    /// 版本不符。
    VersionMismatch { got: u8 },
    /// SOCKS5 类 CONNECT 拒绝。
    ConnectRejected { code: u8 },
    /// 不应发生。
    Internal,
}

/// 一个出站配置对应一个 UDP 出站工厂。
pub(crate) trait UdpOutbound: Send + Sync {
    /// 出站 kind。
    fn kind(&self) -> OutboundKind;
    /// 出站 tag。
    fn tag(&self) -> &str;
    /// 能力声明。
    fn capability(&self) -> UdpCapability;
    /// 为一个目标打开 session；阻塞，调用方在受控上下文中执行。
    fn open_session(&self, target: &TargetAddr) -> Result<Box<dyn UdpSession>, UdpOutboundError>;
}

/// 一个 UDP session（Phase 1 均为 per-target）。
pub(crate) trait UdpSession: Send {
    /// 发送一个数据报（per-target session 只接受自己的 target）。
    fn send(&mut self, target: &TargetAddr, payload: &[u8]) -> Result<(), UdpOutboundError>;
    /// 非阻塞取回包；`None` = 暂无（含 100ms 读超时）。
    fn try_recv(&mut self) -> Result<Option<(TargetAddr, Vec<u8>)>, UdpOutboundError>;
    /// 协作式关闭；幂等。
    fn close(&mut self);
}

/// 会话底层字节流（明文 TCP 或 TLS 之上的流）。
pub(crate) trait UdpStream: Read + Write + Send {}
impl<T: Read + Write + Send> UdpStream for T {}

/// 从 `OutboundConfig` 构造 UDP 出站；不是 UDP kind → `Unsupported`。
pub(crate) fn build_udp_outbound(
    outbound: &OutboundConfig,
) -> Result<Box<dyn UdpOutbound>, UdpOutboundError> {
    let kind = outbound.kind;
    match kind {
        OutboundKind::Vless => Ok(Box::new(VlessUdpOutbound {
            tag: outbound.tag.clone(),
            config: vless_config(outbound)?,
        })),
        OutboundKind::Anytls => Ok(Box::new(AnytlsUdpOutbound {
            tag: outbound.tag.clone(),
            config: anytls_config(outbound)?,
        })),
        OutboundKind::Direct | OutboundKind::Relay | OutboundKind::Vmess => {
            Err(UdpOutboundError::Unsupported {
                kind,
                reason: UdpUnsupportedReason::NoDatagramMode,
            })
        }
        // Trojan/Shadowsocks：crate 无标准 UDP 帧 API（R-3：产品侧取 NotWired）。
        // Hysteria2：实现归后续独立 run。Socks5 出站：Phase 1 不做关联链。
        OutboundKind::Trojan
        | OutboundKind::Shadowsocks
        | OutboundKind::Hysteria2
        | OutboundKind::Socks5 => Err(UdpOutboundError::Unsupported {
            kind,
            reason: UdpUnsupportedReason::NotWired,
        }),
    }
}

/// 规则路由：把 `TargetAddr` 转成 `FlowContext`，复用 `ProxyService::route`。
pub(crate) fn route_udp_target(
    service: &ProxyService,
    target: &TargetAddr,
) -> Result<RoutingDecision, ProxyError> {
    let flow = nexus_ingress::from_socks5(&target.to_destination_string(), "");
    service.route(&flow, None)
}

/// VLESS 出站（一个配置一个工厂；每目标一条 VLESS UDP 连接）。
struct VlessUdpOutbound {
    tag: String,
    config: VlessUdpConfig,
}

impl UdpOutbound for VlessUdpOutbound {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Vless
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn capability(&self) -> UdpCapability {
        // Phase 1 只支持 flow=None；Vision+UDP 线格式未确认（fail-closed）。
        if self.config.flow == VlessFlow::None {
            UdpCapability::Supported(UdpMode::VlessOverTcp {
                server: self.config.server,
            })
        } else {
            UdpCapability::Unsupported {
                reason: UdpUnsupportedReason::NotWired,
            }
        }
    }

    fn open_session(&self, target: &TargetAddr) -> Result<Box<dyn UdpSession>, UdpOutboundError> {
        open_vless_session(&self.config, target)
    }
}

/// AnyTLS 出站（一个配置一个工厂；每目标一条 TLS session + 一条 UoT stream）。
struct AnytlsUdpOutbound {
    tag: String,
    config: AnytlsUdpConfig,
}

impl UdpOutbound for AnytlsUdpOutbound {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Anytls
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn capability(&self) -> UdpCapability {
        UdpCapability::Supported(UdpMode::AnytlsUot {
            server: self.config.server,
        })
    }

    fn open_session(&self, target: &TargetAddr) -> Result<Box<dyn UdpSession>, UdpOutboundError> {
        open_anytls_session(&self.config, target)
    }
}

fn vless_config(outbound: &OutboundConfig) -> Result<VlessUdpConfig, UdpOutboundError> {
    const KIND: OutboundKind = OutboundKind::Vless;
    if crate::outbound_manifest::has_unsupported_obfs(outbound) {
        return Err(UdpOutboundError::Config {
            kind: KIND,
            detail: "obfs unsupported",
        });
    }
    let (server, host) = resolve_locator(KIND, outbound)?;
    let uuid_text = non_empty(&outbound.uuid).ok_or(UdpOutboundError::Config {
        kind: KIND,
        detail: "missing uuid",
    })?;
    let uuid = nexus_outbound_vless::VlessUuid::parse(uuid_text).map_err(|_| {
        UdpOutboundError::Config {
            kind: KIND,
            detail: "invalid uuid",
        }
    })?;
    let flow = VlessFlow::parse(outbound.flow.as_deref().unwrap_or("")).map_err(|_| {
        UdpOutboundError::Config {
            kind: KIND,
            detail: "unsupported flow",
        }
    })?;
    let use_tls = outbound.tls.unwrap_or(false);
    if flow == VlessFlow::XtlsRprxVision && !use_tls {
        return Err(UdpOutboundError::Config {
            kind: KIND,
            detail: "vision requires tls",
        });
    }
    // §3.1：`servername` 作 SNI；缺省 = locator host。
    let sni = non_empty(&outbound.servername)
        .map(str::to_string)
        .unwrap_or(host);
    Ok(VlessUdpConfig {
        server,
        sni,
        uuid,
        flow,
        use_tls,
        skip_cert_verify: outbound.skip_cert_verify.unwrap_or(false),
    })
}

fn anytls_config(outbound: &OutboundConfig) -> Result<AnytlsUdpConfig, UdpOutboundError> {
    const KIND: OutboundKind = OutboundKind::Anytls;
    if crate::outbound_manifest::has_unsupported_obfs(outbound) {
        return Err(UdpOutboundError::Config {
            kind: KIND,
            detail: "obfs unsupported",
        });
    }
    let (server, host) = resolve_locator(KIND, outbound)?;
    let password = non_empty(&outbound.password)
        .ok_or(UdpOutboundError::Config {
            kind: KIND,
            detail: "missing password",
        })?
        .to_string();
    // §3.2：`sni` 优先；缺省 = locator host。
    let sni = non_empty(&outbound.sni).map(str::to_string).unwrap_or(host);
    Ok(AnytlsUdpConfig {
        server,
        sni,
        password,
        skip_cert_verify: outbound.skip_cert_verify.unwrap_or(false),
    })
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.trim().is_empty())
}

/// locator → (SocketAddr, host)。与 nexusd `adapter::resolve_locator` 同规则。
fn resolve_locator(
    kind: OutboundKind,
    outbound: &OutboundConfig,
) -> Result<(SocketAddr, String), UdpOutboundError> {
    let locator = non_empty(&outbound.locator).ok_or(UdpOutboundError::Config {
        kind,
        detail: "missing locator",
    })?;
    let (host, port) = locator.rsplit_once(':').ok_or(UdpOutboundError::Config {
        kind,
        detail: "invalid locator",
    })?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(UdpOutboundError::Config {
            kind,
            detail: "invalid locator",
        });
    }
    let port: u16 = port.parse().map_err(|_| UdpOutboundError::Config {
        kind,
        detail: "invalid locator",
    })?;
    if port == 0 {
        return Err(UdpOutboundError::Config {
            kind,
            detail: "invalid locator",
        });
    }
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|_| UdpOutboundError::Config {
            kind,
            detail: "unresolvable locator",
        })?;
    let server = addrs.next().ok_or(UdpOutboundError::Config {
        kind,
        detail: "unresolvable locator",
    })?;
    Ok((server, host.to_string()))
}

/// 建立 TCP 连接并设置握手期读写超时。
pub(crate) fn connect_tcp(
    kind: OutboundKind,
    server: SocketAddr,
) -> Result<TcpStream, UdpOutboundError> {
    let socket = TcpStream::connect_timeout(&server, CONNECT_TIMEOUT).map_err(|error| {
        if error.kind() == ErrorKind::TimedOut {
            UdpOutboundError::Timeout {
                kind,
                phase: UdpPhase::Connect,
            }
        } else {
            UdpOutboundError::Connect {
                kind,
                io: error.kind(),
            }
        }
    })?;
    socket
        .set_read_timeout(Some(TLS_HANDSHAKE_TIMEOUT))
        .map_err(|error| UdpOutboundError::Io {
            kind,
            io: error.kind(),
        })?;
    socket
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|error| UdpOutboundError::Io {
            kind,
            io: error.kind(),
        })?;
    Ok(socket)
}

/// 握手完成后切到 100ms 读轮询；句柄与原 socket 同 fd，设置对 TLS 包装同样生效。
pub(crate) fn set_poll_timeouts(
    handle: &TcpStream,
    kind: OutboundKind,
) -> Result<(), UdpOutboundError> {
    handle
        .set_read_timeout(Some(READ_POLL_TIMEOUT))
        .map_err(|error| UdpOutboundError::Io {
            kind,
            io: error.kind(),
        })?;
    handle
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|error| UdpOutboundError::Io {
            kind,
            io: error.kind(),
        })
}

/// 客户端 TLS 配置：skip-cert-verify 或系统信任根（不降级）。
pub(crate) fn tls_client_config(
    kind: OutboundKind,
    skip_cert_verify: bool,
) -> Result<Arc<rustls::ClientConfig>, UdpOutboundError> {
    if skip_cert_verify {
        let config =
            nexus_outbound_trojan::client_config_dangerous_skip_verify(&[]).map_err(|_| {
                UdpOutboundError::Tls {
                    kind,
                    failure: UdpTlsFailure::Handshake,
                }
            })?;
        return Ok(Arc::new(config));
    }
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(UdpOutboundError::Tls {
            kind,
            failure: UdpTlsFailure::RootsUnavailable,
        });
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in loaded.certs {
        let _ = roots.add(cert);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| UdpOutboundError::Tls {
            kind,
            failure: UdpTlsFailure::Handshake,
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// 阻塞式 TLS 握手（握手期沿用 socket 的 10s 超时）。
pub(crate) fn tls_connect(
    kind: OutboundKind,
    socket: TcpStream,
    sni: &str,
    config: Arc<rustls::ClientConfig>,
) -> Result<Box<dyn UdpStream>, UdpOutboundError> {
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|_| {
        UdpOutboundError::Tls {
            kind,
            failure: UdpTlsFailure::InvalidSni,
        }
    })?;
    let mut connection =
        rustls::ClientConnection::new(config, name).map_err(|error| UdpOutboundError::Tls {
            kind,
            failure: if matches!(error, rustls::Error::InvalidCertificate(_)) {
                UdpTlsFailure::CertificateVerification
            } else {
                UdpTlsFailure::Handshake
            },
        })?;
    let mut socket = socket;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(|error| {
            if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
                UdpOutboundError::Timeout {
                    kind,
                    phase: UdpPhase::TlsHandshake,
                }
            } else {
                UdpOutboundError::Tls {
                    kind,
                    failure: UdpTlsFailure::Io { kind: error.kind() },
                }
            }
        })?;
    }
    Ok(Box::new(rustls::StreamOwned::new(connection, socket)))
}

/// 协议握手期的写错误（超时归 `ProtocolHandshake`）。
pub(crate) fn map_handshake_write(kind: OutboundKind, error: std::io::Error) -> UdpOutboundError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => UdpOutboundError::Timeout {
            kind,
            phase: UdpPhase::ProtocolHandshake,
        },
        ErrorKind::BrokenPipe
        | ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::NotConnected => UdpOutboundError::Closed { kind },
        other => UdpOutboundError::Io { kind, io: other },
    }
}

/// 发送期错误分类。
pub(crate) fn map_send_error(kind: OutboundKind, error: std::io::Error) -> UdpOutboundError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => UdpOutboundError::Timeout {
            kind,
            phase: UdpPhase::Send,
        },
        ErrorKind::BrokenPipe
        | ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::NotConnected => UdpOutboundError::Closed { kind },
        other => UdpOutboundError::Io { kind, io: other },
    }
}

/// 一次非阻塞读：EOF → `Closed`；超时/WouldBlock → `Ok(false)`（不算错误）。
pub(crate) fn read_into(
    stream: &mut dyn UdpStream,
    buf: &mut Vec<u8>,
    kind: OutboundKind,
) -> Result<bool, UdpOutboundError> {
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Err(UdpOutboundError::Closed { kind }),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                return Ok(true);
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(false);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(UdpOutboundError::Io {
                    kind,
                    io: error.kind(),
                });
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use nexus_proxy_config::{
        ActionChainConfig, ActionConfig, ActionKind, ProxyConfig, RuleConfig, RuleKind,
    };

    fn outbound(kind: OutboundKind) -> OutboundConfig {
        OutboundConfig {
            tag: "node".into(),
            kind,
            locator: Some("127.0.0.1:443".into()),
            method: None,
            password: Some("secret".into()),
            alpn: None,
            skip_cert_verify: Some(true),
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: Some("11111111-1111-1111-1111-111111111111".into()),
            flow: Some(String::new()),
            tls: Some(true),
            servername: Some("node.example".into()),
            sni: Some("node.example".into()),
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
        }
    }

    #[test]
    fn target_addr_roundtrips_through_socks5() {
        let v4 = TargetAddr::Ip("127.0.0.1:5353".parse().unwrap());
        assert_eq!(v4.port(), 5353);
        assert_eq!(v4.to_destination_string(), "127.0.0.1:5353");
        assert_eq!(TargetAddr::from_socks5(&v4.to_socks5()), v4);

        let v6 = TargetAddr::Ip("[2001:db8::1]:53".parse().unwrap());
        assert_eq!(v6.to_destination_string(), "[2001:db8::1]:53");
        assert_eq!(TargetAddr::from_socks5(&v6.to_socks5()), v6);

        let domain = TargetAddr::Domain {
            host: "example.com".into(),
            port: 443,
        };
        assert_eq!(domain.to_destination_string(), "example.com:443");
        assert_eq!(TargetAddr::from_socks5(&domain.to_socks5()), domain);
    }

    #[test]
    fn vless_and_anytls_are_supported_modes() {
        let vless = build_udp_outbound(&outbound(OutboundKind::Vless)).expect("vless");
        assert_eq!(vless.kind(), OutboundKind::Vless);
        assert_eq!(vless.tag(), "node");
        assert_eq!(
            vless.capability(),
            UdpCapability::Supported(UdpMode::VlessOverTcp {
                server: "127.0.0.1:443".parse().unwrap(),
            })
        );

        let anytls = build_udp_outbound(&outbound(OutboundKind::Anytls)).expect("anytls");
        assert_eq!(
            anytls.capability(),
            UdpCapability::Supported(UdpMode::AnytlsUot {
                server: "127.0.0.1:443".parse().unwrap(),
            })
        );
    }

    #[test]
    fn non_udp_kinds_report_expected_reasons() {
        for (kind, reason) in [
            (OutboundKind::Direct, UdpUnsupportedReason::NoDatagramMode),
            (OutboundKind::Relay, UdpUnsupportedReason::NoDatagramMode),
            (OutboundKind::Vmess, UdpUnsupportedReason::NoDatagramMode),
            (OutboundKind::Trojan, UdpUnsupportedReason::NotWired),
            (OutboundKind::Shadowsocks, UdpUnsupportedReason::NotWired),
            (OutboundKind::Socks5, UdpUnsupportedReason::NotWired),
            (OutboundKind::Hysteria2, UdpUnsupportedReason::NotWired),
        ] {
            assert_eq!(
                build_udp_outbound(&outbound(kind)).err(),
                Some(UdpOutboundError::Unsupported { kind, reason }),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn vision_flow_is_fail_closed_not_supported() {
        let mut config = outbound(OutboundKind::Vless);
        config.flow = Some("xtls-rprx-vision".into());
        let outbound = build_udp_outbound(&config).expect("vision builds");
        assert_eq!(
            outbound.capability(),
            UdpCapability::Unsupported {
                reason: UdpUnsupportedReason::NotWired
            }
        );
    }

    #[test]
    fn config_errors_are_structured() {
        let mut missing_uuid = outbound(OutboundKind::Vless);
        missing_uuid.uuid = None;
        assert_eq!(
            build_udp_outbound(&missing_uuid).err(),
            Some(UdpOutboundError::Config {
                kind: OutboundKind::Vless,
                detail: "missing uuid",
            })
        );

        let mut missing_password = outbound(OutboundKind::Anytls);
        missing_password.password = None;
        assert_eq!(
            build_udp_outbound(&missing_password).err(),
            Some(UdpOutboundError::Config {
                kind: OutboundKind::Anytls,
                detail: "missing password",
            })
        );

        let mut bad_locator = outbound(OutboundKind::Vless);
        bad_locator.locator = Some("no-port".into());
        assert_eq!(
            build_udp_outbound(&bad_locator).err(),
            Some(UdpOutboundError::Config {
                kind: OutboundKind::Vless,
                detail: "invalid locator",
            })
        );
    }

    #[test]
    fn route_udp_target_uses_proxy_rules() {
        let config = ProxyConfig {
            schema_version: 1,
            inbounds: Vec::new(),
            rules: vec![RuleConfig {
                tag: "all".into(),
                kind: RuleKind::Match,
                pattern: String::new(),
                action: ActionChainConfig {
                    actions: vec![ActionConfig {
                        kind: ActionKind::SelectOutbound,
                        tag: "node".into(),
                    }],
                },
                no_resolve: false,
            }],
            groups: Vec::new(),
            outbounds: vec![outbound(OutboundKind::Vless)],
            dns: None,
            speedtest: None,
            rule_providers: Vec::new(),
        };
        let service = ProxyService::new(&config).expect("service");
        let target = TargetAddr::Domain {
            host: "example.com".into(),
            port: 443,
        };
        let decision = route_udp_target(&service, &target).expect("route");
        assert_eq!(decision.selected_outbound_tag, "node");

        let v4 = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        assert_eq!(
            route_udp_target(&service, &v4)
                .expect("ip route")
                .selected_outbound_tag,
            "node"
        );
    }
}
