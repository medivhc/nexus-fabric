//! 出站拨号接缝与选路（spec §2.3–§2.6）。
//!
//! - `TunnelStream` / `OutboundDialer`：数据面冻结 trait（本 crate 内 `pub(crate)`
//!   可见，不向 nexusd crate 外泄漏）；
//! - `build_dialer`：单个 `OutboundConfig` → dialer（不发起网络，域名解析除外）。
//!
//! 多出站选路（`OutboundRegistry` / strict-first）由 `proxy_fwd.rs` 承担（Q-4=A）。
//! UDP 能力三类型定义在 `nexus-proxy-config`，本模块只 re-export。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use nexus_outbound_vless::VlessFlow;
use nexus_proxy_config::{ConfigError, OutboundConfig, OutboundKind};
pub(crate) use nexus_proxy_config::{UdpCapability, UdpMode, UdpUnsupportedReason};

mod anytls;
mod framing;
pub(crate) mod legacy;
mod tls;
mod vless;

#[cfg(test)]
mod tests;

/// TCP connect 超时（spec §2.2；沿用 tcp_relay 既有 10s）。
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// 单次 TLS 握手超时（spec §2.2；与 proxy-transport TrojanTlsConfig 的 10s 对齐）。
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 协议层握手超时（spec §6.6；AnyTLS 的 auth/settings/SYNACK）。
pub(crate) const PROTOCOL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 服务端 reason / 日志 detail 的截断上限（spec §2.2）。
pub(crate) const DETAIL_MAX_BYTES: usize = 128;

/// 一条已建立的、可双向读写的隧道字节流。
///
/// `set_write_timeout` / `shutdown` 由步骤 2 的 framed 协议（AnyTLS/VLESS）消费；
/// 步骤 1 的 relay 只用读超时，故此处整体允许未使用。
#[allow(dead_code)]
pub trait TunnelStream: Read + Write + Send {
    /// 设置底层 socket 读超时；`None` = 阻塞。
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    /// 设置底层 socket 写超时；`None` = 阻塞。
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    /// 半关闭写方向；framed 协议在此发送 FIN/close 帧（AnyTLS Fin；VLESS 无）。
    fn shutdown(&mut self) -> io::Result<()>;
}

/// 出站拨号器：一个配置出站对应一个实例，可被多个流并发调用。
pub trait OutboundDialer: Send + Sync {
    /// 配置 kind（用于日志/标注）。
    fn kind(&self) -> OutboundKind;
    /// 配置 tag（用于日志/标注）。
    fn tag(&self) -> &str;
    /// 拨号到 TUN 流的目标地址；阻塞，调用方在独立线程执行。
    fn dial_tcp(&self, target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError>;
    /// UDP 能力声明；VLESS/AnyTLS 返回 Unsupported{NotWired}。
    fn udp_capability(&self) -> UdpCapability;
}

/// 单个出站配置错误（spec §2.6）。错误消息不得包含密码/UUID/hash/obfs_key。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundConfigError {
    MissingLocator,
    InvalidLocator {
        locator: String,
    },
    UnresolvableLocator {
        host: String,
    },
    MissingPassword,
    MissingUuid,
    InvalidUuid,
    UnsupportedFlow {
        flow: String,
    },
    VisionRequiresTls,
    UnsupportedMethod {
        method: String,
    },
    UnsupportedObfs {
        field: &'static str,
    },
    /// Trojan 缺少显式 TLS 声明（skip_cert_verify 与 alpn 都未出现）；明文不支持。
    PlaintextTrojanUnsupported,
    InvalidSni {
        sni: String,
    },
    InvalidAlpnEntry,
    InvalidHeaderFormat {
        format: String,
    },
    /// 目标地址无法编码进协议 ATYP（例如协议只支持 IPv4）。
    UnsupportedTarget {
        target: SocketAddr,
    },
    /// 已接线协议不应出现的请求编码失败（防御）。
    InvalidRequest {
        detail: &'static str,
    },
}

impl OutboundConfigError {
    /// 稳定变体名（启动失败 JSON 的 `cause` 字段）。
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::MissingLocator => "MISSING_LOCATOR",
            Self::InvalidLocator { .. } => "INVALID_LOCATOR",
            Self::UnresolvableLocator { .. } => "UNRESOLVABLE_LOCATOR",
            Self::MissingPassword => "MISSING_PASSWORD",
            Self::MissingUuid => "MISSING_UUID",
            Self::InvalidUuid => "INVALID_UUID",
            Self::UnsupportedFlow { .. } => "UNSUPPORTED_FLOW",
            Self::VisionRequiresTls => "VISION_REQUIRES_TLS",
            Self::UnsupportedMethod { .. } => "UNSUPPORTED_METHOD",
            Self::UnsupportedObfs { .. } => "UNSUPPORTED_OBFS",
            Self::PlaintextTrojanUnsupported => "PLAINTEXT_TROJAN_UNSUPPORTED",
            Self::InvalidSni { .. } => "INVALID_SNI",
            Self::InvalidAlpnEntry => "INVALID_ALPN_ENTRY",
            Self::InvalidHeaderFormat { .. } => "INVALID_HEADER_FORMAT",
            Self::UnsupportedTarget { .. } => "UNSUPPORTED_TARGET",
            Self::InvalidRequest { .. } => "INVALID_REQUEST",
        }
    }

    /// 安全 detail（不含 locator/sni/密码等用户输入值）。
    #[must_use]
    pub fn detail(&self) -> &'static str {
        match self {
            Self::MissingLocator => "outbound locator is required",
            Self::InvalidLocator { .. } => {
                "outbound locator must be host:port with a non-zero port"
            }
            Self::UnresolvableLocator { .. } => "outbound locator host did not resolve",
            Self::MissingPassword => "outbound password is required",
            Self::MissingUuid => "outbound uuid is required",
            Self::InvalidUuid => "outbound uuid is invalid",
            Self::UnsupportedFlow { .. } => "outbound flow is not supported",
            Self::VisionRequiresTls => "xtls-rprx-vision requires tls=true",
            Self::UnsupportedMethod { .. } => "shadowsocks method must be chacha20-ietf-poly1305",
            Self::UnsupportedObfs { .. } => "obfs/obfs_key are not supported for this protocol",
            Self::PlaintextTrojanUnsupported => {
                "trojan requires explicit TLS signal (skip_cert_verify and/or alpn); plaintext is not supported"
            }
            Self::InvalidSni { .. } => "sni/servername is not a valid TLS server name",
            Self::InvalidAlpnEntry => "alpn entries must be non-empty",
            Self::InvalidHeaderFormat { .. } => {
                "trojan header_format must be 'standard' or 'singbox'"
            }
            Self::UnsupportedTarget { .. } => "target address cannot be encoded by this protocol",
            Self::InvalidRequest { .. } => "request encoding failed",
        }
    }
}

/// 运行期拨号/中继错误（spec §2.6）。`Display` / `Debug` 不得包含密钥材料。
///
/// 变体集合为 spec 冻结全集；步骤 1 只构造 legacy 三协议可达的子集，
/// 其余由步骤 2（VLESS/AnyTLS）与资源边界路径消费。
#[allow(dead_code)]
#[derive(Debug)]
pub enum OutboundError {
    Config(OutboundConfigError),
    TcpConnect { kind: std::io::ErrorKind },
    ConnectTimeout,
    TlsHandshake(TlsFailure),
    ProtocolHandshake(HandshakeFailure),
    Io { kind: std::io::ErrorKind },
    Closed,
    UdpUnsupported,
    Internal { what: &'static str },
}

impl OutboundError {
    /// §6.5 日志 `error=` 枚举值。
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::TcpConnect { .. } => "tcp_connect",
            Self::ConnectTimeout => "connect_timeout",
            Self::TlsHandshake(_) => "tls_handshake",
            Self::ProtocolHandshake(HandshakeFailure::AuthRejected { .. }) => "auth_rejected",
            Self::ProtocolHandshake(HandshakeFailure::StreamRejected { .. }) => "stream_rejected",
            Self::ProtocolHandshake(_) => "protocol_handshake",
            Self::Io { .. } => "io",
            Self::Closed => "closed",
            Self::UdpUnsupported => "udp_unsupported",
            Self::Internal { .. } => "internal",
        }
    }

    /// 安全 detail（≤ `DETAIL_MAX_BYTES`，去控制字符；不含密码/UUID/hash）。
    #[must_use]
    pub fn detail(&self) -> String {
        let text = match self {
            Self::Config(error) => error.detail().to_string(),
            Self::TcpConnect { kind } => format!("tcp connect failed ({kind:?})"),
            Self::ConnectTimeout => "connect timed out".to_string(),
            Self::TlsHandshake(failure) => format!("tls handshake failed ({failure:?})"),
            Self::ProtocolHandshake(HandshakeFailure::StreamRejected { reason, .. }) => {
                format!("protocol handshake failed (stream rejected: {reason})")
            }
            Self::ProtocolHandshake(failure) => {
                format!("protocol handshake failed ({failure:?})")
            }
            Self::Io { kind } => format!("io error ({kind:?})"),
            Self::Closed => "closed".to_string(),
            Self::UdpUnsupported => "udp unsupported by this outbound".to_string(),
            Self::Internal { what } => format!("internal error ({what})"),
        };
        sanitize_detail(&text)
    }
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail())
    }
}

/// 截断到 `DETAIL_MAX_BYTES` 并去掉控制字符（spec §6.5）。
fn sanitize_detail(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_control() {
            continue;
        }
        if out.len() + ch.len_utf8() > DETAIL_MAX_BYTES {
            break;
        }
        out.push(ch);
    }
    out
}

/// TLS 失败分类（spec §2.6.3；全变体冻结，rustls 路径在步骤 2 扩展）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFailure {
    InvalidSni,
    RootsUnavailable,
    CertificateVerification,
    Handshake,
    Io { kind: std::io::ErrorKind },
}

/// 协议标识（握手错误分类用；VLESS/AnyTLS 在步骤 2 接线）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Anytls,
    Shadowsocks,
    Trojan,
    Socks5,
}

/// 协议握手失败（spec §2.6.4；全变体冻结，VLESS/AnyTLS 变体在步骤 2 构造）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeFailure {
    AuthRejected {
        protocol: Protocol,
    },
    InvalidFrame {
        protocol: Protocol,
    },
    UnexpectedFrame {
        protocol: Protocol,
        command: u8,
        stream_id: u32,
    },
    StreamRejected {
        protocol: Protocol,
        stream_id: u32,
        reason: String,
    },
    ResponseInvalid {
        protocol: Protocol,
    },
    Truncated {
        protocol: Protocol,
    },
    VersionMismatch {
        protocol: Protocol,
        got: u8,
    },
    ConnectRejected {
        protocol: Protocol,
        code: u8,
    },
    VisionUuidMismatch {
        protocol: Protocol,
    },
    PaddingSchemeUpdate {
        protocol: Protocol,
    },
}

/// 构造/选择阶段的错误（spec §2.4）。
#[derive(Debug)]
pub enum EngineInitError {
    /// proxy.yaml 语法/结构错误。
    Yaml(ConfigError),
    /// 首个“代理类且已接线”的出站配置非法；硬失败，不跳到下一个出站。
    SelectedInvalid {
        tag: String,
        source: OutboundConfigError,
    },
    /// proxy.yaml 存在，但没有任何可接管的出站。
    NoUsableOutbound {
        skipped: Vec<super::SkippedOutbound>,
    },
}

impl std::fmt::Display for EngineInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(error) => write!(f, "{}: {error}", self.variant()),
            Self::SelectedInvalid { tag, source } => {
                write!(f, "{}: tag={tag} cause={}", self.variant(), source.name())
            }
            Self::NoUsableOutbound { skipped } => {
                write!(f, "{}: skipped={}", self.variant(), skipped.len())
            }
        }
    }
}

impl std::error::Error for EngineInitError {}

impl EngineInitError {
    /// 启动失败 JSON 的 `variant`（与枚举一一对应，spec §2.4/§6.5）。
    #[must_use]
    pub fn variant(&self) -> &'static str {
        match self {
            Self::Yaml(_) => "PROXY_YAML_INVALID",
            Self::SelectedInvalid { .. } => "SELECTED_OUTBOUND_INVALID",
            Self::NoUsableOutbound { .. } => "NO_USABLE_OUTBOUND",
        }
    }
}

/// `build_dialer` 的错误：配置错误 vs 未接线。
#[derive(Debug)]
pub enum BuildDialerError {
    Config(OutboundConfigError),
    ProtocolNotWired { kind: OutboundKind },
}

/// 配置面 warning 码（spec §3.1/§3.2/§5）。步骤 3 的五载体从
/// `verdicts.json.messages` 取文案；本步只登记稳定码，不在 adapter 内渲染文案。
#[allow(dead_code)]
pub(crate) const SNI_IGNORED_FOR_VLESS: &str = "SNI_IGNORED_FOR_VLESS";
#[allow(dead_code)]
pub(crate) const ALPN_IGNORED: &str = "ALPN_IGNORED";
#[allow(dead_code)]
pub(crate) const SERVERNAME_IGNORED_FOR_ANYTLS: &str = "SERVERNAME_IGNORED_FOR_ANYTLS";
#[allow(dead_code)]
pub(crate) const VLESS_VISION_SPLICE_NOT_IMPLEMENTED: &str = "VLESS_VISION_SPLICE_NOT_IMPLEMENTED";

/// 本 run（步骤 1 + 步骤 2）已接线的代理出站集合（spec §1.5 / P3）。
///
/// 唯一实现位于 `nexus::outbound_manifest`（CLI/daemon 共享，spec §2.1/§2.8），
/// 避免步骤 4 切 SS 时两份集合漂移。
pub(crate) fn is_wired(kind: OutboundKind) -> bool {
    ::nexus::outbound_manifest::is_wired(kind)
}

/// 单个出站配置 → dialer；不发起网络（locator 的域名解析除外）。
///
/// # Errors
/// - `Config`：配置非法（spec §2.6.1）；
/// - `ProtocolNotWired`：协议本 run 未接线（vmess/hysteria2）。
pub fn build_dialer(
    outbound: &OutboundConfig,
) -> Result<Arc<dyn OutboundDialer>, BuildDialerError> {
    if !is_wired(outbound.kind) {
        return match outbound.kind {
            OutboundKind::Direct | OutboundKind::Relay => Err(BuildDialerError::Config(
                OutboundConfigError::InvalidRequest {
                    detail: "non-proxy outbound cannot build a dialer",
                },
            )),
            kind => Err(BuildDialerError::ProtocolNotWired { kind }),
        };
    }
    check_obfs(outbound).map_err(BuildDialerError::Config)?;
    let locator = non_empty(&outbound.locator).ok_or(BuildDialerError::Config(
        OutboundConfigError::MissingLocator,
    ))?;
    let (server, host) = resolve_locator(locator).map_err(BuildDialerError::Config)?;
    match outbound.kind {
        OutboundKind::Socks5 => Ok(Arc::new(legacy::Socks5Dialer::new(
            outbound.tag.clone(),
            server,
        ))),
        OutboundKind::Shadowsocks => {
            let password = non_empty(&outbound.password)
                .ok_or(BuildDialerError::Config(
                    OutboundConfigError::MissingPassword,
                ))?
                .to_string();
            let method = non_empty(&outbound.method)
                .unwrap_or("chacha20-ietf-poly1305")
                .to_string();
            if method != "chacha20-ietf-poly1305" {
                return Err(BuildDialerError::Config(
                    OutboundConfigError::UnsupportedMethod { method },
                ));
            }
            Ok(Arc::new(legacy::ShadowsocksCrateDialer::new(
                outbound.tag.clone(),
                server,
                password,
            )))
        }
        OutboundKind::Trojan => {
            let password = non_empty(&outbound.password)
                .ok_or(BuildDialerError::Config(
                    OutboundConfigError::MissingPassword,
                ))?
                .to_string();
            // §3.5：TLS 始终启用；skip_cert_verify / alpn 任一出现即 TLS 声明。
            let tls_signal = outbound.skip_cert_verify.is_some()
                || outbound.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty());
            if !tls_signal {
                return Err(BuildDialerError::Config(
                    OutboundConfigError::PlaintextTrojanUnsupported,
                ));
            }
            let alpn = outbound.alpn.clone().unwrap_or_default();
            if alpn.iter().any(|entry| entry.is_empty()) {
                return Err(BuildDialerError::Config(
                    OutboundConfigError::InvalidAlpnEntry,
                ));
            }
            if let Some(format) = outbound.header_format.as_deref()
                && format != "standard"
                && format != "singbox"
            {
                return Err(BuildDialerError::Config(
                    OutboundConfigError::InvalidHeaderFormat {
                        format: format.to_string(),
                    },
                ));
            }
            let sni = match non_empty(&outbound.sni) {
                Some(sni) if valid_sni(sni) => sni.to_string(),
                Some(sni) => {
                    return Err(BuildDialerError::Config(OutboundConfigError::InvalidSni {
                        sni: sni.to_string(),
                    }));
                }
                None => host,
            };
            let config = tls::trojan_tls_config(
                server,
                &password,
                &sni,
                outbound.skip_cert_verify.unwrap_or(false),
                &alpn,
            );
            Ok(Arc::new(legacy::TrojanProxyTransportDialer::new(
                outbound.tag.clone(),
                config,
            )))
        }
        OutboundKind::Vless => {
            let uuid_text = non_empty(&outbound.uuid)
                .ok_or(BuildDialerError::Config(OutboundConfigError::MissingUuid))?;
            let uuid = nexus_outbound_vless::VlessUuid::parse(uuid_text)
                .map_err(|_| BuildDialerError::Config(OutboundConfigError::InvalidUuid))?;
            let flow_text = outbound.flow.as_deref().unwrap_or("");
            let flow = VlessFlow::parse(flow_text).map_err(|_| {
                BuildDialerError::Config(OutboundConfigError::UnsupportedFlow {
                    flow: flow_text.to_string(),
                })
            })?;
            let use_tls = outbound.tls.unwrap_or(false);
            if flow == VlessFlow::XtlsRprxVision && !use_tls {
                return Err(BuildDialerError::Config(
                    OutboundConfigError::VisionRequiresTls,
                ));
            }
            // §3.1：`servername` 作 SNI；缺省 = locator host；`sni` 忽略（warning 码登记）。
            let sni = match non_empty(&outbound.servername) {
                Some(server_name) if valid_sni(server_name) => server_name.to_string(),
                Some(server_name) => {
                    return Err(BuildDialerError::Config(OutboundConfigError::InvalidSni {
                        sni: server_name.to_string(),
                    }));
                }
                None => host,
            };
            Ok(Arc::new(vless::VlessDialer::new(
                outbound.tag.clone(),
                server,
                sni,
                uuid,
                flow,
                use_tls,
                outbound.skip_cert_verify.unwrap_or(false),
            )))
        }
        OutboundKind::Anytls => {
            let password = non_empty(&outbound.password)
                .ok_or(BuildDialerError::Config(
                    OutboundConfigError::MissingPassword,
                ))?
                .to_string();
            // §3.2：`sni` 优先；缺省 = locator host；`servername` 忽略（warning 码登记）。
            let sni = match non_empty(&outbound.sni) {
                Some(sni) if valid_sni(sni) => sni.to_string(),
                Some(sni) => {
                    return Err(BuildDialerError::Config(OutboundConfigError::InvalidSni {
                        sni: sni.to_string(),
                    }));
                }
                None => host,
            };
            Ok(Arc::new(anytls::AnytlsDialer::new(
                outbound.tag.clone(),
                server,
                sni,
                password,
                outbound.skip_cert_verify.unwrap_or(false),
            )))
        }
        _ => Err(BuildDialerError::ProtocolNotWired {
            kind: outbound.kind,
        }),
    }
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.trim().is_empty())
}

fn resolve_locator(locator: &str) -> Result<(SocketAddr, String), OutboundConfigError> {
    let invalid = || OutboundConfigError::InvalidLocator {
        locator: locator.to_string(),
    };
    let (host, port) = locator.rsplit_once(':').ok_or_else(invalid)?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(invalid());
    }
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    let mut addrs =
        (host, port)
            .to_socket_addrs()
            .map_err(|_| OutboundConfigError::UnresolvableLocator {
                host: host.to_string(),
            })?;
    let server = addrs
        .next()
        .ok_or_else(|| OutboundConfigError::UnresolvableLocator {
            host: host.to_string(),
        })?;
    Ok((server, host.to_string()))
}

fn check_obfs(outbound: &OutboundConfig) -> Result<(), OutboundConfigError> {
    // 与 `nexus config check` 共享同一判定（review r1 B2：两份校验曾对
    // obfs_key 给出相反结论）。
    if ::nexus::outbound_manifest::has_unsupported_obfs(outbound) {
        let field = if non_empty(&outbound.obfs).is_some() {
            "obfs"
        } else {
            "obfs_key"
        };
        return Err(OutboundConfigError::UnsupportedObfs { field });
    }
    Ok(())
}

fn valid_sni(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '/')
}
