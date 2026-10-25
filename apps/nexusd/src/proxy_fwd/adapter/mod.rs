//! 出站选择与错误类型（步骤 0 临时选择层）。
//!
//! 本模块在步骤 0 只负责把 `proxy.yaml` 的首个 wired 出站转成
//! `ProxyDialConfig`；步骤 1 会用 `OutboundDialer` / `select_dialer` 取代
//! `select_dialer_legacy` 与 `ProxyDialConfig`（`TODO(deletion-gate: step-1 adapter)`）。

use std::net::{SocketAddr, ToSocketAddrs};

use nexus_proxy_config::{ConfigError, OutboundConfig, OutboundKind};

use super::ProxyDialConfig;

/// 单个出站配置错误（spec §2.6）。错误消息不得包含密码/UUID/hash/obfs_key。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundConfigError {
    MissingLocator,
    InvalidLocator { locator: String },
    UnresolvableLocator { host: String },
    MissingPassword,
    MissingUuid,
    InvalidUuid,
    UnsupportedFlow { flow: String },
    VisionRequiresTls,
    UnsupportedMethod { method: String },
    UnsupportedObfs { field: &'static str },
    PlaintextTrojanUnsupported,
    InvalidSni { sni: String },
    InvalidAlpnEntry,
    InvalidHeaderFormat { format: String },
    UnsupportedTarget { target: SocketAddr },
    InvalidRequest { detail: &'static str },
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
    NoUsableOutbound { skipped: Vec<SkippedOutbound> },
}

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

/// `build_dialer` 的错误：配置错误 vs 未接线（步骤 1 使用）。
#[allow(dead_code)]
#[derive(Debug)]
pub enum BuildDialerError {
    Config(OutboundConfigError),
    ProtocolNotWired { kind: OutboundKind },
}

/// 出站被跳过的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// direct / relay：不是代理出站。
    NotProxyKind,
    /// 协议实现存在但本 run 未接线。
    ProtocolNotWired,
}

/// 被跳过的出站（用于 `NoUsableOutbound` 诊断）。
#[derive(Debug, Clone)]
pub struct SkippedOutbound {
    pub tag: String,
    pub kind: OutboundKind,
    pub reason: SkipReason,
}

/// 步骤 0 临时选路结果（步骤 1 由 `SelectedOutbound` 取代）。
#[derive(Debug)]
pub struct SelectedLegacy {
    pub dial_config: ProxyDialConfig,
    pub skipped: Vec<SkippedOutbound>,
}

fn is_wired(kind: OutboundKind) -> bool {
    matches!(
        kind,
        OutboundKind::Socks5 | OutboundKind::Shadowsocks | OutboundKind::Trojan
    )
}

/// 步骤 0 临时选择层：按文件顺序选首个 wired 出站（spec §2.4 顺序）。
pub(crate) fn select_dialer_legacy(proxy_yaml: &str) -> Result<SelectedLegacy, EngineInitError> {
    let config = nexus_proxy_config::parse(proxy_yaml).map_err(EngineInitError::Yaml)?;
    let mut skipped = Vec::new();
    for outbound in &config.outbounds {
        if matches!(outbound.kind, OutboundKind::Direct | OutboundKind::Relay) {
            skipped.push(SkippedOutbound {
                tag: outbound.tag.clone(),
                kind: outbound.kind,
                reason: SkipReason::NotProxyKind,
            });
            continue;
        }
        if !is_wired(outbound.kind) {
            skipped.push(SkippedOutbound {
                tag: outbound.tag.clone(),
                kind: outbound.kind,
                reason: SkipReason::ProtocolNotWired,
            });
            continue;
        }
        return match build_legacy(outbound) {
            Ok(dial_config) => Ok(SelectedLegacy {
                dial_config,
                skipped,
            }),
            Err(source) => Err(EngineInitError::SelectedInvalid {
                tag: outbound.tag.clone(),
                source,
            }),
        };
    }
    Err(EngineInitError::NoUsableOutbound { skipped })
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
    if non_empty(&outbound.obfs).is_some() {
        return Err(OutboundConfigError::UnsupportedObfs { field: "obfs" });
    }
    if non_empty(&outbound.obfs_key).is_some() {
        return Err(OutboundConfigError::UnsupportedObfs { field: "obfs_key" });
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

fn build_legacy(outbound: &OutboundConfig) -> Result<ProxyDialConfig, OutboundConfigError> {
    check_obfs(outbound)?;
    let locator = non_empty(&outbound.locator).ok_or(OutboundConfigError::MissingLocator)?;
    let (server, host) = resolve_locator(locator)?;
    match outbound.kind {
        OutboundKind::Socks5 => Ok(ProxyDialConfig::Socks5 { server }),
        OutboundKind::Shadowsocks => {
            let password =
                non_empty(&outbound.password).ok_or(OutboundConfigError::MissingPassword)?;
            let method = non_empty(&outbound.method)
                .unwrap_or("chacha20-ietf-poly1305")
                .to_string();
            if method != "chacha20-ietf-poly1305" {
                return Err(OutboundConfigError::UnsupportedMethod { method });
            }
            Ok(ProxyDialConfig::Shadowsocks {
                server,
                method,
                password: password.to_string(),
            })
        }
        OutboundKind::Trojan => {
            let password =
                non_empty(&outbound.password).ok_or(OutboundConfigError::MissingPassword)?;
            let tls_signal = outbound.skip_cert_verify.is_some()
                || outbound.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty());
            if !tls_signal {
                return Err(OutboundConfigError::PlaintextTrojanUnsupported);
            }
            if let Some(alpn) = outbound.alpn.as_ref()
                && alpn.iter().any(|entry| entry.is_empty())
            {
                return Err(OutboundConfigError::InvalidAlpnEntry);
            }
            if let Some(format) = outbound.header_format.as_deref() {
                if format != "standard" && format != "singbox" {
                    return Err(OutboundConfigError::InvalidHeaderFormat {
                        format: format.to_string(),
                    });
                }
            }
            let sni = match non_empty(&outbound.sni) {
                Some(sni) if valid_sni(sni) => sni.to_string(),
                Some(sni) => {
                    return Err(OutboundConfigError::InvalidSni {
                        sni: sni.to_string(),
                    });
                }
                None => host,
            };
            Ok(ProxyDialConfig::TrojanTls {
                server,
                password: password.to_string(),
                sni,
                skip_verify: outbound.skip_cert_verify.unwrap_or(false),
            })
        }
        OutboundKind::Direct
        | OutboundKind::Relay
        | OutboundKind::Vmess
        | OutboundKind::Anytls
        | OutboundKind::Vless
        | OutboundKind::Hysteria2 => Err(OutboundConfigError::InvalidRequest {
            detail: "non-wired outbound cannot be selected",
        }),
    }
}
