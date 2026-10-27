//! nexus-proxy
//!
//! 代理内核产品线的规则引擎 + 策略组 + 编排 service：消费 `ProxyConfig`，对
//! `nexus-ingress` 产出的 `FlowContext` 执行顺序规则匹配，产出 `rule_action` 动作链，
//! 经策略组解析为选定出站 tag，再委派 `nexus-connectivity` 激活 Direct/Relay 链路。
//!
//! 驱动链（ARCHITECTURE §11）：
//!
//! ```text
//! SOCKS5 Ingress（nexus-ingress Socks5Handshake）
//!   -> FlowContext
//!   -> RuleEngine（静态规则表顺序匹配，纯函数零 I/O）
//!   -> rule_action 动作链（首动作 SELECT_OUTBOUND tag）
//!   -> GroupRegistry（selector / urltest）
//!   -> nexus-connectivity LinkActivator（Direct / Relay）
//! ```
//!
//! 边界：
//! - 规则匹配是领域局部组件，**不是**系统级 Core Planner，不产生第二套系统级 Plan；
//! - urltest 复用 `nexus-measurement::LinkMeasurement` 与 nexus-planner 的「最低 RTT 胜出、
//!   未知排后、同分按 tag 字典序」选择语义，但只消费离线注入的确定性 measurement，
//!   不发起真实网络探测；
//! - 出站激活委派注入的 `LinkActivator`（Composition Root 装配 mock/真实 probe）。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

pub mod domain_engine;
pub mod geoip_nex;
pub mod geosite_nex;

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use nexus_connectivity::{LinkActivator, LinkCandidate, LinkKind, LinkProbe, LinkSelection};
use nexus_domain::{FlowContext, FlowOrigin};
use nexus_measurement::LinkMeasurement;
use nexus_proxy_config::{
    ActionKind, GroupKind, OutboundKind, ProviderBehavior, ProxyConfig, RuleKind,
};

// ---------------------------------------------------------------------------
// 结构化错误（PRODUCT.md §11.3 / MODULE.md Outputs）
// ---------------------------------------------------------------------------

/// 代理内核结构化错误（不以日志文本代替错误类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// 规则表缺 MATCH 兜底且流量未命中任何具体规则（防御性；配置层已保证表尾 MATCH）。
    NoMatchRule,
    /// 动作链选定的出站或策略组 tag 不存在。
    OutboundTagUnresolved { tag: String },
    /// selector 策略组候选列表为空。
    SelectorEmpty { tag: String },
    /// urltest 组所有候选均无有效 measurement。
    UrlTestNoValidCandidate,
    /// 目标目的地无法解析为主机。
    InvalidTarget { target: String },
    /// IP-CIDR 规则参数非法。
    InvalidCidr { cidr: String },
    /// GEOIP 规则引用未注入的国家码。
    UnknownGeoCountry { code: String },
    /// GEOSITE 规则引用未注入的分类。
    UnknownGeoSite { category: String },
    /// RULE-SET 规则引用未定义的 provider。
    UnknownRuleProvider { name: String },
    /// rule-provider 规则行非法（classical 语法 / 嵌套数据规则 / CIDR 非法）。
    InvalidProviderRule { line: String },
    /// 端口规则参数非法（非数字 / 范围起点大于终点 / 空）。
    InvalidPortRange { pattern: String },
    /// 进程名规则参数非法（空 pattern）。
    InvalidProcessPattern { pattern: String },
    /// 出站激活失败（来自注入的 Connectivity 层）。
    Connectivity(String),
    /// 配置层错误透传。
    Config(nexus_proxy_config::ConfigError),
}

impl core::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMatchRule => write!(f, "NO_MATCH_RULE"),
            Self::OutboundTagUnresolved { tag } => {
                write!(f, "OUTBOUND_TAG_UNRESOLVED: {tag}")
            }
            Self::SelectorEmpty { tag } => write!(f, "SELECTOR_EMPTY: {tag}"),
            Self::UrlTestNoValidCandidate => write!(f, "URLTEST_NO_VALID_CANDIDATE"),
            Self::InvalidTarget { target } => write!(f, "INVALID_TARGET: {target}"),
            Self::InvalidCidr { cidr } => write!(f, "INVALID_CIDR: {cidr}"),
            Self::UnknownGeoCountry { code } => write!(f, "GEOIP_UNKNOWN_COUNTRY: {code}"),
            Self::UnknownGeoSite { category } => write!(f, "GEOSITE_UNKNOWN_CATEGORY: {category}"),
            Self::UnknownRuleProvider { name } => write!(f, "RULE_PROVIDER_UNKNOWN: {name}"),
            Self::InvalidProviderRule { line } => write!(f, "RULE_PROVIDER_INVALID_RULE: {line}"),
            Self::InvalidPortRange { pattern } => write!(f, "INVALID_PORT_RANGE: {pattern}"),
            Self::InvalidProcessPattern { pattern } => {
                write!(f, "INVALID_PROCESS_PATTERN: {pattern}")
            }
            Self::Connectivity(msg) => write!(f, "CONNECTIVITY: {msg}"),
            Self::Config(e) => write!(f, "CONFIG_INVALID: {e}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<nexus_proxy_config::ConfigError> for ProxyError {
    fn from(e: nexus_proxy_config::ConfigError) -> Self {
        Self::Config(e)
    }
}

// ---------------------------------------------------------------------------
// 中立分流目标：从 FlowContext.destination 抽出 domain / ip
// ---------------------------------------------------------------------------

/// provider 内容来源（§11.12，命中来源可观察）。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProviderSource {
    /// 纯本地文件（无 `url`）。
    Local,
    /// 使用本地缓存（含拉取失败回退过期缓存）。
    Cached,
    /// 本次从在线源拉取。
    Online,
}

/// provider 拉取结果（§11.12）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedProvider {
    /// 规则集原始行。
    pub lines: Vec<String>,
    /// 内容来源。
    pub source: ProviderSource,
}

/// 规则数据拉取接口（§11.12；纯接口零 I/O，实现由组合根提供）。
///
/// 组合根遍历 `config.rule_providers` 调用 `load`，把结果组装进
/// [`RuleData::providers`]，再经 [`RuleEngine::with_data`](crate::RuleEngine::with_data)
/// 编译期展开——决策内核不感知拉取来源。
pub trait ProviderFetcher {
    /// 加载 provider 原始内容（本地 / 缓存 / 在线），返回行列表与来源。
    fn load(
        &mut self,
        cfg: &nexus_proxy_config::RuleProviderConfig,
    ) -> Result<FetchedProvider, String>;
}

/// 组合根注入的规则数据（§11.11）；决策内核零 I/O，数据全部在编译期展开为静态 `Matcher`。
///
/// `Default` 为空（不启用 GEOIP / GEOSITE / rule-providers），既有调用零回归。
#[derive(Debug, Clone, Default)]
pub struct RuleData {
    /// GEOIP 库：国家码（大写）→ CIDR 列表。
    pub geoip: std::collections::HashMap<String, Vec<String>>,
    /// GEOSITE 清单：分类 → 域名后缀列表。
    pub geosite: std::collections::HashMap<String, Vec<String>>,
    /// rule-providers：provider 名 →（行为，原始行列表）。
    pub providers: std::collections::HashMap<String, (ProviderBehavior, Vec<String>)>,
}

/// 把 classical 规则行 `<KIND>,<pattern>` 编译为匹配器（无 policy 行，action 由引用规则提供）。
///
/// # Errors
///
/// 语法非法 / 嵌套数据规则（geoip、geosite、rule_set）/ CIDR 非法时返回 `InvalidProviderRule`。
fn compile_provider(
    behavior: ProviderBehavior,
    lines: &[String],
) -> Result<Vec<Matcher>, ProxyError> {
    match behavior {
        // domain：合并为单个后缀集（语义等价于逐行，一次匹配）。
        ProviderBehavior::Domain => Ok(vec![Matcher::GeoSite(lines.to_vec())]),
        ProviderBehavior::IpCidr => lines
            .iter()
            .map(|c| {
                IpPrefix::parse(c.trim())
                    .map(Matcher::IpCidr)
                    .map_err(|_| ProxyError::InvalidProviderRule { line: c.clone() })
            })
            .collect(),
        ProviderBehavior::Classical => {
            lines
                .iter()
                .map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return Err(ProxyError::InvalidProviderRule {
                            line: line.to_string(),
                        });
                    }
                    let mut parts = line.splitn(2, ',');
                    let kind_s = parts.next().unwrap_or_default().trim();
                    let pattern = parts.next().unwrap_or_default().trim();
                    let kind =
                        RuleKind::parse(kind_s).map_err(|_| ProxyError::InvalidProviderRule {
                            line: line.to_string(),
                        })?;
                    match kind {
                        RuleKind::DomainSuffix => Ok(Matcher::DomainSuffix(pattern.to_string())),
                        RuleKind::Domain => Ok(Matcher::Domain(pattern.to_string())),
                        RuleKind::IpCidr => {
                            IpPrefix::parse(pattern).map(Matcher::IpCidr).map_err(|_| {
                                ProxyError::InvalidProviderRule {
                                    line: line.to_string(),
                                }
                            })
                        }
                        RuleKind::SrcPort => PortRange::parse(pattern)
                            .map(Matcher::SrcPort)
                            .map_err(|_| ProxyError::InvalidProviderRule {
                                line: line.to_string(),
                            }),
                        RuleKind::DstPort => PortRange::parse(pattern)
                            .map(Matcher::DstPort)
                            .map_err(|_| ProxyError::InvalidProviderRule {
                                line: line.to_string(),
                            }),
                        RuleKind::ProcessName => ProcessPattern::parse(pattern)
                            .map(Matcher::ProcessName)
                            .map_err(|_| ProxyError::InvalidProviderRule {
                                line: line.to_string(),
                            }),
                        RuleKind::Match => Ok(Matcher::Match),
                        RuleKind::GeoIp | RuleKind::GeoSite | RuleKind::RuleSet => {
                            Err(ProxyError::InvalidProviderRule {
                                line: line.to_string(),
                            })
                        }
                    }
                })
                .collect()
        }
    }
}

/// 分流目标（从 `FlowContext.destination` 派生）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTarget {
    /// 目的域名（非 IP literal 时）。
    pub domain: Option<String>,
    /// 目的 IP literal（若是）。
    pub ip: Option<IpAddr>,
    /// 源端口（TUN 路径由调用方设置；SOCKS5 路径为 None）。
    pub src_port: Option<u16>,
    /// 目的端口（从 `destination` 的 `host:port` 解析）。
    pub dst_port: Option<u16>,
    /// 进程名（由调用方经 3e ProcessAttributor 设置；缺失为 None）。
    pub process_name: Option<String>,
}

impl FlowTarget {
    /// 从 `host:port` / `[ipv6]:port` 目的地派生分流目标（纯函数）。
    ///
    /// 目的端口从 `destination` 字符串解析；`src_port` 与 `process_name`
    /// 由调用方在返回后设置（字段为 `pub`）。
    ///
    /// # Errors
    ///
    /// 目的地为空时返回 `InvalidTarget`。
    pub fn from_destination(dest: &str) -> Result<Self, ProxyError> {
        let host = host_from_destination(dest)?;
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(ProxyError::InvalidTarget {
                target: dest.to_string(),
            });
        }
        let dst_port = port_from_destination(dest);
        match host.parse::<IpAddr>() {
            Ok(ip) => Ok(Self {
                domain: None,
                ip: Some(ip),
                src_port: None,
                dst_port,
                process_name: None,
            }),
            Err(_) => Ok(Self {
                domain: Some(host),
                ip: None,
                src_port: None,
                dst_port,
                process_name: None,
            }),
        }
    }
}

/// 去掉 `:port` 尾（处理 `[ipv6]:port`）。
fn host_from_destination(dest: &str) -> Result<String, ProxyError> {
    if let Some(rest) = dest.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| ProxyError::InvalidTarget {
            target: dest.to_string(),
        })?;
        return Ok(rest[..close].to_string());
    }
    match dest.rfind(':') {
        Some(idx) => Ok(dest[..idx].to_string()),
        None => Ok(dest.to_string()),
    }
}

/// 从 `host:port` / `[ipv6]:port` 提取目的端口；无端口或非法时返回 `None`
/// （调用方按"无端口信息"处理，不报错）。
fn port_from_destination(dest: &str) -> Option<u16> {
    if let Some(rest) = dest.strip_prefix('[') {
        // [ipv6]:port
        let close = rest.find(']')?;
        let after = rest[close + 1..].strip_prefix(':')?;
        return after.parse::<u16>().ok();
    }
    // host:port（rfind 取最后一个冒号，避免 IPv6 裸地址误判）
    let idx = dest.rfind(':')?;
    let port_s = &dest[idx + 1..];
    // 裸 IPv6 地址含多个冒号，端口段非纯数字时视为无端口
    if dest[..idx].contains(':') {
        return None;
    }
    port_s.parse::<u16>().ok()
}

/// `FlowOrigin` 的稳定机器可读标签（JSON `flow_origin`）。
#[must_use]
pub fn origin_tag(origin: FlowOrigin) -> &'static str {
    match origin {
        FlowOrigin::Socks5 => "socks5",
        FlowOrigin::Http => "http",
        FlowOrigin::VirtualPacketInterface => "virtual-packet-interface",
        FlowOrigin::NativeApi => "native-api",
        FlowOrigin::TransparentSocket => "transparent-socket",
    }
}

// ---------------------------------------------------------------------------
// IP-CIDR（手写，零第三方依赖）
// ---------------------------------------------------------------------------

/// 一个 IPv4/IPv6 CIDR 前缀。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpPrefix {
    net: IpAddr,
    len: u8,
}

impl IpPrefix {
    /// 解析 `a.b.c.d/len` 或 `aaaa::/len`。
    fn parse(s: &str) -> Result<Self, ProxyError> {
        let (addr_part, prefix_part) =
            s.split_once('/').ok_or_else(|| ProxyError::InvalidCidr {
                cidr: s.to_string(),
            })?;
        let net: IpAddr = addr_part.parse().map_err(|_| ProxyError::InvalidCidr {
            cidr: s.to_string(),
        })?;
        let len: u8 = prefix_part.parse().map_err(|_| ProxyError::InvalidCidr {
            cidr: s.to_string(),
        })?;
        let max = match net {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if len > max {
            return Err(ProxyError::InvalidCidr {
                cidr: s.to_string(),
            });
        }
        Ok(Self { net, len })
    }

    /// 判断 IP 是否落在本网段（地址族不同 → false）。
    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let mask = ipv4_mask(self.len);
                u32::from(net) & mask == u32::from(*addr) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let mask = ipv6_mask(self.len);
                u128::from(net) & mask == u128::from(*addr) & mask
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// IPv4 前缀掩码（len=0 → 0；len=32 → u32::MAX）。
const fn ipv4_mask(len: u8) -> u32 {
    match len {
        0 => 0,
        32 => u32::MAX,
        n => u32::MAX << (32 - n),
    }
}

/// IPv6 前缀掩码（len=0 → 0；len=128 → u128::MAX）。
const fn ipv6_mask(len: u8) -> u128 {
    match len {
        0 => 0,
        128 => u128::MAX,
        n => u128::MAX << (128 - n),
    }
}

// ---------------------------------------------------------------------------
// 端口范围与进程名模式（2026-10-01 新增规则类型）
// ---------------------------------------------------------------------------

/// 端口范围（闭区间 `[start, end]`）。
///
/// 从规则 `match` 字段解析：单端口 `"8080"` 或范围 `"8000-9000"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// 范围起点（含）。
    pub start: u16,
    /// 范围终点（含），恒 `>= start`。
    pub end: u16,
}

impl PortRange {
    /// 解析端口模式。
    ///
    /// # Errors
    ///
    /// 空字符串、非数字、范围起点大于终点时返回 `InvalidPortRange`。
    pub fn parse(s: &str) -> Result<Self, ProxyError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ProxyError::InvalidPortRange {
                pattern: s.to_string(),
            });
        }
        if let Some((lo, hi)) = s.split_once('-') {
            let start: u16 = lo
                .trim()
                .parse()
                .map_err(|_| ProxyError::InvalidPortRange {
                    pattern: s.to_string(),
                })?;
            let end: u16 = hi
                .trim()
                .parse()
                .map_err(|_| ProxyError::InvalidPortRange {
                    pattern: s.to_string(),
                })?;
            if start > end {
                return Err(ProxyError::InvalidPortRange {
                    pattern: s.to_string(),
                });
            }
            Ok(Self { start, end })
        } else {
            let port: u16 = s.parse().map_err(|_| ProxyError::InvalidPortRange {
                pattern: s.to_string(),
            })?;
            Ok(Self {
                start: port,
                end: port,
            })
        }
    }

    /// 端口是否落在范围内（含端点）。
    #[must_use]
    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// 进程名匹配模式：精确匹配或前缀通配（尾部 `*`）。
///
/// - `"chrome"`：精确匹配（大小写敏感）；
/// - `"chrome*"`：前缀匹配（大小写敏感）；
/// - `"*"`：匹配任意非空进程名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPattern {
    prefix: String,
    is_wildcard: bool,
}

impl ProcessPattern {
    /// 解析进程名模式。
    ///
    /// # Errors
    ///
    /// 空 pattern 时返回 `InvalidProcessPattern`。
    pub fn parse(s: &str) -> Result<Self, ProxyError> {
        if s.is_empty() {
            return Err(ProxyError::InvalidProcessPattern {
                pattern: s.to_string(),
            });
        }
        if let Some(prefix) = s.strip_suffix('*') {
            Ok(Self {
                prefix: prefix.to_string(),
                is_wildcard: true,
            })
        } else {
            Ok(Self {
                prefix: s.to_string(),
                is_wildcard: false,
            })
        }
    }

    /// 进程名是否匹配（大小写敏感；`None` 恒为 false，由调用方保证）。
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        if self.is_wildcard {
            name.starts_with(&self.prefix)
        } else {
            name == self.prefix
        }
    }
}

// ---------------------------------------------------------------------------
// 规则匹配器（纯函数，零 I/O）
// ---------------------------------------------------------------------------

enum Matcher {
    DomainSuffix(String),
    Domain(String),
    IpCidr(IpPrefix),
    GeoIp(Vec<IpPrefix>),
    GeoSite(Vec<String>),
    RuleSet(Box<[Matcher]>),
    SrcPort(PortRange),
    DstPort(PortRange),
    ProcessName(ProcessPattern),
    Match,
}

impl Matcher {
    fn matches(&self, target: &FlowTarget) -> bool {
        match self {
            Self::DomainSuffix(suffix) => match &target.domain {
                Some(d) => d == suffix || d.ends_with(&format!(".{suffix}")),
                None => false,
            },
            Self::Domain(d) => target.domain.as_deref() == Some(d.as_str()),
            Self::IpCidr(prefix) => match &target.ip {
                Some(ip) => prefix.contains(ip),
                None => false,
            },
            Self::GeoIp(prefixes) => match &target.ip {
                Some(ip) => prefixes.iter().any(|p| p.contains(ip)),
                None => false,
            },
            Self::GeoSite(domains) => match &target.domain {
                Some(d) => domains
                    .iter()
                    .any(|cat| d == cat || d.ends_with(&format!(".{cat}"))),
                None => false,
            },
            Self::RuleSet(inner) => inner.iter().any(|m| m.matches(target)),
            Self::SrcPort(range) => match target.src_port {
                Some(p) => range.contains(p),
                None => false,
            },
            Self::DstPort(range) => match target.dst_port {
                Some(p) => range.contains(p),
                None => false,
            },
            Self::ProcessName(pattern) => match &target.process_name {
                Some(name) => pattern.matches(name),
                None => false,
            },
            Self::Match => true,
        }
    }
}

// ---------------------------------------------------------------------------
// rule_action 动作链
// ---------------------------------------------------------------------------

/// 单个规则动作（P0 仅 `SELECT_OUTBOUND <tag>`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    /// 选定出站或策略组 tag。
    SelectOutbound(String),
}

impl RuleAction {
    /// 动作类型标签（JSON `first_action`）。
    #[must_use]
    pub fn kind_tag(&self) -> &'static str {
        match self {
            Self::SelectOutbound(_) => "select_outbound",
        }
    }

    /// 动作引用的 tag（出站或策略组）。
    #[must_use]
    pub fn target_tag(&self) -> &str {
        match self {
            Self::SelectOutbound(tag) => tag,
        }
    }
}

/// 编译后的单条规则。
struct CompiledRule {
    tag: String,
    kind: RuleKind,
    matcher: Matcher,
    action: Vec<RuleAction>,
    no_resolve: bool,
}

// ---------------------------------------------------------------------------
// RuleEngine（规则表顺序匹配，首命中即终止）
// ---------------------------------------------------------------------------

/// 单条规则的路由输出（动作链首动作）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOutput {
    /// 命中规则名。
    pub matched_rule: String,
    /// 命中规则类型。
    pub rule_kind: RuleKind,
    /// 动作链首动作标签。
    pub first_action: String,
    /// 首动作本身。
    pub action: RuleAction,
    /// 命中规则的 no-resolve 标志（§11.11）。
    pub no_resolve: bool,
}

/// 规则引擎：从 `ProxyConfig` 构建静态规则表，对 `FlowTarget` 做线性首匹配扫描。
///
/// 纯函数（零 I/O）：相同 `FlowTarget` + 相同 `ProxyConfig` 永远产出同一结果。
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    /// 从配置构建规则表（纯函数，注入空 `RuleData`）。
    ///
    /// # Errors
    ///
    /// IP-CIDR 参数非法时返回 `InvalidCidr`。
    pub fn new(config: &ProxyConfig) -> Result<Self, ProxyError> {
        Self::with_data(config, &RuleData::default())
    }

    /// 从配置构建规则表（纯函数），启用组合根注入的 GEOIP / GEOSITE / rule-providers 数据
    /// （§11.11）；数据全部在编译期展开为静态匹配器，运行匹配零 I/O。
    ///
    /// # Errors
    ///
    /// IP-CIDR 参数非法返回 `InvalidCidr`；引用未注入国家码 / 分类 / provider 或
    /// provider 规则行非法时返回对应结构化错误。
    pub fn with_data(config: &ProxyConfig, data: &RuleData) -> Result<Self, ProxyError> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for r in &config.rules {
            let matcher = match r.kind {
                RuleKind::DomainSuffix => Matcher::DomainSuffix(r.pattern.clone()),
                RuleKind::Domain => Matcher::Domain(r.pattern.clone()),
                RuleKind::IpCidr => Matcher::IpCidr(IpPrefix::parse(&r.pattern)?),
                RuleKind::GeoIp => {
                    let code = r.pattern.to_ascii_uppercase();
                    let prefixes = data
                        .geoip
                        .get(&code)
                        .ok_or_else(|| ProxyError::UnknownGeoCountry { code: code.clone() })?;
                    let parsed = prefixes
                        .iter()
                        .map(|c| IpPrefix::parse(c.trim()))
                        .collect::<Result<Vec<_>, _>>()?;
                    Matcher::GeoIp(parsed)
                }
                RuleKind::GeoSite => {
                    let domains =
                        data.geosite
                            .get(&r.pattern)
                            .ok_or_else(|| ProxyError::UnknownGeoSite {
                                category: r.pattern.clone(),
                            })?;
                    Matcher::GeoSite(domains.clone())
                }
                RuleKind::RuleSet => {
                    let (behavior, lines) = data.providers.get(&r.pattern).ok_or_else(|| {
                        ProxyError::UnknownRuleProvider {
                            name: r.pattern.clone(),
                        }
                    })?;
                    let inner = compile_provider(*behavior, lines)?;
                    Matcher::RuleSet(inner.into_boxed_slice())
                }
                RuleKind::SrcPort => Matcher::SrcPort(PortRange::parse(&r.pattern)?),
                RuleKind::DstPort => Matcher::DstPort(PortRange::parse(&r.pattern)?),
                RuleKind::ProcessName => Matcher::ProcessName(ProcessPattern::parse(&r.pattern)?),
                RuleKind::Match => Matcher::Match,
            };
            let action = r
                .action
                .actions
                .iter()
                .map(|a| match a.kind {
                    ActionKind::SelectOutbound => RuleAction::SelectOutbound(a.tag.clone()),
                })
                .collect();
            rules.push(CompiledRule {
                tag: r.tag.clone(),
                kind: r.kind,
                matcher,
                action,
                no_resolve: r.no_resolve,
            });
        }
        Ok(Self { rules })
    }

    /// 对单个分流目标执行顺序匹配，返回动作链首动作。
    ///
    /// # Errors
    ///
    /// 未命中任何规则（含 MATCH）时返回 `NoMatchRule`。
    pub fn route(&self, target: &FlowTarget) -> Result<RouteOutput, ProxyError> {
        for rule in &self.rules {
            if rule.matcher.matches(target) {
                let first = rule.action.first().ok_or(ProxyError::NoMatchRule)?;
                return Ok(RouteOutput {
                    matched_rule: rule.tag.clone(),
                    rule_kind: rule.kind,
                    first_action: first.kind_tag().to_string(),
                    action: first.clone(),
                    no_resolve: rule.no_resolve,
                });
            }
        }
        Err(ProxyError::NoMatchRule)
    }
}

// ---------------------------------------------------------------------------
// 策略组
// ---------------------------------------------------------------------------

/// 离线确定性 measurement 数据源（由 Composition Root / example 注入；禁止真实探测）。
///
/// 复用 `nexus_measurement::LinkMeasurement` 作为事实值类型，与 nexus-planner 的
/// measurement 选择语义保持一致（RTT 为客观事实，选择策略在本层）。
pub trait MeasurementSource {
    /// 读取某候选的事实测量；未观测返回 `None`（显式未知）。
    fn measurement(&self, candidate: &str) -> Option<LinkMeasurement>;
}

/// 内存离线 measurement 表：候选 tag → 确定性 RTT（毫秒）。
#[derive(Debug, Clone, Default)]
pub struct OfflineMeasurements {
    rows: BTreeMap<String, u32>,
}

impl OfflineMeasurements {
    /// 创建空测量表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录（幂等覆盖）一条候选 RTT。
    pub fn insert(&mut self, candidate: impl Into<String>, rtt_ms: u32) {
        self.rows.insert(candidate.into(), rtt_ms);
    }
}

impl MeasurementSource for OfflineMeasurements {
    fn measurement(&self, candidate: &str) -> Option<LinkMeasurement> {
        self.rows.get(candidate).map(|&ms| LinkMeasurement {
            rtt_ms: Some(ms),
            ..Default::default()
        })
    }
}

/// 手动选择策略组（确定性切换，不探测）。
#[derive(Debug, Clone)]
pub struct SelectorGroup {
    candidates: Vec<String>,
    selected: String,
}

impl SelectorGroup {
    /// 构建选择组。
    ///
    /// # Errors
    ///
    /// 候选为空返回 `SelectorEmpty`；初始选中项不在候选中返回 `OutboundTagUnresolved`。
    pub fn new(candidates: Vec<String>, initial: &str) -> Result<Self, ProxyError> {
        if candidates.is_empty() {
            return Err(ProxyError::SelectorEmpty { tag: String::new() });
        }
        if !candidates.iter().any(|c| c == initial) {
            return Err(ProxyError::OutboundTagUnresolved {
                tag: initial.to_string(),
            });
        }
        Ok(Self {
            candidates,
            selected: initial.to_string(),
        })
    }

    /// 当前选中的出站 tag。
    #[must_use]
    pub fn select(&self) -> &str {
        &self.selected
    }

    /// 切换选中项（确定性，零 I/O）。
    ///
    /// # Errors
    ///
    /// 目标 tag 不在候选中返回 `OutboundTagUnresolved`。
    pub fn switch_to(&mut self, tag: &str) -> Result<(), ProxyError> {
        if !self.candidates.iter().any(|c| c == tag) {
            return Err(ProxyError::OutboundTagUnresolved {
                tag: tag.to_string(),
            });
        }
        self.selected = tag.to_string();
        Ok(())
    }

    /// 候选数量。
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }
}

/// urltest 策略组：按离线 measurement 选最低 RTT 候选。
#[derive(Debug, Clone)]
pub struct UrltestGroup {
    candidates: Vec<String>,
}

impl UrltestGroup {
    /// 构建 urltest 组。
    ///
    /// # Errors
    ///
    /// 候选为空返回 `SelectorEmpty`。
    pub fn new(candidates: Vec<String>) -> Result<Self, ProxyError> {
        if candidates.is_empty() {
            return Err(ProxyError::SelectorEmpty { tag: String::new() });
        }
        Ok(Self { candidates })
    }

    /// 候选数量。
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// 选最低 RTT 候选；同分按 tag 字典序稳定决胜（与 nexus-planner 同语义）。
    ///
    /// # Errors
    ///
    /// 所有候选均无有效 measurement 时返回 `UrlTestNoValidCandidate`。
    pub fn select(&self, source: &dyn MeasurementSource) -> Result<String, ProxyError> {
        lowest_rtt(&self.candidates, source)
    }
}

/// 离线选优：返回最低 RTT 候选；ties 按 tag 字典序决胜。
fn lowest_rtt(candidates: &[String], source: &dyn MeasurementSource) -> Result<String, ProxyError> {
    let mut best: Option<(&str, u32)> = None;
    for c in candidates {
        let Some(m) = source.measurement(c) else {
            continue;
        };
        let Some(rtt) = m.rtt_ms else {
            continue;
        };
        match best {
            None => best = Some((c.as_str(), rtt)),
            Some((bc, brtt)) if rtt < brtt || (rtt == brtt && c.as_str() < bc) => {
                best = Some((c.as_str(), rtt));
            }
            Some(_) => {}
        }
    }
    best.map(|(c, _)| c.to_string())
        .ok_or(ProxyError::UrlTestNoValidCandidate)
}

// ---------------------------------------------------------------------------
// 编排 service：route -> group resolve -> outbound（激活由 Composition Root 注入）
// ---------------------------------------------------------------------------

/// 出站注册表项。
#[derive(Debug, Clone)]
struct OutboundRecord {
    kind: OutboundKind,
    locator: Option<String>,
}

/// 策略组注册表项。
#[derive(Debug)]
struct GroupRecord {
    kind: GroupKind,
    candidates: Vec<String>,
    selected: String,
    /// load_balance round-robin 游标（进程内确定性状态；Cell 保持 route(&self) 不可变签名）。
    cursor: AtomicUsize,
}

/// 一次分流决策的可观察结果（MODULE.md Outputs / PRODUCT.md §11.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    /// 命中规则名。
    pub matched_rule: String,
    /// 命中规则类型。
    pub rule_kind: RuleKind,
    /// 动作链首动作标签。
    pub first_action: String,
    /// 流量来源标签（`socks5`）。
    pub flow_origin: String,
    /// 最终选定的出站 tag。
    pub selected_outbound_tag: String,
    /// 解析到的策略组 tag（若首动作命中组）。
    pub selected_group_tag: Option<String>,
    /// 策略组类型（若首动作命中组）。
    pub group_type: Option<String>,
    /// relay 组的完整跳序列表（非 relay 组为空）；末元素即出口。
    pub relay_hops: Vec<String>,
    /// 命中规则的 no-resolve 标志（§11.11）。
    pub no_resolve: bool,
}

/// 编排 service：持有 RuleEngine + 出站注册表 + 策略组注册表。
///
/// 纯决策（零网络 I/O）；出站链路激活经 `LinkActivator` 注入点完成。
pub struct ProxyService {
    engine: RuleEngine,
    outbounds: HashMap<String, OutboundRecord>,
    groups: HashMap<String, GroupRecord>,
}

impl ProxyService {
    /// 从配置构建编排 service（构建规则表 + 注册表）。
    ///
    /// # Errors
    ///
    /// 规则表编译失败（如非法 CIDR）时返回对应错误。
    pub fn new(config: &ProxyConfig) -> Result<Self, ProxyError> {
        Self::with_rule_data(config, &RuleData::default())
    }

    /// 从配置构建编排 service，启用组合根注入的规则数据（§11.11）。
    pub fn with_rule_data(config: &ProxyConfig, data: &RuleData) -> Result<Self, ProxyError> {
        let engine = RuleEngine::with_data(config, data)?;

        let outbounds = config
            .outbounds
            .iter()
            .map(|o| {
                (
                    o.tag.clone(),
                    OutboundRecord {
                        kind: o.kind,
                        locator: o.locator.clone(),
                    },
                )
            })
            .collect();

        let groups = config
            .groups
            .iter()
            .map(|g| {
                // selector 默认选中首候选（确定性；重启后回配置默认值）。
                let selected = g.candidates.first().cloned().unwrap_or_default();
                (
                    g.tag.clone(),
                    GroupRecord {
                        kind: g.kind,
                        candidates: g.candidates.clone(),
                        selected,
                        cursor: AtomicUsize::new(0),
                    },
                )
            })
            .collect();

        Ok(Self {
            engine,
            outbounds,
            groups,
        })
    }

    /// 对单个入站 FlowContext 执行 route -> group resolve，产出分流决策。
    ///
    /// `measurements` 仅在首动作命中 urltest 组时使用；其余情况传 `None`。
    ///
    /// # Errors
    ///
    /// 目标不可解析 / 未命中 / tag 悬空 / urltest 无有效候选。
    pub fn route(
        &self,
        flow: &FlowContext,
        measurements: Option<&dyn MeasurementSource>,
    ) -> Result<RoutingDecision, ProxyError> {
        let target = FlowTarget::from_destination(&flow.destination)?;
        let routed = self.engine.route(&target)?;
        let action_tag = routed.action.target_tag().to_string();

        let (selected_outbound_tag, selected_group_tag, group_type, relay_hops) =
            match self.groups.get(&action_tag) {
                Some(group) => {
                    let mut relay_hops: Vec<String> = Vec::new();
                    let concrete = match group.kind {
                        GroupKind::Selector => group.selected.clone(),
                        GroupKind::UrlTest => {
                            let source = measurements.ok_or(ProxyError::UrlTestNoValidCandidate)?;
                            lowest_rtt(&group.candidates, source)?
                        }
                        GroupKind::LoadBalance => {
                            let n = group.candidates.len();
                            let idx = group.cursor.fetch_add(1, Ordering::Relaxed) % n;
                            group.candidates[idx].clone()
                        }
                        GroupKind::Relay => {
                            relay_hops = group.candidates.clone();
                            // 出口为跳序末跳（配置已保证非空）。
                            relay_hops.last().cloned().unwrap_or_default()
                        }
                    };
                    (
                        concrete,
                        Some(action_tag.clone()),
                        Some(group.kind.as_str().to_string()),
                        relay_hops,
                    )
                }
                None => {
                    // 直接出站 tag：配置层已校验存在。
                    if !self.outbounds.contains_key(&action_tag) {
                        return Err(ProxyError::OutboundTagUnresolved { tag: action_tag });
                    }
                    (action_tag, None, None, Vec::new())
                }
            };

        Ok(RoutingDecision {
            matched_rule: routed.matched_rule,
            rule_kind: routed.rule_kind,
            first_action: routed.first_action,
            no_resolve: routed.no_resolve,
            flow_origin: origin_tag(flow.origin).to_string(),
            selected_outbound_tag,
            selected_group_tag,
            group_type,
            relay_hops,
        })
    }

    /// 出站激活：把选定出站 tag 委派给注入的 `nexus-connectivity::LinkActivator`
    /// （Direct 成功即直连；Direct 不可达回退 Relay）。P0 由 Composition Root 注入
    /// 离线 mock `LinkProbe`，不建真实网络连接。
    ///
    /// # Errors
    ///
    /// 出站 tag 未注册返回 `OutboundTagUnresolved`；激活失败透传 Connectivity 错误。
    pub fn activate_outbound<P: LinkProbe>(
        &self,
        activator: &LinkActivator<P>,
        selected: &str,
    ) -> Result<LinkSelection, ProxyError> {
        let record =
            self.outbounds
                .get(selected)
                .ok_or_else(|| ProxyError::OutboundTagUnresolved {
                    tag: selected.to_string(),
                })?;
        let locator = record
            .locator
            .clone()
            .unwrap_or_else(|| selected.to_string());
        let direct = LinkCandidate::new(LinkKind::Direct, locator.clone(), 0);
        let relay = match record.kind {
            OutboundKind::Relay => Some(LinkCandidate::new(LinkKind::Relay, locator, 0)),
            // Shadowsocks / VMess / SOCKS5 出站不经 LinkActivator 探测；其链路由对应
            // nexus-outbound-* adapter 在 Composition Root 承接（§11.6/§11.7）。
            OutboundKind::Direct
            | OutboundKind::Shadowsocks
            | OutboundKind::Vmess
            | OutboundKind::Socks5 => None,
            // Trojan 出站不经 LinkActivator 探测；由 nexus-outbound-trojan adapter 在
            // Composition Root 承接（§11.9）。
            OutboundKind::Trojan => None,
            // AnyTLS/VLESS/Hysteria2 同理：由各自 adapter 在 Composition Root 承接。
            OutboundKind::Anytls | OutboundKind::Vless | OutboundKind::Hysteria2 => None,
        };
        activator
            .activate(&direct, relay.as_ref(), false, false)
            .map_err(|e| ProxyError::Connectivity(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_proxy_config::parse;

    fn cfg(yaml: &str) -> ProxyConfig {
        parse(yaml).expect("config must parse")
    }

    const FULL: &str = "\
schema_version: 1
rules:
  - tag: rule-suffix
    kind: domain_suffix
    match: example.com
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-cidr
    kind: ip_cidr
    match: 10.0.0.0/8
    action:
      - kind: select_outbound
        tag: relay
  - tag: rule-match
    kind: match
    action:
      - kind: select_outbound
        tag: fallback
outbounds:
  - tag: direct
    kind: direct
  - tag: relay
    kind: relay
  - tag: fallback
    kind: direct
";

    #[test]
    fn domain_suffix_matches_subdomain_and_exact() {
        let engine = RuleEngine::new(&cfg(FULL)).unwrap();
        let t = FlowTarget::from_destination("mail.example.com:443").unwrap();
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-suffix");
        assert_eq!(out.rule_kind.as_str(), "domain_suffix");

        // 精确等于后缀本身也命中。
        let t = FlowTarget::from_destination("example.com:443").unwrap();
        assert_eq!(engine.route(&t).unwrap().matched_rule, "rule-suffix");
    }

    #[test]
    fn ip_cidr_matches_only_literal_ip() {
        let engine = RuleEngine::new(&cfg(FULL)).unwrap();
        let t = FlowTarget::from_destination("10.1.2.3:8080").unwrap();
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-cidr");
        assert_eq!(out.rule_kind.as_str(), "ip_cidr");

        // 域名不命中 CIDR，落入 MATCH。
        let t = FlowTarget::from_destination("unknown.example.org:443").unwrap();
        assert_eq!(engine.route(&t).unwrap().matched_rule, "rule-match");
    }

    #[test]
    fn no_match_falls_through_to_match_rule() {
        let engine = RuleEngine::new(&cfg(FULL)).unwrap();
        let t = FlowTarget::from_destination("other.net:80").unwrap();
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-match");
        assert_eq!(out.first_action, "select_outbound");
        assert_eq!(out.action.target_tag(), "fallback");
    }

    #[test]
    fn routing_is_deterministic_pure_function() {
        let engine = RuleEngine::new(&cfg(FULL)).unwrap();
        let t = FlowTarget::from_destination("10.9.9.9:53").unwrap();
        assert_eq!(engine.route(&t), engine.route(&t));
    }

    #[test]
    fn selector_switches_deterministically() {
        let mut g = SelectorGroup::new(vec!["direct".into(), "relay".into()], "direct").unwrap();
        assert_eq!(g.select(), "direct");
        g.switch_to("relay").unwrap();
        assert_eq!(g.select(), "relay");
        g.switch_to("direct").unwrap();
        assert_eq!(g.select(), "direct");
        assert_eq!(g.candidate_count(), 2);
    }

    #[test]
    fn urltest_picks_lowest_rtt_with_tie_break_by_tag() {
        let g = UrltestGroup::new(vec!["slow".into(), "fast".into(), "mid".into()]).unwrap();
        let mut src = OfflineMeasurements::new();
        src.insert("slow", 320);
        src.insert("mid", 150);
        src.insert("fast", 85);
        assert_eq!(g.select(&src).unwrap(), "fast");
        assert_eq!(g.candidate_count(), 3);
    }

    #[test]
    fn urltest_no_valid_candidate_errors() {
        let g = UrltestGroup::new(vec!["a".into(), "b".into()]).unwrap();
        let src = OfflineMeasurements::new(); // empty
        assert_eq!(g.select(&src), Err(ProxyError::UrlTestNoValidCandidate));
    }

    #[test]
    fn service_routes_domain_to_direct_outbound() {
        let service = ProxyService::new(&cfg(FULL)).unwrap();
        let flow = nexus_domain_flow("mail.example.com:443");
        let d = service.route(&flow, None).unwrap();
        assert_eq!(d.matched_rule, "rule-suffix");
        assert_eq!(d.selected_outbound_tag, "direct");
        assert_eq!(d.flow_origin, "socks5");
        assert!(d.selected_group_tag.is_none());
    }

    #[test]
    fn service_routes_cidr_to_group_resolved_outbound() {
        let yaml = "\
schema_version: 1
rules:
  - tag: rule-cidr
    kind: ip_cidr
    match: 10.0.0.0/8
    action:
      - kind: select_outbound
        tag: relay-group
  - tag: rule-match
    kind: match
    action:
      - kind: select_outbound
        tag: fallback
outbounds:
  - tag: relay
    kind: relay
  - tag: fallback
    kind: direct
groups:
  - tag: relay-group
    kind: selector
    candidates: [relay]
";
        let service = ProxyService::new(&cfg(yaml)).unwrap();
        let flow = nexus_domain_flow("10.1.2.3:8080");
        let d = service.route(&flow, None).unwrap();
        assert_eq!(d.matched_rule, "rule-cidr");
        assert_eq!(d.selected_group_tag.as_deref(), Some("relay-group"));
        assert_eq!(d.selected_outbound_tag, "relay");
        assert_eq!(d.group_type.as_deref(), Some("selector"));
    }

    #[test]
    fn origin_tag_covers_transparent_socket() {
        assert_eq!(
            origin_tag(FlowOrigin::TransparentSocket),
            "transparent-socket"
        );
        assert_eq!(origin_tag(FlowOrigin::Socks5), "socks5");
    }

    fn nexus_domain_flow(dest: &str) -> FlowContext {
        FlowContext {
            origin: FlowOrigin::Socks5,
            resource: nexus_domain::ResourceId("internet-access".into()),
            destination: dest.to_string(),
            profile: String::new(),
            egress_hint: None,
        }
    }

    // ---- 2026-10-01 新增：端口范围解析 ----
    #[test]
    fn port_range_single() {
        let r = PortRange::parse("8080").unwrap();
        assert_eq!((r.start, r.end), (8080, 8080));
        assert!(r.contains(8080));
        assert!(!r.contains(8081));
    }

    #[test]
    fn port_range_span() {
        let r = PortRange::parse("8000-9000").unwrap();
        assert_eq!((r.start, r.end), (8000, 9000));
        assert!(r.contains(8000));
        assert!(r.contains(8500));
        assert!(r.contains(9000));
        assert!(!r.contains(7999));
        assert!(!r.contains(9001));
    }

    #[test]
    fn port_range_invalid() {
        assert!(PortRange::parse("").is_err());
        assert!(PortRange::parse("abc").is_err());
        assert!(PortRange::parse("9000-8000").is_err()); // start > end
        assert!(PortRange::parse("0-99999").is_err()); // out of u16
        assert!(PortRange::parse("80-").is_err());
    }

    #[test]
    fn port_range_boundary() {
        let r = PortRange::parse("1-65535").unwrap();
        assert!(r.contains(1));
        assert!(r.contains(65535));
        let r0 = PortRange::parse("0").unwrap();
        assert!(r0.contains(0));
    }

    // ---- 2026-10-01 新增：进程名模式 ----
    #[test]
    fn process_pattern_exact() {
        let p = ProcessPattern::parse("chrome").unwrap();
        assert!(p.matches("chrome"));
        assert!(!p.matches("chrome_renderer"));
        assert!(!p.matches("Chrome")); // 大小写敏感
    }

    #[test]
    fn process_pattern_wildcard() {
        let p = ProcessPattern::parse("chrome*").unwrap();
        assert!(p.matches("chrome"));
        assert!(p.matches("chrome_renderer"));
        assert!(!p.matches("firefox"));
        assert!(!p.matches("Chrome")); // 大小写敏感
    }

    #[test]
    fn process_pattern_star_only() {
        let p = ProcessPattern::parse("*").unwrap();
        assert!(p.matches("anything"));
        assert!(p.matches(""));
    }

    #[test]
    fn process_pattern_invalid() {
        assert!(ProcessPattern::parse("").is_err());
    }

    // ---- 2026-10-01 新增：destination 端口解析 ----
    #[test]
    fn port_from_destination_cases() {
        assert_eq!(port_from_destination("example.com:8080"), Some(8080));
        assert_eq!(port_from_destination("10.1.2.3:443"), Some(443));
        assert_eq!(port_from_destination("[::1]:8080"), Some(8080));
        assert_eq!(port_from_destination("example.com"), None);
        assert_eq!(port_from_destination("10.1.2.3"), None);
        // 裸 IPv6 无端口
        assert_eq!(port_from_destination("::1"), None);
    }

    #[test]
    fn flow_target_parses_dst_port() {
        let t = FlowTarget::from_destination("example.com:8080").unwrap();
        assert_eq!(t.dst_port, Some(8080));
        assert_eq!(t.src_port, None);
        assert_eq!(t.process_name, None);

        let t2 = FlowTarget::from_destination("10.1.2.3:443").unwrap();
        assert_eq!(t2.dst_port, Some(443));
        assert!(t2.ip.is_some());
    }

    // ---- 2026-10-01 新增：新 Matcher 匹配 ----
    fn target_with_ports(src: Option<u16>, dst: Option<u16>) -> FlowTarget {
        FlowTarget {
            domain: Some("example.com".to_string()),
            ip: None,
            src_port: src,
            dst_port: dst,
            process_name: None,
        }
    }

    #[test]
    fn matcher_src_port() {
        let m = Matcher::SrcPort(PortRange::parse("9000-9100").unwrap());
        assert!(m.matches(&target_with_ports(Some(9050), None)));
        assert!(m.matches(&target_with_ports(Some(9000), None)));
        assert!(m.matches(&target_with_ports(Some(9100), None)));
        assert!(!m.matches(&target_with_ports(Some(8999), None)));
        assert!(!m.matches(&target_with_ports(None, None))); // None 不命中
    }

    #[test]
    fn matcher_dst_port() {
        let m = Matcher::DstPort(PortRange::parse("8080").unwrap());
        assert!(m.matches(&target_with_ports(None, Some(8080))));
        assert!(!m.matches(&target_with_ports(None, Some(8081))));
        assert!(!m.matches(&target_with_ports(None, None))); // None 不命中
    }

    #[test]
    fn matcher_process_name() {
        let m = Matcher::ProcessName(ProcessPattern::parse("chrome*").unwrap());
        let mut t = target_with_ports(None, None);
        t.process_name = Some("chrome_renderer".to_string());
        assert!(m.matches(&t));
        t.process_name = Some("firefox".to_string());
        assert!(!m.matches(&t));
        t.process_name = None;
        assert!(!m.matches(&t)); // None 不命中
    }

    // ---- 2026-10-01 新增：RuleEngine 端到端 ----
    const EXTENDED: &str = "schema_version: 1\nrules:\n  - tag: rule-dst-port\n    kind: dst_port\n    match: \"8080\"\n    action:\n      - kind: select_outbound\n        tag: direct\n  - tag: rule-src-port\n    kind: src_port\n    match: \"9000-9100\"\n    action:\n      - kind: select_outbound\n        tag: direct\n  - tag: rule-process\n    kind: process_name\n    match: \"chrome*\"\n    action:\n      - kind: select_outbound\n        tag: direct\n  - tag: rule-match\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n";

    #[test]
    fn engine_routes_dst_port() {
        let engine = RuleEngine::new(&cfg(EXTENDED)).unwrap();
        let t = FlowTarget::from_destination("example.com:8080").unwrap();
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-dst-port");
        assert_eq!(out.rule_kind, RuleKind::DstPort);
    }

    #[test]
    fn engine_routes_src_port() {
        let engine = RuleEngine::new(&cfg(EXTENDED)).unwrap();
        let mut t = FlowTarget::from_destination("example.com:443").unwrap();
        t.src_port = Some(9050);
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-src-port");
        assert_eq!(out.rule_kind, RuleKind::SrcPort);
    }

    #[test]
    fn engine_routes_process_name() {
        let engine = RuleEngine::new(&cfg(EXTENDED)).unwrap();
        let mut t = FlowTarget::from_destination("example.com:443").unwrap();
        t.process_name = Some("chrome_renderer".to_string());
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-process");
        assert_eq!(out.rule_kind, RuleKind::ProcessName);
    }

    #[test]
    fn engine_falls_through_on_missing_fields() {
        let engine = RuleEngine::new(&cfg(EXTENDED)).unwrap();
        // 无端口无进程名 -> 三个新规则都不命中 -> MATCH 兜底
        let t = FlowTarget::from_destination("example.com:443").unwrap();
        let out = engine.route(&t).unwrap();
        assert_eq!(out.matched_rule, "rule-match");
        assert_eq!(out.rule_kind, RuleKind::Match);
    }

    #[test]
    fn engine_rejects_bad_port_pattern() {
        const BAD: &str = "schema_version: 1\nrules:\n  - tag: bad\n    kind: dst_port\n    match: \"9000-8000\"\n    action:\n      - kind: select_outbound\n        tag: direct\n  - tag: rule-match\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n";
        let err = match RuleEngine::new(&cfg(BAD)) {
            Ok(_) => panic!("expected InvalidPortRange"),
            Err(e) => e,
        };
        assert!(matches!(err, ProxyError::InvalidPortRange { .. }));
    }

    #[test]
    fn engine_rejects_empty_process_pattern() {
        const BAD: &str = "schema_version: 1\nrules:\n  - tag: bad\n    kind: process_name\n    match: \"\"\n    action:\n      - kind: select_outbound\n        tag: direct\n  - tag: rule-match\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n";
        let err = match RuleEngine::new(&cfg(BAD)) {
            Ok(_) => panic!("expected InvalidProcessPattern"),
            Err(e) => e,
        };
        assert!(matches!(err, ProxyError::InvalidProcessPattern { .. }));
    }
}
