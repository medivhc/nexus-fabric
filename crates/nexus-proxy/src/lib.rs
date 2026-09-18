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

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use nexus_connectivity::{LinkActivator, LinkCandidate, LinkKind, LinkProbe, LinkSelection};
use nexus_domain::{FlowContext, FlowOrigin};
use nexus_measurement::LinkMeasurement;
use nexus_proxy_config::{ActionKind, GroupKind, OutboundKind, ProxyConfig, RuleKind};

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

/// 分流目标（从 `FlowContext.destination` 派生）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTarget {
    /// 目的域名（非 IP literal 时）。
    pub domain: Option<String>,
    /// 目的 IP literal（若是）。
    pub ip: Option<IpAddr>,
}

impl FlowTarget {
    /// 从 `host:port` / `[ipv6]:port` 目的地派生分流目标（纯函数）。
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
        match host.parse::<IpAddr>() {
            Ok(ip) => Ok(Self {
                domain: None,
                ip: Some(ip),
            }),
            Err(_) => Ok(Self {
                domain: Some(host),
                ip: None,
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

/// `FlowOrigin` 的稳定机器可读标签（JSON `flow_origin`）。
#[must_use]
pub fn origin_tag(origin: FlowOrigin) -> &'static str {
    match origin {
        FlowOrigin::Socks5 => "socks5",
        FlowOrigin::Http => "http",
        FlowOrigin::VirtualPacketInterface => "virtual-packet-interface",
        FlowOrigin::NativeApi => "native-api",
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
// 规则匹配器（纯函数，零 I/O）
// ---------------------------------------------------------------------------

enum Matcher {
    DomainSuffix(String),
    Domain(String),
    IpCidr(IpPrefix),
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
}

/// 规则引擎：从 `ProxyConfig` 构建静态规则表，对 `FlowTarget` 做线性首匹配扫描。
///
/// 纯函数（零 I/O）：相同 `FlowTarget` + 相同 `ProxyConfig` 永远产出同一结果。
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    /// 从配置构建规则表（纯函数）。
    ///
    /// # Errors
    ///
    /// IP-CIDR 参数非法时返回 `InvalidCidr`。
    pub fn new(config: &ProxyConfig) -> Result<Self, ProxyError> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for r in &config.rules {
            let matcher = match r.kind {
                RuleKind::DomainSuffix => Matcher::DomainSuffix(r.pattern.clone()),
                RuleKind::Domain => Matcher::Domain(r.pattern.clone()),
                RuleKind::IpCidr => Matcher::IpCidr(IpPrefix::parse(&r.pattern)?),
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
#[derive(Debug, Clone)]
struct GroupRecord {
    kind: GroupKind,
    candidates: Vec<String>,
    selected: String,
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
        let engine = RuleEngine::new(config)?;

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

        let (selected_outbound_tag, selected_group_tag, group_type) =
            match self.groups.get(&action_tag) {
                Some(group) => {
                    let concrete = match group.kind {
                        GroupKind::Selector => group.selected.clone(),
                        GroupKind::UrlTest => {
                            let source = measurements.ok_or(ProxyError::UrlTestNoValidCandidate)?;
                            lowest_rtt(&group.candidates, source)?
                        }
                    };
                    (
                        concrete,
                        Some(action_tag.clone()),
                        Some(group.kind.as_str().to_string()),
                    )
                }
                None => {
                    // 直接出站 tag：配置层已校验存在。
                    if !self.outbounds.contains_key(&action_tag) {
                        return Err(ProxyError::OutboundTagUnresolved { tag: action_tag });
                    }
                    (action_tag, None, None)
                }
            };

        Ok(RoutingDecision {
            matched_rule: routed.matched_rule,
            rule_kind: routed.rule_kind,
            first_action: routed.first_action,
            flow_origin: origin_tag(flow.origin).to_string(),
            selected_outbound_tag,
            selected_group_tag,
            group_type,
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
            // Shadowsocks 出站不经 LinkActivator 探测；其链路由 nexus-outbound-shadowsocks
            // adapter 在 Composition Root 承接（§11.6），此处不产生 Relay 候选。
            OutboundKind::Direct | OutboundKind::Shadowsocks => None,
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

    fn nexus_domain_flow(dest: &str) -> FlowContext {
        FlowContext {
            origin: FlowOrigin::Socks5,
            resource: nexus_domain::ResourceId("internet-access".into()),
            destination: dest.to_string(),
            profile: String::new(),
        }
    }
}
