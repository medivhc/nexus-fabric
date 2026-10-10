//! Mesh 网络防火墙规则匹配引擎（内存骨架）。
//!
//! 本模块是 delivery 层共享底座的包过滤骨架：
//! - **规则**：每条 `FirewallRule` 描述 action + 五元组子集（src/dst IP、src/dst 端口、协议）；
//! - **匹配**：`FirewallEngine::evaluate(&PacketContext)` 按规则顺序首匹配生效（first-match-wins）；
//! - **默认策略**：未命中任何规则时走 `default_policy`（白名单模式默认 Deny）；
//! - **通配**：字段为 `None` 表示该维不参与匹配（即通配）。
//!
//! 边界（PRODUCT §12-firewall-rules 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实 socket / TUN / iptables；
//! - IP 匹配支持精确 IPv4 与简化 IPv4 CIDR（`a.b.c.d/n`，按位掩码比较）；不支持 IPv6；
//! - 端口范围 inclusive 匹配；协议精确匹配；
//! - 真实网络包抓取、连接跟踪（conntrack）、状态化规则留 TODO。
//!
//! TODO（真实网络集成，非本骨架范围）：
//! - 在 VirtualSubnetTunnel 收发路径上挂载 engine 作为 ingress/egress/forward 门控；
//! - 引入 conntrack 做状态化匹配（ESTABLISHED/RELATED）；
//! - 规则热加载、持久化与审计日志。
//!
//! 错误面独立：`FirewallError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;
use std::str::FromStr;

// ---------- 错误 ----------

/// 防火墙相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    /// 规则非法（如端口范围 start > end、CIDR 无法解析等）。
    InvalidRule {
        /// 非法原因（人可读）。
        message: String,
    },
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRule { message } => write!(f, "FIREWALL_INVALID_RULE: {message}"),
        }
    }
}

impl std::error::Error for FirewallError {}

// ---------- 协议与判定 ----------

/// 网络协议（骨架仅覆盖 TCP / UDP / ICMP）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP。
    Tcp,
    /// UDP。
    Udp,
    /// ICMP。
    Icmp,
}

impl Protocol {
    /// 协议的稳定字符串标签（用于 Display / 日志 / JSON）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            other => Err(FirewallError::InvalidRule {
                message: format!("unknown protocol: {other:?}"),
            }),
        }
    }
}

/// 规则动作（允许 / 拒绝）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// 允许匹配的包通过。
    Allow,
    /// 拒绝匹配的包。
    Deny,
}

impl FirewallAction {
    /// 动作的稳定字符串标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 引擎对一个包的最终判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallVerdict {
    /// 允许通过。
    Allow,
    /// 拒绝通过。
    Deny,
}

impl FirewallVerdict {
    /// 稳定字符串标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// 是否为允许。
    #[must_use]
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for FirewallVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 端口范围 ----------

/// 端口范围（inclusive，`[start, end]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// 起始端口（含）。
    pub start: u16,
    /// 结束端口（含）。
    pub end: u16,
}

impl PortRange {
    /// 构造一个 inclusive 端口范围；`start > end` 返回 `InvalidRule`。
    pub fn new(start: u16, end: u16) -> Result<Self, FirewallError> {
        if start > end {
            return Err(FirewallError::InvalidRule {
                message: format!("port range start({start}) > end({end})"),
            });
        }
        Ok(Self { start, end })
    }

    /// 单端口范围（`p..=p`）。
    #[must_use]
    pub fn single(p: u16) -> Self {
        Self { start: p, end: p }
    }

    /// 判断端口是否落在 `[start, end]` 内。
    #[must_use]
    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

// ---------- 规则与配置 ----------

/// 一条防火墙规则：动作 + 五元组子集。
///
/// 任一 `Option` 为 `None` 表示该维通配（不参与匹配）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    /// 命中后执行的动作。
    pub action: FirewallAction,
    /// 源 IP：精确 IPv4（`10.0.0.5`）或 CIDR（`10.0.0.0/24`）；`None` 表示通配。
    pub src_ip: Option<String>,
    /// 目的 IP：精确 IPv4 或 CIDR；`None` 表示通配。
    pub dst_ip: Option<String>,
    /// 源端口范围（inclusive）；`None` 表示通配。
    pub src_port: Option<PortRange>,
    /// 目的端口范围（inclusive）；`None` 表示通配。
    pub dst_port: Option<PortRange>,
    /// 协议；`None` 表示通配。
    pub protocol: Option<Protocol>,
}

impl FirewallRule {
    /// 构造规则；字段为空字符串会被规范化为 `None`；非法 CIDR / 端口范围返回 `InvalidRule`。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action: FirewallAction,
        src_ip: Option<impl Into<String>>,
        dst_ip: Option<impl Into<String>>,
        src_port: Option<PortRange>,
        dst_port: Option<PortRange>,
        protocol: Option<Protocol>,
    ) -> Result<Self, FirewallError> {
        let src_ip = src_ip.map(Into::into).filter(|s: &String| !s.is_empty());
        let dst_ip = dst_ip.map(Into::into).filter(|s: &String| !s.is_empty());
        // 预校验 CIDR 合法性，避免运行时才发现规则写错。
        if let Some(ref cidr) = src_ip {
            parse_ip_or_cidr(cidr)?;
        }
        if let Some(ref cidr) = dst_ip {
            parse_ip_or_cidr(cidr)?;
        }
        Ok(Self {
            action,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    }

    /// 构造一条"通配源 + 通配目的"的纯动作规则（兜底用）。
    #[must_use]
    pub fn action_only(action: FirewallAction) -> Self {
        Self {
            action,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
        }
    }
}

/// 防火墙配置：默认策略 + 有序规则列表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallConfig {
    /// 未命中任何规则时采用的默认动作（白名单模式一般为 `Deny`）。
    pub default_policy: FirewallAction,
    /// 有序规则列表；引擎按顺序首匹配生效。
    pub rules: Vec<FirewallRule>,
}

impl FirewallConfig {
    /// 构造配置；立即校验全部规则（非法规则直接返回错误）。
    pub fn new(
        default_policy: FirewallAction,
        rules: Vec<FirewallRule>,
    ) -> Result<Self, FirewallError> {
        for (idx, rule) in rules.iter().enumerate() {
            if let Some(ref cidr) = rule.src_ip {
                parse_ip_or_cidr(cidr).map_err(|e| FirewallError::InvalidRule {
                    message: format!("rule {idx} src_ip: {e}"),
                })?;
            }
            if let Some(ref cidr) = rule.dst_ip {
                parse_ip_or_cidr(cidr).map_err(|e| FirewallError::InvalidRule {
                    message: format!("rule {idx} dst_ip: {e}"),
                })?;
            }
        }
        Ok(Self {
            default_policy,
            rules,
        })
    }
}

// ---------- 包上下文 ----------

/// 进入引擎的包元数据（不含 payload；骨架期由调用方构造）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketContext {
    /// 源 IPv4（如 `10.0.0.5`）。
    pub src_ip: String,
    /// 目的 IPv4（如 `10.0.0.1`）。
    pub dst_ip: String,
    /// 源端口（ICMP 等无端口协议为 `None`）。
    pub src_port: Option<u16>,
    /// 目的端口。
    pub dst_port: Option<u16>,
    /// 协议。
    pub protocol: Protocol,
}

impl PacketContext {
    /// 构造一个 TCP/UDP 包上下文。
    #[must_use]
    pub fn transport(
        src_ip: impl Into<String>,
        dst_ip: impl Into<String>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port,
            dst_port,
            protocol,
        }
    }

    /// 构造一个 ICMP 包上下文（无端口）。
    #[must_use]
    pub fn control(src_ip: impl Into<String>, dst_ip: impl Into<String>) -> Self {
        Self {
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port: None,
            dst_port: None,
            protocol: Protocol::Icmp,
        }
    }
}

// ---------- IPv4 解析与 CIDR 匹配 ----------

/// 把 `a.b.c.d` 解析成大端 u32；非法返回 `InvalidRule`。
fn parse_ipv4(s: &str) -> Result<u32, FirewallError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(FirewallError::InvalidRule {
            message: format!("invalid ipv4: {s:?}"),
        });
    }
    let mut value: u32 = 0;
    for part in &parts {
        let octet: u32 = part.parse().map_err(|_| FirewallError::InvalidRule {
            message: format!("invalid ipv4 octet in {s:?}"),
        })?;
        if octet > 255 {
            return Err(FirewallError::InvalidRule {
                message: format!("octet out of range in {s:?}"),
            });
        }
        value = (value << 8) | octet;
    }
    Ok(value)
}

/// 规则侧的 IP 条目：可能是精确主机地址或 CIDR。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpEntry {
    /// 精确主机（/32 等价）。
    Host(u32),
    /// 网段（network 已按 mask 对齐）。
    Network { network: u32, mask: u32 },
}

/// 解析规则侧 IP 字符串：`a.b.c.d` 或 `a.b.c.d/n`。
fn parse_ip_or_cidr(spec: &str) -> Result<IpEntry, FirewallError> {
    let spec = spec.trim();
    if let Some((ip, prefix)) = spec.split_once('/') {
        let addr = parse_ipv4(ip)?;
        let prefix: u32 = prefix.parse().map_err(|_| FirewallError::InvalidRule {
            message: format!("invalid cidr prefix in {spec:?}"),
        })?;
        if prefix > 32 {
            return Err(FirewallError::InvalidRule {
                message: format!("cidr prefix out of range in {spec:?}"),
            });
        }
        // prefix == 0 时 mask 为 0（全段匹配）；prefix == 32 时为 !0。
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = addr & mask;
        Ok(IpEntry::Network { network, mask })
    } else {
        Ok(IpEntry::Host(parse_ipv4(spec)?))
    }
}

/// 判断包 IP 是否匹配规则侧条目；规则侧解析失败时返回 `false`（保守拒绝该维）。
fn ip_matches(entry: &IpEntry, pkt_ip: &str) -> bool {
    let Ok(pkt) = parse_ipv4(pkt_ip) else {
        return false;
    };
    match entry {
        IpEntry::Host(h) => pkt == *h,
        IpEntry::Network { network, mask } => (pkt & mask) == *network,
    }
}

// ---------- 引擎 ----------

/// 防火墙规则匹配引擎（持有配置的只读引用）。
///
/// 评估语义：
/// 1. 按 `config.rules` 顺序逐条匹配；
/// 2. 某条规则所有"非通配"维度都命中时，立即返回该规则的 action（first-match-wins）；
/// 3. 全部规则未命中时返回 `default_policy` 对应的 verdict。
pub struct FirewallEngine {
    /// 已解析的规则视图：把字符串 IP 预解析成 `IpEntry`，避免每次评估重复解析。
    rules: Vec<CompiledRule>,
    /// 默认动作。
    default_policy: FirewallAction,
}

/// 编译后的单条规则（IP 字段已解析）。
#[derive(Debug, Clone)]
struct CompiledRule {
    action: FirewallAction,
    src_ip: Option<IpEntry>,
    dst_ip: Option<IpEntry>,
    src_port: Option<PortRange>,
    dst_port: Option<PortRange>,
    protocol: Option<Protocol>,
}

impl CompiledRule {
    /// 判断该规则是否命中给定包；任一已设置维不命中即整体不命中。
    fn matches(&self, pkt: &PacketContext) -> bool {
        if let Some(ref entry) = self.src_ip {
            if !ip_matches(entry, &pkt.src_ip) {
                return false;
            }
        }
        if let Some(ref entry) = self.dst_ip {
            if !ip_matches(entry, &pkt.dst_ip) {
                return false;
            }
        }
        if let Some(range) = self.src_port {
            match pkt.src_port {
                Some(p) if range.contains(p) => {}
                _ => return false,
            }
        }
        if let Some(range) = self.dst_port {
            match pkt.dst_port {
                Some(p) if range.contains(p) => {}
                _ => return false,
            }
        }
        if let Some(proto) = self.protocol {
            if pkt.protocol != proto {
                return false;
            }
        }
        true
    }
}

impl FirewallEngine {
    /// 用配置构造引擎；编译阶段会重新校验所有 IP/CIDR（与 `FirewallConfig::new` 一致）。
    pub fn new(config: &FirewallConfig) -> Result<Self, FirewallError> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for (idx, rule) in config.rules.iter().enumerate() {
            let src_ip = match rule.src_ip.as_deref() {
                Some(s) => Some(parse_ip_or_cidr(s).map_err(|e| FirewallError::InvalidRule {
                    message: format!("rule {idx} src_ip: {e}"),
                })?),
                None => None,
            };
            let dst_ip = match rule.dst_ip.as_deref() {
                Some(s) => Some(parse_ip_or_cidr(s).map_err(|e| FirewallError::InvalidRule {
                    message: format!("rule {idx} dst_ip: {e}"),
                })?),
                None => None,
            };
            rules.push(CompiledRule {
                action: rule.action,
                src_ip,
                dst_ip,
                src_port: rule.src_port,
                dst_port: rule.dst_port,
                protocol: rule.protocol,
            });
        }
        Ok(Self {
            rules,
            default_policy: config.default_policy,
        })
    }

    /// 评估一个包上下文，返回判定（first-match-wins；未命中走默认策略）。
    #[must_use]
    pub fn evaluate(&self, pkt: &PacketContext) -> FirewallVerdict {
        for rule in &self.rules {
            if rule.matches(pkt) {
                return match rule.action {
                    FirewallAction::Allow => FirewallVerdict::Allow,
                    FirewallAction::Deny => FirewallVerdict::Deny,
                };
            }
        }
        match self.default_policy {
            FirewallAction::Allow => FirewallVerdict::Allow,
            FirewallAction::Deny => FirewallVerdict::Deny,
        }
    }

    /// 规则数量（供 flow / 审计断言）。
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 默认策略（只读）。
    #[must_use]
    pub fn default_policy(&self) -> FirewallAction {
        self.default_policy
    }
}

// ---------- 演示用：把 DNS 查询映射成 PacketContext ----------

/// 把一条 DNS 查询元数据映射成 UDP/53 包上下文（演示 DNS 过滤集成点）。
///
/// TODO：真实场景应从 UDP 载荷解析域名后再叠加域名级规则；骨架期只表达
/// "DNS 查询 = 源端口任意 + 目的端口 53 + UDP" 的五元组匹配能力。
#[must_use]
pub fn dns_query_context(
    src_ip: impl Into<String>,
    dns_server_ip: impl Into<String>,
) -> PacketContext {
    PacketContext::transport(src_ip, dns_server_ip, None, Some(53), Protocol::Udp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(
        src: &str,
        dst: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        proto: Protocol,
    ) -> PacketContext {
        PacketContext::transport(src, dst, src_port, dst_port, proto)
    }

    #[test]
    fn port_range_rejects_start_gt_end() {
        let err = PortRange::new(8080, 80).expect_err("start > end must fail");
        assert!(matches!(err, FirewallError::InvalidRule { .. }));
    }

    #[test]
    fn port_range_contains_is_inclusive() {
        let r = PortRange::new(1000, 2000).unwrap();
        assert!(r.contains(1000));
        assert!(r.contains(2000));
        assert!(r.contains(1500));
        assert!(!r.contains(999));
        assert!(!r.contains(2001));
        assert!(PortRange::single(53).contains(53));
        assert!(!PortRange::single(53).contains(54));
    }

    #[test]
    fn cidr_matches_non_byte_boundary_prefix() {
        // 10.0.0.0/26 覆盖 10.0.0.0 .. 10.0.0.63。
        let entry = parse_ip_or_cidr("10.0.0.0/26").unwrap();
        assert!(ip_matches(&entry, "10.0.0.0"));
        assert!(ip_matches(&entry, "10.0.0.63"));
        assert!(ip_matches(&entry, "10.0.0.32"));
        assert!(!ip_matches(&entry, "10.0.0.64"));
        assert!(!ip_matches(&entry, "10.0.1.1"));
    }

    #[test]
    fn exact_ip_and_well_known_prefixes() {
        let host = parse_ip_or_cidr("10.0.0.5").unwrap();
        assert!(ip_matches(&host, "10.0.0.5"));
        assert!(!ip_matches(&host, "10.0.0.6"));

        let slash24 = parse_ip_or_cidr("192.168.1.0/24").unwrap();
        assert!(ip_matches(&slash24, "192.168.1.200"));
        assert!(!ip_matches(&slash24, "192.168.2.1"));

        let slash8 = parse_ip_or_cidr("10.0.0.0/8").unwrap();
        assert!(ip_matches(&slash8, "10.99.99.99"));
        assert!(!ip_matches(&slash8, "11.0.0.1"));
    }

    #[test]
    fn invalid_cidr_is_rejected_at_rule_build() {
        let err = FirewallRule::new(
            FirewallAction::Allow,
            Some("not-an-ip"),
            None::<String>,
            None,
            None,
            None,
        )
        .expect_err("invalid ip must fail");
        assert!(matches!(err, FirewallError::InvalidRule { .. }));

        let err = FirewallRule::new(
            FirewallAction::Allow,
            Some("10.0.0.0/99"),
            None::<String>,
            None,
            None,
            None,
        )
        .expect_err("prefix > 32 must fail");
        assert!(matches!(err, FirewallError::InvalidRule { .. }));
    }

    #[test]
    fn default_deny_blocks_unmatched_traffic() {
        let cfg = FirewallConfig::new(FirewallAction::Deny, vec![]).unwrap();
        let engine = FirewallEngine::new(&cfg).unwrap();
        let verdict = engine.evaluate(&pkt(
            "10.0.0.5",
            "10.0.0.1",
            Some(1234),
            Some(80),
            Protocol::Tcp,
        ));
        assert_eq!(verdict, FirewallVerdict::Deny);
    }

    #[test]
    fn allow_whitelist_rule_permits_named_peer() {
        let rule = FirewallRule::new(
            FirewallAction::Allow,
            Some("10.0.0.5"),
            Some("10.0.0.1"),
            None,
            None,
            Some(Protocol::Tcp),
        )
        .unwrap();
        let cfg = FirewallConfig::new(FirewallAction::Deny, vec![rule]).unwrap();
        let engine = FirewallEngine::new(&cfg).unwrap();

        let allowed = pkt("10.0.0.5", "10.0.0.1", Some(1234), Some(80), Protocol::Tcp);
        assert!(engine.evaluate(&allowed).is_allow());

        let wrong_src = pkt("10.0.0.6", "10.0.0.1", Some(1234), Some(80), Protocol::Tcp);
        assert!(!engine.evaluate(&wrong_src).is_allow());

        let wrong_proto = pkt("10.0.0.5", "10.0.0.1", Some(1234), Some(80), Protocol::Udp);
        assert!(!engine.evaluate(&wrong_proto).is_allow());
    }

    #[test]
    fn deny_rule_blocks_named_port() {
        let deny_dns = FirewallRule::new(
            FirewallAction::Deny,
            None::<String>,
            None::<String>,
            None,
            Some(PortRange::single(53)),
            Some(Protocol::Udp),
        )
        .unwrap();
        let cfg = FirewallConfig::new(FirewallAction::Allow, vec![deny_dns]).unwrap();
        let engine = FirewallEngine::new(&cfg).unwrap();

        let dns = dns_query_context("10.0.0.5", "10.0.0.1");
        assert!(!engine.evaluate(&dns).is_allow());

        let http = pkt("10.0.0.5", "10.0.0.1", Some(1234), Some(80), Protocol::Tcp);
        assert!(engine.evaluate(&http).is_allow());
    }

    #[test]
    fn cidr_whitelist_matches_whole_subnet() {
        let rule = FirewallRule::new(
            FirewallAction::Allow,
            Some("10.0.0.0/24"),
            Some("10.0.0.0/24"),
            None,
            None,
            Some(Protocol::Tcp),
        )
        .unwrap();
        let cfg = FirewallConfig::new(FirewallAction::Deny, vec![rule]).unwrap();
        let engine = FirewallEngine::new(&cfg).unwrap();

        assert!(
            engine
                .evaluate(&pkt(
                    "10.0.0.10",
                    "10.0.0.20",
                    Some(1234),
                    Some(80),
                    Protocol::Tcp
                ))
                .is_allow()
        );
        assert!(
            !engine
                .evaluate(&pkt(
                    "192.168.1.10",
                    "10.0.0.20",
                    Some(1234),
                    Some(80),
                    Protocol::Tcp
                ))
                .is_allow()
        );
    }

    #[test]
    fn first_match_wins_even_if_later_rule_matches() {
        // 先 Deny 全段 53，再 Allow 特定主机 -> 前者先生效。
        let deny_all_53 = FirewallRule::new(
            FirewallAction::Deny,
            None::<String>,
            None::<String>,
            None,
            Some(PortRange::single(53)),
            Some(Protocol::Udp),
        )
        .unwrap();
        let allow_named = FirewallRule::new(
            FirewallAction::Allow,
            Some("10.0.0.5"),
            Some("10.0.0.1"),
            None,
            Some(PortRange::single(53)),
            Some(Protocol::Udp),
        )
        .unwrap();
        let cfg =
            FirewallConfig::new(FirewallAction::Deny, vec![deny_all_53, allow_named]).unwrap();
        let engine = FirewallEngine::new(&cfg).unwrap();

        // 即使后一条 allow 能精确匹配，第一条 deny 已经先命中。
        assert_eq!(
            engine.evaluate(&dns_query_context("10.0.0.5", "10.0.0.1")),
            FirewallVerdict::Deny
        );
    }

    #[test]
    fn protocol_display_and_from_str_roundtrip() {
        for p in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let s = p.to_string();
            assert_eq!(Protocol::from_str(&s).unwrap(), p);
        }
        assert!(Protocol::from_str("gre").is_err());
    }

    #[test]
    fn control_context_has_no_ports() {
        let icmp = PacketContext::control("10.0.0.5", "10.0.0.1");
        assert_eq!(icmp.src_port, None);
        assert_eq!(icmp.dst_port, None);
        assert_eq!(icmp.protocol, Protocol::Icmp);
    }
}
