//! nexus-dns
//!
//! 提供 Resolver、DNS Routing、Cache、Synthetic/Fake-IP 映射、Domain/Flow 关联与 Exit-DNS Binding。
//!
//! P0 实现（吸收 sing-box S3/S4 与 WireGuard W12 思想）：
//! - 注入式 `Resolver` trait：Portable Core 不实现真实 DNS 传输；
//! - 缓存去重（singleflight 语义：同一查询在 TTL 窗口内底层解析至多一次）；
//! - 环路守卫：查询名命中已配置上游解析器地址 → `LoopDetected`，不挂死；
//! - RDRC 负缓存：解析失败进入负缓存，TTL 内不重试；
//! - `IpPreference` 过滤/排序（V4Only/V6Only/PreferV4/PreferV6）；
//! - Exit-DNS Binding：`domain -> exit` 规则决策，进入 `NetworkPlanExtension`。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;

use nexus_domain::NetworkPlanExtension;

pub mod mesh;
pub mod unified;
pub mod wire;

pub use mesh::StaticMeshResolver;
pub use unified::{
    DEFAULT_FAKE_IP_RANGE, DEFAULT_FAKE_IP_TTL_SECS, DEFAULT_MESH_SUFFIX, DnsClass,
    DnsUnifiedConfig, FakeIpPool, MeshNameResolver, ProxyClassifier, ResolveStep, UnifiedAnswer,
    UnifiedDns,
};
pub use wire::{
    DnsQuestion, DnsRcode, DnsWireError, UpstreamReply, WireRecord, build_answer, build_error,
    build_query, parse_question, parse_response, patch_id,
};

// ---------- 查询 / 记录 ----------

/// 记录类型（P0 支持 A / AAAA；CNAME 等后续扩展）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    /// IPv4 地址记录。
    A,
    /// IPv6 地址记录。
    Aaaa,
}

/// 一条 DNS 查询。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuery {
    /// 查询名（小写规范形式）。
    pub name: String,
    /// 查询类型。
    pub qtype: DnsType,
}

/// 单条解析记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// 记录名。
    pub name: String,
    /// 记录类型。
    pub rtype: DnsType,
    /// 缓存 TTL（秒）。
    pub ttl_secs: u64,
    /// 解析出的地址。
    pub address: IpAddr,
}

/// 一次解析的应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// 查询名。
    pub name: String,
    /// 按 `IpPreference` 过滤/排序后的地址。
    pub records: Vec<IpAddr>,
    /// 是否来自缓存。
    pub from_cache: bool,
}

/// 结构化 DNS 错误（PRODUCT §2 失败类型 `DNS_RESOLUTION_FAILED` 的模块内表达）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// 底层解析失败（可诊断原因由变体保留）。
    ResolutionFailed(String),
    /// 环路守卫：查询名是已配置上游解析器地址，拒绝自解析循环。
    LoopDetected(String),
    /// RDRC 负缓存命中：该查询在 TTL 内被拒，不重试。
    NegativeCached(String),
    /// 非法查询（空名等）。
    InvalidQuery(String),
    /// 多 server 路由（§11.5）：规则或兜底引用的 server tag 未定义。
    UnknownServer(String),
    /// mesh 名未在静态表命中（R3；不向上游泄露内部名）。
    NameNotFound(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResolutionFailed(name) => write!(f, "dns resolution failed for {name}"),
            Self::LoopDetected(name) => write!(f, "dns loop detected for {name}"),
            Self::NegativeCached(name) => write!(f, "dns query {name} is negative-cached"),
            Self::InvalidQuery(name) => write!(f, "invalid dns query: {name:?}"),
            Self::UnknownServer(tag) => write!(f, "dns server '{tag}' is not defined"),
            Self::NameNotFound(name) => write!(f, "dns name '{name}' not found"),
        }
    }
}

// ---------- 地址偏好 ----------

/// 地址偏好（吸收 sing-box S4：DNS strategy 并行 A+AAAA 与偏好排序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPreference {
    /// 只保留 IPv4。
    V4Only,
    /// 只保留 IPv6。
    V6Only,
    /// IPv4 优先。
    PreferV4,
    /// IPv6 优先。
    PreferV6,
}

impl IpPreference {
    /// 该地址是否满足偏好。
    #[must_use]
    pub fn keeps(&self, addr: IpAddr) -> bool {
        match self {
            Self::V4Only => addr.is_ipv4(),
            Self::V6Only => addr.is_ipv6(),
            Self::PreferV4 | Self::PreferV6 => true,
        }
    }

    /// 排序键：越小越靠前。
    #[must_use]
    pub fn rank(&self, addr: IpAddr) -> u8 {
        match self {
            Self::PreferV4 => u8::from(!addr.is_ipv4()),
            Self::PreferV6 => u8::from(!addr.is_ipv6()),
            Self::V4Only | Self::V6Only => 0,
        }
    }

    /// 稳定字符串表达（供 E4 场景断言）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V4Only => "v4_only",
            Self::V6Only => "v6_only",
            Self::PreferV4 => "prefer_v4",
            Self::PreferV6 => "prefer_v6",
        }
    }
}

// ---------- Resolver trait ----------

/// 注入式解析器（Portable Core）。
///
/// P0 由测试与 E4 场景注入内存 mock；真实 UDP/TLS/HTTPS 传输由后续
/// `Resolver` 实现提供，本 crate 不依赖具体传输。
///
/// `Send + Sync` 超约束：`DnsRuntime` 会被守护进程在多线程 HTTP 服务中经
/// 锁共享持有，故底层 resolver 必须可跨线程传递与共享。所有现有实现者均为
/// 无状态或仅含 Send+Sync 数据的 mock。
pub trait Resolver: Send + Sync {
    /// 解析查询，返回一组地址；失败保留可诊断错误。
    fn resolve(&mut self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError>;
}

// ---------- Exit-DNS Binding ----------

/// Exit-DNS Binding 决策结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDnsDecision {
    /// 查询名。
    pub name: String,
    /// 解析出的地址（已按偏好过滤/排序）。
    pub resolved: Vec<IpAddr>,
    /// 是否来自缓存。
    pub from_cache: bool,
    /// 匹配到的出口（`None` = 无规则匹配）。
    pub exit: Option<String>,
    /// 使用的偏好。
    pub preference: IpPreference,
}

// ---------- DNS 多 server 路由（§11.5） ----------

/// DNS 规则匹配子句（§11.5.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsMatch {
    /// 域名精确/`.{domain}` 子域匹配。
    Domain(String),
    /// IPv4 CIDR：network（大端 u32）+ 前缀；对请求 `client_ip` 匹配。
    IpCidr { network: u32, prefix: u8 },
}

impl DnsMatch {
    /// 构造 IPv4 CIDR 匹配子句；`s` 形如 `a.b.c.d/p`（p∈0..=32）。
    ///
    /// # Errors
    ///
    /// 格式/前缀非法返回 `DnsError::InvalidQuery`。
    pub fn ip_cidr(s: &str) -> Result<Self, DnsError> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| DnsError::InvalidQuery(format!("bad cidr '{s}'")))?;
        let octets: Vec<u8> = addr
            .split('.')
            .map(|o| {
                o.parse::<u8>()
                    .map_err(|_| DnsError::InvalidQuery(addr.to_string()))
            })
            .collect::<Result<_, _>>()?;
        if octets.len() != 4 {
            return Err(DnsError::InvalidQuery(addr.to_string()));
        }
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| DnsError::InvalidQuery(prefix.to_string()))?;
        if prefix > 32 {
            return Err(DnsError::InvalidQuery(format!(
                "prefix /{prefix} too large"
            )));
        }
        let network = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
        Ok(Self::IpCidr { network, prefix })
    }

    /// 是否命中；`name` 为查询名，`client_ip` 为可选请求客户端/目标 IP。
    fn matches(&self, name: &str, client_ip: Option<IpAddr>) -> bool {
        match self {
            Self::Domain(d) => name == d || name.ends_with(&format!(".{d}")),
            Self::IpCidr { network, prefix } => match client_ip {
                Some(IpAddr::V4(v4)) => {
                    let ip = u32::from_be_bytes(v4.octets());
                    let mask = if *prefix == 0 {
                        0u32
                    } else {
                        u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0)
                    };
                    (ip & mask) == (network & mask)
                }
                _ => false,
            },
        }
    }
}

/// 一条 DNS 路由规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRouteRule {
    /// 匹配子句（域名或 IPv4 CIDR）。
    pub matcher: DnsMatch,
    /// 命中后路由到的 server tag。
    pub server: String,
}

/// 一次 server 选择结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerSelection {
    /// 选中的 server tag。
    pub server: String,
    /// 命中的规则 domain；无具体命中（走 MATCH 兜底）时为 `None`。
    pub matched_domain: Option<String>,
}

/// 多 server 路由器：域名规则声明顺序首匹配，否则 `default_server`（MATCH 兜底）。
#[derive(Debug, Clone)]
pub struct DnsRouter {
    rules: Vec<DnsRouteRule>,
    default_server: String,
}

impl DnsRouter {
    /// 构造路由器。
    #[must_use]
    pub fn new(rules: Vec<DnsRouteRule>, default_server: String) -> Self {
        Self {
            rules,
            default_server,
        }
    }

    /// 首匹配（§11.5.1）：按规则声明顺序，域名或 IPv4 CIDR 命中即选；无命中走
    /// `default_server`。`client_ip` 仅对 CIDR 规则有意义。
    #[must_use]
    pub fn select(&self, name: &str, client_ip: Option<IpAddr>) -> DnsServerSelection {
        for rule in &self.rules {
            if rule.matcher.matches(name, client_ip) {
                let label = match &rule.matcher {
                    DnsMatch::Domain(d) => d.clone(),
                    DnsMatch::IpCidr { .. } => "ip_cidr".to_string(),
                };
                return DnsServerSelection {
                    server: rule.server.clone(),
                    matched_domain: Some(label),
                };
            }
        }
        DnsServerSelection {
            server: self.default_server.clone(),
            matched_domain: None,
        }
    }

    /// 路由器引用的全部 server tag（规则 + 兜底），供构造期校验。
    #[must_use]
    pub fn referenced_servers(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.rules.iter().map(|r| r.server.as_str()).collect();
        v.push(self.default_server.as_str());
        v
    }
}

/// 经选中 server 解析的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResolved {
    /// 查询名。
    pub name: String,
    /// 实际承担解析的 server tag。
    pub server: String,
    /// 该 server 解析出的地址。
    pub addresses: Vec<IpAddr>,
    /// 是否命中该 server 自己的缓存（按 server 隔离，§11.5.1）。
    pub from_cache: bool,
}

/// 多 server DNS 运行时：按 `DnsRouter` 选 server，再用该 server 注入的 `Resolver` 解析。
///
/// 离线确定性：每个 server 由 Composition Root 注入内存 mock `Resolver`；本层不发起真实网络。
pub struct MultiServerDns {
    servers: Vec<(String, Box<dyn Resolver>)>,
    router: DnsRouter,
    /// 按 (server_tag, name, qtype) 隔离的解析缓存（§11.5.1）。
    cache: HashMap<(String, String, DnsType), Vec<IpAddr>>,
}

impl MultiServerDns {
    /// 构造并校验：所有规则与 `default_server` 引用的 tag 必须存在于 `servers`，
    /// 否则返回 `DnsError::UnknownServer`。
    ///
    /// # Errors
    ///
    /// 任一被引用的 server tag 未在 `servers` 中定义时返回 `UnknownServer`。
    pub fn new(
        servers: Vec<(String, Box<dyn Resolver>)>,
        router: DnsRouter,
    ) -> Result<Self, DnsError> {
        let tags: std::collections::BTreeSet<&str> =
            servers.iter().map(|(t, _)| t.as_str()).collect();
        for tag in router.referenced_servers() {
            if !tags.contains(tag) {
                return Err(DnsError::UnknownServer(tag.to_string()));
            }
        }
        Ok(Self {
            servers,
            router,
            cache: HashMap::new(),
        })
    }

    /// 仅做 server 选择（不触发解析；client_ip=None）。
    #[must_use]
    pub fn select_server(&self, name: &str) -> DnsServerSelection {
        self.router.select(name, None)
    }

    /// 选择 server 并经该 server 的 `Resolver` 解析；不跨 server。
    ///
    /// # Errors
    ///
    /// 空名返回 `InvalidQuery`；底层 `Resolver` 失败透传其 `DnsError`。
    pub fn resolve(&mut self, name: &str, qtype: DnsType) -> Result<ServerResolved, DnsError> {
        self.resolve_with(name, qtype, None)
    }

    /// 选择 server（可用 `client_ip` 命中 IP-CIDR 规则）并经该 server 解析；
    /// 缓存按 `(server_tag, name, qtype)` 隔离，跨 server 不命中缓存。
    ///
    /// # Errors
    ///
    /// 空名返回 `InvalidQuery`；底层 `Resolver` 失败透传其 `DnsError`。
    pub fn resolve_with(
        &mut self,
        name: &str,
        qtype: DnsType,
        client_ip: Option<IpAddr>,
    ) -> Result<ServerResolved, DnsError> {
        if name.is_empty() {
            return Err(DnsError::InvalidQuery(name.to_string()));
        }
        let selection = self.router.select(name, client_ip);
        let cache_key = (selection.server.clone(), name.to_string(), qtype);

        // 按 server 隔离的缓存命中：不调用该 server 的 Resolver。
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(ServerResolved {
                name: name.to_string(),
                server: selection.server,
                addresses: cached.clone(),
                from_cache: true,
            });
        }

        let resolver = self
            .servers
            .iter_mut()
            .find(|(tag, _)| tag == &selection.server)
            .map(|(_, r)| r)
            .expect("router validated all referenced server tags exist");
        let addresses = resolver.resolve(&DnsQuery {
            name: name.to_string(),
            qtype,
        })?;
        self.cache.insert(cache_key, addresses.clone());
        Ok(ServerResolved {
            name: name.to_string(),
            server: selection.server,
            addresses,
            from_cache: false,
        })
    }
}

// ---------- DnsRuntime ----------

#[derive(Debug)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: u64,
}

/// DNS 运行时：解析 + 缓存 + 环路守卫 + RDRC 负缓存 + Exit-DNS Binding。
///
/// P0 无异步运行时：singleflight 语义由缓存去重表达，并用
/// `resolver_call_count()` 提供可验证观测（同一查询在 TTL 窗口内底层解析至多一次）。
pub struct DnsRuntime {
    resolver: Box<dyn Resolver>,
    cache_ttl_secs: u64,
    cache: HashMap<(String, DnsType), CacheEntry>,
    negative_cache: HashMap<(String, DnsType), u64>,
    resolver_calls: u64,
    upstream_addrs: Vec<String>,
    exit_rules: Vec<(String, String)>,
    last_binding: Option<String>,
}

impl DnsRuntime {
    /// 构造运行时。
    ///
    /// - `resolver`：注入式解析器；
    /// - `cache_ttl_secs`：正/负缓存统一 TTL（秒）；
    /// - `upstream_addrs`：上游解析器地址集合（环路守卫）；
    /// - `exit_rules`：`(domain, exit)` 有序规则，首条匹配生效。
    #[must_use]
    pub fn new(
        resolver: Box<dyn Resolver>,
        cache_ttl_secs: u64,
        upstream_addrs: Vec<String>,
        exit_rules: Vec<(String, String)>,
    ) -> Self {
        Self {
            resolver,
            cache_ttl_secs,
            cache: HashMap::new(),
            negative_cache: HashMap::new(),
            resolver_calls: 0,
            upstream_addrs,
            exit_rules,
            last_binding: None,
        }
    }

    /// 环路守卫：查询名（或其子域）是已配置上游解析器地址。
    fn is_loop(&self, name: &str) -> bool {
        self.upstream_addrs
            .iter()
            .any(|u| name == u || name.ends_with(&format!(".{u}")))
    }

    /// 解析查询：负缓存 → 缓存 → 底层解析 → 偏好过滤/排序。
    ///
    /// `now_secs` 为调用方提供的单调秒数（可测，不依赖平台时钟）。
    pub fn resolve(
        &mut self,
        query: &DnsQuery,
        preference: IpPreference,
        now_secs: u64,
    ) -> Result<DnsAnswer, DnsError> {
        if query.name.is_empty() {
            return Err(DnsError::InvalidQuery(query.name.clone()));
        }
        if self.is_loop(&query.name) {
            return Err(DnsError::LoopDetected(query.name.clone()));
        }

        let key = (query.name.clone(), query.qtype);

        // RDRC 负缓存：TTL 内不重试。
        if let Some(&expires_at) = self.negative_cache.get(&key) {
            if now_secs < expires_at {
                return Err(DnsError::NegativeCached(query.name.clone()));
            }
            self.negative_cache.remove(&key);
        }

        // 缓存命中（singleflight 去重的主要路径：TTL 窗口内不重复解析）。
        if let Some(entry) = self.cache.get(&key) {
            if now_secs < entry.expires_at {
                let records = ordered(&entry.addresses, preference);
                return Ok(DnsAnswer {
                    name: query.name.clone(),
                    records,
                    from_cache: true,
                });
            }
            self.cache.remove(&key);
        }

        self.resolver_calls += 1;
        match self.resolver.resolve(query) {
            Ok(addresses) => {
                let entry = CacheEntry {
                    addresses: addresses.clone(),
                    expires_at: now_secs + self.cache_ttl_secs,
                };
                self.cache.insert(key, entry);
                Ok(DnsAnswer {
                    name: query.name.clone(),
                    records: ordered(&addresses, preference),
                    from_cache: false,
                })
            }
            Err(err) => {
                // RDRC：被拒查询进入负缓存，TTL 内不重试。
                self.negative_cache
                    .insert(key, now_secs + self.cache_ttl_secs);
                Err(err)
            }
        }
    }

    /// 解析并决策 Exit-DNS Binding（吸收 W12：DNS 是编排层职责，Connectivity/VPI 不感知）。
    pub fn resolve_exit_binding(
        &mut self,
        name: &str,
        preference: IpPreference,
        now_secs: u64,
    ) -> Result<ExitDnsDecision, DnsError> {
        let answer = self.resolve(
            &DnsQuery {
                name: name.to_string(),
                qtype: DnsType::A,
            },
            preference,
            now_secs,
        )?;
        let exit = self.exit_dns_binding(name);
        if exit.is_some() {
            self.last_binding = exit.clone();
        }
        Ok(ExitDnsDecision {
            name: name.to_string(),
            resolved: answer.records,
            from_cache: answer.from_cache,
            exit,
            preference,
        })
    }

    /// 返回首个匹配 `domain -> exit` 规则的出口；无匹配返回 `None`。
    #[must_use]
    pub fn exit_dns_binding(&self, name: &str) -> Option<String> {
        self.exit_rules
            .iter()
            .find(|(domain, _)| name == domain || name.ends_with(&format!(".{domain}")))
            .map(|(_, exit)| exit.clone())
    }

    /// 将最近一次 Binding 决策写入 `NetworkPlanExtension`（v1）。
    #[must_use]
    pub fn to_plan_extension(&self) -> NetworkPlanExtension {
        NetworkPlanExtension {
            version: NetworkPlanExtension::VERSION,
            exit_dns_binding: self.last_binding.clone(),
            preferred_transport: None,
        }
    }

    /// 底层解析器累计调用次数（singleflight 语义的可验证观测）。
    #[must_use]
    pub fn resolver_call_count(&self) -> u64 {
        self.resolver_calls
    }

    /// 正缓存快照（§9 dns status/cache 观察出口；元组第三项恒 false = 正缓存）。
    #[must_use]
    pub fn cache_snapshot(&self) -> Vec<(String, DnsType, bool)> {
        self.cache
            .keys()
            .map(|(name, qtype)| (name.clone(), *qtype, false))
            .collect()
    }

    /// RDRC 负缓存快照（§9 观察出口）。
    #[must_use]
    pub fn negative_cache_snapshot(&self) -> Vec<(String, DnsType)> {
        self.negative_cache
            .keys()
            .map(|(name, qtype)| (name.clone(), *qtype))
            .collect()
    }
}

/// 按偏好过滤并按 rank 排序。
fn ordered(records: &[IpAddr], preference: IpPreference) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = records
        .iter()
        .copied()
        .filter(|a| preference.keeps(*a))
        .collect();
    v.sort_by_key(|a| preference.rank(*a));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
    ));

    /// 内存 mock 解析器：example.com 返回 v6 在前 + v4；blacklisted.internal 被拒。
    #[derive(Debug, Default)]
    struct MockResolver;

    impl Resolver for MockResolver {
        fn resolve(&mut self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
            match query.name.as_str() {
                "example.com" => Ok(vec![V6, V4]),
                "blacklisted.internal" => Err(DnsError::ResolutionFailed(query.name.clone())),
                other => Err(DnsError::ResolutionFailed(other.to_string())),
            }
        }
    }

    fn runtime() -> DnsRuntime {
        DnsRuntime::new(
            Box::new(MockResolver),
            300,
            vec!["dns.example.internal".to_string()],
            vec![("example.com".to_string(), "exit-a".to_string())],
        )
    }

    fn a_query(name: &str) -> DnsQuery {
        DnsQuery {
            name: name.to_string(),
            qtype: DnsType::A,
        }
    }

    #[test]
    fn miss_then_cache_hit_singleflight() {
        let mut rt = runtime();
        let first = rt
            .resolve(&a_query("example.com"), IpPreference::PreferV4, 1000)
            .unwrap();
        assert!(!first.from_cache);
        assert_eq!(first.records, vec![V4, V6]);

        let second = rt
            .resolve(&a_query("example.com"), IpPreference::PreferV4, 1000)
            .unwrap();
        assert!(second.from_cache);
        // singleflight：TTL 窗口内底层解析仅一次。
        assert_eq!(rt.resolver_call_count(), 1);
    }

    #[test]
    fn ttl_expiry_re_resolves() {
        let mut rt = runtime();
        rt.resolve(&a_query("example.com"), IpPreference::PreferV4, 1000)
            .unwrap();
        let re = rt
            .resolve(&a_query("example.com"), IpPreference::PreferV4, 1301)
            .unwrap();
        assert!(!re.from_cache);
        assert_eq!(rt.resolver_call_count(), 2);
    }

    #[test]
    fn v4_only_filters_v6() {
        let mut rt = runtime();
        let ans = rt
            .resolve(&a_query("example.com"), IpPreference::V4Only, 1000)
            .unwrap();
        assert_eq!(ans.records, vec![V4]);
    }

    #[test]
    fn v6_only_filters_v4() {
        let mut rt = runtime();
        let ans = rt
            .resolve(&a_query("example.com"), IpPreference::V6Only, 1000)
            .unwrap();
        assert_eq!(ans.records, vec![V6]);
    }

    #[test]
    fn prefer_v6_orders_first() {
        let mut rt = runtime();
        let ans = rt
            .resolve(&a_query("example.com"), IpPreference::PreferV6, 1000)
            .unwrap();
        assert_eq!(ans.records, vec![V6, V4]);
    }

    #[test]
    fn loop_guard_rejects_upstream_self() {
        let mut rt = runtime();
        let err = rt
            .resolve(
                &a_query("dns.example.internal"),
                IpPreference::PreferV4,
                1000,
            )
            .unwrap_err();
        assert!(matches!(err, DnsError::LoopDetected(name) if name == "dns.example.internal"));
        // 环路负测试不挂死：resolve 直接返回，不触发底层解析。
        assert_eq!(rt.resolver_call_count(), 0);
    }

    #[test]
    fn rdrc_negative_cache_blocks_retry() {
        let mut rt = runtime();
        let first = rt.resolve(
            &a_query("blacklisted.internal"),
            IpPreference::PreferV4,
            1000,
        );
        assert!(matches!(first, Err(DnsError::ResolutionFailed(_))));

        let second = rt.resolve(
            &a_query("blacklisted.internal"),
            IpPreference::PreferV4,
            1000,
        );
        assert!(matches!(second, Err(DnsError::NegativeCached(_))));
        // RDRC：负缓存 TTL 内不重试底层解析。
        assert_eq!(rt.resolver_call_count(), 1);
    }

    #[test]
    fn rdrc_expires_and_retries() {
        let mut rt = runtime();
        rt.resolve(
            &a_query("blacklisted.internal"),
            IpPreference::PreferV4,
            1000,
        )
        .unwrap_err();
        let retry = rt.resolve(
            &a_query("blacklisted.internal"),
            IpPreference::PreferV4,
            1301,
        );
        assert!(matches!(retry, Err(DnsError::ResolutionFailed(_))));
        assert_eq!(rt.resolver_call_count(), 2);
    }

    #[test]
    fn exit_binding_first_match() {
        let rt = runtime();
        assert_eq!(
            rt.exit_dns_binding("example.com"),
            Some("exit-a".to_string())
        );
        assert_eq!(
            rt.exit_dns_binding("sub.example.com"),
            Some("exit-a".to_string())
        );
        assert_eq!(rt.exit_dns_binding("other.org"), None);
    }

    #[test]
    fn resolve_exit_binding_carries_exit() {
        let mut rt = runtime();
        let decision = rt
            .resolve_exit_binding("example.com", IpPreference::PreferV4, 1000)
            .unwrap();
        assert_eq!(decision.exit, Some("exit-a".to_string()));
        assert_eq!(decision.resolved, vec![V4, V6]);
    }

    #[test]
    fn plan_extension_carries_binding() {
        let mut rt = runtime();
        assert_eq!(rt.to_plan_extension().exit_dns_binding, None);
        rt.resolve_exit_binding("example.com", IpPreference::PreferV4, 1000)
            .unwrap();
        let ext = rt.to_plan_extension();
        assert_eq!(ext.version, NetworkPlanExtension::VERSION);
        assert_eq!(ext.exit_dns_binding, Some("exit-a".to_string()));
    }

    #[test]
    fn empty_name_is_invalid() {
        let mut rt = runtime();
        let err = rt
            .resolve(&a_query(""), IpPreference::PreferV4, 1000)
            .unwrap_err();
        assert!(matches!(err, DnsError::InvalidQuery(_)));
    }

    #[test]
    fn cache_snapshots_expose_state() {
        let mut rt = runtime();
        rt.resolve(&a_query("example.com"), IpPreference::PreferV4, 1000)
            .unwrap();
        rt.resolve(
            &a_query("blacklisted.internal"),
            IpPreference::PreferV4,
            1000,
        )
        .unwrap_err();
        let positive = rt.cache_snapshot();
        assert!(
            positive
                .iter()
                .any(|(n, t, neg)| n == "example.com" && *t == DnsType::A && !neg)
        );
        let negative = rt.negative_cache_snapshot();
        assert!(
            negative
                .iter()
                .any(|(n, t)| n == "blacklisted.internal" && *t == DnsType::A)
        );
    }

    // --- DNS 多 server 路由（§11.5）---

    struct ConstResolver(IpAddr);
    impl Resolver for ConstResolver {
        fn resolve(&mut self, _q: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec![self.0])
        }
    }

    fn two_servers() -> MultiServerDns {
        let rules = vec![DnsRouteRule {
            matcher: DnsMatch::Domain("example.internal".to_string()),
            server: "a".to_string(),
        }];
        let router = DnsRouter::new(rules, "b".to_string());
        let servers = vec![
            (
                "a".to_string(),
                Box::new(ConstResolver(V4)) as Box<dyn Resolver>,
            ),
            (
                "b".to_string(),
                Box::new(ConstResolver(V6)) as Box<dyn Resolver>,
            ),
        ];
        MultiServerDns::new(servers, router).expect("wire")
    }

    #[test]
    fn dns_router_exact_and_suffix_first_match() {
        let r = two_servers();
        assert_eq!(r.select_server("example.internal").server, "a");
        assert_eq!(r.select_server("sub.example.internal").server, "a");
        assert_eq!(r.select_server("other.example").server, "b");
    }

    #[test]
    fn multi_server_resolve_routes_to_selected_server() {
        let mut r = two_servers();
        let a = r.resolve("example.internal", DnsType::A).unwrap();
        assert_eq!(a.server, "a");
        assert_eq!(a.addresses, vec![V4]);
        let b = r.resolve("other.example", DnsType::A).unwrap();
        assert_eq!(b.server, "b");
        assert_eq!(b.addresses, vec![V6]);
    }

    #[test]
    fn multi_server_new_rejects_dangling_server() {
        let rules = vec![DnsRouteRule {
            matcher: DnsMatch::Domain("x".to_string()),
            server: "ghost".to_string(),
        }];
        let router = DnsRouter::new(rules, "b".to_string());
        let servers = vec![(
            "b".to_string(),
            Box::new(ConstResolver(V6)) as Box<dyn Resolver>,
        )];
        match MultiServerDns::new(servers, router) {
            Err(DnsError::UnknownServer(tag)) => assert_eq!(tag, "ghost"),
            Ok(_) => panic!("expected dangling server to be rejected"),
            Err(e) => panic!("expected UnknownServer, got {e:?}"),
        }
    }
}
