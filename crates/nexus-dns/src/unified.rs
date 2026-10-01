//! 统一 DNS（S-unified）：`nexusd` 单一 DNS 服务的查询分类器。
//!
//! 分类顺序（冻结）：
//! `hosts` 精确匹配 > `*.{mesh_suffix}`（Mesh 解析器）> 代理规则命中
//! （`ProxyClassifier`，fake-ip）> 上游 `Resolver`。
//!
//! 纯内存、可移植：时间由调用方以 `now_secs` 显式传入；Mesh 解析器、
//! 代理分类器、上游解析器均由 Composition Root 注入；不发起真实网络，
//! 不碰 TUN（TUN 侧 `dns-hijack` 接入为后续集成点，见 DAEMON_ARCHITECTURE §10.4）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use super::{DnsError, DnsQuery, DnsType, Resolver};

/// Fake-IP 默认池：`198.18.0.0/15`（RFC 2544 benchmarking，与 Clash 兼容）。
pub const DEFAULT_FAKE_IP_RANGE: &str = "198.18.0.0/15";
/// 默认 mesh 后缀。
pub const DEFAULT_MESH_SUFFIX: &str = "mesh";
/// Fake-IP 默认 TTL（秒）。
pub const DEFAULT_FAKE_IP_TTL_SECS: u64 = 300;

/// 统一 DNS 配置（对应 `dns.toml [dns]`）。
#[derive(Debug, Clone)]
pub struct DnsUnifiedConfig {
    /// 上游 DNS（bypass/直连查询走这里；传输由注入的 `Resolver` 实现）。
    pub upstream: Vec<String>,
    /// fake-ip 开关；关闭时代理类域名走上游解析。
    pub fake_ip_enabled: bool,
    /// fake-ip 池（网络地址 + 前缀长度）。
    pub fake_ip_network: u32,
    /// fake-ip 池前缀长度。
    pub fake_ip_prefix: u8,
    /// mesh 域名后缀（如 `"mesh"` → `*.mesh`）。
    pub mesh_suffix: String,
    /// fake-ip 映射 TTL（秒）。
    pub fake_ip_ttl_secs: u64,
    /// 自定义 hosts：`(域名, IP)` 精确匹配，最高优先级。
    pub hosts: Vec<(String, IpAddr)>,
}

impl Default for DnsUnifiedConfig {
    fn default() -> Self {
        let (network, prefix) =
            parse_ipv4_cidr(DEFAULT_FAKE_IP_RANGE).expect("default fake-ip range parses");
        Self {
            upstream: Vec::new(),
            fake_ip_enabled: true,
            fake_ip_network: network,
            fake_ip_prefix: prefix,
            mesh_suffix: DEFAULT_MESH_SUFFIX.to_string(),
            fake_ip_ttl_secs: DEFAULT_FAKE_IP_TTL_SECS,
            hosts: Vec::new(),
        }
    }
}

impl DnsUnifiedConfig {
    /// 解析 `a.b.c.d/p` 形式的 IPv4 CIDR，返回 `(network_u32_be, prefix)`。
    ///
    /// # Errors
    ///
    /// 格式非法时返回 `DnsError::InvalidQuery`。
    pub fn parse_cidr(s: &str) -> Result<(u32, u8), DnsError> {
        parse_ipv4_cidr(s)
    }
}

fn parse_ipv4_cidr(s: &str) -> Result<(u32, u8), DnsError> {
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
    Ok((network, prefix))
}

/// Mesh 域名解析器（注入式）：peer 主机名 → 虚拟网 IP。
pub trait MeshNameResolver: Send + Sync {
    /// 解析 mesh 域名；未知返回 `None`。
    fn resolve_mesh(&self, name: &str) -> Option<IpAddr>;
}

/// 代理规则分类器（注入式）：域名是否命中代理规则。
///
/// Deletion Test：若删除该 trait，`nexus-dns` 将被迫直接依赖
/// `nexus-proxy` 的 `RuleEngine`（违反 Forbidden Dependencies），故抽象成立。
/// Composition Root 通常用闭包包装真实规则引擎。
pub trait ProxyClassifier: Send + Sync {
    /// 域名命中代理规则时返回 `true`（应走 fake-ip）。
    fn is_proxied(&self, domain: &str) -> bool;
}

/// 查询分类结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    /// 自定义 hosts 精确命中。
    Hosts,
    /// mesh 域名（`*.{mesh_suffix}`）。
    Mesh,
    /// 命中代理规则 → fake-ip。
    FakeIp,
    /// 直连/bypass → 上游。
    Upstream,
}

impl DnsClass {
    /// 稳定字符串表达（供 E4 场景断言）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hosts => "Hosts",
            Self::Mesh => "Mesh",
            Self::FakeIp => "FakeIp",
            Self::Upstream => "Upstream",
        }
    }
}

/// 统一应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedAnswer {
    /// 查询名。
    pub name: String,
    /// 分类。
    pub class: DnsClass,
    /// 应答地址。
    pub records: Vec<IpAddr>,
    /// fake-ip 命中既有映射时为 true（TTL 内稳定）。
    pub from_cache: bool,
}

#[derive(Debug, Clone)]
struct FakeIpEntry {
    ip: Ipv4Addr,
    expires_at: u64,
}

/// Fake-IP 分配池。
///
/// - 顺序分配，跳过网络地址与广播地址；
/// - 同一域名在 TTL 内重复分配返回同一 IP；
/// - `reclaim_expired` 只回收过期条目。
#[derive(Debug)]
pub struct FakeIpPool {
    network: u32,
    prefix: u8,
    size: u32,
    ttl_secs: u64,
    /// domain → entry。
    by_domain: HashMap<String, FakeIpEntry>,
    /// ip(u32) → domain。
    by_ip: HashMap<u32, String>,
    /// 下一个分配候选偏移。
    cursor: u32,
}

impl FakeIpPool {
    /// 构造分配池；`prefix > 30` 时可用地址不足，返回 `InvalidQuery`。
    ///
    /// # Errors
    ///
    /// 前缀过大（可用主机地址 < 2）时返回 `DnsError::InvalidQuery`。
    pub fn new(network: u32, prefix: u8, ttl_secs: u64) -> Result<Self, DnsError> {
        let size = if prefix >= 32 {
            1u32
        } else {
            1u32.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
        };
        // 至少需要网络地址 + 1 个可用主机地址。
        if size < 4 {
            return Err(DnsError::InvalidQuery(format!(
                "fake-ip range /{prefix} too small"
            )));
        }
        Ok(Self {
            network,
            prefix,
            size,
            ttl_secs,
            by_domain: HashMap::new(),
            by_ip: HashMap::new(),
            cursor: 1,
        })
    }

    /// 池容量（主机地址数，含网络/广播保留）。
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.size
    }

    /// 当前有效映射数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_domain.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }

    /// 地址是否落在池范围内。
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from_be_bytes(ip.octets());
        let mask = if self.prefix == 0 {
            0u32
        } else {
            u32::MAX
                .checked_shl(32 - u32::from(self.prefix))
                .unwrap_or(0)
        };
        (v & mask) == (self.network & mask)
    }

    /// 为域名分配 fake-ip；TTL 内重复调用返回同一 IP。
    ///
    /// # Errors
    ///
    /// 地址池耗尽时返回 `DnsError::ResolutionFailed`。
    pub fn allocate(&mut self, domain: &str, now_secs: u64) -> Result<Ipv4Addr, DnsError> {
        if let Some(entry) = self.by_domain.get(domain) {
            if now_secs < entry.expires_at {
                return Ok(entry.ip);
            }
            // 过期：先清掉旧映射再重新分配。
            let old = u32::from_be_bytes(entry.ip.octets());
            self.by_domain.remove(domain);
            self.by_ip.remove(&old);
        }
        // 顺序扫描找空闲主机地址（跳过 .0 网络地址与最后的广播地址）。
        for _ in 0..self.size {
            let offset = self.cursor;
            self.cursor += 1;
            if self.cursor >= self.size {
                self.cursor = 1;
            }
            if offset == 0 || offset == self.size - 1 {
                continue;
            }
            let candidate = self.network.wrapping_add(offset);
            if self.by_ip.contains_key(&candidate) {
                continue;
            }
            let ip = Ipv4Addr::from(candidate.to_be_bytes());
            let domain_owned = domain.to_string();
            self.by_domain.insert(
                domain_owned.clone(),
                FakeIpEntry {
                    ip,
                    expires_at: now_secs + self.ttl_secs,
                },
            );
            self.by_ip.insert(candidate, domain_owned);
            return Ok(ip);
        }
        Err(DnsError::ResolutionFailed(
            "fake-ip pool exhausted".to_string(),
        ))
    }

    /// fake-ip 反查域名；未知或已回收返回 `None`。
    #[must_use]
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        let v = u32::from_be_bytes(ip.octets());
        self.by_ip.get(&v).map(String::as_str)
    }

    /// 回收所有 `expires_at <= now_secs` 的条目，返回回收数。
    pub fn reclaim_expired(&mut self, now_secs: u64) -> usize {
        let expired: Vec<String> = self
            .by_domain
            .iter()
            .filter(|(_, e)| e.expires_at <= now_secs)
            .map(|(d, _)| d.clone())
            .collect();
        let n = expired.len();
        for domain in expired {
            if let Some(entry) = self.by_domain.remove(&domain) {
                let v = u32::from_be_bytes(entry.ip.octets());
                self.by_ip.remove(&v);
            }
        }
        n
    }
}

/// 统一 DNS：单一查询分类器。
pub struct UnifiedDns {
    config: DnsUnifiedConfig,
    mesh: Box<dyn MeshNameResolver>,
    classifier: Box<dyn ProxyClassifier>,
    upstream: Box<dyn Resolver>,
    pool: FakeIpPool,
    upstream_calls: u64,
}

impl UnifiedDns {
    /// 构造统一 DNS。
    ///
    /// # Errors
    ///
    /// fake-ip 池范围非法时返回 `DnsError::InvalidQuery`。
    pub fn new(
        config: DnsUnifiedConfig,
        mesh: Box<dyn MeshNameResolver>,
        classifier: Box<dyn ProxyClassifier>,
        upstream: Box<dyn Resolver>,
    ) -> Result<Self, DnsError> {
        let pool = FakeIpPool::new(
            config.fake_ip_network,
            config.fake_ip_prefix,
            config.fake_ip_ttl_secs,
        )?;
        Ok(Self {
            config,
            mesh,
            classifier,
            upstream,
            pool,
            upstream_calls: 0,
        })
    }

    /// 仅做分类，不触发任何解析/分配。
    #[must_use]
    pub fn classify(&self, name: &str) -> DnsClass {
        let lower = name.to_lowercase();
        if self
            .config
            .hosts
            .iter()
            .any(|(h, _)| h.to_lowercase() == lower)
        {
            return DnsClass::Hosts;
        }
        let suffix = self.config.mesh_suffix.to_lowercase();
        if lower == suffix || lower.ends_with(&format!(".{suffix}")) {
            return DnsClass::Mesh;
        }
        if self.classifier.is_proxied(&lower) {
            return DnsClass::FakeIp;
        }
        DnsClass::Upstream
    }

    /// 解析查询（`now_secs` 为调用方提供的单调秒数）。
    ///
    /// # Errors
    ///
    /// - 空名 → `InvalidQuery`；
    /// - 未知 mesh 域名 → `ResolutionFailed`（不向公网泄露内部名）；
    /// - fake-ip 池耗尽 → `ResolutionFailed`；
    /// - 上游失败透传其 `DnsError`。
    pub fn resolve(&mut self, query: &DnsQuery, now_secs: u64) -> Result<UnifiedAnswer, DnsError> {
        if query.name.is_empty() {
            return Err(DnsError::InvalidQuery(query.name.clone()));
        }
        let name = query.name.to_lowercase();
        match self.classify(&name) {
            DnsClass::Hosts => {
                let ip = self
                    .config
                    .hosts
                    .iter()
                    .find(|(h, _)| h.to_lowercase() == name)
                    .map(|(_, ip)| *ip)
                    .expect("classify returned Hosts so entry exists");
                Ok(UnifiedAnswer {
                    name: query.name.clone(),
                    class: DnsClass::Hosts,
                    records: vec![ip],
                    from_cache: false,
                })
            }
            DnsClass::Mesh => match self.mesh.resolve_mesh(&name) {
                Some(ip) => Ok(UnifiedAnswer {
                    name: query.name.clone(),
                    class: DnsClass::Mesh,
                    records: vec![ip],
                    from_cache: false,
                }),
                None => Err(DnsError::ResolutionFailed(format!(
                    "unknown mesh name '{name}'"
                ))),
            },
            DnsClass::FakeIp => {
                if !self.config.fake_ip_enabled {
                    return self.resolve_upstream(query, DnsClass::FakeIp);
                }
                if query.qtype == DnsType::Aaaa {
                    // fake-ip 仅 IPv4；AAAA 返回空应答，不消耗地址。
                    return Ok(UnifiedAnswer {
                        name: query.name.clone(),
                        class: DnsClass::FakeIp,
                        records: Vec::new(),
                        from_cache: false,
                    });
                }
                let had = self.pool.lookup_ip_of(&name).is_some();
                let ip = self.pool.allocate(&name, now_secs)?;
                Ok(UnifiedAnswer {
                    name: query.name.clone(),
                    class: DnsClass::FakeIp,
                    records: vec![IpAddr::V4(ip)],
                    from_cache: had,
                })
            }
            DnsClass::Upstream => self.resolve_upstream(query, DnsClass::Upstream),
        }
    }

    fn resolve_upstream(
        &mut self,
        query: &DnsQuery,
        class: DnsClass,
    ) -> Result<UnifiedAnswer, DnsError> {
        self.upstream_calls += 1;
        let records = self.upstream.resolve(query)?;
        Ok(UnifiedAnswer {
            name: query.name.clone(),
            class,
            records,
            from_cache: false,
        })
    }

    /// fake-ip 反查域名（供 TUN 包分类器用：fake-ip → 原域名 → 规则引擎）。
    #[must_use]
    pub fn reverse_lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        self.pool.lookup(ip)
    }

    /// 回收过期的 fake-ip 映射，返回回收数。
    pub fn reclaim_expired(&mut self, now_secs: u64) -> usize {
        self.pool.reclaim_expired(now_secs)
    }

    /// 上游解析器累计调用次数（分类隔离的可验证观测）。
    #[must_use]
    pub fn upstream_call_count(&self) -> u64 {
        self.upstream_calls
    }

    /// fake-ip 池当前映射数。
    #[must_use]
    pub fn fake_ip_count(&self) -> usize {
        self.pool.len()
    }
}

impl FakeIpPool {
    /// 域名当前映射的 IP（不分配；过期视为无映射）。
    fn lookup_ip_of(&self, domain: &str) -> Option<Ipv4Addr> {
        self.by_domain.get(domain).map(|e| e.ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct MapMesh {
        map: HashMap<String, IpAddr>,
    }
    impl MeshNameResolver for MapMesh {
        fn resolve_mesh(&self, name: &str) -> Option<IpAddr> {
            self.map.get(name).copied()
        }
    }

    struct SuffixClassifier {
        suffixes: Vec<String>,
    }
    impl ProxyClassifier for SuffixClassifier {
        fn is_proxied(&self, domain: &str) -> bool {
            self.suffixes
                .iter()
                .any(|s| domain == s || domain.ends_with(&format!(".{s}")))
        }
    }

    struct ConstUpstream(IpAddr);
    impl Resolver for ConstUpstream {
        fn resolve(&mut self, _q: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
            Ok(vec![self.0])
        }
    }

    const MESH_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 144, 144, 6));
    const UPSTREAM_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    fn unified() -> UnifiedDns {
        let mut mesh_map = HashMap::new();
        mesh_map.insert("xc-pc-linux.mesh".to_string(), MESH_IP);
        let config = DnsUnifiedConfig {
            hosts: vec![("local.dev".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))],
            ..Default::default()
        };
        UnifiedDns::new(
            config,
            Box::new(MapMesh { map: mesh_map }),
            Box::new(SuffixClassifier {
                suffixes: vec!["example.com".to_string()],
            }),
            Box::new(ConstUpstream(UPSTREAM_IP)),
        )
        .expect("config valid")
    }

    fn a(name: &str) -> DnsQuery {
        DnsQuery {
            name: name.to_string(),
            qtype: DnsType::A,
        }
    }

    #[test]
    fn classify_order_hosts_first() {
        let dns = unified();
        assert_eq!(dns.classify("local.dev"), DnsClass::Hosts);
    }

    #[test]
    fn classify_mesh_before_proxy() {
        // 即使 mesh 名恰好也命中代理后缀，mesh 优先。
        let dns = unified();
        assert_eq!(dns.classify("xc-pc-linux.mesh"), DnsClass::Mesh);
    }

    #[test]
    fn classify_proxy_then_upstream() {
        let dns = unified();
        assert_eq!(dns.classify("proxy.example.com"), DnsClass::FakeIp);
        assert_eq!(dns.classify("direct.example.org"), DnsClass::Upstream);
    }

    #[test]
    fn mesh_resolves_virtual_ip() {
        let mut dns = unified();
        let ans = dns.resolve(&a("xc-pc-linux.mesh"), 1000).unwrap();
        assert_eq!(ans.class, DnsClass::Mesh);
        assert_eq!(ans.records, vec![MESH_IP]);
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn unknown_mesh_name_does_not_leak_upstream() {
        let mut dns = unified();
        let err = dns.resolve(&a("ghost.mesh"), 1000).unwrap_err();
        assert!(matches!(err, DnsError::ResolutionFailed(_)));
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn fake_ip_in_range_and_stable() {
        let mut dns = unified();
        let first = dns.resolve(&a("proxy.example.com"), 1000).unwrap();
        assert_eq!(first.class, DnsClass::FakeIp);
        assert!(!first.from_cache);
        let ip = match first.records[0] {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => panic!("fake-ip must be v4"),
        };
        assert!(dns.pool.contains(ip));

        // TTL 内重复查询返回同一 IP。
        let second = dns.resolve(&a("proxy.example.com"), 1100).unwrap();
        assert!(second.from_cache);
        assert_eq!(second.records, first.records);
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn fake_ip_reverse_lookup() {
        let mut dns = unified();
        let ans = dns.resolve(&a("proxy.example.com"), 1000).unwrap();
        let ip = match ans.records[0] {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => panic!("fake-ip must be v4"),
        };
        assert_eq!(dns.reverse_lookup(ip), Some("proxy.example.com"));
    }

    #[test]
    fn fake_ip_reclaimed_after_ttl() {
        let mut dns = unified();
        let ans = dns.resolve(&a("proxy.example.com"), 1000).unwrap();
        let ip = match ans.records[0] {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => panic!("fake-ip must be v4"),
        };
        // TTL=300，推进到 1400（> 1000+300）后回收。
        assert_eq!(dns.reclaim_expired(1400), 1);
        assert_eq!(dns.reverse_lookup(ip), None);
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn reclaim_keeps_unexpired() {
        let mut dns = unified();
        dns.resolve(&a("proxy.example.com"), 1000).unwrap();
        assert_eq!(dns.reclaim_expired(1100), 0);
        assert_eq!(dns.fake_ip_count(), 1);
    }

    #[test]
    fn upstream_for_bypass() {
        let mut dns = unified();
        let ans = dns.resolve(&a("direct.example.org"), 1000).unwrap();
        assert_eq!(ans.class, DnsClass::Upstream);
        assert_eq!(ans.records, vec![UPSTREAM_IP]);
        assert_eq!(dns.upstream_call_count(), 1);
    }

    #[test]
    fn fake_ip_disabled_falls_back_to_upstream() {
        let mut mesh_map = HashMap::new();
        mesh_map.insert("xc-pc-linux.mesh".to_string(), MESH_IP);
        let config = DnsUnifiedConfig {
            fake_ip_enabled: false,
            ..Default::default()
        };
        let mut dns = UnifiedDns::new(
            config,
            Box::new(MapMesh { map: mesh_map }),
            Box::new(SuffixClassifier {
                suffixes: vec!["example.com".to_string()],
            }),
            Box::new(ConstUpstream(UPSTREAM_IP)),
        )
        .expect("config valid");
        let ans = dns.resolve(&a("proxy.example.com"), 1000).unwrap();
        // 分类仍是 FakeIp（命中代理规则），但解析走了上游。
        assert_eq!(ans.class, DnsClass::FakeIp);
        assert_eq!(ans.records, vec![UPSTREAM_IP]);
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn aaaa_gets_empty_answer_no_allocation() {
        let mut dns = unified();
        let ans = dns
            .resolve(
                &DnsQuery {
                    name: "proxy.example.com".to_string(),
                    qtype: DnsType::Aaaa,
                },
                1000,
            )
            .unwrap();
        assert_eq!(ans.class, DnsClass::FakeIp);
        assert!(ans.records.is_empty());
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn hosts_exact_match_case_insensitive() {
        let mut dns = unified();
        let ans = dns.resolve(&a("LOCAL.DEV"), 1000).unwrap();
        assert_eq!(ans.class, DnsClass::Hosts);
        assert_eq!(ans.records, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn empty_name_invalid() {
        let mut dns = unified();
        let err = dns.resolve(&a(""), 1000).unwrap_err();
        assert!(matches!(err, DnsError::InvalidQuery(_)));
    }

    #[test]
    fn pool_exhaustion_errors() {
        // /30 只有 2 个可用主机地址。
        let pool = FakeIpPool::new(0xC612_0000, 30, 300).expect("pool");
        let mut dns_pool = pool;
        dns_pool.allocate("a.test", 1000).unwrap();
        dns_pool.allocate("b.test", 1000).unwrap();
        let err = dns_pool.allocate("c.test", 1000).unwrap_err();
        assert!(matches!(err, DnsError::ResolutionFailed(_)));
    }

    #[test]
    fn pool_rejects_tiny_range() {
        assert!(FakeIpPool::new(0xC612_0000, 31, 300).is_err());
    }
}
