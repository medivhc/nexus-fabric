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

use super::{DnsError, DnsQuery, DnsType, IpPreference};

/// Fake-IP 默认池：`198.18.0.0/15`（RFC 2544 benchmarking，与 Clash 兼容）。
pub const DEFAULT_FAKE_IP_RANGE: &str = "198.18.0.0/15";
/// 默认 mesh 后缀。
pub const DEFAULT_MESH_SUFFIX: &str = "mesh";
/// Fake-IP 默认 TTL（秒）。
pub const DEFAULT_FAKE_IP_TTL_SECS: u64 = 300;

/// 统一 DNS 配置（对应 `dns.toml [dns]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUnifiedConfig {
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
    /// 地址族偏好（D-impl-5：仅门控 Upstream/Mesh/Hosts 的查询 qtype）。
    pub ip_preference: IpPreference,
}

impl Default for DnsUnifiedConfig {
    fn default() -> Self {
        let (network, prefix) =
            parse_ipv4_cidr(DEFAULT_FAKE_IP_RANGE).expect("default fake-ip range parses");
        Self {
            fake_ip_enabled: true,
            fake_ip_network: network,
            fake_ip_prefix: prefix,
            mesh_suffix: DEFAULT_MESH_SUFFIX.to_string(),
            fake_ip_ttl_secs: DEFAULT_FAKE_IP_TTL_SECS,
            hosts: Vec::new(),
            ip_preference: IpPreference::PreferV4,
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

/// 两阶段解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveStep {
    /// 本地已有完整答案（含 NODATA 空答案）。
    Local(UnifiedAnswer),
    /// 需要上游解析；`class` 保留分类供计数/策略使用。
    Upstream {
        /// 命中的分类（FakeIp 关闭时也会走上游）。
        class: DnsClass,
    },
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
    /// 非规范 CIDR（如 `198.18.1.7/15`）会被掩码归一化到网络地址，保证
    /// 分配的地址恒落在声明范围内。
    ///
    /// # Errors
    ///
    /// 前缀过大（可用主机地址 < 2）时返回 `DnsError::InvalidQuery`.
    pub fn new(network: u32, prefix: u8, ttl_secs: u64) -> Result<Self, DnsError> {
        let mask = if prefix == 0 {
            0u32
        } else if prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
        };
        let network = network & mask;
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

    /// 两阶段解析：本地可判定则返回 `Local`，否则交上游引擎。
    ///
    /// qtype 语义（D-impl-4，A/AAAA）：族不符 → `Local` NODATA；mesh 未知名
    /// → `NameNotFound`（NXDOMAIN，不向上游泄露）；fake-ip 开启时代理类 AAAA
    /// → NODATA 且不消耗地址。非 A/AAAA qtype 由服务面用 [`Self::classify`]
    /// 短路（`DnsType` 不建模其它类型），语义见 MODULE。
    ///
    /// # Errors
    ///
    /// - 空名 → `InvalidQuery`；
    /// - 未知 mesh 域名 → `NameNotFound`；
    /// - fake-ip 池耗尽 → `ResolutionFailed`。
    pub fn step(&mut self, query: &DnsQuery, now_secs: u64) -> Result<ResolveStep, DnsError> {
        if query.name.is_empty() {
            return Err(DnsError::InvalidQuery(query.name.clone()));
        }
        let name = query.name.to_lowercase();
        let class = self.classify(&name);
        match class {
            DnsClass::Hosts => {
                if self.preference_blocks(query.qtype) {
                    return Ok(local_nodata(query, class));
                }
                let ip = self
                    .config
                    .hosts
                    .iter()
                    .find(|(h, _)| h.to_lowercase() == name)
                    .map(|(_, ip)| *ip)
                    .expect("classify returned Hosts so entry exists");
                if !matches_family(ip, query.qtype) {
                    return Ok(local_nodata(query, class));
                }
                Ok(ResolveStep::Local(UnifiedAnswer {
                    name: query.name.clone(),
                    class,
                    records: vec![ip],
                    from_cache: false,
                }))
            }
            DnsClass::Mesh => {
                if self.preference_blocks(query.qtype) {
                    return Ok(local_nodata(query, class));
                }
                match self.mesh.resolve_mesh(&name) {
                    Some(ip) if matches_family(ip, query.qtype) => {
                        Ok(ResolveStep::Local(UnifiedAnswer {
                            name: query.name.clone(),
                            class,
                            records: vec![ip],
                            from_cache: false,
                        }))
                    }
                    // 名字存在但无该族记录 → NODATA。
                    Some(_) => Ok(local_nodata(query, class)),
                    None => Err(DnsError::NameNotFound(name)),
                }
            }
            DnsClass::FakeIp => {
                if !self.config.fake_ip_enabled {
                    if self.preference_blocks(query.qtype) {
                        return Ok(local_nodata(query, class));
                    }
                    return Ok(ResolveStep::Upstream { class });
                }
                if query.qtype == DnsType::Aaaa {
                    // fake-ip 仅 IPv4；AAAA 恒 NODATA，不消耗地址（AC8a）。
                    return Ok(local_nodata(query, class));
                }
                let had = self.pool.lookup_ip_of(&name).is_some();
                let ip = self.pool.allocate(&name, now_secs)?;
                Ok(ResolveStep::Local(UnifiedAnswer {
                    name: query.name.clone(),
                    class,
                    records: vec![IpAddr::V4(ip)],
                    from_cache: had,
                }))
            }
            DnsClass::Upstream => {
                if self.preference_blocks(query.qtype) {
                    return Ok(local_nodata(query, class));
                }
                Ok(ResolveStep::Upstream { class })
            }
        }
    }

    /// `v4_only`/`v6_only` 只门控 A/AAAA 查询（D-impl-5）。
    fn preference_blocks(&self, qtype: DnsType) -> bool {
        matches!(
            (self.config.ip_preference, qtype),
            (IpPreference::V4Only, DnsType::Aaaa) | (IpPreference::V6Only, DnsType::A)
        )
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

    /// 记录一次上游应答（服务面在异步引擎回包时调用）。
    pub fn note_upstream_answer(&mut self) {
        self.upstream_calls += 1;
    }

    /// fake-ip 池容量（主机地址数，含网络/广播保留）。
    #[must_use]
    pub fn fake_ip_capacity(&self) -> u32 {
        self.pool.capacity()
    }

    /// fake-ip 池当前映射数。
    #[must_use]
    pub fn fake_ip_count(&self) -> usize {
        self.pool.len()
    }
}

fn local_nodata(query: &DnsQuery, class: DnsClass) -> ResolveStep {
    ResolveStep::Local(UnifiedAnswer {
        name: query.name.clone(),
        class,
        records: Vec::new(),
        from_cache: false,
    })
}

fn matches_family(addr: IpAddr, qtype: DnsType) -> bool {
    match qtype {
        DnsType::A => addr.is_ipv4(),
        DnsType::Aaaa => addr.is_ipv6(),
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

    const MESH_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 144, 144, 6));

    fn unified_with(config: DnsUnifiedConfig) -> UnifiedDns {
        let mut mesh_map = HashMap::new();
        mesh_map.insert("xc-pc-linux.mesh".to_string(), MESH_IP);
        UnifiedDns::new(
            config,
            Box::new(MapMesh { map: mesh_map }),
            Box::new(SuffixClassifier {
                suffixes: vec!["example.com".to_string()],
            }),
        )
        .expect("config valid")
    }

    /// Drive `step` and return the local answer; upstream stays un-injected now
    /// that the engine owns transport (C11).
    fn local(dns: &mut UnifiedDns, query: &DnsQuery, now_secs: u64) -> UnifiedAnswer {
        match dns.step(query, now_secs).expect("step succeeds") {
            ResolveStep::Local(answer) => answer,
            ResolveStep::Upstream { .. } => panic!("expected a local answer"),
        }
    }

    fn unified() -> UnifiedDns {
        unified_with(DnsUnifiedConfig {
            hosts: vec![("local.dev".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))],
            ..Default::default()
        })
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
        let ans = local(&mut dns, &a("xc-pc-linux.mesh"), 1000);
        assert_eq!(ans.class, DnsClass::Mesh);
        assert_eq!(ans.records, vec![MESH_IP]);
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn unknown_mesh_name_does_not_leak_upstream() {
        let mut dns = unified();
        let err = dns.step(&a("ghost.mesh"), 1000).unwrap_err();
        assert!(matches!(err, DnsError::NameNotFound(ref n) if n == "ghost.mesh"));
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn fake_ip_in_range_and_stable() {
        let mut dns = unified();
        let first = local(&mut dns, &a("proxy.example.com"), 1000);
        assert_eq!(first.class, DnsClass::FakeIp);
        assert!(!first.from_cache);
        let ip = match first.records[0] {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => panic!("fake-ip must be v4"),
        };
        assert!(dns.pool.contains(ip));

        // TTL 内重复查询返回同一 IP。
        let second = local(&mut dns, &a("proxy.example.com"), 1100);
        assert!(second.from_cache);
        assert_eq!(second.records, first.records);
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn fake_ip_reverse_lookup() {
        let mut dns = unified();
        let ans = local(&mut dns, &a("proxy.example.com"), 1000);
        let ip = match ans.records[0] {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => panic!("fake-ip must be v4"),
        };
        assert_eq!(dns.reverse_lookup(ip), Some("proxy.example.com"));
    }

    #[test]
    fn fake_ip_reclaimed_after_ttl() {
        let mut dns = unified();
        let ans = local(&mut dns, &a("proxy.example.com"), 1000);
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
        local(&mut dns, &a("proxy.example.com"), 1000);
        assert_eq!(dns.reclaim_expired(1100), 0);
        assert_eq!(dns.fake_ip_count(), 1);
    }

    #[test]
    fn upstream_for_bypass() {
        let mut dns = unified();
        assert!(matches!(
            dns.step(&a("direct.example.org"), 1000).unwrap(),
            ResolveStep::Upstream {
                class: DnsClass::Upstream
            }
        ));
        // `step` 只分类，不触发上游、不增加计数（引擎在服务线程）。
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn fake_ip_disabled_falls_back_to_upstream() {
        let mut dns = unified_with(DnsUnifiedConfig {
            fake_ip_enabled: false,
            ..Default::default()
        });
        match dns.step(&a("proxy.example.com"), 1000).unwrap() {
            // 分类仍是 FakeIp（命中代理规则），但解析交上游。
            ResolveStep::Upstream { class } => assert_eq!(class, DnsClass::FakeIp),
            ResolveStep::Local(_) => panic!("disabled fake-ip must go upstream"),
        }
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn aaaa_gets_empty_answer_no_allocation() {
        let mut dns = unified();
        let ans = local(
            &mut dns,
            &DnsQuery {
                name: "proxy.example.com".to_string(),
                qtype: DnsType::Aaaa,
            },
            1000,
        );
        assert_eq!(ans.class, DnsClass::FakeIp);
        assert!(ans.records.is_empty());
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn hosts_exact_match_case_insensitive() {
        let mut dns = unified();
        let ans = local(&mut dns, &a("LOCAL.DEV"), 1000);
        assert_eq!(ans.class, DnsClass::Hosts);
        assert_eq!(ans.records, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn empty_name_invalid() {
        let mut dns = unified();
        let err = dns.step(&a(""), 1000).unwrap_err();
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

    #[test]
    fn pool_normalizes_non_canonical_cidr() {
        // 非规范 CIDR 198.18.1.7/15 → 归一化到 198.18.0.0/15；
        // 分配的地址必须落在声明范围内。
        let mut pool = FakeIpPool::new(0xC612_0107, 15, 300).expect("pool");
        let ip = pool.allocate("x.test", 1000).unwrap();
        assert!(pool.contains(ip));
        let v = u32::from_be_bytes(ip.octets());
        assert_eq!(v & 0xFFFE_0000, 0xC612_0000);
    }

    fn aaaa(name: &str) -> DnsQuery {
        DnsQuery {
            name: name.to_string(),
            qtype: DnsType::Aaaa,
        }
    }

    #[test]
    fn step_returns_local_for_hosts_and_mesh() {
        let mut dns = unified();
        match dns.step(&a("local.dev"), 1000).unwrap() {
            ResolveStep::Local(ans) => {
                assert_eq!(ans.class, DnsClass::Hosts);
                assert_eq!(ans.records, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
            }
            ResolveStep::Upstream { .. } => panic!("hosts must be local"),
        }
        match dns.step(&a("xc-pc-linux.mesh"), 1000).unwrap() {
            ResolveStep::Local(ans) => {
                assert_eq!(ans.class, DnsClass::Mesh);
                assert_eq!(ans.records, vec![MESH_IP]);
            }
            ResolveStep::Upstream { .. } => panic!("mesh must be local"),
        }
        // step 本身不触发上游、不增加计数。
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn step_returns_upstream_for_bypass() {
        let mut dns = unified();
        match dns.step(&a("direct.example.org"), 1000).unwrap() {
            ResolveStep::Upstream { class } => assert_eq!(class, DnsClass::Upstream),
            ResolveStep::Local(_) => panic!("bypass must go upstream"),
        }
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn step_unknown_mesh_is_name_not_found() {
        let mut dns = unified();
        let err = dns.step(&a("ghost.mesh"), 1000).unwrap_err();
        assert!(matches!(err, DnsError::NameNotFound(ref n) if n == "ghost.mesh"));
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn hosts_family_mismatch_is_nodata() {
        let mut dns = unified();
        match dns.step(&aaaa("local.dev"), 1000).unwrap() {
            ResolveStep::Local(ans) => {
                assert_eq!(ans.class, DnsClass::Hosts);
                assert!(ans.records.is_empty());
            }
            ResolveStep::Upstream { .. } => panic!("hosts must be local NODATA"),
        }
    }

    #[test]
    fn mesh_family_mismatch_is_nodata_not_error() {
        let mut dns = unified();
        match dns.step(&aaaa("xc-pc-linux.mesh"), 1000).unwrap() {
            ResolveStep::Local(ans) => {
                assert_eq!(ans.class, DnsClass::Mesh);
                assert!(ans.records.is_empty());
            }
            ResolveStep::Upstream { .. } => panic!("mesh family mismatch must be local NODATA"),
        }
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn fake_ip_aaaa_is_nodata_without_allocation_via_step() {
        let mut dns = unified();
        match dns.step(&aaaa("proxy.example.com"), 1000).unwrap() {
            ResolveStep::Local(ans) => {
                assert_eq!(ans.class, DnsClass::FakeIp);
                assert!(ans.records.is_empty());
            }
            ResolveStep::Upstream { .. } => panic!("fake-ip AAAA must be local NODATA"),
        }
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn ip_preference_v4_only_blocks_aaaa_but_not_fake_ip_a() {
        let mut dns = unified_with(DnsUnifiedConfig {
            hosts: vec![("local.dev".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))],
            ip_preference: IpPreference::V4Only,
            ..Default::default()
        });
        // Upstream / Mesh / Hosts 的 AAAA → NODATA。
        for name in ["direct.example.org", "xc-pc-linux.mesh", "local.dev"] {
            match dns.step(&aaaa(name), 1000).unwrap() {
                ResolveStep::Local(ans) => {
                    assert!(ans.records.is_empty(), "{name} should be NODATA");
                }
                ResolveStep::Upstream { .. } => panic!("{name} AAAA must be NODATA"),
            }
        }
        // A 正常走上游。
        assert!(matches!(
            dns.step(&a("direct.example.org"), 1000).unwrap(),
            ResolveStep::Upstream { .. }
        ));
        // proxied A 仍是 fake-ip（不受偏好影响）。
        match dns.step(&a("proxy.example.com"), 1000).unwrap() {
            ResolveStep::Local(ans) => {
                assert_eq!(ans.class, DnsClass::FakeIp);
                assert_eq!(ans.records.len(), 1);
            }
            ResolveStep::Upstream { .. } => panic!("fake-ip A must stay local"),
        }
        assert_eq!(dns.upstream_call_count(), 0);
    }

    #[test]
    fn ip_preference_v6_only_blocks_a_but_not_fake_ip_a() {
        let mut dns = unified_with(DnsUnifiedConfig {
            hosts: vec![("local.dev".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))],
            ip_preference: IpPreference::V6Only,
            ..Default::default()
        });
        for name in ["direct.example.org", "xc-pc-linux.mesh", "local.dev"] {
            match dns.step(&a(name), 1000).unwrap() {
                ResolveStep::Local(ans) => {
                    assert!(ans.records.is_empty(), "{name} A should be NODATA");
                }
                ResolveStep::Upstream { .. } => panic!("{name} A must be NODATA"),
            }
        }
        assert!(matches!(
            dns.step(&aaaa("direct.example.org"), 1000).unwrap(),
            ResolveStep::Upstream { .. }
        ));
        // fake-ip 是内部 v4 机制，A 仍分配地址。
        match dns.step(&a("proxy.example.com"), 1000).unwrap() {
            ResolveStep::Local(ans) => assert_eq!(ans.records.len(), 1),
            ResolveStep::Upstream { .. } => panic!("fake-ip A must stay local"),
        }
    }

    #[test]
    fn prefer_v4_and_prefer_v6_are_noop_for_both_families() {
        for preference in [IpPreference::PreferV4, IpPreference::PreferV6] {
            let mut dns = unified_with(DnsUnifiedConfig {
                ip_preference: preference,
                ..Default::default()
            });
            assert!(matches!(
                dns.step(&a("direct.example.org"), 1000).unwrap(),
                ResolveStep::Upstream { .. }
            ));
            assert!(matches!(
                dns.step(&aaaa("direct.example.org"), 1000).unwrap(),
                ResolveStep::Upstream { .. }
            ));
        }
    }

    #[test]
    fn fake_ip_disabled_aaaa_goes_upstream() {
        let mut dns = unified_with(DnsUnifiedConfig {
            fake_ip_enabled: false,
            ..Default::default()
        });
        match dns.step(&aaaa("proxy.example.com"), 1000).unwrap() {
            ResolveStep::Upstream { class } => assert_eq!(class, DnsClass::FakeIp),
            ResolveStep::Local(_) => panic!("disabled fake-ip must go upstream"),
        }
        assert_eq!(dns.fake_ip_count(), 0);
    }

    #[test]
    fn fake_ip_capacity_exposed() {
        let dns = unified();
        assert_eq!(dns.fake_ip_capacity(), 131_072);
    }
}
