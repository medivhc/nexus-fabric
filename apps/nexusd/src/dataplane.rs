//! 统一数据面装配（D1-D6）。
//!
//! `nexusd <config-folder>` 的数据面：单个 TUN → 包分类器 → DNS 拦截 →
//! QoS 整形 → 转发。见 `apps/nexusd/MODULE.md` 的 D1-D6 冻结契约。
//!
//! 设计要点：
//! - `Dataplane` 拥有 TUN（`Box<dyn TunDevice>`，Mock 或真实设备）；
//! - `process_one()` 处理单个包：读 → DNS 短路 → 分类 → 计数；
//! - MVP：转发为计数（N1/proxy 实际发送由子系统就绪后接入）；
//! - DNS：UDP dport 53 短路到 `UnifiedDns`，响应写回 TUN。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use nexus_connectivity::cake::{CakeConfig, CakeScheduler, EnqueueDecision, FiveTuple};
use nexus_dns::{DnsQuery, DnsType, DnsUnifiedConfig, UnifiedDns};
use nexus_domain::SessionId;
use nexus_flow_session::{
    ChainDeps, ConnectivityEstablisher, FlowDecision, FlowKey, FlowSignal, IpProto, SessionManager,
    SessionManagerConfig,
};
use nexus_network::n1::bridge::N1Sender;
use nexus_path::{CandidatePath, PathConfig, PathManager};
use nexus_projection::TunDevice;
use nexus_projection::classifier::DropReason;
use nexus_projection::classifier::{Classification, PacketClassifier};
use nexus_projection::dns::{DEFAULT_DNS_CACHE_ENTRIES, DnsCache};
use nexus_projection::egress::{EgressNat, RealUdpEgress, Rule, SimpleRuleEngine};
use nexus_projection::routing::{Cidr, parse_ipv4_dst};
use nexus_projection::tcp::{
    FourTuple, STREAM_FIN, STREAM_RST, STREAM_SYN, TcpEvent, TcpTermStats, TcpTerminator,
    decode_stream_frame, encode_stream_frame, encode_syn_payload,
};
use nexus_projection::transparent::direct::{DirectEgressConfig, DirectTcpEvent, DirectTcpRelay};
use nexus_proxy_config::FlowSessionsMode;

mod chain_wiring;

pub use chain_wiring::{
    ChainDepsError, ProductionChainDeps, ProviderDeriveError, build_registry, derive_providers,
};
use nexus_projection::transparent::decision::{
    CachedDecision, FlowDecisionCache, FlowDecisionCacheStats, FlowDecisionKey, Frontend,
};

/// 数据面统计（D6 可观测）。
#[derive(Debug, Default, Clone)]
pub struct DataplaneStats {
    pub mesh_forwarded: u64,
    pub proxy_forwarded: u64,
    pub direct_forwarded: u64,
    pub dropped: u64,
    pub dns_answered: u64,
    pub qos_dropped: u64,
    pub mesh_dropped_no_n1: u64,
    pub proxy_dropped_no_proxy: u64,
    /// 写入 TUN 的包数（DNS 响应等；E4 验证用）。
    pub tun_written: u64,
    /// S10: TCP 终结可观测。
    /// 本地握手完成数（TcpEvent::Syn）。
    pub tcp_handshakes: u64,
    /// 经 N1 发送的 STREAM 帧数（SYN/DATA/FIN/RST）。
    pub mesh_tcp_frames: u64,
    /// 经 N1 发送的应用字节数（DATA 载荷）。
    pub mesh_tcp_bytes: u64,
    /// Proxy 分类的终结流数（GAP-1 前只计数）。
    pub proxy_tcp_streams: u64,
    /// Proxy 分类的应用字节数（GAP-1 前只计数）。
    pub proxy_tcp_bytes: u64,
    /// Direct 不支持协议丢弃（ICMP/分片/非 TCP-UDP）。
    pub direct_dropped_unsupported: u64,
    /// Direct UDP 真实发送数。
    pub direct_udp_sent: u64,
    /// 新流没有域名缓存命中（spec §9.16 `domain_miss`）。
    pub domain_miss: u64,
}

/// S4: 终结流记录（事件分发用）。
#[derive(Debug, Clone, Copy)]
struct TcpStreamInfo {
    /// 原始目的（STREAM 帧经 N1 路由用）。
    dst: SocketAddrV4,
    /// 是否 Proxy 分类（true → 只计数，不经 N1）。
    proxy: bool,
}

/// 数据面配置（从 daemon.toml / network.toml / dns.toml 组装）。
#[derive(Debug, Clone)]
pub struct DataplaneConfig {
    /// Mesh 网段 CIDR（字符串，如 "10.144.144.0/24"）。
    pub mesh_cidrs: Vec<String>,
    /// Bypass/白名单 CIDR。
    pub bypass_cidrs: Vec<String>,
    /// 是否启用 DNS 拦截。
    pub dns_enabled: bool,
    /// DNS 统一配置（dns.toml）。
    pub dns_config: Option<DnsUnifiedConfig>,
    /// 是否启用 QoS。
    pub qos_enabled: bool,
    /// QoS 配置。
    pub qos_config: CakeConfig,
    /// 是否启用 Boost（EWMA 选路）。
    pub boost_enabled: bool,
    /// N1 是否已配置（决定 Mesh 包是转发还是计数丢弃）。
    pub n1_configured: bool,
    /// Proxy 是否已配置。
    pub proxy_configured: bool,
    /// fake-IP 是否启用（本 run 恒为 false，spec §10.6）。
    pub fake_ip_enabled: bool,
    /// 决策缓存容量（spec §11.1：16384）。
    pub decision_cache_capacity: usize,
    /// 决策缓存空闲老化秒数（spec §11.1：300s）。
    pub decision_cache_idle_secs: u64,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            mesh_cidrs: Vec::new(),
            bypass_cidrs: Vec::new(),
            dns_enabled: false,
            dns_config: None,
            qos_enabled: false,
            qos_config: CakeConfig::default(),
            boost_enabled: false,
            n1_configured: false,
            proxy_configured: false,
            fake_ip_enabled: false,
            decision_cache_capacity: 16_384,
            decision_cache_idle_secs: 300,
        }
    }
}

/// 统一数据面：单个 TUN 的完整处理管线。
/// 上游可用性标志（建连器用；`set_n1_sender`/proxy 注入时更新）。
#[derive(Debug, Default)]
struct UpstreamFlags {
    n1: AtomicBool,
    proxy: AtomicBool,
}

/// nexusd 的建连器：检查规划选出的上游是否真实可用。
///
/// - 有任一上游（N1 mesh / proxy engine）→ Ok（会话 Active = 流被接纳到该路径）；
/// - 无上游 → Err（会话失败 → TCP 发 RST，不静默黑洞）。
struct NexusdEstablisher {
    upstream: Arc<UpstreamFlags>,
}

impl ConnectivityEstablisher for NexusdEstablisher {
    fn establish(
        &mut self,
        _session_id: &SessionId,
        _planned: &nexus_flow_session::Planned,
    ) -> Result<String, String> {
        if self.upstream.n1.load(Ordering::Relaxed) {
            return Ok("mesh".into());
        }
        if self.upstream.proxy.load(Ordering::Relaxed) {
            return Ok("proxy".into());
        }
        Err("no upstream path available (n1 and proxy both unset)".into())
    }
}

pub struct Dataplane {
    tun: Box<dyn TunDevice>,
    manager: PathManager,
    candidates: Vec<CandidatePath>,
    mesh_cidrs: Vec<Cidr>,
    bypass_cidrs: Vec<Cidr>,
    dns: Option<UnifiedDns>,
    qos: Option<CakeScheduler>,
    /// N1 发送桥（W1/W3）；`None` 时 Mesh 包走 D2 计数路径。
    n1_sender: Option<std::sync::Arc<dyn N1Sender>>,
    /// Proxy 转发引擎（P1-P5）；`None` 时 Proxy 包走 D2 计数路径。
    proxy_engine: Option<crate::proxy_fwd::ProxyEngine>,
    /// 上次同步的 TCP dial 成功计数（P1：proxy_forwarded 由 dial 结果增量驱动）。
    last_tcp_dials_ok: u64,
    /// 上次同步的 TCP dial 失败计数。
    last_tcp_dials_failed: u64,
    stats: Arc<Mutex<DataplaneStats>>,
    config: DataplaneConfig,
    buf: Vec<u8>,
    /// QoS 时钟起点（单调；避免 Duration::ZERO 冻结导致队列永不满溢回收）。
    qos_start: std::time::Instant,
    /// S1: TCP 终结器（smoltcp，用户态 TCP 栈）。
    tcp: TcpTerminator,
    /// S4: stream_id → 流信息（事件分发：Mesh 经 N1 发帧 / Proxy 计数）。
    tcp_streams: HashMap<u32, TcpStreamInfo>,
    /// Phase B：流→会话映射（`None` = 未启用，保持旧行为；渐进式改造 D3）。
    flow_mgr: Option<SessionManager>,
    /// Phase B：首包链依赖（flow_mgr 启用时构造）。
    flow_chain_deps: Option<ChainDeps>,
    /// Phase B：stream_id → SessionId（smoltcp 终结流绑定 §10 Session）。
    flow_tcp_streams: HashMap<u32, SessionId>,
    /// Phase B：FlowKey → stream_id（信号处理反向查）。
    flow_key_to_stream: HashMap<FlowKey, u32>,
    /// Phase B：stream_id → FlowKey（Data 门控反向查）。
    flow_stream_to_key: HashMap<u32, FlowKey>,
    /// Phase B：建连期缓冲的上行数据（stream_id → 待 flush 字节）。
    flow_pending_data: HashMap<u32, Vec<Vec<u8>>>,
    /// Phase B：待绑定（SYN 包已建会话，待 TcpEvent::Syn 到达）。
    flow_pending: HashMap<FourTuple, SessionId>,
    /// Phase B：上游可用性（建连器用）。
    flow_upstream: Arc<UpstreamFlags>,
    /// 规则引擎（S17 过渡：默认把未命中流量送回 Proxy 分支；S24 注入
    /// `DomainRuleEngine` 后按真实 tag 分流）。
    rules: Box<dyn nexus_domain::RuleEngine>,
    /// TUN/TPROXY 共享的 5 元组决策缓存（spec §9.13）。
    decision_cache: FlowDecisionCache,
    /// 生产 ChainDeps（由组合根注入；`None` = 无 provider 源）。
    production_chain_deps: Option<ProductionChainDeps>,
    /// 流会话状态（state/reason/providers；LocalAPI 读）。
    flow_sessions: FlowSessionsState,
    /// Direct TCP 中继（§9.10.1：终结器归 Dataplane，中继只持真实 socket）。
    direct_tcp: DirectTcpRelay,
    /// Direct UDP 真实出口（共享 NAT 语义，不复制 NAT 表）。
    direct_udp: Option<RealUdpEgress>,
    /// 共享 DNS 缓存（DNS 应答写入 → 后续新流按 dst IP 反查域名）。
    dns_cache: Arc<Mutex<DnsCache>>,
}

/// 流会话可见状态（spec §9.16 / §11.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowSessionsState {
    /// `enabled` / `disabled`。
    pub state: &'static str,
    /// `no_providers` / `config` / `None`。
    pub reason: Option<&'static str>,
    /// 派生 Provider 数量。
    pub providers: usize,
}

impl Default for FlowSessionsState {
    fn default() -> Self {
        Self {
            state: "disabled",
            reason: None,
            providers: 0,
        }
    }
}

impl Dataplane {
    /// 从配置构造数据面。
    ///
    /// # Errors
    /// - CIDR 解析失败 → `String` 错误；
    /// - QoS 配置非法 → `String` 错误；
    /// - DNS 配置非法 → `String` 错误。
    pub fn new(tun: Box<dyn TunDevice>, config: DataplaneConfig) -> Result<Self, String> {
        // 解析 CIDR。
        let mesh_cidrs = config
            .mesh_cidrs
            .iter()
            .map(|s| parse_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;
        let bypass_cidrs = config
            .bypass_cidrs
            .iter()
            .map(|s| parse_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;

        // PathManager（Boost 启用时用于 EWMA 选路；禁用时仍需一个实例供分类器）。
        let manager = PathManager::new(PathConfig::default());
        let candidates: Vec<CandidatePath> = Vec::new();

        // DNS（D3）。
        let dns = if config.dns_enabled {
            let dns_config = config.dns_config.clone().unwrap_or_default();
            let dns = UnifiedDns::new(
                dns_config,
                Box::new(StubMeshResolver),
                Box::new(StubProxyClassifier),
                Box::new(StubUpstreamResolver),
            )
            .map_err(|e| format!("dns config invalid: {e}"))?;
            Some(dns)
        } else {
            None
        };

        // QoS（D4）。
        let qos = if config.qos_enabled {
            config
                .qos_config
                .validate()
                .map_err(|e| format!("qos config invalid: {e}"))?;
            Some(
                CakeScheduler::new(&config.qos_config)
                    .map_err(|e| format!("qos init failed: {e}"))?,
            )
        } else {
            None
        };

        let decision_cache_capacity = config.decision_cache_capacity;
        let decision_cache_idle_secs = config.decision_cache_idle_secs;
        Ok(Self {
            tun,
            manager,
            candidates,
            mesh_cidrs,
            bypass_cidrs,
            dns,
            qos,
            n1_sender: None,
            proxy_engine: None,
            last_tcp_dials_ok: 0,
            last_tcp_dials_failed: 0,
            stats: Arc::new(Mutex::new(DataplaneStats::default())),
            config,
            buf: vec![0u8; 65535],
            qos_start: std::time::Instant::now(),
            tcp: TcpTerminator::new(),
            tcp_streams: HashMap::new(),
            flow_mgr: None,
            flow_chain_deps: None,
            flow_tcp_streams: HashMap::new(),
            flow_key_to_stream: HashMap::new(),
            flow_stream_to_key: HashMap::new(),
            flow_pending_data: HashMap::new(),
            flow_pending: HashMap::new(),
            flow_upstream: Arc::new(UpstreamFlags::default()),
            rules: Box::new(default_simple_engine()?),
            decision_cache: FlowDecisionCache::new(
                decision_cache_capacity,
                std::time::Duration::from_secs(decision_cache_idle_secs),
            ),
            production_chain_deps: None,
            flow_sessions: FlowSessionsState::default(),
            direct_tcp: DirectTcpRelay::new(DirectEgressConfig::default()),
            direct_udp: RealUdpEgress::new(Arc::new(Mutex::new(EgressNat::default()))).ok(),
            dns_cache: Arc::new(Mutex::new(DnsCache::new(DEFAULT_DNS_CACHE_ENTRIES))),
        })
    }

    /// 注入规则引擎（组合根：有 `proxy.yaml` → `DomainRuleEngine`）。
    pub fn set_rule_engine(&mut self, rules: Box<dyn nexus_domain::RuleEngine>) {
        self.rules = rules;
    }

    /// 注入无代理配置默认引擎（`SimpleRuleEngine`，全部流量交 `proxy` 标签）。
    ///
    /// # Errors
    ///
    /// 内置 CIDR 非法（不应发生）。
    pub fn set_default_simple_engine(&mut self) -> Result<(), String> {
        self.rules = Box::new(default_simple_engine()?);
        Ok(())
    }

    /// TUN 设备名（OsAssemble 装配用）。
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// 决策缓存计数器快照。
    pub fn decision_cache_stats(&self) -> FlowDecisionCacheStats {
        self.decision_cache.stats()
    }

    /// 写入一条 DNS 应答映射（SNI/应答写入路径）。
    pub fn record_dns_answer(&mut self, domain: &str, ip: Ipv4Addr) {
        if let Ok(mut cache) = self.dns_cache.lock() {
            cache.insert(domain, IpAddr::V4(ip), 300);
        }
    }

    /// 共享 DNS 缓存句柄（与 UnifiedDns 同源）。
    pub fn dns_cache_handle(&self) -> Arc<Mutex<DnsCache>> {
        Arc::clone(&self.dns_cache)
    }

    /// 某包的缓存出站（测试/可观测用）。
    pub fn cached_outbound(&mut self, packet: &[u8]) -> Option<String> {
        let flow = nexus_projection::egress::FlowKey::parse(packet)?;
        let now = u64::try_from(self.qos_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let key = FlowDecisionKey {
            flow,
            frontend: Frontend::Tun,
        };
        self.decision_cache
            .get(&key, now)
            .map(|d| d.selected_outbound.clone())
    }

    /// 注入组合根构建的 ProductionChainDeps。
    pub fn set_production_chain_deps(&mut self, deps: ProductionChainDeps) {
        self.flow_sessions.providers = deps.provider_count();
        self.production_chain_deps = Some(deps);
    }

    /// 流会话可见状态。
    pub fn flow_sessions_state(&self) -> FlowSessionsState {
        self.flow_sessions
    }

    /// 按配置三态启用流会话（spec §7.6 第 3 步）。
    ///
    /// - `Enabled`：强制启用（无 provider 源时也启用，由建连失败可见）；
    /// - `Auto`：`provider_count > 0` 启用，否则禁用并 `reason=no_providers`；
    /// - `Disabled`：禁用。
    pub fn enable_flow_sessions_for_config(
        &mut self,
        mode: FlowSessionsMode,
        provider_count: usize,
    ) -> bool {
        self.flow_sessions.providers = provider_count;
        match mode {
            FlowSessionsMode::Enabled => {
                self.enable_flow_sessions();
                self.flow_sessions.state = "enabled";
                self.flow_sessions.reason = None;
                true
            }
            FlowSessionsMode::Auto if provider_count > 0 => {
                self.enable_flow_sessions();
                self.flow_sessions.state = "enabled";
                self.flow_sessions.reason = None;
                true
            }
            FlowSessionsMode::Auto => {
                self.flow_sessions.state = "disabled";
                self.flow_sessions.reason = Some("no_providers");
                false
            }
            FlowSessionsMode::Disabled => {
                self.flow_sessions.state = "disabled";
                self.flow_sessions.reason = None;
                false
            }
        }
    }

    /// Phase B：启用流→会话映射（E4/生产按需调用；默认关闭保持旧行为）。
    pub fn enable_flow_sessions(&mut self) {
        let upstream = Arc::clone(&self.flow_upstream);
        // 上游可用性初值：按当前注入状态。
        upstream
            .n1
            .store(self.n1_sender.is_some(), Ordering::Relaxed);
        upstream
            .proxy
            .store(self.proxy_engine.is_some(), Ordering::Relaxed);

        let establisher = NexusdEstablisher { upstream };
        self.enable_flow_sessions_with_establisher(Box::new(establisher));
    }

    /// 测试钩子：注入自定义建连器（E4 用阻塞版保证确定性）。
    pub fn enable_flow_sessions_with_establisher(
        &mut self,
        establisher: Box<dyn nexus_flow_session::ConnectivityEstablisher>,
    ) {
        let chain_deps = match self.production_chain_deps.as_ref() {
            Some(deps) => deps.to_chain_deps(),
            None => ProductionChainDeps::from_config(None, None)
                .expect("empty production chain deps must build")
                .to_chain_deps(),
        };
        self.flow_chain_deps = Some(chain_deps);
        self.flow_mgr = Some(SessionManager::new(
            SessionManagerConfig::default(),
            establisher,
        ));
    }

    /// 注入 N1 发送器（W1/W3；由 Composition Root 在 N1 就绪后调用）。
    pub fn set_n1_sender(&mut self, sender: std::sync::Arc<dyn N1Sender>) {
        self.n1_sender = Some(sender);
        self.flow_upstream.n1.store(true, Ordering::Relaxed);
    }

    /// 注入 Proxy 转发引擎（P1-P5；由 Composition Root 在 proxy.yaml 解析后调用）。
    pub fn set_proxy_engine(&mut self, engine: crate::proxy_fwd::ProxyEngine) {
        self.proxy_engine = Some(engine);
        self.flow_upstream.proxy.store(true, Ordering::Relaxed);
    }

    // ---------- Phase B/C：E4 可观测接口 ----------

    /// 流会话数（`None` = 未启用流映射时返回 0）。
    #[must_use]
    pub fn flow_session_count(&self) -> usize {
        self.flow_mgr
            .as_ref()
            .map(|m| m.session_count())
            .unwrap_or(0)
    }

    /// 首包链总运行次数（E4 `no_planner_in_hot_path` 证明）。
    #[must_use]
    pub fn flow_planner_calls(&self) -> u64 {
        self.flow_mgr.as_ref().map(|m| m.planner_calls).unwrap_or(0)
    }

    /// 某流的 phase。
    #[must_use]
    pub fn flow_phase(&self, key: &FlowKey) -> Option<nexus_flow_session::FlowPhase> {
        self.flow_mgr.as_ref()?.get_phase(key)
    }

    /// 某流绑定的 session id。
    #[must_use]
    pub fn flow_session_for_key(&self, key: &FlowKey) -> Option<SessionId> {
        self.flow_mgr.as_ref()?.session_for_key(key)
    }

    /// 某会话的首包链 policy trace 长度。
    #[must_use]
    pub fn flow_policy_trace_len(&self, session_id: &SessionId) -> usize {
        self.flow_mgr
            .as_ref()
            .map(|m| m.policy_trace_len(session_id))
            .unwrap_or(0)
    }

    /// 某流的 UDP 超 bound 丢弃计数。
    #[must_use]
    pub fn flow_udp_dropped(&self, key: &FlowKey) -> u64 {
        self.flow_mgr
            .as_ref()
            .map(|m| m.udp_dropped(key))
            .unwrap_or(0)
    }

    /// 触发空闲扫描（E4 用；生产由定时器调）。
    pub fn flow_sweep_idle(&mut self) -> usize {
        // S31 之前：driver 在每个扫描点采集一次 `Instant`（core 不读时钟）。
        let now = std::time::Instant::now();
        self.flow_mgr
            .as_mut()
            .map(|m| m.sweep_idle(now))
            .unwrap_or(0)
    }

    /// 设置流空闲超时（E4 用）。
    pub fn set_flow_idle_timeout(&mut self, timeout: std::time::Duration) {
        if let Some(mgr) = self.flow_mgr.as_mut() {
            mgr.set_idle_timeout(timeout);
        }
    }

    /// 当前流表项数。
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flow_mgr.as_ref().map(|m| m.flow_count()).unwrap_or(0)
    }

    /// 路径切换事件（D6，E4 用）：会话记录新 locator，流不断。
    pub fn flow_on_path_switch(&mut self, session_id: &SessionId, new_locator: String) -> bool {
        self.flow_mgr
            .as_mut()
            .map(|m| m.on_path_switch(session_id, new_locator))
            .unwrap_or(false)
    }

    /// Proxy 引擎是否已注入（P1 可观测）。
    #[must_use]
    pub fn proxy_engine_ready(&self) -> bool {
        self.proxy_engine.is_some()
    }

    /// 获取统计的共享句柄（供 LocalAPI 线程读取，B1）。
    #[must_use]
    pub fn stats_handle(&self) -> Arc<Mutex<DataplaneStats>> {
        Arc::clone(&self.stats)
    }

    /// 内部：锁定统计并执行更新。
    fn with_stats<F>(&self, f: F)
    where
        F: FnOnce(&mut DataplaneStats),
    {
        if let Ok(mut stats) = self.stats.lock() {
            f(&mut stats);
        }
    }

    /// 处理单个包（非阻塞；无包时返回 `Ok(false)`）。
    ///
    /// 管线：读 TUN → DNS 短路（UDP dport 53）→ 分类 → [S1: TCP 终结] →
    /// QoS → 计数转发。
    /// 分类并缓存 5 元组决策；命中缓存时不再调用规则引擎（spec §9.13）。
    fn classify_with_cache(&mut self, packet: &[u8]) -> Classification {
        let now_millis = u64::try_from(self.qos_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let cache_key =
            nexus_projection::egress::FlowKey::parse(packet).map(|flow| FlowDecisionKey {
                flow,
                frontend: Frontend::Tun,
            });
        if let Some(key) = cache_key {
            if let Some(cached) = self.decision_cache.get(&key, now_millis) {
                return classification_from_target(&cached.target);
            }
        }
        let domain = parse_ipv4_dst(packet).and_then(|dst| {
            let ip = IpAddr::V4(Ipv4Addr::from(dst));
            let hit = self
                .dns_cache
                .lock()
                .ok()
                .and_then(|mut cache| cache.lookup(&ip));
            if hit.is_none() {
                self.with_stats(|s| s.domain_miss += 1);
            }
            hit
        });
        let candidates: &[CandidatePath] = if self.config.boost_enabled {
            &self.candidates
        } else {
            &[]
        };
        let classification = {
            let classifier = PacketClassifier::new(
                self.mesh_cidrs.clone(),
                self.bypass_cidrs.clone(),
                &*self.rules,
                self.config.fake_ip_enabled,
                &self.manager,
                candidates,
                0.0, // degrade_threshold：MVP 用 0（不触发 degraded）
            );
            classifier.classify(packet, domain.as_deref())
        };
        if let Some(key) = cache_key {
            let decision = decision_from_classification(&classification, now_millis);
            self.decision_cache.insert(key, decision, now_millis);
        }
        classification
    }

    pub fn process_one(&mut self) -> io::Result<bool> {
        // Phase B/C：每轮先回填建连事件（即使无包，保证 Allocating→Active 推进）。
        self.flow_pump();
        let n = match self.tun.read(&mut self.buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        };
        let packet = self.buf[..n].to_vec();

        // D3：DNS 短路（UDP 目的端口 53）。
        if self.dns.is_some() && is_dns_query(&packet) {
            self.handle_dns(&packet);
            return Ok(true);
        }

        // D2：分类。
        // D6：boost_enabled 时分类器经 PathManager 做 EWMA 只读选路（S30）；
        // 禁用时 candidates 为空（回落默认转发）。
        let classification = self.classify_with_cache(&packet);

        // S1：TCP + Mesh/Proxy → smoltcp 终结（不再走 raw-datagram 路径）。
        if is_tcp_packet(&packet) && matches!(classification, Classification::Mesh { .. }) {
            if !self.qos_admit(&packet) {
                return Ok(true);
            }
            // Phase B：流→会话映射（启用时）。首包走 §10 链，会话建好前
            // TCP 本地握手照常（smoltcp 缓冲早期数据，D4）。
            if self.flow_mgr.is_some() && !self.flow_handle_tcp_packet(&packet, &classification) {
                return Ok(true);
            }
            self.handle_tcp_terminated(&packet, &classification);
            self.dispatch_tcp_events();
            self.flow_pump();
            return Ok(true);
        }

        // D4：QoS 整形（启用时）。
        if !self.qos_admit(&packet) {
            return Ok(true);
        }

        // Phase C：UDP + Mesh/Proxy → 流→会话映射（启用时）。
        // Direct/Bypass 不建会话（不消耗 Nexus 资源）；DNS 已在前面短路。
        if self.flow_mgr.is_some()
            && is_udp_packet(&packet)
            && matches!(
                classification,
                Classification::Mesh { .. } | Classification::Proxy { .. }
            )
            && !self.flow_handle_udp_packet(&packet, &classification)
        {
            self.flow_pump();
            return Ok(true);
        }

        // D2/W1：按分类转发。
        match classification {
            Classification::Mesh { .. } => {
                if self.config.n1_configured {
                    // W1：N1 真发（发送器已注入时）；失败则计数 mesh_dropped_no_n1。
                    let sent = match (&self.n1_sender, ipv4_dst_of(&packet)) {
                        (Some(sender), Some(dst)) => sender.send_to_mesh(dst, &packet).is_ok(),
                        _ => false,
                    };
                    if sent {
                        self.with_stats(|s| s.mesh_forwarded += 1);
                    } else {
                        self.with_stats(|s| s.mesh_dropped_no_n1 += 1);
                    }
                } else {
                    self.with_stats(|s| s.mesh_dropped_no_n1 += 1);
                }
            }
            Classification::Proxy { ref outbound } => {
                // P1-P5 / S26：engine 已注入 → 按规则 tag 真实转发；否则计数降级。
                let outcome = self
                    .proxy_engine
                    .as_mut()
                    .map(|e| e.handle_packet(&packet, outbound));
                match outcome {
                    Some(Ok(result)) => {
                        for pkt in result.tun_packets {
                            if self.tun.write(&pkt).is_ok() {
                                self.with_stats(|s| s.tun_written += 1);
                            } else {
                                self.with_stats(|s| s.dropped += 1);
                            }
                        }
                        let more = self
                            .proxy_engine
                            .as_mut()
                            .map(|e| e.poll().tun_packets)
                            .unwrap_or_default();
                        for pkt in more {
                            if self.tun.write(&pkt).is_ok() {
                                self.with_stats(|s| s.tun_written += 1);
                            } else {
                                self.with_stats(|s| s.dropped += 1);
                            }
                        }
                        if packet.get(9) == Some(&17) && result.forwarded {
                            self.with_stats(|s| s.proxy_forwarded += 1);
                        }
                        // 同步 TCP dial 结果增量。
                        let eng_stats = self
                            .proxy_engine
                            .as_ref()
                            .map(|e| e.stats())
                            .unwrap_or_default();
                        let ok_delta = eng_stats
                            .tcp_dials_ok
                            .saturating_sub(self.last_tcp_dials_ok);
                        let fail_delta = eng_stats
                            .tcp_dials_failed
                            .saturating_sub(self.last_tcp_dials_failed);
                        self.last_tcp_dials_ok = eng_stats.tcp_dials_ok;
                        self.last_tcp_dials_failed = eng_stats.tcp_dials_failed;
                        self.with_stats(|s| {
                            s.proxy_forwarded += ok_delta;
                            s.proxy_dropped_no_proxy += fail_delta;
                        });
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::UnknownOutbound { .. }))
                    | Some(Err(crate::proxy_fwd::ProxyEngineError::UnsupportedOutboundKind {
                        ..
                    }))
                    | Some(Err(crate::proxy_fwd::ProxyEngineError::DialFailed { .. })) => {
                        self.with_stats(|s| {
                            s.proxy_dropped_no_proxy += 1;
                            s.dropped += 1;
                        });
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::UnsupportedProtocol {
                        ..
                    })) => {
                        self.with_stats(|s| s.dropped += 1);
                    }
                    None => {
                        self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
                    }
                }
            }
            Classification::Direct => {
                self.handle_direct(&packet);
            }
            Classification::Drop { .. } => {
                self.with_stats(|s| s.dropped += 1);
            }
        }
        Ok(true)
    }

    /// Direct 真转发（spec §9.9 / AC-G6-01..03）。
    ///
    /// - TCP：Dataplane 终结器 + `DirectTcpRelay`（同一终结器实例，§9.10.1）；
    /// - UDP：`RealUdpEgress` 真实发送，回包由 `drain_direct_replies` 写回；
    /// - ICMP/分片/非 TCP-UDP：计数 `direct_dropped_unsupported`，不 forwarding。
    fn handle_direct(&mut self, packet: &[u8]) {
        if packet.len() < 20 {
            self.with_stats(|s| s.direct_dropped_unsupported += 1);
            return;
        }
        // 分片包（MF 或 fragment offset != 0）不支持。
        let frag = u16::from_be_bytes([packet[6], packet[7]]);
        if frag & 0x3fff != 0 {
            self.with_stats(|s| s.direct_dropped_unsupported += 1);
            return;
        }
        match packet[9] {
            6 => self.handle_direct_tcp(packet),
            17 => {
                if let Some(egress) = self.direct_udp.as_ref() {
                    if egress.send(packet, "self") {
                        self.with_stats(|s| {
                            s.direct_forwarded += 1;
                            s.direct_udp_sent += 1;
                        });
                    } else {
                        self.with_stats(|s| s.dropped += 1);
                    }
                } else {
                    self.with_stats(|s| s.dropped += 1);
                }
            }
            _ => self.with_stats(|s| s.direct_dropped_unsupported += 1),
        }
    }

    fn handle_direct_tcp(&mut self, packet: &[u8]) {
        let mut out = self.tcp.handle_uplink(packet, "direct");
        for event in self.tcp.poll() {
            match event {
                TcpEvent::Syn { stream_id, dst, .. } => {
                    if self.direct_tcp.open(stream_id, dst).is_err() {
                        out.extend(self.tcp.handle_fabric_rst(stream_id));
                    }
                }
                TcpEvent::Data {
                    stream_id, bytes, ..
                } => {
                    let _ = self.direct_tcp.write(stream_id, &bytes);
                }
                TcpEvent::Closed {
                    stream_id, reset, ..
                } => self.direct_tcp.close(stream_id, reset),
                TcpEvent::TunPacket(pkt) => out.push(pkt),
            }
        }
        // Direct 下行 → 注入 Dataplane 终结器 → TUN。
        for event in self.direct_tcp.poll() {
            match event {
                DirectTcpEvent::Data { stream_id, bytes } => {
                    out.extend(self.tcp.handle_fabric_data(stream_id, &bytes));
                }
                DirectTcpEvent::Closed { stream_id, reset } => {
                    if reset {
                        out.extend(self.tcp.handle_fabric_rst(stream_id));
                    } else {
                        out.extend(self.tcp.handle_fabric_fin(stream_id));
                    }
                }
                DirectTcpEvent::Failed { stream_id, error } => {
                    let _ = error;
                    out.extend(self.tcp.handle_fabric_rst(stream_id));
                }
            }
        }
        let mut wrote = 0u64;
        for pkt in out {
            if self.tun.write(&pkt).is_ok() {
                wrote += 1;
            }
        }
        self.with_stats(|s| {
            s.tun_written += wrote;
            if wrote > 0 {
                s.direct_forwarded += 1;
            }
        });
    }

    /// 把 Direct UDP 回包写回 TUN；返回写入数。
    pub fn drain_direct_replies(&mut self) -> usize {
        let Some(egress) = self.direct_udp.as_ref() else {
            return 0;
        };
        let mut replies = Vec::new();
        while let Some((pkt, _peer)) = egress.recv_reply() {
            replies.push(pkt);
        }
        let mut wrote = 0;
        for pkt in replies {
            if self.tun.write(&pkt).is_ok() {
                wrote += 1;
            }
        }
        if wrote > 0 {
            self.with_stats(|s| s.tun_written += wrote as u64);
        }
        wrote
    }

    /// D4 QoS 准入检查（S1 复用：终结路径同样先整形）。
    ///
    /// 返回 `false` 表示被整形丢弃（已计数 `qos_dropped`）。
    /// 使用单调时钟（非冻结），避免队列永不回收。
    fn qos_admit(&mut self, packet: &[u8]) -> bool {
        let now = self.qos_start.elapsed();
        let qos = match &mut self.qos {
            Some(q) => q,
            None => return true,
        };
        if let Some(tuple) = five_tuple_of(packet) {
            let decision = qos.enqueue(&tuple, packet.len() as u64, now);
            if !matches!(decision, EnqueueDecision::Admitted { .. }) {
                self.with_stats(|s| s.qos_dropped += 1);
                return false;
            }
        }
        // 排空已准入包（MVP：计数转发，不实际发送；防止队列无限增长）。
        // 上限 64 避免单包处理时长时间占用。
        for _ in 0..64 {
            if qos.dequeue(now).is_none() {
                break;
            }
        }
        // 回收超时流。
        qos.reap(now);
        true
    }

    /// S1/S2：TCP 包送终结器；产生的 TUN 包写回。
    /// Phase C：UDP 包的流→会话映射。
    ///
    /// 返回 true = 继续现有转发路径；false = 包已处理（缓冲/丢弃），不继续。
    fn flow_handle_udp_packet(&mut self, packet: &[u8], classification: &Classification) -> bool {
        let (mgr, deps) = match (self.flow_mgr.as_mut(), self.flow_chain_deps.as_ref()) {
            (Some(m), Some(d)) => (m, d),
            _ => return true,
        };
        let key = match FlowKey::parse_ipv4(packet) {
            Some(k) => k,
            None => return true,
        };
        debug_assert_eq!(key.proto, IpProto::Udp);
        let now = std::time::Instant::now();
        let hint = egress_hint(classification);
        match mgr.on_packet_with_hint(key, packet, false, deps, now, hint) {
            FlowDecision::NewSession { .. } | FlowDecision::Buffered { .. } => {
                // 已入 SessionManager 有界缓冲，暂不转发（Active 后 flush）。
                false
            }
            FlowDecision::Forward { .. } => true,
            FlowDecision::Drop { .. } => {
                self.with_stats(|s| s.dropped += 1);
                false
            }
        }
    }

    /// Phase C：转发 Active 后 flush 的 UDP 缓冲包（重分类后按 Mesh/Proxy 转发）。
    fn forward_buffered_udp(&mut self, packet: &[u8]) {
        let domain = parse_ipv4_dst(packet).and_then(|dst| {
            let ip = IpAddr::V4(Ipv4Addr::from(dst));
            let hit = self
                .dns_cache
                .lock()
                .ok()
                .and_then(|mut cache| cache.lookup(&ip));
            if hit.is_none() {
                self.with_stats(|s| s.domain_miss += 1);
            }
            hit
        });
        let candidates: &[CandidatePath] = if self.config.boost_enabled {
            &self.candidates
        } else {
            &[]
        };
        let classification = {
            let classifier = PacketClassifier::new(
                self.mesh_cidrs.clone(),
                self.bypass_cidrs.clone(),
                &*self.rules,
                self.config.fake_ip_enabled,
                &self.manager,
                candidates,
                0.0,
            );
            classifier.classify(packet, domain.as_deref())
        };
        match classification {
            Classification::Mesh { .. } => {
                if self.config.n1_configured {
                    let sent = match (&self.n1_sender, ipv4_dst_of(packet)) {
                        (Some(sender), Some(dst)) => sender.send_to_mesh(dst, packet).is_ok(),
                        _ => false,
                    };
                    if sent {
                        self.with_stats(|s| s.mesh_forwarded += 1);
                    } else {
                        self.with_stats(|s| s.mesh_dropped_no_n1 += 1);
                    }
                } else {
                    self.with_stats(|s| s.mesh_dropped_no_n1 += 1);
                }
            }
            Classification::Proxy { ref outbound } => {
                if let Some(engine) = self.proxy_engine.as_mut() {
                    match engine.handle_packet(packet, outbound) {
                        Ok(result) => {
                            for pkt in result.tun_packets {
                                if self.tun.write(&pkt).is_ok() {
                                    self.with_stats(|s| s.tun_written += 1);
                                }
                            }
                            if result.forwarded {
                                self.with_stats(|s| s.proxy_forwarded += 1);
                            }
                        }
                        Err(_) => self.with_stats(|s| s.proxy_dropped_no_proxy += 1),
                    }
                } else {
                    self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
                }
            }
            _ => {
                self.with_stats(|s| s.dropped += 1);
            }
        }
    }

    /// Phase B：TCP 包的流→会话映射。
    ///
    /// 返回 true = 继续现有 smoltcp 终结路径；false = 包已处理（丢弃），不继续。
    fn flow_handle_tcp_packet(&mut self, packet: &[u8], classification: &Classification) -> bool {
        let (mgr, deps) = match (self.flow_mgr.as_mut(), self.flow_chain_deps.as_ref()) {
            (Some(m), Some(d)) => (m, d),
            _ => return true,
        };
        let key = match FlowKey::parse_ipv4(packet) {
            Some(k) => k,
            None => return true, // 解析失败走旧路径（防御）。
        };
        debug_assert_eq!(key.proto, IpProto::Tcp);
        let is_syn = is_tcp_syn(packet);
        let now = std::time::Instant::now();
        let hint = egress_hint(classification);
        match mgr.on_packet_with_hint(key, packet, is_syn, deps, now, hint) {
            FlowDecision::NewSession { session_id } => {
                // 待 TcpEvent::Syn 到达时绑定 stream_id。
                let four = FourTuple {
                    src_ip: key.src_ip,
                    src_port: key.src_port,
                    dst_ip: key.dst_ip,
                    dst_port: key.dst_port,
                };
                self.flow_pending.insert(four, session_id);
                true
            }
            FlowDecision::Forward { .. } => true,
            FlowDecision::Buffered { .. } => true, // TCP 不应缓冲；防御性继续。
            FlowDecision::Drop { .. } => {
                self.with_stats(|s| s.dropped += 1);
                false
            }
        }
    }

    /// Phase B：回填建连事件并执行信号（RST/拆除）。
    /// Phase B：该流的会话是否还在 Allocating（是则缓冲上行数据）。
    fn flow_should_buffer_data(&self, stream_id: u32) -> bool {
        let mgr = match self.flow_mgr.as_ref() {
            Some(m) => m,
            None => return false,
        };
        let key = match self.flow_stream_to_key.get(&stream_id) {
            Some(k) => k,
            None => return false, // 未绑定会话的流走旧路径。
        };
        matches!(
            mgr.get_phase(key),
            Some(nexus_flow_session::FlowPhase::Allocating)
        )
    }

    /// Phase B：转发 TCP 上行数据（原 S5 逻辑抽出，供门控/flush 复用）。
    fn forward_tcp_data(&mut self, stream_id: u32, bytes: &[u8]) {
        match self.tcp_streams.get(&stream_id).copied() {
            Some(info) if !info.proxy => {
                // S5-Mesh：STREAM DATA 帧经 N1 发送。
                let frame = encode_stream_frame(stream_id, 0x00, bytes);
                let n = bytes.len() as u64;
                if self.send_mesh_tcp_frame(*info.dst.ip(), &frame) {
                    self.with_stats(|s| s.mesh_tcp_bytes += n);
                }
            }
            Some(_) => {
                // S5-Proxy：GAP-1 前只计数。
                let n = bytes.len() as u64;
                self.with_stats(|s| s.proxy_tcp_bytes += n);
            }
            None => {
                // 防御：未知流的数据（不应发生）。
                self.with_stats(|s| s.dropped += 1);
            }
        }
    }

    fn flow_pump(&mut self) {
        // 作用域隔离 mgr 借用：pump + 收集 Active 流 + 取信号；flush/转发在外层做。
        let (active_streams, signals) = match self.flow_mgr.as_mut() {
            Some(mgr) => {
                mgr.pump();
                let pairs: Vec<(u32, FlowKey)> = self
                    .flow_stream_to_key
                    .iter()
                    .map(|(sid, key)| (*sid, *key))
                    .collect();
                let active: Vec<u32> = pairs
                    .into_iter()
                    .filter(|(sid, key)| {
                        self.flow_pending_data.contains_key(sid)
                            && matches!(
                                mgr.get_phase(key),
                                Some(nexus_flow_session::FlowPhase::Active)
                            )
                    })
                    .map(|(sid, _)| sid)
                    .collect();
                let signals = mgr.drain_signals();
                (active, signals)
            }
            None => return,
        };
        // Active 后 flush 建连期缓冲的上行数据（D4）。
        for stream_id in active_streams {
            if let Some(batches) = self.flow_pending_data.remove(&stream_id) {
                for bytes in batches {
                    self.forward_tcp_data(stream_id, &bytes);
                }
            }
        }
        // Phase C：Active 后 flush UDP 有界缓冲。
        // 在上面作用域内已 pump；这里重新借 mgr 取缓冲。
        let udp_flushes: Vec<(FlowKey, Vec<Vec<u8>>)> = match self.flow_mgr.as_mut() {
            Some(mgr) => mgr.take_udp_buffers_for_active(),
            None => Vec::new(),
        };
        for (key, packets) in udp_flushes {
            let _ = key; // 分类由包内容决定（重分类）。
            for pkt in packets {
                self.forward_buffered_udp(&pkt);
            }
        }
        for signal in signals {
            match signal {
                FlowSignal::TcpReset { key } => {
                    // 找该流的 smoltcp 连接，发 RST（不静默黑洞，D4）。
                    // 优先用已绑定的 stream_id；握手未完成时按 FourTuple 直接重置。
                    // 若 smoltcp 未产生 RST 包，直接构造一个（E4 可观察性）。
                    let four = FourTuple {
                        src_ip: key.src_ip,
                        src_port: key.src_port,
                        dst_ip: key.dst_ip,
                        dst_port: key.dst_port,
                    };
                    let rst_pkts = match self.flow_stream_id_for_key(&key) {
                        Some(sid) => {
                            let pkts = self.tcp.handle_fabric_rst(sid);
                            self.flow_tcp_streams.remove(&sid);
                            pkts
                        }
                        None => self.tcp.reset_by_tuple(&four),
                    };
                    // 确保有 RST 包；没有则构造。
                    let has_rst = rst_pkts.iter().any(|p| {
                        if p.len() < 34 {
                            return false;
                        }
                        let ihl = usize::from(p[0] & 0x0f) * 4;
                        p.len() >= ihl + 14 && p[ihl + 13] & 0x04 != 0
                    });
                    if !has_rst {
                        // 直接写 TUN（不经过 fixup_tun_packet，后者只认 smoltcp iface IP）。
                        let rst = Self::craft_rst(&key);
                        let _ = self.tun.write(&rst);
                        self.with_stats(|s| s.tun_written += 1);
                    }
                    self.write_tun_packets(rst_pkts);
                    if let Some(mgr) = self.flow_mgr.as_mut() {
                        mgr.dispose_flow(&key);
                    }
                    self.with_stats(|s| s.dropped += 1);
                }
                FlowSignal::TearDown { key, .. } => {
                    if let Some(sid) = self.flow_stream_id_for_key(&key) {
                        let fin_pkts = self.tcp.handle_fabric_rst(sid);
                        self.write_tun_packets(fin_pkts);
                        self.flow_tcp_streams.remove(&sid);
                    }
                    // dataplane 已执行拆除 → 流进 Disposed 并 GC。
                    if let Some(mgr) = self.flow_mgr.as_mut() {
                        mgr.dispose_flow(&key);
                    }
                }
            }
        }
    }

    /// Phase B：FlowKey → smoltcp stream_id（经已绑定的映射）。
    fn flow_stream_id_for_key(&self, key: &FlowKey) -> Option<u32> {
        self.flow_key_to_stream.get(key).copied()
    }

    /// 构造 TCP RST 包（回退路径；src/dst 互换）。
    fn craft_rst(key: &FlowKey) -> Vec<u8> {
        use nexus_projection::tcp::{ip_checksum, tcp_checksum};
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 40;
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&key.dst_ip); // src = server
        pkt[16..20].copy_from_slice(&key.src_ip); // dst = client
        pkt[20..22].copy_from_slice(&key.dst_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&key.src_port.to_be_bytes());
        // seq/ack = 0；flags = RST|ACK.
        pkt[32] = 0x50;
        pkt[33] = 0x14;
        let c = ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        let c2 = tcp_checksum(key.dst_ip, key.src_ip, &pkt[20..]);
        pkt[36..38].copy_from_slice(&c2.to_be_bytes());
        pkt
    }

    fn handle_tcp_terminated(&mut self, packet: &[u8], classification: &Classification) {
        let peer = match classification {
            Classification::Mesh { path: Some(p), .. } => p.to_string(),
            Classification::Mesh { path: None, .. } => ipv4_dst_of(packet)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            Classification::Proxy { .. } => "proxy".to_string(),
            // S8：调用方已过滤 Direct/Drop；防御性返回。
            _ => return,
        };
        let tun_pkts = self.tcp.handle_uplink(packet, &peer);
        self.write_tun_packets(tun_pkts);
    }

    /// S2/S7：TUN 包批量写回；写失败计数 `dropped`（不 panic）。
    ///
    /// GAP-5：TCP 终结器产出的包先经 `fixup_tun_packet` 将源 IP 从
    /// `SMOLTCP_IFACE_IP` 改回原始目的（真实 TUN 需要；MockTun 同样受益）。
    /// 无法匹配连接的包 → 计数 `dropped`，不写 TUN。
    fn write_tun_packets(&mut self, pkts: Vec<Vec<u8>>) {
        let mut written = 0u64;
        for pkt in &pkts {
            match self.tcp.fixup_tun_packet(pkt) {
                Some(fixed) => {
                    if self.tun.write(&fixed).is_err() {
                        self.with_stats(|s| s.dropped += 1);
                    } else {
                        written += 1;
                    }
                }
                None => {
                    self.with_stats(|s| s.dropped += 1);
                }
            }
        }
        if written > 0 {
            self.with_stats(|s| s.tun_written += written);
        }
    }

    /// S3–S7：收获终结器事件并按分类分发。
    fn dispatch_tcp_events(&mut self) {
        let events = self.tcp.poll();
        for ev in events {
            match ev {
                TcpEvent::Syn {
                    stream_id,
                    dst,
                    peer,
                } => {
                    let proxy = peer == "proxy";
                    self.tcp_streams
                        .insert(stream_id, TcpStreamInfo { dst, proxy });
                    // Phase B：绑定 §10 Session（SYN 包建会话时已记入 flow_pending）。
                    if let Some(four) = self.tcp.lookup_id(stream_id) {
                        if let Some(session_id) = self.flow_pending.remove(&four) {
                            let key = FlowKey {
                                src_ip: four.src_ip,
                                src_port: four.src_port,
                                dst_ip: four.dst_ip,
                                dst_port: four.dst_port,
                                proto: IpProto::Tcp,
                            };
                            self.flow_tcp_streams.insert(stream_id, session_id);
                            self.flow_key_to_stream.insert(key, stream_id);
                            self.flow_stream_to_key.insert(stream_id, key);
                        }
                    }
                    self.with_stats(|s| s.tcp_handshakes += 1);
                    if proxy {
                        // S4-Proxy：GAP-1 前只计数。
                        self.with_stats(|s| s.proxy_tcp_streams += 1);
                    } else {
                        // S4-Mesh：STREAM SYN 帧经 N1 发送（按原始目的路由）。
                        let payload = encode_syn_payload(&dst.ip().to_string(), dst.port());
                        let frame = encode_stream_frame(stream_id, STREAM_SYN, &payload);
                        self.send_mesh_tcp_frame(*dst.ip(), &frame);
                    }
                }
                TcpEvent::Data {
                    stream_id,
                    peer: _,
                    bytes,
                } => {
                    // Phase B：会话 Allocating 期，上行数据缓冲（Active 后 flush，D4）。
                    if self.flow_should_buffer_data(stream_id) {
                        self.flow_pending_data
                            .entry(stream_id)
                            .or_default()
                            .push(bytes);
                    } else {
                        self.forward_tcp_data(stream_id, &bytes);
                    }
                }
                TcpEvent::Closed {
                    stream_id,
                    peer: _,
                    reset,
                } => {
                    let info = self.tcp_streams.remove(&stream_id);
                    // Phase B：解绑 §10 Session 映射。
                    if let Some(session_id) = self.flow_tcp_streams.remove(&stream_id) {
                        let _ = session_id;
                        self.flow_key_to_stream.retain(|_, sid| *sid != stream_id);
                        self.flow_stream_to_key.remove(&stream_id);
                        self.flow_pending_data.remove(&stream_id);
                    }
                    if let Some(info) = info {
                        if !info.proxy {
                            // S6-Mesh：STREAM FIN/RST 帧经 N1 发送。
                            let flag = if reset { STREAM_RST } else { STREAM_FIN };
                            let frame = encode_stream_frame(stream_id, flag, &[]);
                            self.send_mesh_tcp_frame(*info.dst.ip(), &frame);
                        }
                        // S6-Proxy：S4 已计流数，无额外动作。
                    }
                }
                TcpEvent::TunPacket(pkt) => {
                    self.write_tun_packets(vec![pkt]);
                }
            }
        }
    }

    /// S4/S5/S6-Mesh：STREAM 帧经 N1 发送；返回是否成功。
    ///
    /// 成功 → `mesh_tcp_frames += 1`；失败（无 sender/无路由/发送错）→
    /// `mesh_dropped_no_n1 += 1`（W1 语义复用）。
    fn send_mesh_tcp_frame(&mut self, dst: Ipv4Addr, frame: &[u8]) -> bool {
        let sent = match &self.n1_sender {
            Some(sender) => sender.send_to_mesh(dst, frame).is_ok(),
            None => false,
        };
        if sent {
            self.with_stats(|s| s.mesh_tcp_frames += 1);
        } else {
            self.with_stats(|s| s.mesh_dropped_no_n1 += 1);
        }
        sent
    }

    /// S9：N1 下行的 STREAM 帧注入终结器（fabric → app 方向）。
    ///
    /// 解码失败 → 计数 `dropped`；产生的 TUN 包写回 TUN（S2 规则）。
    /// `inject_from_n1` 的 raw 语义不变。
    pub fn inject_stream_frame_from_n1(&mut self, peer: &str, frame: &[u8]) {
        let (stream_id, flags, payload) = match decode_stream_frame(frame) {
            Some(t) => t,
            None => {
                self.with_stats(|s| s.dropped += 1);
                return;
            }
        };
        let tun_pkts = self.tcp.handle_originator_frame(stream_id, flags, payload);
        let _ = peer;
        self.write_tun_packets(tun_pkts);
    }

    /// S10：终结器内部统计快照（S21–S23 可观测）。
    #[must_use]
    pub fn tcp_term_stats(&self) -> TcpTermStats {
        self.tcp.stats()
    }

    /// 处理 DNS 查询包：解析 → 构造响应 → 写回 TUN。
    fn handle_dns(&mut self, packet: &[u8]) {
        let dns = match self.dns.as_mut() {
            Some(d) => d,
            None => return,
        };
        // 解析 DNS 查询名（最小解析器）。
        let (query_name, query_id) = match parse_dns_query(packet) {
            Some((name, id)) => (name, id),
            None => {
                self.with_stats(|s| s.dropped += 1);
                return;
            }
        };
        // 调用 UnifiedDns。
        let query = DnsQuery {
            name: query_name.clone(),
            qtype: DnsType::A,
        };
        let now_secs = 0; // MVP：零时钟
        match dns.resolve(&query, now_secs) {
            Ok(answer) => {
                // 取第一个 IPv4 记录的 IP。
                if let Some(ip) = answer.records.iter().find_map(|r| match r {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                }) {
                    if let Some(response) = build_dns_response(packet, query_id, &query_name, ip) {
                        self.record_dns_answer(&query_name, ip);
                        if self.tun.write(&response).is_ok() {
                            self.with_stats(|s| {
                                s.dns_answered += 1;
                                s.tun_written += 1;
                            });
                        }
                    }
                }
            }
            Err(_) => {
                self.with_stats(|s| s.dropped += 1);
            }
        }
    }

    /// 获取统计快照（D6 可观测）。
    #[must_use]
    pub fn stats(&self) -> DataplaneStats {
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// QoS 是否旁路（D4 可观测：禁用时为 true）。
    #[must_use]
    pub fn qos_bypassed(&self) -> bool {
        self.qos.is_none()
    }

    /// W2：将 N1 收到的包写回 TUN（下行路径；由 N1 接收线程调用）。
    ///
    /// 写失败 → 计数 `dropped`（不 panic）。
    pub fn inject_from_n1(&mut self, packet: &[u8]) {
        if self.tun.write(packet).is_ok() {
            self.with_stats(|s| s.tun_written += 1);
        } else {
            self.with_stats(|s| s.dropped += 1);
        }
    }

    /// N1 发送器是否已注入（W1 可观测）。
    #[must_use]
    pub fn n1_bridge_ready(&self) -> bool {
        self.n1_sender.is_some()
    }
}

/// 解析 CIDR 字符串（如 "10.0.0.0/8"）为 `Cidr`。
fn parse_cidr(s: &str) -> Result<Cidr, String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR: {s}"));
    }
    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("invalid CIDR IP: {s}"))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| format!("invalid CIDR prefix: {s}"))?;
    let bits = u32::from(ip);
    Cidr::new(bits, prefix).ok_or_else(|| format!("invalid CIDR {s}"))
}

/// 从 IPv4 包提取目的地址。
fn ipv4_dst_of(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// 判断是否为 TCP 包（IPv4 + proto 6；S1 终结范围判定）。
fn is_tcp_packet(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4 && packet[9] == 6
}

/// Phase B：是否为 TCP SYN 包（新流触发首包链）。
fn is_tcp_syn(packet: &[u8]) -> bool {
    if !is_tcp_packet(packet) {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if packet.len() < ihl + 14 {
        return false;
    }
    let flags = packet[ihl + 13];
    // SYN 置位且 ACK 未置位（不把重传/握手中的包当新流）。
    flags & 0x02 != 0 && flags & 0x10 == 0
}

/// Phase C：是否为 UDP 包。
fn is_udp_packet(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4 && packet[9] == 17
}

/// 判断是否为 DNS 查询（IPv4 + UDP + 目的端口 53）。
fn is_dns_query(packet: &[u8]) -> bool {
    if packet.len() < 28 {
        return false;
    }
    // IPv4 头：版本 4，协议 UDP (17)。
    if packet[0] >> 4 != 4 || packet[9] != 17 {
        return false;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 8 {
        return false;
    }
    // UDP 目的端口（偏移 ihl+2）。
    let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    dport == 53
}

/// 从 IP 包提取 5 元组（用于 QoS）。
fn five_tuple_of(packet: &[u8]) -> Option<FiveTuple> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let proto = packet[9];
    let src = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let (sport, dport) = if (proto == 6 || proto == 17) && packet.len() >= ihl + 4 {
        (
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        )
    } else {
        (0, 0)
    };
    Some(FiveTuple {
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
    })
}

/// 最小 DNS 查询解析：返回 (查询名, 事务 ID)。
///
/// B2 修复：严格校验 QTYPE/QCLASS 存在，截断包返回 None（不 panic）。
fn parse_dns_query(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < 28 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let udp_start = ihl;
    let dns_start = udp_start + 8;
    if packet.len() < dns_start + 12 {
        return None;
    }
    let dns = &packet[dns_start..];
    let txid = u16::from_be_bytes([dns[0], dns[1]]);
    // 解析 QNAME（标签序列）。
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= dns.len() {
            return None;
        }
        let len = dns[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // 不支持压缩指针（查询包不应有）
        }
        pos += 1;
        if pos + len > dns.len() {
            return None;
        }
        let label = std::str::from_utf8(&dns[pos..pos + len]).ok()?;
        labels.push(label.to_string());
        pos += len;
    }
    if labels.is_empty() {
        return None;
    }
    // B2：校验 QTYPE(2) + QCLASS(2) 存在。
    if pos + 4 > dns.len() {
        return None;
    }
    Some((labels.join("."), txid))
}

/// 构造最小 DNS 响应包（IP 头 + UDP 头 + DNS 响应）。
fn build_dns_response(
    query_packet: &[u8],
    txid: u16,
    qname: &str,
    answer_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    if query_packet.len() < 28 {
        return None;
    }
    let ihl = ((query_packet[0] & 0x0F) as usize) * 4;
    let udp_start = ihl;
    let dns_start = udp_start + 8;

    // 交换 IP 源/目。
    let src_ip = Ipv4Addr::new(
        query_packet[12],
        query_packet[13],
        query_packet[14],
        query_packet[15],
    );
    let dst_ip = Ipv4Addr::new(
        query_packet[16],
        query_packet[17],
        query_packet[18],
        query_packet[19],
    );
    let src_port = u16::from_be_bytes([query_packet[udp_start], query_packet[udp_start + 1]]);
    let _dst_port = u16::from_be_bytes([query_packet[udp_start + 2], query_packet[udp_start + 3]]);

    // DNS 响应体。
    let mut dns_resp = Vec::new();
    dns_resp.extend_from_slice(&txid.to_be_bytes()); // ID
    dns_resp.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1
    dns_resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    dns_resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    dns_resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    dns_resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    // Question（复制原查询的 QNAME+QTYPE+QCLASS）。
    // B2：边界校验，防止截断包导致切片越界 panic。
    let qname_end = find_qname_end(&query_packet[dns_start..])?;
    let q_section_len = qname_end + 4; // QNAME + QTYPE(2) + QCLASS(2)
    if dns_start + q_section_len > query_packet.len() {
        return None;
    }
    dns_resp.extend_from_slice(&query_packet[dns_start..dns_start + q_section_len]);
    // Answer：NAME(指针), TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4, RDATA=IP。
    dns_resp.extend_from_slice(&[0xC0, 0x0C]); // 指向 QNAME 的压缩指针
    dns_resp.extend_from_slice(&[0x00, 0x01]); // TYPE=A
    dns_resp.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
    dns_resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL=300
    dns_resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
    dns_resp.extend_from_slice(&answer_ip.octets());
    let _ = qname;

    // UDP 头。
    let udp_len = 8 + dns_resp.len();
    let mut udp_hdr = Vec::new();
    udp_hdr.extend_from_slice(&53u16.to_be_bytes()); // 源端口 53
    udp_hdr.extend_from_slice(&src_port.to_be_bytes()); // 目的端口（原源端口）
    udp_hdr.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp_hdr.extend_from_slice(&[0x00, 0x00]); // 校验和（MVP 置零）

    // IP 头。
    let total_len = 20 + udp_len;
    let mut ip_hdr = vec![0u8; 20];
    ip_hdr[0] = 0x45; // 版本 4，IHL 5
    ip_hdr[1] = 0x00; // DSCP
    ip_hdr[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip_hdr[4..6].copy_from_slice(&[0x00, 0x00]); // ID
    ip_hdr[6..8].copy_from_slice(&[0x40, 0x00]); // Flags=DF
    ip_hdr[8] = 64; // TTL
    ip_hdr[9] = 17; // 协议 UDP
    // 源 = 原目的（DNS 服务器），目的 = 原源（客户端）。
    ip_hdr[12..16].copy_from_slice(&dst_ip.octets());
    ip_hdr[16..20].copy_from_slice(&src_ip.octets());
    // IP 校验和。
    let checksum = ip_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&ip_hdr);
    packet.extend_from_slice(&udp_hdr);
    packet.extend_from_slice(&dns_resp);
    Some(packet)
}

/// 找到 DNS 查询包中 QNAME 的结束偏移（相对于 DNS 起始）。
fn find_qname_end(dns: &[u8]) -> Option<usize> {
    let mut pos = 12;
    while pos < dns.len() {
        let len = dns[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
    }
    None
}

/// IP 头校验和。
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ===== B1：全局 stats 句柄（供 LocalAPI 线程读取） =====

/// 全局数据面统计句柄（dataplane 线程发布，LocalAPI 线程读取）。
static STATS_HANDLE: OnceLock<Arc<Mutex<DataplaneStats>>> = OnceLock::new();

/// 发布 stats 句柄（由 dataplane 线程在启动时调用一次）。
pub fn publish_stats_handle(handle: Arc<Mutex<DataplaneStats>>) {
    let _ = STATS_HANDLE.set(handle);
}

/// 获取已发布的 stats 快照（LocalAPI 用；未发布时返回默认零值）。
#[must_use]
pub fn dataplane_stats_snapshot() -> DataplaneStats {
    STATS_HANDLE
        .get()
        .and_then(|h| h.lock().ok())
        .map(|s| s.clone())
        .unwrap_or_default()
}

// ===== 运行期状态（LocalAPI §9.16） =====

/// 运行期状态快照（takeover / flow_sessions / os_assemble）。
#[derive(Debug, Clone, Default)]
pub struct RuntimeStatus {
    /// `system-level` / `resource-level`。
    pub takeover_mode: String,
    /// `ipv4`。
    pub ingress_ip_family: String,
    /// 流会话状态。
    pub flow_sessions: FlowSessionsState,
    /// OS 装配状态。
    pub os_assemble: OsAssembleStatus,
}

/// OS 装配可见状态。
#[derive(Debug, Clone, Default)]
pub struct OsAssembleStatus {
    /// `applied` / `failed` / `skipped`。
    pub state: &'static str,
    /// 接口名。
    pub ifname: String,
    /// 是否安装默认路由。
    pub default_route: bool,
    /// 排除路由数。
    pub excludes: u32,
}

static RUNTIME_STATUS: OnceLock<Mutex<RuntimeStatus>> = OnceLock::new();

fn runtime_slot() -> &'static Mutex<RuntimeStatus> {
    RUNTIME_STATUS.get_or_init(|| Mutex::new(RuntimeStatus::default()))
}

/// 发布 takeover/ingress 基本信息。
pub fn publish_runtime_basics(takeover_mode: &str, ingress_ip_family: &str) {
    if let Ok(mut status) = runtime_slot().lock() {
        status.takeover_mode = takeover_mode.to_string();
        status.ingress_ip_family = ingress_ip_family.to_string();
    }
}

/// 发布流会话状态。
pub fn publish_flow_sessions(state: FlowSessionsState) {
    if let Ok(mut status) = runtime_slot().lock() {
        status.flow_sessions = state;
    }
}

/// 发布 OS 装配状态。
pub fn publish_os_assemble(status: OsAssembleStatus) {
    if let Ok(mut guard) = runtime_slot().lock() {
        guard.os_assemble = status;
    }
}

/// 运行期状态快照。
pub fn runtime_status_snapshot() -> RuntimeStatus {
    runtime_slot().lock().map(|s| s.clone()).unwrap_or_default()
}

/// 构造 `/localapi/v0/dataplane/stats` 的 JSON（纯函数，便于单测）。
pub fn dataplane_stats_json(
    tun_enabled: bool,
    status: &RuntimeStatus,
    stats: &DataplaneStats,
    tproxy: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "verdict": "PASS",
        "tun_enabled": tun_enabled,
        "takeover_mode": status.takeover_mode,
        "ingress_ip_family": status.ingress_ip_family,
        "dataplane": {
            "mesh_forwarded": stats.mesh_forwarded,
            "proxy_forwarded": stats.proxy_forwarded,
            "direct_forwarded": stats.direct_forwarded,
            "direct_dropped_unsupported": stats.direct_dropped_unsupported,
            "dropped": stats.dropped,
            "dns_answered": stats.dns_answered,
            "qos_dropped": stats.qos_dropped,
            "mesh_dropped_no_n1": stats.mesh_dropped_no_n1,
            "proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
            "flow_sessions": {
                "state": status.flow_sessions.state,
                "reason": status.flow_sessions.reason,
                "providers": status.flow_sessions.providers,
                "planner_calls": 0,
            },
            "os_assemble": {
                "state": status.os_assemble.state,
                "ifname": status.os_assemble.ifname,
                "default_route": status.os_assemble.default_route,
                "excludes": status.os_assemble.excludes,
            },
        },
        "tproxy": tproxy,
    })
}

// ===== Stub 实现（MVP：E4 可测；真实解析器由子系统接入） =====

struct StubUpstreamResolver;
impl nexus_dns::Resolver for StubUpstreamResolver {
    fn resolve(&mut self, _query: &DnsQuery) -> Result<Vec<IpAddr>, nexus_dns::DnsError> {
        Err(nexus_dns::DnsError::ResolutionFailed(
            "stub upstream not configured".to_string(),
        ))
    }
}

// ===== 全局 stats 句柄结束 =====

struct StubMeshResolver;
impl nexus_dns::MeshNameResolver for StubMeshResolver {
    fn resolve_mesh(&self, _name: &str) -> Option<IpAddr> {
        None
    }
}

struct StubProxyClassifier;
impl nexus_dns::ProxyClassifier for StubProxyClassifier {
    fn is_proxied(&self, _domain: &str) -> bool {
        true // MVP：默认走 proxy（触发 fake-IP）
    }
}
/// 分类结果携带的规则出站 tag（Q3 `egress_hint`）。
fn egress_hint(classification: &Classification) -> Option<&str> {
    match classification {
        Classification::Proxy { outbound } => Some(outbound.as_str()),
        _ => None,
    }
}

/// 无代理配置时的默认规则实现（spec §5 G2/D2.3）。
fn default_simple_engine() -> Result<SimpleRuleEngine, String> {
    let cidr = "0.0.0.0/0"
        .parse()
        .map_err(|e| format!("compat rule CIDR: {e}"))?;
    Ok(SimpleRuleEngine::new(vec![Rule {
        cidr,
        target: nexus_domain::RouteTarget::Egress {
            peer: "proxy".to_string(),
        },
    }]))
}

fn classification_from_target(target: &nexus_domain::RouteTarget) -> Classification {
    match target {
        nexus_domain::RouteTarget::Egress { peer } if peer == "self" => Classification::Direct,
        nexus_domain::RouteTarget::Egress { peer } => Classification::Proxy {
            outbound: peer.clone(),
        },
        nexus_domain::RouteTarget::Drop => Classification::Drop {
            reason: DropReason::RuleRejected,
        },
        nexus_domain::RouteTarget::MeshPeer { .. } => Classification::Mesh {
            path: None,
            degraded: false,
        },
    }
}

fn decision_from_classification(
    classification: &Classification,
    now_millis: u64,
) -> CachedDecision {
    let (target, selected_outbound) = match classification {
        Classification::Mesh { .. } => (
            nexus_domain::RouteTarget::MeshPeer {
                peer: "mesh".to_string(),
            },
            "mesh".to_string(),
        ),
        Classification::Proxy { outbound } => (
            nexus_domain::RouteTarget::Egress {
                peer: outbound.clone(),
            },
            outbound.clone(),
        ),
        Classification::Direct => (
            nexus_domain::RouteTarget::Egress {
                peer: "self".to_string(),
            },
            "self".to_string(),
        ),
        Classification::Drop { .. } => (nexus_domain::RouteTarget::Drop, "drop".to_string()),
    };
    CachedDecision {
        target,
        matched_rule: String::new(),
        selected_outbound,
        last_seen_millis: now_millis,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_projection::tcp::{ip_checksum, tcp_checksum};
    use std::collections::VecDeque;

    /// 共享 MockTun：dataplane 拥有所有权，测试经 Arc 观察写入。
    struct SharedTun {
        inner: Arc<Mutex<nexus_projection::MockTun>>,
    }

    impl TunDevice for SharedTun {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.lock().unwrap().read(buf)
        }
        fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
            self.inner.lock().unwrap().write(packet)
        }
        fn name(&self) -> &str {
            "test0"
        }
    }

    /// 测试用 N1Sender：捕获发往 mesh 的帧（S4/S5/S6 验证用）。
    #[allow(dead_code)]
    struct TestN1Sender {
        frames: CapturedFrames,
    }

    /// N1Sender 捕获的帧：(目的 IP, STREAM 帧字节)。
    type CapturedFrames = Arc<Mutex<Vec<(Ipv4Addr, Vec<u8>)>>>;

    impl N1Sender for TestN1Sender {
        fn send_to_mesh(
            &self,
            dst: Ipv4Addr,
            packet: &[u8],
        ) -> Result<(), nexus_network::n1::N1Error> {
            self.frames.lock().unwrap().push((dst, packet.to_vec()));
            Ok(())
        }
    }

    /// 构造最小 IPv4/TCP 包（校验和正确）。
    #[allow(clippy::too_many_arguments)]
    fn craft_tcp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 20 + payload.len()];
        pkt[0] = 0x45;
        let tot = (20 + 20 + payload.len()) as u16;
        pkt[2..4].copy_from_slice(&tot.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        let c = ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        let t = &mut pkt[20..40];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t[14..16].copy_from_slice(&8192u16.to_be_bytes());
        pkt[40..].copy_from_slice(payload);
        let tc = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
        pkt[36..38].copy_from_slice(&tc.to_be_bytes());
        pkt
    }

    /// 构造最小 IPv4/UDP 包（端口/地址可辨；校验和本层不校验）。
    fn craft_udp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        let tot = (20 + 8 + payload.len()) as u16;
        pkt[2..4].copy_from_slice(&tot.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    fn test_dataplane() -> (Dataplane, Arc<Mutex<nexus_projection::MockTun>>) {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            n1_configured: true,
            ..Default::default()
        };
        let dp = Dataplane::new(tun, config).expect("dataplane new");
        (dp, mock)
    }

    /// Red Evidence（S1/S2）：Mesh 分类的 TCP SYN 应被终结并回 SYN-ACK。
    /// 实现前：dataplane 只计数，不写回 TUN → 此测试 FAIL。
    #[test]
    fn red_tcp_syn_mesh_gets_syn_ack() {
        let (mut dp, mock) = test_dataplane();
        let syn = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("process_one"));
        let written: VecDeque<Vec<u8>> = mock.lock().unwrap().take_written().into_iter().collect();
        assert!(
            !written.is_empty(),
            "RED: expected SYN-ACK written to TUN (S1/S2), got none"
        );
        // 首包应为 SYN-ACK（源/目端口交换，flags SYN|ACK）。
        let reply = &written[0];
        assert!(reply.len() >= 40, "reply too short");
        let flags = reply[20 + 13];
        assert_eq!(
            flags & 0x12,
            0x12,
            "RED: expected SYN+ACK flags, got {:#x}",
            flags
        );
    }

    /// 从 SYN-ACK 包中提取 server seq（IP 包偏移 24）。
    fn syn_ack_srv_seq(syn_ack: &[u8]) -> u32 {
        u32::from_be_bytes([syn_ack[24], syn_ack[25], syn_ack[26], syn_ack[27]])
    }

    fn mesh_dataplane_with_sender() -> (
        Dataplane,
        Arc<Mutex<nexus_projection::MockTun>>,
        CapturedFrames,
    ) {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            n1_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        let frames = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_sender(Arc::new(TestN1Sender {
            frames: Arc::clone(&frames),
        }));
        (dp, mock, frames)
    }

    /// S3/S4 全流程：SYN→SYN-ACK→ACK→握手→STREAM SYN 帧被 N1Sender 捕获。
    #[test]
    fn tcp_full_flow_mesh_stream_frames() {
        use nexus_projection::tcp::{STREAM_FIN, STREAM_SYN, decode_stream_frame};
        let (mut dp, mock, frames) = mesh_dataplane_with_sender();

        // 1. SYN → SYN-ACK。
        let syn = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("process_one syn"));
        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 1, "expected exactly SYN-ACK");
        let srv_seq = syn_ack_srv_seq(&written[0]);

        // 2. ACK → 握手完成 → Syn 事件 → STREAM SYN 帧。
        let ack = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1001,
            srv_seq + 1,
            0x10,
            &[],
        );
        mock.lock().unwrap().inject(ack);
        assert!(dp.process_one().expect("process_one ack"));
        assert_eq!(dp.stats().tcp_handshakes, 1, "S4: handshake counted");
        let captured = frames.lock().unwrap();
        assert_eq!(captured.len(), 1, "S4: one STREAM SYN frame sent");
        let (dst, frame) = &captured[0];
        assert_eq!(*dst, Ipv4Addr::new(10, 200, 0, 5));
        let (sid, flags, _payload) = decode_stream_frame(frame).expect("decode");
        assert_eq!(flags, STREAM_SYN, "S4: SYN flag");
        assert_eq!(dp.stats().mesh_tcp_frames, 1);
        drop(captured);

        // 3. DATA → STREAM DATA 帧。
        let data = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1001,
            srv_seq + 1,
            0x18,
            b"hello",
        );
        mock.lock().unwrap().inject(data);
        assert!(dp.process_one().expect("process_one data"));
        assert_eq!(dp.stats().mesh_tcp_bytes, 5, "S5: 5 bytes");
        assert_eq!(dp.stats().mesh_tcp_frames, 2, "S5: SYN+DATA frames");

        // 4. FIN → STREAM FIN 帧；流记录删除。
        let fin = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1006,
            srv_seq + 1,
            0x11,
            &[],
        );
        mock.lock().unwrap().inject(fin);
        assert!(dp.process_one().expect("process_one fin"));
        let captured2 = frames.lock().unwrap();
        let (_, last_frame) = captured2.last().expect("fin frame");
        let (_, flags, _) = decode_stream_frame(last_frame).expect("decode fin");
        assert_eq!(flags, STREAM_FIN, "S6: FIN flag");
        assert!(dp.tcp_streams.is_empty(), "S6: stream record removed");
        // 终结器内部统计也可观测（S10）。
        assert_eq!(dp.tcp_term_stats().handshake_done, 1);
        let _ = sid;
    }

    /// S4/S5-Proxy：Proxy 分类的 TCP 只计数，不经 N1（GAP-1 诚实边界）。
    #[test]
    fn tcp_proxy_classified_only_counted() {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        // 8.8.8.8：不在 mesh CIDR、不在 bypass → Proxy。
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            bypass_cidrs: vec!["192.168.0.0/16".to_string()],
            n1_configured: true,
            proxy_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        let frames = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_sender(Arc::new(TestN1Sender {
            frames: Arc::clone(&frames),
        }));

        // S26：Proxy TCP 由 ProxyEngine 终结/中继；未注入 engine → 计数降级，
        // 不再走 Dataplane 的 Mesh 终结器（§9.10.1 归属）。
        let syn = craft_tcp([10, 0, 0, 2], [8, 8, 8, 8], 40001, 443, 2000, 0, 0x02, &[]);
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("syn"));
        assert!(
            mock.lock().unwrap().take_written().is_empty(),
            "S26: Dataplane terminator no longer owns Proxy TCP"
        );
        assert_eq!(dp.stats().tcp_handshakes, 0);
        assert_eq!(dp.stats().proxy_dropped_no_proxy, 1);
        assert!(frames.lock().unwrap().is_empty(), "Proxy must not use N1");
    }

    /// S9：下行 STREAM 帧注入 → terminator → TUN 包。
    #[test]
    fn inject_stream_frame_downlink() {
        use nexus_projection::tcp::encode_stream_frame;
        let (mut dp, mock, _frames) = mesh_dataplane_with_sender();

        // 先建流（SYN→SYN-ACK→ACK）。
        let syn = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("syn"));
        let written = mock.lock().unwrap().take_written();
        let srv_seq = syn_ack_srv_seq(&written[0]);
        let ack = craft_tcp(
            [10, 200, 0, 2],
            [10, 200, 0, 5],
            40000,
            80,
            1001,
            srv_seq + 1,
            0x10,
            &[],
        );
        mock.lock().unwrap().inject(ack);
        assert!(dp.process_one().expect("ack"));
        assert_eq!(dp.stats().tcp_handshakes, 1);
        let _ = mock.lock().unwrap().take_written();

        // 下行 DATA 帧（fabric → app）→ TUN 应有数据包。
        let sid = *dp.tcp_streams.keys().next().expect("stream");
        let frame = encode_stream_frame(sid, 0x00, b"reply");
        let before = dp.stats().tun_written;
        dp.inject_stream_frame_from_n1("10.200.0.5:0", &frame);
        assert!(
            dp.stats().tun_written > before,
            "S9: downlink frame produced TUN packet"
        );
        let written = mock.lock().unwrap().take_written();
        assert!(!written.is_empty(), "S9: TUN packet present");
        // 包应发往 app（目的 = 10.200.0.2）。
        assert_eq!(&written[0][16..20], &[10, 200, 0, 2]);

        // 非法帧 → dropped 计数，不 panic。
        let dropped_before = dp.stats().dropped;
        dp.inject_stream_frame_from_n1("x", &[0x00, 0x01]);
        assert_eq!(dp.stats().dropped, dropped_before + 1);
    }

    /// S30：LocalAPI stats 字段与 takeover_mode 语义。
    #[test]
    fn localapi_stats_fields_and_takeover_mode() {
        let status = RuntimeStatus {
            takeover_mode: "system-level".to_string(),
            ingress_ip_family: "ipv4".to_string(),
            flow_sessions: FlowSessionsState {
                state: "enabled",
                reason: None,
                providers: 2,
            },
            os_assemble: OsAssembleStatus {
                state: "applied",
                ifname: "nexus0".to_string(),
                default_route: true,
                excludes: 1,
            },
        };
        let stats = DataplaneStats {
            direct_dropped_unsupported: 3,
            ..Default::default()
        };
        let json = dataplane_stats_json(
            true,
            &status,
            &stats,
            serde_json::json!({"state": "active"}),
        );
        assert_eq!(json["takeover_mode"], "system-level");
        assert_eq!(json["ingress_ip_family"], "ipv4");
        assert_eq!(json["dataplane"]["direct_dropped_unsupported"], 3);
        assert_eq!(json["dataplane"]["flow_sessions"]["state"], "enabled");
        assert_eq!(json["dataplane"]["flow_sessions"]["providers"], 2);
        assert_eq!(json["dataplane"]["os_assemble"]["state"], "applied");
        assert_eq!(json["dataplane"]["os_assemble"]["excludes"], 1);
        assert!(json.get("providers").is_none(), "no provider list exposed");

        // 仅 socks5 → resource-level（由组合根判定；此处验证空状态默认）。
        let default_status = RuntimeStatus::default();
        let json = dataplane_stats_json(
            false,
            &default_status,
            &DataplaneStats::default(),
            serde_json::Value::Null,
        );
        assert_eq!(json["takeover_mode"], "");
    }

    /// S29：DNS 应答后同 IP 新流命中 DOMAIN-SUFFIX；无缓存计 domain_miss。
    #[test]
    fn dns_cache_domain_suffix_and_miss() {
        use nexus_domain::RouteTarget;
        use nexus_projection::egress::{Rule, SimpleRuleEngine};

        let (mut dp, mock) = test_dataplane();
        let mut engine = SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().unwrap(),
            target: RouteTarget::Egress {
                peer: "p2".to_string(),
            },
        }]);
        engine.add_domain_suffix_rule(
            "example.com",
            RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        );
        dp.set_rule_engine(Box::new(engine));

        dp.record_dns_answer("api.example.com", Ipv4Addr::new(203, 0, 113, 7));
        let pkt = craft_udp([192, 168, 1, 5], [203, 0, 113, 7], 40_000, 443, b"z");
        mock.lock().unwrap().inject(pkt.clone());
        assert!(dp.process_one().expect("packet"));
        assert_eq!(dp.cached_outbound(&pkt).as_deref(), Some("p1"));
        assert_eq!(dp.stats().domain_miss, 0);

        // 无缓存：IP 规则命中，domain_miss 增加。
        let fresh = craft_udp([192, 168, 1, 5], [203, 0, 113, 8], 40_001, 443, b"z");
        mock.lock().unwrap().inject(fresh.clone());
        assert!(dp.process_one().expect("fresh packet"));
        assert_eq!(dp.cached_outbound(&fresh).as_deref(), Some("p2"));
        assert_eq!(dp.stats().domain_miss, 1);
    }

    /// S27：Direct UDP 真实往返 + ICMP 不支持计数。
    #[test]
    fn direct_forwarding_udp_and_unsupported() {
        use std::net::UdpSocket;

        let server = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let server_addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = server.recv_from(&mut buf) {
                let _ = server.send_to(&buf[..n], from);
            }
        });

        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            bypass_cidrs: vec!["127.0.0.0/8".to_string()],
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        let dst = match server_addr {
            std::net::SocketAddr::V4(v4) => [
                v4.ip().octets()[0],
                v4.ip().octets()[1],
                v4.ip().octets()[2],
                v4.ip().octets()[3],
            ],
            std::net::SocketAddr::V6(_) => panic!("v4"),
        };
        let port = server_addr.port();
        let pkt = craft_udp([10, 0, 0, 2], dst, 40000, port, b"echo");
        mock.lock().unwrap().inject(pkt);
        assert!(dp.process_one().expect("udp"));
        assert_eq!(dp.stats().direct_udp_sent, 1);
        assert_eq!(dp.stats().direct_forwarded, 1);

        let mut replied = 0;
        for _ in 0..2_000 {
            replied += dp.drain_direct_replies();
            if replied > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(replied, 1, "Direct UDP reply must be written back to TUN");
        assert_eq!(dp.stats().direct_dropped_unsupported, 0);
        handle.join().unwrap();

        // ICMP（proto=1）→ 不支持，direct_forwarded 不增。
        let before = dp.stats().direct_forwarded;
        let mut icmp = craft_udp([10, 0, 0, 2], dst, 0, 0, &[]);
        icmp[9] = 1;
        mock.lock().unwrap().inject(icmp);
        assert!(dp.process_one().expect("icmp"));
        assert_eq!(dp.stats().direct_dropped_unsupported, 1);
        assert_eq!(
            dp.stats().direct_forwarded,
            before,
            "unsupported must not count as forwarded"
        );
    }

    /// S25：enabled / auto+provider / auto-no-provider / disabled 四分支。
    #[test]
    fn flow_sessions_auto_branches() {
        let (mut dp, _mock) = test_dataplane();
        assert!(dp.enable_flow_sessions_for_config(FlowSessionsMode::Auto, 1));
        assert_eq!(dp.flow_sessions_state().state, "enabled");
        assert!(dp.flow_sessions_state().reason.is_none());

        let (mut dp, _mock) = test_dataplane();
        assert!(!dp.enable_flow_sessions_for_config(FlowSessionsMode::Auto, 0));
        assert_eq!(dp.flow_sessions_state().state, "disabled");
        assert_eq!(dp.flow_sessions_state().reason, Some("no_providers"));

        let (mut dp, _mock) = test_dataplane();
        assert!(dp.enable_flow_sessions_for_config(FlowSessionsMode::Enabled, 0));
        assert_eq!(dp.flow_sessions_state().state, "enabled");

        let (mut dp, _mock) = test_dataplane();
        assert!(!dp.enable_flow_sessions_for_config(FlowSessionsMode::Disabled, 3));
        assert_eq!(dp.flow_sessions_state().state, "disabled");
        assert!(dp.flow_sessions_state().reason.is_none());
        assert_eq!(dp.flow_sessions_state().providers, 3);
    }

    /// S24：同 5 元组第二包命中决策缓存，规则引擎调用次数不增。
    #[test]
    fn dataplane_decision_cache_hits_skip_rule_engine() {
        use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};
        use std::sync::atomic::AtomicUsize;

        struct Counting(Arc<AtomicUsize>);
        impl RuleEngine for Counting {
            fn decide(&self, _req: &RouteRequest<'_>) -> RouteTarget {
                self.0.fetch_add(1, Ordering::SeqCst);
                RouteTarget::Egress {
                    peer: "p1".to_string(),
                }
            }
        }

        let (mut dp, mock) = test_dataplane();
        let calls = Arc::new(AtomicUsize::new(0));
        dp.set_rule_engine(Box::new(Counting(Arc::clone(&calls))));

        let pkt = craft_udp([192, 168, 1, 5], [8, 8, 8, 8], 40_000, 443, b"x");
        mock.lock().unwrap().inject(pkt.clone());
        assert!(dp.process_one().expect("first packet"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(dp.decision_cache_stats().misses, 1);

        // 同 5 元组第二包：缓存命中，不再调用规则引擎。
        mock.lock().unwrap().inject(pkt);
        assert!(dp.process_one().expect("second packet"));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "cache hit must skip rules");
        let stats = dp.decision_cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.entries, 1);
    }

    /// S24：fake_ip_enabled=false 时 198.18/15 按普通 IP 走规则。
    #[test]
    fn dataplane_fake_ip_disabled_uses_rules() {
        use nexus_domain::{RouteRequest, RouteTarget, RuleEngine};

        struct Recording(Arc<Mutex<Option<RouteRequestOwned>>>);
        #[derive(Debug, Clone)]
        struct RouteRequestOwned {
            domain: Option<String>,
        }
        impl RuleEngine for Recording {
            fn decide(&self, req: &RouteRequest<'_>) -> RouteTarget {
                *self.0.lock().unwrap() = Some(RouteRequestOwned {
                    domain: req.domain.map(str::to_string),
                });
                RouteTarget::Drop
            }
        }

        let (mut dp, mock) = test_dataplane();
        let seen = Arc::new(Mutex::new(None));
        dp.set_rule_engine(Box::new(Recording(Arc::clone(&seen))));
        let pkt = craft_udp([192, 168, 1, 5], [198, 18, 0, 5], 40_001, 443, b"y");
        mock.lock().unwrap().inject(pkt);
        assert!(dp.process_one().expect("packet"));
        assert_eq!(seen.lock().unwrap().as_ref().unwrap().domain, None);
        assert_eq!(dp.stats().dropped, 1);
    }

    /// 性能基线（R4）：`process_one()` 现状每包成本。
    ///
    /// `#[ignore]`：`cargo test -p nexusd -- --ignored --nocapture perf_baseline_process_one` 手动跑。
    #[test]
    #[ignore]
    fn perf_baseline_process_one() {
        use std::time::Instant;
        let (mut dp, mock) = test_dataplane();
        // Direct 分类包（bypass 路径，最简转发）。
        // 注意 test_dataplane 的 bypass 为默认；用目的 192.168.1.1（默认 bypass 覆盖）。
        const N: usize = 5_000;
        for i in 0..N {
            let mut pkt = vec![0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
            pkt.extend_from_slice(&[10, 200, 0, 2, 192, 168, 1, 1]);
            pkt.extend_from_slice(&(40000u16 + (i % 1000) as u16).to_be_bytes());
            pkt.extend_from_slice(&80u16.to_be_bytes());
            pkt.extend_from_slice(&[0u8; 20]);
            mock.lock().unwrap().inject(pkt);
        }
        let mut times = Vec::with_capacity(N);
        for _ in 0..N {
            let t = Instant::now();
            let _ = dp.process_one().expect("process_one");
            times.push(t.elapsed());
        }
        times.sort();
        let p50 = times[N / 2].as_nanos();
        let p99 = times[N * 99 / 100].as_nanos();
        println!("process_one (direct path): p50={p50}ns p99={p99}ns over {N} packets");
    }
}
