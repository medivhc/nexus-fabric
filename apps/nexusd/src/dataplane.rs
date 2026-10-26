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
use nexus_platform::{AcceptedTcpStream, ReceivedDatagram, TransparentIngressError};
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
use nexus_projection::transparent::runtime::{TransparentFailureKind, TransparentPipeline};
use nexus_projection::transparent::{
    TcpConnection, TransparentDecision, TransparentOutput, TransparentTcpInput, TransparentUdpInput,
};
use nexus_proxy_config::FlowSessionsMode;

mod chain_wiring;

pub use chain_wiring::{
    ChainDepsError, ProductionChainDeps, ProviderDeriveError, build_registry, derive_providers,
};
use nexus_projection::transparent::decision::{
    CachedDecision, FlowDecisionCache, FlowDecisionCacheStats, FlowDecisionKey, Frontend,
};

/// TPROXY 跨线程消息（spec §9.14）。
#[derive(Debug)]
pub enum TransparentInbound {
    /// 一条已 accept 的透明 TCP 连接。
    Tcp(AcceptedTcpStream),
    /// 一条透明 UDP 数据报。
    Udp(ReceivedDatagram),
    /// listener/socket 捕获失败。
    CaptureFailed(TransparentIngressError),
    /// listener 已停止。
    Stopped,
}

/// TPROXY 计数器（spec §9.16 `tproxy.counters`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TproxyCounters {
    pub tcp_accepted: u64,
    pub tcp_rejected: u64,
    pub udp_datagrams: u64,
    pub udp_dropped: u64,
    pub udp_table_evicted: u64,
    pub udp_reply_failed: u64,
    pub inbound_queue_full: u64,
    pub orig_dst_missing: u64,
    pub rule_no_match: u64,
    pub direct_tcp_dial_failed: u64,
    pub direct_udp_failed: u64,
    pub upstream_failed: u64,
    pub domain_miss: u64,
}

/// 无 TUN 模式下的占位设备：只返回 `WouldBlock`，不伪造任何数据面。
#[derive(Debug, Default)]
pub struct InertTun;

impl TunDevice for InertTun {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        Ok(packet.len())
    }

    fn name(&self) -> &str {
        "none"
    }
}

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
    /// Direct TCP 真实拨号成功数（AC-G6-01）。
    pub direct_tcp_dial_ok: u64,
    /// Proxy 上游建连失败数（TUN/TProxy 共用语义；AC-G3b-01）。
    pub upstream_failed: u64,
    /// P7：拨号窗口期内已接收但未写入上游的字节数。
    pub proxy_dial_buffer_dropped_bytes: u64,
    /// P7：拨号窗口期缓冲超限而被 RST 的流数。
    pub proxy_dial_buffer_overflow_resets: u64,
    /// 规则给出 egress_hint 但规划无可用 Provider（Drop）的计数。
    pub outbound_unresolved: u64,
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
    /// 上次同步的 Proxy 终结流计数（`ProxyFwdStats::tcp_streams`）。
    last_proxy_tcp_streams: u64,
    /// 上次同步的拨号窗口期丢弃字节数（`ProxyFwdStats`，P7）。
    last_proxy_dial_buffer_dropped: u64,
    /// 上次同步的拨号窗口期超限 RST 流数（`ProxyFwdStats`，P7）。
    last_proxy_dial_buffer_overflow: u64,
    stats: Arc<Mutex<DataplaneStats>>,
    config: DataplaneConfig,
    buf: Vec<u8>,
    /// QoS 时钟起点（单调；避免 Duration::ZERO 冻结导致队列永不满溢回收）。
    /// 单调时钟起点（spec §9.14；组合根唯一采集点）。
    epoch: std::time::Instant,
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
    /// 规则引擎（S24：组合根注入 `DomainRuleEngine` 后按配置 tag 分流）。
    ///
    /// `new` 的初始值为空规则（未命中 → Drop，fail-closed）；生产组合根必须
    /// 注入配置引擎，或在无 `proxy.yaml` 时显式调用 [`Self::set_default_simple_engine`]。
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
    /// TPROXY → owner 有界 channel（spec §9.14）。
    transparent_rx: Option<std::sync::mpsc::Receiver<TransparentInbound>>,
    /// owner → listener 的失败回报通道。
    transparent_failure_tx: Option<std::sync::mpsc::SyncSender<TransparentInbound>>,
    /// TPROXY 计数器（listener 与 owner 共享）。
    tproxy_counters: Arc<Mutex<TproxyCounters>>,
    /// 最近一次捕获失败原因（spec §9.16）。
    tproxy_last_failure: Option<String>,
    /// 透明前端管道（S42：TPROXY 生产装配）。
    transparent: Option<TransparentPipeline>,
    /// owner → listener 的 UDP 回包通道（`send_from` 在 listener 线程）。
    transparent_udp_reply_tx: Option<std::sync::mpsc::Sender<TransparentOutput>>,
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
    /// 首包链累计运行次数（实时取自 `SessionManager::planner_calls`）。
    pub planner_calls: u64,
}

impl Default for FlowSessionsState {
    fn default() -> Self {
        Self {
            state: "disabled",
            reason: None,
            providers: 0,
            planner_calls: 0,
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
            last_proxy_tcp_streams: 0,
            last_proxy_dial_buffer_dropped: 0,
            last_proxy_dial_buffer_overflow: 0,
            stats: Arc::new(Mutex::new(DataplaneStats::default())),
            config,
            buf: vec![0u8; 65535],
            epoch: std::time::Instant::now(),
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
            // fail-closed：未注入引擎时未命中 → Drop；不允许静默把流量送回 proxy。
            rules: Box::new(SimpleRuleEngine::new(Vec::new())),
            decision_cache: FlowDecisionCache::new(
                decision_cache_capacity,
                std::time::Duration::from_secs(decision_cache_idle_secs),
            ),
            production_chain_deps: None,
            flow_sessions: FlowSessionsState::default(),
            direct_tcp: DirectTcpRelay::new(DirectEgressConfig::default()),
            direct_udp: RealUdpEgress::new(Arc::new(Mutex::new(EgressNat::default()))).ok(),
            dns_cache: Arc::new(Mutex::new(DnsCache::new(DEFAULT_DNS_CACHE_ENTRIES))),
            transparent_rx: None,
            transparent_failure_tx: None,
            tproxy_counters: Arc::new(Mutex::new(TproxyCounters::default())),
            tproxy_last_failure: None,
            transparent: None,
            transparent_udp_reply_tx: None,
        })
    }

    /// 注入规则引擎（组合根：有 `proxy.yaml` → `DomainRuleEngine`）。
    pub fn set_rule_engine(&mut self, rules: Box<dyn nexus_domain::RuleEngine>) {
        self.rules = rules;
    }

    /// 显式注入无代理配置默认引擎（`SimpleRuleEngine`，全部流量交 `proxy` 标签）。
    ///
    /// 只允许在没有 `proxy.yaml` 的装配路径上调用（由组合根记录显式日志）；
    /// 有配置时规则引擎构造失败必须 fail-closed，不得用本方法顶替。
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
        let now = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
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

    /// 流会话可见状态（`planner_calls` 每次读取时取实时计数）。
    pub fn flow_sessions_state(&self) -> FlowSessionsState {
        FlowSessionsState {
            planner_calls: self.flow_planner_calls(),
            ..self.flow_sessions
        }
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

    /// 首包链规划出的 Provider（E4 `egress_hint`/`outbound` 一致性）。
    #[must_use]
    pub fn flow_planned_provider(&self, key: &FlowKey) -> Option<String> {
        self.flow_mgr
            .as_ref()
            .and_then(|m| m.planned_provider(key))
            .map(str::to_string)
    }

    /// 建连失败累计数（AC-G4-03/AC-G4-04 可见性）。
    #[must_use]
    pub fn flow_establish_failures(&self) -> u64 {
        self.flow_mgr
            .as_ref()
            .map(|m| m.establish_failures())
            .unwrap_or(0)
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
    pub fn flow_sweep_idle(&mut self, now_millis: u64) -> usize {
        let now = self.now_instant(now_millis);
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

    /// 把 ProxyEngine 的增量同步到 DataplaneStats。
    fn sync_proxy_stats(&mut self) {
        let eng_stats = match self.proxy_engine.as_ref() {
            Some(engine) => engine.stats(),
            None => return,
        };
        let ok_delta = eng_stats
            .tcp_dials_ok
            .saturating_sub(self.last_tcp_dials_ok);
        let fail_delta = eng_stats
            .tcp_dials_failed
            .saturating_sub(self.last_tcp_dials_failed);
        let stream_delta = eng_stats
            .tcp_streams
            .saturating_sub(self.last_proxy_tcp_streams);
        let dial_buf_drop_delta = eng_stats
            .tcp_dial_buffer_dropped_bytes
            .saturating_sub(self.last_proxy_dial_buffer_dropped);
        let dial_buf_overflow_delta = eng_stats
            .tcp_dial_buffer_overflow_resets
            .saturating_sub(self.last_proxy_dial_buffer_overflow);
        self.last_tcp_dials_ok = eng_stats.tcp_dials_ok;
        self.last_tcp_dials_failed = eng_stats.tcp_dials_failed;
        self.last_proxy_tcp_streams = eng_stats.tcp_streams;
        self.last_proxy_dial_buffer_dropped = eng_stats.tcp_dial_buffer_dropped_bytes;
        self.last_proxy_dial_buffer_overflow = eng_stats.tcp_dial_buffer_overflow_resets;
        self.with_stats(|s| {
            s.proxy_tcp_streams += stream_delta;
            s.proxy_forwarded += ok_delta;
            s.proxy_dropped_no_proxy += fail_delta;
            s.upstream_failed += fail_delta;
            s.proxy_dial_buffer_dropped_bytes += dial_buf_drop_delta;
            s.proxy_dial_buffer_overflow_resets += dial_buf_overflow_delta;
        });
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
    ///
    /// 返回 `(分类, 首次决策记录)`：第二次及以后为 `None`（缓存命中），
    /// 供 P6-c 的「每流恰好一次」`flow_decision` 事件使用。
    fn classify_with_cache(
        &mut self,
        packet: &[u8],
        now_millis: u64,
    ) -> (Classification, Option<CachedDecision>) {
        let cache_key =
            nexus_projection::egress::FlowKey::parse(packet).map(|flow| FlowDecisionKey {
                flow,
                frontend: Frontend::Tun,
            });
        if let Some(key) = cache_key {
            if let Some(cached) = self.decision_cache.get(&key, now_millis) {
                return (classification_from_target(&cached.target), None);
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
        let (classification, matched_rule) = {
            let classifier = PacketClassifier::new(
                self.mesh_cidrs.clone(),
                self.bypass_cidrs.clone(),
                &*self.rules,
                self.config.fake_ip_enabled,
                &self.manager,
                candidates,
                0.0, // degrade_threshold：MVP 用 0（不触发 degraded）
            );
            // P6-c：同一次决策顺带取回规则命中说明（`matched_rule`），
            // 不额外再跑一遍规则引擎，也不新造第二套决策。
            let (classification, explanation) =
                classifier.classify_explained(packet, domain.as_deref());
            (classification, explanation.map(|e| e.matched_rule))
        };
        let decision = decision_from_classification(&classification, matched_rule, now_millis);
        if let Some(key) = cache_key {
            self.decision_cache
                .insert(key, decision.clone(), now_millis);
        }
        (classification, Some(decision))
    }

    /// P6-c：TUN 前端新流决策事件（spec §11.2，`frontend=tun`）。
    ///
    /// 只在决策缓存 miss（每流首包）时调用；字段取值与 TPROXY 前端同源
    /// （同一 `RuleEngine` / 同一 `FlowDecisionCache`，frontend 不同）。
    fn emit_tun_flow_decision(&self, packet: &[u8], decision: &CachedDecision) {
        if let Some(line) = self.tun_flow_decision_line(packet, decision) {
            eprintln!("{line}");
        }
    }

    /// TUN 新流决策的 spec §11.2 日志行（发射点与测试共用）。
    fn tun_flow_decision_line(&self, packet: &[u8], decision: &CachedDecision) -> Option<String> {
        let flow = nexus_projection::egress::FlowKey::parse(packet)?;
        let peer = SocketAddrV4::new(Ipv4Addr::from(flow.src_ip), flow.src_port);
        let orig_dst = SocketAddrV4::new(Ipv4Addr::from(flow.dst_ip), flow.dst_port);
        let proto = if flow.proto == 17 { "udp" } else { "tcp" };
        let transparent = transparent_decision_from_target(&decision.target);
        let egress_hint = transparent_egress_hint(&decision.target);
        Some(flow_decision_log(
            "tun",
            peer,
            orig_dst,
            proto,
            Some(decision.matched_rule.as_str()),
            egress_hint.as_deref(),
            &transparent,
        ))
    }

    /// 当前单调毫秒（driver 时钟域）。
    pub fn epoch_millis(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// 单调毫秒 → `Instant`（epoch 唯一采集点，core 不读时钟）。
    fn now_instant(&self, now_millis: u64) -> std::time::Instant {
        self.epoch + std::time::Duration::from_millis(now_millis)
    }

    /// 注入 TPROXY 入站 channel（spec §9.14）。
    pub fn set_transparent_rx(
        &mut self,
        rx: std::sync::mpsc::Receiver<TransparentInbound>,
        tx_failure: std::sync::mpsc::SyncSender<TransparentInbound>,
    ) {
        self.transparent_rx = Some(rx);
        self.transparent_failure_tx = Some(tx_failure);
    }

    /// TPROXY 计数器句柄（listener 线程用于记录 `inbound_queue_full`）。
    pub fn tproxy_counters_handle(&self) -> Arc<Mutex<TproxyCounters>> {
        Arc::clone(&self.tproxy_counters)
    }

    /// 当前 TPROXY 计数器快照。
    pub fn tproxy_counters(&self) -> TproxyCounters {
        *self
            .tproxy_counters
            .lock()
            .expect("tproxy counters poisoned")
    }

    /// 最近一次捕获失败原因。
    pub fn tproxy_last_failure(&self) -> Option<&str> {
        self.tproxy_last_failure.as_deref()
    }

    /// 记录最近一次失败（spec §9.16 `last_failure_reason`）。
    ///
    /// 格式：`<规范类别 token>: <细节>`。token 与 `tproxy.counters` 同名
    /// （如 `upstream_failed`），使类别可机判、细节可读。
    /// 只在失败发生的同步路径调用；后续失败覆盖先前值，成功不清除。
    fn note_tproxy_failure(&mut self, token: &str, detail: impl std::fmt::Display) {
        self.tproxy_last_failure = Some(format!("{token}: {detail}"));
    }

    /// 记录 TUN Proxy 引擎拨号失败（`ProxyStreamEvent::Failed`）。
    ///
    /// 与 `sync_proxy_stats` 的 `tcp_dials_failed → upstream_failed` 同源；
    /// 事件里的 reason 原先被丢弃，现持久化到同一 `last_failure_reason` 面。
    fn record_proxy_stream_failures(&mut self, events: Vec<crate::proxy_fwd::ProxyStreamEvent>) {
        for event in events {
            if let crate::proxy_fwd::ProxyStreamEvent::Failed { reason, .. } = event {
                self.note_tproxy_failure(TransparentFailureKind::UpstreamFailed.token(), reason);
            }
        }
    }

    /// 注入透明前端管道与 UDP 回包通道（S42 组合根调用）。
    pub fn set_transparent_pipeline(
        &mut self,
        pipeline: TransparentPipeline,
        udp_reply_tx: std::sync::mpsc::Sender<TransparentOutput>,
    ) {
        self.transparent = Some(pipeline);
        self.transparent_udp_reply_tx = Some(udp_reply_tx);
    }

    /// 透明前端是否已装配。
    pub fn transparent_ready(&self) -> bool {
        self.transparent.is_some()
    }

    /// 关闭透明前端（SIGTERM 清理路径）。
    pub fn shutdown_transparent(&mut self) {
        if let Some(mut pipeline) = self.transparent.take() {
            let _ = pipeline.shutdown();
        }
        self.transparent_udp_reply_tx = None;
    }

    /// 单个 tick：先 drain TPROXY channel（最多 256 条），驱动透明前端，
    /// 空闲也泵送一次 proxy 回程（P8b），再读 TUN 一包。
    pub fn tick(&mut self, now_millis: u64) -> io::Result<bool> {
        let drained = self.drain_transparent_inbound(now_millis);
        let polled = self.poll_transparent(now_millis);
        // P8b（fix-review-r7 F1）：proxy 回程不能只在入站包到达时写回。
        // 本调用无入站包（`process_one_at` WouldBlock 早返）时也必须把
        // `ProxyEngine` 里已入队的回程泵出去；放在 `process_one_at` 之前，
        // 保证同 tick 内旧的回程先于本 tick 新包产生的回程写回。
        let proxy_pumped = self.poll_proxy_engine();
        match self.process_one_at(now_millis) {
            Ok(processed) => Ok(processed || drained > 0 || polled > 0 || proxy_pumped),
            Err(e) => Err(e),
        }
    }

    /// P8b：空闲 tick 泵送 proxy 回程；返回是否写出了包。
    ///
    /// 无引擎时直接返回（零副作用）。每次 tick 只调用一次 `ProxyEngine::poll`，
    /// 其工作量以引擎自身「排空当前队列」语义为界：排空 relay 事件（上限为
    /// 已入队事件数）+ 每条在途连接一次 smoltcp poll（上限为在途流数，产出受
    /// tx 窗口/MSS 限），不产生新工作、不阻塞、不自旋。产出一律走既有
    /// `write_proxy_tun_packets` → `ProxyEngine::fixup_tun_packets` → `tun.write`，
    /// 与包驱动路径同一条写回路。
    fn poll_proxy_engine(&mut self) -> bool {
        let Some(engine) = self.proxy_engine.as_mut() else {
            return false;
        };
        let result = engine.poll();
        let wrote = !result.tun_packets.is_empty();
        self.write_proxy_tun_packets(result.tun_packets);
        self.record_proxy_stream_failures(result.stream_events);
        wrote
    }

    /// 驱动透明前端下行/老化，并把 UDP 回包交给 listener 线程。
    fn poll_transparent(&mut self, now_millis: u64) -> usize {
        let (outputs, stats, failure) = match self.transparent.as_mut() {
            Some(pipeline) => {
                let outputs = pipeline.poll(now_millis);
                (outputs, pipeline.stats(), pipeline.take_failure())
            }
            None => return 0,
        };
        // 异步失败（拨号/发送）在计数点已入队；这里与计数器同 tick 发布。
        if let Some(failure) = failure {
            self.note_tproxy_failure(failure.kind.token(), failure.detail);
        }
        let mut replies = 0usize;
        for output in outputs {
            if let TransparentOutput::UdpReply {
                orig_dst,
                peer,
                payload,
            } = output
            {
                let sent = self.transparent_udp_reply_tx.as_ref().is_some_and(|tx| {
                    tx.send(TransparentOutput::UdpReply {
                        orig_dst,
                        peer,
                        payload,
                    })
                    .is_ok()
                });
                if sent {
                    replies += 1;
                } else {
                    self.with_tproxy_counters(|c| c.udp_reply_failed += 1);
                }
            }
        }
        self.with_tproxy_counters(|c| {
            c.tcp_accepted = stats.tcp_accepted;
            c.tcp_rejected = stats.tcp_rejected;
            c.udp_datagrams = stats.udp_datagrams;
            c.udp_dropped = stats.udp_dropped;
            c.udp_table_evicted = stats.udp_table_evicted;
            c.direct_tcp_dial_failed = stats.direct_tcp_dial_failed;
            c.direct_udp_failed = stats.direct_udp_failed;
            c.upstream_failed = stats.upstream_failed;
            c.domain_miss = stats.domain_miss;
        });
        replies
    }

    fn handle_transparent_tcp(&mut self, accepted: AcceptedTcpStream, now_millis: u64) {
        let peer = accepted.peer;
        let orig_dst = accepted.orig_dst;
        let (decision, matched_rule, egress_hint, _fresh) =
            self.transparent_decision(peer, orig_dst, 6, now_millis);
        eprintln!(
            "{}",
            flow_decision_log(
                "tproxy",
                peer,
                orig_dst,
                "tcp",
                matched_rule.as_deref(),
                egress_hint.as_deref(),
                &decision,
            )
        );
        let Some(pipeline) = self.transparent.as_mut() else {
            self.with_tproxy_counters(|c| c.tcp_rejected += 1);
            self.note_tproxy_failure("tcp_rejected_no_pipeline", format!("{peer}->{orig_dst}"));
            return;
        };
        let input = TransparentTcpInput {
            conn: Box::new(TcpConnection::new(accepted.stream, peer, orig_dst)),
            accepted_at_millis: accepted.accepted_at_millis,
            decision,
        };
        if let Err(error) = pipeline.on_tcp(input) {
            self.record_transparent_error(&error);
        }
    }

    fn handle_transparent_udp(&mut self, datagram: ReceivedDatagram, now_millis: u64) {
        // UDP/53 与 TUN 共用本地 DNS 处理器（spec §5 G10 / §13.2 S2）。
        if datagram.orig_dst.port() == 53 && self.dns.is_some() {
            let packet = synthetic_udp_packet(datagram.peer, datagram.orig_dst, &datagram.payload);
            if let Some(response) = self.dns_response_for(&packet) {
                if let Some(payload) = udp_payload_of(&response) {
                    let sent = self.transparent_udp_reply_tx.as_ref().is_some_and(|tx| {
                        tx.send(TransparentOutput::UdpReply {
                            orig_dst: datagram.orig_dst,
                            peer: datagram.peer,
                            payload: payload.to_vec(),
                        })
                        .is_ok()
                    });
                    if sent {
                        self.with_stats(|s| s.dns_answered += 1);
                        return;
                    }
                    self.with_tproxy_counters(|c| c.udp_reply_failed += 1);
                }
            }
        }
        let (decision, matched_rule, egress_hint, fresh) =
            self.transparent_decision(datagram.peer, datagram.orig_dst, 17, now_millis);
        if fresh {
            eprintln!(
                "{}",
                flow_decision_log(
                    "tproxy",
                    datagram.peer,
                    datagram.orig_dst,
                    "udp",
                    matched_rule.as_deref(),
                    egress_hint.as_deref(),
                    &decision,
                )
            );
        }
        let Some(pipeline) = self.transparent.as_mut() else {
            self.with_tproxy_counters(|c| c.udp_dropped += 1);
            self.note_tproxy_failure(
                "udp_dropped_no_pipeline",
                format!("{}->{}", datagram.peer, datagram.orig_dst),
            );
            return;
        };
        let input = TransparentUdpInput {
            payload: datagram.payload,
            peer: datagram.peer,
            orig_dst: datagram.orig_dst,
            received_at_millis: datagram.received_at_millis,
            decision,
        };
        if let Err(error) = pipeline.on_udp(input) {
            self.record_transparent_error(&error);
        }
    }

    fn record_transparent_error(
        &mut self,
        error: &nexus_projection::transparent::TransparentFrontendError,
    ) {
        use nexus_projection::transparent::TransparentFrontendError as E;
        match error {
            E::OrigDstMissing { .. } => {
                self.with_tproxy_counters(|c| c.orig_dst_missing += 1);
                self.note_tproxy_failure("orig_dst_missing", error);
            }
            E::OrigDstInvalid { .. } => {
                self.with_tproxy_counters(|c| c.udp_dropped += 1);
                self.note_tproxy_failure("orig_dst_invalid", error);
            }
            E::RuleEngineUnavailable { .. } => {
                self.note_tproxy_failure("rule_engine_unavailable", error);
            }
            E::RuleNoMatch { .. } => {
                self.with_tproxy_counters(|c| c.rule_no_match += 1);
                self.note_tproxy_failure("rule_no_match", error);
            }
            E::OutboundUnresolved { .. } => {
                self.note_tproxy_failure("outbound_unresolved", error);
            }
            E::DirectDialFailed { .. } => {
                self.with_tproxy_counters(|c| c.direct_tcp_dial_failed += 1);
                self.note_tproxy_failure("direct_tcp_dial_failed", error);
            }
            E::DirectSendFailed { .. } => {
                self.with_tproxy_counters(|c| c.direct_udp_failed += 1);
                self.note_tproxy_failure("direct_udp_failed", error);
            }
            E::SessionEstablishFailed { .. } => {
                self.with_tproxy_counters(|c| c.upstream_failed += 1);
                self.note_tproxy_failure("upstream_failed", error);
            }
            E::UnsupportedProtocol { .. } => {
                self.note_tproxy_failure("direct_dropped_unsupported", error);
            }
            E::TcpConnLimit { .. } => {
                self.note_tproxy_failure("tcp_conn_limit", error);
            }
            E::PayloadTooLarge { .. } => {
                self.note_tproxy_failure("payload_too_large", error);
            }
            E::UdpTableFull { .. } => {
                self.note_tproxy_failure("udp_table_full", error);
            }
        }
    }

    /// 透明流的规则决策（TUN/TPROXY 共用 `FlowDecisionCache` 与 `RuleEngine`）。
    fn transparent_decision(
        &mut self,
        peer: SocketAddrV4,
        orig_dst: SocketAddrV4,
        proto: u8,
        now_millis: u64,
    ) -> (TransparentDecision, Option<String>, Option<String>, bool) {
        let flow = nexus_projection::egress::FlowKey {
            src_ip: u32::from(*peer.ip()),
            dst_ip: u32::from(*orig_dst.ip()),
            src_port: peer.port(),
            dst_port: orig_dst.port(),
            proto,
        };
        let cache_key = FlowDecisionKey {
            flow,
            frontend: Frontend::Tproxy,
        };
        if let Some(cached) = self.decision_cache.get(&cache_key, now_millis).cloned() {
            return (
                transparent_decision_from_target(&cached.target),
                Some(cached.matched_rule),
                transparent_egress_hint(&cached.target),
                false,
            );
        }
        let packet = synthetic_transport_packet(peer, orig_dst, proto);
        let domain = self
            .dns_cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.lookup(&IpAddr::V4(*orig_dst.ip())));
        if domain.is_none() {
            self.with_stats(|s| s.domain_miss += 1);
        }
        let req = nexus_domain::RouteRequest {
            packet: &packet,
            domain: domain.as_deref(),
            src_port: Some(peer.port()),
            dst_port: Some(orig_dst.port()),
            process_name: None,
        };
        let (target, explanation) = self.rules.explain(&req);
        let matched_rule = explanation
            .as_ref()
            .map(|e| e.matched_rule.clone())
            .unwrap_or_default();
        let selected_outbound = transparent_selected_outbound(&target);
        self.decision_cache.insert(
            cache_key,
            CachedDecision {
                target: target.clone(),
                matched_rule: matched_rule.clone(),
                selected_outbound,
                last_seen_millis: now_millis,
            },
            now_millis,
        );
        (
            transparent_decision_from_target(&target),
            Some(matched_rule),
            transparent_egress_hint(&target),
            true,
        )
    }

    /// 排空透明入站 channel；每 tick 最多 256 条（spec §11.1）。
    pub fn drain_transparent_inbound(&mut self, now_millis: u64) -> usize {
        let Some(rx) = self.transparent_rx.as_ref() else {
            return 0;
        };
        let mut batch = Vec::new();
        while batch.len() < 256 {
            match rx.try_recv() {
                Ok(TransparentInbound::Stopped) => break,
                Ok(message) => batch.push(message),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        let drained = batch.len();
        for message in batch {
            match message {
                TransparentInbound::CaptureFailed(error) => self.record_capture_failure(error),
                TransparentInbound::Tcp(accepted) => {
                    self.handle_transparent_tcp(accepted, now_millis);
                }
                TransparentInbound::Udp(datagram) => {
                    self.handle_transparent_udp(datagram, now_millis);
                }
                TransparentInbound::Stopped => {}
            }
        }
        drained
    }

    fn record_capture_failure(&mut self, error: TransparentIngressError) {
        self.tproxy_last_failure = Some(error.to_string());
        match &error {
            TransparentIngressError::OrigDstMissing { .. } => {
                self.with_tproxy_counters(|c| c.orig_dst_missing += 1);
            }
            TransparentIngressError::OrigDstInvalid { .. } => {
                self.with_tproxy_counters(|c| c.udp_dropped += 1);
            }
            _ => {}
        }
    }

    fn with_tproxy_counters(&self, update: impl FnOnce(&mut TproxyCounters)) {
        let mut guard = self
            .tproxy_counters
            .lock()
            .expect("tproxy counters poisoned");
        update(&mut guard);
    }

    /// 兼容入口：driver 采集当前单调毫秒后调用 [`Self::tick`]。
    pub fn process_one(&mut self) -> io::Result<bool> {
        let now_millis = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.process_one_at(now_millis)
    }

    fn process_one_at(&mut self, now_millis: u64) -> io::Result<bool> {
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
        let (classification, fresh_decision) = self.classify_with_cache(&packet, now_millis);
        // P6-c：TUN 前端 Direct/Proxy 每流恰好一条 flow_decision（首包决策时）。
        if let Some(decision) = fresh_decision.as_ref() {
            if matches!(
                classification,
                Classification::Direct | Classification::Proxy { .. }
            ) {
                self.emit_tun_flow_decision(&packet, decision);
            }
        }

        // Phase B：Proxy TCP 首包也进入流会话（AC-G4-03/05）。
        if is_tcp_packet(&packet)
            && matches!(classification, Classification::Proxy { .. })
            && self.flow_mgr.is_some()
            && !self.flow_handle_tcp_packet(&packet, &classification, now_millis)
        {
            return Ok(true);
        }

        // S1：TCP + Mesh/Proxy → smoltcp 终结（不再走 raw-datagram 路径）。
        if is_tcp_packet(&packet) && matches!(classification, Classification::Mesh { .. }) {
            if !self.qos_admit(&packet) {
                return Ok(true);
            }
            // Phase B：流→会话映射（启用时）。首包走 §10 链，会话建好前
            // TCP 本地握手照常（smoltcp 缓冲早期数据，D4）。
            if self.flow_mgr.is_some()
                && !self.flow_handle_tcp_packet(&packet, &classification, now_millis)
            {
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
            && !self.flow_handle_udp_packet(&packet, &classification, now_millis)
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
                        self.write_proxy_tun_packets(result.tun_packets);
                        self.record_proxy_stream_failures(result.stream_events);
                        let more = self
                            .proxy_engine
                            .as_mut()
                            .map(|e| e.poll())
                            .unwrap_or_default();
                        self.write_proxy_tun_packets(more.tun_packets);
                        self.record_proxy_stream_failures(more.stream_events);
                        if packet.get(9) == Some(&17) && result.forwarded {
                            self.with_stats(|s| s.proxy_forwarded += 1);
                        }
                        // 同步 TCP dial / 终结流 / 失败增量（含异步 poll 结果）。
                        self.sync_proxy_stats();
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::DialFailed {
                        reason, ..
                    })) => {
                        self.note_tproxy_failure(
                            "upstream_failed",
                            format!("PROXY_DIAL_FAILED: {reason}"),
                        );
                        self.with_stats(|s| {
                            s.proxy_dropped_no_proxy += 1;
                            s.dropped += 1;
                        });
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::UnknownOutbound { .. }))
                    | Some(Err(crate::proxy_fwd::ProxyEngineError::UnsupportedOutboundKind {
                        ..
                    })) => {
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
                    } else {
                        self.with_stats(|s| s.direct_tcp_dial_ok += 1);
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
        let wrote = self.write_tun_packets(out);
        if wrote > 0 {
            self.with_stats(|s| s.direct_forwarded += 1);
        }
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
        let now = self.epoch.elapsed();
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
    fn flow_handle_udp_packet(
        &mut self,
        packet: &[u8],
        classification: &Classification,
        now_millis: u64,
    ) -> bool {
        let now = self.now_instant(now_millis);
        let (mgr, deps) = match (self.flow_mgr.as_mut(), self.flow_chain_deps.as_ref()) {
            (Some(m), Some(d)) => (m, d),
            _ => return true,
        };
        let key = match FlowKey::parse_ipv4(packet) {
            Some(k) => k,
            None => return true,
        };
        debug_assert_eq!(key.proto, IpProto::Udp);
        let hint = egress_hint(classification);
        match mgr.on_packet_with_hint(key, packet, false, deps, now, hint) {
            FlowDecision::NewSession { .. } | FlowDecision::Buffered { .. } => {
                // 已入 SessionManager 有界缓冲，暂不转发（Active 后 flush）。
                false
            }
            FlowDecision::Forward { .. } => true,
            FlowDecision::Drop { .. } => {
                if hint.is_some() {
                    self.with_stats(|s| s.outbound_unresolved += 1);
                }
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
                let outcome = self
                    .proxy_engine
                    .as_mut()
                    .map(|e| e.handle_packet(packet, outbound));
                match outcome {
                    Some(Ok(result)) => {
                        self.write_proxy_tun_packets(result.tun_packets);
                        self.record_proxy_stream_failures(result.stream_events);
                        if result.forwarded {
                            self.with_stats(|s| s.proxy_forwarded += 1);
                        }
                    }
                    Some(Err(_)) | None => self.with_stats(|s| s.proxy_dropped_no_proxy += 1),
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
    fn flow_handle_tcp_packet(
        &mut self,
        packet: &[u8],
        classification: &Classification,
        now_millis: u64,
    ) -> bool {
        let now = self.now_instant(now_millis);
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
                if hint.is_some() {
                    self.with_stats(|s| s.outbound_unresolved += 1);
                }
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
        let (active_streams, signals, failure) = match self.flow_mgr.as_mut() {
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
                (active, signals, mgr.take_failure_reason())
            }
            None => return,
        };
        // 建连失败与 `establish_failures` 同点记录，发布到统一失败面（AC-G4-03）。
        if let Some(detail) = failure {
            self.note_tproxy_failure("session_establish_failed", detail);
        }
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
    ///
    /// 返回成功写回的包数（`direct_forwarded` 等调用方口径依赖它）。
    fn write_tun_packets(&mut self, pkts: Vec<Vec<u8>>) -> u64 {
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
        written
    }

    /// P6-a：Proxy 路径写回。fixup 由拥有该流的 `ProxyEngine` 终结器执行
    /// （Proxy 连接不登记在 `Dataplane.tcp` 中，借道 `write_tun_packets`
    /// 会全部查不到连接而整批丢弃）；本方法只负责写 TUN 与计数。
    fn write_proxy_tun_packets(&mut self, pkts: Vec<Vec<u8>>) {
        let (ready, dropped) = match self.proxy_engine.as_ref() {
            Some(engine) => engine.fixup_tun_packets(pkts),
            None => (Vec::new(), pkts.len() as u64),
        };
        if dropped > 0 {
            self.with_stats(|s| s.dropped += dropped);
        }
        let mut written = 0u64;
        for pkt in ready {
            if self.tun.write(&pkt).is_err() {
                self.with_stats(|s| s.dropped += 1);
            } else {
                written += 1;
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
        let Some(response) = self.dns_response_for(packet) else {
            self.with_stats(|s| s.dropped += 1);
            return;
        };
        if self.tun.write(&response).is_ok() {
            self.with_stats(|s| {
                s.dns_answered += 1;
                s.tun_written += 1;
            });
        }
    }

    /// 解析 DNS 查询并构造应答包；TUN 与 TPROXY UDP/53 共用（spec §5 G10）。
    fn dns_response_for(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let dns = self.dns.as_mut()?;
        let (query_name, query_id) = parse_dns_query(packet)?;
        let query = DnsQuery {
            name: query_name.clone(),
            qtype: DnsType::A,
        };
        let answer = dns.resolve(&query, 0).ok()?;
        let ip = answer.records.iter().find_map(|r| match r {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })?;
        let response = build_dns_response(packet, query_id, &query_name, ip)?;
        self.record_dns_answer(&query_name, ip);
        Some(response)
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

/// 构造仅含 IP/TCP-UDP 头的合成包（透明流规则匹配用；无载荷）。
fn synthetic_transport_packet(peer: SocketAddrV4, orig_dst: SocketAddrV4, proto: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x45;
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&peer.ip().octets());
    pkt[16..20].copy_from_slice(&orig_dst.ip().octets());
    pkt[20..22].copy_from_slice(&peer.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&orig_dst.port().to_be_bytes());
    pkt
}

/// 构造透明 UDP 数据报的完整 IPv4/UDP 包（DNS 处理器输入）。
fn synthetic_udp_packet(peer: SocketAddrV4, orig_dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&peer.ip().octets());
    pkt[16..20].copy_from_slice(&orig_dst.ip().octets());
    pkt[20..22].copy_from_slice(&peer.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&orig_dst.port().to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// 取 IPv4/UDP 包的 UDP 载荷。
fn udp_payload_of(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 28 || packet[9] != 17 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < 20 || total > packet.len() || total < ihl + 8 {
        return None;
    }
    Some(&packet[ihl + 8..total])
}

/// 新流决策日志行（spec §11.2 `event=flow_decision`）。
///
/// `frontend` 为 `tun` / `tproxy`（spec §11.2 `frontend=<tun/tproxy>`）；
/// 两个前端字段序与取值口径一致。
fn flow_decision_log(
    frontend: &str,
    peer: SocketAddrV4,
    orig_dst: SocketAddrV4,
    proto: &str,
    matched_rule: Option<&str>,
    egress_hint: Option<&str>,
    decision: &TransparentDecision,
) -> String {
    let outbound = match decision {
        TransparentDecision::Direct => "self",
        TransparentDecision::Proxy { outbound, .. } => outbound.as_str(),
        TransparentDecision::Drop { .. } => "-",
    };
    let matched_rule = matched_rule
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    let egress_hint = egress_hint.filter(|value| !value.is_empty()).unwrap_or("-");
    format!(
        "[nexusd.dataplane] level=info event=flow_decision flow={peer}->{orig_dst} proto={proto} \
frontend={frontend} matched_rule={matched_rule} egress_hint={egress_hint} outbound={outbound} \
session=-"
    )
}

/// `RouteTarget` 选定的出站 tag（`self` 表示 DIRECT）。
fn transparent_selected_outbound(target: &nexus_domain::RouteTarget) -> String {
    use nexus_domain::RouteTarget;
    match target {
        RouteTarget::Egress { peer } | RouteTarget::MeshPeer { peer } => peer.clone(),
        RouteTarget::Drop => "drop".to_string(),
    }
}

/// 规则决策对应的 `egress_hint`：DIRECT 不进入会话层，故为 `None`（spec §7.4）。
fn transparent_egress_hint(target: &nexus_domain::RouteTarget) -> Option<String> {
    use nexus_domain::RouteTarget;
    match target {
        RouteTarget::Egress { peer } if peer == "self" => None,
        _ => Some(transparent_selected_outbound(target)),
    }
}

/// `RouteTarget` → `TransparentDecision`（TUN/TPROXY 同规则语义）。
fn transparent_decision_from_target(target: &nexus_domain::RouteTarget) -> TransparentDecision {
    use nexus_domain::RouteTarget;
    match target {
        RouteTarget::Egress { peer } if peer == "self" => TransparentDecision::Direct,
        RouteTarget::Egress { peer } => TransparentDecision::Proxy {
            outbound: peer.clone(),
            fallback: Vec::new(),
        },
        RouteTarget::MeshPeer { .. } => TransparentDecision::Drop {
            reason: DropReason::MeshUnsupported,
        },
        RouteTarget::Drop => TransparentDecision::Drop {
            reason: DropReason::RuleRejected,
        },
    }
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

/// TPROXY 运行期可见状态（spec §9.16）。
#[derive(Debug, Clone, Default)]
pub struct TproxyStatus {
    /// `disabled` / `active` / `degraded` / `cleanup_failed`。
    pub state: &'static str,
    /// 失败原因（§11.2 reason 枚举）。
    pub reason: Option<&'static str>,
    /// `active` / `block` / `none` / `impossible`。
    pub enforcement: &'static str,
    /// `iptables` / `nftables` / `external`。
    pub backend: &'static str,
    /// `root` / `cap_net_admin` / `insufficient`。
    pub privilege: &'static str,
    /// 专用链名。
    pub chain: String,
    /// fwmark（十六进制文本）。
    pub mark: String,
    /// 策略路由表。
    pub route_table: u32,
    /// 监听地址。
    pub listen: String,
    /// `ipv4`。
    pub ip_family: &'static str,
    /// 本 run 恒为 false。
    pub ipv6_enabled: bool,
    /// 计数器。
    pub counters: TproxyCounters,
    /// 最近失败原因（自由文本）。
    pub last_failure_reason: Option<String>,
}

static TPROXY_STATUS: OnceLock<Mutex<TproxyStatus>> = OnceLock::new();

fn tproxy_slot() -> &'static Mutex<TproxyStatus> {
    TPROXY_STATUS.get_or_init(|| {
        Mutex::new(TproxyStatus {
            state: "disabled",
            reason: None,
            enforcement: "none",
            backend: "iptables",
            privilege: "insufficient",
            chain: "NEXUS_TPROXY".to_string(),
            mark: "0x1f3".to_string(),
            route_table: 100,
            listen: "0.0.0.0:7895".to_string(),
            ip_family: "ipv4",
            ipv6_enabled: false,
            counters: TproxyCounters::default(),
            last_failure_reason: None,
        })
    })
}

/// 发布 TPROXY 状态。
pub fn publish_tproxy_status(status: TproxyStatus) {
    if let Ok(mut guard) = tproxy_slot().lock() {
        *guard = status;
    }
}

/// 发布 TPROXY 计数器与最近失败原因（owner 线程每 tick 调用）。
pub fn publish_tproxy_counters(counters: TproxyCounters, last_failure: Option<String>) {
    if let Ok(mut guard) = tproxy_slot().lock() {
        guard.counters = counters;
        if last_failure.is_some() {
            guard.last_failure_reason = last_failure;
        }
    }
}

/// TPROXY 状态快照。
pub fn tproxy_status_snapshot() -> TproxyStatus {
    tproxy_slot().lock().map(|s| s.clone()).unwrap_or_default()
}

/// 构造 `tproxy` JSON 段（spec §9.16）。
pub fn tproxy_status_json() -> serde_json::Value {
    let status = tproxy_status_snapshot();
    serde_json::json!({
        "state": status.state,
        "reason": status.reason,
        "enforcement": status.enforcement,
        "backend": status.backend,
        "privilege": status.privilege,
        "chain": status.chain,
        "mark": status.mark,
        "route_table": status.route_table,
        "listen": status.listen,
        "ip_family": status.ip_family,
        "ipv6_enabled": status.ipv6_enabled,
        "counters": {
            "tcp_accepted": status.counters.tcp_accepted,
            "tcp_rejected": status.counters.tcp_rejected,
            "udp_datagrams": status.counters.udp_datagrams,
            "udp_dropped": status.counters.udp_dropped,
            "udp_table_evicted": status.counters.udp_table_evicted,
            "udp_reply_failed": status.counters.udp_reply_failed,
            "inbound_queue_full": status.counters.inbound_queue_full,
            "orig_dst_missing": status.counters.orig_dst_missing,
            "rule_no_match": status.counters.rule_no_match,
            "direct_tcp_dial_failed": status.counters.direct_tcp_dial_failed,
            "direct_udp_failed": status.counters.direct_udp_failed,
            "upstream_failed": status.counters.upstream_failed,
            "domain_miss": status.counters.domain_miss,
        },
        "last_failure_reason": status.last_failure_reason,
    })
}

/// 捕获失败后的 enforcement 语义（spec §10.5）。
#[must_use]
pub fn capture_failure_enforcement(
    mode: nexus_proxy_config::CaptureFailureMode,
    backend_available: bool,
) -> &'static str {
    match (mode, backend_available) {
        (nexus_proxy_config::CaptureFailureMode::Bypass, _) => "none",
        (nexus_proxy_config::CaptureFailureMode::Block, true) => "block",
        (nexus_proxy_config::CaptureFailureMode::Block, false) => "impossible",
    }
}

/// 捕获失败状态（state=degraded；reason 为 §11.2 枚举值）。
#[must_use]
pub fn capture_failure_status(
    reason: &'static str,
    privilege: &'static str,
    mode: nexus_proxy_config::CaptureFailureMode,
    backend_available: bool,
) -> TproxyStatus {
    TproxyStatus {
        state: "degraded",
        reason: Some(reason),
        enforcement: capture_failure_enforcement(mode, backend_available),
        privilege,
        ..TproxyStatus::default()
    }
}

/// 当前进程权限自检（root 视为具备 CAP_NET_ADMIN + CAP_NET_RAW）。
#[must_use]
pub fn detect_privilege() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid(2) has no pointer arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return "root";
        }
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            if let Some(caps) = status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:	"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            {
                let net_admin = caps & (1 << 12) != 0;
                let net_raw = caps & (1 << 13) != 0;
                if net_admin && net_raw {
                    return "cap_net_admin";
                }
            }
        }
    }
    "insufficient"
}

/// 创建 TPROXY inbound 有界 channel（容量 1024，spec §11.1）。
#[must_use]
pub fn inbound_channel() -> (
    std::sync::mpsc::SyncSender<TransparentInbound>,
    std::sync::mpsc::Receiver<TransparentInbound>,
) {
    std::sync::mpsc::sync_channel(1024)
}

/// listener 侧 `try_send` 失败时记录 `inbound_queue_full`。
pub fn record_inbound_queue_full(counters: &Arc<Mutex<TproxyCounters>>) {
    if let Ok(mut guard) = counters.lock() {
        guard.inbound_queue_full += 1;
    }
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
            "proxy_tcp_streams": stats.proxy_tcp_streams,
            "direct_tcp_dial_ok": stats.direct_tcp_dial_ok,
            "upstream_failed": stats.upstream_failed,
            "proxy_dial_buffer_dropped_bytes": stats.proxy_dial_buffer_dropped_bytes,
            "proxy_dial_buffer_overflow_resets": stats.proxy_dial_buffer_overflow_resets,
            "outbound_unresolved": stats.outbound_unresolved,
            "flow_sessions": {
                "state": status.flow_sessions.state,
                "reason": status.flow_sessions.reason,
                "providers": status.flow_sessions.providers,
                "planner_calls": status.flow_sessions.planner_calls,
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
    matched_rule: Option<String>,
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
        matched_rule: matched_rule.unwrap_or_default(),
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
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        // 显式注入无配置默认引擎（新装配不再静默回落到它）。
        dp.set_default_simple_engine().expect("default engine");
        (dp, mock)
    }

    /// 装配回归：未注入引擎的 Dataplane 必须 fail-closed（Drop），
    /// 不得静默回落到把全部流量送往 `proxy` 的默认引擎。
    #[test]
    fn dataplane_without_injected_engine_fails_closed() {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let mut dp = Dataplane::new(
            Box::new(SharedTun { inner: mock }),
            DataplaneConfig::default(),
        )
        .expect("dataplane new");
        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 40_000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443);
        let (decision, matched_rule, outbound, _) = dp.transparent_decision(peer, dst, 17, 1);
        assert_eq!(
            decision,
            TransparentDecision::Drop {
                reason: DropReason::RuleRejected
            }
        );
        assert_eq!(matched_rule.as_deref(), Some(""));
        assert_eq!(outbound.as_deref(), Some("drop"));
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
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "proxy".to_string(),
            },
        }])));
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

    /// S31：同一 `now_millis` 序列两次运行输出一致；tick 走生产入口。
    #[test]
    fn flow_tick_is_deterministic() {
        fn run() -> (u64, u64, u64, u64) {
            let (mut dp, mock) = test_dataplane();
            let p1 = craft_udp([192, 168, 1, 5], [8, 8, 8, 8], 40_000, 443, b"a");
            let p2 = craft_udp([192, 168, 1, 5], [8, 8, 8, 9], 40_001, 443, b"b");
            mock.lock().unwrap().inject(p1);
            assert!(dp.tick(1).expect("tick 1"));
            mock.lock().unwrap().inject(p2);
            assert!(dp.tick(2).expect("tick 2"));
            let s = dp.stats();
            let c = dp.decision_cache_stats();
            (
                s.dropped + s.proxy_dropped_no_proxy,
                c.entries,
                c.hits,
                c.misses,
            )
        }
        assert_eq!(run(), run());
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
                planner_calls: 0,
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
        assert_eq!(json["dataplane"]["flow_sessions"]["planner_calls"], 0);
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

    /// T-1：`planner_calls` 从真实 `SessionManager` 实时进入状态面；
    /// 同流后续包不重复计数，不同流递增。
    #[test]
    fn flow_planner_calls_surface_tracks_live_counter() {
        use nexus_domain::RouteTarget;
        use nexus_projection::egress::{Rule, SimpleRuleEngine};

        let yaml = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1080
";
        let (mut dp, mock) = test_dataplane();
        dp.set_production_chain_deps(
            ProductionChainDeps::from_config(None, Some(yaml)).expect("deps"),
        );
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().expect("cidr"),
            target: RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        assert!(dp.enable_flow_sessions_for_config(FlowSessionsMode::Auto, 1));
        assert_eq!(dp.flow_sessions_state().planner_calls, 0);

        let first = craft_udp([10, 0, 0, 2], [203, 0, 113, 10], 40_000, 443, b"first");
        mock.lock().unwrap().inject(first.clone());
        assert!(dp.process_one().expect("first packet"));
        assert_eq!(dp.flow_planner_calls(), 1);
        assert_eq!(dp.flow_sessions_state().planner_calls, 1);

        // 同一 5 元组：已建流走快路径，不得再次运行首包链。
        mock.lock().unwrap().inject(first);
        assert!(dp.process_one().expect("same flow"));
        assert_eq!(dp.flow_sessions_state().planner_calls, 1);

        // 不同 5 元组：新流 → planner 再次被调用。
        let second = craft_udp([10, 0, 0, 2], [203, 0, 113, 11], 40_001, 443, b"second");
        mock.lock().unwrap().inject(second);
        assert!(dp.process_one().expect("second flow"));
        assert_eq!(dp.flow_sessions_state().planner_calls, 2);

        // 状态面（LocalAPI stats 构造器）必须输出实时计数，而不是常量 0。
        let state = dp.flow_sessions_state();
        publish_flow_sessions(state);
        let published = runtime_status_snapshot();
        assert_eq!(published.flow_sessions.planner_calls, 2);
        let json = dataplane_stats_json(false, &published, &dp.stats(), serde_json::Value::Null);
        assert_eq!(json["dataplane"]["flow_sessions"]["planner_calls"], 2);
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

    /// S59：新流决策日志严格遵循 spec §11.2 字段顺序与取值。
    #[test]
    fn flow_decision_log_matches_spec_format() {
        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 40_000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 200, 3, 3), 8080);

        let proxy = flow_decision_log(
            "tproxy",
            peer,
            dst,
            "tcp",
            Some("IP-CIDR,10.200.3.3/32,PROXY"),
            Some("p1"),
            &TransparentDecision::Proxy {
                outbound: "p1".to_string(),
                fallback: Vec::new(),
            },
        );
        assert_eq!(
            proxy,
            "[nexusd.dataplane] level=info event=flow_decision flow=10.200.2.2:40000->10.200.3.3:8080 \
proto=tcp frontend=tproxy matched_rule=IP-CIDR,10.200.3.3/32,PROXY egress_hint=p1 outbound=p1 \
session=-"
        );

        let direct = flow_decision_log(
            "tproxy",
            peer,
            dst,
            "udp",
            None,
            None,
            &TransparentDecision::Direct,
        );
        assert_eq!(
            direct,
            "[nexusd.dataplane] level=info event=flow_decision flow=10.200.2.2:40000->10.200.3.3:8080 \
proto=udp frontend=tproxy matched_rule=- egress_hint=- outbound=self session=-"
        );

        let drop = flow_decision_log(
            "tproxy",
            peer,
            dst,
            "tcp",
            Some("MATCH,DROP"),
            Some("drop"),
            &TransparentDecision::Drop {
                reason: DropReason::RuleRejected,
            },
        );
        assert!(drop.contains("egress_hint=drop outbound=- session=-"));
    }

    /// S59 P4：TPROXY 决策的 `egress_hint` 必须与 TUN 路径一致——
    /// DIRECT 流为 `None`（spec §7.4），Proxy 流为 `Some(tag)`；缓存命中亦然。
    #[test]
    fn transparent_decision_hint_matches_direct_and_proxy_semantics() {
        use nexus_projection::egress::{Rule, SimpleRuleEngine};

        let (mut dp, _mock) = test_dataplane();
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![
            Rule {
                cidr: "10.200.3.3/32".parse().expect("cidr"),
                target: nexus_domain::RouteTarget::Egress {
                    peer: "p1".to_string(),
                },
            },
            Rule {
                cidr: "0.0.0.0/0".parse().expect("cidr"),
                target: nexus_domain::RouteTarget::Egress {
                    peer: "self".to_string(),
                },
            },
        ])));
        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 200, 1, 2), 40_000);
        let direct_dst = SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 8080);
        let proxy_dst = SocketAddrV4::new(Ipv4Addr::new(10, 200, 3, 3), 8080);

        let (decision, _, hint, fresh) = dp.transparent_decision(peer, direct_dst, 6, 1);
        assert!(fresh);
        assert_eq!(decision, TransparentDecision::Direct);
        assert_eq!(hint, None, "DIRECT must not carry an egress_hint");

        let (decision, _, hint, fresh) = dp.transparent_decision(peer, proxy_dst, 6, 2);
        assert!(fresh);
        assert_eq!(
            decision,
            TransparentDecision::Proxy {
                outbound: "p1".to_string(),
                fallback: Vec::new(),
            }
        );
        assert_eq!(hint.as_deref(), Some("p1"));

        // 缓存命中必须复用同一语义（不得回落到 selected_outbound）。
        let (_, _, hint, fresh) = dp.transparent_decision(peer, direct_dst, 6, 3);
        assert!(!fresh);
        assert_eq!(hint, None, "cached DIRECT decision must stay hint-free");
        let (_, _, hint, fresh) = dp.transparent_decision(peer, proxy_dst, 6, 4);
        assert!(!fresh);
        assert_eq!(hint.as_deref(), Some("p1"));
    }

    /// S59：UDP 去重依据决策缓存命中——同流第二包不再算"新流"。
    #[test]
    fn udp_flow_decision_is_fresh_only_on_cache_miss() {
        let (mut dp, _mock) = test_dataplane();
        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 200, 2, 2), 40_000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 200, 3, 3), 8080);

        let (_, _, _, fresh) = dp.transparent_decision(peer, dst, 17, 1_000);
        assert!(fresh, "first packet of a flow is a new decision");
        let (_, _, _, fresh) = dp.transparent_decision(peer, dst, 17, 1_001);
        assert!(!fresh, "same flow within cache TTL must not log again");
        assert_eq!(dp.decision_cache_stats().hits, 1);
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

    #[test]
    fn transparent_queue_drains_at_most_256_per_tick() {
        let (mut dp, _mock) = test_dataplane();
        let (tx, rx) = inbound_channel();
        let (failure_tx, _failure_rx) = inbound_channel();
        for _ in 0..300 {
            tx.try_send(TransparentInbound::CaptureFailed(
                TransparentIngressError::Io {
                    operation: "recvmsg",
                    message: "probe".to_string(),
                },
            ))
            .expect("channel capacity 1024");
        }
        dp.set_transparent_rx(rx, failure_tx);
        assert_eq!(dp.drain_transparent_inbound(1), 256);
        assert_eq!(dp.drain_transparent_inbound(2), 44);
        assert_eq!(
            dp.tproxy_last_failure(),
            Some("TRANSPARENT_IO: recvmsg: probe")
        );
    }

    #[test]
    fn transparent_queue_full_is_counted() {
        let (_mut_dp, _mock) = test_dataplane();
        let (tx, _rx) = inbound_channel();
        for _ in 0..1024 {
            tx.try_send(TransparentInbound::Stopped)
                .expect("channel capacity 1024");
        }
        assert!(tx.try_send(TransparentInbound::Stopped).is_err());
        let counters = Arc::new(Mutex::new(TproxyCounters::default()));
        record_inbound_queue_full(&counters);
        assert_eq!(counters.lock().unwrap().inbound_queue_full, 1);
    }

    #[test]
    fn transparent_capture_failure_policy_branches() {
        use nexus_proxy_config::CaptureFailureMode;
        assert_eq!(
            capture_failure_enforcement(CaptureFailureMode::Block, true),
            "block"
        );
        assert_eq!(
            capture_failure_enforcement(CaptureFailureMode::Block, false),
            "impossible"
        );
        assert_eq!(
            capture_failure_enforcement(CaptureFailureMode::Bypass, true),
            "none"
        );
        let status = capture_failure_status(
            "bind_failed",
            "insufficient",
            CaptureFailureMode::Block,
            false,
        );
        assert_eq!(status.state, "degraded");
        assert_eq!(status.reason, Some("bind_failed"));
        assert_eq!(status.enforcement, "impossible");
        assert_eq!(status.privilege, "insufficient");
    }

    #[test]
    fn transparent_privilege_status_is_one_of_allowed() {
        let privilege = detect_privilege();
        assert!(matches!(
            privilege,
            "root" | "cap_net_admin" | "insufficient"
        ));
    }

    struct DirectEngine;
    impl nexus_domain::RuleEngine for DirectEngine {
        fn decide(&self, _req: &nexus_domain::RouteRequest<'_>) -> nexus_domain::RouteTarget {
            nexus_domain::RouteTarget::Egress {
                peer: "self".to_string(),
            }
        }
    }

    fn transparent_pipeline() -> TransparentPipeline {
        TransparentPipeline::new(nexus_projection::transparent::TransparentDeps {
            proxy_egress: None,
            direct: nexus_projection::transparent::direct::DirectEgress::new(
                nexus_projection::transparent::direct::DirectEgressConfig::default(),
            )
            .expect("direct egress"),
            config: nexus_projection::transparent::TransparentConfig::default(),
        })
    }

    #[test]
    fn tproxy_assembly_direct_udp_roundtrip_and_reply_channel() {
        use nexus_platform::ReceivedDatagram;
        use std::net::{Ipv4Addr, UdpSocket};

        let server = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let orig = match server.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("v4"),
        };
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = server.recv_from(&mut buf) {
                let _ = server.send_to(&buf[..n], from);
            }
        });
        let (mut dp, _mock) = test_dataplane();
        dp.set_rule_engine(Box::new(DirectEngine));
        let (tx, rx) = inbound_channel();
        let (failure_tx, _failure_rx) = inbound_channel();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        dp.set_transparent_pipeline(transparent_pipeline(), reply_tx);
        dp.set_transparent_rx(rx, failure_tx);
        tx.try_send(TransparentInbound::Udp(ReceivedDatagram {
            payload: b"ping".to_vec(),
            peer: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_000),
            orig_dst: orig,
            received_at_millis: 1,
        }))
        .expect("send");
        let mut got_reply = false;
        for step in 0..2_000u64 {
            let _ = dp.tick(step).expect("tick");
            if let Ok(TransparentOutput::UdpReply { payload, .. }) = reply_rx.try_recv() {
                assert_eq!(payload, b"ping");
                got_reply = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let _ = handle.join();
        assert!(got_reply, "pipeline must produce a UDP reply");
        assert!(dp.tproxy_counters().udp_datagrams >= 1);
        assert!(dp.transparent_ready());
        dp.shutdown_transparent();
        assert!(!dp.transparent_ready());
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

    // ===== P6-e：TUN 前端 Direct/Proxy 回包源地址（fixup）包级回归 =====
    //
    // E4 的 TUN 场景只断言事件/计数，回包源地址因此漏网（E5 r6 / S4）。
    // 这些测试直接从 MockTun 捕获写回包并解析 IP/TCP 头。

    const P6_PROXY_YAML: &str = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: p1\noutbounds:\n  - tag: p1\n    kind: socks5\n    locator: 127.0.0.1:9\n";

    /// P6-e 用数据面：`127.0.0.0/8` 走 bypass（Direct，可真实 dial 本机监听），
    /// `10.200.3.3/32` 走规则 → Proxy `p1`。Mesh 网段避开测试地址。
    fn tun_fixup_dataplane() -> (Dataplane, Arc<Mutex<nexus_projection::MockTun>>) {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            bypass_cidrs: vec!["127.0.0.0/8".to_string()],
            n1_configured: true,
            proxy_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "10.200.3.3/32".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        dp.set_proxy_engine(
            crate::proxy_fwd::ProxyEngine::new(P6_PROXY_YAML).expect("proxy engine"),
        );
        (dp, mock)
    }

    /// 解析写回包的 SYN-ACK 四元组：(src_ip, src_port, dst_ip, dst_port)。
    fn syn_ack_of(pkt: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
        if pkt.len() < 40 || pkt[9] != 6 {
            return None;
        }
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if pkt.len() < ihl + 14 {
            return None;
        }
        let flags = pkt[ihl + 13];
        if flags & 0x12 != 0x12 {
            return None;
        }
        Some((
            Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
            Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
            u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
        ))
    }

    /// P6-e ①：TUN Direct 流写回的 SYN-ACK 源 IP/端口 == orig_dst。
    #[test]
    fn tun_direct_syn_ack_source_is_orig_dst() {
        let (mut dp, mock) = tun_fixup_dataplane();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("direct sink");
        let orig_port = listener.local_addr().expect("addr").port();
        let syn = craft_tcp(
            [10, 200, 1, 2],
            [127, 0, 0, 1],
            57364,
            orig_port,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("direct syn"));

        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 1, "one SYN-ACK expected: {written:?}");
        let (src_ip, src_port, dst_ip, dst_port) =
            syn_ack_of(&written[0]).expect("written packet is a SYN-ACK");
        assert_eq!(
            src_ip,
            Ipv4Addr::new(127, 0, 0, 1),
            "GAP-5/P6-b: SYN-ACK source must be the original destination"
        );
        assert_eq!(src_port, orig_port, "source port must be the original one");
        assert_ne!(
            src_ip,
            Ipv4Addr::new(10, 254, 0, 1),
            "smoltcp iface IP must never leak to the client"
        );
        assert_eq!(dst_ip, Ipv4Addr::new(10, 200, 1, 2));
        assert_eq!(dst_port, 57364);
        assert_eq!(dp.stats().direct_forwarded, 1);
        assert!(dp.stats().tun_written >= 1);
        drop(listener);
    }

    /// P6-e ②：TUN Proxy 流写回的 SYN-ACK 源 IP/端口 == orig_dst。
    ///
    /// 专防 P6-a 归属陷阱：fixup 必须由 `ProxyEngine` 的终结器执行；
    /// 若把 Proxy 包改走 `Dataplane::write_tun_packets`，连接查不到 →
    /// 整批丢弃，本测试的 `written.len() == 1` 断言会失败。
    #[test]
    fn tun_proxy_syn_ack_source_is_orig_dst() {
        let (mut dp, mock) = tun_fixup_dataplane();
        let syn = craft_tcp(
            [10, 200, 1, 2],
            [10, 200, 3, 3],
            57365,
            8080,
            2000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("proxy syn"));

        let written = mock.lock().unwrap().take_written();
        assert_eq!(
            written.len(),
            1,
            "P6-a: proxy SYN-ACK must survive fixup (no batch drop)"
        );
        let (src_ip, src_port, dst_ip, dst_port) =
            syn_ack_of(&written[0]).expect("written packet is a SYN-ACK");
        assert_eq!(
            src_ip,
            Ipv4Addr::new(10, 200, 3, 3),
            "P6-a: proxy SYN-ACK source must be the original destination"
        );
        assert_eq!(src_port, 8080);
        assert_ne!(src_ip, Ipv4Addr::new(10, 254, 0, 1));
        assert_eq!(dst_ip, Ipv4Addr::new(10, 200, 1, 2));
        assert_eq!(dst_port, 57365);
        assert!(dp.stats().tun_written >= 1);
        assert_eq!(dp.stats().dropped, 0, "no proxy packet may be dropped");
    }

    /// P6-e ③：两条不同 orig_dst 的流同时在飞，各自 SYN-ACK 改回自己的源。
    #[test]
    fn tun_two_flows_keep_their_own_orig_dst() {
        let (mut dp, mock) = tun_fixup_dataplane();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("direct sink");
        let direct_port = listener.local_addr().expect("addr").port();
        let direct_syn = craft_tcp(
            [10, 200, 1, 2],
            [127, 0, 0, 1],
            57364,
            direct_port,
            1000,
            0,
            0x02,
            &[],
        );
        let proxy_syn = craft_tcp(
            [10, 200, 1, 3],
            [10, 200, 3, 3],
            57365,
            8080,
            2000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(direct_syn);
        mock.lock().unwrap().inject(proxy_syn);
        assert!(dp.process_one().expect("direct syn"));
        assert!(dp.process_one().expect("proxy syn"));

        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 2, "one SYN-ACK per flow: {written:?}");
        for pkt in &written {
            let (src_ip, src_port, _dst_ip, dst_port) =
                syn_ack_of(pkt).expect("written packet is a SYN-ACK");
            match dst_port {
                57364 => {
                    assert_eq!(
                        src_ip,
                        Ipv4Addr::new(127, 0, 0, 1),
                        "direct flow must keep its own orig_dst"
                    );
                    assert_eq!(src_port, direct_port);
                }
                57365 => {
                    assert_eq!(
                        src_ip,
                        Ipv4Addr::new(10, 200, 3, 3),
                        "proxy flow must keep its own orig_dst"
                    );
                    assert_eq!(src_port, 8080);
                }
                other => panic!("unexpected SYN-ACK for client port {other}"),
            }
        }
        drop(listener);
    }

    /// P6-e ④：TUN Direct / Proxy 各产生恰好一条 `flow_decision`（frontend=tun），
    /// 字段值与决策一致（spec §11.2 字段序）。
    #[test]
    fn tun_flow_decision_once_per_flow_with_decision_values() {
        let (mut dp, _mock) = tun_fixup_dataplane();
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![
            Rule {
                cidr: "10.200.2.2/32".parse().expect("cidr"),
                target: nexus_domain::RouteTarget::Egress {
                    peer: "self".to_string(),
                },
            },
            Rule {
                cidr: "10.200.3.3/32".parse().expect("cidr"),
                target: nexus_domain::RouteTarget::Egress {
                    peer: "p1".to_string(),
                },
            },
        ])));
        let direct_syn = craft_tcp(
            [10, 200, 1, 2],
            [10, 200, 2, 2],
            57364,
            8080,
            1000,
            0,
            0x02,
            &[],
        );
        let proxy_syn = craft_tcp(
            [10, 200, 1, 3],
            [10, 200, 3, 3],
            57365,
            8080,
            2000,
            0,
            0x02,
            &[],
        );

        let mut emitted = Vec::new();
        // 每流三个包：只有首包（决策缓存 miss）允许发事件。
        for _ in 0..3 {
            for pkt in [&direct_syn, &proxy_syn] {
                let (classification, fresh) = dp.classify_with_cache(pkt, 10);
                assert!(matches!(
                    classification,
                    Classification::Direct | Classification::Proxy { .. }
                ));
                if let Some(decision) = fresh {
                    emitted.push(
                        dp.tun_flow_decision_line(pkt, &decision)
                            .expect("flow decision line"),
                    );
                }
            }
        }
        assert_eq!(
            emitted.len(),
            2,
            "exactly one flow_decision per TUN flow: {emitted:?}"
        );

        let direct_line = emitted
            .iter()
            .find(|line| line.contains("flow=10.200.1.2:57364"))
            .expect("direct flow decision");
        assert_eq!(
            direct_line,
            "[nexusd.dataplane] level=info event=flow_decision \
flow=10.200.1.2:57364->10.200.2.2:8080 proto=tcp frontend=tun \
matched_rule=IP-CIDR,10.200.2.2/32 egress_hint=- outbound=self session=-"
        );

        let proxy_line = emitted
            .iter()
            .find(|line| line.contains("flow=10.200.1.3:57365"))
            .expect("proxy flow decision");
        assert_eq!(
            proxy_line,
            "[nexusd.dataplane] level=info event=flow_decision \
flow=10.200.1.3:57365->10.200.3.3:8080 proto=tcp frontend=tun \
matched_rule=IP-CIDR,10.200.3.3/32 egress_hint=p1 outbound=p1 session=-"
        );

        // 端到端：同一流两包只算一次新流（发射点由缓存 miss 触发）。
        let (mut dp2, mock2) = tun_fixup_dataplane();
        dp2.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "10.200.3.3/32".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        mock2.lock().unwrap().inject(proxy_syn.clone());
        assert!(dp2.process_one().expect("first proxy syn"));
        mock2.lock().unwrap().inject(proxy_syn);
        assert!(dp2.process_one().expect("retransmitted proxy syn"));
        let cache = dp2.decision_cache_stats();
        assert_eq!(cache.misses, 1, "only the first packet is a new flow");
        assert_eq!(cache.hits, 1, "the retransmission reuses the decision");
    }

    // ===== P8b：纯单流静默窗口的空闲 tick 泵送（fix-review-r7 F1） =====
    //
    // r8 真实形状：客户端发完请求后不再有任何包，上游响应在最后一个入站包
    // 处理之后才入队。旧实现只有 `Classification::Proxy` 分支才会 `poll`
    // engine，因此响应滞留到客户端超时 FIN。这里在 dataplane 层复现：客户端
    // 静默后只驱动主循环实际入口 `Dataplane::tick`，断言回程在有界 tick 内
    // 写回 TUN 且字节内容正确。

    /// 解析写回包的应用层载荷与 TCP seq（非 TCP/无载荷返回空）。
    fn written_tcp_seq_payload(pkt: &[u8]) -> Option<(u32, Vec<u8>)> {
        if pkt.len() < 40 || pkt[9] != 6 {
            return None;
        }
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        let doff = usize::from(pkt[ihl + 12] >> 4) * 4;
        let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        if total < ihl + doff || pkt.len() < total {
            return None;
        }
        let seq = u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]);
        Some((seq, pkt[ihl + doff..total].to_vec()))
    }

    /// 装配 proxy 数据面：`10.200.3.3/32` 走 socks5 出站（locator 指向测试替身）。
    fn silent_window_dataplane(
        socks_addr: std::net::SocketAddr,
    ) -> (Dataplane, Arc<Mutex<nexus_projection::MockTun>>) {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            n1_configured: true,
            proxy_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "10.200.3.3/32".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        let yaml = format!(
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: p1\noutbounds:\n  - tag: p1\n    kind: socks5\n    locator: {socks_addr}\n"
        );
        dp.set_proxy_engine(crate::proxy_fwd::ProxyEngine::new(&yaml).expect("proxy engine"));
        (dp, mock)
    }

    /// 核心回归：零入站包、仅 tick → 静默窗口内的响应必须写回 TUN。
    #[test]
    fn idle_tick_pumps_silent_proxy_response_without_inbound_packets() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        // socks5 测试替身：完成握手/CONNECT 应答，把“上游侧”连接交还测试；
        // 不模拟真实代理语义，只让 `ProxyEngine` 走完整拨号 + 中继线程。
        let socks = TcpListener::bind("127.0.0.1:0").expect("bind socks stub");
        let socks_addr = socks.local_addr().expect("socks addr");
        let (upstream_tx, upstream_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut conn, _) = socks.accept().expect("socks accept");
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout");
            let mut greeting = [0u8; 2];
            conn.read_exact(&mut greeting).expect("socks greeting");
            assert_eq!(greeting[0], 5, "socks5 version");
            let mut methods = vec![0u8; usize::from(greeting[1])];
            conn.read_exact(&mut methods).expect("socks methods");
            conn.write_all(&[5, 0]).expect("method reply");
            let mut head = [0u8; 4];
            conn.read_exact(&mut head).expect("socks request head");
            assert_eq!((head[0], head[1]), (5, 1), "CONNECT request");
            match head[3] {
                1 => {
                    let mut addr = [0u8; 4];
                    conn.read_exact(&mut addr).expect("ipv4 addr");
                }
                3 => {
                    let mut len = [0u8; 1];
                    conn.read_exact(&mut len).expect("domain len");
                    let mut addr = vec![0u8; usize::from(len[0])];
                    conn.read_exact(&mut addr).expect("domain addr");
                }
                4 => {
                    let mut addr = [0u8; 16];
                    conn.read_exact(&mut addr).expect("ipv6 addr");
                }
                other => panic!("unexpected ATYP {other}"),
            }
            let mut port = [0u8; 2];
            conn.read_exact(&mut port).expect("port");
            conn.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
            // 读到客户端 GET 即证明中继已把请求送出；此后客户端静默。
            let mut req = [0u8; 512];
            let n = conn.read(&mut req).expect("upstream request");
            assert!(n > 0, "relay forwarded the client request");
            upstream_tx.send(conn).expect("hand over proxy stream");
        });

        let (mut dp, mock) = silent_window_dataplane(socks_addr);
        let client_ip = [10, 200, 1, 2];
        let server_ip = [10, 200, 3, 3];
        let client_port = 57365u16;
        let server_port = 8080u16;
        let mut now = 0u64;

        // 握手：SYN → SYN-ACK（经 tick 写回）。
        let syn = craft_tcp(
            client_ip,
            server_ip,
            client_port,
            server_port,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        now += 1;
        assert!(dp.tick(now).expect("tick syn"));
        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 1, "SYN-ACK expected: {written:?}");
        let server_isn1 = syn_ack_srv_seq(&written[0]) + 1;

        // ACK + GET：最后一个入站包。
        let ack = craft_tcp(
            client_ip,
            server_ip,
            client_port,
            server_port,
            1001,
            server_isn1,
            0x10,
            &[],
        );
        mock.lock().unwrap().inject(ack);
        now += 1;
        assert!(dp.tick(now).expect("tick ack"));
        let get = craft_tcp(
            client_ip,
            server_ip,
            client_port,
            server_port,
            1001,
            server_isn1,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        mock.lock().unwrap().inject(get);
        now += 1;
        assert!(dp.tick(now).expect("tick get"));

        // 等拨号完成 + GET 送达上游（这段时间仍靠 tick 泵送 relay 事件）。
        let mut upstream = None;
        for _ in 0..5_000 {
            now += 1;
            let _ = dp.tick(now).expect("tick during dial");
            let _ = mock.lock().unwrap().take_written();
            match upstream_rx.recv_timeout(Duration::from_millis(1)) {
                Ok(conn) => {
                    upstream = Some(conn);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(e) => panic!("upstream handoff failed: {e}"),
            }
        }
        let mut upstream = upstream.expect("proxy dial + relay within tick budget");

        // 客户端从此完全静默：不再向 MockTun 注入任何包。
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        upstream
            .write_all(&response)
            .expect("write upstream response");
        assert!(
            mock.lock().unwrap().take_written().is_empty(),
            "client is silent before the response"
        );

        // 只驱动主循环实际入口 tick；有界 tick 内必须把响应写回 TUN。
        let mut payload = Vec::new();
        let mut segments: Vec<(u32, usize)> = Vec::new();
        let mut ticks_used = 0usize;
        for _ in 0..200 {
            now += 1;
            let _ = dp.tick(now).expect("idle tick");
            ticks_used += 1;
            for pkt in mock.lock().unwrap().take_written() {
                if let Some((seq, bytes)) = written_tcp_seq_payload(&pkt) {
                    if !bytes.is_empty() {
                        assert!(
                            payload.len() + bytes.len() <= response.len(),
                            "no bytes beyond the response"
                        );
                        segments.push((seq, bytes.len()));
                        payload.extend_from_slice(&bytes);
                    }
                }
            }
            if payload.len() == response.len() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(
            payload, response,
            "silent-window response must be delivered by idle ticks"
        );
        assert!(
            ticks_used < 200,
            "response must be pumped within the bounded tick budget"
        );
        // 分段 seq 必须按写回顺序连续递增（同流不乱序）。
        let mut expect_seq = server_isn1;
        for (idx, (seq, len)) in segments.iter().enumerate() {
            assert_eq!(*seq, expect_seq, "data segment {idx} seq order");
            expect_seq += u32::try_from(*len).expect("segment len");
        }
        assert_eq!(
            usize::try_from(expect_seq - server_isn1).expect("bytes pumped"),
            response.len()
        );
        drop(upstream);
    }

    /// 无待办时 tick 零副作用：有 engine 但无回程 → 不写 TUN、返回 false。
    #[test]
    fn idle_tick_without_pending_proxy_output_is_noop() {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            n1_configured: true,
            proxy_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        dp.set_proxy_engine(
            crate::proxy_fwd::ProxyEngine::new(P6_PROXY_YAML).expect("proxy engine"),
        );
        assert!(!dp.tick(1).expect("idle tick"), "no work reported");
        assert!(
            mock.lock().unwrap().take_written().is_empty(),
            "no TUN write without pending proxy output"
        );
        assert_eq!(dp.stats().tun_written, 0);
    }

    // --- P9（fix-r9）：失败原因持久化（`tproxy.last_failure_reason`） ---------

    /// 同步建连失败分支：计数与 `last_failure_reason` 同点写入。
    #[test]
    #[allow(unused_mut)]
    fn tproxy_sync_establish_failure_persists_last_failure() {
        use nexus_projection::transparent::TransparentFrontendError;

        let (mut dp, _mock) = test_dataplane();
        let error = TransparentFrontendError::SessionEstablishFailed {
            flow: "10.0.0.2:40000->10.0.0.9:8080".to_string(),
            reason: "socks5 connect refused".to_string(),
        };
        dp.record_transparent_error(&error);

        assert_eq!(dp.tproxy_counters().upstream_failed, 1);
        let reason = dp
            .tproxy_last_failure()
            .expect("establish failure must set last_failure_reason");
        assert!(reason.contains("upstream_failed"), "{reason}");
        assert!(reason.contains("socks5 connect refused"), "{reason}");
    }

    /// 异步拨号失败（生产 S5 路径）：`ProxyEgressEvent::Failed` 的原因不得被丢弃。
    #[test]
    fn tproxy_async_proxy_dial_failure_persists_last_failure() {
        use nexus_projection::egress::FlowKey as ProjectionFlowKey;
        use nexus_projection::transparent::direct::DirectEgress;
        use nexus_projection::transparent::runtime::TransparentPipeline;
        use nexus_projection::transparent::{
            ProxyEgressEvent, ProxyFlowEgress, TransparentConfig, TransparentDeps,
            TransparentFrontendError,
        };

        struct FailingEgress {
            key: ProjectionFlowKey,
            dispatched: bool,
        }
        impl ProxyFlowEgress for FailingEgress {
            fn open_tcp(
                &mut self,
                _key: ProjectionFlowKey,
                _orig_dst: std::net::SocketAddrV4,
                _tag: &str,
            ) -> Result<(), TransparentFrontendError> {
                Ok(())
            }
            fn write_tcp(
                &mut self,
                _key: &ProjectionFlowKey,
                _bytes: &[u8],
            ) -> Result<(), TransparentFrontendError> {
                Ok(())
            }
            fn close_tcp(&mut self, _key: &ProjectionFlowKey) {}
            fn send_udp(
                &mut self,
                _key: ProjectionFlowKey,
                _orig_dst: std::net::SocketAddrV4,
                _payload: &[u8],
            ) -> Result<(), TransparentFrontendError> {
                Ok(())
            }
            fn poll(&mut self) -> Vec<ProxyEgressEvent> {
                if self.dispatched {
                    return Vec::new();
                }
                self.dispatched = true;
                vec![ProxyEgressEvent::Failed {
                    key: self.key,
                    reason: "socks5 connect refused".to_string(),
                }]
            }
        }

        let key = ProjectionFlowKey {
            src_ip: u32::from(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: u32::from(std::net::Ipv4Addr::new(10, 0, 0, 9)),
            src_port: 40_000,
            dst_port: 8080,
            proto: 6,
        };
        let pipeline = TransparentPipeline::new(TransparentDeps {
            proxy_egress: Some(Box::new(FailingEgress {
                key,
                dispatched: false,
            })),
            direct: DirectEgress::new(DirectEgressConfig::default()).expect("direct egress"),
            config: TransparentConfig::default(),
        });
        let (mut dp, _mock) = test_dataplane();
        let (reply_tx, _reply_rx) = std::sync::mpsc::channel();
        dp.set_transparent_pipeline(pipeline, reply_tx);

        dp.poll_transparent(1);
        assert_eq!(dp.tproxy_counters().upstream_failed, 1);
        let reason = dp
            .tproxy_last_failure()
            .expect("async dial failure must set last_failure_reason");
        assert!(reason.contains("upstream_failed"), "{reason}");
        assert!(reason.contains("socks5 connect refused"), "{reason}");
    }

    /// 语义：后者覆盖前者；成功后不清除（last *failure* reason）。
    #[test]
    fn tproxy_last_failure_tracks_latest_and_survives_success() {
        use nexus_projection::transparent::TransparentFrontendError;

        let (mut dp, _mock) = test_dataplane();
        dp.record_transparent_error(&TransparentFrontendError::SessionEstablishFailed {
            flow: "flow-a".to_string(),
            reason: "first failure".to_string(),
        });
        dp.record_transparent_error(&TransparentFrontendError::DirectDialFailed {
            dst: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 9), 8080),
            reason: "second failure".to_string(),
        });
        let latest = dp
            .tproxy_last_failure()
            .expect("latest failure")
            .to_string();
        assert!(latest.contains("direct_tcp_dial_failed"), "{latest}");
        assert!(latest.contains("second failure"), "{latest}");

        // 一次成功 tick（无失败）不得清空 last_failure_reason。
        let _ = dp.tick(1).expect("idle tick");
        assert_eq!(dp.tproxy_last_failure(), Some(latest.as_str()));
    }

    /// TUN 前端：代理拨号失败（流事件）同样写入同一发布面。
    #[test]
    fn tun_proxy_dial_failure_persists_last_failure() {
        let refused = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
            listener.local_addr().expect("probe addr")
        };
        let (mut dp, mock) = silent_window_dataplane(refused);
        let client_ip = [10, 200, 1, 2];
        let server_ip = [10, 200, 3, 3];
        let syn = craft_tcp(client_ip, server_ip, 57_365, 8080, 1000, 0, 0x02, &[]);
        mock.lock().unwrap().inject(syn);
        assert!(dp.tick(1).expect("tick syn"));
        let syn_ack = mock.lock().unwrap().take_written();
        assert!(!syn_ack.is_empty(), "SYN-ACK expected");
        let srv_seq = syn_ack_srv_seq(&syn_ack[0]) + 1;
        let ack = craft_tcp(client_ip, server_ip, 57_365, 8080, 1001, srv_seq, 0x10, &[]);
        mock.lock().unwrap().inject(ack);
        assert!(dp.tick(2).expect("tick ack"));

        let mut seen = None;
        for step in 0..2_000u64 {
            let _ = dp.tick(3 + step).expect("tick");
            if let Some(reason) = dp.tproxy_last_failure() {
                seen = Some(reason.to_string());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let reason = seen.expect("TUN dial failure must set last_failure_reason");
        assert!(reason.contains("upstream_failed"), "{reason}");
    }

    /// TUN 流会话建连失败（AC-G4-03）：与计数同点写入。
    #[test]
    fn tun_flow_session_failure_persists_last_failure() {
        use nexus_domain::RouteTarget;
        use nexus_projection::egress::{Rule, SimpleRuleEngine};

        struct FailingEstablisher;
        impl ConnectivityEstablisher for FailingEstablisher {
            fn establish(
                &mut self,
                _session_id: &SessionId,
                _planned: &nexus_flow_session::Planned,
            ) -> Result<String, String> {
                Err("provider unavailable".to_string())
            }
        }

        let yaml = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1080
";
        let (mut dp, mock) = test_dataplane();
        dp.set_production_chain_deps(
            ProductionChainDeps::from_config(None, Some(yaml)).expect("deps"),
        );
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().expect("cidr"),
            target: RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        dp.enable_flow_sessions_with_establisher(Box::new(FailingEstablisher));

        let syn = craft_tcp(
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            40_000,
            443,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("syn"));

        let mut seen = None;
        for step in 0..2_000u64 {
            let _ = dp.tick(step).expect("tick");
            if let Some(reason) = dp.tproxy_last_failure() {
                seen = Some(reason.to_string());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(dp.flow_establish_failures() >= 1, "establish failure count");
        let reason = seen.expect("TUN flow-session failure must set last_failure_reason");
        assert!(reason.contains("session_establish_failed"), "{reason}");
        assert!(reason.contains("provider unavailable"), "{reason}");
    }
}
