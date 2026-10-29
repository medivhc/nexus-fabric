//! Composition Root 装配胶水（R1/R2/R3，`docs/DAEMON_ARCHITECTURE.md` §13）。
//!
//! Binary (`main.rs`) 是装配的执行者；本模块提供可测试的纯装配逻辑：
//! - `parse_mesh_cidrs`：从 `network.toml [vpi.routes]` 派生 mesh CIDR（R2）；
//! - `parse_mesh_cidrs6`：从 `network.toml [vpi.routes6]` 派生 v6 mesh CIDR（C18）；
//! - `assemble_n1`：构造 `N1MeshBridge` 并尽力 dial（R1）；
//! - `build_dataplane_config`：组装 `DataplaneConfig`（R2/R3）；
//! - `mesh_bypass_overlap`：mesh/bypass 重叠检测（R2 warn）。
//!
//! 降级语义（§13.3）：N1/DNS 组装失败不阻断 dataplane（计数降级）；
//! 只有 TUN 失败是致命的（由 main.rs 处理）。

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use nexus_discovery::DiscoveryHub;
use nexus_fabric::{FabricIdentity, PeerId as FabricPeerId};
use nexus_network::n1::bridge::N1MeshBridge;
use nexus_network::n1::{N1Error, N1PeerId, config::N1Config, session::N1SessionManager};

use super::config::{self, LoadedConfig};
use super::dataplane::DataplaneConfig;

/// 从 `network.toml` 文本派生 mesh CIDR 列表（R2）。
///
/// 来源为 `[vpi.routes]` 的 subnet 字段（`"A.B.C.D/N"` 字符串）；
/// 不再硬编码 `10.0.0.0/8`。
///
/// # Errors
/// - `network.toml` 语义解析失败（`N1Config::parse_toml`）→ `Err`；
///   调用方按 R2 降级为空列表 + warn。
pub fn parse_mesh_cidrs(network_toml: &str) -> Result<Vec<String>, String> {
    let config = nexus_network::n1::config::N1Config::parse_toml(network_toml)
        .map_err(|e| format!("parse network.toml: {e:?}"))?;
    Ok(config
        .vpi
        .routes
        .iter()
        .map(|r| format!("{}/{}", r.subnet.network_addr(), r.subnet.prefix_len()))
        .collect())
}

/// 从 `network.toml` 文本派生 v6 mesh CIDR 列表（C18）。
///
/// 来源为 `[vpi.routes6]` 的 subnet 字段（`"fd00:144::/64"`）；
/// 与 `parse_mesh_cidrs` 同一解析器（`N1Config::parse_toml`），不另写一套。
///
/// # Errors
/// - `network.toml` 语义解析失败 → `Err`；调用方降级为空列表 + warn。
pub fn parse_mesh_cidrs6(network_toml: &str) -> Result<Vec<String>, String> {
    let config = nexus_network::n1::config::N1Config::parse_toml(network_toml)
        .map_err(|e| format!("parse network.toml: {e:?}"))?;
    Ok(config
        .vpi
        .routes6
        .iter()
        .map(|r| format!("{}/{}", r.subnet.network_addr(), r.subnet.prefix_len()))
        .collect())
}

/// v6 bypass 默认集合（与 v4 的 `192.168/16`、`172.16/12` 对等，spec §4.7.3）。
pub const DEFAULT_BYPASS_CIDRS6: [&str; 3] = ["fc00::/7", "fe80::/10", "::1/128"];

/// 检测 mesh CIDR 与 bypass CIDR 的重叠（R2）。
///
/// 返回重叠的 mesh CIDR 字符串列表；非空时调用方记 warn 日志
/// （mesh 优先，分类器 S29 顺序不变）。
/// 解析失败的 CIDR 条目被忽略（Dataplane::new 会再次校验并报错）。
pub fn mesh_bypass_overlap(mesh: &[String], bypass: &[String]) -> Vec<String> {
    let parse = |s: &str| -> Option<(u32, u8)> {
        let (addr_s, prefix_s) = s.split_once('/')?;
        let addr: std::net::Ipv4Addr = addr_s.parse().ok()?;
        let prefix: u8 = prefix_s.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        Some((u32::from(addr) & mask, prefix))
    };
    let overlaps = |a: (u32, u8), b: (u32, u8)| -> bool {
        let min_prefix = a.1.min(b.1);
        let mask = if min_prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - min_prefix)
        };
        (a.0 & mask) == (b.0 & mask)
    };
    let bypass_nets: Vec<(u32, u8)> = bypass.iter().filter_map(|s| parse(s)).collect();
    mesh.iter()
        .filter(|m| parse(m).is_some_and(|mn| bypass_nets.iter().any(|&bn| overlaps(mn, bn))))
        .cloned()
        .collect()
}

/// 装配 N1 网桥（R1；§13.3 步骤 5）。
///
/// - 解析 `network.toml` → 构造 `N1SessionManager`（复用 `nexus::network`
///   的装配器，不复制 dial/discovery 逻辑）；
/// - 由 `vpi.routes` 构造 `N1MeshBridge`；
/// - 各 peer `dial()` 在后台线程尽力而为（不阻塞 daemon 启动；单 peer
///   失败记 warn，不中断，降级语义）。
///
/// `proxy` 为 `[network.proxy]` 配置（#3 fabric-over-proxy）；`shutdown` 是
/// daemon 关闭标志，用于 fallback 的协作式取消。
///
/// # Errors
/// - 配置解析失败；
/// - `[network.proxy]` 映射为可拨号 `ProxyConfig` 失败；
/// - SessionManager 构造失败。
///
/// 调用方按 §13.3 降级：不调 `set_n1_sender`，dataplane 照常跑。
#[derive(Clone)]
pub struct N1Assembly {
    pub bridge: Arc<N1MeshBridge>,
    pub sessions: Arc<N1SessionManager>,
    pub discovery: Arc<DiscoveryHub>,
    /// Static peer ids only (the addresses live in `config.peers`; the hub's
    /// static source keeps just `addrs[0]`, CR-2).
    pub static_peers: Vec<N1PeerId>,
    /// The one authoritative `N1Config` copy for this run.
    pub config: N1Config,
}

/// 拨号退避初值（spec §8.1 `N1_DIAL_RETRY_INITIAL_MS`）。
pub const N1_DIAL_RETRY_INITIAL_MS: u64 = 1000;

/// 拨号退避封顶（spec §8.1 `N1_DIAL_RETRY_MAX_MS`）。
pub const N1_DIAL_RETRY_MAX_MS: u64 = 30000;

/// 已连接 peer 的存活轮询间隔。复用退避初值，不引入新的量化判据。
const N1_DIAL_CONNECTED_POLL_MS: u64 = N1_DIAL_RETRY_INITIAL_MS;

/// shutdown 响应粒度（既有 accept 退化用 100ms；这里只影响退出延迟）。
const N1_DIAL_SHUTDOWN_SLICE_MS: u64 = 100;

/// 可注入时钟：测试用虚拟时间，生产用单调 `Instant`。
trait DialClock {
    fn now_ms(&self) -> u64;
    /// 等待 `ms`；返回 `false` 表示 shutdown 已置位、调用方应退出。
    fn sleep_ms(&self, ms: u64, shutdown: &AtomicBool) -> bool;
}

struct SystemDialClock {
    start: std::time::Instant,
}

impl SystemDialClock {
    fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}

impl DialClock for SystemDialClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep_ms(&self, ms: u64, shutdown: &AtomicBool) -> bool {
        let mut remaining = ms;
        while remaining > 0 {
            if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                return false;
            }
            let slice = remaining.min(N1_DIAL_SHUTDOWN_SLICE_MS);
            std::thread::sleep(std::time::Duration::from_millis(slice));
            remaining -= slice;
        }
        !shutdown.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// dial 生命周期只需要会话表的两个操作，测试可用替身注入。
trait DialSessions {
    fn connected(&self, peer: &N1PeerId) -> bool;
    fn dial(&self, peer: &N1PeerId) -> Result<(), N1Error>;
}

struct SessionDialPort<'a> {
    sessions: &'a N1SessionManager,
}

impl DialSessions for SessionDialPort<'_> {
    fn connected(&self, peer: &N1PeerId) -> bool {
        self.sessions.connection_for(peer).is_some()
    }

    fn dial(&self, peer: &N1PeerId) -> Result<(), N1Error> {
        self.sessions.dial(peer)
    }
}

fn dial_peer_hex(peer: &N1PeerId) -> String {
    peer.to_hex().chars().take(16).collect()
}

fn dial_ok_log(peer: &N1PeerId, attempt: u64) -> String {
    format!(
        "[n1-dial] peer={} attempt={attempt} result=ok",
        dial_peer_hex(peer)
    )
}

fn n1_error_kind(error: &N1Error) -> &'static str {
    match error {
        N1Error::Transport(_) => "Transport",
        N1Error::PeerUnknown => "PeerUnknown",
        N1Error::Closed => "Closed",
        N1Error::PeerClosed(_) => "PeerClosed",
        N1Error::Timeout => "Timeout",
        N1Error::OversizeDatagram(_) => "OversizeDatagram",
        N1Error::InvalidConfig(_) => "InvalidConfig",
    }
}

fn dial_err_log(peer: &N1PeerId, attempt: u64, error: &N1Error) -> String {
    format!(
        "[n1-dial] peer={} attempt={attempt} result=err kind={}",
        dial_peer_hex(peer),
        n1_error_kind(error)
    )
}

struct DialPeerState {
    peer: N1PeerId,
    attempt: u64,
    backoff_ms: u64,
    next_at_ms: u64,
    was_connected: bool,
}

/// 定版拨号生命周期（spec §5.1）：
/// - tie-break：只有 `my_id.0 < peer.0` 一侧拨号；大 id 只等 accept；
/// - 失败按 1000ms 起、×2、封顶 30000ms 退避重试；
/// - 成功停拨，仅轮询连接存活；连接被 `remove` 后按同一退避序重拨；
/// - 自 peer 不拨，输出逐字 WARN 句。
fn run_dial_lifecycle(
    my_id: N1PeerId,
    peers: &[N1PeerId],
    sessions: &dyn DialSessions,
    clock: &dyn DialClock,
    shutdown: &AtomicBool,
    log: &mut dyn FnMut(String),
) {
    let mut states: Vec<DialPeerState> = Vec::new();
    for &peer in peers {
        if peer == my_id {
            log("[n1-dial] self peer skipped".to_string());
            continue;
        }
        if my_id.0 >= peer.0 {
            // 大 id 只等 accept；双向拨号会互相 close（spec §5.1）。
            continue;
        }
        states.push(DialPeerState {
            peer,
            attempt: 0,
            backoff_ms: N1_DIAL_RETRY_INITIAL_MS,
            next_at_ms: 0,
            was_connected: false,
        });
    }
    if states.is_empty() {
        return;
    }

    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let now = clock.now_ms();
        let mut next_wake_ms = u64::MAX;
        for state in &mut states {
            if sessions.connected(&state.peer) {
                if !state.was_connected {
                    state.was_connected = true;
                    state.attempt = 0;
                    state.backoff_ms = N1_DIAL_RETRY_INITIAL_MS;
                    state.next_at_ms = now.saturating_add(N1_DIAL_CONNECTED_POLL_MS);
                }
                if now >= state.next_at_ms {
                    state.next_at_ms = now.saturating_add(N1_DIAL_CONNECTED_POLL_MS);
                }
                next_wake_ms = next_wake_ms.min(state.next_at_ms);
                continue;
            }

            state.was_connected = false;
            if now < state.next_at_ms {
                next_wake_ms = next_wake_ms.min(state.next_at_ms);
                continue;
            }

            state.attempt += 1;
            match sessions.dial(&state.peer) {
                Ok(()) => {
                    log(dial_ok_log(&state.peer, state.attempt));
                    state.attempt = 0;
                    state.backoff_ms = N1_DIAL_RETRY_INITIAL_MS;
                    state.was_connected = true;
                    state.next_at_ms = now.saturating_add(N1_DIAL_CONNECTED_POLL_MS);
                }
                Err(error) => {
                    log(dial_err_log(&state.peer, state.attempt, &error));
                    state.next_at_ms = now.saturating_add(state.backoff_ms);
                    state.backoff_ms = state.backoff_ms.saturating_mul(2).min(N1_DIAL_RETRY_MAX_MS);
                }
            }
            next_wake_ms = next_wake_ms.min(state.next_at_ms);
        }

        if next_wake_ms == u64::MAX {
            // 不可达：每个 state 要么 connected、要么已排定 next_at。
            debug_assert!(false, "dial lifecycle has no scheduled wake");
            return;
        }
        let wait_ms = next_wake_ms.saturating_sub(clock.now_ms()).max(1);
        if !clock.sleep_ms(wait_ms, shutdown) {
            return;
        }
    }
}

/// 从 `network.toml` 的 `peer_id` 与 seed 派生 mTLS 身份（dial 与 listen 共用）。
///
/// # Errors
/// - `network.toml` 解析失败；
/// - seed 与 `peer_id` 不匹配（`nat_relay::identity_from_seed`）。
pub fn identity_from_network_seed(
    network_toml: &str,
    seed: [u8; 32],
) -> Result<FabricIdentity, String> {
    let config =
        N1Config::parse_toml(network_toml).map_err(|e| format!("parse network.toml: {e:?}"))?;
    crate::nat_relay::identity_from_seed(seed, FabricPeerId(config.peer_id.0))
        .map_err(|e| e.to_string())
}

/// Assemble N1 with the single discovery hub (daemon path).
///
/// The hub, the N1 session manager and the returned assembly share one
/// instance; the background dial thread follows the frozen WP2 lifecycle
/// (tie-break ownership + exponential retry, spec §5.1).
pub fn assemble_n1_with_discovery(
    network_toml: &str,
    proxy: Option<&config::ProxySection>,
    shutdown: Arc<AtomicBool>,
    params: nexus::network::DiscoveryParams,
    identity: Option<FabricIdentity>,
) -> Result<N1Assembly, String> {
    let proxy_cfg = match proxy {
        Some(section) => Some(proxy_config_from(section)?),
        None => None,
    };
    let cancel = Arc::clone(&shutdown);
    let (config, sessions, discovery) = match identity {
        Some(identity) => nexus::network::build_session_manager_with_discovery_mtls(
            network_toml,
            proxy_cfg,
            cancel,
            params,
            identity,
        )?,
        None => nexus::network::build_session_manager_with_discovery(
            network_toml,
            proxy_cfg,
            cancel,
            params,
        )?,
    };
    let bridge = Arc::new(N1MeshBridge::new(
        Arc::clone(&sessions),
        config.vpi.routes.clone(),
        config.vpi.routes6.clone(),
    ));
    eprintln!(
        "[nexusd] N1 bridge assembled: {} routes",
        bridge.route_count()
    );
    let static_peers: Vec<N1PeerId> = config.peers.iter().map(|p| p.id).collect();
    // 后台 dial：不阻塞启动；按定版生命周期重试/重拨（降级）。
    let my_id = config.peer_id;
    let peers = static_peers.clone();
    let dial_sessions = Arc::clone(&sessions);
    let dial_shutdown = Arc::clone(&shutdown);
    std::thread::Builder::new()
        .name("nexusd-n1-dial".to_string())
        .spawn(move || {
            let port = SessionDialPort {
                sessions: &dial_sessions,
            };
            let clock = SystemDialClock::new();
            let mut log = |line: String| eprintln!("{line}");
            run_dial_lifecycle(my_id, &peers, &port, &clock, &dial_shutdown, &mut log);
        })
        .map_err(|e| format!("spawn n1 dial thread: {e}"))?;
    Ok(N1Assembly {
        bridge,
        sessions,
        discovery,
        static_peers,
        config,
    })
}

/// Compat wrapper (static-only discovery, no pump): returns the bridge only.
pub fn assemble_n1(
    network_toml: &str,
    proxy: Option<&config::ProxySection>,
    shutdown: Arc<AtomicBool>,
) -> Result<Arc<N1MeshBridge>, String> {
    Ok(assemble_n1_with_discovery(
        network_toml,
        proxy,
        shutdown,
        nexus::network::DiscoveryParams::static_only(),
        None,
    )?
    .bridge)
}

/// 把 `[network.proxy]` 配置节映射为 `nexus::network::ProxyConfig`（#3 AC3）。
///
/// # Errors
/// - `method` 非法（仅 shadowsocks 校验）。
pub fn proxy_config_from(
    section: &config::ProxySection,
) -> Result<nexus::network::ProxyConfig, String> {
    use nexus_proxy_transport::{
        Socks5Auth, Socks5ProxyConfig, SsMethod, SsProxyConfig, TrojanTlsConfig,
    };

    let connect_timeout = std::time::Duration::from_secs(section.connect_timeout_sec);
    let handshake_timeout = std::time::Duration::from_secs(section.handshake_timeout_sec);
    match section.proxy_type {
        config::ProxyType::Socks5 => {
            // socks5：username+password 同时存在 → RFC1929 认证；否则无认证。
            let auth = match (&section.username, &section.password) {
                (Some(u), Some(p)) => Some(Socks5Auth {
                    username: u.clone(),
                    password: p.clone(),
                }),
                _ => None,
            };
            Ok(nexus::network::ProxyConfig::Socks5(Socks5ProxyConfig {
                server: section.server,
                auth,
                connect_timeout,
                handshake_timeout,
            }))
        }
        config::ProxyType::Shadowsocks => {
            let method = match section.method.as_deref() {
                Some(m) => SsMethod::parse(m).map_err(|e| format!("bad ss method: {e:?}"))?,
                None => SsMethod::Chacha20IetfPoly1305,
            };
            Ok(nexus::network::ProxyConfig::Shadowsocks(SsProxyConfig {
                server: section.server,
                method,
                password: section.password.clone().unwrap_or_default(),
                connect_timeout,
                handshake_timeout,
            }))
        }
        config::ProxyType::Trojan => {
            // #3 BLOCKER：真实 trojan 服务端一律在 TLS 内握手；代理 tier 恒走
            // `TlsTrojanTransport`（明文 `TrojanTransport` 对真实节点永远连不上）。
            // SNI 缺省从 server 推导（config 层已补，这里是防御性回退）。
            let sni = section
                .sni
                .clone()
                .unwrap_or_else(|| section.server.ip().to_string());
            let mut cfg = TrojanTlsConfig::new(
                section.server,
                section.password.clone().unwrap_or_default(),
                sni,
            );
            cfg.skip_cert_verify = section.skip_cert_verify;
            cfg.alpn = section
                .alpn
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(String::into_bytes)
                .collect();
            cfg.connect_timeout = connect_timeout;
            cfg.handshake_timeout = handshake_timeout;
            Ok(nexus::network::ProxyConfig::Trojan(cfg))
        }
    }
}

/// 从 `LoadedConfig` 组装 `DataplaneConfig`（R2/R3；原 main.rs 逻辑下沉）。
///
/// - R2：`mesh_cidrs` 取自 `network.toml [vpi.routes]`；解析失败 → 空列表
///   （调用方已记 warn 语义，此处静默降级由 `parse_mesh_cidrs` 的 Err 分支处理，
///   eprintln 在此处发出以保证可观测）；
/// - R3：`dns.toml` 存在 → `parse_dns_toml`；失败 → 返回 `Err`
///   （main.rs 转为 exit 1 + CONFIG 错误）。
///
/// # Errors
/// - `dns.toml` 语义解析失败。
pub fn build_dataplane_config(loaded: &LoadedConfig) -> Result<DataplaneConfig, String> {
    use super::config::parse_dns_toml;

    // R2：mesh CIDR 配置化。
    let mesh_cidrs = match loaded.network_toml.as_deref() {
        Some(text) => match parse_mesh_cidrs(text) {
            Ok(cidrs) => cidrs,
            Err(e) => {
                eprintln!("[nexusd] WARN: {e}; mesh_cidrs empty (degraded)");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    // C18：v6 mesh 网段同样来自 network.toml（[[vpi.routes6]]）；解析失败 → 空。
    let mesh_cidrs6 = match loaded.network_toml.as_deref() {
        Some(text) => match parse_mesh_cidrs6(text) {
            Ok(cidrs) => cidrs,
            Err(e) => {
                eprintln!("[nexusd] WARN: {e}; mesh_cidrs6 empty (degraded)");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    // Bypass：常见内网段（与 Clash Verge 默认一致）。
    let bypass_cidrs = vec!["192.168.0.0/16".to_string(), "172.16.0.0/12".to_string()];
    // C18：v6 bypass（ULA / link-local / loopback；spec §4.7.3）。
    let bypass_cidrs6: Vec<String> = DEFAULT_BYPASS_CIDRS6
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // R2：重叠检测（warn，mesh 优先）。
    let overlapped = mesh_bypass_overlap(&mesh_cidrs, &bypass_cidrs);
    if !overlapped.is_empty() {
        eprintln!("[nexusd] WARN: mesh CIDRs overlap bypass: {overlapped:?} (mesh wins)");
    }

    // QoS：从 daemon.toml [qos] 映射。
    let qos_enabled = loaded.daemon.qos.enabled;
    let mut qos_config = nexus_qos::cake::CakeConfig::default();
    if qos_enabled {
        qos_config.quantum = loaded.daemon.qos.quantum;
        qos_config.high_priority_ports = loaded.daemon.qos.high_priority_ports.clone();
        // mesh/proxy_upload_mbps 映射为 rate_limit（MVP：取最小非零值）。
        let mesh_bps = loaded.daemon.qos.mesh_upload_mbps * 1_000_000 / 8;
        let proxy_bps = loaded.daemon.qos.proxy_upload_mbps * 1_000_000 / 8;
        let rate_bps = match (mesh_bps, proxy_bps) {
            (0, 0) => 0,
            (m, 0) => m,
            (0, p) => p,
            (m, p) => m.min(p),
        };
        if rate_bps > 0 {
            // burst 默认为 1 秒的量。
            // GAP-3：burst < 2×MTU (3028) 会静默拉低实际速率，打 WARN 日志。
            if rate_bps < 3028 {
                eprintln!(
                    "[nexusd] WARN: QoS burst_size={} < 3028 (2×MTU); actual rate will be silently lower than configured. Suggest burst >= 15140 (10×MTU).",
                    rate_bps
                );
            }
            if let Ok(limit) = nexus_qos::bucket::BandwidthLimit::new(rate_bps, rate_bps) {
                qos_config.rate_limit = Some(limit);
            }
        }
    }

    // Boost：从 network.toml [boost] 解析 enabled。
    let boost_enabled = loaded
        .network_toml
        .as_deref()
        .and_then(|s| s.parse::<toml::Value>().ok())
        .and_then(|v| v.get("boost").cloned())
        .and_then(|b| b.get("enabled").cloned())
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    // R3/C11：dns.toml 严格解析（三参数：mesh 网段归属 + 可用出站）。
    // D-impl-6/SU-2：仅 TUN 启用时才解析；no-tun 下非法 dns.toml 不阻塞启动。
    let dns_tun_enabled = loaded.daemon.tun.enabled;
    let has_usable_outbound = match loaded.proxy_yaml.as_deref() {
        Some(yaml) => crate::dns_classify::usable_outbound(yaml).map_err(|e| e.to_string())?,
        None => false,
    };
    let dns_config = if dns_tun_enabled {
        match loaded.dns_toml.as_deref() {
            Some(text) => Some(
                parse_dns_toml(text, loaded.network_toml.as_deref(), has_usable_outbound)
                    .map_err(|e| e.to_string())?,
            ),
            None => None,
        }
    } else {
        None
    };

    Ok(DataplaneConfig {
        mesh_cidrs,
        mesh_cidrs6,
        bypass_cidrs,
        bypass_cidrs6,
        dns_enabled: dns_tun_enabled && loaded.dns_toml.is_some(),
        dns_config,
        qos_enabled,
        qos_config,
        boost_enabled,
        n1_configured: loaded.network_toml.is_some(),
        proxy_configured: loaded.proxy_yaml.is_some(),
        ..DataplaneConfig::default()
    })
}

/// N2 P0-4（D1）：装配 daemon 内唯一的 SessionManager。
///
/// §15 boot 顺序：打开 N2 存储（`<config-dir>/n2/`）→ 加载会话记录 →
/// journal 重放（审计轨迹；尾部撕裂走**显式 discard 路径**，P1-11）→
/// `reconcile_session_records_at`（幂等；用真实 attach window 分类，P1-1：
/// 断开超窗→`Cancelled(ClientDetached)`、窗口内保留、真孤儿→`Failed`）→
/// 返回装配好的 `SessionManager`（Session 生命周期的唯一 Owner）。
///
/// 降级：存储打不开 → `Err`（调用方降级为 None，daemon 照常跑）。
pub fn assemble_n2_session_manager(
    config_root: &std::path::Path,
) -> Result<nexus_session::SessionManager, String> {
    use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionManager, reconcile_session_records_at};

    let store =
        nexus::n2_store::N2Store::open(config_root).map_err(|e| format!("open n2 store: {e}"))?;
    // §15：先重放 journal（审计轨迹可见性），再 reconcile。
    // P1-11：撕裂尾部此前只报 `TornJournalTail` 且无生产修复入口——整个 journal
    // （审计查询＋boot 重放）都不可读。这里给显式 discard 路径：显式记录可读的
    // 完整前缀条数后丢弃撕裂尾部，再重放（幂等）。
    let journal_entries = match store.replay_journal() {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "[nexusd] WARN: N2 journal replay failed ({e}); discarding torn tail explicitly"
            );
            store
                .kv()
                .journal_discard_torn_tail()
                .map_err(|d| format!("discard torn n2 journal tail: {d}"))?;
            store
                .replay_journal()
                .map_err(|e| format!("replay n2 journal after discard: {e}"))?
        }
    };
    if !journal_entries.is_empty() {
        eprintln!(
            "[nexusd] N2 journal replay: {} entries",
            journal_entries.len()
        );
    }
    let mut record_store = store.sessions();
    let report = reconcile_session_records_at(
        &mut record_store,
        false,
        now_unix_secs(),
        DEFAULT_ATTACH_WINDOW_SECS,
    )
    .map_err(|e| format!("reconcile n2 sessions: {e}"))?;
    eprintln!(
        "[nexusd] N2 session reconcile: checked={}, orphans={}",
        report.records_checked, report.orphans_classified,
    );
    let mut manager = SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
    let loaded = manager
        .load_from_store()
        .map_err(|e| format!("load n2 sessions: {e}"))?;
    eprintln!("[nexusd] N2 SessionManager: {loaded} session records loaded");
    Ok(manager)
}

/// The explicit daemon root owns the default token; preserve the operator's
/// dedicated token-file override without consulting NEXUS_CONFIG_DIR again.
pub fn localapi_token_path(config_root: &std::path::Path) -> std::path::PathBuf {
    std::env::var_os("NEXUS_LOCALAPI_TOKEN_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config_root.join("localapi.token"))
}

pub fn load_localapi_token(config_root: &std::path::Path) -> Result<String, String> {
    use std::io::{Read, Write};
    let path = localapi_token_path(config_root);
    let read = || -> Result<String, String> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x20000 | 0x800);
        }
        let mut file = options.open(&path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("LocalAPI token must be a regular file".into());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(129)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let token = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        let token = token.trim();
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("LocalAPI token is corrupt".into());
        }
        Ok(token.to_owned())
    };
    if path.try_exists().map_err(|e| e.to_string())? {
        return read();
    }
    let parent = path
        .parent()
        .ok_or_else(|| "token parent missing".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    // new_task_id is backed by 32 OS-random bytes, independent of Session IDs.
    let random = nexus::n3_acceptance::new_task_id().map_err(|e| e.to_string())?;
    let token = random
        .as_str()
        .strip_prefix("task-")
        .ok_or_else(|| "token randomness format".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(token.as_bytes())
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            #[cfg(unix)]
            std::fs::File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(token.to_owned())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read(),
        Err(error) => Err(error.to_string()),
    }
}

/// 当前 unix 秒（boot reconcile 用时钟）。
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 带超时的 join（R4 关闭顺序用；§13.4）。
///
/// 超时后记 warn 并继续（不杀线程，进程退出时回收）。
/// 返回 `true` 表示线程在超时内结束，`false` 表示超时。
pub fn join_with_timeout(
    handle: std::thread::JoinHandle<()>,
    timeout: std::time::Duration,
    name: &str,
) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = handle.join();
        let _ = tx.send(());
    });
    match rx.recv_timeout(timeout) {
        Ok(_) => {
            eprintln!("[nexusd] shutdown: {name} stopped");
            true
        }
        Err(_) => {
            eprintln!("[nexusd] WARN: shutdown: {name} did not stop in {timeout:?}, continuing");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小合法 network.toml（含 [vpi.routes]）。
    fn network_toml_with_routes() -> String {
        // peer_id 为 32 字节 hex（ed25519 公钥）。
        let peer_hex = "aa".repeat(32);
        format!(
            "peer_id = \"{peer_hex}\"\n\
             [[peers]]\n\
             id = \"{peer_hex}\"\n\
             addrs = [\"127.0.0.1:19001\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             mtu = 1200\n\
             [[vpi.routes]]\n\
             subnet = \"10.200.0.0/24\"\n\
             peer = \"{peer_hex}\"\n"
        )
    }

    #[test]
    fn mesh_cidrs_come_from_vpi_routes() {
        let cidrs = parse_mesh_cidrs(&network_toml_with_routes()).unwrap();
        assert_eq!(cidrs, vec!["10.200.0.0/24"]);
        // 不再硬编码 10.0.0.0/8。
        assert!(!cidrs.contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn mesh_cidrs6_come_from_vpi_routes6() {
        let peer_hex = "aa".repeat(32);
        let text = format!(
            "peer_id = \"{peer_hex}\"\n\
             [[peers]]\n\
             id = \"{peer_hex}\"\n\
             addrs = [\"127.0.0.1:19001\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             address6 = \"fd00:144::1\"\n\
             mtu = 1200\n\
             [[vpi.routes]]\n\
             subnet = \"10.200.0.0/24\"\n\
             peer = \"{peer_hex}\"\n\
             [[vpi.routes6]]\n\
             subnet = \"fd00:144::/64\"\n\
             peer = \"{peer_hex}\"\n"
        );
        assert_eq!(
            parse_mesh_cidrs6(&text).unwrap(),
            vec!["fd00:144::/64".to_string()]
        );
        // v4-only 配置 → 空（不是硬编码）。
        assert!(
            parse_mesh_cidrs6(&network_toml_with_routes())
                .unwrap()
                .is_empty()
        );
        assert!(parse_mesh_cidrs6("[[[unclosed").is_err());
    }

    #[test]
    fn dataplane_config_sets_v6_cidrs() {
        let peer_hex = "aa".repeat(32);
        let text = format!(
            "peer_id = \"{peer_hex}\"\n\
             [[peers]]\n\
             id = \"{peer_hex}\"\n\
             addrs = [\"127.0.0.1:19001\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             address6 = \"fd00:144::1\"\n\
             mtu = 1200\n\
             [[vpi.routes6]]\n\
             subnet = \"fd00:144::/64\"\n\
             peer = \"{peer_hex}\"\n"
        );
        let cfg = build_dataplane_config(&loaded_with(Some(&text), false)).unwrap();
        assert_eq!(cfg.mesh_cidrs6, vec!["fd00:144::/64".to_string()]);
        assert_eq!(cfg.bypass_cidrs6, DEFAULT_BYPASS_CIDRS6.to_vec());
        // 无 network.toml → 两族 mesh 都空，v6 bypass 仍是默认集合。
        let cfg = build_dataplane_config(&loaded_with(None, false)).unwrap();
        assert!(cfg.mesh_cidrs6.is_empty());
        assert_eq!(cfg.bypass_cidrs6, vec!["fc00::/7", "fe80::/10", "::1/128"]);
    }

    #[test]
    fn mesh_cidrs_bad_config_is_err() {
        assert!(parse_mesh_cidrs("[[[unclosed").is_err());
    }

    #[test]
    fn overlap_detected() {
        let overlapped = mesh_bypass_overlap(
            &["172.16.5.0/24".to_string()],
            &["172.16.0.0/12".to_string()],
        );
        assert_eq!(overlapped, vec!["172.16.5.0/24".to_string()]);
    }

    #[test]
    fn overlap_empty_when_disjoint() {
        let overlapped = mesh_bypass_overlap(
            &["10.200.0.0/24".to_string()],
            &["192.168.0.0/16".to_string()],
        );
        assert!(overlapped.is_empty());
    }

    #[test]
    fn assemble_n1_bad_config_is_err() {
        // R1 降级路径：非法配置 → Err（调用方降级，不调 set_n1_sender）。
        assert!(assemble_n1("[[[unclosed", None, Arc::new(AtomicBool::new(false))).is_err());
    }

    #[test]
    fn assemble_n1_with_proxy_ok() {
        // #3：合法 [network.proxy]（socks5）+ 合法 network.toml → Ok，route_count==1。
        let section = crate::config::ProxySection {
            proxy_type: crate::config::ProxyType::Socks5,
            server: "127.0.0.1:1080".parse().unwrap(),
            username: None,
            password: None,
            method: None,
            sni: None,
            skip_cert_verify: false,
            alpn: None,
            connect_timeout_sec: 10,
            handshake_timeout_sec: 10,
        };
        let bridge = assemble_n1(
            &network_toml_with_routes(),
            Some(&section),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("assemble_n1 with proxy should succeed");
        assert_eq!(bridge.route_count(), 1);
    }

    fn loaded_with(network_toml: Option<&str>, qos: bool) -> LoadedConfig {
        LoadedConfig {
            daemon: crate::config::DaemonConfig {
                qos: crate::config::QosSection {
                    enabled: qos,
                    ..Default::default()
                },
                ..Default::default()
            },
            network_toml: network_toml.map(|s| s.to_string()),
            dns_toml: None,
            proxy_yaml: None,
            workspace_toml: None,
            meta: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn dataplane_config_no_network_toml() {
        // network.toml 缺失 → mesh_cidrs 空（降级），不 Err。
        let cfg = build_dataplane_config(&loaded_with(None, false)).unwrap();
        assert!(cfg.mesh_cidrs.is_empty());
    }

    #[test]
    fn dataplane_config_bad_network_toml_degrades() {
        // network.toml 非法 → mesh_cidrs 空（降级），不 Err。
        let cfg = build_dataplane_config(&loaded_with(Some("[[[unclosed"), false)).unwrap();
        assert!(cfg.mesh_cidrs.is_empty());
    }

    #[test]
    fn dataplane_config_qos_mapping() {
        // QoS 开启 → quantum/ports 透传。
        let mut loaded = loaded_with(None, true);
        loaded.daemon.qos.quantum = 9000;
        loaded.daemon.qos.high_priority_ports = vec![443];
        let cfg = build_dataplane_config(&loaded).unwrap();
        assert!(cfg.qos_enabled);
        assert_eq!(cfg.qos_config.quantum, 9000);
        assert_eq!(cfg.qos_config.high_priority_ports, vec![443]);
        // QoS 关闭 → 默认值。
        let cfg = build_dataplane_config(&loaded_with(None, false)).unwrap();
        assert!(!cfg.qos_enabled);
        assert_eq!(
            cfg.qos_config.quantum,
            nexus_qos::cake::CakeConfig::default().quantum
        );
    }

    #[test]
    fn join_with_timeout_fast_thread() {
        // 快速结束的线程 → true。
        let h = std::thread::spawn(|| {});
        assert!(join_with_timeout(
            h,
            std::time::Duration::from_secs(5),
            "test"
        ));
    }

    #[test]
    fn join_with_timeout_slow_thread() {
        // 睡眠线程 → 超时返回 false（不阻塞）。
        let h = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(30)));
        let start = std::time::Instant::now();
        assert!(!join_with_timeout(
            h,
            std::time::Duration::from_millis(100),
            "test"
        ));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    /// S28：OsAssemble 干跑计划（零写入），排除项计入报告。
    #[cfg(target_os = "linux")]
    #[test]
    fn os_assemble_dry_run_plan() {
        use nexus_platform_linux::assemble::{OsAssemble, OsAssembleConfig};
        let config = OsAssembleConfig {
            ifname: "lo".to_string(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: true,
            dry_run: true,
            log_path: None,
            exclude_dst_cidrs: vec![([203, 0, 113, 7], 32)],
            exclude_egress: vec![(
                ([203, 0, 113, 7], 32),
                nexus_platform_linux::assemble::ExcludeEgress {
                    oif: 2,
                    gateway: Some([192, 168, 1, 1]),
                },
            )],
        };
        let mut assemble = OsAssemble::new(config).expect("lo exists");
        let report = assemble.apply().expect("dry run");
        assert!(report.dry_run);
        assert_eq!(report.excludes_added, 1);
        assert!(report.default_route_added);
        assert!(!report.actions.is_empty());
        let cleanup = assemble.cleanup().expect("dry-run cleanup");
        assert_eq!(cleanup.excludes_removed, 0);
    }
    // ---- WP2 dial lifecycle（spec §5.1 生命周期 / §8.1 常量 / §8.2 日志原文） ----

    #[derive(Default)]
    struct FakeClockState {
        now_ms: u64,
        sleeps: Vec<u64>,
        stop_after: Option<usize>,
        shutdown: Option<Arc<AtomicBool>>,
    }

    #[derive(Clone, Default)]
    struct FakeClock(Arc<std::sync::Mutex<FakeClockState>>);

    impl FakeClock {
        fn stopping_after(n: usize, shutdown: Arc<AtomicBool>) -> Self {
            let clock = Self::default();
            {
                let mut state = clock.0.lock().unwrap();
                state.stop_after = Some(n);
                state.shutdown = Some(shutdown);
            }
            clock
        }

        fn sleeps(&self) -> Vec<u64> {
            self.0.lock().unwrap().sleeps.clone()
        }
    }

    impl DialClock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.lock().unwrap().now_ms
        }

        fn sleep_ms(&self, ms: u64, shutdown: &AtomicBool) -> bool {
            if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                return false;
            }
            let mut state = self.0.lock().unwrap();
            state.sleeps.push(ms);
            state.now_ms += ms;
            if state
                .stop_after
                .is_some_and(|limit| state.sleeps.len() >= limit)
            {
                if let Some(flag) = &state.shutdown {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                return false;
            }
            true
        }
    }

    struct FakePort {
        clock: FakeClock,
        dials: std::sync::Mutex<u32>,
        connected: std::sync::Mutex<bool>,
        outcomes: std::sync::Mutex<std::collections::VecDeque<bool>>,
        disconnect_at_ms: Option<u64>,
        disconnected: std::sync::atomic::AtomicBool,
    }

    impl FakePort {
        fn new(clock: FakeClock, outcomes: &[bool]) -> Self {
            Self {
                clock,
                dials: std::sync::Mutex::new(0),
                connected: std::sync::Mutex::new(false),
                outcomes: std::sync::Mutex::new(outcomes.iter().copied().collect()),
                disconnect_at_ms: None,
                disconnected: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn dials(&self) -> u32 {
            *self.dials.lock().unwrap()
        }
    }

    impl DialSessions for FakePort {
        fn connected(&self, _peer: &N1PeerId) -> bool {
            if let Some(at_ms) = self.disconnect_at_ms {
                if self.clock.now_ms() >= at_ms
                    && !self
                        .disconnected
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    *self.connected.lock().unwrap() = false;
                }
            }
            *self.connected.lock().unwrap()
        }

        fn dial(&self, _peer: &N1PeerId) -> Result<(), nexus_network::n1::N1Error> {
            *self.dials.lock().unwrap() += 1;
            let ok = self.outcomes.lock().unwrap().pop_front().unwrap_or(false);
            if ok {
                *self.connected.lock().unwrap() = true;
                Ok(())
            } else {
                Err(nexus_network::n1::N1Error::Timeout)
            }
        }
    }

    fn peer(byte: u8) -> N1PeerId {
        N1PeerId([byte; 32])
    }

    #[test]
    fn dial_lifecycle_only_smaller_id_owns_dialing() {
        let small = peer(0x10);
        let large = peer(0x20);

        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::stopping_after(1, Arc::clone(&shutdown));
        let port = FakePort::new(clock.clone(), &[true]);
        let mut logs = Vec::new();
        run_dial_lifecycle(small, &[large], &port, &clock, &shutdown, &mut |line| {
            logs.push(line)
        });
        assert_eq!(port.dials(), 1, "smaller id must dial the larger peer");
        assert_eq!(
            logs,
            vec!["[n1-dial] peer=2020202020202020 attempt=1 result=ok".to_string()]
        );
        assert_eq!(clock.sleeps(), vec![N1_DIAL_RETRY_INITIAL_MS]);

        // Larger id only waits for accept: zero dials, zero sleeps, zero dial logs.
        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::stopping_after(1, Arc::clone(&shutdown));
        let port = FakePort::new(clock.clone(), &[true]);
        let mut logs = Vec::new();
        run_dial_lifecycle(large, &[small], &port, &clock, &shutdown, &mut |line| {
            logs.push(line)
        });
        assert_eq!(port.dials(), 0, "larger id must never dial");
        assert!(clock.sleeps().is_empty());
        assert!(logs.is_empty());
    }

    #[test]
    fn dial_lifecycle_backoff_doubles_and_caps_at_max() {
        let peer_id = peer(0x20);
        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::stopping_after(7, Arc::clone(&shutdown));
        let port = FakePort::new(clock.clone(), &[]);
        let mut logs = Vec::new();
        run_dial_lifecycle(
            peer(0x10),
            &[peer_id],
            &port,
            &clock,
            &shutdown,
            &mut |line| logs.push(line),
        );

        assert_eq!(port.dials(), 7);
        assert_eq!(
            clock.sleeps(),
            vec![1000, 2000, 4000, 8000, 16000, 30000, 30000],
            "退避必须 1000ms 起、x2、封顶 30000ms"
        );
        assert_eq!(logs.len(), 7);
        for (index, line) in logs.iter().enumerate() {
            assert!(
                line.contains(&format!("attempt={}", index + 1)),
                "attempt counter must increment per failed dial: {line}"
            );
            assert!(
                line.ends_with("result=err kind=Timeout"),
                "log line must follow §8.2: {line}"
            );
        }
    }

    #[test]
    fn dial_lifecycle_stops_after_successful_dial() {
        let peer_id = peer(0x20);
        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::stopping_after(3, Arc::clone(&shutdown));
        let port = FakePort::new(clock.clone(), &[true]);
        let mut logs = Vec::new();
        run_dial_lifecycle(
            peer(0x10),
            &[peer_id],
            &port,
            &clock,
            &shutdown,
            &mut |line| logs.push(line),
        );

        assert_eq!(port.dials(), 1, "successful dial must stop retrying");
        assert_eq!(
            clock.sleeps(),
            vec![1000, 1000, 1000],
            "connected peer must only be polled, not re-dialed"
        );
        assert_eq!(
            logs,
            vec!["[n1-dial] peer=2020202020202020 attempt=1 result=ok".to_string()]
        );
    }

    #[test]
    fn dial_lifecycle_redials_after_connection_removed() {
        let peer_id = peer(0x20);
        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::stopping_after(4, Arc::clone(&shutdown));
        let mut port = FakePort::new(clock.clone(), &[true, false, true]);
        port.disconnect_at_ms = Some(1000);
        let mut logs = Vec::new();
        run_dial_lifecycle(
            peer(0x10),
            &[peer_id],
            &port,
            &clock,
            &shutdown,
            &mut |line| logs.push(line),
        );

        assert_eq!(port.dials(), 3, "removed connection must be re-dialed");
        assert_eq!(
            logs,
            vec![
                "[n1-dial] peer=2020202020202020 attempt=1 result=ok".to_string(),
                "[n1-dial] peer=2020202020202020 attempt=1 result=err kind=Timeout".to_string(),
                "[n1-dial] peer=2020202020202020 attempt=2 result=ok".to_string(),
            ],
            "re-dial must restart the same backoff sequence"
        );
        assert_eq!(clock.sleeps(), vec![1000, 1000, 1000, 1000]);
    }

    #[test]
    fn n1_dial_skips_self() {
        let self_id = peer(0x10);
        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::stopping_after(1, Arc::clone(&shutdown));
        let port = FakePort::new(clock.clone(), &[true]);
        let mut logs = Vec::new();
        run_dial_lifecycle(self_id, &[self_id], &port, &clock, &shutdown, &mut |line| {
            logs.push(line)
        });

        assert_eq!(port.dials(), 0);
        assert!(clock.sleeps().is_empty());
        assert_eq!(logs, vec!["[n1-dial] self peer skipped".to_string()]);
    }

    #[test]
    fn assemble_n1_with_discovery_static_peers_ids_only() {
        let text = network_toml_with_routes();
        let assembly = assemble_n1_with_discovery(
            &text,
            None,
            Arc::new(AtomicBool::new(false)),
            nexus::network::DiscoveryParams::static_only(),
            None,
        )
        .expect("assembly");
        // Id-only: two configured addrs stay in `config.peers`, the id list
        // carries no address.
        assert_eq!(assembly.config.peers[0].addrs.len(), 1);
        assert_eq!(assembly.static_peers.len(), 1);
        assert_eq!(assembly.static_peers[0], assembly.config.peers[0].id);
        // The hub the assembly exposes is the one the N1 adapter reads (the
        // assembly holds the same Arc it passed to the session manager).
        assert_eq!(
            assembly.discovery.self_id().0,
            assembly.config.peer_id.to_hex()
        );
        // Multiple configured addrs still yield exactly one static id.
        let multi = text.replace(
            "addrs = [\"127.0.0.1:19001\"]",
            "addrs = [\"127.0.0.1:19001\", \"127.0.0.1:19002\"]",
        );
        let assembly = assemble_n1_with_discovery(
            &multi,
            None,
            Arc::new(AtomicBool::new(false)),
            nexus::network::DiscoveryParams::static_only(),
            None,
        )
        .expect("assembly with two addrs");
        assert_eq!(assembly.config.peers[0].addrs.len(), 2);
        assert_eq!(assembly.static_peers.len(), 1);
    }
}
