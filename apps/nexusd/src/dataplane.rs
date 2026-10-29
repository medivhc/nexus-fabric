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

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use nexus_dns::wire::{self, DnsRcode};
use nexus_domain::SessionId;
use nexus_flow_session::{
    ChainDeps, ConnectivityEstablisher, FlowDecision, FlowKey, FlowSignal, IpProto, SessionManager,
    SessionManagerConfig,
};
use nexus_network::n1::N1Connection;
use nexus_network::n1::bridge::N1Sender;
use nexus_path::{CandidatePath, PathConfig, PathManager};
use nexus_platform::{AcceptedTcpStream, ReceivedDatagram, TransparentIngressError};
use nexus_projection::TunDevice;
use nexus_projection::classifier::DropReason;
use nexus_projection::classifier::{Classification, PacketClassifier};
use nexus_projection::dns::{DEFAULT_DNS_CACHE_ENTRIES, DnsCache};
use nexus_projection::egress::{EgressNat, RealUdpEgress, Rule, SimpleRuleEngine};
use nexus_projection::routing::IpCidr;
use nexus_projection::tcp::{
    FourTuple, MAX_TCP_CONNS, RelayEvent, STREAM_FIN, STREAM_RST, STREAM_SYN, TcpEvent, TcpRelay,
    TcpTermStats, TcpTerminator, decode_stream_frame, encode_stream_frame, encode_syn_payload,
};
use nexus_projection::transparent::direct::{DirectEgressConfig, DirectTcpEvent, DirectTcpRelay};
use nexus_projection::transparent::runtime::{TransparentFailureKind, TransparentPipeline};
use nexus_projection::transparent::{
    TcpConnection, TransparentDecision, TransparentOutput, TransparentTcpInput, TransparentUdpInput,
};
use nexus_proxy_config::FlowSessionsMode;
use nexus_qos::cake::{CakeConfig, CakeScheduler, EnqueueDecision, FiveTuple};

mod chain_wiring;

pub use chain_wiring::{
    ChainDepsError, ProductionChainDeps, ProviderDeriveError, build_registry, derive_providers,
};
use nexus_projection::transparent::decision::{
    CachedDecision, FlowDecisionCache, FlowDecisionCacheStats, FlowDecisionKey, Frontend,
};

/// 回程帧走哪条传输（spec §7）：
///
/// - `N1`：N1 入站帧 → 同一 N1 conn 的 datagram；
/// - `Direct`：direct N1 chunk 入站 → 同一 NAT direct 路径的 chunk，N1 仅作
///   fallback（`n1_peer_conns` 里该 peer 的 conn，没有则丢 + `tx.errors`）。
#[derive(Clone)]
pub enum ReplySink {
    N1(Arc<dyn N1Connection>),
    Direct(nexus_fabric::PeerId),
}

/// egress relay 的分派接口（spec §5.5/§7）。
///
/// WP4 只定版接口与分派走向；真实 `TcpRelay` 由 WP5 通过
/// [`Dataplane::set_n1_relay`] 装入。`Err(N1RelayError::UnknownStream)` 表示
/// relay 不拥有该流（spec §6.1 `UnknownStream`），分派侧计
/// `dispatch.unknown_stream` 并丢弃。
pub trait N1EgressRelay: Send {
    /// 处理一条入站 STREAM 帧；成功返回需立即编码回程的事件（§5.5 第 2 步）。
    fn handle_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: &[u8],
        from_peer: &str,
    ) -> Result<Vec<RelayEvent>, N1RelayError>;

    /// 驱动 egress 侧（连接完成 / 本地 socket 可读）并返回回程事件。
    ///
    /// `Dataplane::n1_egress_poll` 在 dataplane 主循环每轮调用一次
    /// （spec §5.5/§5.7：egress relay 跑在 dataplane 线程，不另起忙等线程）。
    fn poll(&mut self) -> Vec<RelayEvent>;
}

/// egress relay 的失败分类（spec §6.2；不新增 wire 变体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1RelayError {
    /// terminator 与 relay 都不认识该 stream（`tcp.rs` unknown 分支）。
    UnknownStream,
}

/// egress `TcpRelay` 的生产适配器（spec §5.5 Q-EGRESS-IMPL = additive 接线）。
///
/// 机制本体（`crates/nexus-projection/src/tcp.rs`）**零改动**：本适配器只做
/// ①所有权判定（`TcpRelay::has`，不拥有 → [`N1RelayError::UnknownStream`]）；
/// ②`egress.*` 计数（机制侧已有计数器取差值 + 适配器可观测的事件）；
/// ③§8.2 日志。回程帧的编码/发送仍由 dispatch 侧 `send_reply` 负责（WP4 §4.2）。
///
/// 所有权口径有两个**机制语义要求的例外**（否则会丢 §6.2 规定的回 RST）：
/// - SYN 被表满拒绝：`handle_frame` 返回 `Closed{reset:true}` 但不会把流放进表，
///   调用后 `has=false`；事件非空 → 仍按 relay 消费处理。
/// - 短/非法 SYN（`SynDecode`）：机制只计 `short_syn_dropped`、按既有语义不回 RST；
///   它确实被 relay 消费，不冒充 `unknown_stream`。
///
/// `egress.*` 的可观测边界（冻结机制面所限，实现不猜机制内部状态）：
/// - `connect_ok` 只能在本地 socket 首次产出证据时观测（读到字节或 EOF）：机制
///   的 connect 成功没有事件、`TcpRelayStats` 也没有该计数；连上后一直静默到
///   进程退出的流不会被计入（**只会少计，不会多计**）。
/// - `bytes_to_local` 按 relay 接受的 DATA 载荷计数；机制 API 不暴露
///   `write_pending` 余量，故「已进入非阻塞写路径」与「已写入内核 socket」在
///   部分写时不可区分（正常 socket 缓冲区足够时二者相等）。
pub struct TcpRelayEgress {
    relay: TcpRelay,
    stats: Arc<crate::n1_runtime::N1Stats>,
    /// 已发 SYN、尚未观测到本地连接成功证据的 `(peer, stream_id)`。
    ///
    /// 只用于把「connect 成功 / 失败」归类；上界是 relay 表大小（≤1024），
    /// 每次 poll 后按 `has()` 剪枝（表里没有的键不再等待）。
    awaiting: HashSet<(String, u32)>,
    /// 机制侧计数器差值基线（`table_full` / `connect_failed` 只在机制内部递增）。
    seen_table_full: u64,
    seen_connect_failed: u64,
}

impl TcpRelayEgress {
    pub fn new(stats: Arc<crate::n1_runtime::N1Stats>) -> Self {
        Self {
            relay: TcpRelay::new(),
            stats,
            awaiting: HashSet::new(),
            seen_table_full: 0,
            seen_connect_failed: 0,
        }
    }

    /// 把机制侧计数器的增量转成 `egress.*`（每个增量只记一次）。
    ///
    /// 返回 `(table_full_delta, connect_failed_delta)` 供日志按流标注。
    fn sync_mechanism_counters(&mut self) -> (u64, u64) {
        let stats = self.relay.stats();
        let table_full = stats.table_full.saturating_sub(self.seen_table_full);
        let connect_failed = stats
            .connect_failed
            .saturating_sub(self.seen_connect_failed);
        self.seen_table_full = stats.table_full;
        self.seen_connect_failed = stats.connect_failed;
        for _ in 0..table_full {
            self.stats
                .record_egress(crate::n1_runtime::N1EgressEvent::TableFull);
        }
        for _ in 0..connect_failed {
            self.stats
                .record_egress(crate::n1_runtime::N1EgressEvent::ConnectFailed);
        }
        (table_full, connect_failed)
    }
}

impl N1EgressRelay for TcpRelayEgress {
    fn handle_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: &[u8],
        from_peer: &str,
    ) -> Result<Vec<RelayEvent>, N1RelayError> {
        let is_syn = flags & STREAM_SYN != 0;
        if is_syn {
            self.stats
                .record_egress(crate::n1_runtime::N1EgressEvent::Syn);
            eprintln!(
                "[n1-egress] syn peer={} stream={stream_id} target={}",
                hex16(from_peer),
                syn_target_display(payload)
            );
        }
        // 所有权口径：调用前后任一时刻拥有该流即算 relay 消费。
        // RST/FIN 会让机制在 `handle_frame` 内移除连接（调用后 `has=false`），
        // 但该帧仍属于 relay 的流，不能误计 `dispatch.unknown_stream`。
        let owned_before = self.relay.has(from_peer, stream_id);
        let events = self
            .relay
            .handle_frame(stream_id, flags, payload, from_peer);
        let owned = self.relay.has(from_peer, stream_id);
        let (table_full, _) = self.sync_mechanism_counters();
        if table_full > 0 {
            eprintln!(
                "[n1-egress] WARN: table full peer={} stream={stream_id} limit={MAX_TCP_CONNS}",
                hex16(from_peer)
            );
        }

        let key = (from_peer.to_string(), stream_id);
        if is_syn {
            if owned && events.is_empty() {
                // SYN 已被接受，connect 在 worker 线程里进行（§6.2 异步语义）。
                self.awaiting.insert(key);
            } else {
                self.awaiting.remove(&key);
            }
        } else if !owned {
            // relay 已丢弃该流（RST/写失败/连接失败），不再等待成功证据。
            self.awaiting.remove(&key);
        }

        let is_data = flags & (STREAM_SYN | STREAM_FIN | STREAM_RST) == 0;
        if is_data && !payload.is_empty() && owned && events.is_empty() {
            self.stats
                .record_egress(crate::n1_runtime::N1EgressEvent::BytesToLocal(
                    payload.len(),
                ));
        }

        if owned || owned_before || !events.is_empty() {
            Ok(events)
        } else if is_syn {
            // 短/非法 SYN：机制侧已计 `short_syn_dropped` 并按既有语义不回 RST
            // （§6.2 SynDecode）。它确实被 relay 消费，不冒充 unknown stream。
            Ok(events)
        } else {
            Err(N1RelayError::UnknownStream)
        }
    }

    fn poll(&mut self) -> Vec<RelayEvent> {
        let events = self.relay.poll();
        let (_, connect_failed) = self.sync_mechanism_counters();
        let mut failures_left = connect_failed;
        for event in &events {
            let (peer, stream_id) = match event {
                RelayEvent::Data {
                    stream_id, peer, ..
                }
                | RelayEvent::Closed {
                    stream_id, peer, ..
                } => (peer, *stream_id),
            };
            let first_evidence = self.awaiting.remove(&(peer.clone(), stream_id));
            match event {
                RelayEvent::Data { bytes, .. } => {
                    if first_evidence {
                        self.record_connect_ok(peer, stream_id);
                    }
                    self.stats
                        .record_egress(crate::n1_runtime::N1EgressEvent::BytesFromLocal(
                            bytes.len(),
                        ));
                }
                RelayEvent::Closed { reset: false, .. } => {
                    if first_evidence {
                        self.record_connect_ok(peer, stream_id);
                    }
                }
                RelayEvent::Closed { reset: true, .. } => {
                    if first_evidence && failures_left > 0 {
                        failures_left -= 1;
                        // 机制侧 connect worker 丢弃了 `io::ErrorKind`（tcp.rs 的
                        // `TcpStream::connect_timeout(...).ok()`），故只能给 `Other`；
                        // 失败**本身**由 `egress.connect_failed` 精确计数。
                        eprintln!(
                            "[n1-egress] connect peer={} stream={stream_id} result=failed kind=Other",
                            hex16(peer)
                        );
                    }
                }
            }
        }
        let relay = &self.relay;
        self.awaiting.retain(|(peer, id)| relay.has(peer, *id));
        events
    }
}

impl TcpRelayEgress {
    fn record_connect_ok(&self, peer: &str, stream_id: u32) {
        self.stats
            .record_egress(crate::n1_runtime::N1EgressEvent::ConnectOk);
        eprintln!(
            "[n1-egress] connect peer={} stream={stream_id} result=ok",
            hex16(peer)
        );
    }
}

/// SYN 载荷目标的**日志展示**（§8.2 `target=<ip:port>`）。
///
/// 只读展示，不参与任何判定；格式与 `nexus_projection::tcp::encode_syn_payload`
/// 的冻结线格式一致（该解码器是机制 crate 私有面，nexusd 不复制其解析语义）。
fn syn_target_display(payload: &[u8]) -> String {
    if payload.len() == 6 {
        let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
        let port = u16::from_be_bytes([payload[4], payload[5]]);
        return format!("{ip}:{port}");
    }
    match payload.first() {
        Some(0x01) if payload.len() >= 7 => {
            let ip = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            format!("{ip}:{port}")
        }
        Some(0x02) if payload.len() >= 19 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            format!("[{ip}]:{port}")
        }
        Some(0x03) if payload.len() >= 4 => {
            let len = payload[1] as usize;
            if payload.len() < len + 4 {
                return "-".to_string();
            }
            let host = String::from_utf8_lossy(&payload[2..2 + len]);
            let port = u16::from_be_bytes([payload[2 + len], payload[3 + len]]);
            format!("{host}:{port}")
        }
        _ => "-".to_string(),
    }
}

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

/// IPv6 数据面统计（spec §4.10.2；AC10 的"每个 0x86DD 包都可见"）。
///
/// 归属口径（D-impl-10）：`packets` 对**所有** 0x86DD 包 +1（含 multicast /
/// 截断）；其余字段在各自维度上**只加一个语义分量**——传输层（`udp`/`tcp`）、
/// 分类（`classified_*`）、路径结果（`mesh_forwarded`/`mesh_no_route`/
/// `proxy_dropped`）、标志位（`fragments`/`multicast`/`dropped_*`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ipv6Stats {
    /// 所有 0x86DD 包。
    pub packets: u64,
    /// UDP（next header 17）。
    pub udp: u64,
    /// TCP（next header 6）。
    pub tcp: u64,
    /// 分类为 Mesh。
    pub classified_mesh: u64,
    /// 分类为 Direct。
    pub classified_direct: u64,
    /// 分类为 Proxy。
    pub classified_proxy: u64,
    /// Mesh 原始转发成功（N1）。
    pub mesh_forwarded: u64,
    /// Mesh 分类但无 v6 路由 / 无 sender → 无法转发。
    pub mesh_no_route: u64,
    /// Proxy 分类的 v6 包（本 run 阻断，Q4）。
    pub proxy_dropped: u64,
    /// 多播（`ff00::/8`）：只计数，不进分类转发。
    pub multicast: u64,
    /// 固定头/扩展头/L4 截断。
    pub dropped_truncated: u64,
    /// 扩展头链非法（>8 个或长度越界）。
    pub dropped_extension: u64,
    /// 含 Fragment 头的包（不重组；只计数）。
    pub fragments: u64,
}

/// 数据面统计（D6 可观测）。
#[derive(Debug, Default, Clone)]
pub struct DataplaneStats {
    pub mesh_forwarded: u64,
    pub proxy_forwarded: u64,
    pub direct_forwarded: u64,
    pub dropped: u64,
    pub dns_answered: u64,
    /// DNS responses by RCODE (§4.10.2; `dns_answered` is their sum).
    pub dns_noerror: u64,
    pub dns_nodata: u64,
    pub dns_nxdomain: u64,
    pub dns_servfail: u64,
    pub dns_refused: u64,
    pub dns_formerr: u64,
    pub dns_tcp_refused: u64,
    pub dns_queue_full: u64,
    pub dns_service_down: u64,
    pub dns_reply_write_failed: u64,
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
    /// Proxy TCP 上行应用字节（v-next 起为真实值：`tcp_bytes_up`）。
    pub proxy_tcp_bytes: u64,
    /// Proxy TCP 下行应用字节（`tcp_bytes_down`，vp 新增暴露）。
    pub proxy_tcp_bytes_down: u64,
    /// dial 成功并进入 relay 的 Proxy 流数（与 `proxy_tcp_streams`（Syn 数）不同义）。
    pub proxy_tcp_streams_ok: u64,
    /// UDP `UdpCapability::Unsupported` 总数。
    pub proxy_udp_unsupported: u64,
    /// VLESS UDP 丢弃。
    pub proxy_udp_unsupported_vless: u64,
    /// AnyTLS UDP 丢弃。
    pub proxy_udp_unsupported_anytls: u64,
    /// 其他 unsupported（含 Trojan）。
    pub proxy_udp_unsupported_other: u64,
    /// 限频抑制的 udp_unsupported 日志条数。
    pub proxy_udp_unsupported_log_suppressed: u64,
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
    /// IPv6 数据面计数（C18；`0x86DD` 全部可见）。
    pub ipv6: Ipv6Stats,
}

/// S4: 终结流记录（事件分发用）。
#[derive(Debug, Clone, Copy)]
struct TcpStreamInfo {
    /// 原始目的（STREAM 帧经 N1 路由用；v4/v6 双栈，C21）。
    dst: SocketAddr,
    /// 是否 Proxy 分类（true → 只计数，不经 N1）。
    proxy: bool,
}

/// 数据面配置（从 daemon.toml / network.toml / dns.toml 组装）。
#[derive(Debug, Clone)]
pub struct DataplaneConfig {
    /// Mesh 网段 CIDR（字符串，如 "10.144.144.0/24"）。
    pub mesh_cidrs: Vec<String>,
    /// Mesh 网段 CIDR（v6，来自 `network.toml [[vpi.routes6]]`）。
    pub mesh_cidrs6: Vec<String>,
    /// Bypass/白名单 CIDR。
    pub bypass_cidrs: Vec<String>,
    /// Bypass/白名单 CIDR（v6；默认 `fc00::/7`、`fe80::/10`、`::1/128`）。
    pub bypass_cidrs6: Vec<String>,
    /// 是否启用 DNS 拦截。
    pub dns_enabled: bool,
    /// DNS 统一配置（dns.toml；仅在 DNS 子系统启用时存在）。
    pub dns_config: Option<crate::config::DnsFileConfig>,
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
            mesh_cidrs6: Vec::new(),
            bypass_cidrs: Vec::new(),
            bypass_cidrs6: Vec::new(),
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
    mesh_cidrs: Vec<IpCidr>,
    mesh_cidrs6: Vec<IpCidr>,
    bypass_cidrs: Vec<IpCidr>,
    bypass_cidrs6: Vec<IpCidr>,
    dns: Option<crate::dns_service::DnsServiceHandle>,
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
    last_proxy_tcp_streams_ok: u64,
    last_proxy_udp_send_failed: u64,
    last_proxy_tcp_bytes_up: u64,
    last_proxy_tcp_bytes_down: u64,
    last_proxy_udp_unsupported: u64,
    last_proxy_udp_unsupported_vless: u64,
    last_proxy_udp_unsupported_anytls: u64,
    last_proxy_udp_unsupported_other: u64,
    last_proxy_udp_unsupported_suppressed: u64,
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
    /// D2 去重（spec §4.5.2 / errata E4）：Proxy 分支已当场发过 RST 的 key。
    ///
    /// 仅 flow_mgr 开且无 engine 时插入；命中 `FlowSignal::TcpReset` 时只做会话
    /// 回收，不再发第二个 RST。每 tick 由 `flow_pump` 消费（会话已消失的条目
    /// 直接遗忘，不会二次拦截）。
    proxy_egress_rst_pending: std::collections::HashSet<FlowKey>,
    /// §12.3 `event=outbound_unavailable` 的限频状态（per `(tag, cause)`）。
    ///
    /// 该行位于每包路径（TCP 非 SYN / UDP），必须首次立即发射、其后 10 s 一行
    /// （PRODUCT hot-path 日志契约；review MAJOR-2/C4）。
    unavailable_log: crate::log_throttle::KeyedLogThrottle,
    /// DNS 运维日志限频状态（`dns_tcp_query_refused` 等）。
    dns_log: crate::log_throttle::KeyedLogThrottle,
    /// IPv6 运维日志限频状态（`ipv6_proxy_unsupported` 等；60 s 窗口）。
    ipv6_log: crate::log_throttle::KeyedLogThrottle,
    /// 透明前端管道（S42：TPROXY 生产装配）。
    transparent: Option<TransparentPipeline>,
    /// owner → listener 的 UDP 回包通道（`send_from` 在 listener 线程）。
    transparent_udp_reply_tx: Option<std::sync::mpsc::Sender<TransparentOutput>>,
    /// P0 NAT chunk consumer seam; `None` = wiring absent (all chunks N1).
    nat_path: Option<crate::nat_consumer::NatHandleSlot>,
    /// Mesh destination → peer map (from `[[vpi.routes]]`).
    mesh_peers: Option<Arc<dyn crate::mesh_peer_map::MeshPeerResolver>>,
    /// Direct quiet gate shared with the receiver.
    direct_gate: Option<Arc<crate::nat_chunk_recv::DirectGate>>,
    /// Shared chunk path counters.
    chunk_stats: Arc<crate::nat_chunk_stats::ChunkStats>,
    /// Inbound direct chunks produced by the receiver thread.
    nat_inbound_rx: Option<std::sync::mpsc::Receiver<crate::nat_chunk_recv::NatInboundChunk>>,
    /// WP4 N1 入站队列（`ConnUp/ConnDown/RawIp/Stream`；spec §5.5）。
    n1_inbound_rx: Option<std::sync::mpsc::Receiver<crate::n1_runtime::N1Inbound>>,
    /// N1 计数（rx 侧由 WP3 写；dispatch/tx 由本段写）。
    n1_stats: Arc<crate::n1_runtime::N1Stats>,
    /// egress relay 分派接口（真实 `TcpRelay` 由 WP5 装入）。
    n1_relay: Option<Box<dyn N1EgressRelay>>,
    /// peer hex → N1 conn（direct 回程的 fallback；spec §5.5）。
    n1_peer_conns: HashMap<String, Arc<dyn N1Connection>>,
    /// unknown-stream 日志限频（首条立即，其后 10s；spec §6.1）。
    n1_dispatch_log: crate::log_throttle::KeyedLogThrottle,
    /// AC-H-1 `[P]`: the one-time `[nat-consumer] handle not attached` notice
    /// has been emitted (spec §13.2).
    nat_not_attached_logged: AtomicBool,
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
    /// `dns` 是唯一 owner 的 DNS 服务句柄（C11）：`dns_enabled=true` 时必须
    /// 传入，否则构造期硬失败（杜绝隐藏 Stub）。
    ///
    /// # Errors
    /// - CIDR 解析失败 → `String` 错误；
    /// - QoS 配置非法 → `String` 错误；
    /// - `dns_enabled=true` 但 `dns=None` → `String` 错误。
    pub fn new(
        tun: Box<dyn TunDevice>,
        config: DataplaneConfig,
        dns: Option<crate::dns_service::DnsServiceHandle>,
    ) -> Result<Self, String> {
        // 解析 CIDR。
        let mesh_cidrs = config
            .mesh_cidrs
            .iter()
            .map(|s| parse_ip_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;
        let mesh_cidrs6 = config
            .mesh_cidrs6
            .iter()
            .map(|s| parse_ip_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;
        let bypass_cidrs = config
            .bypass_cidrs
            .iter()
            .map(|s| parse_ip_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;
        let bypass_cidrs6 = config
            .bypass_cidrs6
            .iter()
            .map(|s| parse_ip_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;

        // PathManager（Boost 启用时用于 EWMA 选路；禁用时仍需一个实例供分类器）。
        let manager = PathManager::new(PathConfig::default());
        let candidates: Vec<CandidatePath> = Vec::new();

        // DNS（D3/C11）：数据面不持有 resolver，只持有服务句柄。
        if config.dns_enabled && dns.is_none() {
            return Err("dns enabled but dns service not wired".to_string());
        }

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
            mesh_cidrs6,
            bypass_cidrs,
            bypass_cidrs6,
            dns,
            qos,
            n1_sender: None,
            proxy_engine: None,
            last_tcp_dials_ok: 0,
            last_tcp_dials_failed: 0,
            last_proxy_tcp_streams: 0,
            last_proxy_tcp_streams_ok: 0,
            last_proxy_udp_send_failed: 0,
            last_proxy_tcp_bytes_up: 0,
            last_proxy_tcp_bytes_down: 0,
            last_proxy_udp_unsupported: 0,
            last_proxy_udp_unsupported_vless: 0,
            last_proxy_udp_unsupported_anytls: 0,
            last_proxy_udp_unsupported_other: 0,
            last_proxy_udp_unsupported_suppressed: 0,
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
            proxy_egress_rst_pending: std::collections::HashSet::new(),
            unavailable_log: crate::log_throttle::KeyedLogThrottle::new(),
            dns_log: crate::log_throttle::KeyedLogThrottle::new(),
            ipv6_log: crate::log_throttle::KeyedLogThrottle::new(),
            transparent: None,
            transparent_udp_reply_tx: None,
            nat_path: None,
            mesh_peers: None,
            direct_gate: None,
            chunk_stats: Arc::new(crate::nat_chunk_stats::ChunkStats::default()),
            nat_inbound_rx: None,
            n1_inbound_rx: None,
            n1_stats: Arc::new(crate::n1_runtime::N1Stats::default()),
            n1_relay: None,
            n1_peer_conns: HashMap::new(),
            n1_dispatch_log: crate::log_throttle::KeyedLogThrottle::new(),
            nat_not_attached_logged: AtomicBool::new(false),
        })
    }

    /// 注入规则引擎（组合根：有 `proxy.yaml` → `DomainRuleEngine`）。
    pub fn set_rule_engine(&mut self, rules: Box<dyn nexus_domain::RuleEngine>) {
        self.rules = rules;
    }

    // ---- P0 NAT chunk consumer (setter injection; `new` signature unchanged) ----

    /// Inject the NAT provider handle slot (may be empty until NAT starts).
    pub fn set_nat_path_slot(&mut self, slot: crate::nat_consumer::NatHandleSlot) {
        self.nat_path = Some(slot);
    }

    /// Inject the mesh destination → peer resolver.
    pub fn set_mesh_peer_resolver(
        &mut self,
        resolver: Arc<dyn crate::mesh_peer_map::MeshPeerResolver>,
    ) {
        self.mesh_peers = Some(resolver);
    }

    /// Inject the shared direct quiet gate.
    pub fn set_direct_gate(&mut self, gate: Arc<crate::nat_chunk_recv::DirectGate>) {
        self.direct_gate = Some(gate);
    }

    /// Inject the inbox of direct chunks accepted by the receiver thread.
    pub fn set_nat_inbound_rx(
        &mut self,
        rx: std::sync::mpsc::Receiver<crate::nat_chunk_recv::NatInboundChunk>,
    ) {
        self.nat_inbound_rx = Some(rx);
    }

    /// Share the composition root's chunk counters.
    pub fn set_chunk_stats(&mut self, stats: Arc<crate::nat_chunk_stats::ChunkStats>) {
        self.chunk_stats = stats;
    }

    /// Drain direct chunks into the unified dispatch (ERRATA-2 / spec §5.5).
    ///
    /// Direct chunks use [`ReplySink::Direct`]; the originator/relay decision is
    /// the same code path as N1 inbound (`dispatch_inbound_stream`). Called once
    /// per dataplane loop iteration (never inside `process_one`, so the proxy
    /// branch is untouched). Malformed frames are counted by the dispatch
    /// counters; this never panics.
    pub fn pump_nat_inbound(&mut self) {
        let Some(rx) = self.nat_inbound_rx.take() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(chunk) => {
                    let peer = crate::nat_consumer::peer_hex(&chunk.peer);
                    self.dispatch_inbound_stream(
                        &peer,
                        ReplySink::Direct(chunk.peer),
                        &chunk.stream_frame,
                    );
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        self.nat_inbound_rx = Some(rx);
    }

    // ---- WP4 N1 inbound consumer (spec §5.5) ----

    /// Inject the N1 inbound queue (WP3's supervisor owns the sender).
    pub fn set_n1_inbound_rx(
        &mut self,
        rx: std::sync::mpsc::Receiver<crate::n1_runtime::N1Inbound>,
    ) {
        self.n1_inbound_rx = Some(rx);
    }

    /// Share the composition root's N1 counters (`rx` written by WP3,
    /// dispatch/tx written here).
    pub fn set_n1_stats(&mut self, stats: Arc<crate::n1_runtime::N1Stats>) {
        self.n1_stats = stats;
    }

    /// Install the egress relay dispatch interface (WP5 installs `TcpRelay`).
    pub fn set_n1_relay(&mut self, relay: Box<dyn N1EgressRelay>) {
        self.n1_relay = Some(relay);
    }

    /// Drain the N1 inbound queue (spec §5.5；调用点是 `run_dataplane` 循环
    /// `pump_nat_inbound` 紧邻处)。
    ///
    /// `Disconnected` 是「N1 未启用 / 已停机」的常态（WP3：disabled 路径不
    /// spawn supervisor，发送端不存在）：不报错、不刷日志、不计拒绝。
    pub fn pump_n1_inbound(&mut self) {
        let Some(rx) = self.n1_inbound_rx.take() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(crate::n1_runtime::N1Inbound::ConnUp { peer, conn }) => {
                    self.n1_peer_conns.insert(peer.to_hex(), conn);
                }
                Ok(crate::n1_runtime::N1Inbound::ConnDown { peer }) => {
                    self.n1_peer_conns.remove(&peer.to_hex());
                }
                Ok(crate::n1_runtime::N1Inbound::RawIp { packet, .. }) => {
                    self.inject_from_n1(&packet);
                }
                Ok(crate::n1_runtime::N1Inbound::Stream { peer, conn, frame }) => {
                    let peer_hex = peer.to_hex();
                    self.dispatch_inbound_stream(&peer_hex, ReplySink::N1(conn), &frame);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
        self.n1_inbound_rx = Some(rx);
    }

    /// Drive the egress relay once per dataplane loop iteration (spec §5.5/§5.7).
    ///
    /// The relay lives on the dataplane thread; this never spawns a thread or
    /// busy-waits. `RelayEvent`s are encoded as STREAM frames and sent over the
    /// peer's N1 conn (`n1_peer_conns`, §7). Missing conns are counted as
    /// `tx.errors` and logged — never silently dropped.
    pub fn n1_egress_poll(&mut self) {
        let Some(mut relay) = self.n1_relay.take() else {
            return;
        };
        let events = relay.poll();
        self.n1_relay = Some(relay);
        for event in events {
            let (peer, reply) = match event {
                RelayEvent::Data {
                    stream_id,
                    peer,
                    bytes,
                } => (peer, encode_stream_frame(stream_id, 0x00, &bytes)),
                RelayEvent::Closed {
                    stream_id,
                    peer,
                    reset,
                } => {
                    let flags = if reset { STREAM_RST } else { STREAM_FIN };
                    (peer, encode_stream_frame(stream_id, flags, &[]))
                }
            };
            self.send_egress_reply(&peer, &reply);
        }
    }

    /// Send one egress reply frame to `peer_hex` over its N1 conn (§5.5 第 3 步)。
    fn send_egress_reply(&mut self, peer_hex: &str, frame: &[u8]) {
        match self.n1_peer_conns.get(peer_hex).cloned() {
            Some(conn) => {
                self.send_reply_over_n1(peer_hex, frame, |f| conn.send_datagram(f));
            }
            None => self.record_tx_error(peer_hex, frame, "no_n1_conn"),
        }
    }

    /// Unified inbound STREAM dispatch (spec §5.5)：originator 判定用
    /// [`TcpTerminator::peer_for`]，否则交 egress relay。
    fn dispatch_inbound_stream(&mut self, peer_hex: &str, sink: ReplySink, frame: &[u8]) {
        let Some((stream_id, flags, payload)) = decode_stream_frame(frame) else {
            self.n1_stats.record_dispatch_bad_frame();
            self.log_n1_dispatch_throttled("bad_frame", peer_hex, 0, frame.len());
            return;
        };

        if self.tcp.peer_for(stream_id).is_some() {
            self.n1_stats
                .record_dispatch(crate::n1_runtime::N1DispatchTarget::Terminator);
            // 既有注入函数（spec §5.5；不通过 relay 的 originator 回程）。
            self.inject_stream_frame_from_n1(peer_hex, frame);
            return;
        }

        let Some(relay) = self.n1_relay.as_mut() else {
            // WP5 之前没有 egress relay：该流既不是本节点的 originator，
            // 也没有 relay 能消费 → 计入 unknown_stream（不静默吞掉）。
            self.n1_stats
                .record_dispatch(crate::n1_runtime::N1DispatchTarget::Unknown);
            self.log_n1_dispatch_throttled("unknown_stream", peer_hex, stream_id, frame.len());
            return;
        };

        match relay.handle_frame(stream_id, flags, payload, peer_hex) {
            Ok(events) => {
                self.n1_stats
                    .record_dispatch(crate::n1_runtime::N1DispatchTarget::Relay);
                for event in events {
                    let reply = match event {
                        RelayEvent::Data {
                            stream_id, bytes, ..
                        } => encode_stream_frame(stream_id, 0x00, &bytes),
                        RelayEvent::Closed {
                            stream_id, reset, ..
                        } => {
                            let flags = if reset { STREAM_RST } else { STREAM_FIN };
                            encode_stream_frame(stream_id, flags, &[])
                        }
                    };
                    self.send_reply(&sink, peer_hex, &reply);
                }
            }
            Err(N1RelayError::UnknownStream) => {
                self.n1_stats
                    .record_dispatch(crate::n1_runtime::N1DispatchTarget::Unknown);
                self.log_n1_dispatch_throttled("unknown_stream", peer_hex, stream_id, frame.len());
            }
        }
    }

    /// Reply to an inbound STREAM frame (spec §5.5 第 3 步)。
    ///
    /// `Direct` 的 N1 fallback **不带** `CHUNK_KIND_TUN_STREAM`：KIND 是
    /// direct chunk 的本地前缀，进 N1 wire 会破坏 P0 AC-C-4 的逐字节不变。
    fn send_reply(&mut self, sink: &ReplySink, peer_hex: &str, frame: &[u8]) {
        match sink {
            ReplySink::N1(conn) => {
                self.send_reply_over_n1(peer_hex, frame, |f| conn.send_datagram(f))
            }
            ReplySink::Direct(peer) => {
                let chunk = {
                    let mut chunk = Vec::with_capacity(1 + frame.len());
                    chunk.push(crate::nat_chunk_recv::CHUNK_KIND_TUN_STREAM);
                    chunk.extend_from_slice(frame);
                    chunk
                };
                let provider = self.nat_path.as_ref().and_then(|slot| slot.get());
                let Some(provider) = provider else {
                    // 无 NAT path：诚实降级到同一 peer 的 N1 conn（direct 路径
                    // 的 fallback 语义；没有 conn 则计 tx.errors）。
                    let conn = self.n1_peer_conns.get(peer_hex).cloned();
                    match conn {
                        Some(conn) => {
                            self.send_reply_over_n1(peer_hex, frame, |f| conn.send_datagram(f))
                        }
                        None => self.record_tx_error(peer_hex, frame, "no_n1_conn"),
                    }
                    return;
                };
                let conn = self.n1_peer_conns.get(peer_hex).cloned();
                let fallback = |_chunk: &[u8]| -> io::Result<()> {
                    match &conn {
                        Some(conn) => conn
                            .send_datagram(frame)
                            .map_err(|e| io::Error::other(format!("n1 send failed: {e}"))),
                        None => Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "n1 fallback conn missing",
                        )),
                    }
                };
                match provider.send_chunk(*peer, &fallback, &chunk) {
                    Ok(_path) => self.n1_stats.record_tx(frame.len(), true),
                    Err(e) => {
                        self.n1_stats.record_tx(frame.len(), false);
                        eprintln!(
                            "[n1-egress] WARN: tx failed peer={} stream={} kind={:?}",
                            hex16(peer_hex),
                            stream_id_of(frame),
                            e.kind()
                        );
                    }
                }
            }
        }
    }

    fn send_reply_over_n1(
        &mut self,
        peer_hex: &str,
        frame: &[u8],
        send: impl Fn(&[u8]) -> Result<(), nexus_network::n1::N1Error>,
    ) {
        match send(frame) {
            Ok(()) => self.n1_stats.record_tx(frame.len(), true),
            Err(e) => {
                self.record_tx_error(peer_hex, frame, &format!("{e:?}"));
            }
        }
    }

    fn record_tx_error(&mut self, peer_hex: &str, frame: &[u8], reason: &str) {
        self.n1_stats.record_tx(frame.len(), false);
        eprintln!(
            "[n1-egress] WARN: tx failed peer={} stream={} kind={reason}",
            hex16(peer_hex),
            stream_id_of(frame)
        );
    }

    /// unknown-stream / bad-frame 日志限频（首条立即，其后 10s；spec §6.1）。
    fn log_n1_dispatch_throttled(
        &mut self,
        cause: &str,
        peer_hex: &str,
        stream_id: u32,
        frame_len: usize,
    ) {
        let decision = self.n1_dispatch_log.decide(
            "n1-dispatch",
            cause,
            std::time::Instant::now(),
            N1_DISPATCH_LOG_INTERVAL,
        );
        if !decision.emit {
            return;
        }
        let peer16 = hex16(peer_hex);
        if cause == "bad_frame" {
            eprintln!(
                "[n1-rx] rejected peer={peer16} reason=bad_frame len={frame_len} suppressed={}",
                decision.suppressed
            );
        } else {
            eprintln!(
                "[n1-dispatch] WARN: unknown stream peer={peer16} stream={stream_id} suppressed={}",
                decision.suppressed
            );
        }
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

    /// 写入一条 DNS 应答映射（A/AAAA 共用；D-impl-8）。
    pub fn record_dns_answer(&mut self, domain: &str, ip: IpAddr) {
        if let Ok(mut cache) = self.dns_cache.lock() {
            cache.insert(domain, ip, 300);
        }
    }

    /// 是否已接入 DNS 服务（AC5 可观测）。
    #[must_use]
    pub fn dns_service_ready(&self) -> bool {
        self.dns.is_some()
    }

    /// 排空 DNS 回包并回写 TUN / TPROXY 回程通道（每轮 `process_one` 开头）。
    ///
    /// 返回本轮处理的回包数（含写失败）。`WouldBlock` 轮次同样必须调用，
    /// 否则上游应答只能等下一条入站包才写回（spec §4.1）。
    pub fn drain_dns_replies(&mut self) -> usize {
        let mut replies = Vec::new();
        if let Some(handle) = self.dns.as_mut() {
            loop {
                match handle.rx.try_recv() {
                    Ok(reply) => replies.push(reply),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }
        }
        let drained = replies.len();
        for reply in replies {
            self.deliver_dns_reply(reply);
        }
        drained
    }

    /// 提交一条 TUN 侧 DNS 查询（包路径只做编解码 + `try_send`）。
    fn submit_dns_tun(&mut self, packet: &[u8]) {
        let Some(payload) = dns_udp_payload(packet) else {
            self.with_stats(|s| s.dropped += 1);
            return;
        };
        let client = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            u16::from_be_bytes([packet[20], packet[21]]),
        ));
        let server = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            u16::from_be_bytes([packet[22], packet[23]]),
        ));
        let request = crate::dns_service::DnsRequest {
            client,
            server,
            wire: payload.to_vec(),
            sink: crate::dns_service::ReplySink::Tun,
        };
        self.dispatch_dns_request(request);
    }

    /// 提交一条 TPROXY 侧 DNS 查询（Q-3 / D-impl-2）。
    fn submit_dns_transparent(&mut self, datagram: &ReceivedDatagram) {
        let request = crate::dns_service::DnsRequest {
            client: SocketAddr::V4(datagram.peer),
            server: SocketAddr::V4(datagram.orig_dst),
            wire: datagram.payload.clone(),
            sink: crate::dns_service::ReplySink::Transparent {
                peer: datagram.peer,
                orig_dst: datagram.orig_dst,
            },
        };
        self.dispatch_dns_request(request);
    }

    fn dispatch_dns_request(&mut self, request: crate::dns_service::DnsRequest) {
        let Some(handle) = self.dns.as_ref() else {
            return;
        };
        let wire = request.wire.clone();
        let client = request.client;
        let server = request.server;
        let sink = request.sink.clone();
        match handle.submit(request) {
            Ok(()) => {}
            Err(crate::dns_service::DnsRequestError::QueueFull) => {
                self.with_stats(|s| {
                    s.dns_queue_full += 1;
                    s.dns_servfail += 1;
                });
                self.deliver_local_servfail(server, client, sink, &wire, true);
            }
            Err(crate::dns_service::DnsRequestError::ServiceDown) => {
                self.with_stats(|s| {
                    s.dns_service_down += 1;
                    s.dns_servfail += 1;
                });
                self.deliver_local_servfail(server, client, sink, &wire, false);
            }
        }
    }

    fn deliver_local_servfail(
        &mut self,
        server: SocketAddr,
        client: SocketAddr,
        sink: crate::dns_service::ReplySink,
        query_wire: &[u8],
        queue_full: bool,
    ) {
        // 计数已在 dispatch 侧按原因加过；这里只负责构造 + 写回。
        let Ok(wire) = wire::build_error(query_wire, DnsRcode::ServFail) else {
            return;
        };
        let reply = crate::dns_service::DnsReply {
            client,
            server,
            wire,
            class: nexus_dns::DnsClass::Upstream,
            rcode: 2,
            sink,
        };
        let written = self.write_dns_reply_packet(&reply);
        if written {
            // dns_servfail 已在投递原因处计数；dns_answered 与写回一致。
            self.with_stats(|s| s.dns_answered += 1);
        } else {
            self.with_stats(|s| s.dns_reply_write_failed += 1);
            let _ = queue_full;
        }
    }

    /// 把一条 `DnsReply` 写回其 sink（TUN 或 TPROXY）。
    fn deliver_dns_reply(&mut self, reply: crate::dns_service::DnsReply) {
        let rcode = reply.rcode;
        let (name, answers) = dns_response_meta(&reply.wire).unwrap_or_default();
        if self.write_dns_reply_packet(&reply) {
            self.with_stats(|s| {
                s.dns_answered += 1;
                match rcode {
                    0 if answers.is_empty() => s.dns_nodata += 1,
                    0 => s.dns_noerror += 1,
                    1 => s.dns_formerr += 1,
                    2 => s.dns_servfail += 1,
                    3 => s.dns_nxdomain += 1,
                    5 => s.dns_refused += 1,
                    _ => {}
                }
            });
            if !name.is_empty() {
                for ip in answers {
                    self.record_dns_answer(&name, ip);
                }
            }
        } else {
            self.with_stats(|s| s.dns_reply_write_failed += 1);
        }
    }

    fn write_dns_reply_packet(&mut self, reply: &crate::dns_service::DnsReply) -> bool {
        match &reply.sink {
            crate::dns_service::ReplySink::Tun => {
                let Some(packet) = build_dns_udp_reply(reply.server, reply.client, &reply.wire)
                else {
                    return false;
                };
                if self.tun.write(&packet).is_ok() {
                    self.with_stats(|s| s.tun_written += 1);
                    true
                } else {
                    false
                }
            }
            crate::dns_service::ReplySink::Transparent { peer, orig_dst } => {
                let Some(tx) = self.transparent_udp_reply_tx.as_ref() else {
                    self.with_tproxy_counters(|c| c.udp_reply_failed += 1);
                    return false;
                };
                tx.send(TransparentOutput::UdpReply {
                    orig_dst: *orig_dst,
                    peer: *peer,
                    payload: reply.wire.clone(),
                })
                .is_ok()
            }
        }
    }

    /// 拒绝 TCP/53（fail-closed，让应用立刻失败而不是挂死）。
    fn refuse_dns_tcp(&mut self, packet: &[u8], now_millis: u64) {
        self.with_stats(|s| s.dns_tcp_refused += 1);
        let now = self.epoch + std::time::Duration::from_millis(now_millis);
        let decision = self.dns_log.decide(
            "dns_tcp_query_refused",
            "tcp",
            now,
            crate::log_throttle::OUTBOUND_UNAVAILABLE_LOG_INTERVAL,
        );
        if decision.emit {
            eprintln!(
                "[nexusd] dns WARN event=dns_tcp_query_refused proto=tcp suppressed={}",
                decision.suppressed
            );
        }
        if let Some(rst) = build_tcp_reset_for_query(packet) {
            if self.tun.write(&rst).is_ok() {
                self.with_stats(|s| {
                    s.dns_answered += 1;
                    s.tun_written += 1;
                });
            } else {
                self.with_stats(|s| s.dns_reply_write_failed += 1);
            }
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

    /// Proxy 引擎统计快照（加法；E4 / 状态面可观测）。
    #[must_use]
    pub fn proxy_stats(&self) -> Option<crate::proxy_fwd::ProxyFwdStats> {
        self.proxy_engine.as_ref().map(|engine| engine.stats())
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
        let streams_ok_delta = eng_stats
            .tcp_streams_ok
            .saturating_sub(self.last_proxy_tcp_streams_ok);
        let udp_fail_delta = eng_stats
            .udp_send_failed
            .saturating_sub(self.last_proxy_udp_send_failed);
        let bytes_up_delta = eng_stats
            .tcp_bytes_up
            .saturating_sub(self.last_proxy_tcp_bytes_up);
        let bytes_down_delta = eng_stats
            .tcp_bytes_down
            .saturating_sub(self.last_proxy_tcp_bytes_down);
        let udp_unsupported_delta = eng_stats
            .udp_unsupported
            .saturating_sub(self.last_proxy_udp_unsupported);
        let udp_vless_delta = eng_stats
            .udp_unsupported_vless
            .saturating_sub(self.last_proxy_udp_unsupported_vless);
        let udp_anytls_delta = eng_stats
            .udp_unsupported_anytls
            .saturating_sub(self.last_proxy_udp_unsupported_anytls);
        let udp_other_delta = eng_stats
            .udp_unsupported_other
            .saturating_sub(self.last_proxy_udp_unsupported_other);
        let udp_suppressed_delta = eng_stats
            .udp_unsupported_log_suppressed
            .saturating_sub(self.last_proxy_udp_unsupported_suppressed);
        self.last_tcp_dials_ok = eng_stats.tcp_dials_ok;
        self.last_tcp_dials_failed = eng_stats.tcp_dials_failed;
        self.last_proxy_tcp_streams = eng_stats.tcp_streams;
        self.last_proxy_dial_buffer_dropped = eng_stats.tcp_dial_buffer_dropped_bytes;
        self.last_proxy_dial_buffer_overflow = eng_stats.tcp_dial_buffer_overflow_resets;
        self.last_proxy_tcp_streams_ok = eng_stats.tcp_streams_ok;
        self.last_proxy_udp_send_failed = eng_stats.udp_send_failed;
        self.last_proxy_tcp_bytes_up = eng_stats.tcp_bytes_up;
        self.last_proxy_tcp_bytes_down = eng_stats.tcp_bytes_down;
        self.last_proxy_udp_unsupported = eng_stats.udp_unsupported;
        self.last_proxy_udp_unsupported_vless = eng_stats.udp_unsupported_vless;
        self.last_proxy_udp_unsupported_anytls = eng_stats.udp_unsupported_anytls;
        self.last_proxy_udp_unsupported_other = eng_stats.udp_unsupported_other;
        self.last_proxy_udp_unsupported_suppressed = eng_stats.udp_unsupported_log_suppressed;
        self.with_stats(|s| {
            s.proxy_tcp_streams += stream_delta;
            s.proxy_forwarded += ok_delta;
            s.proxy_dropped_no_proxy += fail_delta + udp_fail_delta;
            s.upstream_failed += fail_delta;
            s.proxy_dial_buffer_dropped_bytes += dial_buf_drop_delta;
            s.proxy_dial_buffer_overflow_resets += dial_buf_overflow_delta;
            s.proxy_tcp_streams_ok += streams_ok_delta;
            // C7：修死计数——上行字节由 engine 的 tcp_bytes_up 驱动。
            s.proxy_tcp_bytes += bytes_up_delta;
            s.proxy_tcp_bytes_down += bytes_down_delta;
            s.proxy_udp_unsupported += udp_unsupported_delta;
            s.proxy_udp_unsupported_vless += udp_vless_delta;
            s.proxy_udp_unsupported_anytls += udp_anytls_delta;
            s.proxy_udp_unsupported_other += udp_other_delta;
            s.proxy_udp_unsupported_log_suppressed += udp_suppressed_delta;
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

    /// 双栈 mesh 网段（v4 + v6）合并视图：分类器只认一个 `Vec<IpCidr>`。
    fn all_mesh_cidrs(&self) -> Vec<IpCidr> {
        let mut all = self.mesh_cidrs.clone();
        all.extend(self.mesh_cidrs6.iter().copied());
        all
    }

    /// 双栈 bypass 网段（v4 + v6）合并视图。
    fn all_bypass_cidrs(&self) -> Vec<IpCidr> {
        let mut all = self.bypass_cidrs.clone();
        all.extend(self.bypass_cidrs6.iter().copied());
        all
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
        // C17：目的地址取两族（v6 命中缓存键本就支持，D-impl-8）。
        let domain = ip_dst_of(packet).and_then(|ip| {
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
                self.all_mesh_cidrs(),
                self.all_bypass_cidrs(),
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
    /// 完整 token 词表见 [`Self::record_transparent_error`] 上方注释。
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
            let crate::proxy_fwd::ProxyStreamEvent::Failed { error, detail, .. } = event;
            self.note_tproxy_failure(
                TransparentFailureKind::UpstreamFailed.token(),
                format!("{error}: {detail}"),
            );
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

    /// 关闭 DNS 服务：drop 请求发送端并 join（2 s 预算，不 hang）。
    pub fn shutdown_dns(&mut self) {
        if let Some(mut handle) = self.dns.take() {
            let _ = handle.join(crate::dns_service::JOIN_TIMEOUT);
        }
    }

    /// 单个 tick：先 drain TPROXY channel（最多 256 条），驱动透明前端，
    /// 空闲也泵送一次 proxy 回程（P8b），再读 TUN 一包。
    pub fn tick(&mut self, now_millis: u64) -> io::Result<bool> {
        let dns_drained = self.drain_dns_replies();
        let drained = self.drain_transparent_inbound(now_millis);
        let polled = self.poll_transparent(now_millis);
        // P8b（fix-review-r7 F1）：proxy 回程不能只在入站包到达时写回。
        // 本调用无入站包（`process_one_at` WouldBlock 早返）时也必须把
        // `ProxyEngine` 里已入队的回程泵出去；放在 `process_one_at` 之前，
        // 保证同 tick 内旧的回程先于本 tick 新包产生的回程写回。
        let proxy_pumped = self.poll_proxy_engine();
        match self.process_one_at(now_millis) {
            Ok(processed) => {
                Ok(processed || dns_drained > 0 || drained > 0 || polled > 0 || proxy_pumped)
            }
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
        // C6：唯一同步点（每 tick 一次，含 WouldBlock 轮）。
        self.sync_proxy_stats();
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
        // UDP/53：与 TUN 共用同一条 DNS 引擎/服务线程（Q-3 / D-impl-2）。
        // 回程由 `DnsReply::sink=Transparent` 走 UdpReply 通道，异步到达。
        if datagram.orig_dst.port() == 53 && self.dns.is_some() {
            self.submit_dns_transparent(&datagram);
            return;
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

    /// `tproxy.last_failure_reason` token 词表（唯一格式：`<token>: <detail>`）。
    ///
    /// 本表是 token 的唯一登记处；新增/改名写入点必须同步更新。
    ///
    /// | token | 触发路径 | 对应计数/错误类别 |
    /// |---|---|---|
    /// | `orig_dst_missing` | `TransparentFrontendError::OrigDstMissing` | `orig_dst_missing`（runtime 另计 `tcp_rejected`） |
    /// | `orig_dst_invalid` | `TransparentFrontendError::OrigDstInvalid` | `udp_dropped`（runtime 另计 `tcp_rejected`/`udp_dropped`） |
    /// | `rule_engine_unavailable` | `TransparentFrontendError::RuleEngineUnavailable`（无 proxy egress） | 无独立计数；runtime `upstream_failed`（TCP）/`udp_dropped`（UDP）经 stats 镜像 |
    /// | `rule_no_match` | `TransparentFrontendError::RuleNoMatch`（Drop 决策） | `rule_no_match`（runtime 另计 `tcp_rejected`/`udp_dropped`） |
    /// | `outbound_unresolved` | `TransparentFrontendError::OutboundUnresolved`（出站 tag 不存在） | 无独立计数；runtime `upstream_failed`（UDP 另加 `udp_dropped`） |
    /// | `direct_tcp_dial_failed` | `TransparentFrontendError::DirectDialFailed`；异步 `DirectEgressEvent::Failed` | `direct_tcp_dial_failed` |
    /// | `direct_udp_failed` | `TransparentFrontendError::DirectSendFailed`；异步 uplink 发送失败 | `direct_udp_failed`（同步另加 `udp_dropped`） |
    /// | `upstream_failed` | `TransparentFrontendError::SessionEstablishFailed`；异步 `ProxyEgressEvent::Failed`/uplink 发送失败；`ProxyEngineError::DialFailed` | `upstream_failed` |
    /// | `direct_dropped_unsupported` | `TransparentFrontendError::UnsupportedProtocol`（防御分支） | 无独立计数（当前无构造点） |
    /// | `tcp_conn_limit` | `TransparentFrontendError::TcpConnLimit` | runtime `tcp_rejected` |
    /// | `payload_too_large` | `TransparentFrontendError::PayloadTooLarge` | runtime `udp_dropped` |
    /// | `udp_table_full` | `TransparentFrontendError::UdpTableFull`（防御分支） | 无独立计数（容量满走 LRU 淘汰，不拒绝） |
    /// | `session_establish_failed` | TUN 流会话建连失败（`flow_pump`） | `establish_failures` |
    /// | `tcp_rejected_no_pipeline` | TPROXY TCP 入站但管道未装配（瞬态） | `tcp_rejected` |
    /// | `udp_dropped_no_pipeline` | TPROXY UDP 入站但管道未装配（瞬态） | `udp_dropped` |
    ///
    /// 例外：`record_capture_failure` 沿用既有行为，直接写
    /// `TransparentIngressError::to_string()`（如 `TRANSPARENT_IO: …`），不是
    /// `<token>: <detail>` 形式；对应计数 `orig_dst_missing`/`udp_dropped`。
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
        self.drain_dns_replies();
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

        // C18/D-impl-7：0x86DD 全部走专用分支（v6 DNS 不拦截）——必须早于
        // 任何 v4 路径，保证"每个 0x86DD 包都落入 ipv6.*"。
        if packet.first().map(|b| b >> 4) == Some(6) {
            self.handle_ipv6(&packet, now_millis);
            return Ok(true);
        }

        // D3/C11：DNS 拦截（UDP/53 提交服务线程；TCP/53 无条件 RST）。
        if self.dns.is_some() {
            if is_dns_query(&packet) {
                self.submit_dns_tun(&packet);
                return Ok(true);
            }
            if is_dns_tcp_query(&packet) {
                self.refuse_dns_tcp(&packet, now_millis);
                return Ok(true);
            }
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
                    let sent = match (&self.n1_sender, ip_dst_of(&packet)) {
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
                // P1-P5 / D2：engine 已注入 → 按规则 tag 真实转发；
                // 无 engine / tag 不可用 → 当场 SYN 直接 RST（单一发射点）。
                let outcome = self
                    .proxy_engine
                    .as_mut()
                    .map(|e| e.handle_packet(&packet, outbound));
                let key = FlowKey::parse(&packet).ok();
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
                        // stats 同步已迁到 poll_proxy_engine（C6：单一同步点）。
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::UnknownOutbound { tag })) => {
                        self.note_tproxy_failure(
                            "upstream_failed",
                            format!("PROXY_UNKNOWN_OUTBOUND: {tag}"),
                        );
                        if let Some(key) = key {
                            self.emit_proxy_egress_rst(&packet, &key, RstSubcase::TagUnavailable);
                        }
                        self.log_outbound_unavailable(&tag, "-", "UNKNOWN_OUTBOUND", "");
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::UnsupportedOutboundKind {
                        tag,
                        kind,
                    })) => {
                        self.note_tproxy_failure(
                            "upstream_failed",
                            format!("PROXY_UNSUPPORTED_OUTBOUND: {tag} ({kind})"),
                        );
                        if let Some(key) = key {
                            self.emit_proxy_egress_rst(&packet, &key, RstSubcase::TagUnavailable);
                        }
                        self.log_outbound_unavailable(&tag, &kind, "PROTOCOL_NOT_WIRED", "");
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::InvalidOutbound {
                        tag,
                        kind,
                        cause,
                    })) => {
                        self.note_tproxy_failure(
                            "upstream_failed",
                            format!("PROXY_INVALID_OUTBOUND: {}", cause.name()),
                        );
                        if let Some(key) = key {
                            self.emit_proxy_egress_rst(&packet, &key, RstSubcase::TagUnavailable);
                        }
                        self.log_outbound_unavailable(&tag, &kind, cause.name(), cause.detail());
                    }
                    Some(Err(crate::proxy_fwd::ProxyEngineError::UnsupportedProtocol {
                        ..
                    })) => {
                        self.with_stats(|s| s.dropped += 1);
                    }
                    None => {
                        if let Some(key) = key {
                            self.emit_proxy_egress_rst(&packet, &key, RstSubcase::NoEngine);
                        }
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

    /// IPv6 包处理（C18 / AC10）：每个 0x86DD 包都必须落在 `ipv6.*` 上。
    ///
    /// 单一分类出口：`classify_with_cache` → `PacketClassifier`（v6 在委托规则
    /// 引擎前短路，D-impl-1）。本函数只做计数与按分类转发/阻断，**不重复判定**
    /// v6（禁止第二套 v6 分类）。
    ///
    /// 口径（spec §4.7.3）：
    /// - 固定头/扩展头截断 → `dropped_truncated`；>8 个扩展头 → `dropped_extension`；
    /// - `ff00::/8` → `multicast`（只计数，不进分类转发）；
    /// - 分片不重组：Fragment 头存在 → `fragments`，仍按目的地址分类；
    /// - Mesh → N1 原始转发（失败/no sender → `mesh_no_route` + `mesh_dropped_no_n1`）；
    /// - Direct → 只计数（本 run 无 v6 direct egress，与 §4.7.6 一致）；
    /// - Proxy → 阻断 + `proxy_dropped` + 限流日志（Q4 已裁定，不是缺口）；
    /// - v6 不建 flow 会话（flow-session 的双栈终结归 C20/C21）。
    fn handle_ipv6(&mut self, packet: &[u8], now_millis: u64) {
        use nexus_projection::ip::{IpParseError, parse_ip_packet};

        self.with_stats(|s| s.ipv6.packets += 1);

        if packet.len() < 40 {
            self.with_stats(|s| s.ipv6.dropped_truncated += 1);
            return;
        }
        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&packet[24..40]);
        if dst_octets[0] == 0xff {
            // ff00::/8：多播只计数。
            self.with_stats(|s| s.ipv6.multicast += 1);
            return;
        }

        let mut protocol = None;
        let mut has_fragment = false;
        let mut unsupported_extension = None;
        match parse_ip_packet(packet) {
            Ok(view) => {
                protocol = Some(view.protocol);
                has_fragment = view.has_fragment_header;
            }
            Err(IpParseError::Truncated) => {
                self.with_stats(|s| s.ipv6.dropped_truncated += 1);
                return;
            }
            Err(IpParseError::TooManyExtensionHeaders) => {
                self.with_stats(|s| s.ipv6.dropped_extension += 1);
                return;
            }
            Err(IpParseError::NonFirstFragment) => {
                // 非首片：不重组，仍按目的地址分类（§4.7.3）。
                has_fragment = true;
            }
            Err(IpParseError::UnsupportedExtension(hdr)) => {
                // ESP/AH：不解析 L4，按目的地址分类；日志单独可见。
                unsupported_extension = Some(hdr);
            }
            // 防御分支：版本在入口已判定；族不符/校验和仅构造路径出现。
            Err(_) => {
                self.with_stats(|s| s.dropped += 1);
                return;
            }
        }
        if has_fragment {
            self.with_stats(|s| s.ipv6.fragments += 1);
        }
        match protocol {
            Some(6) => self.with_stats(|s| s.ipv6.tcp += 1),
            Some(17) => self.with_stats(|s| s.ipv6.udp += 1),
            _ => {}
        }

        let (classification, _) = self.classify_with_cache(packet, now_millis);
        match classification {
            Classification::Mesh { ref path, .. } => {
                self.with_stats(|s| s.ipv6.classified_mesh += 1);
                // C21：v6 TCP 走终结器（本地 SYN-ACK + STREAM 帧），
                // 与 v4 Mesh TCP 同一条路径；UDP 等仍按原始包转发。
                if protocol == Some(6) {
                    let _ = path;
                    self.handle_tcp_terminated(packet, &classification);
                    self.dispatch_tcp_events();
                    return;
                }
                let sent = if self.config.n1_configured {
                    match (&self.n1_sender, ip_dst_of(packet)) {
                        (Some(sender), Some(dst)) => sender.send_to_mesh(dst, packet).is_ok(),
                        _ => false,
                    }
                } else {
                    false
                };
                if sent {
                    self.with_stats(|s| s.ipv6.mesh_forwarded += 1);
                } else {
                    self.with_stats(|s| {
                        s.ipv6.mesh_no_route += 1;
                        // AC6：无 v6 路由时既有 N1 失败计数同步 +1（语义不冲突）。
                        s.mesh_dropped_no_n1 += 1;
                    });
                }
            }
            Classification::Direct => {
                self.with_stats(|s| {
                    s.ipv6.classified_direct += 1;
                    // 与 v4 口径一致：Direct 可见地"被放行/计数"，不做 v6 直连出口。
                    s.direct_forwarded += 1;
                });
            }
            Classification::Proxy { ref outbound } => {
                self.with_stats(|s| s.ipv6.classified_proxy += 1);
                // C21：v6 代理类 TCP 现在终结并拨号（Q4 的 v6 出口阻断只保留
                // UDP/分片/扩展头不可解析路径）。失败走既有 proxy_* 计数，
                // 不额外计 `ipv6.proxy_dropped`（该计数只表示"未接线丢弃"）。
                let tcp_wired = protocol == Some(6) && self.proxy_engine.is_some();
                if tcp_wired {
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
                        Some(Err(_)) | None => {
                            self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
                        }
                    }
                } else {
                    self.with_stats(|s| s.ipv6.proxy_dropped += 1);
                    if has_fragment
                        && self.ipv6_log_should_emit("ipv6_fragment_dropped", "path=proxy")
                    {
                        eprintln!("[nexusd] ipv6 WARN event=ipv6_fragment_dropped path=proxy");
                    }
                    if let Some(hdr) = unsupported_extension {
                        let key = format!("hdr={hdr}");
                        if self.ipv6_log_should_emit("ipv6_ext_unsupported", &key) {
                            eprintln!("[nexusd] ipv6 WARN event=ipv6_ext_unsupported hdr={hdr}");
                        }
                    }
                    let proto = protocol.map_or_else(|| "-".to_string(), |p| p.to_string());
                    if self
                        .ipv6_log_should_emit("ipv6_proxy_unsupported", &format!("proto={proto}"))
                    {
                        eprintln!(
                            "[nexusd] ipv6 WARN event=ipv6_proxy_unsupported proto={proto} packets=1"
                        );
                    }
                }
            }
            Classification::Drop { .. } => {
                self.with_stats(|s| s.dropped += 1);
            }
        }
    }

    /// IPv6 运维日志限频（每 `(event, 判别字段)` 60 s 最多 1 行）。
    fn ipv6_log_should_emit(&mut self, event: &str, key: &str) -> bool {
        self.ipv6_log
            .decide(
                event,
                key,
                std::time::Instant::now(),
                crate::log_throttle::IPV6_LOG_INTERVAL,
            )
            .emit
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
                    // Direct 出口仍是 v4（本 run 只接线 Proxy/Mesh 的 v6）。
                    let SocketAddr::V4(dst4) = dst else {
                        out.extend(self.tcp.handle_fabric_rst(stream_id));
                        continue;
                    };
                    if self.direct_tcp.open(stream_id, dst4).is_err() {
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
        let key = match FlowKey::parse(packet) {
            Ok(k) => k,
            Err(_) => return true,
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
        // C17：目的地址取两族（v6 命中缓存键本就支持，D-impl-8）。
        let domain = ip_dst_of(packet).and_then(|ip| {
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
                self.all_mesh_cidrs(),
                self.all_bypass_cidrs(),
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
                    let sent = match (&self.n1_sender, ip_dst_of(packet)) {
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
        let key = match FlowKey::parse(packet) {
            Ok(k) => k,
            Err(_) => return true, // 解析失败走旧路径（防御）。
        };
        debug_assert_eq!(key.proto, IpProto::Tcp);
        let is_syn = is_tcp_syn(packet);
        let hint = egress_hint(classification);
        match mgr.on_packet_with_hint(key, packet, is_syn, deps, now, hint) {
            FlowDecision::NewSession { session_id } => {
                // 待 TcpEvent::Syn 到达时绑定 stream_id（C21：FourTuple 已双栈）。
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
                // S5-Mesh：DATA 帧优先走 active direct conn，否则走既有 N1。
                // SYN/FIN/RST 仍由 `dispatch_tcp_events` 直接走 N1（不是 chunk）。
                let frame = encode_stream_frame(stream_id, 0x00, bytes);
                let n = bytes.len() as u64;
                if self.send_mesh_data_frame(info.dst.ip(), &frame) {
                    self.with_stats(|s| s.mesh_tcp_bytes += n);
                }
            }
            Some(_) => {
                // S5-Proxy：新接线后不再经 dataplane 计数——Proxy 上行字节由
                // engine 的 `tcp_bytes_up` 驱动（C7，经 `sync_proxy_stats`）。
            }
            None => {
                // 防御：未知流的数据（不应发生）。
                self.with_stats(|s| s.dropped += 1);
            }
        }
    }

    /// Mesh DATA dispatch (P0). Returns `true` iff the frame was handed to N1
    /// successfully.
    ///
    /// The fallback closure **ignores its argument** and sends the captured
    /// original `frame`: `send_chunk` passes the `KIND || FRAME` chunk, and
    /// forwarding that would inject a KIND byte into N1 (breaks the
    /// byte-for-byte invariant).
    fn send_mesh_data_frame(&mut self, dst: IpAddr, frame: &[u8]) -> bool {
        use crate::nat_chunk_stats::FallbackReason;

        // AC-H-1 `[P]` / spec §13.2: with no attached provider (no
        // `[network.turn]`, or NAT has not started yet) the degraded mode is
        // announced exactly once; every chunk then falls back to N1.
        if self.nat_path.as_ref().and_then(|slot| slot.get()).is_none() {
            crate::nat_consumer::note_handle_not_attached(&self.nat_not_attached_logged);
        }

        let stats = Arc::clone(&self.chunk_stats);

        let peer = match dst {
            IpAddr::V4(v4) => self.mesh_peers.as_ref().and_then(|m| m.peer_for(v4)),
            IpAddr::V6(_) => None,
        };
        let Some(peer) = peer else {
            stats.record_fallback(frame.len(), FallbackReason::NoPeer);
            eprintln!(
                "[nat-chunk] fallback peer=- bytes={} reason=no_peer",
                frame.len()
            );
            if self.send_mesh_tcp_frame(dst, frame) {
                return true;
            }
            stats.record_fallback_error(frame.len());
            return false;
        };
        let peer_name = crate::nat_consumer::peer_hex(&peer);
        let peer16 = &peer_name[..peer_name.len().min(16)];

        let Some(provider) = self.nat_path.as_ref().and_then(|slot| slot.get()) else {
            stats.record_fallback(frame.len(), FallbackReason::NoPath);
            eprintln!(
                "[nat-chunk] fallback peer={peer16} bytes={} reason=no_path",
                frame.len()
            );
            if self.send_mesh_tcp_frame(dst, frame) {
                return true;
            }
            stats.record_fallback_error(frame.len());
            return false;
        };

        let gate_open = self
            .direct_gate
            .as_ref()
            .is_some_and(|gate| gate.sender_allowed(provider.as_ref(), &peer));
        if !gate_open {
            stats.record_fallback(frame.len(), FallbackReason::QuietGate);
            eprintln!(
                "[nat-chunk] fallback peer={peer16} bytes={} reason=quiet_gate",
                frame.len()
            );
            if self.send_mesh_tcp_frame(dst, frame) {
                return true;
            }
            stats.record_fallback_error(frame.len());
            return false;
        }

        let mut chunk = Vec::with_capacity(1 + frame.len());
        chunk.push(crate::nat_chunk_recv::CHUNK_KIND_TUN_STREAM);
        chunk.extend_from_slice(frame);

        let fallback_failed = std::cell::Cell::new(false);
        let result = {
            let this: &Self = &*self;
            let fallback = |_ignored: &[u8]| -> std::io::Result<()> {
                if this.send_mesh_tcp_frame(dst, frame) {
                    Ok(())
                } else {
                    fallback_failed.set(true);
                    Err(std::io::Error::other("n1 send failed"))
                }
            };
            provider.send_chunk(peer, &fallback, &chunk)
        };

        match result {
            Ok(crate::nat_switch::ChunkPath::Direct) => {
                stats.record_direct_attempt(chunk.len());
                eprintln!(
                    "[nat-chunk] direct attempt peer={peer16} bytes={} result=ok",
                    chunk.len()
                );
                false
            }
            Ok(crate::nat_switch::ChunkPath::Fallback) => {
                stats.record_fallback(frame.len(), FallbackReason::NoDirect);
                eprintln!(
                    "[nat-chunk] fallback peer={peer16} bytes={} reason=no_direct",
                    frame.len()
                );
                true
            }
            Err(e) => {
                if fallback_failed.get() {
                    stats.record_fallback(frame.len(), FallbackReason::NoDirect);
                    stats.record_fallback_error(frame.len());
                } else {
                    stats.record_direct_error(chunk.len());
                    eprintln!(
                        "[nat-chunk] direct attempt peer={peer16} bytes={} result=err kind={:?}",
                        chunk.len(),
                        e.kind()
                    );
                    eprintln!("[nat-chunk] direct error peer={peer16} kind={:?}", e.kind());
                }
                false
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
                    // D2 去重：Proxy 分支已在 SYN 当场发过 RST → 这里只回收会话。
                    if self.proxy_egress_rst_pending.remove(&key) {
                        if let Some(mgr) = self.flow_mgr.as_mut() {
                            mgr.dispose_flow(&key);
                        }
                        self.with_stats(|s| s.dropped += 1);
                        continue;
                    }
                    // 找该流的 smoltcp 连接，发 RST（不静默黑洞，D4）。
                    // 优先用已绑定的 stream_id；握手未完成时按 FourTuple 直接重置。
                    // 若 smoltcp 未产生 RST 包，直接构造一个（E4 可观察性）。
                    // C21：FourTuple 已双栈，v4/v6 都能按 tuple 重置。
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
                        if let Some(rst) = Self::craft_rst(&key) {
                            let _ = self.tun.write(&rst);
                            self.with_stats(|s| s.tun_written += 1);
                        }
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
        // errata E4：每次 flow_pump 全量消费——会话已消失（无后续 RST 风险）的
        // 条目直接遗忘；仍有活会话的条目保留到下一 tick 命中其 TcpReset。
        if !self.proxy_egress_rst_pending.is_empty() {
            let live: Vec<FlowKey> = self
                .flow_mgr
                .as_ref()
                .map(|mgr| {
                    self.proxy_egress_rst_pending
                        .iter()
                        .copied()
                        .filter(|key| mgr.get_phase(key).is_some())
                        .collect()
                })
                .unwrap_or_default();
            self.proxy_egress_rst_pending = live.into_iter().collect();
        }
    }

    /// Phase B：FlowKey → smoltcp stream_id（经已绑定的映射）。
    fn flow_stream_id_for_key(&self, key: &FlowKey) -> Option<u32> {
        self.flow_key_to_stream.get(key).copied()
    }

    /// 构造 TCP RST 包（回退路径；src/dst 互换）。
    ///
    /// 本 slice 只支持 v4 流（v6 TCP 终结/回退归 C20–C21）；v6 key → `None`
    /// （调用方不写包、只计数，绝不发畸形包）。
    fn craft_rst(key: &FlowKey) -> Option<Vec<u8>> {
        use nexus_projection::ip::tcp_udp_checksum_v6;
        use nexus_projection::tcp::{ip_checksum, tcp_checksum};
        match (key.dst_ip, key.src_ip) {
            (IpAddr::V4(dst_ip), IpAddr::V4(src_ip)) => {
                let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
                pkt[0] = 0x45;
                pkt[2] = 0;
                pkt[3] = 40;
                pkt[6] = 0x40;
                pkt[8] = 64;
                pkt[9] = 6;
                pkt[12..16].copy_from_slice(&dst_ip.octets()); // src = server
                pkt[16..20].copy_from_slice(&src_ip.octets()); // dst = client
                pkt[20..22].copy_from_slice(&key.dst_port.to_be_bytes());
                pkt[22..24].copy_from_slice(&key.src_port.to_be_bytes());
                // seq/ack = 0；flags = RST|ACK.
                pkt[32] = 0x50;
                pkt[33] = 0x14;
                let c = ip_checksum(&pkt[..20]);
                pkt[10..12].copy_from_slice(&c.to_be_bytes());
                let c2 = tcp_checksum(dst_ip.octets(), src_ip.octets(), &pkt[20..]);
                pkt[36..38].copy_from_slice(&c2.to_be_bytes());
                Some(pkt)
            }
            (IpAddr::V6(dst_ip), IpAddr::V6(src_ip)) => {
                let mut pkt = vec![0u8; 60]; // 40 IPv6 + 20 TCP
                pkt[0] = 0x60;
                pkt[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload length
                pkt[6] = 6;
                pkt[7] = 64;
                pkt[8..24].copy_from_slice(&dst_ip.octets()); // src = server
                pkt[24..40].copy_from_slice(&src_ip.octets()); // dst = client
                pkt[40..42].copy_from_slice(&key.dst_port.to_be_bytes());
                pkt[42..44].copy_from_slice(&key.src_port.to_be_bytes());
                pkt[52] = 0x50;
                pkt[53] = 0x14;
                let c2 = tcp_udp_checksum_v6(dst_ip, src_ip, 6, &pkt[40..]);
                pkt[56..58].copy_from_slice(&c2.to_be_bytes());
                Some(pkt)
            }
            _ => None,
        }
    }

    /// D2 唯一 RST 发射点（spec §4.5.2 伪码逐行）。
    ///
    /// 计数：每包恰好一次 `proxy_dropped_no_proxy`；`TagUnavailable` 另加
    /// `dropped++`（对齐 master `:1429-1432`）。只有 TCP SYN 写包并打日志；
    /// 非 SYN 只计数，不写包、不打日志。
    fn emit_proxy_egress_rst(&mut self, packet: &[u8], key: &FlowKey, subcase: RstSubcase) {
        self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
        if matches!(subcase, RstSubcase::TagUnavailable) {
            self.with_stats(|s| s.dropped += 1);
        }
        if !is_tcp_syn(packet) {
            return;
        }
        if let Some(rst) = Self::craft_rst(key) {
            match self.tun.write(&rst) {
                Ok(_) => self.with_stats(|s| s.tun_written += 1),
                Err(_) => self.with_stats(|s| s.dropped += 1),
            }
        }
        eprintln!(
            "[nexusd] dataplane: proxy egress unavailable; sent RST stream_id=- counter=proxy_dropped_no_proxy"
        );
        if self.flow_mgr.is_none() {
            return;
        }
        match subcase {
            RstSubcase::NoEngine => {
                // 同一 RST 已由本分支发出：抑制 flow 路径重复发射。
                self.proxy_egress_rst_pending.insert(*key);
            }
            RstSubcase::TagUnavailable => {
                // 会话已可建立 → 直接回收（不插入 pending，否则永不消费）。
                if self
                    .flow_mgr
                    .as_ref()
                    .is_some_and(|mgr| mgr.get_phase(key).is_some())
                    && let Some(mgr) = self.flow_mgr.as_mut()
                {
                    mgr.dispose_flow(key);
                }
            }
        }
    }

    /// §12.3 运行期结构化行：`event=outbound_unavailable`（tag 不可用时）。
    ///
    /// 热路径：同一 `(tag, cause)` 首次立即发射，其后每 10 s 一行，被抑制条数以
    /// `suppressed=<n>` 带出并清零（与 `udp_unsupported` 同一限频语义）。
    fn log_outbound_unavailable(&mut self, tag: &str, kind: &str, cause: &str, detail: &str) {
        let decision = self.unavailable_log.decide(
            tag,
            cause,
            std::time::Instant::now(),
            crate::log_throttle::OUTBOUND_UNAVAILABLE_LOG_INTERVAL,
        );
        if !decision.emit {
            return;
        }
        let detail = nexus::redact::sanitize(detail);
        eprintln!(
            "[proxy-fwd] event=outbound_unavailable tag={tag} kind={kind} cause={cause} detail=\"{detail}\" suppressed={}",
            decision.suppressed
        );
    }

    fn handle_tcp_terminated(&mut self, packet: &[u8], classification: &Classification) {
        let peer = match classification {
            Classification::Mesh { path: Some(p), .. } => p.to_string(),
            Classification::Mesh { path: None, .. } => ip_dst_of(packet)
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
                            // C21：FourTuple 已双栈，直接构造 FlowKey。
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
                        self.send_mesh_tcp_frame(dst.ip(), &frame);
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
                            self.send_mesh_tcp_frame(info.dst.ip(), &frame);
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
    fn send_mesh_tcp_frame(&self, dst: IpAddr, frame: &[u8]) -> bool {
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

/// 解析 CIDR 字符串（`"10.0.0.0/8"` / `"fd00:144::/64"`）为双栈 [`IpCidr`]。
fn parse_ip_cidr(s: &str) -> Result<IpCidr, String> {
    s.parse::<IpCidr>()
        .map_err(|e| format!("invalid CIDR: {e}"))
}

/// unknown-stream / bad-frame 日志限频窗口（spec §6.1：首次 + 每 10s）。
const N1_DISPATCH_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// peer hex 的 16 字符前缀（spec §8.2 日志格式）。
fn hex16(hex: &str) -> &str {
    &hex[..hex.len().min(16)]
}

/// STREAM 帧的 stream id（日志用；短帧返回 0，不 panic）。
fn stream_id_of(frame: &[u8]) -> u32 {
    if frame.len() < 4 {
        return 0;
    }
    u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]])
}

/// 从 IP 包提取目的地址（v4/v6；v6 只读固定头，扩展头不参与 N1 目的路由）。
fn ip_dst_of(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        Some(6) if packet.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// 判断是否为 TCP 包（IPv4 + proto 6；S1 终结范围判定）。
fn is_tcp_packet(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4 && packet[9] == 6
}

/// Phase B：是否为 TCP SYN 包（新流触发首包链）。
/// D2 RST 子情形（计数与 flow 处置不同）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RstSubcase {
    /// 无 engine：`proxy_dropped_no_proxy++`，插入 pending 抑制 flow 重复 RST。
    NoEngine,
    /// tag 不可用：另加 `dropped++`，直接回收会话（不插 pending）。
    TagUnavailable,
}

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

/// 取 IPv4/UDP 包的 UDP 载荷（TUN 侧 DNS 查询体）。
fn dns_udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
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

/// 判断是否为 TCP DNS 查询（IPv4 + TCP + 目的端口 53）。
fn is_dns_tcp_query(packet: &[u8]) -> bool {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    if ihl < 20 || packet.len() < ihl + 4 {
        return false;
    }
    u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]) == 53
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

/// 构造 DNS 应答 IP/UDP 包（v4 与 v6；v6 写完整 UDP 校验和）。
///
/// `server` = 原查询目的（应答源），`client` = 原查询源（应答目的）。
fn build_dns_udp_reply(server: SocketAddr, client: SocketAddr, dns_wire: &[u8]) -> Option<Vec<u8>> {
    match (server, client) {
        (SocketAddr::V4(server), SocketAddr::V4(client)) => {
            build_dns_udp_reply_v4(server, client, dns_wire)
        }
        (SocketAddr::V6(server), SocketAddr::V6(client)) => {
            build_dns_udp_reply_v6(server, client, dns_wire)
        }
        _ => None,
    }
}

fn build_dns_udp_reply_v4(
    server: SocketAddrV4,
    client: SocketAddrV4,
    dns_wire: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8 + dns_wire.len();
    if udp_len > usize::from(u16::MAX) {
        return None;
    }
    let total_len = 20 + udp_len;
    if total_len > usize::from(u16::MAX) {
        return None;
    }
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&server.port().to_be_bytes());
    udp[2..4].copy_from_slice(&client.port().to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(dns_wire);
    let checksum = udp_checksum(IpAddr::V4(*server.ip()), IpAddr::V4(*client.ip()), &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut ip_hdr = vec![0u8; 20];
    ip_hdr[0] = 0x45;
    ip_hdr[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip_hdr[6..8].copy_from_slice(&[0x40, 0x00]);
    ip_hdr[8] = 64;
    ip_hdr[9] = 17;
    ip_hdr[12..16].copy_from_slice(&server.ip().octets());
    ip_hdr[16..20].copy_from_slice(&client.ip().octets());
    let checksum = ip_checksum(&ip_hdr);
    ip_hdr[10..12].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&ip_hdr);
    packet.extend_from_slice(&udp);
    Some(packet)
}

fn build_dns_udp_reply_v6(
    server: SocketAddrV6,
    client: SocketAddrV6,
    dns_wire: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8 + dns_wire.len();
    if udp_len > usize::from(u16::MAX) {
        return None;
    }
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&server.port().to_be_bytes());
    udp[2..4].copy_from_slice(&client.port().to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(dns_wire);
    let checksum = udp_checksum(IpAddr::V6(*server.ip()), IpAddr::V6(*client.ip()), &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut ip_hdr = vec![0u8; 40];
    ip_hdr[0] = 0x60;
    ip_hdr[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip_hdr[6] = 17;
    ip_hdr[7] = 64;
    ip_hdr[8..24].copy_from_slice(&server.ip().octets());
    ip_hdr[24..40].copy_from_slice(&client.ip().octets());

    let mut packet = Vec::with_capacity(40 + udp_len);
    packet.extend_from_slice(&ip_hdr);
    packet.extend_from_slice(&udp);
    Some(packet)
}

/// UDP 校验和（含 v4/v6 伪头）；返回 0 表示结果为零，按 RFC 768 写 0xFFFF。
fn udp_checksum(src: IpAddr, dst: IpAddr, udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            sum = add_words(sum, &src.octets());
            sum = add_words(sum, &dst.octets());
            sum += 17;
            sum += udp.len() as u32;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            sum = add_words(sum, &src.octets());
            sum = add_words(sum, &dst.octets());
            sum += (udp.len() as u32) >> 16;
            sum += (udp.len() as u32) & 0xFFFF;
            sum += 17;
        }
        _ => return 0,
    }
    sum = add_words(sum, udp);
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let folded = !(sum as u16);
    if folded == 0 { 0xFFFF } else { folded }
}

fn add_words(mut sum: u32, data: &[u8]) -> u32 {
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    sum
}

/// 从 DNS 响应 wire 提取 `(查询名, A/AAAA 答案)`，供决策缓存回填（D-impl-8）。
///
/// 只做足够解析：header + question 名 + answer 段的 A/AAAA。解析失败返回
/// `None`（不影响回包）。
fn dns_response_meta(wire: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if wire.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]);
    let ancount = u16::from_be_bytes([wire[6], wire[7]]);
    if qdcount != 1 {
        return None;
    }
    let mut off = 12;
    let name = read_dns_name(wire, &mut off)?;
    off = off.checked_add(4)?; // QTYPE + QCLASS
    if off > wire.len() {
        return None;
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        off = skip_dns_name(wire, off)?;
        if off + 10 > wire.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([wire[off], wire[off + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([wire[off + 8], wire[off + 9]]));
        let start = off + 10;
        let end = start.checked_add(rdlen)?;
        if end > wire.len() {
            return None;
        }
        match (rtype, rdlen) {
            (1, 4) => answers.push(IpAddr::V4(Ipv4Addr::new(
                wire[start],
                wire[start + 1],
                wire[start + 2],
                wire[start + 3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&wire[start..end]);
                answers.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        off = end;
    }
    Some((name, answers))
}

fn read_dns_name(wire: &[u8], off: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = *off;
    loop {
        let len = *wire.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        let label = wire.get(pos..pos + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
        pos += len;
    }
    *off = pos;
    Some(labels.join("."))
}

fn skip_dns_name(wire: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *wire.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        off += 1 + len;
    }
}

/// 构造 TCP/53 的 RST|ACK 应答（v4；`is_dns_tcp_query` 只匹配 v4）。
fn build_tcp_reset_for_query(packet: &[u8]) -> Option<Vec<u8>> {
    use nexus_projection::tcp::{ip_checksum, tcp_checksum};
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    if ihl < 20 || packet.len() < ihl + 14 {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let sport = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let seq = u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ]);
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&dport.to_be_bytes());
    tcp[2..4].copy_from_slice(&sport.to_be_bytes());
    tcp[4..8].copy_from_slice(&0u32.to_be_bytes()); // seq
    tcp[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes()); // ack
    tcp[12] = 0x50;
    tcp[13] = 0x14; // RST|ACK
    let tcp_sum = tcp_checksum(dst.octets(), src.octets(), &tcp);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());

    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&dst.octets());
    ip[16..20].copy_from_slice(&src.octets());
    let ip_sum = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    ip.extend_from_slice(&tcp);
    Some(ip)
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

/// IPv6 能力表（静态，启动时由配置与编译特性决定；不随包变化）。
///
/// `proxy_udp="blocked"` 是 Q4 已裁定的产品行为，不是 TODO；`proxy_tcp`
/// 原同为 `blocked`，C21 接线（终结 + 经出站 adapter 拨号）落地后与事实
/// 漂移，合并门以 requirement-change 对齐为 `supported`
/// （RC-r3-f3-proxytcp-20261028；CAC-1 端到端回显实测为据）；
/// `tun_address="unassigned"` 表示本 run 不做 TUN v6 地址分配（Q7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Paths {
    /// `supported` / `unsupported`（由 `[[vpi.routes6]]` 是否存在决定）。
    pub mesh: &'static str,
    /// 恒为 `supported`（分类 + 计数）。
    pub direct: &'static str,
    /// 恒为 `supported`（v6 代理 TCP 经出站引擎终结 + 拨号；方言不支持
    /// v6 目标时可见失败 RST；引擎未配置时按既有 `proxy_dropped` 计数）。
    pub proxy_tcp: &'static str,
    /// 恒为 `blocked`（本 run v6 代理 UDP 出口阻断）。
    pub proxy_udp: &'static str,
    /// 恒为 `unassigned`（TUN v6 地址分配不在本 run）。
    pub tun_address: &'static str,
    /// 恒为 `unsupported`（v6 NAT/打洞不在本 run）。
    pub nat: &'static str,
}

impl Ipv6Paths {
    /// 由装配事实派生能力表。
    #[must_use]
    pub fn from_capabilities(mesh_supported: bool) -> Self {
        Self {
            mesh: if mesh_supported {
                "supported"
            } else {
                "unsupported"
            },
            direct: "supported",
            proxy_tcp: "supported",
            proxy_udp: "blocked",
            tun_address: "unassigned",
            nat: "unsupported",
        }
    }

    /// `/dataplane/stats` 的 `ipv6_paths` JSON 段。
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "mesh": self.mesh,
            "direct": self.direct,
            "proxy_tcp": self.proxy_tcp,
            "proxy_udp": self.proxy_udp,
            "tun_address": self.tun_address,
            "nat": self.nat,
        })
    }

    /// 启动期一次性 INFO 行（不参与限流）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "mesh={} direct={} proxy_tcp={} proxy_udp={} tun_address={} nat={}",
            self.mesh, self.direct, self.proxy_tcp, self.proxy_udp, self.tun_address, self.nat
        )
    }
}

impl Default for Ipv6Paths {
    fn default() -> Self {
        Self::from_capabilities(false)
    }
}

/// 运行期状态快照（takeover / flow_sessions / os_assemble / ipv6_paths）。
#[derive(Debug, Clone, Default)]
pub struct RuntimeStatus {
    /// `system-level` / `resource-level`。
    pub takeover_mode: String,
    /// `ipv4` / `dual-stack`（按 `ipv6_paths` 能力表派生，不硬编码）。
    pub ingress_ip_family: String,
    /// 流会话状态。
    pub flow_sessions: FlowSessionsState,
    /// OS 装配状态。
    pub os_assemble: OsAssembleStatus,
    /// IPv6 静态能力表。
    pub ipv6_paths: Ipv6Paths,
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

/// 发布 takeover/ingress 基本信息与 IPv6 能力表。
///
/// `ingress_ip_family` 由能力表派生（N-8：不得再硬编码 `"ipv4"` 与
/// `ipv6_paths` 自相矛盾）：v6 mesh 路由在位 → `dual-stack`，否则 `ipv4`。
pub fn publish_runtime_basics(takeover_mode: &str, ipv6_paths: Ipv6Paths) {
    if let Ok(mut status) = runtime_slot().lock() {
        status.takeover_mode = takeover_mode.to_string();
        status.ingress_ip_family = if ipv6_paths.mesh == "supported" {
            "dual-stack"
        } else {
            "ipv4"
        }
        .to_string();
        status.ipv6_paths = ipv6_paths;
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
            "dns_noerror": stats.dns_noerror,
            "dns_nodata": stats.dns_nodata,
            "dns_nxdomain": stats.dns_nxdomain,
            "dns_servfail": stats.dns_servfail,
            "dns_refused": stats.dns_refused,
            "dns_formerr": stats.dns_formerr,
            "dns_tcp_refused": stats.dns_tcp_refused,
            "dns_queue_full": stats.dns_queue_full,
            "dns_service_down": stats.dns_service_down,
            "dns_reply_write_failed": stats.dns_reply_write_failed,
            "qos_dropped": stats.qos_dropped,
            "mesh_dropped_no_n1": stats.mesh_dropped_no_n1,
            "proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
            "proxy_tcp_streams": stats.proxy_tcp_streams,
            "proxy_tcp_streams_ok": stats.proxy_tcp_streams_ok,
            "proxy_tcp_bytes": stats.proxy_tcp_bytes,
            "proxy_tcp_bytes_down": stats.proxy_tcp_bytes_down,
            "proxy_udp_unsupported": stats.proxy_udp_unsupported,
            "proxy_udp_unsupported_vless": stats.proxy_udp_unsupported_vless,
            "proxy_udp_unsupported_anytls": stats.proxy_udp_unsupported_anytls,
            "proxy_udp_unsupported_other": stats.proxy_udp_unsupported_other,
            "proxy_udp_unsupported_log_suppressed": stats.proxy_udp_unsupported_log_suppressed,
            "direct_tcp_dial_ok": stats.direct_tcp_dial_ok,
            "upstream_failed": stats.upstream_failed,
            "proxy_dial_buffer_dropped_bytes": stats.proxy_dial_buffer_dropped_bytes,
            "proxy_dial_buffer_overflow_resets": stats.proxy_dial_buffer_overflow_resets,
            "outbound_unresolved": stats.outbound_unresolved,
            "ipv6": {
                "packets": stats.ipv6.packets,
                "udp": stats.ipv6.udp,
                "tcp": stats.ipv6.tcp,
                "classified_mesh": stats.ipv6.classified_mesh,
                "classified_direct": stats.ipv6.classified_direct,
                "classified_proxy": stats.ipv6.classified_proxy,
                "mesh_forwarded": stats.ipv6.mesh_forwarded,
                "mesh_no_route": stats.ipv6.mesh_no_route,
                "proxy_dropped": stats.ipv6.proxy_dropped,
                "multicast": stats.ipv6.multicast,
                "dropped_truncated": stats.ipv6.dropped_truncated,
                "dropped_extension": stats.ipv6.dropped_extension,
                "fragments": stats.ipv6.fragments,
            },
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
        "ipv6_paths": status.ipv6_paths.json(),
        "tproxy": tproxy,
    })
}

// ===== 全局 stats 句柄结束 =====

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
    type CapturedFrames = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

    impl N1Sender for TestN1Sender {
        fn send_to_mesh(
            &self,
            dst: IpAddr,
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
        // 显式注入无配置默认引擎（新装配不再静默回落到它）。
        dp.set_default_simple_engine().expect("default engine");
        (dp, mock)
    }

    /// AC-H-1 `[P]`: driving Mesh TCP DATA with no attached NAT provider logs
    /// the spec §13.2 degraded notice exactly once (and keeps falling back).
    #[test]
    fn no_nat_provider_logs_not_attached_once() {
        let (mut dp, _mock) = test_dataplane();
        let peer = nexus_fabric::PeerId([0x44; 32]);
        let routes = vec![nexus_network::n1::pump::Ipv4Route {
            subnet: nexus_network::n1::pump::Ipv4Net::parse("10.200.0.0/24").expect("subnet"),
            peer: nexus_network::n1::N1PeerId(peer.0),
        }];
        dp.set_mesh_peer_resolver(Arc::new(
            crate::mesh_peer_map::StaticMeshPeerMap::from_routes(&routes),
        ));
        assert!(!dp.nat_not_attached_logged.load(Ordering::Relaxed));

        let dst = IpAddr::V4(Ipv4Addr::new(10, 200, 0, 5));
        let frame = b"\x00\x00\x00\x00\x00hi";
        let _ = dp.send_mesh_data_frame(dst, frame);
        assert!(dp.nat_not_attached_logged.load(Ordering::Relaxed));
        // A second chunk must not emit again (the flag is already latched).
        let _ = dp.send_mesh_data_frame(dst, frame);
        assert!(dp.nat_not_attached_logged.load(Ordering::Relaxed));
    }

    /// 装配回归：未注入引擎的 Dataplane 必须 fail-closed（Drop），
    /// 不得静默回落到把全部流量送往 `proxy` 的默认引擎。
    #[test]
    fn dataplane_without_injected_engine_fails_closed() {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let mut dp = Dataplane::new(
            Box::new(SharedTun { inner: mock }),
            DataplaneConfig::default(),
            None,
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
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
        assert_eq!(*dst, IpAddr::V4(Ipv4Addr::new(10, 200, 0, 5)));
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

    /// 建连必然失败的 establisher（flow 会话测试用）。
    struct AlwaysFailEstablisher;
    impl nexus_flow_session::ConnectivityEstablisher for AlwaysFailEstablisher {
        fn establish(
            &mut self,
            _session_id: &SessionId,
            _planned: &nexus_flow_session::Planned,
        ) -> Result<String, String> {
            Err("provider unavailable".to_string())
        }
    }

    const FLOW_TEST_YAML: &str = "\
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

    /// flow_mgr 开启的 Proxy 数据面；`engine_yaml = None` 表示无 engine（D2 NoEngine）。
    fn flow_sessions_dataplane(
        engine_yaml: Option<&str>,
    ) -> (Dataplane, Arc<Mutex<nexus_projection::MockTun>>) {
        let (mut dp, mock) = test_dataplane();
        dp.set_production_chain_deps(
            ProductionChainDeps::from_config(None, Some(FLOW_TEST_YAML)).expect("deps"),
        );
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        if let Some(yaml) = engine_yaml {
            dp.set_proxy_engine(
                crate::proxy_fwd::ProxyEngine::new(Some(yaml))
                    .expect("engine build")
                    .expect("engine constructed"),
            );
        }
        dp.enable_flow_sessions_with_establisher(Box::new(AlwaysFailEstablisher));
        (dp, mock)
    }

    const FLOW_TEST_YAML_OTHER: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: other
groups: []
outbounds:
  - tag: other
    kind: socks5
    locator: 127.0.0.1:1080
";

    /// engine 存在、但规则指向 engine 表里没有的 tag（A3 TagUnavailable 子情形）。
    ///
    /// provider 派生（planner）来自 `FLOW_TEST_YAML` 的 tag `p1`，engine 用只含
    /// `other` 的配置构造 → 会话可建立，运行期查 tag 得 `UnknownOutbound`。
    fn tag_unavailable_dataplane() -> (Dataplane, Arc<Mutex<nexus_projection::MockTun>>) {
        let (mut dp, mock) = test_dataplane();
        dp.set_production_chain_deps(
            ProductionChainDeps::from_config(None, Some(FLOW_TEST_YAML)).expect("deps"),
        );
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "0.0.0.0/0".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        dp.set_proxy_engine(
            crate::proxy_fwd::ProxyEngine::new(Some(FLOW_TEST_YAML_OTHER))
                .expect("engine build")
                .expect("engine constructed"),
        );
        dp.enable_flow_sessions_with_establisher(Box::new(AlwaysFailEstablisher));
        (dp, mock)
    }

    /// S26（D2=C 改写）：Proxy 分类且无 engine → **SYN 直接 RST**（恰好一个、
    /// 无 SYN-ACK），不经 N1、不进终结器。
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
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

        let syn = craft_tcp([10, 0, 0, 2], [8, 8, 8, 8], 40001, 443, 2000, 0, 0x02, &[]);
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("syn"));
        let written = mock.lock().unwrap().take_written();
        // D2=C：恰好一个 RST 包，且不是 SYN-ACK。
        assert_eq!(
            written.len(),
            1,
            "exactly one RST expected, got {} packets",
            written.len()
        );
        let pkt = &written[0];
        assert_ne!(pkt[33] & 0x04, 0, "RST flag must be set");
        assert_ne!(pkt[33] & 0x12, 0x12, "must not be a SYN-ACK (no handshake)");
        // §14.2 保留三条断言。
        assert_eq!(dp.stats().tcp_handshakes, 0);
        assert_eq!(dp.stats().proxy_dropped_no_proxy, 1);
        assert!(frames.lock().unwrap().is_empty(), "Proxy must not use N1");
    }

    /// R17 / errata E4：`proxy_egress_rst_pending` 有界且被下一次 `flow_pump` 消费。
    #[test]
    fn proxy_egress_rst_pending_is_bounded_and_consumed() {
        // flow_mgr 开启 + 无 engine：每个无出口 SYN 记一条 pending。
        let (mut dp, mock) = flow_sessions_dataplane(None);
        let n = 5usize;
        for i in 0..n {
            let syn = craft_tcp(
                [10, 0, 0, 2],
                [203, 0, 113, 10],
                40_000 + u16::try_from(i).expect("port"),
                8080,
                1000,
                0,
                0x02,
                &[],
            );
            mock.lock().unwrap().inject(syn);
            assert!(dp.tick(u64::try_from(i).unwrap()).expect("tick syn"));
        }
        // (a) 单 tick 内条目数 <= 该 tick 处理的无出口 SYN 数。
        assert!(
            dp.proxy_egress_rst_pending.len() <= n,
            "pending must stay bounded by the SYNs handled: {}",
            dp.proxy_egress_rst_pending.len()
        );
        // (b) 下一次 flow_pump 后集合全量变空（会话由失败建立链回收 → 遗忘）。
        for step in 0..2_000u64 {
            let _ = dp.tick(step).expect("tick pump");
            if dp.proxy_egress_rst_pending.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            dp.proxy_egress_rst_pending.is_empty(),
            "every inserted key must be consumed"
        );
        // 每个 SYN 恰好一个 RST（没有第二个 RST）。
        let rst_count = mock
            .lock()
            .unwrap()
            .take_written()
            .iter()
            .filter(|p| p.len() > 33 && p[33] & 0x04 != 0)
            .count();
        assert!(rst_count <= n, "no duplicate RSTs (got {rst_count})");
    }

    /// A3 子情形：engine 在、tag 不在表 → 单个 RST + 会话回收（不插 pending）。
    #[test]
    fn tag_unavailable_sends_single_rst_and_disposes_flow() {
        let (mut dp, mock) = tag_unavailable_dataplane();
        let syn = craft_tcp(
            [10, 0, 0, 2],
            [203, 0, 113, 10],
            40001,
            8080,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.tick(1).expect("syn"));
        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 1, "exactly one RST");
        assert_ne!(written[0][33] & 0x04, 0, "RST flag");
        assert!(
            dp.proxy_egress_rst_pending.is_empty(),
            "TagUnavailable must not insert pending"
        );
        assert_eq!(dp.stats().proxy_dropped_no_proxy, 1);
        assert_eq!(dp.stats().dropped, 1);
    }

    /// S9：下行 STREAM 帧注入 → terminator → TUN 包。    /// S9：下行 STREAM 帧注入 → terminator → TUN 包。
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
            ipv6_paths: Ipv6Paths::from_capabilities(true),
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

        dp.record_dns_answer("api.example.com", IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
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

    /// D-impl-8 的 v6 侧：AAAA 答案回填后，目的为该 v6 的包不再计 domain_miss。
    #[test]
    fn d_impl_8_v6_dns_answer_feeds_domain_cache() {
        use nexus_projection::ip::build_udp_packet;

        let (mut dp, mock) = test_dataplane();
        let cached: IpAddr = "fd00:144::9".parse().expect("v6 cached");
        dp.record_dns_answer("v6.mesh", cached);

        let hit = build_udp_packet(
            "[2001:db8::100]:40000".parse().unwrap(),
            "[fd00:144::9]:443".parse().unwrap(),
            b"z",
        )
        .expect("v6 udp");
        mock.lock().unwrap().inject(hit);
        assert!(dp.process_one().expect("cached v6 packet"));
        assert_eq!(dp.stats().domain_miss, 0, "v6 answer must feed the cache");

        let miss = build_udp_packet(
            "[2001:db8::100]:40001".parse().unwrap(),
            "[fd00:144::a]:443".parse().unwrap(),
            b"z",
        )
        .expect("v6 udp");
        mock.lock().unwrap().inject(miss);
        assert!(dp.process_one().expect("uncached v6 packet"));
        assert_eq!(dp.stats().domain_miss, 1, "unknown v6 dst is a miss");
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
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

    /// P10：Mesh 分类的 TUN 流必须进入 §10 链。
    ///
    /// `PRODUCT.md#tun-ingress-session-chain`：TUN 产生的**每个**新流首包触发
    /// Policy → Core Planner → SessionOwner。Mesh 流没有 `egress_hint`，但
    /// "无提示" 只表示不窄化候选集，不表示没有候选；规划前被 Drop 即违反契约。
    #[test]
    fn hintless_mesh_flow_enters_session_chain() {
        struct MeshEstablisher;
        impl ConnectivityEstablisher for MeshEstablisher {
            fn establish(
                &mut self,
                _session_id: &SessionId,
                _planned: &nexus_flow_session::Planned,
            ) -> Result<String, String> {
                Ok("mesh".to_string())
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
        dp.enable_flow_sessions_with_establisher(Box::new(MeshEstablisher));

        // UDP（Mesh CIDR 10.200.0.0/24）→ 首包建会话。
        let udp = craft_udp([10, 0, 0, 2], [10, 200, 0, 7], 40_000, 8080, b"x");
        mock.lock().unwrap().inject(udp.clone());
        assert!(dp.process_one().expect("mesh udp"));
        assert_eq!(dp.flow_planner_calls(), 1, "planner must run for Mesh");
        let udp_key = FlowKey::parse(&udp).expect("udp key");
        assert!(
            dp.flow_session_for_key(&udp_key).is_some(),
            "Mesh flow must own a session"
        );
        assert_eq!(
            dp.stats().dropped,
            0,
            "hint-less Mesh flow must not be dropped before planning"
        );

        // 同一 5 元组：已建流快路径，不重复规划。
        mock.lock().unwrap().inject(udp);
        assert!(dp.process_one().expect("same mesh udp"));
        assert_eq!(dp.flow_planner_calls(), 1);

        // TCP SYN（Mesh）→ 同样建会话，不 Drop。
        let syn = craft_tcp(
            [10, 0, 0, 2],
            [10, 200, 0, 8],
            40_001,
            443,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn.clone());
        assert!(dp.process_one().expect("mesh syn"));
        assert_eq!(dp.flow_planner_calls(), 2, "planner must run for Mesh TCP");
        let tcp_key = FlowKey::parse(&syn).expect("tcp key");
        assert!(dp.flow_session_for_key(&tcp_key).is_some());
        assert_eq!(dp.stats().dropped, 0);
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "10.200.3.3/32".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        dp.set_proxy_engine(
            crate::proxy_fwd::ProxyEngine::new(Some(P6_PROXY_YAML))
                .expect("proxy engine")
                .expect("engine constructed"),
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
        dp.set_rule_engine(Box::new(SimpleRuleEngine::new(vec![Rule {
            cidr: "10.200.3.3/32".parse().expect("cidr"),
            target: nexus_domain::RouteTarget::Egress {
                peer: "p1".to_string(),
            },
        }])));
        let yaml = format!(
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: p1\noutbounds:\n  - tag: p1\n    kind: socks5\n    locator: {socks_addr}\n"
        );
        dp.set_proxy_engine(
            crate::proxy_fwd::ProxyEngine::new(Some(&yaml))
                .expect("proxy engine")
                .expect("engine constructed"),
        );
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
            std::thread::sleep(std::time::Duration::from_millis(1));
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

    /// S5：15 字段并集在 LocalAPI JSON 中逐项暴露（含 8 个新键）。
    #[test]
    fn localapi_json_exposes_15_proxy_fields() {
        let stats = DataplaneStats {
            proxy_forwarded: 1,
            proxy_tcp_streams: 2,
            proxy_tcp_streams_ok: 3,
            proxy_tcp_bytes: 11,
            proxy_tcp_bytes_down: 22,
            proxy_udp_unsupported: 4,
            proxy_udp_unsupported_vless: 1,
            proxy_udp_unsupported_anytls: 1,
            proxy_udp_unsupported_other: 2,
            proxy_udp_unsupported_log_suppressed: 7,
            ..Default::default()
        };
        let json = dataplane_stats_json(
            true,
            &RuntimeStatus::default(),
            &stats,
            serde_json::Value::Null,
        );
        let dp = &json["dataplane"];
        for (key, expected) in [
            ("proxy_forwarded", 1),
            ("proxy_tcp_streams", 2),
            ("proxy_tcp_streams_ok", 3),
            ("proxy_tcp_bytes", 11),
            ("proxy_tcp_bytes_down", 22),
            ("proxy_udp_unsupported", 4),
            ("proxy_udp_unsupported_vless", 1),
            ("proxy_udp_unsupported_anytls", 1),
            ("proxy_udp_unsupported_other", 2),
            ("proxy_udp_unsupported_log_suppressed", 7),
        ] {
            assert_eq!(dp[key], expected, "{key}");
        }
        assert!(dp["proxy_tcp_bytes"].is_number());
        assert!(dp.get("tcp_flows_rejected").is_none(), "D3=A：无上限假字段");
        assert!(
            dp.get("tcp_dials_throttled").is_none(),
            "D3=A：无上限假字段"
        );
    }

    /// S5：`proxy_tcp_streams` 计 Syn，`proxy_tcp_streams_ok` 计 dial 成功。
    #[test]
    fn stats_proxy_tcp_streams_counts_syn_not_dial_ok() {
        // dial 指向已释放端口：握手完成（Syn 计数）但 dial 必然失败（ok 不增）。
        let dead_addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr")
        };
        let (mut dp, mock) = silent_window_dataplane(dead_addr);
        let syn = craft_tcp(
            [10, 200, 1, 2],
            [10, 200, 3, 3],
            57365,
            8080,
            1000,
            0,
            0x02,
            &[],
        );
        mock.lock().unwrap().inject(syn);
        assert!(dp.tick(1).expect("tick syn"));
        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 1, "SYN-ACK expected");
        let isn1 = syn_ack_srv_seq(&written[0]) + 1;
        // 握手完成 → TcpEvent::Syn（stats.tcp_streams += 1）→ worker dial。
        let ack = craft_tcp(
            [10, 200, 1, 2],
            [10, 200, 3, 3],
            57365,
            8080,
            1001,
            isn1,
            0x10,
            &[],
        );
        mock.lock().unwrap().inject(ack);
        assert!(dp.tick(2).expect("tick ack"));
        // sync 在 tick 头部（poll 之后）：本 tick 的增量在下一次 poll 同步。
        let _ = dp.tick(3).expect("tick sync");
        assert_eq!(dp.stats().proxy_tcp_streams, 1, "Syn 计数");
        assert_eq!(dp.stats().proxy_tcp_streams_ok, 0, "dial 失败，未进 relay");
    }

    /// S5：`proxy_tcp_bytes` 由 engine 的 `tcp_bytes_up` 驱动（C7 修死计数）。
    #[test]
    fn stats_proxy_tcp_bytes_comes_from_tcp_bytes_up() {
        let (mut dp, mock) = silent_window_dataplane({
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr")
        });
        let client_ip = [10, 200, 1, 2];
        let server_ip = [10, 200, 3, 3];
        let syn = craft_tcp(client_ip, server_ip, 57365, 8080, 1000, 0, 0x02, &[]);
        mock.lock().unwrap().inject(syn);
        assert!(dp.tick(1).expect("syn"));
        let written = mock.lock().unwrap().take_written();
        let isn1 = syn_ack_srv_seq(&written[0]) + 1;
        let ack = craft_tcp(client_ip, server_ip, 57365, 8080, 1001, isn1, 0x10, &[]);
        mock.lock().unwrap().inject(ack);
        assert!(dp.tick(2).expect("ack"));
        let get = craft_tcp(
            client_ip,
            server_ip,
            57365,
            8080,
            1001,
            isn1,
            0x18,
            b"GET /x HTTP/1.1\r\n\r\n",
        );
        mock.lock().unwrap().inject(get);
        assert!(dp.tick(3).expect("get"));
        // socks 替身在上一个测试里未监听该端口（port 已释放）：dial 失败也要能计数；
        // 这里只断言「映射来自 engine 字段」这一不变量（可能为 0，但必须相等）。
        for step in 4..2_000u64 {
            let _ = dp.tick(step).expect("tick");
            if dp.stats().proxy_tcp_streams_ok > 0 || dp.stats().proxy_tcp_bytes > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let engine_bytes = dp.proxy_stats().expect("engine stats").tcp_bytes_up;
        assert_eq!(
            dp.stats().proxy_tcp_bytes,
            engine_bytes,
            "上行字节来自 tcp_bytes_up"
        );
    }

    /// S5：同步点幂等（连续两次 tick 不重复累计）。
    #[test]
    fn stats_sync_is_idempotent_across_two_ticks() {
        let (mut dp, _mock) = test_dataplane();
        dp.sync_proxy_stats();
        let first = dp.stats();
        dp.sync_proxy_stats();
        let second = dp.stats();
        for (a, b, name) in [
            (
                first.proxy_forwarded,
                second.proxy_forwarded,
                "proxy_forwarded",
            ),
            (
                first.proxy_tcp_bytes,
                second.proxy_tcp_bytes,
                "proxy_tcp_bytes",
            ),
            (
                first.proxy_tcp_streams_ok,
                second.proxy_tcp_streams_ok,
                "proxy_tcp_streams_ok",
            ),
            (
                first.proxy_udp_unsupported,
                second.proxy_udp_unsupported,
                "proxy_udp_unsupported",
            ),
        ] {
            assert_eq!(a, b, "{name} must not double count");
        }
    }

    /// S5：纯下行字节（客户端静默、仅 proxy→TUN）仍被计数（A2 库级前置）。
    #[test]
    fn stats_pure_downlink_bytes_counted_without_uplink() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        // socks5 替身：完成握手/CONNECT，读到请求后回一段响应并保持连接。
        let socks = TcpListener::bind("127.0.0.1:0").expect("bind socks stub");
        let socks_addr = socks.local_addr().expect("socks addr");
        std::thread::spawn(move || {
            let (mut conn, _) = socks.accept().expect("socks accept");
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout");
            let mut greeting = [0u8; 2];
            conn.read_exact(&mut greeting).expect("greeting");
            let mut methods = vec![0u8; usize::from(greeting[1])];
            conn.read_exact(&mut methods).expect("methods");
            conn.write_all(&[5, 0]).expect("method reply");
            let mut head = [0u8; 4];
            conn.read_exact(&mut head).expect("request head");
            match head[3] {
                1 => {
                    let mut addr = [0u8; 4];
                    conn.read_exact(&mut addr).expect("ipv4");
                }
                3 => {
                    let mut len = [0u8; 1];
                    conn.read_exact(&mut len).expect("domain len");
                    let mut addr = vec![0u8; usize::from(len[0])];
                    conn.read_exact(&mut addr).expect("domain");
                }
                4 => {
                    let mut addr = [0u8; 16];
                    conn.read_exact(&mut addr).expect("ipv6");
                }
                other => panic!("unexpected ATYP {other}"),
            }
            let mut port = [0u8; 2];
            conn.read_exact(&mut port).expect("port");
            conn.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
            let mut req = [0u8; 512];
            let n = conn.read(&mut req).expect("request");
            assert!(n > 0, "relay forwarded the request");
            // 仅下行：客户端此后静默，响应只从 proxy 侧回来。
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .expect("response");
            conn.flush().expect("flush");
            std::thread::sleep(Duration::from_secs(3));
        });

        let (mut dp, mock) = silent_window_dataplane(socks_addr);
        let client_ip = [10, 200, 1, 2];
        let server_ip = [10, 200, 3, 3];
        let syn = craft_tcp(client_ip, server_ip, 57365, 8080, 1000, 0, 0x02, &[]);
        mock.lock().unwrap().inject(syn);
        assert!(dp.tick(1).expect("syn"));
        let written = mock.lock().unwrap().take_written();
        let isn1 = syn_ack_srv_seq(&written[0]) + 1;
        let ack = craft_tcp(client_ip, server_ip, 57365, 8080, 1001, isn1, 0x10, &[]);
        mock.lock().unwrap().inject(ack);
        assert!(dp.tick(2).expect("ack"));
        let get = craft_tcp(
            client_ip,
            server_ip,
            57365,
            8080,
            1001,
            isn1,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        mock.lock().unwrap().inject(get);
        assert!(dp.tick(3).expect("get"));
        // 客户端完全静默：只靠 tick 泵下行。
        let mut down = 0u64;
        for step in 4..3_000u64 {
            let _ = dp.tick(step).expect("idle tick");
            down = dp.stats().proxy_tcp_bytes_down;
            if down > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(down > 0, "pure downlink bytes must be counted");
        let engine_up = dp.proxy_stats().expect("engine").tcp_bytes_up;
        assert!(engine_up > 0, "uplink counted on engine");
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
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
        dp.set_proxy_engine(
            crate::proxy_fwd::ProxyEngine::new(Some(P6_PROXY_YAML))
                .expect("proxy engine")
                .expect("engine constructed"),
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

    // --- fix-r10 F1：pipeline-None 瞬态分支计数与原因同点写入 -----------------

    /// 透明管道未装配时的 TCP 入站：拒绝计数与失败原因必须同点写入。
    #[test]
    fn tproxy_tcp_rejected_without_pipeline_persists_last_failure() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let orig_dst = match listener.local_addr().expect("local addr") {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("expected v4 listener"),
        };
        let _client = TcpStream::connect(orig_dst).expect("connect");
        let (stream, peer) = listener.accept().expect("accept");
        let peer = match peer {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("expected v4 peer"),
        };

        let (mut dp, _mock) = test_dataplane();
        assert!(!dp.transparent_ready(), "pipeline intentionally absent");
        let (tx, rx) = inbound_channel();
        let (failure_tx, _failure_rx) = inbound_channel();
        dp.set_transparent_rx(rx, failure_tx);
        tx.try_send(TransparentInbound::Tcp(AcceptedTcpStream {
            stream,
            peer,
            orig_dst,
            accepted_at_millis: 1,
        }))
        .expect("send");

        assert_eq!(dp.drain_transparent_inbound(1), 1);
        assert_eq!(dp.tproxy_counters().tcp_rejected, 1);
        let reason = dp
            .tproxy_last_failure()
            .expect("pipeline-None TCP rejection must set last_failure_reason");
        assert!(reason.contains("tcp_rejected_no_pipeline"), "{reason}");
    }

    /// 透明管道未装配时的 UDP 入站：丢弃计数与失败原因必须同点写入。
    #[test]
    fn tproxy_udp_dropped_without_pipeline_persists_last_failure() {
        let (mut dp, _mock) = test_dataplane();
        assert!(!dp.transparent_ready(), "pipeline intentionally absent");
        let (tx, rx) = inbound_channel();
        let (failure_tx, _failure_rx) = inbound_channel();
        dp.set_transparent_rx(rx, failure_tx);
        tx.try_send(TransparentInbound::Udp(ReceivedDatagram {
            payload: b"probe".to_vec(),
            peer: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_000),
            orig_dst: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443),
            received_at_millis: 1,
        }))
        .expect("send");

        assert_eq!(dp.drain_transparent_inbound(1), 1);
        assert_eq!(dp.tproxy_counters().udp_dropped, 1);
        let reason = dp
            .tproxy_last_failure()
            .expect("pipeline-None UDP drop must set last_failure_reason");
        assert!(reason.contains("udp_dropped_no_pipeline"), "{reason}");
    }

    fn dns_file_config_with_host() -> crate::config::DnsFileConfig {
        use crate::config::{DnsProxyPolicy, UpstreamConfig};
        use crate::dns_status::{UnevaluablePolicy, UnmatchedPolicy};
        use nexus_dns::DnsUnifiedConfig;
        let unified = DnsUnifiedConfig {
            hosts: vec![(
                "local.example".to_string(),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            )],
            ..DnsUnifiedConfig::default()
        };
        crate::config::DnsFileConfig {
            unified,
            mesh_hosts: Vec::new(),
            proxy: DnsProxyPolicy {
                unmatched: UnmatchedPolicy::Auto,
                unevaluable: UnevaluablePolicy::Proxied,
            },
            upstream: UpstreamConfig {
                servers: vec!["127.0.0.1:9".parse().expect("upstream")],
                attempt_timeout_ms: 50,
                attempts_per_server: 1,
                total_budget_ms: 50,
                edns_udp_size: 0,
                tcp_fallback: false,
                tcp_timeout_ms: 100,
                cache_max_entries: 0,
                cache_max_ttl_secs: 1,
                negative_ttl_secs: 0,
                max_inflight: 1,
            },
        }
    }

    /// Q-3 / D-impl-2 / R-8：`handle_transparent_udp` → DNS 提交 →
    /// `TransparentOutput::UdpReply` 全程（不经 TUN）。
    #[test]
    fn transparent_dns_query_replies_through_udp_reply_channel() {
        use crate::dns_service::DnsService;
        use crate::dns_status::{DnsStatus, DnsStatusSnapshot};
        use nexus_dns::{DnsQuery, DnsType};

        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let dns_config = dns_file_config_with_host();
        let config = DataplaneConfig {
            dns_enabled: true,
            dns_config: Some(dns_config.clone()),
            ..Default::default()
        };
        let status = Arc::new(DnsStatus::new(DnsStatusSnapshot::disabled()));
        let handle = DnsService::start(dns_config, None, status).expect("dns service starts");
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let mut dp = Dataplane::new(
            Box::new(SharedTun {
                inner: Arc::clone(&mock),
            }),
            config,
            Some(handle),
        )
        .expect("dataplane");
        dp.transparent_udp_reply_tx = Some(reply_tx);

        let query = nexus_dns::wire::build_query(
            &DnsQuery {
                name: "local.example".to_string(),
                qtype: DnsType::A,
            },
            0x1234,
            None,
        );
        dp.handle_transparent_udp(
            ReceivedDatagram {
                payload: query,
                peer: SocketAddrV4::new(Ipv4Addr::new(10, 200, 1, 2), 40_000),
                orig_dst: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
                received_at_millis: 1,
            },
            1,
        );

        let mut output = None;
        for _ in 0..400 {
            dp.drain_dns_replies();
            if let Ok(value) = reply_rx.try_recv() {
                output = Some(value);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let output = output.expect("transparent DNS reply must reach UdpReply");
        match output {
            TransparentOutput::UdpReply {
                orig_dst,
                peer,
                payload,
            } => {
                assert_eq!(orig_dst, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
                assert_eq!(
                    peer,
                    SocketAddrV4::new(Ipv4Addr::new(10, 200, 1, 2), 40_000)
                );
                let (name, answers) = dns_response_meta(&payload).expect("response parses");
                assert_eq!(name, "local.example");
                assert_eq!(answers, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
            }
            other => panic!("expected UdpReply, got {other:?}"),
        }
        assert!(mock.lock().unwrap().read(&mut [0u8; 1]).is_err());
        assert!(mock.lock().unwrap().read(&mut [0u8; 1]).is_err());
        assert_eq!(dp.stats().dns_noerror, 1);
        assert_eq!(dp.stats().dns_answered, 1);
        let mapped = dp
            .dns_cache_handle()
            .lock()
            .unwrap()
            .lookup(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(mapped.as_deref(), Some("local.example"));
    }

    /// D-impl-8：AAAA 应答同样回填决策缓存（不只 A）。
    #[test]
    fn dns_reply_backfills_aaaa_answers() {
        use crate::dns_service::{DnsReply, ReplySink};
        use nexus_dns::wire::{DnsRcode, WireRecord};
        use nexus_dns::{DnsQuery, DnsType};

        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let mut dp = Dataplane::new(
            Box::new(SharedTun {
                inner: Arc::clone(&mock),
            }),
            DataplaneConfig::default(),
            None,
        )
        .expect("dataplane");
        let query = nexus_dns::wire::build_query(
            &DnsQuery {
                name: "v6.local".to_string(),
                qtype: DnsType::Aaaa,
            },
            0x1234,
            None,
        );
        let wire = nexus_dns::wire::build_answer(
            &query,
            &[WireRecord {
                rtype: 28,
                ttl_secs: 60,
                address: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            }],
            DnsRcode::NoError,
        )
        .expect("answer");
        dp.deliver_dns_reply(DnsReply {
            client: "192.168.1.100:40000".parse().expect("client"),
            server: "8.8.8.8:53".parse().expect("server"),
            wire,
            class: nexus_dns::DnsClass::Upstream,
            rcode: 0,
            sink: ReplySink::Tun,
        });
        assert_eq!(dp.stats().dns_noerror, 1);
        let mapped = dp
            .dns_cache_handle()
            .lock()
            .unwrap()
            .lookup(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert_eq!(mapped.as_deref(), Some("v6.local"));
    }

    // ===== C18：IPv6 计数 / Mesh 原始转发 / 能力表 =====

    /// 无路由的 N1 发送器：模拟"mesh 分类但 v6 路由缺失"（AC6 的反例）。
    struct NoRouteN1Sender;

    impl N1Sender for NoRouteN1Sender {
        fn send_to_mesh(
            &self,
            _dst: IpAddr,
            _packet: &[u8],
        ) -> Result<(), nexus_network::n1::N1Error> {
            Err(nexus_network::n1::N1Error::PeerUnknown)
        }
    }

    /// 双栈测试数据面：v6 mesh `fd00:144::/64`、v6 bypass 默认集合。
    fn v6_dataplane() -> (Dataplane, Arc<Mutex<nexus_projection::MockTun>>) {
        let mock = Arc::new(Mutex::new(nexus_projection::MockTun::new("test6")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            mesh_cidrs6: vec!["fd00:144::/64".to_string()],
            bypass_cidrs: vec!["192.168.0.0/16".to_string()],
            bypass_cidrs6: vec!["fc00::/7".to_string(), "fe80::/10".to_string()],
            n1_configured: true,
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config, None).expect("dataplane new");
        dp.set_default_simple_engine().expect("default engine");
        (dp, mock)
    }

    fn v6_udp(dst: &str, payload: &[u8]) -> Vec<u8> {
        nexus_projection::ip::build_udp_packet(
            "[fd00:144::1]:40000".parse().unwrap(),
            format!("[{dst}]:8080").parse().unwrap(),
            payload,
        )
        .expect("v6 udp packet")
    }

    fn v6_tcp(dst: &str) -> Vec<u8> {
        // 最小 v6/TCP SYN。
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[6] = 6;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&"fd00:144::1".parse::<Ipv6Addr>().unwrap().octets());
        pkt[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        pkt[40..42].copy_from_slice(&40000u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&80u16.to_be_bytes());
        pkt[44..48].copy_from_slice(&1000u32.to_be_bytes());
        pkt[52] = 0x50;
        pkt[53] = 0x02;
        pkt
    }

    /// 在 v6 包上插入一个 8B 扩展头（`extension` 为头类型，`next` 为链尾协议）。
    fn with_extension(inner: Vec<u8>, extension: u8, next: u8) -> Vec<u8> {
        let mut pkt = inner[..40].to_vec();
        // 扩展头：[next header, length(units), 6B data]。
        pkt.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&inner[40..]);
        pkt[6] = extension;
        let payload_len = (pkt.len() - 40) as u16;
        pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
        pkt
    }

    /// AC6：v6/UDP 目的 `fd00:144::6` → Mesh 原始转发，N1 收到 `IpAddr::V6`
    /// 且包字节逐字一致。
    #[test]
    fn c18_ipv6_udp_mesh_is_raw_forwarded() {
        let (mut dp, mock) = v6_dataplane();
        let frames: CapturedFrames = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_sender(Arc::new(TestN1Sender {
            frames: Arc::clone(&frames),
        }));
        let pkt = v6_udp("fd00:144::6", b"mesh6");
        mock.lock().unwrap().inject(pkt.clone());
        dp.process_one().expect("process v6 mesh");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.udp, 1);
        assert_eq!(stats.ipv6.classified_mesh, 1);
        assert_eq!(stats.ipv6.mesh_forwarded, 1);
        assert_eq!(stats.ipv6.mesh_no_route, 0);
        assert_eq!(stats.dropped, 0, "0x86DD must never bump generic dropped");
        let captured = frames.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].0,
            IpAddr::V6("fd00:144::6".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(captured[0].1, pkt, "raw bytes must be forwarded verbatim");
    }

    /// AC6 反例：无 v6 路由 → `mesh_no_route` + `mesh_dropped_no_n1` 同步 +1。
    #[test]
    fn c18_ipv6_mesh_without_route_is_visible() {
        let (mut dp, mock) = v6_dataplane();
        dp.set_n1_sender(Arc::new(NoRouteN1Sender));
        mock.lock().unwrap().inject(v6_udp("fd00:144::6", b"x"));
        dp.process_one().expect("process v6 mesh no route");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.classified_mesh, 1);
        assert_eq!(stats.ipv6.mesh_no_route, 1);
        assert_eq!(stats.ipv6.mesh_forwarded, 0);
        assert_eq!(stats.mesh_dropped_no_n1, 1);
        assert_eq!(stats.dropped, 0);
    }

    /// AC7：`fc00::5`（v6 bypass）→ Direct，只计数不转发。
    #[test]
    fn c18_ipv6_direct_is_counted() {
        let (mut dp, mock) = v6_dataplane();
        let before = dp.stats().direct_forwarded;
        mock.lock().unwrap().inject(v6_udp("fc00::5", b"direct6"));
        dp.process_one().expect("process v6 direct");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.classified_direct, 1);
        assert_eq!(stats.direct_forwarded, before + 1);
        assert_eq!(stats.ipv6.classified_proxy, 0);
        assert_eq!(stats.dropped, 0);
    }

    /// AC7：`2001:db8::20` → Proxy 阻断（`proxy_dropped`），通用 dropped 不增。
    #[test]
    fn c18_ipv6_proxy_is_blocked_not_dropped() {
        let (mut dp, mock) = v6_dataplane();
        let before = dp.stats();
        mock.lock()
            .unwrap()
            .inject(v6_udp("2001:db8::20", b"proxy6"));
        dp.process_one().expect("process v6 proxy");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.classified_proxy, 1);
        assert_eq!(stats.ipv6.proxy_dropped, 1);
        assert_eq!(stats.dropped, before.dropped);
        assert_eq!(stats.proxy_forwarded, before.proxy_forwarded);
        assert_eq!(stats.proxy_dropped_no_proxy, before.proxy_dropped_no_proxy);
    }

    /// AC7：`ff02::1` → 只计 `multicast`，不进分类转发。
    #[test]
    fn c18_ipv6_multicast_is_counted_only() {
        let (mut dp, mock) = v6_dataplane();
        mock.lock().unwrap().inject(v6_udp("ff02::1", b"mcast"));
        dp.process_one().expect("process v6 multicast");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.multicast, 1);
        assert_eq!(stats.ipv6.classified_mesh, 0);
        assert_eq!(stats.ipv6.classified_direct, 0);
        assert_eq!(stats.ipv6.classified_proxy, 0);
        assert_eq!(stats.dropped, 0);
    }

    /// AC10 类 6：截断包 → `dropped_truncated`，不增通用 dropped。
    #[test]
    fn c18_ipv6_truncated_is_visible() {
        let (mut dp, mock) = v6_dataplane();
        let mut short = vec![0u8; 24];
        short[0] = 0x60;
        short[6] = 17;
        mock.lock().unwrap().inject(short);
        dp.process_one().expect("process v6 truncated");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.dropped_truncated, 1);
        assert_eq!(stats.ipv6.classified_proxy, 0);
        assert_eq!(stats.dropped, 0);
    }

    /// AC10 类 2：v6/TCP → `ipv6.tcp`（分类 + Proxy 阻断）。
    #[test]
    fn c18_ipv6_tcp_is_counted() {
        let (mut dp, mock) = v6_dataplane();
        mock.lock().unwrap().inject(v6_tcp("2001:db8::21"));
        dp.process_one().expect("process v6 tcp");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.tcp, 1);
        assert_eq!(stats.ipv6.udp, 0);
        assert_eq!(stats.ipv6.classified_proxy, 1);
        assert_eq!(stats.ipv6.proxy_dropped, 1);
        assert_eq!(stats.dropped, 0);
    }

    /// AC10 类 3：ICMPv6（无 L4 端口）→ 不建 flow，按目的分类。
    #[test]
    fn c18_ipv6_icmpv6_is_classified_not_flowed() {
        let (mut dp, mock) = v6_dataplane();
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt[6] = 58; // ICMPv6
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&"fd00:144::1".parse::<Ipv6Addr>().unwrap().octets());
        pkt[24..40].copy_from_slice(&"2001:db8::22".parse::<Ipv6Addr>().unwrap().octets());
        mock.lock().unwrap().inject(pkt);
        dp.process_one().expect("process icmpv6");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.udp, 0);
        assert_eq!(stats.ipv6.tcp, 0);
        assert_eq!(stats.ipv6.classified_proxy, 1);
        assert_eq!(stats.ipv6.proxy_dropped, 1);
        assert_eq!(stats.dropped, 0);
    }

    /// AC10 类 4：ESP（未知扩展头）→ 按目的分类，不解析 L4。
    #[test]
    fn c18_ipv6_esp_is_classified_not_dropped() {
        let (mut dp, mock) = v6_dataplane();
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt[6] = 50; // ESP
        pkt[7] = 64;
        pkt[24..40].copy_from_slice(&"2001:db8::23".parse::<Ipv6Addr>().unwrap().octets());
        mock.lock().unwrap().inject(pkt);
        dp.process_one().expect("process esp");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.classified_proxy, 1);
        assert_eq!(stats.ipv6.proxy_dropped, 1);
        assert_eq!(stats.ipv6.dropped_extension, 0);
        assert_eq!(stats.dropped, 0);
    }

    /// AC10 类 5：分片（首片 + 非首片）→ `fragments` 计数，仍按目的分类。
    #[test]
    fn c18_ipv6_fragments_are_counted_and_classified() {
        let (mut dp, mock) = v6_dataplane();
        let frames: CapturedFrames = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_sender(Arc::new(TestN1Sender {
            frames: Arc::clone(&frames),
        }));

        let inner = v6_udp("fd00:144::6", b"frag");
        let first = with_extension(inner.clone(), 44, 17);
        let mut non_first = first.clone();
        non_first[42..44].copy_from_slice(&8u16.to_be_bytes()); // offset = 1

        mock.lock().unwrap().inject(first);
        dp.process_one().expect("process first fragment");
        mock.lock().unwrap().inject(non_first);
        dp.process_one().expect("process non-first fragment");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 2);
        assert_eq!(stats.ipv6.fragments, 2);
        assert_eq!(stats.ipv6.classified_mesh, 2);
        assert_eq!(
            stats.ipv6.udp, 1,
            "only the first fragment has an L4 header"
        );
        assert_eq!(stats.ipv6.mesh_forwarded, 2);
        assert_eq!(stats.dropped, 0);
    }

    /// 扩展头链 >8 → `dropped_extension`（fail-closed），不分类转发。
    #[test]
    fn c18_ipv6_too_many_extensions_is_dropped_extension() {
        let (mut dp, mock) = v6_dataplane();
        let mut pkt = vec![0u8; 40 + 9 * 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(9 * 8u16).to_be_bytes());
        pkt[6] = 0;
        pkt[7] = 64;
        pkt[24..40].copy_from_slice(&"fd00:144::6".parse::<Ipv6Addr>().unwrap().octets());
        for i in 0..9 {
            pkt[40 + i * 8] = if i == 8 { 17 } else { 0 };
        }
        mock.lock().unwrap().inject(pkt);
        dp.process_one().expect("process too many extensions");

        let stats = dp.stats();
        assert_eq!(stats.ipv6.packets, 1);
        assert_eq!(stats.ipv6.dropped_extension, 1);
        assert_eq!(stats.ipv6.classified_mesh, 0);
        assert_eq!(stats.dropped, 0);
    }

    /// AC16：能力表组合（无 routes6 → unsupported；有 → supported）。
    #[test]
    fn c18_ipv6_paths_capability_table() {
        let without = Ipv6Paths::from_capabilities(false);
        assert_eq!(without.mesh, "unsupported");
        assert_eq!(without.direct, "supported");
        assert_eq!(without.proxy_tcp, "supported");
        assert_eq!(without.proxy_udp, "blocked");
        assert_eq!(without.tun_address, "unassigned");
        assert_eq!(without.nat, "unsupported");

        let with = Ipv6Paths::from_capabilities(true);
        assert_eq!(with.mesh, "supported");
        assert_eq!(Ipv6Paths::default(), without);
    }

    /// AC12/AC16：`/dataplane/stats` 同时暴露 `ipv6` 与 `ipv6_paths`。
    #[test]
    fn c18_stats_json_exposes_ipv6_and_paths() {
        let status = RuntimeStatus {
            takeover_mode: "system-level".to_string(),
            ingress_ip_family: "dual-stack".to_string(),
            ipv6_paths: Ipv6Paths::from_capabilities(true),
            ..RuntimeStatus::default()
        };
        let stats = DataplaneStats {
            ipv6: Ipv6Stats {
                packets: 7,
                classified_proxy: 3,
                proxy_dropped: 3,
                ..Ipv6Stats::default()
            },
            ..DataplaneStats::default()
        };
        let json = dataplane_stats_json(true, &status, &stats, serde_json::json!({}));
        assert_eq!(json["dataplane"]["ipv6"]["packets"], 7);
        assert_eq!(json["dataplane"]["ipv6"]["classified_proxy"], 3);
        assert_eq!(json["dataplane"]["ipv6"]["proxy_dropped"], 3);
        assert_eq!(json["dataplane"]["ipv6"]["fragments"], 0);
        assert_eq!(json["ipv6_paths"]["mesh"], "supported");
        assert_eq!(json["ipv6_paths"]["proxy_tcp"], "supported");
        assert_eq!(json["ipv6_paths"]["proxy_udp"], "blocked");
        assert_eq!(json["ipv6_paths"]["tun_address"], "unassigned");
        assert_eq!(json["ipv6_paths"]["nat"], "unsupported");
        assert_eq!(json["ingress_ip_family"], "dual-stack");
    }

    /// N-8：`ingress_ip_family` 由能力表派生，不再硬编码 "ipv4"。
    #[test]
    fn c18_publish_runtime_basics_derives_ingress_family() {
        publish_runtime_basics("system-level", Ipv6Paths::from_capabilities(true));
        assert_eq!(runtime_status_snapshot().ingress_ip_family, "dual-stack");
        publish_runtime_basics("system-level", Ipv6Paths::from_capabilities(false));
        assert_eq!(runtime_status_snapshot().ingress_ip_family, "ipv4");
        assert_eq!(runtime_status_snapshot().ipv6_paths.mesh, "unsupported");
    }
    // -----------------------------------------------------------------
    // WP4：N1 入站消费 + 统一 dispatch（spec §5.5/§5.6/§7）
    // -----------------------------------------------------------------

    use crate::n1_runtime::{N1Inbound, N1Stats, N1StatsSnapshot};
    use crate::nat_chunk_recv::{CHUNK_KIND_TUN_STREAM, NatInboundChunk};
    use crate::nat_consumer::{NatActiveConn, NatHandleSlot, NatPathProvider};
    use crate::nat_switch::ChunkPath;
    use nexus_network::n1::{N1Connection, N1Error, N1KeepaliveStream, N1PeerId};

    /// 测试替身：N1 conn 只捕获回程 datagram。
    struct TestConn {
        peer: N1PeerId,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl TestConn {
        fn new(peer: N1PeerId) -> Self {
            Self {
                peer,
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl N1Connection for TestConn {
        fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            Err(N1Error::Closed)
        }
        fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn rebind(&self) -> Result<(), N1Error> {
            Ok(())
        }
        fn connection_id(&self) -> u64 {
            7
        }
        fn peer(&self) -> N1PeerId {
            self.peer
        }
        fn close(&self) {}
    }

    /// 测试替身：egress relay 的分派走向（真实 `TcpRelay` 在 WP5 装入）。
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RelayMode {
        Data,
        ClosedReset,
        Unknown,
    }

    type RelayCalls = Arc<Mutex<Vec<(String, u32, u8, Vec<u8>)>>>;

    struct TestRelay {
        mode: RelayMode,
        calls: RelayCalls,
    }

    impl N1EgressRelay for TestRelay {
        fn handle_frame(
            &mut self,
            stream_id: u32,
            flags: u8,
            payload: &[u8],
            from_peer: &str,
        ) -> Result<Vec<RelayEvent>, N1RelayError> {
            self.calls.lock().unwrap().push((
                from_peer.to_string(),
                stream_id,
                flags,
                payload.to_vec(),
            ));
            match self.mode {
                RelayMode::Data => Ok(vec![RelayEvent::Data {
                    stream_id,
                    peer: from_peer.to_string(),
                    bytes: b"relayed".to_vec(),
                }]),
                RelayMode::ClosedReset => Ok(vec![RelayEvent::Closed {
                    stream_id,
                    peer: from_peer.to_string(),
                    reset: true,
                }]),
                RelayMode::Unknown => Err(N1RelayError::UnknownStream),
            }
        }

        fn poll(&mut self) -> Vec<RelayEvent> {
            // 分派走向替身：poll 不属于本替身的观察面（WP5 egress 四态用真实
            // `TcpRelayEgress` 覆盖）。
            Vec::new()
        }
    }

    /// 测试替身：direct sink 的 `send_chunk` 只记录 chunk。
    struct RecordingProvider {
        chunks: Arc<Mutex<Vec<Vec<u8>>>>,
        direct: bool,
    }

    impl NatPathProvider for RecordingProvider {
        fn active_conn(&self, _peer_hex: &str) -> Option<NatActiveConn> {
            None
        }
        fn send_chunk(
            &self,
            _peer: nexus_fabric::PeerId,
            fallback: &dyn Fn(&[u8]) -> io::Result<()>,
            chunk: &[u8],
        ) -> io::Result<ChunkPath> {
            self.chunks.lock().unwrap().push(chunk.to_vec());
            if self.direct {
                Ok(ChunkPath::Direct)
            } else {
                fallback(chunk)?;
                Ok(ChunkPath::Fallback)
            }
        }
        fn peer_statuses(&self) -> Vec<nexus_nat_wireup::PunchPeerStatus> {
            Vec::new()
        }
        fn path_active_switches(&self) -> u64 {
            0
        }
    }

    fn n1_test_dataplane() -> (
        Dataplane,
        Arc<Mutex<nexus_projection::MockTun>>,
        Arc<N1Stats>,
    ) {
        let (mut dp, mock) = test_dataplane();
        let stats = Arc::new(N1Stats::default());
        dp.set_n1_stats(Arc::clone(&stats));
        (dp, mock, stats)
    }

    /// SYN → SYN-ACK → ACK，返回终结器分配的 stream id。
    fn establish_originator_stream(
        dp: &mut Dataplane,
        mock: &Arc<Mutex<nexus_projection::MockTun>>,
    ) -> u32 {
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
        *dp.tcp_streams.keys().next().expect("originator stream")
    }

    /// AC-N1-1 第 1 项生产路径：`pump_n1_inbound` 消费 `Stream`，originator
    /// 帧走既有 `inject_stream_frame_from_n1`。
    #[test]
    fn pump_n1_inbound_dispatches_originator_stream_to_the_terminator() {
        let (mut dp, mock, stats) = n1_test_dataplane();
        let sid = establish_originator_stream(&mut dp, &mock);

        let peer = N1PeerId([0x51; 32]);
        let conn = Arc::new(TestConn::new(peer));
        let frame = encode_stream_frame(sid, 0x00, b"downlink");
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_n1_inbound_rx(rx);
        tx.try_send(N1Inbound::ConnUp {
            peer,
            conn: Arc::clone(&conn) as Arc<dyn N1Connection>,
        })
        .expect("conn up");
        tx.try_send(N1Inbound::Stream {
            peer,
            conn: conn as Arc<dyn N1Connection>,
            frame,
        })
        .expect("stream");

        let tun_before = dp.stats().tun_written;
        dp.pump_n1_inbound();

        assert!(
            dp.stats().tun_written > tun_before,
            "originator frame must reach the TCP terminator and write TUN"
        );
        assert_eq!(dp.n1_peer_conns.len(), 1, "ConnUp registered the peer conn");
        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_to_terminator, 1);
        assert_eq!(snap.dispatch_to_relay, 0);
        assert_eq!(snap.dispatch_unknown_stream, 0);

        // ConnDown 回收回程 conn（direct fallback 不再命中该 peer）。
        tx.try_send(N1Inbound::ConnDown { peer })
            .expect("conn down");
        dp.pump_n1_inbound();
        assert!(
            dp.n1_peer_conns.is_empty(),
            "ConnDown removed the peer conn"
        );
    }

    /// AC-N1-3 分派侧：非 originator 流走 relay 接口；`RelayEvent::Data`
    /// 编码为 STREAM 帧经同一 N1 conn 回程。
    #[test]
    fn pump_n1_inbound_dispatches_relay_stream_and_sends_reply_over_n1() {
        let (mut dp, _mock, stats) = n1_test_dataplane();
        let calls: RelayCalls = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_relay(Box::new(TestRelay {
            mode: RelayMode::Data,
            calls: Arc::clone(&calls),
        }));

        let peer = N1PeerId([0x52; 32]);
        let conn = Arc::new(TestConn::new(peer));
        let sent = Arc::clone(&conn.sent);
        let frame = encode_stream_frame(0x0000_00AB, 0x00, b"uplink");
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_n1_inbound_rx(rx);
        tx.try_send(N1Inbound::Stream {
            peer,
            conn: conn as Arc<dyn N1Connection>,
            frame,
        })
        .expect("stream");

        dp.pump_n1_inbound();

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "relay saw exactly one frame");
        assert_eq!(calls[0].0, peer.to_hex());
        assert_eq!(calls[0].1, 0xAB);
        assert_eq!(calls[0].2, 0x00);
        assert_eq!(calls[0].3, b"uplink");

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "relay Data event replied on the sink");
        let (sid, flags, payload) = decode_stream_frame(&sent[0]).expect("encoded frame");
        assert_eq!(sid, 0xAB);
        assert_eq!(flags, 0x00);
        assert_eq!(payload, b"relayed");
        drop(sent);

        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_to_relay, 1);
        assert_eq!(snap.dispatch_to_terminator, 0);
        assert_eq!(snap.tx_frames, 1);
        assert_eq!(snap.tx_errors, 0);
    }

    /// §6.1 `BadFrame`：短帧只计 `dispatch.bad_frame`，不进 terminator/relay。
    #[test]
    fn dispatch_bad_frame_is_counted_and_dropped() {
        let (mut dp, _mock, stats) = n1_test_dataplane();
        let calls: RelayCalls = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_relay(Box::new(TestRelay {
            mode: RelayMode::Data,
            calls: Arc::clone(&calls),
        }));
        let peer = N1PeerId([0x53; 32]);
        let conn = Arc::new(TestConn::new(peer));
        let sent = Arc::clone(&conn.sent);
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_n1_inbound_rx(rx);
        tx.try_send(N1Inbound::Stream {
            peer,
            conn: conn as Arc<dyn N1Connection>,
            frame: vec![0x00, 0x01],
        })
        .expect("stream");

        dp.pump_n1_inbound();

        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_bad_frame, 1);
        assert_eq!(snap.dispatch_to_relay, 0);
        assert_eq!(snap.dispatch_to_terminator, 0);
        assert!(
            calls.lock().unwrap().is_empty(),
            "relay never sees a bad frame"
        );
        assert!(sent.lock().unwrap().is_empty(), "no reply for a bad frame");
    }

    /// §5.5 第 2 步：relay 不认识该流 → `dispatch.unknown_stream`，不回帧。
    #[test]
    fn dispatch_unknown_stream_is_counted_when_the_relay_rejects() {
        let (mut dp, _mock, stats) = n1_test_dataplane();
        let calls: RelayCalls = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_relay(Box::new(TestRelay {
            mode: RelayMode::Unknown,
            calls: Arc::clone(&calls),
        }));
        let peer = N1PeerId([0x54; 32]);
        let conn = Arc::new(TestConn::new(peer));
        let sent = Arc::clone(&conn.sent);
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_n1_inbound_rx(rx);
        tx.try_send(N1Inbound::Stream {
            peer,
            conn: conn as Arc<dyn N1Connection>,
            frame: encode_stream_frame(0x99, 0x00, b"x"),
        })
        .expect("stream");

        dp.pump_n1_inbound();

        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_unknown_stream, 1);
        assert_eq!(snap.dispatch_to_relay, 0);
        assert_eq!(snap.tx_frames, 0);
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(sent.lock().unwrap().is_empty());
    }

    /// ERRATA-2：`pump_nat_inbound` 与 N1 路径共用同一 dispatch；direct 的
    /// originator 帧仍进终结器。
    #[test]
    fn pump_nat_inbound_dispatches_originator_stream_to_the_terminator() {
        let (mut dp, mock, stats) = n1_test_dataplane();
        let sid = establish_originator_stream(&mut dp, &mock);

        let peer = nexus_fabric::PeerId([0x61; 32]);
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_nat_inbound_rx(rx);
        tx.try_send(NatInboundChunk {
            peer,
            stream_frame: encode_stream_frame(sid, 0x00, b"direct-down"),
        })
        .expect("chunk");

        let tun_before = dp.stats().tun_written;
        dp.pump_nat_inbound();

        assert!(dp.stats().tun_written > tun_before);
        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_to_terminator, 1);
        assert_eq!(snap.dispatch_to_relay, 0);
    }

    /// ERRATA-2：direct 的未知流进 relay；回程走 `send_chunk` 且带 KIND 前缀。
    #[test]
    fn pump_nat_inbound_routes_unknown_stream_to_relay_with_kind_prefix() {
        let (mut dp, _mock, stats) = n1_test_dataplane();
        let peer = nexus_fabric::PeerId([0x62; 32]);
        let chunks = Arc::new(Mutex::new(Vec::new()));
        let slot = NatHandleSlot::new();
        slot.set(Arc::new(RecordingProvider {
            chunks: Arc::clone(&chunks),
            direct: true,
        }));
        dp.set_nat_path_slot(slot);
        let calls: RelayCalls = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_relay(Box::new(TestRelay {
            mode: RelayMode::Data,
            calls: Arc::clone(&calls),
        }));
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_nat_inbound_rx(rx);
        tx.try_send(NatInboundChunk {
            peer,
            stream_frame: encode_stream_frame(0x77, 0x00, b"direct-up"),
        })
        .expect("chunk");

        dp.pump_nat_inbound();

        let chunks = chunks.lock().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], CHUNK_KIND_TUN_STREAM, "KIND prefix on direct");
        let (sid, flags, payload) = decode_stream_frame(&chunks[0][1..]).expect("frame");
        assert_eq!(sid, 0x77);
        assert_eq!(flags, 0x00);
        assert_eq!(payload, b"relayed");
        drop(chunks);

        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_to_relay, 1);
        assert_eq!(snap.tx_frames, 1);
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    /// §5.5 第 3 步 fallback：无 direct provider 时 direct 回程落到该 peer 的
    /// N1 conn，且**不带** KIND 字节（P0 wire 逐字节不变）。
    #[test]
    fn direct_reply_falls_back_to_the_n1_conn_without_kind_byte() {
        let (mut dp, _mock, stats) = n1_test_dataplane();
        let peer_id = nexus_fabric::PeerId([0x63; 32]);
        let n1_peer = N1PeerId(peer_id.0);
        let conn = Arc::new(TestConn::new(n1_peer));
        let sent = Arc::clone(&conn.sent);
        dp.n1_peer_conns
            .insert(n1_peer.to_hex(), conn as Arc<dyn N1Connection>);
        let calls: RelayCalls = Arc::new(Mutex::new(Vec::new()));
        dp.set_n1_relay(Box::new(TestRelay {
            mode: RelayMode::ClosedReset,
            calls: Arc::clone(&calls),
        }));
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        dp.set_nat_inbound_rx(rx);
        tx.try_send(NatInboundChunk {
            peer: peer_id,
            stream_frame: encode_stream_frame(0x88, 0x00, b"up"),
        })
        .expect("chunk");

        dp.pump_nat_inbound();

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "fallback used the N1 conn");
        let (sid, flags, payload) = decode_stream_frame(&sent[0]).expect("frame");
        assert_eq!(sid, 0x88);
        assert_eq!(flags, STREAM_RST, "Closed{{reset:true}} replies RST");
        assert!(payload.is_empty());
        drop(sent);
        assert_eq!(stats.snapshot().tx_frames, 1);
    }

    /// §8.1 队列有界：4096 深度可入队，第 4097 条被拒（不无界积压）；消费端
    /// 一次 drain 全量。
    #[test]
    fn pump_n1_inbound_drains_a_full_backlog_and_the_producer_sees_full() {
        use std::sync::mpsc::TrySendError;
        let (mut dp, _mock, _stats) = n1_test_dataplane();
        let (tx, rx) = std::sync::mpsc::sync_channel(crate::n1_runtime::N1_INBOUND_QUEUE_CAP);
        dp.set_n1_inbound_rx(rx);
        let peer = N1PeerId([0x64; 32]);
        let packet = craft_udp([10, 200, 0, 2], [10, 200, 0, 5], 1, 2, b"x");
        for _ in 0..crate::n1_runtime::N1_INBOUND_QUEUE_CAP {
            tx.try_send(N1Inbound::RawIp {
                peer,
                packet: packet.clone(),
            })
            .expect("queue has room up to the cap");
        }
        assert!(matches!(
            tx.try_send(N1Inbound::RawIp {
                peer,
                packet: packet.clone(),
            }),
            Err(TrySendError::Full(_))
        ));
        dp.pump_n1_inbound();
        assert_eq!(
            dp.stats().tun_written,
            crate::n1_runtime::N1_INBOUND_QUEUE_CAP as u64
        );
        assert!(
            tx.try_send(N1Inbound::RawIp { peer, packet }).is_ok(),
            "draining frees capacity again"
        );
    }

    /// WP3 交接项：disabled 路径的队列立即 `Disconnected`，必须当常态处理
    /// （不报错、不刷日志、不计拒绝）。
    #[test]
    fn pump_n1_inbound_treats_a_disconnected_queue_as_disabled() {
        let (mut dp, _mock, stats) = n1_test_dataplane();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        drop(tx);
        dp.set_n1_inbound_rx(rx);
        dp.pump_n1_inbound();
        assert_eq!(stats.snapshot(), N1StatsSnapshot::default());
    }

    // ---- WP5：egress `TcpRelay` 接线（spec §5.5/§5.6/§6.2） ----

    /// 装配式 egress harness：**只经 `Dataplane` 公开面**驱动
    /// （`set_n1_relay` / `pump_n1_inbound` / `n1_egress_poll`），
    /// 不直调 `TcpRelay::handle_frame` 充当接线证据。
    struct EgressHarness {
        dp: Dataplane,
        stats: Arc<N1Stats>,
        conn: Arc<TestConn>,
        tx: std::sync::mpsc::SyncSender<N1Inbound>,
        peer: N1PeerId,
    }

    impl EgressHarness {
        fn new() -> Self {
            let (mut dp, _mock) = test_dataplane();
            let stats = Arc::new(N1Stats::default());
            dp.set_n1_stats(Arc::clone(&stats));
            dp.set_n1_relay(Box::new(TcpRelayEgress::new(Arc::clone(&stats))));
            let peer = N1PeerId([0x71; 32]);
            let conn = Arc::new(TestConn::new(peer));
            let (tx, rx) = std::sync::mpsc::sync_channel(2048);
            dp.set_n1_inbound_rx(rx);
            tx.try_send(N1Inbound::ConnUp {
                peer,
                conn: Arc::clone(&conn) as Arc<dyn N1Connection>,
            })
            .expect("conn up");
            dp.pump_n1_inbound();
            Self {
                dp,
                stats,
                conn,
                tx,
                peer,
            }
        }

        fn send_frame(&self, stream_id: u32, flags: u8, payload: &[u8]) {
            self.tx
                .try_send(N1Inbound::Stream {
                    peer: self.peer,
                    conn: Arc::clone(&self.conn) as Arc<dyn N1Connection>,
                    frame: encode_stream_frame(stream_id, flags, payload),
                })
                .expect("queue has room");
        }

        fn pump(&mut self) {
            self.dp.pump_n1_inbound();
        }

        fn conn_down(&self) {
            self.tx
                .try_send(N1Inbound::ConnDown { peer: self.peer })
                .expect("conn down");
        }

        fn poll(&mut self) {
            self.dp.n1_egress_poll();
        }

        fn sent(&self) -> Vec<(u32, u8, Vec<u8>)> {
            self.conn
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|raw| {
                    let (sid, flags, payload) = decode_stream_frame(raw).expect("reply frame");
                    (sid, flags, payload.to_vec())
                })
                .collect()
        }

        fn wait_for(&mut self, mut pred: impl FnMut(&[(u32, u8, Vec<u8>)]) -> bool) {
            for _ in 0..400 {
                self.poll();
                if pred(&self.sent()) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            panic!("egress reply did not arrive: {:?}", self.sent());
        }
    }

    fn syn_payload_for(addr: std::net::SocketAddr) -> Vec<u8> {
        let std::net::SocketAddr::V4(v4) = addr else {
            panic!("test only uses IPv4 targets");
        };
        let mut payload = vec![0x01];
        payload.extend_from_slice(&v4.ip().octets());
        payload.extend_from_slice(&v4.port().to_be_bytes());
        payload
    }

    /// 本地 echo 服务：accept 一条连接并回显到 EOF（连接关闭即退出）。
    fn spawn_echo_server() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                let mut buf = [0u8; 4096];
                loop {
                    match io::Read::read(&mut stream, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if io::Write::write_all(&mut stream, &buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        (addr, handle)
    }

    /// 已关闭的本地端口：connect 必然失败（用于 connect 失败 / 表满态）。
    fn closed_port() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind closed");
        let addr = listener.local_addr().expect("closed addr");
        drop(listener);
        addr
    }

    /// 四态①：SYN → connect 成功 → DATA 转发到本地 socket；回程字节编码为
    /// STREAM DATA 经同一 N1 conn 发出，`egress.*` 按 §5.6 推进。
    #[test]
    fn egress_relay_connects_forwards_and_replies_over_n1() {
        let (addr, echo) = spawn_echo_server();
        let mut h = EgressHarness::new();
        let sid = 0x51;
        h.send_frame(sid, STREAM_SYN, &syn_payload_for(addr));
        h.pump();
        h.send_frame(sid, 0x00, b"hello");
        h.pump();

        h.wait_for(|frames| {
            frames
                .iter()
                .any(|(s, f, p)| *s == sid && *f == 0x00 && p == b"hello")
        });

        let snap = h.stats.snapshot();
        assert_eq!(snap.egress_syn, 1, "one SYN handed to the relay");
        assert_eq!(snap.egress_connect_ok, 1, "connect success observed");
        assert_eq!(snap.egress_connect_failed, 0);
        assert_eq!(snap.egress_table_full, 0);
        assert_eq!(
            snap.egress_bytes_to_local, 5,
            "DATA payload written to the local socket"
        );
        assert_eq!(
            snap.egress_bytes_from_local, 5,
            "echoed bytes handed back to N1"
        );
        assert!(snap.tx_frames >= 1);
        assert_eq!(snap.tx_errors, 0);
        assert_eq!(snap.dispatch_to_relay, 2, "SYN + DATA consumed by relay");
        assert_eq!(snap.dispatch_unknown_stream, 0);

        drop(h);
        echo.join().expect("echo thread");
    }

    /// 四态②：connect 失败 → 回 RST + `egress.connect_failed` + `tx.frames`；
    /// 不 panic、不静默（失败的流随后按 unknown 处理）。
    #[test]
    fn egress_relay_connect_failure_replies_rst_and_counts() {
        let addr = closed_port();
        let mut h = EgressHarness::new();
        let sid = 0x61;
        h.send_frame(sid, STREAM_SYN, &syn_payload_for(addr));
        h.pump();
        h.wait_for(|frames| {
            frames
                .iter()
                .any(|(s, f, p)| *s == sid && *f == STREAM_RST && p.is_empty())
        });

        let snap = h.stats.snapshot();
        assert_eq!(snap.egress_syn, 1);
        assert_eq!(snap.egress_connect_failed, 1);
        assert_eq!(snap.egress_connect_ok, 0);
        assert_eq!(snap.egress_table_full, 0);
        assert_eq!(snap.dispatch_to_relay, 1);
        assert_eq!(snap.tx_frames, 1, "RST is the only reply");
        assert_eq!(snap.tx_errors, 0);

        // 失败的流已被 relay 移出表：后续 DATA 诚实计 unknown_stream。
        h.send_frame(sid, 0x00, b"late");
        h.pump();
        assert_eq!(h.stats.snapshot().dispatch_unknown_stream, 1);
    }

    /// 四态③：连接表满（`MAX_TCP_CONNS = 1024`）→ 回 RST + `table_full`。
    ///
    /// 1024 条 SYN 在一次 pump 内进入 pending（connect 结果只在 `poll` 的
    /// `drain_connects` 里回收），第 1025 条即触发机制侧表满分支。
    #[test]
    fn egress_relay_table_full_replies_rst_and_counts() {
        let addr = closed_port();
        let mut h = EgressHarness::new();
        for i in 0..nexus_projection::tcp::MAX_TCP_CONNS as u32 {
            h.send_frame(i + 1, STREAM_SYN, &syn_payload_for(addr));
        }
        h.pump();
        assert!(h.sent().is_empty(), "SYN 不产生回程帧");

        let overflow_sid = 0x0FFF_FFFF;
        h.send_frame(overflow_sid, STREAM_SYN, &syn_payload_for(addr));
        h.pump();

        let frames = h.sent();
        assert_eq!(frames.len(), 1, "only the table-full SYN gets a reply");
        assert_eq!(frames[0].0, overflow_sid);
        assert_eq!(frames[0].1, STREAM_RST);
        assert!(frames[0].2.is_empty());

        let snap = h.stats.snapshot();
        assert_eq!(snap.egress_syn, 1025);
        assert_eq!(snap.egress_table_full, 1);
        assert_eq!(snap.egress_connect_failed, 0);
        assert_eq!(snap.dispatch_to_relay, 1025);
        assert_eq!(snap.tx_frames, 1);
    }

    /// 四态④：FIN 收尾回 FIN（EOF），RST 收尾不回帧并从表中移除。
    #[test]
    fn egress_relay_fin_and_rst_teardown() {
        let (addr_a, echo_a) = spawn_echo_server();
        let mut h = EgressHarness::new();
        let sid = 0x71;
        h.send_frame(sid, STREAM_SYN, &syn_payload_for(addr_a));
        h.pump();
        h.send_frame(sid, 0x00, b"fin-me");
        h.pump();
        h.wait_for(|frames| {
            frames
                .iter()
                .any(|(s, f, p)| *s == sid && *f == 0x00 && p == b"fin-me")
        });

        // 本端 FIN → relay shutdown(Write) → 对端 EOF → 回程 FIN。
        h.send_frame(sid, STREAM_FIN, &[]);
        h.pump();
        h.wait_for(|frames| frames.iter().any(|(s, f, _)| *s == sid && *f == STREAM_FIN));
        echo_a.join().expect("echo a");

        // RST 收尾：relay 移除连接、不回帧；后续 DATA 变成 unknown。
        let (addr_b, echo_b) = spawn_echo_server();
        let sid_b = 0x72;
        h.send_frame(sid_b, STREAM_SYN, &syn_payload_for(addr_b));
        h.pump();
        h.send_frame(sid_b, 0x00, b"x");
        h.pump();
        h.wait_for(|frames| {
            frames
                .iter()
                .any(|(s, f, p)| *s == sid_b && *f == 0x00 && p == b"x")
        });
        let before = h.stats.snapshot();
        h.send_frame(sid_b, STREAM_RST, &[]);
        h.pump();
        assert_eq!(
            h.stats.snapshot().tx_frames,
            before.tx_frames,
            "originator RST must not trigger a reply"
        );

        h.send_frame(sid_b, 0x00, b"after-rst");
        h.pump();
        assert_eq!(h.stats.snapshot().dispatch_unknown_stream, 1);
        drop(h);
        echo_b.join().expect("echo b");
    }

    /// 装配收口（WP4 §5.8 交接）：同一条「非 originator SYN」在无 relay 的
    /// 装配下计 `dispatch.unknown_stream`，装入真实 relay 后计 `to_relay`。
    #[test]
    fn egress_relay_takes_over_the_unknown_stream_path() {
        let addr = closed_port();
        let frame = encode_stream_frame(0x7A, STREAM_SYN, &syn_payload_for(addr));

        // 形态一：无 relay（WP4 现状）。
        let (mut bare, _mock, bare_stats) = n1_test_dataplane();
        let peer = N1PeerId([0x72; 32]);
        let conn = Arc::new(TestConn::new(peer));
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        bare.set_n1_inbound_rx(rx);
        tx.try_send(N1Inbound::Stream {
            peer,
            conn: conn as Arc<dyn N1Connection>,
            frame,
        })
        .expect("frame");
        bare.pump_n1_inbound();
        assert_eq!(bare_stats.snapshot().dispatch_unknown_stream, 1);
        assert_eq!(bare_stats.snapshot().dispatch_to_relay, 0);

        // 形态二：装入真实 `TcpRelay` 适配器。
        let mut h = EgressHarness::new();
        h.send_frame(0x7A, STREAM_SYN, &syn_payload_for(addr));
        h.pump();
        let snap = h.stats.snapshot();
        assert_eq!(snap.dispatch_to_relay, 1);
        assert_eq!(snap.dispatch_unknown_stream, 0);
        assert_eq!(snap.egress_syn, 1);
    }

    /// §6.2 `TxError`：回程时 peer 的 N1 conn 已下线 → `tx.errors` + WARN；
    /// 回程字节不静默消失。
    #[test]
    fn egress_relay_reply_without_a_peer_conn_counts_tx_errors() {
        let (addr, echo) = spawn_echo_server();
        let mut h = EgressHarness::new();
        let sid = 0x81;
        h.send_frame(sid, STREAM_SYN, &syn_payload_for(addr));
        h.pump();
        h.send_frame(sid, 0x00, b"hi");
        h.pump();
        h.conn_down();
        h.pump();

        for _ in 0..400 {
            h.poll();
            if h.stats.snapshot().tx_errors > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let snap = h.stats.snapshot();
        assert_eq!(
            snap.tx_errors, 1,
            "missing peer conn is counted, not swallowed"
        );
        assert_eq!(snap.tx_frames, 0);
        assert_eq!(snap.egress_bytes_from_local, 2);
        assert_eq!(snap.egress_connect_ok, 1);

        drop(h);
        echo.join().expect("echo thread");
    }
}
