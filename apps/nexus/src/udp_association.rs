//! UDP 关联管理器（spec §5；`apps/nexus` 内部，C3 只做纯逻辑，不接 serve）。
//!
//! Owner 模型：关联持有 flow 表、回包队列、限速器与唯一终态；session 只发回包/
//! 关闭事件。纯逻辑不读系统时间——所有方法接收调用方传入的 `now`（R-5=(a)），
//! 测试用 `base + Duration` 推进虚拟时间。R-7=(a)：串行 accept 模型保留，
//! `MAX_UDP_ASSOCIATIONS` 在现行模型下不可达（有效并发=1，见 C4/报告）。

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_ingress::{Socks5Address, decode_udp_datagram};
use nexus_proxy_config::OutboundKind;

use super::udp_outbound::{TargetAddr, UdpOutbound, UdpOutboundError, UdpSession};

/// 单 flow 空闲回收（60s；与 nexusd `UDP_FLOW_TIMEOUT` 同值）。
pub(crate) const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(60);
/// 全局 flow 上限（1024；与 nexusd `MAX_UDP_FLOWS` 同值）。
pub(crate) const MAX_UDP_FLOWS: usize = 1024;
/// 单关联 flow 上限（64）。
pub(crate) const MAX_UDP_FLOWS_PER_ASSOCIATION: usize = 64;
/// 全局关联上限（128；C4 在握手阶段判定）。
pub(crate) const MAX_UDP_ASSOCIATIONS: usize = 128;
/// 关联回包队列深度（256 包）。
pub(crate) const UDP_REPLY_QUEUE_DEPTH: usize = 256;
/// 关联回包队列字节上限（256 KiB）。
pub(crate) const UDP_REPLY_QUEUE_BYTES: usize = 256 * 1024;
/// 单关联 pps 上限。
pub(crate) const UDP_MAX_PPS_PER_ASSOCIATION: u32 = 2000;
/// 单关联 bytes/s 上限（8 MiB/s）。
pub(crate) const UDP_MAX_BYTES_PER_SECOND_PER_ASSOCIATION: u64 = 8 * 1024 * 1024;
/// 全局 pps 上限。
pub(crate) const UDP_MAX_PPS_GLOBAL: u32 = 20000;
/// 入口单包上限（IPv4 UDP 最大载荷）。
pub(crate) const UDP_MAX_DATAGRAM_BYTES: usize = 65507;
/// 限频日志间隔（10s；与 nexusd 同值）。
pub(crate) const UDP_LOG_INTERVAL: Duration = Duration::from_secs(10);
/// 关联空闲超时默认值（None = 只随控制连接结束；可选 300s）。
pub(crate) const UDP_ASSOCIATION_IDLE_TIMEOUT: Option<Duration> = None;
/// 可选关联空闲超时（§5.2）。
// 产品默认 `None`（只随控制连接结束）；该值由启用 300s 的测试与后续开关使用。
#[allow(dead_code)]
pub(crate) const UDP_ASSOCIATION_IDLE_TIMEOUT_OPTION: Duration = Duration::from_secs(300);

/// 关联资源配置（§5.1；等价重构：`global_flows`/`global_rate` 由构造参数注入）。
#[derive(Debug, Clone)]
pub(crate) struct UdpAssociationConfig {
    /// 单 flow 空闲回收。
    pub(crate) flow_timeout: Duration,
    /// 关联空闲超时；None = 只随控制连接结束。
    pub(crate) association_idle_timeout: Option<Duration>,
    /// 单关联 flow 上限。
    pub(crate) max_flows_per_association: usize,
    /// 全局 flow 上限。
    pub(crate) max_flows_global: usize,
    /// 单包载荷上限。
    pub(crate) max_datagram_bytes: usize,
    /// 回包队列深度。
    pub(crate) max_queue_depth: usize,
    /// 回包队列字节上限。
    pub(crate) max_queue_bytes: usize,
    /// 单关联 pps 上限。
    pub(crate) max_pps_per_association: u32,
    /// 单关联 bytes/s 上限。
    pub(crate) max_bytes_per_second_per_association: u64,
    /// 全局 pps 上限。
    pub(crate) max_pps_global: u32,
    /// 限频日志间隔（C4 消费）。
    pub(crate) log_interval: Duration,
}

impl Default for UdpAssociationConfig {
    fn default() -> Self {
        Self {
            flow_timeout: UDP_FLOW_TIMEOUT,
            association_idle_timeout: UDP_ASSOCIATION_IDLE_TIMEOUT,
            max_flows_per_association: MAX_UDP_FLOWS_PER_ASSOCIATION,
            max_flows_global: MAX_UDP_FLOWS,
            max_datagram_bytes: UDP_MAX_DATAGRAM_BYTES,
            max_queue_depth: UDP_REPLY_QUEUE_DEPTH,
            max_queue_bytes: UDP_REPLY_QUEUE_BYTES,
            max_pps_per_association: UDP_MAX_PPS_PER_ASSOCIATION,
            max_bytes_per_second_per_association: UDP_MAX_BYTES_PER_SECOND_PER_ASSOCIATION,
            max_pps_global: UDP_MAX_PPS_GLOBAL,
            log_interval: UDP_LOG_INTERVAL,
        }
    }
}

/// 关联统计（§5.1 全字段）。
#[derive(Debug, Default, Clone)]
pub(crate) struct Stats {
    pub(crate) associations_opened: u64,
    pub(crate) associations_closed: u64,
    pub(crate) associations_rejected: u64,
    pub(crate) control_closed: u64,
    pub(crate) udp_control_protocol_violation: u64,
    pub(crate) datagrams_in: u64,
    pub(crate) datagrams_out: u64,
    pub(crate) bytes_in: u64,
    pub(crate) bytes_out: u64,
    pub(crate) flows_opened: u64,
    pub(crate) flows_reaped: u64,
    pub(crate) flows_closed: u64,
    pub(crate) dropped_malformed: u64,
    pub(crate) dropped_fragment: u64,
    pub(crate) dropped_source_mismatch: u64,
    pub(crate) dropped_no_route: u64,
    pub(crate) dropped_unsupported: u64,
    pub(crate) dropped_unsupported_vless: u64,
    pub(crate) dropped_unsupported_anytls: u64,
    pub(crate) dropped_unsupported_trojan: u64,
    pub(crate) dropped_unsupported_shadowsocks: u64,
    pub(crate) dropped_unsupported_hysteria2: u64,
    pub(crate) dropped_unsupported_other: u64,
    pub(crate) dropped_oversize: u64,
    pub(crate) dropped_flow_limit: u64,
    pub(crate) dropped_association_flow_limit: u64,
    pub(crate) dropped_global_flow_limit: u64,
    pub(crate) dropped_rate_limited: u64,
    pub(crate) dropped_queue_full: u64,
    pub(crate) send_failed: u64,
    pub(crate) recv_failed: u64,
    pub(crate) unmatched_replies: u64,
    pub(crate) log_suppressed: u64,
}

/// 唯一终态（由关联 owner 写一次）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// 正常结束（控制连接 EOF / 空闲超时）。
    Completed,
    /// 失败结束。
    Failed(UdpAssociateError),
    /// 进程/daemon 关闭（spec §3.6 T4；进程级关闭信号未接入，当前不构造）。
    #[allow(dead_code)]
    Cancelled,
}

/// 关联层错误（spec §4.7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpAssociateError {
    /// UDP bind 失败（spec §4.7；C4 在 bind 失败处直接回 REP=0x01，不构造本变体）。
    #[allow(dead_code)]
    BindFailed { kind: std::io::ErrorKind },
    /// 控制连接 EOF（spec §3.6 T1；正常路径记 `Completed` + `control_closed`）。
    #[allow(dead_code)]
    ControlClosed,
    /// 控制连接错误。
    ControlIo { kind: std::io::ErrorKind },
    /// 全局关联数达上限（spec §3.6 T6；C4 在握手阶段直接拒绝，不构造本变体）。
    #[allow(dead_code)]
    AssociationLimit { active: usize, limit: usize },
    /// UDP socket fatal error。
    UdpSocketIo { kind: std::io::ErrorKind },
    /// 出站工厂构造失败（spec §4.7；C4 归类为 `OutboundHandshake` 丢弃原因）。
    #[allow(dead_code)]
    OutboundFactory { detail: &'static str },
    /// 控制连接上出现额外数据。
    ProtocolViolation,
    /// 不应发生。
    #[allow(dead_code)]
    Internal { what: &'static str },
}

/// flow 表 key（目标 + 出站 tag）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    pub(crate) target: TargetAddr,
    pub(crate) outbound_tag: String,
}

/// 本轮事件（由 owner 消费）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// 无事件。
    None,
    /// 控制连接已关闭（spec §5.1；owner 在 serve 循环自行判定，关联内不构造）。
    #[allow(dead_code)]
    ControlClosed,
    /// 关联空闲超时（启用时）。
    IdleTimeout,
    /// 控制连接协议违规（spec §5.1；owner 在 serve 循环自行判定，关联内不构造）。
    #[allow(dead_code)]
    ProtocolViolation,
    /// 致命错误（spec §5.1；owner 在 serve 循环自行判定，关联内不构造）。
    #[allow(dead_code)]
    Fatal(UdpAssociateError),
}

/// 策略层丢弃原因（不是错误回包）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpDropReason {
    MalformedDatagram,
    FragmentUnsupported {
        fragment: u8,
    },
    SourceMismatch,
    NoRoute,
    UnsupportedProtocol {
        kind: OutboundKind,
    },
    DatagramTooLarge {
        len: usize,
        limit: usize,
    },
    /// 单 flow 上限（spec §5.1；当前按关联/全局两档判定，不构造本变体）。
    #[allow(dead_code)]
    FlowLimit {
        active: usize,
        limit: usize,
    },
    AssociationFlowLimit {
        active: usize,
        limit: usize,
    },
    GlobalFlowLimit {
        active: usize,
        limit: usize,
    },
    RateLimited,
    /// 队列满（spec §5.1；队列丢弃在 `collect_replies` 内直接计数，不构造本变体）。
    #[allow(dead_code)]
    QueueFull,
    OutboundIo {
        kind: OutboundKind,
    },
    OutboundClosed {
        kind: OutboundKind,
    },
    OutboundTimeout {
        kind: OutboundKind,
    },
    OutboundHandshake {
        kind: OutboundKind,
    },
    /// 回包目标不在 flow 表（spec §5.1；`collect_replies` 内直接计数，不构造本变体）。
    #[allow(dead_code)]
    UnmatchedReply,
    ControlClosed,
}

/// 路由结果：目标命中的出站（tag + 工厂）。
pub(crate) struct RoutedOutbound {
    pub(crate) tag: String,
    pub(crate) outbound: Arc<dyn UdpOutbound>,
}

/// 目标 → 出站的路由接缝（C4 用 `ProxyService` 实现；测试用固定/失败替身）。
pub(crate) trait UdpOutboundRouter: Send + Sync {
    fn route(&self, target: &TargetAddr) -> Result<RoutedOutbound, UdpDropReason>;
}

/// 全局 pps 限速器（跨关联共享）。
#[derive(Debug)]
pub(crate) struct GlobalRateLimiter {
    window: Mutex<RateWindow>,
}

impl GlobalRateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            window: Mutex::new(RateWindow::default()),
        }
    }

    fn allow(&self, now: Instant, limit: u32) -> bool {
        self.window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allow(now, limit)
    }
}

impl Default for GlobalRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// 1 秒固定窗口计数（虚拟时间由调用方推进）。
#[derive(Debug, Default)]
struct RateWindow {
    start: Option<Instant>,
    count: u32,
}

impl RateWindow {
    fn allow(&mut self, now: Instant, limit: u32) -> bool {
        let expired = match self.start {
            Some(start) => now.saturating_duration_since(start) >= Duration::from_secs(1),
            None => true,
        };
        if expired {
            self.start = Some(now);
            self.count = 0;
        }
        if self.count >= limit {
            return false;
        }
        self.count += 1;
        true
    }
}

/// 单关联 pps + bytes/s 固定窗口。
#[derive(Debug, Default)]
struct AssociationRate {
    start: Option<Instant>,
    packets: u32,
    bytes: u64,
}

impl AssociationRate {
    fn allow(&mut self, now: Instant, pps_limit: u32, bytes_limit: u64, bytes: u64) -> bool {
        let expired = match self.start {
            Some(start) => now.saturating_duration_since(start) >= Duration::from_secs(1),
            None => true,
        };
        if expired {
            self.start = Some(now);
            self.packets = 0;
            self.bytes = 0;
        }
        if self.packets >= pps_limit || self.bytes.saturating_add(bytes) > bytes_limit {
            return false;
        }
        self.packets += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        true
    }
}

/// 被回收的 flow 观测（C4 的 `[proxy-udp] event=flow_reaped` 数据源）。
///
/// 只承载观测所需字段，不改变关联的 flow 表/终态语义；由 `take_reaped` 取走。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReapedFlow {
    /// flow 目标。
    pub(crate) target: TargetAddr,
    /// 出站 tag。
    pub(crate) outbound_tag: String,
    /// 出站 kind。
    pub(crate) outbound_kind: OutboundKind,
    /// 回收时的空闲时长（`now - last_seen`）。
    pub(crate) idle: Duration,
}

/// flow 表项（session 由关联独占持有；worker 不直接改统计/终态）。
struct FlowEntry {
    target: TargetAddr,
    outbound_tag: String,
    outbound_kind: OutboundKind,
    session: Box<dyn UdpSession>,
    last_seen: Instant,
}

/// 一个 UDP 关联（owner 唯一持有）。
pub(crate) struct UdpAssociation {
    id: u64,
    client_ip: IpAddr,
    client_udp_port: Option<u16>,
    router: Arc<dyn UdpOutboundRouter>,
    flows: HashMap<FlowKey, FlowEntry>,
    replies: VecDeque<(Socks5Address, Vec<u8>)>,
    queued_bytes: usize,
    config: UdpAssociationConfig,
    stats: Stats,
    outcome: Option<Outcome>,
    last_activity: Instant,
    rate: AssociationRate,
    global_rate: Arc<GlobalRateLimiter>,
    global_flows: Arc<AtomicUsize>,
    reaped: Vec<ReapedFlow>,
}

impl UdpAssociation {
    /// 新建关联（不绑定 socket；C4 在 bind 成功后构造并写 `associations_opened`）。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: u64,
        client_ip: IpAddr,
        client_udp_port: Option<u16>,
        router: Arc<dyn UdpOutboundRouter>,
        config: UdpAssociationConfig,
        global_rate: Arc<GlobalRateLimiter>,
        global_flows: Arc<AtomicUsize>,
        now: Instant,
    ) -> Self {
        let stats = Stats {
            associations_opened: 1,
            ..Stats::default()
        };
        Self {
            id,
            client_ip,
            client_udp_port,
            router,
            flows: HashMap::new(),
            replies: VecDeque::new(),
            queued_bytes: 0,
            config,
            stats,
            outcome: None,
            last_activity: now,
            rate: AssociationRate::default(),
            global_rate,
            global_flows,
            reaped: Vec::new(),
        }
    }

    /// 关联 id（日志关联字段）。
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// 当前 flow 数。
    pub(crate) fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// 是否已写终态。
    pub(crate) fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// 统计快照。
    pub(crate) fn stats(&self) -> Stats {
        self.stats.clone()
    }

    /// 处理一个客户端 UDP 数据报：源校验 → 解码 → 路由 → 投递。
    ///
    /// 成功投递返回 `Ok(())`；被策略丢弃返回 `Err(UdpDropReason)`（已计数）。
    pub(crate) fn handle_client_datagram(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        now: Instant,
    ) -> Result<(), UdpDropReason> {
        if self.outcome.is_some() {
            return Err(UdpDropReason::ControlClosed);
        }
        // §3.3/§6.1：源校验发生在解析之前。
        if source.ip() != self.client_ip {
            return Err(self.record_drop(UdpDropReason::SourceMismatch));
        }
        match self.client_udp_port {
            Some(port) if port != source.port() => {
                return Err(self.record_drop(UdpDropReason::SourceMismatch));
            }
            Some(_) => {}
            None => self.client_udp_port = Some(source.port()),
        }
        self.last_activity = now;

        // 包长在解码/分配前判定。
        if datagram.len() > self.config.max_datagram_bytes {
            return Err(self.record_drop(UdpDropReason::DatagramTooLarge {
                len: datagram.len(),
                limit: self.config.max_datagram_bytes,
            }));
        }
        if !self.rate.allow(
            now,
            self.config.max_pps_per_association,
            self.config.max_bytes_per_second_per_association,
            datagram.len() as u64,
        ) || !self.global_rate.allow(now, self.config.max_pps_global)
        {
            return Err(self.record_drop(UdpDropReason::RateLimited));
        }

        let decoded = match decode_udp_datagram(datagram) {
            Ok(decoded) => decoded,
            Err(_) => return Err(self.record_drop(UdpDropReason::MalformedDatagram)),
        };
        if decoded.fragment != 0 {
            return Err(self.record_drop(UdpDropReason::FragmentUnsupported {
                fragment: decoded.fragment,
            }));
        }

        let target = TargetAddr::from_socks5(&decoded.address);
        let routed = match self.router.route(&target) {
            Ok(routed) => routed,
            Err(reason) => return Err(self.record_drop(reason)),
        };
        let key = FlowKey {
            target: target.clone(),
            outbound_tag: routed.tag.clone(),
        };

        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.config.max_flows_per_association {
                return Err(self.record_drop(UdpDropReason::AssociationFlowLimit {
                    active: self.flows.len(),
                    limit: self.config.max_flows_per_association,
                }));
            }
            let active = self.global_flows.fetch_add(1, Ordering::Relaxed);
            if active >= self.config.max_flows_global {
                self.global_flows.fetch_sub(1, Ordering::Relaxed);
                return Err(self.record_drop(UdpDropReason::GlobalFlowLimit {
                    active,
                    limit: self.config.max_flows_global,
                }));
            }
            let session = match routed.outbound.open_session(&target) {
                Ok(session) => session,
                Err(error) => {
                    self.global_flows.fetch_sub(1, Ordering::Relaxed);
                    let reason = outbound_drop_reason(&error, routed.outbound.kind());
                    return Err(self.record_drop(reason));
                }
            };
            self.flows.insert(
                key.clone(),
                FlowEntry {
                    target: target.clone(),
                    outbound_tag: routed.tag,
                    outbound_kind: routed.outbound.kind(),
                    session,
                    last_seen: now,
                },
            );
            self.stats.flows_opened += 1;
        }

        let sent = match self.flows.get_mut(&key) {
            Some(entry) => {
                entry.last_seen = now;
                entry.session.send(&target, &decoded.payload)
            }
            None => return Err(self.record_drop(UdpDropReason::NoRoute)),
        };
        match sent {
            Ok(()) => {
                self.stats.datagrams_in += 1;
                self.stats.bytes_in += decoded.payload.len() as u64;
                Ok(())
            }
            Err(error) => {
                let kind = self
                    .flows
                    .get(&key)
                    .map_or(OutboundKind::Direct, |entry| entry.outbound_kind);
                let reason = outbound_drop_reason(&error, kind);
                self.evict_flow(&key);
                Err(self.record_drop(reason))
            }
        }
    }

    /// 非阻塞取出所有待回写客户端的 SOCKS5 UDP 数据报（`(address, payload)`）。
    ///
    /// 先收集 session 回包（受队列上限约束），再清空并返回；C4 负责编码 + 发送。
    pub(crate) fn drain_replies(&mut self, now: Instant) -> Vec<(Socks5Address, Vec<u8>)> {
        if self.outcome.is_some() {
            return Vec::new();
        }
        self.collect_replies();
        if self.replies.is_empty() {
            return Vec::new();
        }
        self.last_activity = now;
        self.queued_bytes = 0;
        self.replies.drain(..).collect()
    }

    /// 回收超时 flow、收集回包、判定空闲超时；返回本轮事件。
    pub(crate) fn poll(&mut self, now: Instant) -> Event {
        if self.outcome.is_some() {
            return Event::None;
        }
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, entry)| {
                now.saturating_duration_since(entry.last_seen) >= self.config.flow_timeout
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            if let Some(entry) = self.flows.get(&key) {
                self.reaped.push(ReapedFlow {
                    target: entry.target.clone(),
                    outbound_tag: entry.outbound_tag.clone(),
                    outbound_kind: entry.outbound_kind,
                    idle: now.saturating_duration_since(entry.last_seen),
                });
            }
            self.evict_flow(&key);
            self.stats.flows_reaped += 1;
        }
        self.collect_replies();
        if let Some(idle) = self.config.association_idle_timeout
            && now.saturating_duration_since(self.last_activity) >= idle
        {
            return Event::IdleTimeout;
        }
        Event::None
    }

    /// 取走自上次调用以来被回收的 flow 观测（C4 `flow_reaped` 日志用）。
    pub(crate) fn take_reaped(&mut self) -> Vec<ReapedFlow> {
        std::mem::take(&mut self.reaped)
    }

    /// 主动终止；幂等，只写一次终态（AGENTS §14）。
    pub(crate) fn terminate(&mut self, outcome: Outcome, _now: Instant) {
        if self.outcome.is_some() {
            return;
        }
        let keys: Vec<FlowKey> = self.flows.keys().cloned().collect();
        for key in keys {
            self.evict_flow(&key);
        }
        self.replies.clear();
        self.queued_bytes = 0;
        self.outcome = Some(outcome);
        self.stats.associations_closed += 1;
    }

    /// 从各 session 收集回包到队列；队列满即停止本轮收集（不阻塞、不无限循环）。
    // 需要显式 `loop`：循环体内会 `evict_flow` 修改 flow 表，不能持有 map 借用。
    #[allow(clippy::while_let_loop)]
    fn collect_replies(&mut self) {
        let keys: Vec<FlowKey> = self.flows.keys().cloned().collect();
        for key in keys {
            loop {
                let next = match self.flows.get_mut(&key) {
                    Some(entry) => entry.session.try_recv(),
                    None => break,
                };
                match next {
                    Ok(Some((target, payload))) => {
                        let expected = self.flows.get(&key).map(|entry| &entry.target);
                        if expected != Some(&target) {
                            self.stats.unmatched_replies += 1;
                            continue;
                        }
                        if payload.len() > self.config.max_datagram_bytes {
                            self.stats.dropped_oversize += 1;
                            continue;
                        }
                        if self.replies.len() >= self.config.max_queue_depth
                            || self.queued_bytes.saturating_add(payload.len())
                                > self.config.max_queue_bytes
                        {
                            self.stats.dropped_queue_full += 1;
                            return;
                        }
                        self.queued_bytes += payload.len();
                        self.stats.datagrams_out += 1;
                        self.stats.bytes_out += payload.len() as u64;
                        self.replies.push_back((target.to_socks5(), payload));
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let kind = self
                            .flows
                            .get(&key)
                            .map_or(OutboundKind::Direct, |entry| entry.outbound_kind);
                        let reason = outbound_drop_reason(&error, kind);
                        self.evict_flow(&key);
                        self.record_drop(reason);
                        break;
                    }
                }
            }
        }
    }

    /// 移除 flow、关闭 session、释放全局计数（幂等）。
    fn evict_flow(&mut self, key: &FlowKey) {
        if let Some(mut entry) = self.flows.remove(key) {
            entry.session.close();
            self.global_flows.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// 计数一次丢弃并原样返回原因。
    fn record_drop(&mut self, reason: UdpDropReason) -> UdpDropReason {
        match &reason {
            UdpDropReason::MalformedDatagram => self.stats.dropped_malformed += 1,
            UdpDropReason::FragmentUnsupported { .. } => self.stats.dropped_fragment += 1,
            UdpDropReason::SourceMismatch => self.stats.dropped_source_mismatch += 1,
            UdpDropReason::NoRoute => self.stats.dropped_no_route += 1,
            UdpDropReason::UnsupportedProtocol { kind } => {
                self.stats.dropped_unsupported += 1;
                match kind {
                    OutboundKind::Vless => self.stats.dropped_unsupported_vless += 1,
                    OutboundKind::Anytls => self.stats.dropped_unsupported_anytls += 1,
                    OutboundKind::Trojan => self.stats.dropped_unsupported_trojan += 1,
                    OutboundKind::Shadowsocks => self.stats.dropped_unsupported_shadowsocks += 1,
                    OutboundKind::Hysteria2 => self.stats.dropped_unsupported_hysteria2 += 1,
                    _ => self.stats.dropped_unsupported_other += 1,
                }
            }
            UdpDropReason::DatagramTooLarge { .. } => self.stats.dropped_oversize += 1,
            UdpDropReason::FlowLimit { .. } => self.stats.dropped_flow_limit += 1,
            UdpDropReason::AssociationFlowLimit { .. } => {
                self.stats.dropped_association_flow_limit += 1;
            }
            UdpDropReason::GlobalFlowLimit { .. } => self.stats.dropped_global_flow_limit += 1,
            UdpDropReason::RateLimited => self.stats.dropped_rate_limited += 1,
            UdpDropReason::QueueFull => self.stats.dropped_queue_full += 1,
            UdpDropReason::OutboundClosed { .. } => self.stats.flows_closed += 1,
            UdpDropReason::OutboundIo { .. }
            | UdpDropReason::OutboundTimeout { .. }
            | UdpDropReason::OutboundHandshake { .. } => self.stats.send_failed += 1,
            UdpDropReason::UnmatchedReply => self.stats.unmatched_replies += 1,
            UdpDropReason::ControlClosed => self.stats.control_closed += 1,
        }
        reason
    }
}

/// 出站错误 → 丢弃原因（计数由 `record_drop` 统一处理）。
fn outbound_drop_reason(error: &UdpOutboundError, fallback_kind: OutboundKind) -> UdpDropReason {
    match error {
        UdpOutboundError::Unsupported { kind, .. } => {
            UdpDropReason::UnsupportedProtocol { kind: *kind }
        }
        UdpOutboundError::DatagramTooLarge { len, limit, .. } => UdpDropReason::DatagramTooLarge {
            len: *len,
            limit: *limit,
        },
        UdpOutboundError::Closed { kind } => UdpDropReason::OutboundClosed { kind: *kind },
        UdpOutboundError::Timeout { kind, .. } => UdpDropReason::OutboundTimeout { kind: *kind },
        UdpOutboundError::Tls { kind, .. }
        | UdpOutboundError::Handshake { kind, .. }
        | UdpOutboundError::Config { kind, .. }
        | UdpOutboundError::Connect { kind, .. } => {
            UdpDropReason::OutboundHandshake { kind: *kind }
        }
        UdpOutboundError::Io { kind, .. } => UdpDropReason::OutboundIo { kind: *kind },
        UdpOutboundError::Internal { .. } => UdpDropReason::OutboundHandshake {
            kind: fallback_kind,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    use nexus_ingress::encode_udp_datagram;
    use nexus_proxy_config::{UdpCapability, UdpMode};

    #[derive(Default)]
    struct Script {
        open_error: Option<UdpOutboundError>,
        send_error: Option<UdpOutboundError>,
        replies: VecDeque<(TargetAddr, Vec<u8>)>,
        sent: Vec<(TargetAddr, Vec<u8>)>,
        opens: usize,
        closes: usize,
    }

    struct ScriptedOutbound {
        tag: String,
        kind: OutboundKind,
        script: Arc<Mutex<Script>>,
    }

    impl ScriptedOutbound {
        fn new(tag: &str, kind: OutboundKind) -> (Arc<Self>, Arc<Mutex<Script>>) {
            let script = Arc::new(Mutex::new(Script::default()));
            (
                Arc::new(Self {
                    tag: tag.into(),
                    kind,
                    script: Arc::clone(&script),
                }),
                script,
            )
        }
    }

    impl UdpOutbound for ScriptedOutbound {
        fn kind(&self) -> OutboundKind {
            self.kind
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn capability(&self) -> UdpCapability {
            UdpCapability::Supported(UdpMode::VlessOverTcp {
                server: "127.0.0.1:1".parse().unwrap(),
            })
        }

        fn open_session(
            &self,
            _target: &TargetAddr,
        ) -> Result<Box<dyn UdpSession>, UdpOutboundError> {
            let mut script = self.script.lock().unwrap();
            script.opens += 1;
            if let Some(error) = script.open_error.clone() {
                return Err(error);
            }
            drop(script);
            Ok(Box::new(ScriptedSession {
                script: Arc::clone(&self.script),
            }))
        }
    }

    struct ScriptedSession {
        script: Arc<Mutex<Script>>,
    }

    impl UdpSession for ScriptedSession {
        fn send(&mut self, target: &TargetAddr, payload: &[u8]) -> Result<(), UdpOutboundError> {
            let mut script = self.script.lock().unwrap();
            if let Some(error) = script.send_error.clone() {
                return Err(error);
            }
            script.sent.push((target.clone(), payload.to_vec()));
            Ok(())
        }

        fn try_recv(&mut self) -> Result<Option<(TargetAddr, Vec<u8>)>, UdpOutboundError> {
            Ok(self.script.lock().unwrap().replies.pop_front())
        }

        fn close(&mut self) {
            self.script.lock().unwrap().closes += 1;
        }
    }

    struct FixedRouter {
        tag: String,
        outbound: Arc<dyn UdpOutbound>,
    }

    impl UdpOutboundRouter for FixedRouter {
        fn route(&self, _target: &TargetAddr) -> Result<RoutedOutbound, UdpDropReason> {
            Ok(RoutedOutbound {
                tag: self.tag.clone(),
                outbound: Arc::clone(&self.outbound),
            })
        }
    }

    struct FailingRouter {
        kind: OutboundKind,
    }

    impl UdpOutboundRouter for FailingRouter {
        fn route(&self, _target: &TargetAddr) -> Result<RoutedOutbound, UdpDropReason> {
            Err(UdpDropReason::UnsupportedProtocol { kind: self.kind })
        }
    }

    struct Fixture {
        assoc: UdpAssociation,
        script: Arc<Mutex<Script>>,
        base: Instant,
        global_flows: Arc<AtomicUsize>,
    }

    fn fixture_with(
        config: UdpAssociationConfig,
        global_rate: Arc<GlobalRateLimiter>,
        client_port: Option<u16>,
    ) -> Fixture {
        let (outbound, script) = ScriptedOutbound::new("node", OutboundKind::Vless);
        let base = Instant::now();
        let global_flows = Arc::new(AtomicUsize::new(0));
        let assoc = UdpAssociation::new(
            1,
            "127.0.0.1".parse().unwrap(),
            client_port,
            Arc::new(FixedRouter {
                tag: outbound.tag.clone(),
                outbound,
            }),
            config,
            global_rate,
            Arc::clone(&global_flows),
            base,
        );
        Fixture {
            assoc,
            script,
            base,
            global_flows,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(
            UdpAssociationConfig::default(),
            Arc::new(GlobalRateLimiter::new()),
            None,
        )
    }

    fn source(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn v4(port: u16) -> Socks5Address {
        Socks5Address::Ipv4 {
            addr: [127, 0, 0, 1],
            port,
        }
    }

    fn datagram(address: &Socks5Address, payload: &[u8]) -> Vec<u8> {
        encode_udp_datagram(address, payload).expect("datagram")
    }

    #[test]
    fn flow_reaped_after_60s() {
        let Fixture {
            mut assoc, base, ..
        } = fixture();
        assoc
            .handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base)
            .expect("first datagram");
        assert_eq!(assoc.flow_count(), 1);

        assert_eq!(assoc.poll(base + Duration::from_secs(59)), Event::None);
        assert_eq!(assoc.flow_count(), 1);
        assert_eq!(assoc.stats().flows_reaped, 0);

        assert_eq!(assoc.poll(base + Duration::from_secs(61)), Event::None);
        assert_eq!(assoc.flow_count(), 0);
        assert_eq!(assoc.stats().flows_reaped, 1);
        let reaped = assoc.take_reaped();
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].target, TargetAddr::from_socks5(&v4(53)));
        assert_eq!(reaped[0].outbound_tag, "node");
        assert!(reaped[0].idle >= Duration::from_secs(60));
        assert!(assoc.take_reaped().is_empty(), "观测只取走一次");
    }

    #[test]
    fn association_has_no_idle_timer_by_default() {
        let Fixture {
            mut assoc, base, ..
        } = fixture();
        assoc
            .handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base)
            .expect("first datagram");
        assert_eq!(assoc.poll(base + Duration::from_secs(600)), Event::None);
        assert!(assoc.outcome().is_none());
        // flow 已按 60s 回收，但关联本身不结束。
        assert_eq!(assoc.flow_count(), 0);
    }

    #[test]
    fn association_idle_timeout_300s() {
        let config = UdpAssociationConfig {
            association_idle_timeout: Some(UDP_ASSOCIATION_IDLE_TIMEOUT_OPTION),
            ..UdpAssociationConfig::default()
        };
        let Fixture {
            mut assoc, base, ..
        } = fixture_with(config, Arc::new(GlobalRateLimiter::new()), None);
        assoc
            .handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base)
            .expect("first datagram");
        assert_eq!(assoc.poll(base + Duration::from_secs(299)), Event::None);
        assert_eq!(
            assoc.poll(base + Duration::from_secs(301)),
            Event::IdleTimeout
        );
    }

    #[test]
    fn rate_limit_refills_with_virtual_time() {
        let Fixture {
            mut assoc, base, ..
        } = fixture();
        let packet = datagram(&v4(53), b"x");
        for _ in 0..UDP_MAX_PPS_PER_ASSOCIATION {
            assoc
                .handle_client_datagram(source(1000), &packet, base)
                .expect("within budget");
        }
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &packet, base),
            Err(UdpDropReason::RateLimited)
        );
        assert_eq!(assoc.stats().dropped_rate_limited, 1);
        assert!(
            assoc
                .handle_client_datagram(source(1000), &packet, base + Duration::from_secs(1))
                .is_ok()
        );
    }

    #[test]
    fn global_pps_shared_across_associations() {
        let config = UdpAssociationConfig {
            max_pps_per_association: 100_000,
            max_pps_global: 20_000,
            ..UdpAssociationConfig::default()
        };
        let global_rate = Arc::new(GlobalRateLimiter::new());
        let base = Instant::now();
        let mut first = fixture_with(config.clone(), Arc::clone(&global_rate), None).assoc;
        let mut second = fixture_with(config, Arc::clone(&global_rate), None).assoc;
        let packet = datagram(&v4(53), b"x");
        for _ in 0..10_000 {
            first
                .handle_client_datagram(source(1000), &packet, base)
                .expect("first association budget");
            second
                .handle_client_datagram(source(2000), &packet, base)
                .expect("second association budget");
        }
        assert_eq!(
            first.handle_client_datagram(source(1000), &packet, base),
            Err(UdpDropReason::RateLimited)
        );
    }

    #[test]
    fn source_ip_mismatch_dropped_before_parse() {
        let Fixture {
            mut assoc,
            script,
            base,
            ..
        } = fixture();
        // 非法数据报：若先解析会记 malformed；实际必须先命中源校验。
        assert_eq!(
            assoc.handle_client_datagram(
                "10.0.0.9:1234".parse().unwrap(),
                b"not-a-socks5-datagram",
                base
            ),
            Err(UdpDropReason::SourceMismatch)
        );
        let stats = assoc.stats();
        assert_eq!(stats.dropped_source_mismatch, 1);
        assert_eq!(stats.dropped_malformed, 0);
        assert_eq!(assoc.flow_count(), 0);
        assert!(script.lock().unwrap().sent.is_empty());
    }

    #[test]
    fn first_datagram_locks_port() {
        let Fixture {
            mut assoc, base, ..
        } = fixture();
        let packet = datagram(&v4(53), b"x");
        assoc
            .handle_client_datagram(source(1111), &packet, base)
            .expect("first packet locks port");
        assert_eq!(
            assoc.handle_client_datagram(source(2222), &packet, base),
            Err(UdpDropReason::SourceMismatch)
        );
        assert_eq!(assoc.stats().dropped_source_mismatch, 1);
        assert!(
            assoc
                .handle_client_datagram(source(1111), &packet, base)
                .is_ok()
        );
    }

    #[test]
    fn fragment_nonzero_dropped() {
        let Fixture {
            mut assoc,
            script,
            base,
            ..
        } = fixture();
        let mut packet = datagram(&v4(53), b"x");
        packet[2] = 1;
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &packet, base),
            Err(UdpDropReason::FragmentUnsupported { fragment: 1 })
        );
        assert_eq!(assoc.stats().dropped_fragment, 1);
        assert!(script.lock().unwrap().sent.is_empty());
    }

    #[test]
    fn oversize_dropped_before_allocation() {
        let Fixture {
            mut assoc,
            script,
            base,
            ..
        } = fixture();
        let big = vec![0u8; UDP_MAX_DATAGRAM_BYTES + 1];
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &big, base),
            Err(UdpDropReason::DatagramTooLarge {
                len: UDP_MAX_DATAGRAM_BYTES + 1,
                limit: UDP_MAX_DATAGRAM_BYTES,
            })
        );
        assert_eq!(assoc.stats().dropped_oversize, 1);
        assert_eq!(assoc.flow_count(), 0);
        assert!(script.lock().unwrap().sent.is_empty());
    }

    #[test]
    fn flow_limit_drops_new_without_evicting() {
        let config = UdpAssociationConfig {
            max_flows_per_association: 64,
            ..UdpAssociationConfig::default()
        };
        let Fixture {
            mut assoc,
            script,
            base,
            ..
        } = fixture_with(config, Arc::new(GlobalRateLimiter::new()), None);
        for port in 1..=64 {
            assoc
                .handle_client_datagram(source(1000), &datagram(&v4(port), b"x"), base)
                .expect("within flow limit");
        }
        assert_eq!(assoc.flow_count(), 64);
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &datagram(&v4(65), b"x"), base),
            Err(UdpDropReason::AssociationFlowLimit {
                active: 64,
                limit: 64,
            })
        );
        // 前 64 个仍可用。
        assert!(
            assoc
                .handle_client_datagram(source(1000), &datagram(&v4(1), b"y"), base)
                .is_ok()
        );
        assert_eq!(assoc.flow_count(), 64);
        assert_eq!(script.lock().unwrap().opens, 64);
    }

    #[test]
    fn queue_full_drops_new() {
        let Fixture {
            mut assoc,
            script,
            base,
            ..
        } = fixture();
        assoc
            .handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base)
            .expect("flow opened");
        {
            let mut script = script.lock().unwrap();
            for _ in 0..300 {
                script
                    .replies
                    .push_back((TargetAddr::from_socks5(&v4(53)), vec![7u8]));
            }
        }
        assert_eq!(assoc.poll(base), Event::None);
        assert_eq!(assoc.stats().dropped_queue_full, 1);
        let drained = assoc.drain_replies(base);
        assert_eq!(drained.len(), UDP_REPLY_QUEUE_DEPTH);
        assert_eq!(drained[0].0, v4(53));
    }

    #[test]
    fn control_close_terminates_association() {
        let Fixture {
            mut assoc,
            script,
            base,
            global_flows,
            ..
        } = fixture();
        assoc
            .handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base)
            .expect("flow opened");
        assert_eq!(global_flows.load(Ordering::Relaxed), 1);

        assoc.terminate(Outcome::Completed, base);
        assert_eq!(assoc.outcome(), Some(&Outcome::Completed));
        assert_eq!(assoc.flow_count(), 0);
        assert_eq!(global_flows.load(Ordering::Relaxed), 0);
        assert_eq!(assoc.stats().associations_closed, 1);
        assert_eq!(script.lock().unwrap().closes, 1);

        // 幂等：第二次不覆盖终态、不重复计数/关闭。
        assoc.terminate(Outcome::Cancelled, base);
        assert_eq!(assoc.outcome(), Some(&Outcome::Completed));
        assert_eq!(assoc.stats().associations_closed, 1);
        assert_eq!(script.lock().unwrap().closes, 1);

        // 终止后不再处理数据报（也不投递）。
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base),
            Err(UdpDropReason::ControlClosed)
        );
        assert_eq!(script.lock().unwrap().sent.len(), 1);
    }

    #[test]
    fn outbound_failure_removes_flow_not_association() {
        let Fixture {
            mut assoc,
            script,
            base,
            global_flows,
            ..
        } = fixture();
        script.lock().unwrap().send_error = Some(UdpOutboundError::Io {
            kind: OutboundKind::Vless,
            io: std::io::ErrorKind::ConnectionReset,
        });
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &datagram(&v4(53), b"x"), base),
            Err(UdpDropReason::OutboundIo {
                kind: OutboundKind::Vless
            })
        );
        assert_eq!(assoc.flow_count(), 0);
        assert_eq!(global_flows.load(Ordering::Relaxed), 0);
        assert!(assoc.outcome().is_none());
        assert_eq!(assoc.stats().send_failed, 1);

        // 关联继续：清掉失败后同一目标可重新开 flow。
        script.lock().unwrap().send_error = None;
        assert!(
            assoc
                .handle_client_datagram(source(1000), &datagram(&v4(53), b"x"), base)
                .is_ok()
        );
        assert_eq!(assoc.flow_count(), 1);
        assert_eq!(script.lock().unwrap().opens, 2);
    }

    #[test]
    fn unmatched_reply_dropped() {
        let Fixture {
            mut assoc,
            script,
            base,
            ..
        } = fixture();
        assoc
            .handle_client_datagram(source(1000), &datagram(&v4(53), b"q"), base)
            .expect("flow opened");
        script
            .lock()
            .unwrap()
            .replies
            .push_back((TargetAddr::from_socks5(&v4(9999)), vec![1u8]));
        assert!(assoc.drain_replies(base).is_empty());
        assert_eq!(assoc.stats().unmatched_replies, 1);
    }

    #[test]
    fn fail_closed_no_direct() {
        let base = Instant::now();
        let mut assoc = UdpAssociation::new(
            1,
            "127.0.0.1".parse().unwrap(),
            None,
            Arc::new(FailingRouter {
                kind: OutboundKind::Vless,
            }),
            UdpAssociationConfig::default(),
            Arc::new(GlobalRateLimiter::new()),
            Arc::new(AtomicUsize::new(0)),
            base,
        );
        assert_eq!(
            assoc.handle_client_datagram(source(1000), &datagram(&v4(53), b"x"), base),
            Err(UdpDropReason::UnsupportedProtocol {
                kind: OutboundKind::Vless
            })
        );
        let stats = assoc.stats();
        assert_eq!(stats.dropped_unsupported, 1);
        assert_eq!(stats.dropped_unsupported_vless, 1);
        assert_eq!(stats.datagrams_in, 0);
        assert_eq!(assoc.flow_count(), 0);
    }
}
