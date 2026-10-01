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
use std::sync::{Arc, Mutex, OnceLock};

use nexus_connectivity::cake::{CakeConfig, CakeScheduler, EnqueueDecision, FiveTuple};
use nexus_dns::{DnsQuery, DnsType, DnsUnifiedConfig, UnifiedDns};
use nexus_network::n1::bridge::N1Sender;
use nexus_path::{CandidatePath, PathConfig, PathManager};
use nexus_projection::TunDevice;
use nexus_projection::classifier::{Classification, PacketClassifier};
use nexus_projection::routing::Cidr;
use nexus_projection::tcp::{
    STREAM_FIN, STREAM_RST, STREAM_SYN, TcpEvent, TcpTermStats, TcpTerminator, decode_stream_frame,
    encode_stream_frame, encode_syn_payload,
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
#[derive(Debug, Clone, Default)]
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
}

/// 统一数据面：单个 TUN 的完整处理管线。
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
        })
    }

    /// 注入 N1 发送器（W1/W3；由 Composition Root 在 N1 就绪后调用）。
    pub fn set_n1_sender(&mut self, sender: std::sync::Arc<dyn N1Sender>) {
        self.n1_sender = Some(sender);
    }

    /// 注入 Proxy 转发引擎（P1-P5；由 Composition Root 在 proxy.yaml 解析后调用）。
    pub fn set_proxy_engine(&mut self, engine: crate::proxy_fwd::ProxyEngine) {
        self.proxy_engine = Some(engine);
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
    pub fn process_one(&mut self) -> io::Result<bool> {
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
        let candidates: &[CandidatePath] = if self.config.boost_enabled {
            &self.candidates
        } else {
            &[]
        };
        let classifier = PacketClassifier::new(
            self.mesh_cidrs.clone(),
            self.bypass_cidrs.clone(),
            &self.manager,
            candidates,
            0.0, // degrade_threshold：MVP 用 0（不触发 degraded）
        );
        let classification = classifier.classify(&packet);

        // S1：TCP + Mesh/Proxy → smoltcp 终结（不再走 raw-datagram 路径）。
        if is_tcp_packet(&packet)
            && matches!(
                classification,
                Classification::Mesh { .. } | Classification::Proxy
            )
        {
            if !self.qos_admit(&packet) {
                return Ok(true);
            }
            self.handle_tcp_terminated(&packet, &classification);
            self.dispatch_tcp_events();
            return Ok(true);
        }

        // D4：QoS 整形（启用时）。
        if !self.qos_admit(&packet) {
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
            Classification::Proxy => {
                // P1-P5：engine 已注入 → 真实转发；否则走 D2 计数路径。
                // 先取出 engine 处理结果（避免 borrow 冲突）。
                let engine_outcome: Option<(Vec<Vec<u8>>, bool)> =
                    self.proxy_engine.as_mut().map(|e| e.handle_packet(&packet));
                match engine_outcome {
                    Some((tun_pkts, forwarded)) => {
                        for pkt in tun_pkts {
                            if self.tun.write(&pkt).is_ok() {
                                self.with_stats(|s| s.tun_written += 1);
                            } else {
                                self.with_stats(|s| s.dropped += 1);
                            }
                        }
                        // 驱动 engine（回包/重传/事件）。
                        let more: Vec<Vec<u8>> =
                            self.proxy_engine.as_mut().map(|e| e.poll()).unwrap_or_default();
                        for pkt in more {
                            if self.tun.write(&pkt).is_ok() {
                                self.with_stats(|s| s.tun_written += 1);
                            } else {
                                self.with_stats(|s| s.dropped += 1);
                            }
                        }
                        // P1：proxy_forwarded 仅在真实转发发生时计数。
                        // - UDP：handle_packet 返回真实发送结果 → 按包计数。
                        // - TCP：dial 异步，转发尚未确认；计数由下方
                        //   engine.stats() 的 tcp_dials_ok/failed 增量驱动，
                        //   此处不按包计数。
                        if packet.get(9) == Some(&17) {
                            if forwarded {
                                self.with_stats(|s| s.proxy_forwarded += 1);
                            } else {
                                self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
                            }
                        }
                        // P1：同步 TCP dial 结果增量（dial 成功 → proxy_forwarded；
                        // dial 失败 → proxy_dropped_no_proxy）。
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
                    // P3：engine 未注入（无可用出站或未配置）→
                    // proxy_dropped_no_proxy。旧"兼容"分支（计 proxy_forwarded）
                    // 已删除：那是契约废除的纯分类计数。
                    None => {
                        self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
                    }
                }
            }
            Classification::Direct => {
                self.with_stats(|s| s.direct_forwarded += 1);
            }
            Classification::Drop => {
                self.with_stats(|s| s.dropped += 1);
            }
        }
        Ok(true)
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
    fn handle_tcp_terminated(&mut self, packet: &[u8], classification: &Classification) {
        let peer = match classification {
            Classification::Mesh { path: Some(p), .. } => p.to_string(),
            Classification::Mesh { path: None, .. } => ipv4_dst_of(packet)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            Classification::Proxy => "proxy".to_string(),
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
                } => match self.tcp_streams.get(&stream_id).copied() {
                    Some(info) if !info.proxy => {
                        // S5-Mesh：STREAM DATA 帧经 N1 发送。
                        let frame = encode_stream_frame(stream_id, 0x00, &bytes);
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
                },
                TcpEvent::Closed {
                    stream_id,
                    peer: _,
                    reset,
                } => {
                    let info = self.tcp_streams.remove(&stream_id);
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
        // 8.8.8.8：不在 mesh CIDR、不在 bypass → Proxy（MVP 回落）。
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

        // SYN → SYN-ACK（终结仍发生，S1）。
        let syn = craft_tcp([10, 0, 0, 2], [8, 8, 8, 8], 40001, 443, 2000, 0, 0x02, &[]);
        mock.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("syn"));
        let written = mock.lock().unwrap().take_written();
        assert_eq!(written.len(), 1, "S1: proxy TCP also terminated");
        let srv_seq = syn_ack_srv_seq(&written[0]);

        // ACK → 握手完成 → 只计数，不经 N1。
        let ack = craft_tcp(
            [10, 0, 0, 2],
            [8, 8, 8, 8],
            40001,
            443,
            2001,
            srv_seq + 1,
            0x10,
            &[],
        );
        mock.lock().unwrap().inject(ack);
        assert!(dp.process_one().expect("ack"));
        assert_eq!(dp.stats().proxy_tcp_streams, 1, "S4-Proxy: counted");
        assert!(
            frames.lock().unwrap().is_empty(),
            "S4-Proxy: no N1 frames (GAP-1)"
        );

        // DATA → proxy_tcp_bytes 计数。
        let data = craft_tcp(
            [10, 0, 0, 2],
            [8, 8, 8, 8],
            40001,
            443,
            2001,
            srv_seq + 1,
            0x18,
            b"world!",
        );
        mock.lock().unwrap().inject(data);
        assert!(dp.process_one().expect("data"));
        assert_eq!(dp.stats().proxy_tcp_bytes, 6, "S5-Proxy: 6 bytes counted");
        assert_eq!(dp.stats().mesh_tcp_frames, 0, "no mesh frames");
    }

    /// S8：Direct 分类的 TCP 永不进终结器（零回归）。
    #[test]
    fn tcp_direct_untouched() {
        // 192.168.1.1 需 bypass 配置 → Direct。
        let mock2 = Arc::new(Mutex::new(nexus_projection::MockTun::new("test0")));
        let tun = Box::new(SharedTun {
            inner: Arc::clone(&mock2),
        });
        let config = DataplaneConfig {
            mesh_cidrs: vec!["10.200.0.0/24".to_string()],
            bypass_cidrs: vec!["192.168.0.0/16".to_string()],
            ..Default::default()
        };
        let mut dp = Dataplane::new(tun, config).expect("dataplane new");
        let syn = craft_tcp(
            [192, 168, 1, 2],
            [192, 168, 1, 1],
            40002,
            80,
            3000,
            0,
            0x02,
            &[],
        );
        mock2.lock().unwrap().inject(syn);
        assert!(dp.process_one().expect("process_one"));
        assert_eq!(dp.stats().direct_forwarded, 1, "S8: direct counted");
        assert_eq!(dp.stats().tcp_handshakes, 0, "S8: not terminated");
        assert!(
            mock2.lock().unwrap().take_written().is_empty(),
            "S8: no TUN write"
        );
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
}
