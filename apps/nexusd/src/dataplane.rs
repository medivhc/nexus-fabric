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

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};

use nexus_connectivity::cake::{CakeConfig, CakeScheduler, EnqueueDecision, FiveTuple};
use nexus_dns::{DnsQuery, DnsType, DnsUnifiedConfig, UnifiedDns};
use nexus_network::n1::bridge::N1Sender;
use nexus_path::{CandidatePath, PathConfig, PathManager};
use nexus_projection::TunDevice;
use nexus_projection::classifier::{Classification, PacketClassifier};
use nexus_projection::routing::Cidr;

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
    stats: Arc<Mutex<DataplaneStats>>,
    config: DataplaneConfig,
    buf: Vec<u8>,
    /// QoS 时钟起点（单调；避免 Duration::ZERO 冻结导致队列永不满溢回收）。
    qos_start: std::time::Instant,
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
            stats: Arc::new(Mutex::new(DataplaneStats::default())),
            config,
            buf: vec![0u8; 65535],
            qos_start: std::time::Instant::now(),
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
    /// 管线：读 TUN → DNS 短路（UDP dport 53）→ 分类 → QoS → 计数转发。
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

        // D4：QoS 整形（启用时）。
        // 使用单调时钟（非冻结），避免队列永不回收。
        let now = self.qos_start.elapsed();
        if let Some(qos) = &mut self.qos {
            if let Some(tuple) = five_tuple_of(&packet) {
                let decision = qos.enqueue(&tuple, packet.len() as u64, now);
                if !matches!(decision, EnqueueDecision::Admitted { .. }) {
                    self.with_stats(|s| s.qos_dropped += 1);
                    return Ok(true);
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
                        if forwarded {
                            self.with_stats(|s| s.proxy_forwarded += 1);
                        } else {
                            self.with_stats(|s| s.proxy_dropped_no_proxy += 1);
                        }
                    }
                    None if self.config.proxy_configured => {
                        // 兼容：已配置但 engine 未注入（旧计数行为）。
                        self.with_stats(|s| s.proxy_forwarded += 1);
                    }
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

struct StubUpstreamResolver;
impl nexus_dns::Resolver for StubUpstreamResolver {
    fn resolve(&mut self, _query: &DnsQuery) -> Result<Vec<IpAddr>, nexus_dns::DnsError> {
        Err(nexus_dns::DnsError::ResolutionFailed(
            "stub upstream not configured".to_string(),
        ))
    }
}

// ===== 全局 stats 句柄结束 =====
