//! CAKE-like QoS 调度器（DRR 公平队列 + 严格优先级 + 令牌桶整形，内存确定性）。
//!
//! 本模块是 delivery 层共享底座的用户态包调度器（MVP）：
//! - **流识别**：`FiveTuple`（5 元组）→ `FlowId`（同进程内确定性哈希，不持久化）；
//! - **优先级**：`Priority::{High, Medium, Low}`，类间严格优先级（High 排空前不看
//!   Medium/Low），类内 DRR；新流按端口/协议规则定级（ICMP 恒 High，命中
//!   `high_priority_ports` → High，命中 `low_priority_ports` → Low，否则 Medium）；
//! - **DRR**：每流 `deficit` 计数器；每次访问 `deficit += quantum`，队首包
//!   `len <= deficit` 则发送并 `deficit -= len`；单包大于 quantum 时 deficit
//!   跨轮累积直到能发（保证大包最终能走，不饿死）；
//! - **整形**：复用 `qos::TokenBucket` 做 per-egress 速率门控；令牌不足时**不**出队、
//!   **不**扣 deficit、**不**跳过找小包，直接返回 `None`（调用方稍后重试）；
//! - **流回收**：`reap(now)` 回收 `now - last_seen >= flow_timeout` 的流（默认 60s）；
//! - **时钟**：调用方显式传入 `now: Duration`（`QosClock` 体系），单测用假时钟；
//! - **背压**：单流队列上限 `max_queue_packets`（默认 64），满则丢弃并计数
//!   （TCP 发送端自适应降速）；超 `max_packet_bytes` 的包整包丢弃。
//!
//! 边界（`scenarios/product/qos_cake.toml` 冻结，见 MODULE.md）：
//! - 纯内存、纯同步；不接真实 socket / TUN / 内核 tc（TUN 接入点见下）；
//! - 调度器只处理 `(FlowId, 字节数)`，包缓冲所有权在调用方：调用方把包映射为
//!   `(FiveTuple, bytes)` 入队，出队后按 `(FlowId, bytes)` 取回自己的包缓冲；
//! - 不做多路径；`qos.rs` 的令牌桶冻结契约不动（本模块复用）；
//! - 无 `unsafe`；库代码不 panic/unwrap/expect（`new` 失败走 `Result`）。
//!
//! # TUN 接入点（未来，非本 MVP 范围）
//!
//! ```text
//! TUN 读包 → 解析 IP 头得 FiveTuple → cake.enqueue(&tuple, ip_len, now)
//!                                                ↓
//! 定时/事件驱动：while let Some((flow, len)) = cake.dequeue(now) { write_to_egress(flow, len) }
//! 定时：cake.reap(now)（如每 10s 一次）
//! ```

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::Duration;

use super::qos::{BandwidthLimit, QosError, TokenBucket};

// ---------- 常量 ----------

/// TCP 协议号。
pub const PROTO_TCP: u8 = 6;
/// UDP 协议号。
pub const PROTO_UDP: u8 = 17;
/// ICMP 协议号（恒为高优先级）。
pub const PROTO_ICMP: u8 = 1;

/// `quantum` 下限（字节）：过小会导致大包需要过多累积轮次。
pub(crate) const MIN_QUANTUM: u32 = 64;
/// `quantum` 上限（字节）。
pub(crate) const MAX_QUANTUM: u32 = 65536;
/// `max_packet_bytes` 上限（16MB）：控制 DRR 累积轮次上界与 deficit 范围。
pub(crate) const MAX_PACKET_BYTES_LIMIT: u64 = 16 * 1024 * 1024;

// ---------- 五元组 / 流 / 优先级 ----------

/// 包五元组（流识别键）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// 源 IP（v4/v6 均可）。
    pub src_ip: IpAddr,
    /// 目的 IP。
    pub dst_ip: IpAddr,
    /// 源端口（ICMP 等无端口协议填 0）。
    pub src_port: u16,
    /// 目的端口。
    pub dst_port: u16,
    /// IP 协议号（6=TCP / 17=UDP / 1=ICMP）。
    pub proto: u8,
}

/// 流 ID：五元组的同进程内确定性哈希（`DefaultHasher`，不持久化、不跨进程比较）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(pub u64);

impl FiveTuple {
    /// 计算流 ID。
    #[must_use]
    pub fn flow_id(&self) -> FlowId {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        FlowId(h.finish())
    }
}

/// 优先级：类间严格优先级。`Ord` 为 High < Medium < Low（值越小越优先）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// 高：SSH/DNS/ICMP/游戏等（端口/协议规则，可配置）。
    High,
    /// 中：默认（网页、API）。
    Medium,
    /// 低：下载、备份等（端口规则，可配置）。
    Low,
}

impl Priority {
    /// 在统计数组 / active 队列数组中的下标（High=0, Medium=1, Low=2）。
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

// ---------- 配置 ----------

/// CAKE 调度器配置。
#[derive(Debug, Clone)]
pub struct CakeConfig {
    /// DRR quantum（字节），默认 1514。
    pub quantum: u32,
    /// 流空闲回收超时，默认 60s。
    pub flow_timeout: Duration,
    /// 单流队列上限（包数），默认 64；满则丢弃（背压）。
    pub max_queue_packets: usize,
    /// 单包字节上限，默认 65535；超限整包丢弃。
    pub max_packet_bytes: u64,
    /// 高优先级端口（源/目的任一命中即 High），默认 `[22, 53, 3389]`。
    pub high_priority_ports: Vec<u16>,
    /// 低优先级端口（源/目的任一命中即 Low），默认空。
    pub low_priority_ports: Vec<u16>,
    /// per-egress 整形（令牌桶）；`None` = 不整形。
    pub rate_limit: Option<BandwidthLimit>,
}

impl Default for CakeConfig {
    fn default() -> Self {
        Self {
            quantum: 1514,
            flow_timeout: Duration::from_secs(60),
            max_queue_packets: 64,
            max_packet_bytes: 65535,
            high_priority_ports: vec![22, 53, 3389],
            low_priority_ports: Vec::new(),
            rate_limit: None,
        }
    }
}

impl CakeConfig {
    /// 校验配置合法性；非法返回 `QosError::InvalidLimit`（复用冻结错误面，
    /// message 说明具体原因，不新增错误变体）。
    pub fn validate(&self) -> Result<(), QosError> {
        if !(MIN_QUANTUM..=MAX_QUANTUM).contains(&self.quantum) {
            return Err(QosError::InvalidLimit {
                message: format!(
                    "quantum must be in [{MIN_QUANTUM}, {MAX_QUANTUM}] (got {})",
                    self.quantum
                ),
            });
        }
        if self.flow_timeout.is_zero() {
            return Err(QosError::InvalidLimit {
                message: "flow_timeout must be > 0".to_string(),
            });
        }
        if self.max_queue_packets == 0 {
            return Err(QosError::InvalidLimit {
                message: "max_queue_packets must be >= 1".to_string(),
            });
        }
        if self.max_packet_bytes == 0 || self.max_packet_bytes > MAX_PACKET_BYTES_LIMIT {
            return Err(QosError::InvalidLimit {
                message: format!(
                    "max_packet_bytes must be in [1, {MAX_PACKET_BYTES_LIMIT}] (got {})",
                    self.max_packet_bytes
                ),
            });
        }
        for p in &self.high_priority_ports {
            if self.low_priority_ports.contains(p) {
                return Err(QosError::InvalidLimit {
                    message: format!("port {p} is in both high and low priority lists"),
                });
            }
        }
        Ok(())
    }
}

// ---------- 入队结果 / 统计 ----------

/// 入队结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueDecision {
    /// 已入队（返回流 ID 与定级）。
    Admitted {
        /// 流 ID。
        flow: FlowId,
        /// 该流优先级（流创建时按规则确定，生命周期内不变）。
        priority: Priority,
    },
    /// 丢弃：该流队列已满（背压，计入 `packets_dropped`）。
    DroppedQueueFull,
    /// 丢弃：单包超过 `max_packet_bytes`（计入 `packets_dropped`）。
    DroppedOversize,
}

/// 调度器统计快照（纯计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CakeStats {
    /// 累计入队包数。
    pub packets_enqueued: u64,
    /// 累计出队包数。
    pub packets_dequeued: u64,
    /// 累计丢弃包数（队列满 + 超限 + 回收时残包）。
    pub packets_dropped: u64,
    /// 累计出队字节数。
    pub bytes_dequeued: u64,
    /// 按优先级累计出队字节（下标 High=0, Medium=1, Low=2）。
    pub per_priority_dequeued: [u64; 3],
    /// 当前流表流数。
    pub flows_current: usize,
    /// 累计回收流数。
    pub flows_reaped: u64,
}

// ---------- 流状态（内部） ----------

/// 单流状态。
struct FlowState {
    /// 待发包队列（MVP 只存字节数；包缓冲所有权在调用方）。
    queue: VecDeque<u64>,
    /// DRR deficit 计数器。
    deficit: i64,
    /// 最后入队时间（回收依据）。
    last_seen: Duration,
    /// 流优先级（创建时确定）。
    priority: Priority,
}

impl FlowState {
    fn new(priority: Priority, now: Duration) -> Self {
        Self {
            queue: VecDeque::new(),
            deficit: 0,
            last_seen: now,
            priority,
        }
    }
}

// ---------- 调度器 ----------

/// CAKE-like 调度器：per-flow DRR + 三级严格优先级 + per-egress 令牌桶整形。
///
/// 一个实例对应一个 egress（mesh / proxy 各一实例，互不抢带宽）。
/// 纯内存、纯同步；时钟由调用方显式传入。
pub struct CakeScheduler {
    config: CakeConfig,
    flows: HashMap<FlowId, FlowState>,
    /// 各优先级 active 流队列（有 backlog 的流，轮询顺序）。
    active: [VecDeque<FlowId>; 3],
    /// 整形令牌桶（`None` = 不整形）。
    shaper: Option<TokenBucket>,
    packets_enqueued: u64,
    packets_dequeued: u64,
    packets_dropped: u64,
    bytes_dequeued: u64,
    per_priority_dequeued: [u64; 3],
    flows_reaped: u64,
}

impl CakeScheduler {
    /// 用配置构造调度器；配置非法返回 `QosError::InvalidLimit`。
    pub fn new(config: &CakeConfig) -> Result<Self, QosError> {
        config.validate()?;
        Ok(Self {
            config: config.clone(),
            flows: HashMap::new(),
            active: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            shaper: config.rate_limit.as_ref().map(TokenBucket::new),
            packets_enqueued: 0,
            packets_dequeued: 0,
            packets_dropped: 0,
            bytes_dequeued: 0,
            per_priority_dequeued: [0; 3],
            flows_reaped: 0,
        })
    }

    /// 按端口/协议规则为五元组定级（新流创建时调用）。
    ///
    /// 关联函数（取 `&CakeConfig` 而非 `&self`），以便在 `self.flows` 可变借用
    /// 的同时调用，无借用冲突。
    fn classify(config: &CakeConfig, tuple: &FiveTuple) -> Priority {
        if tuple.proto == PROTO_ICMP {
            return Priority::High;
        }
        if config.high_priority_ports.contains(&tuple.src_port)
            || config.high_priority_ports.contains(&tuple.dst_port)
        {
            return Priority::High;
        }
        if config.low_priority_ports.contains(&tuple.src_port)
            || config.low_priority_ports.contains(&tuple.dst_port)
        {
            return Priority::Low;
        }
        Priority::Medium
    }

    /// 入队一个包（`bytes` 为包字节数；包缓冲所有权在调用方）。
    ///
    /// 新流按规则定级并加入对应优先级 active 队列；`now` 更新流 `last_seen`。
    pub fn enqueue(&mut self, tuple: &FiveTuple, bytes: u64, now: Duration) -> EnqueueDecision {
        if bytes > self.config.max_packet_bytes {
            self.packets_dropped += 1;
            return EnqueueDecision::DroppedOversize;
        }
        let fid = tuple.flow_id();
        // 新流按规则定级：先读后写，无借用冲突（classify 只读 config）。
        let priority = match self.flows.get(&fid) {
            Some(flow) => flow.priority,
            None => Self::classify(&self.config, tuple),
        };
        let flow = self
            .flows
            .entry(fid)
            .or_insert_with(|| FlowState::new(priority, now));
        flow.last_seen = now;
        let max_q = self.config.max_queue_packets;
        if flow.queue.len() >= max_q {
            self.packets_dropped += 1;
            return EnqueueDecision::DroppedQueueFull;
        }
        let was_empty = flow.queue.is_empty();
        flow.queue.push_back(bytes);
        self.packets_enqueued += 1;
        if was_empty {
            self.active[priority.index()].push_back(fid);
        }
        EnqueueDecision::Admitted {
            flow: fid,
            priority,
        }
    }

    /// 整形门控：令牌够则扣减返回 `true`，不够返回 `false`（不阻塞）。
    fn try_shape(&mut self, bytes: u64, now: Duration) -> bool {
        match self.shaper.as_mut() {
            Some(bucket) => bucket.try_consume(bytes, now),
            None => true,
        }
    }

    /// 出队一包，返回 `(流ID, 字节数)`。
    ///
    /// - 类间严格优先级：High 类有 active 流时不看 Medium/Low；
    /// - 类内 DRR：每流每轮 `deficit += quantum`，队首 `len <= deficit` 则发送；
    ///   单包大于 quantum 时 deficit 跨轮累积（本函数内多轮直到发出或被整形阻塞）；
    /// - 整形阻塞时：不扣 deficit、不跳过找小包，直接返回 `None`；
    /// - 返回 `None` 当且仅当全部 active 为空或整形令牌不足。
    pub fn dequeue(&mut self, now: Duration) -> Option<(FlowId, u64)> {
        for prio in [Priority::High, Priority::Medium, Priority::Low] {
            let pi = prio.index();
            if self.active[pi].is_empty() {
                continue;
            }
            // 类内 DRR 多轮：deficit 持续累积直到某流队首可发。
            // 终止性：每轮每流 deficit += quantum（>0），队首 len <= max_packet_bytes
            // 有界，故有限轮后必有流可发（除非整形阻塞，此时直接返回）。
            loop {
                let n = self.active[pi].len();
                if n == 0 {
                    break; // 本类已排空（防御性；正常应在发送时返回）
                }
                let mut shaped_block = false;
                let mut sent: Option<(FlowId, u64)> = None;
                for _ in 0..n {
                    let Some(fid) = self.active[pi].pop_front() else {
                        break; // 防御性：计数内正常不应为空
                    };
                    // 步骤 1：累积 deficit 并读取队首（借用在此作用域结束）。
                    // active 与流表不一致时跳过该条目（自愈，不 panic）。
                    enum Step {
                        Send(u64),
                        Wait,
                        Gone,
                    }
                    let step = {
                        let Some(flow) = self.flows.get_mut(&fid) else {
                            continue;
                        };
                        flow.deficit += self.config.quantum as i64;
                        match flow.queue.front().copied() {
                            Some(len) if flow.deficit >= 0 && (flow.deficit as u64) >= len => {
                                Step::Send(len)
                            }
                            Some(_) => Step::Wait,
                            None => Step::Gone,
                        }
                    };
                    match step {
                        Step::Send(len) => {
                            // 步骤 2：整形门控。
                            if !self.try_shape(len, now) {
                                // 令牌不足：回滚本轮 deficit，流放回队首，直接返回。
                                if let Some(flow) = self.flows.get_mut(&fid) {
                                    flow.deficit -= self.config.quantum as i64;
                                }
                                self.active[pi].push_front(fid);
                                shaped_block = true;
                                break;
                            }
                            // 步骤 3：出队。
                            let still_backlogged = match self.flows.get_mut(&fid) {
                                Some(flow) => {
                                    flow.queue.pop_front();
                                    flow.deficit -= len as i64;
                                    !flow.queue.is_empty()
                                }
                                // 防御性：流已消失则视为排空
                                None => false,
                            };
                            if still_backlogged {
                                self.active[pi].push_back(fid);
                            }
                            self.packets_dequeued += 1;
                            self.bytes_dequeued += len;
                            self.per_priority_dequeued[pi] += len;
                            sent = Some((fid, len));
                            break;
                        }
                        Step::Wait => {
                            // deficit 不够：流保持 active，下一轮继续累积。
                            self.active[pi].push_back(fid);
                        }
                        Step::Gone => {
                            // active 流队列为空：防御性移除（正常不应发生）。
                        }
                    }
                }
                if let Some(out) = sent {
                    return Some(out);
                }
                if shaped_block {
                    return None;
                }
                // 完整一轮无人可发：deficit 已增长，继续下一轮。
            }
        }
        None
    }

    /// 回收 `now - last_seen >= flow_timeout` 的流；队内残包计入 dropped。
    /// 返回回收的流数。
    pub fn reap(&mut self, now: Duration) -> usize {
        let timeout = self.config.flow_timeout;
        let ids: Vec<FlowId> = self
            .flows
            .iter()
            .filter(|(_, f)| now.saturating_sub(f.last_seen) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        let mut reaped = 0;
        for fid in ids {
            if let Some(flow) = self.flows.remove(&fid) {
                self.packets_dropped += flow.queue.len() as u64;
                reaped += 1;
            }
        }
        if reaped > 0 {
            for q in self.active.iter_mut() {
                q.retain(|fid| self.flows.contains_key(fid));
            }
        }
        self.flows_reaped += reaped as u64;
        reaped
    }

    /// 当前流表流数。
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// 统计快照。
    #[must_use]
    pub fn snapshot(&self) -> CakeStats {
        CakeStats {
            packets_enqueued: self.packets_enqueued,
            packets_dequeued: self.packets_dequeued,
            packets_dropped: self.packets_dropped,
            bytes_dequeued: self.bytes_dequeued,
            per_priority_dequeued: self.per_priority_dequeued,
            flows_current: self.flows.len(),
            flows_reaped: self.flows_reaped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tcp_tuple(src_port: u16, dst_port: u16) -> FiveTuple {
        FiveTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            proto: PROTO_TCP,
        }
    }

    fn udp_tuple(src_port: u16, dst_port: u16) -> FiveTuple {
        FiveTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            proto: PROTO_UDP,
        }
    }

    #[test]
    fn config_validation_rejects_bad_values() {
        // quantum 越界。
        assert!(
            CakeConfig {
                quantum: MIN_QUANTUM - 1,
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CakeConfig {
                quantum: MAX_QUANTUM + 1,
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );
        // flow_timeout 为零。
        assert!(
            CakeConfig {
                flow_timeout: Duration::ZERO,
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );
        // max_queue_packets 为零。
        assert!(
            CakeConfig {
                max_queue_packets: 0,
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );
        // max_packet_bytes 越界。
        assert!(
            CakeConfig {
                max_packet_bytes: 0,
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CakeConfig {
                max_packet_bytes: MAX_PACKET_BYTES_LIMIT + 1,
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );
        // 同一端口不能又在 high 又在 low。
        assert!(
            CakeConfig {
                low_priority_ports: vec![22],
                ..CakeConfig::default()
            }
            .validate()
            .is_err()
        );

        // 默认配置合法；非法配置下 new 失败。
        assert!(CakeConfig::default().validate().is_ok());
        let bad = CakeConfig {
            quantum: 1,
            ..CakeConfig::default()
        };
        assert!(CakeScheduler::new(&bad).is_err());
    }

    #[test]
    fn same_five_tuple_maps_to_same_flow() {
        let a = tcp_tuple(1000, 2000);
        let b = tcp_tuple(1000, 2000);
        let c = tcp_tuple(1000, 2001);
        assert_eq!(a.flow_id(), b.flow_id());
        assert_ne!(a.flow_id(), c.flow_id());
    }

    #[test]
    fn icmp_is_always_high_priority() {
        let cfg = CakeConfig::default();
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t = FiveTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 0,
            dst_port: 0,
            proto: PROTO_ICMP,
        };
        match s.enqueue(&t, 64, Duration::ZERO) {
            EnqueueDecision::Admitted { priority, .. } => assert_eq!(priority, Priority::High),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn port_rules_classify_priority() {
        let cfg = CakeConfig::default();
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t0 = Duration::ZERO;
        // dport 53（DNS）→ High。
        match s.enqueue(&udp_tuple(40000, 53), 100, t0) {
            EnqueueDecision::Admitted { priority, .. } => assert_eq!(priority, Priority::High),
            other => panic!("unexpected: {other:?}"),
        }
        // 普通端口 → Medium。
        match s.enqueue(&tcp_tuple(40001, 443), 100, t0) {
            EnqueueDecision::Admitted { priority, .. } => assert_eq!(priority, Priority::Medium),
            other => panic!("unexpected: {other:?}"),
        }
        // low 列表命中 → Low。
        let cfg2 = CakeConfig {
            low_priority_ports: vec![9999],
            ..CakeConfig::default()
        };
        let mut s2 = CakeScheduler::new(&cfg2).unwrap();
        match s2.enqueue(&tcp_tuple(40002, 9999), 100, t0) {
            EnqueueDecision::Admitted { priority, .. } => assert_eq!(priority, Priority::Low),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn drr_is_fair_by_bytes_between_backlogged_flows() {
        let cfg = CakeConfig::default(); // quantum 1514
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t0 = Duration::ZERO;
        let a = tcp_tuple(1000, 80);
        let b = tcp_tuple(2000, 80);
        let fid_a = a.flow_id();
        let fid_b = b.flow_id();
        // A：4 包 × 1500B；B：12 包 × 500B（总量均为 6000B，持续 backlog）。
        for _ in 0..4 {
            assert!(matches!(
                s.enqueue(&a, 1500, t0),
                EnqueueDecision::Admitted { .. }
            ));
        }
        for _ in 0..12 {
            assert!(matches!(
                s.enqueue(&b, 500, t0),
                EnqueueDecision::Admitted { .. }
            ));
        }
        let mut a_bytes = 0u64;
        let mut b_bytes = 0u64;
        let mut order = Vec::new();
        for _ in 0..16 {
            let (fid, len) = s.dequeue(t0).expect("packet expected");
            if fid == fid_a {
                a_bytes += len;
                order.push('A');
            } else {
                assert_eq!(fid, fid_b);
                b_bytes += len;
                order.push('B');
            }
        }
        // DRR 按字节公平：两流各出 6000B。
        assert_eq!(a_bytes, 6000);
        assert_eq!(b_bytes, 6000);
        // 轮询交错：前 4 包为 A,B,A,B（每 dequeue 一包，active 轮转）。
        assert_eq!(&order[..4], &['A', 'B', 'A', 'B']);
        // 排空后无包。
        assert_eq!(s.dequeue(t0), None);
        let snap = s.snapshot();
        assert_eq!(snap.packets_dequeued, 16);
        assert_eq!(snap.bytes_dequeued, 12000);
    }

    #[test]
    fn strict_priority_drains_high_first() {
        let cfg = CakeConfig::default();
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t0 = Duration::ZERO;
        let high = udp_tuple(40000, 53); // High
        let low = tcp_tuple(40001, 443); // Medium
        for _ in 0..3 {
            s.enqueue(&high, 100, t0);
            s.enqueue(&low, 100, t0);
        }
        let fid_h = high.flow_id();
        let mut sig = String::new();
        for _ in 0..6 {
            let (fid, _) = s.dequeue(t0).expect("packet expected");
            sig.push(if fid == fid_h { 'H' } else { 'L' });
        }
        assert_eq!(sig, "HHHLLL");
        assert_eq!(s.dequeue(t0), None);
    }

    #[test]
    fn shaping_blocks_when_tokens_empty_and_resumes() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let cfg = CakeConfig {
            rate_limit: Some(limit),
            ..CakeConfig::default()
        };
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t = tcp_tuple(1000, 80);
        for _ in 0..3 {
            s.enqueue(&t, 1000, Duration::ZERO);
        }
        // t=0：burst 1000 → 第一包放行。
        let first = s.dequeue(Duration::ZERO).expect("first packet");
        assert_eq!(first.1, 1000);
        // 令牌已空 → 第二包被整形阻塞（不扣 deficit、不跳过）。
        assert_eq!(s.dequeue(Duration::ZERO), None);
        // t=1s：令牌恢复 1000 → 放行第二包。
        let second = s.dequeue(Duration::from_secs(1)).expect("second packet");
        assert_eq!(second.1, 1000);
        // 令牌又空 → 阻塞。
        assert_eq!(s.dequeue(Duration::from_secs(1)), None);
        // t=2s：第三包放行，队列排空。
        let third = s.dequeue(Duration::from_secs(2)).expect("third packet");
        assert_eq!(third.1, 1000);
        assert_eq!(s.dequeue(Duration::from_secs(2)), None);
        let snap = s.snapshot();
        assert_eq!(snap.bytes_dequeued, 3000);
    }

    #[test]
    fn shaping_block_preserves_order_no_priority_inversion() {
        // 整形阻塞时返回 None，但 deficit 已回滚：令牌恢复后同一包仍能发出
        //（顺序不变，无优先级反转）。
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let cfg = CakeConfig {
            rate_limit: Some(limit),
            ..CakeConfig::default()
        };
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let big = tcp_tuple(1000, 80);
        let small = tcp_tuple(2000, 80);
        s.enqueue(&big, 1000, Duration::ZERO);
        s.enqueue(&small, 100, Duration::ZERO);
        // 先发 big（1000B 耗尽 burst）。
        assert_eq!(s.dequeue(Duration::ZERO).unwrap().1, 1000);
        // small 的 100B 也发不出去（令牌 0），不能跳过 big 去发 small：
        // big 已出队，这里阻塞的是 small。
        assert_eq!(s.dequeue(Duration::ZERO), None);
        // t=1s 恢复后 small 发出。
        assert_eq!(s.dequeue(Duration::from_secs(1)).unwrap().1, 100);
    }

    #[test]
    fn large_packet_accumulates_deficit_across_rounds() {
        // 单包 3000B > quantum 1514：deficit 跨轮累积，最终发出（不饿死）。
        let cfg = CakeConfig::default();
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t = tcp_tuple(1000, 80);
        s.enqueue(&t, 3000, Duration::ZERO);
        let (fid, len) = s.dequeue(Duration::ZERO).expect("jumbo eventually sent");
        assert_eq!(fid, t.flow_id());
        assert_eq!(len, 3000);
    }

    #[test]
    fn queue_full_drops_and_counts() {
        let cfg = CakeConfig {
            max_queue_packets: 2,
            ..CakeConfig::default()
        };
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t = tcp_tuple(1000, 80);
        let t0 = Duration::ZERO;
        assert!(matches!(
            s.enqueue(&t, 100, t0),
            EnqueueDecision::Admitted { .. }
        ));
        assert!(matches!(
            s.enqueue(&t, 100, t0),
            EnqueueDecision::Admitted { .. }
        ));
        assert_eq!(s.enqueue(&t, 100, t0), EnqueueDecision::DroppedQueueFull);
        let snap = s.snapshot();
        assert_eq!(snap.packets_dropped, 1);
        assert_eq!(snap.packets_enqueued, 2);
    }

    #[test]
    fn oversize_packet_is_dropped() {
        let cfg = CakeConfig {
            max_packet_bytes: 1500,
            ..CakeConfig::default()
        };
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t = tcp_tuple(1000, 80);
        assert_eq!(
            s.enqueue(&t, 1501, Duration::ZERO),
            EnqueueDecision::DroppedOversize
        );
        assert_eq!(s.flow_count(), 0); // 丢弃的包不建流
        assert_eq!(s.snapshot().packets_dropped, 1);
    }

    #[test]
    fn reap_removes_idle_flows_and_counts_leftover() {
        let cfg = CakeConfig::default(); // flow_timeout 60s
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let x = tcp_tuple(1000, 80);
        let y = tcp_tuple(2000, 80);
        s.enqueue(&x, 100, Duration::ZERO);
        s.enqueue(&y, 100, Duration::ZERO);
        // y 在 t=59s 又有包 → last_seen=59s。
        s.enqueue(&y, 100, Duration::from_secs(59));
        assert_eq!(s.flow_count(), 2);
        // t=61s：x 空闲 61s ≥ 60s 被回收（含队内 1 包计 dropped）；y 空闲 2s 保留。
        let reaped = s.reap(Duration::from_secs(61));
        assert_eq!(reaped, 1);
        assert_eq!(s.flow_count(), 1);
        let snap = s.snapshot();
        assert_eq!(snap.flows_reaped, 1);
        assert_eq!(snap.packets_dropped, 1); // x 的残包
        // y 的包仍可出队。
        let (fid, len) = s.dequeue(Duration::from_secs(61)).expect("y packet");
        assert_eq!(fid, y.flow_id());
        assert_eq!(len, 100);
    }

    #[test]
    fn empty_scheduler_dequeue_returns_none() {
        let cfg = CakeConfig::default();
        let mut s = CakeScheduler::new(&cfg).unwrap();
        assert_eq!(s.dequeue(Duration::ZERO), None);
        assert_eq!(s.reap(Duration::from_secs(3600)), 0);
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn per_priority_stats_indexed_high_zero() {
        let cfg = CakeConfig::default();
        let mut s = CakeScheduler::new(&cfg).unwrap();
        let t0 = Duration::ZERO;
        s.enqueue(&udp_tuple(40000, 53), 100, t0); // High
        s.enqueue(&tcp_tuple(40001, 443), 200, t0); // Medium
        s.dequeue(t0);
        s.dequeue(t0);
        let snap = s.snapshot();
        assert_eq!(snap.per_priority_dequeued[Priority::High.index()], 100);
        assert_eq!(snap.per_priority_dequeued[Priority::Medium.index()], 200);
        assert_eq!(snap.per_priority_dequeued[Priority::Low.index()], 0);
    }
}
