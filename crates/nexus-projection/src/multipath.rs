//! 多路径调度器（S29，文档 §12.6）。
//!
//! 统一数据面的路径调度胶水（独立高级选项，不进 boost 开关）：
//!
//! - `MultipathStrategy`：`Single`（只用最优 egress，默认）/ `PerFlow`
//!   （按流哈希固定 egress）/ `PerPacket`（按包加权轮询）。
//! - `PathScheduler::select`：按策略选 egress。纯函数（`&self` 只读），
//!   不持有 egress 状态（egress 集合由调用方管理）。
//! - `ReorderBuffer`：per-packet 接收端重排。按 `seq` 缓冲乱序包，按序吐出；
//!   容量有界（`O(reorder_buffer)`），超限丢弃最小 seq 并计数。
//!
//! Sync API，零 tokio（与 `nexus-path` / `boost.rs` 一致）。
//! 纯内存、纯同步、零真实网络；TUN/QUIC 接入点预留。

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

/// 多路径调度策略（`network.toml [multipath] strategy`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultipathStrategy {
    /// 只用最优 egress（调用方排序首位）。默认；零行为变化。
    #[default]
    Single,
    /// 按流哈希固定 egress（流内有序）。
    PerFlow,
    /// 按包加权轮询（需接收端重排）。
    PerPacket,
}

impl MultipathStrategy {
    /// 从配置字符串解析；未知值返回 `None`（调用方决定是报错还是回落默认）。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "single" => Some(Self::Single),
            "per-flow" | "perflow" => Some(Self::PerFlow),
            "per-packet" | "perpacket" => Some(Self::PerPacket),
            _ => None,
        }
    }

    /// 配置字符串形式（round-trip 用）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::PerFlow => "per-flow",
            Self::PerPacket => "per-packet",
        }
    }
}

/// 多路径配置（`network.toml [multipath]` 的纯数据映射）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipathConfig {
    /// 调度策略，默认 `Single`。
    pub strategy: MultipathStrategy,
    /// per-packet 接收端重排缓冲上限（包数），默认 64，必须 >= 1。
    pub reorder_buffer: usize,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            strategy: MultipathStrategy::Single,
            reorder_buffer: 64,
        }
    }
}

impl MultipathConfig {
    /// 校验配置；`reorder_buffer == 0` 时返回错误描述。
    pub fn validate(&self) -> Result<(), String> {
        if self.reorder_buffer == 0 {
            return Err("multipath.reorder_buffer must be >= 1".to_string());
        }
        Ok(())
    }
}

/// Egress 描述符（调度器的输出目标）。
///
/// 纯数据；`kind` 供未来映射到真实 egress（N1 mesh / proxy / TURN），
/// 当前阶段仅做标识（TUN 接入点预留）。
///
/// 字段私有：必须经 `new()` 构造，保证 `weight >= 1`（F1：防止结构体
/// 字面量绕过钳位构造 `weight=0` 导致 `PerPacket` 除零 panic）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EgressDescriptor {
    /// Egress 唯一标识（如 "mesh-direct" / "proxy" / "turn"）。
    id: String,
    /// 调度类别（展示/未来映射用）。
    kind: EgressKind,
    /// 加权轮询权重（`PerPacket` 用），恒 `>= 1`。
    weight: u32,
}

/// Egress 类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressKind {
    /// N1 mesh 直连。
    MeshDirect,
    /// 代理出口。
    Proxy,
    /// TURN 中继。
    Turn,
    /// 其他/未来扩展。
    Other,
}

impl EgressDescriptor {
    /// 构造；`weight == 0` 时钳位到 1（不报错，保证调度永不除零）。
    pub fn new(id: impl Into<String>, kind: EgressKind, weight: u32) -> Self {
        Self {
            id: id.into(),
            kind,
            weight: weight.max(1),
        }
    }

    /// Egress 唯一标识。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 调度类别。
    pub fn kind(&self) -> EgressKind {
        self.kind
    }

    /// 加权轮询权重（恒 `>= 1`）。
    pub fn weight(&self) -> u32 {
        self.weight
    }
}

/// 路径调度器（`PerPacket` 有轮询游标状态；`Single`/`PerFlow` 分支不修改状态）。
///
/// `select` 的 `Single`/`PerFlow` 分支是纯函数语义：相同输入 → 相同输出
/// （`PerFlow` 确定性不变量）；`Single` 模式等价于无调度器（零回归）。
/// egress 集合由调用方持有并传入（调度器不拥有）。
#[derive(Debug, Default)]
pub struct PathScheduler {
    /// 加权轮询游标（`PerPacket` 用；`Single`/`PerFlow` 不用）。
    rr_cursor: u64,
}

impl PathScheduler {
    /// 新建调度器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 按策略选择 egress。
    ///
    /// - `egresses`：调用方排序（`Single` 取首位为最优；`PerFlow`/`PerPacket`
    ///   按给定顺序做哈希/轮询，顺序变化视为集合变化）；
    /// - `flow_id`：流标识（如 5 元组哈希；`PerFlow` 用，`Single`/`PerPacket` 忽略）；
    /// - `_seq`：包序号（未来加权/拥塞感知用；当前未使用，下划线前缀防警告）。
    ///
    /// 空 `egresses` 返回 `None`（调用方处理无可用 egress，不 panic）。
    pub fn select<'a>(
        &mut self,
        strategy: MultipathStrategy,
        egresses: &'a [EgressDescriptor],
        flow_id: u64,
        _seq: u64,
    ) -> Option<&'a EgressDescriptor> {
        if egresses.is_empty() {
            return None;
        }
        match strategy {
            MultipathStrategy::Single => egresses.first(),
            MultipathStrategy::PerFlow => {
                let idx = (flow_id % egresses.len() as u64) as usize;
                egresses.get(idx)
            }
            MultipathStrategy::PerPacket => {
                // 加权轮询：按 weight 展开的虚拟槽位上轮转。
                // 总权重为 0 不可能（EgressDescriptor::new 钳位 >= 1）。
                let total_weight: u64 = egresses.iter().map(|e| e.weight() as u64).sum();
                debug_assert!(total_weight > 0);
                let slot = self.rr_cursor % total_weight;
                self.rr_cursor = self.rr_cursor.wrapping_add(1);
                let mut acc: u64 = 0;
                for e in egresses {
                    acc += e.weight() as u64;
                    if slot < acc {
                        return Some(e);
                    }
                }
                // 逻辑不可达（slot < total_weight 恒成立）；防御性回落首位。
                egresses.first()
            }
        }
    }

    /// 重置轮询游标（测试/egress 集合变化时调用方显式重置）。
    pub fn reset(&mut self) {
        self.rr_cursor = 0;
    }
}

/// 接收端重排缓冲（per-packet 模式）。
///
/// 按 `seq`（u64 包序号，调用方从包头提取，未来复用 QUIC 包号）缓冲乱序包，
/// `pop_in_order` 按序吐出连续 seq。容量上限 `capacity`（`O(capacity)` 内存）；
/// 插入时超限 → 丢弃最小 seq 的包并计数 `dropped()`（防内存爆炸）。
///
/// 重复 `seq` 的包：保留先到的，丢弃后到的（计数到 `dropped_duplicate`，
/// 与容量丢弃分开计数，诊断可区分）。
#[derive(Debug)]
pub struct ReorderBuffer {
    /// 待按序吐出的包：seq → 载荷。
    pending: BTreeMap<u64, Vec<u8>>,
    /// 下一个期望吐出的 seq。
    next_seq: u64,
    /// 容量上限（包数）。
    capacity: usize,
    /// 容量超限丢弃计数。
    dropped_overflow: u64,
    /// 重复 seq 丢弃计数。
    dropped_duplicate: u64,
    /// 成功按序吐出的包数。
    emitted: u64,
}

impl ReorderBuffer {
    /// 新建；`capacity == 0` 时钳位到 1（保证至少能缓冲 1 个包）。
    pub fn new(capacity: usize) -> Self {
        Self {
            pending: BTreeMap::new(),
            next_seq: 0,
            capacity: capacity.max(1),
            dropped_overflow: 0,
            dropped_duplicate: 0,
            emitted: 0,
        }
    }

    /// 期望的下一个 seq（初始化/排空后为 0 或最后吐出 seq + 1）。
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// 容量超限丢弃的包数。
    pub fn dropped_overflow(&self) -> u64 {
        self.dropped_overflow
    }

    /// 重复 seq 丢弃的包数。
    pub fn dropped_duplicate(&self) -> u64 {
        self.dropped_duplicate
    }

    /// 按序吐出的包数。
    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// 当前缓冲的包数（`<= capacity` 恒成立）。
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// 缓冲是否为空。
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// 喂入一个包（`seq` + 载荷）。
    ///
    /// - `seq < next_seq`（已吐出）：视为重复/迟到，丢弃并计 `dropped_duplicate`；
    /// - 已在缓冲：丢弃并计 `dropped_duplicate`；
    /// - 插入后超限：丢弃最小 seq（不一定是刚插入的），计 `dropped_overflow`。
    pub fn push(&mut self, seq: u64, payload: Vec<u8>) {
        if seq < self.next_seq || self.pending.contains_key(&seq) {
            self.dropped_duplicate += 1;
            return;
        }
        self.pending.insert(seq, payload);
        // 容量 enforcement：丢弃最小 seq 直到不超限。
        // BTreeMap 有序，首个即最小。
        while self.pending.len() > self.capacity {
            // pop_first 稳定版可用（MSRV 需确认）；用迭代器取首 key 再 remove。
            if let Some(&smallest) = self.pending.keys().next() {
                self.pending.remove(&smallest);
                self.dropped_overflow += 1;
            } else {
                break;
            }
        }
        debug_assert!(self.pending.len() <= self.capacity);
    }

    /// 按序吐出连续可用的包（`next_seq` 起连续的）。
    ///
    /// 返回吐出的 `(seq, payload)` 列表（按 seq 升序）；无连续可用时返回空。
    pub fn pop_in_order(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(payload) = self.pending.remove(&self.next_seq) {
            out.push((self.next_seq, payload));
            self.next_seq += 1;
            self.emitted += 1;
        }
        out
    }

    /// 设置期望的下一个 seq（流重置/新流时调用方显式设置）。
    pub fn reset(&mut self, next_seq: u64) {
        self.pending.clear();
        self.next_seq = next_seq;
        // 计数器不清零（累积诊断）；如需清零调用方重建。
    }
}

/// 流 ID 计算辅助：从任意 `Hash` 的流标识（如 5 元组）得 u64。
pub fn flow_id_of<T: Hash>(flow_key: &T) -> u64 {
    // FNV-1a 64（std-only，无外部依赖；与仓库内哈希风格一致）。
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    struct FnvHasher(u64);
    impl Hasher for FnvHasher {
        fn write(&mut self, bytes: &[u8]) {
            for b in bytes {
                self.0 ^= *b as u64;
                self.0 = self.0.wrapping_mul(FNV_PRIME);
            }
        }
        fn finish(&self) -> u64 {
            self.0
        }
    }
    let mut h = FnvHasher(FNV_OFFSET);
    flow_key.hash(&mut h);
    h.finish()
}

/// `network.toml [multipath]` 的最小解析（纯数据；完整 TOML 解析由 nexusd 配置层做）。
///
/// 输入为已提取的键值对（`strategy` / `reorder_buffer` 可选）；缺失取默认。
/// 未知 strategy 字符串 → `Err`（调用方决定报错还是回落）。
pub fn parse_multipath_config(
    strategy: Option<&str>,
    reorder_buffer: Option<usize>,
) -> Result<MultipathConfig, String> {
    let strategy = match strategy {
        None => MultipathStrategy::Single,
        Some(s) => {
            MultipathStrategy::parse(s).ok_or_else(|| format!("unknown multipath.strategy: {s}"))?
        }
    };
    let cfg = MultipathConfig {
        strategy,
        reorder_buffer: reorder_buffer.unwrap_or(64),
    };
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three_egresses() -> Vec<EgressDescriptor> {
        vec![
            EgressDescriptor::new("mesh-direct", EgressKind::MeshDirect, 1),
            EgressDescriptor::new("proxy", EgressKind::Proxy, 1),
            EgressDescriptor::new("turn", EgressKind::Turn, 1),
        ]
    }

    #[test]
    fn strategy_parse_round_trip() {
        for s in ["single", "per-flow", "per-packet", "SINGLE", " PerFlow "] {
            let st = MultipathStrategy::parse(s).expect(s);
            assert_eq!(MultipathStrategy::parse(st.as_str()), Some(st));
        }
        assert_eq!(MultipathStrategy::parse("bogus"), None);
        assert_eq!(MultipathStrategy::default(), MultipathStrategy::Single);
    }

    #[test]
    fn config_validate_rejects_zero_buffer() {
        let cfg = MultipathConfig {
            strategy: MultipathStrategy::PerPacket,
            reorder_buffer: 0,
        };
        assert!(cfg.validate().is_err());
        assert!(parse_multipath_config(Some("per-packet"), Some(0)).is_err());
        assert!(parse_multipath_config(Some("bogus"), None).is_err());
        // 缺省取默认。
        let d = parse_multipath_config(None, None).unwrap();
        assert_eq!(d, MultipathConfig::default());
    }

    #[test]
    fn egress_weight_zero_clamped() {
        let e = EgressDescriptor::new("x", EgressKind::Other, 0);
        assert_eq!(e.weight(), 1);
        // F1 回归：字段私有后，结构体字面量无法绕过 new() 构造 weight=0。
        // （编译期保证：EgressDescriptor { id: .., kind: .., weight: 0 } 已无法编译。）
    }

    #[test]
    fn single_always_picks_first() {
        let mut sched = PathScheduler::new();
        let eg = three_egresses();
        for flow in 0..10u64 {
            for seq in 0..5u64 {
                let got = sched
                    .select(MultipathStrategy::Single, &eg, flow, seq)
                    .unwrap();
                assert_eq!(got.id(), "mesh-direct");
            }
        }
    }

    #[test]
    fn select_empty_returns_none() {
        let mut sched = PathScheduler::new();
        let empty: Vec<EgressDescriptor> = vec![];
        assert!(
            sched
                .select(MultipathStrategy::Single, &empty, 0, 0)
                .is_none()
        );
        assert!(
            sched
                .select(MultipathStrategy::PerFlow, &empty, 42, 0)
                .is_none()
        );
        assert!(
            sched
                .select(MultipathStrategy::PerPacket, &empty, 0, 7)
                .is_none()
        );
    }

    #[test]
    fn perflow_stable_per_flow_id() {
        let mut sched = PathScheduler::new();
        let eg = three_egresses();
        // 同一 flow_id 多次 select → 同一 egress（确定性）。
        for flow in [0u64, 1, 42, 999, u64::MAX] {
            let first = sched
                .select(MultipathStrategy::PerFlow, &eg, flow, 0)
                .unwrap()
                .id()
                .to_string();
            for seq in 1..100u64 {
                let got = sched
                    .select(MultipathStrategy::PerFlow, &eg, flow, seq)
                    .unwrap();
                assert_eq!(got.id(), first, "flow {flow} seq {seq} 不稳定");
            }
        }
    }

    #[test]
    fn perflow_distributes_across_egresses() {
        let mut sched = PathScheduler::new();
        let eg = three_egresses();
        let mut seen = std::collections::HashSet::new();
        for flow in 0..64u64 {
            let got = sched
                .select(MultipathStrategy::PerFlow, &eg, flow, 0)
                .unwrap();
            seen.insert(got.id().to_string());
        }
        assert_eq!(seen.len(), 3, "64 个流应覆盖 3 个 egress，实际 {seen:?}");
    }

    #[test]
    fn perpacket_weighted_round_robin() {
        let mut sched = PathScheduler::new();
        let eg = three_egresses();
        let ids: Vec<String> = (0..6)
            .map(|seq| {
                sched
                    .select(MultipathStrategy::PerPacket, &eg, 0, seq)
                    .unwrap()
                    .id()
                    .to_string()
            })
            .collect();
        assert_eq!(
            ids,
            vec![
                "mesh-direct",
                "proxy",
                "turn",
                "mesh-direct",
                "proxy",
                "turn"
            ]
        );
    }

    #[test]
    fn perpacket_weighted() {
        let mut sched = PathScheduler::new();
        let eg = vec![
            EgressDescriptor::new("a", EgressKind::MeshDirect, 2),
            EgressDescriptor::new("b", EgressKind::Proxy, 1),
        ];
        let ids: Vec<String> = (0..6)
            .map(|seq| {
                sched
                    .select(MultipathStrategy::PerPacket, &eg, 0, seq)
                    .unwrap()
                    .id()
                    .to_string()
            })
            .collect();
        // 权重 2:1 → a,a,b,a,a,b。
        assert_eq!(ids, vec!["a", "a", "b", "a", "a", "b"]);
    }

    #[test]
    fn reorder_in_order_passthrough() {
        let mut rb = ReorderBuffer::new(64);
        for seq in 0..5u64 {
            rb.push(seq, vec![seq as u8]);
        }
        let out = rb.pop_in_order();
        assert_eq!(out.len(), 5);
        for (i, (seq, _)) in out.iter().enumerate() {
            assert_eq!(*seq, i as u64);
        }
        assert_eq!(rb.emitted(), 5);
        assert!(rb.is_empty());
    }

    #[test]
    fn reorder_out_of_order_reassembled() {
        let mut rb = ReorderBuffer::new(64);
        for seq in [3u64, 1, 2, 5, 4] {
            rb.push(seq, vec![seq as u8]);
            // 喂 3 时 next_seq=0，无连续可吐。
        }
        // 此时 next_seq 仍为 0（缺 seq 0），啥也吐不出。
        assert!(rb.pop_in_order().is_empty());
        rb.push(0, vec![0]);
        let out = rb.pop_in_order();
        let seqs: Vec<u64> = out.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn reorder_duplicate_dropped() {
        let mut rb = ReorderBuffer::new(64);
        rb.push(0, vec![0]);
        rb.push(0, vec![9]); // 重复
        assert_eq!(rb.dropped_duplicate(), 1);
        let out = rb.pop_in_order();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, vec![0]); // 保留先到的
        // 迟到包（seq < next_seq）。
        rb.push(0, vec![8]);
        assert_eq!(rb.dropped_duplicate(), 2);
    }

    #[test]
    fn reorder_overflow_bounded() {
        let mut rb = ReorderBuffer::new(4);
        // 喂 6 个包（seq 0..6），容量 4 → 丢 2 个最小 seq（0,1）。
        for seq in 0..6u64 {
            rb.push(seq, vec![seq as u8]);
        }
        assert_eq!(rb.len(), 4, "缓冲有界");
        assert_eq!(rb.dropped_overflow(), 2, "丢弃 2 个最小 seq");
        // next_seq=0，但 0,1 已被丢弃 → 吐不出（诚实：超限丢弃不可恢复）。
        assert!(rb.pop_in_order().is_empty());
        // 验证缓冲中是 2,3,4,5：再次推送它们应被判重复（已在缓冲中）。
        let dup_before = rb.dropped_duplicate();
        for seq in 2..6u64 {
            rb.push(seq, vec![0xFF]);
        }
        assert_eq!(rb.dropped_duplicate() - dup_before, 4);
    }

    #[test]
    fn reorder_capacity_zero_clamped() {
        let rb = ReorderBuffer::new(0);
        assert_eq!(rb.len(), 0);
        // 内部 capacity 被钳位到 1（push 1 个不超限）。
        let mut rb = rb;
        rb.push(0, vec![0]);
        assert_eq!(rb.len(), 1);
        assert_eq!(rb.dropped_overflow(), 0);
    }

    #[test]
    fn flow_id_of_deterministic() {
        let a = flow_id_of(&("10.0.0.1", 1234, "10.0.0.2", 80, 6u8));
        let b = flow_id_of(&("10.0.0.1", 1234, "10.0.0.2", 80, 6u8));
        let c = flow_id_of(&("10.0.0.1", 1235, "10.0.0.2", 80, 6u8));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// HashMap 不直接用做 egress 键：EgressDescriptor 已派生 Hash，冒烟验证。
    #[test]
    fn egress_descriptor_hashable() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let e = EgressDescriptor::new("proxy", EgressKind::Proxy, 1);
        map.insert(e.clone(), 7u32);
        assert_eq!(map[&e], 7);
    }
}
