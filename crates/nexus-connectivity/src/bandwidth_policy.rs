//! 带宽分配策略（按组/按节点配额 + 优先级 + 超额处理，纯内存确定性）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的**分配器**骨架，与 `qos` 令牌桶互补：
//! - **两级配额**：`BandwidthPolicy` 持有「每组每秒配额」与「每节点每秒配额」，
//!   `PolicyAllocator` 按 `now_second`（逻辑秒，调用方显式传入，单调）对各/各节点
//!   的已用字节计数做跨秒清零；
//! - **优先级**：`Priority`（High/Normal/Low）。Normal/Low 必须组与节点配额都够才放行；
//!   High 只要组内尚有任意配额即可放行到「组剩余上限」（即使超过该节点自身配额），
//!   不做复杂抢占，保持确定性可测；
//! - **超额策略**：`OverflowStrategy`（Drop/Queue）。配额不足时 Drop 直接拒绝、
//!   Queue 排队（不记账）。
//!
//! 边界（PRODUCT §12-bandwidth-policy 冻结）：
//! - 纯内存、纯同步、纯逻辑；不接真实 socket / 内核 tc；
//! - 不引入令牌桶时钟逻辑（refill 由 `qos` 负责），本模块只按逻辑秒做配额记账；
//! - `now_second` 由调用方显式传入，模块自身不读墙钟；
//! - 不做：真实排队缓冲/回灌、跨流公平调度、动态抢占与重排留 TODO。
//!
//! TODO（真实数据面集成，非本骨架范围）：
//! - 在 VirtualSubnetTunnel / RelayChannel 收发路径上挂接 `PolicyAllocator` 作为门控；
//! - 把 `now_second` 接入真实单调时钟；
//! - 排队请求的超时、回灌与按优先级出队；策略配置热加载与持久化。
//!
//! 错误面独立：`BandwidthPolicyError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::HashMap;
use std::fmt;

// ---------- 错误 ----------

/// 带宽分配策略相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BandwidthPolicyError {
    /// 配额参数非法（组配额或节点配额为 0）。
    InvalidQuota {
        /// 非法原因（人可读）。
        message: String,
    },
}

impl fmt::Display for BandwidthPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuota { message } => {
                write!(f, "BANDWIDTH_POLICY_INVALID_QUOTA: {message}")
            }
        }
    }
}

impl std::error::Error for BandwidthPolicyError {}

// ---------- 枚举 ----------

/// 节点优先级（High=0 最高，排序数值越小优先级越高）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// 高优先级：只要组内尚有任意配额即放行到组剩余上限。
    High,
    /// 普通优先级：组与节点配额都够才放行。
    Normal,
    /// 低优先级：组与节点配额都够才放行（与 Normal 同规则，仅用于区分）。
    Low,
}

impl Priority {
    /// 稳定字符串标签（"high" / "normal" / "low"）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
        }
    }

    /// 排序优先级数值（High=0 最高，数值越小优先级越高）。
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
        }
    }
}

/// 超额策略：配额不足时是丢弃还是排队。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowStrategy {
    /// 直接丢弃（不记账）。
    Drop,
    /// 排队（不记账，累计 queued_bytes）。
    Queue,
}

impl OverflowStrategy {
    /// 稳定字符串标签（"drop" / "queue"）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Queue => "queue",
        }
    }
}

/// 一次分配尝试的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationOutcome {
    /// 放行 `bytes` 字节（已记账）。
    Granted {
        /// 实际放行字节（High 被组剩余上限截断时 < 请求字节）。
        bytes: u64,
    },
    /// 丢弃 `bytes` 字节（未记账）。
    Dropped {
        /// 请求字节。
        bytes: u64,
    },
    /// 排队 `bytes` 字节（未记账）。
    Queued {
        /// 请求字节。
        bytes: u64,
    },
}

impl AllocationOutcome {
    /// 稳定字符串标签（"granted" / "dropped" / "queued"）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Granted { .. } => "granted",
            Self::Dropped { .. } => "dropped",
            Self::Queued { .. } => "queued",
        }
    }
}

// ---------- 策略 ----------

/// 带宽分配策略：两级配额（按组 / 按节点，均为每秒字节数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthPolicy {
    /// 每组每秒配额（字节/秒），必须 > 0。
    pub group_quota_bytes_per_sec: u64,
    /// 每节点每秒配额（字节/秒），必须 > 0。
    pub per_node_quota_bytes_per_sec: u64,
}

impl BandwidthPolicy {
    /// 构造策略；任一配额为 0 返回 `InvalidQuota`。
    pub fn new(
        group_quota_bytes_per_sec: u64,
        per_node_quota_bytes_per_sec: u64,
    ) -> Result<Self, BandwidthPolicyError> {
        if group_quota_bytes_per_sec == 0 {
            return Err(BandwidthPolicyError::InvalidQuota {
                message: format!(
                    "group_quota_bytes_per_sec must be > 0 (got {group_quota_bytes_per_sec})"
                ),
            });
        }
        if per_node_quota_bytes_per_sec == 0 {
            return Err(BandwidthPolicyError::InvalidQuota {
                message: format!(
                    "per_node_quota_bytes_per_sec must be > 0 (got {per_node_quota_bytes_per_sec})"
                ),
            });
        }
        Ok(Self {
            group_quota_bytes_per_sec,
            per_node_quota_bytes_per_sec,
        })
    }
}

// ---------- 分配器 ----------

/// 单个节点的记账条目（按逻辑秒累计已放行字节）。
struct NodeEntry {
    /// 所属组。
    group: String,
    /// 节点优先级。
    priority: Priority,
    /// 当前秒已用字节。
    used_bytes: u64,
    /// 当前已用字节所属逻辑秒。
    used_second: u64,
}

/// 单个组的记账条目（按逻辑秒累计已放行字节）。
struct GroupEntry {
    /// 当前秒已用字节。
    used_bytes: u64,
    /// 当前已用字节所属逻辑秒。
    used_second: u64,
}

/// 带宽分配器：按组/按节点配额 + 优先级 + 超额策略做确定性分配。
///
/// 时钟为逻辑秒（`now_second`），跨秒自动清零；不读墙钟、不阻塞、不 sleep。
pub struct PolicyAllocator {
    /// 两级配额策略。
    policy: BandwidthPolicy,
    /// 超额策略。
    strategy: OverflowStrategy,
    /// 已注册节点记账。
    nodes: HashMap<String, NodeEntry>,
    /// 各组记账。
    groups: HashMap<String, GroupEntry>,
    /// 累计排队字节（Queue 策略下）。
    queued_bytes: u64,
    /// 累计排队请求数（Queue 策略下）。
    queued_requests: usize,
}

impl PolicyAllocator {
    /// 用策略与超额策略构造分配器。
    #[must_use]
    pub fn new(policy: BandwidthPolicy, strategy: OverflowStrategy) -> Self {
        Self {
            policy,
            strategy,
            nodes: HashMap::new(),
            groups: HashMap::new(),
            queued_bytes: 0,
            queued_requests: 0,
        }
    }

    /// 注册节点（重复注册不覆盖既有记账）。
    pub fn register_node(&mut self, node_id: &str, group: &str, priority: Priority) {
        self.nodes.entry(node_id.to_string()).or_insert(NodeEntry {
            group: group.to_string(),
            priority,
            used_bytes: 0,
            used_second: 0,
        });
        self.groups.entry(group.to_string()).or_insert(GroupEntry {
            used_bytes: 0,
            used_second: 0,
        });
    }

    /// 若节点记账的逻辑秒落后于 `now_second`，跨秒清零。
    fn reset_node_if_needed(&mut self, node_id: &str, now_second: u64) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            if node.used_second != now_second {
                node.used_bytes = 0;
                node.used_second = now_second;
            }
        }
    }

    /// 若组记账的逻辑秒落后于 `now_second`，跨秒清零。
    fn reset_group_if_needed(&mut self, group: &str, now_second: u64) {
        let entry = self.groups.entry(group.to_string()).or_insert(GroupEntry {
            used_bytes: 0,
            used_second: now_second,
        });
        if entry.used_second != now_second {
            entry.used_bytes = 0;
            entry.used_second = now_second;
        }
    }

    /// 尝试为 `node_id` 放行 `bytes` 字节（逻辑秒 `now_second`）。
    ///
    /// - 未注册节点：直接 `Dropped`（不记账）；
    /// - Normal/Low：节点剩余与组剩余都 >= `bytes` 才 `Granted(bytes)`；
    /// - High：组剩余 > 0 时 `Granted(min(bytes, 组剩余))`（可超过节点自身配额）；
    /// - 不满足放行：按策略 `Dropped` 或 `Queued`（均不记账）。
    pub fn try_allocate(
        &mut self,
        node_id: &str,
        bytes: u64,
        now_second: u64,
    ) -> AllocationOutcome {
        // 未注册节点：直接丢弃，不记账、不建条目。
        let Some(node) = self.nodes.get(node_id) else {
            return AllocationOutcome::Dropped { bytes };
        };
        let group = node.group.clone();
        let priority = node.priority;

        // 跨秒清零。
        self.reset_node_if_needed(node_id, now_second);
        self.reset_group_if_needed(&group, now_second);

        let node_used = self.nodes[node_id].used_bytes;
        let group_used = self.groups[&group].used_bytes;
        let node_rem = self
            .policy
            .per_node_quota_bytes_per_sec
            .saturating_sub(node_used);
        let group_rem = self
            .policy
            .group_quota_bytes_per_sec
            .saturating_sub(group_used);

        // 计算实际放行字节（None 表示不满足放行条件）。
        let granted = match priority {
            // High：组内尚有任意配额即放行，截断到组剩余上限；忽略节点自身配额。
            Priority::High if group_rem > 0 => Some(bytes.min(group_rem)),
            Priority::High => None,
            // Normal/Low：节点与组配额都够才放行请求的完整字节。
            Priority::Normal | Priority::Low => {
                if node_rem >= bytes && group_rem >= bytes {
                    Some(bytes)
                } else {
                    None
                }
            }
        };

        match granted {
            Some(g) => {
                // 放行：记账（节点与组各累加 g）。
                if let Some(node) = self.nodes.get_mut(node_id) {
                    node.used_bytes = node.used_bytes.saturating_add(g);
                }
                if let Some(group_entry) = self.groups.get_mut(&group) {
                    group_entry.used_bytes = group_entry.used_bytes.saturating_add(g);
                }
                AllocationOutcome::Granted { bytes: g }
            }
            None => match self.strategy {
                OverflowStrategy::Drop => AllocationOutcome::Dropped { bytes },
                OverflowStrategy::Queue => {
                    self.queued_bytes = self.queued_bytes.saturating_add(bytes);
                    self.queued_requests = self.queued_requests.saturating_add(1);
                    AllocationOutcome::Queued { bytes }
                }
            },
        }
    }

    /// 某组在逻辑秒 `now_second` 的已用字节（跨秒后逻辑上为 0）。
    #[must_use]
    pub fn group_used_bytes(&self, group: &str, now_second: u64) -> u64 {
        match self.groups.get(group) {
            Some(entry) if entry.used_second == now_second => entry.used_bytes,
            _ => 0,
        }
    }

    /// 累计排队请求数（Queue 策略下；Drop 策略恒为 0）。
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.queued_requests
    }

    /// 累计排队字节数（Queue 策略下；Drop 策略恒为 0）。
    #[must_use]
    pub fn queued_bytes(&self) -> u64 {
        self.queued_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BandwidthPolicy {
        BandwidthPolicy::new(1000, 600).expect("valid policy")
    }

    #[test]
    fn priority_rank_and_str() {
        assert_eq!(Priority::High.as_str(), "high");
        assert_eq!(Priority::Normal.as_str(), "normal");
        assert_eq!(Priority::Low.as_str(), "low");
        assert!(Priority::High.rank() < Priority::Normal.rank());
        assert!(Priority::Normal.rank() < Priority::Low.rank());
        assert_eq!(Priority::High.rank(), 0);
    }

    #[test]
    fn overflow_and_outcome_str() {
        assert_eq!(OverflowStrategy::Drop.as_str(), "drop");
        assert_eq!(OverflowStrategy::Queue.as_str(), "queue");
        assert_eq!(AllocationOutcome::Granted { bytes: 1 }.as_str(), "granted");
        assert_eq!(AllocationOutcome::Dropped { bytes: 1 }.as_str(), "dropped");
        assert_eq!(AllocationOutcome::Queued { bytes: 1 }.as_str(), "queued");
    }

    #[test]
    fn zero_quota_is_rejected() {
        assert!(matches!(
            BandwidthPolicy::new(0, 600),
            Err(BandwidthPolicyError::InvalidQuota { .. })
        ));
        assert!(matches!(
            BandwidthPolicy::new(1000, 0),
            Err(BandwidthPolicyError::InvalidQuota { .. })
        ));
        assert!(BandwidthPolicy::new(1000, 600).is_ok());
        let msg = BandwidthPolicy::new(0, 600).unwrap_err().to_string();
        assert!(msg.starts_with("BANDWIDTH_POLICY_INVALID_QUOTA:"));
    }

    #[test]
    fn within_group_quota_is_granted_and_counted() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::Normal);
        let out = alloc.try_allocate("a", 500, 0);
        assert_eq!(out, AllocationOutcome::Granted { bytes: 500 });
        assert_eq!(alloc.group_used_bytes("A", 0), 500);
        assert_eq!(alloc.queued_count(), 0);
    }

    #[test]
    fn exhausted_group_quota_drops_normal_request() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::High);
        alloc.register_node("b", "A", Priority::Normal);
        // High 一次性打满组配额 1000。
        assert_eq!(
            alloc.try_allocate("a", 1000, 0),
            AllocationOutcome::Granted { bytes: 1000 }
        );
        // 组已耗尽：Normal 请求被丢弃。
        assert_eq!(
            alloc.try_allocate("b", 1, 0),
            AllocationOutcome::Dropped { bytes: 1 }
        );
        assert_eq!(alloc.group_used_bytes("A", 0), 1000);
    }

    #[test]
    fn queue_strategy_queues_instead_of_dropping() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Queue);
        alloc.register_node("a", "A", Priority::High);
        assert_eq!(
            alloc.try_allocate("a", 1000, 0),
            AllocationOutcome::Granted { bytes: 1000 }
        );
        assert_eq!(
            alloc.try_allocate("a", 100, 0),
            AllocationOutcome::Queued { bytes: 100 }
        );
        assert_eq!(alloc.queued_count(), 1);
        assert_eq!(alloc.queued_bytes(), 100);
        // 排队不记账。
        assert_eq!(alloc.group_used_bytes("A", 0), 1000);
    }

    #[test]
    fn cross_second_reset_recovers_quota() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::Normal);
        // t=0：节点配额打满 600。
        assert_eq!(
            alloc.try_allocate("a", 600, 0),
            AllocationOutcome::Granted { bytes: 600 }
        );
        // t=0 同秒再发：节点配额耗尽 -> 丢弃。
        assert_eq!(
            alloc.try_allocate("a", 100, 0),
            AllocationOutcome::Dropped { bytes: 100 }
        );
        // t=1 新秒：配额重置，再次放行 600。
        assert_eq!(
            alloc.try_allocate("a", 600, 1),
            AllocationOutcome::Granted { bytes: 600 }
        );
        assert_eq!(alloc.group_used_bytes("A", 1), 600);
        // 记账已推进到 t=1：回查 t=0 的旧秒逻辑上为 0。
        assert_eq!(alloc.group_used_bytes("A", 0), 0);
    }

    #[test]
    fn high_priority_bypasses_node_quota() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::High);
        // 请求 900 > 节点配额 600，但 High 且组内有配额 -> 放行 900。
        assert_eq!(
            alloc.try_allocate("a", 900, 0),
            AllocationOutcome::Granted { bytes: 900 }
        );
        assert_eq!(alloc.group_used_bytes("A", 0), 900);
    }

    #[test]
    fn high_priority_capped_at_group_remaining() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::High);
        alloc.register_node("b", "A", Priority::High);
        // b 先用掉 700，组剩 300。
        assert_eq!(
            alloc.try_allocate("b", 700, 0),
            AllocationOutcome::Granted { bytes: 700 }
        );
        // a 请求 500，但组只剩 300 -> 放行 300（截断到组剩余上限）。
        assert_eq!(
            alloc.try_allocate("a", 500, 0),
            AllocationOutcome::Granted { bytes: 300 }
        );
        assert_eq!(alloc.group_used_bytes("A", 0), 1000);
    }

    #[test]
    fn unregistered_node_is_dropped() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::Normal);
        // 未注册节点：直接丢弃，不创建条目。
        assert_eq!(
            alloc.try_allocate("ghost", 100, 0),
            AllocationOutcome::Dropped { bytes: 100 }
        );
        assert_eq!(alloc.queued_count(), 0);
    }

    #[test]
    fn groups_are_isolated_per_second() {
        let mut alloc = PolicyAllocator::new(policy(), OverflowStrategy::Drop);
        alloc.register_node("a", "A", Priority::Normal);
        alloc.register_node("c", "B", Priority::Normal);
        assert_eq!(
            alloc.try_allocate("a", 600, 0),
            AllocationOutcome::Granted { bytes: 600 }
        );
        // 组 B 不受组 A 影响。
        assert_eq!(
            alloc.try_allocate("c", 600, 0),
            AllocationOutcome::Granted { bytes: 600 }
        );
        assert_eq!(alloc.group_used_bytes("A", 0), 600);
        assert_eq!(alloc.group_used_bytes("B", 0), 600);
    }
}
