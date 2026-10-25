//! 节点优先级选择（内存骨架）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的节点优先级骨架：
//! - **优先级**：每个节点可注册一个优先级（0-100，越小越优先）；
//! - **路由候选**：`RouteCandidate` 聚合 node_id + priority + latency + bandwidth；
//! - **选择器**：`PrioritySelector` 维护 node_id → priority 映射，并按多键排序选最优路由。
//!
//! 边界（PRODUCT §12-node-priority 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实网络传输；
//! - 优先级取值范围 0..=100，越小越优先；
//! - 排序键：(priority 升序, latency_ms 升序, bandwidth_mbps 降序)；
//! - 真实延迟/带宽测量、动态优先级调整留 TODO。
//!
//! TODO（真实网络集成，非本骨架范围）：
//! - 从链路测量（`nexus-measurement`）实时填充 latency_ms / bandwidth_mbps；
//! - 在多跳路由（`routing`）中用 `PrioritySelector` 选下一跳；
//! - 优先级随健康检查（`health_check`）动态降级。
//!
//! 错误面独立：`PriorityError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::BTreeMap;
use std::fmt;

// ---------- 错误 ----------

/// 节点优先级相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorityError {
    /// 优先级值越界（必须在 0..=100 之间）。
    InvalidPriority {
        /// 越界的优先级值。
        value: u8,
    },
    /// 查询的节点未在选择器中注册。
    UnknownNode(String),
}

impl fmt::Display for PriorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPriority { value } => {
                write!(f, "PRIORITY_INVALID: value {value} out of range 0..=100")
            }
            Self::UnknownNode(node_id) => {
                write!(f, "PRIORITY_UNKNOWN_NODE: node {node_id:?} not registered")
            }
        }
    }
}

impl std::error::Error for PriorityError {}

// ---------- 节点优先级 ----------

/// 单个节点的优先级注册条目。
///
/// 优先级取值 0..=100，越小表示越优先。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePriority {
    /// 节点唯一标识。
    pub node_id: String,
    /// 优先级（0..=100，越小越优先）。
    pub priority: u8,
}

impl NodePriority {
    /// 构造一个节点优先级条目；priority 越界（>100）返回 `InvalidPriority`。
    pub fn new(node_id: impl Into<String>, priority: u8) -> Result<Self, PriorityError> {
        if priority > 100 {
            return Err(PriorityError::InvalidPriority { value: priority });
        }
        Ok(Self {
            node_id: node_id.into(),
            priority,
        })
    }
}

// ---------- 路由候选 ----------

/// 单个路由候选节点的静态画像。
///
/// 用于 `PrioritySelector::select_best` 的排序输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    /// 节点唯一标识。
    pub node_id: String,
    /// 优先级（0..=100，越小越优先）。
    pub priority: u8,
    /// 链路延迟（毫秒，越小越好）。
    pub latency_ms: u64,
    /// 链路带宽（Mbps，越大越好）。
    pub bandwidth_mbps: u64,
}

impl RouteCandidate {
    /// 构造一个路由候选；priority 越界（>100）返回 `InvalidPriority`。
    pub fn new(
        node_id: impl Into<String>,
        priority: u8,
        latency_ms: u64,
        bandwidth_mbps: u64,
    ) -> Result<Self, PriorityError> {
        if priority > 100 {
            return Err(PriorityError::InvalidPriority { value: priority });
        }
        Ok(Self {
            node_id: node_id.into(),
            priority,
            latency_ms,
            bandwidth_mbps,
        })
    }
}

// ---------- 优先级选择器 ----------

/// 节点优先级选择器。
///
/// 内部维护 node_id → priority 映射，并按多键排序选最优路由。
///
/// 排序键：(priority 升序, latency_ms 升序, bandwidth_mbps 降序)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrioritySelector {
    /// node_id → priority 映射。
    priorities: BTreeMap<String, u8>,
}

impl PrioritySelector {
    /// 构造空选择器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            priorities: BTreeMap::new(),
        }
    }

    /// 构造空选择器（语义同 `new`）。
    #[must_use]
    pub fn empty() -> Self {
        Self::new()
    }

    /// 注册或更新节点优先级；priority 越界（>100）返回 `InvalidPriority`。
    pub fn set(&mut self, node_id: impl Into<String>, priority: u8) -> Result<(), PriorityError> {
        if priority > 100 {
            return Err(PriorityError::InvalidPriority { value: priority });
        }
        self.priorities.insert(node_id.into(), priority);
        Ok(())
    }

    /// 查询节点优先级；未注册返回 `UnknownNode`。
    pub fn get(&self, node_id: &str) -> Result<u8, PriorityError> {
        self.priorities
            .get(node_id)
            .copied()
            .ok_or_else(|| PriorityError::UnknownNode(node_id.to_string()))
    }

    /// 按多键排序选择最优路由候选。
    ///
    /// 排序键：(priority 升序, latency_ms 升序, bandwidth_mbps 降序)。
    /// 返回第一名的克隆；空列表返回 `None`。
    #[must_use]
    pub fn select_best(candidates: &[RouteCandidate]) -> Option<RouteCandidate> {
        candidates
            .iter()
            .min_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then_with(|| a.latency_ms.cmp(&b.latency_ms))
                    .then_with(|| b.bandwidth_mbps.cmp(&a.bandwidth_mbps))
            })
            .cloned()
    }

    /// 已注册的节点数量。
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.priorities.len()
    }
}

impl Default for PrioritySelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_priority_new_accepts_valid_range() {
        let n0 = NodePriority::new("n0", 0).expect("0 is valid");
        assert_eq!(n0.priority, 0);
        let n100 = NodePriority::new("n100", 100).expect("100 is valid");
        assert_eq!(n100.priority, 100);
    }

    #[test]
    fn node_priority_new_rejects_out_of_range() {
        let err = NodePriority::new("n", 101).expect_err("101 out of range");
        assert!(matches!(err, PriorityError::InvalidPriority { value: 101 }));
    }

    #[test]
    fn selector_set_and_get_roundtrip() {
        let mut sel = PrioritySelector::new();
        sel.set("node-a", 10).expect("valid priority");
        sel.set("node-b", 5).expect("valid priority");
        assert_eq!(sel.get("node-a"), Ok(10));
        assert_eq!(sel.get("node-b"), Ok(5));
        assert_eq!(sel.registered_count(), 2);
    }

    #[test]
    fn selector_set_rejects_out_of_range() {
        let mut sel = PrioritySelector::new();
        let err = sel.set("n", 200).expect_err("200 out of range");
        assert!(matches!(err, PriorityError::InvalidPriority { value: 200 }));
    }

    #[test]
    fn selector_get_unknown_node_returns_error() {
        let sel = PrioritySelector::new();
        let err = sel.get("missing").expect_err("unknown node");
        assert!(matches!(err, PriorityError::UnknownNode(_)));
    }

    #[test]
    fn select_best_priority_overrides_latency() {
        let c10_fast = RouteCandidate::new("c10-fast", 10, 10, 100).unwrap();
        let c5_slow = RouteCandidate::new("c5-slow", 5, 100, 100).unwrap();
        let best = PrioritySelector::select_best(&[c10_fast, c5_slow]);
        let best = best.expect("non-empty");
        assert_eq!(best.node_id, "c5-slow");
        assert_eq!(best.priority, 5);
    }

    #[test]
    fn select_best_same_priority_picks_lower_latency() {
        let a = RouteCandidate::new("a", 10, 20, 100).unwrap();
        let b = RouteCandidate::new("b", 10, 10, 100).unwrap();
        let best = PrioritySelector::select_best(&[a, b]).expect("non-empty");
        assert_eq!(best.node_id, "b");
        assert_eq!(best.latency_ms, 10);
    }

    #[test]
    fn select_best_same_priority_latency_picks_higher_bandwidth() {
        let a = RouteCandidate::new("a", 10, 10, 100).unwrap();
        let b = RouteCandidate::new("b", 10, 10, 1000).unwrap();
        let best = PrioritySelector::select_best(&[a, b]).expect("non-empty");
        assert_eq!(best.node_id, "b");
        assert_eq!(best.bandwidth_mbps, 1000);
    }

    #[test]
    fn select_best_empty_returns_none() {
        let best = PrioritySelector::select_best(&[]);
        assert!(best.is_none());
    }

    #[test]
    fn route_candidate_new_rejects_out_of_range() {
        let err = RouteCandidate::new("n", 101, 10, 100).expect_err("101 out of range");
        assert!(matches!(err, PriorityError::InvalidPriority { value: 101 }));
    }
}
