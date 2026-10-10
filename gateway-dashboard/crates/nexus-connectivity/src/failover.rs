//! 故障转移（主备切换 + 自动回切状态机，内存骨架，纯逻辑）。
//!
//! 本模块是 delivery 层共享底座的主备故障转移骨架：
//! - **配置**：`FailoverConfig` 声明一个主节点 `primary_node` 与一组备节点
//!   `standby_nodes`（按顺序尝试），以及是否 `auto_failback`（主恢复后自动切回）；
//! - **状态机**：`FailoverState` 四态——`Primary`（主在用）/ `Standby { node }`
//!   （某备在用）/ `FailingOver { from, to }`（切换过渡，骨架内同步瞬时态）/
//!   `Failed`（无可用节点，整体失败）；
//! - **切换**：`FailoverManager::report_failure` 在当前 active 失败时按 standby 列表顺序
//!   退到下一个尚未失败的备节点；全部备节点都失败后落入 `Failed`；
//! - **回切**：`report_recovery` 在 `auto_failback=true` 且主节点恢复时自动切回 `Primary`。
//!
//! 决策规则：
//! 1. 初始 `state=Primary`、`active=primary_node`；
//! 2. `report_failure(node)`：累加连续失败计数与 `last_failure_ms`；若失败节点即当前
//!    active，则选 standby 列表中第一个尚未失败的备节点接管（`FailingOver` -> `Standby`）；
//!    无可用备节点 -> `Failed`；
//! 3. `report_recovery(node)`：`auto_failback` 且 `node==primary` 且当前不在 Primary
//!    -> 切回 Primary 并清零连续失败；否则仅把该节点标记为可用（从失败集合移除）。
//!
//! 边界（PRODUCT §12-failover 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不接真实健康探测、不做真实流量切换；
//! - 时间由调用方以 `now_ms: u64` 显式注入（仿 `bandwidth_policy` 的 `now_second`），
//!   模块自身不读墙钟；
//! - `FailingOver` 在同步骨架内是瞬时态（一次 `report_failure` 调用内完成），
//!   不暴露可观察的中间状态给外部调用方；
//! - 真实探测、真实流量摘除/挂载、跨进程状态持久化留 TODO。
//!
//! TODO（真实数据面集成，非本骨架范围）：
//! - 把 `report_failure`/`report_recovery` 接到真实健康检查（`health_check`）事件流；
//! - 主备切换时在传输层摘除/挂载真实连接（DNS 切换、连接迁移、优雅 drain）；
//! - `now_ms` 接入真实单调时钟；故障转移决策持久化与 crash 后 reconcile。
//!
//! 错误面独立：`FailoverError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::HashSet;
use std::fmt;

// ---------- 错误 ----------

/// 故障转移相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverError {
    /// 主节点配置非法（如为空串）。
    InvalidPrimary {
        /// 非法原因（人可读）。
        details: String,
    },
    /// 备节点列表配置非法（含空串 / 重复 / 含主节点本身）。
    InvalidStandby {
        /// 非法原因（人可读）。
        details: String,
    },
}

impl fmt::Display for FailoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrimary { details } => {
                write!(f, "FAILOVER_INVALID_PRIMARY: {details}")
            }
            Self::InvalidStandby { details } => {
                write!(f, "FAILOVER_INVALID_STANDBY: {details}")
            }
        }
    }
}

impl std::error::Error for FailoverError {}

// ---------- 状态 ----------

/// 故障转移状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverState {
    /// 主节点在用。
    Primary,
    /// 某备节点在用。
    Standby {
        /// 当前在用的备节点。
        node: String,
    },
    /// 切换过渡（骨架内同步瞬时态）。
    FailingOver {
        /// 切换前节点。
        from: String,
        /// 切换后节点。
        to: String,
    },
    /// 无可用节点，整体失败。
    Failed,
}

impl FailoverState {
    /// 返回稳定字符串标签（"primary"/"standby"/"failing-over"/"failed"）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Standby { .. } => "standby",
            Self::FailingOver { .. } => "failing-over",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for FailoverState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 故障转移配置：一个主节点 + 有序备节点列表 + 是否自动回切。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverConfig {
    /// 主节点标识（非空）。
    primary_node: String,
    /// 备节点列表（按顺序尝试，不得含主节点、不得重复、不得空串）。
    standby_nodes: Vec<String>,
    /// 主节点恢复后是否自动切回。
    auto_failback: bool,
}

impl FailoverConfig {
    /// 构造配置并做校验：
    /// - `primary_node` 不能为空；
    /// - `standby_nodes` 不得含空串、不得重复、不得包含 `primary_node` 本身。
    pub fn new(
        primary_node: impl Into<String>,
        standby_nodes: Vec<String>,
        auto_failback: bool,
    ) -> Result<Self, FailoverError> {
        let primary_node = primary_node.into();
        if primary_node.is_empty() {
            return Err(FailoverError::InvalidPrimary {
                details: "primary_node must not be empty".to_string(),
            });
        }
        for (idx, node) in standby_nodes.iter().enumerate() {
            if node.is_empty() {
                return Err(FailoverError::InvalidStandby {
                    details: format!("standby_nodes[{idx}] is empty"),
                });
            }
            if node == &primary_node {
                return Err(FailoverError::InvalidStandby {
                    details: format!("standby_nodes[{idx}] {node:?} must not equal primary_node"),
                });
            }
        }
        let mut seen = HashSet::new();
        for node in &standby_nodes {
            if !seen.insert(node.clone()) {
                return Err(FailoverError::InvalidStandby {
                    details: format!("standby node {node:?} is duplicated"),
                });
            }
        }
        Ok(Self {
            primary_node,
            standby_nodes,
            auto_failback,
        })
    }

    /// 主节点标识。
    #[must_use]
    pub fn primary_node(&self) -> &str {
        &self.primary_node
    }

    /// 备节点列表（只读视图）。
    #[must_use]
    pub fn standby_nodes(&self) -> &[String] {
        &self.standby_nodes
    }

    /// 是否启用自动回切。
    #[must_use]
    pub fn auto_failback(&self) -> bool {
        self.auto_failback
    }
}

// ---------- 管理器 ----------

/// 故障转移管理器：持有配置与当前主备状态，纯内存纯逻辑。
///
/// 时钟为逻辑毫秒（`now_ms`），由调用方显式传入；不读墙钟、不阻塞。
pub struct FailoverManager {
    /// 故障转移配置。
    config: FailoverConfig,
    /// 当前故障转移状态。
    state: FailoverState,
    /// 当前活跃节点（主或某备）。
    active: String,
    /// 连续失败计数。
    consecutive_failures: u32,
    /// 最近一次失败的逻辑毫秒时间戳。
    last_failure_ms: Option<u64>,
    /// 已失败的节点集合（用于选择下一个可用备节点）。
    dead: HashSet<String>,
}

impl FailoverManager {
    /// 用配置构造管理器；初始 `state=Primary`、`active=primary_node`。
    #[must_use]
    pub fn new(config: FailoverConfig) -> Self {
        let active = config.primary_node.clone();
        Self {
            config,
            state: FailoverState::Primary,
            active,
            consecutive_failures: 0,
            last_failure_ms: None,
            dead: HashSet::new(),
        }
    }

    /// 当前活跃节点。
    #[must_use]
    pub fn active_node(&self) -> &str {
        &self.active
    }

    /// 当前故障转移状态。
    #[must_use]
    pub fn state(&self) -> &FailoverState {
        &self.state
    }

    /// 连续失败计数。
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// 最近一次失败的逻辑毫秒时间戳。
    #[must_use]
    pub fn last_failure_ms(&self) -> Option<u64> {
        self.last_failure_ms
    }

    /// 在备节点列表中找下一个尚未失败的备节点。
    fn next_standby(&self) -> Option<String> {
        self.config
            .standby_nodes
            .iter()
            .find(|node| !self.dead.contains(*node))
            .cloned()
    }

    /// 报告 `node` 失败（逻辑毫秒 `now_ms`）。
    ///
    /// - 累加连续失败计数并记录 `last_failure_ms`；
    /// - 若失败节点即当前 active：按 standby 列表顺序切到下一个尚未失败的备节点
    ///   （`FailingOver{from,to}` -> `Standby{node}`，同步骨架内直接落 `Standby`）；
    ///   无可用备节点 -> `Failed`；
    /// - 若失败节点不是 active：仅把它记入失败集合（后续选备时跳过）。
    pub fn report_failure(&mut self, node: &str, now_ms: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure_ms = Some(now_ms);
        self.dead.insert(node.to_string());

        // 已经整体失败：不再切换。
        if self.state == FailoverState::Failed {
            return;
        }
        // 失败节点不是当前 active：不切换。
        if node != self.active {
            return;
        }

        match self.next_standby() {
            Some(next) => {
                // FailingOver{from,to} 为同步瞬时态，此处直接落 Standby{next}。
                self.state = FailoverState::Standby { node: next.clone() };
                self.active = next;
            }
            None => {
                self.state = FailoverState::Failed;
            }
        }
    }

    /// 报告 `node` 恢复（逻辑毫秒 `now_ms`）。
    ///
    /// - `auto_failback=true` 且 `node==primary_node` 且当前不在 Primary
    ///   -> 切回 Primary、active=primary、清零连续失败与失败集合；
    /// - 否则仅把该节点从失败集合移除（标记为可用），不主动切换。
    pub fn report_recovery(&mut self, node: &str, _now_ms: u64) {
        self.dead.remove(node);

        if self.config.auto_failback
            && node == self.config.primary_node
            && self.state != FailoverState::Primary
        {
            // 主节点恢复：自动切回 Primary。
            self.state = FailoverState::Primary;
            self.active = self.config.primary_node.clone();
            self.consecutive_failures = 0;
            self.dead.clear();
        }
    }
}

// === 12.40.2 消费健康事件流驱动主备切换（additive） ============================

use crate::health_check::{HealthEvent, HealthState};

impl FailoverManager {
    /// 消费一条健康事件（PRODUCT §12.40.2），驱动既有 `report_failure` /
    /// `report_recovery`，不改既有切换/回切语义：
    /// - `event.to == Unhealthy` -> `report_failure(node_id, now_ms)`；
    /// - `event.to == Healthy`   -> `report_recovery(node_id, now_ms)`；
    /// - `event.to == Degraded`  -> 忽略（不切换）。
    pub fn apply_health_event(&mut self, event: &HealthEvent, now_ms: u64) {
        match event.to {
            HealthState::Unhealthy => self.report_failure(&event.node_id, now_ms),
            HealthState::Healthy => self.report_recovery(&event.node_id, now_ms),
            HealthState::Degraded => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(standby: Vec<&str>, auto_failback: bool) -> FailoverConfig {
        FailoverConfig::new(
            "primary",
            standby.into_iter().map(str::to_string).collect(),
            auto_failback,
        )
        .expect("valid config")
    }

    #[test]
    fn starts_on_primary() {
        let mgr = FailoverManager::new(cfg(vec!["s1", "s2"], false));
        assert_eq!(mgr.active_node(), "primary");
        assert_eq!(mgr.state().as_str(), "primary");
        assert_eq!(mgr.consecutive_failures(), 0);
        assert_eq!(mgr.last_failure_ms(), None);
    }

    #[test]
    fn primary_failure_switches_to_first_standby() {
        let mut mgr = FailoverManager::new(cfg(vec!["s1", "s2"], false));
        mgr.report_failure("primary", 1000);
        assert_eq!(mgr.active_node(), "s1");
        assert_eq!(mgr.state().as_str(), "standby");
        assert_eq!(mgr.consecutive_failures(), 1);
        assert_eq!(mgr.last_failure_ms(), Some(1000));
    }

    #[test]
    fn consecutive_failures_walk_through_standbys() {
        let mut mgr = FailoverManager::new(cfg(vec!["s1", "s2"], false));
        mgr.report_failure("primary", 1000);
        assert_eq!(mgr.active_node(), "s1");
        // 当前 active=s1 再失败 -> 退到 s2。
        mgr.report_failure("s1", 2000);
        assert_eq!(mgr.active_node(), "s2");
        assert_eq!(mgr.state().as_str(), "standby");
        // s2 也失败 -> 无可用备 -> Failed。
        mgr.report_failure("s2", 3000);
        assert_eq!(mgr.state().as_str(), "failed");
        assert_eq!(mgr.consecutive_failures(), 3);
    }

    #[test]
    fn no_standby_goes_failed() {
        let mut mgr = FailoverManager::new(cfg(vec![], false));
        mgr.report_failure("primary", 1000);
        assert_eq!(mgr.state().as_str(), "failed");
        assert_eq!(mgr.active_node(), "primary");
    }

    #[test]
    fn standby_failure_not_active_does_not_switch() {
        let mut mgr = FailoverManager::new(cfg(vec!["s1", "s2"], false));
        // s2 先失败（不是 active）：不切换，但记入失败集合。
        mgr.report_failure("s2", 1000);
        assert_eq!(mgr.active_node(), "primary");
        assert_eq!(mgr.state().as_str(), "primary");
        // primary 失败时跳过已失败的 s2，直接选 s1。
        mgr.report_failure("primary", 2000);
        assert_eq!(mgr.active_node(), "s1");
    }

    #[test]
    fn auto_failback_switches_back_to_primary() {
        let mut mgr = FailoverManager::new(cfg(vec!["s1"], true));
        mgr.report_failure("primary", 1000);
        assert_eq!(mgr.active_node(), "s1");
        // primary 恢复：auto_failback=true -> 切回。
        mgr.report_recovery("primary", 2000);
        assert_eq!(mgr.active_node(), "primary");
        assert_eq!(mgr.state().as_str(), "primary");
        assert_eq!(mgr.consecutive_failures(), 0);
    }

    #[test]
    fn no_auto_failback_stays_on_standby() {
        let mut mgr = FailoverManager::new(cfg(vec!["s1"], false));
        mgr.report_failure("primary", 1000);
        assert_eq!(mgr.active_node(), "s1");
        // auto_failback=false：primary 恢复不切回。
        mgr.report_recovery("primary", 2000);
        assert_eq!(mgr.active_node(), "s1");
        assert_eq!(mgr.state().as_str(), "standby");
    }

    #[test]
    fn empty_primary_rejected() {
        let err = FailoverConfig::new("", vec!["s1".into()], false).unwrap_err();
        assert!(matches!(err, FailoverError::InvalidPrimary { .. }));
        assert!(err.to_string().starts_with("FAILOVER_INVALID_PRIMARY:"));
    }

    #[test]
    fn standby_containing_primary_rejected() {
        let err = FailoverConfig::new("primary", vec!["primary".into()], false).unwrap_err();
        assert!(matches!(err, FailoverError::InvalidStandby { .. }));
    }

    #[test]
    fn duplicate_standby_rejected() {
        let err =
            FailoverConfig::new("primary", vec!["s1".into(), "s1".into()], false).unwrap_err();
        assert!(matches!(err, FailoverError::InvalidStandby { .. }));
    }

    #[test]
    fn empty_standby_rejected() {
        let err = FailoverConfig::new("primary", vec!["".into()], false).unwrap_err();
        assert!(matches!(err, FailoverError::InvalidStandby { .. }));
    }

    #[test]
    fn as_str_and_display() {
        assert_eq!(FailoverState::Primary.as_str(), "primary");
        assert_eq!(
            FailoverState::Standby { node: "x".into() }.as_str(),
            "standby"
        );
        assert_eq!(FailoverState::Failed.as_str(), "failed");
        assert_eq!(FailoverState::Primary.to_string(), "primary");
    }
}
