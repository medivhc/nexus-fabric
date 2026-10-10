//! 节点分组隔离（内存骨架，纯逻辑）。
//!
//! 本模块是 delivery 层共享底座的节点分组隔离骨架：
//! - **隔离模式**：`IsolationMode` 二态——`Full`（按组隔离）/ `None`（全开，不隔离）；
//! - **组配置**：`GroupConfig` 声明一个具名隔离组（组名 + 该组隔离模式）；
//! - **归属**：`GroupIsolation::assign` 把节点划入已声明的组；
//! - **例外**：`allow_exception` 登记一条单向跨组放行（src_group 可访问 dst_group）；
//! - **决策**：`check` 对 (src_node, dst_node) 返回 `AccessDecision`（Allow / Deny）。
//!
//! 决策规则（`IsolationMode::Full` 下）：
//! 1. 任一节点未分配组 → `Deny`；
//! 2. 两节点同组 → `Allow`；
//! 3. 跨组且例外表存在 `(src_group, dst_group)` → `Allow`；
//! 4. 其余跨组 → `Deny`。
//! `IsolationMode::None` 下一律 `Allow`（含未分配节点）。
//!
//! 边界（PRODUCT §12-group-isolation 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不接真实网络、不做真实 ACL 下发；
//! - 组必须先 `define_group` 声明后才能 `assign` 节点，否则视为未知组；
//! - 例外是单向（src→dst），不自动对称；组名空串视为非法；
//! - 真实 ACL 下发、规则热更新、与防火墙规则联动留 TODO。
//!
//! TODO（真实网络集成，非本骨架范围）：
//! - 在 `firewall` 中把 `check` 决策物化为真实包过滤规则；
//! - 在节点发现（`nexus-discovery`）注册/心跳时携带所属组；
//! - 与 `node_tags` 的 region/role 维度组合成复合隔离策略；
//! - 规则持久化与 crash 后 reconcile（幂等重建组/例外表）。
//!
//! 错误面独立：`GroupIsolationError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------- 错误 ----------

/// 节点分组隔离相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupIsolationError {
    /// 组名为空（非法）。
    InvalidGroupName {
        /// 非法组名（人可读，通常为空串）。
        name: String,
    },
    /// 把节点划入一个未声明的未知组。
    UnknownGroup {
        /// 未知组名。
        name: String,
    },
}

impl fmt::Display for GroupIsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGroupName { name } => {
                write!(
                    f,
                    "GROUP_ISOLATION_INVALID_GROUP_NAME: group name must not be empty (got {name:?})"
                )
            }
            Self::UnknownGroup { name } => {
                write!(
                    f,
                    "GROUP_ISOLATION_UNKNOWN_GROUP: group {name:?} is not declared; call define_group first"
                )
            }
        }
    }
}

impl std::error::Error for GroupIsolationError {}

// ---------- 隔离模式 ----------

/// 节点分组隔离模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationMode {
    /// 按组隔离：同组互通、跨组默认拒绝、例外放行。
    Full,
    /// 全开：不做任何隔离，一律放行（含未分配节点）。
    None,
}

impl IsolationMode {
    /// 返回稳定字符串表示（"full" / "none"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::None => "none",
        }
    }
}

impl fmt::Display for IsolationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 访问决策 ----------

/// 一次跨节点访问的决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// 放行。
    Allow,
    /// 拒绝。
    Deny,
}

impl AccessDecision {
    /// 返回稳定字符串表示（"allow" / "deny"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl fmt::Display for AccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 组配置 ----------

/// 单个隔离组的配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupConfig {
    /// 组名（非空唯一标识，如 `prod`、`dev`）。
    pub group_name: String,
    /// 该组的隔离模式（本骨架下决策以管理器全局模式为准，此字段为组级元数据）。
    pub mode: IsolationMode,
}

impl GroupConfig {
    /// 构造组配置；`group_name` 为空返回 `InvalidGroupName`。
    pub fn new(
        group_name: impl Into<String>,
        mode: IsolationMode,
    ) -> Result<Self, GroupIsolationError> {
        let group_name = group_name.into();
        if group_name.is_empty() {
            return Err(GroupIsolationError::InvalidGroupName { name: group_name });
        }
        Ok(Self { group_name, mode })
    }
}

// ---------- 管理器 ----------

/// 节点分组隔离管理器：持有组注册表、节点归属与跨组例外表，纯内存纯逻辑。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupIsolation {
    /// 全局隔离模式（`None` 时一律放行）。
    mode: IsolationMode,
    /// 已声明的组注册表（组名 → 组配置）。
    groups: HashMap<String, GroupConfig>,
    /// 节点归属（node_id → group_name）。
    nodes: HashMap<String, String>,
    /// 单向跨组例外（src_group, dst_group），登记即放行。
    exceptions: HashSet<(String, String)>,
}

impl GroupIsolation {
    /// 构造空管理器（无组、无节点、无例外），按给定全局模式。
    #[must_use]
    pub fn new(mode: IsolationMode) -> Self {
        Self {
            mode,
            groups: HashMap::new(),
            nodes: HashMap::new(),
            exceptions: HashSet::new(),
        }
    }

    /// 声明一个隔离组（幂等：重复声明同名组会覆盖其配置）。
    pub fn define_group(&mut self, config: GroupConfig) {
        self.groups.insert(config.group_name.clone(), config);
    }

    /// 把节点划入指定组。
    ///
    /// 失败：
    /// - `group_name` 为空 → `InvalidGroupName`；
    /// - `group_name` 未通过 `define_group` 声明 → `UnknownGroup`。
    pub fn assign(&mut self, node_id: &str, group_name: &str) -> Result<(), GroupIsolationError> {
        if group_name.is_empty() {
            return Err(GroupIsolationError::InvalidGroupName {
                name: group_name.to_string(),
            });
        }
        if !self.groups.contains_key(group_name) {
            return Err(GroupIsolationError::UnknownGroup {
                name: group_name.to_string(),
            });
        }
        self.nodes
            .insert(node_id.to_string(), group_name.to_string());
        Ok(())
    }

    /// 登记一条单向跨组例外：`src_group` 可访问 `dst_group`。
    ///
    /// 幂等；不校验组是否已声明（允许先登记例外再声明组）。
    pub fn allow_exception(&mut self, src_group: &str, dst_group: &str) {
        self.exceptions
            .insert((src_group.to_string(), dst_group.to_string()));
    }

    /// 查询节点所属组（未分配返回 `None`）。
    #[must_use]
    pub fn node_group(&self, node_id: &str) -> Option<&str> {
        self.nodes.get(node_id).map(String::as_str)
    }

    /// 已登记的跨组例外条数。
    #[must_use]
    pub fn exception_count(&self) -> usize {
        self.exceptions.len()
    }

    /// 对 (src_node, dst_node) 做访问决策。
    ///
    /// 规则见模块头 `//!`：
    /// - `None` 模式 → 一律 `Allow`；
    /// - 任一节点未分配 → `Deny`；
    /// - 同组 → `Allow`；
    /// - 例外表含 `(src_group, dst_group)` → `Allow`；
    /// - 其余跨组 → `Deny`。
    #[must_use]
    pub fn check(&self, src_node: &str, dst_node: &str) -> AccessDecision {
        if self.mode == IsolationMode::None {
            return AccessDecision::Allow;
        }
        let (Some(src), Some(dst)) = (self.node_group(src_node), self.node_group(dst_node)) else {
            return AccessDecision::Deny;
        };
        if src == dst {
            return AccessDecision::Allow;
        }
        if self
            .exceptions
            .contains(&(src.to_string(), dst.to_string()))
        {
            return AccessDecision::Allow;
        }
        AccessDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> GroupIsolation {
        let mut mgr = GroupIsolation::new(IsolationMode::Full);
        mgr.define_group(GroupConfig::new("prod", IsolationMode::Full).unwrap());
        mgr.define_group(GroupConfig::new("dev", IsolationMode::Full).unwrap());
        mgr.assign("prod-a", "prod").unwrap();
        mgr.assign("prod-b", "prod").unwrap();
        mgr.assign("dev-a", "dev").unwrap();
        mgr.assign("dev-b", "dev").unwrap();
        mgr
    }

    #[test]
    fn same_group_is_allowed() {
        let mgr = make_manager();
        assert_eq!(mgr.node_group("prod-a"), Some("prod"));
        assert_eq!(mgr.check("prod-a", "prod-b"), AccessDecision::Allow);
    }

    #[test]
    fn cross_group_is_deny_by_default() {
        let mgr = make_manager();
        assert_eq!(mgr.check("prod-a", "dev-a"), AccessDecision::Deny);
    }

    #[test]
    fn exception_allows_cross_group() {
        let mut mgr = make_manager();
        assert_eq!(mgr.check("prod-a", "dev-a"), AccessDecision::Deny);
        mgr.allow_exception("prod", "dev");
        assert_eq!(mgr.exception_count(), 1);
        assert_eq!(mgr.check("prod-a", "dev-a"), AccessDecision::Allow);
        // 单向：dev→prod 仍拒绝（不自动对称）。
        assert_eq!(mgr.check("dev-a", "prod-a"), AccessDecision::Deny);
    }

    #[test]
    fn open_mode_allows_everything() {
        let mgr = GroupIsolation::new(IsolationMode::None);
        // 含未分配节点也一律放行。
        assert_eq!(mgr.check("prod-a", "dev-a"), AccessDecision::Allow);
        assert_eq!(mgr.check("ghost", "nobody"), AccessDecision::Allow);
        assert_eq!(IsolationMode::None.as_str(), "none");
    }

    #[test]
    fn unassigned_node_is_denied() {
        let mgr = make_manager();
        assert_eq!(mgr.node_group("ghost"), None);
        assert_eq!(mgr.check("prod-a", "ghost"), AccessDecision::Deny);
        assert_eq!(mgr.check("ghost", "dev-a"), AccessDecision::Deny);
    }

    #[test]
    fn empty_group_name_rejected() {
        let err = GroupConfig::new("", IsolationMode::Full).unwrap_err();
        assert!(matches!(err, GroupIsolationError::InvalidGroupName { .. }));

        let mut mgr = make_manager();
        let err = mgr.assign("x", "").unwrap_err();
        assert!(matches!(err, GroupIsolationError::InvalidGroupName { .. }));
    }

    #[test]
    fn unknown_group_assign_rejected() {
        let mut mgr = make_manager();
        let err = mgr.assign("x", "ghost").unwrap_err();
        assert!(matches!(
            err,
            GroupIsolationError::UnknownGroup { name } if name == "ghost"
        ));
        // 未知组失败后该节点仍未分配。
        assert_eq!(mgr.node_group("x"), None);
    }

    #[test]
    fn as_str_stable_and_display_roundtrip() {
        assert_eq!(IsolationMode::Full.as_str(), "full");
        assert_eq!(AccessDecision::Allow.as_str(), "allow");
        assert_eq!(AccessDecision::Deny.as_str(), "deny");
        assert_eq!(AccessDecision::Allow.to_string(), "allow");
    }

    #[test]
    fn error_display_is_structured() {
        let err = GroupIsolationError::UnknownGroup {
            name: "prod".into(),
        };
        assert!(
            err.to_string()
                .starts_with("GROUP_ISOLATION_UNKNOWN_GROUP:")
        );
    }
}
