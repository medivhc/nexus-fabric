//! nexus-planner
//!
//! 唯一系统级 Planner：根据 Resource + Intent + Constraint 决定 Provider、Placement、Path、Execution Strategy，并生成 DecisionTrace。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_PLANNER_MODULE: &str = "nexus-planner";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "唯一系统级 Planner：根据 Resource + Intent + Constraint 决定 Provider、Placement、Path、Execution Strategy，并生成 DecisionTrace。"
}
