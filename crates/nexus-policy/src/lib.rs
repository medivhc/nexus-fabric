//! nexus-policy
//!
//! 把 Flow/Resource Context 转换为 Intent 与 Constraint。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_POLICY_MODULE: &str = "nexus-policy";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "把 Flow/Resource Context 转换为 Intent 与 Constraint。"
}
