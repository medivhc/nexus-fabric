//! nexus-compute
//!
//! 实现 Compute Resource 的能力描述、估计输入、执行会话、Workspace Snapshot Pin、Artifact 与可选 Write-back。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_COMPUTE_MODULE: &str = "nexus-compute";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 Compute Resource 的能力描述、估计输入、执行会话、Workspace Snapshot Pin、Artifact 与可选 Write-back。"
}
