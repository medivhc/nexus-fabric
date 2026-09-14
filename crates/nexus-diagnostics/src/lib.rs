//! nexus-diagnostics
//!
//! 定义统一诊断 DTO、诊断类别与低成本/深度诊断接口。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_DIAGNOSTICS_MODULE: &str = "nexus-diagnostics";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "定义统一诊断 DTO、诊断类别与低成本/深度诊断接口。"
}
