//! nexus-auth
//!
//! 定义 Resource Authorization、Principal 与类型化权限判定。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_AUTH_MODULE: &str = "nexus-auth";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "定义 Resource Authorization、Principal 与类型化权限判定。"
}
