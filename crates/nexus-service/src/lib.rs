//! nexus-service
//!
//! 实现 Service Resource 的解析、授权后的连接、connect/forward 与服务会话行为。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_SERVICE_MODULE: &str = "nexus-service";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 Service Resource 的解析、授权后的连接、connect/forward 与服务会话行为。"
}
