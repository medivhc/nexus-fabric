//! nexus-discovery
//!
//! 执行 Bootstrap、Peer Discovery、Endpoint/Candidate Exchange 与 Presence 建立。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_DISCOVERY_MODULE: &str = "nexus-discovery";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "执行 Bootstrap、Peer Discovery、Endpoint/Candidate Exchange 与 Presence 建立。"
}
