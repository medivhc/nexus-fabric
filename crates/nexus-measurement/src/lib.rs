//! nexus-measurement
//!
//! 定义并维护 RTT、Loss、Jitter、Throughput、Load、Battery、Storage 等事实 Measurement。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_MEASUREMENT_MODULE: &str = "nexus-measurement";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "定义并维护 RTT、Loss、Jitter、Throughput、Load、Battery、Storage 等事实 Measurement。"
}
