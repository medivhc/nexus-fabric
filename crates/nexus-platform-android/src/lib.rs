//! nexus-platform-android
//!
//! 实现 Android 平台 Capability Adapter，包括 VPN Service、underlay bypass、移动生命周期与文件访问桥接。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_PLATFORM_ANDROID_MODULE: &str = "nexus-platform-android";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 Android 平台 Capability Adapter，包括 VPN Service、underlay bypass、移动生命周期与文件访问桥接。"
}
