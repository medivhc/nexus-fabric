//! nexus-platform-ios
//!
//! 实现 iOS 平台 Capability Adapter，包括 Packet Tunnel Extension、移动生命周期、文件投影与安全存储桥接。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_PLATFORM_IOS_MODULE: &str = "nexus-platform-ios";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "实现 iOS 平台 Capability Adapter，包括 Packet Tunnel Extension、移动生命周期、文件投影与安全存储桥接。"
}
