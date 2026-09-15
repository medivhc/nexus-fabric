//! nexus-ingress
//!
//! 系统级、可移植的输入组件：提供 SOCKS5/HTTP 代理协议状态机与 Packet/Stream
//! 解码后的 Flow Classification 与中立 `FlowContext` 构造。
//!
//! 边界（ARCHITECTURE §2 / §10）：
//! - 只产出中立 `FlowContext` 并提交给 SessionManager / Application Layer；
//! - 不直接调用 Core Planner，不是 nexus-network 的私有子模块；
//! - 不持有平台专有透明拦截实现（那属于 nexus-platform-*）。
//!
//! 本 crate 是 Portable Core：纯函数、零 I/O、零第三方依赖，可编译到 WASI。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use nexus_domain::{FlowContext, FlowOrigin, ResourceId};

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_INGRESS_MODULE: &str = "nexus-ingress";

/// InternetAccess 对应的 Network Resource 标识。
pub const INTERNET_ACCESS_RESOURCE: &str = "internet-access";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "便携 Flow Classification 与中立 FlowContext 构造（不调用 Planner、不做平台拦截）。"
}

/// 由指定来源构造一个中立 FlowContext（内部统一构造点，保证字段一致）。
#[must_use]
fn classify(origin: FlowOrigin, destination: &str, profile: &str) -> FlowContext {
    FlowContext {
        origin,
        resource: ResourceId(INTERNET_ACCESS_RESOURCE.into()),
        destination: destination.to_string(),
        profile: profile.to_string(),
    }
}

/// 来自 SOCKS5 协议状态机的流。
#[must_use]
pub fn from_socks5(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::Socks5, destination, profile)
}

/// 来自 HTTP 代理协议状态机的流。
#[must_use]
pub fn from_http(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::Http, destination, profile)
}

/// 来自虚拟包接口（VPI）的包/流；平台拦截实现在 nexus-platform-*。
#[must_use]
pub fn from_virtual_packet_interface(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::VirtualPacketInterface, destination, profile)
}

/// 来自进程内 Native API 的直接提交。
#[must_use]
pub fn from_native_api(destination: &str, profile: &str) -> FlowContext {
    classify(FlowOrigin::NativeApi, destination, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_origin_and_stays_neutral() {
        let f = from_socks5("example.invalid:443", "Balanced");
        assert_eq!(f.origin, FlowOrigin::Socks5);
        assert_eq!(f.resource, ResourceId(INTERNET_ACCESS_RESOURCE.into()));
        assert_eq!(f.destination, "example.invalid:443");
        assert_eq!(from_http("h", "p").origin, FlowOrigin::Http);
        assert_eq!(
            from_virtual_packet_interface("h", "p").origin,
            FlowOrigin::VirtualPacketInterface
        );
        assert_eq!(from_native_api("h", "p").origin, FlowOrigin::NativeApi);
    }

    #[test]
    fn ingress_does_not_carry_path_or_provider() {
        let f = from_native_api("h", "p");
        // 中立上下文只含 resource/destination/profile，编译期即无 Path/Provider 字段可设。
        assert_eq!(f.profile, "p");
    }
}
