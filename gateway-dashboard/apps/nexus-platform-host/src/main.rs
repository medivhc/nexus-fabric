#![forbid(unsafe_code)]

//! Nexus 平台组合根：装配平台 Capability Adapter，暴露只读能力命令。
//!
//! 子命令：
//! - `vpi-capabilities [--json]`：输出 Windows VirtualPacketInterface 能力
//!   声明（静态契约，不创建驱动对象），供 E4 scenario 机检。

#[cfg(feature = "platform-windows")]
use nexus_platform::PacketInterfaceCapabilities;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        #[cfg(feature = "platform-windows")]
        Some("vpi-capabilities") => print_vpi_capabilities(),
        _ => println!("nexus-platform-host: repository-contract bootstrap"),
    }
}

/// 输出 VPI 能力声明的固定结构 JSON（零第三方依赖；字段全为字面量）。
#[cfg(feature = "platform-windows")]
fn print_vpi_capabilities() {
    let c: PacketInterfaceCapabilities = nexus_platform_windows::WintunVpiAdapter::capabilities();
    let json = format!(
        concat!(
            "{{",
            "\"backend\":\"{}\",",
            "\"portable_consumer\":\"nexus-ingress\",",
            "\"adapter_api\":\"nexus-platform-windows\",",
            "\"mtu\":{},",
            "\"capabilities\":{{",
            "\"packet_ingress\":{},\"packet_injection\":{},\"ipv4\":{},\"ipv6\":{},",
            "\"route_include\":{},\"route_exclude\":{},\"dns_override\":{},",
            "\"mtu_configurable\":{},\"per_app_routing\":{},\"underlay_bypass\":{}",
            "}}",
            "}}"
        ),
        nexus_platform_windows::WintunVpiAdapter::backend(),
        nexus_platform_windows::WintunVpiAdapter::mtu(),
        bool_json(c.packet_ingress),
        bool_json(c.packet_injection),
        bool_json(c.ipv4),
        bool_json(c.ipv6),
        bool_json(c.route_include),
        bool_json(c.route_exclude),
        bool_json(c.dns_override),
        bool_json(c.mtu_configurable),
        bool_json(c.per_app_routing),
        bool_json(c.underlay_bypass),
    );
    println!("{json}");
}

#[cfg(feature = "platform-windows")]
fn bool_json(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}
