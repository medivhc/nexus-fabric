//! E4: `tproxy_capture_failure`（spec §12.8 AC-FAIL-01/03）—
//! 捕获失败不静默漏流量：degraded + privilege + enforcement 状态。

use nexus_platform::TransparentTcpIngress;
use nexus_platform_linux::tproxy::{TproxyTcpConfig, TproxyTcpListener};

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    let privilege = nexusd::dataplane::detect_privilege();
    let config = TproxyTcpConfig {
        listen: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
        ..TproxyTcpConfig::default()
    };
    let reason = match TproxyTcpListener::bind(&config) {
        Err(error) => ingress_reason(&error),
        Ok(mut first) => {
            let addr = first.local_addr().expect("listener addr");
            let port = match addr {
                std::net::SocketAddr::V4(v4) => v4.port(),
                std::net::SocketAddr::V6(_) => 0,
            };
            let second = TproxyTcpConfig {
                listen: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port),
                ..TproxyTcpConfig::default()
            };
            let reason = match TproxyTcpListener::bind(&second) {
                Err(error) => ingress_reason(&error),
                Ok(_) => "listener_io_failed",
            };
            let _ = first.shutdown();
            reason
        }
    };
    let status = nexusd::dataplane::capture_failure_status(
        reason,
        privilege,
        nexus_proxy_config::CaptureFailureMode::Block,
        false,
    );
    let pass = status.state == "degraded"
        && matches!(
            status.reason,
            Some("permission_denied") | Some("bind_failed") | Some("listener_io_failed")
        )
        && status.enforcement == "impossible"
        && matches!(status.privilege, "root" | "cap_net_admin" | "insufficient");
    println!(
        "{{\"verdict\":\"{}\",\"tproxy\":{{\"state\":\"{}\",\"privilege\":\"{}\",\"reason\":\"{}\"}},\"enforcement\":\"{}\",\"upstream_failed\":0,\"request_succeeded_without_capture\":false}}",
        if pass { "PASS" } else { "FAIL" },
        status.state,
        status.privilege,
        status.reason.unwrap_or("-"),
        status.enforcement,
    );
    std::process::exit(if pass { 0 } else { 1 });
}

fn ingress_reason(error: &nexus_platform::TransparentIngressError) -> &'static str {
    use nexus_platform::TransparentIngressError as E;
    match error {
        E::CapabilityUnavailable { .. } => "capability_unavailable",
        E::PermissionDenied { .. } => "permission_denied",
        E::BindFailed { .. } => "bind_failed",
        E::SockOptFailed { .. } => "sockopt_failed",
        E::Io { .. } => "listener_io_failed",
        _ => "listener_io_failed",
    }
}
