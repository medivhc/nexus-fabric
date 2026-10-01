//! Windows IP 配置与路由管理（W-IPR）。
//!
//! 对标 Linux 的 `addr.rs`/`route.rs`，经 `netsh`/`route` 命令实现。
//! 安全 Rust（`std::process::Command`，无 unsafe），类比 `autostart.rs`
//! 的 `schtasks.exe` 模式。
//!
//! 契约见 `MODULE.md` § "Windows IP 配置与路由（W-IPR）"。

use nexus_platform::PlatformError;
use std::process::Command;

/// 把 prefix_len（如 24）转成子网掩码字符串（如 "255.255.255.0")。
///
/// `prefix_len` 范围 [0, 32]，非法返回 `PlatformError::Invalid`。
fn prefix_to_mask(prefix_len: u8) -> Result<String, PlatformError> {
    if prefix_len > 32 {
        return Err(PlatformError::Invalid {
            message: format!("prefix_len must be <= 32 (got {prefix_len})"),
        });
    }
    let bits = if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ok(format!(
        "{}.{}.{}.{}",
        (bits >> 24) & 0xff,
        (bits >> 16) & 0xff,
        (bits >> 8) & 0xff,
        bits & 0xff
    ))
}

/// 解析 CIDR（如 "10.200.0.0/24"）为 (network, mask)。
fn parse_cidr(cidr: &str) -> Result<(String, String), PlatformError> {
    let (net, prefix) = cidr.split_once('/').ok_or_else(|| PlatformError::Invalid {
        message: format!("cidr must be <ip>/<prefix> (got {cidr})"),
    })?;
    let prefix_len: u8 = prefix.parse().map_err(|_| PlatformError::Invalid {
        message: format!("invalid prefix in cidr (got {cidr})"),
    })?;
    let mask = prefix_to_mask(prefix_len)?;
    // 校验 network 是合法 IPv4
    let octets: Vec<&str> = net.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
        return Err(PlatformError::Invalid {
            message: format!("invalid ipv4 in cidr (got {cidr})"),
        });
    }
    Ok((net.to_string(), mask))
}

/// 构造 `assign_ip` 的 argv（单一真相源；执行与展示都用它）。
///
/// 返回 `None` 当 prefix_len 非法。
fn assign_ip_argv(iface: &str, ip: [u8; 4], prefix_len: u8) -> Option<Vec<String>> {
    let mask = prefix_to_mask(prefix_len).ok()?;
    let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    Some(vec![
        "interface".to_string(),
        "ip".to_string(),
        "set".to_string(),
        "address".to_string(),
        iface.to_string(),
        "static".to_string(),
        ip_str,
        mask,
    ])
}

/// 构造 `assign_ip` 的展示命令字符串（纯函数，可单元测试）。
///
/// 由 [`assign_ip_argv`] 派生，保证与真实执行一致。
#[must_use]
#[cfg(test)]
fn build_assign_ip_cmd(iface: &str, ip: [u8; 4], prefix_len: u8) -> Option<String> {
    let argv = assign_ip_argv(iface, ip, prefix_len)?;
    Some(format!("netsh {}", argv.join(" ")))
}

/// 构造 `add_route` 的 argv（单一真相源）。
fn add_route_argv(cidr: &str, gateway: &str, metric: u32) -> Option<Vec<String>> {
    let (network, mask) = parse_cidr(cidr).ok()?;
    Some(vec![
        "add".to_string(),
        network,
        "mask".to_string(),
        mask,
        gateway.to_string(),
        "metric".to_string(),
        metric.to_string(),
    ])
}

/// 构造 `add_route` 的展示命令字符串（纯函数，可单元测试）。
#[must_use]
#[cfg(test)]
fn build_add_route_cmd(cidr: &str, gateway: &str, metric: u32) -> Option<String> {
    let argv = add_route_argv(cidr, gateway, metric)?;
    Some(format!("route {}", argv.join(" ")))
}

/// 构造 `exclude_ip` 的 argv（/32，metric=1）。
fn exclude_ip_argv(ip: [u8; 4], gateway: &str) -> Vec<String> {
    let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    vec![
        "add".to_string(),
        ip_str,
        "mask".to_string(),
        "255.255.255.255".to_string(),
        gateway.to_string(),
        "metric".to_string(),
        "1".to_string(),
    ]
}

/// 构造 `exclude_ip` 的展示命令（/32，metric=1）。
#[must_use]
#[cfg(test)]
fn build_exclude_ip_cmd(ip: [u8; 4], gateway: &str) -> String {
    format!("route {}", exclude_ip_argv(ip, gateway).join(" "))
}

/// 执行一个命令，返回 stdout。失败时映射为 PlatformError::Io。
fn run_cmd(program: &str, args: &[&str], operation: &str) -> Result<(), PlatformError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| PlatformError::Io {
            operation: operation.to_string(),
            message: format!("failed to spawn {program}: {e}"),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let msg: String = stderr.chars().take(200).collect();
    Err(PlatformError::Io {
        operation: operation.to_string(),
        message: format!("{program} failed: {msg}"),
    })
}

/// 给 TUN 接口分配 IPv4 地址。
///
/// 等价：`netsh interface ip set address "<iface>" static <ip> <mask>`
pub fn assign_ip(iface: &str, ip: [u8; 4], prefix_len: u8) -> Result<(), PlatformError> {
    let argv = assign_ip_argv(iface, ip, prefix_len).ok_or_else(|| PlatformError::Invalid {
        message: format!("prefix_len must be <= 32 (got {prefix_len})"),
    })?;
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_cmd("netsh", &args, "assign_ip")
}

/// 删除 TUN 接口的 IPv4 地址。
///
/// 等价：`netsh interface ip delete address "<iface>" <ip>`
pub fn remove_ip(iface: &str, ip: [u8; 4]) -> Result<(), PlatformError> {
    let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    run_cmd(
        "netsh",
        &["interface", "ip", "delete", "address", iface, &ip_str],
        "remove_ip",
    )
}

/// 添加路由。
///
/// 等价：`route add <network> mask <netmask> <gateway> metric <metric>`
pub fn add_route(cidr: &str, gateway: &str, metric: u32) -> Result<(), PlatformError> {
    let argv = add_route_argv(cidr, gateway, metric).ok_or_else(|| PlatformError::Invalid {
        message: format!("invalid cidr (got {cidr})"),
    })?;
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_cmd("route", &args, "add_route")
}

/// 删除路由（不存在时视为成功，幂等）。
///
/// 等价：`route delete <network>`
pub fn delete_route(cidr: &str) -> Result<(), PlatformError> {
    let (network, _) = parse_cidr(cidr)?;
    match run_cmd("route", &["delete", &network], "delete_route") {
        Ok(()) => Ok(()),
        Err(PlatformError::Io { message, .. }) if message.contains("not found") => Ok(()),
        Err(e) => Err(e),
    }
}

/// 防回环：给代理服务器 IP 加 /32 路由，走物理网关，metric=1。
///
/// 等价：`route add <ip> mask 255.255.255.255 <gateway> metric 1`
pub fn exclude_ip(ip: [u8; 4], gateway: &str) -> Result<(), PlatformError> {
    let argv = exclude_ip_argv(ip, gateway);
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_cmd("route", &args, "exclude_ip")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_to_mask_24() {
        assert_eq!(prefix_to_mask(24).unwrap(), "255.255.255.0");
    }

    #[test]
    fn prefix_to_mask_16() {
        assert_eq!(prefix_to_mask(16).unwrap(), "255.255.0.0");
    }

    #[test]
    fn prefix_to_mask_32() {
        assert_eq!(prefix_to_mask(32).unwrap(), "255.255.255.255");
    }

    #[test]
    fn prefix_to_mask_0() {
        assert_eq!(prefix_to_mask(0).unwrap(), "0.0.0.0");
    }

    #[test]
    fn prefix_to_mask_invalid() {
        assert!(prefix_to_mask(33).is_err());
    }

    #[test]
    fn build_assign_ip_cmd_basic() {
        let cmd = build_assign_ip_cmd("nexus", [10, 200, 0, 5], 24).unwrap();
        assert_eq!(
            cmd,
            "netsh interface ip set address nexus static 10.200.0.5 255.255.255.0"
        );
    }

    #[test]
    fn build_assign_ip_cmd_invalid_prefix() {
        assert!(build_assign_ip_cmd("nexus", [10, 200, 0, 5], 33).is_none());
    }

    #[test]
    fn build_add_route_cmd_basic() {
        let cmd = build_add_route_cmd("10.200.0.0/24", "192.168.1.1", 10).unwrap();
        assert_eq!(
            cmd,
            "route add 10.200.0.0 mask 255.255.255.0 192.168.1.1 metric 10"
        );
    }

    #[test]
    fn build_add_route_cmd_invalid_cidr() {
        assert!(build_add_route_cmd("not-a-cidr", "192.168.1.1", 10).is_none());
        assert!(build_add_route_cmd("10.200.0.0/33", "192.168.1.1", 10).is_none());
    }

    #[test]
    fn build_exclude_ip_cmd_basic() {
        let cmd = build_exclude_ip_cmd([1, 2, 3, 4], "192.168.1.1");
        assert_eq!(
            cmd,
            "route add 1.2.3.4 mask 255.255.255.255 192.168.1.1 metric 1"
        );
    }

    #[test]
    fn parse_cidr_valid() {
        let (net, mask) = parse_cidr("10.200.0.0/24").unwrap();
        assert_eq!(net, "10.200.0.0");
        assert_eq!(mask, "255.255.255.0");
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("10.200.0.0").is_err());
        assert!(parse_cidr("10.200.0.0/33").is_err());
        assert!(parse_cidr("999.1.1.0/24").is_err());
    }
}
