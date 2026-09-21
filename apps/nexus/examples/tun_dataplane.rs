//! E4 产品场景 `product.tun-dataplane` 的可执行驱动（PRODUCT §12.29）。
//!
//! 由 `scenarios/product/tun_dataplane.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example tun_dataplane -- --json
//! ```
//!
//! `--real` 标志走真实 TUN 设备验收（E5，需管理员 + wintun.dll / /dev/net/tun）：
//! 创建命名适配器 → 能力声明 → 驱动版本 → 读一帧（超时返回）。

#![forbid(unsafe_code)]

use nexus::tun_dataplane_flow;
use nexus_platform::VirtualPacketInterface;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");
    let real = args.iter().any(|a| a == "--real");

    if real {
        run_real(&args);
        return;
    }

    match tun_dataplane_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("tun dataplane flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("tun_dataplane_flow failed: {err}");
            std::process::exit(1);
        }
    }
}

/// E5 真机验收：wintun 适配器创建 + 能力/版本 + 一次非阻塞读帧。
fn run_real(args: &[String]) {
    #[cfg(windows)]
    {
        let name = args
            .iter()
            .position(|a| a == "--tun-name")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| "nexus-e5".to_string());
        match nexus_platform_windows::WintunVpiAdapter::create(&name, "Nexus") {
            Ok(mut vpi) => {
                let caps = nexus_platform_windows::WintunVpiAdapter::capabilities();
                println!(
                    "{}",
                    serde_json::json!({
                        "verdict": "PASS",
                        "command": "tun real e5",
                        "backend": nexus_platform_windows::WintunVpiAdapter::backend(),
                        "mtu": nexus_platform_windows::WintunVpiAdapter::mtu(),
                        "driver_version": vpi.driver_version(),
                        "capabilities": {
                            "packet_ingress": caps.packet_ingress,
                            "packet_injection": caps.packet_injection,
                            "ipv4": caps.ipv4,
                            "ipv6": caps.ipv6,
                        },
                        "read_frame": {
                            "bytes": vpi.receive(&mut [0u8; 2048]).map(|n| n as u64).unwrap_or(0),
                        }
                    })
                );
            }
            Err(e) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "verdict": "TUN_ERROR",
                        "command": "tun real e5",
                        "error": e.to_string(),
                    })
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("--real TUN E5 only supported on Windows (wintun) in this build");
        std::process::exit(1);
    }
}
