//! Linux VirtualPacketInterface：/dev/net/tun 数据面。
//!
//! 本模块不含 `unsafe`（全部集中在 `tun.rs`）；名称校验、错误映射为纯逻辑，
//! 可直接单测。TUN 设备创建需 root / CAP_NET_ADMIN（PRODUCT §12.17）。

use crate::tun::{IFNAMSIZ, TunFd};
use nexus_platform::{PacketInterfaceCapabilities, PlatformError, VirtualPacketInterface};

/// 建议 MTU（对齐 Windows wintun 惯例）。
pub const DEFAULT_MTU: u16 = 1420;

/// 后端标识（供组合根/诊断输出）。
pub const BACKEND: &str = "tun";

/// 接口名最大字节数（不含 NUL）。
pub const MAX_NAME_BYTES: usize = IFNAMSIZ - 1;

/// Linux TUN 设备（fd 所有权 + 名称）。
///
/// 生命周期：`TunFd` 的 Drop 负责 `close`；本结构为薄包装。
pub struct TunVpi {
    fd: TunFd,
    name: String,
}

impl TunVpi {
    /// 校验接口名（纯函数）：非空、≤15 字节、不含 NUL。
    pub fn validate_name(name: &str) -> Result<(), PlatformError> {
        if name.is_empty() {
            return Err(PlatformError::Invalid {
                message: "tun name is empty".into(),
            });
        }
        if name.len() >= IFNAMSIZ {
            return Err(PlatformError::Invalid {
                message: format!(
                    "tun name too long: {} bytes (max {MAX_NAME_BYTES})",
                    name.len()
                ),
            });
        }
        if name.as_bytes().contains(&0) {
            return Err(PlatformError::Invalid {
                message: "tun name contains NUL".into(),
            });
        }
        Ok(())
    }

    /// 创建并打开命名 TUN 设备（需 root / CAP_NET_ADMIN）。
    pub fn create(name: &str) -> Result<Self, PlatformError> {
        Self::validate_name(name).map_err(|e| PlatformError::Invalid {
            message: e.to_string(),
        })?;
        let fd = TunFd::open_tun(name.as_bytes()).map_err(|e| PlatformError::Io {
            operation: "tun open".into(),
            message: e.to_string(),
        })?;
        Ok(TunVpi {
            fd,
            name: name.to_string(),
        })
    }

    /// 静态能力声明（tun 能力面）。
    #[must_use]
    pub const fn capabilities() -> PacketInterfaceCapabilities {
        PacketInterfaceCapabilities {
            packet_ingress: true,
            packet_injection: true,
            ipv4: true,
            ipv6: true,
            route_include: true,
            route_exclude: true,
            dns_override: false,
            mtu_configurable: true,
            per_app_routing: false,
            underlay_bypass: true,
        }
    }

    /// 建议 MTU。
    #[must_use]
    pub const fn mtu() -> u16 {
        DEFAULT_MTU
    }

    /// 后端标识。
    #[must_use]
    pub const fn backend() -> &'static str {
        BACKEND
    }

    /// 接口名。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl VirtualPacketInterface for TunVpi {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        self.fd.read_frame(output).map_err(|e| PlatformError::Io {
            operation: "tun read".into(),
            message: e.to_string(),
        })
    }

    fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
        if packet.is_empty() {
            return Err(PlatformError::Invalid {
                message: "cannot send empty packet".into(),
            });
        }
        self.fd.write_frame(packet).map_err(|e| PlatformError::Io {
            operation: "tun write".into(),
            message: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation() {
        assert!(matches!(
            TunVpi::validate_name(""),
            Err(PlatformError::Invalid { .. })
        ));
        assert!(matches!(
            TunVpi::validate_name(&"x".repeat(IFNAMSIZ)),
            Err(PlatformError::Invalid { .. })
        ));
        assert!(matches!(
            TunVpi::validate_name("bad\0name"),
            Err(PlatformError::Invalid { .. })
        ));
        assert!(TunVpi::validate_name("nexus0").is_ok());
        assert!(TunVpi::validate_name(&"x".repeat(IFNAMSIZ - 1)).is_ok());
    }

    #[test]
    fn capabilities_surface() {
        let c = TunVpi::capabilities();
        assert!(c.packet_ingress && c.packet_injection && c.ipv4 && c.ipv6);
        assert!(!c.dns_override);
        assert_eq!(TunVpi::backend(), "tun");
        assert_eq!(TunVpi::mtu(), 1420);
    }
}
