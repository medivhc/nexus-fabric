//! 出站 UDP 能力声明（spec §2.6，v1.3 起为共享配置 DTO）。
//!
//! 本模块只承载能力声明（Supported / Unsupported + 承载模式），不含运行时状态，
//! 也不发起任何 I/O；消费方是 daemon / adapter 层。三类型均为本 crate 的 `pub`
//! API，`apps/nexusd/src/proxy_fwd/adapter/mod.rs` 只做 `pub(crate) use` re-export。

use std::net::SocketAddr;

/// 出站 UDP 能力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpCapability {
    /// 可经该模式转发 UDP。
    Supported(UdpMode),
    /// 不可转发；`reason` 用于统计与限频日志分类。
    Unsupported { reason: UdpUnsupportedReason },
}

/// UDP 承载模式。
///
/// `Debug` 手写：`ShadowsocksAead::password` 输出 `***`，禁止 `#[derive(Debug)]`。
/// v1.3 新增变体无 password 字段、只输出 `server`，仍不得改回 derive。
#[derive(Clone, PartialEq, Eq)]
pub enum UdpMode {
    /// SOCKS5 UDP ASSOCIATE。
    Socks5Associate { server: SocketAddr },
    /// Shadowsocks AEAD（每包独立 salt）。
    ShadowsocksAead {
        server: SocketAddr,
        password: String,
    },
    /// VLESS over TCP（additive；本 run 未接线，消费在 fixes-6）。
    VlessOverTcp { server: SocketAddr },
    /// AnyTLS UoT（additive；本 run 未接线）。
    AnytlsUot { server: SocketAddr },
    /// Trojan UDP over TLS（additive；本 run 未接线）。
    TrojanUdpOverTls { server: SocketAddr },
    /// Hysteria2 datagram（additive；本 run 未接线）。
    Hysteria2Datagram { server: SocketAddr },
}

impl std::fmt::Debug for UdpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socks5Associate { server } => f
                .debug_struct("Socks5Associate")
                .field("server", server)
                .finish(),
            Self::ShadowsocksAead { server, .. } => f
                .debug_struct("ShadowsocksAead")
                .field("server", server)
                .field("password", &"***")
                .finish(),
            Self::VlessOverTcp { server } => f
                .debug_struct("VlessOverTcp")
                .field("server", server)
                .finish(),
            Self::AnytlsUot { server } => {
                f.debug_struct("AnytlsUot").field("server", server).finish()
            }
            Self::TrojanUdpOverTls { server } => f
                .debug_struct("TrojanUdpOverTls")
                .field("server", server)
                .finish(),
            Self::Hysteria2Datagram { server } => f
                .debug_struct("Hysteria2Datagram")
                .field("server", server)
                .finish(),
        }
    }
}

/// UDP 不可用原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpUnsupportedReason {
    /// 协议有 crate 级 UDP 实现，但本 run 未接（VLESS/AnyTLS）。
    NotWired,
    /// 协议只有 TLS 变体、UDP 路径未实现（当前 trojan-tls）。
    TlsVariantNotSupported,
    /// 协议无 datagram 模式（保留）。
    NoDatagramMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> SocketAddr {
        "127.0.0.1:8388".parse().expect("server addr")
    }

    #[test]
    fn udp_mode_debug_redacts_password() {
        let mode = UdpMode::ShadowsocksAead {
            server: server(),
            password: "super-secret-password".to_string(),
        };
        let text = format!("{mode:?}");
        assert!(
            !text.contains("super-secret-password"),
            "password must never appear in Debug: {text}"
        );
        assert!(text.contains("***"), "password placeholder missing: {text}");
        assert!(text.contains("127.0.0.1:8388"), "server missing: {text}");
    }

    #[test]
    fn udp_capability_debug_does_not_leak_password() {
        let capability = UdpCapability::Supported(UdpMode::ShadowsocksAead {
            server: server(),
            password: "another-secret".to_string(),
        });
        let text = format!("{capability:?}");
        assert!(!text.contains("another-secret"), "{text}");
        assert!(text.contains("***"), "{text}");
    }

    #[test]
    fn additive_modes_only_render_server() {
        for mode in [
            UdpMode::VlessOverTcp { server: server() },
            UdpMode::AnytlsUot { server: server() },
            UdpMode::TrojanUdpOverTls { server: server() },
            UdpMode::Hysteria2Datagram { server: server() },
        ] {
            let text = format!("{mode:?}");
            assert!(text.contains("127.0.0.1:8388"), "{text}");
            assert!(!text.contains("password"), "{text}");
        }
    }

    #[test]
    fn unsupported_reasons_are_distinct() {
        assert_ne!(
            UdpUnsupportedReason::NotWired,
            UdpUnsupportedReason::TlsVariantNotSupported
        );
        assert_ne!(
            UdpUnsupportedReason::TlsVariantNotSupported,
            UdpUnsupportedReason::NoDatagramMode
        );
        assert_eq!(
            UdpCapability::Unsupported {
                reason: UdpUnsupportedReason::TlsVariantNotSupported
            },
            UdpCapability::Unsupported {
                reason: UdpUnsupportedReason::TlsVariantNotSupported
            }
        );
    }
}
