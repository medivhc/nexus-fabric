//! adapter 单元测试（选路顺序 / build_dialer 变体 / 错误映射）。
//!
//! 期望与 spec §2.4 / §2.6.1 对齐；VLESS 专属变体（MissingUuid / InvalidUuid /
//! UnsupportedFlow / VisionRequiresTls）在步骤 2 接线 VLESS 后覆盖。

use std::io;
use std::net::SocketAddr;

use nexus_proxy_config::{
    OutboundConfig, OutboundKind, UdpCapability, UdpMode, UdpUnsupportedReason,
};

use super::*;

fn outbound(kind: OutboundKind) -> OutboundConfig {
    OutboundConfig {
        tag: "test".to_string(),
        kind,
        locator: None,
        method: None,
        password: None,
        alpn: None,
        skip_cert_verify: None,
        header_format: None,
        obfs: None,
        obfs_key: None,
        uuid: None,
        flow: None,
        tls: None,
        servername: None,
        sni: None,
        ports: None,
        up: None,
        down: None,
        obfs_password: None,
        fallback_guard: None,
        ready_window_ms: None,
    }
}

fn build_error(config: &OutboundConfig) -> BuildDialerError {
    match build_dialer(config) {
        Ok(_) => panic!("expected build_dialer error"),
        Err(error) => error,
    }
}

fn config_error(error: BuildDialerError) -> OutboundConfigError {
    match error {
        BuildDialerError::Config(error) => error,
        BuildDialerError::ProtocolNotWired { kind } => {
            panic!(
                "expected config error, got ProtocolNotWired({})",
                kind.as_str()
            )
        }
    }
}

#[test]
fn build_socks5_declares_associate_udp() {
    let mut config = outbound(OutboundKind::Socks5);
    config.locator = Some("127.0.0.1:1080".to_string());
    let dialer = build_dialer(&config).expect("socks5 dialer");
    assert_eq!(dialer.kind(), OutboundKind::Socks5);
    assert_eq!(dialer.tag(), "test");
    let server: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    assert_eq!(
        dialer.udp_capability(),
        UdpCapability::Supported(UdpMode::Socks5Associate { server })
    );
}

#[test]
fn build_shadowsocks_declares_aead_udp_without_leaking_password_in_debug() {
    let mut config = outbound(OutboundKind::Shadowsocks);
    config.locator = Some("127.0.0.1:8388".to_string());
    config.password = Some("secret".to_string());
    let dialer = build_dialer(&config).expect("ss dialer");
    assert_eq!(dialer.kind(), OutboundKind::Shadowsocks);
    let capability = dialer.udp_capability();
    assert!(matches!(
        capability,
        UdpCapability::Supported(UdpMode::ShadowsocksAead { .. })
    ));
    let text = format!("{capability:?}");
    assert!(!text.contains("secret"), "{text}");
}

#[test]
fn build_trojan_is_always_tls_and_udp_unsupported() {
    let mut config = outbound(OutboundKind::Trojan);
    config.locator = Some("127.0.0.1:443".to_string());
    config.password = Some("secret".to_string());
    config.skip_cert_verify = Some(false);
    let dialer = build_dialer(&config).expect("trojan dialer");
    assert_eq!(dialer.kind(), OutboundKind::Trojan);
    assert_eq!(
        dialer.udp_capability(),
        UdpCapability::Unsupported {
            reason: UdpUnsupportedReason::TlsVariantNotSupported
        }
    );
}

#[test]
fn build_trojan_plaintext_is_rejected() {
    let mut config = outbound(OutboundKind::Trojan);
    config.locator = Some("127.0.0.1:443".to_string());
    config.password = Some("secret".to_string());
    let error = build_error(&config);
    assert_eq!(
        config_error(error),
        OutboundConfigError::PlaintextTrojanUnsupported
    );
}

#[test]
fn build_dialer_missing_locator() {
    let config = outbound(OutboundKind::Socks5);
    assert_eq!(
        config_error(build_error(&config)),
        OutboundConfigError::MissingLocator
    );
}

#[test]
fn build_dialer_invalid_locator() {
    for locator in ["127.0.0.1", "127.0.0.1:not-a-port", "127.0.0.1:0"] {
        let mut config = outbound(OutboundKind::Socks5);
        config.locator = Some(locator.to_string());
        assert!(matches!(
            config_error(build_error(&config)),
            OutboundConfigError::InvalidLocator { .. }
        ));
    }
}

#[test]
fn build_dialer_unresolvable_locator() {
    let mut config = outbound(OutboundKind::Socks5);
    config.locator = Some("bad host:80".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::UnresolvableLocator { .. }
    ));
}

#[test]
fn build_dialer_missing_password() {
    for kind in [OutboundKind::Shadowsocks, OutboundKind::Trojan] {
        let mut config = outbound(kind);
        config.locator = Some("127.0.0.1:443".to_string());
        config.skip_cert_verify = Some(false);
        assert_eq!(
            config_error(build_error(&config)),
            OutboundConfigError::MissingPassword
        );
    }
}

#[test]
fn build_dialer_unsupported_method() {
    let mut config = outbound(OutboundKind::Shadowsocks);
    config.locator = Some("127.0.0.1:8388".to_string());
    config.password = Some("secret".to_string());
    config.method = Some("aes-256-gcm".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::UnsupportedMethod { .. }
    ));
}

#[test]
fn build_dialer_unsupported_obfs_fields() {
    for (obfs, obfs_key, field) in [
        (Some("plain"), None, "obfs"),
        (None, Some("secret"), "obfs_key"),
    ] {
        let mut config = outbound(OutboundKind::Socks5);
        config.locator = Some("127.0.0.1:1080".to_string());
        config.obfs = obfs.map(str::to_string);
        config.obfs_key = obfs_key.map(str::to_string);
        assert_eq!(
            config_error(build_error(&config)),
            OutboundConfigError::UnsupportedObfs { field }
        );
    }
}

#[test]
fn build_dialer_invalid_sni() {
    let mut config = outbound(OutboundKind::Trojan);
    config.locator = Some("127.0.0.1:443".to_string());
    config.password = Some("secret".to_string());
    config.skip_cert_verify = Some(false);
    config.sni = Some("bad/name".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::InvalidSni { .. }
    ));
}

#[test]
fn build_dialer_invalid_alpn_entry() {
    let mut config = outbound(OutboundKind::Trojan);
    config.locator = Some("127.0.0.1:443".to_string());
    config.password = Some("secret".to_string());
    config.alpn = Some(vec![String::new()]);
    assert_eq!(
        config_error(build_error(&config)),
        OutboundConfigError::InvalidAlpnEntry
    );
}

#[test]
fn build_dialer_invalid_header_format() {
    let mut config = outbound(OutboundKind::Trojan);
    config.locator = Some("127.0.0.1:443".to_string());
    config.password = Some("secret".to_string());
    config.skip_cert_verify = Some(false);
    config.header_format = Some("fancy".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::InvalidHeaderFormat { .. }
    ));
}

#[test]
fn build_dialer_reports_unwired_protocols() {
    for kind in [OutboundKind::Vmess, OutboundKind::Hysteria2] {
        let mut config = outbound(kind);
        config.locator = Some("127.0.0.1:443".to_string());
        assert!(matches!(
            build_error(&config),
            BuildDialerError::ProtocolNotWired { .. }
        ));
    }
}

fn vless_config() -> OutboundConfig {
    let mut config = outbound(OutboundKind::Vless);
    config.locator = Some("127.0.0.1:443".to_string());
    config.uuid = Some("11111111-1111-1111-1111-111111111111".to_string());
    config
}

#[test]
fn build_vless_requires_uuid() {
    let mut config = vless_config();
    config.uuid = None;
    assert_eq!(
        config_error(build_error(&config)),
        OutboundConfigError::MissingUuid
    );
}

#[test]
fn build_vless_rejects_invalid_uuid() {
    let mut config = vless_config();
    config.uuid = Some("not-a-uuid".to_string());
    assert_eq!(
        config_error(build_error(&config)),
        OutboundConfigError::InvalidUuid
    );
}

#[test]
fn build_vless_rejects_unknown_flow() {
    let mut config = vless_config();
    config.flow = Some("xtls-rprx-direct".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::UnsupportedFlow { .. }
    ));
}

#[test]
fn build_vless_vision_requires_tls() {
    let mut config = vless_config();
    config.flow = Some("xtls-rprx-vision".to_string());
    config.tls = None;
    assert_eq!(
        config_error(build_error(&config)),
        OutboundConfigError::VisionRequiresTls
    );
    config.tls = Some(true);
    let dialer = build_dialer(&config).expect("vision vless dialer");
    assert_eq!(dialer.kind(), OutboundKind::Vless);
}

#[test]
fn build_vless_ignores_sni_and_alpn_but_keeps_servername_as_sni() {
    let mut config = vless_config();
    config.sni = Some("ignored.example".to_string());
    config.alpn = Some(vec!["h2".to_string()]);
    config.servername = Some("front.example".to_string());
    let dialer = build_dialer(&config).expect("vless dialer");
    assert_eq!(dialer.kind(), OutboundKind::Vless);
    assert_eq!(dialer.tag(), "test");
    // PRODUCT §11.18.1（requirement-change 2026-10-28）：VLESS 承载代理 UDP。
    let server: SocketAddr = "127.0.0.1:443".parse().expect("server");
    assert_eq!(
        dialer.udp_capability(),
        UdpCapability::Supported(UdpMode::VlessOverTcp { server })
    );
}

#[test]
fn build_vless_rejects_invalid_servername() {
    let mut config = vless_config();
    config.servername = Some("bad/name".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::InvalidSni { .. }
    ));
}

#[test]
fn build_anytls_requires_password_and_declares_uot_udp() {
    let mut config = outbound(OutboundKind::Anytls);
    config.locator = Some("127.0.0.1:443".to_string());
    assert_eq!(
        config_error(build_error(&config)),
        OutboundConfigError::MissingPassword
    );

    config.password = Some("secret".to_string());
    config.sni = Some("front.example".to_string());
    config.servername = Some("ignored.example".to_string());
    config.alpn = Some(vec!["h2".to_string()]);
    let dialer = build_dialer(&config).expect("anytls dialer");
    assert_eq!(dialer.kind(), OutboundKind::Anytls);
    // PRODUCT §11.18.1（requirement-change 2026-10-28）：AnyTLS 经 UoT 承载代理 UDP。
    let server: SocketAddr = "127.0.0.1:443".parse().expect("server");
    assert_eq!(
        dialer.udp_capability(),
        UdpCapability::Supported(UdpMode::AnytlsUot { server })
    );
}

#[test]
fn build_anytls_rejects_invalid_sni() {
    let mut config = outbound(OutboundKind::Anytls);
    config.locator = Some("127.0.0.1:443".to_string());
    config.password = Some("secret".to_string());
    config.sni = Some("bad/name".to_string());
    assert!(matches!(
        config_error(build_error(&config)),
        OutboundConfigError::InvalidSni { .. }
    ));
}

#[test]
fn outbound_error_reason_enum_is_stable() {
    let cases = [
        (
            OutboundError::Config(OutboundConfigError::MissingPassword),
            "config",
        ),
        (
            OutboundError::TcpConnect {
                kind: io::ErrorKind::ConnectionRefused,
            },
            "tcp_connect",
        ),
        (OutboundError::ConnectTimeout, "connect_timeout"),
        (
            OutboundError::TlsHandshake(TlsFailure::Handshake),
            "tls_handshake",
        ),
        (
            OutboundError::ProtocolHandshake(HandshakeFailure::AuthRejected {
                protocol: Protocol::Socks5,
            }),
            "auth_rejected",
        ),
        (
            OutboundError::ProtocolHandshake(HandshakeFailure::StreamRejected {
                protocol: Protocol::Anytls,
                stream_id: 7,
                reason: "nope".to_string(),
            }),
            "stream_rejected",
        ),
        (
            OutboundError::ProtocolHandshake(HandshakeFailure::Truncated {
                protocol: Protocol::Vless,
            }),
            "protocol_handshake",
        ),
        (
            OutboundError::Io {
                kind: io::ErrorKind::Other,
            },
            "io",
        ),
        (OutboundError::Closed, "closed"),
        (OutboundError::UdpUnsupported, "udp_unsupported"),
        (OutboundError::Internal { what: "test" }, "internal"),
    ];
    for (error, expected) in cases {
        assert_eq!(error.reason(), expected, "{error:?}");
    }
}

#[test]
fn stream_rejected_reason_is_sanitized_and_truncated() {
    let error = OutboundError::ProtocolHandshake(HandshakeFailure::StreamRejected {
        protocol: Protocol::Anytls,
        stream_id: 7,
        reason: format!("bad\nreason {}", "x".repeat(300)),
    });
    let detail = error.detail();
    assert!(!detail.contains('\n'), "{detail}");
    assert!(detail.len() <= DETAIL_MAX_BYTES, "{}", detail.len());
}

#[test]
fn outbound_error_display_never_leaks_password() {
    let error = OutboundError::Config(OutboundConfigError::UnsupportedObfs { field: "obfs_key" });
    assert!(!error.to_string().contains("secret"));
    let capability = UdpCapability::Supported(UdpMode::ShadowsocksAead {
        server: "127.0.0.1:8388".parse().unwrap(),
        password: "secret".to_string(),
    });
    assert!(!format!("{capability:?}").contains("secret"));
}
