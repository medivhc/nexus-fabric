//! TLS 装配（spec §2.1 / §3.5）。
//!
//! 步骤 1 只包含 Trojan：`TrojanTlsConfig` 的字段映射（sni / skip_cert_verify /
//! alpn / 握手超时）。VLESS / AnyTLS 的 rustls helper 在步骤 2 增加。

use std::net::SocketAddr;

use nexus_proxy_transport::TrojanTlsConfig;

use super::TLS_HANDSHAKE_TIMEOUT;

/// 装配 Trojan-over-TLS 配置（密码不落日志；`Debug` 由 crate 手写脱敏）。
pub(super) fn trojan_tls_config(
    server: SocketAddr,
    password: &str,
    sni: &str,
    skip_cert_verify: bool,
    alpn: &[String],
) -> TrojanTlsConfig {
    let mut config = TrojanTlsConfig::new(server, password.to_string(), sni.to_string());
    config.skip_cert_verify = skip_cert_verify;
    config.alpn = alpn.iter().map(|entry| entry.as_bytes().to_vec()).collect();
    config.handshake_timeout = TLS_HANDSHAKE_TIMEOUT;
    config
}
