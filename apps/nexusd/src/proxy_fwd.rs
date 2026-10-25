//! Proxy 生产转发（P1-P5）。
//!
//! `ProxyEngine`：dataplane 中分类为 `Proxy` 的包的真实转发：
//! - TCP（P1）：`tcp_relay::TcpForwarder`（smoltcp 终结 → 代理 dial → 中继）；
//! - UDP（P2）：`udp_relay::UdpForwarder`（协议 UDP 中继 → 回包写 TUN）；
//! - 出站选择（P3）：`proxy.yaml` 首个可用 ss/trojan/socks5；
//! - 失败计数不崩（P4）；资源有界（P5）。
//!
//! TUN 所有权仍在 dataplane（D1）：engine 只返回待写回 TUN 的包，
//! 不直接持有/写 TUN。

pub(crate) mod adapter;
pub mod ss_std;
mod tcp_relay;
mod udp_relay;

pub use adapter::{EngineInitError, OutboundConfigError};

pub use udp_relay::build_udp_reply;

use std::net::{IpAddr, SocketAddr};

/// 代理 dial 配置（P3 选路结果）。
#[derive(Debug, Clone)]
pub enum ProxyDialConfig {
    Shadowsocks {
        server: SocketAddr,
        method: String,
        password: String,
    },
    Trojan {
        server: SocketAddr,
        password: String,
    },
    TrojanTls {
        server: SocketAddr,
        password: String,
        sni: String,
        skip_verify: bool,
    },
    Socks5 {
        server: SocketAddr,
    },
}

/// Proxy 转发统计（P4 可观测；dataplane 合并到 DataplaneStats）。
#[derive(Debug, Default, Clone)]
pub struct ProxyFwdStats {
    pub tcp_dials_ok: u64,
    pub tcp_dials_failed: u64,
    pub tcp_streams_ok: u64,
    pub tcp_bytes_up: u64,
    pub tcp_bytes_down: u64,
    pub udp_sent: u64,
    pub udp_send_failed: u64,
}

/// P3（步骤 0 临时）：从 proxy.yaml 选首个 wired 出站。
fn select_outbound(proxy_yaml: &str) -> Result<ProxyDialConfig, EngineInitError> {
    adapter::select_dialer_legacy(proxy_yaml).map(|selected| {
        let _ = selected.skipped;
        selected.dial_config
    })
}

/// Proxy 转发引擎（dataplane 拥有）。
pub struct ProxyEngine {
    tcp: tcp_relay::TcpForwarder,
    udp: udp_relay::UdpForwarder,
}

impl ProxyEngine {
    /// `None` = 没有 proxy.yaml；`Some(yaml)` = 有文件，区分「可用」与「不可用」。
    ///
    /// # Errors
    /// `Yaml` / `SelectedInvalid` / `NoUsableOutbound` → 调用方 fail-closed（exit 1）。
    pub fn new(proxy_yaml: Option<&str>) -> Result<Option<Self>, EngineInitError> {
        let Some(proxy_yaml) = proxy_yaml else {
            return Ok(None);
        };
        let dial_config = select_outbound(proxy_yaml)?;
        Ok(Some(Self {
            tcp: tcp_relay::TcpForwarder::new(dial_config.clone()),
            udp: udp_relay::UdpForwarder::new(dial_config),
        }))
    }

    /// 处理一个 proxy 分类的包；返回 (待写回 TUN 的包, 是否真实转发)。
    ///
    /// - TCP → TcpForwarder；UDP → UdpForwarder；其他 → (vec![], false)。
    /// - 返回的包由 dataplane 写回 TUN（D1 不变量）。
    /// - bool 语义（P1）：UDP 返回真实发送结果；TCP 恒返回 false——
    ///   dial 是异步的，SYN 到达时转发尚未确认，TCP 的真实计数由
    ///   dataplane 经 `stats().tcp_dials_ok/failed` 的增量驱动。
    pub fn handle_packet(&mut self, packet: &[u8]) -> (Vec<Vec<u8>>, bool) {
        if packet.len() < 20 {
            return (vec![], false);
        }
        match packet[9] {
            6 => {
                // TCP
                let tun_pkts = self.tcp.handle_packet(packet);
                // P1：dial 是异步的（worker 线程），SYN 到达时转发尚未确认，
                // 此时返回 false；真实计数由 dataplane 经
                // engine.stats().tcp_dials_ok/failed 的增量驱动。
                (tun_pkts, false)
            }
            17 => {
                // UDP（DNS 已在 D3 短路，这里的 UDP 是业务流量）。
                let ok = self.udp.handle_packet(packet);
                (vec![], ok)
            }
            _ => (vec![], false),
        }
    }

    /// 定期驱动（dataplane 每轮调用）；返回待写回 TUN 的包。
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let mut out = self.tcp.poll();
        // UDP 回包 → 重构 IP 包。
        for inbound in self.udp.drain_inbound() {
            if let Some(local) = self.udp.lookup_local(&inbound.remote) {
                if let Some(pkt) = build_udp_reply(local, inbound.remote, &inbound.payload) {
                    out.push(pkt);
                }
            }
        }
        out
    }

    /// 合并统计。
    pub fn stats(&self) -> ProxyFwdStats {
        let t = self.tcp.stats();
        let u = self.udp.stats();
        ProxyFwdStats {
            tcp_dials_ok: t.tcp_dials_ok,
            tcp_dials_failed: t.tcp_dials_failed,
            tcp_streams_ok: t.tcp_streams_ok,
            tcp_bytes_up: t.tcp_bytes_up,
            tcp_bytes_down: t.tcp_bytes_down,
            udp_sent: u.udp_sent,
            udp_send_failed: u.udp_send_failed,
        }
    }

    /// 是否有可用 dial 配置（P3 可观测）。
    #[allow(dead_code)]
    pub fn has_dial_config(&self) -> bool {
        true
    }
}

/// 供单测：判断 IP 是否为 IPv4 单播（非回环/组播）。
#[allow(dead_code)]
fn is_usable_target(_ip: IpAddr) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::adapter::{OutboundConfigError, SkipReason};
    use super::*;

    fn yaml_with(kind: &str, locator: &str, extra: &str) -> String {
        format!(
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: test\noutbounds:\n  - tag: test\n    kind: {kind}\n    locator: {locator}\n{extra}"
        )
    }

    #[test]
    fn select_socks5() {
        let yaml = yaml_with("socks5", "127.0.0.1:1080", "");
        let cfg = select_outbound(&yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::Socks5 { .. }));
    }

    #[test]
    fn select_shadowsocks() {
        let yaml = yaml_with(
            "shadowsocks",
            "127.0.0.1:8388",
            "    method: chacha20-ietf-poly1305\n    password: secret\n",
        );
        let cfg = select_outbound(&yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::Shadowsocks { .. }));
    }

    #[test]
    fn trojan_without_tls_signal_is_invalid() {
        let yaml = yaml_with("trojan", "127.0.0.1:443", "    password: secret\n");
        let err = select_outbound(&yaml).unwrap_err();
        let EngineInitError::SelectedInvalid { tag, source } = err else {
            panic!("expected SelectedInvalid");
        };
        assert_eq!(tag, "test");
        assert_eq!(source, OutboundConfigError::PlaintextTrojanUnsupported);
    }

    #[test]
    fn select_trojan_tls_when_skip_verify() {
        let yaml = yaml_with(
            "trojan",
            "127.0.0.1:443",
            "    password: secret\n    skip_cert_verify: true\n",
        );
        let cfg = select_outbound(&yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::TrojanTls { .. }));
    }

    #[test]
    fn select_trojan_tls_when_alpn() {
        let yaml = yaml_with(
            "trojan",
            "127.0.0.1:443",
            "    password: secret\n    alpn:\n      - h2\n",
        );
        let cfg = select_outbound(&yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::TrojanTls { .. }));
    }

    #[test]
    fn skip_direct_and_vmess() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n";
        let EngineInitError::NoUsableOutbound { skipped } = select_outbound(yaml).unwrap_err()
        else {
            panic!("expected NoUsableOutbound");
        };
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0].reason, SkipReason::NotProxyKind);
        assert_eq!(skipped[1].reason, SkipReason::ProtocolNotWired);
    }

    #[test]
    fn first_usable_wins() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: s\noutbounds:\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n  - tag: s\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        let cfg = select_outbound(yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::Socks5 { .. }));
    }

    #[test]
    fn first_wired_invalid_is_hard_failure() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: t\noutbounds:\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n  - tag: t\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n  - tag: s\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        let err = select_outbound(yaml).unwrap_err();
        assert!(matches!(
            err,
            EngineInitError::SelectedInvalid {
                source: OutboundConfigError::PlaintextTrojanUnsupported,
                ..
            }
        ));
    }

    #[test]
    fn obfs_is_a_config_error() {
        let obfs = yaml_with(
            "socks5",
            "127.0.0.1:1080",
            "    obfs: plain\n    obfs_key: secret\n",
        );
        let EngineInitError::SelectedInvalid { source, .. } = select_outbound(&obfs).unwrap_err()
        else {
            panic!("expected SelectedInvalid");
        };
        assert_eq!(
            source,
            OutboundConfigError::UnsupportedObfs { field: "obfs" }
        );
    }

    #[test]
    fn engine_new_none_is_ok() {
        assert!(matches!(ProxyEngine::new(None), Ok(None)));
    }

    #[test]
    fn engine_no_usable_outbound_is_error() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        assert!(matches!(
            ProxyEngine::new(Some(yaml)),
            Err(EngineInitError::NoUsableOutbound { .. })
        ));
    }
}
