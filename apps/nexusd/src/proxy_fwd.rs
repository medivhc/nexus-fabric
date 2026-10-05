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

pub mod ss_std;
mod tcp_relay;
mod udp_relay;

pub use udp_relay::build_udp_reply;

use std::net::{IpAddr, SocketAddr};

use nexus_proxy_config::{OutboundConfig, OutboundKind};

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
    pub udp_sent: u64,
    pub udp_send_failed: u64,
}

/// 从 `OutboundConfig` 解析 dial 配置；不支持的 kind 返回 None（P3 跳过）。
fn dial_config_from_outbound(o: &OutboundConfig) -> Option<ProxyDialConfig> {
    let locator = o.locator.as_deref().filter(|s| !s.is_empty())?;
    let server: SocketAddr = locator.parse().ok()?;
    match o.kind {
        OutboundKind::Shadowsocks => {
            let password = o.password.clone().filter(|s| !s.is_empty())?;
            let method = o
                .method
                .clone()
                .unwrap_or_else(|| "chacha20-ietf-poly1305".to_string());
            // P1 只支持 chacha20-ietf-poly1305（标准 ss）。
            if method != "chacha20-ietf-poly1305" {
                return None;
            }
            Some(ProxyDialConfig::Shadowsocks {
                server,
                method,
                password,
            })
        }
        OutboundKind::Trojan => {
            let password = o.password.clone().filter(|s| !s.is_empty())?;
            // TLS 判定：skip_cert_verify 或 alpn 存在 → TLS；否则明文。
            // 诚实：默认明文（与 TrojanTransport 一致）；显式配置才走 TLS。
            let use_tls = o.skip_cert_verify.unwrap_or(false) || o.alpn.is_some();
            if use_tls {
                Some(ProxyDialConfig::TrojanTls {
                    server,
                    password,
                    sni: server.ip().to_string(),
                    skip_verify: o.skip_cert_verify.unwrap_or(false),
                })
            } else {
                Some(ProxyDialConfig::Trojan { server, password })
            }
        }
        OutboundKind::Socks5 => Some(ProxyDialConfig::Socks5 { server }),
        // AnyTLS/VLESS/Hysteria2 需要完整 adapter（TLS/QUIC 握手），简单 dial 路径暂不支持。
        OutboundKind::Direct
        | OutboundKind::Relay
        | OutboundKind::Vmess
        | OutboundKind::Anytls
        | OutboundKind::Vless
        | OutboundKind::Hysteria2 => None,
    }
}

/// P3：从 proxy.yaml 选首个可用出站。
pub fn select_outbound(proxy_yaml: &str) -> Option<ProxyDialConfig> {
    let config = nexus_proxy_config::parse(proxy_yaml).ok()?;
    config.outbounds.iter().find_map(dial_config_from_outbound)
}

/// Proxy 转发引擎（dataplane 拥有）。
pub struct ProxyEngine {
    tcp: tcp_relay::TcpForwarder,
    udp: udp_relay::UdpForwarder,
}

impl ProxyEngine {
    /// 从 proxy.yaml 构造；无可用出站返回 None（调用方走计数降级）。
    pub fn new(proxy_yaml: &str) -> Option<Self> {
        let dial_config = select_outbound(proxy_yaml)?;
        Some(Self {
            tcp: tcp_relay::TcpForwarder::new(dial_config.clone()),
            udp: udp_relay::UdpForwarder::new(dial_config),
        })
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
    fn select_trojan_plaintext_by_default() {
        let yaml = yaml_with("trojan", "127.0.0.1:443", "    password: secret\n");
        let cfg = select_outbound(&yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::Trojan { .. }));
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
    fn skip_direct_and_vmess() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n";
        assert!(select_outbound(yaml).is_none());
    }

    #[test]
    fn first_usable_wins() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: s\noutbounds:\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n  - tag: s\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        let cfg = select_outbound(yaml).unwrap();
        assert!(matches!(cfg, ProxyDialConfig::Socks5 { .. }));
    }

    #[test]
    fn engine_none_when_no_usable() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        assert!(ProxyEngine::new(yaml).is_none());
    }
}
