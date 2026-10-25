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
pub(crate) mod tcp_relay;
pub(crate) mod udp_relay;

pub use udp_relay::build_udp_reply;

use std::net::{IpAddr, SocketAddr};

use nexus_projection::tcp::TcpTerminator;
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
    /// 进入终结器的 Proxy TCP 流数（SYN 事件，AC-G1-TUN-02）。
    pub tcp_streams: u64,
    pub tcp_dials_ok: u64,
    pub tcp_dials_failed: u64,
    pub udp_sent: u64,
    pub udp_send_failed: u64,
}

/// 从 `OutboundConfig` 解析 dial 配置；不支持的 kind 返回 None（P3 跳过）。
pub(crate) fn dial_config_from_outbound(o: &OutboundConfig) -> Option<ProxyDialConfig> {
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

/// ProxyEngine 结构化错误（spec §8.9 / §9.10）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEngineError {
    /// 规则选出的 tag 不在引擎出站表。
    UnknownOutbound { tag: String },
    /// 出站 kind 无对应拨号器。
    UnsupportedOutboundKind { tag: String, kind: String },
    /// 代理服务器拒绝/超时。
    DialFailed { tag: String, reason: String },
    /// 非 TCP/UDP 包。
    UnsupportedProtocol { ip_proto: u8 },
}

impl std::fmt::Display for ProxyEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOutbound { tag } => write!(f, "PROXY_UNKNOWN_OUTBOUND: {tag}"),
            Self::UnsupportedOutboundKind { tag, kind } => {
                write!(f, "PROXY_UNSUPPORTED_OUTBOUND: {tag} ({kind})")
            }
            Self::DialFailed { tag, reason } => {
                write!(f, "PROXY_DIAL_FAILED: {tag}: {reason}")
            }
            Self::UnsupportedProtocol { ip_proto } => {
                write!(f, "PROXY_UNSUPPORTED_PROTOCOL: {ip_proto}")
            }
        }
    }
}

impl std::error::Error for ProxyEngineError {}

/// 异步流事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyStreamEvent {
    /// 本地 SYN 已进入终结器。
    Syn { stream_id: u32 },
    /// 代理拨号成功。
    Established { stream_id: u32 },
    /// 关闭。
    Closed { stream_id: u32, reset: bool },
    /// 失败。
    Failed { stream_id: u32, reason: String },
}

/// `handle_packet` 结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHandleResult {
    /// 待写回 TUN 的包。
    pub tun_packets: Vec<Vec<u8>>,
    /// 是否真实转发（UDP 发送成功）。
    pub forwarded: bool,
    /// 本次使用的出站 tag。
    pub outbound_tag: String,
    /// 同步产生的流事件。
    pub stream_events: Vec<ProxyStreamEvent>,
}

/// `poll()` 结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyPollResult {
    /// 待写回 TUN 的包。
    pub tun_packets: Vec<Vec<u8>>,
    /// 异步流事件。
    pub stream_events: Vec<ProxyStreamEvent>,
}

/// Proxy 转发引擎（dataplane 拥有）。
///
/// TCP 共享单个 `TcpTerminator`（§9.10.1 的两个实例之一），按规则 tag 选拨号器；
/// UDP 每个 tag 一个转发器（不新增终结器）。
pub struct ProxyEngine {
    /// TCP 共享终结器（AC-G3b-03：实例只允许两个——ProxyEngine 与 Dataplane）。
    terminator: TcpTerminator,
    tcp: tcp_relay::TcpForwarder,
    udp: std::collections::HashMap<String, udp_relay::UdpForwarder>,
    outbounds: std::collections::HashMap<String, ProxyDialConfig>,
    unsupported: std::collections::HashMap<String, String>,
}

impl ProxyEngine {
    /// 从 `proxy.yaml` 构造；无可拨号出站或配置非法 → Err。
    ///
    /// # Errors
    ///
    /// 配置解析失败 → `UnsupportedOutboundKind`；无代理出站 → `UnknownOutbound`。
    pub fn new(proxy_yaml: &str) -> Result<Self, ProxyEngineError> {
        let config = nexus_proxy_config::parse(proxy_yaml).map_err(|e| {
            ProxyEngineError::UnsupportedOutboundKind {
                tag: "<config>".to_string(),
                kind: e.to_string(),
            }
        })?;
        let mut outbounds = std::collections::HashMap::new();
        let mut unsupported = std::collections::HashMap::new();
        for outbound in &config.outbounds {
            match dial_config_from_outbound(outbound) {
                Some(cfg) => {
                    outbounds.insert(outbound.tag.clone(), cfg);
                }
                None => {
                    unsupported.insert(outbound.tag.clone(), outbound.kind.as_str().to_string());
                }
            }
        }
        if outbounds.is_empty() {
            return Err(ProxyEngineError::UnknownOutbound {
                tag: "<no-proxy-outbound>".to_string(),
            });
        }
        Ok(Self {
            terminator: TcpTerminator::new(),
            tcp: tcp_relay::TcpForwarder::new(outbounds.clone()),
            udp: std::collections::HashMap::new(),
            outbounds,
            unsupported,
        })
    }

    /// 处理一个 proxy 分类的包（按规则 tag 选路）。
    ///
    /// # Errors
    ///
    /// tag 不存在/不支持、非 TCP-UDP。
    pub fn handle_packet(
        &mut self,
        packet: &[u8],
        outbound_tag: &str,
    ) -> Result<ProxyHandleResult, ProxyEngineError> {
        if packet.len() < 20 {
            return Err(ProxyEngineError::UnsupportedProtocol { ip_proto: 0 });
        }
        let proto = packet[9];
        if proto != 6 && proto != 17 {
            return Err(ProxyEngineError::UnsupportedProtocol { ip_proto: proto });
        }
        if let Some(kind) = self.unsupported.get(outbound_tag) {
            return Err(ProxyEngineError::UnsupportedOutboundKind {
                tag: outbound_tag.to_string(),
                kind: kind.clone(),
            });
        }
        let Some(config) = self.outbounds.get(outbound_tag).cloned() else {
            return Err(ProxyEngineError::UnknownOutbound {
                tag: outbound_tag.to_string(),
            });
        };
        if proto == 6 {
            let tun_packets = self
                .tcp
                .handle_packet(&mut self.terminator, packet, outbound_tag);
            let stream_events = self
                .tcp
                .take_failures()
                .into_iter()
                .map(|f| ProxyStreamEvent::Failed {
                    stream_id: f.stream_id,
                    reason: f.reason,
                })
                .collect();
            return Ok(ProxyHandleResult {
                tun_packets,
                forwarded: false,
                outbound_tag: outbound_tag.to_string(),
                stream_events,
            });
        }
        let forwarder = self
            .udp
            .entry(outbound_tag.to_string())
            .or_insert_with(|| udp_relay::UdpForwarder::new(config));
        let forwarded = forwarder.handle_packet(packet);
        Ok(ProxyHandleResult {
            tun_packets: Vec::new(),
            forwarded,
            outbound_tag: outbound_tag.to_string(),
            stream_events: Vec::new(),
        })
    }

    /// 定期驱动（dataplane 每轮调用）；返回待写回 TUN 的包与流事件。
    pub fn poll(&mut self) -> ProxyPollResult {
        let tun_packets = self.tcp.poll(&mut self.terminator);
        let stream_events = self
            .tcp
            .take_failures()
            .into_iter()
            .map(|f| ProxyStreamEvent::Failed {
                stream_id: f.stream_id,
                reason: f.reason,
            })
            .collect();
        let mut out = ProxyPollResult {
            tun_packets,
            stream_events,
        };
        for forwarder in self.udp.values_mut() {
            for inbound in forwarder.drain_inbound() {
                if let Some(local) = forwarder.lookup_local(&inbound.remote) {
                    if let Some(pkt) = build_udp_reply(local, inbound.remote, &inbound.payload) {
                        out.tun_packets.push(pkt);
                    }
                }
            }
        }
        out
    }

    /// 写回 TUN 前的 fixup（P6-a 归属：Proxy 流归本引擎的终结器）。
    ///
    /// Proxy TCP 连接的 orig_dst 只登记在 `ProxyEngine.terminator`（§9.10.1
    /// 两个终结器之一），dataplane 自己的连接表查不到它们；因此这条路径的
    /// `fixup_tun_packet` 必须在这里执行，不能借道
    /// `Dataplane::write_tun_packets`。非 TCP 包（UDP 回包由
    /// `build_udp_reply` 合成，源地址已是原始目的）原样透传。
    ///
    /// 返回 (fixup 后的可写包, 丢弃数)；TCP 包查不到连接 → 丢弃计数
    /// （与 `Dataplane::write_tun_packets` 同语义）。
    pub fn fixup_tun_packets(&self, pkts: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, u64) {
        let mut ready = Vec::with_capacity(pkts.len());
        let mut dropped = 0u64;
        for pkt in pkts {
            let is_tcp = pkt.len() >= 20 && pkt[9] == 6;
            if !is_tcp {
                ready.push(pkt);
                continue;
            }
            match self.terminator.fixup_tun_packet(&pkt) {
                Some(fixed) => ready.push(fixed),
                None => dropped += 1,
            }
        }
        (ready, dropped)
    }

    /// 合并统计。
    pub fn stats(&self) -> ProxyFwdStats {
        let mut stats = self.tcp.stats();
        for forwarder in self.udp.values() {
            let u = forwarder.stats();
            stats.udp_sent += u.udp_sent;
            stats.udp_send_failed += u.udp_send_failed;
        }
        stats
    }

    /// 是否有可用 dial 配置（P3 可观测）。
    pub fn has_dial_config(&self) -> bool {
        !self.outbounds.is_empty()
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

    fn craft_syn(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x02;
        pkt
    }

    #[test]
    fn engine_unknown_outbound_tag() {
        let yaml = yaml_with("socks5", "127.0.0.1:1080", "");
        let mut engine = ProxyEngine::new(&yaml).expect("engine");
        let err = engine
            .handle_packet(&craft_syn([127, 0, 0, 1], 18080), "missing")
            .expect_err("unknown tag");
        assert_eq!(
            err,
            ProxyEngineError::UnknownOutbound {
                tag: "missing".to_string()
            }
        );
    }

    #[test]
    fn engine_unsupported_outbound_kind() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: s\noutbounds:\n  - tag: s\n    kind: socks5\n    locator: 127.0.0.1:1080\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n";
        let mut engine = ProxyEngine::new(yaml).expect("engine");
        let err = engine
            .handle_packet(&craft_syn([127, 0, 0, 1], 18080), "v")
            .expect_err("unsupported kind");
        assert!(matches!(
            err,
            ProxyEngineError::UnsupportedOutboundKind { .. }
        ));
    }

    #[test]
    fn engine_dial_failure_emits_stream_event() {
        let yaml = yaml_with("socks5", "127.0.0.1:1", "");
        let mut engine = ProxyEngine::new(&yaml).expect("engine");
        let syn = craft_syn([127, 0, 0, 1], 18080);
        let syn_ack = engine.handle_packet(&syn, "test").expect("syn").tun_packets;
        assert_eq!(syn_ack.len(), 1, "SYN-ACK expected");
        let srv_seq = u32::from_be_bytes([
            syn_ack[0][24],
            syn_ack[0][25],
            syn_ack[0][26],
            syn_ack[0][27],
        ]);
        let mut ack = craft_syn([127, 0, 0, 1], 18080);
        ack[24..28].copy_from_slice(&1u32.to_be_bytes());
        ack[28..32].copy_from_slice(&(srv_seq + 1).to_be_bytes());
        ack[33] = 0x10;
        let _ = engine.handle_packet(&ack, "test");
        let mut failed = None;
        for _ in 0..15_000 {
            for event in engine.poll().stream_events {
                if let ProxyStreamEvent::Failed { reason, .. } = event {
                    failed = Some(reason);
                }
            }
            if failed.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(failed.is_some(), "dial failure must surface as StreamEvent");
        assert!(engine.stats().tcp_dials_failed >= 1);
    }

    #[test]
    fn engine_error_when_no_usable() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        assert!(matches!(
            ProxyEngine::new(yaml),
            Err(ProxyEngineError::UnknownOutbound { .. })
        ));
    }
}
