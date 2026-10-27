//! Proxy 生产转发（P1-P5）。
//!
//! `ProxyEngine`：dataplane 中分类为 `Proxy` 的包的真实转发：
//! - TCP（P1）：`tcp_relay::TcpForwarder`（smoltcp 终结 → dialer → 中继）；
//! - UDP（P2）：`udp_relay::UdpForwarder`（协议 UDP 中继 → 回包写 TUN）；
//! - 出站注册表（Q-4=A）：`OutboundRegistry` = 全部 wired 出站入表 + strict-first；
//! - 失败计数不崩（P4）；资源有界（P5）。
//!
//! TUN 所有权仍在 dataplane（D1）：engine 只返回待写回 TUN 的包，
//! 不直接持有/写 TUN。

pub mod ss_std;

pub(crate) mod adapter;
pub(crate) mod tcp_relay;
pub(crate) mod udp_relay;

pub use udp_relay::build_udp_reply;

use std::collections::HashMap;
use std::sync::Arc;

use nexus_projection::tcp::TcpTerminator;
use nexus_proxy_config::OutboundKind;

pub(crate) use adapter::OutboundDialer;
pub use adapter::{EngineInitError, OutboundConfigError};

/// 一个出站槽位（Q-4=A：多出站 + strict-first）。
pub enum OutboundSlot {
    /// 可用 dialer（`dialers` 表内，冗余存放以便三态查询）。
    Dialer(Arc<dyn OutboundDialer>),
    /// wired 但配置非法（`build_dialer` 返回 `Config`）；运行期选到它 → 结构化错误。
    Invalid {
        kind: OutboundKind,
        cause: OutboundConfigError,
    },
    /// 未接线协议（vmess / hysteria2）；保留 master 运行期错误形态。
    ProtocolNotWired { kind: OutboundKind },
}

impl std::fmt::Debug for OutboundSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dialer(dialer) => f
                .debug_struct("Dialer")
                .field("kind", &dialer.kind())
                .field("tag", &dialer.tag())
                .finish(),
            Self::Invalid { kind, cause } => f
                .debug_struct("Invalid")
                .field("kind", kind)
                .field("cause", &cause.name())
                .finish(),
            Self::ProtocolNotWired { kind } => f
                .debug_struct("ProtocolNotWired")
                .field("kind", kind)
                .finish(),
        }
    }
}

/// 被跳过的出站原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// direct / relay：不是代理出站。
    NotProxyKind,
    /// 协议实现存在但本 run 未接线。
    ProtocolNotWired,
}

/// 被跳过的出站（启动面 + `NoUsableOutbound` 诊断）。
#[derive(Debug, Clone)]
pub struct SkippedOutbound {
    pub tag: String,
    pub kind: OutboundKind,
    pub reason: SkipReason,
}

/// 出站注册表：TUN engine 与 TPROXY egress 共享（Q-5=B）。
pub struct OutboundRegistry {
    dialers: HashMap<String, Arc<dyn OutboundDialer>>,
    /// 只含 `Invalid` / `ProtocolNotWired`（N8：三态拆分）。
    unsupported: HashMap<String, OutboundSlot>,
    /// `outbound_manifest::select_index` 命中的出站 tag（N9 同源）。
    selected: Option<String>,
    skipped: Vec<SkippedOutbound>,
}

impl std::fmt::Debug for OutboundRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundRegistry")
            .field("dialers", &self.dialers.keys().collect::<Vec<_>>())
            .field("unsupported", &self.unsupported)
            .field("selected", &self.selected)
            .field("skipped", &self.skipped)
            .finish()
    }
}

impl OutboundRegistry {
    /// 构造注册表。
    ///
    /// `None` = 没有 proxy.yaml → `Ok(None)`（不构造 engine）。
    /// `Some(yaml)`：解析失败 → `Yaml`；首个 wired 非法 → `SelectedInvalid`；
    /// 无任何 proxy+wired → `NoUsableOutbound`。
    ///
    /// # Errors
    ///
    /// 见上（D1=C1 分层）。
    pub fn build(proxy_yaml: Option<&str>) -> Result<Option<Arc<Self>>, EngineInitError> {
        let Some(yaml) = proxy_yaml else {
            return Ok(None);
        };
        let config = nexus_proxy_config::parse(yaml).map_err(EngineInitError::Yaml)?;
        let selected_index = nexus::outbound_manifest::select_index(&config.outbounds);
        let mut dialers: HashMap<String, Arc<dyn OutboundDialer>> = HashMap::new();
        let mut unsupported: HashMap<String, OutboundSlot> = HashMap::new();
        let mut skipped: Vec<SkippedOutbound> = Vec::new();
        let mut selected: Option<String> = None;
        for (index, outbound) in config.outbounds.iter().enumerate() {
            if matches!(outbound.kind, OutboundKind::Direct | OutboundKind::Relay) {
                skipped.push(SkippedOutbound {
                    tag: outbound.tag.clone(),
                    kind: outbound.kind,
                    reason: SkipReason::NotProxyKind,
                });
                continue;
            }
            if !nexus::outbound_manifest::is_wired(outbound.kind) {
                skipped.push(SkippedOutbound {
                    tag: outbound.tag.clone(),
                    kind: outbound.kind,
                    reason: SkipReason::ProtocolNotWired,
                });
                unsupported.insert(
                    outbound.tag.clone(),
                    OutboundSlot::ProtocolNotWired {
                        kind: outbound.kind,
                    },
                );
                continue;
            }
            match adapter::build_dialer(outbound) {
                Ok(dialer) => {
                    if selected_index == Some(index) {
                        selected = Some(outbound.tag.clone());
                    }
                    dialers.insert(outbound.tag.clone(), dialer);
                }
                Err(adapter::BuildDialerError::Config(cause)) => {
                    if selected_index == Some(index) {
                        // strict-first：首个 wired 非法 → 硬失败，不跳到下一个。
                        return Err(EngineInitError::SelectedInvalid {
                            tag: outbound.tag.clone(),
                            source: cause,
                        });
                    }
                    unsupported.insert(
                        outbound.tag.clone(),
                        OutboundSlot::Invalid {
                            kind: outbound.kind,
                            cause,
                        },
                    );
                }
                Err(adapter::BuildDialerError::ProtocolNotWired { kind }) => {
                    // 防御性：is_wired 与 build_dialer 使用同一集合，正常不可达。
                    skipped.push(SkippedOutbound {
                        tag: outbound.tag.clone(),
                        kind,
                        reason: SkipReason::ProtocolNotWired,
                    });
                    unsupported.insert(
                        outbound.tag.clone(),
                        OutboundSlot::ProtocolNotWired { kind },
                    );
                }
            }
        }
        if dialers.is_empty() {
            return Err(EngineInitError::NoUsableOutbound { skipped });
        }
        Ok(Some(Arc::new(Self {
            dialers,
            unsupported,
            selected,
            skipped,
        })))
    }

    /// 至少一个可用 dialer（N10）。
    #[must_use]
    pub fn has_any_dialer(&self) -> bool {
        !self.dialers.is_empty()
    }

    /// 按 tag 取 dialer。
    #[must_use]
    pub fn dialer(&self, tag: &str) -> Option<&Arc<dyn OutboundDialer>> {
        self.dialers.get(tag)
    }

    /// 按 tag 取不可用槽位。
    #[must_use]
    pub fn unsupported(&self, tag: &str) -> Option<&OutboundSlot> {
        self.unsupported.get(tag)
    }

    /// `select_index` 命中的出站 tag。
    #[must_use]
    pub fn selected_tag(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// 被跳过的出站（启动面）。
    #[must_use]
    pub fn skipped(&self) -> &[SkippedOutbound] {
        &self.skipped
    }

    /// 全部可用 dialer 的 tag。
    pub fn wired_tags(&self) -> impl Iterator<Item = &str> {
        self.dialers.keys().map(String::as_str)
    }

    /// 启动面（§12.1）：非首个 wired 非法出站的 `engine=unsupported` 行。
    ///
    /// 「不静默」的启动半数：配置非法但非 selected 的出站必须人可见。
    #[must_use]
    pub fn unsupported_warnings(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .unsupported
            .iter()
            .filter_map(|(tag, slot)| match slot {
                OutboundSlot::Invalid { cause, .. } => Some(format!(
                    "[nexusd] WARN outbound tag={tag} engine=unsupported cause={} detail=\"{}\"",
                    cause.name(),
                    nexus::redact::sanitize(cause.detail())
                )),
                OutboundSlot::Dialer(_) | OutboundSlot::ProtocolNotWired { .. } => None,
            })
            .collect();
        lines.sort();
        lines
    }

    /// 内部：拷贝 dialer 表（TcpForwarder 拥有自己的 map）。
    fn dialer_map(&self) -> HashMap<String, Arc<dyn OutboundDialer>> {
        self.dialers.clone()
    }
}

/// Proxy 转发统计（P4 可观测；dataplane 合并到 DataplaneStats）。
///
/// 15 个恒定字段（D3=A）：master 7 + R2 加法 8。
/// **明确不存在** `tcp_flows_rejected` / `tcp_dials_throttled`（不是 0 值字段）。
#[derive(Debug, Default, Clone)]
pub struct ProxyFwdStats {
    /// 进入终结器并完成握手的 Proxy TCP 流数（SYN 事件，AC-G1-TUN-02）。
    pub tcp_streams: u64,
    pub tcp_dials_ok: u64,
    pub tcp_dials_failed: u64,
    /// 拨号窗口期内已从 TUN 接收、但最终未写入上游的字节数（P7）。
    pub tcp_dial_buffer_dropped_bytes: u64,
    /// 拨号窗口期缓冲超限而被 RST 的流数（P7）。
    pub tcp_dial_buffer_overflow_resets: u64,
    pub udp_sent: u64,
    pub udp_send_failed: u64,
    /// dial 成功并进入 relay 的流数（R2 加法；与 `tcp_streams`（Syn 数）不同义）。
    pub tcp_streams_ok: u64,
    /// client→proxy 明文字节。
    pub tcp_bytes_up: u64,
    /// proxy→client 明文字节。
    pub tcp_bytes_down: u64,
    /// `UdpCapability::Unsupported` 总数。
    pub udp_unsupported: u64,
    pub udp_unsupported_vless: u64,
    pub udp_unsupported_anytls: u64,
    pub udp_unsupported_other: u64,
    /// 限频抑制的 `udp_unsupported` 日志条数。
    pub udp_unsupported_log_suppressed: u64,
}

/// ProxyEngine 结构化错误（spec §5.4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEngineError {
    /// 规则选出的 tag 不在引擎出站表。
    UnknownOutbound { tag: String },
    /// 出站 kind 无对应拨号器（未接线协议）。
    UnsupportedOutboundKind { tag: String, kind: String },
    /// wired 但配置非法（Q-4=A 的非首个坏出站）。
    InvalidOutbound {
        tag: String,
        kind: String,
        cause: OutboundConfigError,
    },
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
            Self::InvalidOutbound { tag, kind, cause } => {
                write!(
                    f,
                    "PROXY_INVALID_OUTBOUND: {tag} ({kind}): {}",
                    cause.name()
                )
            }
            Self::UnsupportedProtocol { ip_proto } => {
                write!(f, "PROXY_UNSUPPORTED_PROTOCOL: {ip_proto}")
            }
        }
    }
}

impl std::error::Error for ProxyEngineError {}

/// 异步流事件（唯一变体；master 只构造 `Failed`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyStreamEvent {
    /// 拨号/中继失败。
    Failed {
        stream_id: u32,
        /// `OutboundKind` 文本。
        kind: String,
        /// 规则/当前 tag。
        tag: String,
        /// `OutboundError::reason()`。
        error: &'static str,
        /// 已截断（128B）+ 去控制字符。
        detail: String,
    },
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
/// TCP 共享单个 `TcpTerminator`（§9.10.1 的两个实例之一），按规则 tag 选 dialer；
/// UDP 每个 tag 一个转发器（不新增终结器）。
pub struct ProxyEngine {
    /// TCP 共享终结器（AC-G3b-03：实例只允许两个——ProxyEngine 与 Dataplane）。
    terminator: TcpTerminator,
    tcp: tcp_relay::TcpForwarder,
    udp: HashMap<String, udp_relay::UdpForwarder>,
    registry: Arc<OutboundRegistry>,
}

impl ProxyEngine {
    /// 组合根入口：`None` = 无 proxy.yaml；`Some` = 有文件。
    ///
    /// # Errors
    ///
    /// 与 [`OutboundRegistry::build`] 相同（D1=C1 分层）。
    pub fn new(proxy_yaml: Option<&str>) -> Result<Option<Self>, EngineInitError> {
        match OutboundRegistry::build(proxy_yaml)? {
            Some(registry) => Ok(Self::from_registry(registry)),
            None => Ok(None),
        }
    }

    /// 已构造的 registry → engine（examples / 组合根复用同一份解析结果）。
    pub fn from_registry(registry: Arc<OutboundRegistry>) -> Option<Self> {
        if !registry.has_any_dialer() {
            return None;
        }
        let tcp = tcp_relay::TcpForwarder::new(registry.dialer_map());
        Some(Self {
            terminator: TcpTerminator::new(),
            tcp,
            udp: HashMap::new(),
            registry,
        })
    }

    /// 处理一个 proxy 分类的包（按规则 tag 选路）。
    ///
    /// # Errors
    ///
    /// tag 不存在/不支持/配置非法、非 TCP-UDP。
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
        // 三态查询：ProtocolNotWired / Invalid / 不存在（N8）。
        if let Some(slot) = self.registry.unsupported(outbound_tag) {
            return match slot {
                OutboundSlot::ProtocolNotWired { kind } => {
                    Err(ProxyEngineError::UnsupportedOutboundKind {
                        tag: outbound_tag.to_string(),
                        kind: kind.as_str().to_string(),
                    })
                }
                OutboundSlot::Invalid { kind, cause } => Err(ProxyEngineError::InvalidOutbound {
                    tag: outbound_tag.to_string(),
                    kind: kind.as_str().to_string(),
                    cause: cause.clone(),
                }),
                OutboundSlot::Dialer(dialer) => Ok(ProxyHandleResult {
                    tun_packets: Vec::new(),
                    forwarded: false,
                    outbound_tag: dialer.tag().to_string(),
                    stream_events: Vec::new(),
                }),
            };
        }
        let Some(dialer) = self.registry.dialer(outbound_tag).cloned() else {
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
                    kind: f.kind,
                    tag: f.tag,
                    error: f.error,
                    detail: f.detail,
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
            .or_insert_with(|| udp_relay::UdpForwarder::new(dialer));
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
                kind: f.kind,
                tag: f.tag,
                error: f.error,
                detail: f.detail,
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
    /// `fixup_tun_packet` 必须在这里执行。非 TCP 包（UDP 回包）原样透传。
    ///
    /// 返回 (fixup 后的可写包, 丢弃数)。
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

    /// 合并统计（15 字段）。
    pub fn stats(&self) -> ProxyFwdStats {
        let mut stats = self.tcp.stats();
        for forwarder in self.udp.values() {
            let u = forwarder.stats();
            stats.udp_sent += u.udp_sent;
            stats.udp_send_failed += u.udp_send_failed;
            stats.udp_unsupported += u.udp_unsupported;
            stats.udp_unsupported_vless += u.udp_unsupported_vless;
            stats.udp_unsupported_anytls += u.udp_unsupported_anytls;
            stats.udp_unsupported_other += u.udp_unsupported_other;
            stats.udp_unsupported_log_suppressed += u.udp_unsupported_log_suppressed;
        }
        stats
    }

    /// 是否有可用 dial 配置（N10：至少一个可用 dialer）。
    pub fn has_dial_config(&self) -> bool {
        self.registry.has_any_dialer()
    }

    /// 只读 registry（examples / 启动面）。
    #[must_use]
    pub fn registry(&self) -> &Arc<OutboundRegistry> {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_with(kind: &str, locator: &str, extra: &str) -> String {
        format!(
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: test\noutbounds:\n  - tag: test\n    kind: {kind}\n    locator: {locator}\n{extra}"
        )
    }

    fn engine(yaml: &str) -> ProxyEngine {
        ProxyEngine::new(Some(yaml))
            .expect("build")
            .expect("engine")
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
    fn registry_selected_is_first_proxy_wired() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: s\noutbounds:\n  - tag: d\n    kind: direct\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n  - tag: s\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        let registry = OutboundRegistry::build(Some(yaml))
            .expect("registry")
            .expect("some");
        assert_eq!(registry.selected_tag(), Some("s"));
        assert!(registry.dialer("s").is_some());
        assert!(registry.dialer("v").is_none());
        assert!(matches!(
            registry.unsupported("v"),
            Some(OutboundSlot::ProtocolNotWired { .. })
        ));
        assert_eq!(registry.skipped().len(), 2);
        assert_eq!(registry.skipped()[0].reason, SkipReason::NotProxyKind);
        assert_eq!(registry.skipped()[1].reason, SkipReason::ProtocolNotWired);
    }

    #[test]
    fn registry_first_wired_invalid_is_selected_invalid() {
        // 首个 wired 缺 password → 硬失败，不跳到下一个合法出站。
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ok\noutbounds:\n  - tag: bad\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n  - tag: ok\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        match OutboundRegistry::build(Some(yaml)) {
            Err(EngineInitError::SelectedInvalid { tag, source }) => {
                assert_eq!(tag, "bad");
                assert_eq!(source.name(), "PLAINTEXT_TROJAN_UNSUPPORTED");
            }
            other => panic!("expected SelectedInvalid, got {other:?}"),
        }
    }

    #[test]
    fn registry_non_first_invalid_goes_to_invalid_slot() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ok\noutbounds:\n  - tag: ok\n    kind: socks5\n    locator: 127.0.0.1:1080\n  - tag: bad\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n";
        let registry = OutboundRegistry::build(Some(yaml))
            .expect("registry")
            .expect("some");
        assert_eq!(registry.selected_tag(), Some("ok"));
        match registry.unsupported("bad") {
            Some(OutboundSlot::Invalid { cause, .. }) => {
                assert_eq!(cause.name(), "PLAINTEXT_TROJAN_UNSUPPORTED");
            }
            other => panic!("expected Invalid slot, got {other:?}"),
        }
        let mut engine = ProxyEngine::from_registry(registry).expect("engine");
        let err = engine
            .handle_packet(&craft_syn([127, 0, 0, 1], 18080), "bad")
            .expect_err("invalid outbound");
        assert!(matches!(err, ProxyEngineError::InvalidOutbound { .. }));
    }

    /// Q-4=A：非首个 wired 非法 → 运行期 `InvalidOutbound`（含 cause 名称）。
    #[test]
    fn engine_invalid_outbound_tag() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ok\noutbounds:\n  - tag: ok\n    kind: socks5\n    locator: 127.0.0.1:1080\n  - tag: bad\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n";
        let mut engine = engine(yaml);
        let err = engine
            .handle_packet(&craft_syn([127, 0, 0, 1], 18080), "bad")
            .expect_err("invalid outbound");
        match err {
            ProxyEngineError::InvalidOutbound { tag, kind, cause } => {
                assert_eq!(tag, "bad");
                assert_eq!(kind, "trojan");
                assert_eq!(cause.name(), "PLAINTEXT_TROJAN_UNSUPPORTED");
            }
            other => panic!("expected InvalidOutbound, got {other:?}"),
        }
    }

    #[test]
    fn registry_vmess_hy2_are_skipped_protocol_not_wired() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: s\noutbounds:\n  - tag: v\n    kind: vmess\n    locator: 127.0.0.1:1234\n  - tag: h\n    kind: hysteria2\n    locator: 127.0.0.1:443\n    password: p\n  - tag: s\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        let registry = OutboundRegistry::build(Some(yaml))
            .expect("registry")
            .expect("some");
        for tag in ["v", "h"] {
            assert!(
                matches!(
                    registry.unsupported(tag),
                    Some(OutboundSlot::ProtocolNotWired { .. })
                ),
                "{tag}"
            );
        }
        let mut engine = ProxyEngine::from_registry(registry).expect("engine");
        for tag in ["v", "h"] {
            let err = engine
                .handle_packet(&craft_syn([127, 0, 0, 1], 18080), tag)
                .expect_err("protocol not wired");
            assert!(matches!(
                err,
                ProxyEngineError::UnsupportedOutboundKind { .. }
            ));
        }
    }

    #[test]
    fn registry_no_wired_is_no_usable_outbound() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        match OutboundRegistry::build(Some(yaml)) {
            Err(EngineInitError::NoUsableOutbound { skipped }) => {
                assert_eq!(skipped.len(), 1);
                assert_eq!(skipped[0].reason, SkipReason::NotProxyKind);
            }
            other => panic!("expected NoUsableOutbound, got {other:?}"),
        }
    }

    #[test]
    fn registry_none_yaml_is_ok_none() {
        assert!(OutboundRegistry::build(None).expect("ok").is_none());
        assert!(ProxyEngine::new(None).expect("ok").is_none());
    }

    #[test]
    fn registry_bad_yaml_is_yaml_variant() {
        match OutboundRegistry::build(Some("not: [valid")) {
            Err(EngineInitError::Yaml(_)) => {}
            other => panic!("expected Yaml, got {other:?}"),
        }
    }

    #[test]
    fn has_dial_config_is_at_least_one_dialer() {
        let yaml = yaml_with("socks5", "127.0.0.1:1080", "");
        let engine = engine(&yaml);
        assert!(engine.has_dial_config());
        assert!(engine.registry().has_any_dialer());
        assert_eq!(engine.registry().wired_tags().count(), 1);
    }

    #[test]
    fn engine_unknown_tag() {
        let yaml = yaml_with("socks5", "127.0.0.1:1080", "");
        let mut engine = engine(&yaml);
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
    fn engine_dial_failure_emits_structured_stream_event() {
        let yaml = yaml_with("socks5", "127.0.0.1:1", "");
        let mut engine = engine(&yaml);
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
                let ProxyStreamEvent::Failed {
                    kind,
                    tag,
                    error,
                    detail,
                    ..
                } = event;
                failed = Some((kind, tag, error, detail));
            }
            if failed.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (kind, tag, error, detail) = failed.expect("dial failure must surface");
        assert_eq!(kind, "socks5");
        assert_eq!(tag, "test");
        assert!(
            error == "io" || error == "tcp_connect",
            "unexpected dial error class: {error}"
        );
        assert!(!detail.is_empty());
        assert!(engine.stats().tcp_dials_failed >= 1);
    }

    #[test]
    fn registry_domain_locator_resolved_once() {
        // 域名 locator：构造期解析一次；不可解析 → SelectedInvalid（Q-6=A）。
        let yaml = yaml_with("socks5", "definitely-not-a-real-host.invalid:1080", "");
        match OutboundRegistry::build(Some(&yaml)) {
            Err(EngineInitError::SelectedInvalid { tag, source }) => {
                assert_eq!(tag, "test");
                assert_eq!(source.name(), "UNRESOLVABLE_LOCATOR");
            }
            other => panic!("expected SelectedInvalid(UNRESOLVABLE_LOCATOR), got {other:?}"),
        }
    }
}
