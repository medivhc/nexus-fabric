//! §11.17 TUN 透明入站：per-packet NAT/决策缓存（portable，零网络 I/O）。
//!
//! wintun/VPI 每来一个 IP 包，不能像 SOCKS5 那样每连接决策一次——必须按 5 元组缓存
//! 首包的 `RoutingDecision`，同流后续包直接命中。本模块是 TUN per-packet 数据面相对
//! SOCKS5 per-stream 的独立决策频率维度（Deletion Test：删除它则每个 IP 包都重跑线性
//! 规则表）。它仍是领域局部组件，不产生第二套系统级 Plan。

use std::collections::HashMap;

use nexus_domain::FlowContext;
use nexus_ingress::from_virtual_packet_interface;
use nexus_ingress::ip_packet::TunPacket;

use crate::{ProxyError, ProxyService, RoutingDecision};

/// 一次 TUN 包路由的可观察结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunRouteOutcome {
    /// 中立目的地 `"dst_ip:dst_port"`。
    pub destination: String,
    /// IP 层协议号（TCP=6 / UDP=17）。
    pub protocol: u8,
    /// 流量来源标签（`virtual-packet-interface`）。
    pub flow_origin: String,
    /// 命中规则名。
    pub matched_rule: String,
    /// 命中规则类型。
    pub rule_kind: String,
    /// 最终选定出站 tag。
    pub selected_outbound_tag: String,
    /// 是否命中 5 元组缓存（true = 复用首包决策，未重跑规则表）。
    pub cache_hit: bool,
}

/// TUN 入站计数器（§11.17 可观测性；counter，禁止 per-packet 日志）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunStats {
    /// 收到并尝试处理的包总数。
    pub packets: u64,
    /// 收到的字节总数。
    pub bytes: u64,
    /// 无法解析或非 TCP/UDP 而丢弃的包数。
    pub dropped: u64,
    /// 当前活跃 5 元组映射数（首包建表次数）。
    pub mappings: u64,
    /// 命中 NAT 缓存的包数。
    pub cache_hits: u64,
}

/// 5 元组键：`(protocol, src_ip, src_port, dst_ip, dst_port)`。
type FlowKey = (u8, [u8; 4], u16, [u8; 4], u16);

/// TUN NAT/决策路由器：持有 `ProxyService` + 5 元组决策缓存。
pub struct TunNatRouter {
    service: ProxyService,
    cache: HashMap<FlowKey, RoutingDecision>,
    stats: TunStats,
}

impl TunNatRouter {
    /// 从 `ProxyService` 构造（规则表/组/出站注册表已装载）。
    #[must_use]
    pub fn new(service: ProxyService) -> Self {
        Self {
            service,
            cache: HashMap::new(),
            stats: TunStats::default(),
        }
    }

    /// 路由一个已解析的 TUN 包：首包 miss 走规则引擎并建映射；同流后续包 hit 复用缓存。
    ///
    /// `packet_len` 为原始 IP 包字节数（计入 bytes 计数）。
    ///
    /// # Errors
    ///
    /// 首包决策失败（目标不可解析 / 未命中 / tag 悬空）透传 `ProxyError`；缓存命中不重新决策。
    pub fn route_packet(
        &mut self,
        pkt: &TunPacket,
        packet_len: usize,
    ) -> Result<TunRouteOutcome, ProxyError> {
        self.stats.packets += 1;
        self.stats.bytes += packet_len as u64;
        let key = pkt.flow_key();
        let destination = pkt.destination();

        if let Some(cached) = self.cache.get(&key) {
            self.stats.cache_hits += 1;
            return Ok(Self::outcome(&destination, pkt.protocol, cached, true));
        }

        let flow: FlowContext = from_virtual_packet_interface(&destination, "");
        let decision = self.service.route(&flow, None)?;
        self.cache.insert(key, decision.clone());
        self.stats.mappings += 1;
        Ok(Self::outcome(&destination, pkt.protocol, &decision, false))
    }

    /// 记录一个被丢弃的包（无法解析 / 非 TCP/UDP）。
    pub fn record_dropped(&mut self, packet_len: usize) {
        self.stats.packets += 1;
        self.stats.bytes += packet_len as u64;
        self.stats.dropped += 1;
    }

    /// 当前计数器快照。
    #[must_use]
    pub fn stats(&self) -> TunStats {
        self.stats
    }

    fn outcome(
        destination: &str,
        protocol: u8,
        d: &RoutingDecision,
        cache_hit: bool,
    ) -> TunRouteOutcome {
        TunRouteOutcome {
            destination: destination.to_string(),
            protocol,
            flow_origin: d.flow_origin.clone(),
            matched_rule: d.matched_rule.clone(),
            rule_kind: d.rule_kind.as_str().to_string(),
            selected_outbound_tag: d.selected_outbound_tag.clone(),
            cache_hit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::FlowOrigin;
    use nexus_ingress::ip_packet::{PROTO_TCP, PROTO_UDP, parse_ipv4_packet};
    use nexus_proxy_config::parse;

    const CFG: &str = "\
schema_version: 1
rules:
  - tag: rule-internal-cidr
    kind: ip_cidr
    match: 10.0.0.0/8
    action:
      - kind: select_outbound
        tag: relay-group
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
groups:
  - tag: relay-group
    kind: selector
    candidates: [relay]
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: relay
    kind: relay
    locator: relay.internal:443
";

    fn router() -> TunNatRouter {
        let cfg = parse(CFG).expect("config must parse");
        let service = ProxyService::new(&cfg).expect("service build");
        TunNatRouter::new(service)
    }

    fn pkt(protocol: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = (4u8 << 4) | 5;
        p[9] = protocol;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn first_packet_routes_and_caches() {
        let mut r = router();
        let raw = pkt(PROTO_TCP, [192, 168, 1, 5], 12345, [10, 1, 2, 3], 443);
        let parsed = parse_ipv4_packet(&raw).unwrap();
        let out = r.route_packet(&parsed, raw.len()).expect("route");
        assert_eq!(out.destination, "10.1.2.3:443");
        assert_eq!(out.flow_origin, "virtual-packet-interface");
        assert_eq!(out.matched_rule, "rule-internal-cidr");
        assert_eq!(out.selected_outbound_tag, "relay");
        assert!(!out.cache_hit);
        assert_eq!(r.stats().mappings, 1);

        // 同 5 元组第二个包 -> cache hit，mappings 不增。
        let out2 = r.route_packet(&parsed, raw.len()).expect("route");
        assert!(out2.cache_hit);
        assert_eq!(out2.matched_rule, "rule-internal-cidr");
        assert_eq!(r.stats().mappings, 1);
        assert_eq!(r.stats().cache_hits, 1);
    }

    #[test]
    fn distinct_flows_build_distinct_mappings() {
        let mut r = router();
        let tcp = pkt(PROTO_TCP, [192, 168, 1, 5], 12345, [10, 1, 2, 3], 443);
        let udp = pkt(PROTO_UDP, [192, 168, 1, 5], 53000, [8, 8, 8, 8], 53);
        r.route_packet(&parse_ipv4_packet(&tcp).unwrap(), tcp.len())
            .unwrap();
        let udp_out = r
            .route_packet(&parse_ipv4_packet(&udp).unwrap(), udp.len())
            .unwrap();
        assert_eq!(udp_out.matched_rule, "rule-match");
        assert_eq!(udp_out.selected_outbound_tag, "direct");
        assert_eq!(r.stats().mappings, 2);
    }

    #[test]
    fn dropped_packets_counted() {
        let mut r = router();
        r.record_dropped(20);
        r.record_dropped(0);
        assert_eq!(r.stats().dropped, 2);
        assert_eq!(r.stats().packets, 2);
    }

    #[test]
    fn flow_origin_is_virtual_packet_interface() {
        // 直接构造校验 origin_tag 一致性。
        assert_eq!(
            crate::origin_tag(FlowOrigin::VirtualPacketInterface),
            "virtual-packet-interface"
        );
    }
}
