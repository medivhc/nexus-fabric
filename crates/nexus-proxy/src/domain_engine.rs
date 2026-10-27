//! `nexus_domain::RuleEngine` 适配器（spec §9.4 / §5 G2）。
//!
//! 把 Clash 规则核心（[`crate::RuleEngine`] + [`crate::ProxyService`]）适配为
//! 领域层统一规则接口，供 TUN / TPROXY 前端共用同一实现。
//!
//! 映射（spec §9.4）：
//! - `DIRECT` / `kind: direct` 出站 → `RouteTarget::Egress { peer: "self" }`
//! - 代理出站 tag → `RouteTarget::Egress { peer: <tag> }`
//! - `REJECT` / `reject` tag → `RouteTarget::Drop`
//! - 策略组解析为具体出站 tag 后再映射
//!
//! 本类型必须 `Send + Sync`（可注入 `Box<dyn RuleEngine>` 跨线程使用）。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nexus_domain::{
    FlowContext, FlowOrigin, ResourceId, RouteRequest, RouteTarget, RuleEngine, RuleExplanation,
};
use nexus_proxy_config::{GroupKind, OutboundKind, ProxyConfig};

use crate::{MeasurementSource, ProxyError, ProxyService};

/// 适配层结构化错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRuleError {
    /// 配置无法构建规则表 / 策略组。
    InvalidConfig(ProxyError),
    /// urltest 策略组存在但未注入 measurement（启动期显式失败，spec §9.4）。
    UrlTestWithoutMeasurement { group: String },
}

impl core::fmt::Display for DomainRuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidConfig(e) => write!(f, "DOMAIN_RULE_INVALID_CONFIG: {e}"),
            Self::UrlTestWithoutMeasurement { group } => {
                write!(f, "URLTEST_WITHOUT_MEASUREMENT: {group}")
            }
        }
    }
}

impl std::error::Error for DomainRuleError {}

/// 适配层计数器（`AtomicU64`，跨线程安全）。
#[derive(Debug, Default)]
pub struct DomainRuleCounters {
    /// 决策总次数。
    pub decisions: AtomicU64,
    /// 直连决策次数。
    pub direct: AtomicU64,
    /// 代理出站决策次数。
    pub proxy: AtomicU64,
    /// 丢弃决策次数。
    pub drop: AtomicU64,
    /// 决策失败（目标无法解析 / tag 悬空）次数。
    pub errors: AtomicU64,
}

/// 计数器快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DomainRuleStats {
    /// 决策总次数。
    pub decisions: u64,
    /// 直连决策次数。
    pub direct: u64,
    /// 代理出站决策次数。
    pub proxy: u64,
    /// 丢弃决策次数。
    pub drop: u64,
    /// 决策失败次数。
    pub errors: u64,
    /// 规则条数。
    pub rules: usize,
}

/// Clash 规则核心到 `nexus_domain::RuleEngine` 的适配器。
pub struct DomainRuleEngine {
    service: ProxyService,
    measurements: Option<Arc<dyn MeasurementSource + Send + Sync>>,
    outbound_kinds: HashMap<String, OutboundKind>,
    counters: DomainRuleCounters,
    rule_count: usize,
}

impl DomainRuleEngine {
    /// 从已解析配置构建（无 measurement；存在 urltest 组时启动期失败）。
    ///
    /// # Errors
    ///
    /// 配置无法构建规则表，或 urltest 组缺少 measurement。
    pub fn from_config(config: &ProxyConfig) -> Result<Self, DomainRuleError> {
        Self::with_measurements(config, None)
    }

    /// 从 YAML 构建（无 measurement）。
    ///
    /// # Errors
    ///
    /// YAML 解析失败或规则表构建失败。
    pub fn from_yaml(yaml: &str) -> Result<Self, DomainRuleError> {
        let config = nexus_proxy_config::parse(yaml)
            .map_err(|e| DomainRuleError::InvalidConfig(ProxyError::Config(e)))?;
        Self::from_config(&config)
    }

    /// 从配置构建并注入可选 measurement 数据源。
    ///
    /// # Errors
    ///
    /// 配置无法构建规则表，或 urltest 组缺少 measurement。
    pub fn with_measurements(
        config: &ProxyConfig,
        measurements: Option<Arc<dyn MeasurementSource + Send + Sync>>,
    ) -> Result<Self, DomainRuleError> {
        if measurements.is_none() {
            if let Some(group) = config.groups.iter().find(|g| g.kind == GroupKind::UrlTest) {
                return Err(DomainRuleError::UrlTestWithoutMeasurement {
                    group: group.tag.clone(),
                });
            }
        }
        let service = ProxyService::new(config).map_err(DomainRuleError::InvalidConfig)?;
        let outbound_kinds = config
            .outbounds
            .iter()
            .map(|o| (o.tag.clone(), o.kind))
            .collect();
        Ok(Self {
            service,
            measurements,
            outbound_kinds,
            counters: DomainRuleCounters::default(),
            rule_count: config.rules.len(),
        })
    }

    /// 计数器快照。
    #[must_use]
    pub fn stats(&self) -> DomainRuleStats {
        DomainRuleStats {
            decisions: self.counters.decisions.load(Ordering::Relaxed),
            direct: self.counters.direct.load(Ordering::Relaxed),
            proxy: self.counters.proxy.load(Ordering::Relaxed),
            drop: self.counters.drop.load(Ordering::Relaxed),
            errors: self.counters.errors.load(Ordering::Relaxed),
            rules: self.rule_count,
        }
    }

    fn decide_inner(&self, req: &RouteRequest<'_>) -> (RouteTarget, Option<RuleExplanation>) {
        let flow = flow_for(req);
        let measurements: Option<&dyn MeasurementSource> = self
            .measurements
            .as_ref()
            .map(|m| m.as_ref() as &dyn MeasurementSource);
        let decision = match self.service.route(&flow, measurements) {
            Ok(d) => d,
            Err(_) => {
                self.counters.decisions.fetch_add(1, Ordering::Relaxed);
                self.counters.errors.fetch_add(1, Ordering::Relaxed);
                self.counters.drop.fetch_add(1, Ordering::Relaxed);
                return (RouteTarget::Drop, None);
            }
        };
        let tag = decision.selected_outbound_tag.as_str();
        let target = if tag.eq_ignore_ascii_case("reject") {
            self.counters.drop.fetch_add(1, Ordering::Relaxed);
            RouteTarget::Drop
        } else if self.outbound_kinds.get(tag) == Some(&OutboundKind::Direct) {
            self.counters.direct.fetch_add(1, Ordering::Relaxed);
            RouteTarget::Egress {
                peer: "self".to_string(),
            }
        } else if self.outbound_kinds.contains_key(tag) {
            self.counters.proxy.fetch_add(1, Ordering::Relaxed);
            RouteTarget::Egress {
                peer: tag.to_string(),
            }
        } else {
            self.counters.errors.fetch_add(1, Ordering::Relaxed);
            self.counters.drop.fetch_add(1, Ordering::Relaxed);
            RouteTarget::Drop
        };
        self.counters.decisions.fetch_add(1, Ordering::Relaxed);
        let explanation = RuleExplanation {
            matched_rule: decision.matched_rule,
            rule_kind: decision.rule_kind.as_str().to_string(),
        };
        (target, Some(explanation))
    }
}

impl RuleEngine for DomainRuleEngine {
    fn decide(&self, req: &RouteRequest<'_>) -> RouteTarget {
        self.decide_inner(req).0
    }

    fn explain(&self, req: &RouteRequest<'_>) -> (RouteTarget, Option<RuleExplanation>) {
        self.decide_inner(req)
    }
}

/// 由领域路由请求构造中立 `FlowContext`（不引入平台/会话语义）。
fn flow_for(req: &RouteRequest<'_>) -> FlowContext {
    let destination = match req.domain {
        Some(domain) => match req.dst_port {
            Some(port) => format!("{domain}:{port}"),
            None => domain.to_string(),
        },
        None => match parse_ipv4_dst(req.packet) {
            Some(ip) => match req.dst_port {
                Some(port) => format!("{ip}:{port}"),
                None => ip.to_string(),
            },
            None => String::new(),
        },
    };
    FlowContext {
        origin: FlowOrigin::TransparentSocket,
        resource: ResourceId("internet-access".to_string()),
        destination,
        profile: String::new(),
        egress_hint: None,
    }
}

/// 解析 IPv4 目的地址（与 `nexus-projection` 的包解析语义一致）。
fn parse_ipv4_dst(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "schema_version: 1\nrules:\n  - tag: direct-rule\n    kind: domain_suffix\n    match: internal.example\n    action:\n      - kind: select_outbound\n        tag: d\n  - tag: proxy-rule\n    kind: ip_cidr\n    match: 1.2.3.0/24\n    action:\n      - kind: select_outbound\n        tag: p1\n  - tag: match-all\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: p1\noutbounds:\n  - tag: d\n    kind: direct\n  - tag: p1\n    kind: socks5\n    locator: 127.0.0.1:1080\n";

    fn ipv4_packet(dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&443u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    fn req<'a>(packet: &'a [u8], domain: Option<&'a str>, dport: u16) -> RouteRequest<'a> {
        RouteRequest {
            packet,
            domain,
            src_port: Some(40000),
            dst_port: Some(dport),
            process_name: None,
        }
    }

    #[test]
    fn domain_suffix_direct_maps_to_self() {
        let e = DomainRuleEngine::from_yaml(YAML).unwrap();
        let pkt = ipv4_packet([10, 0, 0, 1], 443);
        let (target, explanation) = e.explain(&req(&pkt, Some("api.internal.example"), 443));
        assert_eq!(
            target,
            RouteTarget::Egress {
                peer: "self".to_string()
            }
        );
        let explanation = explanation.unwrap();
        assert_eq!(explanation.rule_kind, "domain_suffix");
        assert_eq!(explanation.matched_rule, "direct-rule");
    }

    #[test]
    fn ip_cidr_proxy_maps_to_tag() {
        let e = DomainRuleEngine::from_yaml(YAML).unwrap();
        let pkt = ipv4_packet([1, 2, 3, 4], 443);
        assert_eq!(
            e.decide(&req(&pkt, None, 443)),
            RouteTarget::Egress {
                peer: "p1".to_string()
            }
        );
    }

    #[test]
    fn stats_are_deterministic_across_calls() {
        let e = DomainRuleEngine::from_yaml(YAML).unwrap();
        let pkt = ipv4_packet([1, 2, 3, 4], 443);
        assert_eq!(
            e.decide(&req(&pkt, None, 443)),
            e.decide(&req(&pkt, None, 443))
        );
        let stats = e.stats();
        assert_eq!(stats.decisions, 2);
        assert_eq!(stats.proxy, 2);
        assert_eq!(stats.rules, 3);
    }

    #[test]
    fn urltest_without_measurement_fails_at_startup() {
        let yaml = "schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: g\noutbounds:\n  - tag: p1\n    kind: socks5\n    locator: 127.0.0.1:1080\n  - tag: p2\n    kind: socks5\n    locator: 127.0.0.1:1081\ngroups:\n  - tag: g\n    kind: urltest\n    candidates: [p1, p2]\n";
        let err = DomainRuleEngine::from_yaml(yaml).err().unwrap();
        assert_eq!(
            err,
            DomainRuleError::UrlTestWithoutMeasurement {
                group: "g".to_string()
            }
        );
    }

    #[test]
    fn selector_resolves_to_concrete_tag() {
        let yaml = "schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: g\noutbounds:\n  - tag: p1\n    kind: socks5\n    locator: 127.0.0.1:1080\ngroups:\n  - tag: g\n    kind: selector\n    candidates: [p1]\n";
        let e = DomainRuleEngine::from_yaml(yaml).unwrap();
        let pkt = ipv4_packet([9, 9, 9, 9], 443);
        assert_eq!(
            e.decide(&req(&pkt, None, 443)),
            RouteTarget::Egress {
                peer: "p1".to_string()
            }
        );
    }

    #[test]
    fn reject_tag_maps_to_drop() {
        let yaml = "schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: REJECT\noutbounds:\n  - tag: REJECT\n    kind: direct\n  - tag: d\n    kind: direct\n";
        let e = DomainRuleEngine::from_yaml(yaml).unwrap();
        let pkt = ipv4_packet([9, 9, 9, 9], 443);
        assert_eq!(e.decide(&req(&pkt, None, 443)), RouteTarget::Drop);
    }

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DomainRuleEngine>();
    }
}
