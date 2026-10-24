//! 生产 `ChainDeps`：从 `proxy.yaml` 出站派生 Provider，注入真实快照（spec §9.7）。
//!
//! `derive_providers` 是纯函数：只读已经过配置层校验的 `ProxyConfig`，不重新解析
//! YAML，不访问网络。Provider 身份在本 run 里 1:1 对应出站 tag（Q4 定案）。

use std::sync::{Arc, Mutex};

use nexus_domain::{FlowContext, ProviderId, ResourceId};
use nexus_flow_session::ChainDeps;
use nexus_planner::PlanningSnapshot;
use nexus_policy::PolicyEngine;
use nexus_proxy_config::{OutboundKind, ProxyConfig};
use nexus_registry::{ProviderRecord, Registry};

/// Provider 派生结构化错误（spec §8.7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderDeriveError {
    /// 出站之间/出站与策略组重名。
    DuplicateTag {
        /// tag。
        tag: String,
    },
    /// 非 direct 出站或策略组使用保留 tag `DIRECT`/`direct`。
    ReservedTag {
        /// tag。
        tag: String,
    },
    /// tag 为空/含空白/控制字符/超长。
    InvalidTag {
        /// tag。
        tag: String,
        /// 原因。
        reason: &'static str,
    },
    /// 需要 locator 的出站缺失 locator。
    MissingLocator {
        /// tag。
        tag: String,
    },
}

impl std::fmt::Display for ProviderDeriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateTag { tag } => write!(f, "duplicate tag '{tag}'"),
            Self::ReservedTag { tag } => write!(f, "reserved tag '{tag}'"),
            Self::InvalidTag { tag, reason } => write!(f, "invalid tag '{tag}': {reason}"),
            Self::MissingLocator { tag } => {
                write!(f, "outbound '{tag}' requires a locator")
            }
        }
    }
}

impl std::error::Error for ProviderDeriveError {}

/// 组合根 ChainDeps 装配错误（spec §8.9）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDepsError {
    /// `network.toml` 非法。
    NetworkConfig(String),
    /// `proxy.yaml` 非法。
    ProxyConfig(nexus_proxy_config::ConfigError),
    /// Provider 派生失败。
    Provider(ProviderDeriveError),
    /// Policy 初始化失败。
    PolicyInit(String),
}

impl std::fmt::Display for ChainDepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkConfig(e) => write!(f, "CONFIG_INVALID [network]: {e}"),
            Self::ProxyConfig(e) => write!(f, "CONFIG_INVALID [proxy]: {e}"),
            Self::Provider(e) => write!(f, "CONFIG_INVALID [outbounds]: {e}"),
            Self::PolicyInit(e) => write!(f, "CONFIG_INVALID [policy]: {e}"),
        }
    }
}

impl std::error::Error for ChainDepsError {}

fn validate_tag(tag: &str) -> Result<(), ProviderDeriveError> {
    if tag.is_empty() {
        return Err(ProviderDeriveError::InvalidTag {
            tag: tag.to_string(),
            reason: "tag must not be empty",
        });
    }
    if tag.len() > 64 {
        return Err(ProviderDeriveError::InvalidTag {
            tag: tag.to_string(),
            reason: "tag must be at most 64 characters",
        });
    }
    if tag.trim() != tag {
        return Err(ProviderDeriveError::InvalidTag {
            tag: tag.to_string(),
            reason: "tag must not have leading or trailing whitespace",
        });
    }
    if tag.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ProviderDeriveError::InvalidTag {
            tag: tag.to_string(),
            reason: "tag must not contain whitespace or control characters",
        });
    }
    Ok(())
}

/// 从 `proxy.yaml` 出站派生 Provider 记录（Q4 定案；direct 不入 Registry）。
pub fn derive_providers(config: &ProxyConfig) -> Result<Vec<ProviderRecord>, ProviderDeriveError> {
    let mut seen: Vec<String> = Vec::new();

    for outbound in &config.outbounds {
        validate_tag(&outbound.tag)?;
        if outbound.kind != OutboundKind::Direct && outbound.tag.eq_ignore_ascii_case("direct") {
            return Err(ProviderDeriveError::ReservedTag {
                tag: outbound.tag.clone(),
            });
        }
        if seen.contains(&outbound.tag) {
            return Err(ProviderDeriveError::DuplicateTag {
                tag: outbound.tag.clone(),
            });
        }
        seen.push(outbound.tag.clone());
    }
    for group in &config.groups {
        validate_tag(&group.tag)?;
        if group.tag.eq_ignore_ascii_case("direct") {
            return Err(ProviderDeriveError::ReservedTag {
                tag: group.tag.clone(),
            });
        }
        if seen.contains(&group.tag) {
            return Err(ProviderDeriveError::DuplicateTag {
                tag: group.tag.clone(),
            });
        }
        seen.push(group.tag.clone());
    }

    let mut providers = Vec::new();
    for outbound in &config.outbounds {
        if outbound.kind == OutboundKind::Direct {
            continue;
        }
        let needs_locator = matches!(
            outbound.kind,
            OutboundKind::Trojan
                | OutboundKind::Anytls
                | OutboundKind::Vless
                | OutboundKind::Hysteria2
        );
        let locator = outbound.locator.clone().unwrap_or_default();
        if needs_locator && locator.is_empty() {
            return Err(ProviderDeriveError::MissingLocator {
                tag: outbound.tag.clone(),
            });
        }
        providers.push(ProviderRecord {
            id: ProviderId(outbound.tag.clone()),
            resource: ResourceId("internet-access".to_string()),
            placement: outbound.kind.as_str().to_string(),
            locator,
            capabilities: vec!["internet-access".to_string()],
            present: true,
        });
    }
    Ok(providers)
}

/// 构建只包含派生 Provider 的 Registry。
///
/// # Errors
///
/// 同 [`derive_providers`]。
pub fn build_registry(config: &ProxyConfig) -> Result<Registry, ProviderDeriveError> {
    let mut registry = Registry::new();
    for record in derive_providers(config)? {
        registry.register(record);
    }
    Ok(registry)
}

/// 生产 ChainDeps 持有者（组合根）。
#[derive(Clone)]
pub struct ProductionChainDeps {
    registry: Arc<Mutex<Registry>>,
    policy: PolicyEngine,
    measurements: Option<Arc<dyn nexus_proxy::MeasurementSource + Send + Sync>>,
    provider_tags: Vec<String>,
}

impl ProductionChainDeps {
    /// 从可选配置文本装配。
    ///
    /// # Errors
    ///
    /// network/proxy 配置非法或 Provider 派生失败。
    pub fn from_config(
        network_toml: Option<&str>,
        proxy_yaml: Option<&str>,
    ) -> Result<Self, ChainDepsError> {
        if let Some(text) = network_toml {
            let _: toml::Value =
                toml::from_str(text).map_err(|e| ChainDepsError::NetworkConfig(e.to_string()))?;
        }
        let config = match proxy_yaml {
            Some(text) => {
                Some(nexus_proxy_config::parse(text).map_err(ChainDepsError::ProxyConfig)?)
            }
            None => None,
        };
        let (registry, provider_tags) = match config.as_ref() {
            Some(config) => {
                let records = derive_providers(config).map_err(ChainDepsError::Provider)?;
                let tags = records.iter().map(|r| r.id.0.clone()).collect();
                let registry = build_registry(config).map_err(ChainDepsError::Provider)?;
                (registry, tags)
            }
            None => (Registry::new(), Vec::new()),
        };
        Ok(Self {
            registry: Arc::new(Mutex::new(registry)),
            policy: PolicyEngine::default_network(),
            measurements: None,
            provider_tags,
        })
    }

    /// 注入 measurement 源（本 run 不启用主动测速）。
    pub fn set_measurements(
        &mut self,
        measurements: Option<Arc<dyn nexus_proxy::MeasurementSource + Send + Sync>>,
    ) {
        self.measurements = measurements;
    }

    /// 派生 Provider 数量；0 = 无 provider 源（`reason=no_providers`）。
    pub fn provider_count(&self) -> usize {
        self.provider_tags.len()
    }

    /// 派生 Provider tag 列表（只读；LocalAPI 不暴露列表）。
    pub fn provider_tags(&self) -> &[String] {
        &self.provider_tags
    }

    /// 构造会话层 ChainDeps；`build_snapshot` 按 `egress_hint` 过滤候选。
    pub fn to_chain_deps(&self) -> ChainDeps {
        let registry = Arc::clone(&self.registry);
        let policy = self.policy.clone();
        let measurements = self.measurements.clone();
        let measure = Box::new(move |_provider: &ProviderId| {
            let _ = measurements.as_ref()?;
            // 本 run 不启用主动测速：未知返回 None（不伪造 0 RTT）。
            None
        });
        ChainDeps {
            policy: self.policy.clone(),
            build_snapshot: Box::new(move |flow: &FlowContext| {
                let probe = policy.evaluate(flow);
                let candidates = match flow.egress_hint.as_deref() {
                    Some(tag) => {
                        let registry = registry.lock().expect("registry poisoned");
                        let mut candidates = registry.candidates(&flow.resource);
                        candidates.retain(|record| record.id.0 == tag);
                        candidates
                    }
                    // 调用方违约（Direct/Mesh 不进入会话层）：防御性空候选。
                    None => Vec::new(),
                };
                PlanningSnapshot::new(candidates, probe.decision.constraints)
            }),
            measure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "\
schema_version: 1
rules:
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: p1
    kind: shadowsocks
    locator: p1.example:443
    method: chacha20-ietf-poly1305
    password: test-password
  - tag: p2
    kind: trojan
    locator: p2.example:443
    password: test-password
";

    fn config(yaml: &str) -> ProxyConfig {
        nexus_proxy_config::parse(yaml).expect("config parses")
    }

    #[test]
    fn chain_wiring_derives_direct_ss_trojan() {
        let records = derive_providers(&config(YAML)).expect("derive");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, ProviderId("p1".into()));
        assert_eq!(records[0].placement, "shadowsocks");
        assert_eq!(records[0].locator, "p1.example:443");
        assert_eq!(records[0].resource, ResourceId("internet-access".into()));
        assert_eq!(records[0].capabilities, vec!["internet-access"]);
        assert!(records[0].present);
        assert_eq!(records[1].id, ProviderId("p2".into()));
    }

    #[test]
    fn chain_wiring_empty_when_all_direct() {
        let yaml = "\
schema_version: 1
rules:
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
groups: []
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
";
        let records = derive_providers(&config(yaml)).expect("derive");
        assert!(records.is_empty());
    }

    #[test]
    fn chain_wiring_rejects_duplicate_reserved_invalid_and_missing_locator() {
        // 配置层已拒绝重复/保留/非法 tag；derive_providers 做防御性复查。
        let mut duplicate = config(YAML);
        duplicate.outbounds[2].tag = "p1".to_string();
        assert!(matches!(
            derive_providers(&duplicate),
            Err(ProviderDeriveError::DuplicateTag { .. })
        ));

        let mut reserved = config(YAML);
        reserved.outbounds[1].tag = "DIRECT".to_string();
        assert!(matches!(
            derive_providers(&reserved),
            Err(ProviderDeriveError::ReservedTag { .. })
        ));

        let mut invalid = config(YAML);
        invalid.outbounds[1].tag = "p 1".to_string();
        assert!(matches!(
            derive_providers(&invalid),
            Err(ProviderDeriveError::InvalidTag { .. })
        ));

        let mut missing = config(YAML);
        missing.outbounds[2].locator = Some(String::new());
        assert!(matches!(
            derive_providers(&missing),
            Err(ProviderDeriveError::MissingLocator { .. })
        ));
    }

    #[test]
    fn chain_wiring_snapshot_filters_by_egress_hint() {
        let deps = ProductionChainDeps::from_config(None, Some(YAML)).expect("deps");
        assert_eq!(deps.provider_count(), 2);
        let chain = deps.to_chain_deps();
        let flow = FlowContext {
            origin: nexus_domain::FlowOrigin::TransparentSocket,
            resource: ResourceId("internet-access".into()),
            destination: "example.com:443".into(),
            profile: "Balanced".into(),
            egress_hint: Some("p1".to_string()),
        };
        let snapshot = (chain.build_snapshot)(&flow);
        assert_eq!(snapshot.candidates.len(), 1);
        assert_eq!(snapshot.candidates[0].id, ProviderId("p1".into()));

        // hint 指向不存在的 tag → 空候选（不回退为全部候选）。
        let flow = FlowContext {
            egress_hint: Some("missing".to_string()),
            ..flow
        };
        let snapshot = (chain.build_snapshot)(&flow);
        assert!(snapshot.candidates.is_empty());

        // None 是调用方违约 → 防御性空候选。
        let flow = FlowContext {
            egress_hint: None,
            ..flow
        };
        let snapshot = (chain.build_snapshot)(&flow);
        assert!(snapshot.candidates.is_empty());
    }
}
