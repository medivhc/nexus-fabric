//! DNS-time proxy classification from the `proxy.yaml` domain subset (§4.4).
//!
//! Deliberately does **not** depend on `nexus-proxy::RuleEngine`: geo/rule-set
//! data is not loaded in the daemon, so those rules are counted as
//! *unevaluable* and resolved by `[dns].unevaluable` (conservative default:
//! proxied). `ip_cidr` / `geoip` / port / process rules cannot match a bare
//! domain and are skipped, mirroring `RuleEngine`'s `None`-field semantics.
//!
//! Usable-outbound detection is delegated to
//! `nexus::outbound_manifest::select_index` (F1 / §6.2); this module never
//! implements a second notion of "usable".

use nexus_proxy_config::{ActionKind, OutboundKind, ProxyConfig, RuleKind};

use crate::config::DnsProxyPolicy;
use crate::dns_status::UnevaluablePolicy;

/// One DNS-evaluable rule after action resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleMatcher {
    /// Exact domain (lowercase).
    Domain(String),
    /// Domain or `.{suffix}` (lowercase).
    DomainSuffix(String),
    /// Always matches.
    Match,
    /// Needs unloaded data; resolved by the policy.
    Unevaluable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsRule {
    matcher: RuleMatcher,
    proxied: bool,
}

/// DNS-time classification outcome (exposed for counters/tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClassifyOutcome {
    /// A DNS-evaluable rule matched.
    Rule {
        /// Whether the rule selects a proxy.
        proxied: bool,
    },
    /// A rule needed unloaded data (`geosite` / `rule_set`).
    Unevaluable {
        /// Effective verdict from `[dns].unevaluable`.
        proxied: bool,
    },
    /// No rule matched; `[dns].unmatched` decided.
    Unmatched {
        /// Effective verdict.
        proxied: bool,
    },
}

impl DnsClassifyOutcome {
    /// Effective proxied verdict.
    #[must_use]
    pub fn proxied(&self) -> bool {
        match self {
            Self::Rule { proxied }
            | Self::Unevaluable { proxied }
            | Self::Unmatched { proxied } => *proxied,
        }
    }

    /// Whether the outcome consumed an unevaluable rule.
    #[must_use]
    pub fn is_unevaluable(&self) -> bool {
        matches!(self, Self::Unevaluable { .. })
    }
}

/// Startup failures for the DNS classifier (§6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsClassifierError {
    /// `proxy.yaml` did not parse, or a rule has no `select_outbound` action.
    InvalidProxyConfig(String),
    /// Action tag is neither an outbound nor a group.
    UndefinedActionTag(String),
    /// `unmatched=proxied` without a usable outbound.
    ProxiedWithoutOutbound,
}

impl std::fmt::Display for DnsClassifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProxyConfig(detail) => {
                write!(f, "dns classifier: invalid proxy.yaml: {detail}")
            }
            Self::UndefinedActionTag(tag) => {
                write!(f, "dns classifier: undefined action tag '{tag}'")
            }
            Self::ProxiedWithoutOutbound => write!(
                f,
                "dns classifier: unmatched=proxied requires a usable outbound"
            ),
        }
    }
}

impl std::error::Error for DnsClassifierError {}

/// Domain-subset classifier implementing [`nexus_dns::ProxyClassifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProxyClassifier {
    rules: Vec<DnsRule>,
    default_proxied: bool,
    policy: DnsProxyPolicy,
    rule_count: usize,
    unevaluable_rules: usize,
}

impl DnsProxyClassifier {
    /// Build from `proxy.yaml` plus the effective DNS policy.
    ///
    /// `has_usable_outbound` must come from
    /// [`usable_outbound`] (which calls `outbound_manifest::select_index`).
    ///
    /// # Errors
    ///
    /// See [`DnsClassifierError`].
    pub fn from_yaml(
        proxy_yaml: &str,
        policy: DnsProxyPolicy,
        has_usable_outbound: bool,
    ) -> Result<Self, DnsClassifierError> {
        let config = nexus_proxy_config::parse(proxy_yaml)
            .map_err(|e| DnsClassifierError::InvalidProxyConfig(e.to_string()))?;
        Self::from_proxy_config(config, policy, has_usable_outbound)
    }

    /// Build from an already-parsed config (C11 may parse once for both the
    /// engine and the classifier).
    ///
    /// # Errors
    ///
    /// See [`DnsClassifierError`].
    pub(crate) fn from_proxy_config(
        config: ProxyConfig,
        policy: DnsProxyPolicy,
        has_usable_outbound: bool,
    ) -> Result<Self, DnsClassifierError> {
        let mut rules = Vec::new();
        let mut unevaluable_rules = 0;
        for rule in &config.rules {
            let action = rule
                .action
                .actions
                .iter()
                .find(|action| action.kind == ActionKind::SelectOutbound)
                .ok_or_else(|| {
                    DnsClassifierError::InvalidProxyConfig(format!(
                        "rule '{}' has no select_outbound action",
                        rule.tag
                    ))
                })?;
            let proxied =
                if let Some(outbound) = config.outbounds.iter().find(|o| o.tag == action.tag) {
                    !matches!(outbound.kind, OutboundKind::Direct)
                } else if config.groups.iter().any(|group| group.tag == action.tag) {
                    // A group may select a proxy; conservative (§4.4).
                    true
                } else {
                    return Err(DnsClassifierError::UndefinedActionTag(action.tag.clone()));
                };
            let matcher = match rule.kind {
                RuleKind::Domain => RuleMatcher::Domain(rule.pattern.to_ascii_lowercase()),
                RuleKind::DomainSuffix => {
                    RuleMatcher::DomainSuffix(rule.pattern.to_ascii_lowercase())
                }
                RuleKind::Match => RuleMatcher::Match,
                RuleKind::GeoSite | RuleKind::RuleSet => {
                    unevaluable_rules += 1;
                    RuleMatcher::Unevaluable
                }
                RuleKind::IpCidr
                | RuleKind::GeoIp
                | RuleKind::SrcPort
                | RuleKind::DstPort
                | RuleKind::ProcessName => continue,
            };
            rules.push(DnsRule { matcher, proxied });
        }

        let default_proxied = match policy.unmatched {
            crate::dns_status::UnmatchedPolicy::Auto => has_usable_outbound,
            crate::dns_status::UnmatchedPolicy::Proxied => {
                if !has_usable_outbound {
                    return Err(DnsClassifierError::ProxiedWithoutOutbound);
                }
                true
            }
            crate::dns_status::UnmatchedPolicy::Upstream => false,
        };

        Ok(Self {
            rules,
            default_proxied,
            policy,
            rule_count: config.rules.len(),
            unevaluable_rules,
        })
    }

    /// Rules declared in `proxy.yaml` (including non-DNS kinds).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Rules that need unloaded data (`geosite` / `rule_set`).
    #[must_use]
    pub fn unevaluable_count(&self) -> usize {
        self.unevaluable_rules
    }

    /// Effective unmatched verdict.
    #[must_use]
    pub fn default_proxied(&self) -> bool {
        self.default_proxied
    }

    /// Classify a domain, reporting which stage decided.
    #[must_use]
    pub fn evaluate(&self, domain: &str) -> DnsClassifyOutcome {
        let lower = domain.to_ascii_lowercase();
        for rule in &self.rules {
            let hit = match &rule.matcher {
                RuleMatcher::Domain(pattern) => lower == *pattern,
                RuleMatcher::DomainSuffix(pattern) => {
                    lower == *pattern || lower.ends_with(&format!(".{pattern}"))
                }
                RuleMatcher::Match => true,
                RuleMatcher::Unevaluable => {
                    return DnsClassifyOutcome::Unevaluable {
                        proxied: self.policy.unevaluable == UnevaluablePolicy::Proxied,
                    };
                }
            };
            if hit {
                return DnsClassifyOutcome::Rule {
                    proxied: rule.proxied,
                };
            }
        }
        DnsClassifyOutcome::Unmatched {
            proxied: self.default_proxied,
        }
    }
}

impl nexus_dns::ProxyClassifier for DnsProxyClassifier {
    fn is_proxied(&self, domain: &str) -> bool {
        self.evaluate(domain).proxied()
    }
}

/// Current "usable outbound" definition: the first proxy-kind + wired outbound
/// in file order (F1 / §6.2). Delegates to the single source of truth.
///
/// # Errors
///
/// `proxy.yaml` parse failure.
pub fn usable_outbound(proxy_yaml: &str) -> Result<bool, DnsClassifierError> {
    let config = nexus_proxy_config::parse(proxy_yaml)
        .map_err(|e| DnsClassifierError::InvalidProxyConfig(e.to_string()))?;
    Ok(nexus::outbound_manifest::select_index(&config.outbounds).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsProxyPolicy;
    use crate::dns_status::UnmatchedPolicy;

    const PROXY_YAML: &str = r#"
schema_version: 1
rules:
  - tag: exact
    kind: domain
    match: exact.example
    action:
      - kind: select_outbound
        tag: proxy
  - tag: suffix
    kind: domain_suffix
    match: corp.example
    action:
      - kind: select_outbound
        tag: direct
  - tag: all
    kind: match
    action:
      - kind: select_outbound
        tag: proxy
outbounds:
  - tag: direct
    kind: direct
  - tag: proxy
    kind: socks5
    locator: 127.0.0.1:1080
"#;

    fn policy(unmatched: UnmatchedPolicy, unevaluable: UnevaluablePolicy) -> DnsProxyPolicy {
        DnsProxyPolicy {
            unmatched,
            unevaluable,
        }
    }

    fn classifier(yaml: &str) -> DnsProxyClassifier {
        DnsProxyClassifier::from_yaml(
            yaml,
            policy(UnmatchedPolicy::Auto, UnevaluablePolicy::Proxied),
            true,
        )
        .expect("classifier builds")
    }

    #[test]
    fn domain_suffix_and_match_semantics() {
        let c = classifier(PROXY_YAML);
        assert_eq!(
            c.evaluate("exact.example"),
            DnsClassifyOutcome::Rule { proxied: true }
        );
        assert_eq!(
            c.evaluate("EXACT.EXAMPLE"),
            DnsClassifyOutcome::Rule { proxied: true }
        );
        // Exact rule does not match subdomains; the suffix rule does, to direct.
        assert_eq!(
            c.evaluate("sub.exact.example"),
            DnsClassifyOutcome::Rule { proxied: true }
        );
        assert_eq!(
            c.evaluate("a.corp.example"),
            DnsClassifyOutcome::Rule { proxied: false }
        );
        assert_eq!(
            c.evaluate("corp.example"),
            DnsClassifyOutcome::Rule { proxied: false }
        );
        // The trailing MATCH rule catches everything else.
        assert_eq!(
            c.evaluate("other.example"),
            DnsClassifyOutcome::Rule { proxied: true }
        );
        assert_eq!(c.rule_count(), 3);
        assert_eq!(c.unevaluable_count(), 0);
    }

    #[test]
    fn non_dns_rule_kinds_are_skipped() {
        let yaml = r#"
schema_version: 1
rules:
  - tag: cidr
    kind: ip_cidr
    match: 10.0.0.0/8
    action:
      - kind: select_outbound
        tag: proxy
  - tag: geo
    kind: geoip
    match: CN
    action:
      - kind: select_outbound
        tag: proxy
  - tag: port
    kind: dst_port
    match: "443"
    action:
      - kind: select_outbound
        tag: proxy
  - tag: proc
    kind: process_name
    match: curl
    action:
      - kind: select_outbound
        tag: proxy
  - tag: all
    kind: match
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
  - tag: proxy
    kind: socks5
    locator: 127.0.0.1:1080
"#;
        let c = classifier(yaml);
        // Only the MATCH rule is DNS-evaluable here.
        assert_eq!(c.rule_count(), 5);
        assert_eq!(
            c.evaluate("anything.example"),
            DnsClassifyOutcome::Rule { proxied: false }
        );
    }

    #[test]
    fn unevaluable_rules_follow_the_policy() {
        let yaml = r#"
schema_version: 1
rules:
  - tag: geo
    kind: geosite
    match: cn
    action:
      - kind: select_outbound
        tag: proxy
  - tag: all
    kind: match
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
  - tag: proxy
    kind: socks5
    locator: 127.0.0.1:1080
"#;
        let c = DnsProxyClassifier::from_yaml(
            yaml,
            policy(UnmatchedPolicy::Auto, UnevaluablePolicy::Proxied),
            true,
        )
        .expect("builds");
        assert_eq!(c.unevaluable_count(), 1);
        assert_eq!(
            c.evaluate("anything.example"),
            DnsClassifyOutcome::Unevaluable { proxied: true }
        );
        assert!(c.evaluate("anything.example").is_unevaluable());

        let c = DnsProxyClassifier::from_yaml(
            yaml,
            policy(UnmatchedPolicy::Auto, UnevaluablePolicy::Upstream),
            true,
        )
        .expect("builds");
        assert_eq!(
            c.evaluate("anything.example"),
            DnsClassifyOutcome::Unevaluable { proxied: false }
        );
    }

    #[test]
    fn group_actions_are_conservatively_proxied() {
        let yaml = r#"
schema_version: 1
rules:
  - tag: via-group
    kind: domain
    match: grouped.example
    action:
      - kind: select_outbound
        tag: g
  - tag: all
    kind: match
    action:
      - kind: select_outbound
        tag: direct
groups:
  - tag: g
    kind: selector
    candidates: [proxy]
outbounds:
  - tag: direct
    kind: direct
  - tag: proxy
    kind: socks5
    locator: 127.0.0.1:1080
"#;
        let c = classifier(yaml);
        assert_eq!(
            c.evaluate("grouped.example"),
            DnsClassifyOutcome::Rule { proxied: true }
        );
    }

    #[test]
    fn undefined_action_tag_is_an_error() {
        let mut config = nexus_proxy_config::parse(PROXY_YAML).expect("parses");
        config.rules[0].action.actions[0].tag = "ghost".to_string();
        let error = DnsProxyClassifier::from_proxy_config(
            config,
            policy(UnmatchedPolicy::Auto, UnevaluablePolicy::Proxied),
            true,
        )
        .expect_err("ghost tag rejected");
        assert_eq!(
            error,
            DnsClassifierError::UndefinedActionTag("ghost".to_string())
        );
    }

    #[test]
    fn proxied_without_outbound_is_an_error() {
        let error = DnsProxyClassifier::from_yaml(
            PROXY_YAML,
            policy(UnmatchedPolicy::Proxied, UnevaluablePolicy::Proxied),
            false,
        )
        .expect_err("proxied without outbound");
        assert_eq!(error, DnsClassifierError::ProxiedWithoutOutbound);
    }

    #[test]
    fn unmatched_policy_drives_default() {
        // Without a MATCH rule we can construct the config directly; the parser
        // requires MATCH, so patch the parsed rule list.
        let mut config = nexus_proxy_config::parse(PROXY_YAML).expect("parses");
        config.rules.truncate(1);
        let c = DnsProxyClassifier::from_proxy_config(
            config.clone(),
            policy(UnmatchedPolicy::Auto, UnevaluablePolicy::Proxied),
            true,
        )
        .expect("builds");
        assert!(c.default_proxied());
        assert_eq!(
            c.evaluate("unmatched.example"),
            DnsClassifyOutcome::Unmatched { proxied: true }
        );
        let c = DnsProxyClassifier::from_proxy_config(
            config,
            policy(UnmatchedPolicy::Auto, UnevaluablePolicy::Proxied),
            false,
        )
        .expect("builds");
        assert!(!c.default_proxied());
        assert_eq!(
            c.evaluate("unmatched.example"),
            DnsClassifyOutcome::Unmatched { proxied: false }
        );
    }

    #[test]
    fn usable_outbound_matches_select_index_semantics() {
        let socks5 = r#"
schema_version: 1
rules:
  - tag: all
    kind: match
    action:
      - kind: select_outbound
        tag: p
outbounds:
  - tag: p
    kind: socks5
    locator: 127.0.0.1:1080
"#;
        assert_eq!(usable_outbound(socks5), Ok(true));

        // vmess/hysteria2 are not wired (F1): no usable outbound.
        for outbound in [
            "  - tag: p\n    kind: vmess\n    locator: 127.0.0.1:443\n    uuid: 11111111-1111-1111-1111-111111111111\n",
            "  - tag: p\n    kind: hysteria2\n    locator: 127.0.0.1:443\n    password: secret\n",
        ] {
            let yaml = format!(
                "schema_version: 1\nrules:\n  - tag: all\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: p\noutbounds:\n{outbound}"
            );
            assert_eq!(usable_outbound(&yaml), Ok(false), "{outbound}");
        }

        // direct only is not a usable proxy outbound either.
        let direct = r#"
schema_version: 1
rules:
  - tag: all
    kind: match
    action:
      - kind: select_outbound
        tag: d
outbounds:
  - tag: d
    kind: direct
"#;
        assert_eq!(usable_outbound(direct), Ok(false));
    }

    #[test]
    fn invalid_yaml_is_reported() {
        let error = usable_outbound("not: [valid").expect_err("bad yaml");
        assert!(matches!(error, DnsClassifierError::InvalidProxyConfig(_)));
    }
}
