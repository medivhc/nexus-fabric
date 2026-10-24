//! nftables backend（spec §9.2.1，可选）。
//!
//! 使用独立 table `inet nexus_tproxy` 与同名链；清理只删除本 table/链，
//! 不触碰宿主其它规则。

use std::collections::HashSet;

use nexus_platform::{
    CaptureRuleError, CaptureRuleSpec, RuleApplyReport, RuleCleanupReport, TransparentCaptureRules,
};

use super::{CommandRunner, SystemRunner, run_ok, run_probe};

#[derive(Debug)]
enum Action {
    TableCreated,
    ChainCreated,
    Rule,
    IpRule,
    IpRoute,
}

/// nftables 捕获规则集。
pub struct NftablesCaptureRules {
    runner: Box<dyn CommandRunner>,
    added: Vec<Action>,
    seen_rules: HashSet<String>,
    active: bool,
    spec: Option<CaptureRuleSpec>,
}

impl std::fmt::Debug for NftablesCaptureRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NftablesCaptureRules")
            .field("active", &self.active)
            .field("added", &self.added.len())
            .finish()
    }
}

impl Default for NftablesCaptureRules {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesCaptureRules {
    /// 生产构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Box::new(SystemRunner),
            added: Vec::new(),
            seen_rules: HashSet::new(),
            active: false,
            spec: None,
        }
    }

    /// 测试/示例注入执行器。
    #[cfg(test)]
    pub(crate) fn with_runner(runner: Box<dyn CommandRunner>) -> Self {
        Self {
            runner,
            added: Vec::new(),
            seen_rules: HashSet::new(),
            active: false,
            spec: None,
        }
    }

    fn chain(&self) -> String {
        self.spec
            .as_ref()
            .map(|s| s.chain.clone())
            .unwrap_or_else(|| "NEXUS_TPROXY".to_string())
    }

    fn table(&self) -> String {
        self.spec
            .as_ref()
            .map_or(100, |s| s.route_table)
            .to_string()
    }

    fn mark(&self) -> String {
        let spec = self.spec.as_ref();
        let mark = spec.map_or(0x1f3, |s| s.mark);
        let mask = spec.map_or(0x1f3, |s| s.mark_mask);
        format!("0x{mark:x}/0x{mask:x}")
    }

    fn ensure_table(&mut self) -> Result<bool, CaptureRuleError> {
        let probe = run_probe(
            self.runner.as_mut(),
            "nft",
            &["list", "table", "inet", "nexus_tproxy"],
        )?;
        if probe.success() {
            return Ok(false);
        }
        run_ok(
            self.runner.as_mut(),
            "add-table",
            "nft",
            &["add", "table", "inet", "nexus_tproxy"],
        )?;
        self.added.push(Action::TableCreated);
        Ok(true)
    }

    fn ensure_chain(&mut self) -> Result<bool, CaptureRuleError> {
        let chain = self.chain();
        let probe = run_probe(
            self.runner.as_mut(),
            "nft",
            &["list", "chain", "inet", "nexus_tproxy", &chain],
        )?;
        if probe.success() {
            return Ok(false);
        }
        let declaration = "{ type filter hook prerouting priority mangle; policy accept; }";
        run_ok(
            self.runner.as_mut(),
            "add-chain",
            "nft",
            &["add", "chain", "inet", "nexus_tproxy", &chain, declaration],
        )?;
        self.added.push(Action::ChainCreated);
        Ok(true)
    }

    fn ensure_rule(&mut self, rule: &str) -> Result<bool, CaptureRuleError> {
        if self.seen_rules.contains(rule) {
            return Ok(false);
        }
        let chain = self.chain();
        let listing = run_probe(
            self.runner.as_mut(),
            "nft",
            &["list", "chain", "inet", "nexus_tproxy", &chain],
        )?;
        if listing.stdout.contains(rule) {
            self.seen_rules.insert(rule.to_string());
            return Ok(false);
        }
        run_ok(
            self.runner.as_mut(),
            "add-rule",
            "nft",
            &["add", "rule", "inet", "nexus_tproxy", &chain, rule],
        )?;
        self.seen_rules.insert(rule.to_string());
        self.added.push(Action::Rule);
        Ok(true)
    }

    fn ensure_ip_rule(&mut self) -> Result<bool, CaptureRuleError> {
        let show = run_ok(
            self.runner.as_mut(),
            "show-ip-rule",
            "ip",
            &["rule", "show"],
        )?;
        let needle = format!("fwmark {} lookup {}", self.mark(), self.table());
        if show.stdout.to_lowercase().contains(&needle) {
            return Ok(false);
        }
        let mark = self.mark();
        let table = self.table();
        run_ok(
            self.runner.as_mut(),
            "add-ip-rule",
            "ip",
            &["rule", "add", "fwmark", &mark, "lookup", &table],
        )?;
        self.added.push(Action::IpRule);
        Ok(true)
    }

    fn ensure_route(&mut self) -> Result<bool, CaptureRuleError> {
        let table = self.table();
        let show = run_ok(
            self.runner.as_mut(),
            "show-route",
            "ip",
            &["route", "show", "table", &table],
        )?;
        if show.stdout.contains("local 0.0.0.0/0") {
            return Ok(false);
        }
        run_ok(
            self.runner.as_mut(),
            "add-route",
            "ip",
            &[
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                &table,
            ],
        )?;
        self.added.push(Action::IpRoute);
        Ok(true)
    }

    fn rules(&self, spec: &CaptureRuleSpec, block: bool) -> Vec<String> {
        let mut out = vec!["fib daddr type local return".to_string()];
        for cidr in &spec.exclude_dst_cidrs {
            out.push(format!("ip daddr {cidr} return"));
        }
        let mark = format!("0x{:x}", spec.mark);
        if block {
            out.push("meta l4proto tcp drop".to_string());
            out.push("meta l4proto udp drop".to_string());
        } else {
            out.push(format!(
                "meta l4proto tcp meta mark set {mark} tproxy to :{}",
                spec.tcp_port
            ));
            out.push(format!(
                "meta l4proto udp meta mark set {mark} tproxy to :{}",
                spec.udp_port
            ));
        }
        out
    }

    fn apply_inner(
        &mut self,
        spec: &CaptureRuleSpec,
        block: bool,
    ) -> Result<RuleApplyReport, CaptureRuleError> {
        self.spec = Some(spec.clone());
        let table_created = self.ensure_table()?;
        let chain_created = self.ensure_chain()?;
        let mut report = RuleApplyReport {
            chain_created: table_created || chain_created,
            ..RuleApplyReport::default()
        };
        for rule in self.rules(spec, block) {
            if self.ensure_rule(&rule)? {
                report.rules_added += 1;
            }
        }
        if !block {
            if self.ensure_ip_rule()? {
                report.ip_rules_added += 1;
            }
            if self.ensure_route()? {
                report.routes_added += 1;
            }
        }
        self.active = true;
        Ok(report)
    }
}

impl TransparentCaptureRules for NftablesCaptureRules {
    fn apply(&mut self, spec: &CaptureRuleSpec) -> Result<RuleApplyReport, CaptureRuleError> {
        self.apply_inner(spec, false)
    }

    fn enforce_block(
        &mut self,
        spec: &CaptureRuleSpec,
    ) -> Result<RuleApplyReport, CaptureRuleError> {
        self.apply_inner(spec, true)
    }

    fn cleanup(&mut self) -> Result<RuleCleanupReport, CaptureRuleError> {
        let mut report = RuleCleanupReport::default();
        let actions = std::mem::take(&mut self.added);
        let table = self.table();
        let mark = self.mark();
        let chain = self.chain();
        for action in actions.into_iter().rev() {
            match action {
                Action::IpRoute => {
                    run_ok(
                        self.runner.as_mut(),
                        "del-route",
                        "ip",
                        &[
                            "route",
                            "del",
                            "local",
                            "0.0.0.0/0",
                            "dev",
                            "lo",
                            "table",
                            &table,
                        ],
                    )
                    .map_err(|e| cleanup_error("del-route", e))?;
                    report.routes_removed += 1;
                }
                Action::IpRule => {
                    let show = run_ok(
                        self.runner.as_mut(),
                        "show-route",
                        "ip",
                        &["route", "show", "table", &table],
                    )?;
                    if !show.stdout.trim().is_empty() {
                        continue;
                    }
                    run_ok(
                        self.runner.as_mut(),
                        "del-ip-rule",
                        "ip",
                        &["rule", "del", "fwmark", &mark, "lookup", &table],
                    )
                    .map_err(|e| cleanup_error("del-ip-rule", e))?;
                    report.ip_rules_removed += 1;
                }
                Action::Rule => {
                    report.rules_removed += 1;
                }
                Action::ChainCreated => {
                    run_ok(
                        self.runner.as_mut(),
                        "flush-chain",
                        "nft",
                        &["flush", "chain", "inet", "nexus_tproxy", &chain],
                    )
                    .map_err(|e| cleanup_error("flush-chain", e))?;
                    run_ok(
                        self.runner.as_mut(),
                        "del-chain",
                        "nft",
                        &["delete", "chain", "inet", "nexus_tproxy", &chain],
                    )
                    .map_err(|e| cleanup_error("del-chain", e))?;
                }
                Action::TableCreated => {
                    run_ok(
                        self.runner.as_mut(),
                        "del-table",
                        "nft",
                        &["delete", "table", "inet", "nexus_tproxy"],
                    )
                    .map_err(|e| cleanup_error("del-table", e))?;
                    report.chain_removed = true;
                }
            }
        }
        self.active = false;
        Ok(report)
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

fn cleanup_error(step: &'static str, error: CaptureRuleError) -> CaptureRuleError {
    match error {
        CaptureRuleError::PermissionDenied { .. } => error,
        CaptureRuleError::ToolMissing { .. } => error,
        other => CaptureRuleError::CleanupFailed {
            step,
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tproxy::rules::test_support::FakeRunner;
    use nexus_platform::CaptureBackend;

    fn spec() -> CaptureRuleSpec {
        let mut spec = CaptureRuleSpec::new(CaptureBackend::Nftables);
        spec.exclude_dst_cidrs = vec!["203.0.113.10/32".to_string()];
        spec
    }

    #[test]
    fn nftables_rules_apply_sequence() {
        let fake = FakeRunner::with_failure("list table");
        let mut rules = NftablesCaptureRules::with_runner(Box::new(fake));
        let report = rules.apply(&spec()).unwrap();
        assert!(report.chain_created);
        assert_eq!(report.rules_added, 4);
        assert_eq!(report.ip_rules_added, 1);
        assert_eq!(report.routes_added, 1);
        assert!(rules.is_active());
        let second = rules.apply(&spec()).unwrap();
        assert_eq!(second.rules_added, 0);
    }

    #[test]
    fn nftables_rules_cleanup_deletes_table() {
        let fake = FakeRunner::with_failure("list table");
        let mut rules = NftablesCaptureRules::with_runner(Box::new(fake));
        rules.apply(&spec()).unwrap();
        let report = rules.cleanup().unwrap();
        assert!(report.chain_removed);
        assert!(!rules.is_active());
    }

    #[test]
    fn nftables_rules_permission_error_is_structured() {
        let fake = FakeRunner {
            fail_on: Some(String::new()),
            fail_stderr: "Operation not permitted".to_string(),
            ..FakeRunner::default()
        };
        let mut rules = NftablesCaptureRules::with_runner(Box::new(fake));
        let err = rules.apply(&spec()).unwrap_err();
        assert!(matches!(err, CaptureRuleError::PermissionDenied { .. }));
    }

    #[test]
    fn nftables_rules_skip_when_listing_contains_rule() {
        let fake = FakeRunner::with_output("meta l4proto tcp meta mark set 0x1f3 tproxy to :7895");
        let mut rules = NftablesCaptureRules::with_runner(Box::new(fake));
        let report = rules.apply(&spec()).unwrap();
        assert!(report.rules_added < 4);
    }
}
