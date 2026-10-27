//! iptables mangle backend（spec §9.2.1，默认）。
//!
//! 只操作专用链 `NEXUS_TPROXY`、PREROUTING 跳转、`ip rule` 与 table 100；
//! 写前用 `-C` / `list` 探测，重复 `apply` 不产生重复规则；`cleanup` 逆序
//! 只删除本实例添加的条目。

use nexus_platform::{
    CaptureRuleError, CaptureRuleSpec, RuleApplyReport, RuleCleanupReport, TransparentCaptureRules,
};

use super::{CommandRunner, SystemRunner, add_local_route, route_exists, run_ok, run_probe};

#[derive(Debug)]
enum Action {
    ChainCreated,
    Rule(Vec<String>),
    Jump,
    IpRule,
    IpRoute,
}

/// iptables 捕获规则集。
pub struct IptablesCaptureRules {
    runner: Box<dyn CommandRunner>,
    added: Vec<Action>,
    active: bool,
    spec: Option<CaptureRuleSpec>,
}

impl std::fmt::Debug for IptablesCaptureRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IptablesCaptureRules")
            .field("active", &self.active)
            .field("added", &self.added.len())
            .finish()
    }
}

impl Default for IptablesCaptureRules {
    fn default() -> Self {
        Self::new()
    }
}

impl IptablesCaptureRules {
    /// 生产构造（`timeout 5s` + 真实命令）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Box::new(SystemRunner),
            added: Vec::new(),
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

    fn mark(&self) -> String {
        let spec = self.spec.as_ref();
        let mark = spec.map_or(0x1f3, |s| s.mark);
        let mask = spec.map_or(0x1f3, |s| s.mark_mask);
        format!("0x{mark:x}/0x{mask:x}")
    }

    fn ensure_chain(&mut self, step: &'static str) -> Result<bool, CaptureRuleError> {
        let chain = self.chain();
        let probe = run_probe(
            self.runner.as_mut(),
            "iptables",
            &["-t", "mangle", "-S", &chain],
        )?;
        if probe.success() {
            return Ok(false);
        }
        run_ok(
            self.runner.as_mut(),
            step,
            "iptables",
            &["-t", "mangle", "-N", &chain],
        )?;
        self.added.push(Action::ChainCreated);
        Ok(true)
    }

    fn ensure_rule(&mut self, step: &'static str, rule: &[&str]) -> Result<bool, CaptureRuleError> {
        let chain = self.chain();
        let mut probe_args = vec!["-t", "mangle", "-C", chain.as_str()];
        probe_args.extend_from_slice(rule);
        let probe = run_probe(self.runner.as_mut(), "iptables", &probe_args)?;
        if probe.success() {
            return Ok(false);
        }
        let mut add_args = vec!["-t", "mangle", "-A", chain.as_str()];
        add_args.extend_from_slice(rule);
        run_ok(self.runner.as_mut(), step, "iptables", &add_args)?;
        let mut stored = vec![chain];
        stored.extend(rule.iter().map(|s| (*s).to_string()));
        self.added.push(Action::Rule(stored));
        Ok(true)
    }

    fn ensure_jump(&mut self) -> Result<bool, CaptureRuleError> {
        let chain = self.chain();
        let probe = run_probe(
            self.runner.as_mut(),
            "iptables",
            &["-t", "mangle", "-C", "PREROUTING", "-j", &chain],
        )?;
        if probe.success() {
            return Ok(false);
        }
        run_ok(
            self.runner.as_mut(),
            "add-prerouting",
            "iptables",
            &["-t", "mangle", "-A", "PREROUTING", "-j", &chain],
        )?;
        self.added.push(Action::Jump);
        Ok(true)
    }

    fn ensure_ip_rule(&mut self) -> Result<bool, CaptureRuleError> {
        let show = run_ok(
            self.runner.as_mut(),
            "show-ip-rule",
            "ip",
            &["rule", "show"],
        )?;
        let mark = self.mark();
        let needle = format!("fwmark {mark} lookup {}", self.route_table());
        if show.stdout.to_lowercase().contains(&needle) {
            return Ok(false);
        }
        let table = self.route_table();
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
        let table = self.route_table();
        if route_exists(self.runner.as_mut(), &table)? {
            return Ok(false);
        }
        if !add_local_route(self.runner.as_mut(), &table)? {
            return Ok(false);
        }
        self.added.push(Action::IpRoute);
        Ok(true)
    }

    fn route_table(&self) -> String {
        self.spec
            .as_ref()
            .map_or(100, |s| s.route_table)
            .to_string()
    }

    fn build_rules(&self, spec: &CaptureRuleSpec, block: bool) -> Vec<Vec<String>> {
        let mut rules: Vec<Vec<String>> = Vec::new();
        rules.push(vec![
            "-m".into(),
            "addrtype".into(),
            "--dst-type".into(),
            "LOCAL".into(),
            "-j".into(),
            "RETURN".into(),
        ]);
        for cidr in &spec.exclude_dst_cidrs {
            rules.push(vec![
                "-d".into(),
                cidr.clone(),
                "-j".into(),
                "RETURN".into(),
            ]);
        }
        let mark = format!("0x{:x}/0x{:x}", spec.mark, spec.mark_mask);
        if block {
            rules.push(vec!["-p".into(), "tcp".into(), "-j".into(), "DROP".into()]);
            rules.push(vec!["-p".into(), "udp".into(), "-j".into(), "DROP".into()]);
        } else {
            for (proto, port) in [("tcp", spec.tcp_port), ("udp", spec.udp_port)] {
                rules.push(vec![
                    "-p".into(),
                    proto.into(),
                    "-j".into(),
                    "TPROXY".into(),
                    "--on-port".into(),
                    port.to_string(),
                    "--tproxy-mark".into(),
                    mark.clone(),
                ]);
            }
        }
        rules
    }

    fn apply_inner(
        &mut self,
        spec: &CaptureRuleSpec,
        block: bool,
    ) -> Result<RuleApplyReport, CaptureRuleError> {
        self.spec = Some(spec.clone());
        let chain_created = self.ensure_chain("create-chain")?;
        let mut report = RuleApplyReport {
            chain_created,
            ..RuleApplyReport::default()
        };
        for rule in self.build_rules(spec, block) {
            let args: Vec<&str> = rule.iter().map(String::as_str).collect();
            if self.ensure_rule("add-rule", &args)? {
                report.rules_added += 1;
            }
        }
        if self.ensure_jump()? {
            report.rules_added += 1;
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

impl TransparentCaptureRules for IptablesCaptureRules {
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
        for action in actions.into_iter().rev() {
            match action {
                Action::IpRoute => {
                    let table = self.route_table();
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
                    let table = self.route_table();
                    let show = run_ok(
                        self.runner.as_mut(),
                        "show-route",
                        "ip",
                        &["route", "show", "table", &table],
                    )?;
                    if !show.stdout.trim().is_empty() {
                        continue;
                    }
                    let mark = self.mark();
                    run_ok(
                        self.runner.as_mut(),
                        "del-ip-rule",
                        "ip",
                        &["rule", "del", "fwmark", &mark, "lookup", &table],
                    )
                    .map_err(|e| cleanup_error("del-ip-rule", e))?;
                    report.ip_rules_removed += 1;
                }
                Action::Jump => {
                    let chain = self.chain();
                    run_ok(
                        self.runner.as_mut(),
                        "del-prerouting",
                        "iptables",
                        &["-t", "mangle", "-D", "PREROUTING", "-j", &chain],
                    )
                    .map_err(|e| cleanup_error("del-prerouting", e))?;
                    report.rules_removed += 1;
                }
                Action::Rule(rule) => {
                    let mut args = vec!["-t", "mangle", "-D"];
                    args.extend(rule.iter().map(String::as_str));
                    run_ok(self.runner.as_mut(), "del-rule", "iptables", &args)
                        .map_err(|e| cleanup_error("del-rule", e))?;
                    report.rules_removed += 1;
                }
                Action::ChainCreated => {
                    let chain = self.chain();
                    run_ok(
                        self.runner.as_mut(),
                        "del-chain",
                        "iptables",
                        &["-t", "mangle", "-X", &chain],
                    )
                    .map_err(|e| cleanup_error("del-chain", e))?;
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
    use crate::tproxy::rules::test_support::{FakeRunner, SharedFakeRunner};
    use nexus_platform::CaptureBackend;

    #[derive(Default)]
    struct StatefulRunner {
        chain: bool,
        rules: std::collections::HashSet<String>,
        ip_rule: bool,
        route: bool,
        calls: Vec<String>,
        fail_needle: Option<String>,
    }

    impl CommandRunner for StatefulRunner {
        fn run(
            &mut self,
            program: &'static str,
            args: &[String],
        ) -> Result<super::super::CommandOutput, CaptureRuleError> {
            let joined = format!("{program} {}", args.join(" "));
            self.calls.push(joined.clone());
            if let Some(needle) = &self.fail_needle {
                if joined.contains(needle.as_str()) {
                    return Ok(super::super::CommandOutput {
                        exit_code: Some(1),
                        stdout: String::new(),
                        stderr: "Operation not permitted".to_string(),
                    });
                }
            }
            let ok = |stdout: String| {
                Ok(super::super::CommandOutput {
                    exit_code: Some(0),
                    stdout,
                    stderr: String::new(),
                })
            };
            let fail = || {
                Ok(super::super::CommandOutput {
                    exit_code: Some(1),
                    stdout: String::new(),
                    stderr: "not found".to_string(),
                })
            };
            match program {
                "iptables" => {
                    if args.len() >= 4 && args[0] == "-t" && args[1] == "mangle" {
                        match args[2].as_str() {
                            "-S" => {
                                if self.chain {
                                    ok(String::new())
                                } else {
                                    fail()
                                }
                            }
                            "-N" => {
                                self.chain = true;
                                ok(String::new())
                            }
                            "-C" => {
                                let key = joined.replacen(" -C ", " -A ", 1);
                                if self.rules.contains(&key) {
                                    ok(String::new())
                                } else {
                                    fail()
                                }
                            }
                            "-A" => {
                                self.rules.insert(joined);
                                ok(String::new())
                            }
                            "-D" => {
                                let key = joined.replacen(" -D ", " -A ", 1);
                                self.rules.remove(&key);
                                ok(String::new())
                            }
                            "-X" => {
                                self.chain = false;
                                ok(String::new())
                            }
                            _ => fail(),
                        }
                    } else {
                        fail()
                    }
                }
                "ip" if args == ["rule", "show"] => {
                    if self.ip_rule {
                        ok("0:\tfrom all fwmark 0x1f3/0x1f3 lookup 100".to_string())
                    } else {
                        ok(String::new())
                    }
                }
                "ip" if args.starts_with(&["rule".to_string(), "add".to_string()]) => {
                    self.ip_rule = true;
                    ok(String::new())
                }
                "ip" if args.starts_with(&["rule".to_string(), "del".to_string()]) => {
                    self.ip_rule = false;
                    ok(String::new())
                }
                "ip" if args.starts_with(&["route".to_string(), "show".to_string()]) => {
                    if self.route {
                        ok("local 0.0.0.0/0 dev lo scope host".to_string())
                    } else {
                        ok(String::new())
                    }
                }
                "ip" if args.starts_with(&["route".to_string(), "add".to_string()]) => {
                    self.route = true;
                    ok(String::new())
                }
                "ip" if args.starts_with(&["route".to_string(), "del".to_string()]) => {
                    self.route = false;
                    ok(String::new())
                }
                _ => fail(),
            }
        }
    }

    fn spec() -> CaptureRuleSpec {
        let mut spec = CaptureRuleSpec::new(CaptureBackend::Iptables);
        spec.exclude_dst_cidrs = vec!["203.0.113.10/32".to_string()];
        spec
    }

    #[test]
    fn iptables_rules_apply_order_and_idempotent() {
        let mut rules = IptablesCaptureRules::with_runner(Box::new(StatefulRunner::default()));
        let report = rules.apply(&spec()).unwrap();
        assert!(report.chain_created);
        assert!(report.rules_added >= 5);
        assert_eq!(report.ip_rules_added, 1);
        assert_eq!(report.routes_added, 1);
        assert!(rules.is_active());
        let second = rules.apply(&spec()).unwrap();
        assert!(!second.chain_created);
        assert_eq!(second.rules_added, 0);
        assert_eq!(second.ip_rules_added, 0);
        assert_eq!(second.routes_added, 0);
    }

    #[test]
    fn iptables_rules_cleanup_reverses_and_removes_chain() {
        let mut rules = IptablesCaptureRules::with_runner(Box::new(StatefulRunner::default()));
        rules.apply(&spec()).unwrap();
        let report = rules.cleanup().unwrap();
        assert!(report.chain_removed);
        assert!(report.rules_removed >= 5);
        assert_eq!(report.ip_rules_removed, 1);
        assert_eq!(report.routes_removed, 1);
        assert!(!rules.is_active());
    }

    #[test]
    fn iptables_rules_enforce_block_uses_drop_and_no_ip_rule() {
        let mut rules = IptablesCaptureRules::with_runner(Box::new(StatefulRunner::default()));
        let report = rules.enforce_block(&spec()).unwrap();
        assert_eq!(report.ip_rules_added, 0);
        assert_eq!(report.routes_added, 0);
        assert!(rules.is_active());
    }

    #[test]
    fn iptables_rules_permission_error_is_structured() {
        let runner = StatefulRunner {
            fail_needle: Some("-A NEXUS_TPROXY".to_string()),
            ..StatefulRunner::default()
        };
        let mut rules = IptablesCaptureRules::with_runner(Box::new(runner));
        let err = rules.apply(&spec()).unwrap_err();
        assert!(matches!(err, CaptureRuleError::PermissionDenied { .. }));
        assert!(!rules.is_active());
    }

    #[test]
    fn iptables_ensure_route_adds_when_table_missing() {
        let shared = SharedFakeRunner::new(FakeRunner {
            fail_on: Some("route show".to_string()),
            fail_exit_code: Some(2),
            fail_stderr: "Error: ipv4: FIB table does not exist.".to_string(),
            ..FakeRunner::default()
        });
        let mut rules = IptablesCaptureRules::with_runner(Box::new(shared.clone()));
        assert!(rules.ensure_route().unwrap());
        assert_eq!(rules.added.len(), 1);
        let calls = shared.calls();
        assert!(
            calls
                .iter()
                .any(|(_, args)| args[..3] == ["route", "add", "local"])
        );
    }

    #[test]
    fn iptables_ensure_route_skips_existing_local_default() {
        let shared =
            SharedFakeRunner::new(FakeRunner::with_output("local default dev lo scope host"));
        let mut rules = IptablesCaptureRules::with_runner(Box::new(shared.clone()));
        assert!(!rules.ensure_route().unwrap());
        assert!(rules.added.is_empty());
        let calls = shared.calls();
        assert!(!calls.iter().any(|(_, args)| args[..2] == ["route", "add"]));
    }

    #[test]
    fn iptables_ensure_route_treats_file_exists_as_present() {
        let shared = SharedFakeRunner::new(FakeRunner {
            fail_on: Some("route add".to_string()),
            fail_exit_code: Some(2),
            fail_stderr: "RTNETLINK answers: File exists".to_string(),
            ..FakeRunner::default()
        });
        let mut rules = IptablesCaptureRules::with_runner(Box::new(shared));
        assert!(!rules.ensure_route().unwrap());
        assert!(rules.added.is_empty());
    }
}
