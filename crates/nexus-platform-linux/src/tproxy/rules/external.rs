//! external backend（spec §9.2.1，高级选项）：只校验，不写规则。
//!
//! `apply` 只探测 `iptables -t mangle -S <chain>` 或 `nft list chain`；
//! 校验失败 → `CommandFailed { step: "validate" }`；`cleanup` 只清空本地
//! `is_active`，不删除任何外部规则。

use nexus_platform::{
    CaptureRuleError, CaptureRuleSpec, RuleApplyReport, RuleCleanupReport, TransparentCaptureRules,
};

use super::{CommandRunner, SystemRunner, command_error, run_probe};

/// external 捕获规则集。
pub struct ExternalCaptureRules {
    runner: Box<dyn CommandRunner>,
    active: bool,
}

impl std::fmt::Debug for ExternalCaptureRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalCaptureRules")
            .field("active", &self.active)
            .finish()
    }
}

impl Default for ExternalCaptureRules {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalCaptureRules {
    /// 生产构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Box::new(SystemRunner),
            active: false,
        }
    }

    /// 测试/示例注入执行器。
    #[cfg(test)]
    pub(crate) fn with_runner(runner: Box<dyn CommandRunner>) -> Self {
        Self {
            runner,
            active: false,
        }
    }

    fn validate(&mut self, chain: &str) -> Result<(), CaptureRuleError> {
        let iptables = run_probe(
            self.runner.as_mut(),
            "iptables",
            &["-t", "mangle", "-S", chain],
        )?;
        if iptables.success() {
            return Ok(());
        }
        let nft = run_probe(
            self.runner.as_mut(),
            "nft",
            &["list", "chain", "inet", "nexus_tproxy", chain],
        )?;
        if nft.success() {
            return Ok(());
        }
        Err(command_error("validate", "iptables", &iptables))
    }
}

impl TransparentCaptureRules for ExternalCaptureRules {
    fn apply(&mut self, spec: &CaptureRuleSpec) -> Result<RuleApplyReport, CaptureRuleError> {
        self.validate(&spec.chain)?;
        self.active = true;
        Ok(RuleApplyReport::default())
    }

    fn enforce_block(
        &mut self,
        spec: &CaptureRuleSpec,
    ) -> Result<RuleApplyReport, CaptureRuleError> {
        // external 不能写规则：即使链存在也不能声称已阻断。
        self.validate(&spec.chain)?;
        Err(CaptureRuleError::UnsupportedBackend {
            backend: "external".to_string(),
        })
    }

    fn cleanup(&mut self) -> Result<RuleCleanupReport, CaptureRuleError> {
        self.active = false;
        Ok(RuleCleanupReport::default())
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tproxy::rules::test_support::FakeRunner;
    use nexus_platform::CaptureBackend;

    #[test]
    fn external_rules_validate_only_and_cleanup_keeps_external() {
        let fake = FakeRunner::default();
        let mut rules = ExternalCaptureRules::with_runner(Box::new(fake));
        let spec = CaptureRuleSpec::new(CaptureBackend::External);
        rules.apply(&spec).unwrap();
        assert!(rules.is_active());
        let report = rules.cleanup().unwrap();
        assert_eq!(report.rules_removed, 0);
        assert_eq!(report.ip_rules_removed, 0);
        assert!(!rules.is_active());
    }

    #[test]
    fn external_rules_missing_chain_is_command_failed_validate() {
        let fake = FakeRunner {
            fail_on: Some(String::new()),
            fail_stderr: "not found".to_string(),
            ..FakeRunner::default()
        };
        let mut rules = ExternalCaptureRules::with_runner(Box::new(fake));
        let spec = CaptureRuleSpec::new(CaptureBackend::External);
        let err = rules.apply(&spec).unwrap_err();
        match err {
            CaptureRuleError::CommandFailed { step, .. } => assert_eq!(step, "validate"),
            other => panic!("unexpected: {other}"),
        }
        assert!(!rules.is_active());
    }

    #[test]
    fn external_rules_enforce_block_is_impossible() {
        let fake = FakeRunner::default();
        let mut rules = ExternalCaptureRules::with_runner(Box::new(fake));
        let spec = CaptureRuleSpec::new(CaptureBackend::External);
        let err = rules.enforce_block(&spec).unwrap_err();
        assert!(matches!(err, CaptureRuleError::UnsupportedBackend { .. }));
    }
}
