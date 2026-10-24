//! 捕获规则的命令执行抽象与 backend 分派（spec §9.2.1）。
//!
//! 所有外部命令经 [`CommandRunner`] 执行：生产用 [`SystemRunner`]（每条命令
//! `timeout 5s`），单测用 fake runner 断言 argv 顺序与幂等性，不触碰宿主网络。

pub mod iptables;

pub use iptables::IptablesCaptureRules;

use std::process::Command;

use nexus_platform::CaptureRuleError;

/// 单条命令的超时（spec §11.1）。
pub(crate) const COMMAND_TIMEOUT_SECS: &str = "5";
/// stderr 保留上限（spec §8.2）。
pub(crate) const STDERR_LIMIT: usize = 512;

/// 命令执行结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// 退出码（被信号终止时为 `None`）。
    pub exit_code: Option<i32>,
    /// stdout。
    pub stdout: String,
    /// stderr。
    pub stderr: String,
}

impl CommandOutput {
    /// 是否成功。
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// 外部命令执行器（可替换，便于无特权单测）。
pub trait CommandRunner: Send {
    /// 执行一条命令。
    ///
    /// # Errors
    ///
    /// 启动失败 → `ToolMissing`。
    fn run(
        &mut self,
        program: &'static str,
        args: &[String],
    ) -> Result<CommandOutput, CaptureRuleError>;
}

/// 生产执行器：`timeout 5s <program> <args...>`。
#[derive(Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(
        &mut self,
        program: &'static str,
        args: &[String],
    ) -> Result<CommandOutput, CaptureRuleError> {
        let output = Command::new("timeout")
            .arg(COMMAND_TIMEOUT_SECS)
            .arg(program)
            .args(args)
            .output();
        match output {
            Ok(output) => Ok(CommandOutput {
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(CaptureRuleError::ToolMissing { tool: program })
            }
            Err(e) => Err(CaptureRuleError::CommandFailed {
                step: "spawn",
                exit_code: None,
                stderr: e.to_string(),
            }),
        }
    }
}

/// 把非 0 退出映射为结构化错误。
pub(crate) fn command_error(
    step: &'static str,
    program: &'static str,
    output: &CommandOutput,
) -> CaptureRuleError {
    let stderr = output.stderr.chars().take(STDERR_LIMIT).collect::<String>();
    if output.exit_code == Some(127) {
        return CaptureRuleError::ToolMissing { tool: program };
    }
    if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
        return CaptureRuleError::PermissionDenied { step };
    }
    CaptureRuleError::CommandFailed {
        step,
        exit_code: output.exit_code,
        stderr,
    }
}

/// 执行并断言成功。
pub(crate) fn run_ok(
    runner: &mut dyn CommandRunner,
    step: &'static str,
    program: &'static str,
    args: &[&str],
) -> Result<CommandOutput, CaptureRuleError> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let output = runner.run(program, &owned)?;
    if output.success() {
        Ok(output)
    } else {
        Err(command_error(step, program, &output))
    }
}

/// 执行但允许非 0（用于 `-C` 幂等检查）。
pub(crate) fn run_probe(
    runner: &mut dyn CommandRunner,
    program: &'static str,
    args: &[&str],
) -> Result<CommandOutput, CaptureRuleError> {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    runner.run(program, &owned)
}
