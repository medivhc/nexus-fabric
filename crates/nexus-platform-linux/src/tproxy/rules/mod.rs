//! 捕获规则的命令执行抽象与 backend 分派（spec §9.2.1）。
//!
//! 所有外部命令经 [`CommandRunner`] 执行：生产用 [`SystemRunner`]（每条命令
//! `timeout 5s`），单测用 fake runner 断言 argv 顺序与幂等性，不触碰宿主网络。

pub mod external;
pub mod iptables;
pub mod nftables;

pub use external::ExternalCaptureRules;
pub use iptables::IptablesCaptureRules;
pub use nftables::NftablesCaptureRules;

use nexus_platform::{CaptureBackend, TransparentCaptureRules};

/// 按配置 backend 构造规则集。
#[must_use]
pub fn capture_rules_for(backend: CaptureBackend) -> Box<dyn TransparentCaptureRules> {
    match backend {
        CaptureBackend::Iptables => Box::new(IptablesCaptureRules::new()),
        CaptureBackend::Nftables => Box::new(NftablesCaptureRules::new()),
        CaptureBackend::External => Box::new(ExternalCaptureRules::new()),
    }
}

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

/// `ip route show table N` 输出是否已含本 backend 添加的 `local` 缺省路由。
///
/// iproute2 把 `local 0.0.0.0/0` 显示为 `local default dev lo scope host`，旧版
/// 也可能原样显示 `local 0.0.0.0/0`；两条都识别，避免误判后重复 add。
pub(crate) fn local_default_route_present(stdout: &str) -> bool {
    stdout.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("local") && matches!(fields.next(), Some("default" | "0.0.0.0/0"))
    })
}

/// 探测 table 是否已有 `local` 缺省路由。
///
/// 全新 netns 中 table 尚不存在时 iproute2 以 exit=2 +
/// `FIB table does not exist` 结束；这是"路由不存在"而非失败。
pub(crate) fn route_exists(
    runner: &mut dyn CommandRunner,
    table: &str,
) -> Result<bool, CaptureRuleError> {
    let show = run_probe(runner, "ip", &["route", "show", "table", table])?;
    if show.success() {
        return Ok(local_default_route_present(&show.stdout));
    }
    if show.exit_code == Some(2) && show.stderr.contains("FIB table does not exist") {
        return Ok(false);
    }
    Err(command_error("show-route", "ip", &show))
}

/// 添加 `local` 缺省路由；返回是否真的新增。
///
/// 并发 apply 时 add 可能撞上已存在的同路由（`RTNETLINK answers: File exists`），
/// 此时按幂等收敛处理为"已存在"。
pub(crate) fn add_local_route(
    runner: &mut dyn CommandRunner,
    table: &str,
) -> Result<bool, CaptureRuleError> {
    let add = run_probe(
        runner,
        "ip",
        &[
            "route",
            "add",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            table,
        ],
    )?;
    if add.success() {
        return Ok(true);
    }
    if add.stderr.contains("File exists") {
        return Ok(false);
    }
    Err(command_error("add-route", "ip", &add))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// 记录 argv 的 fake runner；`fail_on` 命中子串时返回非 0。
    #[derive(Debug, Default)]
    pub struct FakeRunner {
        pub calls: Vec<(String, Vec<String>)>,
        pub fail_on: Option<String>,
        pub fail_exit_code: Option<i32>,
        pub fail_stderr: String,
        pub output: String,
    }

    impl FakeRunner {
        pub fn with_failure(needle: &str) -> Self {
            Self {
                fail_on: Some(needle.to_string()),
                fail_stderr: "Operation not permitted".to_string(),
                ..Self::default()
            }
        }

        pub fn with_output(output: &str) -> Self {
            Self {
                output: output.to_string(),
                ..Self::default()
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &mut self,
            program: &'static str,
            args: &[String],
        ) -> Result<CommandOutput, CaptureRuleError> {
            self.calls.push((program.to_string(), args.to_vec()));
            let joined = format!("{program} {}", args.join(" "));
            if let Some(needle) = &self.fail_on {
                if joined.contains(needle.as_str()) {
                    return Ok(CommandOutput {
                        exit_code: Some(self.fail_exit_code.unwrap_or(1)),
                        stdout: String::new(),
                        stderr: self.fail_stderr.clone(),
                    });
                }
            }
            Ok(CommandOutput {
                exit_code: Some(0),
                stdout: self.output.clone(),
                stderr: String::new(),
            })
        }
    }

    /// 共享句柄版 fake：把 runner 交给 backend 后仍可回看调用记录。
    #[derive(Debug, Clone, Default)]
    pub struct SharedFakeRunner(std::sync::Arc<std::sync::Mutex<FakeRunner>>);

    impl SharedFakeRunner {
        pub fn new(runner: FakeRunner) -> Self {
            Self(std::sync::Arc::new(std::sync::Mutex::new(runner)))
        }

        pub fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.0.lock().unwrap().calls.clone()
        }
    }

    impl CommandRunner for SharedFakeRunner {
        fn run(
            &mut self,
            program: &'static str,
            args: &[String],
        ) -> Result<CommandOutput, CaptureRuleError> {
            self.0.lock().unwrap().run(program, args)
        }
    }
}
