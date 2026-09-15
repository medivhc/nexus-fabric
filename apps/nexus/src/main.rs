//! nexus — 用户 CLI 前端。
//!
//! 仅负责：参数解析 → 构造 `ControlCommand` → 调用 `ControlService` → 渲染结构化输出。
//! 可复用核心逻辑必须下沉到对应 crate；本 app 承担前端与 Composition Root 角色。

#![forbid(unsafe_code)]

use nexus_control_api::{
    ControlCommand, ControlOutput, ControlService, NexusError, ResourceId, SessionId, StatusView,
};

const USAGE: &str = "\
nexus — Nexus 统一 Resource Fabric 控制面 CLI

用法:
  nexus <command> [args]

命令:
  status                                  总体状态
  plan explain <resource>                 展示 Plan 决策
  session watch <session-id>              观察 Session 状态
  connectivity status                     连接状态
  connectivity candidates                 候选 Provider
  connectivity probe <target>             探测目标可达性
  connectivity links                      活动链路
  dns status                              DNS 子系统状态
  dns resolve <name>                      解析域名
  dns providers                           DNS Provider 列表
  dns cache                               DNS 缓存
  workspace heads <workspace>             Workspace Head Set
  workspace conflicts <workspace>         未合并冲突
  workspace cache <workspace>             Workspace 缓存状态
  compute jobs                            Compute 任务
  diagnose                                统一诊断
  platform capabilities                   平台能力清单
  help / --help                           显示本帮助
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

fn run(args: &[String]) -> i32 {
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print!("{USAGE}");
        return 0;
    }

    let command = match parse_command(args) {
        Ok(cmd) => cmd,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprint!("{USAGE}");
            return 2;
        }
    };

    let service = BootstrapControlService;
    match service.execute(command) {
        Ok(output) => {
            for line in output.to_lines() {
                println!("{line}");
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn parse_command(args: &[String]) -> Result<ControlCommand, String> {
    let need = |i: usize, what: &str| -> Result<String, String> {
        args.get(i)
            .cloned()
            .ok_or_else(|| format!("missing argument: {what}"))
    };

    match args[0].as_str() {
        "status" => Ok(ControlCommand::Status),
        "plan" => match args.get(1).map(String::as_str) {
            Some("explain") => Ok(ControlCommand::PlanExplain {
                resource: ResourceId(need(2, "<resource>")?),
            }),
            _ => Err("usage: nexus plan explain <resource>".into()),
        },
        "session" => match args.get(1).map(String::as_str) {
            Some("watch") => Ok(ControlCommand::SessionWatch {
                session: SessionId(need(2, "<session-id>")?),
            }),
            _ => Err("usage: nexus session watch <session-id>".into()),
        },
        "connectivity" => match args.get(1).map(String::as_str) {
            Some("status") => Ok(ControlCommand::ConnectivityStatus),
            Some("candidates") => Ok(ControlCommand::ConnectivityCandidates),
            Some("probe") => Ok(ControlCommand::ConnectivityProbe {
                target: need(2, "<target>")?,
            }),
            Some("links") => Ok(ControlCommand::ConnectivityLinks),
            _ => Err("usage: nexus connectivity status|candidates|probe <target>|links".into()),
        },
        "dns" => match args.get(1).map(String::as_str) {
            Some("status") => Ok(ControlCommand::DnsStatus),
            Some("resolve") => Ok(ControlCommand::DnsResolve {
                name: need(2, "<name>")?,
            }),
            Some("providers") => Ok(ControlCommand::DnsProviders),
            Some("cache") => Ok(ControlCommand::DnsCache),
            _ => Err("usage: nexus dns status|resolve <name>|providers|cache".into()),
        },
        "workspace" => match args.get(1).map(String::as_str) {
            Some("heads") => Ok(ControlCommand::WorkspaceHeads {
                workspace: need(2, "<workspace>")?,
            }),
            Some("conflicts") => Ok(ControlCommand::WorkspaceConflicts {
                workspace: need(2, "<workspace>")?,
            }),
            Some("cache") => Ok(ControlCommand::WorkspaceCache {
                workspace: need(2, "<workspace>")?,
            }),
            _ => Err("usage: nexus workspace heads|conflicts|cache <workspace>".into()),
        },
        "compute" => match args.get(1).map(String::as_str) {
            Some("jobs") => Ok(ControlCommand::ComputeJobs),
            _ => Err("usage: nexus compute jobs".into()),
        },
        "diagnose" => Ok(ControlCommand::Diagnose),
        "platform" => match args.get(1).map(String::as_str) {
            Some("capabilities") => Ok(ControlCommand::PlatformCapabilities),
            _ => Err("usage: nexus platform capabilities".into()),
        },
        other => Err(format!("unknown command: {other}")),
    }
}

/// Composition Root 的最小 ControlService：领域实现尚未就绪的命令返回
/// 结构化 `Unsupported`（PRODUCT §7 禁止静默改变语义）。
struct BootstrapControlService;

impl ControlService for BootstrapControlService {
    fn execute(&self, command: ControlCommand) -> Result<ControlOutput, NexusError> {
        match command {
            ControlCommand::Status => Ok(ControlOutput::Status(StatusView {
                lines: vec![
                    "nexus control plane: contract bootstrap".into(),
                    "domain runtimes not yet implemented; use 'plan explain' etc. once available"
                        .into(),
                ],
            })),
            ControlCommand::PlanExplain { .. } => Err(NexusError::Unsupported {
                feature: "plan explain (planner not yet implemented)".into(),
            }),
            ControlCommand::SessionWatch { .. } => Err(NexusError::Unsupported {
                feature: "session watch (session runtime not yet implemented)".into(),
            }),
            ControlCommand::ConnectivityStatus
            | ControlCommand::ConnectivityCandidates
            | ControlCommand::ConnectivityProbe { .. }
            | ControlCommand::ConnectivityLinks => Err(NexusError::Unsupported {
                feature: "connectivity observability (connectivity not yet implemented)".into(),
            }),
            ControlCommand::DnsStatus
            | ControlCommand::DnsResolve { .. }
            | ControlCommand::DnsProviders
            | ControlCommand::DnsCache => Err(NexusError::Unsupported {
                feature: "dns observability (dns not yet implemented)".into(),
            }),
            ControlCommand::WorkspaceHeads { .. }
            | ControlCommand::WorkspaceConflicts { .. }
            | ControlCommand::WorkspaceCache { .. } => Err(NexusError::Unsupported {
                feature: "workspace observability (workspace not yet implemented)".into(),
            }),
            ControlCommand::ComputeJobs => Err(NexusError::Unsupported {
                feature: "compute jobs (compute not yet implemented)".into(),
            }),
            ControlCommand::Diagnose => Err(NexusError::Unsupported {
                feature: "diagnose (diagnostics not yet implemented)".into(),
            }),
            ControlCommand::PlatformCapabilities => Err(NexusError::Unsupported {
                feature: "platform capabilities (platform adapters not yet implemented)".into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_control_api::ControlOutput;

    fn parse(args: &[&str]) -> Result<ControlCommand, String> {
        parse_command(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_status() {
        assert_eq!(parse(&["status"]).unwrap(), ControlCommand::Status);
    }

    #[test]
    fn parses_plan_explain_with_resource() {
        assert_eq!(
            parse(&["plan", "explain", "net"]).unwrap(),
            ControlCommand::PlanExplain {
                resource: ResourceId("net".into()),
            }
        );
    }

    #[test]
    fn plan_explain_missing_resource_is_error() {
        assert!(parse(&["plan", "explain"]).is_err());
    }

    #[test]
    fn parses_nested_subcommands() {
        assert_eq!(
            parse(&["connectivity", "probe", "8.8.8.8"]).unwrap(),
            ControlCommand::ConnectivityProbe {
                target: "8.8.8.8".into(),
            }
        );
        assert_eq!(
            parse(&["workspace", "heads", "ws1"]).unwrap(),
            ControlCommand::WorkspaceHeads {
                workspace: "ws1".into(),
            }
        );
        assert_eq!(
            parse(&["compute", "jobs"]).unwrap(),
            ControlCommand::ComputeJobs
        );
    }

    #[test]
    fn unknown_command_is_error() {
        assert!(parse(&["bogus"]).is_err());
    }

    #[test]
    fn status_output_is_structured() {
        let out = BootstrapControlService
            .execute(ControlCommand::Status)
            .expect("status must not fail");
        assert!(matches!(out, ControlOutput::Status(_)));
        assert!(!out.to_lines().is_empty());
    }

    #[test]
    fn unimplemented_command_returns_structured_error() {
        let err = BootstrapControlService
            .execute(ControlCommand::PlanExplain {
                resource: ResourceId("net".into()),
            })
            .expect_err("must be unsupported");
        assert!(matches!(err, NexusError::Unsupported { .. }));
    }
}
