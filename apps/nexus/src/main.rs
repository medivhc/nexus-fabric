//! nexus — 用户 CLI 前端。
//!
//! 仅负责：参数解析 → 构造 `ControlCommand` → 调用 `ControlService` → 渲染结构化输出。
//! 全部 17 个 §9 观察命令直接路由到 `nexus::observability` SDK 快照（与 nexusd 同源，
//! 不复制领域逻辑）；领域未就绪命令（如 connectivity trace）返回结构化 `Unsupported`
//! （PRODUCT §9 禁止静默降级）。

#![forbid(unsafe_code)]

use nexus::control_service::{ControlServiceImpl, render_text};
use nexus_control_api::{ControlCommand, ResourceId, SessionId};

const USAGE: &str = "\
nexus — Nexus 统一 Resource Fabric 控制面 CLI

用法:
  nexus [--json] <command> [args]

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
  run <resource>                          执行远程资源访问
  help / --help                           显示本帮助

输出:
  --json        原样打印 observability 快照 JSON（机器可读，stderr 静默）。
  默认          渲染人读文本视图（JSON 的字段投影）。

exit 语义（对齐 nexusd）:
  0             业务成功；NexusError 领域拒绝（verdict=FAIL，请求已被处理）。
  2             用法/解析错误（缺参、未知命令）。
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

/// 从参数中剥离全局 `--json`，返回 (json_mode, 剩余 args)。
/// 在 `parse_command` 之前剥离，位置参数与 `--json` 顺序无关。
fn split_json_flag(args: &[String]) -> (bool, Vec<String>) {
    let json_mode = args.iter().any(|a| a == "--json");
    let rest: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    (json_mode, rest)
}

fn run(args: &[String]) -> i32 {
    let (json_mode, args) = split_json_flag(args);

    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print!("{USAGE}");
        return 0;
    }

    let command = match parse_command(&args) {
        Ok(cmd) => cmd,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprint!("{USAGE}");
            return 2;
        }
    };

    let service = ControlServiceImpl;
    match service.snapshot(&command) {
        Ok(json) => {
            if json_mode {
                // --json：快照 JSON 原样打到 stdout，stderr 静默。
                println!("{json}");
            } else {
                for line in render_text(&json) {
                    println!("{line}");
                }
            }
            0
        }
        Err(err) => {
            // 领域拒绝：--json 下输出结构化 FAIL JSON（exit 0 = 请求已被处理）；
            // 人读模式打到 stderr。与 nexusd print_json_result 一致。
            if json_mode {
                println!("{}", service.error_to_json(&err));
            } else {
                eprintln!("error: {err}");
            }
            0
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
        "run" => match args.get(1) {
            Some(resource) => Ok(ControlCommand::Run {
                resource: resource.clone(),
            }),
            None => Err("usage: nexus run <resource>".into()),
        },
        other => Err(format!("unknown command: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_control_api::ResourceId;

    fn parse(args: &[&str]) -> Result<ControlCommand, String> {
        parse_command(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn run_str(args: &[&str]) -> i32 {
        run(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
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
    fn json_flag_is_stripped_before_parse() {
        let args = vec![
            "connectivity".to_string(),
            "candidates".to_string(),
            "--json".to_string(),
        ];
        let (json_mode, rest) = split_json_flag(&args);
        assert!(json_mode);
        assert_eq!(rest, vec!["connectivity", "candidates"]);
        assert_eq!(
            parse_command(&rest).unwrap(),
            ControlCommand::ConnectivityCandidates
        );
    }

    #[test]
    fn json_flag_anywhere_is_stripped() {
        let args = vec![
            "dns".to_string(),
            "--json".to_string(),
            "resolve".to_string(),
            "example.com".to_string(),
        ];
        let (json_mode, rest) = split_json_flag(&args);
        assert!(json_mode);
        assert_eq!(
            parse_command(&rest).unwrap(),
            ControlCommand::DnsResolve {
                name: "example.com".into(),
            }
        );
    }

    #[test]
    fn usage_error_exits_2_on_missing_arg() {
        // 用法/解析错误走 parse_command 错误路径 -> exit 2。
        let code = run_str(&["plan", "explain"]);
        assert_eq!(code, 2);
    }

    #[test]
    fn help_exits_0() {
        assert_eq!(run_str(&[]), 0);
        assert_eq!(run_str(&["help"]), 0);
    }
}
