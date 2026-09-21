//! nexus — 用户 CLI 前端（瘦客户端模式）。
//!
//! 职责：参数解析 → 构造 `ControlCommand` → 通过 [`nexus::localapi_client`] 向
//! `nexusd serve` 的 HTTP LocalAPI 发裸 GET → 渲染结构化输出。
//!
//! 对有 LocalAPI 路由的 7 个观察命令（status / dns status / dns cache / session watch /
//! plan explain / connectivity status / platform capabilities），CLI 不进程内装配 SDK，
//! 而是把 daemon 返回的 JSON 原文渲染（--json 原样 / 默认人读投影）。
//!
//! 对暂无 daemon 路由的命令（dns resolve/providers、connectivity candidates/probe/links、
//! workspace heads/conflicts/cache、compute jobs、diagnose），CLI 本地合成
//! `UNSUPPORTED` FAIL JSON（与 nexusd 兜底同形），不回退到进程内 observability
//! （PRODUCT §9 禁止静默降级）。
//!
//! `run <resource>` 仍走进程内 SDK 路径（LocalAPI 无对应路由）。

#![forbid(unsafe_code)]

use nexus::control_service::{ControlServiceImpl, render_text};
use nexus::localapi_client::{self, DEFAULT_LOCALAPI_ADDR};
use nexus::subnet_cli::{default_state_path, subnet_leave, subnet_status, subnet_up};
use nexus_control_api::{ControlCommand, ResourceId, SessionId};
use serde_json::Value;
use std::path::PathBuf;

const USAGE: &str = "\
nexus — Nexus 统一 Resource Fabric 控制面 CLI（瘦客户端）

用法:
  nexus [--json] [--addr <ip:port>] <command> [args]

全局选项:
  --json        原样打印 daemon 返回 JSON（机器可读，stderr 静默）。
  --addr <host:port>   nexusd serve LocalAPI 地址（默认 127.0.0.1:18080）。

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
  run <resource>                          执行远程资源访问（进程内 SDK）
  help / --help                           显示本帮助

前置条件:
  观察命令需要先在另一个终端启动 `nexusd serve --addr <ip:port>`。
  daemon 未运行时，CLI 输出 DAEMON_UNREACHABLE FAIL JSON（exit 0）。

输出:
  --json        原样打印 observability 快照 JSON（机器可读，stderr 静默）。
  默认          渲染人读文本视图（JSON 的字段投影）。
  --socket <path> / --addr <ip:port>
                thin-client 远程传输目标（--addr 为 TCP loopback；
                --socket 暂仅服务端监听支持，CLI 建连待落地）。

exit 语义（对齐 nexusd）:
  0             业务结果（含 verdict=FAIL / daemon 不可达，请求已被处理）。
  2             用法/解析错误（缺参、未知命令、--socket 在本构建不可用）。
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

/// thin-client 远程传输目标：Unix domain socket 或 TCP loopback 地址。
///
/// CLI 端当前仅支持 TCP loopback（`--addr`）；`--socket` 服务端监听已支持，
/// CLI 建连待落地。
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Socket variant reserved for future CLI socket transport; extract() returns Err on --socket.
enum RemoteTarget {
    /// `--socket <path>`（Unix: unix socket；Windows: named pipe）。
    Socket(String),
    /// `--addr <ip:port>`（TCP loopback）。
    Tcp(String),
}

/// 从参数中剥离全局 `--addr <ip:port>`；遇 `--socket` 报错。
/// 返回 (remote, 剩余 args)。
fn extract_remote_target(args: &[String]) -> Result<(RemoteTarget, Vec<String>), String> {
    let mut remote = RemoteTarget::Tcp(DEFAULT_LOCALAPI_ADDR.to_string());
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                let value = args
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| "missing value for --addr".to_string())?;
                remote = RemoteTarget::Tcp(value.clone());
                i += 2;
            }
            "--socket" => {
                return Err(
                    "--socket transport is not available in this build; use --addr <ip:port> (TCP loopback)"
                        .to_string(),
                );
            }
            other => {
                rest.push(other.to_string());
                i += 1;
            }
        }
    }
    Ok((remote, rest))
}

fn run(args: &[String]) -> i32 {
    let (target, args) = match extract_remote_target(args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprint!("{USAGE}");
            return 2;
        }
    };
    let addr = match target {
        RemoteTarget::Tcp(a) => a,
        RemoteTarget::Socket(_) => {
            eprintln!("error: --socket not supported in CLI client build");
            eprint!("{USAGE}");
            return 2;
        }
    };
    let (json_mode, args) = split_json_flag(&args);

    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print!("{USAGE}");
        return 0;
    }

    // 子网命令族走进程内 SDK（PRODUCT §12.16）。
    if args[0].as_str() == "subnet" {
        return run_subnet(&args[1..], json_mode);
    }

    let command = match parse_command(&args) {
        Ok(cmd) => cmd,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprint!("{USAGE}");
            return 2;
        }
    };

    // Run 保持进程内 SDK 路径（LocalAPI 无对应路由）。
    if matches!(command, ControlCommand::Run { .. }) {
        let service = ControlServiceImpl;
        return match service.snapshot(&command) {
            Ok(json) => render_and_exit(&json, json_mode),
            Err(err) => {
                if json_mode {
                    println!("{}", service.error_to_json(&err));
                } else {
                    eprintln!("error: {err}");
                }
                0
            }
        };
    }

    // 有 daemon 路由 → 裸 HTTP GET；无路由 → 本地合成 UNSUPPORTED。
    match localapi_client::route_for(&command) {
        Some(path) => query_daemon(&addr, path, json_mode),
        None => {
            let json = localapi_client::unsupported_json(&command);
            render_and_exit(&json, json_mode)
        }
    }
}

/// 向 daemon 发一次 GET，解析 body JSON，按模式渲染。
fn query_daemon(addr: &str, path: &str, json_mode: bool) -> i32 {
    match localapi_client::http_get(addr, path) {
        Ok(body) => match serde_json::from_str::<Value>(&body) {
            Ok(json) => render_and_exit(&json, json_mode),
            Err(e) => {
                // daemon 返回了无法解析为 JSON 的 body：结构化 FAIL（exit 0）。
                let json = localapi_client::bad_response_json(addr, &e.to_string());
                render_and_exit(&json, json_mode)
            }
        },
        Err(e) => {
            // 连接失败：--json 打结构化 FAIL JSON 到 stdout（exit 0）；人读打 stderr。
            if json_mode {
                let json = localapi_client::unreachable_json(addr, &e.to_string());
                println!("{json}");
            } else {
                eprintln!("error: {e}");
            }
            0
        }
    }
}

/// 按输出模式渲染 JSON：--json 原样打 stdout；人读走 `render_text` 投影。
fn render_and_exit(json: &Value, json_mode: bool) -> i32 {
    if json_mode {
        println!("{json}");
    } else {
        for line in render_text(json) {
            println!("{line}");
        }
    }
    0
}

/// `subnet up/status/leave`：进程内 SDK（LocalAPI 无 subnet 路由，同 `run` 路径）。
/// 配置/状态路径由 `--config <path>` / `--state <path>` 指定，默认
/// `~/.nexus/subnet.json`（PRODUCT §12.16）。
fn run_subnet(args: &[String], json_mode: bool) -> i32 {
    let Some(sub) = args.first() else {
        eprintln!("error: missing subnet subcommand (up|status|leave)");
        eprint!("{USAGE}");
        return 2;
    };
    let mut config: Option<PathBuf> = None;
    let mut state: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: missing value for --config");
                    return 2;
                };
                config = Some(PathBuf::from(v));
                i += 2;
            }
            "--state" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: missing value for --state");
                    return 2;
                };
                state = Some(PathBuf::from(v));
                i += 2;
            }
            other if other.starts_with("--") => {
                eprintln!("error: unknown option: {other}");
                return 2;
            }
            other => {
                eprintln!("error: unexpected argument: {other}");
                return 2;
            }
        }
    }
    let state_path = state.unwrap_or_else(default_state_path);
    let json = match sub.as_str() {
        "up" => {
            let Some(cfg) = config else {
                eprintln!("error: subnet up requires --config <path>");
                return 2;
            };
            match subnet_up(&cfg, &state_path) {
                Ok(v) => v,
                Err(e) => serde_json::json!({
                    "verdict": "CONFIG_ERROR",
                    "command": "subnet up",
                    "error": e,
                }),
            }
        }
        "status" => subnet_status(&state_path),
        "leave" => subnet_leave(&state_path),
        other => {
            eprintln!("error: unknown subnet subcommand: {other}");
            eprint!("{USAGE}");
            return 2;
        }
    };
    render_and_exit(&json, json_mode)
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
        // 用法/解析错误走 parse_command 错误路径 -> exit 2（不触网）。
        let code = run_str(&["plan", "explain"]);
        assert_eq!(code, 2);
    }

    #[test]
    fn help_exits_0() {
        assert_eq!(run_str(&[]), 0);
        assert_eq!(run_str(&["help"]), 0);
    }

    #[test]
    fn addr_flag_extracts_value_and_leaves_command() {
        let args = vec![
            "--addr".to_string(),
            "127.0.0.1:9999".to_string(),
            "status".to_string(),
        ];
        let (target, rest) = extract_remote_target(&args).unwrap();
        assert_eq!(target, RemoteTarget::Tcp("127.0.0.1:9999".into()));
        assert_eq!(rest, vec!["status".to_string()]);
    }

    #[test]
    fn addr_defaults_to_loopback() {
        let args = vec!["status".to_string()];
        let (target, rest) = extract_remote_target(&args).unwrap();
        assert_eq!(target, RemoteTarget::Tcp(DEFAULT_LOCALAPI_ADDR.into()));
        assert_eq!(rest, vec!["status".to_string()]);
    }

    #[test]
    fn socket_flag_is_rejected() {
        let args = vec!["--socket".to_string(), "/tmp/nexusd.sock".to_string()];
        let err = extract_remote_target(&args).unwrap_err();
        assert!(err.contains("--socket"));
        // 端到端：--socket 必须 exit 2（用法错误），且不触网。
        assert_eq!(run_str(&["--socket", "/tmp/nexusd.sock", "status"]), 2);
    }

    #[test]
    fn status_with_no_daemon_exits_0_with_fail_json() {
        // 没有 daemon 在 18080 上：--json 模式输出 DAEMON_UNREACHABLE FAIL JSON 到 stdout，
        // exit 0（请求已被处理，只是连不上）。
        let code = run_str(&["--json", "status"]);
        assert_eq!(code, 0);
    }

    #[test]
    fn unsupported_command_synthesizes_local_fail_json() {
        // connectivity candidates 无 daemon 路由：本地合成 UNSUPPORTED，不触网。
        let code = run_str(&["--json", "connectivity", "candidates"]);
        assert_eq!(code, 0);
    }
}
