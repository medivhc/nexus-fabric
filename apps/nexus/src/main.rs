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
use nexus::localapi_client::{self};
use nexus::mesh::AutoMeshController;
use nexus::schedule_cli::{
    default_state_path as schedule_state_path, error_json as schedule_error_json, schedule_at,
    schedule_cancel, schedule_every, schedule_list, schedule_tick, unix_now_secs,
};
use nexus::subnet_cli::{
    allocate_ephemeral_udp_locator, assemble_default_tunnel, assemble_real_tunnel_for_daemon,
    classify_tun_error, default_state_path, subnet_leave, subnet_status, subnet_up, subnet_up_tun,
};
use nexus_control_api::{ControlCommand, ResourceId, SessionId};
use serde_json::Value;
// Windows 侧 system-proxy / autostart 分支使用裸 `json!` 宏。
#[cfg(windows)]
use serde_json::json;
use std::path::PathBuf;

const USAGE: &str = "\
nexus — Nexus 统一 Resource Fabric 控制面 CLI（瘦客户端）

用法:
  nexus [--json] [--addr <ip:port>] <command> [args]

全局选项:
  --json        原样打印 daemon 返回 JSON（机器可读，stderr 静默）。
  --addr <host:port>   nexusd serve LocalAPI 地址（TCP loopback；默认走 unix socket）。
  --socket <path>      nexusd serve LocalAPI socket 路径（默认见下）。

命令:
  status                                  总体状态
  plan <resource>                       只读规划预览（resolve＋filter＋score，不建连）
  plan explain <resource|session-id>     Plan 决策解释（双模式：历史记录 / 估算非承诺）
  use <resource>                          N2 资源访问入口（resolve→plan→authorize→establish）
  session list|watch <id>|close <id>      会话管理（状态查询＋历史 DecisionTrace＋关闭）
  resource list|show <name>               资源目录（list / show）
  resource publish|revoke                 资源发布 / 撤销发布
  session watch <session-id>              观察 Session 状态（N2 语义；§9 daemon 路由保留）
  connectivity status                     连接状态
  connectivity candidates                 候选 Provider
  connectivity probe <target>             探测目标可达性
  connectivity links                      活动链路
  connectivity nat [--peer <hex>]         NAT 穿透状态
  dns status                              DNS 子系统状态
  dns resolve <name>                      解析域名
  dns providers                           DNS Provider 列表
  dns cache                               DNS 缓存
  workspace heads <workspace>             Workspace Head Set
  workspace conflicts <workspace>         未合并冲突
  workspace cache <workspace>             Workspace 缓存状态
  workspace commit <workspace>            提交 Workspace 暂存变更（经 daemon）
  snapshot freeze <workspace> --config <absolute-dir> --commit <id>
      --include <path> [--exclude <path>] [--executable <path>] --output <absolute-new-dir>
                                        离线冻结指定 Commit；selection 可重复且不覆盖目标
  snapshot upload --bundle <absolute-dir> --provider <id> --resource <id> --key <id>
  snapshot status|cancel <upload-id>       本机认证 staging；Staged 不表示任务执行
  task submit --request <json-file>       N3 提交（完整执行接线尚未装配）
  task show|cancel|artifacts <id>          查询或取消本地提供方任务
  task logs <id> --stream <stdout|stderr> --offset <n>
  task-provider grant list --config <dir> [--resource <name>]
                                        本地提供方 Workspace 的授权取证（不读取身份）
  task-provider grant add|revoke --config <dir> --resource <name> (--self|--principal <p>)
                                        本地 Use 授权运维（仅 add 允许 --not-after <unix>）
                                        config 必须为显式绝对路径；不接受 --addr/--socket
  artifact get <id> --output <path>        N3 完整下载尚未装配（不修改输出）
  compute jobs                            Compute 任务
  diagnose                                统一诊断
  platform capabilities                   平台能力清单
  run <resource>                          执行远程资源访问（进程内 SDK）
                                          注：`run -- <cmd>` 为 N3 任务语义，N2 诚实拒绝
                                          （UNSUPPORTED run-with-command；资源访问请用 `nexus use`）
  network up --config <toml>              N1 装配前台运行（建 TUN→dial→包泵，Ctrl-C 退出）
  network status [--config <toml>]        N1 装配状态（无 daemon 时诚实标注）
  subnet up|status|leave|punch            虚拟子网命令族（进程内 SDK，PRODUCT §12.28）
  schedule at|every|list|cancel|tick      计划任务命令族（进程内 SDK，PRODUCT §14）
  proxy [--addr <ip:port>] [--config <path>] [--tun]
                                        真实 SOCKS5 数据面（进程内，PRODUCT §11）
  proxy speedtest                         节点测速（loopback 自检）
  proxy bufferbloat-test --proxy <ip:port> bufferbloat 诊断（定位拥塞段）
  proxy run|host|relay ...                数据面组合根（进程内 SDK）
  system-proxy <status|set|clear|e2e>     系统代理控制（进程内 SDK，PRODUCT §13）
  autostart <install|remove|status>       开机自启（进程内 SDK，PRODUCT §13）
  pair invite|join|list|remove --dir <config-dir>
                                        设备配对（D7；带外配对码 + ed25519 签名）
  node init [--force]                   生成本节点 X25519 身份（NodeId 内容派生，N2 P0-1）
  node trust --provider <id> --pubkey <hex>
                                        显式信任提供方 ed25519 身份（D6 TOFU，N2 P0-4）
  help / --help                           显示本帮助

前置条件:
  观察命令需要先在另一个终端启动 `nexusd serve`（默认 unix socket；
  `~/.config/nexus/localapi.token` 为共享 bearer token，0600）。
  daemon 未运行时，CLI 输出 DAEMON_UNREACHABLE FAIL JSON（exit 0）。

输出:
  --json        原样打印 observability 快照 JSON（机器可读，stderr 静默）。
  默认          渲染人读文本视图（JSON 的字段投影）。
  --socket <path> / --addr <ip:port>
                thin-client 远程传输目标（默认 unix socket：
                $XDG_RUNTIME_DIR/nexus-localapi.sock；--addr 切 TCP loopback）。

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
/// D8（N2 P0-1）：默认 unix socket；`--addr` 显式切到 TCP loopback。
#[derive(Debug, Clone, PartialEq)]
enum RemoteTarget {
    /// `--socket <path>`（Unix: unix socket；Windows: named pipe）。
    Socket(String),
    /// `--addr <ip:port>`（TCP loopback）。
    Tcp(String),
}

impl RemoteTarget {
    /// 转为 localapi_client 的传输目标。
    fn to_client_target(&self) -> localapi_client::LocalApiTarget {
        match self {
            RemoteTarget::Socket(p) => {
                localapi_client::LocalApiTarget::Socket(std::path::PathBuf::from(p))
            }
            RemoteTarget::Tcp(a) => localapi_client::LocalApiTarget::Tcp(a.clone()),
        }
    }

    /// 人读/JSON 展示用标签。
    fn label(&self) -> String {
        match self {
            RemoteTarget::Socket(p) => format!("socket:{p}"),
            RemoteTarget::Tcp(a) => a.clone(),
        }
    }
}

/// 从参数中剥离全局 `--addr <ip:port>` / `--socket <path>`（D8：默认 unix socket）。
///
/// 仅消费**子命令 token 之前**的全局选项；子命令之后出现的同名选项归子命令所有
/// （对齐 usage 文法 `nexus [--json] [--addr <ip:port>] <command> [args]`）。
/// 返回 (remote, 剩余 args)。
fn extract_remote_target(args: &[String]) -> Result<(RemoteTarget, Vec<String>), String> {
    let mut remote = match localapi_client::default_target() {
        localapi_client::LocalApiTarget::Socket(p) => RemoteTarget::Socket(p.display().to_string()),
        localapi_client::LocalApiTarget::Tcp(a) => RemoteTarget::Tcp(a),
    };

    // 定位子命令位置：从开头跳过已知全局标志及其值，第一个非全局标志 token 即子命令。
    // 全局标志：--json（无值）、--addr <v>、--socket <v>、--addr=<v>、--socket=<v>。
    let mut subcommand_idx = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                i += 1;
            }
            "--addr" | "--socket" => {
                i += 2;
            }
            s if s.starts_with("--addr=") || s.starts_with("--socket=") => {
                i += 1;
            }
            _ => {
                subcommand_idx = i;
                break;
            }
        }
        subcommand_idx = i;
    }

    // 仅在全局前缀（args[0..subcommand_idx]）内剥离 --addr / --socket。
    let mut rest = Vec::with_capacity(args.len());
    let mut j = 0;
    while j < subcommand_idx {
        match args[j].as_str() {
            "--addr" => {
                let value = args
                    .get(j + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| "missing value for --addr".to_string())?;
                remote = RemoteTarget::Tcp(value.clone());
                j += 2;
            }
            "--socket" => {
                let value = args
                    .get(j + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| "missing value for --socket".to_string())?;
                remote = RemoteTarget::Socket(value.clone());
                j += 2;
            }
            other => {
                rest.push(other.to_string());
                j += 1;
            }
        }
    }

    // 子命令及其后所有参数原样保留（含子命令自己的 --addr / --socket）。
    rest.extend_from_slice(&args[subcommand_idx..]);

    Ok((remote, rest))
}

fn run(args: &[String]) -> i32 {
    if nexus::snapshot_cli::handles(args) {
        return match nexus::snapshot_cli::run(args) {
            Ok(output) => {
                println!("{output}");
                0
            }
            Err(reason) => {
                eprintln!("error: {reason}");
                2
            }
        };
    }
    // Local operator commands must inspect the raw global options before the
    // remote parser consumes them. This branch never selects a daemon target.
    if is_task_provider_command(args) {
        if args.iter().any(|arg| {
            matches!(arg.as_str(), "--addr" | "--socket")
                || arg.starts_with("--addr=")
                || arg.starts_with("--socket=")
        }) || args.iter().filter(|arg| arg.as_str() == "--json").count() > 1
        {
            eprintln!("error: task-provider rejects remote targets and duplicate global options");
            eprint!("{USAGE}");
            return 2;
        }
        let (json_mode, local_args) = split_json_flag(args);
        return nexus::task_provider_grant::run(&local_args[1..], json_mode);
    }
    let (target, args) = match extract_remote_target(args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprint!("{USAGE}");
            return 2;
        }
    };
    let (json_mode, args) = split_json_flag(&args);

    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print!("{USAGE}");
        return 0;
    }

    // N3 is a thin client of the authenticated, versioned daemon service.
    if matches!(args[0].as_str(), "task" | "artifact") {
        return match nexus::task_cli::run(&args, json_mode, &target.to_client_target()) {
            Ok(output) => {
                println!("{output}");
                0
            }
            Err(reason) => {
                eprintln!("error: {reason}");
                eprint!("{USAGE}");
                2
            }
        };
    }

    // D4（2026-10-03，requirement-change）：`nexus run <resource> -- <cmd...>`
    // 为 N3 任务提交语义（白皮书 A.1），在 N2 永远不是可执行命令——在解析层
    // 直接诚实拒绝，不进入 ControlCommand 分发、不假执行。
    // `--json` 已在 split_json_flag 剥离，此处不会误伤。
    if args[0].as_str() == "run" && args.iter().any(|a| a == "--") {
        return run_with_command_rejected(&args, json_mode);
    }

    // 子网命令族走进程内 SDK（PRODUCT §12.16）。
    if args[0].as_str() == "subnet" {
        return run_subnet(&args[1..], json_mode);
    }
    // 计划任务命令族走进程内 SDK（PRODUCT §14）。
    if args[0].as_str() == "schedule" {
        return run_schedule(&args[1..], json_mode);
    }
    // 代理数据面命令族走进程内 SDK（PRODUCT §11；自 nexusd 迁移，refactor: CLI 统一）。
    if args[0].as_str() == "proxy" {
        return run_proxy(&args[1..]);
    }
    // 系统代理控制走进程内 SDK（PRODUCT §13；自 nexusd 迁移，refactor: CLI 统一）。
    if args[0].as_str() == "system-proxy" {
        return dispatch_system_proxy(&args[1..]);
    }
    // 开机自启走进程内 SDK（PRODUCT §13；自 nexusd 迁移，refactor: CLI 统一）。
    if args[0].as_str() == "autostart" {
        return dispatch_autostart(&args[1..]);
    }
    // 配置文件夹管理（本地文件操作，不经过 daemon；daemon 热加载）。
    if args[0].as_str() == "config" {
        return run_config(&args[1..]);
    }
    // 设备配对（D7；本地文件 + 前台 TCP，不经过 daemon；daemon 热加载 peers/）。
    if args[0].as_str() == "pair" {
        return nexus::pair_cli::run_pair(&args[1..]);
    }
    // 节点身份（N2 P0-1；本地文件操作，不经过 daemon）。
    if args[0].as_str() == "node" {
        return nexus::node_cli::run_node(&args[1..], json_mode);
    }
    // 规划预览（N2 P0-3；纯本地 resolve＋filter＋score，不建连，不经过 daemon）。
    if args[0].as_str() == "plan" {
        return nexus::plan_cli::run_plan(&args[1..], json_mode);
    }
    // 资源访问四步闭环（N2 P0-4，D4；进程内 N2 存储，不经过 daemon）。
    if args[0].as_str() == "use" {
        return nexus::use_cli::run_use(&args[1..], json_mode);
    }
    // 会话管理（N2 P0-4；进程内 N2 存储；`session watch` 的 N2 语义在此，
    // daemon 的 /localapi/v0/session/watch 保留 §9 冻结行为）。
    if args[0].as_str() == "session" {
        return nexus::session_cli::run_session(&args[1..], json_mode);
    }
    // 资源目录管理（N2 P0-4/P0-5；进程内 N2 存储，不经过 daemon）。
    if args[0].as_str() == "resource" {
        return nexus::resource_cli::run_resource(&args[1..], json_mode);
    }
    // DNS 子系统命令族（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "dns" {
        return run_dns(&args[1..], json_mode, &target.to_client_target());
    }
    // 连通性子系统命令族（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "connectivity" {
        return run_connectivity(&args[1..], json_mode, &target.to_client_target());
    }
    // Workspace 命令族（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "workspace" {
        return run_workspace(&args[1..], json_mode, &target.to_client_target());
    }
    // Compute 任务（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "compute" {
        return run_compute(&args[1..], json_mode, &target.to_client_target());
    }
    // Snapshot 命令族（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "snapshot" {
        return run_snapshot(&args[1..], json_mode, &target.to_client_target());
    }
    // Diagnose（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "diagnose" {
        return run_diagnose(&json_mode, &target.to_client_target());
    }
    // Platform capabilities（薄客户端；daemon 路由 + 本地合成 UNSUPPORTED）。
    if args[0].as_str() == "platform" {
        return run_platform(&args[1..], json_mode, &target.to_client_target());
    }

    // 未知命令
    eprintln!("error: unknown command: {}", args[0]);
    eprint!("{USAGE}");
    2
}
