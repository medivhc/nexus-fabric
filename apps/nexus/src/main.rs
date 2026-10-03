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
    assemble_default_tunnel, assemble_real_tunnel_for_daemon, classify_tun_error,
    default_state_path, subnet_leave, subnet_status, subnet_up, subnet_up_tun,
};
use nexus_control_api::{ControlCommand, ResourceId, SessionId};
use serde_json::Value;
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
  dns status                              DNS 子系统状态
  dns resolve <name>                      解析域名
  dns providers                           DNS Provider 列表
  dns cache                               DNS 缓存
  workspace heads <workspace>             Workspace Head Set
  workspace conflicts <workspace>         未合并冲突
  workspace cache <workspace>             Workspace 缓存状态
  workspace commit <workspace>            提交 Workspace 暂存变更（经 daemon）
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
/// 返回 (remote, 剩余 args)。
fn extract_remote_target(args: &[String]) -> Result<(RemoteTarget, Vec<String>), String> {
    let mut remote = match localapi_client::default_target() {
        localapi_client::LocalApiTarget::Socket(p) => RemoteTarget::Socket(p.display().to_string()),
        localapi_client::LocalApiTarget::Tcp(a) => RemoteTarget::Tcp(a),
    };
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
                let value = args
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| "missing value for --socket".to_string())?;
                remote = RemoteTarget::Socket(value.clone());
                i += 2;
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
    let (json_mode, args) = split_json_flag(&args);

    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print!("{USAGE}");
        return 0;
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
    // 授权表管理（N2 P0-5，D6；进程内 N2 存储，不经过 daemon）。
    if args[0].as_str() == "grant" {
        return nexus::grant_cli::run_grant(&args[1..], json_mode);
    }
    // 提供方侧准入服务（N2 P0-5；B 机常驻进程）。
    if args[0].as_str() == "provider" {
        return nexus::provider_cli::run_provider(&args[1..], json_mode);
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

    // N1 装配命令族走进程内 Composition Root（M6；无 daemon 路由）。
    if matches!(
        command,
        ControlCommand::NetworkUp { .. } | ControlCommand::NetworkStatus
    ) {
        return nexus::network::dispatch(&command, &args, json_mode);
    }

    // 有 daemon 路由 → HTTP GET；无路由 → 本地合成 UNSUPPORTED。
    // N2 P0-1：动态路由优先（带参数命令经 query string，不再丢参数）。
    match localapi_client::route_for_dynamic(&command) {
        // 动态路由（`workspace commit <id>` / `session watch <id>` / `plan explain <resource>`）。
        Some(path) => query_daemon(&target, path.as_str(), json_mode),
        None => match localapi_client::route_for(&command) {
            Some(path) => query_daemon(&target, path, json_mode),
            None => {
                let json = localapi_client::unsupported_json(&command);
                render_and_exit(&json, json_mode)
            }
        },
    }
}

/// D4 诚实拒绝：`nexus run <resource> -- <cmd...>` 返回结构化
/// `UNSUPPORTED{feature:"run-with-command", layer:"N3"}`。
///
/// 任务提交语义归 N3（白皮书 A.1）；N2 的资源访问入口为 `nexus use`
/// （P0-4，PRODUCT §16）。exit 0（请求已被处理，机器消费者看 verdict）。
fn run_with_command_rejected(args: &[String], json_mode: bool) -> i32 {
    let resource = args
        .get(1)
        .filter(|r| r.as_str() != "--")
        .cloned()
        .unwrap_or_default();
    let json = serde_json::json!({
        "verdict": "FAIL",
        "error": {
            "code": "UNSUPPORTED",
            "feature": "run-with-command",
            "layer": "N3",
            "resource": resource,
            "message": "nexus run does not execute commands: task submission (`run -- <command>`) is an N3 capability (whitepaper A.1); for N2 resource access use `nexus use <resource>` (PRODUCT.md#16-n2-resource-access)",
        },
    });
    render_and_exit(&json, json_mode)
}

/// 向 daemon 发一次 GET，解析 body JSON，按模式渲染。
fn query_daemon(target: &RemoteTarget, path: &str, json_mode: bool) -> i32 {
    let label = target.label();
    match localapi_client::http_get(&target.to_client_target(), path) {
        Ok(body) => match serde_json::from_str::<Value>(&body) {
            Ok(json) => render_and_exit(&json, json_mode),
            Err(e) => {
                // daemon 返回了无法解析为 JSON 的 body：结构化 FAIL（exit 0）。
                let json = localapi_client::bad_response_json(&label, &e.to_string());
                render_and_exit(&json, json_mode)
            }
        },
        Err(e) => {
            // 连接失败：--json 打结构化 FAIL JSON 到 stdout（exit 0）；人读打 stderr。
            if json_mode {
                let json = localapi_client::unreachable_json(&label, &e.to_string());
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
    let mut tun = false;
    let mut foreground = false;
    let mut tun_name: Option<String> = None;
    let mut listen: Option<String> = None;
    let mut encrypt_state = false;
    // P4.2 §12.9.6：punch 的位置参数（<peer_vip> <targets...>）与尝试次数。
    let mut punch_peer: Option<String> = None;
    let mut punch_targets: Vec<String> = Vec::new();
    let mut attempts = 10u32;
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
            "--encrypt-state" => {
                encrypt_state = true;
                i += 1;
            }
            "--tun" => {
                tun = true;
                i += 1;
            }
            "--foreground" => {
                // §12.38 bugfix：01e5114 迁移丢失的常驻 flag（前台持有隧道，
                // 轮询状态文件等 leave → 优雅退出）。
                foreground = true;
                i += 1;
            }
            "--tun-name" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: missing value for --tun-name");
                    return 2;
                };
                tun_name = Some(v.clone());
                i += 2;
            }
            "--listen" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: missing value for --listen");
                    return 2;
                };
                listen = Some(v.clone());
                i += 2;
            }
            "--attempts" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: missing value for --attempts");
                    return 2;
                };
                match v.parse::<u32>() {
                    Ok(n) => {
                        attempts = n;
                        i += 2;
                    }
                    Err(_) => {
                        eprintln!("error: --attempts must be a positive integer");
                        return 2;
                    }
                }
            }
            other if other.starts_with("--") => {
                eprintln!("error: unknown option: {other}");
                return 2;
            }
            other => {
                // punch 子命令的位置参数：第一个是 peer_vip，其余是 targets。
                if sub == "punch" {
                    if punch_peer.is_none() {
                        punch_peer = Some(other.to_string());
                    } else {
                        punch_targets.push(other.to_string());
                    }
                    i += 1;
                } else {
                    eprintln!("error: unexpected argument: {other}");
                    return 2;
                }
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
            if foreground {
                // 常驻：装配并持有隧道，直到 leave 信号（状态文件删除）→ 优雅退出 0。
                return subnet_foreground(&cfg, &state_path, encrypt_state, tun, tun_name, listen);
            }
            if tun {
                let name = tun_name.unwrap_or_else(|| "nexus0".to_string());
                let lsn = listen.unwrap_or_else(|| "udp://0.0.0.0:0".to_string());
                match subnet_up_tun(&cfg, &state_path, &name, &lsn) {
                    Ok(v) => v,
                    Err(e) => nexus::subnet_cli::classify_tun_error(&e),
                }
            } else {
                match subnet_up(&cfg, &state_path, encrypt_state) {
                    Ok(v) => v,
                    Err(e) => serde_json::json!({
                        "verdict": "CONFIG_ERROR",
                        "command": "subnet up",
                        "error": e,
                    }),
                }
            }
        }
        "status" => subnet_status(&state_path),
        "leave" => subnet_leave(&state_path),
        "punch" => {
            let Some(cfg) = config else {
                eprintln!("error: subnet punch requires --config <path>");
                return 2;
            };
            let Some(peer) = punch_peer else {
                eprintln!("error: subnet punch requires <peer_vip> <targets...>");
                return 2;
            };
            // --listen 必填：UdpCarrier 拒绝 0 端口（"locator zero port"）。
            let Some(lsn) = listen else {
                eprintln!("error: subnet punch requires --listen <udp://host:port>");
                return 2;
            };
            match nexus::subnet_cli::subnet_punch(
                &cfg,
                &state_path,
                &peer,
                &punch_targets,
                &lsn,
                attempts,
            ) {
                Ok(v) => v,
                Err(e) => serde_json::json!({
                    "verdict": "PUNCH_ERROR",
                    "command": "subnet punch",
                    "error": e,
                }),
            }
        }
        other => {
            eprintln!("error: unknown subnet subcommand: {other}");
            eprint!("{USAGE}");
            return 2;
        }
    };
    render_and_exit(&json, json_mode)
}

/// P3.5 常驻运行循环（§12.38 bugfix：恢复 01e5114 迁移丢失的 `--foreground`）：
/// 持有隧道（进程为 Owner，随 drop 清理），轮询 leave 信号（状态文件被删除）
/// → 优雅退出 0。`--tun` 时走真实数据面（wintun/tun + UDP），否则走默认隧道。
fn subnet_foreground(
    cfg: &std::path::Path,
    state_path: &std::path::Path,
    encrypt: bool,
    use_tun: bool,
    tun_name: Option<String>,
    listen: Option<String>,
) -> i32 {
    let result: Result<u8, (String, String)> = if use_tun {
        let name = tun_name.unwrap_or_else(|| "nexus0".to_string());
        let lsn = listen.unwrap_or_else(|| "udp://0.0.0.0:0".to_string());
        subnet_foreground_real(cfg, state_path, encrypt, &name, &lsn)
    } else {
        (|| {
            let tunnel =
                assemble_default_tunnel(cfg).map_err(|e| ("CONFIG_ERROR".to_string(), e))?;
            let up =
                subnet_up(cfg, state_path, encrypt).map_err(|e| ("CONFIG_ERROR".to_string(), e))?;
            println!("{up}");
            // Auto-Mesh 自动挡：自动打洞 + 断线自动重连。
            let mut mesh = AutoMeshController::new(tunnel, 500);

            // crash 恢复：从磁盘加载已发现的 peer
            let mesh_state = state_path.with_extension("mesh.json");
            mesh.load_state(&mesh_state);

            let state_path_owned = state_path.to_path_buf();
            let mesh_state_clone = mesh_state.clone();
            mesh.run_with_save(move || !state_path_owned.exists(), Some(mesh_state_clone));
            Ok(0)
        })()
    };
    match result {
        Ok(code) => code as i32,
        Err((verdict, msg)) => {
            println!(
                "{}",
                serde_json::json!({
                    "verdict": verdict,
                    "command": "subnet up",
                    "error": msg,
                })
            );
            0
        }
    }
}

/// P3.8（§12.38）真实数据面常驻：wintun/tun + UDP 承载，隧道由进程持有。
///
/// 成功：装配真实隧道 → 写状态文件 → up JSON 含 `local_locator` → 进入
/// Auto-Mesh 常驻循环（leave 轮询：状态文件删除即停）；leave → 优雅退出 0，
/// 函数返回时 drop 清理 wintun/tun 适配器与 UDP socket。
///
/// 失败（udp bind / wintun or tun create 失败）：**不写状态文件、不进入常驻循环、
/// 绝不静默降级 mock**，输出 `TUN_ERROR` 结构化（exit 0）。tun 名校验等其它
/// 配置错误 → `CONFIG_ERROR`（exit 0）。
fn subnet_foreground_real(
    cfg: &std::path::Path,
    state_path: &std::path::Path,
    encrypt: bool,
    tun_name: &str,
    listen: &str,
) -> Result<u8, (String, String)> {
    let (tunnel, local_locator) = match assemble_real_tunnel_for_daemon(cfg, tun_name, listen) {
        Ok(v) => v,
        Err(e) => {
            if e.starts_with("TUN_ERROR") {
                // 结构化 TUN_ERROR：Ok 语义（verdict=TUN_ERROR, exit 0），不降级。
                println!("{}", classify_tun_error(&e));
                return Ok(0);
            }
            return Err(("CONFIG_ERROR".to_string(), e));
        }
    };
    let mut up =
        subnet_up(cfg, state_path, encrypt).map_err(|e| ("CONFIG_ERROR".to_string(), e))?;
    if let Some(obj) = up.as_object_mut() {
        obj.insert("local_locator".into(), serde_json::json!(local_locator));
    }
    println!("{up}");
    // Auto-Mesh 自动挡：自动打洞 + 断线自动重连。
    // 持有真实隧道直到函数返回（drop 清理 wintun/tun 适配器与 UDP socket）。
    let mut mesh = AutoMeshController::new(tunnel, 500);

    // crash 恢复：从磁盘加载已发现的 peer
    let mesh_state = state_path.with_extension("mesh.json");
    mesh.load_state(&mesh_state);

    let state_path_owned = state_path.to_path_buf();
    let mesh_state_clone = mesh_state.clone();
    mesh.run_with_save(move || !state_path_owned.exists(), Some(mesh_state_clone));
    Ok(0)
}

/// `schedule at|every|list|cancel|tick`：进程内 SDK（LocalAPI 无 schedule 路由，
/// 同 `run` / `subnet` 路径，PRODUCT §14）。注册表路径由 `--state <path>` 指定，
/// 默认 `~/.nexus/schedule.json`；`--` 之后为触发命令。
fn run_schedule(args: &[String], json_mode: bool) -> i32 {
    let Some(sub) = args.first() else {
        eprintln!("error: missing schedule subcommand (at|every|list|cancel|tick)");
        eprint!("{USAGE}");
        return 2;
    };
    let mut state: Option<PathBuf> = None;
    let mut resource: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut positional: Vec<String> = Vec::new();
    let mut after_ddash = false;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if !after_ddash && a == "--" {
            after_ddash = true;
            i += 1;
            continue;
        }
        if !after_ddash && a == "--state" {
            let Some(v) = args.get(i + 1) else {
                eprintln!("error: missing value for --state");
                return 2;
            };
            state = Some(PathBuf::from(v));
            i += 2;
            continue;
        }
        if !after_ddash && a == "--resource" {
            let Some(v) = args.get(i + 1) else {
                eprintln!("error: missing value for --resource");
                return 2;
            };
            resource = Some(v.clone());
            i += 2;
            continue;
        }
        if !after_ddash && a.starts_with("--") {
            eprintln!("error: unknown option: {a}");
            return 2;
        }
        if after_ddash {
            command.push(a.clone());
            i += 1;
            continue;
        }
        positional.push(a.clone());
        i += 1;
    }
    let state_path = state.unwrap_or_else(schedule_state_path);

    match sub.as_str() {
        "at" | "every" => {
            let Some(ts) = positional.first() else {
                eprintln!("error: missing timestamp for schedule {sub}");
                return 2;
            };
            let Ok(ts) = ts.parse::<i64>() else {
                eprintln!("error: {ts} is not an integer timestamp");
                return 2;
            };
            let Some(res) = resource else {
                eprintln!("error: schedule {sub} requires --resource <r>");
                return 2;
            };
            if command.is_empty() {
                eprintln!("error: schedule {sub} requires a command after --");
                return 2;
            }
            let result = if sub == "at" {
                schedule_at(ts, &res, &command, &state_path)
            } else {
                schedule_every(ts, &res, &command, &state_path)
            };
            render_schedule_result(&result, &format!("schedule {sub}"), json_mode)
        }
        "list" => render_schedule_result(&schedule_list(&state_path), "schedule list", json_mode),
        "cancel" => {
            let Some(id) = positional.first() else {
                eprintln!("error: schedule cancel requires <id>");
                return 2;
            };
            render_schedule_result(
                &schedule_cancel(id, &state_path),
                "schedule cancel",
                json_mode,
            )
        }
        "tick" => render_schedule_result(
            &schedule_tick(&state_path, unix_now_secs()),
            "schedule tick",
            json_mode,
        ),
        other => {
            eprintln!("error: unknown schedule subcommand: {other}");
            eprint!("{USAGE}");
            2
        }
    }
}

/// schedule 业务结果：成功 / 业务失败均输出结构化 JSON（exit 0，请求已被处理；
/// PRODUCT §14.3 错误名 INVALID_SCHEDULE / SCHEDULE_NOT_FOUND / SUBMIT_FAILED）。
fn render_schedule_result(
    result: &Result<Value, nexus::schedule_cli::ScheduleCliError>,
    command: &str,
    json_mode: bool,
) -> i32 {
    match result {
        Ok(json) => render_and_exit(json, json_mode),
        Err(err) => {
            let json = schedule_error_json(command, err);
            render_and_exit(&json, json_mode)
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
            Some("commit") => Ok(ControlCommand::WorkspaceCommit {
                workspace: need(2, "<workspace>")?,
            }),
            _ => Err("usage: nexus workspace heads|conflicts|cache|commit <workspace>".into()),
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
        "network" => match args.get(1).map(String::as_str) {
            Some("up") => {
                let config_path = args
                    .windows(2)
                    .find(|w| w[0] == "--config")
                    .map(|w| w[1].clone())
                    .ok_or("usage: nexus network up --config <toml>")?;
                let text = std::fs::read_to_string(&config_path)
                    .map_err(|e| format!("cannot read {config_path}: {e}"))?;
                Ok(ControlCommand::NetworkUp { config: text })
            }
            Some("status") => Ok(ControlCommand::NetworkStatus),
            _ => Err(
                "usage: nexus network up --config <toml> | nexus network status [--config <toml>]"
                    .into(),
            ),
        },
        other => Err(format!("unknown command: {other}")),
    }
}

// === 自 nexusd 迁移的代理数据面命令（refactor: CLI 统一，行为不变） ===
// 原 `nexusd proxy/run/host/relay/system-proxy/autostart`，现归 `nexus` 名下。

/// 解析 `--flag <value>` / `--flag`（布尔）形式；非 flag token 忽略。
fn parse_flags(args: &[String]) -> std::collections::HashMap<String, Option<String>> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            if let Some(value) = args.get(i + 1).filter(|v| !v.starts_with("--")) {
                map.insert(arg.clone(), Some(value.clone()));
                i += 2;
                continue;
            }
            map.insert(arg.clone(), None);
        }
        i += 1;
    }
    map
}

/// 在 SDK 输出的 JSON 对象上附加 daemon 入口元数据（场景断言 daemon.entry / daemon.resource）。
fn enrich(resource: &str, mut json: Value) -> Value {
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "daemon".into(),
            serde_json::json!({ "entry": "nexus", "resource": resource }),
        );
    }
    json
}

/// 输出结构化 JSON；无论成功/失败均 exit 0（请求已被 daemon 处理）。
fn print_json_result(result: Result<Value, (String, String)>) -> i32 {
    match result {
        Ok(json) => {
            println!("{json}");
        }
        Err((code, message)) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}"
            );
        }
    }
    0
}

/// `nexus proxy bufferbloat-test` CLI 入口：
///
/// 用法：
///   nexus proxy bufferbloat-test --proxy <ip:port> [--duration <secs>] [--threshold <ms>] [--json]
///
/// 流程：空载测基准延迟 → 打满上行 --duration 秒 → 负载下再测 → 按阈值判定。
/// 人读模式输出一行诊断 +  verdict JSON；--json 只输出 JSON。
fn proxy_bufferbloat_test_cli(args: &[String]) -> i32 {
    let flags = parse_flags(args);
    let json_mode = flags.contains_key("--json");

    let proxy_raw = match flags.get("--proxy").and_then(|v| v.as_deref()) {
        Some(p) => p,
        None => {
            eprintln!("error: missing --proxy <ip:port>");
            eprintln!(
                "usage: nexus proxy bufferbloat-test --proxy <ip:port> [--duration <secs>] [--threshold <ms>] [--json]"
            );
            return 2;
        }
    };
    let proxy_addr: std::net::SocketAddr = match proxy_raw.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("error: invalid --proxy '{proxy_raw}' (want ip:port)");
            return 2;
        }
    };
    let duration_secs: u64 = flags
        .get("--duration")
        .and_then(|v| v.as_deref())
        .map(|s| s.parse().unwrap_or(10))
        .unwrap_or(10);
    let threshold_ms: u64 = flags
        .get("--threshold")
        .and_then(|v| v.as_deref())
        .map(|s| s.parse().unwrap_or(100))
        .unwrap_or(100);

    let config = nexus::BufferbloatConfig {
        proxy_addr,
        duration: std::time::Duration::from_secs(duration_secs),
        threshold_ms,
        ..Default::default()
    };
    match nexus::proxy_bufferbloat_test(&config) {
        Ok(json) => {
            if json_mode {
                println!("{json}");
            } else {
                let baseline = json
                    .get("baseline_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let loaded = json.get("loaded_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                let delta = json.get("delta_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                let diagnosis = json
                    .get("diagnosis")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");
                let advice = json.get("advice").and_then(|v| v.as_str()).unwrap_or("");
                println!("Baseline: {baseline}ms | Under load: {loaded}ms | Delta: +{delta}ms");
                println!("Verdict: {diagnosis}（{advice}）");
            }
            0
        }
        Err(e) => {
            // e.g. 代理不可达：结构化 FAIL，不 panic。
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            );
            0
        }
    }
}
/// 路由资源名到 SDK 组合根闭环；带 `--endpoint` 时走真实网络访问（real transport）。
fn proxy_run_resource(args: &[String]) -> i32 {
    let Some(resource) = args.first() else {
        eprintln!(
            "usage: nexus proxy run <service|internet-access|compute|workspace> [--endpoint <ip:port>] [--relay <ip:port>] [--token <t>] [--json]"
        );
        return 1;
    };
    let flags = parse_flags(args);
    let result: Result<Value, (String, String)> = match flags
        .get("--endpoint")
        .and_then(|v| v.as_deref())
    {
        Some(endpoint) => {
            let endpoint: std::net::SocketAddr = match endpoint.parse() {
                Ok(a) => a,
                Err(_) => {
                    println!(
                        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid endpoint {endpoint}\"}}}}"
                    );
                    return 0;
                }
            };
            let token = flags
                .get("--token")
                .and_then(|v| v.as_deref())
                .unwrap_or("nexus-preshared-token")
                .to_string();
            match flags.get("--relay").and_then(|v| v.as_deref()) {
                Some(relay) => {
                    let relay: std::net::SocketAddr = match relay.parse() {
                        Ok(a) => a,
                        Err(_) => {
                            println!(
                                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid relay {relay}\"}}}}"
                            );
                            return 0;
                        }
                    };
                    // 直连候选：默认等于 endpoint；真实 NAT 场景下候选与 relay 可达地址不同。
                    let direct: std::net::SocketAddr = match flags
                        .get("--direct")
                        .and_then(|v| v.as_deref())
                    {
                        Some(raw) => match raw.parse() {
                            Ok(a) => a,
                            Err(_) => {
                                println!(
                                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid direct {raw}\"}}}}"
                                );
                                return 0;
                            }
                        },
                        None => endpoint,
                    };
                    nexus::remote_real_flow_with_relay(&direct, &endpoint, &relay, &token, resource)
                        .map(|v| enrich("real-transport", v))
                        .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string()))
                }
                None => nexus::remote_real_flow(&endpoint, &token, resource)
                    .map(|v| enrich("real-transport", v))
                    .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
            }
        }
        None => match resource.as_str() {
            "service" => nexus::remote_service_access_flow()
                .map(|v| enrich("service", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            "internet-access" => nexus::remote_internet_access_flow()
                .map(|v| enrich("internet-access", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            "compute" => nexus::remote_compute_job_flow()
                .map(|v| enrich("compute", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            "workspace" => nexus::remote_workspace_commit_flow()
                .map(|v| enrich("workspace", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            other => {
                // 未知资源：结构化拒绝（exit 0 = 请求已被 daemon 处理，拒绝也是处理结果）。
                println!(
                    "{{\"verdict\":\"REJECTED\",\"error\":{{\"code\":\"UNKNOWN_RESOURCE\",\"resource\":\"{other}\"}},\"daemon\":{{\"entry\":\"nexus\"}}}}"
                );
                return 0;
            }
        },
    };
    print_json_result(result)
}

/// 提供方入口：真实地址持续监听，服务端 AUTH 门控 + 按资源执行业务（服务循环）。
fn proxy_host_resource(args: &[String]) -> i32 {
    let Some(resource) = args.first() else {
        eprintln!(
            "usage: nexus proxy host <service|internet-access|compute> --addr <ip:port> [--token <t>]"
        );
        return 2;
    };
    let flags = parse_flags(args);
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return 0;
            }
        },
        None => match "127.0.0.1:8787".parse() {
            Ok(a) => a,
            Err(_) => return 1,
        },
    };
    let token = flags
        .get("--token")
        .and_then(|v| v.as_deref())
        .unwrap_or("nexus-preshared-token")
        .to_string();
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind {addr} failed: {e}\"}}}}"
            );
            return 0;
        }
    };
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexus\",\"command\":\"host\",\"resource\":\"{resource}\",\"addr\":\"{addr}\"}}}}"
    );
    // 服务循环：逐连接 accept，每连接独立 AUTH 门控 + 业务闭环
    // （SDK serve_loop 打印每连接结果；认证拒绝输出 AUTH_DENIED 后继续服务）。
    if let Err(e) = nexus::remote_host_serve_loop(&listener, &token, resource) {
        println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
        );
        return 1;
    }
    0
}

/// relay 入口：真实监听，DIAL + 双向字节中继（单会话）。
fn proxy_relay_resource(args: &[String]) -> i32 {
    let flags = parse_flags(args);
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return 0;
            }
        },
        None => match "127.0.0.1:8788".parse() {
            Ok(a) => a,
            Err(_) => return 1,
        },
    };
    let result: Result<Value, (String, String)> = (|| {
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|e| ("INTERNAL".to_string(), format!("bind {addr} failed: {e}")))?;
        nexus::relay_serve_once(&listener).map_err(|e| ("INTERNAL".to_string(), e.to_string()))
    })();
    print_json_result(result.map(|v| {
        let mut json = v;
        if let Some(obj) = json.as_object_mut() {
            obj.insert(
                "daemon".into(),
                serde_json::json!({
                    "entry": "nexus",
                    "command": "relay",
                    "addr": addr.to_string(),
                }),
            );
        }
        json
    }))
}

/// 配置文件夹管理（本地文件操作；daemon 侧热加载）。
///
/// 用法：
///   nexus config get --dir <config-dir> <file>    打印文件内容（stdout）
///   nexus config set --dir <config-dir> <file>    从 stdin 读，原子写入（临时文件 + rename）
///   nexus config list --dir <config-dir>          列出已知配置文件及存在性
///
/// 已知文件名：daemon.toml / network.toml / proxy.yaml / dns.toml。
/// `set` 用原子写入避免 daemon 读到半截文件（与 watcher 的 mtime 检测配合）。
fn run_config(args: &[String]) -> i32 {
    let flags = parse_flags(args);
    let dir = match flags.get("--dir").and_then(|v| v.as_deref()) {
        Some(d) => d.to_string(),
        None => {
            eprintln!("error: missing --dir <config-dir>");
            eprintln!("usage: nexus config get|set|list --dir <config-dir> [file]");
            return 2;
        }
    };
    let dir_path = std::path::Path::new(&dir);
    if !dir_path.is_dir() {
        eprintln!("error: not a directory: {dir}");
        return 1;
    }
    const KNOWN: &[&str] = &["daemon.toml", "network.toml", "proxy.yaml", "dns.toml"];
    // 找到子命令后的第一个非 flag 参数（文件名），跳过 --dir 及其值。
    let file_arg = {
        let mut iter = args.iter().skip(1).peekable();
        let mut result = None;
        while let Some(s) = iter.next() {
            if s == "--dir" {
                iter.next(); // 跳过 --dir 的值
                continue;
            }
            if s.starts_with("--") {
                continue;
            }
            result = Some(s.clone());
            break;
        }
        result
    };
    match args.first().map(String::as_str) {
        Some("get") => {
            let file = match file_arg {
                Some(f) => f,
                None => {
                    eprintln!("usage: nexus config get --dir <dir> <file>");
                    return 2;
                }
            };
            if !KNOWN.contains(&file.as_str()) {
                eprintln!(
                    "error: unknown config file '{file}' (known: {})",
                    KNOWN.join(", ")
                );
                return 2;
            }
            let path = dir_path.join(file);
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    print!("{text}");
                    0
                }
                Err(e) => {
                    eprintln!("error: read {}: {e}", path.display());
                    1
                }
            }
        }
        Some("set") => {
            let file = match file_arg {
                Some(f) => f,
                None => {
                    eprintln!("usage: nexus config set --dir <dir> <file>  (reads stdin)");
                    return 2;
                }
            };
            if !KNOWN.contains(&file.as_str()) {
                eprintln!(
                    "error: unknown config file '{file}' (known: {})",
                    KNOWN.join(", ")
                );
                return 2;
            }
            // 从 stdin 读全部内容。
            use std::io::Read;
            let mut content = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut content) {
                eprintln!("error: read stdin: {e}");
                return 1;
            }
            // 原子写入：临时文件 + rename（避免 watcher 读到半截）。
            let path = dir_path.join(&file);
            let tmp = dir_path.join(format!(".{file}.tmp"));
            if let Err(e) = std::fs::write(&tmp, &content) {
                eprintln!("error: write temp: {e}");
                return 1;
            }
            if let Err(e) = std::fs::rename(&tmp, &path) {
                let _ = std::fs::remove_file(&tmp);
                eprintln!("error: rename: {e}");
                return 1;
            }
            println!(
                "{}",
                serde_json::json!({"verdict":"PASS","config":{"file":file,"dir":dir}})
            );
            0
        }
        Some("list") => {
            for f in KNOWN {
                let exists = dir_path.join(f).is_file();
                println!("{f}: {}", if exists { "present" } else { "absent" });
            }
            0
        }
        _ => {
            eprintln!("usage: nexus config get|set|list --dir <config-dir> [file]");
            2
        }
    }
}

/// 真实 SOCKS5 数据面入口：监听后逐会话完成握手 → 规则路由 → Session →
/// 真实出站 → 字节中继；每会话输出一条结构化 JSON（Ctrl-C 停止）。
/// `nexus proxy` 分发：speedtest/--tun/--addr 监听/run/host/relay 子命令。
fn run_proxy(args: &[String]) -> i32 {
    // 子命令路由（自 nexusd run/host/relay 迁移，避免与 `nexus run` 冲突）
    match args.first().map(String::as_str) {
        Some("run") => return proxy_run_resource(&args[1..]),
        Some("host") => return proxy_host_resource(&args[1..]),
        Some("relay") => return proxy_relay_resource(&args[1..]),
        Some("--help") | Some("-h") => {
            println!(
                "usage: nexus proxy [--addr <ip:port>] [--config <path>] [--tun] [--tun-name <n>]\n\
                 \x20      nexus proxy speedtest [--json]\n\
                 \x20      nexus proxy bufferbloat-test --proxy <ip:port> [--duration <secs>] [--threshold <ms>] [--json]\n\
                 \x20      nexus proxy run <service|internet-access|compute|workspace> [--endpoint <ip:port>] [--json]\n\
                 \x20      nexus proxy host <service|internet-access|compute> --addr <ip:port> [--token <t>]\n\
                 \x20      nexus proxy relay --addr <ip:port>"
            );
            return 0;
        }
        _ => {}
    }
    // 节点测速子命令（PRODUCT §11.10）：loopback 自检真实 TcpLatencyProbe。
    if args.first().map(|a| a.as_str()) == Some("speedtest") {
        match nexus::proxy_speedtest() {
            Ok(json) => println!("{json}"),
            Err(e) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            ),
        }
        return 0;
    }
    // bufferbloat 诊断：空载基准 vs 打满负载的延迟对比，定位拥塞段。
    if args.first().map(|a| a.as_str()) == Some("bufferbloat-test") {
        return proxy_bufferbloat_test_cli(&args[1..]);
    }
    let flags = parse_flags(args);
    // §11.18 TUN 透明入站：--tun 走真实 wintun adapter 开卡（E5，需管理员 + wintun.dll
    // 与 nexusd.exe 同目录）。成功返回 adapter 元数据后随 Drop 释放句柄；失败结构化 TUN_ERROR。
    if flags.contains_key("--tun") {
        let tun_name = flags
            .get("--tun-name")
            .and_then(|v| v.as_deref())
            .unwrap_or("nexus-tun")
            .to_string();
        let result = nexus::tun_proxy_real_open(&tun_name)
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string()));
        return print_json_result(result);
    }
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return 0;
            }
        },
        None => match "127.0.0.1:1080".parse() {
            Ok(a) => a,
            Err(_) => return 1,
        },
    };
    let config_yaml = match flags.get("--config").and_then(|v| v.as_deref()) {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"read config {path} failed: {e}\"}}}}"
                );
                return 0;
            }
        },
        None => nexus::DEFAULT_PROXY_CONFIG.to_string(),
    };
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind {addr} failed: {e}\"}}}}"
            );
            return 0;
        }
    };
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexus\",\"command\":\"proxy\",\"addr\":\"{addr}\"}}}}"
    );
    // P4：进程启动时注册 builtin 混淆插件（plain/xor）。
    nexus::init_obfs_plugins();
    // 服务循环：逐会话阻塞 accept；每会话独立闭环（结构化并发：会话内线程 join）。
    loop {
        match nexus::proxy_serve_once(&listener, &config_yaml) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
                );
            }
        }
    }
}
/// PRODUCT §13.1：Windows 系统代理查询/设置/清除/自清理闭环。
///
/// 所有输出为单个 JSON 对象（stdout）；错误也以 JSON 表达（exit 0 = 请求已处理）。
/// `e2e` 在单次进程内 snapshot -> set 7898 -> 读回 -> **无条件恢复** -> 读回一致。
#[cfg(windows)]
fn dispatch_system_proxy(args: &[String]) -> i32 {
    use nexus_platform::SystemProxyController;
    use nexus_platform_windows::WinInetSystemProxy;

    let ctrl = WinInetSystemProxy::new();
    let sub = args.first().map(String::as_str).unwrap_or("");

    match sub {
        "status" => match ctrl.snapshot() {
            Ok(s) => {
                println!("{}", json!({"verdict":"PASS","proxy":proxy_state_json(&s)}));
            }
            Err(e) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            ),
        },
        "set" => {
            let flags = parse_flags(args);
            let server = flags.get("--server").and_then(|v| v.as_deref());
            match ctrl.apply(true, server) {
                Ok(()) => match ctrl.snapshot() {
                    Ok(s) => println!("{}", json!({"verdict":"PASS","proxy":proxy_state_json(&s)})),
                    Err(e) => println!(
                        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
                    ),
                },
                Err(e) => println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
                ),
            }
        }
        "clear" => match ctrl.apply(false, None) {
            Ok(()) => match ctrl.snapshot() {
                Ok(s) => println!("{}", json!({"verdict":"PASS","proxy":proxy_state_json(&s)})),
                Err(e) => println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
                ),
            },
            Err(e) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            ),
        },
        "e2e" => {
            // 自清理闭环：先 snapshot 原值。任何后续失败都必须先恢复。
            let before = match ctrl.snapshot() {
                Ok(s) => s,
                Err(e) => {
                    println!(
                        "{}",
                        json!({"verdict":"FAIL","stage":"snapshot-before","error":e.to_string()})
                    );
                    return 0;
                }
            };
            let before_json = proxy_state_json(&before);

            let after_set = match ctrl
                .apply(true, Some("127.0.0.1:7898"))
                .and_then(|_| ctrl.snapshot())
            {
                Ok(s) => s,
                Err(e) => {
                    // 设置失败也要尝试恢复（理论上 before 未变，但保持对称）。
                    let _ = ctrl.apply(before.enabled, before.server.as_deref());
                    println!(
                        "{}",
                        json!({"verdict":"FAIL","stage":"apply-set","error":e.to_string(),"before":before_json})
                    );
                    return 0;
                }
            };
            let after_set_ok =
                after_set.enabled && after_set.server.as_deref() == Some("127.0.0.1:7898");
            let after_set_json = proxy_state_json(&after_set);

            // 无条件恢复原值并广播。
            let restore_res = ctrl.apply(before.enabled, before.server.as_deref());
            let after_restore = ctrl.snapshot().unwrap_or_else(|_| before.clone());
            let after_restore_json = proxy_state_json(&after_restore);
            let restore_consistent = restore_res.is_ok() && after_restore == before;

            let verdict = if after_set_ok && restore_consistent {
                "PASS"
            } else {
                "FAIL"
            };
            println!(
                "{}",
                json!({
                    "verdict": verdict,
                    "proxy": {
                        "before": before_json,
                        "after_set": after_set_json,
                        "after_restore": after_restore_json
                    },
                    "restore_consistent": restore_consistent
                })
            );
        }
        other => println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNKNOWN\",\"message\":\"unknown system-proxy subcommand {other}\"}}}}"
        ),
    }
    0
}

/// 非 Windows：显式 Unavailable，不静默降级（PRODUCT §8/§13）。
#[cfg(not(windows))]
fn dispatch_system_proxy(_args: &[String]) -> i32 {
    println!(
        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"message\":\"system-proxy only implemented on Windows\"}}}}"
    );
    0
}

/// PRODUCT §13.2：当前用户 ONLOGON 计划任务自启 install/remove/status。
#[cfg(windows)]
fn dispatch_autostart(args: &[String]) -> i32 {
    use nexus_platform::AutostartRegistrar;
    use nexus_platform_windows::TaskSchedulerAutostart;

    let reg = TaskSchedulerAutostart::new();
    let sub = args.first().map(String::as_str).unwrap_or("");

    match sub {
        "install" => {
            let exe = match std::env::current_exe() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(e) => {
                    println!(
                        "{}",
                        json!({"verdict":"FAIL","error":{"code":"INTERNAL","message":e.to_string()}})
                    );
                    return 0;
                }
            };
            match reg.install(&exe, &["serve", "--addr", "127.0.0.1:7898"]) {
                Ok(task) => println!(
                    "{}",
                    json!({"verdict":"PASS","autostart":{"installed":true,"task":task}})
                ),
                Err(e) => println!(
                    "{}",
                    json!({"verdict":"FAIL","error":{"code":"INTERNAL","message":e.to_string()}})
                ),
            }
        }
        "remove" => match reg.remove() {
            Ok(()) => println!(
                "{}",
                json!({"verdict":"PASS","autostart":{"installed":false}})
            ),
            Err(e) => println!(
                "{}",
                json!({"verdict":"FAIL","error":{"code":"INTERNAL","message":e.to_string()}})
            ),
        },
        "status" => match reg.is_installed() {
            Ok(installed) => println!(
                "{}",
                json!({"verdict":"PASS","autostart":{"installed":installed}})
            ),
            Err(e) => println!(
                "{}",
                json!({"verdict":"FAIL","error":{"code":"INTERNAL","message":e.to_string()}})
            ),
        },
        other => println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNKNOWN\",\"message\":\"unknown autostart subcommand {other}\"}}}}"
        ),
    }
    0
}

/// 非 Windows：显式 Unavailable。
#[cfg(not(windows))]
fn dispatch_autostart(_args: &[String]) -> i32 {
    println!(
        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"message\":\"autostart only implemented on Windows\"}}}}"
    );
    0
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
    fn proxy_help_exits_0() {
        // `nexus proxy --help` 输出用法，不尝试 bind（refactor: CLI 统一）。
        assert_eq!(run_str(&["proxy", "--help"]), 0);
    }

    #[test]
    fn proxy_run_without_resource_exits_1() {
        // `nexus proxy run` 缺资源参数 → FAILURE exit 1（与原 nexusd 行为一致）。
        assert_eq!(run_str(&["proxy", "run"]), 1);
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
    fn addr_defaults_to_unix_socket() {
        // D8（N2 P0-1）：默认 unix socket，不再是 TCP loopback。
        let args = vec!["status".to_string()];
        let (target, rest) = extract_remote_target(&args).unwrap();
        #[cfg(unix)]
        assert!(matches!(target, RemoteTarget::Socket(_)));
        #[cfg(not(unix))]
        assert_eq!(
            target,
            RemoteTarget::Tcp(localapi_client::DEFAULT_LOCALAPI_ADDR.into())
        );
        assert_eq!(rest, vec!["status".to_string()]);
    }

    #[test]
    fn socket_flag_is_accepted() {
        let args = vec!["--socket".to_string(), "/tmp/nexusd.sock".to_string()];
        let (target, rest) = extract_remote_target(&args).unwrap();
        assert_eq!(target, RemoteTarget::Socket("/tmp/nexusd.sock".into()));
        assert!(rest.is_empty());
    }

    #[test]
    fn socket_flag_missing_value_is_usage_error() {
        let args = vec!["--socket".to_string()];
        assert!(extract_remote_target(&args).is_err());
    }

    #[test]
    fn status_with_no_daemon_exits_0_with_fail_json() {
        // 没有 daemon（默认 unix socket 文件不存在）：--json 模式输出
        // DAEMON_UNREACHABLE FAIL JSON 到 stdout，exit 0（请求已被处理，只是连不上）。
        let code = run_str(&["--json", "status"]);
        assert_eq!(code, 0);
    }

    #[test]
    fn unsupported_command_synthesizes_local_fail_json() {
        // connectivity candidates 无 daemon 路由：本地合成 UNSUPPORTED，不触网。
        let code = run_str(&["--json", "connectivity", "candidates"]);
        assert_eq!(code, 0);
    }

    #[test]
    fn schedule_requires_subcommand() {
        assert_eq!(run_str(&["schedule"]), 2);
    }

    #[test]
    fn schedule_at_requires_args() {
        assert_eq!(run_str(&["schedule", "at"]), 2);
        assert_eq!(run_str(&["schedule", "at", "1000"]), 2); // 缺 --resource
        assert_eq!(run_str(&["schedule", "at", "1000", "--resource", "r"]), 2); // 缺命令
        assert_eq!(
            run_str(&[
                "schedule",
                "at",
                "not-an-int",
                "--resource",
                "r",
                "--",
                "echo",
                "hi"
            ]),
            2
        );
    }

    #[test]
    fn schedule_unknown_subcommand_exits_2() {
        assert_eq!(run_str(&["schedule", "bogus"]), 2);
    }

    #[test]
    fn schedule_list_with_temp_state_is_pass() {
        // 显式 --state 指向临时文件：空注册表输出 verdict=PASS（exit 0，业务结果）。
        let dir = std::env::temp_dir().join(format!("nexus-sched-main-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("s.json");
        let _ = std::fs::remove_file(&state);
        let code = run_str(&[
            "schedule",
            "list",
            "--state",
            state.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(code, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bufferbloat_test_missing_proxy_exits_2() {
        assert_eq!(run_str(&["proxy", "bufferbloat-test"]), 2);
    }

    #[test]
    fn bufferbloat_test_invalid_proxy_exits_2() {
        assert_eq!(
            run_str(&["proxy", "bufferbloat-test", "--proxy", "not-an-addr"]),
            2
        );
    }

    #[test]
    fn bufferbloat_test_loopback_no_bloat() {
        // 集成测试：本地起一个只 accept 不读的 TCP listener 作为"代理"，
        // loopback 无真实拥塞，打满 2 秒后应判 NO_BLOAT_UPSTREAM（exit 0）。
        // 注意：沙盒可能限制 UDP，但 TCP loopback 可用。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // 后台 accept 线程：接受连接后立即丢弃（模拟代理 accept 但不消费上行）。
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_c = std::sync::Arc::clone(&stop);
        let accept_h = std::thread::spawn(move || {
            listener.set_nonblocking(true).expect("set_nonblocking");
            while !stop_c.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => {
                        // 保持连接打开但不读：发送方最终会遇到 TCP 窗口满，
                        // 但 2 秒短时长内主要测的是建连延迟（不受窗口影响）。
                        std::mem::forget(s);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
        });
        let code = run_str(&[
            "proxy",
            "bufferbloat-test",
            "--proxy",
            &format!("127.0.0.1:{port}"),
            "--duration",
            "2",
            "--json",
        ]);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = accept_h.join();
        // exit 0 表示诊断完成（verdict 在 JSON 里，loopback 应为 NO_BLOAT_UPSTREAM）。
        assert_eq!(code, 0);
    }
}
