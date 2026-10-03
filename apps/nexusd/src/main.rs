//! nexusd：Nexus Daemon（用户愿景架构）。
//!
//! 用法：
//!   nexusd <config-folder>     -> 启动 daemon，唯一参数为配置文件夹（如 `nexusd /etc/nexus/`）
//!
//! 配置文件夹结构（缺失文件 = 对应子系统不启用）：
//! ```text
//! /etc/nexus/
//! ├── daemon.toml    # daemon 自身：LocalAPI 地址等（可选）
//! ├── network.toml   # N1 mesh（可选）
//! ├── proxy.yaml     # Clash 风格代理（可选）
//! └── dns.toml       # DNS（可选）
//! ```
//!
//! 架构（用户愿景）：
//! - `nexusd <config-folder>` 启动 daemon，盯文件夹，配置热加载。
//! - `nexus ...` 为瘦客户端：改配置（`nexus config set`）、看状态（`nexus status`）。
//! - 配置变更 2 秒内热生效（轮询）；校验失败拒绝应用，不 crash。
//!
//! v9 术语：`nexus` 为正式 CLI；`nexusd` 为 Composition Root / daemon 进程。
//! 本文件只承担 CLI 解析与装配；领域逻辑复用 `nexus` SDK，不复制。
//!
//! 诚实边界：
//! - 本 daemon 负责配置加载/校验/热加载 + LocalAPI。各子系统（mesh/proxy/dns）的
//!   实际长驻运行时装配为后续工作；当前 `status` 如实报告"已配置/未配置"，
//!   不虚构"运行中"。
//! - `serve` 子命令保留作内部 LocalAPI 实现（历史兼容），用户入口为 config-folder。

#![forbid(unsafe_code)]

// T4：tun_enabled 状态供 LocalAPI 查询（no-tun 模式可观测）。
static TUN_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// C1：daemon 的 workspace 子系统（Linux only；LocalAPI 路由与关闭序列共享）。
#[cfg(target_os = "linux")]
static WORKSPACE_MGR: std::sync::OnceLock<
    std::sync::Mutex<Option<nexusd::workspace::WorkspaceManager>>,
> = std::sync::OnceLock::new();

/// D1（N2）：daemon 内**全系统唯一**的 N2 `SessionManager`（N2 P1-1）。
///
/// 此前装配完即被 drop（`let _n2_session_manager = ...`），daemon 从不持有实例，
/// 于是"daemon 内唯一 SessionManager"只是纸面声明；Session 生命周期实际由每个
/// CLI 进程各建一个 manager。现在实例真正被持有：
/// - LocalAPI 的 N2 会话读口（`/localapi/v0/n2/session/list`、`/attach`）从这里读；
/// - [`spawn_n2_session_sweeper`] 的周期性 `sweep_detached` 在这里提交终态。
///
/// `None` = 装配失败（degraded：daemon 照常跑，LocalAPI 返回结构化 FAIL）。
static N2_SESSION_MANAGER: std::sync::OnceLock<
    std::sync::Mutex<Option<nexus_session::SessionManager>>,
> = std::sync::OnceLock::new();

/// N2 会话清扫周期（秒）：断开超 attach window 的会话由 daemon 收敛为
/// `Cancelled(ClientDetached)`（P1-2：`sweep_detached` 生产可达）。
const N2_SESSION_SWEEP_INTERVAL_SECS: u64 = 30;

/// 发布 tun_enabled 状态（daemon 启动时调用一次）。
fn publish_tun_enabled(enabled: bool) {
    let _ = TUN_ENABLED.set(enabled);
}

/// 周期性子线程：提交断开超窗会话的终态（P1-2 / D7：断开≠Failed，窗口外→Cancelled）。
///
/// §13 结构化并发：Owner 是 `N2_SESSION_MANAGER` 里的唯一 SessionManager；
/// 子线程只调用 `sweep_detached`（Owner 状态机写入），`shutdown` 置位后退出。
fn spawn_n2_session_sweeper(shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let flag = shutdown.clone();
    std::thread::Builder::new()
        .name("n2-session-sweeper".to_string())
        .spawn(move || {
            loop {
                for _ in 0..N2_SESSION_SWEEP_INTERVAL_SECS {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let swept = {
                    let Some(cell) = N2_SESSION_MANAGER.get() else {
                        continue;
                    };
                    let Ok(mut guard) = cell.lock() else {
                        eprintln!("[nexusd] WARN: N2 session sweeper: manager lock poisoned");
                        return;
                    };
                    let Some(mgr) = guard.as_mut() else {
                        continue;
                    };
                    mgr.sweep_detached(now_unix())
                };
                for id in swept {
                    eprintln!(
                        "[nexusd] N2 session detached beyond attach window -> Cancelled: {id:?}"
                    );
                }
            }
        })
        .map(|_| ())
        .unwrap_or_else(|e| eprintln!("[nexusd] WARN: N2 session sweeper spawn failed: {e}"));
}

/// 当前 unix 秒（daemon 侧时钟；reconcile/sweep 用）。
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// N2 会话视图 → LocalAPI JSON（daemon 内唯一 SessionManager 的读口）。
fn n2_session_view_json(view: &nexus_session::SessionView) -> Value {
    json!({
        "id": view.id.0,
        "resource": view.resource.0,
        "provider": view.provider.0,
        "phase": format!("{:?}", view.phase),
        "outcome": outcome_label(&view.outcome),
        "cancel_reason": view.cancel_reason.as_ref().map(|r| r.as_str()),
        "reattachable": view.reattachable,
        "plan_id": view.plan_snapshot.as_ref().map(|s| s.plan_id.0.clone()),
    })
}

fn outcome_label(outcome: &nexus_domain::TerminalOutcome) -> &'static str {
    use nexus_domain::TerminalOutcome;
    match outcome {
        TerminalOutcome::Unfinished => "Unfinished",
        TerminalOutcome::Completed => "Completed",
        TerminalOutcome::Cancelled => "Cancelled",
        TerminalOutcome::Failed(_) => "Failed",
    }
}

/// `GET /localapi/v0/n2/session/list` — daemon 内唯一 SessionManager 的会话列表（D1）。
fn n2_session_list() -> Result<Value, (String, String)> {
    let Some(cell) = N2_SESSION_MANAGER.get() else {
        return Err((
            "N2_UNAVAILABLE".to_string(),
            "N2 session manager not assembled".to_string(),
        ));
    };
    let guard = cell.lock().map_err(|_| {
        (
            "N2_UNAVAILABLE".to_string(),
            "N2 session manager lock poisoned".to_string(),
        )
    })?;
    let mgr = guard.as_ref().ok_or_else(|| {
        (
            "N2_UNAVAILABLE".to_string(),
            "N2 session manager assembly degraded".to_string(),
        )
    })?;
    Ok(json!({
        "verdict": "PASS",
        "owner": "daemon",
        "sessions": mgr.list().iter().map(n2_session_view_json).collect::<Vec<_>>(),
    }))
}

/// `GET /localapi/v0/n2/session/attach?session=<id>` — 重附着查询（完成标志 3）。
fn n2_session_attach(id: Option<&str>) -> Result<Value, (String, String)> {
    let Some(cell) = N2_SESSION_MANAGER.get() else {
        return Err((
            "N2_UNAVAILABLE".to_string(),
            "N2 session manager not assembled".to_string(),
        ));
    };
    let guard = cell.lock().map_err(|_| {
        (
            "N2_UNAVAILABLE".to_string(),
            "N2 session manager lock poisoned".to_string(),
        )
    })?;
    let mgr = guard.as_ref().ok_or_else(|| {
        (
            "N2_UNAVAILABLE".to_string(),
            "N2 session manager assembly degraded".to_string(),
        )
    })?;
    let Some(id) = id.filter(|s| !s.is_empty()) else {
        return Err((
            "BAD_REQUEST".to_string(),
            "missing 'session' query parameter".to_string(),
        ));
    };
    match mgr.attach(&nexus_domain::SessionId(id.to_string())) {
        Ok(view) => Ok(
            json!({"verdict": "PASS", "owner": "daemon", "session": n2_session_view_json(&view)}),
        ),
        Err(_) => Ok(json!({
            "verdict": "FAIL",
            "owner": "daemon",
            "error": {"code": "NOT_FOUND", "session": id},
        })),
    }
}

/// 读取 tun_enabled 状态（默认 true，保持向后兼容）。
fn tun_enabled() -> bool {
    *TUN_ENABLED.get().unwrap_or(&true)
}

mod watcher;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::time::Duration;

use serde_json::{Value, json};

use nexusd::assembly;
use nexusd::config::{self, ConfigDir, LoadedConfig};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        // 新入口：nexusd <config-folder>
        Some(path) if !path.starts_with('-') && path != "serve" => {
            if args.len() != 1 {
                eprintln!("usage: nexusd <config-folder>\n  e.g. nexusd /etc/nexus/");
                return ExitCode::from(2);
            }
            run_daemon(path)
        }
        // 内部/历史：nexusd serve（LocalAPI），保留兼容
        Some("serve") => serve_resource(&args[1..]),
        _ => {
            eprintln!(
                "usage: nexusd <config-folder>\n\
                 \n\
                 启动 daemon，唯一参数为配置文件夹：\n\
                 \x20 nexusd /etc/nexus/\n\
                 \n\
                 配置文件夹内（缺失 = 不启用）：\n\
                 \x20 daemon.toml    LocalAPI 地址等（可选）\n\
                 \x20 network.toml   N1 mesh（可选）\n\
                 \x20 proxy.yaml     Clash 风格代理（可选）\n\
                 \x20 dns.toml       DNS（可选）\n\
                 \x20 workspace.toml Workspace FUSE 挂载（可选，C1）\n\
                 \n\
                 瘦客户端：\n\
                 \x20 nexus config get --dir <dir> <file>\n\
                 \x20 nexus config set --dir <dir> <file>  （从 stdin 读，原子写入）\n\
                 \x20 nexus status"
            );
            ExitCode::from(2)
        }
    }
}

/// 数据面线程主循环：创建 TUN → 处理包 → 出错时退出线程（daemon 继续服务 LocalAPI）。
/// 数据面线程主循环：创建 TUN → 处理包 → 出错或收到关闭信号时退出线程。
///
/// R1：`n1_sender` 为 Some 时注入 dataplane（`set_n1_sender`），Mesh 包真发；
/// 为 None 时保持 D2 计数降级。
/// P1-P5：`proxy_yaml` 为 Some 且含可用出站时注入 `ProxyEngine`，Proxy 包真发；
/// 否则 D2 计数降级。
/// R4：每次循环检查 `shutdown` 标志，置位后退出（join 1s 超时由调用方执行）。
fn run_dataplane(
    config: nexusd::dataplane::DataplaneConfig,
    shutdown: Arc<AtomicBool>,
    n1_sender: Option<Arc<dyn nexus_network::n1::bridge::N1Sender>>,
    tun_name: &str,
    tun_mtu: u32,
    proxy_yaml: Option<String>,
) {
    use nexus_projection::TunDevice;
    // D1：创建单个 TUN（Linux）。设备名与 MTU 来自 [tun] 配置（T1）。
    let tun_pattern = format!("{tun_name}%d");
    let tun: Box<dyn nexus_projection::TunDevice> =
        match nexus_projection::tun_rs_device::TunRsDevice::create(&tun_pattern, tun_mtu) {
            Ok(dev) => {
                eprintln!("[nexusd] dataplane: TUN {} created", dev.name());
                Box::new(dev)
            }
            Err(e) => {
                eprintln!(
                    "[nexusd] dataplane: TUN creation failed ({e}); dataplane disabled, LocalAPI still serving"
                );
                return;
            }
        };

    let mut dp = match nexusd::dataplane::Dataplane::new(tun, config) {
        Ok(dp) => dp,
        Err(e) => {
            eprintln!("[nexusd] dataplane: init failed ({e}); dataplane disabled");
            return;
        }
    };

    // B1：发布 stats 句柄供 LocalAPI 读取。
    nexusd::dataplane::publish_stats_handle(dp.stats_handle());

    // R1：注入 N1 发送器（有则真发，无则 D2 计数降级）。
    if let Some(sender) = n1_sender {
        dp.set_n1_sender(sender);
        eprintln!("[nexusd] dataplane: N1 sender wired (n1_bridge_ready=true)");
    }

    // P1-P5：注入 Proxy 转发引擎（有可用出站则真发，无则 D2 计数降级）。
    if let Some(yaml) = proxy_yaml.as_deref() {
        match nexusd::proxy_fwd::ProxyEngine::new(yaml) {
            Some(engine) => {
                dp.set_proxy_engine(engine);
                eprintln!("[nexusd] dataplane: ProxyEngine wired (proxy_engine_ready=true)");
            }
            None => {
                eprintln!(
                    "[nexusd] dataplane: proxy.yaml has no usable outbound; proxy packets counted"
                );
            }
        }
    }

    eprintln!("[nexusd] dataplane: running");
    loop {
        // R4：关闭信号 → 退出循环（TUN 随 Dataplane drop 关闭）。
        if shutdown.load(Ordering::Relaxed) {
            eprintln!("[nexusd] dataplane: shutdown signal, exiting");
            break;
        }
        match dp.process_one() {
            Ok(true) => continue,
            Ok(false) => {
                // 无包：短暂休眠避免忙轮询。
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("[nexusd] dataplane: TUN read error ({e}); exiting dataplane thread");
                break;
            }
        }
    }
}

/// Daemon 主流程：加载配置 → 装配子系统 → 启动线程 → 事件循环 → 优雅关闭。
///
/// 启动顺序（§13.3）：配置加载 → 校验 → TUN（致命）→ Dataplane → N1（可降级）
/// → Proxy（可降级）→ LocalAPI → 主循环。
/// 关闭顺序（§13.4/R4/D7）：SIGTERM/SIGINT → LocalAPI → Workspace unmount → Dataplane（1s 超时）
/// → N1（5s 超时）→ TUN（随线程退出）→ exit 0。
fn run_daemon(config_dir: &str) -> ExitCode {
    let dir = match ConfigDir::new(std::path::Path::new(config_dir)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"CONFIG\",\"message\":\"{e}\"}}}}"
            );
            return ExitCode::from(1);
        }
    };

    // R4：关闭标志；Unix 下 SIGTERM/SIGINT 置位。
    let shutdown = Arc::new(AtomicBool::new(false));
    register_shutdown_flag(&shutdown);

    // 1. 启动时加载全部配置（校验失败则拒绝启动）。
    let loaded = match config::load(&dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"CONFIG\",\"message\":\"{e}\"}}}}"
            );
            return ExitCode::from(1);
        }
    };
    log_enabled_subsystems(&loaded);

    // F1：orphan FUSE 挂载收敛进 boot_reconcile 统一报告。挂载点在 reconcile
    // 之前解析，与 WorkspaceManager::start 共用 resolve_mountpoints，保证一致。
    // 解析失败 → warn + 空集合（WorkspaceManager::start 稍后会以相同的
    // fail-fast 语义退出，保持现有行为不变）。
    #[cfg(target_os = "linux")]
    let orphan_mountpoints: Vec<std::path::PathBuf> = match loaded.workspace_toml.as_deref() {
        Some(text) => {
            match nexusd::workspace::WorkspaceManager::resolve_mountpoints(
                std::path::Path::new(config_dir),
                text,
            ) {
                Ok(mps) => mps,
                Err(e) => {
                    eprintln!(
                        "[nexusd] WARN: workspace config parse failed before reconcile ({e}); orphan mount cleanup skipped"
                    );
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    };
    #[cfg(not(target_os = "linux"))]
    let orphan_mountpoints: Vec<std::path::PathBuf> = Vec::new();

    // 0. 开机 reconcile（v9 §15.3）：先恢复 durable state，再接受新工作。
    //    位置在 T3 校验之前——reconcile 不依赖子系统配置，只依赖 config dir。
    let state_dir = nexusd::recovery::state_dir(&dir.root);
    let boot_report = nexusd::recovery::boot_reconcile(&state_dir, &orphan_mountpoints);
    println!("{}", boot_report.to_json());
    // stdout 管道下是块缓冲：启动期的机器可读行必须立即 flush，
    // 否则编排器（如 E4）在进程退出前永远看不到（2026-10-02 真机踩坑）。
    {
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
    }
    for e in &boot_report.errors {
        eprintln!("[nexusd] boot-reconcile error: {e}");
    }

    // N2 P0-4（D1）：装配 daemon 内唯一的 SessionManager。
    //
    // §15 顺序：N2 会话存储（`<config-dir>/n2/`）加载 → journal 重放 →
    // `reconcile_session_records_at`（幂等；用真实 attach window 分类，P1-1：
    // 不再一律判 Failed）→ 接受新工作。SessionManager 是 Session 生命周期的
    // 唯一 Owner（§13 结构化并发）；提供方侧只做 admission＋租约，不做第二个
    // 领域 Session。
    match assembly::assemble_n2_session_manager(&dir.root) {
        Ok(mgr) => {
            eprintln!(
                "[nexusd] N2 SessionManager assembled ({} sessions loaded)",
                mgr.len()
            );
            // 真正持有实例（D1 落地）＋周期性 sweep_detached（P1-2）。
            let _ = N2_SESSION_MANAGER.set(std::sync::Mutex::new(Some(mgr)));
            spawn_n2_session_sweeper(&shutdown);
        }
        Err(e) => {
            eprintln!("[nexusd] WARN: N2 SessionManager assembly failed: {e} (degraded)");
            let _ = N2_SESSION_MANAGER.set(std::sync::Mutex::new(None));
        }
    }

    // T3：缺 proxy.yaml 且缺 network.toml 且缺 workspace.toml → 拒绝启动（无意义）。
    if loaded.proxy_yaml.is_none()
        && loaded.network_toml.is_none()
        && loaded.workspace_toml.is_none()
    {
        eprintln!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"CONFIG\",\"message\":\"no subsystem configured: need proxy.yaml and/or network.toml and/or workspace.toml\"}}}}"
        );
        return ExitCode::from(1);
    }

    // T4：发布 tun_enabled 状态供 LocalAPI 查询。
    publish_tun_enabled(loaded.daemon.tun.enabled);

    // 2. 组装 DataplaneConfig（R2/R3；dns.toml 解析失败 → exit 1）。
    let dataplane_config = match assembly::build_dataplane_config(&loaded) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"CONFIG\",\"message\":\"{e}\"}}}}"
            );
            return ExitCode::from(1);
        }
    };

    // 3. R1：装配 N1 网桥（失败 → 降级，dataplane 照常跑）。
    let n1_bridge: Option<Arc<nexus_network::n1::bridge::N1MeshBridge>> = match loaded
        .network_toml
        .as_deref()
    {
        Some(text) => match assembly::assemble_n1(text) {
            Ok(bridge) => Some(bridge),
            Err(e) => {
                eprintln!(
                    "[nexusd] ERROR: N1 assembly failed ({e}); degraded (mesh packets counted, not sent)"
                );
                None
            }
        },
        None => None,
    };
    let n1_sender: Option<Arc<dyn nexus_network::n1::bridge::N1Sender>> = n1_bridge
        .clone()
        .map(|b| b as Arc<dyn nexus_network::n1::bridge::N1Sender>);

    // 4. 统一数据面线程（D1：单个 TUN 由 nexusd 持有；TUN 创建失败则线程内降级）。
    //    T2：[tun].enabled=false 时跳过 TUN/数据面（no-tun 模式）。
    let tun_name = loaded.daemon.tun.name.clone();
    let tun_mtu = loaded.daemon.tun.mtu;
    let proxy_yaml = loaded.proxy_yaml.clone();
    let dataplane_handle = if tun_enabled() {
        let dp_shutdown = Arc::clone(&shutdown);
        Some(
            std::thread::Builder::new()
                .name("nexusd-dataplane".to_string())
                .spawn(move || {
                    run_dataplane(
                        dataplane_config,
                        dp_shutdown,
                        n1_sender,
                        &tun_name,
                        tun_mtu,
                        proxy_yaml,
                    );
                })
                .expect("spawn dataplane thread"),
        )
    } else {
        eprintln!("[nexusd] tun disabled; dataplane not started (no-tun mode)");
        None
    };

    // 5. LocalAPI 线程（R4：可经 shutdown 标志停止）。
    let localapi_addr = loaded.daemon.localapi_addr.clone();
    let (ready_tx, ready_rx) = channel();
    let api_shutdown = Arc::clone(&shutdown);
    let localapi_handle = std::thread::Builder::new()
        .name("nexusd-localapi".to_string())
        .spawn(move || {
            serve_localapi(&localapi_addr, ready_tx, api_shutdown);
        })
        .expect("spawn localapi thread");
    // 等 LocalAPI 就绪（最多 5 秒）。
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(addr) => {
            println!(
                "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"config_dir\":\"{config_dir}\",\"localapi\":\"{addr}\"}}}}"
            );
            // 同上：READY 行必须立即 flush（块缓冲坑）。
            {
                use std::io::Write as _;
                let _ = std::io::stdout().flush();
            }
        }
        Err(_) => {
            eprintln!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"localapi did not start\"}}}}"
            );
            return ExitCode::from(1);
        }
    }

    // 5.5. C1：Workspace 生产接线（Linux only）。放在 LocalAPI 就绪之后：
    // F7：同配置双启动时，第二个 daemon 在 LocalAPI 端口冲突处先失败退出，
    // 不会走到这里 unmount 第一个 daemon 的活挂载。workspace.toml 缺失 → 跳过（D1）；
    // 挂载失败 → 拒绝启动（fail-fast，诚实）。
    #[cfg(target_os = "linux")]
    if let Some(text) = loaded.workspace_toml.as_deref() {
        match nexusd::workspace::WorkspaceManager::start(std::path::Path::new(config_dir), text) {
            Ok(mgr) => {
                if !mgr.fuse_available {
                    eprintln!("[nexusd] workspace subsystem disabled (no /dev/fuse)");
                }
                let _ = WORKSPACE_MGR.set(std::sync::Mutex::new(Some(mgr)));
            }
            Err(e) => {
                eprintln!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"WORKSPACE\",\"message\":\"workspace mount failed: {e}\"}}}}"
                );
                return ExitCode::from(1);
            }
        }
    }

    // 6. 配置 watcher（后台线程；主线程拥有 JoinHandle，不直接改共享状态）。
    let (ev_tx, ev_rx) = channel();
    let _watcher = watcher::spawn(dir.clone(), loaded, ev_tx);

    // 7. 主事件循环：处理重载事件 + 检查关闭信号（single writer 原则）。
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match ev_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(watcher::ReloadEvent::Applied { files }) => {
                eprintln!("[nexusd] config hot-reloaded: {files:?}");
            }
            Ok(watcher::ReloadEvent::NeedsRestart { reason }) => {
                eprintln!("[nexusd] WARN: {reason}");
            }
            Ok(watcher::ReloadEvent::Rejected { error }) => {
                eprintln!("[nexusd] ERROR: config reload rejected: {error} (keeping old config)");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("[nexusd] WARN: config watcher channel closed");
            }
        }
    }

    // 8. R4：优雅关闭（§13.4 反向顺序，超时强制继续）。
    shutdown_sequence(localapi_handle, dataplane_handle, n1_bridge, &state_dir);
    ExitCode::from(0)
}

/// R4：优雅关闭序列（§13.4）。
///
/// 顺序：LocalAPI → Workspace unmount（D7）→ Dataplane（1s）→ N1（5s）→ TUN（随 dataplane 线程退出）。
/// 任一步超时 → warn 日志后强制继续，不无限等。
fn shutdown_sequence(
    localapi_handle: std::thread::JoinHandle<()>,
    dataplane_handle: Option<std::thread::JoinHandle<()>>,
    n1_bridge: Option<Arc<nexus_network::n1::bridge::N1MeshBridge>>,
    state_dir: &std::path::Path,
) {
    eprintln!("[nexusd] shutdown: stopping LocalAPI");
    // LocalAPI 线程已通过 shutdown 标志退出 accept 循环；join 确认。
    assembly::join_with_timeout(localapi_handle, Duration::from_secs(2), "localapi");

    // D7（C1）：Workspace unmount 在 LocalAPI 之后、Dataplane 之前。
    #[cfg(target_os = "linux")]
    {
        let mgr = WORKSPACE_MGR
            .get()
            .and_then(|m| m.lock().ok().and_then(|mut g| g.take()));
        if let Some(mgr) = mgr {
            eprintln!("[nexusd] shutdown: unmounting workspaces");
            mgr.shutdown();
        }
    }

    eprintln!("[nexusd] shutdown: stopping dataplane");
    if let Some(handle) = dataplane_handle {
        assembly::join_with_timeout(handle, Duration::from_secs(1), "dataplane");
    } else {
        eprintln!("[nexusd] shutdown: dataplane not running (no-tun mode)");
    }

    if let Some(bridge) = n1_bridge {
        eprintln!("[nexusd] shutdown: stopping N1");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            bridge.shutdown();
            let _ = tx.send(());
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(_) => eprintln!("[nexusd] shutdown: N1 stopped"),
            Err(_) => {
                eprintln!("[nexusd] WARN: shutdown: N1 did not stop in 5s, continuing")
            }
        }
    } else {
        eprintln!("[nexusd] shutdown: N1 not assembled, skipping");
    }

    // ProxyEngine 尚无独立运行时（R4 no-op）。
    eprintln!("[nexusd] shutdown: proxy engine not yet a separate runtime, skipping");
    // TUN 随 dataplane 线程退出而关闭（Dataplane drop）。
    eprintln!("[nexusd] shutdown: complete");
    // 干净关闭：清除 run marker，下次启动 crashed_before=false（v9 §15.2）。
    if let Err(e) = nexusd::recovery::clear_run_marker(state_dir) {
        eprintln!("[nexusd] WARN: shutdown: clear run marker failed: {e}");
    }
}

/// R4：注册 Unix 信号处理（SIGTERM/SIGINT → 置位关闭标志）。
/// 非 Unix 平台为 no-op（诚实：优雅关闭仅 Unix）。
#[cfg(unix)]
fn register_shutdown_flag(flag: &Arc<AtomicBool>) {
    use signal_hook::consts::{SIGINT, SIGTERM};
    for sig in [SIGTERM, SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(flag)) {
            eprintln!("[nexusd] WARN: failed to register signal handler for {sig}: {e}");
        }
    }
}

#[cfg(not(unix))]
fn register_shutdown_flag(_flag: &Arc<AtomicBool>) {
    eprintln!("[nexusd] WARN: graceful shutdown on signal not supported on this platform");
}

/// 启动时日志：哪些子系统被配置启用。
fn log_enabled_subsystems(cfg: &LoadedConfig) {
    let mut enabled: Vec<&str> = Vec::new();
    if cfg.network_toml.is_some() {
        enabled.push("network (N1 mesh)");
    }
    if cfg.proxy_yaml.is_some() {
        enabled.push("proxy");
    }
    if cfg.dns_toml.is_some() {
        enabled.push("dns");
    }
    if enabled.is_empty() {
        eprintln!("[nexusd] no subsystem configured (empty config dir); LocalAPI only");
    } else {
        eprintln!("[nexusd] subsystems configured: {}", enabled.join(", "));
    }
    eprintln!("[nexusd] localapi_addr={}", cfg.daemon.localapi_addr);
}

/// LocalAPI 服务（后台线程版；复用既有 serve 逻辑，READY 经 channel 上报）。
/// LocalAPI 服务（后台线程版；R4：经 shutdown 标志可停止）。
///
/// 非阻塞 accept + 100ms 轮询，关闭信号置位后退出循环。
fn serve_localapi(
    addr_raw: &str,
    ready_tx: std::sync::mpsc::Sender<String>,
    shutdown: Arc<AtomicBool>,
) {
    let addr: std::net::SocketAddr = match addr_raw.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[nexusd] invalid localapi addr {addr_raw}: {e}");
            return;
        }
    };
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[nexusd] bind localapi {addr}: {e}");
            return;
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("[nexusd] localapi set_nonblocking failed: {e}");
        return;
    }
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let _ = ready_tx.send(actual);
    let token = match nexus::localapi_client::load_or_create_bearer_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[nexusd] localapi bearer token unavailable: {e}");
            return;
        }
    };
    loop {
        if shutdown.load(Ordering::Relaxed) {
            eprintln!("[nexusd] localapi: shutdown signal, exiting");
            break;
        }
        match listener.accept() {
            Ok((mut s, _)) => {
                if let Err(e) = handle_localapi_request(&mut s, &token) {
                    eprintln!("[nexusd] localapi error: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[nexusd] localapi accept error: {e}");
                break;
            }
        }
    }
}

// ===== 以下为既有 serve 逻辑（内部实现，保留） =====

/// 解析 `--flag <value>` / `--flag=value` / `--flag`（布尔）形式；非 flag token 忽略。
fn parse_flags(args: &[String]) -> std::collections::HashMap<String, Option<String>> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            // `--key=value` 形式：直接拆分（serve_localapi_e2e 用此形式传 --addr）。
            if let Some((key, value)) = arg.split_once('=') {
                map.insert(key.to_string(), Some(value.to_string()));
                i += 1;
                continue;
            }
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

/// serve 子命令（内部/历史兼容）：常驻 LocalAPI。
fn serve_resource(args: &[String]) -> ExitCode {
    let flags = parse_flags(args);
    match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => serve_over_tcp(raw),
        None => match flags.get("--socket").and_then(|v| v.as_deref()) {
            Some(path) => serve_over_socket(path),
            // D8（N2 P0-1）：默认 unix socket（与 CLI `default_socket_path` 一致）。
            // P1-15：socket 路径必须来自 `$XDG_RUNTIME_DIR`（0700、per-user、
            // 不可预测）；未设置时**不**回落到可预测的 `/tmp` 路径，改用 TCP
            // loopback 并告警（bearer token 仍是唯一屏障）。
            #[cfg(unix)]
            None => match nexus::localapi_client::runtime_socket_path() {
                Some(sock) => serve_over_socket(&sock.display().to_string()),
                None => {
                    eprintln!(
                        "[nexusd] WARN: XDG_RUNTIME_DIR unset; refusing predictable /tmp socket path — falling back to TCP loopback"
                    );
                    serve_over_tcp(nexus::localapi_client::DEFAULT_LOCALAPI_ADDR)
                }
            },
            #[cfg(not(unix))]
            None => serve_over_tcp("127.0.0.1:0"),
        },
    }
}

/// 加载 LocalAPI bearer token；失败则打印结构化 FAIL 并返回 Err(ExitCode)。
fn localapi_bearer_token() -> Result<String, ExitCode> {
    nexus::localapi_client::load_or_create_bearer_token().map_err(|e| {
        println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"TOKEN_SETUP\",\"message\":\"bearer token: {e}\"}}}}"
        );
        ExitCode::SUCCESS
    })
}

/// LocalAPI 每连接读写超时（P1-15）。
///
/// 控制面是单线程顺序服务：一个"连上不发换行"的客户端会永久占住它，
/// 连带阻塞所有有副作用的路由（如 `workspace commit`）。
const LOCALAPI_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TCP loopback 监听 + 服务循环（既有行为）。
fn serve_over_tcp(addr_raw: &str) -> ExitCode {
    let token = match localapi_bearer_token() {
        Ok(t) => t,
        Err(code) => return code,
    };
    let addr: std::net::SocketAddr = match addr_raw.parse() {
        Ok(a) => a,
        Err(_) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {addr_raw}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind {addr} failed: {e}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    let actual_addr = listener.local_addr().expect("local_addr");
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"addr\":\"{actual_addr}\"}}}}"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // P1-15：每连接读写超时（与 unix socket 传输同）。
                let _ = stream.set_read_timeout(Some(LOCALAPI_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(LOCALAPI_IO_TIMEOUT));
                if let Err(e) = handle_localapi_request(&mut stream, &token) {
                    eprintln!("serve connection error: {e}");
                }
            }
            Err(e) => {
                eprintln!("serve accept error: {e}");
                break;
            }
        }
    }
    ExitCode::SUCCESS
}

/// LocalAPI unix socket 的权限收紧（P1-15）：bind 后立即 `chmod 0600`。
///
/// bind 之前 socket 文件的权限受 umask 影响，可能是 0755/0777——同机其他用户
/// 可连上控制面。0600 与 bearer token 双保险。返回是否收紧成功。
///
/// 独立函数便于单测（`serve_over_socket` 内联无法单测）。
#[cfg(unix)]
fn harden_localapi_socket(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "[nexusd] ERROR: chmod 0600 {path} failed: {e}; continuing (bearer token still required)"
            );
            false
        }
    }
}

#[cfg(unix)]
fn serve_over_socket(path: &str) -> ExitCode {
    use std::os::unix::net::UnixListener;
    let token = match localapi_bearer_token() {
        Ok(t) => t,
        Err(code) => return code,
    };
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind socket {path} failed: {e}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    harden_localapi_socket(path);
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"socket\":\"{path}\"}}}}"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // P1-15：每连接读写超时——连上不发换行的客户端不得永久占住
                // 控制面（`/workspace/commit/<id>` 等有副作用的路由在其后）。
                let _ = stream.set_read_timeout(Some(LOCALAPI_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(LOCALAPI_IO_TIMEOUT));
                if let Err(e) = handle_localapi_request(&mut stream, &token) {
                    eprintln!("serve connection error: {e}");
                }
            }
            Err(e) => {
                eprintln!("serve accept error: {e}");
                break;
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(windows)]
fn serve_over_socket(path: &str) -> ExitCode {
    println!(
        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"message\":\"named-pipe not implemented; use --addr\"}}}}"
    );
    let _ = path;
    ExitCode::SUCCESS
}

trait LocalIo: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> LocalIo for T {}

/// C1：`GET /localapi/v0/workspace/mounts` — 已挂载 workspace 状态快照。
#[cfg(target_os = "linux")]
fn workspace_mounts_status() -> Value {
    let guard = WORKSPACE_MGR.get().and_then(|m| m.lock().ok());
    let (fuse_available, mounts) = match guard.as_deref() {
        Some(Some(mgr)) => (mgr.fuse_available, mgr.mounts_status()),
        _ => (false, Vec::new()),
    };
    json!({
        "verdict": "PASS",
        "fuse_available": fuse_available,
        "mounts": mounts.iter().map(|s| json!({
            "id": s.id,
            "mountpoint": s.mountpoint,
            "head": s.head,
            "has_uncommitted_changes": s.has_uncommitted_changes,
        })).collect::<Vec<_>>(),
    })
}

/// C1：`GET /localapi/v0/workspace/commit/<id>` — 显式提交（D5）。
#[cfg(target_os = "linux")]
fn workspace_commit(id: &str) -> Result<Value, (String, String)> {
    let mgr_guard = WORKSPACE_MGR
        .get()
        .and_then(|m| m.lock().ok())
        .ok_or_else(|| {
            (
                "WORKSPACE_DISABLED".to_string(),
                "workspace subsystem not enabled".to_string(),
            )
        })?;
    let mgr = mgr_guard.as_ref().ok_or_else(|| {
        (
            "WORKSPACE_DISABLED".to_string(),
            "workspace subsystem not enabled".to_string(),
        )
    })?;
    match mgr.commit(id) {
        Ok(head) => Ok(json!({"verdict": "PASS", "id": id, "head": head})),
        Err(e) => Err(("WORKSPACE_COMMIT".to_string(), e)),
    }
}

fn handle_localapi_request(stream: &mut dyn LocalIo, expected_token: &str) -> Result<(), String> {
    use std::io::BufRead;
    let (request_line, headers): (String, Vec<String>) = {
        let mut reader = std::io::BufReader::new(&mut *stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read request line: {e}"))?;
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            reader
                .read_line(&mut h)
                .map_err(|e| format!("read header: {e}"))?;
            let h = h.trim_end_matches(['\r', '\n']);
            if h.is_empty() {
                break;
            }
            headers.push(h.to_string());
        }
        (line, headers)
    };
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        write_http_json(
            &mut *stream,
            405,
            &json!({"verdict":"FAIL","error":{"code":"METHOD_NOT_ALLOWED"}}),
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    // D8（N2 P0-1）：bearer token 鉴权（两种传输无条件执行）。
    if !bearer_authorized(&headers, expected_token) {
        write_http_json(
            &mut *stream,
            401,
            &json!({"verdict":"FAIL","error":{"code":"UNAUTHORIZED","message":"missing or invalid bearer token"}}),
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    // N2 P0-1 bugfix：解析 query string（此前精确路径匹配，`?k=v` 直接 404）。
    let target = parts[1];
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let params = parse_query(query);
    let qp = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    // C1：workspace commit 走 GET（本 LocalAPI 为最小 GET-only 控制面；变更语义由路径表达）。
    // id 字符集已在 workspace.toml 解析时校验（字母数字/-/_），无注入风险。
    #[cfg(target_os = "linux")]
    if let Some(id) = path.strip_prefix("/localapi/v0/workspace/commit/") {
        let result = workspace_commit(id);
        let body = match result {
            Ok(v) => v,
            Err((code, msg)) => json!({"verdict":"FAIL","error":{"code":code,"message":msg}}),
        };
        write_http_json(stream, 200, &body).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let result: Result<Value, (String, String)> = match path {
        "/localapi/v0/status" => nexus::observability::status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/dataplane/stats" => {
            // B1：统一数据面统计（D6 可观测）。
            // T4：包含 tun_enabled 状态（no-tun 模式可观测）。
            let s = nexusd::dataplane::dataplane_stats_snapshot();
            Ok(json!({
                "verdict": "PASS",
                "tun_enabled": tun_enabled(),
                "dataplane": {
                    "mesh_forwarded": s.mesh_forwarded,
                    "proxy_forwarded": s.proxy_forwarded,
                    "direct_forwarded": s.direct_forwarded,
                    "dropped": s.dropped,
                    "dns_answered": s.dns_answered,
                    "qos_dropped": s.qos_dropped,
                    "mesh_dropped_no_n1": s.mesh_dropped_no_n1,
                    "proxy_dropped_no_proxy": s.proxy_dropped_no_proxy,
                }
            }))
        }
        "/localapi/v0/dns/status" => nexus::observability::dns_status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/dns/cache" => nexus::observability::dns_cache()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/session/watch" => nexus::observability::session_watch(qp("session"))
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        // D1（P1-1）：daemon 内唯一 SessionManager 的会话读口。
        "/localapi/v0/n2/session/list" => n2_session_list(),
        "/localapi/v0/n2/session/attach" => n2_session_attach(qp("session")),
        "/localapi/v0/plan/explain" => nexus::observability::plan_explain(qp("resource"))
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/connectivity/status" => nexus::observability::connectivity_status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/platform/capabilities" => nexus::observability::platform_capabilities()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        #[cfg(target_os = "linux")]
        "/localapi/v0/workspace/mounts" => Ok(workspace_mounts_status()),
        _ => {
            write_http_json(
                stream,
                404,
                &json!({"verdict":"FAIL","error":{"code":"NOT_FOUND","path":path}}),
            )
            .map_err(|e| e.to_string())?;
            return Ok(());
        }
    };
    let body = match result {
        Ok(v) => v,
        Err((code, msg)) => json!({"verdict":"FAIL","error":{"code":code,"message":msg}}),
    };
    write_http_json(stream, 200, &body).map_err(|e| e.to_string())?;
    Ok(())
}

/// bearer 鉴权（D8）：`Authorization: Bearer <token>` 常量时间比较。
///
/// token 缺失 / 格式错误 / 不匹配一律拒绝（fail-closed）。
fn bearer_authorized(headers: &[String], expected_token: &str) -> bool {
    let presented = headers.iter().find_map(|h| {
        let (name, value) = h.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("authorization") {
            value.trim().strip_prefix("Bearer ").map(str::trim)
        } else {
            None
        }
    });
    match presented {
        Some(token) => constant_time_eq(token.as_bytes(), expected_token.as_bytes()),
        None => false,
    }
}

/// 常量时间字节比较（防时序侧信道；与 `nexus-auth::verify_token` 同构）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// 解析 query string 为 `(key, pct-decoded value)` 列表（N2 P0-1 bugfix：
/// daemon 此前完全不解析 query string）。
fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Some((pct_decode(k)?, pct_decode(v)?))
        })
        .collect()
}

/// `%XX` 解码；非法序列 → `None`（该 pair 被丢弃）。
fn pct_decode(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len());
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                if i + 2 >= raw.len() {
                    return None;
                }
                let hi = char::from(raw[i + 1]).to_digit(16)?;
                let lo = char::from(raw[i + 2]).to_digit(16)?;
                bytes.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'+' => {
                bytes.push(b' ');
                i += 1;
            }
            b => {
                bytes.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(bytes).ok()
}

fn write_http_json(
    stream: &mut dyn std::io::Write,
    status: u16,
    body: &Value,
) -> Result<(), std::io::Error> {
    let body_str = serde_json::to_string(body)?;
    let status_text = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod parse_flags_tests {
    use super::{
        LOCALAPI_IO_TIMEOUT, N2_SESSION_SWEEP_INTERVAL_SECS, harden_localapi_socket, parse_flags,
    };

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_equals_form() {
        // 回归：serve_localapi_e2e 用 `--addr=127.0.0.1:0` 形式；
        // 旧实现把整个 `--addr=...` 当 key，导致 --addr 查不到而回落到 unix socket。
        let m = parse_flags(&args(&["--addr=127.0.0.1:0"]));
        assert_eq!(
            m.get("--addr").and_then(|v| v.as_deref()),
            Some("127.0.0.1:0")
        );
    }

    #[test]
    fn parses_space_separated_form() {
        let m = parse_flags(&args(&["--addr", "127.0.0.1:8080"]));
        assert_eq!(
            m.get("--addr").and_then(|v| v.as_deref()),
            Some("127.0.0.1:8080")
        );
    }

    #[test]
    fn parses_boolean_flag() {
        let m = parse_flags(&args(&["--verbose"]));
        assert_eq!(m.get("--verbose"), Some(&None));
    }

    #[test]
    fn equals_form_with_empty_value() {
        let m = parse_flags(&args(&["--addr="]));
        assert_eq!(m.get("--addr").and_then(|v| v.as_deref()), Some(""));
    }

    #[cfg(unix)]
    #[test]
    fn localapi_socket_is_hardened_to_0600_after_bind() {
        // P1-15 回归：bind 后未 chmod 时 socket 权限受 umask 影响，可能世界可写。
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("nexusd-sock-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("localapi.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // 人为放宽权限模拟"umask 宽松"的危险起点。
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(harden_localapi_socket(&path.to_string_lossy()));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be owner-only after bind");
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn localapi_io_timeout_is_bounded() {
        // P1-15：读请求行/头必须有超时，否则一个不发换行的客户端永久占住控制面。
        assert!(LOCALAPI_IO_TIMEOUT.as_secs() > 0);
        assert!(LOCALAPI_IO_TIMEOUT <= std::time::Duration::from_secs(30));
    }

    #[test]
    fn n2_session_sweep_interval_is_bounded() {
        const { assert!(N2_SESSION_SWEEP_INTERVAL_SECS > 0) };
    }
}
