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

// D1 硬约束 3：ProxyEngine 在主线程构造、移入 dataplane 线程 → 必须 Send。
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<nexusd::proxy_fwd::ProxyEngine>();
};

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
static N2_SESSION_MANAGER: std::sync::OnceLock<(
    std::path::PathBuf,
    nexusd::task_service::SharedSessionManager,
)> = std::sync::OnceLock::new();

/// N2 会话清扫周期（秒）：断开超 attach window 的会话由 daemon 收敛为
/// `Cancelled(ClientDetached)`（P1-2：`sweep_detached` 生产可达）。
const N2_SESSION_SWEEP_INTERVAL_SECS: u64 = 30;

/// 发布 tun_enabled 状态（daemon 启动时调用一次）。
fn publish_tun_enabled(enabled: bool) {
    let _ = TUN_ENABLED.set(enabled);
}

/// 周期性子线程：提交断开超窗会话的终态（P1-2 / D7：断开≠Failed，窗口外→Cancelled）。
/// §13 结构化并发：Owner 是 `N2_SESSION_MANAGER` 里的唯一 SessionManager；
/// 子线程只调用 `sweep_detached`（Owner 状态机写入），`shutdown` 置位后退出。
fn spawn_n2_session_sweeper(
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
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
                    let Some((_, cell)) = N2_SESSION_MANAGER.get() else {
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
        .map_err(|e| {
            eprintln!("[nexusd] WARN: N2 session sweeper spawn failed: {e}");
            e
        })
        .ok()
}

/// Assemble once inside the initializer, binding ownership to this entry's root.
fn ensure_n2_session_manager(
    config_root: &std::path::Path,
) -> nexusd::task_service::SharedSessionManager {
    let root = config_root
        .canonicalize()
        .unwrap_or_else(|_| config_root.to_owned());
    let (owned_root, sessions) = N2_SESSION_MANAGER.get_or_init(|| {
        let manager = match assembly::assemble_n2_session_manager(&root) {
            Ok(manager) => {
                eprintln!(
                    "[nexusd] N2 SessionManager assembled ({} sessions loaded)",
                    manager.len()
                );
                Some(manager)
            }
            Err(error) => {
                eprintln!("[nexusd] WARN: N2 SessionManager assembly failed: {error} (degraded)");
                None
            }
        };
        (root.clone(), Arc::new(std::sync::Mutex::new(manager)))
    });
    if owned_root != &root {
        eprintln!(
            "[nexusd] WARN: N2 SessionManager already owns a different config root; refusing Task integration"
        );
        return Arc::new(std::sync::Mutex::new(None));
    }
    Arc::clone(sessions)
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
    let Some((_, cell)) = N2_SESSION_MANAGER.get() else {
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
    let Some((_, cell)) = N2_SESSION_MANAGER.get() else {
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

mod nat_gather;
mod nat_stun;
mod nat_turn;
mod task_provider_command;
mod watcher;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};

use nexus_fabric::{Driver, FabricIdentity, PeerId as FabricPeerId};
use nexus_nat_traversal::{LocalCandidates, PortSample};
// C1：权威 fabric 身份来自 daemon 自己的 `network.toml`（`peer_id` = 64-hex
// ed25519 公钥）；解析发生在组合根，不在 NAT 运行时内部。
use nexus_network::n1::N1PeerId;

use nexusd::assembly;
use nexusd::config::{self, ConfigDir, DiscoverySection, LoadedConfig, TurnSection};
use nexusd::discovery_runtime;
use nexusd::peer_source;

/// Verify managed bindings before any startup operation can create durable state.
fn validate_task_provider_startup(config_root: &std::path::Path) -> Result<bool, ExitCode> {
    #[cfg(target_os = "linux")]
    {
        nexusd::task_provider_init::validate_managed_root(config_root).map_err(|error| {
            eprintln!(
                "{}",
                json!({"schema_version":1, "verdict":"FAIL", "error":{
                    "code":error.code.as_str(), "reason":error.reason, "retryable":error.retryable
                }, "phase":"managed-provider-preflight", "mutation_may_have_applied":false})
            );
            ExitCode::from(1)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config_root;
        Ok(false)
    }
}

/// Recovery must finish before identity, Task recovery, token or socket writes.
fn open_snapshot_service(
    config_root: &std::path::Path,
) -> Result<nexusd::snapshot_service::LocalSnapshotService, ExitCode> {
    nexusd::snapshot_service::LocalSnapshotService::open(config_root).map_err(|error| {
        eprintln!(
            "{}",
            json!({"schema_version":1, "verdict":"FAIL", "error":{
                "code":error.code.as_str(), "reason":error.reason, "retryable":error.retryable
            }, "phase":"snapshot-staging-recovery"})
        );
        ExitCode::from(1)
    })
}

fn validate_token_authority(authority: &nexusd::task_http::TokenAuthority) -> Result<(), ExitCode> {
    if authority.valid() {
        return Ok(());
    }
    eprintln!(
        "{}",
        json!({"schema_version":1, "verdict":"FAIL", "error":{
            "code":"AUTH_DENIED", "reason":"LocalAPI token authority is invalid", "retryable":false
        }, "phase":"localapi-token-authority"})
    );
    Err(ExitCode::from(1))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("task-provider") => task_provider_command::run(&args[1..]),
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

/// 跨线程规则引擎句柄（组合根构建，数据面线程注入）。
type ErasedRuleEngine = Box<dyn nexus_domain::RuleEngine>;

/// 由已解析的 `proxy.yaml` 构建数据面规则引擎（组合根唯一构建点）。
///
/// - `Some(config)` → `DomainRuleEngine`，失败返回 `Err`（调用方 fail-fast，
///   不得回落到 `default_simple_engine`）；
/// - `None` → `Ok(None)`，由装配层显式选择无配置默认引擎并留痕。
fn build_dataplane_rule_engine(
    proxy_config: Option<&nexus_proxy_config::ProxyConfig>,
) -> Result<Option<ErasedRuleEngine>, String> {
    match proxy_config {
        Some(config) => nexus_proxy::domain_engine::DomainRuleEngine::from_config(config)
            .map(|engine| Some(Box::new(engine) as ErasedRuleEngine))
            .map_err(|e| format!("rule engine from proxy.yaml: {e}")),
        None => Ok(None),
    }
}

/// 构造数据面并注入规则引擎（生产唯一装配点）。
///
/// 有配置 → 注入 `DomainRuleEngine`；无配置 → 显式启用并记录默认引擎。
/// 有配置但引擎缺失/注入失败不在本函数内静默兜底（`None` 仅来自无配置路径）。
fn assemble_dataplane(
    tun: Box<dyn nexus_projection::TunDevice>,
    config: nexusd::dataplane::DataplaneConfig,
    rule_engine: Option<ErasedRuleEngine>,
    dns: Option<nexusd::dns_service::DnsServiceHandle>,
) -> Result<nexusd::dataplane::Dataplane, String> {
    let mut dp = nexusd::dataplane::Dataplane::new(tun, config, dns)?;
    match rule_engine {
        Some(engine) => {
            dp.set_rule_engine(engine);
            eprintln!(
                "[nexusd.dataplane] level=info event=rule_engine state=wired source=proxy.yaml"
            );
        }
        None => {
            dp.set_default_simple_engine()
                .map_err(|e| format!("default rule engine: {e}"))?;
            eprintln!(
                "[nexusd.dataplane] level=warn event=rule_engine state=default source=none reason=no_proxy_yaml"
            );
        }
    }
    Ok(dp)
}

/// proxy.yaml 原文的 SHA-1（spec §7.6.2 `active_config_sha1` / `file_config_sha1`）。
fn config_sha1(text: Option<&str>) -> String {
    use sha1::{Digest, Sha1};
    let mut hash = Sha1::new();
    hash.update(text.unwrap_or_default().as_bytes());
    format!("{:x}", hash.finalize())
}

/// 发布 outbound `engine` / `dataplane` 启动事实（加法字段）。
///
/// no-tun 模式不构造 `ProxyEngine`；TUN 模式下 engine 由 dataplane 线程装配，
/// 这里先标 `starting`，线程内 wiring 完成后更新为 `running`
/// （TUN 创建/初始化失败 → `disabled`）。
fn publish_engine_state(tun_enabled: bool) {
    let state = if tun_enabled {
        nexus::outbound_manifest::DataplaneState::Starting
    } else {
        nexus::outbound_manifest::DataplaneState::NotStarted
    };
    nexus::outbound_manifest::install_engine_state(false, state);
}

/// D1：spawn **之前**构造 ProxyEngine（spec §3.3 定稿顺序）。
///
/// - `Err(Yaml | SelectedInvalid)` → 打印 `stage=proxy_engine_init` JSON 并返回 exit 1；
/// - `Err(NoUsableOutbound)` → warn 一行（§12.1）+ 无 engine（降级，非错误态）；
/// - 门槛 `tun_enabled() || has_tproxy`：no-tun 模式不构造、不产生该 stage 失败。
fn build_proxy_engine_for_startup(
    proxy_yaml: Option<&str>,
    tun_enabled: bool,
    has_tproxy: bool,
) -> Result<
    (
        Option<nexusd::proxy_fwd::ProxyEngine>,
        Option<Arc<nexusd::proxy_fwd::OutboundRegistry>>,
    ),
    ExitCode,
> {
    if !(tun_enabled || has_tproxy) {
        return Ok((None, None));
    }
    match nexusd::proxy_fwd::OutboundRegistry::build(proxy_yaml) {
        Ok(None) => Ok((None, None)),
        Ok(Some(registry)) => {
            // §12.1：非首个 wired 非法出站的启动 warn 行（不静默）。
            for line in registry.unsupported_warnings() {
                eprintln!("{line}");
            }
            let engine = nexusd::proxy_fwd::ProxyEngine::from_registry(Arc::clone(&registry));
            Ok((engine, Some(registry)))
        }
        Err(nexusd::proxy_fwd::EngineInitError::NoUsableOutbound { .. }) => {
            eprintln!(
                "[nexusd] dataplane: ProxyEngine unavailable (NO_USABLE_OUTBOUND); proxy flows answered with RST"
            );
            Ok((None, None))
        }
        Err(error) => {
            eprintln!("{}", proxy_engine_init_failure_json(&error));
            Err(ExitCode::from(1))
        }
    }
}

/// `stage=proxy_engine_init` 的启动失败 JSON（spec §12.2-A 逐字模板）。
fn proxy_engine_init_failure_json(error: &nexusd::proxy_fwd::EngineInitError) -> serde_json::Value {
    use nexusd::proxy_fwd::OutboundConfigError;
    match error {
        nexusd::proxy_fwd::EngineInitError::Yaml(config) => json!({
            "verdict": "FAIL",
            "command": "nexusd",
            "stage": "proxy_engine_init",
            "error": {
                "code": "CONFIG",
                "variant": error.variant(),
                "cause": "CONFIG_INVALID",
                "field": nexus::redact::sanitize(&config.field),
                "tag": "-",
                "kind": "-",
                "detail": nexus::redact::sanitize(&config.reason),
            }
        }),
        nexusd::proxy_fwd::EngineInitError::SelectedInvalid { tag, source } => {
            let mut body = json!({
                "verdict": "FAIL",
                "command": "nexusd",
                "stage": "proxy_engine_init",
                "error": {
                    "code": "CONFIG",
                    "variant": error.variant(),
                    "cause": source.name(),
                    "tag": tag,
                    "kind": "-",
                    "detail": nexus::redact::sanitize(source.detail()),
                }
            });
            if matches!(source, OutboundConfigError::PlaintextTrojanUnsupported) {
                // `tls: true` 对 trojan 被静默忽略（该字段仅 VLESS 语义），不能作为
                // 建议动作：否则「照 hint 改 → 仍报同一错」形成循环。
                body["error"]["hint"] = json!(
                    "trojan requires an explicit TLS signal: add alpn (e.g. alpn: [h2]) or \
                     skip_cert_verify (true or false both declare TLS; false validates against \
                     system roots). tls: true does not enable TLS for trojan."
                );
            }
            body
        }
        // 防御：NoUsableOutbound 在格式化之前已转入降级（§12.2-A）。
        nexusd::proxy_fwd::EngineInitError::NoUsableOutbound { .. } => json!({
            "verdict": "FAIL",
            "command": "nexusd",
            "stage": "proxy_engine_init",
            "error": {
                "code": "CONFIG",
                "variant": error.variant(),
                "cause": "CONFIG_INVALID",
                "tag": "-",
                "kind": "-",
                "detail": "no usable outbound (should have degraded before JSON)",
            }
        }),
    }
}

/// 数据面线程主循环：创建 TUN → 处理包 → 出错或收到关闭信号时退出线程。
///
/// R1：`n1_sender` 为 Some 时注入 dataplane（`set_n1_sender`），Mesh 包真发；
/// 为 None 时保持 D2 计数降级。
/// P1-P5：`proxy_yaml` 有可用出站时注入 `ProxyEngine`，Proxy 包真发；否则 D2 降级。
/// S24：`rule_engine` 由组合根从同一份 `proxy.yaml` 构建并注入，分类走配置规则。
/// R4：每次循环检查 `shutdown` 标志，置位后退出（join 1s 超时由调用方执行）。
#[allow(clippy::too_many_arguments)]
fn run_dataplane(
    config: nexusd::dataplane::DataplaneConfig,
    shutdown: Arc<AtomicBool>,
    n1_sender: Option<Arc<dyn nexus_network::n1::bridge::N1Sender>>,
    tun_name: &str,
    tun_mtu: u32,
    rule_engine: Option<ErasedRuleEngine>,
    proxy_engine: Option<nexusd::proxy_fwd::ProxyEngine>,
    outbound_registry: Option<Arc<nexusd::proxy_fwd::OutboundRegistry>>,
    proxy_yaml: Option<String>,
    network_toml: Option<String>,
    flow_sessions_mode: nexus_proxy_config::FlowSessionsMode,
    tun_default_route: bool,
    tun_excludes: Vec<([u8; 4], u8)>,
    tproxy_config: Option<nexus_proxy_config::TproxyInboundConfig>,
    tproxy_listen: String,
    nat_slot: nexusd::nat_consumer::NatHandleSlot,
    peer_map: Arc<dyn nexusd::mesh_peer_map::MeshPeerResolver>,
    direct_gate: Arc<nexusd::nat_chunk_recv::DirectGate>,
    nat_inbound_rx: std::sync::mpsc::Receiver<nexusd::nat_chunk_recv::NatInboundChunk>,
    chunk_stats: Arc<nexusd::nat_chunk_stats::ChunkStats>,
) {
    use nexus_projection::TunDevice;
    // D1：TUN 模式创建单个 TUN；纯 TPROXY 模式使用 InertTun（不伪造数据面）。
    let create_tun = tun_enabled();
    let tun: Box<dyn nexus_projection::TunDevice> = if create_tun {
        let tun_pattern = format!("{tun_name}%d");
        match nexus_projection::tun_rs_device::TunRsDevice::create(&tun_pattern, tun_mtu) {
            Ok(dev) => {
                eprintln!("[nexusd] dataplane: TUN {} created", dev.name());
                Box::new(dev)
            }
            Err(e) => {
                eprintln!(
                    "[nexusd] dataplane: TUN creation failed ({e}); dataplane disabled, LocalAPI still serving"
                );
                nexus::outbound_manifest::install_engine_state(
                    false,
                    nexus::outbound_manifest::DataplaneState::Disabled,
                );
                return;
            }
        }
    } else {
        eprintln!("[nexusd] dataplane: TUN disabled; using InertTun (tproxy-only mode)");
        Box::new(nexusd::dataplane::InertTun)
    };

    // C11 / D-impl-9：DNS 服务在 TUN 创建成功后启动；owner 线程与句柄由本函数持有。
    let dns_status = Arc::new(nexusd::dns_status::DnsStatus::new(
        nexusd::dns_status::DnsStatusSnapshot::disabled(),
    ));
    nexusd::dns_status::publish(Arc::clone(&dns_status));
    let dns_service = if config.dns_enabled {
        let Some(dns_config) = config.dns_config.clone() else {
            eprintln!("[nexusd] dns ERROR event=dns_config_invalid reason=missing-dns-config");
            return;
        };
        match nexusd::dns_service::DnsService::start(
            dns_config,
            proxy_yaml.as_deref(),
            Arc::clone(&dns_status),
        ) {
            Ok(handle) => {
                eprintln!(
                    "[nexusd] dns level=info event=dns_service state=running entry=tun+tproxy"
                );
                Some(handle)
            }
            Err(e) => {
                eprintln!("[nexusd] dns ERROR event=dns_config_invalid reason={e}");
                return;
            }
        }
    } else {
        None
    };

    let mut dp = match assemble_dataplane(tun, config, rule_engine, dns_service) {
        Ok(dp) => dp,
        Err(e) => {
            eprintln!("[nexusd] dataplane: init failed ({e}); dataplane disabled");
            nexus::outbound_manifest::install_engine_state(
                false,
                nexus::outbound_manifest::DataplaneState::Disabled,
            );
            return;
        }
    };

    // B1：发布 stats 句柄供 LocalAPI 读取。
    nexusd::dataplane::publish_stats_handle(dp.stats_handle());

    // S28：TUN 数据面启动时装配 OS 路由；失败 → os_assemble=failed 降级。
    #[cfg(target_os = "linux")]
    let mut os_assemble = if !create_tun {
        None
    } else {
        use nexus_platform_linux::assemble::{
            ExcludeEgress, OsAssemble, OsAssembleConfig, capture_egress_for,
        };
        // P5-b：exclude CIDR 必须沿用**接管前**该目的地址的真实出口，不得
        // `dev <TUN>`。在此刻（TUN 已建、路由尚未接管）逐项捕获 oif+gateway
        // 并显式传入；捕获不到的项交给 OsAssemble 从接管前快照再解析，
        // 仍解析不到则以显式错误降级（不静默回退 TUN）。
        let exclude_egress: Vec<(([u8; 4], u8), ExcludeEgress)> = tun_excludes
            .iter()
            .filter_map(|dst| match capture_egress_for(*dst) {
                Ok(Some(egress)) => {
                    eprintln!(
                        "[nexusd.os] level=info event=os_assemble_exclude_egress dst={dst:?} oif={} gateway={:?}",
                        egress.oif, egress.gateway
                    );
                    Some((*dst, egress))
                }
                Ok(None) => {
                    eprintln!(
                        "[nexusd.os] level=warn event=os_assemble_exclude_egress dst={dst:?} reason=no_pre_takeover_route"
                    );
                    None
                }
                Err(e) => {
                    eprintln!(
                        "[nexusd.os] level=warn event=os_assemble_exclude_egress dst={dst:?} reason={e}"
                    );
                    None
                }
            })
            .collect();
        let config = OsAssembleConfig {
            ifname: dp.tun_name().to_string(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: tun_default_route,
            dry_run: false,
            log_path: None,
            exclude_dst_cidrs: tun_excludes,
            exclude_egress,
        };
        match OsAssemble::new(config) {
            Ok(mut assemble) => match assemble.apply() {
                Ok(report) => {
                    nexusd::dataplane::publish_os_assemble(nexusd::dataplane::OsAssembleStatus {
                        state: "applied",
                        ifname: dp.tun_name().to_string(),
                        default_route: report.default_route_added,
                        excludes: report.excludes_added,
                    });
                    eprintln!(
                        "[nexusd.os] level=info event=os_assemble state=applied ifname={} addrs={} routes={} default_route={} excludes={}",
                        dp.tun_name(),
                        report.addrs_added,
                        report.routes_added,
                        report.default_route_added,
                        report.excludes_added,
                    );
                    Some(assemble)
                }
                Err(e) => {
                    nexusd::dataplane::publish_os_assemble(nexusd::dataplane::OsAssembleStatus {
                        state: "failed",
                        ifname: dp.tun_name().to_string(),
                        default_route: tun_default_route,
                        excludes: 0,
                    });
                    eprintln!(
                        "[nexusd.os] level=error event=os_assemble state=failed ifname={} reason={e}",
                        dp.tun_name()
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "[nexusd.os] level=error event=os_assemble state=failed ifname={} reason={e}",
                    dp.tun_name()
                );
                None
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let mut os_assemble: Option<()> = None;

    // R1：注入 N1 发送器（有则真发，无则 D2 计数降级）。
    if let Some(sender) = n1_sender {
        dp.set_n1_sender(sender);
        eprintln!("[nexusd] dataplane: N1 sender wired (n1_bridge_ready=true)");
    }

    // S25：生产 ChainDeps + 流会话三态（spec §7.6 第 3 步）。
    match nexusd::dataplane::ProductionChainDeps::from_config(
        network_toml.as_deref(),
        proxy_yaml.as_deref(),
    ) {
        Ok(deps) => {
            let providers = deps.provider_count();
            dp.set_production_chain_deps(deps);
            let enabled = dp.enable_flow_sessions_for_config(flow_sessions_mode, providers);
            let status = dp.flow_sessions_state();
            nexusd::dataplane::publish_flow_sessions(status);
            eprintln!(
                "[nexusd.session] level=info event=flow_sessions state={} reason={} providers={} auto={}",
                status.state,
                status.reason.unwrap_or("-"),
                status.providers,
                matches!(
                    flow_sessions_mode,
                    nexus_proxy_config::FlowSessionsMode::Auto
                ),
            );
            if enabled {
                eprintln!("[nexusd.session] level=info event=providers_derived count={providers}");
            }
        }
        Err(e) => {
            eprintln!("[nexusd] ERROR: flow session wiring failed: {e}");
        }
    }

    // P1-P5 / D1：engine 已在 spawn 之前构造（组合根移入），这里只注入。
    if let Some(engine) = proxy_engine {
        dp.set_proxy_engine(engine);
        eprintln!("[nexusd] dataplane: ProxyEngine wired (proxy_engine_ready=true)");
    }

    // P0：NAT chunk 消费接线（slot 可为空；空 = 全 fallback，诚实降级）。
    dp.set_nat_path_slot(nat_slot);
    dp.set_mesh_peer_resolver(peer_map);
    dp.set_direct_gate(direct_gate);
    dp.set_nat_inbound_rx(nat_inbound_rx);
    dp.set_chunk_stats(chunk_stats);

    #[cfg(target_os = "linux")]
    let mut tproxy_frontend = match tproxy_config {
        Some(config) => setup_tproxy_frontend(
            &config,
            &tproxy_listen,
            proxy_yaml.as_deref(),
            outbound_registry.clone(),
            &mut dp,
            Arc::clone(&shutdown),
        ),
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let mut tproxy_frontend: Option<()> = None;

    // 启动事实：dataplane 已进主循环（engine 构造与否如实）。
    nexus::outbound_manifest::install_engine_state(
        dp.proxy_engine_ready(),
        nexus::outbound_manifest::DataplaneState::Running,
    );

    eprintln!("[nexusd] dataplane: running");
    let _ = &mut os_assemble;
    let loop_start = std::time::Instant::now();
    let mut last_tproxy_publish = std::time::Instant::now();
    loop {
        // R4：关闭信号 → 退出循环（TUN 随 Dataplane drop 关闭）。
        if shutdown.load(Ordering::Relaxed) {
            eprintln!("[nexusd] dataplane: shutdown signal, exiting");
            break;
        }
        let now_millis = u64::try_from(loop_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        match dp.tick(now_millis) {
            Ok(true) => {}
            Ok(false) => {
                // 无包：短暂休眠避免忙轮询。
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("[nexusd] dataplane: TUN read error ({e}); exiting dataplane thread");
                break;
            }
        }
        // P0：每轮 drain direct chunk（不放进 process_one，Proxy 分支零改动）。
        dp.pump_nat_inbound();
        if last_tproxy_publish.elapsed() >= std::time::Duration::from_secs(1) {
            nexusd::dataplane::publish_flow_sessions(dp.flow_sessions_state());
            nexusd::dataplane::publish_tproxy_counters(
                dp.tproxy_counters(),
                dp.tproxy_last_failure().map(str::to_string),
            );
            last_tproxy_publish = std::time::Instant::now();
        }
    }
    // §13.4 清理顺序：停收包 → 透明前端 → DNS 服务 → 捕获规则 → OS 装配。
    dp.shutdown_transparent();
    dp.shutdown_dns();
    #[cfg(target_os = "linux")]
    if let Some(mut frontend) = tproxy_frontend.take() {
        frontend.shutdown();
    }
    #[cfg(not(target_os = "linux"))]
    let _ = tproxy_frontend.take();
    #[cfg(target_os = "linux")]
    if let Some(mut assemble) = os_assemble.take() {
        match assemble.cleanup() {
            Ok(report) => eprintln!(
                "[nexusd.os] level=info event=os_assemble state=cleaned addrs={} routes={} excludes={}",
                report.addrs_removed, report.routes_removed, report.excludes_removed
            ),
            Err(e) => eprintln!(
                "[nexusd.os] level=error event=os_assemble state=cleanup_failed reason={e}"
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = os_assemble.take();
}

/// TPROXY 前端运行期句柄（S42：listener 线程 + 捕获规则所有权）。
#[cfg(target_os = "linux")]
struct TproxyFrontend {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    rules: Box<dyn nexus_platform::TransparentCaptureRules>,
}

#[cfg(target_os = "linux")]
impl TproxyFrontend {
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        match self.rules.cleanup() {
            Ok(report) => eprintln!(
                "[nexusd.tproxy] level=info event=rules_cleaned chain={} rules={} ip_rules={} routes={}",
                nexusd::dataplane::tproxy_status_snapshot().chain,
                report.rules_removed,
                report.ip_rules_removed,
                report.routes_removed,
            ),
            Err(e) => {
                let mut status = nexusd::dataplane::tproxy_status_snapshot();
                status.state = "cleanup_failed";
                status.reason = Some("cleanup_failed");
                nexusd::dataplane::publish_tproxy_status(status);
                eprintln!(
                    "[nexusd.tproxy] level=error event=rules_failed step=cleanup reason=cleanup_failed stderr=\"{e}\""
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn map_capture_backend(
    backend: nexus_proxy_config::CaptureBackendConfig,
) -> nexus_platform::CaptureBackend {
    match backend {
        nexus_proxy_config::CaptureBackendConfig::Iptables => {
            nexus_platform::CaptureBackend::Iptables
        }
        nexus_proxy_config::CaptureBackendConfig::Nftables => {
            nexus_platform::CaptureBackend::Nftables
        }
        nexus_proxy_config::CaptureBackendConfig::External => {
            nexus_platform::CaptureBackend::External
        }
    }
}

#[cfg(target_os = "linux")]
fn ingress_reason(error: &nexus_platform::TransparentIngressError) -> &'static str {
    use nexus_platform::TransparentIngressError as E;
    match error {
        E::CapabilityUnavailable { .. } => "capability_unavailable",
        E::PermissionDenied { .. } => "permission_denied",
        E::BindFailed { .. } => "bind_failed",
        E::SockOptFailed { .. } => "sockopt_failed",
        E::OrigDstMissing { .. } => "orig_dst_missing",
        E::OrigDstInvalid { .. } => "orig_dst_invalid",
        E::AncillaryParseFailed { .. } => "ancillary_parse_failed",
        E::UnsupportedFamily { .. } => "unsupported_family",
        E::Io { .. } => "listener_io_failed",
    }
}

#[cfg(target_os = "linux")]
fn rule_reason(error: &nexus_platform::CaptureRuleError) -> &'static str {
    use nexus_platform::CaptureRuleError as E;
    match error {
        E::PermissionDenied { .. } => "rule_permission_denied",
        E::ToolMissing { .. } => "tool_missing",
        E::CommandFailed { .. } => "rule_apply_failed",
        E::CleanupFailed { .. } => "cleanup_failed",
        E::UnsupportedBackend { .. } => "rule_apply_failed",
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn setup_tproxy_frontend(
    config: &nexus_proxy_config::TproxyInboundConfig,
    listen: &str,
    proxy_yaml: Option<&str>,
    outbound_registry: Option<Arc<nexusd::proxy_fwd::OutboundRegistry>>,
    dp: &mut nexusd::dataplane::Dataplane,
    shutdown: Arc<AtomicBool>,
) -> Option<TproxyFrontend> {
    use nexus_platform::CaptureRuleSpec;
    use nexus_platform::{TransparentTcpIngress, TransparentUdpIngress};
    use nexus_platform_linux::tproxy::rules::capture_rules_for;
    use nexus_platform_linux::tproxy::{
        TproxyTcpConfig, TproxyTcpListener, TproxyUdpConfig, TproxyUdpSocket,
    };
    use nexus_projection::transparent::direct::{DirectEgress, DirectEgressConfig};
    use nexus_projection::transparent::runtime::TransparentPipeline;
    use nexus_projection::transparent::{
        PathFailurePolicy, ProxyFlowEgress, TransparentConfig, TransparentDeps, TransparentOutput,
    };

    let privilege = nexusd::dataplane::detect_privilege();
    let backend = map_capture_backend(config.backend);
    let mut spec = CaptureRuleSpec::new(backend);
    spec.chain = config.chain.clone();
    spec.tcp_port = config.tcp_port;
    spec.udp_port = config.udp_port;
    spec.mark = config.mark;
    spec.mark_mask = config.mark;
    spec.route_table = config.route_table;
    spec.intercept_dst_cidrs = config.intercept_dst_cidrs.clone();
    spec.exclude_dst_cidrs = config.exclude_dst_cidrs.clone();
    if let Some(yaml) = proxy_yaml {
        if let Ok(parsed) = nexus_proxy_config::parse(yaml) {
            for outbound in &parsed.outbounds {
                if let Some(locator) = outbound.locator.as_deref() {
                    let host = locator.rsplit_once(':').map_or(locator, |(host, _)| host);
                    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                        let cidr = format!("{ip}/32");
                        if !spec.exclude_dst_cidrs.contains(&cidr) {
                            spec.exclude_dst_cidrs.push(cidr);
                        }
                    }
                }
            }
        }
    }

    let listen_addr = listen
        .parse::<std::net::SocketAddr>()
        .ok()
        .and_then(|addr| match addr {
            std::net::SocketAddr::V4(v4) => Some(v4),
            std::net::SocketAddr::V6(_) => None,
        })
        .unwrap_or_else(|| {
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, config.tcp_port)
        });
    let tcp_config = TproxyTcpConfig {
        listen: std::net::SocketAddrV4::new(*listen_addr.ip(), config.tcp_port),
        ..TproxyTcpConfig::default()
    };
    let udp_config = TproxyUdpConfig {
        listen: std::net::SocketAddrV4::new(*listen_addr.ip(), config.udp_port),
        ..TproxyUdpConfig::default()
    };
    let mut rules = capture_rules_for(backend);

    let mut tcp = match TproxyTcpListener::bind(&tcp_config) {
        Ok(listener) => listener,
        Err(error) => {
            let reason = ingress_reason(&error);
            let mut status = nexusd::dataplane::capture_failure_status(
                reason,
                privilege,
                config.on_capture_failure,
                true,
            );
            status.backend = backend.as_str();
            status.chain = config.chain.clone();
            status.mark = format!("0x{:x}", config.mark);
            status.route_table = config.route_table;
            status.listen = listen.to_string();
            if config.on_capture_failure == nexus_proxy_config::CaptureFailureMode::Block {
                status.enforcement = match rules.enforce_block(&spec) {
                    Ok(_) => "block",
                    Err(_) => "impossible",
                };
            }
            nexusd::dataplane::publish_tproxy_status(status);
            eprintln!(
                "[nexusd.tproxy] level=error event=capture_failed reason={reason} addr={} errno=0 msg=\"{error}\"",
                listen_addr
            );
            return None;
        }
    };
    let mut udp = match TproxyUdpSocket::bind(&udp_config) {
        Ok(socket) => socket,
        Err(error) => {
            let reason = ingress_reason(&error);
            let mut status = nexusd::dataplane::capture_failure_status(
                reason,
                privilege,
                config.on_capture_failure,
                true,
            );
            status.backend = backend.as_str();
            status.chain = config.chain.clone();
            status.mark = format!("0x{:x}", config.mark);
            status.route_table = config.route_table;
            status.listen = listen.to_string();
            if config.on_capture_failure == nexus_proxy_config::CaptureFailureMode::Block {
                status.enforcement = match rules.enforce_block(&spec) {
                    Ok(_) => "block",
                    Err(_) => "impossible",
                };
            }
            nexusd::dataplane::publish_tproxy_status(status);
            eprintln!(
                "[nexusd.tproxy] level=error event=capture_failed reason={reason} addr={} errno=0 msg=\"{error}\"",
                listen_addr
            );
            return None;
        }
    };
    let _ = tcp.start();
    let _ = udp.start();

    let mut status = nexusd::dataplane::TproxyStatus {
        state: "active",
        reason: None,
        enforcement: "active",
        backend: backend.as_str(),
        privilege,
        chain: config.chain.clone(),
        mark: format!("0x{:x}", config.mark),
        route_table: config.route_table,
        listen: listen.to_string(),
        ip_family: "ipv4",
        ipv6_enabled: false,
        counters: nexusd::dataplane::TproxyCounters::default(),
        last_failure_reason: None,
    };
    match rules.apply(&spec) {
        Ok(report) => eprintln!(
            "[nexusd.tproxy] level=info event=rules_applied backend={} chain={} rules={} ip_rules={} routes={} idempotent=true",
            backend.as_str(),
            config.chain,
            report.rules_added,
            report.ip_rules_added,
            report.routes_added,
        ),
        Err(error) => {
            let reason = rule_reason(&error);
            status.state = "degraded";
            status.reason = Some(reason);
            status.enforcement = match config.on_capture_failure {
                nexus_proxy_config::CaptureFailureMode::Bypass => "none",
                nexus_proxy_config::CaptureFailureMode::Block => match rules.enforce_block(&spec) {
                    Ok(_) => "block",
                    Err(_) => "impossible",
                },
            };
            eprintln!(
                "[nexusd.tproxy] level=error event=rules_failed step=apply reason={reason} stderr=\"{error}\""
            );
        }
    }

    let Ok(direct) = DirectEgress::new(DirectEgressConfig::default()) else {
        eprintln!(
            "[nexusd.tproxy] level=error event=capture_failed reason=sockopt_failed addr={listen_addr} errno=0 msg=\"direct egress init failed\""
        );
        return None;
    };
    // Q-5=B：TPROXY 与 TUN 共享同一批 dialer（同一份 registry）。
    let proxy_egress: Option<Box<dyn ProxyFlowEgress>> = outbound_registry
        .and_then(nexusd::tproxy_egress::StreamProxyEgress::from_registry)
        .map(|egress| Box::new(egress) as Box<dyn ProxyFlowEgress>);
    let transparent_config = TransparentConfig {
        udp_table_capacity: config.udp_table_capacity,
        max_tcp_conns: config.max_tcp_conns,
        udp_idle: std::time::Duration::from_secs(config.udp_idle_secs),
        on_path_failure: match config.on_path_failure {
            nexus_proxy_config::PathFailureMode::Block => PathFailurePolicy::Block,
            nexus_proxy_config::PathFailureMode::Fallback => PathFailurePolicy::Fallback,
        },
        ..TransparentConfig::default()
    };
    let pipeline = TransparentPipeline::new(TransparentDeps {
        proxy_egress,
        direct,
        config: transparent_config,
    });
    let (tx, rx) = nexusd::dataplane::inbound_channel();
    let failure_tx = tx.clone();
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    dp.set_transparent_pipeline(pipeline, reply_tx);
    dp.set_transparent_rx(rx, failure_tx);
    let counters = dp.tproxy_counters_handle();
    nexusd::dataplane::publish_tproxy_status(status.clone());

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("nexusd-tproxy".to_string())
        .spawn(move || {
            let started = std::time::Instant::now();
            while !thread_stop.load(Ordering::Relaxed) && !shutdown.load(Ordering::Relaxed) {
                let now_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match tcp.accept(now_millis) {
                    Ok(Some(accepted)) => {
                        if tx
                            .try_send(nexusd::dataplane::TransparentInbound::Tcp(accepted))
                            .is_err()
                        {
                            nexusd::dataplane::record_inbound_queue_full(&counters);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if tx
                            .try_send(nexusd::dataplane::TransparentInbound::CaptureFailed(error))
                            .is_err()
                        {
                            nexusd::dataplane::record_inbound_queue_full(&counters);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
                match udp.recv(now_millis) {
                    Ok(Some(datagram)) => {
                        if tx
                            .try_send(nexusd::dataplane::TransparentInbound::Udp(datagram))
                            .is_err()
                        {
                            nexusd::dataplane::record_inbound_queue_full(&counters);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if tx
                            .try_send(nexusd::dataplane::TransparentInbound::CaptureFailed(error))
                            .is_err()
                        {
                            nexusd::dataplane::record_inbound_queue_full(&counters);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
                while let Ok(output) = reply_rx.try_recv() {
                    if let TransparentOutput::UdpReply {
                        orig_dst,
                        peer,
                        payload,
                    } = output
                    {
                        if udp.send_from(orig_dst, peer, &payload).is_err() {
                            if let Ok(mut guard) = counters.lock() {
                                guard.udp_reply_failed += 1;
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = tcp.shutdown();
            let _ = udp.shutdown();
        })
        .ok()?;

    Some(TproxyFrontend {
        stop,
        handle: Some(handle),
        rules,
    })
}

/// NAT switching daemon runtime（AC5）。
///
/// 持有 `TurnManager` + `StunProber` + `NatSwitching` + （可选）`TurnRelayProvider`，在后台 worker 线程驱动：
/// - 启动时懒分配 TURN（失败 → WARN + Disabled 降级，不阻断进程）；
/// - 按节奏 Refresh 保活（AC3）；
/// - 周期性 STUN 采样（5min），更新本地候选与 NAT 类型分支（AC4）。
///
/// 诚实边界：
/// - 本运行时的 fabric 身份（`my_id`）与 punch `Driver` 由组合根（`run_daemon`）
///   在启动时一次性解析并注入：`my_id` 来自 daemon 自己的 `network.toml`
///   `peer_id`（64-hex ed25519 公钥），**不会**在运行时内部铸造随机身份。
/// - punch `Driver` 同时充当 punch responder 的 server 端点；N1 mesh 的
///   dialer 使用 per-dial 临时 socket（`FabricDialer` 每次拨号新建 socket），
///   不暴露共享 server socket，因此 mesh 数据面与打洞共用同一 UDP socket
///   （AC6 严格字面）需要更深的 mesh/fabric 集成——作为跨模块后续工作记录，
///   不在本任务内静默模拟。
/// - D5 生产触发（spec §14.3 / B17）已接线：`start` 在 identity 就绪时构造
///   `TurnRelayProvider` 并 `attach_relay_provider` 到 `sw`；`NatSwitching`
///   实现生产 `RelayConnSink`，provider 事件直通 `on_relay_connected`
///   （auto_punch: true），loopback 验收已证明该路径。生产 peer 源由
///   `PeerSourceFeed` 提供（静态配置 ∪ 发现 ∪ N1 session），它在同一 worker
///   线程内按 `feed_interval` tick，并在 relay 地址簿出现地址后触发
///   `on_turn_allocated`。
struct NatSwitchRuntime {
    turn: nat_turn::TurnManager,
    // B14 fix: the gatherer owns the sampling prober (probing goes through
    // gatherer.stun_prober()); candidate composition goes through gather().
    gatherer: nat_gather::CandidateGatherer,
    sw: Arc<nexusd::nat_switch::NatSwitching>,
    _driver: Arc<Driver>,
    /// D5 production relay provider (spec §14.3 / B17). Owns the daemon
    /// fabric identity (bind_with_transport_identity); `run` uses
    /// `identity_peer_id()` for the self-publish book path. `None` when
    /// the relay provider path is disabled (identity absent).
    provider: Option<Arc<nexusd::nat_relay::TurnRelayProvider>>,
    /// Tech debt (W-2)：协作式退出标志。未用 `CancellationToken` 是因为 nexusd
    /// 没有 tokio/tokio-util 依赖，为这一个标志引入异步运行时不划算。AC5 的
    /// 5s 优雅退出仍有界：worker 内所有阻塞操作都有超时（TURN 请求 3s、STUN
    /// 探测 2s、主循环 500ms 轮询），且退出前只做 best-effort 的释放调用；
    /// 最坏情况 SIGTERM → 线程退出 < 5s。
    stop: Arc<AtomicBool>,
    /// STUN 端口样本滚动历史（供 D2 有界端口预测的 Δ 稳定性判定；上限
    /// `MAX_PORT_SAMPLES`，由 5min 刷新循环追加）。
    port_samples: Vec<PortSample>,
    /// Peer-source feed (owned by value; only this worker ticks it).
    feed: Option<peer_source::PeerSourceFeed>,
    /// Feed tick interval (from `[network.discovery]`).
    feed_interval: Duration,
}

/// STUN 端口样本滚动历史上限（D2 判定最少需要 3 个；保留 8 个抗抖动）。
const MAX_PORT_SAMPLES: usize = 8;

impl NatSwitchRuntime {
    /// 从 `[network.turn]` 配置创建并启动运行时。
    ///
    /// `shutdown` 是 daemon 全局关闭标志：worker 在收到 SIGTERM/SIGINT 后
    /// 协作式退出（与 dataplane/LocalAPI 线程同源）。返回 worker
    /// `JoinHandle`（主线程在 [`shutdown_sequence`] 中 join）；运行时被移入 worker。
    ///
    /// `driver` 与 `my_id` 由组合根注入（见 [`NatSwitchRuntime`] 诚实边界）：
    /// `driver` 是 punch responder 的 fabric server 端点，`my_id` 是 daemon 的
    /// 权威 mesh 身份（来自 `network.toml` 的 `peer_id`）。
    #[allow(clippy::too_many_arguments)]
    fn start(
        section: &TurnSection,
        shutdown: Arc<AtomicBool>,
        driver: Arc<Driver>,
        my_id: FabricPeerId,
        identity: Option<FabricIdentity>,
        discovery: &DiscoverySection,
        hub: Option<Arc<nexus_discovery::hub::DiscoveryHub>>,
        sessions: Option<Arc<nexus_network::n1::session::N1SessionManager>>,
        static_peers: Vec<N1PeerId>,
        nat_slot: nexusd::nat_consumer::NatHandleSlot,
        punch_clock: Arc<dyn nexus_nat_traversal::PunchClock>,
    ) -> Option<JoinHandle<()>> {
        if let Some(id) = &identity {
            eprintln!(
                "[nat-relay] provider_ready identity={}",
                id.peer_id()
                    .0
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
        }
        // TURN 生命周期管理器（配置缺失时由调用方保证为 Some）。
        let turn = nat_turn::TurnManager::new(Some(section.clone()));

        // STUN 探测器：真实 UDP 传输。
        let stun_transport: Box<dyn nat_stun::StunTransport> = match nat_stun::UdpStunTransport::new(
            "0.0.0.0:0".parse().expect("0.0.0.0:0 parses"),
        ) {
            Ok(t) => Box::new(t),
            Err(e) => {
                eprintln!(
                    "[nat-switch] WARN: STUN socket bind failed ({e}); stun disabled, punch disabled"
                );
                return None;
            }
        };
        let stun = nat_stun::StunProber::new(stun_transport);

        // B14 fix: initial candidates go through the gatherer, not a
        // hardcoded literal. No TURN allocation exists yet at this point, so
        // turn_mapped is None by rule (not by literal); the first
        // sample_and_update overwrites this with the real mapping. Hosts are
        // overlaid with the G3 interface enumeration either way.
        let hosts = nexusd::nat_switch::gather_host_candidates(&driver);
        let bind_for_gather = hosts
            .first()
            .copied()
            .unwrap_or_else(|| "0.0.0.0:0".parse().expect("0.0.0.0:0 parses"));
        let mut gatherer = nat_gather::CandidateGatherer::new(stun, bind_for_gather);
        let local = match gatherer.gather(None, false, &mut Vec::new()) {
            Ok(mut c) => {
                c.host = hosts;
                c
            }
            Err(e) => {
                eprintln!("[nat-switch] WARN: initial gather failed ({e}); using bare hosts");
                LocalCandidates {
                    host: hosts,
                    srflx: None,
                    srflx_stun: None,
                    // Computed, not hardcoded: no TURN allocation exists yet,
                    // so this is None by rule (same as the gather path).
                    srflx_turn: turn.mapped_addr(),
                    nat_type: nexus_domain::nat::NatType::Unknown,
                }
            }
        };
        let sw = nexusd::nat_switch::NatSwitching::new(
            driver.clone(),
            my_id,
            local,
            Vec::new(), // STUN 样本由 worker 周期性喂入
            Arc::clone(&punch_clock),
        );

        nexusd::nat_status::publish_nat_status_source(Box::new(Arc::clone(&sw)));

        // P0: expose the narrow consumer seam. The dataplane may already be
        // running; an empty slot simply means "all chunks fallback".
        let provider: Arc<dyn nexusd::nat_consumer::NatPathProvider> = sw.clone();
        nat_slot.set(provider);
        eprintln!("[nat-consumer] handle attached");

        // D5: one address book for the whole process (provider publish + feed
        // poll). `relay_book_dir` selects the shared-directory book; otherwise
        // the legacy per-self temp file.
        let book: Option<Arc<dyn nexusd::nat_relay::RelayAddressBook>> = match &section
            .relay_book_dir
        {
            Some(dir) => match nexusd::nat_relay::DirRelayAddressBook::new(dir.clone(), my_id.0) {
                Ok(book) => {
                    eprintln!("[nat-relay] book mode=shared-dir path={}", dir.display());
                    Some(Arc::new(book))
                }
                Err(e) => {
                    eprintln!(
                        "[nat-relay] WARN: shared relay book dir unavailable ({e}); relay provider not attached"
                    );
                    None
                }
            },
            None => {
                let hex: String = my_id.0.iter().map(|b| format!("{b:02x}")).collect();
                let book_path = std::env::temp_dir().join(format!("nexus-relay-{hex}.toml"));
                match nexusd::nat_relay::FileRelayAddressBook::new(&book_path) {
                    Ok(book) => {
                        eprintln!(
                            "[nat-relay] book mode=per-self path={}",
                            book_path.display()
                        );
                        Some(Arc::new(book))
                    }
                    Err(e) => {
                        eprintln!(
                            "[nat-relay] WARN: address book open failed ({e}); relay provider not attached"
                        );
                        None
                    }
                }
            }
        };

        // The provider consumes the identity when attached; it owns its own
        // TURN allocation (the runtime's manager stays the warm backup).
        let provider = match (identity, book.clone()) {
            (Some(id), Some(book)) => {
                let provider = nexusd::nat_relay::TurnRelayProvider::new(
                    my_id,
                    id,
                    // NOTE: the bin has its own `nat_turn` module (same file,
                    // separate compilation); the provider needs the LIB's
                    // TurnManager type.
                    nexusd::nat_turn::TurnManager::new(Some(section.clone())),
                    book,
                );
                sw.attach_relay_provider(
                    Arc::clone(&provider) as Arc<dyn nexusd::nat_relay::RelayConnProvider>
                );
                Some(provider)
            }
            _ => None,
        };

        // Peer-source state is decided (and published) *before* the feed is
        // constructed; only `running` gets a feed (spec §4.11.1).
        let peer_status = Arc::new(peer_source::PeerSourceStatus::default());
        let state = peer_source::decide_state(peer_source::PeerSourceStateInputs {
            enabled: discovery.enabled,
            feed: discovery.feed,
            has_nat_switch: true,
            has_provider: provider.is_some(),
            has_hub: hub.is_some(),
            has_sessions: sessions.is_some(),
        });
        peer_status.set_state(state);
        nexusd::nat_status::publish_peer_source_status(Arc::clone(&peer_status));
        eprintln!("[peer-source] state={state}");

        let feed_cfg = peer_source::PeerSourceConfig {
            book_poll_interval: Duration::from_millis(discovery.book_poll_ms),
            trigger_max_failures: discovery.trigger_max_failures,
            ..peer_source::PeerSourceConfig::default()
        };
        let feed_interval = feed_cfg.feed_interval;
        let feed = match (provider.as_ref(), book, hub, sessions) {
            (Some(provider), Some(book), Some(hub), Some(sessions)) if state == "running" => {
                Some(peer_source::PeerSourceFeed::new(
                    Arc::clone(&sw),
                    Arc::clone(provider) as Arc<dyn nexusd::nat_relay::RelayTrigger>,
                    book,
                    sessions,
                    static_peers,
                    hub,
                    my_id,
                    feed_cfg,
                    Arc::clone(&peer_status),
                    Arc::clone(&shutdown),
                ))
            }
            _ => None,
        };

        let runtime = NatSwitchRuntime {
            turn,
            gatherer,
            sw,
            _driver: driver,
            provider,
            stop: shutdown,
            port_samples: Vec::new(),
            feed,
            feed_interval,
        };

        let stun_servers = stun_servers(section);
        let worker = std::thread::Builder::new()
            .name("nexusd-nat-switch".to_string())
            .spawn(move || {
                runtime.run(stun_servers);
            })
            .map_err(|e| format!("spawn nat-switch thread: {e}"))
            .ok()?;
        Some(worker)
    }

    /// Worker 主循环（单写入者；`stop` 置位后协作式退出）。
    ///
    /// `servers`: `(server1, server2)`；`server2` 为 `Some` 且与 `server1` 不同
    /// 时做双服务器 NAT 类型检测（AC4），否则只做单服务器采样（`nat_type`
    /// 保持 `Unknown`）。
    fn run(mut self, servers: Option<(std::net::SocketAddr, Option<std::net::SocketAddr>)>) {
        // 1. 懒初始化 runtime 的 warm-backup TURN 分配（失败 → WARN，中继照常）。
        match self.turn.ensure_allocated() {
            Ok(relayed) => eprintln!("[nat-switch] TURN relayed={relayed} (warm backup)"),
            Err(e) => eprintln!(
                "[nat-switch] WARN: {}; punch disabled",
                nat_gather::GatherError::Turn(e)
            ),
        }

        // 1b. The provider allocates and publishes **its own** relayed address.
        // The runtime's warm-backup allocation is never published (peers would
        // dial an allocation nobody accepts).
        if let Some(provider) = &self.provider {
            if let Err(e) = provider.ensure_relay_ready() {
                eprintln!("[nat-relay] WARN: relay not ready ({e}); provider stays attached");
            }
        }

        // 2. 初始 STUN 采样（失败不阻断）。
        let mut last_stun = std::time::Instant::now();
        if let Some((s1, s2)) = servers {
            self.sample_and_update(s1, s2);
        }

        // 3. 节奏循环：Refresh 保活（runtime + provider）+ 周期 STUN + feed tick。
        let mut last_feed: Option<std::time::Instant> = None;
        let feed_interval = self.feed_interval;
        while !self.stop.load(Ordering::Relaxed) {
            self.turn.refresh_if_needed();
            if let Some(provider) = &self.provider {
                // `Lost` is fully handled inside the provider (slot cleared,
                // sinks notified); the feed re-arms on the next book poll.
                let _ = provider.refresh();
            }
            if let Some(feed) = &mut self.feed {
                let due = last_feed
                    .map(|at: std::time::Instant| at.elapsed() >= feed_interval)
                    .unwrap_or(true);
                if due {
                    last_feed = Some(std::time::Instant::now());
                    feed.tick(std::time::Instant::now());
                }
            }
            if let Some((s1, s2)) = servers {
                if last_stun.elapsed() >= nat_stun::STUN_REFRESH_INTERVAL {
                    self.sample_and_update(s1, s2);
                    last_stun = std::time::Instant::now();
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // 4. 协作式退出顺序（冻结）：feed → sw → turn。
        if let Some(feed) = &mut self.feed {
            feed.shutdown();
        }
        self.sw.shutdown();
        self.turn.shutdown();
        eprintln!("[nat-switch] worker exited");
    }

    /// STUN 采样并更新本地候选（AC4 + D2）。
    ///
    /// - `server2` 为 `Some` 时：双服务器映射对比做 NAT 类型检测
    ///   （`detect_nat_type` 口径），`nat_type` 为真实检测结果；
    /// - `server2` 为 `None` 时：只做单服务器采样，`nat_type` 保持 `Unknown`
    ///   （如实标记，不做无依据的类型断言）。
    ///
    /// 每次采样的公网端口追加到 `port_samples` 滚动历史（上限
    /// `MAX_PORT_SAMPLES`），供 D2 有界端口预测做 Δ 稳定性判定。
    fn sample_and_update(
        &mut self,
        server1: std::net::SocketAddr,
        server2: Option<std::net::SocketAddr>,
    ) {
        // Tech debt (W-1)：时间源直接用 std；见模块级说明。
        let at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let probed = match server2 {
            Some(s2) => self.gatherer.stun_prober().probe_and_detect(server1, s2),
            None => {
                eprintln!(
                    "[nat-switch] single STUN server; NAT-type detection skipped (nat_type=Unknown)"
                );
                self.gatherer
                    .stun_prober()
                    .probe_once(server1, nat_stun::STUN_PROBE_TIMEOUT)
                    .map(|m| (m, nexus_domain::nat::NatType::Unknown))
            }
        };
        match probed {
            Ok((mapping, nat_type)) => {
                let sample = PortSample {
                    port: mapping.public.port(),
                    at_ms,
                    target: server1,
                    observed_from: mapping.local,
                };
                self.port_samples.push(sample);
                if self.port_samples.len() > MAX_PORT_SAMPLES {
                    let excess = self.port_samples.len() - MAX_PORT_SAMPLES;
                    self.port_samples.drain(..excess);
                }
                // B14 fix: the TURN mapping flows through the gatherer.
                // Composition-root assertion (spec §4.1 item 3): the
                // TurnManager owns a separate UDP socket, never the punch
                // driver socket, so turn_same_socket is false until a
                // shared-socket TURN path exists. The gatherer therefore
                // records srflx_turn as diagnostic here; the copy path is
                // proven by nat_gather quadrant tests and activates if/when
                // TURN shares the punch socket.
                let turn_mapped = self.turn.mapped_addr();
                self.gatherer.set_nat_type(nat_type);
                let mut local = match self.gatherer.gather(
                    turn_mapped,
                    false,
                    &mut self.port_samples,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!(
                            "[nat-switch] WARN: candidate gather failed ({e}); keeping STUN-derived candidates"
                        );
                        LocalCandidates {
                            host: nexusd::nat_switch::gather_host_candidates(&self._driver),
                            srflx: None,
                            srflx_stun: None,
                            srflx_turn: turn_mapped,
                            nat_type,
                        }
                    }
                };
                // STUN-derived values are primary; the gatherer copy (if any)
                // agrees with them under same-socket+cone. Hosts always come
                // from the G3 enumeration.
                if local.srflx.is_none() {
                    local.srflx = Some(mapping.public);
                }
                local.srflx_stun = Some(server1);
                local.host = nexusd::nat_switch::gather_host_candidates(&self._driver);
                local.nat_type = nat_type;
                self.sw.set_local(local, self.port_samples.clone());
                eprintln!(
                    "[nat-switch] STUN sample: public={} nat_type={:?} samples={} (local={})",
                    mapping.public,
                    nat_type,
                    self.port_samples.len(),
                    mapping.local
                );
            }
            Err(e) => eprintln!(
                "[nat-switch] WARN: {}; keeping previous candidates",
                nat_gather::GatherError::Stun(e)
            ),
        }
    }
}

/// 解析 STUN 服务器地址（AC4 双服务器检测）。
///
/// 返回 `(server1, server2)`：
/// - `server1` = `stun_server`，缺失时回落 `[network.turn].server`；
/// - `server2` = `stun_server2`，且必须能解析、与 `server1` 不同，否则为 `None`
///   （此时只做单服务器采样，`nat_type` 保持 `Unknown`）。
///
/// `server1` 本身解析失败 → `None`（STUN 探测整体禁用）。
fn stun_servers(
    section: &TurnSection,
) -> Option<(std::net::SocketAddr, Option<std::net::SocketAddr>)> {
    let s1: std::net::SocketAddr = section
        .stun_server
        .as_deref()
        .unwrap_or(&section.server)
        .parse()
        .ok()?;
    let s2 = section
        .stun_server2
        .as_deref()
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .filter(|s2| *s2 != s1);
    Some((s1, s2))
}

/// `stage=config_load` 失败行（spec §12.2-B）；proxy.yaml 解析失败时补四字段。
///
/// 全部字段经 `redact_secrets`/`sanitize`（写点 1/6，spec §9.1），并用
/// `serde_json::json!` 构造（禁止手拼转义回归）。
fn config_load_failure_json(error: &str, dir: Option<&ConfigDir>) -> serde_json::Value {
    let parse_error = dir
        .and_then(|dir| std::fs::read_to_string(dir.file(config::PROXY_YAML)).ok())
        .and_then(|text| nexus_proxy_config::parse(&text).err());
    match parse_error {
        Some(parse) => json!({
            "verdict": "FAIL",
            "command": "nexusd",
            "stage": "config_load",
            "error": {
                "code": "CONFIG",
                "message": nexus::redact::sanitize(error),
                "variant": "PROXY_YAML_INVALID",
                "field": nexus::redact::sanitize(&parse.field),
                "detail": nexus::redact::sanitize(&parse.reason),
            }
        }),
        None => json!({
            "verdict": "FAIL",
            "command": "nexusd",
            "stage": "config_load",
            "error": {"code": "CONFIG", "message": nexus::redact::sanitize(error)}
        }),
    }
}

/// Daemon 主流程：加载配置 → 装配子系统 → 启动线程 → 事件循环 → 优雅关闭。
///
/// 启动顺序（§13.3）：配置加载 → 校验 → TUN（致命）→ Dataplane → N1（可降级）
/// → Proxy（分层：配置错误致命 / 无可用出口降级）→ LocalAPI → 主循环。
/// D1：ProxyEngine 在 dataplane 线程 `spawn` **之前**构造（硬失败 → stderr JSON +
/// exit 1；仅 `NoUsableOutbound` 降级为无 engine）。
/// 关闭顺序（§13.4/R4/D7）：SIGTERM/SIGINT → LocalAPI → Workspace unmount → Dataplane（1s 超时）
/// → N1（5s 超时）→ TUN（随线程退出）→ exit 0。
/// 按磁盘现状刷新 proxy.yaml 的 file 侧（Applied / NeedsRestart / Rejected 共用，Q-7=B）。
///
/// 只描述磁盘现状：解析失败 → `mark_file_rejected`（带脱敏原因）；成功 →
/// `update_file_side`（R2-F12：成功即无条件清 `file_rejected`）。
/// 返回 `stale`（无快照 → `None`）。
fn refresh_proxy_file_side(dir: &ConfigDir, rejected_reason: Option<&str>) -> Option<bool> {
    use nexus::outbound_manifest;
    let text = std::fs::read_to_string(dir.file(config::PROXY_YAML)).ok();
    let surface = outbound_manifest::startup_surface(text.as_deref());
    let (file_tag, file_kind) = surface
        .selected
        .and_then(|index| surface.labels.get(index))
        .map(|label| (Some(label.tag.clone()), Some(label.kind.clone())))
        .unwrap_or((None, None));
    let sha1 = config_sha1(text.as_deref());
    match rejected_reason {
        Some(reason) if surface.error.is_some() => outbound_manifest::mark_file_rejected(
            file_tag,
            file_kind,
            &sha1,
            &nexus::redact::redact_secrets(reason),
        ),
        _ => outbound_manifest::update_file_side(file_tag, file_kind, &sha1),
    }
}

/// spec §12.1 stale 行（`some(true)` 时打印）。
fn log_stale_line(stale: Option<bool>) {
    if stale == Some(true)
        && let Some(line) = nexus::outbound_manifest::stale_line()
    {
        eprintln!("{line}");
    }
}

fn run_daemon(config_dir: &str) -> ExitCode {
    // Anchor relative daemon input once without resolving symlinks or removing
    // parent components: managed preflight must retain its path safety checks.
    let config_root = match std::path::absolute(config_dir) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("{}", config_load_failure_json(&error.to_string(), None));
            return ExitCode::from(1);
        }
    };
    let managed_provider = match validate_task_provider_startup(&config_root) {
        Ok(managed) => managed,
        Err(exit) => return exit,
    };
    let snapshots = match open_snapshot_service(&config_root) {
        Ok(snapshots) => snapshots,
        Err(exit) => return exit,
    };
    let dir = match ConfigDir::new(&config_root) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}", config_load_failure_json(&e.to_string(), None));
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
            eprintln!("{}", config_load_failure_json(&e.to_string(), Some(&dir)));
            return ExitCode::from(1);
        }
    };
    let no_other_subsystem = loaded.proxy_yaml.is_none()
        && loaded.network_toml.is_none()
        && loaded.workspace_toml.is_none();
    if managed_provider
        && no_other_subsystem
        && (!loaded.meta.contains_key(config::DAEMON_TOML) || loaded.daemon.tun.enabled)
    {
        eprintln!(
            "{}",
            json!({"verdict":"FAIL", "error":{"code":"CONFIG", "message":"N3-only startup requires explicit daemon.toml [tun] enabled=false"}})
        );
        return ExitCode::from(1);
    }
    log_enabled_subsystems(&loaded);

    // 五载体（spec §7.7 载体 1/3/4）：manifest 解析失败 = 打包错误，fail-closed；
    // 成功则打印逐出站启动面并发布进程内运行快照（stats/status 共用同一序列化）。
    if let Err(error) = nexus::outbound_manifest::manifest() {
        eprintln!(
            "{}",
            json!({"verdict":"FAIL","command":"nexusd","stage":"outbound_manifest","error":{"code":"CONFIG","message":nexus::redact::sanitize(&error.to_string())}})
        );
        return ExitCode::from(1);
    }
    let outbound_surface = nexus::outbound_manifest::startup_surface(loaded.proxy_yaml.as_deref());
    for line in &outbound_surface.lines {
        eprintln!("{line}");
    }
    nexus::outbound_manifest::install_surface(
        &outbound_surface,
        &config_sha1(loaded.proxy_yaml.as_deref()),
    );
    publish_engine_state(loaded.daemon.tun.enabled);

    // F1：orphan FUSE 挂载收敛进 boot_reconcile 统一报告。挂载点在 reconcile
    // 之前解析，与 WorkspaceManager::start 共用 resolve_mountpoints，保证一致。
    // 解析失败 → warn + 空集合（WorkspaceManager::start 稍后会以相同的
    // fail-fast 语义退出，保持现有行为不变）。
    #[cfg(target_os = "linux")]
    let orphan_mountpoints: Vec<std::path::PathBuf> = match loaded.workspace_toml.as_deref() {
        Some(text) => {
            match nexusd::workspace::WorkspaceManager::resolve_mountpoints(&config_root, text) {
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
    // 真正持有实例（D1 落地）＋周期性 sweep_detached（P1-2）。
    ensure_n2_session_manager(&dir.root);
    let n2_sweeper_handle = spawn_n2_session_sweeper(&shutdown);

    // T3: a validated managed provider is also an effective subsystem.
    if no_other_subsystem && !managed_provider {
        eprintln!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"CONFIG\",\"message\":\"no subsystem configured: need proxy.yaml and/or network.toml and/or workspace.toml\"}}}}"
        );
        return ExitCode::from(1);
    }

    // T4：发布 tun_enabled 状态供 LocalAPI 查询。
    publish_tun_enabled(loaded.daemon.tun.enabled);
    let takeover_mode = loaded
        .proxy_yaml
        .as_deref()
        .and_then(|yaml| nexus_proxy_config::parse(yaml).ok())
        .map(|config| {
            let has_system_inbound = config.inbounds.iter().any(|inbound| {
                matches!(
                    inbound.kind,
                    nexus_proxy_config::InboundKind::Tun | nexus_proxy_config::InboundKind::Tproxy
                )
            });
            if has_system_inbound || loaded.daemon.tun.enabled {
                "system-level"
            } else {
                "resource-level"
            }
        })
        .unwrap_or(if loaded.daemon.tun.enabled {
            "system-level"
        } else {
            "resource-level"
        });
    // 2. 组装 DataplaneConfig（R2/R3；dns.toml 解析失败 → exit 1）。
    let dataplane_config = match assembly::build_dataplane_config(&loaded) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", config_load_failure_json(&e.to_string(), Some(&dir)));
            return ExitCode::from(1);
        }
    };

    // T4b：发布 takeover/ingress + IPv6 能力表（N-8：地址族由能力表派生，
    // 不再硬编码 "ipv4" 而与 ipv6_paths 自相矛盾）。
    let ipv6_paths =
        nexusd::dataplane::Ipv6Paths::from_capabilities(!dataplane_config.mesh_cidrs6.is_empty());
    nexusd::dataplane::publish_runtime_basics(takeover_mode, ipv6_paths);
    eprintln!("[nexusd] IPv6 capability table: {}", ipv6_paths.summary());

    // 3. R1：装配 N1 网桥 + 单一 discovery hub（失败 → 降级，dataplane 照常跑）。
    //
    // 本段是进程内**唯一**的 N1/hub 装配点（spec §4.10.2）：hub、sessions、
    // static_peers 与权威 N1Config 都由 `N1Assembly` 提供，NAT/发现段不再二次解析。
    let discovery_section = loaded.daemon.discovery.clone();
    // One resolved address, one source label: the summary below is the only
    // operator-facing statement of what will actually be advertised.
    let (advertise_ip, advertise_source) = match discovery_section.advertise_ip {
        Some(ip) => (Some(ip), "config"),
        None => (discovery_runtime::select_advertise_ipv4(), "auto"),
    };
    eprintln!(
        "{}",
        discovery_runtime::production_summary(&discovery_section, advertise_ip, advertise_source)
    );
    let discovery_params = nexus::network::DiscoveryParams {
        mdns: match (discovery_section.mdns, advertise_ip) {
            (true, Some(ip)) => Some(nexus::network::MdnsParams {
                // CR-BLOCKED-1: SRV carries the discovery/gossip endpoint.
                service_port: discovery_section.gossip_port,
                announce_ip: ip,
            }),
            _ => None,
        },
        lsa_stale_after: Duration::from_secs(discovery_section.lsa_stale_sec),
    };
    let n1_assembly: Option<assembly::N1Assembly> = match loaded.network_toml.as_deref() {
        Some(text) => {
            match assembly::assemble_n1_with_discovery(
                text,
                loaded.daemon.proxy.as_ref(),
                Arc::clone(&shutdown),
                discovery_params,
            ) {
                Ok(assembly) => Some(assembly),
                Err(e) => {
                    eprintln!(
                        "[nexusd] ERROR: N1 assembly failed ({e}); degraded (mesh packets counted, not sent)"
                    );
                    None
                }
            }
        }
        None => None,
    };
    let n1_bridge: Option<Arc<nexus_network::n1::bridge::N1MeshBridge>> =
        n1_assembly.as_ref().map(|a| Arc::clone(&a.bridge));
    let n1_sender: Option<Arc<dyn nexus_network::n1::bridge::N1Sender>> = n1_bridge
        .clone()
        .map(|b| b as Arc<dyn nexus_network::n1::bridge::N1Sender>);

    // 3b. 发现 pump：即使没有 `[network.turn]` 也启动（发现/状态面独立，
    // 启动顺序冻结：装配 → DiscoveryRuntime::start → NatSwitchRuntime::start）。
    let discovery_handle = match n1_assembly.as_ref() {
        Some(assembly) if discovery_section.enabled => {
            let static_gossip_addrs: Vec<std::net::SocketAddr> = assembly
                .config
                .peers
                .iter()
                .flat_map(|p| {
                    p.addrs.iter().map(|addr| {
                        std::net::SocketAddr::new(addr.ip(), discovery_section.gossip_port)
                    })
                })
                .collect();
            // CAP_RELAY is advertised when the daemon is configured to relay;
            // the authoritative identity check stays fail-closed at NAT start.
            let mut capabilities = nexus_discovery::lsa::CAP_TUN;
            if loaded.daemon.punch.enabled
                && loaded.daemon.punch.relay_provider_enabled
                && loaded.daemon.identity.seed_file.is_some()
            {
                capabilities |= nexus_discovery::lsa::CAP_RELAY;
            }
            let incarnation = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
                .max(1);
            let self_lsa = discovery_runtime::SelfLsaConfig {
                node_id: nexus_discovery::PeerId(assembly.config.peer_id.to_hex()),
                vip: assembly.config.vpi.address.to_string(),
                capabilities,
                incarnation,
            };
            let cfg = discovery_runtime::production_config(
                &discovery_section,
                advertise_ip,
                static_gossip_addrs,
            );
            Some(discovery_runtime::DiscoveryRuntime::start(
                Arc::clone(&assembly.discovery),
                cfg,
                self_lsa,
                Arc::clone(&shutdown),
            ))
        }
        _ => None,
    };
    if let Some(handle) = &discovery_handle {
        nexusd::nat_status::publish_discovery_status(handle.status());
    }
    if let Some(assembly) = n1_assembly.as_ref() {
        nexusd::nat_status::publish_discovery_hub(Arc::clone(&assembly.discovery));
    }

    // 4. 统一数据面线程（D1：单个 TUN 由 nexusd 持有；TUN 创建失败则线程内降级）。
    //    T2：[tun].enabled=false 时跳过 TUN/数据面（no-tun 模式）。
    let tun_name = loaded.daemon.tun.name.clone();
    let tun_mtu = loaded.daemon.tun.mtu;
    let proxy_yaml = loaded.proxy_yaml.clone();
    let network_toml = loaded.network_toml.clone();
    let flow_sessions_mode = loaded
        .daemon
        .flow_sessions
        .enabled
        .unwrap_or(nexus_proxy_config::FlowSessionsMode::Auto);
    let tun_default_route = loaded.daemon.tun.default_route;
    let parsed_proxy = loaded
        .proxy_yaml
        .as_deref()
        .and_then(|yaml| nexus_proxy_config::parse(yaml).ok());
    let tproxy_inbound = parsed_proxy.as_ref().and_then(|config| {
        config
            .inbounds
            .iter()
            .find(|inbound| inbound.kind == nexus_proxy_config::InboundKind::Tproxy)
            .map(|inbound| (inbound.listen.clone(), inbound.tproxy.clone()))
    });
    let has_tproxy = tproxy_inbound.is_some();
    // S28：exclude_server_routes=true 时从 proxy outbounds locator 收集 IP → /32。
    let tun_excludes: Vec<([u8; 4], u8)> = if loaded.daemon.tun.exclude_server_routes {
        loaded
            .proxy_yaml
            .as_deref()
            .and_then(|yaml| nexus_proxy_config::parse(yaml).ok())
            .map(|config| {
                config
                    .outbounds
                    .iter()
                    .filter_map(|outbound| outbound.locator.as_deref())
                    .filter_map(|locator| {
                        let host = locator.rsplit_once(':').map(|(h, _)| h).unwrap_or(locator);
                        host.parse::<std::net::Ipv4Addr>().ok()
                    })
                    .map(|ip| (ip.octets(), 32))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    // S24：数据面规则引擎来自同一份 proxy.yaml；构造失败 → 启动失败（fail-fast，
    // 不得静默回落到把全部流量送往 `proxy` 的默认引擎）。
    // 此接线由 dataplane_rule_engine_assembly_tests 装配回归测试钉住；
    // 删改接线（如改传 None）时必须同步更新该测试。
    let rule_engine = if tun_enabled() || has_tproxy {
        match build_dataplane_rule_engine(parsed_proxy.as_ref()) {
            Ok(engine) => engine,
            Err(e) => {
                // §12.2-C：stage 按阶段定死（rule_engine_init），message 脱敏。
                eprintln!(
                    "{}",
                    json!({
                        "verdict": "FAIL",
                        "command": "nexusd",
                        "stage": "rule_engine_init",
                        "error": {
                            "code": "CONFIG",
                            "message": nexus::redact::sanitize(&e),
                        }
                    })
                );
                return ExitCode::from(1);
            }
        }
    } else {
        None
    };
    // D1（spec §3.3 步骤 4）：spawn 之前构造；硬失败在此返回 exit 1（不 process::exit）。
    let (proxy_engine, outbound_registry) = match build_proxy_engine_for_startup(
        loaded.proxy_yaml.as_deref(),
        tun_enabled(),
        has_tproxy,
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    // NAT chunk consumer scaffolding (P0 §3.1.3): the slot and the single
    // monotonic PunchClock are created before the dataplane thread starts. The
    // slot stays empty until the NAT runtime is up (all chunks fallback in the
    // meantime, which is the honest degraded mode).
    let punch_clock: Arc<dyn nexus_nat_traversal::PunchClock> =
        Arc::new(nexus_nat_wireup::SystemPunchClock::new());
    let nat_slot = nexusd::nat_consumer::NatHandleSlot::new();
    // Consumed by the direct-stream receiver spawned in the next commit;
    // created here so the composition root owns one shared clock.
    let direct_gate = Arc::new(nexusd::nat_chunk_recv::DirectGate::new(Arc::clone(
        &punch_clock,
    )));
    let chunk_stats = Arc::new(nexusd::nat_chunk_stats::ChunkStats::default());
    nexusd::nat_chunk_stats::publish_chunk_stats(Arc::clone(&chunk_stats));
    nexusd::nat_chunk_stats::publish_nat_slot_for_status(nat_slot.clone());
    let peer_map: Arc<dyn nexusd::mesh_peer_map::MeshPeerResolver> = Arc::new(
        nexusd::mesh_peer_map::StaticMeshPeerMap::from_toml(loaded.network_toml.as_deref()),
    );
    let (nat_tx, nat_rx) = std::sync::mpsc::sync_channel::<nexusd::nat_chunk_recv::NatInboundChunk>(
        nexusd::nat_chunk_recv::NAT_INBOUND_QUEUE_CAP,
    );
    let dp_nat_slot = nat_slot.clone();
    let dp_peer_map = Arc::clone(&peer_map);
    let dp_direct_gate = Arc::clone(&direct_gate);
    let dp_chunk_stats = Arc::clone(&chunk_stats);
    let dataplane_handle = if tun_enabled() || has_tproxy {
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
                        rule_engine,
                        proxy_engine,
                        outbound_registry,
                        proxy_yaml,
                        network_toml,
                        flow_sessions_mode,
                        tun_default_route,
                        tun_excludes,
                        tproxy_inbound
                            .as_ref()
                            .and_then(|(_, tproxy)| tproxy.clone()),
                        tproxy_inbound
                            .as_ref()
                            .map(|(listen, _)| listen.clone())
                            .unwrap_or_else(|| "0.0.0.0:7895".to_string()),
                        dp_nat_slot,
                        dp_peer_map,
                        dp_direct_gate,
                        nat_rx,
                        dp_chunk_stats,
                    );
                })
                .expect("spawn dataplane thread"),
        )
    } else {
        eprintln!("[nexusd] tun disabled; dataplane not started (no-tun mode)");
        None
    };

    // 4b. P0：direct chunk 接收端（supervisor + per-(peer,conn) acceptor）。
    // slot 空时轮询等待；与 dataplane 的 slot 共享同一实例。
    match nexusd::nat_chunk_recv::spawn_nat_chunk_receiver(
        nat_slot.clone(),
        Arc::clone(&direct_gate),
        nat_tx,
        Arc::clone(&chunk_stats),
        Arc::clone(&shutdown),
    ) {
        Ok(_handle) => {}
        Err(e) => eprintln!("[nat-consumer] WARN: chunk receiver spawn failed ({e})"),
    }

    // 5. LocalAPI 线程（R4：可经 shutdown 标志停止）。
    let localapi_addr = loaded.daemon.localapi_addr.clone();
    let task_config_root = dir.root.clone();
    let (ready_tx, ready_rx) = channel();
    let api_shutdown = Arc::clone(&shutdown);
    let localapi_handle = std::thread::Builder::new()
        .name("nexusd-localapi".to_string())
        .spawn(move || {
            serve_localapi(
                &localapi_addr,
                ready_tx,
                api_shutdown,
                &task_config_root,
                snapshots,
            );
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
        match nexusd::workspace::WorkspaceManager::start(&config_root, text) {
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

    // 5.6. NAT switching daemon runtime（AC5）：TURN 生命周期 + STUN 采样 + 打洞决策。
    //      `[network.turn]` 配置存在时启动后台 worker（daemon 共享 shutdown 标志，
    //      收到 SIGTERM/SIGINT 后协作式退出）；启动/绑定失败 → WARN + 降级，
    //      不阻断进程，LocalAPI 照常服务（诚实边界见 `NatSwitchRuntime` 文档）。
    //
    // C1：权威 fabric 身份来自 `N1Assembly.config`（本 run 唯一的 N1Config
    // 副本，不再二次解析 network.toml）；punch `Driver` 也在组合根创建。
    // 装配缺失 → WARN + 跳过 nat-switch（无权威身份时打洞无法关联 offer）。
    let punch_section = loaded.daemon.punch.clone();
    let identity_section = loaded.daemon.identity.clone();
    let turn_section = loaded.daemon.turn.clone();
    let nat_switch_handle = match turn_section.as_ref() {
        None => None,
        Some(section) => match (|| -> Result<Option<std::thread::JoinHandle<()>>, ExitCode> {
            let Some(n1) = n1_assembly.as_ref() else {
                eprintln!(
                    "[nat-switch] WARN: network.toml absent or unparsed; nat-switch disabled (no authoritative fabric identity)"
                );
                return Ok(None);
            };
            let my_id = FabricPeerId(n1.config.peer_id.0);
            // BLOCKED-1 ruling (a): the relay provider needs the daemon's fabric
            // identity. There is no ed25519 seed in the node identity store, so
            // the seed comes from `[network.identity].seed_file` and MUST match
            // the configured `peer_id`. Mismatch/missing => fail-closed.
            let identity = if punch_section.enabled && punch_section.relay_provider_enabled {
                let Some(path) = identity_section.seed_file.as_deref() else {
                    eprintln!(
                        "[nat-identity] ERROR: identity mismatch: no [network.identity].seed_file configured; refusing to start (fail-closed)"
                    );
                    return Err(ExitCode::FAILURE);
                };
                let seed = match nexusd::nat_relay::load_seed_file(std::path::Path::new(path)) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[nat-identity] ERROR: {e}; refusing to start (fail-closed)");
                        return Err(ExitCode::FAILURE);
                    }
                };
                match nexusd::nat_relay::identity_from_seed(seed, my_id) {
                    Ok(id) => Some(id),
                    Err(e) => {
                        eprintln!(
                            "[nat-identity] ERROR: identity mismatch: {e}; refusing to start (fail-closed)"
                        );
                        return Err(ExitCode::FAILURE);
                    }
                }
            } else {
                None
            };
            let driver = match Driver::new_server("0.0.0.0:0".parse().expect("0.0.0.0:0 parses")) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!(
                        "[nat-switch] WARN: fabric driver bind failed ({e}); nat-switch disabled, punch disabled"
                    );
                    return Ok(None);
                }
            };
            Ok(NatSwitchRuntime::start(
                section,
                Arc::clone(&shutdown),
                driver,
                my_id,
                identity,
                &discovery_section,
                Some(Arc::clone(&n1.discovery)),
                Some(Arc::clone(&n1.sessions)),
                n1.static_peers.clone(),
                nat_slot.clone(),
                Arc::clone(&punch_clock),
            ))
        })() {
            Ok(handle) => handle,
            Err(code) => return code,
        },
    };

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
                // §7.6.2：只对 Hot 文件宣告「已生效」；proxy.yaml 走 NeedsRestart。
                eprintln!("[nexusd] config applied: {files:?}");
                if files.iter().any(|f| f == config::PROXY_YAML) {
                    log_stale_line(refresh_proxy_file_side(&dir, None));
                }
            }
            Ok(watcher::ReloadEvent::NeedsRestart { files, reason }) => {
                eprintln!("[nexusd] WARN: {reason}");
                if files.iter().any(|f| f == config::PROXY_YAML) {
                    // §12.1：active/file 对照 + stale=true（磁盘改了但未生效）。
                    log_stale_line(refresh_proxy_file_side(&dir, None));
                }
            }
            Ok(watcher::ReloadEvent::Rejected { error }) => {
                // 写点 3：打印点再脱敏（幂等；双写点漏网防护）。
                eprintln!(
                    "[nexusd] ERROR: config reload rejected: {} (keeping old config)",
                    nexus::redact::redact_secrets(&error)
                );
                // R2-F12/PR2R1-02：拒绝后按磁盘现状刷新 file 侧，避免观测面继续
                // 报「文件与 active 同步」；proxy.yaml 自身解析失败才标 file_rejected。
                let _ = refresh_proxy_file_side(&dir, Some(&error));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("[nexusd] WARN: config watcher channel closed");
            }
        }
    }

    // 8. R4：优雅关闭（§13.4 反向顺序，超时强制继续）。
    shutdown_sequence(
        localapi_handle,
        dataplane_handle,
        n1_bridge,
        n2_sweeper_handle,
        discovery_handle,
        nat_switch_handle,
        &state_dir,
    );
    ExitCode::from(0)
}

/// R4：优雅关闭序列（§13.4）。
///
/// 顺序：LocalAPI → N2 sweeper → discovery pump（1s）→ NAT switch（5s，
/// 内部 feed → switch → turn）→ Workspace unmount（D7）→ Dataplane（1s）→
/// N1（5s）→ TUN（随 dataplane 线程退出）。
/// 任一步超时 → warn 日志后强制继续，不无限等。
fn shutdown_sequence(
    localapi_handle: std::thread::JoinHandle<()>,
    dataplane_handle: Option<std::thread::JoinHandle<()>>,
    n1_bridge: Option<Arc<nexus_network::n1::bridge::N1MeshBridge>>,
    n2_sweeper_handle: Option<std::thread::JoinHandle<()>>,
    discovery_handle: Option<nexusd::discovery_runtime::DiscoveryRuntimeHandle>,
    nat_switch_handle: Option<std::thread::JoinHandle<()>>,
    state_dir: &std::path::Path,
) {
    eprintln!("[nexusd] shutdown: stopping LocalAPI");
    // LocalAPI 线程已通过 shutdown 标志退出 accept 循环；join 确认。
    assembly::join_with_timeout(localapi_handle, Duration::from_secs(2), "localapi");

    // P1-1：N2 SessionManager 的唯一持有者（sweeper 线程）确认结束。
    if let Some(handle) = n2_sweeper_handle {
        assembly::join_with_timeout(handle, Duration::from_secs(2), "n2-session-sweeper");
    }

    // 发现 pump 先停：它的 socket 线程只读 hub，先于 NAT 订阅面退出。
    if let Some(handle) = discovery_handle {
        eprintln!("[nexusd] shutdown: stopping discovery pump");
        handle.join(Duration::from_secs(1));
    }

    // AC5：NAT switching worker 共享 daemon shutdown 标志（协作式退出），
    // 但 TURN/STUN socket 是网络资源，优先于数据面释放（5s 超时强制继续）。
    if let Some(handle) = nat_switch_handle {
        eprintln!("[nexusd] shutdown: stopping nat-switch");
        assembly::join_with_timeout(handle, Duration::from_secs(5), "nat-switch");
    }

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
    let mut enabled: Vec<String> = Vec::new();
    if cfg.network_toml.is_some() {
        enabled.push("network (N1 mesh)".to_string());
    }
    if cfg.proxy_yaml.is_some() {
        enabled.push("proxy".to_string());
    }
    if let Some(p) = cfg.daemon.proxy.as_ref() {
        // #3：只报协议与服务器地址，密码永不落日志（AC3）。
        enabled.push(format!(
            "network.proxy ({} @ {})",
            p.proxy_type.as_str(),
            p.server
        ));
    }
    if cfg.dns_toml.is_some() {
        enabled.push("dns".to_string());
    }
    if cfg.daemon.turn.is_some() {
        enabled.push("nat-switch (TURN relay)".to_string());
        eprintln!(
            "[nexusd] nat-stun: probe timeout {}s, refresh interval {}s",
            nat_stun::STUN_PROBE_TIMEOUT.as_secs(),
            nat_stun::STUN_REFRESH_INTERVAL.as_secs()
        );
    }
    if enabled.is_empty() {
        eprintln!("[nexusd] no subsystem configured (empty config dir); LocalAPI only");
    } else {
        eprintln!("[nexusd] subsystems configured: {}", enabled.join(", "));
    }
    eprintln!("[nexusd] localapi_addr={}", cfg.daemon.localapi_addr);
    if cfg.daemon.turn.is_none() {
        eprintln!("[nat-switch] turn unconfigured, punch disabled");
    }
}

/// P1-15：单连接读写超时。`handle_localapi_request` 逐行读 request line /
/// headers，旧行为下"连上不发换行"的客户端会永久占住控制面（TCP 与 unix
/// socket 都中招）。设置失败只告警——超时机制本身不阻断服务。
const LOCALAPI_IO_TIMEOUT: Duration = Duration::from_secs(5);

macro_rules! apply_localapi_io_timeouts {
    ($stream:expr) => {{
        if let Err(e) = $stream.set_read_timeout(Some(LOCALAPI_IO_TIMEOUT)) {
            eprintln!("[nexusd] localapi set_read_timeout: {e}");
        }
        if let Err(e) = $stream.set_write_timeout(Some(LOCALAPI_IO_TIMEOUT)) {
            eprintln!("[nexusd] localapi set_write_timeout: {e}");
        }
    }};
}

/// LocalAPI 服务（后台线程版；复用既有 serve 逻辑，READY 经 channel 上报）。
/// LocalAPI 服务（后台线程版；R4：经 shutdown 标志可停止）。
///
/// 非阻塞 accept + 100ms 轮询，关闭信号置位后退出循环。
fn serve_localapi(
    addr_raw: &str,
    ready_tx: std::sync::mpsc::Sender<String>,
    shutdown: Arc<AtomicBool>,
    config_root: &std::path::Path,
    snapshots: nexusd::snapshot_service::LocalSnapshotService,
) {
    if validate_task_provider_startup(config_root).is_err() {
        return;
    }
    let sessions = ensure_n2_session_manager(config_root);
    let tasks = nexusd::task_service::LocalTaskService::open_with_sessions(config_root, sessions);
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
    let token = match assembly::load_localapi_token(config_root) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[nexusd] localapi bearer token unavailable: {e}");
            return;
        }
    };
    let token_authority = nexusd::task_http::TokenAuthority::open_at(
        &token,
        assembly::localapi_token_path(config_root),
    );
    if validate_token_authority(&token_authority).is_err() {
        return;
    }
    let _ = ready_tx.send(actual);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            eprintln!("[nexusd] localapi: shutdown signal, exiting");
            break;
        }
        match listener.accept() {
            Ok((mut s, _)) => {
                apply_localapi_io_timeouts!(s);
                if let Err(e) = handle_localapi_request(
                    &mut s,
                    &token,
                    addr.ip().is_loopback(),
                    &tasks,
                    &snapshots,
                    &token_authority,
                ) {
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
    // P1-1：`serve` 形态也必须持有 daemon 内唯一的 N2 SessionManager，否则
    // `/localapi/v0/n2/session/*` 会报 N2_UNAVAILABLE（D1 只在 `run_daemon`
    // 路径装配）。token 与 N2 存储同源于 node_dir，这里沿用同一口径。
    let config_root = match task_config_root() {
        Ok(root) => root,
        Err(exit) => return exit,
    };
    let managed = match validate_task_provider_startup(&config_root) {
        Ok(managed) => managed,
        Err(exit) => return exit,
    };
    let snapshots = match open_snapshot_service(&config_root) {
        Ok(snapshots) => snapshots,
        Err(exit) => return exit,
    };
    if managed {
        let loaded = ConfigDir::new(&config_root).and_then(|dir| config::load(&dir));
        match loaded {
            Ok(loaded)
                if loaded.meta.contains_key(config::DAEMON_TOML) && !loaded.daemon.tun.enabled => {}
            _ => {
                eprintln!(
                    "{}",
                    json!({"verdict":"FAIL", "error":{"code":"CONFIG", "message":"managed provider serve requires explicit daemon.toml [tun] enabled=false"}})
                );
                return ExitCode::from(1);
            }
        }
    }
    match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => serve_over_tcp(raw, &config_root, snapshots),
        None => match flags.get("--socket").and_then(|v| v.as_deref()) {
            Some(path) => serve_over_socket(path, &config_root, snapshots),
            // D8（N2 P0-1）：默认 unix socket（与 CLI `default_socket_path` 一致）。
            // P1-15：socket 路径必须来自 `$XDG_RUNTIME_DIR`（0700、per-user、
            // 不可预测）；未设置时**不**回落到可预测的 `/tmp` 路径，改用 TCP
            // loopback 并告警（bearer token 仍是唯一屏障）。
            #[cfg(unix)]
            None => match nexus::localapi_client::default_socket_path() {
                Some(sock) => {
                    serve_over_socket(&sock.display().to_string(), &config_root, snapshots)
                }
                // P1-15：无安全的 socket 目录 → 回退 TCP loopback（而不是
                // 落到世界可写、可被抢占的 temp socket）。
                None => {
                    eprintln!(
                        "[nexusd] WARN: no safe unix socket dir; falling back to TCP loopback {}",
                        nexus::localapi_client::DEFAULT_LOCALAPI_ADDR
                    );
                    serve_over_tcp(
                        nexus::localapi_client::DEFAULT_LOCALAPI_ADDR,
                        &config_root,
                        snapshots,
                    )
                }
            },
            #[cfg(not(unix))]
            None => serve_over_tcp("127.0.0.1:0", &config_root, snapshots),
        },
    }
}

/// 加载 LocalAPI bearer token；失败则打印结构化 FAIL 并返回 Err(ExitCode)。
fn localapi_bearer_token(config_root: &std::path::Path) -> Result<String, ExitCode> {
    assembly::load_localapi_token(config_root).map_err(|e| {
        println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"TOKEN_SETUP\",\"message\":\"bearer token: {e}\"}}}}"
        );
        ExitCode::SUCCESS
    })
}

/// TCP loopback 监听 + 服务循环（既有行为）。
fn serve_over_tcp(
    addr_raw: &str,
    config_root: &std::path::Path,
    snapshots: nexusd::snapshot_service::LocalSnapshotService,
) -> ExitCode {
    let sessions = ensure_n2_session_manager(config_root);
    let tasks = nexusd::task_service::LocalTaskService::open_with_sessions(config_root, sessions);
    let token = match localapi_bearer_token(config_root) {
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
    let token_authority = nexusd::task_http::TokenAuthority::open_at(
        &token,
        assembly::localapi_token_path(config_root),
    );
    if let Err(exit) = validate_token_authority(&token_authority) {
        return exit;
    }
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"addr\":\"{actual_addr}\"}}}}"
    );
    {
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
    }
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                apply_localapi_io_timeouts!(stream);
                if let Err(e) = handle_localapi_request(
                    &mut stream,
                    &token,
                    addr.ip().is_loopback(),
                    &tasks,
                    &snapshots,
                    &token_authority,
                ) {
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

#[cfg(unix)]
fn serve_over_socket(
    path: &str,
    config_root: &std::path::Path,
    snapshots: nexusd::snapshot_service::LocalSnapshotService,
) -> ExitCode {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let sessions = ensure_n2_session_manager(config_root);
    let tasks = nexusd::task_service::LocalTaskService::open_with_sessions(config_root, sessions);
    let private_parent = std::path::Path::new(path)
        .parent()
        .and_then(|p| std::fs::symlink_metadata(p).ok())
        .is_some_and(|m| {
            m.is_dir() && !m.file_type().is_symlink() && m.permissions().mode() & 0o077 == 0
        });
    let token = match localapi_bearer_token(config_root) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let token_authority = nexusd::task_http::TokenAuthority::open_at(
        &token,
        assembly::localapi_token_path(config_root),
    );
    if let Err(exit) = validate_token_authority(&token_authority) {
        return exit;
    }
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
    // P1-15：socket 建成后立刻收紧为 0600（umask 只能做减法，默认往往
    // 落在 0755/0777——同机其他用户就能连上拿 bearer token）。失败即
    // fail-closed：宁可不提供控制面，也不留一个可被冒充的 socket。
    if let Err(e) = harden_socket_permissions(path) {
        println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
        );
        let _ = std::fs::remove_file(path);
        return ExitCode::SUCCESS;
    }
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"socket\":\"{path}\"}}}}"
    );
    {
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
    }
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                apply_localapi_io_timeouts!(stream);
                if let Err(e) = handle_localapi_request(
                    &mut stream,
                    &token,
                    private_parent,
                    &tasks,
                    &snapshots,
                    &token_authority,
                ) {
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

/// P1-15：把 unix socket 文件收紧为仅属主可读写（0600）。
#[cfg(unix)]
fn harden_socket_permissions(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 socket {path}: {e}"))
}

#[cfg(windows)]
fn serve_over_socket(
    path: &str,
    config_root: &std::path::Path,
    snapshots: nexusd::snapshot_service::LocalSnapshotService,
) -> ExitCode {
    println!(
        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"message\":\"named-pipe not implemented; use --addr\"}}}}"
    );
    let _ = (path, config_root, snapshots);
    ExitCode::SUCCESS
}

use nexusd::task_http::HttpIo as LocalIo;

fn task_config_root() -> Result<std::path::PathBuf, ExitCode> {
    // Give N2, token setup and Task adapters one lexical startup root.
    // Preflight still rejects managed symlinks and parent components.
    std::path::absolute(nexus::node_cli::node_dir()).map_err(|error| {
        eprintln!(
            "{}",
            json!({"verdict":"FAIL", "error":{"code":"CONFIG", "message":error.to_string()}})
        );
        ExitCode::from(1)
    })
}

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

fn handle_localapi_request(
    stream: &mut dyn LocalIo,
    expected_token: &str,
    local_transport: bool,
    tasks: &nexusd::task_service::LocalTaskService,
    snapshots: &nexusd::snapshot_service::LocalSnapshotService,
    token_authority: &nexusd::task_http::TokenAuthority,
) -> Result<(), String> {
    let Some(head) = nexusd::task_http::dispatch_with_snapshots(
        stream,
        expected_token,
        local_transport,
        tasks,
        snapshots,
        token_authority,
    )?
    else {
        return Ok(());
    };
    let request_line = head.request_line;
    let headers = head.headers;
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
    if path == "/localapi/v0/connectivity/nat" {
        match nexusd::nat_status::connectivity_nat() {
            Ok(v) => write_http_json(stream, 200, &v).map_err(|e| e.to_string())?,
            Err(e) => {
                let status = if matches!(e, nexus_domain::NexusError::NatStatusUnavailable { .. }) {
                    503
                } else {
                    200
                };
                let body = json!({
                    "verdict": "FAIL",
                    "error": {"code": nexus::error_code(&e), "message": e.to_string()}
                });
                write_http_json(stream, status, &body).map_err(|err| err.to_string())?;
            }
        }
        return Ok(());
    }
    let result: Result<Value, (String, String)> = match path {
        "/localapi/v0/status" => nexus::observability::status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/dataplane/stats" => {
            // B1 / S30：统一数据面统计（D6 可观测，spec §9.16）。
            let s = nexusd::dataplane::dataplane_stats_snapshot();
            let status = nexusd::dataplane::runtime_status_snapshot();
            let tproxy = nexusd::dataplane::tproxy_status_json();
            let (outbound, outbound_error) = nexus::outbound_manifest::runtime_outbound_json();
            let mut body =
                nexusd::dataplane::dataplane_stats_json(tun_enabled(), &status, &s, tproxy);
            // 五载体（§7.7 载体 4）：顶层 `outbound` 块与 `nexus status` 同一序列化。
            body["outbound"] = outbound;
            body["interop_warnings"] = nexus::outbound_manifest::interop_warning_counts().to_json();
            if let Some(error) = outbound_error {
                body["outbound_error"] = error;
            }
            Ok(body)
        }
        "/localapi/v0/dns/status" => {
            let snapshot = nexusd::dns_status::snapshot()
                .unwrap_or_else(nexusd::dns_status::DnsStatusSnapshot::disabled);
            let mut body = snapshot.to_json();
            body["verdict"] = json!("PASS");
            Ok(body)
        }
        "/localapi/v0/dns/cache" => {
            let entries = nexusd::dns_status::cache_entries();
            let mut cache = Vec::new();
            let mut negative_cache = Vec::new();
            for entry in entries {
                let value = json!({
                    "name": entry.name,
                    "qtype": entry.qtype,
                    "expires_at_ms": entry.expires_at_ms,
                    "rcode": entry.rcode,
                });
                if entry.negative {
                    negative_cache.push(value);
                } else {
                    cache.push(value);
                }
            }
            Ok(json!({
                "verdict": "PASS",
                "enabled": nexusd::dns_status::snapshot().map(|s| s.enabled).unwrap_or(false),
                "cache": cache,
                "negative_cache": negative_cache,
            }))
        }
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
    use super::{LOCALAPI_IO_TIMEOUT, N2_SESSION_SWEEP_INTERVAL_SECS, parse_flags};

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

/// P1-15：控制面加固回归。
#[cfg(all(test, unix))]
mod p1_15_localapi_hardening_tests {
    use super::{LOCALAPI_IO_TIMEOUT, harden_socket_permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    #[test]
    fn socket_hardening_tightens_mode_to_owner_only() {
        // bind 后必须 0600：umask 只做减法，默认常落在 0755/0777，
        // 同机其他用户就能连上拿 bearer token。
        let path = std::env::temp_dir().join(format!("nexusd-sock-hard-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();

        harden_socket_permissions(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // 失败路径：不存在的文件 → Err（调用方据此 fail-closed）。
        assert!(
            harden_socket_permissions("/nonexistent/nexus-sock").is_err(),
            "missing socket must fail closed, not silently succeed"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn localapi_io_timeout_is_bounded() {
        // "连上不发换行"不得永久挂住控制面：超时必须有限。
        assert!(LOCALAPI_IO_TIMEOUT > Duration::ZERO);
        assert!(
            LOCALAPI_IO_TIMEOUT <= Duration::from_secs(30),
            "must be a real bound, got {:?}",
            LOCALAPI_IO_TIMEOUT
        );
    }
}

/// 装配级回归（P3）：规则引擎必须由生产装配路径注入数据面。
///
/// 本缺陷的形态是“单测全绿、生产从未接线”：因此这里跨过 `run_dataplane` 使用的
/// 两个装配步骤（`build_dataplane_rule_engine` → `assemble_dataplane`），
/// 直接对装配出的 `Dataplane` 断言分类结果。
#[cfg(test)]
mod dataplane_rule_engine_assembly_tests {
    use super::{assemble_dataplane, build_dataplane_rule_engine};
    use nexus_projection::{MockTun, TunDevice};
    use nexusd::dataplane::DataplaneConfig;
    use std::sync::{Arc, Mutex};

    const DIRECT_MATCH_YAML: &str = "\
schema_version: 1
inbounds:
  - tag: tp-in
    kind: tproxy
    listen: 0.0.0.0:7895
    backend: iptables
rules:
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
";

    struct SharedTun(Arc<Mutex<MockTun>>);

    impl TunDevice for SharedTun {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(buf)
        }
        fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(packet)
        }
        fn name(&self) -> &str {
            "test0"
        }
    }

    fn craft_udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
        pkt
    }

    fn assemble(proxy_yaml: Option<&str>) -> (nexusd::dataplane::Dataplane, Vec<u8>) {
        let proxy = proxy_yaml.map(|yaml| nexus_proxy_config::parse(yaml).expect("proxy.yaml"));
        let engine = build_dataplane_rule_engine(proxy.as_ref()).expect("rule engine");
        let mock = Arc::new(Mutex::new(MockTun::new("test0")));
        let mut dp = assemble_dataplane(
            Box::new(SharedTun(Arc::clone(&mock))),
            DataplaneConfig::default(),
            engine,
            None,
        )
        .expect("assemble dataplane");
        let pkt = craft_udp([10, 200, 1, 2], [203, 0, 113, 7], 32_890, 8080);
        mock.lock().unwrap().inject(pkt.clone());
        assert!(dp.process_one().expect("process_one"));
        (dp, pkt)
    }

    #[test]
    fn config_rule_engine_directs_flow_in_assembled_dataplane() {
        // S1 的 proxy.yaml：MATCH -> direct。旧缺陷下分类走默认引擎 → Proxy("proxy")。
        let (mut dp, pkt) = assemble(Some(DIRECT_MATCH_YAML));
        let outbound = dp.cached_outbound(&pkt).expect("decision cached");
        assert_eq!(
            outbound, "self",
            "config MATCH->direct must classify as direct, not Proxy(proxy)"
        );
    }

    #[test]
    fn no_config_uses_explicit_default_engine() {
        // 无 proxy.yaml 是显式保留的唯一默认路径（装配层记录 warn 日志）。
        let (mut dp, pkt) = assemble(None);
        let outbound = dp.cached_outbound(&pkt).expect("decision cached");
        assert_eq!(outbound, "proxy");
    }
}

/// S7：脱敏 parity（daemon 启动行 / CLI `config check` detail 同一份实现）。
#[cfg(test)]
mod redact_parity_tests {
    use super::config_load_failure_json;
    use nexusd::config::ConfigDir;

    const MARKER: &str = "r2f3redactmarker9a1b";

    fn temp_config_dir(tag: &str) -> (std::path::PathBuf, ConfigDir) {
        let dir = std::env::temp_dir().join(format!(
            "nexusd-redact-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp config dir");
        let conversation = ConfigDir::new(&dir).expect("config dir");
        (dir, conversation)
    }

    #[test]
    fn parity_daemon_and_cli_detail_hide_password_marker() {
        let (path, dir) = temp_config_dir("parity");
        // 畸形输入：引号紧凑形态 + 多词口令。
        let broken = format!(
            "schema_version: 1\noutbounds:\n  - tag: a\n    kind: shadowsocks\n    locator: 1.2.3.4:1\n    password={MARKER} alpha beta\n"
        );
        std::fs::write(path.join("proxy.yaml"), &broken).expect("write");

        let error = "parse proxy.yaml failed";
        let daemon = config_load_failure_json(error, Some(&dir));
        let daemon_text = serde_json::to_string(&daemon).expect("json");
        assert!(
            !daemon_text.contains(MARKER),
            "daemon leaked: {daemon_text}"
        );

        // CLI 同一份实现（`config check` 的 detail 字段路径）。
        let cli_detail = nexus::redact::sanitize(&err_text(&dir));
        assert!(!cli_detail.contains(MARKER), "cli leaked: {cli_detail}");
        assert!(cli_detail.contains("***"), "mask missing: {cli_detail}");

        let _ = std::fs::remove_dir_all(&path);
    }

    /// 取与 CLI detail 同源的解析错误文本（含原始回显）。
    fn err_text(dir: &ConfigDir) -> String {
        let text = std::fs::read_to_string(dir.file(nexusd::config::PROXY_YAML)).expect("read");
        nexus_proxy_config::parse(&text)
            .expect_err("must fail")
            .to_string()
    }

    #[test]
    fn redact_double_application_is_idempotent() {
        let raw = format!("files [\"proxy.yaml\"]: got 'password={MARKER}'");
        let once = nexus::redact::redact_secrets(&raw);
        let twice = nexus::redact::redact_secrets(&once);
        assert_eq!(once, twice, "double application must be idempotent");
        assert!(!once.contains("*** ***"), "double mask: {once}");
    }

    #[test]
    fn config_failure_json_is_parseable() {
        let (path, dir) = temp_config_dir("parseable");
        std::fs::write(path.join("proxy.yaml"), "not: [valid").expect("write");
        let value = config_load_failure_json("parse proxy.yaml failed", Some(&dir));
        let text = serde_json::to_string(&value).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("parseable");
        assert_eq!(parsed["verdict"], "FAIL");
        assert_eq!(parsed["stage"], "config_load");
        assert_eq!(parsed["error"]["variant"], "PROXY_YAML_INVALID");
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn error_debug_hides_secrets() {
        use nexus_proxy_config::UdpMode;
        let mode = UdpMode::ShadowsocksAead {
            server: "127.0.0.1:8388".parse().expect("addr"),
            password: MARKER.to_string(),
        };
        let text = format!("{mode:?}");
        assert!(!text.contains(MARKER), "UdpMode leaked: {text}");
        assert!(text.contains("***"), "mask missing: {text}");
    }
}

/// S9 / A10：reload 拒绝后原样恢复，status 清标记（R2-F12）。
#[cfg(test)]
mod reload_restore_tests {
    use super::{config_sha1, refresh_proxy_file_side};
    use nexusd::config::ConfigDir;

    const GOOD: &str = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n";

    fn temp_dir(tag: &str) -> (std::path::PathBuf, ConfigDir) {
        let path = std::env::temp_dir().join(format!(
            "nexusd-reload-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        let dir = ConfigDir::new(&path).expect("config dir");
        (path, dir)
    }

    #[test]
    fn rejected_then_restored_clears_file_rejected() {
        let (path, dir) = temp_dir("restore");
        std::fs::write(dir.file(nexusd::config::PROXY_YAML), GOOD).expect("good yaml");
        let surface = nexus::outbound_manifest::startup_surface(Some(GOOD));
        nexus::outbound_manifest::install_surface(&surface, &config_sha1(Some(GOOD)));

        // 1) 磁盘被覆盖为畸形文件 → 拒绝分支刷新 file 侧并标 rejected。
        let broken = format!("{GOOD}    password r2f12marker multi word\n");
        std::fs::write(dir.file(nexusd::config::PROXY_YAML), &broken).expect("broken yaml");
        let stale = refresh_proxy_file_side(&dir, Some("parse proxy.yaml failed"));
        assert_eq!(stale, Some(true), "rejected disk config must look stale");
        let snapshot = nexus::outbound_manifest::runtime_snapshot().expect("snapshot");
        assert!(snapshot.file_rejected, "rejection must be visible");

        // 2) 原样改回（与 active 逐字节相同）→ Applied 分支刷新 → 标记清空。
        std::fs::write(dir.file(nexusd::config::PROXY_YAML), GOOD).expect("restore");
        let stale = refresh_proxy_file_side(&dir, None);
        assert_eq!(
            stale,
            Some(false),
            "restored file equals active → not stale"
        );
        let snapshot = nexus::outbound_manifest::runtime_snapshot().expect("snapshot");
        assert!(
            !snapshot.file_rejected,
            "R2-F12: restored file clears rejection"
        );
        assert_eq!(
            snapshot.file_config_sha1, snapshot.active_config_sha1,
            "file sha must match active sha after restore"
        );
        let _ = std::fs::remove_dir_all(&path);
    }
}
