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

/// 发布 tun_enabled 状态（daemon 启动时调用一次）。
fn publish_tun_enabled(enabled: bool) {
    let _ = TUN_ENABLED.set(enabled);
}

/// 读取 tun_enabled 状态（默认 true，保持向后兼容）。
fn tun_enabled() -> bool {
    *TUN_ENABLED.get().unwrap_or(&true)
}

mod config;
mod watcher;

use std::process::ExitCode;
use std::sync::mpsc::channel;

use serde_json::{Value, json};

use config::{ConfigDir, LoadedConfig};

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

/// 从 LoadedConfig 组装 DataplaneConfig（D1-D6）。
fn build_dataplane_config(loaded: &LoadedConfig) -> nexusd::dataplane::DataplaneConfig {
    use nexusd::dataplane::DataplaneConfig;

    // Mesh CIDR：network.toml 存在时默认 10.0.0.0/8（MVP；完整解析后置）。
    let mesh_cidrs = if loaded.network_toml.is_some() {
        vec!["10.0.0.0/8".to_string()]
    } else {
        vec![]
    };
    // Bypass：常见内网段（与 Clash Verge 默认一致）。
    let bypass_cidrs = vec!["192.168.0.0/16".to_string(), "172.16.0.0/12".to_string()];

    // QoS：从 daemon.toml [qos] 映射。
    let qos_enabled = loaded.daemon.qos.enabled;
    let mut qos_config = nexus_connectivity::cake::CakeConfig::default();
    if qos_enabled {
        qos_config.quantum = loaded.daemon.qos.quantum;
        qos_config.high_priority_ports = loaded.daemon.qos.high_priority_ports.clone();
        // mesh/proxy_upload_mbps 映射为 rate_limit（MVP：取最小非零值）。
        let mesh_bps = loaded.daemon.qos.mesh_upload_mbps * 1_000_000 / 8;
        let proxy_bps = loaded.daemon.qos.proxy_upload_mbps * 1_000_000 / 8;
        let rate_bps = match (mesh_bps, proxy_bps) {
            (0, 0) => 0,
            (m, 0) => m,
            (0, p) => p,
            (m, p) => m.min(p),
        };
        if rate_bps > 0 {
            // burst 默认为 1 秒的量。
            if let Ok(limit) = nexus_connectivity::qos::BandwidthLimit::new(rate_bps, rate_bps) {
                qos_config.rate_limit = Some(limit);
            }
        }
    }

    // Boost：从 network.toml [boost] 解析 enabled（D6）。
    // B3 残余修复：不再硬编码 false。
    let boost_enabled = loaded
        .network_toml
        .as_deref()
        .and_then(|s| s.parse::<toml::Value>().ok())
        .and_then(|v| v.get("boost").cloned())
        .and_then(|b| b.get("enabled").cloned())
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    DataplaneConfig {
        mesh_cidrs,
        bypass_cidrs,
        dns_enabled: loaded.dns_toml.is_some(),
        dns_config: None, // MVP：用默认（dns.toml 解析后置）
        qos_enabled,
        qos_config,
        boost_enabled,
        n1_configured: loaded.network_toml.is_some(),
        proxy_configured: loaded.proxy_yaml.is_some(),
    }
}

/// 数据面线程主循环：创建 TUN → 处理包 → 出错时退出线程（daemon 继续服务 LocalAPI）。
fn run_dataplane(config: nexusd::dataplane::DataplaneConfig, tun_name: &str, tun_mtu: u32) {
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

    eprintln!("[nexusd] dataplane: running");
    loop {
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

/// Daemon 主流程：加载配置 → 启动 LocalAPI → 启动 watcher → 事件循环。
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

    // T3：缺 proxy.yaml 且缺 network.toml → 拒绝启动（无意义）。
    if loaded.proxy_yaml.is_none() && loaded.network_toml.is_none() {
        eprintln!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"CONFIG\",\"message\":\"no subsystem configured: need proxy.yaml and/or network.toml\"}}}}"
        );
        return ExitCode::from(1);
    }

    // T4：发布 tun_enabled 状态供 LocalAPI 查询。
    let tun_enabled = loaded.daemon.tun.enabled;
    publish_tun_enabled(tun_enabled);

    // 2. 统一数据面（后台线程；TUN 创建失败时降级为无数据面，记日志）。
    //    D1：单个 TUN 由 nexusd 持有。
    //    T2：[tun].enabled=false 时跳过 TUN/数据面（no-tun 模式）。
    if tun_enabled {
        let dataplane_config = build_dataplane_config(&loaded);
        let tun_name = loaded.daemon.tun.name.clone();
        let tun_mtu = loaded.daemon.tun.mtu;
        std::thread::Builder::new()
            .name("nexusd-dataplane".to_string())
            .spawn(move || {
                run_dataplane(dataplane_config, &tun_name, tun_mtu);
            })
            .expect("spawn dataplane thread");
    } else {
        eprintln!("[nexusd] tun disabled; dataplane not started (no-tun mode)");
    }

    // 3. LocalAPI（后台线程；沿用既有 serve 逻辑）。
    let localapi_addr = loaded.daemon.localapi_addr.clone();
    let (ready_tx, ready_rx) = channel();
    std::thread::Builder::new()
        .name("nexusd-localapi".to_string())
        .spawn(move || {
            serve_localapi(&localapi_addr, ready_tx);
        })
        .expect("spawn localapi thread");
    // 等 LocalAPI 就绪（最多 5 秒）。
    match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(addr) => println!(
            "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"config_dir\":\"{config_dir}\",\"localapi\":\"{addr}\"}}}}"
        ),
        Err(_) => {
            eprintln!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"localapi did not start\"}}}}"
            );
            return ExitCode::from(1);
        }
    }

    // 3. 配置 watcher（后台线程；主线程拥有 JoinHandle，不直接改共享状态）。
    let (ev_tx, ev_rx) = channel();
    let _watcher = watcher::spawn(dir.clone(), loaded, ev_tx);

    // 4. 主事件循环：处理重载事件（single writer 原则）。
    //    注意：当前实现下热加载仅更新"已加载配置快照"并记日志；
    //    各子系统运行时的实际重装配为后续工作（见模块文档诚实边界）。
    loop {
        match ev_rx.recv() {
            Ok(watcher::ReloadEvent::Applied { files }) => {
                eprintln!("[nexusd] config hot-reloaded: {files:?}");
            }
            Ok(watcher::ReloadEvent::NeedsRestart { reason }) => {
                eprintln!("[nexusd] WARN: {reason}");
            }
            Ok(watcher::ReloadEvent::Rejected { error }) => {
                eprintln!("[nexusd] ERROR: config reload rejected: {error} (keeping old config)");
            }
            Err(_) => {
                // watcher 线程退出（不应发生）；记日志并继续（LocalAPI 仍服务）。
                eprintln!("[nexusd] WARN: config watcher channel closed");
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
    }
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
fn serve_localapi(addr_raw: &str, ready_tx: std::sync::mpsc::Sender<String>) {
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
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let _ = ready_tx.send(actual);
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = handle_localapi_request(&mut s) {
                    eprintln!("[nexusd] localapi error: {e}");
                }
            }
            Err(e) => {
                eprintln!("[nexusd] localapi accept error: {e}");
                break;
            }
        }
    }
}

// ===== 以下为既有 serve 逻辑（内部实现，保留） =====

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

/// serve 子命令（内部/历史兼容）：常驻 LocalAPI。
fn serve_resource(args: &[String]) -> ExitCode {
    let flags = parse_flags(args);
    match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => serve_over_tcp(raw),
        None => match flags.get("--socket").and_then(|v| v.as_deref()) {
            Some(path) => serve_over_socket(path),
            None => serve_over_tcp("127.0.0.1:0"),
        },
    }
}

/// TCP loopback 监听 + 服务循环（既有行为）。
fn serve_over_tcp(addr_raw: &str) -> ExitCode {
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
                if let Err(e) = handle_localapi_request(&mut stream) {
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
fn serve_over_socket(path: &str) -> ExitCode {
    use std::os::unix::net::UnixListener;
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
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"socket\":\"{path}\"}}}}"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(e) = handle_localapi_request(&mut stream) {
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

fn handle_localapi_request(stream: &mut dyn LocalIo) -> Result<(), String> {
    use std::io::BufRead;
    let request_line: String = {
        let mut reader = std::io::BufReader::new(&mut *stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read request line: {e}"))?;
        line
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
    let path = parts[1].to_string();
    let result: Result<Value, (String, String)> = match path.as_str() {
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
        "/localapi/v0/session/watch" => nexus::observability::session_watch()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/plan/explain" => nexus::observability::plan_explain()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/connectivity/status" => nexus::observability::connectivity_status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/platform/capabilities" => nexus::observability::platform_capabilities()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
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

fn write_http_json(
    stream: &mut dyn std::io::Write,
    status: u16,
    body: &Value,
) -> Result<(), std::io::Error> {
    let body_str = serde_json::to_string(body)?;
    let status_text = match status {
        200 => "OK",
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
