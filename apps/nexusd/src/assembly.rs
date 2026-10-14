//! Composition Root 装配胶水（R1/R2/R3，`docs/DAEMON_ARCHITECTURE.md` §13）。
//!
//! Binary (`main.rs`) 是装配的执行者；本模块提供可测试的纯装配逻辑：
//! - `parse_mesh_cidrs`：从 `network.toml [vpi.routes]` 派生 mesh CIDR（R2）；
//! - `assemble_n1`：构造 `N1MeshBridge` 并尽力 dial（R1）；
//! - `build_dataplane_config`：组装 `DataplaneConfig`（R2/R3）；
//! - `mesh_bypass_overlap`：mesh/bypass 重叠检测（R2 warn）。
//!
//! 降级语义（§13.3）：N1/DNS 组装失败不阻断 dataplane（计数降级）；
//! 只有 TUN 失败是致命的（由 main.rs 处理）。

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use nexus_network::n1::bridge::N1MeshBridge;

use super::config::{self, LoadedConfig};
use super::dataplane::DataplaneConfig;

/// 从 `network.toml` 文本派生 mesh CIDR 列表（R2）。
///
/// 来源为 `[vpi.routes]` 的 subnet 字段（`"A.B.C.D/N"` 字符串）；
/// 不再硬编码 `10.0.0.0/8`。
///
/// # Errors
/// - `network.toml` 语义解析失败（`N1Config::parse_toml`）→ `Err`；
///   调用方按 R2 降级为空列表 + warn。
pub fn parse_mesh_cidrs(network_toml: &str) -> Result<Vec<String>, String> {
    let config = nexus_network::n1::config::N1Config::parse_toml(network_toml)
        .map_err(|e| format!("parse network.toml: {e:?}"))?;
    Ok(config
        .vpi
        .routes
        .iter()
        .map(|r| format!("{}/{}", r.subnet.network_addr(), r.subnet.prefix_len()))
        .collect())
}

/// 检测 mesh CIDR 与 bypass CIDR 的重叠（R2）。
///
/// 返回重叠的 mesh CIDR 字符串列表；非空时调用方记 warn 日志
/// （mesh 优先，分类器 S29 顺序不变）。
/// 解析失败的 CIDR 条目被忽略（Dataplane::new 会再次校验并报错）。
pub fn mesh_bypass_overlap(mesh: &[String], bypass: &[String]) -> Vec<String> {
    let parse = |s: &str| -> Option<(u32, u8)> {
        let (addr_s, prefix_s) = s.split_once('/')?;
        let addr: std::net::Ipv4Addr = addr_s.parse().ok()?;
        let prefix: u8 = prefix_s.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        Some((u32::from(addr) & mask, prefix))
    };
    let overlaps = |a: (u32, u8), b: (u32, u8)| -> bool {
        let min_prefix = a.1.min(b.1);
        let mask = if min_prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - min_prefix)
        };
        (a.0 & mask) == (b.0 & mask)
    };
    let bypass_nets: Vec<(u32, u8)> = bypass.iter().filter_map(|s| parse(s)).collect();
    mesh.iter()
        .filter(|m| parse(m).is_some_and(|mn| bypass_nets.iter().any(|&bn| overlaps(mn, bn))))
        .cloned()
        .collect()
}

/// 装配 N1 网桥（R1；§13.3 步骤 5）。
///
/// - 解析 `network.toml` → 构造 `N1SessionManager`（复用 `nexus::network`
///   的装配器，不复制 dial/discovery 逻辑）；
/// - 由 `vpi.routes` 构造 `N1MeshBridge`；
/// - 各 peer `dial()` 在后台线程尽力而为（不阻塞 daemon 启动；单 peer
///   失败记 warn，不中断，降级语义）。
///
/// `proxy` 为 `[network.proxy]` 配置（#3 fabric-over-proxy）；`shutdown` 是
/// daemon 关闭标志，用于 fallback 的协作式取消。
///
/// # Errors
/// - 配置解析失败；
/// - `[network.proxy]` 映射为可拨号 `ProxyConfig` 失败；
/// - SessionManager 构造失败。
///
/// 调用方按 §13.3 降级：不调 `set_n1_sender`，dataplane 照常跑。
pub fn assemble_n1(
    network_toml: &str,
    proxy: Option<&config::ProxySection>,
    shutdown: Arc<AtomicBool>,
) -> Result<Arc<N1MeshBridge>, String> {
    let proxy_cfg = match proxy {
        Some(section) => Some(proxy_config_from(section)?),
        None => None,
    };
    let (config, mgr) = nexus::network::build_session_manager(network_toml, proxy_cfg, shutdown)?;
    // Arc 共享：bridge 持有 mgr 做路由，dial 线程持有 mgr 做尽力拨号。
    // dial 线程有界（N peers × 10s 握手超时），随进程退出而终止，无需显式回收。
    let mgr = Arc::new(mgr);
    let bridge = Arc::new(N1MeshBridge::new(
        Arc::clone(&mgr),
        config.vpi.routes.clone(),
    ));
    eprintln!(
        "[nexusd] N1 bridge assembled: {} routes",
        bridge.route_count()
    );
    // 后台 dial：不阻塞启动；失败记 warn（降级）。
    let peers: Vec<_> = config.peers.iter().map(|p| p.id).collect();
    std::thread::Builder::new()
        .name("nexusd-n1-dial".to_string())
        .spawn(move || {
            for peer_id in peers {
                if let Err(e) = mgr.dial(&peer_id) {
                    let hex = peer_id.to_hex();
                    eprintln!(
                        "[nexusd] WARN: N1 dial peer {} failed: {e:?} (degraded, continuing)",
                        &hex[..8.min(hex.len())]
                    );
                }
            }
        })
        .map_err(|e| format!("spawn n1 dial thread: {e}"))?;
    Ok(bridge)
}

/// 把 `[network.proxy]` 配置节映射为 `nexus::network::ProxyConfig`（#3 AC3）。
///
/// # Errors
/// - `method` 非法（仅 shadowsocks 校验）。
pub fn proxy_config_from(
    section: &config::ProxySection,
) -> Result<nexus::network::ProxyConfig, String> {
    use nexus_proxy_transport::{
        Socks5Auth, Socks5ProxyConfig, SsMethod, SsProxyConfig, TrojanProxyConfig,
    };

    let connect_timeout = std::time::Duration::from_secs(section.connect_timeout_sec);
    let handshake_timeout = std::time::Duration::from_secs(section.handshake_timeout_sec);
    match section.proxy_type {
        config::ProxyType::Socks5 => {
            // socks5：username+password 同时存在 → RFC1929 认证；否则无认证。
            let auth = match (&section.username, &section.password) {
                (Some(u), Some(p)) => Some(Socks5Auth {
                    username: u.clone(),
                    password: p.clone(),
                }),
                _ => None,
            };
            Ok(nexus::network::ProxyConfig::Socks5(Socks5ProxyConfig {
                server: section.server,
                auth,
                connect_timeout,
                handshake_timeout,
            }))
        }
        config::ProxyType::Shadowsocks => {
            let method = match section.method.as_deref() {
                Some(m) => SsMethod::parse(m).map_err(|e| format!("bad ss method: {e:?}"))?,
                None => SsMethod::Chacha20IetfPoly1305,
            };
            Ok(nexus::network::ProxyConfig::Shadowsocks(SsProxyConfig {
                server: section.server,
                method,
                password: section.password.clone().unwrap_or_default(),
                connect_timeout,
                handshake_timeout,
            }))
        }
        config::ProxyType::Trojan => Ok(nexus::network::ProxyConfig::Trojan(TrojanProxyConfig {
            server: section.server,
            password: section.password.clone().unwrap_or_default(),
            connect_timeout,
            handshake_timeout,
        })),
    }
}

/// 从 `LoadedConfig` 组装 `DataplaneConfig`（R2/R3；原 main.rs 逻辑下沉）。
///
/// - R2：`mesh_cidrs` 取自 `network.toml [vpi.routes]`；解析失败 → 空列表
///   （调用方已记 warn 语义，此处静默降级由 `parse_mesh_cidrs` 的 Err 分支处理，
///   eprintln 在此处发出以保证可观测）；
/// - R3：`dns.toml` 存在 → `parse_dns_toml`；失败 → 返回 `Err`
///   （main.rs 转为 exit 1 + CONFIG 错误）。
///
/// # Errors
/// - `dns.toml` 语义解析失败。
pub fn build_dataplane_config(loaded: &LoadedConfig) -> Result<DataplaneConfig, String> {
    use super::config::parse_dns_toml;

    // R2：mesh CIDR 配置化。
    let mesh_cidrs = match loaded.network_toml.as_deref() {
        Some(text) => match parse_mesh_cidrs(text) {
            Ok(cidrs) => cidrs,
            Err(e) => {
                eprintln!("[nexusd] WARN: {e}; mesh_cidrs empty (degraded)");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    // Bypass：常见内网段（与 Clash Verge 默认一致）。
    let bypass_cidrs = vec!["192.168.0.0/16".to_string(), "172.16.0.0/12".to_string()];

    // R2：重叠检测（warn，mesh 优先）。
    let overlapped = mesh_bypass_overlap(&mesh_cidrs, &bypass_cidrs);
    if !overlapped.is_empty() {
        eprintln!("[nexusd] WARN: mesh CIDRs overlap bypass: {overlapped:?} (mesh wins)");
    }

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
            // GAP-3：burst < 2×MTU (3028) 会静默拉低实际速率，打 WARN 日志。
            if rate_bps < 3028 {
                eprintln!(
                    "[nexusd] WARN: QoS burst_size={} < 3028 (2×MTU); actual rate will be silently lower than configured. Suggest burst >= 15140 (10×MTU).",
                    rate_bps
                );
            }
            if let Ok(limit) = nexus_connectivity::qos::BandwidthLimit::new(rate_bps, rate_bps) {
                qos_config.rate_limit = Some(limit);
            }
        }
    }

    // Boost：从 network.toml [boost] 解析 enabled。
    let boost_enabled = loaded
        .network_toml
        .as_deref()
        .and_then(|s| s.parse::<toml::Value>().ok())
        .and_then(|v| v.get("boost").cloned())
        .and_then(|b| b.get("enabled").cloned())
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    // R3：dns.toml 解析。
    let dns_config = match loaded.dns_toml.as_deref() {
        Some(text) => Some(parse_dns_toml(text)?),
        None => None,
    };

    Ok(DataplaneConfig {
        mesh_cidrs,
        bypass_cidrs,
        dns_enabled: loaded.dns_toml.is_some(),
        dns_config,
        qos_enabled,
        qos_config,
        boost_enabled,
        n1_configured: loaded.network_toml.is_some(),
        proxy_configured: loaded.proxy_yaml.is_some(),
    })
}

/// N2 P0-4（D1）：装配 daemon 内唯一的 SessionManager。
///
/// §15 boot 顺序：打开 N2 存储（`<config-dir>/n2/`）→ 加载会话记录 →
/// journal 重放（审计轨迹；尾部撕裂走**显式 discard 路径**，P1-11）→
/// `reconcile_session_records_at`（幂等；用真实 attach window 分类，P1-1：
/// 断开超窗→`Cancelled(ClientDetached)`、窗口内保留、真孤儿→`Failed`）→
/// 返回装配好的 `SessionManager`（Session 生命周期的唯一 Owner）。
///
/// 降级：存储打不开 → `Err`（调用方降级为 None，daemon 照常跑）。
pub fn assemble_n2_session_manager(
    config_root: &std::path::Path,
) -> Result<nexus_session::SessionManager, String> {
    use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionManager, reconcile_session_records_at};

    let store =
        nexus::n2_store::N2Store::open(config_root).map_err(|e| format!("open n2 store: {e}"))?;
    // §15：先重放 journal（审计轨迹可见性），再 reconcile。
    // P1-11：撕裂尾部此前只报 `TornJournalTail` 且无生产修复入口——整个 journal
    // （审计查询＋boot 重放）都不可读。这里给显式 discard 路径：显式记录可读的
    // 完整前缀条数后丢弃撕裂尾部，再重放（幂等）。
    let journal_entries = match store.replay_journal() {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "[nexusd] WARN: N2 journal replay failed ({e}); discarding torn tail explicitly"
            );
            store
                .kv()
                .journal_discard_torn_tail()
                .map_err(|d| format!("discard torn n2 journal tail: {d}"))?;
            store
                .replay_journal()
                .map_err(|e| format!("replay n2 journal after discard: {e}"))?
        }
    };
    if !journal_entries.is_empty() {
        eprintln!(
            "[nexusd] N2 journal replay: {} entries",
            journal_entries.len()
        );
    }
    let mut record_store = store.sessions();
    let report = reconcile_session_records_at(
        &mut record_store,
        false,
        now_unix_secs(),
        DEFAULT_ATTACH_WINDOW_SECS,
    )
    .map_err(|e| format!("reconcile n2 sessions: {e}"))?;
    eprintln!(
        "[nexusd] N2 session reconcile: checked={}, orphans={}",
        report.records_checked, report.orphans_classified,
    );
    let mut manager = SessionManager::new(Box::new(store.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
    let loaded = manager
        .load_from_store()
        .map_err(|e| format!("load n2 sessions: {e}"))?;
    eprintln!("[nexusd] N2 SessionManager: {loaded} session records loaded");
    Ok(manager)
}

/// The explicit daemon root owns the default token; preserve the operator's
/// dedicated token-file override without consulting NEXUS_CONFIG_DIR again.
pub fn localapi_token_path(config_root: &std::path::Path) -> std::path::PathBuf {
    std::env::var_os("NEXUS_LOCALAPI_TOKEN_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config_root.join("localapi.token"))
}

pub fn load_localapi_token(config_root: &std::path::Path) -> Result<String, String> {
    use std::io::{Read, Write};
    let path = localapi_token_path(config_root);
    let read = || -> Result<String, String> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x20000 | 0x800);
        }
        let mut file = options.open(&path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("LocalAPI token must be a regular file".into());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(129)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let token = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        let token = token.trim();
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("LocalAPI token is corrupt".into());
        }
        Ok(token.to_owned())
    };
    if path.try_exists().map_err(|e| e.to_string())? {
        return read();
    }
    let parent = path
        .parent()
        .ok_or_else(|| "token parent missing".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    // new_task_id is backed by 32 OS-random bytes, independent of Session IDs.
    let random = nexus::n3_acceptance::new_task_id().map_err(|e| e.to_string())?;
    let token = random
        .as_str()
        .strip_prefix("task-")
        .ok_or_else(|| "token randomness format".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(token.as_bytes())
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            #[cfg(unix)]
            std::fs::File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(token.to_owned())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read(),
        Err(error) => Err(error.to_string()),
    }
}

/// 当前 unix 秒（boot reconcile 用时钟）。
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 带超时的 join（R4 关闭顺序用；§13.4）。
///
/// 超时后记 warn 并继续（不杀线程，进程退出时回收）。
/// 返回 `true` 表示线程在超时内结束，`false` 表示超时。
pub fn join_with_timeout(
    handle: std::thread::JoinHandle<()>,
    timeout: std::time::Duration,
    name: &str,
) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = handle.join();
        let _ = tx.send(());
    });
    match rx.recv_timeout(timeout) {
        Ok(_) => {
            eprintln!("[nexusd] shutdown: {name} stopped");
            true
        }
        Err(_) => {
            eprintln!("[nexusd] WARN: shutdown: {name} did not stop in {timeout:?}, continuing");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小合法 network.toml（含 [vpi.routes]）。
    fn network_toml_with_routes() -> String {
        // peer_id 为 32 字节 hex（ed25519 公钥）。
        let peer_hex = "aa".repeat(32);
        format!(
            "peer_id = \"{peer_hex}\"\n\
             [[peers]]\n\
             id = \"{peer_hex}\"\n\
             addrs = [\"127.0.0.1:19001\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             mtu = 1200\n\
             [[vpi.routes]]\n\
             subnet = \"10.200.0.0/24\"\n\
             peer = \"{peer_hex}\"\n"
        )
    }

    #[test]
    fn mesh_cidrs_come_from_vpi_routes() {
        let cidrs = parse_mesh_cidrs(&network_toml_with_routes()).unwrap();
        assert_eq!(cidrs, vec!["10.200.0.0/24"]);
        // 不再硬编码 10.0.0.0/8。
        assert!(!cidrs.contains(&"10.0.0.0/8".to_string()));
    }

    #[test]
    fn mesh_cidrs_bad_config_is_err() {
        assert!(parse_mesh_cidrs("[[[unclosed").is_err());
    }

    #[test]
    fn overlap_detected() {
        let overlapped = mesh_bypass_overlap(
            &["172.16.5.0/24".to_string()],
            &["172.16.0.0/12".to_string()],
        );
        assert_eq!(overlapped, vec!["172.16.5.0/24".to_string()]);
    }

    #[test]
    fn overlap_empty_when_disjoint() {
        let overlapped = mesh_bypass_overlap(
            &["10.200.0.0/24".to_string()],
            &["192.168.0.0/16".to_string()],
        );
        assert!(overlapped.is_empty());
    }

    #[test]
    fn assemble_n1_bad_config_is_err() {
        // R1 降级路径：非法配置 → Err（调用方降级，不调 set_n1_sender）。
        assert!(assemble_n1("[[[unclosed", None, Arc::new(AtomicBool::new(false))).is_err());
    }

    #[test]
    fn assemble_n1_with_proxy_ok() {
        // #3：合法 [network.proxy]（socks5）+ 合法 network.toml → Ok，route_count==1。
        let section = crate::config::ProxySection {
            proxy_type: crate::config::ProxyType::Socks5,
            server: "127.0.0.1:1080".parse().unwrap(),
            username: None,
            password: None,
            method: None,
            connect_timeout_sec: 10,
            handshake_timeout_sec: 10,
        };
        let bridge = assemble_n1(
            &network_toml_with_routes(),
            Some(&section),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("assemble_n1 with proxy should succeed");
        assert_eq!(bridge.route_count(), 1);
    }

    fn loaded_with(network_toml: Option<&str>, qos: bool) -> LoadedConfig {
        LoadedConfig {
            daemon: crate::config::DaemonConfig {
                qos: crate::config::QosSection {
                    enabled: qos,
                    ..Default::default()
                },
                ..Default::default()
            },
            network_toml: network_toml.map(|s| s.to_string()),
            dns_toml: None,
            proxy_yaml: None,
            workspace_toml: None,
            meta: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn dataplane_config_no_network_toml() {
        // network.toml 缺失 → mesh_cidrs 空（降级），不 Err。
        let cfg = build_dataplane_config(&loaded_with(None, false)).unwrap();
        assert!(cfg.mesh_cidrs.is_empty());
    }

    #[test]
    fn dataplane_config_bad_network_toml_degrades() {
        // network.toml 非法 → mesh_cidrs 空（降级），不 Err。
        let cfg = build_dataplane_config(&loaded_with(Some("[[[unclosed"), false)).unwrap();
        assert!(cfg.mesh_cidrs.is_empty());
    }

    #[test]
    fn dataplane_config_qos_mapping() {
        // QoS 开启 → quantum/ports 透传。
        let mut loaded = loaded_with(None, true);
        loaded.daemon.qos.quantum = 9000;
        loaded.daemon.qos.high_priority_ports = vec![443];
        let cfg = build_dataplane_config(&loaded).unwrap();
        assert!(cfg.qos_enabled);
        assert_eq!(cfg.qos_config.quantum, 9000);
        assert_eq!(cfg.qos_config.high_priority_ports, vec![443]);
        // QoS 关闭 → 默认值。
        let cfg = build_dataplane_config(&loaded_with(None, false)).unwrap();
        assert!(!cfg.qos_enabled);
        assert_eq!(
            cfg.qos_config.quantum,
            nexus_connectivity::cake::CakeConfig::default().quantum
        );
    }

    #[test]
    fn join_with_timeout_fast_thread() {
        // 快速结束的线程 → true。
        let h = std::thread::spawn(|| {});
        assert!(join_with_timeout(
            h,
            std::time::Duration::from_secs(5),
            "test"
        ));
    }

    #[test]
    fn join_with_timeout_slow_thread() {
        // 睡眠线程 → 超时返回 false（不阻塞）。
        let h = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(30)));
        let start = std::time::Instant::now();
        assert!(!join_with_timeout(
            h,
            std::time::Duration::from_millis(100),
            "test"
        ));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
}
