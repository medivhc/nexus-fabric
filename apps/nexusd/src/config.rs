//! nexusd 配置文件夹管理。
//!
//! 配置文件夹结构（缺失文件 = 对应子系统不启用，优雅降级）：
//! ```text
//! /etc/nexus/
//! ├── daemon.toml    # daemon 自身：LocalAPI 监听地址、PID 文件、日志（可选）
//! ├── network.toml   # N1 mesh 网络（可选；存在即启用 mesh）
//! ├── proxy.yaml     # Clash 风格代理（可选；存在即启用 proxy；YAML 格式沿用现有）
//! └── dns.toml       # DNS（可选；存在即启用自定义 DNS）
//! ```
//!
//! 热加载分级（见 `watcher.rs`）：
//! - 热生效：代理规则、peer 列表、DNS 规则等纯数据变更
//! - 需重启：监听端口、TUN 设备名、LocalAPI 地址（记 warning，提示重启 daemon）
//! - 校验失败：拒绝应用，保留旧配置，记 error 日志，不 crash

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 配置文件夹中已知的文件名。
pub const DAEMON_TOML: &str = "daemon.toml";
pub const NETWORK_TOML: &str = "network.toml";
pub const PROXY_YAML: &str = "proxy.yaml";
pub const DNS_TOML: &str = "dns.toml";

/// 配置文件夹的抽象。
#[derive(Debug, Clone)]
pub struct ConfigDir {
    /// 配置文件夹根路径（如 `/etc/nexus/`）。
    pub root: PathBuf,
}

impl ConfigDir {
    /// 校验路径存在且为目录。
    pub fn new(root: &Path) -> Result<Self, String> {
        if !root.exists() {
            return Err(format!("config dir does not exist: {}", root.display()));
        }
        if !root.is_dir() {
            return Err(format!(
                "config path is not a directory: {}",
                root.display()
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// 某配置文件完整路径。
    pub fn file(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// 文件是否存在。
    pub fn has(&self, name: &str) -> bool {
        self.file(name).is_file()
    }
}

/// Daemon 自身配置（`daemon.toml`，全部可选，有默认值）。
#[derive(Debug, Clone, Default)]
pub struct DaemonConfig {
    /// LocalAPI 监听地址（默认 `127.0.0.1:18080`）。
    pub localapi_addr: String,
    /// `[qos]` 小节：CAKE-like QoS 开关与整形参数（默认禁用，零开销）。
    pub qos: QosSection,
}

/// `daemon.toml` 的 `[qos]` 小节（CAKE-like QoS，`docs/DAEMON_ARCHITECTURE.md` §11）。
///
/// 全部可选；`enabled = false`（默认）时调度器不实例化。
/// 热加载分类：任一字段变化 → `NeedsRestart`（子系统启停/重配；MVP 尚无运行中
/// 调度器可热应用，保守处理）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosSection {
    /// 是否启用 QoS 调度器（默认 false）。
    pub enabled: bool,
    /// mesh egress 上行整形（Mbps；0 = 不限，默认 0）。
    pub mesh_upload_mbps: u64,
    /// proxy egress 上行整形（Mbps；0 = 不限，默认 0）。
    pub proxy_upload_mbps: u64,
    /// DRR quantum（字节；默认 1514，合法范围 [64, 65536]）。
    pub quantum: u32,
    /// 高优先级端口（默认 [22, 53, 3389]）。
    pub high_priority_ports: Vec<u16>,
}

impl Default for QosSection {
    fn default() -> Self {
        Self {
            enabled: false,
            mesh_upload_mbps: 0,
            proxy_upload_mbps: 0,
            quantum: 1514,
            high_priority_ports: vec![22, 53, 3389],
        }
    }
}

impl DaemonConfig {
    fn default_addr() -> String {
        "127.0.0.1:18080".to_string()
    }
}

/// 已加载的全量配置（各子系统按文件存在性启用）。
#[derive(Debug, Clone, Default)]
pub struct LoadedConfig {
    /// daemon 自身配置（始终有值，缺失文件时用默认）。
    pub daemon: DaemonConfig,
    /// N1 mesh 配置原文（`network.toml` 存在时为 Some）。
    pub network_toml: Option<String>,
    /// 代理配置原文（`proxy.yaml` 存在时为 Some）。
    pub proxy_yaml: Option<String>,
    /// DNS 配置原文（`dns.toml` 存在时为 Some）。
    pub dns_toml: Option<String>,
    /// 各文件的元信息（用于热加载变更检测）。
    pub meta: HashMap<String, FileMeta>,
}

/// 文件元信息（mtime + size，用于轮询检测变更）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub mtime_secs: u64,
    pub size: u64,
}

impl FileMeta {
    pub fn of(path: &Path) -> Option<Self> {
        let md = std::fs::metadata(path).ok()?;
        let mtime = md
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(Self {
            mtime_secs: mtime,
            size: md.len(),
        })
    }
}

/// 加载配置文件夹内所有配置文件。
///
/// - 缺失文件 → 对应字段为 None（子系统不启用），不报错。
/// - 存在但读失败 → Err（I/O 错误，非配置内容错误）。
/// - 内容校验在 `validate()` 做（热加载时调用；启动时同样调用）。
pub fn load(dir: &ConfigDir) -> Result<LoadedConfig, String> {
    let mut cfg = LoadedConfig {
        daemon: DaemonConfig {
            localapi_addr: DaemonConfig::default_addr(),
            qos: QosSection::default(),
        },
        ..Default::default()
    };

    // daemon.toml（可选；解析失败则 Err，由调用方决定是启动失败还是热加载拒绝）
    if dir.has(DAEMON_TOML) {
        let text = std::fs::read_to_string(dir.file(DAEMON_TOML))
            .map_err(|e| format!("read {}: {e}", DAEMON_TOML))?;
        cfg.daemon = parse_daemon_toml(&text)?;
        if let Some(m) = FileMeta::of(&dir.file(DAEMON_TOML)) {
            cfg.meta.insert(DAEMON_TOML.to_string(), m);
        }
    }

    // network.toml（可选；原文透传，N1 侧自行解析）
    if dir.has(NETWORK_TOML) {
        let text = std::fs::read_to_string(dir.file(NETWORK_TOML))
            .map_err(|e| format!("read {}: {e}", NETWORK_TOML))?;
        // 基础 TOML 语法校验（深层语义由 N1 消费方校验）
        toml::from_str::<toml::Value>(&text).map_err(|e| format!("parse {NETWORK_TOML}: {e}"))?;
        cfg.network_toml = Some(text);
        if let Some(m) = FileMeta::of(&dir.file(NETWORK_TOML)) {
            cfg.meta.insert(NETWORK_TOML.to_string(), m);
        }
    }

    // proxy.yaml（可选；用内置最小 YAML 子集解析器校验）
    if dir.has(PROXY_YAML) {
        let text = std::fs::read_to_string(dir.file(PROXY_YAML))
            .map_err(|e| format!("read {}: {e}", PROXY_YAML))?;
        nexus_proxy_config::parse(&text).map_err(|e| format!("parse {PROXY_YAML}: {e:?}"))?;
        cfg.proxy_yaml = Some(text);
        if let Some(m) = FileMeta::of(&dir.file(PROXY_YAML)) {
            cfg.meta.insert(PROXY_YAML.to_string(), m);
        }
    }

    // dns.toml（可选；基础 TOML 语法校验）
    if dir.has(DNS_TOML) {
        let text = std::fs::read_to_string(dir.file(DNS_TOML))
            .map_err(|e| format!("read {}: {e}", DNS_TOML))?;
        toml::from_str::<toml::Value>(&text).map_err(|e| format!("parse {DNS_TOML}: {e}"))?;
        cfg.dns_toml = Some(text);
        if let Some(m) = FileMeta::of(&dir.file(DNS_TOML)) {
            cfg.meta.insert(DNS_TOML.to_string(), m);
        }
    }

    Ok(cfg)
}

/// 解析 `daemon.toml`（扁平或 `[localapi]` 小节均可）。
fn parse_daemon_toml(text: &str) -> Result<DaemonConfig, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("parse {DAEMON_TOML}: {e}"))?;
    let mut cfg = DaemonConfig {
        localapi_addr: DaemonConfig::default_addr(),
        qos: QosSection::default(),
    };
    // 支持 `localapi_addr = "..."` 或 `[localapi] addr = "..."`
    if let Some(s) = v.get("localapi_addr").and_then(|x| x.as_str()) {
        cfg.localapi_addr = s.to_string();
    }
    if let Some(addr) = v
        .get("localapi")
        .and_then(|t| t.get("addr"))
        .and_then(|x| x.as_str())
    {
        cfg.localapi_addr = addr.to_string();
    }
    // 校验地址可解析（避免启动后才发现 bind 失败）
    cfg.localapi_addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("{DAEMON_TOML}: invalid localapi addr: {e}"))?;
    // [qos] 小节（可选；缺失则用默认值=禁用）
    if let Some(t) = v.get("qos") {
        cfg.qos = parse_qos_section(t)?;
    }
    Ok(cfg)
}

/// 解析 `daemon.toml` 的 `[qos]` 小节。
///
/// 接受 `enabled`（或别名 `enable`）、`mesh_upload_mbps` / `proxy_upload_mbps`
/// （整数 Mbps，0=不限）、`quantum`（整数，需在 [64, 65536] 内）、
/// `high_priority_ports`（逗号分隔字符串 `"22,53,3389"` 或整数数组）。
fn parse_qos_section(t: &toml::Value) -> Result<QosSection, String> {
    let get_bool = |k: &str| t.get(k).and_then(|x| x.as_bool());
    let enabled = get_bool("enabled")
        .or_else(|| get_bool("enable"))
        .unwrap_or(false);
    let get_mbps = |k: &str| {
        t.get(k)
            .and_then(|x| x.as_integer())
            .and_then(|i| u64::try_from(i).ok())
            .unwrap_or(0)
    };
    let quantum = match t.get("quantum") {
        // 缺失 → 默认 1514
        None => 1514,
        // 存在 → 必须为 [64, 65536] 内整数，否则拒绝加载（不静默取默认）
        Some(x) => {
            let n = x
                .as_integer()
                .and_then(|i| u32::try_from(i).ok())
                .ok_or_else(|| {
                    format!("{DAEMON_TOML}: [qos].quantum must be an integer in [64, 65536]")
                })?;
            if !(64..=65536).contains(&n) {
                return Err(format!(
                    "{DAEMON_TOML}: [qos].quantum must be in [64, 65536] (got {n})"
                ));
            }
            n
        }
    };
    let high_priority_ports = match t.get("high_priority_ports") {
        Some(v) => parse_port_list(v)?,
        None => vec![22, 53, 3389],
    };
    Ok(QosSection {
        enabled,
        mesh_upload_mbps: get_mbps("mesh_upload_mbps"),
        proxy_upload_mbps: get_mbps("proxy_upload_mbps"),
        quantum,
        high_priority_ports,
    })
}

/// 解析端口列表：逗号分隔字符串或整数数组。
fn parse_port_list(v: &toml::Value) -> Result<Vec<u16>, String> {
    if let Some(s) = v.as_str() {
        let mut ports = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let p: u16 = part.parse().map_err(|_| {
                format!("{DAEMON_TOML}: [qos].high_priority_ports: invalid port '{part}'")
            })?;
            ports.push(p);
        }
        return Ok(ports);
    }
    if let Some(arr) = v.as_array() {
        let mut ports = Vec::new();
        for item in arr {
            let p = item
                .as_integer()
                .and_then(|i| u16::try_from(i).ok())
                .ok_or_else(|| {
                    format!("{DAEMON_TOML}: [qos].high_priority_ports: ports must be 0..=65535")
                })?;
            ports.push(p);
        }
        return Ok(ports);
    }
    Err(format!(
        "{DAEMON_TOML}: [qos].high_priority_ports: expected comma-separated string or integer array"
    ))
}

/// 热加载变更分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// 纯数据变更，可热生效（规则、peer 列表、DNS 记录等）。
    Hot,
    /// 需重启子系统/daemon（监听端口、TUN 设备名、LocalAPI 地址）。
    /// 当前实现：记 warning，提示重启，不自动重启。
    NeedsRestart,
}

/// 对比新旧配置，判断变更类型。
///
/// 保守策略：目前仅做文件级判断——
/// - `proxy.yaml` / `dns.toml` 内容变更 → Hot（规则/记录类数据）
/// - `network.toml` 内容变更 → Hot（peer 列表等；若含监听端口变更则 NeedsRestart，
///   当前未做字段级 diff，一律按 Hot 处理并记 info，端口类变更由 N1 侧自行决定）
/// - `daemon.toml` 的 `localapi_addr` 变更 → NeedsRestart
/// - `daemon.toml` 的 `[qos]` 小节变更 → NeedsRestart（子系统启停/重配）
/// - 文件新增/删除 → NeedsRestart（子系统启停需重新装配）
pub fn classify_change(old: &LoadedConfig, new: &LoadedConfig) -> ChangeKind {
    // daemon.toml：localapi 地址变化需重启
    if old.daemon.localapi_addr != new.daemon.localapi_addr {
        return ChangeKind::NeedsRestart;
    }
    // daemon.toml：[qos] 小节变化需重启
    if old.daemon.qos != new.daemon.qos {
        return ChangeKind::NeedsRestart;
    }
    // 任一文件的增删 → 需重启（子系统启停）
    let files = [NETWORK_TOML, PROXY_YAML, DNS_TOML, DAEMON_TOML];
    for f in files {
        let o = old.meta.get(f);
        let n = new.meta.get(f);
        match (o, n) {
            (None, Some(_)) | (Some(_), None) => return ChangeKind::NeedsRestart,
            _ => {}
        }
    }
    ChangeKind::Hot
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn empty_dir_loads_defaults() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-empty");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let dir = ConfigDir::new(&d).unwrap();
        let cfg = load(&dir).unwrap();
        assert_eq!(cfg.daemon.localapi_addr, "127.0.0.1:18080");
        assert!(cfg.network_toml.is_none());
        assert!(cfg.proxy_yaml.is_none());
        assert!(cfg.dns_toml.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn daemon_toml_overrides_addr() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-daemon");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, DAEMON_TOML, "[localapi]\naddr = \"127.0.0.1:19090\"\n");
        let dir = ConfigDir::new(&d).unwrap();
        let cfg = load(&dir).unwrap();
        assert_eq!(cfg.daemon.localapi_addr, "127.0.0.1:19090");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bad_toml_is_rejected() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-bad");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, NETWORK_TOML, "[[[unclosed");
        let dir = ConfigDir::new(&d).unwrap();
        assert!(load(&dir).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn classify_hot_vs_restart() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-classify");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // 最小合法 proxy.yaml（schema_version + rules/outbounds）
        let yaml_v1 = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let yaml_v2 = "schema_version: 1\nrules:\n  - tag: r2\n    kind: domain\n    match: x.com\n    action:\n      - kind: select_outbound\n        tag: d\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        write(&d, PROXY_YAML, yaml_v1);
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        // proxy.yaml 内容变更 → Hot
        write(&d, PROXY_YAML, yaml_v2);
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::Hot);
        // daemon addr 变更 → NeedsRestart
        write(&d, DAEMON_TOML, "[localapi]\naddr = \"127.0.0.1:19999\"\n");
        let new2 = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new2), ChangeKind::NeedsRestart);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_dir_is_error() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-missing-xyz");
        let _ = std::fs::remove_dir_all(&d);
        assert!(ConfigDir::new(&d).is_err());
    }

    #[test]
    fn qos_section_defaults_when_absent() {
        // 无 [qos] 小节 → 禁用，零开销。
        let cfg = parse_daemon_toml("[localapi]\naddr = \"127.0.0.1:18080\"\n").unwrap();
        assert!(!cfg.qos.enabled);
        assert_eq!(cfg.qos.mesh_upload_mbps, 0);
        assert_eq!(cfg.qos.proxy_upload_mbps, 0);
        assert_eq!(cfg.qos.quantum, 1514);
        assert_eq!(cfg.qos.high_priority_ports, vec![22, 53, 3389]);
    }

    #[test]
    fn qos_section_parses_canonical_snippet() {
        // 与 scenarios/product/qos_cake.toml (e) 的 wire format 对齐。
        let text = "[qos]\nenabled = true\nmesh_upload_mbps = 100\nproxy_upload_mbps = 50\nquantum = 1514\nhigh_priority_ports = \"22,53,3389\"\n";
        let cfg = parse_daemon_toml(text).unwrap();
        assert!(cfg.qos.enabled);
        assert_eq!(cfg.qos.mesh_upload_mbps, 100);
        assert_eq!(cfg.qos.proxy_upload_mbps, 50);
        assert_eq!(cfg.qos.quantum, 1514);
        assert_eq!(cfg.qos.high_priority_ports, vec![22, 53, 3389]);
    }

    #[test]
    fn qos_section_accepts_enable_alias_and_array_ports() {
        let text = "[qos]\nenable = true\nhigh_priority_ports = [22, 53]\n";
        let cfg = parse_daemon_toml(text).unwrap();
        assert!(cfg.qos.enabled);
        assert_eq!(cfg.qos.high_priority_ports, vec![22, 53]);
    }

    #[test]
    fn qos_section_rejects_bad_quantum_and_ports() {
        let bad_q = "[qos]\nquantum = 63\n";
        assert!(parse_daemon_toml(bad_q).is_err());
        let bad_q2 = "[qos]\nquantum = 70000\n";
        assert!(parse_daemon_toml(bad_q2).is_err());
        // 负数 quantum：拒绝加载（不静默取默认）。
        let bad_q3 = "[qos]\nquantum = -5\n";
        assert!(parse_daemon_toml(bad_q3).is_err());
        // 非整数 quantum：拒绝加载。
        let bad_q4 = "[qos]\nquantum = \"fast\"\n";
        assert!(parse_daemon_toml(bad_q4).is_err());
        let bad_p = "[qos]\nhigh_priority_ports = \"22,abc\"\n";
        assert!(parse_daemon_toml(bad_p).is_err());
        let bad_p2 = "[qos]\nhigh_priority_ports = [99999]\n";
        assert!(parse_daemon_toml(bad_p2).is_err());
    }

    #[test]
    fn qos_change_needs_restart() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-qos");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, DAEMON_TOML, "[qos]\nenabled = false\n");
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        // [qos] 字段变更 → NeedsRestart。
        write(
            &d,
            DAEMON_TOML,
            "[qos]\nenabled = true\nmesh_upload_mbps = 100\n",
        );
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        // 无变化 → Hot（沿用既有保守规则）。
        let same = load(&dir).unwrap();
        assert_eq!(classify_change(&new, &same), ChangeKind::Hot);
        let _ = std::fs::remove_dir_all(&d);
    }
}
