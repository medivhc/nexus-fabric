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
    Ok(cfg)
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
/// - 文件新增/删除 → NeedsRestart（子系统启停需重新装配）
pub fn classify_change(old: &LoadedConfig, new: &LoadedConfig) -> ChangeKind {
    // daemon.toml：localapi 地址变化需重启
    if old.daemon.localapi_addr != new.daemon.localapi_addr {
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
}
