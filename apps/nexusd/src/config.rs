//! nexusd 配置文件夹管理。
//!
//! 配置文件夹结构（缺失文件 = 对应子系统不启用，优雅降级）：
//! ```text
//! /etc/nexus/
//! ├── daemon.toml    # daemon 自身：LocalAPI 监听地址、PID 文件、日志（可选）
//! ├── network.toml   # N1 mesh 网络（可选；存在即启用 mesh）
//! ├── proxy.yaml     # Clash 风格代理（可选；存在即启用 proxy；YAML 格式沿用现有）
//! ├── dns.toml       # DNS（可选；存在即启用自定义 DNS）
//! └── workspace.toml # Workspace 生产接线（可选；存在即启用 workspace FUSE 挂载，C1）
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
/// Workspace 生产接线（C1/D1）：`[[workspace]]` 数组；缺失文件 = workspace 子系统不启用。
pub const WORKSPACE_TOML: &str = "workspace.toml";

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
    /// `[tun]` 小节：TUN 设备开关与参数（默认启用）。
    pub tun: TunSection,
    /// `[network.turn]` 小节：TURN 中继配置（可选；缺失 = NAT 打洞/turn 子系统禁用）。
    pub turn: Option<TurnSection>,
}

/// `daemon.toml` 的 `[tun]` 小节（no-tun 模式，`docs/WINDOWS_TUN_DESIGN.md` §1）。
///
/// 全部可选；`enabled = false` 时不创建 TUN（no-tun 模式：纯 N1 节点/显式代理）。
/// 热加载分类：任一字段变化 → `NeedsRestart`（TUN 设备启停需重建）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSection {
    /// 是否创建 TUN 设备（默认 true）。
    pub enabled: bool,
    /// TUN 设备名（默认 "nexus"；Linux）。
    pub name: String,
    /// MTU（默认 1500，合法范围 [1280, 9000]）。
    pub mtu: u32,
}

impl Default for TunSection {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "nexus".to_string(),
            mtu: 1500,
        }
    }
}

/// `daemon.toml` 的 `[network.turn]` 小节（NAT switching daemon activation，AC2）。
///
/// 存在即启用 TURN 中继分配与 NAT 打洞；缺失时 daemon 不实例化 turn/打洞栈
/// （启动时记录 WARN，punch disabled）。
/// 热加载分类：任一字段变化 → `NeedsRestart`（TURN 客户端生命周期需重建）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnSection {
    /// TURN 服务器 locator（如 `turn.example.org:3478`）。
    pub server: String,
    /// 长期凭证 realm（由 TURN 服务器下发，RFC 5389 §10.2）。
    pub realm: String,
    /// 长期凭证用户名。
    pub username: String,
    /// 长期凭证密码。
    pub password: String,
    /// 请求的分配生命周期 / 刷新间隔（秒；默认 300，必须 > 0）。
    pub refresh_interval_sec: u64,
    /// STUN 探测服务器（可选；缺失时回落到 `server` 做 STUN Binding 探测）。
    pub stun_server: Option<String>,
}

impl Default for TurnSection {
    fn default() -> Self {
        Self {
            server: String::new(),
            realm: String::new(),
            username: String::new(),
            password: String::new(),
            refresh_interval_sec: 300,
            stun_server: None,
        }
    }
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
    /// Workspace 配置原文（`workspace.toml` 存在时为 Some；C1/D1）。
    pub workspace_toml: Option<String>,
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
            tun: TunSection::default(),
            turn: None,
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

    // workspace.toml（可选；C1/D1。基础 TOML 语法校验，深层语义由 workspace manager 校验）
    if dir.has(WORKSPACE_TOML) {
        let text = std::fs::read_to_string(dir.file(WORKSPACE_TOML))
            .map_err(|e| format!("read {}: {e}", WORKSPACE_TOML))?;
        toml::from_str::<toml::Value>(&text).map_err(|e| format!("parse {WORKSPACE_TOML}: {e}"))?;
        cfg.workspace_toml = Some(text);
        if let Some(m) = FileMeta::of(&dir.file(WORKSPACE_TOML)) {
            cfg.meta.insert(WORKSPACE_TOML.to_string(), m);
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
        tun: TunSection::default(),
        turn: None,
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
    // [tun] 小节（可选；缺失则用默认值=启用）
    if let Some(t) = v.get("tun") {
        cfg.tun = parse_tun_section(t)?;
    }
    // [network.turn] 小节（可选；缺失 = turn/打洞子系统禁用）
    if let Some(t) = v.get("network").and_then(|n| n.get("turn")) {
        cfg.turn = Some(parse_turn_section(t)?);
    }
    Ok(cfg)
}

/// 解析 `daemon.toml` 的 `[network.turn]` 小节（AC2）。
///
/// `server` / `realm` / `username` / `password` 为必填非空字符串；
/// `refresh_interval_sec` 可选（默认 300，必须 > 0）；
/// `stun_server` 可选（缺失时回落 `server` 做 STUN 探测）。
fn parse_turn_section(t: &toml::Value) -> Result<TurnSection, String> {
    let get_required = |k: &str| -> Result<String, String> {
        let s = t
            .get(k)
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("{DAEMON_TOML}: [network.turn].{k} must be a string"))?;
        if s.is_empty() {
            return Err(format!(
                "{DAEMON_TOML}: [network.turn].{k} must not be empty"
            ));
        }
        Ok(s.to_string())
    };
    let server = get_required("server")?;
    let realm = get_required("realm")?;
    let username = get_required("username")?;
    let password = get_required("password")?;
    let refresh_interval_sec = match t.get("refresh_interval_sec") {
        None => 300,
        Some(x) => {
            let n = x
                .as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| {
                    format!("{DAEMON_TOML}: [network.turn].refresh_interval_sec must be a positive integer")
                })?;
            if n == 0 {
                return Err(format!(
                    "{DAEMON_TOML}: [network.turn].refresh_interval_sec must be > 0"
                ));
            }
            n
        }
    };
    let stun_server = match t.get("stun_server") {
        None => None,
        Some(x) => {
            let s = x.as_str().ok_or_else(|| {
                format!("{DAEMON_TOML}: [network.turn].stun_server must be a string")
            })?;
            if s.is_empty() {
                return Err(format!(
                    "{DAEMON_TOML}: [network.turn].stun_server must not be empty"
                ));
            }
            Some(s.to_string())
        }
    };
    Ok(TurnSection {
        server,
        realm,
        username,
        password,
        refresh_interval_sec,
        stun_server,
    })
}

/// 解析 `daemon.toml` 的 `[tun]` 小节（T1）。
///
/// 接受 `enabled`（bool，默认 true）、`name`（非空字符串，默认 "nexus"）、
/// `mtu`（整数，需在 [1280, 9000] 内，默认 1500）。
fn parse_tun_section(t: &toml::Value) -> Result<TunSection, String> {
    let enabled = t.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
    let name = match t.get("name") {
        None => "nexus".to_string(),
        Some(x) => {
            let s = x
                .as_str()
                .ok_or_else(|| format!("{DAEMON_TOML}: [tun].name must be a string"))?;
            if s.is_empty() {
                return Err(format!("{DAEMON_TOML}: [tun].name must not be empty"));
            }
            s.to_string()
        }
    };
    let mtu = match t.get("mtu") {
        None => 1500,
        Some(x) => {
            let n = x
                .as_integer()
                .and_then(|i| u32::try_from(i).ok())
                .ok_or_else(|| {
                    format!("{DAEMON_TOML}: [tun].mtu must be an integer in [1280, 9000]")
                })?;
            if !(1280..=9000).contains(&n) {
                return Err(format!(
                    "{DAEMON_TOML}: [tun].mtu must be in [1280, 9000] (got {n})"
                ));
            }
            n
        }
    };
    Ok(TunSection { enabled, name, mtu })
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

/// 解析 `dns.toml` 为 `DnsUnifiedConfig`（R3）。
///
/// 字段从 `[dns]` 小节读取；小节缺失时读根级键；全缺失时取默认值。
/// 字段：
/// - `upstream`：字符串数组（默认空）；
/// - `fake_ip_enabled`：bool（默认 true）；
/// - `fake_ip_range`：CIDR 字符串（默认 `198.18.0.0/15`）；
/// - `mesh_suffix`：字符串（默认 `"mesh"`）；
/// - `fake_ip_ttl_secs`：整数秒（默认 300）；
/// - `hosts`：表，域名 → IP 字符串。
///
/// # Errors
/// - TOML 语法错误；
/// - `fake_ip_range` 非法 CIDR；
/// - `hosts` 中 IP 非法。
///
/// 调用方按 §13.6 处理：解析失败 → daemon 启动失败 exit 1。
pub fn parse_dns_toml(text: &str) -> Result<nexus_dns::DnsUnifiedConfig, String> {
    use nexus_dns::{DEFAULT_FAKE_IP_RANGE, DEFAULT_MESH_SUFFIX, DnsUnifiedConfig};

    let v: toml::Value = toml::from_str(text).map_err(|e| format!("{}: {e}", DNS_TOML))?;
    // [dns] 小节优先，否则读根级。
    let t = v.get("dns").unwrap_or(&v);

    let upstream: Vec<String> = t
        .get("upstream")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|i| i.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let fake_ip_enabled = t
        .get("fake_ip_enabled")
        .and_then(|x| x.as_bool())
        .unwrap_or(true);

    let fake_ip_range = t
        .get("fake_ip_range")
        .and_then(|x| x.as_str())
        .unwrap_or(DEFAULT_FAKE_IP_RANGE);
    let (fake_ip_network, fake_ip_prefix) =
        parse_cidr_v4(fake_ip_range).map_err(|e| format!("{DNS_TOML}: bad fake_ip_range: {e}"))?;

    let mesh_suffix = t
        .get("mesh_suffix")
        .and_then(|x| x.as_str())
        .unwrap_or(DEFAULT_MESH_SUFFIX)
        .to_string();

    let fake_ip_ttl_secs = t
        .get("fake_ip_ttl_secs")
        .and_then(|x| x.as_integer())
        .and_then(|i| u64::try_from(i).ok())
        .unwrap_or(300);

    let mut hosts = Vec::new();
    if let Some(table) = t.get("hosts").and_then(|x| x.as_table()) {
        for (name, ip_v) in table {
            let ip_s = ip_v
                .as_str()
                .ok_or_else(|| format!("{DNS_TOML}: hosts.{name} must be an IP string"))?;
            let ip: std::net::IpAddr = ip_s
                .parse()
                .map_err(|_| format!("{DNS_TOML}: hosts.{name} bad IP '{ip_s}'"))?;
            hosts.push((name.clone(), ip));
        }
    }

    Ok(DnsUnifiedConfig {
        upstream,
        fake_ip_enabled,
        fake_ip_network,
        fake_ip_prefix,
        mesh_suffix,
        fake_ip_ttl_secs,
        hosts,
    })
}

/// 解析 IPv4 CIDR（`"A.B.C.D/N"`）→ `(网络地址 u32, 前缀长度)`。
fn parse_cidr_v4(s: &str) -> Result<(u32, u8), String> {
    let (addr_s, prefix_s) = s
        .split_once('/')
        .ok_or_else(|| format!("expected A.B.C.D/N, got '{s}'"))?;
    let addr: std::net::Ipv4Addr = addr_s
        .parse()
        .map_err(|_| format!("bad IPv4 address '{addr_s}'"))?;
    let prefix: u8 = prefix_s
        .parse()
        .map_err(|_| format!("bad prefix '{prefix_s}'"))?;
    if prefix > 32 {
        return Err(format!("prefix out of range: {prefix}"));
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((u32::from(addr) & mask, prefix))
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
/// - `proxy.yaml` 内容变更 → Hot（规则类数据）
/// - `dns.toml` 内容变更 → Hot（上游变更热生效，R5）
/// - `network.toml` 内容变更 → NeedsRestart（mesh CIDR 属重启类，R5/§13.6）
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
    // daemon.toml：[tun] 小节变化需重启（T4：TUN 设备启停需重建）
    if old.daemon.tun != new.daemon.tun {
        return ChangeKind::NeedsRestart;
    }
    // daemon.toml：[network.turn] 小节变化需重启（TURN 客户端启停需重建）。
    if old.daemon.turn != new.daemon.turn {
        return ChangeKind::NeedsRestart;
    }
    // R5：network.toml 内容变更 → NeedsRestart（mesh CIDR 可能变化）。
    if old.network_toml != new.network_toml {
        return ChangeKind::NeedsRestart;
    }
    // C1/D1：workspace.toml 内容变更 → NeedsRestart（挂载点/工作区集合变化需重新装配）。
    if old.workspace_toml != new.workspace_toml {
        return ChangeKind::NeedsRestart;
    }
    // 任一文件的增删 → 需重启（子系统启停）
    let files = [
        NETWORK_TOML,
        PROXY_YAML,
        DNS_TOML,
        DAEMON_TOML,
        WORKSPACE_TOML,
    ];
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
    fn tun_section_defaults_when_absent() {
        // 无 [tun] 小节 → enabled=true, name="nexus", mtu=1500（T1）。
        let cfg = parse_daemon_toml("[localapi]\naddr = \"127.0.0.1:18080\"\n").unwrap();
        assert!(cfg.tun.enabled);
        assert_eq!(cfg.tun.name, "nexus");
        assert_eq!(cfg.tun.mtu, 1500);
    }

    #[test]
    fn tun_section_parses_canonical_snippet() {
        // 与 docs/WINDOWS_TUN_DESIGN.md §1 的 wire format 对齐（T1）。
        let text = "[tun]\nenabled = false\nname = \"nexus-test\"\nmtu = 9000\n";
        let cfg = parse_daemon_toml(text).unwrap();
        assert!(!cfg.tun.enabled);
        assert_eq!(cfg.tun.name, "nexus-test");
        assert_eq!(cfg.tun.mtu, 9000);
    }

    #[test]
    fn tun_section_rejects_bad_mtu() {
        // mtu 非法 → 拒绝加载（T1）。
        assert!(parse_daemon_toml("[tun]\nmtu = 1279\n").is_err());
        assert!(parse_daemon_toml("[tun]\nmtu = 9001\n").is_err());
        assert!(parse_daemon_toml("[tun]\nmtu = -1\n").is_err());
        assert!(parse_daemon_toml("[tun]\nmtu = \"big\"\n").is_err());
        // 边界值合法。
        assert!(parse_daemon_toml("[tun]\nmtu = 1280\n").is_ok());
        assert!(parse_daemon_toml("[tun]\nmtu = 9000\n").is_ok());
    }

    #[test]
    fn tun_section_rejects_empty_name() {
        // 空设备名 → 拒绝加载（T1）。
        assert!(parse_daemon_toml("[tun]\nname = \"\"\n").is_err());
    }

    #[test]
    fn tun_change_needs_restart() {
        // [tun] 字段变更 → NeedsRestart（T4）。
        let d = std::env::temp_dir().join("nexusd-cfg-test-tun");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, DAEMON_TOML, "[tun]\nenabled = true\n");
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        write(&d, DAEMON_TOML, "[tun]\nenabled = false\n");
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        let _ = std::fs::remove_dir_all(&d);
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

    #[test]
    fn dns_toml_empty_uses_defaults() {
        let cfg = parse_dns_toml("").unwrap();
        assert_eq!(cfg.mesh_suffix.as_str(), "mesh");
        assert!(cfg.upstream.is_empty());
        assert!(cfg.hosts.is_empty());
    }

    #[test]
    fn dns_toml_section_and_root_level() {
        // [dns] 节。
        let cfg = parse_dns_toml("[dns]\nmesh_suffix = \"lan\"\n").unwrap();
        assert_eq!(cfg.mesh_suffix.as_str(), "lan");
        // 根级字段。
        let cfg = parse_dns_toml("upstream = [\"9.9.9.9\"]\n").unwrap();
        assert_eq!(cfg.upstream, vec!["9.9.9.9"]);
    }

    #[test]
    fn dns_toml_hosts_parsed() {
        let cfg = parse_dns_toml("[dns.hosts]\nprinter = \"192.168.1.50\"\n").unwrap();
        assert_eq!(cfg.hosts.len(), 1);
    }

    #[test]
    fn dns_toml_bad_rejected() {
        assert!(parse_dns_toml("not toml [[[").is_err());
        assert!(parse_dns_toml("[dns]\nfake_ip_range = \"999.1.1.0/24\"\n").is_err());
        assert!(parse_dns_toml("[dns.hosts]\nbad = \"not-an-ip\"\n").is_err());
    }

    // ---------- [network.turn] 小节（NAT switching daemon activation，AC2） ----------

    #[test]
    fn turn_section_absent_by_default() {
        // 无 [network.turn] 小节 → turn=None（子系统不启用）。
        let cfg = parse_daemon_toml("[localapi]\naddr = \"127.0.0.1:18080\"\n").unwrap();
        assert!(cfg.turn.is_none());
    }

    #[test]
    fn turn_section_parses_canonical_snippet() {
        // 与规格 wire format 对齐：server/realm/username/password 必填，
        // refresh_interval_sec / stun_server 可选。
        let text = "[network.turn]\n\
                    server = \"turn.example.org:3478\"\n\
                    realm = \"example.org\"\n\
                    username = \"nexus-node-a\"\n\
                    password = \"secret\"\n\
                    refresh_interval_sec = 300\n\
                    stun_server = \"stun.example.org:3478\"\n";
        let cfg = parse_daemon_toml(text).unwrap();
        let turn = cfg.turn.expect("turn section should parse");
        assert_eq!(turn.server, "turn.example.org:3478");
        assert_eq!(turn.realm, "example.org");
        assert_eq!(turn.username, "nexus-node-a");
        assert_eq!(turn.password, "secret");
        assert_eq!(turn.refresh_interval_sec, 300);
        assert_eq!(turn.stun_server.as_deref(), Some("stun.example.org:3478"));
    }

    #[test]
    fn turn_section_defaults_for_optional_fields() {
        // 缺失 refresh_interval_sec → 300；缺失 stun_server → None。
        let text = "[network.turn]\n\
                    server = \"turn.example.org:3478\"\n\
                    realm = \"example.org\"\n\
                    username = \"u\"\n\
                    password = \"p\"\n";
        let cfg = parse_daemon_toml(text).unwrap();
        let turn = cfg.turn.unwrap();
        assert_eq!(turn.refresh_interval_sec, 300);
        assert!(turn.stun_server.is_none());
    }

    #[test]
    fn turn_section_rejects_missing_or_empty_required() {
        // 缺失 server。
        let text = "[network.turn]\nrealm = \"r\"\nusername = \"u\"\npassword = \"p\"\n";
        assert!(parse_daemon_toml(text).is_err());
        // 空 username。
        let text =
            "[network.turn]\nserver = \"s\"\nrealm = \"r\"\nusername = \"\"\npassword = \"p\"\n";
        assert!(parse_daemon_toml(text).is_err());
        // 空密码。
        let text =
            "[network.turn]\nserver = \"s\"\nrealm = \"r\"\nusername = \"u\"\npassword = \"\"\n";
        assert!(parse_daemon_toml(text).is_err());
        // 非字符串字段。
        let text =
            "[network.turn]\nserver = 42\nrealm = \"r\"\nusername = \"u\"\npassword = \"p\"\n";
        assert!(parse_daemon_toml(text).is_err());
    }

    #[test]
    fn turn_section_rejects_bad_refresh_interval() {
        let base =
            "[network.turn]\nserver = \"s\"\nrealm = \"r\"\nusername = \"u\"\npassword = \"p\"\n";
        assert!(parse_daemon_toml(&format!("{base}refresh_interval_sec = 0\n")).is_err());
        assert!(parse_daemon_toml(&format!("{base}refresh_interval_sec = -5\n")).is_err());
        assert!(parse_daemon_toml(&format!("{base}refresh_interval_sec = \"fast\"\n")).is_err());
        assert!(parse_daemon_toml(&format!("{base}refresh_interval_sec = 60\n")).is_ok());
    }

    #[test]
    fn turn_change_needs_restart() {
        // [network.turn] 字段变更 → NeedsRestart（TURN 客户端启停需重建）。
        let d = std::env::temp_dir().join("nexusd-cfg-test-turn");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(
            &d,
            DAEMON_TOML,
            "[network.turn]\nserver = \"turn.example.org:3478\"\nrealm = \"r\"\nusername = \"u\"\npassword = \"p\"\n",
        );
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        write(
            &d,
            DAEMON_TOML,
            "[network.turn]\nserver = \"turn2.example.org:3478\"\nrealm = \"r\"\nusername = \"u\"\npassword = \"p\"\n",
        );
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        let _ = std::fs::remove_dir_all(&d);
    }
}
