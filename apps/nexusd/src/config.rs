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
//! 三个 "proxy" 的语义区分（#1 命名澄清，键名不动）：
//! 1. `daemon.toml [network.proxy]`（`ProxySection`）= **N1 建连经代理**：
//!    dial 时的代理 tier（#3 fabric-over-proxy，翻墙/中继建链）；
//! 2. `proxy.yaml` = **TUN 出站经代理**：互联网出口策略
//!    （Clash 风格规则引擎，管出向流量）；
//! 3. `nexus proxy` CLI 子命令（one-shot SOCKS5/数据面组合根）——
//!    本轮仅记录观察项，不处理（OQ4）。
//!    另：`daemon.toml [network.turn]`（`TurnSection`）= **TURN+STUN**：
//!    NAT switching 用（打洞候选与中继分配），与代理无关
//!    （常被混淆，特此并列）。
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
    /// `[flow_sessions]` 小节：流会话全局开关（默认 `auto`，spec §10.4）。
    pub flow_sessions: FlowSessionsSection,
    /// `[network.turn]` 小节：TURN 中继配置（可选；缺失 = NAT 打洞/turn 子系统禁用）。
    pub turn: Option<TurnSection>,
    /// `[network.proxy]` 小节：fabric-over-proxy 代理配置（缺失 = 不启用）。
    pub proxy: Option<ProxySection>,
    /// `[network.punch]` 小节：NAT 打洞配置（缺失 = 全默认）。
    pub punch: PunchSection,
    /// `[network.identity]` 小节：fabric ed25519 身份种子文件（BLOCKED-1 (a)）。
    pub identity: IdentitySection,
    /// `[network.discovery]` 小节：peer 发现（LSA/mDNS pump 与订阅 feed）。
    pub discovery: DiscoverySection,
}

/// `[network.identity]`：daemon 的 fabric ed25519 seed 来源。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentitySection {
    /// Ed25519 seed 文件路径（64 hex 字符；权限必须 0600）。
    pub seed_file: Option<String>,
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
    /// 是否接管默认路由（legacy 映射到 tun 入站，默认 false）。
    pub default_route: bool,
    /// 是否自动排除代理服务器路由（legacy 映射，默认 true）。
    pub exclude_server_routes: bool,
    /// `enabled` 是否在 `daemon.toml` 中显式出现（§10.7 冲突判定）。
    pub(crate) enabled_explicit: bool,
    /// `name` 是否显式出现。
    pub(crate) name_explicit: bool,
    /// `mtu` 是否显式出现。
    pub(crate) mtu_explicit: bool,
    /// `default_route` 是否显式出现。
    pub(crate) default_route_explicit: bool,
    /// `exclude_server_routes` 是否显式出现。
    pub(crate) exclude_server_routes_explicit: bool,
}

impl Default for TunSection {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "nexus".to_string(),
            mtu: 1500,
            default_route: false,
            exclude_server_routes: true,
            enabled_explicit: false,
            name_explicit: false,
            mtu_explicit: false,
            default_route_explicit: false,
            exclude_server_routes_explicit: false,
        }
    }
}

/// `daemon.toml` 的 `[flow_sessions]` 小节（spec §10.4）。
///
/// 全部可选；未配置时由数据面按 `auto` 解析。与 `inbounds[kind=tun].sessions`
/// 同时显式设置且不同 → `CONFIG_INVALID [flow_sessions.enabled]`（spec §10.7）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowSessionsSection {
    /// 全局流会话开关（`auto` / `enabled` / `disabled`）。
    pub enabled: Option<nexus_proxy_config::FlowSessionsMode>,
    /// 会话空闲超时秒数（默认 300；0 非法）。
    pub idle_timeout_secs: Option<u64>,
    /// UDP 会话缓冲报文数（默认 64；0 非法）。
    pub udp_buffer_datagrams: Option<usize>,
}

/// `daemon.toml` 的 `[network.discovery]` 小节（peer 发现与订阅）。
///
/// 全部可选；缺失时与默认值一致。语义（spec §4.11.1）：
/// - `enabled=false` 或 `feed=false` → `peer_source.state="disabled:config"`；
/// - `mdns=false` / `lsa=false` 只停对应 pump；
/// - 任一字段变化 → `NeedsRestart`（与 `[network.turn]` 同口径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySection {
    /// 总开关（默认 true）。
    pub enabled: bool,
    /// mDNS pump 开关（默认 true）。
    pub mdns: bool,
    /// LSA gossip pump 开关（默认 true）。
    pub lsa: bool,
    /// 订阅/触发 feed 开关（默认 true）。
    pub feed: bool,
    /// LSA gossip 端口（默认 19010；不得等于 mDNS 的 5353）。
    pub gossip_port: u16,
    /// mDNS 通告 IPv4（`None` = 自动选择）。
    pub advertise_ip: Option<std::net::Ipv4Addr>,
    /// 自身 LSA 刷新间隔秒（默认 30）。
    pub lsa_refresh_sec: u64,
    /// LSA 新鲜度窗口秒（默认 90）。
    pub lsa_stale_sec: u64,
    /// relay 地址簿轮询间隔毫秒（默认 5000）。
    pub book_poll_ms: u64,
    /// 连续触发失败上限（默认 3）。
    pub trigger_max_failures: u32,
}

impl Default for DiscoverySection {
    fn default() -> Self {
        Self {
            enabled: true,
            mdns: true,
            lsa: true,
            feed: true,
            gossip_port: 19010,
            advertise_ip: None,
            lsa_refresh_sec: 30,
            lsa_stale_sec: 90,
            book_poll_ms: 5000,
            trigger_max_failures: 3,
        }
    }
}

impl DiscoverySection {
    /// 校验取值范围（越界 → `Err` → 启动失败 CONFIG）。
    fn validate(&self) -> Result<(), String> {
        if self.gossip_port == 0 || self.gossip_port == 5353 {
            return Err(format!(
                "[network.discovery].gossip_port must be 1..=65535 and != 5353 (mDNS), got {}",
                self.gossip_port
            ));
        }
        if !(5..=300).contains(&self.lsa_refresh_sec) {
            return Err(format!(
                "[network.discovery].lsa_refresh_sec must be 5..=300, got {}",
                self.lsa_refresh_sec
            ));
        }
        let stale_min = std::cmp::max(60, self.lsa_refresh_sec.saturating_mul(2));
        if !(stale_min..=3600).contains(&self.lsa_stale_sec) {
            return Err(format!(
                "[network.discovery].lsa_stale_sec must be {stale_min}..=3600 (>= 2x lsa_refresh_sec), got {}",
                self.lsa_stale_sec
            ));
        }
        if !(1000..=60000).contains(&self.book_poll_ms) {
            return Err(format!(
                "[network.discovery].book_poll_ms must be 1000..=60000, got {}",
                self.book_poll_ms
            ));
        }
        if !(1..=10).contains(&self.trigger_max_failures) {
            return Err(format!(
                "[network.discovery].trigger_max_failures must be 1..=10, got {}",
                self.trigger_max_failures
            ));
        }
        Ok(())
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
    /// 第二 STUN 探测服务器（可选；用于双服务器 NAT 类型对比检测，
    /// AC4/D2；缺失时只做单服务器采样，`nat_type` 保持 `Unknown`）。
    pub stun_server2: Option<String>,
    /// TURN 客户端的本地绑定地址（生产 `0.0.0.0:0`）。
    pub bind_addr: String,
    /// relayed 地址簿目录（`Some` = 共享目录 `DirRelayAddressBook`，INTERIM
    /// 跨主机渠道；`None` = 现有 per-self 临时文件）。
    pub relay_book_dir: Option<std::path::PathBuf>,
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
            stun_server2: None,
            bind_addr: "0.0.0.0:0".to_string(),
            relay_book_dir: None,
        }
    }
}

/// `daemon.toml` 的 `[network.proxy]` 小节（#3 fabric-over-proxy）。
///
/// 语义：**N1 建连经代理**（dial 时的代理 tier），与 `proxy.yaml`
/// （TUN 出站策略）、`[network.turn]`（TURN+STUN）区分；详见本模块
/// 顶部文档的“三个 proxy 的语义区分”。
///
/// 缺失 `[network.proxy]` → `proxy: None`（daemon 正常启动，chain 跳过 proxy tier）。
/// 任一字段非法 → 配置加载失败（daemon exit 1 + CONFIG 错误），不是运行时降级。
/// 热加载分类：任一字段变化 → `NeedsRestart`（代理客户端生命周期需重建）。
#[derive(Clone, PartialEq, Eq)]
pub struct ProxySection {
    /// 代理协议类型（`socks5 | shadowsocks | trojan`）。
    pub proxy_type: ProxyType,
    /// 代理服务器地址（`host:port`，必须可解析为 `SocketAddr`）。
    pub server: std::net::SocketAddr,
    /// SOCKS5 RFC 1929 认证用户名（可选；shadowsocks/trojan 忽略）。
    pub username: Option<String>,
    /// 密码（shadowsocks/trojan 必填；socks5 可选，缺省 = 无认证）。
    pub password: Option<String>,
    /// 仅 shadowsocks 使用（默认 `chacha20-ietf-poly1305`）。
    pub method: Option<String>,
    /// 仅 trojan 使用：TLS SNI（缺省从 `server` 的 IP 字符串推导，#4 行为一致）。
    pub sni: Option<String>,
    /// 仅 trojan 使用：跳过证书链/主机名校验（自签/内网，默认 false）。
    pub skip_cert_verify: bool,
    /// 仅 trojan 使用：ALPN 协议列表（默认空）。
    pub alpn: Option<Vec<String>>,
    /// TCP connect 超时（秒，默认 10，必须 > 0）。
    pub connect_timeout_sec: u64,
    /// 代理协议握手超时（秒，默认 10，必须 > 0）。
    pub handshake_timeout_sec: u64,
}

/// 手动 `Debug`：密码字段只输出 `***`，永不落日志（AC3）。
impl std::fmt::Debug for ProxySection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySection")
            .field("proxy_type", &self.proxy_type)
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("method", &self.method)
            .field("sni", &self.sni)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("alpn", &self.alpn)
            .field("connect_timeout_sec", &self.connect_timeout_sec)
            .field("handshake_timeout_sec", &self.handshake_timeout_sec)
            .finish()
    }
}

/// `[network.proxy]` 的 `type` 枚举值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    /// SOCKS5（RFC 1928/1929）。
    Socks5,
    /// Shadowsocks（AEAD session）。
    Shadowsocks,
    /// Trojan。
    Trojan,
}

impl ProxyType {
    /// 稳定标签（与 `daemon.toml` 的 `type` 字段一致）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Shadowsocks => "shadowsocks",
            Self::Trojan => "trojan",
        }
    }

    /// 解析 `type` 标签；非法值返回 `Err`。
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "socks5" => Ok(Self::Socks5),
            "shadowsocks" => Ok(Self::Shadowsocks),
            "trojan" => Ok(Self::Trojan),
            other => Err(format!(
                "{DAEMON_TOML}: [network.proxy].type must be one of socks5|shadowsocks|trojan (got '{other}')"
            )),
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
            flow_sessions: FlowSessionsSection::default(),
            turn: None,
            proxy: None,
            punch: PunchSection::default(),
            identity: IdentitySection::default(),
            discovery: DiscoverySection::default(),
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
        let parsed =
            nexus_proxy_config::parse(&text).map_err(|e| format!("parse {PROXY_YAML}: {e:?}"))?;
        validate_flow_sessions_conflicts(&cfg.daemon.flow_sessions, &parsed)?;
        validate_legacy_tun_mapping(&cfg.daemon.tun, &parsed)?;
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
        flow_sessions: FlowSessionsSection::default(),
        turn: None,
        proxy: None,
        punch: PunchSection::default(),
        identity: IdentitySection::default(),
        discovery: DiscoverySection::default(),
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
    // [flow_sessions] 小节（可选；缺失则默认 auto）
    if let Some(t) = v.get("flow_sessions") {
        cfg.flow_sessions = parse_flow_sessions_section(t)?;
    }
    // [network.turn] 小节（可选；缺失 = turn/打洞子系统禁用）
    if let Some(t) = v.get("network").and_then(|n| n.get("turn")) {
        cfg.turn = Some(parse_turn_section(t)?);
    }
    // [network.proxy] 小节（可选；缺失 = 不启用，不报错）
    if let Some(t) = v.get("network").and_then(|n| n.get("proxy")) {
        cfg.proxy = Some(parse_proxy_section(t)?);
    }
    // [network.identity] 小节（可选；缺失 = 无 seed）
    if let Some(t) = v.get("network").and_then(|n| n.get("identity")) {
        let seed_file = match t.get("seed_file") {
            None => None,
            Some(x) => Some(
                x.as_str()
                    .ok_or_else(|| {
                        format!("{DAEMON_TOML}: [network.identity].seed_file must be a string")
                    })?
                    .to_string(),
            ),
        };
        cfg.identity = IdentitySection { seed_file };
    }
    // [network.discovery] 小节（可选；缺失 = 默认值）
    if let Some(t) = v.get("network").and_then(|n| n.get("discovery")) {
        cfg.discovery = parse_discovery_section(t)?;
    }
    // [network.punch] 小节（可选；缺失 = 默认值）
    if let Some(t) = v.get("network").and_then(|n| n.get("punch")) {
        cfg.punch = parse_punch_section(t)?;
        cfg.punch
            .validate()
            .map_err(|e| format!("{DAEMON_TOML}: [network.punch] {e}"))?;
    }
    Ok(cfg)
}

/// 解析 `daemon.toml` 的 `[network.discovery]` 小节。
///
/// 键全部可选（缺失 = `DiscoverySection::default()` 的值）；`advertise_ip`
/// 为空字符串表示自动选择，非空必须是 IPv4 字面量。
fn parse_discovery_section(t: &toml::Value) -> Result<DiscoverySection, String> {
    let mut out = DiscoverySection::default();
    let get_bool = |k: &str, dst: &mut bool| -> Result<(), String> {
        if let Some(x) = t.get(k) {
            *dst = x.as_bool().ok_or_else(|| {
                format!("{DAEMON_TOML}: [network.discovery].{k} must be a boolean")
            })?;
        }
        Ok(())
    };
    get_bool("enabled", &mut out.enabled)?;
    get_bool("mdns", &mut out.mdns)?;
    get_bool("lsa", &mut out.lsa)?;
    get_bool("feed", &mut out.feed)?;

    let get_u64 = |k: &str, dst: &mut u64| -> Result<(), String> {
        if let Some(x) = t.get(k) {
            *dst = x
                .as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| {
                    format!("{DAEMON_TOML}: [network.discovery].{k} must be a positive integer")
                })?;
        }
        Ok(())
    };
    get_u64("lsa_refresh_sec", &mut out.lsa_refresh_sec)?;
    get_u64("lsa_stale_sec", &mut out.lsa_stale_sec)?;
    get_u64("book_poll_ms", &mut out.book_poll_ms)?;

    if let Some(x) = t.get("gossip_port") {
        let n = x
            .as_integer()
            .and_then(|i| u16::try_from(i).ok())
            .ok_or_else(|| {
                format!(
                    "{DAEMON_TOML}: [network.discovery].gossip_port must be an integer 1..=65535"
                )
            })?;
        out.gossip_port = n;
    }
    if let Some(x) = t.get("trigger_max_failures") {
        let n = x
            .as_integer()
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| {
                format!(
                    "{DAEMON_TOML}: [network.discovery].trigger_max_failures must be an integer 1..=10"
                )
            })?;
        out.trigger_max_failures = n;
    }
    if let Some(x) = t.get("advertise_ip") {
        let s = x.as_str().ok_or_else(|| {
            format!("{DAEMON_TOML}: [network.discovery].advertise_ip must be a string")
        })?;
        if !s.is_empty() {
            out.advertise_ip = Some(s.parse::<std::net::Ipv4Addr>().map_err(|_| {
                format!(
                    "{DAEMON_TOML}: [network.discovery].advertise_ip must be an IPv4 literal, got '{s}'"
                )
            })?);
        }
    }
    out.validate().map_err(|e| format!("{DAEMON_TOML}: {e}"))?;
    Ok(out)
}

/// 解析 `daemon.toml` 的 `[network.turn]` 小节（AC2）。
///
/// `server` / `realm` / `username` / `password` 为必填非空字符串；
/// `refresh_interval_sec` 可选（默认 300，必须 > 0）；
/// `stun_server` / `stun_server2` 可选（缺失时回落 `server` 做 STUN 探测）。
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
    let opt_server = |k: &str| -> Result<Option<String>, String> {
        match t.get(k) {
            None => Ok(None),
            Some(x) => {
                let s = x
                    .as_str()
                    .ok_or_else(|| format!("{DAEMON_TOML}: [network.turn].{k} must be a string"))?;
                if s.is_empty() {
                    return Err(format!(
                        "{DAEMON_TOML}: [network.turn].{k} must not be empty"
                    ));
                }
                Ok(Some(s.to_string()))
            }
        }
    };
    let stun_server = opt_server("stun_server")?;
    let stun_server2 = opt_server("stun_server2")?;
    let bind_addr = match t.get("bind_addr") {
        None => "0.0.0.0:0".to_string(),
        Some(x) => {
            let addr = x.as_str().ok_or_else(|| {
                format!("{DAEMON_TOML}: [network.turn].bind_addr must be a string")
            })?;
            addr.parse::<std::net::SocketAddr>()
                .map_err(|e| format!("{DAEMON_TOML}: [network.turn].bind_addr invalid: {e}"))?;
            addr.to_string()
        }
    };
    // `relay_book_dir`：缺失 = None（per-self 临时文件）；空字符串 = CONFIG 错误。
    let relay_book_dir = match t.get("relay_book_dir") {
        None => None,
        Some(x) => {
            let s = x.as_str().ok_or_else(|| {
                format!("{DAEMON_TOML}: [network.turn].relay_book_dir must be a string")
            })?;
            if s.is_empty() {
                return Err(format!(
                    "{DAEMON_TOML}: [network.turn].relay_book_dir must not be empty"
                ));
            }
            Some(std::path::PathBuf::from(s))
        }
    };
    Ok(TurnSection {
        server,
        realm,
        username,
        password,
        refresh_interval_sec,
        stun_server,
        stun_server2,
        bind_addr,
        relay_book_dir,
    })
}

/// 解析 `daemon.toml` 的 `[network.proxy]` 小节（#3 AC3 字段契约）。
///
/// 任一校验失败 → `Err`（daemon exit 1 + CONFIG 错误），不是运行时降级。
fn parse_proxy_section(t: &toml::Value) -> Result<ProxySection, String> {
    let proxy_type = match t.get("type") {
        Some(x) => {
            let s = x
                .as_str()
                .ok_or_else(|| format!("{DAEMON_TOML}: [network.proxy].type must be a string"))?;
            ProxyType::parse(s)?
        }
        None => {
            return Err(format!(
                "{DAEMON_TOML}: [network.proxy].type is required (socks5|shadowsocks|trojan)"
            ));
        }
    };

    let server = match t.get("server") {
        Some(x) => {
            let s = x
                .as_str()
                .ok_or_else(|| format!("{DAEMON_TOML}: [network.proxy].server must be a string"))?;
            if s.is_empty() {
                return Err(format!(
                    "{DAEMON_TOML}: [network.proxy].server must not be empty"
                ));
            }
            s.parse::<std::net::SocketAddr>().map_err(|e| {
                format!("{DAEMON_TOML}: [network.proxy].server must be a SocketAddr: {e}")
            })?
        }
        None => {
            return Err(format!(
                "{DAEMON_TOML}: [network.proxy].server is required (host:port)"
            ));
        }
    };

    let get_timeout = |key: &str| -> Result<u64, String> {
        match t.get(key) {
            None => Ok(10),
            Some(x) => {
                let n = x
                    .as_integer()
                    .and_then(|i| u64::try_from(i).ok())
                    .ok_or_else(|| {
                        format!("{DAEMON_TOML}: [network.proxy].{key} must be a positive integer")
                    })?;
                if n == 0 {
                    return Err(format!("{DAEMON_TOML}: [network.proxy].{key} must be > 0"));
                }
                Ok(n)
            }
        }
    };
    let connect_timeout_sec = get_timeout("connect_timeout_sec")?;
    let handshake_timeout_sec = get_timeout("handshake_timeout_sec")?;

    let username = t
        .get("username")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let password = t
        .get("password")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    let method = t
        .get("method")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // Trojan-only TLS 字段（#3 BLOCKER：trojan 真实服务端一律在 TLS 内握手）。
    let sni = match t.get("sni") {
        None => None,
        Some(x) => {
            let s = x
                .as_str()
                .ok_or_else(|| format!("{DAEMON_TOML}: [network.proxy].sni must be a string"))?;
            if s.is_empty() {
                return Err(format!(
                    "{DAEMON_TOML}: [network.proxy].sni must not be empty"
                ));
            }
            Some(s.to_string())
        }
    };
    let skip_cert_verify = match t.get("skip_cert_verify") {
        None => false,
        Some(x) => x.as_bool().ok_or_else(|| {
            format!("{DAEMON_TOML}: [network.proxy].skip_cert_verify must be a boolean")
        })?,
    };
    let alpn = match t.get("alpn") {
        None => None,
        Some(x) => {
            let arr = x.as_array().ok_or_else(|| {
                format!("{DAEMON_TOML}: [network.proxy].alpn must be an array of strings")
            })?;
            let mut protos = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item.as_str().ok_or_else(|| {
                    format!("{DAEMON_TOML}: [network.proxy].alpn must be an array of strings")
                })?;
                if s.is_empty() {
                    return Err(format!(
                        "{DAEMON_TOML}: [network.proxy].alpn entries must be non-empty"
                    ));
                }
                protos.push(s.to_string());
            }
            Some(protos)
        }
    };

    match proxy_type {
        ProxyType::Socks5 => {
            // socks5：username 有值而 password 缺失 → 认证不完整，Err。
            if username.is_some() && password.is_none() {
                return Err(format!(
                    "{DAEMON_TOML}: [network.proxy].password is required when username is set (socks5 RFC1929 auth)"
                ));
            }
        }
        ProxyType::Shadowsocks | ProxyType::Trojan => {
            // shadowsocks/trojan：password 必填非空。
            match password.as_deref() {
                Some(p) if !p.is_empty() => {}
                _ => {
                    return Err(format!(
                        "{DAEMON_TOML}: [network.proxy].password is required (non-empty) for {}",
                        proxy_type.as_str()
                    ));
                }
            }
        }
    }

    // sni/skip_cert_verify/alpn 仅对 trojan 有效；其他类型配置了 → 配置期报错
    // （不是静默忽略，#3 BLOCKER：避免"配了却永远不生效"）。
    if proxy_type != ProxyType::Trojan {
        let offending = if sni.is_some() {
            Some("sni")
        } else if t.get("skip_cert_verify").is_some() {
            Some("skip_cert_verify")
        } else if alpn.is_some() {
            Some("alpn")
        } else {
            None
        };
        if let Some(field) = offending {
            return Err(format!(
                "{DAEMON_TOML}: [network.proxy].{field} is only valid when type = \"trojan\" (got '{}')",
                proxy_type.as_str()
            ));
        }
    }

    // synth：trojan 缺省 SNI 从 server 的 IP 字符串推导（#4 TrojanTlsConfig::try_from 一致）。
    let sni = match proxy_type {
        ProxyType::Trojan => Some(sni.unwrap_or_else(|| server.ip().to_string())),
        _ => None,
    };

    // method：仅 shadowsocks 校验；非 ss 协议配置了 method 则忽略（不报错）。
    if proxy_type == ProxyType::Shadowsocks {
        if let Some(m) = method.as_deref() {
            nexus_proxy_transport::SsMethod::parse(m).map_err(|e| {
                format!("{DAEMON_TOML}: [network.proxy].method unsupported for shadowsocks: {e:?}")
            })?;
        }
    }

    Ok(ProxySection {
        proxy_type,
        server,
        username,
        password,
        method,
        sni,
        skip_cert_verify,
        alpn,
        connect_timeout_sec,
        handshake_timeout_sec,
    })
}

/// 解析 `daemon.toml` 的 `[tun]` 小节（T1）。
///
/// 接受 `enabled`（bool，默认 true）、`name`（非空字符串，默认 "nexus"）、
/// `mtu`（整数，需在 [1280, 9000] 内，默认 1500）。
fn parse_tun_section(t: &toml::Value) -> Result<TunSection, String> {
    let enabled_explicit = t.get("enabled").is_some();
    let enabled = t.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
    let name_explicit = t.get("name").is_some();
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
    let mtu_explicit = t.get("mtu").is_some();
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
    let default_route_explicit = t.get("default_route").is_some();
    let default_route = match t.get("default_route") {
        None => false,
        Some(x) => x
            .as_bool()
            .ok_or_else(|| format!("{DAEMON_TOML}: [tun].default_route must be a bool"))?,
    };
    let exclude_server_routes_explicit = t.get("exclude_server_routes").is_some();
    let exclude_server_routes = match t.get("exclude_server_routes") {
        None => true,
        Some(x) => x
            .as_bool()
            .ok_or_else(|| format!("{DAEMON_TOML}: [tun].exclude_server_routes must be a bool"))?,
    };
    Ok(TunSection {
        enabled,
        name,
        mtu,
        default_route,
        exclude_server_routes,
        enabled_explicit,
        name_explicit,
        mtu_explicit,
        default_route_explicit,
        exclude_server_routes_explicit,
    })
}

/// 解析 `daemon.toml` 的 `[flow_sessions]` 小节（spec §10.4）。
fn parse_flow_sessions_section(t: &toml::Value) -> Result<FlowSessionsSection, String> {
    use nexus_proxy_config::FlowSessionsMode;

    let enabled = match t.get("enabled") {
        None => None,
        Some(toml::Value::Boolean(b)) => Some(if *b {
            FlowSessionsMode::Enabled
        } else {
            FlowSessionsMode::Disabled
        }),
        Some(toml::Value::String(s)) => match s.as_str() {
            "auto" => Some(FlowSessionsMode::Auto),
            "true" => Some(FlowSessionsMode::Enabled),
            "false" => Some(FlowSessionsMode::Disabled),
            other => {
                return Err(format!(
                    "CONFIG_INVALID [flow_sessions.enabled]: expected \"auto\", true or false, got '{other}'"
                ));
            }
        },
        Some(_) => {
            return Err(
                "CONFIG_INVALID [flow_sessions.enabled]: expected \"auto\", true or false"
                    .to_string(),
            );
        }
    };

    let idle_timeout_secs = match t.get("idle_timeout_secs") {
        None => None,
        Some(x) => {
            let n = x.as_integer().and_then(|i| u64::try_from(i).ok()).ok_or_else(|| {
                "CONFIG_INVALID [flow_sessions.idle_timeout_secs]: must be a non-negative integer"
                    .to_string()
            })?;
            if n == 0 {
                return Err(
                    "CONFIG_INVALID [flow_sessions.idle_timeout_secs]: must be >= 1".to_string(),
                );
            }
            Some(n)
        }
    };

    let udp_buffer_datagrams = match t.get("udp_buffer_datagrams") {
        None => None,
        Some(x) => {
            let n = x
                .as_integer()
                .and_then(|i| usize::try_from(i).ok())
                .ok_or_else(|| {
                    "CONFIG_INVALID [flow_sessions.udp_buffer_datagrams]: must be a non-negative integer"
                        .to_string()
                })?;
            if n == 0 {
                return Err(
                    "CONFIG_INVALID [flow_sessions.udp_buffer_datagrams]: must be >= 1".to_string(),
                );
            }
            Some(n)
        }
    };

    Ok(FlowSessionsSection {
        enabled,
        idle_timeout_secs,
        udp_buffer_datagrams,
    })
}

/// `daemon.toml [tun]` 与 `inbounds[kind=tun]` 的映射/冲突规则（spec §10.7）。
fn validate_legacy_tun_mapping(
    tun: &TunSection,
    proxy: &nexus_proxy_config::ProxyConfig,
) -> Result<(), String> {
    let tun_inbounds: Vec<(usize, &nexus_proxy_config::TunInboundConfig)> = proxy
        .inbounds
        .iter()
        .enumerate()
        .filter(|(_, inbound)| inbound.kind == nexus_proxy_config::InboundKind::Tun)
        .filter_map(|(i, inbound)| inbound.tun.as_ref().map(|cfg| (i, cfg)))
        .collect();

    if tun.enabled_explicit && !tun.enabled {
        if let Some((i, _)) = tun_inbounds.first() {
            return Err(format!(
                "CONFIG_INVALID [inbounds[{i}].kind]: daemon.toml [tun].enabled=false conflicts with a tun inbound"
            ));
        }
    }

    for (i, inbound) in &tun_inbounds {
        if tun.name_explicit && inbound.name != tun.name {
            return Err(format!(
                "CONFIG_INVALID [tun.name]: '{}' conflicts with inbounds[{i}].name='{}' (set only one)",
                tun.name, inbound.name
            ));
        }
        if tun.mtu_explicit && inbound.mtu != u16::try_from(tun.mtu).unwrap_or(u16::MAX) {
            return Err(format!(
                "CONFIG_INVALID [tun.mtu]: {} conflicts with inbounds[{i}].mtu={} (set only one)",
                tun.mtu, inbound.mtu
            ));
        }
    }
    Ok(())
}

/// `[flow_sessions].enabled` 与 `inbounds[kind=tun].sessions` 的冲突校验（spec §10.7）。
fn validate_flow_sessions_conflicts(
    flow: &FlowSessionsSection,
    proxy: &nexus_proxy_config::ProxyConfig,
) -> Result<(), String> {
    let Some(flow_mode) = flow.enabled else {
        return Ok(());
    };
    for (i, inbound) in proxy.inbounds.iter().enumerate() {
        if inbound.kind != nexus_proxy_config::InboundKind::Tun {
            continue;
        }
        let Some(tun) = inbound.tun.as_ref() else {
            continue;
        };
        if tun.sessions_explicit && tun.sessions != flow_mode {
            return Err(format!(
                "CONFIG_INVALID [flow_sessions.enabled]: {} conflicts with inbounds[{i}].sessions={} (set only one)",
                flow_mode.as_str(),
                tun.sessions.as_str()
            ));
        }
    }
    Ok(())
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
        ip_preference: nexus_dns::IpPreference::PreferV4,
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

// ---------------------------------------------------------------------------
// R3 strict dns.toml schema (§4.6.1) — additive; production switches in C11.
// ---------------------------------------------------------------------------

pub use crate::dns_status::{UnevaluablePolicy, UnmatchedPolicy};

/// Upstream engine knobs, flat under `[dns]` (§4.6.1 / §4.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    /// `IP[:port]` / `[v6]:port`, deduplicated in declaration order, 1..=8.
    pub servers: Vec<std::net::SocketAddr>,
    /// Single-send wait (default 500).
    pub attempt_timeout_ms: u64,
    /// Sends per server including the first (default 2, 1..=4).
    pub attempts_per_server: u8,
    /// Whole-query budget from submit (default 4000, >= attempt_timeout_ms).
    pub total_budget_ms: u64,
    /// EDNS UDP payload size; `0` disables OPT (default 1232).
    pub edns_udp_size: u16,
    /// Retry over TCP on TC=1 (default true).
    pub tcp_fallback: bool,
    /// TCP fallback timeout (default 2000, 100..=10000).
    pub tcp_timeout_ms: u64,
    /// Total positive+negative cache entries (default 1024; 0 disables).
    pub cache_max_entries: usize,
    /// Positive TTL clamp upper bound (default 3600).
    pub cache_max_ttl_secs: u32,
    /// Negative cache TTL (default 60; 0 disables negative caching).
    pub negative_ttl_secs: u32,
    /// In-flight upstream queries (default 64, 1..=1024).
    pub max_inflight: usize,
}

/// DNS proxy policy (`[dns].unmatched` / `[dns].unevaluable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProxyPolicy {
    /// No rule matched.
    pub unmatched: UnmatchedPolicy,
    /// Rule needs unloaded data (`geosite` / `rule_set`).
    pub unevaluable: UnevaluablePolicy,
}

/// Fully validated `dns.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFileConfig {
    /// Classification inputs consumed by `UnifiedDns`.
    pub unified: nexus_dns::DnsUnifiedConfig,
    /// `[dns.mesh.hosts]` entries (lowercase FQDN → address).
    pub mesh_hosts: Vec<(String, std::net::IpAddr)>,
    /// Proxy policy.
    pub proxy: DnsProxyPolicy,
    /// Upstream engine knobs.
    pub upstream: UpstreamConfig,
}

/// Strict `dns.toml` validation error (§5.3; exactly nine variants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsConfigError {
    /// Unknown key, or a root-level key that must move under `[dns]`.
    UnknownKey(String),
    /// `dns.toml` exists but `[dns].upstream` is missing/empty.
    EmptyUpstream,
    /// More than eight unique upstream servers.
    TooManyUpstream,
    /// Upstream address/port cannot be parsed.
    BadUpstreamAddr(String),
    /// Wrong type, range, enum value, or TOML syntax.
    BadValue {
        /// Key path without the `dns.` prefix.
        key: String,
        /// Human-readable reason.
        reason: String,
    },
    /// Mesh key is not lowercase, lacks the mesh suffix, or is too long.
    MeshNameInvalid(String),
    /// Mesh value is not a unicast address or is outside the mesh routes.
    MeshAddrInvalid(String),
    /// Mesh hosts exist but `network.toml` has no route for that family.
    MeshWithoutRoutes,
    /// `unmatched=proxied` without any usable outbound.
    ProxyPolicyConflict,
}

impl std::fmt::Display for DnsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey(key) => write!(
                f,
                "{DNS_TOML}: unknown key '{key}' (all keys must live under [dns])"
            ),
            Self::EmptyUpstream => write!(f, "{DNS_TOML}: dns.upstream must not be empty"),
            Self::TooManyUpstream => {
                write!(f, "{DNS_TOML}: dns.upstream accepts at most 8 servers")
            }
            Self::BadUpstreamAddr(addr) => {
                write!(f, "{DNS_TOML}: dns.upstream bad address '{addr}'")
            }
            Self::BadValue { key, reason } => write!(f, "{DNS_TOML}: {key}: {reason}"),
            Self::MeshNameInvalid(name) => {
                write!(f, "{DNS_TOML}: dns.mesh.hosts invalid name '{name}'")
            }
            Self::MeshAddrInvalid(detail) => {
                write!(f, "{DNS_TOML}: dns.mesh.hosts invalid address: {detail}")
            }
            Self::MeshWithoutRoutes => write!(
                f,
                "{DNS_TOML}: dns.mesh.hosts requires [[vpi.routes]]/[[vpi.routes6]] in network.toml"
            ),
            Self::ProxyPolicyConflict => write!(
                f,
                "{DNS_TOML}: dns.unmatched=proxied requires a usable outbound"
            ),
        }
    }
}

impl std::error::Error for DnsConfigError {}

impl UnmatchedPolicy {
    /// Parse `[dns].unmatched`.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "proxied" => Some(Self::Proxied),
            "upstream" => Some(Self::Upstream),
            _ => None,
        }
    }
}

impl UnevaluablePolicy {
    /// Parse `[dns].unevaluable`.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "proxied" => Some(Self::Proxied),
            "upstream" => Some(Self::Upstream),
            _ => None,
        }
    }
}

const DNS_KEYS: &[&str] = &[
    "upstream",
    "fake_ip_enabled",
    "fake_ip_range",
    "mesh_suffix",
    "fake_ip_ttl_secs",
    "hosts",
    "ip_preference",
    "unmatched",
    "unevaluable",
    "attempt_timeout_ms",
    "attempts_per_server",
    "total_budget_ms",
    "edns_udp_size",
    "tcp_fallback",
    "tcp_timeout_ms",
    "cache_max_entries",
    "cache_max_ttl_secs",
    "negative_ttl_secs",
    "max_inflight",
    "mesh",
];

fn dns_bad(key: &str, reason: impl Into<String>) -> DnsConfigError {
    DnsConfigError::BadValue {
        key: format!("dns.{key}"),
        reason: reason.into(),
    }
}

fn dns_bool(table: &toml::value::Table, key: &str, default: bool) -> Result<bool, DnsConfigError> {
    match table.get(key) {
        None => Ok(default),
        Some(v) => v.as_bool().ok_or_else(|| dns_bad(key, "expected a bool")),
    }
}

fn dns_str<'a>(
    table: &'a toml::value::Table,
    key: &str,
    default: &'a str,
) -> Result<&'a str, DnsConfigError> {
    match table.get(key) {
        None => Ok(default),
        Some(v) => v.as_str().ok_or_else(|| dns_bad(key, "expected a string")),
    }
}

fn dns_u64(table: &toml::value::Table, key: &str, default: u64) -> Result<u64, DnsConfigError> {
    match table.get(key) {
        None => Ok(default),
        Some(v) => {
            let n = v
                .as_integer()
                .ok_or_else(|| dns_bad(key, "expected an integer"))?;
            u64::try_from(n).map_err(|_| dns_bad(key, "must be >= 0"))
        }
    }
}

fn dns_usize(
    table: &toml::value::Table,
    key: &str,
    default: usize,
) -> Result<usize, DnsConfigError> {
    let n = dns_u64(table, key, default as u64)?;
    usize::try_from(n).map_err(|_| dns_bad(key, "value out of range"))
}

fn dns_u16(table: &toml::value::Table, key: &str, default: u16) -> Result<u16, DnsConfigError> {
    let n = dns_u64(table, key, u64::from(default))?;
    u16::try_from(n).map_err(|_| dns_bad(key, "value out of range"))
}

fn dns_u32(table: &toml::value::Table, key: &str, default: u32) -> Result<u32, DnsConfigError> {
    let n = dns_u64(table, key, u64::from(default))?;
    u32::try_from(n).map_err(|_| dns_bad(key, "value out of range"))
}

fn dns_u8(table: &toml::value::Table, key: &str, default: u8) -> Result<u8, DnsConfigError> {
    let n = dns_u64(table, key, u64::from(default))?;
    u8::try_from(n).map_err(|_| dns_bad(key, "value out of range"))
}

fn range_err(key: &str, allowed: &str) -> DnsConfigError {
    dns_bad(key, format!("must be {allowed}"))
}

/// Parse `A.B.C.D[:port]` / `[v6]:port` / bare IPv6 (port 53).
fn parse_upstream_addr(raw: &str) -> Result<std::net::SocketAddr, DnsConfigError> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    let s = raw.trim();
    if s.is_empty() {
        return Err(DnsConfigError::BadUpstreamAddr(raw.to_string()));
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        if addr.port() == 0 {
            return Err(DnsConfigError::BadUpstreamAddr(raw.to_string()));
        }
        return Ok(addr);
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let v6: Ipv6Addr = inner
            .parse()
            .map_err(|_| DnsConfigError::BadUpstreamAddr(raw.to_string()))?;
        return Ok(SocketAddr::new(v6.into(), 53));
    }
    let colons = s.matches(':').count();
    let (host, port) = match colons {
        0 => (s, 53),
        1 => {
            let (h, p) = s
                .split_once(':')
                .ok_or_else(|| DnsConfigError::BadUpstreamAddr(raw.to_string()))?;
            let port: u16 = p
                .parse()
                .map_err(|_| DnsConfigError::BadUpstreamAddr(raw.to_string()))?;
            (h, port)
        }
        _ => (s, 53),
    };
    if port == 0 {
        return Err(DnsConfigError::BadUpstreamAddr(raw.to_string()));
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(v4.into(), port));
    }
    let v6: Ipv6Addr = host
        .parse()
        .map_err(|_| DnsConfigError::BadUpstreamAddr(raw.to_string()))?;
    Ok(SocketAddr::new(v6.into(), port))
}

/// Minimal `network.toml` view needed for mesh route validation. Returns `None`
/// when the document is unreadable; callers turn that into `MeshWithoutRoutes`.
struct MeshNetworks {
    v4: Vec<(u32, u8)>,
    v6: Vec<(u128, u8)>,
}

fn parse_mesh_networks(text: Option<&str>) -> Option<MeshNetworks> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let value: toml::Value = toml::from_str(text?).ok()?;
    let vpi = value.get("vpi")?.as_table()?;
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    if let Some(routes) = vpi.get("routes").and_then(|v| v.as_array()) {
        for route in routes {
            let Some(subnet) = route.get("subnet").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some((addr, prefix)) = subnet.split_once('/') {
                let (Ok(addr), Ok(prefix)) = (addr.parse::<Ipv4Addr>(), prefix.parse::<u8>())
                else {
                    continue;
                };
                if prefix <= 32 {
                    v4.push((u32::from(addr) & mask_v4(prefix), prefix));
                }
            }
        }
    }
    if let Some(routes) = vpi.get("routes6").and_then(|v| v.as_array()) {
        for route in routes {
            let Some(subnet) = route.get("subnet").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some((addr, prefix)) = subnet.split_once('/') {
                let (Ok(addr), Ok(prefix)) = (addr.parse::<Ipv6Addr>(), prefix.parse::<u8>())
                else {
                    continue;
                };
                if prefix <= 128 {
                    v6.push((u128::from(addr) & mask_v6(prefix), prefix));
                }
            }
        }
    }
    Some(MeshNetworks { v4, v6 })
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl MeshNetworks {
    fn contains(&self, ip: std::net::IpAddr) -> Result<bool, DnsConfigError> {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if self.v4.is_empty() {
                    return Err(DnsConfigError::MeshWithoutRoutes);
                }
                let raw = u32::from(v4);
                Ok(self
                    .v4
                    .iter()
                    .any(|(net, prefix)| raw & mask_v4(*prefix) == *net))
            }
            std::net::IpAddr::V6(v6) => {
                if self.v6.is_empty() {
                    return Err(DnsConfigError::MeshWithoutRoutes);
                }
                let raw = u128::from(v6);
                Ok(self
                    .v6
                    .iter()
                    .any(|(net, prefix)| raw & mask_v6(*prefix) == *net))
            }
        }
    }
}

/// Strictly parse `dns.toml` (§4.6.1), validating mesh ownership against the
/// raw `network.toml` text and the `unmatched=proxied` policy against the
/// outbound layer.
///
/// `has_usable_outbound` must be derived from
/// `nexus::outbound_manifest::select_index` (F1 / §6.2), never re-implemented.
///
/// The old loose [`parse_dns_toml`] stays in place until C11 replaces it.
///
/// # Errors
///
/// Any of the nine [`DnsConfigError`] variants.
pub fn parse_dns_config(
    text: &str,
    network_toml: Option<&str>,
    has_usable_outbound: bool,
) -> Result<DnsFileConfig, DnsConfigError> {
    use nexus_dns::{DEFAULT_FAKE_IP_RANGE, DEFAULT_MESH_SUFFIX, DnsUnifiedConfig, IpPreference};

    let value: toml::Value = toml::from_str(text).map_err(|e| DnsConfigError::BadValue {
        key: DNS_TOML.to_string(),
        reason: format!("invalid TOML: {e}"),
    })?;
    let root = value.as_table().ok_or_else(|| DnsConfigError::BadValue {
        key: DNS_TOML.to_string(),
        reason: "root must be a table".to_string(),
    })?;
    for key in root.keys() {
        if key != "dns" {
            return Err(DnsConfigError::UnknownKey(key.clone()));
        }
    }
    let Some(dns_value) = root.get("dns") else {
        return Err(DnsConfigError::EmptyUpstream);
    };
    let table = dns_value
        .as_table()
        .ok_or_else(|| DnsConfigError::BadValue {
            key: DNS_TOML.to_string(),
            reason: "[dns] must be a table".to_string(),
        })?;
    for key in table.keys() {
        if !DNS_KEYS.contains(&key.as_str()) {
            return Err(DnsConfigError::UnknownKey(key.clone()));
        }
    }

    // upstream: required, non-empty, deduped in order, at most 8.
    let upstream_value = table.get("upstream").ok_or(DnsConfigError::EmptyUpstream)?;
    let upstream_items = upstream_value
        .as_array()
        .ok_or_else(|| dns_bad("upstream", "expected an array of strings"))?;
    if upstream_items.is_empty() {
        return Err(DnsConfigError::EmptyUpstream);
    }
    let mut raw_upstream = Vec::with_capacity(upstream_items.len());
    let mut servers: Vec<std::net::SocketAddr> = Vec::new();
    for item in upstream_items {
        let raw = item
            .as_str()
            .ok_or_else(|| dns_bad("upstream", "expected an array of strings"))?;
        let addr = parse_upstream_addr(raw)?;
        if !servers.contains(&addr) {
            servers.push(addr);
            raw_upstream.push(raw.trim().to_string());
        }
    }
    if servers.len() > 8 {
        return Err(DnsConfigError::TooManyUpstream);
    }

    let fake_ip_enabled = dns_bool(table, "fake_ip_enabled", true)?;
    let fake_ip_range = dns_str(table, "fake_ip_range", DEFAULT_FAKE_IP_RANGE)?;
    let (fake_ip_network, fake_ip_prefix) =
        parse_cidr_v4(fake_ip_range).map_err(|e| dns_bad("fake_ip_range", e))?;
    if fake_ip_prefix > 30 {
        return Err(range_err(
            "fake_ip_range",
            "an IPv4 CIDR with prefix <= 30 (at least two hosts)",
        ));
    }

    let mesh_suffix = dns_str(table, "mesh_suffix", DEFAULT_MESH_SUFFIX)?.to_ascii_lowercase();
    if mesh_suffix.is_empty() || mesh_suffix.chars().count() > 63 || mesh_suffix.contains('.') {
        return Err(range_err("mesh_suffix", "1..=63 characters without '.'"));
    }

    let fake_ip_ttl_secs = dns_u64(table, "fake_ip_ttl_secs", 300)?;
    if fake_ip_ttl_secs == 0 {
        return Err(range_err("fake_ip_ttl_secs", ">= 1"));
    }

    let mut hosts = Vec::new();
    if let Some(hosts_value) = table.get("hosts") {
        let hosts_table = hosts_value
            .as_table()
            .ok_or_else(|| dns_bad("hosts", "expected a table of name -> IP"))?;
        for (name, value) in hosts_table {
            let ip_str = value
                .as_str()
                .ok_or_else(|| dns_bad("hosts", format!("hosts.{name} must be an IP string")))?;
            let ip: std::net::IpAddr = ip_str
                .parse()
                .map_err(|_| dns_bad("hosts", format!("hosts.{name} bad IP '{ip_str}'")))?;
            let normalized = name.to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(dns_bad("hosts", "empty host name"));
            }
            if hosts
                .iter()
                .any(|(n, _): &(String, std::net::IpAddr)| *n == normalized)
            {
                return Err(dns_bad("hosts", format!("duplicate host '{normalized}'")));
            }
            hosts.push((normalized, ip));
        }
    }

    let preference = dns_str(table, "ip_preference", "prefer_v4")?;
    let ip_preference = match preference {
        "v4_only" => IpPreference::V4Only,
        "v6_only" => IpPreference::V6Only,
        "prefer_v4" => IpPreference::PreferV4,
        "prefer_v6" => IpPreference::PreferV6,
        other => {
            return Err(dns_bad(
                "ip_preference",
                format!("unknown value '{other}' (v4_only|v6_only|prefer_v4|prefer_v6)"),
            ));
        }
    };

    let unmatched_raw = dns_str(table, "unmatched", "auto")?;
    let unmatched = UnmatchedPolicy::parse(unmatched_raw).ok_or_else(|| {
        dns_bad(
            "unmatched",
            format!("unknown value '{unmatched_raw}' (auto|proxied|upstream)"),
        )
    })?;
    let unevaluable_raw = dns_str(table, "unevaluable", "proxied")?;
    let unevaluable = UnevaluablePolicy::parse(unevaluable_raw).ok_or_else(|| {
        dns_bad(
            "unevaluable",
            format!("unknown value '{unevaluable_raw}' (proxied|upstream)"),
        )
    })?;

    let attempt_timeout_ms = dns_u64(table, "attempt_timeout_ms", 500)?;
    if !(50..=5000).contains(&attempt_timeout_ms) {
        return Err(range_err("attempt_timeout_ms", "in 50..=5000"));
    }
    let attempts_per_server = dns_u8(table, "attempts_per_server", 2)?;
    if !(1..=4).contains(&attempts_per_server) {
        return Err(range_err("attempts_per_server", "in 1..=4"));
    }
    let total_budget_ms = dns_u64(table, "total_budget_ms", 4000)?;
    if total_budget_ms < attempt_timeout_ms || total_budget_ms > 30_000 {
        return Err(range_err(
            "total_budget_ms",
            ">= attempt_timeout_ms and <= 30000",
        ));
    }
    let edns_udp_size = dns_u16(table, "edns_udp_size", 1232)?;
    if edns_udp_size != 0 && !(512..=4096).contains(&edns_udp_size) {
        return Err(range_err("edns_udp_size", "0 (disabled) or in 512..=4096"));
    }
    let tcp_fallback = dns_bool(table, "tcp_fallback", true)?;
    let tcp_timeout_ms = dns_u64(table, "tcp_timeout_ms", 2000)?;
    if !(100..=10_000).contains(&tcp_timeout_ms) {
        return Err(range_err("tcp_timeout_ms", "in 100..=10000"));
    }
    let cache_max_entries = dns_usize(table, "cache_max_entries", 1024)?;
    let cache_max_ttl_secs = dns_u32(table, "cache_max_ttl_secs", 3600)?;
    if cache_max_ttl_secs == 0 {
        return Err(range_err("cache_max_ttl_secs", ">= 1"));
    }
    let negative_ttl_secs = dns_u32(table, "negative_ttl_secs", 60)?;
    let max_inflight = dns_usize(table, "max_inflight", 64)?;
    if !(1..=1024).contains(&max_inflight) {
        return Err(range_err("max_inflight", "in 1..=1024"));
    }

    // [dns.mesh] may only contain `hosts`.
    let mut mesh_hosts = Vec::new();
    if let Some(mesh_value) = table.get("mesh") {
        let mesh_table = mesh_value
            .as_table()
            .ok_or_else(|| dns_bad("mesh", "expected a table"))?;
        for key in mesh_table.keys() {
            if key != "hosts" {
                return Err(DnsConfigError::UnknownKey(format!("mesh.{key}")));
            }
        }
        if let Some(hosts_value) = mesh_table.get("hosts") {
            let mesh_table = hosts_value
                .as_table()
                .ok_or_else(|| dns_bad("mesh.hosts", "expected a table of name -> IP"))?;
            for (name, value) in mesh_table {
                let lower = name.to_ascii_lowercase();
                let suffix = format!(".{mesh_suffix}");
                if &lower != name
                    || name.len() > 253
                    || !name.ends_with(&suffix)
                    || name.split('.').any(str::is_empty)
                {
                    return Err(DnsConfigError::MeshNameInvalid(name.clone()));
                }
                let ip_str = value.as_str().ok_or_else(|| {
                    DnsConfigError::MeshAddrInvalid(format!("{name}: expected an IP string"))
                })?;
                let ip: std::net::IpAddr = ip_str
                    .parse()
                    .map_err(|_| DnsConfigError::MeshAddrInvalid(format!("{name}={ip_str}")))?;
                // SU-3: loopback rejected, link-local accepted, non-unicast rejected.
                nexus_dns::StaticMeshResolver::new([(name.clone(), ip)]).map_err(|e| {
                    DnsConfigError::MeshAddrInvalid(format!("{name}={ip_str}: {e}"))
                })?;
                mesh_hosts.push((name.clone(), ip));
            }
        }
    }

    if !mesh_hosts.is_empty() {
        let networks =
            parse_mesh_networks(network_toml).ok_or(DnsConfigError::MeshWithoutRoutes)?;
        for (name, ip) in &mesh_hosts {
            if !networks.contains(*ip)? {
                return Err(DnsConfigError::MeshAddrInvalid(format!(
                    "{name}={ip} is outside the configured mesh routes"
                )));
            }
        }
    }

    if unmatched == UnmatchedPolicy::Proxied && !has_usable_outbound {
        return Err(DnsConfigError::ProxyPolicyConflict);
    }

    Ok(DnsFileConfig {
        unified: DnsUnifiedConfig {
            upstream: raw_upstream,
            fake_ip_enabled,
            fake_ip_network,
            fake_ip_prefix,
            mesh_suffix,
            fake_ip_ttl_secs,
            hosts,
            ip_preference,
        },
        mesh_hosts,
        proxy: DnsProxyPolicy {
            unmatched,
            unevaluable,
        },
        upstream: UpstreamConfig {
            servers,
            attempt_timeout_ms,
            attempts_per_server,
            total_budget_ms,
            edns_udp_size,
            tcp_fallback,
            tcp_timeout_ms,
            cache_max_entries,
            cache_max_ttl_secs,
            negative_ttl_secs,
            max_inflight,
        },
    })
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

/// 入站装配签名：只覆盖影响数据面装配的字段（spec §10.8）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct InboundSignature {
    kind: nexus_proxy_config::InboundKind,
    tun: Option<nexus_proxy_config::TunInboundConfig>,
    tproxy: Option<nexus_proxy_config::TproxyInboundConfig>,
}

/// 从 `proxy.yaml` 原文提取入站签名；缺失或解析失败时返回 `None`
/// （解析失败由 `load` 先行拒绝，这里只做变更分类）。
fn inbound_signatures(yaml: Option<&str>) -> Option<Vec<InboundSignature>> {
    let parsed = nexus_proxy_config::parse(yaml?).ok()?;
    Some(
        parsed
            .inbounds
            .iter()
            .map(|inbound| InboundSignature {
                kind: inbound.kind,
                tun: inbound.tun.clone(),
                tproxy: inbound.tproxy.clone(),
            })
            .collect(),
    )
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
    // daemon.toml：[flow_sessions] 变化需重启数据面（spec §10.8）。
    if old.daemon.flow_sessions != new.daemon.flow_sessions {
        return ChangeKind::NeedsRestart;
    }
    // daemon.toml：[network.turn] 小节变化需重启（TURN 客户端启停需重建）。
    if old.daemon.turn != new.daemon.turn {
        return ChangeKind::NeedsRestart;
    }
    // daemon.toml：[network.discovery] 小节变化需重启（pump/feed 生命周期
    // 需重建；与 [network.turn] 同口径，spec §4.11.1）。
    if old.daemon.discovery != new.daemon.discovery {
        return ChangeKind::NeedsRestart;
    }
    // daemon.toml：[network.proxy] 小节变化需重启（#3：代理客户端生命周期需重建）
    if old.daemon.proxy != new.daemon.proxy {
        return ChangeKind::NeedsRestart;
    }
    // Q-7=B（spec §7.6.1）：proxy.yaml **内容变更** → NeedsRestart（engine 只在
    // 启动构造；不允许再谎报 hot-reloaded）。
    if old.proxy_yaml != new.proxy_yaml {
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
    // proxy.yaml 的 tun/tproxy 入站增删或参数（端口/设备/MTU/默认路由）变化 →
    // NeedsRestart。Q-7=B 之后本特判已被上方的「内容变更 → NeedsRestart」覆盖，
    // 保留无害（防御未来把内容变更改回 Hot 的回归）。
    if inbound_signatures(old.proxy_yaml.as_deref())
        != inbound_signatures(new.proxy_yaml.as_deref())
    {
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

/// `[network.punch]` 配置小节（spec §14.4/§15；26 字段）。
#[derive(Debug, Clone, PartialEq)]
pub struct PunchSection {
    pub enabled: bool,
    pub punch_timeout_ms: u64,
    pub coord_skew_ms: u64,
    pub spray_k: u8,
    pub spray_interval_ms: u64,
    pub spray_time_budget_ms: u64,
    pub repunch_interval_sec: u64,
    pub repunch_jitter_sec: u64,
    pub repunch_on_reflexive_change: bool,
    pub repunch_on_relay_degradation: bool,
    pub prediction_samples: u8,
    pub max_sample_age_sec: u64,
    pub max_stable_delta: u16,
    pub mapping_probe_count: u8,
    pub mapping_probe_interval_ms: u64,
    pub relay_provider_enabled: bool,
    pub hysteresis_pct: f64,
    pub switch_hold_ms: u64,
    pub boost_hysteresis_pct: f64,
    pub boost_hold_ms: u64,
    pub probe_active_ms: u64,
    pub probe_backup_ms: u64,
    pub max_missed_probes: u32,
    pub cost_direct: f64,
    pub cost_turn: f64,
    pub cost_peer_relay: f64,
}

impl Default for PunchSection {
    fn default() -> Self {
        Self {
            enabled: true,
            punch_timeout_ms: 5_000,
            coord_skew_ms: 200,
            spray_k: 16,
            spray_interval_ms: 50,
            spray_time_budget_ms: 3_000,
            repunch_interval_sec: 300,
            repunch_jitter_sec: 0,
            repunch_on_reflexive_change: true,
            repunch_on_relay_degradation: true,
            prediction_samples: 3,
            max_sample_age_sec: 900,
            max_stable_delta: 8,
            mapping_probe_count: 3,
            mapping_probe_interval_ms: 50,
            relay_provider_enabled: true,
            hysteresis_pct: 0.20,
            switch_hold_ms: 3_000,
            boost_hysteresis_pct: 0.10,
            boost_hold_ms: 1_000,
            probe_active_ms: 1_000,
            probe_backup_ms: 5_000,
            max_missed_probes: 3,
            cost_direct: 0.0,
            cost_turn: 5.0,
            cost_peer_relay: 2.0,
        }
    }
}

impl PunchSection {
    /// Validate the external file-boundary values (no silent clamping).
    pub fn validate(&self) -> Result<(), nexus_nat_traversal::PunchConfigError> {
        use nexus_nat_traversal::PunchConfigError;
        let checks: [(&'static str, i64, i64, i64); 18] = [
            (
                "punch_timeout_ms",
                self.punch_timeout_ms as i64,
                500,
                30_000,
            ),
            ("coord_skew_ms", self.coord_skew_ms as i64, 0, 2_000),
            ("spray_k", i64::from(self.spray_k), 1, 32),
            ("spray_interval_ms", self.spray_interval_ms as i64, 10, 500),
            (
                "spray_time_budget_ms",
                self.spray_time_budget_ms as i64,
                500,
                10_000,
            ),
            (
                "repunch_interval_sec",
                self.repunch_interval_sec as i64,
                60,
                3_600,
            ),
            ("repunch_jitter_sec", self.repunch_jitter_sec as i64, 0, 60),
            (
                "prediction_samples",
                i64::from(self.prediction_samples),
                3,
                8,
            ),
            (
                "max_sample_age_sec",
                self.max_sample_age_sec as i64,
                60,
                3_600,
            ),
            ("max_stable_delta", i64::from(self.max_stable_delta), 1, 64),
            (
                "mapping_probe_count",
                i64::from(self.mapping_probe_count),
                1,
                5,
            ),
            (
                "mapping_probe_interval_ms",
                self.mapping_probe_interval_ms as i64,
                10,
                500,
            ),
            (
                "hysteresis_pct",
                (self.hysteresis_pct * 100.0) as i64,
                0,
                100,
            ),
            ("switch_hold_ms", self.switch_hold_ms as i64, 0, 60_000),
            (
                "boost_hysteresis_pct",
                (self.boost_hysteresis_pct * 100.0) as i64,
                0,
                100,
            ),
            ("boost_hold_ms", self.boost_hold_ms as i64, 0, 60_000),
            ("probe_active_ms", self.probe_active_ms as i64, 100, 60_000),
            (
                "max_missed_probes",
                i64::from(self.max_missed_probes),
                1,
                10,
            ),
        ];
        for (field, value, min, max) in checks {
            if value < min || value > max {
                return Err(PunchConfigError::OutOfRange {
                    field,
                    value,
                    min,
                    max,
                });
            }
        }
        if self.probe_backup_ms < self.probe_active_ms || self.probe_backup_ms > 60_000 {
            return Err(PunchConfigError::OutOfRange {
                field: "probe_backup_ms",
                value: self.probe_backup_ms as i64,
                min: self.probe_active_ms as i64,
                max: 60_000,
            });
        }
        for (field, v) in [
            ("cost_direct", self.cost_direct),
            ("cost_turn", self.cost_turn),
            ("cost_peer_relay", self.cost_peer_relay),
        ] {
            if !(0.0..=10.0).contains(&v) {
                return Err(PunchConfigError::OutOfRange {
                    field,
                    value: v as i64,
                    min: 0,
                    max: 10,
                });
            }
        }
        if self.spray_time_budget_ms > self.punch_timeout_ms {
            return Err(PunchConfigError::InvalidCombination {
                field: "spray_time_budget_ms",
                reason: "spray time budget cannot exceed punch_timeout_ms",
            });
        }
        let window = 2u64 * u64::from(self.spray_k) * self.spray_interval_ms;
        if window > self.spray_time_budget_ms {
            return Err(PunchConfigError::InvalidCombination {
                field: "spray_interval_ms",
                reason: "spray window cannot fit in spray_time_budget_ms",
            });
        }
        Ok(())
    }

    pub fn to_punch_config(&self) -> nexus_nat_traversal::PunchConfig {
        use std::time::Duration;
        nexus_nat_traversal::PunchConfig {
            punch_timeout: Duration::from_millis(self.punch_timeout_ms),
            coord_skew_ms: self.coord_skew_ms,
            spray_k: self.spray_k,
            spray_interval_ms: self.spray_interval_ms,
            spray_time_budget: Duration::from_millis(self.spray_time_budget_ms),
            repunch_interval: Duration::from_secs(self.repunch_interval_sec),
            repunch_jitter: Duration::from_secs(self.repunch_jitter_sec),
            prediction_samples: self.prediction_samples,
            max_sample_age: Duration::from_secs(self.max_sample_age_sec),
            max_stable_delta: self.max_stable_delta,
            mapping_probe_count: self.mapping_probe_count,
            mapping_probe_interval_ms: self.mapping_probe_interval_ms,
        }
    }

    pub fn to_path_config(&self) -> nexus_path::PathConfig {
        nexus_path::PathConfig {
            hysteresis_pct: self.hysteresis_pct,
            switch_hold_ms: self.switch_hold_ms,
            probe_interval_ms: self.probe_active_ms,
            ewma_alpha: 0.3,
            max_missed_probes: self.max_missed_probes,
            race_budget: nexus_path::RaceBudget::default(),
        }
    }
}

fn parse_punch_section(t: &toml::Value) -> Result<PunchSection, String> {
    let mut p = PunchSection::default();
    let err = |f: &str| format!("{DAEMON_TOML}: [network.punch].{f} invalid");
    macro_rules! get_bool {
        ($f:ident) => {
            if let Some(x) = t.get(stringify!($f)) {
                p.$f = x.as_bool().ok_or_else(|| err(stringify!($f)))?;
            }
        };
    }
    macro_rules! get_num {
        ($f:ident, $ty:ty) => {
            if let Some(x) = t.get(stringify!($f)) {
                p.$f = x
                    .as_integer()
                    .and_then(|i| <$ty>::try_from(i).ok())
                    .ok_or_else(|| err(stringify!($f)))?;
            }
        };
    }
    macro_rules! get_float {
        ($f:ident) => {
            if let Some(x) = t.get(stringify!($f)) {
                p.$f = x.as_float().ok_or_else(|| err(stringify!($f)))?;
            }
        };
    }
    get_bool!(enabled);
    get_num!(punch_timeout_ms, u64);
    get_num!(coord_skew_ms, u64);
    get_num!(spray_k, u8);
    get_num!(spray_interval_ms, u64);
    get_num!(spray_time_budget_ms, u64);
    get_num!(repunch_interval_sec, u64);
    get_num!(repunch_jitter_sec, u64);
    get_bool!(repunch_on_reflexive_change);
    get_bool!(repunch_on_relay_degradation);
    get_num!(prediction_samples, u8);
    get_num!(max_sample_age_sec, u64);
    get_num!(max_stable_delta, u16);
    get_num!(mapping_probe_count, u8);
    get_num!(mapping_probe_interval_ms, u64);
    get_bool!(relay_provider_enabled);
    get_float!(hysteresis_pct);
    get_num!(switch_hold_ms, u64);
    get_float!(boost_hysteresis_pct);
    get_num!(boost_hold_ms, u64);
    get_num!(probe_active_ms, u64);
    get_num!(probe_backup_ms, u64);
    get_num!(max_missed_probes, u32);
    get_float!(cost_direct);
    get_float!(cost_turn);
    get_float!(cost_peer_relay);
    p.validate().map_err(|e| {
        let field = match &e {
            nexus_nat_traversal::PunchConfigError::OutOfRange { field, .. } => *field,
            nexus_nat_traversal::PunchConfigError::InvalidCombination { field, .. } => *field,
        };
        format!("{DAEMON_TOML}: [network.punch].{field} {e}")
    })?;
    Ok(p)
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
        // proxy.yaml 内容变更 → NeedsRestart（Q-7=B：engine 只在启动构造）
        write(&d, PROXY_YAML, yaml_v2);
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        // 「只有规则/出站变化」也不再是 Hot（同一判据，术语保留以便审计）
        assert_ne!(classify_change(&old, &new), ChangeKind::Hot);
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
                    stun_server = \"stun.example.org:3478\"\n\
                    stun_server2 = \"stun2.example.org:3478\"\n";
        let cfg = parse_daemon_toml(text).unwrap();
        let turn = cfg.turn.expect("turn section should parse");
        assert_eq!(turn.server, "turn.example.org:3478");
        assert_eq!(turn.realm, "example.org");
        assert_eq!(turn.username, "nexus-node-a");
        assert_eq!(turn.password, "secret");
        assert_eq!(turn.refresh_interval_sec, 300);
        assert_eq!(turn.stun_server.as_deref(), Some("stun.example.org:3478"));
        assert_eq!(turn.stun_server2.as_deref(), Some("stun2.example.org:3478"));
    }

    #[test]
    fn turn_section_rejects_empty_stun_server2() {
        // stun_server2 为空字符串 → 解析失败（与 stun_server 同规则）。
        let text = "[network.turn]\n\
                    server = \"turn.example.org:3478\"\n\
                    realm = \"example.org\"\n\
                    username = \"u\"\n\
password=\"p\"\n\
                    stun_server2 = \"\"\n";
        assert!(parse_daemon_toml(text).is_err());
    }

    #[test]
    fn turn_section_defaults_for_optional_fields() {
        // 缺失 refresh_interval_sec → 300；缺失 stun_server/stun_server2 → None。
        let text = "[network.turn]\n\
                    server = \"turn.example.org:3478\"\n\
                    realm = \"example.org\"\n\
                    username = \"u\"\n\
                    password = \"p\"\n";
        let cfg = parse_daemon_toml(text).unwrap();
        let turn = cfg.turn.unwrap();
        assert_eq!(turn.refresh_interval_sec, 300);
        assert!(turn.stun_server.is_none());
        assert!(turn.stun_server2.is_none());
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

    // ---------- [network.proxy]（#3 fabric-over-proxy，AC3） ----------

    fn socks5_section(type_line: &str, extra: &str) -> String {
        format!("[network.proxy]\ntype = \"{type_line}\"\nserver = \"127.0.0.1:1080\"\n{extra}")
    }

    #[test]
    fn proxy_absent_when_no_section() {
        let cfg = parse_daemon_toml("[localapi]\naddr = \"127.0.0.1:18080\"\n").unwrap();
        assert!(cfg.proxy.is_none());
    }

    #[test]
    fn proxy_socks5_no_auth_ok() {
        let cfg = parse_daemon_toml(&socks5_section("socks5", "")).unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.proxy_type, ProxyType::Socks5);
        assert_eq!(p.server.to_string(), "127.0.0.1:1080");
        assert!(p.username.is_none());
        assert!(p.password.is_none());
        assert_eq!(p.connect_timeout_sec, 10);
        assert_eq!(p.handshake_timeout_sec, 10);
    }

    #[test]
    fn proxy_socks5_with_auth_ok() {
        let cfg = parse_daemon_toml(&socks5_section(
            "socks5",
            "username = \"nexus\"\npassword = \"changeme\"\n",
        ))
        .unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.username.as_deref(), Some("nexus"));
        assert_eq!(p.password.as_deref(), Some("changeme"));
    }

    #[test]
    fn proxy_socks5_timeouts_parsed() {
        let cfg = parse_daemon_toml(&socks5_section(
            "socks5",
            "connect_timeout_sec = 3\nhandshake_timeout_sec = 7\n",
        ))
        .unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.connect_timeout_sec, 3);
        assert_eq!(p.handshake_timeout_sec, 7);
    }

    #[test]
    fn proxy_shadowsocks_default_method_ok() {
        let cfg = parse_daemon_toml(&socks5_section("shadowsocks", "password = \"pw\"\n")).unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.proxy_type, ProxyType::Shadowsocks);
        assert!(p.method.is_none());
    }

    #[test]
    fn proxy_shadowsocks_explicit_method_ok() {
        let cfg = parse_daemon_toml(&socks5_section(
            "shadowsocks",
            "password = \"pw\"\nmethod = \"chacha20-ietf-poly1305\"\n",
        ))
        .unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.method.as_deref(), Some("chacha20-ietf-poly1305"));
    }

    #[test]
    fn proxy_trojan_ok() {
        let cfg =
            parse_daemon_toml(&socks5_section("trojan", "password = \"trojan-secret\"\n")).unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.proxy_type, ProxyType::Trojan);
        // #3 BLOCKER：缺省 SNI 从 server 的 IP 字符串推导（#4 行为一致）。
        assert_eq!(p.sni.as_deref(), Some("127.0.0.1"));
        assert!(!p.skip_cert_verify);
        assert!(p.alpn.is_none());
    }

    #[test]
    fn proxy_trojan_tls_fields_parsed() {
        let cfg = parse_daemon_toml(&socks5_section(
            "trojan",
            "password = \"pw\"\nsni = \"node.example.com\"\nskip_cert_verify = true\nalpn = [\"h2\", \"http/1.1\"]\n",
        ))
        .unwrap();
        let p = cfg.proxy.expect("proxy");
        assert_eq!(p.sni.as_deref(), Some("node.example.com"));
        assert!(p.skip_cert_verify);
        assert_eq!(
            p.alpn.as_deref(),
            Some(&["h2".to_string(), "http/1.1".to_string()][..])
        );
    }

    #[test]
    fn proxy_trojan_sni_defaults_to_server_ip() {
        // 显式 server 是 IPv4 字面量 → SNI 缺省取 IP 字符串。
        let cfg = parse_daemon_toml(
            "[network.proxy]\ntype = \"trojan\"\nserver = \"203.0.113.7:443\"\npassword = \"pw\"\n",
        )
        .unwrap();
        assert_eq!(
            cfg.proxy.expect("proxy").sni.as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn proxy_non_trojan_tls_fields_rejected() {
        // 非 trojan 配置 sni/skip_cert_verify/alpn → 配置期报错（不静默忽略）。
        assert!(parse_daemon_toml(&socks5_section("socks5", "sni = \"x\"\n")).is_err());
        assert!(
            parse_daemon_toml(&socks5_section(
                "shadowsocks",
                "password = \"pw\"\nsni = \"x\"\n"
            ))
            .is_err()
        );
        assert!(parse_daemon_toml(&socks5_section("socks5", "skip_cert_verify = true\n")).is_err());
        assert!(parse_daemon_toml(&socks5_section("socks5", "alpn = [\"h2\"]\n")).is_err());
    }

    #[test]
    fn proxy_trojan_bad_tls_field_types_rejected() {
        assert!(
            parse_daemon_toml(&socks5_section(
                "trojan",
                "password = \"pw\"\nskip_cert_verify = \"yes\"\n",
            ))
            .is_err()
        );
        assert!(
            parse_daemon_toml(&socks5_section(
                "trojan",
                "password = \"pw\"\nalpn = \"h2\"\n"
            ))
            .is_err()
        );
        assert!(
            parse_daemon_toml(&socks5_section("trojan", "password = \"pw\"\nalpn = [1]\n"))
                .is_err()
        );
        assert!(
            parse_daemon_toml(&socks5_section("trojan", "password = \"pw\"\nsni = \"\"\n"))
                .is_err()
        );
    }

    #[test]
    fn proxy_missing_type_is_err() {
        assert!(parse_daemon_toml("[network.proxy]\nserver = \"127.0.0.1:1080\"\n").is_err());
    }

    #[test]
    fn proxy_bad_type_is_err() {
        assert!(parse_daemon_toml(&socks5_section("http", "")).is_err());
        assert!(parse_daemon_toml(&socks5_section("", "")).is_err());
    }

    #[test]
    fn proxy_missing_server_is_err() {
        assert!(parse_daemon_toml("[network.proxy]\ntype = \"socks5\"\n").is_err());
    }

    #[test]
    fn proxy_server_not_socket_addr_is_err() {
        assert!(
            parse_daemon_toml(&socks5_section("socks5", "server = \"proxy.example\"\n")).is_err()
        );
        assert!(parse_daemon_toml(&socks5_section("socks5", "server = \"\"\n")).is_err());
    }

    #[test]
    fn proxy_bad_method_is_err() {
        assert!(
            parse_daemon_toml(&socks5_section(
                "shadowsocks",
                "password = \"pw\"\nmethod = \"aes-256-gcm\"\n",
            ))
            .is_err()
        );
    }

    #[test]
    fn proxy_non_ss_method_ignored() {
        // 非 ss 协议配置 method → 忽略不报错（A8）。
        let cfg = parse_daemon_toml(&socks5_section(
            "socks5",
            "method = \"chacha20-ietf-poly1305\"\n",
        ))
        .unwrap();
        assert_eq!(cfg.proxy.expect("proxy").proxy_type, ProxyType::Socks5);
    }

    #[test]
    fn proxy_timeout_zero_is_err() {
        assert!(
            parse_daemon_toml(&socks5_section("socks5", "connect_timeout_sec = 0\n",)).is_err()
        );
        assert!(
            parse_daemon_toml(&socks5_section("socks5", "handshake_timeout_sec = 0\n",)).is_err()
        );
    }

    #[test]
    fn proxy_timeout_negative_is_err() {
        assert!(
            parse_daemon_toml(&socks5_section("socks5", "connect_timeout_sec = -1\n",)).is_err()
        );
        assert!(
            parse_daemon_toml(&socks5_section("socks5", "handshake_timeout_sec = -1\n",)).is_err()
        );
    }

    #[test]
    fn proxy_timeout_non_integer_is_err() {
        assert!(
            parse_daemon_toml(&socks5_section(
                "socks5",
                "connect_timeout_sec = \"fast\"\n",
            ))
            .is_err()
        );
    }

    #[test]
    fn proxy_ss_missing_password_is_err() {
        assert!(parse_daemon_toml(&socks5_section("shadowsocks", "")).is_err());
        assert!(parse_daemon_toml(&socks5_section("shadowsocks", "password = \"\"\n")).is_err());
        assert!(parse_daemon_toml(&socks5_section("trojan", "")).is_err());
    }

    #[test]
    fn proxy_socks5_username_without_password_is_err() {
        assert!(parse_daemon_toml(&socks5_section("socks5", "username = \"nexus\"\n",)).is_err());
    }

    #[test]
    fn proxy_debug_masks_password() {
        let cfg = parse_daemon_toml(&socks5_section(
            "socks5",
            "username = \"nexus\"\npassword = \"supersecret\"\n",
        ))
        .unwrap();
        let dbg = format!("{:?}", cfg.proxy.expect("proxy"));
        assert!(!dbg.contains("supersecret"));
        assert!(dbg.contains("\"***\""));
    }

    #[test]
    fn proxy_change_needs_restart() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-proxy");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(
            &d,
            DAEMON_TOML,
            "[network.proxy]\ntype = \"socks5\"\nserver = \"127.0.0.1:1080\"\n",
        );
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        write(
            &d,
            DAEMON_TOML,
            "[network.proxy]\ntype = \"socks5\"\nserver = \"127.0.0.1:1081\"\n",
        );
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        let _ = std::fs::remove_dir_all(&d);
    }

    const TUN_PROXY_YAML: &str = "schema_version: 1\ninbounds:\n  - tag: t\n    kind: tun\n    sessions: enabled\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";

    #[test]
    fn load_exposes_flow_sessions_and_tun_surfaces() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-expose-surfaces");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(
            &d,
            DAEMON_TOML,
            "[tun]\ndefault_route = true\nexclude_server_routes = false\n[flow_sessions]\nenabled = \"auto\"\nidle_timeout_secs = 120\n",
        );
        let dir = ConfigDir::new(&d).unwrap();
        let cfg = load(&dir).unwrap();
        assert!(cfg.daemon.tun.default_route);
        assert!(!cfg.daemon.tun.exclude_server_routes);
        assert_eq!(
            cfg.daemon.flow_sessions.enabled,
            Some(nexus_proxy_config::FlowSessionsMode::Auto)
        );
        assert_eq!(cfg.daemon.flow_sessions.idle_timeout_secs, Some(120));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn flow_sessions_defaults_when_absent() {
        let cfg = parse_daemon_toml("[localapi]\naddr = \"127.0.0.1:18080\"\n").unwrap();
        assert_eq!(cfg.flow_sessions, FlowSessionsSection::default());
        assert!(cfg.flow_sessions.enabled.is_none());
        assert!(cfg.flow_sessions.idle_timeout_secs.is_none());
        assert!(cfg.flow_sessions.udp_buffer_datagrams.is_none());
    }

    #[test]
    fn flow_sessions_parses_enabled_forms() {
        use nexus_proxy_config::FlowSessionsMode;
        let cfg = parse_daemon_toml("[flow_sessions]\nenabled = \"auto\"\n").unwrap();
        assert_eq!(cfg.flow_sessions.enabled, Some(FlowSessionsMode::Auto));
        let cfg = parse_daemon_toml("[flow_sessions]\nenabled = true\n").unwrap();
        assert_eq!(cfg.flow_sessions.enabled, Some(FlowSessionsMode::Enabled));
        let cfg = parse_daemon_toml("[flow_sessions]\nenabled = false\n").unwrap();
        assert_eq!(cfg.flow_sessions.enabled, Some(FlowSessionsMode::Disabled));
        let cfg = parse_daemon_toml(
            "[flow_sessions]\nenabled = \"auto\"\nidle_timeout_secs = 120\nudp_buffer_datagrams = 32\n",
        )
        .unwrap();
        assert_eq!(cfg.flow_sessions.idle_timeout_secs, Some(120));
        assert_eq!(cfg.flow_sessions.udp_buffer_datagrams, Some(32));
    }

    #[test]
    fn flow_sessions_rejects_invalid_values() {
        let err = parse_daemon_toml("[flow_sessions]\nenabled = \"yes\"\n").unwrap_err();
        assert!(
            err.contains("CONFIG_INVALID [flow_sessions.enabled]"),
            "{err}"
        );
        let err = parse_daemon_toml("[flow_sessions]\nenabled = 1\n").unwrap_err();
        assert!(
            err.contains("CONFIG_INVALID [flow_sessions.enabled]"),
            "{err}"
        );
        let err = parse_daemon_toml("[flow_sessions]\nidle_timeout_secs = 0\n").unwrap_err();
        assert!(
            err.contains("CONFIG_INVALID [flow_sessions.idle_timeout_secs]"),
            "{err}"
        );
        let err = parse_daemon_toml("[flow_sessions]\nudp_buffer_datagrams = 0\n").unwrap_err();
        assert!(
            err.contains("CONFIG_INVALID [flow_sessions.udp_buffer_datagrams]"),
            "{err}"
        );
    }

    #[test]
    fn flow_sessions_conflicting_with_tun_sessions_is_rejected() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-flow-conflict");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, TUN_PROXY_YAML);
        write(&d, DAEMON_TOML, "[flow_sessions]\nenabled = false\n");
        let dir = ConfigDir::new(&d).unwrap();
        let err = load(&dir).unwrap_err();
        assert!(
            err.contains("CONFIG_INVALID [flow_sessions.enabled]"),
            "{err}"
        );
        assert!(err.contains("inbounds[0].sessions"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn flow_sessions_and_tun_sessions_agree() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-flow-agree");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, TUN_PROXY_YAML);
        write(&d, DAEMON_TOML, "[flow_sessions]\nenabled = true\n");
        let dir = ConfigDir::new(&d).unwrap();
        assert!(load(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn flow_sessions_single_source_is_accepted() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-flow-single");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, TUN_PROXY_YAML);
        let dir = ConfigDir::new(&d).unwrap();
        assert!(load(&dir).is_ok());
        std::fs::remove_file(d.join(PROXY_YAML)).unwrap();
        write(&d, DAEMON_TOML, "[flow_sessions]\nenabled = false\n");
        let dir = ConfigDir::new(&d).unwrap();
        assert!(load(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    const TPROXY_PROXY_YAML: &str = "schema_version: 1\ninbounds:\n  - tag: t\n    kind: tproxy\n    listen: 127.0.0.1:7895\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";

    fn classify_pair(dir_name: &str, old_yaml: &str, new_yaml: &str) -> ChangeKind {
        let d = std::env::temp_dir().join(dir_name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, old_yaml);
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        write(&d, PROXY_YAML, new_yaml);
        let new = load(&dir).unwrap();
        let kind = classify_change(&old, &new);
        let _ = std::fs::remove_dir_all(&d);
        kind
    }

    #[test]
    fn classify_change_tproxy_listen_port_needs_restart() {
        let new_yaml = TPROXY_PROXY_YAML.replace("7895", "7896");
        assert_eq!(
            classify_pair(
                "nexusd-cfg-test-classify-tproxy-port",
                TPROXY_PROXY_YAML,
                &new_yaml
            ),
            ChangeKind::NeedsRestart
        );
    }

    #[test]
    fn classify_change_tun_inbound_name_needs_restart() {
        let old_yaml = "schema_version: 1\ninbounds:\n  - tag: t\n    kind: tun\n    name: nexus\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let new_yaml = old_yaml.replace("name: nexus", "name: nexus2");
        assert_eq!(
            classify_pair("nexusd-cfg-test-classify-tun-name", old_yaml, &new_yaml),
            ChangeKind::NeedsRestart
        );
    }

    #[test]
    fn classify_change_outbound_only_is_needs_restart() {
        let old_yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let new_yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d2\noutbounds:\n  - tag: d2\n    kind: direct\n";
        // Q-7=B（§7.6.1）：proxy.yaml 内容变更 = NeedsRestart（engine 只在启动构造）。
        assert_eq!(
            classify_pair("nexusd-cfg-test-classify-outbound-hot", old_yaml, new_yaml),
            ChangeKind::NeedsRestart
        );
    }

    #[test]
    fn flow_sessions_change_needs_restart() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-flow-restart");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, DAEMON_TOML, "[flow_sessions]\nenabled = true\n");
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        write(&d, DAEMON_TOML, "[flow_sessions]\nenabled = false\n");
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_tun_enabled_false_conflicts_with_tun_inbound() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-legacy-tun-conflict");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, TUN_PROXY_YAML);
        write(&d, DAEMON_TOML, "[tun]\nenabled = false\n");
        let dir = ConfigDir::new(&d).unwrap();
        let err = load(&dir).unwrap_err();
        assert!(err.contains("CONFIG_INVALID [inbounds[0].kind]"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_tun_enabled_false_without_inbound_is_no_tun() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-legacy-tun-notun");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, DAEMON_TOML, "[tun]\nenabled = false\n");
        let dir = ConfigDir::new(&d).unwrap();
        let cfg = load(&dir).unwrap();
        assert!(!cfg.daemon.tun.enabled);
        assert!(cfg.daemon.tun.enabled_explicit);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_tun_name_and_mtu_conflicts() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-legacy-tun-name");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, TUN_PROXY_YAML);
        write(&d, DAEMON_TOML, "[tun]\nname = \"legacy0\"\n");
        let dir = ConfigDir::new(&d).unwrap();
        let err = load(&dir).unwrap_err();
        assert!(err.contains("CONFIG_INVALID [tun.name]"), "{err}");
        write(&d, DAEMON_TOML, "[tun]\nmtu = 1400\n");
        let dir = ConfigDir::new(&d).unwrap();
        let err = load(&dir).unwrap_err();
        assert!(err.contains("CONFIG_INVALID [tun.mtu]"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_tun_matching_values_are_accepted() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-legacy-tun-match");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, PROXY_YAML, TUN_PROXY_YAML);
        write(
            &d,
            DAEMON_TOML,
            "[tun]\nenabled = true\nname = \"nexus\"\nmtu = 1500\n",
        );
        let dir = ConfigDir::new(&d).unwrap();
        assert!(load(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_tun_maps_default_route_and_exclude_flags() {
        let cfg = parse_daemon_toml("[tun]\ndefault_route = true\nexclude_server_routes = false\n")
            .unwrap();
        assert!(cfg.tun.default_route);
        assert!(cfg.tun.default_route_explicit);
        assert!(!cfg.tun.exclude_server_routes);
        assert!(cfg.tun.exclude_server_routes_explicit);
        assert!(parse_daemon_toml("[tun]\ndefault_route = \"yes\"\n").is_err());
        assert!(parse_daemon_toml("[tun]\nexclude_server_routes = 1\n").is_err());
    }
    // ---------- [network.discovery]（AC1） ----------

    #[test]
    fn discovery_section_defaults() {
        let d = DiscoverySection::default();
        assert!(d.enabled);
        assert!(d.mdns);
        assert!(d.lsa);
        assert!(d.feed);
        assert_eq!(d.gossip_port, 19010);
        assert_eq!(d.advertise_ip, None);
        assert_eq!(d.lsa_refresh_sec, 30);
        assert_eq!(d.lsa_stale_sec, 90);
        assert_eq!(d.book_poll_ms, 5000);
        assert_eq!(d.trigger_max_failures, 3);
        // An absent section parses to exactly the defaults.
        let parsed = parse_daemon_toml("").expect("empty daemon.toml");
        assert_eq!(parsed.discovery, DiscoverySection::default());
    }

    #[test]
    fn discovery_section_validation_rejects() {
        let cases = [
            "[network.discovery]\ngossip_port = 0\n",
            "[network.discovery]\ngossip_port = 5353\n",
            "[network.discovery]\nlsa_refresh_sec = 30\nlsa_stale_sec = 59\n",
            "[network.discovery]\nlsa_refresh_sec = 31\nlsa_stale_sec = 61\n",
            "[network.discovery]\nbook_poll_ms = 999\n",
            "[network.discovery]\ntrigger_max_failures = 0\n",
            "[network.discovery]\nadvertise_ip = \"not-an-ip\"\n",
        ];
        for text in cases {
            assert!(
                parse_daemon_toml(text).is_err(),
                "expected CONFIG error for: {text}"
            );
        }
        // Boundary values are accepted.
        let ok = "[network.discovery]\ngossip_port = 19011\nadvertise_ip = \"10.1.2.3\"\n\
                  lsa_refresh_sec = 5\nlsa_stale_sec = 60\nbook_poll_ms = 1000\n\
                  trigger_max_failures = 10\n";
        let parsed = parse_daemon_toml(ok).expect("boundary values must parse");
        assert_eq!(parsed.discovery.gossip_port, 19011);
        assert_eq!(
            parsed.discovery.advertise_ip,
            Some("10.1.2.3".parse().unwrap())
        );
    }

    #[test]
    fn relay_book_dir_validation() {
        let base = "[network.turn]\nserver = \"127.0.0.1:3478\"\nrealm = \"nexus\"\n\
                    username = \"u\"\npassword = \"p\"\n";
        let absent = parse_daemon_toml(base).expect("turn without book dir");
        assert_eq!(absent.turn.expect("turn").relay_book_dir, None);

        let empty = format!("{base}relay_book_dir = \"\"\n");
        assert!(parse_daemon_toml(&empty).is_err());

        let explicit = format!("{base}relay_book_dir = \"/tmp/nexus-relay-book\"\n");
        let parsed = parse_daemon_toml(&explicit).expect("explicit dir");
        assert_eq!(
            parsed.turn.expect("turn").relay_book_dir,
            Some(std::path::PathBuf::from("/tmp/nexus-relay-book"))
        );
    }

    #[test]
    fn discovery_change_needs_restart() {
        let d = std::env::temp_dir().join("nexusd-cfg-test-discovery");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        write(&d, DAEMON_TOML, "[network.discovery]\nlsa = true\n");
        let dir = ConfigDir::new(&d).unwrap();
        let old = load(&dir).unwrap();
        write(&d, DAEMON_TOML, "[network.discovery]\nlsa = false\n");
        let new = load(&dir).unwrap();
        assert_eq!(classify_change(&old, &new), ChangeKind::NeedsRestart);
        let same = load(&dir).unwrap();
        assert_eq!(classify_change(&new, &same), ChangeKind::Hot);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod punch_gap_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn g12_punch_config_defaults() {
        let p = PunchSection::default();
        assert!(p.enabled);
        assert!(p.relay_provider_enabled);
        assert_eq!(p.punch_timeout_ms, 5_000);
        assert_eq!(p.coord_skew_ms, 200);
        assert_eq!(p.spray_k, 16);
        assert_eq!(p.spray_interval_ms, 50);
        assert_eq!(p.spray_time_budget_ms, 3_000);
        assert_eq!(p.repunch_interval_sec, 300);
        assert_eq!(p.repunch_jitter_sec, 0);
        assert_eq!(p.prediction_samples, 3);
        assert_eq!(p.max_sample_age_sec, 900);
        assert_eq!(p.max_stable_delta, 8);
        assert_eq!(p.mapping_probe_count, 3);
        assert_eq!(p.mapping_probe_interval_ms, 50);
        let c = p.to_punch_config();
        assert_eq!(c.punch_timeout, Duration::from_millis(5_000));
        assert_eq!(c.repunch_interval, Duration::from_secs(300));
        assert_eq!(c.mapping_probe_count, 3);
        assert_eq!(c.mapping_probe_interval_ms, 50);
        assert_eq!(c.repunch_jitter, Duration::ZERO);
    }

    #[test]
    fn punch_rejects_illegal_combination() {
        let p = PunchSection {
            spray_k: 32,
            spray_interval_ms: 500,
            spray_time_budget_ms: 3_000,
            ..PunchSection::default()
        };
        let err = p.validate().expect_err("combination must be rejected");
        assert!(matches!(
            err,
            nexus_nat_traversal::PunchConfigError::InvalidCombination {
                field: "spray_interval_ms",
                ..
            }
        ));
    }
}

#[cfg(test)]
mod dns_config_tests {
    use super::*;

    const BASE: &str = "[dns]\nupstream = [\"1.1.1.1\"]\n";

    fn parse(text: &str) -> Result<DnsFileConfig, DnsConfigError> {
        parse_dns_config(text, None, false)
    }

    fn ok(text: &str) -> DnsFileConfig {
        parse(text).expect("dns.toml must parse")
    }

    fn err(text: &str) -> DnsConfigError {
        parse(text).expect_err("dns.toml must be rejected")
    }

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().expect("test address")
    }

    const MESH_NET: &str = r#"
[vpi]
address6 = "fd00::1"
[[vpi.routes]]
subnet = "10.144.144.0/24"
peer = "00"
[[vpi.routes6]]
subnet = "fd00:144::/64"
peer = "00"
[[vpi.routes6]]
subnet = "fe80::/64"
peer = "00"
"#;

    #[test]
    fn defaults_match_frozen_schema() {
        let c = ok(BASE);
        assert_eq!(c.upstream.servers, vec![addr("1.1.1.1:53")]);
        assert_eq!(c.upstream.attempt_timeout_ms, 500);
        assert_eq!(c.upstream.attempts_per_server, 2);
        assert_eq!(c.upstream.total_budget_ms, 4000);
        assert_eq!(c.upstream.edns_udp_size, 1232);
        assert!(c.upstream.tcp_fallback);
        assert_eq!(c.upstream.tcp_timeout_ms, 2000);
        assert_eq!(c.upstream.cache_max_entries, 1024);
        assert_eq!(c.upstream.cache_max_ttl_secs, 3600);
        assert_eq!(c.upstream.negative_ttl_secs, 60);
        assert_eq!(c.upstream.max_inflight, 64);
        assert_eq!(c.proxy.unmatched, UnmatchedPolicy::Auto);
        assert_eq!(c.proxy.unevaluable, UnevaluablePolicy::Proxied);
        assert!(c.unified.fake_ip_enabled);
        assert_eq!(c.unified.fake_ip_prefix, 15);
        assert_eq!(c.unified.mesh_suffix, "mesh");
        assert_eq!(c.unified.fake_ip_ttl_secs, 300);
        assert_eq!(c.unified.ip_preference, nexus_dns::IpPreference::PreferV4);
        assert!(c.unified.hosts.is_empty());
        assert!(c.mesh_hosts.is_empty());
    }

    #[test]
    fn every_key_accepts_an_override() {
        let text = r#"
[dns]
upstream = ["8.8.8.8", "1.1.1.1:5353", "[2001:db8::53]:53", "8.8.8.8"]
fake_ip_enabled = false
fake_ip_range = "198.19.0.0/16"
mesh_suffix = "MESH"
fake_ip_ttl_secs = 600
ip_preference = "v6_only"
unmatched = "upstream"
unevaluable = "upstream"
attempt_timeout_ms = 1000
attempts_per_server = 3
total_budget_ms = 8000
edns_udp_size = 0
tcp_fallback = false
tcp_timeout_ms = 500
cache_max_entries = 0
cache_max_ttl_secs = 60
negative_ttl_secs = 0
max_inflight = 16

[dns.hosts]
"Host.Example" = "10.0.0.1"

[dns.mesh.hosts]
"xc.mesh" = "10.144.144.6"
"ll.mesh" = "fe80::1"
"#;
        let c = parse_dns_config(text, Some(MESH_NET), true).expect("full schema parses");
        // Deduplicated in declaration order (8.8.8.8 appears once).
        assert_eq!(
            c.upstream.servers,
            vec![
                addr("8.8.8.8:53"),
                addr("1.1.1.1:5353"),
                addr("[2001:db8::53]:53")
            ]
        );
        assert_eq!(
            c.unified.upstream,
            vec!["8.8.8.8", "1.1.1.1:5353", "[2001:db8::53]:53"]
        );
        assert!(!c.unified.fake_ip_enabled);
        assert_eq!(c.unified.fake_ip_prefix, 16);
        assert_eq!(c.unified.mesh_suffix, "mesh");
        assert_eq!(c.unified.fake_ip_ttl_secs, 600);
        assert_eq!(c.unified.ip_preference, nexus_dns::IpPreference::V6Only);
        assert_eq!(
            c.unified.hosts,
            vec![("host.example".to_string(), "10.0.0.1".parse().unwrap())]
        );
        assert_eq!(c.proxy.unmatched, UnmatchedPolicy::Upstream);
        assert_eq!(c.proxy.unevaluable, UnevaluablePolicy::Upstream);
        assert_eq!(c.upstream.attempt_timeout_ms, 1000);
        assert_eq!(c.upstream.attempts_per_server, 3);
        assert_eq!(c.upstream.total_budget_ms, 8000);
        assert_eq!(c.upstream.edns_udp_size, 0);
        assert!(!c.upstream.tcp_fallback);
        assert_eq!(c.upstream.tcp_timeout_ms, 500);
        assert_eq!(c.upstream.cache_max_entries, 0);
        assert_eq!(c.upstream.cache_max_ttl_secs, 60);
        assert_eq!(c.upstream.negative_ttl_secs, 0);
        assert_eq!(c.upstream.max_inflight, 16);
        assert_eq!(c.mesh_hosts.len(), 2);
        assert!(
            c.mesh_hosts
                .contains(&("xc.mesh".to_string(), "10.144.144.6".parse().unwrap()))
        );
        assert!(
            c.mesh_hosts
                .contains(&("ll.mesh".to_string(), "fe80::1".parse().unwrap()))
        );
    }

    #[test]
    fn upstream_accepts_bare_v6_and_defaults_to_port_53() {
        let c = ok("[dns]\nupstream = [\"2001:db8::1\"]\n");
        assert_eq!(c.upstream.servers, vec![addr("[2001:db8::1]:53")]);
    }

    #[test]
    fn nine_error_variants_are_reachable() {
        // UnknownKey: unknown key.
        assert!(matches!(
            err("[dns]\nupstream = [\"1.1.1.1\"]\nshiny = true\n"),
            DnsConfigError::UnknownKey(key) if key == "shiny"
        ));
        // UnknownKey: root-level key (R3 migration).
        assert!(matches!(
            err("upstream = [\"1.1.1.1\"]\n"),
            DnsConfigError::UnknownKey(key) if key == "upstream"
        ));
        // EmptyUpstream: missing and empty.
        assert_eq!(
            err("[dns]\nfake_ip_enabled = true\n"),
            DnsConfigError::EmptyUpstream
        );
        assert_eq!(err("[dns]\nupstream = []\n"), DnsConfigError::EmptyUpstream);
        // TooManyUpstream.
        let nine = (1..=9)
            .map(|i| format!("\"10.0.0.{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            err(&format!("[dns]\nupstream = [{nine}]\n")),
            DnsConfigError::TooManyUpstream
        );
        // BadUpstreamAddr.
        assert!(matches!(
            err("[dns]\nupstream = [\"not-an-ip\"]\n"),
            DnsConfigError::BadUpstreamAddr(_)
        ));
        assert!(matches!(
            err("[dns]\nupstream = [\"1.1.1.1:0\"]\n"),
            DnsConfigError::BadUpstreamAddr(_)
        ));
        // BadValue.
        assert!(matches!(
            err("[dns]\nupstream = [\"1.1.1.1\"]\nattempt_timeout_ms = \"fast\"\n"),
            DnsConfigError::BadValue { .. }
        ));
        // MeshNameInvalid.
        assert!(matches!(
            err(
                "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"XC.MESH\" = \"10.144.144.6\"\n"
            ),
            DnsConfigError::MeshNameInvalid(_)
        ));
        assert!(matches!(
            err(
                "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"xc.other\" = \"10.144.144.6\"\n"
            ),
            DnsConfigError::MeshNameInvalid(_)
        ));
        // MeshAddrInvalid: loopback (SU-3 #1) and multicast.
        assert!(matches!(
            parse_dns_config(
                "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"loop.mesh\" = \"127.0.0.1\"\n",
                Some(MESH_NET),
                false
            ),
            Err(DnsConfigError::MeshAddrInvalid(_))
        ));
        assert!(matches!(
            parse_dns_config(
                "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"mc.mesh\" = \"ff02::1\"\n",
                Some(MESH_NET),
                false
            ),
            Err(DnsConfigError::MeshAddrInvalid(_))
        ));
        // MeshWithoutRoutes: mesh hosts without network.toml.
        assert_eq!(
            parse_dns_config(
                "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"xc.mesh\" = \"10.144.144.6\"\n",
                None,
                false
            ),
            Err(DnsConfigError::MeshWithoutRoutes)
        );
        // ProxyPolicyConflict.
        assert_eq!(
            parse_dns_config(
                "[dns]\nupstream = [\"1.1.1.1\"]\nunmatched = \"proxied\"\n",
                None,
                false
            ),
            Err(DnsConfigError::ProxyPolicyConflict)
        );
    }

    #[test]
    fn ranges_are_enforced_at_the_boundaries() {
        let cases: &[(&str, &str)] = &[
            ("attempt_timeout_ms = 49", "attempt_timeout_ms"),
            ("attempt_timeout_ms = 5001", "attempt_timeout_ms"),
            ("attempts_per_server = 0", "attempts_per_server"),
            ("attempts_per_server = 5", "attempts_per_server"),
            ("total_budget_ms = 100", "total_budget_ms"),
            ("total_budget_ms = 30001", "total_budget_ms"),
            ("edns_udp_size = 1", "edns_udp_size"),
            ("edns_udp_size = 511", "edns_udp_size"),
            ("edns_udp_size = 4097", "edns_udp_size"),
            ("tcp_timeout_ms = 99", "tcp_timeout_ms"),
            ("tcp_timeout_ms = 10001", "tcp_timeout_ms"),
            ("cache_max_ttl_secs = 0", "cache_max_ttl_secs"),
            ("max_inflight = 0", "max_inflight"),
            ("max_inflight = 1025", "max_inflight"),
            ("fake_ip_ttl_secs = 0", "fake_ip_ttl_secs"),
            ("fake_ip_range = \"198.18.0.0/31\"", "fake_ip_range"),
            ("mesh_suffix = \"\"", "mesh_suffix"),
            ("mesh_suffix = \"a.b\"", "mesh_suffix"),
            ("ip_preference = \"v4\"", "ip_preference"),
            ("unmatched = \"never\"", "unmatched"),
            ("unevaluable = \"auto\"", "unevaluable"),
        ];
        for (line, key) in cases {
            let text = format!("{BASE}{line}\n");
            let error = err(&text);
            assert!(
                matches!(error, DnsConfigError::BadValue { .. }),
                "{line} -> {error:?}"
            );
            assert!(
                error.to_string().contains(key),
                "{line} message must mention {key}: {error}"
            );
        }
        // total_budget_ms must stay >= attempt_timeout_ms.
        assert!(matches!(
            err(
                "[dns]\nupstream = [\"1.1.1.1\"]\nattempt_timeout_ms = 1000\ntotal_budget_ms = 999\n"
            ),
            DnsConfigError::BadValue { .. }
        ));
        // edns 0/512/4096 are accepted.
        for size in [0u16, 512, 4096] {
            assert_eq!(
                ok(&format!("{BASE}edns_udp_size = {size}\n"))
                    .upstream
                    .edns_udp_size,
                size
            );
        }
    }

    #[test]
    fn su3_three_examples_are_covered() {
        // 1. loopback mesh values are rejected (::1 and 127.0.0.1).
        for value in ["::1", "127.0.0.1"] {
            let text = format!(
                "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"loop.mesh\" = \"{value}\"\n"
            );
            assert!(matches!(
                parse_dns_config(&text, Some(MESH_NET), false),
                Err(DnsConfigError::MeshAddrInvalid(_))
            ));
        }
        // 2. fe80:: link-local is accepted when routes6 covers it.
        let text = "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"ll.mesh\" = \"fe80::1\"\n";
        let net = "[vpi]\naddress6 = \"fd00::1\"\n[[vpi.routes6]]\nsubnet = \"fe80::/64\"\npeer = \"00\"\n";
        let c = parse_dns_config(text, Some(net), false).expect("link-local mesh accepted");
        assert_eq!(
            c.mesh_hosts,
            vec![("ll.mesh".to_string(), "fe80::1".parse().unwrap())]
        );
        // 3. [vpi].address6 without [[vpi.routes6]] is accepted (§4.6.2 SU-3).
        let c = parse_dns_config(BASE, Some("[vpi]\naddress6 = \"fd00::1\"\n"), false)
            .expect("address6 alone is allowed");
        assert!(c.mesh_hosts.is_empty());
    }

    #[test]
    fn mesh_address_must_be_inside_a_route() {
        let net = "[vpi]\n[[vpi.routes]]\nsubnet = \"10.144.144.0/24\"\npeer = \"00\"\n";
        let outside =
            "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"xc.mesh\" = \"10.9.9.9\"\n";
        assert!(matches!(
            parse_dns_config(outside, Some(net), false),
            Err(DnsConfigError::MeshAddrInvalid(_))
        ));
        let inside =
            "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"xc.mesh\" = \"10.144.144.6\"\n";
        assert!(parse_dns_config(inside, Some(net), false).is_ok());
        // A v6 mesh host without routes6 is MeshWithoutRoutes even if address6 exists.
        let v6 = "[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh.hosts]\n\"v6.mesh\" = \"fd00::9\"\n";
        assert_eq!(
            parse_dns_config(v6, Some("[vpi]\naddress6 = \"fd00::1\"\n"), false),
            Err(DnsConfigError::MeshWithoutRoutes)
        );
    }

    #[test]
    fn unknown_mesh_subkey_is_rejected() {
        assert_eq!(
            err("[dns]\nupstream = [\"1.1.1.1\"]\n[dns.mesh]\nother = 1\n"),
            DnsConfigError::UnknownKey("mesh.other".to_string())
        );
    }

    #[test]
    fn unmatched_proxied_requires_a_usable_outbound() {
        let text = "[dns]\nupstream = [\"1.1.1.1\"]\nunmatched = \"proxied\"\n";
        assert_eq!(
            parse_dns_config(text, None, false),
            Err(DnsConfigError::ProxyPolicyConflict)
        );
        let c = parse_dns_config(text, None, true).expect("usable outbound satisfies proxied");
        assert_eq!(c.proxy.unmatched, UnmatchedPolicy::Proxied);
    }

    #[test]
    fn policy_enums_round_trip() {
        assert_eq!(UnmatchedPolicy::parse("auto"), Some(UnmatchedPolicy::Auto));
        assert_eq!(
            UnmatchedPolicy::parse("proxied"),
            Some(UnmatchedPolicy::Proxied)
        );
        assert_eq!(
            UnmatchedPolicy::parse("upstream"),
            Some(UnmatchedPolicy::Upstream)
        );
        assert_eq!(UnmatchedPolicy::parse("nope"), None);
        assert_eq!(
            UnevaluablePolicy::parse("proxied"),
            Some(UnevaluablePolicy::Proxied)
        );
        assert_eq!(
            UnevaluablePolicy::parse("upstream"),
            Some(UnevaluablePolicy::Upstream)
        );
        assert_eq!(UnevaluablePolicy::parse("auto"), None);
    }

    #[test]
    fn error_display_carries_actionable_detail() {
        let e = DnsConfigError::UnknownKey("shiny".to_string());
        assert!(e.to_string().contains("shiny"));
        let e = DnsConfigError::BadValue {
            key: "dns.max_inflight".to_string(),
            reason: "must be in 1..=1024".to_string(),
        };
        assert!(e.to_string().contains("dns.max_inflight"));
        assert!(e.to_string().contains("1..=1024"));
    }
}
