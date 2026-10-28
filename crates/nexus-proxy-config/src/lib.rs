//! nexus-proxy-config
//!
//! 代理内核产品线的配置模型层：把用户提供的 YAML 配置文本解析为 typed structs
//! （入站监听、规则表、策略组、出站定义），并做结构化校验。这是 Nexus 首个
//! 配置文件入口。
//!
//! 边界（ARCHITECTURE §11 / MODULE.md）：
//! - 配置解析为纯函数（零 I/O、零副作用）；同一份 YAML 永远产出同一个 `ProxyConfig`；
//! - 内置一个最小确定性 YAML 子集解析器（mapping / list / scalar / 注释 / 行内 list），
//!   不引入第三方序列化依赖，保持 Portable / WASI 可检查；
//! - 不执行规则匹配、不选择出站、不发起网络 I/O；文件 I/O 由 Composition Root 完成，
//!   本层只消费已读入的文本。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

/// 出站 UDP 能力声明（共享 DTO；CONTRACT：`UdpMode` 手写 `Debug` 脱敏）。
pub mod udp;

pub use udp::{UdpCapability, UdpMode, UdpUnsupportedReason};

/// TPROXY 透明入站默认监听地址（spec §11.1 冻结端口 7895）。
pub const TPROXY_DEFAULT_LISTEN: &str = "0.0.0.0:7895";

// ---------------------------------------------------------------------------
// 结构化配置错误（不以日志文本代替错误类型，MODULE.md Outputs）
// ---------------------------------------------------------------------------

/// 结构化配置错误：保留字段路径与原因（`CONFIG_INVALID { field, reason }`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// 出错字段的机器可读路径（如 `rules[1].action[0].tag`）。
    pub field: String,
    /// 失败原因（人类可读、可诊断）。
    pub reason: String,
}

impl ConfigError {
    /// 构造一个配置错误。
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CONFIG_INVALID [{}]: {}", self.field, self.reason)
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// Typed 配置模型（MODULE.md Public API）
// ---------------------------------------------------------------------------

/// 配置根：入站监听、规则表、策略组、出站定义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// schema 版本号（P0 冻结为 1）。
    pub schema_version: u32,
    /// 入站监听定义。
    pub inbounds: Vec<InboundConfig>,
    /// 规则表（声明顺序，首匹配；必须以 `MATCH` 结尾）。
    pub rules: Vec<RuleConfig>,
    /// 策略组定义（selector / urltest）。
    pub groups: Vec<GroupConfig>,
    /// 出站定义（direct / relay）。
    pub outbounds: Vec<OutboundConfig>,
    /// 可选 DNS 多 server 路由段（§11.5）。
    pub dns: Option<DnsConfig>,
    /// 可选节点测速段（§11.10）；缺失走默认值。
    pub speedtest: Option<SpeedtestConfig>,
    /// 可选 rule-providers 规则集定义（§11.11）。
    pub rule_providers: Vec<RuleProviderConfig>,
}

/// 入站协议类型（显式代理与透明入站）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    /// SOCKS5 显式代理入口。
    Socks5,
    /// SOCKS5/HTTP 混合显式代理入口。
    Mixed,
    /// TUN 透明入站（系统级接管）。
    Tun,
    /// TPROXY 透明入站（Linux 捕获前端）。
    Tproxy,
}

impl InboundKind {
    /// 解析 YAML 的 `kind` 取值；未知值结构化报错。
    ///
    /// # Errors
    ///
    /// 返回 `CONFIG_INVALID [kind]`，调用方负责补全 `inbounds[i]` 字段路径。
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "socks5" => Ok(Self::Socks5),
            "mixed" => Ok(Self::Mixed),
            "tun" => Ok(Self::Tun),
            "tproxy" => Ok(Self::Tproxy),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown inbound kind '{other}' (supports socks5/mixed/tun/tproxy)"),
            )),
        }
    }

    /// 稳定的机器可读标签（与配置取值一致）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Mixed => "mixed",
            Self::Tun => "tun",
            Self::Tproxy => "tproxy",
        }
    }
}

/// 入站监听配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConfig {
    /// 入站标识。
    pub tag: String,
    /// 入站协议。
    pub kind: InboundKind,
    /// 监听地址（host:port；tun 不使用，tproxy 缺省 `0.0.0.0:7895`）。
    pub listen: String,
    /// `kind: tun` 的子配置；非 tun 入站为 `None`。
    pub tun: Option<TunInboundConfig>,
    /// `kind: tproxy` 的子配置；非 tproxy 入站为 `None`。
    pub tproxy: Option<TproxyInboundConfig>,
}

/// 流会话开关模式（Q2 定案默认 `auto`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSessionsMode {
    /// 有 provider 源时启用，无源禁用。
    Auto,
    /// 强制启用。
    Enabled,
    /// 强制禁用。
    Disabled,
}

impl FlowSessionsMode {
    /// 解析配置取值（`auto` / `enabled` / `disabled`）。
    ///
    /// # Errors
    ///
    /// 未知取值返回 `CONFIG_INVALID [kind]`，调用方补全字段路径。
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "auto" => Ok(Self::Auto),
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown flow sessions mode '{other}' (supports auto/enabled/disabled)"),
            )),
        }
    }

    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// `kind: tun` 入站子配置（spec §10.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunInboundConfig {
    /// TUN 设备名（默认 `nexus`）。
    pub name: String,
    /// MTU（默认 1500，范围 `[1280, 9000]`）。
    pub mtu: u16,
    /// 设备地址（默认 `10.99.0.1/24`，IPv4 CIDR）。
    pub address: String,
    /// 是否接管默认路由（默认 `false`，必须显式 opt-in）。
    pub default_route: bool,
    /// 是否自动排除代理服务器路由（默认 `true`）。
    pub exclude_server_routes: bool,
    /// fake-IP（本 run 必须 `false`）。
    pub fake_ip: bool,
    /// IPv6（本 run 必须 `false`）。
    pub ipv6: bool,
    /// 流会话模式（默认 `auto`）。
    pub sessions: FlowSessionsMode,
    /// YAML 是否显式给出 `sessions`（用于 §10.7 与 `[flow_sessions].enabled` 的冲突判定）。
    pub sessions_explicit: bool,
}

impl Default for TunInboundConfig {
    fn default() -> Self {
        Self {
            name: "nexus".to_string(),
            mtu: 1500,
            address: "10.99.0.1/24".to_string(),
            default_route: false,
            exclude_server_routes: true,
            fake_ip: false,
            ipv6: false,
            sessions: FlowSessionsMode::Auto,
            sessions_explicit: false,
        }
    }
}

/// TPROXY 捕获 backend。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackendConfig {
    /// iptables（默认）。
    Iptables,
    /// nftables。
    Nftables,
    /// external：只校验不写规则。
    External,
}

impl CaptureBackendConfig {
    /// 解析配置取值。
    ///
    /// # Errors
    ///
    /// 未知取值返回 `CONFIG_INVALID [kind]`，调用方补全字段路径。
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "iptables" => Ok(Self::Iptables),
            "nftables" => Ok(Self::Nftables),
            "external" => Ok(Self::External),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown capture backend '{other}' (supports iptables/nftables/external)"),
            )),
        }
    }

    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
            Self::External => "external",
        }
    }
}

/// 捕获失败策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFailureMode {
    /// 阻断（默认）：安装 DROP 规则；backend 不可用时 `enforcement=impossible`。
    Block,
    /// 显式 bypass：不写规则。
    Bypass,
}

impl CaptureFailureMode {
    /// 解析配置取值。
    ///
    /// # Errors
    ///
    /// 未知取值返回 `CONFIG_INVALID [kind]`，调用方补全字段路径。
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "block" => Ok(Self::Block),
            "bypass" => Ok(Self::Bypass),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown capture failure mode '{other}' (supports block/bypass)"),
            )),
        }
    }

    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Bypass => "bypass",
        }
    }
}

/// 路径失败策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFailureMode {
    /// 阻断（默认）：TCP RST、UDP 丢弃，不静默直连。
    Block,
    /// 按策略组剩余候选重试（有上限）。
    Fallback,
}

impl PathFailureMode {
    /// 解析配置取值。
    ///
    /// # Errors
    ///
    /// 未知取值返回 `CONFIG_INVALID [kind]`，调用方补全字段路径。
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "block" => Ok(Self::Block),
            "fallback" => Ok(Self::Fallback),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown path failure mode '{other}' (supports block/fallback)"),
            )),
        }
    }

    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Fallback => "fallback",
        }
    }
}

/// `kind: tproxy` 入站子配置（spec §10.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TproxyInboundConfig {
    /// TCP 监听端口（默认取 `listen` 端口）。
    pub tcp_port: u16,
    /// UDP 监听端口（默认取 `listen` 端口）。
    pub udp_port: u16,
    /// 捕获 backend（默认 iptables）。
    pub backend: CaptureBackendConfig,
    /// 专用链名（默认 `NEXUS_TPROXY`）。
    pub chain: String,
    /// fwmark（默认 `0x1f3`）。
    pub mark: u32,
    /// 策略路由表（默认 100）。
    pub route_table: u32,
    /// 拦截目的 CIDR（默认 `["0.0.0.0/0"]`）。
    pub intercept_dst_cidrs: Vec<String>,
    /// 排除目的 CIDR（默认空；mesh/TUN/代理服务器自动追加）。
    pub exclude_dst_cidrs: Vec<String>,
    /// 捕获失败策略（默认 block）。
    pub on_capture_failure: CaptureFailureMode,
    /// 路径失败策略（默认 block）。
    pub on_path_failure: PathFailureMode,
    /// TCP 并发连接上限（默认 4096）。
    pub max_tcp_conns: usize,
    /// UDP 流表容量（默认 8192）。
    pub udp_table_capacity: usize,
    /// UDP 流空闲老化秒数（默认 60）。
    pub udp_idle_secs: u64,
    /// IPv6（本 run 必须 `false`）。
    pub ipv6: bool,
}

impl Default for TproxyInboundConfig {
    fn default() -> Self {
        Self {
            tcp_port: 7895,
            udp_port: 7895,
            backend: CaptureBackendConfig::Iptables,
            chain: "NEXUS_TPROXY".to_string(),
            mark: 0x1f3,
            route_table: 100,
            intercept_dst_cidrs: vec!["0.0.0.0/0".to_string()],
            exclude_dst_cidrs: Vec::new(),
            on_capture_failure: CaptureFailureMode::Block,
            on_path_failure: PathFailureMode::Block,
            max_tcp_conns: 4096,
            udp_table_capacity: 8192,
            udp_idle_secs: 60,
            ipv6: false,
        }
    }
}

/// 规则类型（P0 冻结为四类；2026-10-01 新增端口/进程三类）。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RuleKind {
    /// 目的域名等于或以 `.` 拼接规则后缀结尾。
    DomainSuffix,
    /// 目的域名精确匹配。
    Domain,
    /// 目的为 IP literal 且落在 CIDR 网段内。
    IpCidr,
    /// 目的 IP 归属地为规则指定国家码（数据注入，§11.11）。
    GeoIp,
    /// 目的域名属于规则指定分类集合（数据注入，§11.11）。
    GeoSite,
    /// 引用 rule-providers 规则集（数据注入，§11.11）。
    RuleSet,
    /// 源端口匹配（单端口 `8080` 或范围 `8000-9000`）。
    SrcPort,
    /// 目的端口匹配（单端口 `443` 或范围 `8000-9000`）。
    DstPort,
    /// 进程名匹配（精确 `chrome` 或前缀通配 `chrome*`）。
    ProcessName,
    /// 兜底规则（匹配一切未命中流量）。
    Match,
}

impl RuleKind {
    /// 稳定的机器可读标签（与 YAML 取值、JSON 输出一致）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DomainSuffix => "domain_suffix",
            Self::Domain => "domain",
            Self::IpCidr => "ip_cidr",
            Self::GeoIp => "geoip",
            Self::GeoSite => "geosite",
            Self::RuleSet => "rule_set",
            Self::SrcPort => "src_port",
            Self::DstPort => "dst_port",
            Self::ProcessName => "process_name",
            Self::Match => "match",
        }
    }

    /// 解析 YAML kind 取值（classical provider 规则行跨 crate 复用，§11.11）。
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "domain_suffix" => Ok(Self::DomainSuffix),
            "domain" => Ok(Self::Domain),
            "ip_cidr" => Ok(Self::IpCidr),
            "geoip" => Ok(Self::GeoIp),
            "geosite" => Ok(Self::GeoSite),
            "rule_set" => Ok(Self::RuleSet),
            "src_port" => Ok(Self::SrcPort),
            "dst_port" => Ok(Self::DstPort),
            "process_name" => Ok(Self::ProcessName),
            "match" => Ok(Self::Match),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown rule kind '{other}'"),
            )),
        }
    }
}

/// 单条规则配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleConfig {
    /// 规则名（分流决策可观察字段 `matched_rule`）。
    pub tag: String,
    /// 规则类型。
    pub kind: RuleKind,
    /// 匹配参数（后缀 / 精确域名 / CIDR；`MATCH` 时为空）。
    pub pattern: String,
    /// 命中后的动作链（有序）。
    pub action: ActionChainConfig,
    /// no-resolve 标志（IP 类规则对未解析域名流量不命中；默认 false，§11.11）。
    pub no_resolve: bool,
}

/// rule-provider 行为（§11.11）。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProviderBehavior {
    /// 每行一个域名（后缀匹配语义同 GEOSITE）。
    Domain,
    /// 每行一个 CIDR（复用 `IpPrefix` 解析）。
    IpCidr,
    /// 每行 `<KIND>,<pattern>`（复用现有全部 RuleKind）。
    Classical,
}

impl ProviderBehavior {
    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::IpCidr => "ipcidr",
            Self::Classical => "classical",
        }
    }

    fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "domain" => Ok(Self::Domain),
            "ipcidr" => Ok(Self::IpCidr),
            "classical" => Ok(Self::Classical),
            other => Err(ConfigError::new(
                "behavior",
                format!("unknown provider behavior '{other}'"),
            )),
        }
    }
}

/// rule-provider 配置（§11.11 本地；§11.12 在线 `url` + 刷新）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleProviderConfig {
    /// provider 标识（规则 `kind: rule_set, match: <tag>` 引用）。
    pub tag: String,
    /// 规则集行为。
    pub behavior: ProviderBehavior,
    /// 本地规则集文件路径（有 `url` 时为缓存落盘位置）。
    pub path: String,
    /// 在线源（可选；无则纯本地加载，§11.11 语义不变）。
    pub url: Option<String>,
    /// 刷新间隔秒数（可选；默认 86400，必须 ≥ 1）。
    pub refresh_interval_secs: Option<u64>,
}

/// 动作链配置：有序动作列表。P0 首动作为 `select_outbound`，后续动作为 P1+ 扩展口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionChainConfig {
    pub actions: Vec<ActionConfig>,
}

/// 动作类型（P0 仅 `select_outbound`）。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ActionKind {
    /// 选定出站或策略组 tag。
    SelectOutbound,
}

impl ActionKind {
    /// 稳定的机器可读标签（JSON `first_action`）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectOutbound => "select_outbound",
        }
    }

    fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "select_outbound" => Ok(Self::SelectOutbound),
            other => Err(ConfigError::new(
                "kind",
                format!("unknown action kind '{other}' (P0 supports only 'select_outbound')"),
            )),
        }
    }
}

/// 单个动作配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionConfig {
    pub kind: ActionKind,
    /// 选定的出站 tag 或策略组 tag。
    pub tag: String,
}

/// 策略组类型。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GroupKind {
    /// 手动选择（确定性切换，不探测）。
    Selector,
    /// 按离线 measurement 选最低延迟。
    UrlTest,
    /// round-robin 在多候选间均匀分发。
    LoadBalance,
    /// 链式级联：候选列表即跳序 [A, B, ...]。
    Relay,
}

impl GroupKind {
    /// 稳定的机器可读标签（JSON `group_type`）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selector => "selector",
            Self::UrlTest => "urltest",
            Self::LoadBalance => "load_balance",
            Self::Relay => "relay",
        }
    }

    fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "selector" => Ok(Self::Selector),
            "urltest" => Ok(Self::UrlTest),
            "load_balance" => Ok(Self::LoadBalance),
            "relay" => Ok(Self::Relay),
            other => Err(ConfigError::new(
                "kind",
                format!(
                    "unknown group kind '{other}' (supports selector/urltest/load_balance/relay)"
                ),
            )),
        }
    }
}

/// 策略组配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupConfig {
    pub tag: String,
    pub kind: GroupKind,
    /// 候选出站 tag 列表（不得为空）。
    pub candidates: Vec<String>,
}

/// 出站类型。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OutboundKind {
    /// 直连（复用 nexus-connectivity Direct 链路）。
    Direct,
    /// 进程内中继（复用 nexus-connectivity Relay 链路）。
    Relay,
    /// Shadowsocks AEAD 出站（§11.6；nexus-outbound-shadowsocks）。
    Shadowsocks,
    /// VMess AEAD 出站（§11.7；nexus-outbound-vmess）。
    Vmess,
    /// Trojan TLS 出站（§11.9；nexus-outbound-trojan）。
    Trojan,
    /// SOCKS5 出站（RFC 1928；P3 新增，用于 ProxyEngine TCP/UDP 转发）。
    Socks5,
    /// AnyTLS 出站（nexus-outbound-anytls）。
    Anytls,
    /// VLESS 出站（nexus-outbound-vless）。
    Vless,
    /// Hysteria2 出站（nexus-outbound-hysteria2）。
    Hysteria2,
}

impl OutboundKind {
    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Shadowsocks => "shadowsocks",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Socks5 => "socks5",
            Self::Anytls => "anytls",
            Self::Vless => "vless",
            Self::Hysteria2 => "hysteria2",
        }
    }

    fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "direct" => Ok(Self::Direct),
            "relay" => Ok(Self::Relay),
            "shadowsocks" => Ok(Self::Shadowsocks),
            "vmess" => Ok(Self::Vmess),
            "trojan" => Ok(Self::Trojan),
            "socks5" => Ok(Self::Socks5),
            "anytls" => Ok(Self::Anytls),
            "vless" => Ok(Self::Vless),
            "hysteria2" => Ok(Self::Hysteria2),
            other => Err(ConfigError::new(
                "kind",
                format!(
                    "unknown outbound kind '{other}' (supports direct/relay/shadowsocks/vmess/trojan/socks5/anytls/vless/hysteria2)"
                ),
            )),
        }
    }
}

/// 出站定义配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConfig {
    pub tag: String,
    pub kind: OutboundKind,
    /// 出口 locator（direct 可空；shadowsocks 形如 host:port）。
    pub locator: Option<String>,
    /// shadowsocks method（仅 shadowsocks 出站）。
    pub method: Option<String>,
    /// shadowsocks password（仅 shadowsocks 出站）。
    pub password: Option<String>,
    /// trojan ALPN 协议列表（§11.9.3，可空）。
    pub alpn: Option<Vec<String>>,
    /// trojan 是否跳过服务端证书链校验（§11.9.3）。
    pub skip_cert_verify: Option<bool>,
    /// trojan 请求头格式（§11.9.2）："standard" | "singbox"，缺省 standard。
    pub header_format: Option<String>,
    /// 混淆插件名（§7.3 二期；None = plain 直通；未知名 → dial 硬失败）。
    pub obfs: Option<String>,
    /// 混淆插件参数 key（如 xor 的 key 材料；None/空 → 需 key 的插件 wrap 失败）。
    pub obfs_key: Option<String>,
    /// vless UUID（仅 vless）。
    pub uuid: Option<String>,
    /// vless flow（仅 vless）："xtls-rprx-vision" 或空。
    pub flow: Option<String>,
    /// vless 是否启用 TLS（仅 vless；Vision 要求 true）。
    pub tls: Option<bool>,
    /// vless servername/SNI（仅 vless；缺省用 locator host）。
    pub servername: Option<String>,
    /// anytls/hysteria2 SNI（缺省用 locator host）。
    pub sni: Option<String>,
    /// hysteria2 端口跳跃范围（仅 hysteria2）："10000-20000,30000"。
    pub ports: Option<String>,
    /// hysteria2 上行带宽（仅 hysteria2）："100 Mbps"。
    pub up: Option<String>,
    /// hysteria2 下行带宽（仅 hysteria2）："100 Mbps"。
    pub down: Option<String>,
    /// hysteria2 salamander 混淆密码（仅 hysteria2）。
    pub obfs_password: Option<String>,
    /// trojan 第一响应守卫策略（仅 kind=trojan 生效；§11.9.3 / spec §8）：
    /// `"strict"`（缺省）| `"signature"`。不存在 `off`/完全关闭语义。
    /// 非 trojan 出站上的**合法值**被忽略（不生效、不报错），**非法值**硬失败。
    pub fallback_guard: Option<String>,
    /// trojan 就绪窗口毫秒覆盖（仅 kind=trojan 生效）：`None`/`0` = 自适应公式，
    /// `n>0` 时实际等待 `min(n, 5000)`ms。非 trojan 出站同上（合法值忽略、非法值硬失败）。
    pub ready_window_ms: Option<u64>,
}

/// DNS 多 server 路由配置（PRODUCT §11.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// 可选 DNS server 定义。
    pub servers: Vec<DnsServerConfig>,
    /// 有序域名路由规则（首匹配）。
    pub rules: Vec<DnsRouteRuleConfig>,
    /// MATCH 兜底 server tag。
    pub default_server: String,
}

/// 单个 DNS server 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerConfig {
    /// server 标识。
    pub tag: String,
    /// 上游地址（离线标签，本期不拨号）。
    pub address: String,
}

/// 一条 DNS 路由规则配置：命中 `domain`（域名）或 `ip_cidr`（IPv4 前缀，§11.5.1）走 `server`。
/// `domain` 与 `ip_cidr` 必须恰好给一个。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRouteRuleConfig {
    pub domain: Option<String>,
    pub ip_cidr: Option<String>,
    pub server: String,
}

/// 节点测速配置段（可选，PRODUCT §11.10）；缺失字段走默认值
/// （target=`http://www.gstatic.com/generate_204`、timeout_ms=5000、probe_kind=`tcp`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedtestConfig {
    /// 探测目标（仅 http/https）。
    pub target: String,
    /// 探测超时（毫秒）。
    pub timeout_ms: u64,
    /// 探测方式（P0 仅 `"tcp"`）。
    pub probe_kind: String,
}

// ---------------------------------------------------------------------------
// 最小确定性 YAML 子集解析器
//
// 支持：2 空格缩进 mapping / `- ` 序列 / 标量 / `#` 注释 / 行内 flow list `[a, b]`。
// 不支持：锚点/别名、多行标量、复杂 flow、多文档。纯 safe Rust，零依赖。
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Map(Vec<(String, Node)>),
    Seq(Vec<Node>),
    Scalar(String),
}

impl Node {
    fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            Node::Seq(_) | Node::Scalar(_) => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Node::Scalar(s) => Some(s.as_str()),
            Node::Map(_) | Node::Seq(_) => None,
        }
    }

    fn as_seq(&self) -> Option<&[Node]> {
        match self {
            Node::Seq(items) => Some(items),
            Node::Map(_) | Node::Scalar(_) => None,
        }
    }
}

/// 预处理：去注释、去首尾空白、记录缩进；返回 `(indent, text)` 序列。
fn preprocess(yaml: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for raw in yaml.split('\n') {
        let line = raw.trim_end_matches('\r');
        // 注释起始于行首或其后随空白的 `#`（我们的标量值不含 `#`）。
        let mut cut: Option<usize> = None;
        let mut prev_is_ws = true;
        for (i, b) in line.bytes().enumerate() {
            if b == b'#' && prev_is_ws {
                cut = Some(i);
                break;
            }
            prev_is_ws = b == b' ' || b == b'\t';
        }
        let line: &str = match cut {
            Some(i) => &line[..i],
            None => line,
        };
        let trimmed_end = line.trim_end();
        if trimmed_end.trim().is_empty() {
            continue;
        }
        let indent = trimmed_end.len() - trimmed_end.trim_start().len();
        out.push((indent, trimmed_end.trim_start().to_string()));
    }
    out
}

fn parse_block(
    lines: &[(usize, String)],
    pos: &mut usize,
    indent: usize,
) -> Result<Node, ConfigError> {
    let (ci, text) = &lines[*pos];
    if *ci != indent {
        return Err(ConfigError::new(
            "<parser>",
            format!("unexpected indentation at '{text}'"),
        ));
    }
    if text.starts_with('-') {
        parse_seq(lines, pos, indent)
    } else {
        parse_map(lines, pos, indent)
    }
}

fn parse_map(
    lines: &[(usize, String)],
    pos: &mut usize,
    indent: usize,
) -> Result<Node, ConfigError> {
    let mut entries = Vec::new();
    while *pos < lines.len() {
        let (ci, text) = &lines[*pos];
        if *ci != indent || text.starts_with('-') {
            break;
        }
        let colon = text.find(':').ok_or_else(|| {
            ConfigError::new("<map>", format!("expected 'key: value', got '{text}'"))
        })?;
        let key = text[..colon].trim().to_string();
        let rest = text[colon + 1..].trim().to_string();
        *pos += 1;
        let value = if rest.is_empty() {
            nested(lines, pos, indent)?
        } else {
            parse_scalar(&rest)?
        };
        entries.push((key, value));
    }
    Ok(Node::Map(entries))
}

/// 消费一个空值键后的嵌套块（下一行缩进必须更深）。
fn nested(
    lines: &[(usize, String)],
    pos: &mut usize,
    parent_indent: usize,
) -> Result<Node, ConfigError> {
    if *pos < lines.len() && lines[*pos].0 > parent_indent {
        parse_block(lines, pos, lines[*pos].0)
    } else {
        Ok(Node::Scalar(String::new()))
    }
}

fn parse_seq(
    lines: &[(usize, String)],
    pos: &mut usize,
    indent: usize,
) -> Result<Node, ConfigError> {
    let mut items = Vec::new();
    while *pos < lines.len() {
        let (ci, text) = &lines[*pos];
        if *ci != indent || !text.starts_with('-') {
            break;
        }
        // `- ` 之后的内容起始列（后续映射键对齐到此列）。
        let content_col = if text.starts_with("- ") {
            *ci + 2
        } else {
            *ci + 1
        };
        let after = text[1..].trim_start().to_string();
        *pos += 1;

        if after.is_empty() {
            items.push(nested(lines, pos, indent)?);
        } else if after.contains(':') {
            let colon = after.find(':').expect("checked contains ':'");
            let key = after[..colon].trim().to_string();
            let rest = after[colon + 1..].trim().to_string();
            let mut entries = Vec::new();
            if rest.is_empty() {
                let child = nested(lines, pos, content_col)?;
                entries.push((key, child));
            } else {
                entries.push((key, parse_scalar(&rest)?));
            }
            // 继续消费本映射项在 content_col 上的后续键。
            while *pos < lines.len() {
                let (nci, ntext) = &lines[*pos];
                if *nci != content_col || ntext.starts_with('-') {
                    break;
                }
                let colon = ntext.find(':').ok_or_else(|| {
                    ConfigError::new(
                        "<seq-item>",
                        format!("expected 'key: value', got '{ntext}'"),
                    )
                })?;
                let k = ntext[..colon].trim().to_string();
                let r = ntext[colon + 1..].trim().to_string();
                *pos += 1;
                let v = if r.is_empty() {
                    nested(lines, pos, content_col)?
                } else {
                    parse_scalar(&r)?
                };
                entries.push((k, v));
            }
            items.push(Node::Map(entries));
        } else {
            items.push(parse_scalar(&after)?);
        }
    }
    Ok(Node::Seq(items))
}

fn unquote(t: &str) -> String {
    let len = t.len();
    if len >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..len - 1].to_string()
    } else {
        t.to_string()
    }
}

fn parse_scalar(s: &str) -> Result<Node, ConfigError> {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('[') && t.ends_with(']') {
        let inner = &t[1..t.len() - 1];
        let items = inner
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| Node::Scalar(unquote(x)))
            .collect();
        return Ok(Node::Seq(items));
    }
    Ok(Node::Scalar(unquote(t)))
}

// ---------------------------------------------------------------------------
// 类型化提取辅助
// ---------------------------------------------------------------------------

fn req_str<'a>(node: &'a Node, key: &str, field: &str) -> Result<&'a str, ConfigError> {
    node.get(key)
        .and_then(Node::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ConfigError::new(field, format!("missing or non-string field '{key}'")))
}

/// 读取可选 u64 字段（YAML 数值以字符串标量承载）。
fn opt_u64(node: &Node, key: &str) -> Option<u64> {
    node.get(key)
        .and_then(Node::as_str)
        .and_then(|s| s.trim().parse::<u64>().ok())
}
fn opt_str(node: &Node, key: &str) -> Option<String> {
    node.get(key)
        .and_then(Node::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// 读取可选字符串字段，并**保留「存在但非法」的信号**（spec §8 的 presence-aware 提取）。
///
/// - `None`：字段缺失；
/// - `Some(Ok(v))`：标量值（可能是空串——空串是非法值，不是「未配置」）；
/// - `Some(Err(()))`：字段存在但不是标量（映射/序列）。
///
/// 不能用 [`opt_str`]：它过滤空串，会把 `fallback_guard: ""` 静默当成未配置。
fn opt_str_present(node: &Node, key: &str) -> Option<Result<String, ()>> {
    node.get(key)
        .map(|n| n.as_str().map(str::to_string).ok_or(()))
}

/// 读取可选 u64 字段，并保留「存在但非整数」的原始文本（供错误消息原样引用）。
///
/// - `None`：字段缺失；
/// - `Some(Ok(n))`：非负整数；
/// - `Some(Err(raw))`：存在但不是非负整数（`raw` 为原始文本；非标量为 `<non-scalar>`）。
fn opt_u64_present(node: &Node, key: &str) -> Option<Result<u64, String>> {
    node.get(key).map(|n| match n.as_str() {
        Some(s) => s.trim().parse::<u64>().map_err(|_| s.to_string()),
        None => Err("<non-scalar>".to_string()),
    })
}

/// 可选字符串列表（flow list `[a, b]` 或 `- ` 序列）。
fn opt_str_seq(node: &Node, key: &str) -> Option<Vec<String>> {
    node.get(key).and_then(Node::as_seq).map(|items| {
        items
            .iter()
            .filter_map(|n| n.as_str().map(str::to_string))
            .collect()
    })
}

/// 可选布尔（仅字面 `true` 为真，其余标量为假）。
fn opt_bool(node: &Node, key: &str) -> Option<bool> {
    node.get(key).and_then(Node::as_str).map(|s| s == "true")
}

fn req_seq<'a>(node: &'a Node, key: &str, field: &str) -> Result<&'a [Node], ConfigError> {
    node.get(key)
        .and_then(Node::as_seq)
        .ok_or_else(|| ConfigError::new(field, format!("missing or non-list field '{key}'")))
}

fn refield(mut e: ConfigError, field: &str) -> ConfigError {
    // 保留原因，仅提升字段路径到更具体的位置。
    e.field = format!("{field}.{}", e.field);
    e
}

/// 宽松数值字段：存在时必须能解析为 `u64`，不静默回退默认值。
fn req_opt_u64(node: &Node, key: &str, base: &str) -> Result<Option<u64>, ConfigError> {
    let Some(raw) = node.get(key) else {
        return Ok(None);
    };
    let text = raw
        .as_str()
        .ok_or_else(|| ConfigError::new(format!("{base}.{key}"), "expected an integer scalar"))?;
    let value = text.trim().parse::<u64>().map_err(|_| {
        ConfigError::new(
            format!("{base}.{key}"),
            format!("expected an integer, got '{text}'"),
        )
    })?;
    Ok(Some(value))
}

/// 校验 IPv4 CIDR（`a.b.c.d/prefix`，prefix ∈ `[0, 32]`）。
fn validate_ipv4_cidr(value: &str) -> Result<(), String> {
    let (addr, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("must be IPv4 CIDR (a.b.c.d/prefix), got '{value}'"))?;
    addr.parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 address '{addr}'"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("invalid CIDR prefix '{prefix}'"))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix out of range: {prefix}"));
    }
    Ok(())
}

/// 校验 TUN 设备名（Linux `IFNAMSIZ` 上限 15 字节）。
fn validate_tun_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("must not be empty".to_string());
    }
    if name.len() > 15 {
        return Err(format!("must be at most 15 bytes, got {}", name.len()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(format!("contains invalid character in '{name}'"));
    }
    Ok(())
}

fn parse_tun_inbound(node: &Node, base: &str) -> Result<TunInboundConfig, ConfigError> {
    let mut cfg = TunInboundConfig::default();
    if let Some(name) = opt_str(node, "name") {
        validate_tun_name(&name)
            .map_err(|reason| ConfigError::new(format!("{base}.name"), reason))?;
        cfg.name = name;
    }
    if let Some(mtu) = req_opt_u64(node, "mtu", base)? {
        let mtu = u16::try_from(mtu).map_err(|_| {
            ConfigError::new(
                format!("{base}.mtu"),
                format!("must be in [1280, 9000], got {mtu}"),
            )
        })?;
        if !(1280..=9000).contains(&mtu) {
            return Err(ConfigError::new(
                format!("{base}.mtu"),
                format!("must be in [1280, 9000], got {mtu}"),
            ));
        }
        cfg.mtu = mtu;
    }
    if let Some(address) = opt_str(node, "address") {
        validate_ipv4_cidr(&address)
            .map_err(|reason| ConfigError::new(format!("{base}.address"), reason))?;
        cfg.address = address;
    }
    if let Some(value) = opt_bool(node, "default_route") {
        cfg.default_route = value;
    }
    if let Some(value) = opt_bool(node, "exclude_server_routes") {
        cfg.exclude_server_routes = value;
    }
    if opt_bool(node, "fake_ip") == Some(true) {
        return Err(ConfigError::new(
            format!("{base}.fake_ip"),
            "fake-IP is not supported in this release; must be false",
        ));
    }
    if opt_bool(node, "ipv6") == Some(true) {
        return Err(ConfigError::new(
            format!("{base}.ipv6"),
            "IPv6 is not supported in this release; must be false",
        ));
    }
    if let Some(mode) = opt_str(node, "sessions") {
        cfg.sessions = FlowSessionsMode::parse(&mode)
            .map_err(|e| ConfigError::new(format!("{base}.sessions"), e.reason))?;
        cfg.sessions_explicit = true;
    }
    Ok(cfg)
}

/// 数值字段（支持十进制与 `0x` 十六进制）。
fn req_opt_int(node: &Node, key: &str, base: &str) -> Result<Option<u64>, ConfigError> {
    let Some(raw) = node.get(key) else {
        return Ok(None);
    };
    let text = raw
        .as_str()
        .ok_or_else(|| ConfigError::new(format!("{base}.{key}"), "expected an integer scalar"))?;
    let trimmed = text.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map(Some).map_err(|_| {
        ConfigError::new(
            format!("{base}.{key}"),
            format!("expected an integer, got '{text}'"),
        )
    })
}

/// 校验出站/策略组 tag 的字符约束（spec §9.7.1）。
fn validate_tag_text(tag: &str) -> Result<(), String> {
    if tag.is_empty() {
        return Err("must not be empty".to_string());
    }
    if tag.trim() != tag {
        return Err(format!(
            "must not have leading/trailing whitespace in '{tag}'"
        ));
    }
    if tag.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "must not contain whitespace or control characters in '{tag}'"
        ));
    }
    if tag.len() > 64 {
        return Err(format!("must be at most 64 bytes, got {}", tag.len()));
    }
    Ok(())
}

/// 出站/策略组 tag 的完整性与唯一性校验（spec §8.7 / §9.7.1）。
fn validate_tags(outbounds: &[OutboundConfig], groups: &[GroupConfig]) -> Result<(), ConfigError> {
    use std::collections::BTreeMap;

    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, outbound) in outbounds.iter().enumerate() {
        validate_tag_text(&outbound.tag)
            .map_err(|reason| ConfigError::new(format!("outbounds[{i}].tag"), reason))?;
        if outbound.tag.eq_ignore_ascii_case("direct") && outbound.kind != OutboundKind::Direct {
            return Err(ConfigError::new(
                format!("outbounds[{i}].tag"),
                format!("reserved tag '{}'", outbound.tag),
            ));
        }
        if seen.insert(outbound.tag.as_str(), i).is_some() {
            return Err(ConfigError::new(
                format!("outbounds[{i}].tag"),
                format!("duplicate tag '{}'", outbound.tag),
            ));
        }
    }
    for (i, group) in groups.iter().enumerate() {
        validate_tag_text(&group.tag)
            .map_err(|reason| ConfigError::new(format!("groups[{i}].tag"), reason))?;
        if group.tag.eq_ignore_ascii_case("direct") {
            return Err(ConfigError::new(
                format!("groups[{i}].tag"),
                format!("reserved tag '{}'", group.tag),
            ));
        }
        if seen.insert(group.tag.as_str(), i).is_some() {
            return Err(ConfigError::new(
                format!("groups[{i}].tag"),
                format!("duplicate tag '{}'", group.tag),
            ));
        }
    }
    Ok(())
}

fn validate_chain_name(chain: &str) -> Result<(), String> {
    if chain.is_empty() {
        return Err("must not be empty".to_string());
    }
    if chain.len() > 28 {
        return Err(format!("must be at most 28 bytes, got {}", chain.len()));
    }
    if chain.chars().any(char::is_whitespace) {
        return Err(format!("must not contain whitespace in '{chain}'"));
    }
    Ok(())
}

fn validate_cidr_list(values: &[String], field: &str) -> Result<(), ConfigError> {
    for cidr in values {
        validate_ipv4_cidr(cidr).map_err(|reason| {
            ConfigError::new(field, format!("invalid CIDR '{cidr}': {reason}"))
        })?;
    }
    Ok(())
}

fn parse_tproxy_inbound(
    node: &Node,
    base: &str,
    listen: &str,
) -> Result<TproxyInboundConfig, ConfigError> {
    let listen_addr: std::net::SocketAddrV4 = listen.parse().map_err(|_| {
        ConfigError::new(
            format!("{base}.listen"),
            format!("must be an IPv4 ip:port, got '{listen}'"),
        )
    })?;
    let mut cfg = TproxyInboundConfig {
        tcp_port: listen_addr.port(),
        udp_port: listen_addr.port(),
        ..TproxyInboundConfig::default()
    };

    for (key, is_tcp) in [("tcp_port", true), ("udp_port", false)] {
        if let Some(value) = req_opt_int(node, key, base)? {
            if value == 0 || value > u64::from(u16::MAX) {
                return Err(ConfigError::new(
                    format!("{base}.{key}"),
                    format!("must be in [1, 65535], got {value}"),
                ));
            }
            let port = u16::try_from(value).expect("range checked");
            if is_tcp {
                cfg.tcp_port = port;
            } else {
                cfg.udp_port = port;
            }
        }
    }

    if let Some(backend) = opt_str(node, "backend") {
        cfg.backend = CaptureBackendConfig::parse(&backend)
            .map_err(|e| ConfigError::new(format!("{base}.backend"), e.reason))?;
    }
    if let Some(chain) = opt_str(node, "chain") {
        validate_chain_name(&chain)
            .map_err(|reason| ConfigError::new(format!("{base}.chain"), reason))?;
        cfg.chain = chain;
    }
    if let Some(mark) = req_opt_int(node, "mark", base)? {
        if mark == 0 || mark > u64::from(u32::MAX) {
            return Err(ConfigError::new(
                format!("{base}.mark"),
                format!("must be in [1, 4294967295], got {mark}"),
            ));
        }
        cfg.mark = u32::try_from(mark).expect("range checked");
    }
    if let Some(table) = req_opt_int(node, "route_table", base)? {
        if table == 0 || table > u64::from(u32::MAX) {
            return Err(ConfigError::new(
                format!("{base}.route_table"),
                format!("must be in [1, 4294967295], got {table}"),
            ));
        }
        cfg.route_table = u32::try_from(table).expect("range checked");
    }
    if let Some(list) = opt_str_seq(node, "intercept_dst_cidrs") {
        validate_cidr_list(&list, &format!("{base}.intercept_dst_cidrs"))?;
        cfg.intercept_dst_cidrs = list;
    }
    if let Some(list) = opt_str_seq(node, "exclude_dst_cidrs") {
        validate_cidr_list(&list, &format!("{base}.exclude_dst_cidrs"))?;
        cfg.exclude_dst_cidrs = list;
    }
    if cfg.intercept_dst_cidrs.len() + cfg.exclude_dst_cidrs.len() > 256 {
        return Err(ConfigError::new(
            format!("{base}.exclude_dst_cidrs"),
            "total CIDR entries must not exceed 256",
        ));
    }
    if let Some(mode) = opt_str(node, "on_capture_failure") {
        cfg.on_capture_failure = CaptureFailureMode::parse(&mode)
            .map_err(|e| ConfigError::new(format!("{base}.on_capture_failure"), e.reason))?;
    }
    if let Some(mode) = opt_str(node, "on_path_failure") {
        cfg.on_path_failure = PathFailureMode::parse(&mode)
            .map_err(|e| ConfigError::new(format!("{base}.on_path_failure"), e.reason))?;
    }
    if let Some(value) = req_opt_int(node, "max_tcp_conns", base)? {
        if value == 0 {
            return Err(ConfigError::new(
                format!("{base}.max_tcp_conns"),
                "must be >= 1",
            ));
        }
        cfg.max_tcp_conns = usize::try_from(value).expect("fits usize on supported targets");
    }
    if let Some(value) = req_opt_int(node, "udp_table_capacity", base)? {
        if value == 0 {
            return Err(ConfigError::new(
                format!("{base}.udp_table_capacity"),
                "must be >= 1",
            ));
        }
        cfg.udp_table_capacity = usize::try_from(value).expect("fits usize on supported targets");
    }
    if let Some(value) = req_opt_int(node, "udp_idle_secs", base)? {
        if value == 0 {
            return Err(ConfigError::new(
                format!("{base}.udp_idle_secs"),
                "must be >= 1",
            ));
        }
        cfg.udp_idle_secs = value;
    }
    if opt_bool(node, "ipv6") == Some(true) {
        return Err(ConfigError::new(
            format!("{base}.ipv6"),
            "IPv6 is not supported in this release; must be false",
        ));
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// 公开解析入口
// ---------------------------------------------------------------------------

/// 把 YAML 文本解析为 typed `ProxyConfig`，并做结构化校验。
///
/// 失败一律返回 `CONFIG_INVALID { field, reason }`，不静默回退默认值。
///
/// # Errors
///
/// - `schema_version` 缺失/非整数/不为 1；
/// - 规则表为空或不以 `MATCH` 结尾；
/// - 动作链为空、首动作非 `select_outbound`、引用悬空 tag；
/// - 策略组候选为空或候选引用悬空出站；
/// - 未知 kind。
pub fn parse(yaml: &str) -> Result<ProxyConfig, ConfigError> {
    let lines = preprocess(yaml);
    if lines.is_empty() {
        return Err(ConfigError::new("<root>", "empty config"));
    }
    let mut pos = 0;
    let root = parse_block(&lines, &mut pos, lines[0].0)?;
    if root.get("rules").is_none() && root.get("outbounds").is_none() {
        return Err(ConfigError::new("<root>", "root must be a mapping"));
    }

    let schema_version = root
        .get("schema_version")
        .and_then(Node::as_str)
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| ConfigError::new("schema_version", "must be an integer"))?;
    if schema_version != 1 {
        return Err(ConfigError::new(
            "schema_version",
            format!("expected 1, got {schema_version}"),
        ));
    }

    // ---- outbounds ----
    let mut outbounds = Vec::new();
    if let Some(seq) = root.get("outbounds").and_then(Node::as_seq) {
        for (i, item) in seq.iter().enumerate() {
            let field = format!("outbounds[{i}]");
            let tag = req_str(item, "tag", &field)
                .map_err(|mut e| {
                    if e.field == field {
                        e.field = format!("{field}.tag");
                    }
                    e
                })?
                .to_string();
            let kind_s = req_str(item, "kind", &field)?;
            let kind =
                OutboundKind::parse(kind_s).map_err(|e| refield(e, &format!("{field}.kind")))?;
            let locator = opt_str(item, "locator");
            let method = opt_str(item, "method");
            let password = opt_str(item, "password");
            let alpn = opt_str_seq(item, "alpn");
            let skip_cert_verify = opt_bool(item, "skip_cert_verify");
            let header_format = opt_str(item, "header_format");
            let obfs = opt_str(item, "obfs");
            let obfs_key = opt_str(item, "obfs_key");
            let uuid = opt_str(item, "uuid");
            let flow = opt_str(item, "flow");
            let tls = opt_bool(item, "tls");
            let servername = opt_str(item, "servername");
            let sni = opt_str(item, "sni");
            let ports = opt_str(item, "ports");
            let up = opt_str(item, "up");
            let down = opt_str(item, "down");
            let obfs_password = opt_str(item, "obfs_password");
            // 新增字段的 presence-aware 提取 + 值域校验（spec §8）：
            // 校验顺序 = 先按 trojan 值域校验（对所有 kind），再按 kind 决定是否生效。
            // 「存在但非法」一律 CONFIG_INVALID —— 这是本 run 新增的 fail-closed 裁决，
            // 比现状 header_format（仅在 kind==Trojan 块内校验、非 trojan 非法值被静默忽略）
            // 更严；不写成「与既有/R2 惯例对齐」。
            let fallback_guard = match opt_str_present(item, "fallback_guard") {
                None => None,
                Some(Ok(v)) if v == "strict" || v == "signature" => Some(v),
                Some(Ok(v)) => {
                    return Err(ConfigError::new(
                        format!("outbounds[{tag}].fallback_guard"),
                        format!("fallback_guard must be 'strict' or 'signature', got '{v}'"),
                    ));
                }
                Some(Err(())) => {
                    return Err(ConfigError::new(
                        format!("outbounds[{tag}].fallback_guard"),
                        "fallback_guard must be 'strict' or 'signature', got '<non-scalar>'",
                    ));
                }
            };
            let ready_window_ms = match opt_u64_present(item, "ready_window_ms") {
                None => None,
                Some(Ok(n)) if n <= 5000 => Some(n),
                Some(Ok(n)) => {
                    return Err(ConfigError::new(
                        format!("outbounds[{tag}].ready_window_ms"),
                        format!("ready_window_ms must be in 0..=5000, got {n}"),
                    ));
                }
                Some(Err(raw)) => {
                    return Err(ConfigError::new(
                        format!("outbounds[{tag}].ready_window_ms"),
                        format!("ready_window_ms must be in 0..=5000, got {raw}"),
                    ));
                }
            };
            outbounds.push(OutboundConfig {
                tag,
                kind,
                locator,
                method,
                password,
                alpn,
                skip_cert_verify,
                header_format,
                obfs,
                obfs_key,
                uuid,
                flow,
                tls,
                servername,
                sni,
                ports,
                up,
                down,
                obfs_password,
                fallback_guard,
                ready_window_ms,
            });
        }
    }
    if outbounds.is_empty() {
        return Err(ConfigError::new(
            "outbounds",
            "at least one outbound required",
        ));
    }

    // Shadowsocks 出站必须携带合法 method 与非空 password（§11.6）。
    for o in &outbounds {
        if o.kind == OutboundKind::Shadowsocks {
            if o.method.as_deref() != Some("chacha20-ietf-poly1305") {
                return Err(ConfigError::new(
                    format!("outbounds[{}].method", o.tag),
                    "shadowsocks outbound requires method 'chacha20-ietf-poly1305'",
                ));
            }
            if o.password.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].password", o.tag),
                    "shadowsocks outbound requires a non-empty password",
                ));
            }
        }
    }

    // Trojan 出站（§11.9.3）：password/locator 必填；header_format 仅 standard|singbox。
    for o in &outbounds {
        if o.kind == OutboundKind::Anytls {
            if o.password.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].password", o.tag),
                    "anytls outbound requires a non-empty password",
                ));
            }
            if o.locator.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].locator", o.tag),
                    "anytls outbound requires a locator (host:port)",
                ));
            }
        }
    }

    for o in &outbounds {
        if o.kind == OutboundKind::Vless {
            if o.uuid.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].uuid", o.tag),
                    "vless outbound requires a non-empty uuid",
                ));
            }
            if o.locator.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].locator", o.tag),
                    "vless outbound requires a locator (host:port)",
                ));
            }
            if let Some(f) = o.flow.as_deref() {
                if !f.is_empty() && f != "xtls-rprx-vision" {
                    return Err(ConfigError::new(
                        format!("outbounds[{}].flow", o.tag),
                        format!("vless flow must be '' or 'xtls-rprx-vision', got '{f}'"),
                    ));
                }
                if f == "xtls-rprx-vision" && o.tls != Some(true) {
                    return Err(ConfigError::new(
                        format!("outbounds[{}].tls", o.tag),
                        "vless flow xtls-rprx-vision requires tls: true",
                    ));
                }
            }
        }
    }

    for o in &outbounds {
        if o.kind == OutboundKind::Hysteria2 {
            if o.password.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].password", o.tag),
                    "hysteria2 outbound requires a non-empty password",
                ));
            }
            if o.locator.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].locator", o.tag),
                    "hysteria2 outbound requires a locator (host:port)",
                ));
            }
            // WARN5: obfs 枚举校验——只允许已知值，拼写错误直接报错，
            // 防止绕过 salamander 密码必填检查。
            // NEW_COMMENTED_1: 允许 none （与 Obfs::parse 对齐：空串/none 均为无混淆）。
            if let Some(ob) = o.obfs.as_deref() {
                if !ob.is_empty() && ob != "salamander" && ob != "none" {
                    return Err(ConfigError::new(
                        format!("outbounds[{}].obfs", o.tag),
                        format!("hysteria2 unknown obfs '{ob}'; allowed: none, salamander"),
                    ));
                }
            }
            if let Some(ob) = o.obfs.as_deref() {
                if ob == "salamander"
                    && o.obfs_password
                        .as_ref()
                        .map(String::is_empty)
                        .unwrap_or(true)
                {
                    return Err(ConfigError::new(
                        format!("outbounds[{}].obfs_password", o.tag),
                        "hysteria2 obfs salamander requires obfs_password",
                    ));
                }
            }
        }
    }

    for o in &outbounds {
        if o.kind == OutboundKind::Trojan {
            if o.password.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].password", o.tag),
                    "trojan outbound requires a non-empty password",
                ));
            }
            if o.locator.as_ref().map(String::is_empty).unwrap_or(true) {
                return Err(ConfigError::new(
                    format!("outbounds[{}].locator", o.tag),
                    "trojan outbound requires a locator (host:port)",
                ));
            }
            if let Some(hf) = o.header_format.as_deref() {
                if hf != "standard" && hf != "singbox" {
                    return Err(ConfigError::new(
                        format!("outbounds[{}].header_format", o.tag),
                        format!("header_format must be 'standard' or 'singbox', got '{hf}'"),
                    ));
                }
            }
        }
    }

    // ---- groups ----
    let mut groups = Vec::new();
    if let Some(seq) = root.get("groups").and_then(Node::as_seq) {
        for (i, item) in seq.iter().enumerate() {
            let field = format!("groups[{i}]");
            let tag = req_str(item, "tag", &field)
                .map_err(|mut e| {
                    if e.field == field {
                        e.field = format!("{field}.tag");
                    }
                    e
                })?
                .to_string();
            let kind_s = req_str(item, "kind", &field)?;
            let kind =
                GroupKind::parse(kind_s).map_err(|e| refield(e, &format!("{field}.kind")))?;
            let cseq = item
                .get("candidates")
                .and_then(Node::as_seq)
                .ok_or_else(|| ConfigError::new(format!("{field}.candidates"), "must be a list"))?;
            let candidates = cseq
                .iter()
                .map(|c| {
                    c.as_str().map(str::to_string).ok_or_else(|| {
                        ConfigError::new(format!("{field}.candidates"), "non-string candidate")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if candidates.is_empty() {
                return Err(ConfigError::new(
                    format!("{field}.candidates"),
                    "selector/urltest group candidates must not be empty",
                ));
            }
            groups.push(GroupConfig {
                tag,
                kind,
                candidates,
            });
        }
    }

    validate_tags(&outbounds, &groups)?;

    // ---- inbounds ----
    let mut inbounds = Vec::new();
    if let Some(seq) = root.get("inbounds").and_then(Node::as_seq) {
        for (i, item) in seq.iter().enumerate() {
            let field = format!("inbounds[{i}]");
            let tag = req_str(item, "tag", &field)?.to_string();
            let kind_s = req_str(item, "kind", &field)?;
            let kind = InboundKind::parse(kind_s).map_err(|mut e| {
                e.field = format!("{field}.kind");
                e
            })?;
            let listen = match kind {
                InboundKind::Socks5 | InboundKind::Mixed => {
                    req_str(item, "listen", &field)?.to_string()
                }
                InboundKind::Tun => opt_str(item, "listen").unwrap_or_default(),
                InboundKind::Tproxy => opt_str(item, "listen")
                    .unwrap_or_else(|| crate::TPROXY_DEFAULT_LISTEN.to_string()),
            };
            let tun = if kind == InboundKind::Tun {
                Some(parse_tun_inbound(item, &field)?)
            } else {
                None
            };
            let tproxy = if kind == InboundKind::Tproxy {
                Some(parse_tproxy_inbound(item, &field, &listen)?)
            } else {
                None
            };
            inbounds.push(InboundConfig {
                tag,
                kind,
                listen,
                tun,
                tproxy,
            });
        }
    }
    if inbounds
        .iter()
        .filter(|i| i.kind == InboundKind::Tun)
        .count()
        > 1
    {
        return Err(ConfigError::new(
            "inbounds",
            "only one tun inbound is supported",
        ));
    }
    if inbounds
        .iter()
        .filter(|i| i.kind == InboundKind::Tproxy)
        .count()
        > 1
    {
        return Err(ConfigError::new(
            "inbounds",
            "only one tproxy inbound is supported",
        ));
    }

    // ---- rules ----
    let rules_seq = req_seq(&root, "rules", "<root>")?;
    if rules_seq.is_empty() {
        return Err(ConfigError::new("rules", "at least one rule required"));
    }
    let mut rules = Vec::new();
    for (i, item) in rules_seq.iter().enumerate() {
        let field = format!("rules[{i}]");
        let tag = req_str(item, "tag", &field)?.to_string();
        let kind_s = req_str(item, "kind", &field)?;
        let kind = RuleKind::parse(kind_s).map_err(|e| refield(e, &format!("{field}.kind")))?;
        let pattern = opt_str(item, "match").unwrap_or_default();
        let no_resolve = opt_bool(item, "no_resolve").unwrap_or(false);

        let action_node = item
            .get("action")
            .ok_or_else(|| ConfigError::new(format!("{field}.action"), "missing action chain"))?;
        let action_seq = action_node.as_seq().ok_or_else(|| {
            ConfigError::new(format!("{field}.action"), "action must be an ordered list")
        })?;
        if action_seq.is_empty() {
            return Err(ConfigError::new(
                format!("{field}.action"),
                "action chain must not be empty",
            ));
        }
        let mut actions = Vec::new();
        for (j, a) in action_seq.iter().enumerate() {
            let afield = format!("{field}.action[{j}]");
            let akind_s = req_str(a, "kind", &afield)?;
            let akind =
                ActionKind::parse(akind_s).map_err(|e| refield(e, &format!("{afield}.kind")))?;
            let atag = req_str(a, "tag", &afield)?.to_string();
            actions.push(ActionConfig {
                kind: akind,
                tag: atag,
            });
        }
        rules.push(RuleConfig {
            tag,
            kind,
            pattern,
            action: ActionChainConfig { actions },
            no_resolve,
        });
    }

    // ---- dns（可选，§11.5）----
    let dns = if let Some(dns_node) = root.get("dns") {
        let sseq = req_seq(dns_node, "servers", "dns")?;
        let mut servers = Vec::new();
        for (i, item) in sseq.iter().enumerate() {
            let f = format!("dns.servers[{i}]");
            let tag = req_str(item, "tag", &f)?.to_string();
            let address = req_str(item, "address", &f)?.to_string();
            servers.push(DnsServerConfig { tag, address });
        }
        if servers.is_empty() {
            return Err(ConfigError::new(
                "dns.servers",
                "at least one dns server required",
            ));
        }
        let mut rules = Vec::new();
        if let Some(rseq) = dns_node.get("rules").and_then(Node::as_seq) {
            for (i, item) in rseq.iter().enumerate() {
                let f = format!("dns.rules[{i}]");
                let domain = opt_str(item, "domain");
                let ip_cidr = opt_str(item, "ip_cidr");
                let server = req_str(item, "server", &f)?.to_string();
                if domain.is_none() && ip_cidr.is_none() {
                    return Err(ConfigError::new(
                        f,
                        "dns rule requires exactly one of `domain` or `ip_cidr`",
                    ));
                }
                if domain.is_some() && ip_cidr.is_some() {
                    return Err(ConfigError::new(
                        f,
                        "dns rule must not set both `domain` and `ip_cidr`",
                    ));
                }
                rules.push(DnsRouteRuleConfig {
                    domain,
                    ip_cidr,
                    server,
                });
            }
        }
        let default_server = req_str(dns_node, "default_server", "dns")?.to_string();
        Some(DnsConfig {
            servers,
            rules,
            default_server,
        })
    } else {
        None
    };

    // ---- 结构化校验（MODULE.md Invariants / PRODUCT.md §11.3） ----
    if rules.last().map(|r| r.kind) != Some(RuleKind::Match) {
        return Err(ConfigError::new(
            "rules",
            "rule table must end with a MATCH fallback rule",
        ));
    }

    let outbound_tags: BTreeSet<&str> = outbounds.iter().map(|o| o.tag.as_str()).collect();
    let group_tags: BTreeSet<&str> = groups.iter().map(|g| g.tag.as_str()).collect();

    // 动作链首动作引用的 tag 必须能在出站/策略组表中解析（OUTBOUND_TAG_UNRESOLVED）。
    for rule in &rules {
        for action in &rule.action.actions {
            match action.kind {
                ActionKind::SelectOutbound => {
                    if !outbound_tags.contains(action.tag.as_str())
                        && !group_tags.contains(action.tag.as_str())
                    {
                        return Err(ConfigError::new(
                            format!("rules[{}].action.tag", rule.tag),
                            format!("outbound/group tag '{}' is not defined", action.tag),
                        ));
                    }
                }
            }
        }
    }

    // DNS 规则与兜底引用的 server tag 必须已定义（DNS_SERVER_UNRESOLVED）。
    if let Some(cfg) = &dns {
        let dns_tags: BTreeSet<&str> = cfg.servers.iter().map(|s| s.tag.as_str()).collect();
        for r in &cfg.rules {
            if !dns_tags.contains(r.server.as_str()) {
                return Err(ConfigError::new(
                    format!("dns.rules[server={}]", r.server),
                    format!("dns server '{}' is not defined", r.server),
                ));
            }
        }
        if !dns_tags.contains(cfg.default_server.as_str()) {
            return Err(ConfigError::new(
                "dns.default_server",
                format!("dns server '{}' is not defined", cfg.default_server),
            ));
        }
    }

    // ---- speedtest（可选，§11.10）----
    let speedtest = if let Some(st_node) = root.get("speedtest") {
        let target = match st_node.get("target") {
            Some(v) => match v.as_str() {
                Some(s) if s.starts_with("http://") || s.starts_with("https://") => s.to_string(),
                _ => {
                    return Err(ConfigError::new("speedtest.target", "must be http(s) URL"));
                }
            },
            None => "http://www.gstatic.com/generate_204".to_string(),
        };
        let timeout_ms = match st_node.get("timeout_ms") {
            Some(v) => v
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| ConfigError::new("speedtest.timeout_ms", "must be integer"))?,
            None => 5000,
        };
        let probe_kind = match st_node.get("probe_kind") {
            Some(v) => match v.as_str() {
                Some("tcp") => "tcp".to_string(),
                Some("http204") => "http204".to_string(),
                _ => {
                    return Err(ConfigError::new(
                        "speedtest.probe_kind",
                        "must be `tcp` or `http204`",
                    ));
                }
            },
            None => "tcp".to_string(),
        };
        Some(SpeedtestConfig {
            target,
            timeout_ms,
            probe_kind,
        })
    } else {
        None
    };
    // ---- rule-providers（可选，§11.11）----
    let mut rule_providers = Vec::new();
    if let Some(rp_node) = root.get("rule-providers") {
        let entries = match rp_node {
            Node::Map(items) => items,
            _ => return Err(ConfigError::new("rule-providers", "must be a mapping")),
        };
        for (name, item) in entries {
            let field = format!("rule-providers.{name}");
            let behavior_s = req_str(item, "behavior", &field)?;
            let behavior = ProviderBehavior::parse(behavior_s)
                .map_err(|e| refield(e, &format!("{field}.behavior")))?;
            let path = req_str(item, "path", &field)?.to_string();
            if path.is_empty() {
                return Err(ConfigError::new(
                    format!("{field}.path"),
                    "path must not be empty",
                ));
            }
            let url = opt_str(item, "url");
            let refresh_interval_secs = match opt_u64(item, "refresh_interval_secs") {
                Some(0) => {
                    return Err(ConfigError::new(
                        format!("{field}.refresh_interval_secs"),
                        "must be >= 1",
                    ));
                }
                other => other,
            };
            rule_providers.push(RuleProviderConfig {
                tag: name.clone(),
                behavior,
                path,
                url,
                refresh_interval_secs,
            });
        }
    }
    // 策略组候选必须引用已定义出站。
    for g in &groups {
        for c in &g.candidates {
            if !outbound_tags.contains(c.as_str()) {
                return Err(ConfigError::new(
                    format!("groups[{}].candidates", g.tag),
                    format!("candidate outbound '{c}' is not defined"),
                ));
            }
        }
    }

    Ok(ProxyConfig {
        schema_version,
        inbounds,
        rules,
        groups,
        outbounds,
        dns,
        speedtest,
        rule_providers,
    })
}

// ---------------------------------------------------------------------------
// Clash 订阅节点解析（PRODUCT.md §11.8）
// ---------------------------------------------------------------------------

/// 一条被显式拒绝（不支持）的订阅节点行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedEntry {
    /// 原始行文本（截断保留以可诊断）。
    pub line: String,
    /// 拒绝原因（如 "unsupported scheme 'trojan'"）。
    pub reason: String,
}

/// 订阅解析结果：成功映射的出站 + 被拒绝的行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionParse {
    /// 映射出的出站（ss/vmess）。
    pub outbounds: Vec<OutboundConfig>,
    /// 显式拒绝的行（未知协议等，非致命）。
    pub rejected: Vec<RejectedEntry>,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 base64 字母表解码（支持 `=` 填充；输入先剥离全部空白）。
///
/// # Errors
///
/// 含非字母表字符、或长度对齐非法时返回 `ConfigError`。
fn base64_decode(text: &str) -> Result<Vec<u8>, ConfigError> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut lut = [u8::MAX; 256];
    for (i, &c) in B64.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let mut iter = clean.iter().copied().enumerate().peekable();
    while let Some((idx, byte)) = iter.next() {
        if byte == b'=' {
            break;
        }
        let d0 = lut[byte as usize];
        if d0 == u8::MAX {
            return Err(ConfigError::new(
                "subscription",
                format!("invalid base64 char at byte {idx}"),
            ));
        }
        let Some((_, b1)) = iter.next() else {
            return Err(ConfigError::new("subscription", "truncated base64"));
        };
        let d1 = lut[b1 as usize];
        if d1 == u8::MAX {
            return Err(ConfigError::new("subscription", "invalid base64 char"));
        }
        out.push((d0 << 2) | (d1 >> 4));
        // 第三个 sextet：可能是 '=' 填充。
        match iter.next() {
            Some((_, b2)) if b2 != b'=' => {
                let d2 = lut[b2 as usize];
                if d2 == u8::MAX {
                    return Err(ConfigError::new("subscription", "invalid base64 char"));
                }
                out.push((d1 << 4) | (d2 >> 2));
                match iter.next() {
                    Some((_, b3)) if b3 != b'=' => {
                        let d3 = lut[b3 as usize];
                        if d3 == u8::MAX {
                            return Err(ConfigError::new("subscription", "invalid base64 char"));
                        }
                        out.push((d2 << 6) | d3);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let _ = &mut iter;
    Ok(out)
}

/// 从 `host:port` 末尾拆出端口。
fn split_host_port(hostport: &str) -> Option<(&str, u16)> {
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some((host, port))
}

/// 解析单行 `scheme://userinfo@host:port#name` 为出站；不支持的 scheme 返回 rejected 原因。
fn parse_node_line(line: &str) -> Result<OutboundConfig, (String, RejectedEntry)> {
    let (scheme, rest) = line.split_once("://").ok_or_else(|| {
        (
            line.to_string(),
            RejectedEntry {
                line: line.to_string(),
                reason: "no scheme".to_string(),
            },
        )
    })?;
    let (target, name) = rest.split_once('#').unwrap_or((rest, line));
    let name = percent_name(name);
    let (userinfo, hostport) = target.rsplit_once('@').ok_or_else(|| {
        (
            line.to_string(),
            RejectedEntry {
                line: line.to_string(),
                reason: "missing userinfo@host".to_string(),
            },
        )
    })?;
    let (host, port) = split_host_port(hostport).ok_or_else(|| {
        (
            line.to_string(),
            RejectedEntry {
                line: line.to_string(),
                reason: "bad host:port".to_string(),
            },
        )
    })?;
    let locator = format!("{host}:{port}");

    match scheme {
        "ss" => {
            // userinfo = base64("method:password")
            let raw = base64_decode(userinfo).map_err(|e| {
                (
                    line.to_string(),
                    RejectedEntry {
                        line: line.to_string(),
                        reason: format!("ss userinfo decode: {e}"),
                    },
                )
            })?;
            let text = String::from_utf8(raw).map_err(|_| {
                (
                    line.to_string(),
                    RejectedEntry {
                        line: line.to_string(),
                        reason: "ss userinfo not utf-8".to_string(),
                    },
                )
            })?;
            let (method, password) = text.split_once(':').ok_or_else(|| {
                (
                    line.to_string(),
                    RejectedEntry {
                        line: line.to_string(),
                        reason: "ss userinfo needs method:password".to_string(),
                    },
                )
            })?;
            Ok(OutboundConfig {
                tag: name,
                kind: OutboundKind::Shadowsocks,
                locator: Some(locator),
                method: Some(method.to_string()),
                password: Some(password.to_string()),
                alpn: None,
                skip_cert_verify: None,
                header_format: None,
                obfs: None,
                obfs_key: None,
                uuid: None,
                flow: None,
                tls: None,
                servername: None,
                sni: None,
                ports: None,
                up: None,
                down: None,
                obfs_password: None,
                fallback_guard: None,
                ready_window_ms: None,
            })
        }
        "vmess" => Ok(OutboundConfig {
            tag: name,
            kind: OutboundKind::Vmess,
            locator: Some(locator),
            method: Some("chacha20-poly1305".to_string()),
            password: Some(userinfo.to_string()),
            alpn: None,
            skip_cert_verify: None,
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: None,
            flow: None,
            tls: None,
            servername: None,
            sni: None,
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
        }),
        other => Err((
            line.to_string(),
            RejectedEntry {
                line: line.to_string(),
                reason: format!("unsupported scheme '{other}'"),
            },
        )),
    }
}

/// `#name` 去除可能的 `%23` 等编码占位；本期仅做字面截取，保留可读字符。
fn percent_name(raw: &str) -> String {
    raw.trim().to_string()
}

/// 解析 Clash/通用 base64 订阅文本为出站列表 + 拒绝行（§11.8，纯函数、离线）。
///
/// # Errors
///
/// 整段 base64 非法（字符/对齐）返回 `ConfigError`。
pub fn parse_clash_subscription(text: &str) -> Result<SubscriptionParse, ConfigError> {
    let bytes = base64_decode(text)?;
    let decoded = String::from_utf8(bytes)
        .map_err(|_| ConfigError::new("subscription", "decoded bytes not utf-8"))?;
    let mut outbounds = Vec::new();
    let mut rejected = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_node_line(line) {
            Ok(o) => outbounds.push(o),
            Err((_, entry)) => rejected.push(entry),
        }
    }
    Ok(SubscriptionParse {
        outbounds,
        rejected,
    })
}

// ---------------------------------------------------------------------------
// 订阅节点在线更新（PRODUCT.md §11.17，requirement-change）
//
// 本 crate 只持有可移植、纯内存、离线的配置与状态机：
// - [`SubscriptionSourceConfig`]：订阅源声明（url/interval/user-agent/headers/TLS 选项）；
// - [`SubscriptionRuntime`]：喂入一次拉取到的订阅文本（Ok(body)）或失败（Err），
//   复用 [`parse_clash_subscription`] 解析、整体替换订阅节点集、失败回退保留旧集。
//
// 真正的 HTTP(S) 拉取与后台拉取线程在组合根（apps/nexus）装配，不污染 portable core。
// ---------------------------------------------------------------------------

/// 订阅源配置（§11.17）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionSourceConfig {
    /// 订阅源标识（可观察事件关联字段）。
    pub tag: String,
    /// 订阅地址（`http://` 明文 / `https://` rustls，§11.14 传输层）。
    pub url: String,
    /// 拉取间隔秒数（逻辑时钟；>= 1）。
    pub interval_secs: u64,
    /// HTTP `User-Agent` 请求头。
    pub user_agent: String,
    /// 附加请求头（有序）。
    pub headers: Vec<(String, String)>,
    /// https 是否跳过服务端证书校验（自签/私有场景；默认 false 走 Mozilla 根）。
    pub tls_skip_cert_verify: bool,
}

impl SubscriptionSourceConfig {
    /// 构造并校验：tag 非空、url 为 http/https、interval >= 1。
    ///
    /// # Errors
    ///
    /// 非法字段返回 `ConfigError`（`CONFIG_INVALID` 语义）。
    pub fn new(
        tag: impl Into<String>,
        url: impl Into<String>,
        interval_secs: u64,
    ) -> Result<Self, ConfigError> {
        let tag = tag.into();
        let url = url.into();
        if tag.is_empty() {
            return Err(ConfigError::new("subscription.tag", "must not be empty"));
        }
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(ConfigError::new(
                "subscription.url",
                format!("url must be http:// or https://, got '{url}'"),
            ));
        }
        if interval_secs < 1 {
            return Err(ConfigError::new(
                "subscription.interval_secs",
                "must be >= 1",
            ));
        }
        Ok(Self {
            tag,
            url,
            interval_secs,
            user_agent: "Nexus-Subscription/1".to_string(),
            headers: Vec::new(),
            tls_skip_cert_verify: false,
        })
    }

    /// 覆盖默认 User-Agent。
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// 追加一个附加请求头。
    #[must_use]
    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    /// 设置 https 跳过证书校验。
    #[must_use]
    pub fn with_tls_skip_cert_verify(mut self, skip: bool) -> Self {
        self.tls_skip_cert_verify = skip;
        self
    }
}

/// 一次订阅拉取尝试的结构化可观察事件（§11.17）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionUpdateEvent {
    /// 订阅源 tag（关联字段）。
    pub subscription_tag: String,
    /// 本次是第几次尝试（从 1 开始）。
    pub attempt: u64,
    /// 本次拉取+解析是否成功并热生效。
    pub ok: bool,
    /// 尝试前有效节点数。
    pub node_count_before: usize,
    /// 尝试后有效节点数（失败时应与 before 相同）。
    pub node_count_after: usize,
    /// 本次解析被显式拒绝的未知协议行数。
    pub rejected: u32,
    /// 本次拉取耗时（毫秒）。
    pub latency_ms: u64,
    /// 失败原因（`ok=false` 时）。
    pub error: Option<String>,
}

/// 订阅节点运行时状态机（纯内存、离线、确定性）。
///
/// 不变量：
/// - 本地手写 outbounds 在整个生命周期内恒定保留，永不被订阅清空；
/// - 订阅节点集独立于本地 outbounds；每次成功拉取**整体替换**订阅节点集（非累积）；
/// - 失败（拉取或解析失败）时订阅节点集保持上一次成功的值（无历史则为空）；
/// - 有效节点数 = `local_outbounds.len() + subscription_nodes.len()`。
pub struct SubscriptionRuntime {
    source_tag: String,
    local_outbounds: Vec<OutboundConfig>,
    subscription_nodes: Vec<OutboundConfig>,
    last_body: Option<String>,
    attempt: u64,
}

impl SubscriptionRuntime {
    /// 用本地手写 outbounds 构造（这些节点恒定保留）。
    #[must_use]
    pub fn new(source_tag: impl Into<String>, local_outbounds: Vec<OutboundConfig>) -> Self {
        Self {
            source_tag: source_tag.into(),
            local_outbounds,
            subscription_nodes: Vec::new(),
            last_body: None,
            attempt: 0,
        }
    }

    /// 当前有效节点数（本地 ++ 订阅）。
    #[must_use]
    pub fn effective_node_count(&self) -> usize {
        self.local_outbounds.len() + self.subscription_nodes.len()
    }

    /// 当前有效节点列表（本地手写 outbounds ++ 当前订阅节点集）。
    #[must_use]
    pub fn effective_nodes(&self) -> Vec<OutboundConfig> {
        self.local_outbounds
            .iter()
            .chain(self.subscription_nodes.iter())
            .cloned()
            .collect()
    }

    /// 上一次成功拉取的订阅原文（缓存兜底用；无则 `None`）。
    #[must_use]
    pub fn last_body(&self) -> Option<&str> {
        self.last_body.as_deref()
    }

    /// 已发生的尝试次数。
    #[must_use]
    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    /// 喂入一次拉取结果：
    ///
    /// - `Ok(text)`：解析订阅；成功则整体替换订阅节点集（同订阅内 tag 去重，后出现者覆盖），
    ///   记录 last_body；
    /// - `Err(e)` 或解析失败：保留上一次成功的订阅节点集，**不清空**。
    ///
    /// 返回结构化事件；是否推进热生效 revision 由调用方（组合根按 `ok` 决定）。
    pub fn apply_body(
        &mut self,
        body: Result<String, String>,
        latency_ms: u64,
    ) -> SubscriptionUpdateEvent {
        self.attempt += 1;
        let attempt = self.attempt;
        let before = self.effective_node_count();
        let after_ok = |parsed: SubscriptionParse| {
            // 同订阅内 tag 去重：后出现者覆盖先出现者。
            let mut deduped: Vec<OutboundConfig> = Vec::with_capacity(parsed.outbounds.len());
            for node in parsed.outbounds {
                match deduped.iter().position(|n| n.tag == node.tag) {
                    Some(pos) => deduped[pos] = node,
                    None => deduped.push(node),
                }
            }
            deduped
        };
        match body {
            Ok(text) => match parse_clash_subscription(&text) {
                Ok(parsed) => {
                    let rejected = parsed.rejected.len() as u32;
                    self.subscription_nodes = after_ok(parsed);
                    self.last_body = Some(text);
                    let after = self.effective_node_count();
                    SubscriptionUpdateEvent {
                        subscription_tag: self.source_tag.clone(),
                        attempt,
                        ok: true,
                        node_count_before: before,
                        node_count_after: after,
                        rejected,
                        latency_ms,
                        error: None,
                    }
                }
                Err(e) => {
                    // 解析失败：保留旧订阅节点集。
                    let after = self.effective_node_count();
                    SubscriptionUpdateEvent {
                        subscription_tag: self.source_tag.clone(),
                        attempt,
                        ok: false,
                        node_count_before: before,
                        node_count_after: after,
                        rejected: 0,
                        latency_ms,
                        error: Some(format!("parse: {e}")),
                    }
                }
            },
            Err(e) => {
                // 拉取失败：保留旧订阅节点集。
                let after = self.effective_node_count();
                SubscriptionUpdateEvent {
                    subscription_tag: self.source_tag.clone(),
                    attempt,
                    ok: false,
                    node_count_before: before,
                    node_count_after: after,
                    rejected: 0,
                    latency_ms,
                    error: Some(e),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 出站互操作标注（PRODUCT §11.21）
// ---------------------------------------------------------------------------

/// 结构化配置警告：不阻断解析，仅标注风险（PRODUCT §11.21）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// 稳定的机器可读警告码（如 `OUTBOUND_INTEROP_BROKEN`）。
    pub code: &'static str,
    /// 触发警告的字段路径（如 `outbounds[2].kind`）。
    pub field: String,
    /// 被标注出站的 tag。
    pub tag: String,
    /// 被标注出站的 kind 标签。
    pub kind: &'static str,
    /// `docs/protocols/interop/MATRIX.md` 中该协议的 verdict。
    pub interop_verdict: &'static str,
    /// 人类可读原因。
    pub reason: &'static str,
}

/// MATRIX verdict 为 `BROKEN` 的出站及其原因；变更须走 requirement-change（§11.21）。
fn interop_broken_reason(kind: OutboundKind) -> Option<&'static str> {
    match kind {
        OutboundKind::Trojan => Some(
            "trojan interop is BROKEN (MATRIX): on a wrong password or a server-side fallback \
             the fallback response is relayed as tunnel data (fail-open); treat as unverified",
        ),
        OutboundKind::Hysteria2 => Some(
            "hysteria2 interop is BROKEN (MATRIX): large uploads hang after auth and the \
             salamander handshake fails; treat as unverified",
        ),
        _ => None,
    }
}

/// 列出配置中互操作不可用出站的结构化警告，按 `outbounds` 声明顺序（纯函数、零 I/O）。
#[must_use]
pub fn outbound_warnings(cfg: &ProxyConfig) -> Vec<ConfigWarning> {
    cfg.outbounds
        .iter()
        .enumerate()
        .filter_map(|(i, o)| {
            interop_broken_reason(o.kind).map(|reason| ConfigWarning {
                code: "OUTBOUND_INTEROP_BROKEN",
                field: format!("outbounds[{i}].kind"),
                tag: o.tag.clone(),
                kind: o.kind.as_str(),
                interop_verdict: "BROKEN",
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config_to_typed_structs() {
        let yaml = "\
schema_version: 1
inbounds:
  - tag: socks5-in
    kind: socks5
    listen: 127.0.0.1:1080
rules:
  - tag: rule-example-suffix
    kind: domain_suffix
    match: example.com
    action:
      - kind: select_outbound
        tag: direct
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: fallback-outbound
groups:
  - tag: relay-group
    kind: selector
    candidates: [relay, direct]
outbounds:
  - tag: direct
    kind: direct
    locator: \"\"
  - tag: relay
    kind: relay
    locator: relay.example:443
  - tag: fallback-outbound
    kind: direct
    locator: \"\"
";
        let cfg = parse(yaml).expect("valid config");
        assert_eq!(cfg.schema_version, 1);
        assert_eq!(cfg.inbounds[0].tag, "socks5-in");
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].kind.as_str(), "domain_suffix");
        assert_eq!(cfg.rules[0].action.actions[0].tag, "direct");
        assert_eq!(cfg.rules[1].kind.as_str(), "match");
        assert_eq!(cfg.groups[0].candidates, vec!["relay", "direct"]);
        assert_eq!(cfg.outbounds.len(), 3);
    }

    #[test]
    fn deterministic_parse_same_text_same_config() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let a = parse(yaml).expect("ok");
        let b = parse(yaml).expect("ok");
        assert_eq!(a, b);
    }

    #[test]
    fn missing_match_fallback_is_config_invalid() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: domain\n    match: x.com\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).expect_err("must fail");
        assert!(err.reason.contains("MATCH"), "{err:?}");
    }

    #[test]
    fn dangling_outbound_tag_is_config_invalid() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ghost\noutbounds:\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).expect_err("must fail");
        assert!(err.reason.contains("ghost"), "{err:?}");
    }

    #[test]
    fn empty_group_candidates_is_config_invalid() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: g\noutbounds:\n  - tag: d\n    kind: direct\ngroups:\n  - tag: g\n    kind: selector\n    candidates: []\n";
        let err = parse(yaml).expect_err("must fail");
        assert!(err.reason.contains("empty"), "{err:?}");
    }

    #[test]
    fn wrong_schema_version_is_config_invalid() {
        let yaml = "schema_version: 2\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).expect_err("must fail");
        assert_eq!(err.field, "schema_version");
    }

    #[test]
    fn parses_optional_dns_section() {
        let yaml = "\
schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\ndns:\n  servers:\n    - tag: a\n      address: 1.1.1.1\n    - tag: b\n      address: 8.8.8.8\n  rules:\n    - domain: example.internal\n      server: a\n  default_server: b\n";
        let cfg = parse(yaml).expect("ok");
        let d = cfg.dns.expect("dns present");
        assert_eq!(d.servers.len(), 2);
        assert_eq!(d.rules[0].server, "a");
        assert_eq!(d.default_server, "b");
    }

    #[test]
    fn absent_dns_section_is_none() {
        let yaml = "schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let cfg = parse(yaml).expect("ok");
        assert!(cfg.dns.is_none());
    }

    #[test]
    fn dangling_dns_server_is_config_invalid() {
        let yaml = "\
schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\ndns:\n  servers:\n    - tag: a\n      address: 1.1.1.1\n  rules:\n    - domain: x\n      server: ghost\n  default_server: a\n";
        let err = parse(yaml).expect_err("must fail");
        assert!(err.reason.contains("ghost"), "{err:?}");
    }

    #[test]
    fn parses_trojan_node_config() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t-a
outbounds:
  - tag: t-a
    kind: trojan
    locator: ty-3.tr202613.com:443
    password: CHANGE_ME
    alpn: [h2, http/1.1]
    skip_cert_verify: true
    header_format: singbox
  - tag: t-b
    kind: trojan
    locator: os-3.tr202613.com:443
    password: CHANGE_ME
    alpn: [h2, http/1.1]
    skip_cert_verify: true
    header_format: singbox
";
        let cfg = parse(yaml).expect("ok");
        assert_eq!(cfg.outbounds.len(), 2);
        assert_eq!(cfg.outbounds[0].kind.as_str(), "trojan");
        assert_eq!(
            cfg.outbounds[0].alpn.as_ref().unwrap(),
            &vec!["h2", "http/1.1"]
        );
        assert_eq!(cfg.outbounds[0].skip_cert_verify, Some(true));
        assert_eq!(cfg.outbounds[0].header_format.as_deref(), Some("singbox"));
    }

    #[test]
    fn parses_obfs_plugin_config() {
        // P2：obfs/obfs_key 从 YAML 解析；缺省为 None（plain 直通）。
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: ss-a
outbounds:
  - tag: ss-a
    kind: shadowsocks
    locator: 127.0.0.1:8388
    method: chacha20-ietf-poly1305
    password: demo-password-123
    obfs: xor
    obfs_key: test-key-123
  - tag: ss-b
    kind: shadowsocks
    locator: 127.0.0.1:8389
    method: chacha20-ietf-poly1305
    password: demo-password-123
";
        let cfg = parse(yaml).expect("ok");
        assert_eq!(cfg.outbounds.len(), 2);
        assert_eq!(cfg.outbounds[0].obfs.as_deref(), Some("xor"));
        assert_eq!(cfg.outbounds[0].obfs_key.as_deref(), Some("test-key-123"));
        // 未配置 → None = plain（P6）。
        assert_eq!(cfg.outbounds[1].obfs, None);
        assert_eq!(cfg.outbounds[1].obfs_key, None);
    }

    #[test]
    fn trojan_missing_password_is_config_invalid() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t
outbounds:
  - tag: t
    kind: trojan
    locator: example:443
";
        let err = parse(yaml).expect_err("must fail");
        assert!(err.reason.contains("password"), "{err:?}");
    }

    #[test]
    fn trojan_bad_header_format_is_config_invalid() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t
outbounds:
  - tag: t
    kind: trojan
    locator: example:443
    password: pwd
    header_format: bogus
";
        let err = parse(yaml).expect_err("must fail");
        assert!(err.reason.contains("header_format"), "{err:?}");
    }

    /// 构造一份最小 proxy.yaml：单个出站 + 匹配规则（新增字段测试用）。
    fn yaml_with_outbound(kind: &str, extra: &str) -> String {
        format!(
            "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t
outbounds:
  - tag: t
    kind: {kind}
    locator: 127.0.0.1:443
    password: pwd
{extra}"
        )
    }

    #[test]
    fn fallback_guard_and_window_are_absent_by_default() {
        let cfg = parse(&yaml_with_outbound("trojan", "")).expect("ok");
        assert_eq!(cfg.outbounds[0].fallback_guard, None);
        assert_eq!(cfg.outbounds[0].ready_window_ms, None);
    }

    #[test]
    fn fallback_guard_accepts_strict_and_signature() {
        for v in ["strict", "signature"] {
            let cfg = parse(&yaml_with_outbound(
                "trojan",
                &format!("    fallback_guard: {v}\n"),
            ))
            .expect("legal value");
            assert_eq!(cfg.outbounds[0].fallback_guard.as_deref(), Some(v));
        }
    }

    #[test]
    fn fallback_guard_rejects_off_and_every_other_string() {
        // 不存在「完全关闭守卫」的官方开关（spec §8）：off/none/disabled/空串/其他
        // 一律 CONFIG_INVALID，字段路径与消息逐字对齐。
        for v in ["off", "none", "disabled", "bogus", "Strict", ""] {
            let yaml = yaml_with_outbound("trojan", &format!("    fallback_guard: {v}\n"));
            let err = parse(&yaml).expect_err("illegal value must fail");
            assert_eq!(err.field, "outbounds[t].fallback_guard", "{v}");
            assert_eq!(
                err.reason,
                format!("fallback_guard must be 'strict' or 'signature', got '{v}'")
            );
            assert_eq!(
                err.to_string(),
                format!(
                    "CONFIG_INVALID [outbounds[t].fallback_guard]: \
                     fallback_guard must be 'strict' or 'signature', got '{v}'"
                )
            );
        }
    }

    #[test]
    fn ready_window_accepts_zero_and_upper_bound() {
        for (raw, expect) in [("0", 0u64), ("5000", 5000), ("1", 1)] {
            let cfg = parse(&yaml_with_outbound(
                "trojan",
                &format!("    ready_window_ms: {raw}\n"),
            ))
            .expect("legal range");
            assert_eq!(cfg.outbounds[0].ready_window_ms, Some(expect));
        }
    }

    #[test]
    fn ready_window_rejects_out_of_range_and_non_integer() {
        for raw in ["5001", "999999", "-5", "abc", "12ms"] {
            let yaml = yaml_with_outbound("trojan", &format!("    ready_window_ms: {raw}\n"));
            let err = parse(&yaml).expect_err("illegal value must fail");
            assert_eq!(err.field, "outbounds[t].ready_window_ms", "{raw}");
            assert_eq!(
                err.reason,
                format!("ready_window_ms must be in 0..=5000, got {raw}")
            );
        }
    }

    #[test]
    fn non_trojan_outbound_ignores_legal_values() {
        // spec §8 的 kind 口径：非 trojan 出站上的**合法值**忽略（不生效、不报错）。
        // 值域校验在 kind 分派之前执行（对所有 kind），是否生效由 arm 决定。
        let cfg = parse(&yaml_with_outbound(
            "direct",
            "    fallback_guard: signature\n    ready_window_ms: 120\n",
        ))
        .expect("legal values on non-trojan outbound must parse");
        assert_eq!(
            cfg.outbounds[0].fallback_guard.as_deref(),
            Some("signature")
        );
        assert_eq!(cfg.outbounds[0].ready_window_ms, Some(120));
        assert_eq!(cfg.outbounds[0].kind.as_str(), "direct");

        let cfg = parse(&yaml_with_outbound(
            "vless",
            "    uuid: 123e4567-e89b-12d3-a456-426614174000\n    tls: true\n    \
             fallback_guard: strict\n    ready_window_ms: 0\n",
        ))
        .expect("legal values on vless outbound must parse");
        assert_eq!(cfg.outbounds[0].fallback_guard.as_deref(), Some("strict"));
        assert_eq!(cfg.outbounds[0].ready_window_ms, Some(0));
        assert_eq!(cfg.outbounds[0].kind.as_str(), "vless");
    }

    #[test]
    fn non_trojan_outbound_rejects_illegal_values() {
        // 本 run 新增裁决：非法值硬失败（比现状 header_format 的「非 trojan 静默忽略」更严）。
        let yaml = yaml_with_outbound("direct", "    fallback_guard: off\n");
        let err = parse(&yaml).expect_err("illegal value must fail for any kind");
        assert_eq!(err.field, "outbounds[t].fallback_guard");

        let yaml = yaml_with_outbound("direct", "    ready_window_ms: 5001\n");
        let err = parse(&yaml).expect_err("illegal range must fail for any kind");
        assert_eq!(err.field, "outbounds[t].ready_window_ms");
    }

    #[test]
    fn anytls_config_parses_all_fields() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: a
outbounds:
  - tag: a
    kind: anytls
    locator: example.com:443
    password: secret123
    sni: example.com
    skip_cert_verify: true
";
        let cfg = parse(yaml).expect("ok");
        let o = &cfg.outbounds[0];
        assert_eq!(o.kind, OutboundKind::Anytls);
        assert_eq!(o.kind.as_str(), "anytls");
        assert_eq!(o.locator.as_deref(), Some("example.com:443"));
        assert_eq!(o.password.as_deref(), Some("secret123"));
        assert_eq!(o.sni.as_deref(), Some("example.com"));
        assert_eq!(o.skip_cert_verify, Some(true));
    }

    #[test]
    fn anytls_rejects_missing_password() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: a
outbounds:
  - tag: a
    kind: anytls
    locator: example.com:443
";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn vless_config_parses_all_fields() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: v
outbounds:
  - tag: v
    kind: vless
    locator: example.com:443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    flow: xtls-rprx-vision
    tls: true
    servername: example.com
";
        let cfg = parse(yaml).expect("ok");
        let o = &cfg.outbounds[0];
        assert_eq!(o.kind, OutboundKind::Vless);
        assert_eq!(o.kind.as_str(), "vless");
        assert_eq!(
            o.uuid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(o.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(o.tls, Some(true));
        assert_eq!(o.servername.as_deref(), Some("example.com"));
    }

    #[test]
    fn vless_vision_requires_tls() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: v
outbounds:
  - tag: v
    kind: vless
    locator: example.com:443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    flow: xtls-rprx-vision
";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn vless_rejects_bad_flow() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: v
outbounds:
  - tag: v
    kind: vless
    locator: example.com:443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    flow: bogus-flow
";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn hysteria2_config_parses_all_fields() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: h
outbounds:
  - tag: h
    kind: hysteria2
    locator: example.com:443
    password: secret123
    ports: 10000-20000,30000
    up: 100 Mbps
    down: 200 Mbps
    sni: example.com
    skip_cert_verify: true
";
        let cfg = parse(yaml).expect("ok");
        let o = &cfg.outbounds[0];
        assert_eq!(o.kind, OutboundKind::Hysteria2);
        assert_eq!(o.kind.as_str(), "hysteria2");
        assert_eq!(o.password.as_deref(), Some("secret123"));
        assert_eq!(o.ports.as_deref(), Some("10000-20000,30000"));
        assert_eq!(o.up.as_deref(), Some("100 Mbps"));
        assert_eq!(o.down.as_deref(), Some("200 Mbps"));
        assert_eq!(o.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn hysteria2_salamander_requires_obfs_password() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: h
outbounds:
  - tag: h
    kind: hysteria2
    locator: example.com:443
    password: secret123
    obfs: salamander
";
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn unknown_kind_error_lists_new_protocols() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: x
outbounds:
  - tag: x
    kind: wireguard
    locator: example.com:443
";
        let err = parse(yaml).unwrap_err().to_string();
        assert!(err.contains("anytls"), "err: {err}");
        assert!(err.contains("vless"), "err: {err}");
        assert!(err.contains("hysteria2"), "err: {err}");
    }

    #[test]
    fn trojan_default_header_format_is_standard() {
        let yaml = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: t
outbounds:
  - tag: t
    kind: trojan
    locator: example:443
    password: pwd
";
        let cfg = parse(yaml).expect("ok");
        assert_eq!(cfg.outbounds[0].header_format, None);
    }
}

#[cfg(test)]
mod subscription_online_tests {
    use super::*;

    /// 极简标准字母表 base64 编码（仅测试用）。
    fn b64(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.len();
            let b0 = chunk[0] as u32;
            let b1 = if n > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if n > 2 { chunk[2] as u32 } else { 0 };
            let bits = (b0 << 16) | (b1 << 8) | b2;
            s.push(T[((bits >> 18) & 63) as usize] as char);
            s.push(T[((bits >> 12) & 63) as usize] as char);
            s.push(if n > 1 {
                T[((bits >> 6) & 63) as usize] as char
            } else {
                '='
            });
            s.push(if n > 2 {
                T[(bits & 63) as usize] as char
            } else {
                '='
            });
        }
        s
    }

    fn local_direct() -> Vec<OutboundConfig> {
        vec![OutboundConfig {
            tag: "direct".to_string(),
            kind: OutboundKind::Direct,
            locator: Some("".to_string()),
            method: None,
            password: None,
            alpn: None,
            skip_cert_verify: None,
            header_format: None,
            obfs: None,
            obfs_key: None,
            uuid: None,
            flow: None,
            tls: None,
            servername: None,
            sni: None,
            ports: None,
            up: None,
            down: None,
            obfs_password: None,
            fallback_guard: None,
            ready_window_ms: None,
        }]
    }

    #[test]
    fn source_config_rejects_bad_inputs() {
        assert!(SubscriptionSourceConfig::new("", "http://x", 60).is_err());
        assert!(SubscriptionSourceConfig::new("s", "ftp://x", 60).is_err());
        assert!(SubscriptionSourceConfig::new("s", "http://x", 0).is_err());
        let ok = SubscriptionSourceConfig::new("sub", "https://127.0.0.1:1/x", 60)
            .expect("valid")
            .with_user_agent("ua")
            .with_header("K", "V")
            .with_tls_skip_cert_verify(true);
        assert_eq!(ok.user_agent, "ua");
        assert!(ok.tls_skip_cert_verify);
    }

    #[test]
    fn success_pull_adds_sub_nodes_and_keeps_local() {
        let body = b64(
            b"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h1:8388#NodeA\nvmess://uuid@h2:10086#NodeB",
        );
        let mut rt = SubscriptionRuntime::new("sub", local_direct());
        assert_eq!(rt.effective_node_count(), 1);
        let ev = rt.apply_body(Ok(body), 5);
        assert!(ev.ok);
        assert_eq!(ev.node_count_before, 1);
        assert_eq!(ev.node_count_after, 3); // local direct + 2 sub
        assert_eq!(ev.rejected, 0);
        assert_eq!(rt.attempt(), 1);
    }

    #[test]
    fn failed_pull_keeps_previous_nodes_and_does_not_clear() {
        let body = b64(b"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h1:8388#NodeA");
        let mut rt = SubscriptionRuntime::new("sub", local_direct());
        rt.apply_body(Ok(body), 5);
        assert_eq!(rt.effective_node_count(), 2);
        // 拉取失败：节点数保持不变（回退），不清空。
        let ev = rt.apply_body(Err("connect refused".to_string()), 1);
        assert!(!ev.ok);
        assert_eq!(ev.node_count_before, 2);
        assert_eq!(ev.node_count_after, 2);
        assert!(ev.error.is_some());
        assert_eq!(rt.effective_node_count(), 2);
    }

    #[test]
    fn subsequent_success_replaces_subset_wholesale() {
        let b1 = b64(b"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h1:8388#NodeA");
        let b2 = b64(b"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h1:8388#NodeA\n\
              ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h2:8389#NodeB\n\
              ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h3:8390#NodeC");
        let mut rt = SubscriptionRuntime::new("sub", local_direct());
        rt.apply_body(Ok(b1), 5);
        assert_eq!(rt.effective_node_count(), 2); // local + 1
        rt.apply_body(Ok(b2), 6);
        // 整体替换：订阅集从 1 -> 3，非累积（不是 1+1+3=5）。
        assert_eq!(rt.effective_node_count(), 4); // local + 3
    }

    #[test]
    fn unknown_scheme_lines_are_rejected_not_fatal() {
        let body =
            b64(b"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h1:8388#NodeA\ntrojan://p@tr:443#Bad");
        let mut rt = SubscriptionRuntime::new("sub", local_direct());
        let ev = rt.apply_body(Ok(body), 5);
        assert!(ev.ok);
        assert_eq!(ev.rejected, 1);
        assert_eq!(ev.node_count_after, 2); // local + 1 valid
    }

    #[test]
    fn parse_failure_keeps_previous_subset() {
        let good = b64(b"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpw@h1:8388#NodeA");
        let mut rt = SubscriptionRuntime::new("sub", local_direct());
        rt.apply_body(Ok(good), 5);
        assert_eq!(rt.effective_node_count(), 2);
        // 非法 base64：解析失败，保留旧集。
        let ev = rt.apply_body(Ok("!!!not-base64!!!".to_string()), 5);
        assert!(!ev.ok);
        assert_eq!(ev.node_count_after, 2);
        assert_eq!(rt.effective_node_count(), 2);
    }

    // ---- 2026-10-01 新增：新规则类型解析 ----
    #[test]
    fn rule_kind_parse_new_kinds() {
        assert_eq!(RuleKind::parse("src_port").unwrap(), RuleKind::SrcPort);
        assert_eq!(RuleKind::parse("dst_port").unwrap(), RuleKind::DstPort);
        assert_eq!(
            RuleKind::parse("process_name").unwrap(),
            RuleKind::ProcessName
        );
    }

    #[test]
    fn rule_kind_as_str_new_kinds() {
        assert_eq!(RuleKind::SrcPort.as_str(), "src_port");
        assert_eq!(RuleKind::DstPort.as_str(), "dst_port");
        assert_eq!(RuleKind::ProcessName.as_str(), "process_name");
    }

    #[test]
    fn rule_kind_parse_roundtrip() {
        for kind in [
            RuleKind::DomainSuffix,
            RuleKind::Domain,
            RuleKind::IpCidr,
            RuleKind::GeoIp,
            RuleKind::GeoSite,
            RuleKind::RuleSet,
            RuleKind::SrcPort,
            RuleKind::DstPort,
            RuleKind::ProcessName,
            RuleKind::Match,
        ] {
            assert_eq!(RuleKind::parse(kind.as_str()).unwrap(), kind);
        }
    }
}

#[cfg(test)]
mod warn5_obfs_validation_tests {
    use super::*;

    fn hy2_yaml(obfs: &str) -> String {
        format!(
            "schema_version: 1\nrules:\n  - tag: m\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: h\noutbounds:\n  - tag: h\n    kind: hysteria2\n    locator: 127.0.0.1:443\n    password: secret123\n    obfs: {obfs}\n    obfs_password: s3cr3t\n"
        )
    }

    // WARN5: obfs 拼写错误直接报错，不绕过 salamander 密码检查。
    #[test]
    fn hy2_obfs_typo_rejected() {
        let err = parse(&hy2_yaml("salamandar")).unwrap_err();
        assert!(err.reason.contains("unknown obfs"), "got: {}", err.reason);
    }

    #[test]
    fn hy2_obfs_salamander_ok() {
        assert!(parse(&hy2_yaml("salamander")).is_ok());
    }

    // NEW_COMMENTED_1: none 与 Obfs::parse 对齐，为无混淆的有效别名。
    #[test]
    fn hy2_obfs_none_ok() {
        assert!(parse(&hy2_yaml("none")).is_ok());
        // 空串同样表示无混淆（Obfs::parse: "" | "none" => None）。
        assert!(parse(&hy2_yaml("")).is_ok());
    }
}

#[cfg(test)]
mod inbound_kind_tests {
    use super::*;

    #[test]
    fn inbound_kind_as_str_roundtrip() {
        for (raw, kind) in [
            ("socks5", InboundKind::Socks5),
            ("mixed", InboundKind::Mixed),
            ("tun", InboundKind::Tun),
            ("tproxy", InboundKind::Tproxy),
        ] {
            assert_eq!(InboundKind::parse(raw).unwrap(), kind);
            assert_eq!(kind.as_str(), raw);
        }
    }

    #[test]
    fn unknown_inbound_kind_is_structured() {
        let yaml = "schema_version: 1\ninbounds:\n  - tag: in\n    kind: wireguard\n    listen: 127.0.0.1:1080\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).expect_err("unknown kind must fail");
        assert_eq!(err.field, "inbounds[0].kind");
        assert!(err.reason.contains("wireguard"), "got: {}", err.reason);
    }

    #[test]
    fn explicit_inbound_kinds_parse() {
        let yaml = "schema_version: 1\ninbounds:\n  - tag: a\n    kind: socks5\n    listen: 127.0.0.1:1080\n  - tag: b\n    kind: mixed\n    listen: 127.0.0.1:1081\n  - tag: c\n    kind: tun\n  - tag: e\n    kind: tproxy\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let cfg = parse(yaml).expect("valid config");
        assert_eq!(cfg.inbounds[0].kind, InboundKind::Socks5);
        assert_eq!(cfg.inbounds[1].kind, InboundKind::Mixed);
        assert_eq!(cfg.inbounds[2].kind, InboundKind::Tun);
        assert_eq!(cfg.inbounds[3].kind, InboundKind::Tproxy);
        assert_eq!(cfg.inbounds[2].listen, "");
        assert_eq!(cfg.inbounds[3].listen, TPROXY_DEFAULT_LISTEN);
    }
}

#[cfg(test)]
mod tun_inbound_tests {
    use super::*;

    fn yaml_with_tun(extra: &str) -> String {
        format!(
            "schema_version: 1\ninbounds:\n  - tag: tun-in\n    kind: tun\n{extra}rules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n"
        )
    }

    #[test]
    fn tun_inbound_defaults_match_spec() {
        let cfg = parse(&yaml_with_tun("")).expect("valid tun inbound");
        let tun = cfg.inbounds[0].tun.as_ref().expect("tun sub config");
        assert_eq!(tun.name, "nexus");
        assert_eq!(tun.mtu, 1500);
        assert_eq!(tun.address, "10.99.0.1/24");
        assert!(!tun.default_route);
        assert!(tun.exclude_server_routes);
        assert!(!tun.fake_ip);
        assert!(!tun.ipv6);
        assert_eq!(tun.sessions, FlowSessionsMode::Auto);
    }

    #[test]
    fn tun_inbound_overrides_parse() {
        let extra = "    name: nexus-test\n    mtu: 9000\n    address: 10.42.0.1/16\n    default_route: true\n    exclude_server_routes: false\n    sessions: enabled\n";
        let cfg = parse(&yaml_with_tun(extra)).expect("valid tun inbound");
        let tun = cfg.inbounds[0].tun.as_ref().unwrap();
        assert_eq!(tun.name, "nexus-test");
        assert_eq!(tun.mtu, 9000);
        assert_eq!(tun.address, "10.42.0.1/16");
        assert!(tun.default_route);
        assert!(!tun.exclude_server_routes);
        assert_eq!(tun.sessions, FlowSessionsMode::Enabled);
    }

    #[test]
    fn tun_inbound_rejects_bad_mtu_range() {
        for mtu in ["1279", "9001"] {
            let err = parse(&yaml_with_tun(&format!("    mtu: {mtu}\n"))).unwrap_err();
            assert_eq!(err.field, "inbounds[0].mtu", "{err:?}");
            assert!(err.reason.contains("1280"), "{err:?}");
        }
    }

    #[test]
    fn tun_inbound_rejects_bad_address() {
        let err = parse(&yaml_with_tun("    address: 10.99.0.1/33\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].address");
        let err = parse(&yaml_with_tun("    address: not-a-cidr\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].address");
    }

    #[test]
    fn tun_inbound_rejects_bad_name() {
        let err = parse(&yaml_with_tun("    name: bad name\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].name");
        let err = parse(&yaml_with_tun(&format!("    name: {}\n", "a".repeat(16)))).unwrap_err();
        assert_eq!(err.field, "inbounds[0].name");
    }

    #[test]
    fn tun_inbound_rejects_fake_ip_and_ipv6() {
        let err = parse(&yaml_with_tun("    fake_ip: true\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].fake_ip");
        let err = parse(&yaml_with_tun("    ipv6: true\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].ipv6");
    }

    #[test]
    fn tun_inbound_rejects_unknown_sessions_mode() {
        let err = parse(&yaml_with_tun("    sessions: sometimes\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].sessions");
    }

    #[test]
    fn only_one_tun_inbound_is_supported() {
        let yaml = "schema_version: 1\ninbounds:\n  - tag: a\n    kind: tun\n  - tag: b\n    kind: tun\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).unwrap_err();
        assert_eq!(err.field, "inbounds");
        assert!(err.reason.contains("only one tun"), "{err:?}");
    }
}

#[cfg(test)]
mod tproxy_inbound_tests {
    use super::*;

    fn yaml_with_tproxy(extra: &str) -> String {
        format!(
            "schema_version: 1\ninbounds:\n  - tag: tp\n    kind: tproxy\n{extra}rules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n"
        )
    }

    #[test]
    fn tproxy_inbound_defaults_match_spec() {
        let cfg = parse(&yaml_with_tproxy("")).expect("valid tproxy inbound");
        let tp = cfg.inbounds[0].tproxy.as_ref().expect("tproxy sub config");
        assert_eq!(cfg.inbounds[0].listen, "0.0.0.0:7895");
        assert_eq!(tp.tcp_port, 7895);
        assert_eq!(tp.udp_port, 7895);
        assert_eq!(tp.backend, CaptureBackendConfig::Iptables);
        assert_eq!(tp.chain, "NEXUS_TPROXY");
        assert_eq!(tp.mark, 0x1f3);
        assert_eq!(tp.route_table, 100);
        assert_eq!(tp.intercept_dst_cidrs, vec!["0.0.0.0/0".to_string()]);
        assert!(tp.exclude_dst_cidrs.is_empty());
        assert_eq!(tp.on_capture_failure, CaptureFailureMode::Block);
        assert_eq!(tp.on_path_failure, PathFailureMode::Block);
        assert_eq!(tp.max_tcp_conns, 4096);
        assert_eq!(tp.udp_table_capacity, 8192);
        assert_eq!(tp.udp_idle_secs, 60);
        assert!(!tp.ipv6);
    }

    #[test]
    fn tproxy_ports_default_to_listen_port() {
        let cfg = parse(&yaml_with_tproxy("    listen: 127.0.0.1:7896\n")).unwrap();
        let tp = cfg.inbounds[0].tproxy.as_ref().unwrap();
        assert_eq!(tp.tcp_port, 7896);
        assert_eq!(tp.udp_port, 7896);
    }

    #[test]
    fn tproxy_inbound_overrides_parse() {
        let extra = "    tcp_port: 9001\n    udp_port: 9002\n    backend: nftables\n    chain: MYCHAIN\n    mark: 0x2a\n    route_table: 200\n    intercept_dst_cidrs: [10.0.0.0/8]\n    exclude_dst_cidrs: [10.1.0.0/16, 192.168.0.0/16]\n    on_capture_failure: bypass\n    on_path_failure: fallback\n    max_tcp_conns: 10\n    udp_table_capacity: 20\n    udp_idle_secs: 30\n";
        let cfg = parse(&yaml_with_tproxy(extra)).unwrap();
        let tp = cfg.inbounds[0].tproxy.as_ref().unwrap();
        assert_eq!(tp.tcp_port, 9001);
        assert_eq!(tp.udp_port, 9002);
        assert_eq!(tp.backend, CaptureBackendConfig::Nftables);
        assert_eq!(tp.chain, "MYCHAIN");
        assert_eq!(tp.mark, 0x2a);
        assert_eq!(tp.route_table, 200);
        assert_eq!(tp.intercept_dst_cidrs, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(tp.exclude_dst_cidrs.len(), 2);
        assert_eq!(tp.on_capture_failure, CaptureFailureMode::Bypass);
        assert_eq!(tp.on_path_failure, PathFailureMode::Fallback);
        assert_eq!(tp.max_tcp_conns, 10);
        assert_eq!(tp.udp_table_capacity, 20);
        assert_eq!(tp.udp_idle_secs, 30);
    }

    #[test]
    fn tproxy_ipv6_true_is_exact_field_error() {
        let err = parse(&yaml_with_tproxy("    ipv6: true\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].ipv6");
        assert!(err.reason.contains("IPv6"), "{err:?}");
    }

    #[test]
    fn tproxy_rejects_zero_ports_and_limits() {
        for (field, value) in [
            ("tcp_port", "0"),
            ("udp_port", "0"),
            ("mark", "0"),
            ("route_table", "0"),
            ("max_tcp_conns", "0"),
            ("udp_table_capacity", "0"),
            ("udp_idle_secs", "0"),
        ] {
            let err = parse(&yaml_with_tproxy(&format!("    {field}: {value}\n"))).unwrap_err();
            assert_eq!(err.field, format!("inbounds[0].{field}"), "{field}");
        }
    }

    #[test]
    fn tproxy_rejects_bad_chain_and_cidr_and_backend() {
        let err = parse(&yaml_with_tproxy("    chain: NEXUS TPROXY\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].chain");
        let err = parse(&yaml_with_tproxy(
            "    intercept_dst_cidrs: [999.0.0.0/8]\n",
        ))
        .unwrap_err();
        assert_eq!(err.field, "inbounds[0].intercept_dst_cidrs");
        let err = parse(&yaml_with_tproxy("    backend: pf\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].backend");
    }

    #[test]
    fn tproxy_rejects_too_many_excludes() {
        let items = (0..257)
            .map(|i| format!("10.{}.0.0/16", i % 250))
            .collect::<Vec<_>>()
            .join(", ");
        let err = parse(&yaml_with_tproxy(&format!(
            "    exclude_dst_cidrs: [{items}]\n"
        )))
        .unwrap_err();
        assert_eq!(err.field, "inbounds[0].exclude_dst_cidrs");
        assert!(err.reason.contains("256"), "{err:?}");
    }

    #[test]
    fn tproxy_rejects_unknown_failure_modes() {
        let err = parse(&yaml_with_tproxy("    on_capture_failure: drop\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].on_capture_failure");
        let err = parse(&yaml_with_tproxy("    on_path_failure: direct\n")).unwrap_err();
        assert_eq!(err.field, "inbounds[0].on_path_failure");
    }

    #[test]
    fn only_one_tproxy_inbound_is_supported() {
        let yaml = "schema_version: 1\ninbounds:\n  - tag: a\n    kind: tproxy\n  - tag: b\n    kind: tproxy\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).unwrap_err();
        assert_eq!(err.field, "inbounds");
        assert!(err.reason.contains("only one tproxy"), "{err:?}");
    }
}
#[cfg(test)]
mod tag_validation_tests {
    use super::*;

    fn yaml_with(outbounds: &str, groups: &str) -> String {
        format!(
            "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n{outbounds}{groups}"
        )
    }

    fn direct_outbound(tag: &str) -> String {
        format!("  - tag: \"{tag}\"\n    kind: direct\n")
    }

    fn proxy_outbound(tag: &str) -> String {
        format!("  - tag: \"{tag}\"\n    kind: socks5\n    locator: 127.0.0.1:1080\n")
    }

    #[test]
    fn duplicate_outbound_tags_are_rejected() {
        let yaml = yaml_with(
            &format!("{}{}", proxy_outbound("p1"), proxy_outbound("p1")),
            "",
        );
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[1].tag");
        assert!(err.reason.contains("duplicate tag 'p1'"), "{err:?}");
    }

    #[test]
    fn outbound_and_group_tags_must_be_unique() {
        let yaml = yaml_with(
            &proxy_outbound("p1"),
            "groups:\n  - tag: p1\n    kind: selector\n    candidates: [p1]\n",
        );
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "groups[0].tag");
        assert!(err.reason.contains("duplicate tag 'p1'"), "{err:?}");
    }

    #[test]
    fn reserved_direct_tag_only_allowed_for_direct_outbound() {
        let yaml = yaml_with(&proxy_outbound("DIRECT"), "");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");
        assert!(err.reason.contains("reserved tag"), "{err:?}");

        let yaml = yaml_with(
            &proxy_outbound("p1"),
            "groups:\n  - tag: Direct\n    kind: selector\n    candidates: [p1]\n",
        );
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "groups[0].tag");
        assert!(err.reason.contains("reserved tag"), "{err:?}");

        let yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n";
        assert!(parse(yaml).is_ok());
    }

    #[test]
    fn invalid_tag_text_is_rejected() {
        let yaml = yaml_with(&proxy_outbound(""), "");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");

        let yaml = yaml_with(&direct_outbound(" lead"), "");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");
        assert!(err.reason.contains("leading/trailing"), "{err:?}");

        let yaml = yaml_with(&direct_outbound("a b"), "");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");
        assert!(err.reason.contains("whitespace"), "{err:?}");

        let long = "x".repeat(65);
        let yaml = yaml_with(&direct_outbound(&long), "");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");
        assert!(err.reason.contains("64"), "{err:?}");
    }
}

#[cfg(test)]
mod config_error_matrix_tests {
    use super::*;

    fn base(extra_inbounds: &str) -> String {
        format!(
            "schema_version: 1\ninbounds:\n{extra_inbounds}rules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n"
        )
    }

    #[test]
    fn config_error_matrix_no_outbounds() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\n";
        let err = parse(yaml).unwrap_err();
        assert_eq!(err.field, "outbounds");
    }

    #[test]
    fn config_error_matrix_all_direct_is_legal() {
        let cfg = parse(&base("")).expect("all-direct outbounds are legal");
        assert_eq!(cfg.outbounds.len(), 1);
        assert_eq!(cfg.outbounds[0].kind, OutboundKind::Direct);
    }

    #[test]
    fn config_error_matrix_unknown_inbound_kind() {
        let yaml = base("  - tag: in\n    kind: wireguard\n");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "inbounds[0].kind");
    }

    #[test]
    fn config_error_matrix_two_tun() {
        let yaml = base("  - tag: a\n    kind: tun\n  - tag: b\n    kind: tun\n");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "inbounds");
        assert!(err.reason.contains("only one tun"), "{err:?}");
    }

    #[test]
    fn config_error_matrix_two_tproxy() {
        let yaml = base("  - tag: a\n    kind: tproxy\n  - tag: b\n    kind: tproxy\n");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "inbounds");
        assert!(err.reason.contains("only one tproxy"), "{err:?}");
    }

    #[test]
    fn config_error_matrix_ipv6_true_tun() {
        let yaml = base("  - tag: a\n    kind: tun\n    ipv6: true\n");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "inbounds[0].ipv6");
    }

    #[test]
    fn config_error_matrix_ipv6_true_tproxy() {
        let yaml = base("  - tag: a\n    kind: tproxy\n    ipv6: true\n");
        let err = parse(&yaml).unwrap_err();
        assert_eq!(err.field, "inbounds[0].ipv6");
    }

    #[test]
    fn config_error_matrix_duplicate_tag() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n  - tag: d\n    kind: direct\n";
        let err = parse(yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[1].tag");
        assert!(err.reason.contains("duplicate"), "{err:?}");
    }

    #[test]
    fn config_error_matrix_reserved_tag() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: DIRECT\n    kind: socks5\n    locator: 127.0.0.1:1080\n";
        let err = parse(yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");
        assert!(err.reason.contains("reserved"), "{err:?}");
    }

    #[test]
    fn config_error_matrix_invalid_tag_text() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: \"a b\"\n    kind: direct\n";
        let err = parse(yaml).unwrap_err();
        assert_eq!(err.field, "outbounds[0].tag");
        assert!(err.reason.contains("whitespace"), "{err:?}");
    }
}

#[cfg(test)]
mod outbound_interop_warning_tests {
    use super::*;

    const MIXED: &str = "\
schema_version: 1
rules:
  - tag: m
    kind: match
    action:
      - kind: select_outbound
        tag: d
outbounds:
  - tag: d
    kind: direct
  - tag: t
    kind: trojan
    locator: 127.0.0.1:443
    password: p
  - tag: v
    kind: vless
    locator: 127.0.0.1:443
    uuid: 00000000-0000-0000-0000-000000000000
  - tag: h
    kind: hysteria2
    locator: 127.0.0.1:443
    password: p
  - tag: s
    kind: shadowsocks
    locator: 127.0.0.1:8388
    method: chacha20-ietf-poly1305
    password: p
";

    /// MIXED with its outbounds replaced by one synthetic outbound per `kinds` entry.
    fn config_with(kinds: &[OutboundKind]) -> ProxyConfig {
        let mut cfg = parse(MIXED).unwrap();
        let template = cfg.outbounds[0].clone();
        cfg.outbounds = kinds
            .iter()
            .enumerate()
            .map(|(i, &kind)| OutboundConfig {
                tag: format!("o{i}"),
                kind,
                ..template.clone()
            })
            .collect();
        cfg
    }

    #[test]
    fn broken_outbounds_warned_in_declaration_order() {
        let cfg = parse(MIXED).expect("labeling never blocks parsing");
        let w = outbound_warnings(&cfg);
        let got: Vec<_> = w
            .iter()
            .map(|w| (w.tag.as_str(), w.kind, w.field.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("t", "trojan", "outbounds[1].kind"),
                ("h", "hysteria2", "outbounds[3].kind")
            ]
        );
        assert!(
            w.iter()
                .all(|w| w.code == "OUTBOUND_INTEROP_BROKEN" && w.interop_verdict == "BROKEN")
        );
    }

    // Exhaustive on purpose: a new OutboundKind fails to compile here until its
    // §11.21 labeling is decided.
    #[test]
    fn only_trojan_and_hysteria2_are_labeled() {
        let all = [
            OutboundKind::Direct,
            OutboundKind::Relay,
            OutboundKind::Shadowsocks,
            OutboundKind::Vmess,
            OutboundKind::Trojan,
            OutboundKind::Socks5,
            OutboundKind::Anytls,
            OutboundKind::Vless,
            OutboundKind::Hysteria2,
        ];
        for kind in all {
            let expected = match kind {
                OutboundKind::Trojan | OutboundKind::Hysteria2 => 1,
                OutboundKind::Direct
                | OutboundKind::Relay
                | OutboundKind::Shadowsocks
                | OutboundKind::Vmess
                | OutboundKind::Socks5
                | OutboundKind::Anytls
                | OutboundKind::Vless => 0,
            };
            assert_eq!(
                outbound_warnings(&config_with(&[kind])).len(),
                expected,
                "{}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn one_warning_per_labeled_outbound_not_per_kind() {
        let w = outbound_warnings(&config_with(&[
            OutboundKind::Trojan,
            OutboundKind::Direct,
            OutboundKind::Trojan,
        ]));
        let fields: Vec<_> = w
            .iter()
            .map(|w| (w.tag.as_str(), w.field.as_str()))
            .collect();
        assert_eq!(
            fields,
            [("o0", "outbounds[0].kind"), ("o2", "outbounds[2].kind")]
        );
    }

    #[test]
    fn no_outbounds_no_warnings() {
        assert!(outbound_warnings(&config_with(&[])).is_empty());
    }

    #[test]
    fn reasons_name_the_failure() {
        let w = outbound_warnings(&config_with(&[
            OutboundKind::Trojan,
            OutboundKind::Hysteria2,
        ]));
        let trojan = w[0].reason.to_lowercase();
        assert!(
            trojan.contains("fallback") && trojan.contains("fail-open"),
            "trojan reason must name the fallback fail-open: {}",
            w[0].reason
        );
        assert!(!w[1].reason.trim().is_empty(), "hysteria2 reason empty");
    }
}
