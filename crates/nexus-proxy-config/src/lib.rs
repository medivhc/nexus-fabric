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

/// 入站监听配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConfig {
    /// 入站标识。
    pub tag: String,
    /// 入站协议（P0 仅 `"socks5"`）。
    pub kind: String,
    /// 监听地址（host:port）。
    pub listen: String,
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
        }
    }

    fn parse(s: &str) -> Result<Self, ConfigError> {
        match s {
            "direct" => Ok(Self::Direct),
            "relay" => Ok(Self::Relay),
            "shadowsocks" => Ok(Self::Shadowsocks),
            "vmess" => Ok(Self::Vmess),
            "trojan" => Ok(Self::Trojan),
            other => Err(ConfigError::new(
                "kind",
                format!(
                    "unknown outbound kind '{other}' (supports direct/relay/shadowsocks/vmess/trojan)"
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
            let tag = req_str(item, "tag", &field)?.to_string();
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
            let tag = req_str(item, "tag", &field)?.to_string();
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

    // ---- inbounds ----
    let mut inbounds = Vec::new();
    if let Some(seq) = root.get("inbounds").and_then(Node::as_seq) {
        for (i, item) in seq.iter().enumerate() {
            let field = format!("inbounds[{i}]");
            let tag = req_str(item, "tag", &field)?.to_string();
            let kind = req_str(item, "kind", &field)?.to_string();
            if kind != "socks5" && kind != "mixed" {
                return Err(ConfigError::new(
                    format!("{field}.kind"),
                    format!("supports 'socks5' or 'mixed', got '{kind}'"),
                ));
            }
            let listen = req_str(item, "listen", &field)?.to_string();
            inbounds.push(InboundConfig { tag, kind, listen });
        }
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
