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

/// 规则类型（P0 冻结为四类）。
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
            outbounds.push(OutboundConfig {
                tag,
                kind,
                locator,
                method,
                password,
                alpn,
                skip_cert_verify,
                header_format,
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
            if kind != "socks5" {
                return Err(ConfigError::new(
                    format!("{field}.kind"),
                    format!("P0 supports only 'socks5', got '{kind}'"),
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
                _ => {
                    return Err(ConfigError::new(
                        "speedtest.probe_kind",
                        "P0 only supports `tcp`",
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
