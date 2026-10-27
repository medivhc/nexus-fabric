//! 出站互操作标注（outbound-adapter-wiring 步骤 3；spec v1.4 §5.2/§5.3/§5.4）。
//!
//! **唯一数据源**：编译期 `include_str!` 嵌入仓库根
//! `docs/protocols/interop/verdicts.json`，运行时反序列化一次。五个呈现载体
//! （`nexus config check`、daemon 启动日志、LocalAPI dataplane stats、
//! `nexus status`、manifest 本身）全部经本模块取值，禁止各写一份文案。
//!
//! **数据派生纪律（AC-CFG-2）**：本模块只做“反序列化 + 映射 + 渲染”。协议可用性
//! 判断、warning 文案、label 全部来自 JSON；`.rs` 里不存在“协议名 → 警示文案”
//! 的 match 表。唯一的字符串比较是 spec §5.3 冻结的 verdict→label 映射
//! （`label_for_verdict`），它属于反序列化映射，不是业务分支。
//!
//! 运行时快照（`OutboundRuntimeSnapshot`）放在进程内 `RwLock`：nexusd 是唯一
//! writer（启动/重载），LocalAPI stats 与 `observability::status()` 读同一份，
//! 保证 `nexus status` 与 stats 的 `outbound` 块逐字段一致（spec §5.3 载体 4）。

use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

use nexus_proxy_config::{OutboundConfig, OutboundKind, ProxyConfig};
use serde::Deserialize;
use serde_json::{Value, json};

/// 构建期嵌入的 manifest（缺失文件 = 构建失败；spec §5.2）。
const MANIFEST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/protocols/interop/verdicts.json"
));

/// 统一标签（spec §5.3）：序列化 `verified | partial | broken | unknown | n/a`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Label {
    /// `VERIFIED`。
    #[serde(rename = "verified")]
    Verified,
    /// `PARTIAL`。
    #[serde(rename = "partial")]
    Partial,
    /// `BROKEN`。
    #[serde(rename = "broken")]
    Broken,
    /// manifest 缺该 kind / 非法 verdict。
    #[serde(rename = "unknown")]
    Unknown,
    /// `direct` / `relay`（不是代理出站）。
    #[serde(rename = "n/a")]
    NotApplicable,
}

impl Label {
    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Broken => "broken",
            Self::Unknown => "unknown",
            Self::NotApplicable => "n/a",
        }
    }
}

/// warning 严重度（spec §2.8/§5.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
pub enum Severity {
    /// 信息。
    #[serde(rename = "info")]
    Info,
    /// 警告。
    #[serde(rename = "warn")]
    Warn,
    /// 安全。
    #[serde(rename = "security")]
    Security,
}

impl Severity {
    /// 稳定的机器可读标签。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Security => "security",
        }
    }
}

/// 一条 warning（文案来自 manifest `messages`）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Warning {
    /// 稳定 code。
    pub code: String,
    /// 严重度。
    pub severity: Severity,
    /// `messages[code].text` 原文。
    pub message: String,
}

/// 单个出站的呈现标注（spec §2.8）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OutboundLabel {
    /// 配置 tag。
    pub tag: String,
    /// 配置 kind 文本。
    pub kind: String,
    /// manifest verdict 原文（`VERIFIED` / `PARTIAL` / `BROKEN` / `UNKNOWN` / `N/A`）。
    pub verdict: String,
    /// manifest scope 原文。
    pub scope: String,
    /// manifest claim 原文。
    pub claim: String,
    /// 统一标签。
    pub label: Label,
    /// manifest boundaries + safety 解析出的 warnings。
    pub warnings: Vec<Warning>,
}

/// manifest 溯源信息（spec §5.3 `manifest` 块）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManifestInfo {
    /// schema 版本。
    pub schema_version: u32,
    /// MATRIX 基线 revision。
    pub generated_from_revision: String,
    /// 生成时间（RFC3339）。
    pub generated_at: String,
    /// 互操作 run id。
    pub run_id: String,
    /// 生成输入 sha256。
    pub inputs_sha256: String,
}

/// daemon 进程内运行快照（spec §2.8/§5.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRuntimeSnapshot {
    /// 启动时选中的出站；`None` = 无可用出站。
    pub active: Option<OutboundLabel>,
    /// 启动时 proxy.yaml 原文 sha1。
    pub active_config_sha1: String,
    /// 文件侧 proxy.yaml 原文 sha1。
    pub file_config_sha1: String,
    /// 文件侧选中 tag。
    pub file_tag: Option<String>,
    /// 文件侧选中 kind。
    pub file_kind: Option<String>,
    /// `active_config_sha1 != file_config_sha1`。
    pub stale: bool,
    /// 磁盘 proxy.yaml 已被 watcher 拒绝（无法解析；生效的是旧配置）。
    pub file_rejected: bool,
    /// 拒绝原因（已脱敏；`file_rejected=true` 时存在）。
    pub file_rejected_reason: Option<String>,
}

/// dataplane / engine 的启动事实（PR2R1-04；加法字段，不改 `active` 语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataplaneState {
    /// no-tun 模式：dataplane 线程未启动，ProxyEngine 未构造。
    #[default]
    NotStarted,
    /// dataplane 线程已启动，engine 构造结果尚未发布。
    Starting,
    /// dataplane 运行中（engine 是否构造见 `engine.constructed`）。
    Running,
    /// dataplane 已启动但被降级（TUN 创建/初始化失败）。
    Disabled,
}

impl DataplaneState {
    /// 稳定的机器可读文本。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Disabled => "disabled",
        }
    }
}

/// `active` 的人读限定语（status/stats 的 `engine.note`）。
const ENGINE_NOTE: &str =
    "active 表示配置面选中的出站；dataplane 未启动或 engine 未构造时不表示正在转发。";

/// `warning_for` 的返回值：某 kind 的一句话 interop 警示（非 VERIFIED 才有）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundWarning {
    /// kind 文本。
    pub kind: String,
    /// 统一标签。
    pub label: Label,
    /// claim 原文。
    pub claim: String,
    /// scope 原文。
    pub scope: String,
    /// 稳定 code 列表。
    pub codes: Vec<String>,
    /// `messages` 原文（按 code 顺序）。
    pub notes: Vec<String>,
}

/// `interop_warnings` 聚合计数（按 label/claim 分类）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InteropWarningCounts {
    /// label=broken 的出站数。
    pub broken: u64,
    /// label=partial 的出站数。
    pub partial: u64,
    /// label=unknown（缺失/非法 verdict）的出站数。
    pub unverified: u64,
    /// claim=NOT_CLAIMED 的出站数。
    pub not_claimed: u64,
}

impl InteropWarningCounts {
    /// JSON 形态（LocalAPI stats 的 `interop_warnings` 块）。
    #[must_use]
    pub fn to_json(self) -> Value {
        json!({
            "broken": self.broken,
            "partial": self.partial,
            "unverified": self.unverified,
            "not_claimed": self.not_claimed,
        })
    }
}

/// manifest 解析失败（构建/打包错误；daemon 启动 exit 1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError(pub String);

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ManifestError {}

/// manifest 单协议条目（spec §5.2 冻结字段）。
#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolEntry {
    #[allow(dead_code)]
    origin: String,
    verdict: String,
    scope: String,
    claim: String,
    #[serde(default)]
    boundaries: Vec<String>,
    #[serde(default)]
    safety: Vec<String>,
}

/// manifest 文案条目。
#[derive(Debug, Clone, Deserialize)]
pub struct MessageEntry {
    severity: Severity,
    text: String,
}

/// 解析后的 manifest。
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    schema_version: u32,
    generated_from_revision: String,
    generated_at: String,
    run_id: String,
    inputs_sha256: String,
    protocols: BTreeMap<String, ProtocolEntry>,
    #[serde(default)]
    messages: BTreeMap<String, MessageEntry>,
}

impl Manifest {
    /// 溯源信息（spec §5.3 `manifest` 块）。
    #[must_use]
    pub fn info(&self) -> ManifestInfo {
        ManifestInfo {
            schema_version: self.schema_version,
            generated_from_revision: self.generated_from_revision.clone(),
            generated_at: self.generated_at.clone(),
            run_id: self.run_id.clone(),
            inputs_sha256: self.inputs_sha256.clone(),
        }
    }

    /// 某协议条目；`None` = manifest 缺该 kind。
    #[must_use]
    pub fn protocol(&self, key: &str) -> Option<&ProtocolEntry> {
        self.protocols.get(key)
    }

    /// 某 code 的文案条目。
    #[must_use]
    pub fn message(&self, code: &str) -> Option<&MessageEntry> {
        self.messages.get(code)
    }

    /// 条目对应的 label（spec §5.3 冻结映射）。
    #[must_use]
    pub fn label_for(&self, key: &str) -> Label {
        self.protocol(key)
            .map_or(Label::Unknown, |entry| label_for_verdict(&entry.verdict))
    }
}

impl ProtocolEntry {
    fn claim(&self) -> &str {
        &self.claim
    }

    fn scope(&self) -> &str {
        &self.scope
    }

    fn verdict(&self) -> &str {
        &self.verdict
    }

    fn warning_codes(&self) -> impl Iterator<Item = &String> {
        self.boundaries.iter().chain(self.safety.iter())
    }
}

impl Manifest {
    fn warning_codes(&self, key: &str) -> Vec<&String> {
        self.protocol(key)
            .map(|entry| entry.warning_codes().collect())
            .unwrap_or_default()
    }
}

/// spec §5.3 冻结映射：verdict 原文 → label。
fn label_for_verdict(verdict: &str) -> Label {
    match verdict {
        "VERIFIED" => Label::Verified,
        "PARTIAL" => Label::Partial,
        "BROKEN" => Label::Broken,
        _ => Label::Unknown,
    }
}

/// 反序列化 manifest 文本（测试也用它覆盖“损坏 manifest”行为）。
///
/// # Errors
/// JSON 非法或冻结字段缺失 → [`ManifestError`]。
pub fn parse_manifest(text: &str) -> Result<Manifest, ManifestError> {
    serde_json::from_str(text)
        .map_err(|e| ManifestError(format!("verdicts.json parse failed: {e}")))
}

/// 进程内单次解析的 manifest 句柄。
///
/// # Errors
/// 嵌入 JSON 损坏（构建/打包错误）→ [`ManifestError`]。
pub fn manifest() -> Result<&'static Manifest, ManifestError> {
    static PARSED: OnceLock<Result<Manifest, ManifestError>> = OnceLock::new();
    PARSED
        .get_or_init(|| parse_manifest(MANIFEST_JSON))
        .as_ref()
        .map_err(Clone::clone)
}

/// 协议出站（非 direct/relay）。
#[must_use]
pub fn is_proxy_kind(kind: OutboundKind) -> bool {
    !matches!(kind, OutboundKind::Direct | OutboundKind::Relay)
}

/// 本 run 已接线的代理出站集合（spec §1.5/P3；与 nexusd adapter 同一集合）。
#[must_use]
pub fn is_wired(kind: OutboundKind) -> bool {
    matches!(
        kind,
        OutboundKind::Socks5
            | OutboundKind::Shadowsocks
            | OutboundKind::Trojan
            | OutboundKind::Vless
            | OutboundKind::Anytls
    )
}

/// P3：文件顺序里第一个 proxy 且 wired 的下标；无则 `None`。
#[must_use]
pub fn select_index(outbounds: &[OutboundConfig]) -> Option<usize> {
    outbounds
        .iter()
        .position(|outbound| is_proxy_kind(outbound.kind) && is_wired(outbound.kind))
}

/// Q2：Trojan 是否显式声明 TLS（字段“出现”而非值；`skip_cert_verify=false` 也算）。
#[must_use]
pub fn trojan_tls_signal(outbound: &OutboundConfig) -> bool {
    outbound.skip_cert_verify.is_some()
        || outbound.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty())
}

/// wired 协议不允许非空 `obfs` / `obfs_key`（spec §2.9/§5.6，`UNSUPPORTED_OBFS`）。
///
/// 唯一实现：nexusd `adapter::check_obfs` 与 `nexus config check` 都调用它，
/// 避免两份静态校验漂移（review r1 B2）。
#[must_use]
pub fn has_unsupported_obfs(outbound: &OutboundConfig) -> bool {
    non_empty(&outbound.obfs).is_some() || non_empty(&outbound.obfs_key).is_some()
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.trim().is_empty())
}

fn manifest_text(code: &str) -> (Severity, String) {
    manifest()
        .ok()
        .and_then(|m| m.message(code))
        .map(|message| (message.severity, message.text.clone()))
        .unwrap_or((Severity::Warn, "verdicts.json unavailable".to_string()))
}

fn warnings_from_codes(codes: impl IntoIterator<Item = String>) -> Vec<Warning> {
    codes
        .into_iter()
        .map(|code| warning_for_code(&code))
        .collect()
}

/// 由 stable code 构造 warning（文案来自 `messages`，调用方不拼文案）。
#[must_use]
pub fn warning_for_code(code: &str) -> Warning {
    let (severity, message) = manifest_text(code);
    Warning {
        code: code.to_string(),
        severity,
        message,
    }
}

/// 配置事实类 warning code（spec §5.4 / §3.1 / §3.2 / §3.5 / §5.6）。
///
/// 文案仍来自 manifest `messages`；这里只决定“哪些 code 适用于该配置”。
fn config_fact_codes(outbound: &OutboundConfig) -> Vec<&'static str> {
    let mut codes = Vec::new();
    // AC-CFG-9 覆盖“任意出站”（含本 run 未接线的 vmess/hysteria2）。
    if outbound.skip_cert_verify == Some(true) {
        codes.push("SKIP_CERT_VERIFY");
    }
    if !is_wired(outbound.kind) {
        return codes;
    }
    if has_unsupported_obfs(outbound) {
        codes.push("UNSUPPORTED_OBFS");
    }
    match outbound.kind {
        OutboundKind::Vless => {
            if outbound.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty()) {
                codes.push("ALPN_IGNORED");
            }
            if non_empty(&outbound.sni).is_some() {
                codes.push("SNI_IGNORED_FOR_VLESS");
            }
        }
        OutboundKind::Anytls => {
            if outbound.alpn.as_ref().is_some_and(|alpn| !alpn.is_empty()) {
                codes.push("ALPN_IGNORED");
            }
            if non_empty(&outbound.servername).is_some() {
                codes.push("SERVERNAME_IGNORED_FOR_ANYTLS");
            }
        }
        OutboundKind::Trojan => {
            if non_empty(&outbound.servername).is_some() {
                codes.push("SERVERNAME_IGNORED_FOR_TROJAN");
            }
            if !trojan_tls_signal(outbound) {
                codes.push("TROJAN_PLAINTEXT_UNSUPPORTED");
            }
        }
        OutboundKind::Shadowsocks | OutboundKind::Socks5 => {}
        OutboundKind::Direct
        | OutboundKind::Relay
        | OutboundKind::Vmess
        | OutboundKind::Hysteria2 => {}
    }
    codes
}

fn label_with_codes(tag: &str, kind: OutboundKind, extra: &[&str]) -> OutboundLabel {
    if !is_proxy_kind(kind) {
        return OutboundLabel {
            tag: tag.to_string(),
            kind: kind.as_str().to_string(),
            verdict: "N/A".to_string(),
            scope: "N/A".to_string(),
            claim: "N/A".to_string(),
            label: Label::NotApplicable,
            warnings: Vec::new(),
        };
    }
    let key = kind.as_str();
    let Some(parsed) = manifest().ok() else {
        return OutboundLabel {
            tag: tag.to_string(),
            kind: key.to_string(),
            verdict: "UNKNOWN".to_string(),
            scope: "UNKNOWN".to_string(),
            claim: "UNKNOWN".to_string(),
            label: Label::Unknown,
            warnings: warnings_from_codes(["VERDICT_MISSING".to_string()]),
        };
    };
    let Some(entry) = parsed.protocol(key) else {
        return OutboundLabel {
            tag: tag.to_string(),
            kind: key.to_string(),
            verdict: "UNKNOWN".to_string(),
            scope: "UNKNOWN".to_string(),
            claim: "UNKNOWN".to_string(),
            label: Label::Unknown,
            warnings: warnings_from_codes(["VERDICT_MISSING".to_string()]),
        };
    };
    let mut codes = parsed
        .warning_codes(key)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    for extra in extra {
        if !codes.iter().any(|code| code == extra) {
            codes.push((*extra).to_string());
        }
    }
    OutboundLabel {
        tag: tag.to_string(),
        kind: key.to_string(),
        verdict: entry.verdict().to_string(),
        scope: entry.scope().to_string(),
        claim: entry.claim().to_string(),
        label: label_for_verdict(entry.verdict()),
        warnings: warnings_from_codes(codes),
    }
}

/// VLESS Vision 边界码（spec §5.4：仅在 `flow=xtls-rprx-vision` 时适用；PR2R1-06）。
const VLESS_VISION_CODE: &str = "VLESS_VISION_SPLICE_NOT_IMPLEMENTED";

/// 按配置事实收窄 Vision 边界：非 `flow=xtls-rprx-vision` 的 VLESS（及其它协议）
/// 不显示该 warning（manifest 的 boundaries 是无条件列出的）。
fn apply_vless_vision_condition(outbound: &OutboundConfig, label: &mut OutboundLabel) {
    let vision = outbound.kind == OutboundKind::Vless
        && non_empty(&outbound.flow) == Some("xtls-rprx-vision");
    if !vision {
        label
            .warnings
            .retain(|warning| warning.code != VLESS_VISION_CODE);
    }
}

/// 单个配置出站的标注（manifest + 配置事实；缺失 → `unknown` + `VERDICT_MISSING`）。
#[must_use]
pub fn outbound_label(outbound: &OutboundConfig) -> OutboundLabel {
    let mut label = label_with_codes(&outbound.tag, outbound.kind, &config_fact_codes(outbound));
    apply_vless_vision_condition(outbound, &mut label);
    label
}

/// 仅有 kind 的标注（无配置事实；用于 `warning_for(kind)` 等纯 kind 场景）。
#[must_use]
pub fn outbound_label_for_kind(tag: &str, kind: OutboundKind) -> OutboundLabel {
    label_with_codes(tag, kind, &[])
}

fn warning_from_label(label: &OutboundLabel) -> OutboundWarning {
    OutboundWarning {
        kind: label.kind.clone(),
        label: label.label,
        claim: label.claim.clone(),
        scope: label.scope.clone(),
        codes: label.warnings.iter().map(|w| w.code.clone()).collect(),
        notes: label.warnings.iter().map(|w| w.message.clone()).collect(),
    }
}

/// 某 kind 的一句话 interop 警示；`VERIFIED`（以及 direct/relay）返回 `None`。
///
/// 只含 manifest boundaries/safety（无配置事实）；带配置事实的载体使用
/// [`warning_from_label`] 的公开包装 [`outbound_warning`]。
#[must_use]
pub fn warning_for(kind: OutboundKind) -> Option<OutboundWarning> {
    if !is_proxy_kind(kind) {
        return None;
    }
    let label = outbound_label_for_kind("", kind);
    if label.label == Label::Verified {
        return None;
    }
    Some(warning_from_label(&label))
}

/// 由完整配置出站构造一句话警示（含配置事实 warning）。
///
/// `VERIFIED` 且没有 security 级配置事实时返回 `None`（呈现规则：verified 不打印
/// 边界说明）；`skip_cert_verify=true` 这类安全事实仍必须打印（AC-CFG-9）。
#[must_use]
pub fn outbound_warning(outbound: &OutboundConfig) -> Option<OutboundWarning> {
    let label = outbound_label(outbound);
    if label.label == Label::Verified
        && !label
            .warnings
            .iter()
            .any(|warning| warning.severity == Severity::Security)
    {
        return None;
    }
    Some(warning_from_label(&label))
}

/// `config check` 的警示行（非 JSON 通道，走 stderr；VERIFIED 不打印）。
#[must_use]
pub fn warning_line(tag: &str, warning: &OutboundWarning) -> String {
    format!(
        "outbound[{tag}] kind={}: interop {} — {}",
        warning.kind,
        warning.label.as_str(),
        warning.notes.join("；")
    )
}

/// daemon 启动面：逐出站日志行 + 标注 + 选中下标 + 解析错误。
#[derive(Debug, Default, Clone)]
pub struct StartupSurface {
    /// `proxy.yaml` 是否存在（解析失败也算存在）。
    pub present: bool,
    /// stderr 行（spec §5.3 载体 2 逐字格式）。
    pub lines: Vec<String>,
    /// 每个配置出站的标注（文件顺序）。
    pub labels: Vec<OutboundLabel>,
    /// 选中出站下标。
    pub selected: Option<usize>,
    /// proxy.yaml 解析失败原因（sanitized）。
    pub error: Option<String>,
}

/// 由 proxy.yaml 文本构造启动面（不联网、不解析 DNS）。
#[must_use]
pub fn startup_surface(proxy_yaml: Option<&str>) -> StartupSurface {
    let Some(text) = proxy_yaml else {
        return StartupSurface {
            lines: vec!["[nexusd] proxy: no proxy.yaml; proxy egress unavailable".to_string()],
            ..StartupSurface::default()
        };
    };
    let config = match nexus_proxy_config::parse(text) {
        Ok(config) => config,
        Err(error) => {
            return StartupSurface {
                present: true,
                error: Some(error.reason.clone()),
                ..StartupSurface::default()
            };
        }
    };
    StartupSurface::from_config(&config)
}

impl StartupSurface {
    fn from_config(config: &ProxyConfig) -> Self {
        let selected = select_index(&config.outbounds);
        let mut lines = Vec::new();
        let mut labels = Vec::new();
        for (index, outbound) in config.outbounds.iter().enumerate() {
            let label = outbound_label(outbound);
            if !is_proxy_kind(outbound.kind) {
                lines.push(format!(
                    "[nexusd] outbound skipped kind={} tag={} reason=not_proxy_kind",
                    outbound.kind.as_str(),
                    outbound.tag
                ));
                labels.push(label);
                continue;
            }
            let wired = is_wired(outbound.kind);
            let is_selected = wired && selected == Some(index);
            // spec §5.3 载体 2：每个 configured 代理出站一行（未接线也给出
            // verdict/label/warnings，保证五载体一致）；跳过行随后追加。
            lines.push(format!(
                "[nexusd] outbound kind={} tag={} verdict={} label={} wired={} selected={}",
                label.kind,
                label.tag,
                label.verdict,
                label.label.as_str(),
                wired,
                is_selected
            ));
            if is_selected {
                lines.push(format!(
                    "[nexusd] outbound selected kind={} tag={} verdict={} label={}",
                    label.kind,
                    label.tag,
                    label.verdict,
                    label.label.as_str()
                ));
            }
            if !wired {
                lines.push(format!(
                    "[nexusd] outbound skipped kind={} tag={} reason=protocol_not_wired",
                    outbound.kind.as_str(),
                    outbound.tag
                ));
            }
            for warning in &label.warnings {
                lines.push(format!(
                    "[nexusd] WARN outbound tag={} code={} severity={} message=\"{}\"",
                    label.tag,
                    warning.code,
                    warning.severity.as_str(),
                    warning.message
                ));
            }
            labels.push(label);
        }
        Self {
            present: true,
            lines,
            labels,
            selected,
            error: None,
        }
    }
}

/// 进程内共享状态：运行快照 + 配置面标注（供 `interop_warnings` 聚合）。
#[derive(Debug, Default)]
struct SurfaceState {
    snapshot: Option<OutboundRuntimeSnapshot>,
    labels: Vec<OutboundLabel>,
    error_code: Option<&'static str>,
    engine_constructed: bool,
    dataplane: DataplaneState,
}

fn surface_state() -> &'static RwLock<SurfaceState> {
    static STATE: OnceLock<RwLock<SurfaceState>> = OnceLock::new();
    STATE.get_or_init(|| RwLock::new(SurfaceState::default()))
}

/// nexusd 启动时写入运行快照（唯一 writer；spec §5.3）。
pub fn install_surface(surface: &StartupSurface, active_config_sha1: &str) {
    let mut state = surface_state().write().unwrap_or_else(|e| e.into_inner());
    state.labels = surface.labels.clone();
    match surface
        .selected
        .and_then(|index| surface.labels.get(index).cloned())
    {
        Some(active) => {
            state.snapshot = Some(OutboundRuntimeSnapshot {
                active: Some(active.clone()),
                active_config_sha1: active_config_sha1.to_string(),
                file_config_sha1: active_config_sha1.to_string(),
                file_tag: Some(active.tag.clone()),
                file_kind: Some(active.kind.clone()),
                stale: false,
                file_rejected: false,
                file_rejected_reason: None,
            });
            state.error_code = None;
        }
        None => {
            state.snapshot = None;
            state.error_code = Some(if surface.present {
                "NO_USABLE_OUTBOUND"
            } else {
                "NO_PROXY_YAML"
            });
        }
    }
}

/// watcher 观察到文件侧变化后刷新 file_* 与 `stale`；返回 `stale`（无快照 → `None`）。
///
/// 成功解析的新文件同时清除 `file_rejected` 标记（拒绝状态只描述磁盘现状）。
pub fn update_file_side(
    file_tag: Option<String>,
    file_kind: Option<String>,
    file_config_sha1: &str,
) -> Option<bool> {
    let mut state = surface_state().write().unwrap_or_else(|e| e.into_inner());
    let snapshot = state.snapshot.as_mut()?;
    snapshot.file_tag = file_tag;
    snapshot.file_kind = file_kind;
    snapshot.file_config_sha1 = file_config_sha1.to_string();
    snapshot.stale = snapshot.active_config_sha1 != snapshot.file_config_sha1;
    snapshot.file_rejected = false;
    snapshot.file_rejected_reason = None;
    Some(snapshot.stale)
}

/// watcher 拒绝 reload 后刷新文件侧为磁盘现状，并标记拒绝事实（PR2R1-02）。
///
/// 拒绝后 `stale` 仍按 active/file sha1 计算：磁盘文件与生效配置不同即 `true`，
/// 不伪报“文件与 active 同步”；`file_rejected` / `file_rejected_reason` 让主观察面
/// （LocalAPI stats 与 `nexus status`）直接看到“磁盘配置已被拒绝、生效的是旧配置”。
///
/// 返回 `stale`（无快照 → `None`）。
pub fn mark_file_rejected(
    file_tag: Option<String>,
    file_kind: Option<String>,
    file_config_sha1: &str,
    reason: &str,
) -> Option<bool> {
    let mut state = surface_state().write().unwrap_or_else(|e| e.into_inner());
    let snapshot = state.snapshot.as_mut()?;
    snapshot.file_tag = file_tag;
    snapshot.file_kind = file_kind;
    snapshot.file_config_sha1 = file_config_sha1.to_string();
    snapshot.stale = snapshot.active_config_sha1 != snapshot.file_config_sha1;
    snapshot.file_rejected = true;
    snapshot.file_rejected_reason = Some(reason.to_string());
    Some(snapshot.stale)
}

/// 发布 engine / dataplane 启动事实（PR2R1-04；daemon 启动路径与 dataplane 线程调用）。
pub fn install_engine_state(constructed: bool, dataplane: DataplaneState) {
    let mut state = surface_state().write().unwrap_or_else(|e| e.into_inner());
    state.engine_constructed = constructed;
    state.dataplane = dataplane;
}

/// spec §5.5 stale 日志行（`stale=true` 时调用）。
#[must_use]
pub fn stale_line() -> Option<String> {
    let state = surface_state().read().unwrap_or_else(|e| e.into_inner());
    let snapshot = state.snapshot.as_ref()?;
    if !snapshot.stale {
        return None;
    }
    let active = snapshot.active.as_ref()?;
    Some(format!(
        "[nexusd] WARN: proxy.yaml changed on disk; active tag={} kind={} file tag={} kind={}; restart required (stale=true)",
        active.tag,
        active.kind,
        snapshot.file_tag.as_deref().unwrap_or("-"),
        snapshot.file_kind.as_deref().unwrap_or("-"),
    ))
}

fn manifest_info_json() -> Value {
    match manifest() {
        Ok(parsed) => serde_json::to_value(parsed.info()).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

fn snapshot_json(
    snapshot: &OutboundRuntimeSnapshot,
    engine_constructed: bool,
    dataplane: DataplaneState,
) -> Value {
    let active = snapshot.active.as_ref();
    let mut warnings = active.map(|a| a.warnings.clone()).unwrap_or_default();
    // PR2R1-07：stale 时把 manifest 已有的“需重启 daemon”文案接到主观察面
    // （此前该 message 全仓无引用，只有 stderr 说明下一步）。
    if snapshot.stale
        && !warnings
            .iter()
            .any(|warning| warning.code == "ACTIVE_OUTBOUND_STALE_REQUIRES_RESTART")
    {
        warnings.push(warning_for_code("ACTIVE_OUTBOUND_STALE_REQUIRES_RESTART"));
    }
    json!({
        "active": active.is_some(),
        "stale": snapshot.stale,
        "tag": active.map(|a| a.tag.clone()),
        "kind": active.map(|a| a.kind.clone()),
        "verdict": active.map(|a| a.verdict.clone()),
        "scope": active.map(|a| a.scope.clone()),
        "claim": active.map(|a| a.claim.clone()),
        "label": active.map(|a| a.label),
        "warnings": warnings,
        "manifest": manifest_info_json(),
        "active_config_sha1": snapshot.active_config_sha1,
        "file_config_sha1": snapshot.file_config_sha1,
        "file_tag": snapshot.file_tag,
        "file_kind": snapshot.file_kind,
        "file_rejected": snapshot.file_rejected,
        "file_rejected_reason": snapshot.file_rejected_reason,
        "engine": {
            "constructed": engine_constructed,
            "dataplane": dataplane.as_str(),
            "note": ENGINE_NOTE,
        },
    })
}

fn outbound_error_json(code: &str) -> Value {
    let (_, message) = manifest_text(code);
    json!({"code": code, "message": message})
}

/// 当前运行快照的副本（spec §2.8 `runtime_snapshot`；测试/只读消费者用）。
#[must_use]
pub fn runtime_snapshot() -> Option<OutboundRuntimeSnapshot> {
    let state = surface_state().read().unwrap_or_else(|e| e.into_inner());
    state.snapshot.clone()
}

/// LocalAPI stats / `nexus status` 共用的 `outbound` 块 + `outbound_error`。
///
/// 返回值 `(outbound, outbound_error)`；无 active 出站时 `outbound = null`
/// 并给出 spec §5.3 允许的错误码。
#[must_use]
pub fn runtime_outbound_json() -> (Value, Option<Value>) {
    let state = surface_state().read().unwrap_or_else(|e| e.into_inner());
    match state.snapshot.as_ref() {
        Some(snapshot) if snapshot.active.is_some() => (
            snapshot_json(snapshot, state.engine_constructed, state.dataplane),
            None,
        ),
        _ => (
            Value::Null,
            Some(outbound_error_json(
                state.error_code.unwrap_or("NO_PROXY_YAML"),
            )),
        ),
    }
}

/// 当前配置面标注的 `interop_warnings` 聚合（按 label/claim 计数）。
#[must_use]
pub fn interop_warning_counts() -> InteropWarningCounts {
    let state = surface_state().read().unwrap_or_else(|e| e.into_inner());
    let mut counts = InteropWarningCounts::default();
    for label in &state.labels {
        match label.label {
            Label::Broken => counts.broken += 1,
            Label::Partial => counts.partial += 1,
            Label::Unknown => counts.unverified += 1,
            Label::Verified | Label::NotApplicable => {}
        }
        if label.claim == "NOT_CLAIMED" {
            counts.not_claimed += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 运行快照是进程级单例；这些用例必须串行，避免并行测试互相覆盖。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn embedded_manifest_parses_and_has_seven_protocols() {
        let parsed = manifest().expect("embedded verdicts.json must parse");
        for key in [
            "vless",
            "anytls",
            "hysteria2",
            "trojan",
            "shadowsocks",
            "socks5",
            "vmess",
        ] {
            assert!(parsed.protocol(key).is_some(), "missing {key}");
        }
        assert_eq!(parsed.info().run_id, "protocol-interop-fixes-1");
        assert_eq!(parsed.info().schema_version, 1);
    }

    #[test]
    fn corrupt_manifest_is_a_parse_error() {
        let error = parse_manifest("{not json}").unwrap_err();
        assert!(error.to_string().contains("parse failed"));
        let missing = parse_manifest(r#"{"schema_version":1}"#).unwrap_err();
        assert!(missing.to_string().contains("parse failed"));
    }

    #[test]
    fn shadowsocks_uses_frozen_partial_triplet() {
        let parsed = manifest().unwrap();
        let ss = parsed.protocol("shadowsocks").unwrap();
        assert_eq!(ss.verdict(), "PARTIAL");
        assert_eq!(ss.scope(), "TCP_ONLY");
        assert_eq!(ss.claim(), "USABLE_WITH_GAPS");
        assert_eq!(parsed.label_for("shadowsocks"), Label::Partial);
    }

    /// PR2R1-01/09/13：用户可见文案必须与步骤 4 后事实一致（SS 告警区分 TCP/UDP），
    /// 且不得再出现内部 run id / 组件名（`本 run` / `fixes-*` / `ss_std` 等）。
    #[test]
    fn manifest_messages_are_user_judgeable_and_tcp_udp_scoped() {
        let parsed = manifest().unwrap();
        for (code, message) in &parsed.messages {
            for needle in [
                "本 run",
                "fixes-",
                "ss_std",
                "nexus-outbound-shadowsocks",
                "verdicts.json",
            ] {
                assert!(
                    !message.text.contains(needle),
                    "{code} still leaks internal term {needle:?}: {}",
                    message.text
                );
            }
        }

        let ss = parsed.protocol("shadowsocks").unwrap();
        assert!(
            ss.boundaries
                .iter()
                .any(|code| code == "SHADOWSOCKS_UDP_LEGACY_NONCOMPLIANT"),
            "SS must carry an explicit UDP gap code: {:?}",
            ss.boundaries
        );
        assert!(
            !ss.boundaries
                .iter()
                .any(|code| code == "SHADOWSOCKS_CRATE_WIRE_NONCOMPLIANT"),
            "SS crate TCP wire format is compliant; the code must be withdrawn"
        );

        let derive = parsed
            .message("SHADOWSOCKS_STD_DERIVE_NONCOMPLIANT")
            .unwrap();
        assert!(derive.text.contains("UDP"), "{}", derive.text);
        assert!(derive.text.contains("TCP"), "{}", derive.text);
        assert!(
            !derive.text.contains("与标准 SS 服务端不可互通"),
            "the blanket incompatibility claim is false for TCP: {}",
            derive.text
        );
        let interop = parsed.message("SHADOWSOCKS_NO_INTEROP_EVIDENCE").unwrap();
        assert!(interop.text.contains("UDP"), "{}", interop.text);

        assert!(
            parsed.message("NO_USABLE_OUTBOUND").is_some(),
            "NO_USABLE_OUTBOUND must have a real message (no manifest fallback)"
        );
    }

    #[test]
    fn labels_follow_spec_mapping() {
        assert_eq!(label_for_verdict("VERIFIED"), Label::Verified);
        assert_eq!(label_for_verdict("PARTIAL"), Label::Partial);
        assert_eq!(label_for_verdict("BROKEN"), Label::Broken);
        assert_eq!(label_for_verdict("UNKNOWN"), Label::Unknown);
        assert_eq!(Label::NotApplicable.as_str(), "n/a");
    }

    #[test]
    fn direct_and_relay_are_not_applicable() {
        let direct = outbound_label_for_kind("d", OutboundKind::Direct);
        assert_eq!(direct.label, Label::NotApplicable);
        assert!(direct.warnings.is_empty());
        assert!(warning_for(OutboundKind::Relay).is_none());
    }

    #[test]
    fn verified_outbound_has_no_warning() {
        let vless = outbound_label_for_kind("v", OutboundKind::Vless);
        assert_eq!(vless.label, Label::Verified);
        assert!(
            !vless.warnings.is_empty(),
            "boundaries still carried in JSON"
        );
        assert!(
            warning_for(OutboundKind::Vless).is_none(),
            "VERIFIED must not print an interop warning"
        );
    }

    /// PR2R1-06（spec §5.4）：`VLESS_VISION_SPLICE_NOT_IMPLEMENTED` 只在
    /// `flow=xtls-rprx-vision` 时呈现；普通 VLESS / 其他协议不受影响。
    #[test]
    fn vless_vision_boundary_is_conditional_on_flow() {
        const RULES: &str = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: t\n";
        let parse_one = |tag: &str, tail: &str| {
            let rules = RULES.replace("tag: t\n", &format!("tag: {tag}\n"));
            let yaml = format!("{rules}{tail}");
            nexus_proxy_config::parse(&yaml)
                .expect("test config must parse")
                .outbounds
                .into_iter()
                .next()
                .expect("one outbound")
        };

        let plain = parse_one(
            "v",
            "outbounds:\n  - tag: v\n    kind: vless\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n    locator: 127.0.0.1:443\n    tls: true\n",
        );
        let label = outbound_label(&plain);
        assert!(
            !label.warnings.iter().any(|w| w.code == VLESS_VISION_CODE),
            "no-flow VLESS must not report the Vision boundary: {:?}",
            label.warnings
        );
        assert!(
            label
                .warnings
                .iter()
                .any(|w| w.code == "PRODUCT_UDP_NOT_IMPLEMENTED"),
            "other VLESS boundaries must be untouched: {:?}",
            label.warnings
        );

        let vision = parse_one(
            "v",
            "outbounds:\n  - tag: v\n    kind: vless\n    uuid: 123e4567-e89b-12d3-a456-426614174000\n    locator: 127.0.0.1:443\n    tls: true\n    flow: xtls-rprx-vision\n",
        );
        assert!(
            outbound_label(&vision)
                .warnings
                .iter()
                .any(|w| w.code == VLESS_VISION_CODE),
            "flow=vision must keep the Vision boundary"
        );

        let anytls = parse_one(
            "a",
            "outbounds:\n  - tag: a\n    kind: anytls\n    locator: 127.0.0.1:443\n    password: secret\n",
        );
        let anytls_label = outbound_label(&anytls);
        assert!(
            !anytls_label
                .warnings
                .iter()
                .any(|w| w.code == VLESS_VISION_CODE),
            "other protocols never carry the Vision boundary: {:?}",
            anytls_label.warnings
        );
        assert!(
            anytls_label
                .warnings
                .iter()
                .any(|w| w.code == "PRODUCT_UDP_NOT_IMPLEMENTED"),
            "AnyTLS boundaries must be untouched"
        );
    }

    #[test]
    fn partial_and_broken_outbounds_carry_notes_from_messages() {
        let ss = warning_for(OutboundKind::Shadowsocks).expect("SS is partial");
        assert_eq!(ss.label, Label::Partial);
        assert_eq!(ss.claim, "USABLE_WITH_GAPS");
        assert!(
            ss.codes
                .iter()
                .any(|c| c == "SHADOWSOCKS_NO_INTEROP_EVIDENCE")
        );
        assert!(ss.notes.iter().any(|n| n.contains("EVP_BytesToKey")));
        let line = warning_line("ss-a", &ss);
        assert!(line.starts_with("outbound[ss-a] kind=shadowsocks: interop partial — "));

        let vmess = warning_for(OutboundKind::Vmess).expect("VMess is broken");
        assert_eq!(vmess.label, Label::Broken);
        assert_eq!(vmess.codes, vec!["PROTOCOL_NOT_WIRED".to_string()]);
    }

    #[test]
    fn startup_surface_logs_one_line_per_outbound_and_selection() {
        let yaml = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: direct-a\n    kind: direct\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n  - tag: vmess-a\n    kind: vmess\n    locator: 127.0.0.1:443\n";
        let surface = startup_surface(Some(yaml));
        assert!(surface.error.is_none());
        assert_eq!(surface.selected, Some(1));
        let text = surface.lines.join("\n");
        assert!(text.contains("outbound skipped kind=direct tag=direct-a reason=not_proxy_kind"));
        assert!(text.contains("outbound kind=shadowsocks tag=ss-a verdict=PARTIAL label=partial wired=true selected=true"));
        assert!(
            text.contains(
                "outbound selected kind=shadowsocks tag=ss-a verdict=PARTIAL label=partial"
            )
        );
        assert!(text.contains(
            "outbound kind=vmess tag=vmess-a verdict=BROKEN label=broken wired=false selected=false"
        ));
        assert!(text.contains("outbound skipped kind=vmess tag=vmess-a reason=protocol_not_wired"));
        assert!(text.contains("WARN outbound tag=vmess-a code=PROTOCOL_NOT_WIRED severity=warn"));
        assert!(text.contains("code=SHADOWSOCKS_STD_DERIVE_NONCOMPLIANT severity=warn"));
    }

    #[test]
    fn no_proxy_yaml_line_matches_spec() {
        let surface = startup_surface(None);
        assert_eq!(
            surface.lines,
            vec!["[nexusd] proxy: no proxy.yaml; proxy egress unavailable".to_string()]
        );
        assert!(surface.selected.is_none());
    }

    #[test]
    fn runtime_snapshot_serializes_stale_and_file_side() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_surface(
            &startup_surface(Some(
                "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n",
            )),
            "original-sha1",
        );
        let (block, error) = runtime_outbound_json();
        assert!(error.is_none());
        assert_eq!(block["active"], true);
        assert_eq!(block["stale"], false);
        assert_eq!(block["tag"], "ss-a");
        assert_eq!(block["label"], "partial");
        assert_eq!(block["manifest"]["run_id"], "protocol-interop-fixes-1");

        let stale = update_file_side(
            Some("ss-b".to_string()),
            Some("shadowsocks".to_string()),
            "changed-sha1",
        );
        assert_eq!(stale, Some(true));
        let (block, _) = runtime_outbound_json();
        assert_eq!(block["stale"], true);
        assert_eq!(block["file_tag"], "ss-b");
        assert!(stale_line().unwrap().contains("stale=true"));
    }

    /// 合法 SS 配置（PR2R1-02/04/07 用例共用）。
    const SS_OK_YAML: &str = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n";

    fn warning_codes(block: &Value) -> Vec<String> {
        block["warnings"]
            .as_array()
            .map(|warnings| {
                warnings
                    .iter()
                    .filter_map(|warning| warning["code"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// PR2R1-07：`stale=true` 时把 `ACTIVE_OUTBOUND_STALE_REQUIRES_RESTART` 注入
    /// `outbound.warnings`（文案来自 manifest）；非 stale 时不出现。
    #[test]
    fn stale_snapshot_injects_restart_requirement_warning() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_surface(&startup_surface(Some(SS_OK_YAML)), "sha-active");
        let (block, _) = runtime_outbound_json();
        assert!(
            !warning_codes(&block)
                .iter()
                .any(|code| code == "ACTIVE_OUTBOUND_STALE_REQUIRES_RESTART"),
            "fresh snapshot must not warn about restart: {block}"
        );

        assert_eq!(
            update_file_side(
                Some("ss-a".to_string()),
                Some("shadowsocks".to_string()),
                "sha-changed",
            ),
            Some(true)
        );
        let (block, _) = runtime_outbound_json();
        let warning = block["warnings"]
            .as_array()
            .and_then(|warnings| {
                warnings
                    .iter()
                    .find(|warning| warning["code"] == "ACTIVE_OUTBOUND_STALE_REQUIRES_RESTART")
            })
            .unwrap_or_else(|| panic!("stale snapshot missing restart warning: {block}"));
        assert!(
            warning["message"]
                .as_str()
                .unwrap()
                .contains("需重启 daemon"),
            "unexpected message: {warning}"
        );
    }

    /// PR2R1-04：no-tun + selected 非法（评审 d-invald 形态）。`active` 既有语义
    /// 零变化（仍是配置面选中项），但 engine/dataplane 字段必须如实报“无 engine”。
    #[test]
    fn no_tun_selected_invalid_reports_no_engine() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let invalid_selected = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: vless-bad\noutbounds:\n  - tag: vless-bad\n    kind: vless\n    uuid: not-a-uuid\n    locator: 127.0.0.1:443\n    tls: true\n";
        install_surface(&startup_surface(Some(invalid_selected)), "sha");
        install_engine_state(false, DataplaneState::NotStarted);

        let (block, error) = runtime_outbound_json();
        assert!(error.is_none(), "outbound_error must stay null: {error:?}");
        // 既有语义（PR2R1-04 裁决：不改 `active`）。
        assert_eq!(block["active"], true);
        assert_eq!(block["tag"], "vless-bad");
        assert_eq!(block["label"], "verified");
        // 新字段如实反映事实。
        assert_eq!(block["engine"]["constructed"], false);
        assert_eq!(block["engine"]["dataplane"], "not_started");
        assert!(
            block["engine"]["note"]
                .as_str()
                .unwrap()
                .contains("不表示正在转发"),
            "missing qualifier: {block}"
        );

        // TUN dataplane 跑起来后同样的 active 语义 + 事实变化。
        install_engine_state(true, DataplaneState::Running);
        let (block, _) = runtime_outbound_json();
        assert_eq!(block["active"], true);
        assert_eq!(block["engine"]["constructed"], true);
        assert_eq!(block["engine"]["dataplane"], "running");
    }

    /// PR2R1-02（manifest 侧）：磁盘文件被拒后必须暴露拒绝事实，且不能继续报
    /// `stale=false` / file==active 的假同步；后续成功解析清除拒绝标记。
    #[test]
    fn rejected_file_side_is_visible_and_not_reported_as_synced() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_surface(&startup_surface(Some(SS_OK_YAML)), "sha-active");
        assert_eq!(
            mark_file_rejected(
                None,
                None,
                "sha-bad-disk",
                "parse proxy.yaml: expected 'key: value', got 'password:***",
            ),
            Some(true)
        );

        let (block, error) = runtime_outbound_json();
        assert!(error.is_none());
        assert_eq!(block["active"], true);
        assert_eq!(block["stale"], true, "rejected file must not look synced");
        assert_eq!(block["file_rejected"], true);
        assert_eq!(block["file_config_sha1"], "sha-bad-disk");
        assert_ne!(block["file_config_sha1"], block["active_config_sha1"]);
        assert!(
            block["file_rejected_reason"]
                .as_str()
                .unwrap()
                .contains("expected 'key: value'"),
            "rejection reason lost: {block}"
        );
        assert_eq!(block["file_tag"], Value::Null);

        // 之后磁盘文件恢复合法 → 拒绝标记清除（stale 仍按 sha 计算）。
        assert_eq!(
            update_file_side(
                Some("ss-a".to_string()),
                Some("shadowsocks".to_string()),
                "sha-recovered",
            ),
            Some(true)
        );
        let (block, _) = runtime_outbound_json();
        assert_eq!(block["file_rejected"], false);
        assert_eq!(block["file_rejected_reason"], Value::Null);
    }

    #[test]
    fn no_proxy_yaml_snapshot_reports_no_proxy_yaml_error() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_surface(&startup_surface(None), "");
        let (block, error) = runtime_outbound_json();
        assert_eq!(block, Value::Null);
        assert_eq!(error.unwrap()["code"], "NO_PROXY_YAML");
    }

    #[test]
    fn interop_warning_counts_bucket_labels_and_claims() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_surface(
            &startup_surface(Some(
                "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n  - tag: trojan-a\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n    skip_cert_verify: false\n  - tag: vmess-a\n    kind: vmess\n    locator: 127.0.0.1:443\n",
            )),
            "x-sha1",
        );
        let counts = interop_warning_counts();
        assert_eq!(counts.partial, 1);
        assert_eq!(counts.broken, 2);
        assert_eq!(counts.unverified, 0);
        assert_eq!(counts.not_claimed, 0);
    }
}
