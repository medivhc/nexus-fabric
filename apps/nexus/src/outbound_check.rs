//! `nexus config check`（spec v1.4 §5.3 载体 1 / §7）。
//!
//! 只读、离线：读配置文件 → 静态校验 → 单个 JSON 对象到 stdout；不写文件、不联网、
//! 不做 DNS 解析、不改 schema。退出码：`0` = `static_valid=true`（即使协议 verdict
//! 是 broken）、`1` = 文件读取/解析失败或 `static_valid=false`、`2` = 用法错误
//! （由 CLI 层返回）。
//!
//! 与 daemon 的关系：校验语义以 nexusd `proxy_fwd::adapter::build_dialer` 为事实
//! 标准；这里只做**不需要网络**的子集（locator 只查语法、SNI 只查可构造性），
//! 因此不会出现“config check 通过但 daemon 因 DNS 失败”以外的分歧。
//! 警示文案全部来自 [`crate::outbound_manifest`]（include_str! 的 verdicts.json）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nexus_outbound_vless::{VlessFlow, VlessUuid};
use nexus_proxy_config::{OutboundConfig, OutboundKind};
use serde_json::{Value, json};

use crate::outbound_manifest::{self, OutboundLabel, Warning, warning_for_code};

/// 检查结果（JSON + 退出码 + stderr 警示行）。
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// 单个 JSON 对象（stdout）。
    pub json: Value,
    /// 进程退出码（0/1）。
    pub exit_code: i32,
    /// 非 verified 出站的警示行（stderr；`VERIFIED` 不打印）。
    pub stderr_lines: Vec<String>,
}

#[derive(Debug, Clone)]
struct CheckError {
    code: &'static str,
    field: String,
    detail: String,
}

impl CheckError {
    fn new(code: &'static str, field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            field: field.into(),
            detail: crate::redact::sanitize(&detail.into()),
        }
    }

    fn to_json(&self) -> Value {
        json!({"code": self.code, "field": self.field, "detail": self.detail})
    }
}

/// 键名规范化：去掉两侧所有非字母数字、非下划线字符，再转小写。
///
/// 解析器用单引号包裹回显行（`expected 'key: value', got '{text}'`），紧凑键值
/// 形态（`password=…` / `password:…`）分词后键与前导 `'` 粘连；标点必须在这里
/// 统一剥掉。bare 分支与 inline 分支共用本函数——两分支曾各自去标点，导致引号
/// 邻接形态只有一边命中（fix-r1 review F1；R2-F8 把同一口径同步到 CLI）。
fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.trim().is_empty())
}

/// 静态 SNI 可构造性（与 nexusd adapter 的 `valid_sni` 同规则；不发网络）。
fn valid_sni(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '/')
}

/// locator 语法（host:port；只查语法，不解析 DNS）。
fn valid_locator(locator: &str) -> bool {
    let Some((host, port)) = locator.rsplit_once(':') else {
        return false;
    };
    let host = host.trim_matches(['[', ']']);
    !host.is_empty() && port.parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

fn static_errors(outbound: &OutboundConfig) -> Vec<CheckError> {
    if !outbound_manifest::is_wired(outbound.kind) {
        return Vec::new();
    }
    let mut errors = Vec::new();
    if outbound_manifest::has_unsupported_obfs(outbound) {
        errors.push(CheckError::new(
            "UNSUPPORTED_OBFS",
            "obfs",
            "wired outbounds do not support obfs/obfs_key in this run",
        ));
    }
    match non_empty(&outbound.locator) {
        None => errors.push(CheckError::new(
            "MISSING_LOCATOR",
            "locator",
            "locator is required",
        )),
        Some(locator) if !valid_locator(locator) => errors.push(CheckError::new(
            "INVALID_LOCATOR",
            "locator",
            format!("not host:port: {locator}"),
        )),
        Some(_) => {}
    }
    match outbound.kind {
        OutboundKind::Socks5 => {}
        OutboundKind::Shadowsocks => {
            if non_empty(&outbound.password).is_none() {
                errors.push(CheckError::new(
                    "MISSING_PASSWORD",
                    "password",
                    "shadowsocks requires password",
                ));
            }
            let method = non_empty(&outbound.method).unwrap_or("chacha20-ietf-poly1305");
            if method != "chacha20-ietf-poly1305" {
                errors.push(CheckError::new(
                    "UNSUPPORTED_METHOD",
                    "method",
                    format!("unsupported method: {method}"),
                ));
            }
        }
        OutboundKind::Trojan => {
            if non_empty(&outbound.password).is_none() {
                errors.push(CheckError::new(
                    "MISSING_PASSWORD",
                    "password",
                    "trojan requires password",
                ));
            }
            if !outbound_manifest::trojan_tls_signal(outbound) {
                errors.push(CheckError::new(
                    "PLAINTEXT_TROJAN_UNSUPPORTED",
                    "skip_cert_verify",
                    "trojan requires an explicit TLS declaration (skip_cert_verify or alpn)",
                ));
            }
            if outbound
                .alpn
                .as_ref()
                .is_some_and(|alpn| alpn.iter().any(String::is_empty))
            {
                errors.push(CheckError::new(
                    "INVALID_ALPN_ENTRY",
                    "alpn",
                    "alpn entries must be non-empty",
                ));
            }
            if let Some(format) = outbound.header_format.as_deref()
                && format != "standard"
                && format != "singbox"
            {
                errors.push(CheckError::new(
                    "INVALID_HEADER_FORMAT",
                    "header_format",
                    format!("unsupported header_format: {format}"),
                ));
            }
            if let Some(sni) = non_empty(&outbound.sni)
                && !valid_sni(sni)
            {
                errors.push(CheckError::new(
                    "INVALID_SNI",
                    "sni",
                    "sni cannot be used as a TLS server name",
                ));
            }
        }
        OutboundKind::Vless => {
            match non_empty(&outbound.uuid) {
                None => errors.push(CheckError::new(
                    "MISSING_UUID",
                    "uuid",
                    "vless requires uuid",
                )),
                Some(text) => {
                    if VlessUuid::parse(text).is_err() {
                        errors.push(CheckError::new(
                            "INVALID_UUID",
                            "uuid",
                            "uuid is not a valid VLESS UUID",
                        ));
                    }
                }
            }
            let flow_text = outbound.flow.as_deref().unwrap_or("");
            match VlessFlow::parse(flow_text) {
                Ok(flow) => {
                    if flow == VlessFlow::XtlsRprxVision && !outbound.tls.unwrap_or(false) {
                        errors.push(CheckError::new(
                            "VISION_REQUIRES_TLS",
                            "flow",
                            "xtls-rprx-vision requires tls: true",
                        ));
                    }
                }
                Err(_) => errors.push(CheckError::new(
                    "UNSUPPORTED_FLOW",
                    "flow",
                    format!("unsupported flow: {flow_text}"),
                )),
            }
            if let Some(servername) = non_empty(&outbound.servername)
                && !valid_sni(servername)
            {
                errors.push(CheckError::new(
                    "INVALID_SNI",
                    "servername",
                    "servername cannot be used as a TLS server name",
                ));
            }
        }
        OutboundKind::Anytls => {
            if non_empty(&outbound.password).is_none() {
                errors.push(CheckError::new(
                    "MISSING_PASSWORD",
                    "password",
                    "anytls requires password",
                ));
            }
            if let Some(sni) = non_empty(&outbound.sni)
                && !valid_sni(sni)
            {
                errors.push(CheckError::new(
                    "INVALID_SNI",
                    "sni",
                    "sni cannot be used as a TLS server name",
                ));
            }
        }
        OutboundKind::Direct
        | OutboundKind::Relay
        | OutboundKind::Vmess
        | OutboundKind::Hysteria2 => {}
    }
    errors
}

fn warning_json(warning: &Warning) -> Value {
    json!({
        "code": warning.code,
        "severity": warning.severity.as_str(),
        "message": warning.message,
    })
}

fn label_json(label: &OutboundLabel, wired: bool, selected: bool, errors: &[CheckError]) -> Value {
    json!({
        "tag": label.tag,
        "kind": label.kind,
        "wired": wired,
        "selected": selected,
        "verdict": label.verdict,
        "scope": label.scope,
        "claim": label.claim,
        "label": label.label,
        "warnings": label.warnings.iter().map(warning_json).collect::<Vec<_>>(),
        "errors": errors.iter().map(CheckError::to_json).collect::<Vec<_>>(),
    })
}

fn file_warning(code: &str) -> Value {
    warning_json(&warning_for_code(code))
}

fn manifest_json() -> Value {
    outbound_manifest::manifest()
        .ok()
        .map(|m| serde_json::to_value(m.info()).unwrap_or(Value::Null))
        .unwrap_or(Value::Null)
}

/// 执行一次 `config check`。
#[must_use]
pub fn check(config_dir: &Path, file: Option<&str>) -> CheckOutcome {
    let file_name = file.unwrap_or("proxy.yaml");
    let path = resolve_path(config_dir, file_name);
    let config_file = if path.is_file() {
        json!(file_name)
    } else {
        Value::Null
    };
    let mut stdout_warnings = Vec::new();
    let mut errors: Vec<CheckError> = Vec::new();

    let text = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => None,
        Err(read_error) => {
            errors.push(CheckError::new(
                "PROXY_YAML_INVALID",
                file_name,
                format!("read failed: {read_error}"),
            ));
            None
        }
    };

    let Some(text) = text else {
        if errors.is_empty() {
            stdout_warnings.push(file_warning("NO_PROXY_YAML"));
            return finish(
                json!(config_file),
                true,
                Vec::new(),
                stdout_warnings,
                errors,
                Vec::new(),
            );
        }
        return finish(
            json!(config_file),
            false,
            Vec::new(),
            stdout_warnings,
            errors,
            Vec::new(),
        );
    };

    let config = match nexus_proxy_config::parse(&text) {
        Ok(config) if config.outbounds.is_empty() => {
            errors.push(CheckError::new(
                "PROXY_YAML_INVALID",
                "outbounds",
                "proxy.yaml has no outbounds",
            ));
            return finish(
                json!(config_file),
                false,
                Vec::new(),
                stdout_warnings,
                errors,
                Vec::new(),
            );
        }
        Ok(config) => config,
        Err(parse_error) => {
            errors.push(CheckError::new(
                "PROXY_YAML_INVALID",
                parse_error.field,
                parse_error.reason,
            ));
            return finish(
                json!(config_file),
                false,
                Vec::new(),
                stdout_warnings,
                errors,
                Vec::new(),
            );
        }
    };

    // 重复 tag（warning，不改变 exit code；spec §2.9）。
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for outbound in &config.outbounds {
        *seen.entry(outbound.tag.as_str()).or_insert(0) += 1;
    }
    if seen.values().any(|count| *count > 1) {
        stdout_warnings.push(file_warning("DUPLICATE_OUTBOUND_TAG"));
    }

    let selected = outbound_manifest::select_index(&config.outbounds);
    let mut outbounds = Vec::new();
    let mut stderr_lines = Vec::new();
    let mut selected_errors = 0usize;
    for (index, outbound) in config.outbounds.iter().enumerate() {
        let wired = outbound_manifest::is_wired(outbound.kind);
        let is_selected = selected == Some(index);
        let label = outbound_manifest::outbound_label(outbound);
        let item_errors = static_errors(outbound);
        if is_selected {
            selected_errors = item_errors.len();
        }
        if let Some(warning) = outbound_manifest::outbound_warning(outbound) {
            stderr_lines.push(outbound_manifest::warning_line(&outbound.tag, &warning));
        }
        outbounds.push(label_json(&label, wired, is_selected, &item_errors));
    }
    if selected.is_none() {
        errors.push(CheckError::new(
            "NO_USABLE_OUTBOUND",
            "outbounds",
            "no proxy outbound is wired",
        ));
    } else {
        stdout_warnings.push(file_warning("ENGINE_CONFIG_REQUIRES_RESTART"));
    }

    let static_valid = errors.is_empty() && selected.is_some() && selected_errors == 0;
    finish(
        json!(config_file),
        static_valid,
        outbounds,
        stdout_warnings,
        errors,
        stderr_lines,
    )
}

fn resolve_path(config_dir: &Path, file_name: &str) -> PathBuf {
    let candidate = Path::new(file_name);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        config_dir.join(candidate)
    }
}

fn finish(
    config_file: Value,
    static_valid: bool,
    outbounds: Vec<Value>,
    warnings: Vec<Value>,
    errors: Vec<CheckError>,
    stderr_lines: Vec<String>,
) -> CheckOutcome {
    let json = json!({
        "verdict": if static_valid { "PASS" } else { "FAIL" },
        "command": "config check",
        "config_file": config_file,
        "static_valid": static_valid,
        "manifest": manifest_json(),
        "outbounds": outbounds,
        "warnings": warnings,
        "errors": errors.iter().map(CheckError::to_json).collect::<Vec<_>>(),
    });
    CheckOutcome {
        json,
        exit_code: if static_valid { 0 } else { 1 },
        stderr_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_yaml(dir: &Path, body: &str) {
        std::fs::write(dir.join("proxy.yaml"), body).unwrap();
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nexus-config-check-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SS_VLESS_VMESS: &str = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: vless-a\n    kind: vless\n    locator: 127.0.0.1:443\n    uuid: 6f1c2a3b-4d5e-6f70-8192-a3b4c5d6e7f8\n    tls: true\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n  - tag: vmess-a\n    kind: vmess\n    locator: 127.0.0.1:443\n";

    #[test]
    fn missing_file_is_static_valid_with_no_proxy_yaml() {
        let dir = temp_dir("missing");
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.json["static_valid"], true);
        assert_eq!(outcome.json["config_file"], Value::Null);
        assert_eq!(outcome.json["errors"].as_array().unwrap().len(), 0);
        assert!(
            outcome.json["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["code"] == "NO_PROXY_YAML")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn surface_labels_and_warning_lines_are_manifest_derived() {
        let dir = temp_dir("surface");
        write_yaml(&dir, SS_VLESS_VMESS);
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 0, "{}", outcome.json);
        assert_eq!(outcome.json["static_valid"], true);
        let outbounds = outcome.json["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["label"], "verified");
        assert_eq!(outbounds[1]["label"], "partial");
        assert_eq!(outbounds[1]["claim"], "USABLE_WITH_GAPS");
        assert_eq!(outbounds[2]["label"], "broken");
        assert!(outbounds[2]["wired"] == false);
        assert_eq!(
            outcome.json["manifest"]["run_id"],
            "protocol-interop-fixes-1"
        );
        assert_eq!(outcome.stderr_lines.len(), 2, "{:?}", outcome.stderr_lines);
        assert!(
            outcome
                .stderr_lines
                .iter()
                .any(|l| l.contains("kind=shadowsocks"))
        );
        assert!(
            outcome
                .stderr_lines
                .iter()
                .any(|l| l.contains("kind=vmess"))
        );
        assert!(
            !outcome
                .stderr_lines
                .iter()
                .any(|l| l.contains("kind=vless")),
            "VERIFIED must not print a warning line"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_yaml_exits_one_with_proxy_yaml_invalid() {
        let dir = temp_dir("invalid");
        write_yaml(&dir, "schema_version: [\n");
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.json["static_valid"], false);
        assert_eq!(outcome.json["errors"][0]["code"], "PROXY_YAML_INVALID");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selected_plaintext_trojan_fails_static_validation() {
        let dir = temp_dir("plaintext-trojan");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: trojan-a\noutbounds:\n  - tag: trojan-a\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.json["static_valid"], false);
        let codes: Vec<&str> = outcome.json["outbounds"][0]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["code"].as_str())
            .collect();
        assert!(codes.contains(&"PLAINTEXT_TROJAN_UNSUPPORTED"), "{codes:?}");
        // MINOR-3：field 必须指向真实信号字段（`tls` 对 trojan 无效）。
        let field = outcome.json["outbounds"][0]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["code"] == "PLAINTEXT_TROJAN_UNSUPPORTED")
            .map(|e| e["field"].clone())
            .unwrap_or(Value::Null);
        assert_eq!(field, "skip_cert_verify");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_selected_errors_do_not_invalidate() {
        let dir = temp_dir("non-selected");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n  - tag: trojan-b\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 0, "{}", outcome.json);
        assert_eq!(outcome.json["static_valid"], true);
        assert_eq!(
            outcome.json["outbounds"][1]["errors"][0]["code"],
            "PLAINTEXT_TROJAN_UNSUPPORTED"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_wired_outbound_is_no_usable_outbound() {
        let dir = temp_dir("no-usable");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        assert!(
            outcome.json["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["code"] == "NO_USABLE_OUTBOUND")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PR2R1-13：config check 的错误 detail 也不得引用内部 run 语境（用户无法
    /// 判断“本 run”是哪个版本）；与 `NO_USABLE_OUTBOUND` message 同口径。
    #[test]
    fn no_usable_outbound_detail_has_no_internal_run_reference() {
        let dir = temp_dir("no-usable-detail");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n",
        );
        let outcome = check(&dir, None);
        let detail = outcome.json["errors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|error| error["code"] == "NO_USABLE_OUTBOUND")
            .and_then(|error| error["detail"].as_str())
            .expect("NO_USABLE_OUTBOUND detail");
        assert_eq!(detail, "no proxy outbound is wired");
        assert!(
            !detail.contains("this run"),
            "internal run reference leaked: {detail}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 重复 tag 在 **master 的解析器** 阶段即被拒绝（`CONFIG_INVALID`），
    /// 因此 `DUPLICATE_OUTBOUND_TAG` 的 warning 分支在本仓库不可达。
    ///
    /// 口径说明（implement 偏差，已记入 implement-report）：spec §7.5 要求
    /// 「`DUPLICATE_OUTBOUND_TAG` 只 warning、不改 exit code」；本仓
    /// `nexus_proxy_config::parse` 对重复 tag 直接报 `outbounds[i].tag duplicate`，
    /// 该 warning 因此**不可能被触发**，规则在「无重复可观测」的意义上仍成立。
    /// 代码保留该分支（解析器放宽时可自动生效），测试改钉解析器层拒绝。
    #[test]
    fn duplicate_tag_is_rejected_by_parser() {
        let dir = temp_dir("duplicate");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8389\n    password: secret\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1, "duplicate tag is a hard config error");
        assert!(
            outcome.json["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["code"] == "PROXY_YAML_INVALID"),
            "expected PROXY_YAML_INVALID error: {}",
            outcome.json
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_fact_warnings_come_from_messages() {
        let dir = temp_dir("config-facts");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: vless-a\noutbounds:\n  - tag: vless-a\n    kind: vless\n    locator: 127.0.0.1:443\n    uuid: 6f1c2a3b-4d5e-6f70-8192-a3b4c5d6e7f8\n    tls: true\n    skip_cert_verify: true\n    alpn: [h2]\n    sni: ignored.example\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 0, "{}", outcome.json);
        let codes: Vec<&str> = outcome.json["outbounds"][0]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|w| w["code"].as_str())
            .collect();
        for code in ["SKIP_CERT_VERIFY", "ALPN_IGNORED", "SNI_IGNORED_FOR_VLESS"] {
            assert!(codes.contains(&code), "missing {code}: {codes:?}");
        }
        // AC-CFG-9：即使 label=verified，security 级配置事实仍要有 stderr 警示行。
        assert!(
            outcome
                .stderr_lines
                .iter()
                .any(|line| line.contains("SKIP_CERT_VERIFY") || line.contains("已关闭证书校验")),
            "{:?}",
            outcome.stderr_lines
        );
        let skip = outcome.json["outbounds"][0]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "SKIP_CERT_VERIFY")
            .unwrap();
        assert_eq!(skip["severity"], "security");
        assert_eq!(skip["message"], "已关闭证书校验，存在中间人风险。");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plaintext_trojan_carries_config_fact_warning() {
        let dir = temp_dir("trojan-warning");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: trojan-a\noutbounds:\n  - tag: trojan-a\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n",
        );
        let outcome = check(&dir, None);
        let codes: Vec<&str> = outcome.json["outbounds"][0]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|w| w["code"].as_str())
            .collect();
        assert!(codes.contains(&"TROJAN_PLAINTEXT_UNSUPPORTED"), "{codes:?}");
        assert!(codes.contains(&"TROJAN_FALLBACK_FAIL_OPEN"), "{codes:?}");
        assert_eq!(outcome.exit_code, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn obfs_key_is_rejected_like_daemon() {
        let dir = temp_dir("obfs-key");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n    obfs_key: k1\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(
            outcome.json["outbounds"][0]["errors"][0]["code"],
            "UNSUPPORTED_OBFS"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_error_detail_does_not_leak_secrets() {
        let dir = temp_dir("leak");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n    password supersecretpass\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        let detail = outcome.json["errors"][0]["detail"].as_str().unwrap();
        assert!(
            !detail.contains("supersecretpass"),
            "detail leaked: {detail}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_word_password_in_parse_error_is_redacted() {
        let dir = temp_dir("leak-multi");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n    password \"abc def ghi\"\n",
        );
        let outcome = check(&dir, None);
        let detail = outcome.json["errors"][0]["detail"].as_str().unwrap();
        for secret in ["abc", "def", "ghi"] {
            assert!(!detail.contains(secret), "detail leaked {secret}: {detail}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R2-F8 回归（fix-r1 F1 的 CLI 同形态漏网）：解析器用单引号包裹回显
    /// （`expected 'key: value', got '{line}'`），引号邻接的紧凑形态
    /// （无冒号的 `password=<marker>`）会让键与前导 `'` 粘连；端到端断言 config
    /// check 最终 JSON 的 `detail` 不含口令原文，且保留诊断信息与掩码标记。
    #[test]
    fn quoted_adjacent_inline_password_in_parse_error_is_redacted() {
        const MARKER: &str = "r2f8-marker-eq-e2e";
        let dir = temp_dir("leak-quoted-inline");
        write_yaml(&dir, &format!("{SS_VLESS_VMESS}    password={MARKER}\n"));
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        let detail = outcome.json["errors"][0]["detail"].as_str().unwrap();
        assert!(!detail.contains(MARKER), "detail leaked: {detail}");
        assert!(detail.contains("***"), "mask missing: {detail}");
        assert!(
            detail.contains("expected 'key: value'"),
            "diagnostic category lost: {detail}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PR2R1-08（前半）：CLI 与 daemon 同口径——解析器用单引号包裹回显的紧凑
    /// 口令行脱敏后保留闭合引号、只留单掩码（此前 detail 截断在 `password:***`，
    /// 单引号不闭合）。
    #[test]
    fn inline_password_detail_keeps_quotes_closed_and_single_mask() {
        const MARKER: &str = "r2f3-cli-marker-c1d2";
        let dir = temp_dir("leak-inline-quotes");
        write_yaml(&dir, &format!("{SS_VLESS_VMESS}    password={MARKER}\n"));
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        let detail = outcome.json["errors"][0]["detail"].as_str().unwrap();
        assert!(!detail.contains(MARKER), "detail leaked: {detail}");
        assert_eq!(
            detail.matches("***").count(),
            1,
            "double mask in config check detail: {detail}"
        );
        assert!(
            detail.contains("'password:***'"),
            "closing quote lost: {detail}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R2-F8 形态矩阵（镜像 nexusd F1 用例族）：断言落在 CLI 最终输出面
    /// `sanitize` / `CheckError::detail` 上，覆盖引号邻接 `=` 与 `:` 两种形态。
    #[test]
    fn quoted_adjacent_inline_password_forms_are_masked() {
        let eq = CheckError::new(
            "PROXY_YAML_INVALID",
            "proxy.yaml",
            "got 'password=r2f8-marker-eq'",
        )
        .detail;
        assert!(!eq.contains("r2f8-marker-eq"), "leaked: {eq}");
        assert!(eq.contains("***"), "mask missing: {eq}");

        let colon = crate::redact::sanitize("at 'password:r2f8-marker-colon'");
        assert!(!colon.contains("r2f8-marker-colon"), "leaked: {colon}");
        assert!(colon.contains("***"), "mask missing: {colon}");
    }

    /// R2-F8：其他 secret 键在引号邻接紧凑形态下同样命中，且键大小写不敏感。
    #[test]
    fn quoted_adjacent_inline_other_secret_keys_are_masked() {
        let uuid = crate::redact::sanitize("got 'uuid=r2f8-marker-uuid'");
        assert!(!uuid.contains("r2f8-marker-uuid"), "leaked: {uuid}");
        assert!(uuid.contains("***"), "mask missing: {uuid}");

        let obfs = crate::redact::sanitize("at 'OBFS_PASSWORD:r2f8-marker-obfs'");
        assert!(!obfs.contains("r2f8-marker-obfs"), "leaked: {obfs}");
        assert!(obfs.contains("***"), "mask missing: {obfs}");
    }

    /// R2-F8：引号邻接 + 多词口令仍整段截断（值边界未知）。
    #[test]
    fn quoted_adjacent_colonless_multi_word_password_is_masked() {
        let got = crate::redact::sanitize(
            "expected 'key: value', got 'password \"r2f8-marker-multi alpha beta\"'",
        );
        for secret in ["r2f8-marker-multi", "alpha", "beta"] {
            assert!(!got.contains(secret), "leaked {secret}: {got}");
        }
        assert!(got.contains("***"), "mask missing: {got}");
        assert!(
            got.contains("expected 'key: value'"),
            "diagnostic category lost: {got}"
        );
    }

    /// R2-F8：非 secret 文本不被误伤（`sanitize` 既有契约内：单行、无控制字符、
    /// 未超 128B 时逐字保留）。
    #[test]
    fn non_secret_text_is_untouched_by_redaction() {
        let text = "parse proxy.yaml: unexpected indentation at 'tag: r1'";
        assert_eq!(crate::redact::sanitize(text), text);
    }

    #[test]
    fn skip_cert_verify_is_reported_even_for_non_wired_kinds() {
        let dir = temp_dir("skip-nonwired");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: 127.0.0.1:8388\n    password: secret\n  - tag: vm-a\n    kind: vmess\n    locator: 127.0.0.1:443\n    skip_cert_verify: true\n",
        );
        let outcome = check(&dir, None);
        let codes: Vec<&str> = outcome.json["outbounds"][1]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|w| w["code"].as_str())
            .collect();
        assert!(codes.contains(&"SKIP_CERT_VERIFY"), "{codes:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_locator_syntax_is_reported_without_dns() {
        let dir = temp_dir("locator");
        write_yaml(
            &dir,
            "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: ss-a\noutbounds:\n  - tag: ss-a\n    kind: shadowsocks\n    method: chacha20-ietf-poly1305\n    locator: no-port\n    password: secret\n",
        );
        let outcome = check(&dir, None);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(
            outcome.json["outbounds"][0]["errors"][0]["code"],
            "INVALID_LOCATOR"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
