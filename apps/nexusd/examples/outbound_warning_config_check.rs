//! E3：`nexus config check` 出站 interop 警示（outbound-adapter-wiring 步骤 3；
//! spec v1.4 §5.3 载体 1 / §5.4）。
//!
//! 场景 `scenarios/product/outbound_warning_config_check.toml` 的可执行验证：
//! - 临时配置目录：VLESS（verified）+ Shadowsocks（partial）+ VMess（synthetic
//!   broken/未接线）；
//! - 调用生产校验函数 `nexus::outbound_check::check`（CLI `config check` 的实现体，
//!   真实二进制路径另由 `apps/nexus/tests/outbound_config_check_cli.rs` 覆盖）；
//! - 断言：`static_valid=true`、exit 0；SS/VMess 有 interop 警示行，VLESS 没有；
//!   非法配置仍 exit 1。

use std::path::Path;

use serde_json::{Value, json};

fn main() {
    match run() {
        Ok(summary) => println!("{summary}"),
        Err(reason) => {
            println!("{}", json!({"verdict": "FAIL", "reason": reason}));
            std::process::exit(1);
        }
    }
}

const PROXY_YAML: &str = "schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: ss-a
outbounds:
  - tag: vless-a
    kind: vless
    locator: 127.0.0.1:443
    uuid: 6f1c2a3b-4d5e-6f70-8192-a3b4c5d6e7f8
    tls: true
  - tag: ss-a
    kind: shadowsocks
    method: chacha20-ietf-poly1305
    locator: 127.0.0.1:8388
    password: secret
  - tag: vmess-a
    kind: vmess
    locator: 127.0.0.1:443
";

fn run() -> Result<Value, String> {
    let dir = std::env::temp_dir().join(format!("nexus-config-check-e3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create config dir: {e}"))?;
    let result = validate(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn validate(dir: &Path) -> Result<Value, String> {
    std::fs::write(dir.join("proxy.yaml"), PROXY_YAML)
        .map_err(|e| format!("write proxy.yaml: {e}"))?;
    let valid = nexus::outbound_check::check(dir, None);
    let outbounds = valid
        .json
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or("config check JSON has no outbounds")?;
    let label_of = |tag: &str| -> Option<String> {
        outbounds
            .iter()
            .find(|o| o.get("tag").and_then(Value::as_str) == Some(tag))
            .and_then(|o| o.get("label").and_then(Value::as_str))
            .map(str::to_string)
    };
    let claim_of = |tag: &str| -> Option<String> {
        outbounds
            .iter()
            .find(|o| o.get("tag").and_then(Value::as_str) == Some(tag))
            .and_then(|o| o.get("claim").and_then(Value::as_str))
            .map(str::to_string)
    };
    let ss_warning = valid
        .stderr_lines
        .iter()
        .find(|line| line.contains("kind=shadowsocks"))
        .cloned();
    let vmess_warning = valid
        .stderr_lines
        .iter()
        .find(|line| line.contains("kind=vmess"))
        .cloned();
    let vless_warning = valid
        .stderr_lines
        .iter()
        .any(|line| line.contains("kind=vless"));

    // 非法配置：静态校验必须失败（exit 1），不因警示通道改变校验语义。
    let invalid_dir = dir.join("invalid");
    std::fs::create_dir_all(&invalid_dir).map_err(|e| format!("create invalid dir: {e}"))?;
    std::fs::write(invalid_dir.join("proxy.yaml"), "schema_version: [\n")
        .map_err(|e| format!("write invalid proxy.yaml: {e}"))?;
    let invalid = nexus::outbound_check::check(&invalid_dir, None);

    let mut failures = Vec::new();
    if valid.exit_code != 0 || valid.json["static_valid"] != Value::Bool(true) {
        failures.push(format!(
            "valid config exit={} static_valid={}",
            valid.exit_code, valid.json["static_valid"]
        ));
    }
    if label_of("vless-a").as_deref() != Some("verified") {
        failures.push(format!("vless label={:?}", label_of("vless-a")));
    }
    if label_of("ss-a").as_deref() != Some("partial") {
        failures.push(format!("ss label={:?}", label_of("ss-a")));
    }
    if claim_of("ss-a").as_deref() != Some("USABLE_WITH_GAPS") {
        failures.push(format!("ss claim={:?}", claim_of("ss-a")));
    }
    if label_of("vmess-a").as_deref() != Some("broken") {
        failures.push(format!("vmess label={:?}", label_of("vmess-a")));
    }
    if ss_warning.is_none() {
        failures.push("missing shadowsocks warning line".to_string());
    }
    if vmess_warning.is_none() {
        failures.push("missing vmess warning line".to_string());
    }
    if vless_warning {
        failures.push("verified VLESS must not print a warning line".to_string());
    }
    if invalid.exit_code != 1 {
        failures.push(format!("invalid config exit={}", invalid.exit_code));
    }
    if !failures.is_empty() {
        return Err(format!(
            "assertions failed: {}; stderr={:?}",
            failures.join(", "),
            valid.stderr_lines
        ));
    }

    Ok(json!({
        "verdict": "PASS",
        "static_valid": valid.json["static_valid"],
        "exit_code": valid.exit_code,
        "invalid_exit_code": invalid.exit_code,
        "invalid_error_code": invalid.json["errors"][0]["code"],
        "vless_label": label_of("vless-a"),
        "ss_label": label_of("ss-a"),
        "ss_claim": claim_of("ss-a"),
        "vmess_label": label_of("vmess-a"),
        "ss_warning_line": ss_warning,
        "vmess_warning_line": vmess_warning,
        "vless_warning_line": vless_warning,
        "manifest_run_id": valid.json["manifest"]["run_id"],
    }))
}
