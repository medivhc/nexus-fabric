//! `nexus config check` 真实二进制边界（E3；spec v1.4 §5.3 载体 1）。
//!
//! 覆盖：合法配置（SS partial / VMess broken / VLESS verified）、非法 YAML exit 1、
//! 无 proxy.yaml exit 0、未知文件名 usage exit 2；stdout 必须是单个 JSON 对象，
//! interop 警示行走 stderr。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nexus-config-check-cli-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli(config_dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["config", "check", "--dir", config_dir.to_str().unwrap()];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args(&args)
        .output()
        .expect("run nexus config check")
}

const CONFIG: &str = "schema_version: 1
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

#[test]
fn valid_config_prints_single_json_and_interop_lines() {
    let dir = temp_dir("valid");
    std::fs::write(dir.join("proxy.yaml"), CONFIG).unwrap();
    let output = cli(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be one JSON object");
    assert_eq!(json["command"], "config check");
    assert_eq!(json["static_valid"], true);
    assert_eq!(json["outbounds"][0]["label"], "verified");
    assert_eq!(json["outbounds"][1]["label"], "partial");
    assert_eq!(json["outbounds"][2]["label"], "broken");
    assert_eq!(json["manifest"]["run_id"], "protocol-interop-fixes-1");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("outbound[ss-a] kind=shadowsocks: interop partial — "));
    assert!(stderr.contains("outbound[vmess-a] kind=vmess: interop broken — "));
    assert!(
        !stderr.contains("kind=vless"),
        "verified VLESS must not print an interop line: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_yaml_exits_one() {
    let dir = temp_dir("invalid");
    std::fs::write(dir.join("proxy.yaml"), "schema_version: [\n").unwrap();
    let output = cli(&dir, &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let json: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(json["static_valid"], false);
    assert_eq!(json["errors"][0]["code"], "PROXY_YAML_INVALID");
    assert_eq!(json["verdict"], "FAIL");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_proxy_yaml_is_static_valid_with_no_proxy_warning() {
    let dir = temp_dir("missing");
    let output = cli(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(json["static_valid"], true);
    assert_eq!(json["config_file"], serde_json::Value::Null);
    assert_eq!(json["warnings"][0]["code"], "NO_PROXY_YAML");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_file_argument_is_usage_error() {
    let dir = temp_dir("usage");
    let output = cli(&dir, &["not-a-config.yml"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explicit_proxy_yaml_argument_is_accepted() {
    let dir = temp_dir("explicit");
    std::fs::write(dir.join("proxy.yaml"), CONFIG).unwrap();
    let output = cli(&dir, &["proxy.yaml"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(json["config_file"], "proxy.yaml");
    let _ = std::fs::remove_dir_all(&dir);
}
