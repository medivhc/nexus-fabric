//! E4 产品场景 `product.proxy-outbound-interop-labeling` 的可执行驱动（PRODUCT §11.21）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_interop_labeling -- --json
//! ```
//!
//! 以含 trojan / shadowsocks / hysteria2 / vless / direct 出站的配置启动真实
//! `nexus proxy` 子进程，只读取其 `READY` 行（不发起会话），随后终止子进程。断言
//! MATRIX verdict 为 PARTIAL 的 trojan / shadowsocks 各有一条分级的
//! `OUTBOUND_INTEROP_PARTIAL` 警告（TCP 可用 / UDP 未实现；仅 trojan 含 fallback 警示），
//! VERIFIED 的 hysteria2 / vless 无标注。

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const CONFIG: &str = "\
schema_version: 1
rules:
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: trojan_node
    kind: trojan
    locator: 127.0.0.1:9
    password: labeling-only
  - tag: ss_node
    kind: shadowsocks
    locator: 127.0.0.1:9
    method: chacha20-ietf-poly1305
    password: labeling-only
  - tag: hy2_node
    kind: hysteria2
    locator: 127.0.0.1:9
    password: labeling-only
  - tag: vless_node
    kind: vless
    locator: 127.0.0.1:9
    uuid: 00000000-0000-0000-0000-000000000000
  - tag: direct
    kind: direct
    locator: \"\"
";

// 无 PARTIAL 出站（只有 VERIFIED 与 direct）：warnings 必须是空数组（字段仍存在）。
const CONFIG_CLEAN: &str = "\
schema_version: 1
rules:
  - tag: rule-match
    kind: match
    match: \"\"
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: hy2_node
    kind: hysteria2
    locator: 127.0.0.1:9
    password: labeling-only
  - tag: vless_node
    kind: vless
    locator: 127.0.0.1:9
    uuid: 00000000-0000-0000-0000-000000000000
  - tag: direct
    kind: direct
    locator: \"\"
";

// 启动时无法解析（规则表缺 MATCH）：READY 照常，warnings 为空数组。
const CONFIG_INVALID: &str = "\
schema_version: 1
rules: []
outbounds:
  - tag: trojan_node
    kind: trojan
    locator: 127.0.0.1:9
    password: labeling-only
";

// 首次运行可能要编译 nexus 二进制。
const READY_TIMEOUT: Duration = Duration::from_secs(600);

fn read_ready_line(config_path: &std::path::Path) -> Result<String, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut child = Command::new(cargo)
        .args(["run", "--quiet", "-p", "nexus", "--bin", "nexus", "--"])
        .args(["proxy", "--addr", "127.0.0.1:0", "--config"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn nexus proxy: {e}"))?;
    let stdout = child.stdout.take().ok_or("no child stdout")?;
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(res);
    });
    let line = rx.recv_timeout(READY_TIMEOUT);
    // 只关心 READY 行；读到（或超时）后终止服务循环并回收子进程与读线程。
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    match line {
        Ok(Ok(l)) if !l.trim().is_empty() => Ok(l),
        Ok(Ok(_)) => Err("nexus proxy exited without output".into()),
        Ok(Err(e)) => Err(format!("read READY line: {e}")),
        Err(_) => Err("timed out waiting for READY line".into()),
    }
}

fn warning_view(warnings: &[Value], tag: &str) -> Value {
    let mentions = |w: &Value, word: &str| {
        w["reason"]
            .as_str()
            .is_some_and(|r| r.to_lowercase().contains(word))
    };
    match warnings.iter().find(|w| w["tag"] == tag) {
        Some(w) => json!({
            "present": true,
            "code": w["code"],
            "kind": w["kind"],
            "field": w["field"],
            "interop_verdict": w["interop_verdict"],
            "tcp": w["tcp"],
            "udp": w["udp"],
            "fallback_warning": w["fallback_warning"],
            "reason_mentions_udp": mentions(w, "udp"),
            "reason_mentions_fallback": mentions(w, "fallback"),
        }),
        None => json!({"present": false}),
    }
}

/// 以 `config` 启动 `nexus proxy` 并返回解析后的 READY 行。
fn ready_for(name: &str, config: &str) -> Result<Value, String> {
    let path = std::env::temp_dir().join(format!(
        "nexus-interop-labeling-{name}-{}.yaml",
        std::process::id()
    ));
    let ready = std::fs::write(&path, config)
        .map_err(|e| format!("write config: {e}"))
        .and_then(|()| read_ready_line(&path))
        .and_then(|l| {
            serde_json::from_str::<Value>(&l).map_err(|e| format!("READY not JSON: {e}"))
        });
    let _ = std::fs::remove_file(&path);
    ready
}

/// 无标注时 READY 的摘要：字段存在且为空数组。
fn empty_view(ready: &Value) -> Value {
    json!({
        "ready_verdict": ready["verdict"],
        "warnings_field_present": ready.get("warnings").is_some_and(Value::is_array),
        "warnings_count": ready["warnings"].as_array().map_or(0, Vec::len),
    })
}

fn main() {
    let as_json = std::env::args().any(|a| a == "--json");
    let report = match (
        ready_for("mixed", CONFIG),
        ready_for("clean", CONFIG_CLEAN),
        ready_for("invalid", CONFIG_INVALID),
    ) {
        (Ok(ready), Ok(clean_ready), Ok(invalid_ready)) => {
            let warnings = ready["warnings"].as_array().cloned().unwrap_or_default();
            let trojan = warning_view(&warnings, "trojan_node");
            let ss = warning_view(&warnings, "ss_node");
            let hy2 = warning_view(&warnings, "hy2_node");
            let vless = warning_view(&warnings, "vless_node");
            let order = warnings
                .iter()
                .filter_map(|w| w["tag"].as_str())
                .collect::<Vec<_>>()
                .join(",");
            let clean = empty_view(&clean_ready);
            let invalid = empty_view(&invalid_ready);
            let empty_ok = |v: &Value| {
                v["ready_verdict"] == "READY"
                    && v["warnings_field_present"] == true
                    && v["warnings_count"] == 0
            };
            // TCP 可用 / UDP 未实现 / 原因点明 UDP：两个 PARTIAL 协议共有的分级。
            let partial = |v: &Value| {
                v["code"] == "OUTBOUND_INTEROP_PARTIAL"
                    && v["interop_verdict"] == "PARTIAL"
                    && v["tcp"] == "usable"
                    && v["udp"] == "not_implemented"
                    && v["reason_mentions_udp"] == true
            };
            let pass = ready["verdict"] == "READY"
                && ready.get("warnings").is_some_and(Value::is_array)
                && warnings.len() == 2
                && partial(&trojan)
                && trojan["kind"] == "trojan"
                && trojan["field"] == "outbounds[0].kind"
                && trojan["fallback_warning"] == true
                && trojan["reason_mentions_fallback"] == true
                && partial(&ss)
                && ss["kind"] == "shadowsocks"
                && ss["field"] == "outbounds[1].kind"
                && ss["fallback_warning"] == false
                && hy2["present"] == false
                && vless["present"] == false
                && order == "trojan_node,ss_node"
                && empty_ok(&clean)
                && empty_ok(&invalid);
            json!({
                "verdict": if pass { "PASS" } else { "FAIL" },
                "ready": {
                    "verdict": ready["verdict"],
                    "warnings_field_present": ready.get("warnings").is_some_and(Value::is_array),
                },
                "warnings": {
                    "count": warnings.len(),
                    "order": order,
                    "trojan_node": trojan,
                    "ss_node": ss,
                    "hy2_node": hy2,
                    "vless_node": vless,
                },
                "clean": clean,
                "invalid": invalid,
            })
        }
        (a, b, c) => {
            let errors = [a, b, c]
                .into_iter()
                .filter_map(Result::err)
                .collect::<Vec<_>>();
            json!({"verdict": "FAIL", "error": errors.join("; ")})
        }
    };
    if as_json {
        println!("{report}");
    } else {
        println!(
            "verdict={} warnings={}",
            report["verdict"], report["warnings"]
        );
    }
}
