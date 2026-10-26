//! E4 产品场景 `product.proxy-outbound-interop-labeling` 的可执行驱动（PRODUCT §11.21）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_interop_labeling -- --json
//! ```
//!
//! 以含 trojan / hysteria2 / vless / direct 出站的配置启动真实 `nexus proxy` 子进程，
//! 只读取其 `READY` 行（不发起会话），随后终止子进程。断言 MATRIX verdict 为 BROKEN 的
//! trojan / hysteria2 各有一条 `OUTBOUND_INTEROP_BROKEN` 警告，VERIFIED 的 vless 无标注。

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
    match warnings.iter().find(|w| w["tag"] == tag) {
        Some(w) => json!({
            "present": true,
            "code": w["code"],
            "kind": w["kind"],
            "field": w["field"],
            "interop_verdict": w["interop_verdict"],
            "reason_mentions_fallback": w["reason"]
                .as_str()
                .is_some_and(|r| r.to_lowercase().contains("fallback")),
        }),
        None => json!({"present": false}),
    }
}

fn main() {
    let as_json = std::env::args().any(|a| a == "--json");
    let path = std::env::temp_dir().join(format!(
        "nexus-interop-labeling-{}.yaml",
        std::process::id()
    ));
    let report = match std::fs::write(&path, CONFIG)
        .map_err(|e| format!("write config: {e}"))
        .and_then(|()| read_ready_line(&path))
        .and_then(|l| serde_json::from_str::<Value>(&l).map_err(|e| format!("READY not JSON: {e}")))
    {
        Ok(ready) => {
            let warnings = ready["warnings"].as_array().cloned().unwrap_or_default();
            let trojan = warning_view(&warnings, "trojan_node");
            let hy2 = warning_view(&warnings, "hy2_node");
            let vless = warning_view(&warnings, "vless_node");
            let broken = |v: &Value| {
                v["code"] == "OUTBOUND_INTEROP_BROKEN" && v["interop_verdict"] == "BROKEN"
            };
            let pass = ready["verdict"] == "READY"
                && ready.get("warnings").is_some_and(Value::is_array)
                && warnings.len() == 2
                && broken(&trojan)
                && trojan["reason_mentions_fallback"] == true
                && broken(&hy2)
                && vless["present"] == false;
            json!({
                "verdict": if pass { "PASS" } else { "FAIL" },
                "ready": {
                    "verdict": ready["verdict"],
                    "warnings_field_present": ready.get("warnings").is_some_and(Value::is_array),
                },
                "warnings": {
                    "count": warnings.len(),
                    "trojan_node": trojan,
                    "hy2_node": hy2,
                    "vless_node": vless,
                },
            })
        }
        Err(e) => json!({"verdict": "FAIL", "error": e}),
    };
    let _ = std::fs::remove_file(&path);
    if as_json {
        println!("{report}");
    } else {
        println!(
            "verdict={} warnings={}",
            report["verdict"], report["warnings"]
        );
    }
}
