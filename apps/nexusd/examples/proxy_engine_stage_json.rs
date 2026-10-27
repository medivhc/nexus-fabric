//! A4（E4）：启动失败按**阶段**输出 JSON + exit code。
//!
//! 真实 `nexusd <config-dir>` 子进程，三个配置目录各触发一个 stage：
//! - `config_load`：proxy.yaml 语法错误（`config::load` 先失败）；
//! - `rule_engine_init`：配置可解析，但 `urltest` 组缺 measurement（rule engine 构建失败）；
//! - `proxy_engine_init`：首个 wired 出站非法（Trojan 未声明 TLS → `SelectedInvalid`）。
//!
//! 断言只看结构化字段（stage / exit code / variant / cause），不读文案。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).expect("json"));
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run() -> Value {
    let nexusd = match nexusd_binary() {
        Ok(path) => path,
        Err(error) => return json!({"verdict": "FAIL", "error": error}),
    };

    let base = std::env::temp_dir().join(format!("nexusd-stage-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);

    let config_load = stage_case(
        &nexusd,
        &base.join("config-load"),
        "schema_version: 1\nrules: [ unclosed\n",
        "config_load",
    );
    let rule_engine = stage_case(
        &nexusd,
        &base.join("rule-engine"),
        RULE_ENGINE_FAIL_YAML,
        "rule_engine_init",
    );
    let proxy_engine = stage_case(
        &nexusd,
        &base.join("proxy-engine"),
        PLAINTEXT_TROJAN_YAML,
        "proxy_engine_init",
    );

    let verdict = if config_load["stage_ok"] == true
        && config_load["exit_code"] == 1
        && rule_engine["stage_ok"] == true
        && rule_engine["exit_code"] == 1
        && proxy_engine["stage_ok"] == true
        && proxy_engine["exit_code"] == 1
        && proxy_engine["variant"] == "SELECTED_OUTBOUND_INVALID"
        && proxy_engine["cause"] == "PLAINTEXT_TROJAN_UNSUPPORTED"
    {
        "PASS"
    } else {
        "FAIL"
    };

    let _ = std::fs::remove_dir_all(&base);
    json!({
        "verdict": verdict,
        "config_load": config_load,
        "rule_engine_init": rule_engine,
        "proxy_engine_init": proxy_engine,
    })
}

const RULE_ENGINE_FAIL_YAML: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: auto
groups:
  - tag: auto
    kind: urltest
    candidates:
      - p1
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1080
";

const PLAINTEXT_TROJAN_YAML: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: tp
outbounds:
  - tag: tp
    kind: trojan
    locator: 127.0.0.1:443
    password: secret
";

fn stage_case(nexusd: &Path, dir: &Path, yaml: &str, expected_stage: &str) -> Value {
    if let Err(error) = std::fs::create_dir_all(dir) {
        return json!({"stage_ok": false, "error": format!("mkdir: {error}")});
    }
    let proxy = dir.join("proxy.yaml");
    if let Err(error) = std::fs::write(&proxy, yaml) {
        return json!({"stage_ok": false, "error": format!("write: {error}")});
    }
    let mut child = match Command::new(nexusd)
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return json!({"stage_ok": false, "error": format!("spawn: {error}")}),
    };
    // stderr 由独立线程收集（避免管道缓冲阻塞子进程）。
    let stderr = child.stderr.take().expect("piped stderr");
    let collected = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = std::sync::Arc::clone(&collected);
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut reader = stderr;
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        if let Ok(mut guard) = sink.lock() {
            guard.push_str(&String::from_utf8_lossy(&buf));
        }
    });
    // 有界等待：启动失败应在毫秒级退出；超时则判定「未失败」并 kill。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };
    let _ = reader.join();
    let stderr = collected.lock().map(|g| g.clone()).unwrap_or_default();
    let json_line = stderr
        .lines()
        .find(|line| line.trim_start().starts_with('{') && line.contains("\"stage\""));
    let parsed: Option<Value> = json_line.and_then(|line| serde_json::from_str(line).ok());
    let exit_code = status.and_then(|status| status.code());
    match parsed {
        Some(value) => json!({
            "stage_ok": value["stage"] == expected_stage,
            "stage": value["stage"],
            "exit_code": exit_code,
            "variant": value["error"]["variant"],
            "cause": value["error"]["cause"],
            "json_parseable": true,
            "timed_out": timed_out,
        }),
        None => json!({
            "stage_ok": false,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stderr_tail": tail(&stderr, 3),
        }),
    }
}

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..].join(" | ")
}

/// `nexusd` 二进制：example 位于 `target/debug/examples/`，其父目录即 `target/debug`。
fn nexusd_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    if let Some(debug_dir) = exe.parent().and_then(|p| p.parent()) {
        let candidate = debug_dir.join("nexusd");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("nexusd not found next to {exe:?}"))
}
