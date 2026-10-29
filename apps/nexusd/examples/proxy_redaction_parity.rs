//! A6（装配级 E4）：口令脱敏 parity —— 真实畸形 proxy.yaml 启动 + CLI check，
//! 两侧捕获输出里 marker **0 命中**。
//!
//! spec §10.1 A6 的证据形态是「真实畸形 proxy.yaml 启动 + CLI check / stderr+
//! stdout marker 0 命中」。本 example 覆盖两个失败面与两个载体：
//!
//! 1. 启动侧（真实 `nexusd <config-dir>` 子进程，捕获全部 stdout + stderr）：
//!    - `proxy_engine_init`：明文 Trojan（`password` 值为 marker）；
//!    - `config_load`：解析失败的 YAML（失败行原文含 marker，解析器会把该行
//!      回显进 `field`/`detail`，是最容易漏脱敏的路径）。
//! 2. check 侧（生产函数 `nexus::outbound_check::check`，即 `nexus config check`
//!    的实现体；真实二进制路径由 `apps/nexus/tests/outbound_config_check_cli.rs`
//!    覆盖）：同一批配置目录的 JSON + stderr 警示行。
//!
//! 断言：两侧 marker 命中数 = 0（`marker_hits_total`），且**预期失败确实发生**
//! （stage / exit code / `static_valid=false`），避免「没跑到」的假绿。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// 高可辨识 marker：出现在 password 值与解析失败行原文里。
const MARKER: &str = "NXPARITYMARKER7F3C9A1D";

/// 明文 Trojan（首个 wired）→ `stage=proxy_engine_init` 硬失败；password = marker。
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
    password: NXPARITYMARKER7F3C9A1D
";

/// 解析失败的 YAML：失败行原文是 `password NXPARITYMARKER7F3C9A1D`（缺冒号），
/// 解析器把它回显进 `got '<text>'`，脱敏必须把 marker 掩成 `***`。
fn malformed_yaml() -> String {
    format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: tp\noutbounds:\n  - tag: tp\n    kind: trojan\n    locator: 127.0.0.1:443\n    password {MARKER}\n"
    )
}

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
    let base = std::env::temp_dir().join(format!("nexusd-a6-parity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);

    let trojan_dir = base.join("plaintext-trojan");
    let malformed_dir = base.join("malformed-yaml");
    let trojan_startup = startup_case(&nexusd, &trojan_dir, PLAINTEXT_TROJAN_YAML);
    let malformed_startup = startup_case(&nexusd, &malformed_dir, &malformed_yaml());

    let trojan_check = check_case(&trojan_dir);
    let malformed_check = check_case(&malformed_dir);

    let marker_hits_total = trojan_startup["marker_hits"].as_u64().unwrap_or(1)
        + malformed_startup["marker_hits"].as_u64().unwrap_or(1)
        + trojan_check["marker_hits"].as_u64().unwrap_or(1)
        + malformed_check["marker_hits"].as_u64().unwrap_or(1);

    let failures_observed = trojan_startup["stage"] == "proxy_engine_init"
        && trojan_startup["exit_code"] == 1
        && malformed_startup["stage"] == "config_load"
        && malformed_startup["exit_code"] == 1
        && trojan_check["static_valid"] == false
        && malformed_check["static_valid"] == false;

    let verdict = marker_hits_total == 0 && failures_observed;
    let _ = std::fs::remove_dir_all(&base);

    json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "marker_hits_total": marker_hits_total,
        "failures_observed": failures_observed,
        "startup": {
            "proxy_engine_init": trojan_startup,
            "config_load": malformed_startup,
        },
        "check": {
            "plaintext_trojan": trojan_check,
            "malformed_yaml": malformed_check,
        },
    })
}

/// 真实 `nexusd <dir>`：有界等待退出，返回 stage/exit_code/marker 命中数。
fn startup_case(nexusd: &Path, dir: &Path, yaml: &str) -> Value {
    if std::fs::create_dir_all(dir).is_err() {
        return json!({"marker_hits": 1, "error": "mkdir failed"});
    }
    let Ok(port) = free_port() else {
        return json!({"marker_hits": 1, "error": "no free port"});
    };
    if std::fs::write(
        dir.join("daemon.toml"),
        format!("localapi_addr = \"127.0.0.1:{port}\"\n"),
    )
    .is_err()
        || std::fs::write(dir.join("proxy.yaml"), yaml).is_err()
    {
        return json!({"marker_hits": 1, "error": "write config failed"});
    }
    let mut child = match Command::new(nexusd)
        .arg(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return json!({"marker_hits": 1, "error": format!("spawn: {error}")}),
    };

    let capture = Capture::default();
    let stderr_handle = capture.pump(child.stderr.take(), false);
    let stdout_handle = capture.pump(child.stdout.take(), true);

    let deadline = Instant::now() + Duration::from_secs(15);
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    let _ = stderr_handle.join();
    let _ = stdout_handle.join();
    let (stdout, stderr) = capture.text();

    let stage = stderr.lines().find_map(|line| {
        let value: Value = serde_json::from_str(line.trim()).ok()?;
        value
            .get("stage")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let combined = format!("{stdout}\n{stderr}");
    json!({
        "stage": stage,
        "exit_code": exit_code,
        "marker_hits": count_marker(&combined),
        "mask_present": combined.contains("***"),
        "output_bytes": combined.len(),
    })
}

/// `nexus config check` 的实现体（生产函数），JSON + stderr 警示行一并计入命中。
fn check_case(dir: &Path) -> Value {
    let outcome = nexus::outbound_check::check(dir, None);
    let rendered = format!(
        "{}\n{}",
        serde_json::to_string(&outcome.json).unwrap_or_default(),
        outcome.stderr_lines.join("\n")
    );
    let codes: Vec<String> = outcome.json["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .filter_map(|e| e["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "exit_code": outcome.exit_code,
        "static_valid": outcome.json["static_valid"],
        "error_codes": codes,
        "marker_hits": count_marker(&rendered),
        "mask_present": rendered.contains("***"),
    })
}

fn count_marker(text: &str) -> usize {
    text.matches(MARKER).count()
}

/// stdout/stderr 并行抽干（避免管道缓冲阻塞子进程）。
#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<(String, String)>>);

impl Capture {
    fn pump(
        &self,
        pipe: Option<impl Read + Send + 'static>,
        is_stdout: bool,
    ) -> std::thread::JoinHandle<()> {
        let sink = std::sync::Arc::clone(&self.0);
        std::thread::spawn(move || {
            let Some(mut pipe) = pipe else {
                return;
            };
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            if let Ok(mut guard) = sink.lock() {
                if is_stdout {
                    guard.0 = String::from_utf8_lossy(&buf).into_owned();
                } else {
                    guard.1 = String::from_utf8_lossy(&buf).into_owned();
                }
            }
        })
    }

    fn text(&self) -> (String, String) {
        self.0
            .lock()
            .map(|guard| (guard.0.clone(), guard.1.clone()))
            .unwrap_or_default()
    }
}

fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| e.to_string())
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
