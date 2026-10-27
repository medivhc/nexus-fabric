//! A4（E4）：启动失败按**阶段**输出 JSON + exit code。
//!
//! 真实 `nexusd <config-dir>` 子进程，三个配置目录各触发一个 stage：
//! - `config_load`：proxy.yaml 语法错误（`config::load` 先失败）；
//! - `rule_engine_init`：配置可解析，但 `urltest` 组缺 measurement（rule engine 构建失败）；
//! - `proxy_engine_init`：首个 wired 出站非法（Trojan 未声明 TLS → `SelectedInvalid`）。
//!
//! 另带 MAJOR-1/C1 + MINOR-3 的 `hint_repair` 用例：明文 Trojan 启动失败 JSON 的
//! `hint` 不得把对 Trojan 无效的 `tls: true` 列为建议动作；按 hint 的真实信号
//! （`skip_cert_verify: false`，字段出现即 TLS 声明）修复后 daemon 必须真正启动。
//!
//! 断言只看结构化字段（stage / exit code / variant / cause / hint 关键词），不读文案。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
    let hint_repair = hint_repair_case(&nexusd, &base.join("hint-repair"));

    let verdict = if config_load["stage_ok"] == true
        && config_load["exit_code"] == 1
        && rule_engine["stage_ok"] == true
        && rule_engine["exit_code"] == 1
        && proxy_engine["stage_ok"] == true
        && proxy_engine["exit_code"] == 1
        && proxy_engine["variant"] == "SELECTED_OUTBOUND_INVALID"
        && proxy_engine["cause"] == "PLAINTEXT_TROJAN_UNSUPPORTED"
        && hint_repair["plaintext"]["cause"] == "PLAINTEXT_TROJAN_UNSUPPORTED"
        && hint_repair["plaintext"]["hint_present"] == true
        && hint_repair["plaintext"]["hint_suggests_tls_true"] == false
        && hint_repair["plaintext"]["hint_mentions_alpn"] == true
        && hint_repair["plaintext"]["hint_mentions_skip_cert_verify"] == true
        && hint_repair["repaired_start_ok"] == true
        && hint_repair["repaired_startup_failure_json"] == false
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
        "hint_repair": hint_repair,
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

/// 按启动失败 JSON 的 `hint` 真实信号修复：`skip_cert_verify` 字段出现（写 `false`
/// 也算 TLS 声明，此时走系统根证书校验）。
const REPAIRED_TROJAN_YAML: &str = "\
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
    skip_cert_verify: false
";

/// 一次 `nexusd <dir>` 的有界运行结果（stdout/stderr 全量 + 退出码/存活）。
struct DaemonRun {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    alive: bool,
    startup_failure: bool,
}

/// MAJOR-1/C1：明文 Trojan → 硬失败且 hint 不推荐 `tls: true`；
/// 按 hint 的真实信号修复 → daemon 真正启动（不再是「照改仍报同错」的循环）。
fn hint_repair_case(nexusd: &Path, dir: &Path) -> Value {
    let plaintext = run_daemon(nexusd, dir, PLAINTEXT_TROJAN_YAML, Duration::from_secs(10));
    let error = startup_error_body(&plaintext.stderr);
    let hint = error
        .as_ref()
        .and_then(|e| e.get("hint"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let lower = hint.to_ascii_lowercase();
    // 旧文案的第一建议动作是 `add tls: true`；该字段对 Trojan 被静默忽略，
    // 属于「照 hint 改 → 仍报同一错」的循环，必须不再出现。
    let hint_suggests_tls_true = lower.contains("add tls: true") || lower.contains("tls: true (or");

    let plaintext_json = json!({
        "cause": error.as_ref().and_then(|e| e.get("cause")).cloned().unwrap_or(Value::Null),
        "stage_proxy_engine_init": plaintext.startup_failure,
        "exit_code": plaintext.exit_code,
        "hint_present": !hint.is_empty(),
        "hint_suggests_tls_true": hint_suggests_tls_true,
        "hint_mentions_alpn": lower.contains("alpn"),
        "hint_mentions_skip_cert_verify": lower.contains("skip_cert_verify"),
    });

    let repaired = run_daemon(
        nexusd,
        dir,
        REPAIRED_TROJAN_YAML,
        Duration::from_millis(1500),
    );
    json!({
        "plaintext": plaintext_json,
        "repaired_start_ok": repaired.alive && !repaired.startup_failure,
        "repaired_startup_failure_json": repaired.startup_failure,
        "repaired_exit_code": repaired.exit_code,
        "repaired_stdout_len": repaired.stdout.len(),
    })
}

/// 起一个 `nexusd <dir>`：写 `daemon.toml`（TUN 不启用、LocalAPI 用空闲端口）+
/// `proxy.yaml`；`wait` 是「等退出」或「观察窗口内是否存活」的时限。
fn run_daemon(nexusd: &Path, dir: &Path, yaml: &str, wait: Duration) -> DaemonRun {
    let empty = DaemonRun {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: None,
        alive: false,
        startup_failure: false,
    };
    if std::fs::create_dir_all(dir).is_err() {
        return empty;
    }
    let Ok(port) = free_port() else {
        return empty;
    };
    // TUN 不启用：本用例只观察 `proxy_engine_init` 之后的启动结果，
    // 不需要 root / `/dev/net/tun`（与 A11 的 daemon 存活用例同形态）。
    let daemon_toml = format!("localapi_addr = \"127.0.0.1:{port}\"\n");
    if std::fs::write(dir.join("daemon.toml"), daemon_toml).is_err()
        || std::fs::write(dir.join("proxy.yaml"), yaml).is_err()
    {
        return empty;
    }
    let mut child = match Command::new(nexusd)
        .arg(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return empty,
    };
    let sink = std::sync::Arc::new(std::sync::Mutex::new((String::new(), String::new())));
    let stderr_pipe = child.stderr.take();
    let stdout_pipe = child.stdout.take();
    let stderr_sink = std::sync::Arc::clone(&sink);
    let stderr_reader = std::thread::spawn(move || {
        if let Some(mut pipe) = stderr_pipe {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            if let Ok(mut guard) = stderr_sink.lock() {
                guard.1 = String::from_utf8_lossy(&buf).into_owned();
            }
        }
    });
    let stdout_sink = std::sync::Arc::clone(&sink);
    let stdout_reader = std::thread::spawn(move || {
        if let Some(mut pipe) = stdout_pipe {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            if let Ok(mut guard) = stdout_sink.lock() {
                guard.0 = String::from_utf8_lossy(&buf).into_owned();
            }
        }
    });

    let deadline = Instant::now() + wait;
    let (exit_code, alive) = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break (status.code(), false);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (None, true);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break (None, false),
        }
    };
    let _ = stderr_reader.join();
    let _ = stdout_reader.join();
    let (stdout, stderr) = sink
        .lock()
        .map(|guard| (guard.0.clone(), guard.1.clone()))
        .unwrap_or_default();
    let startup_failure = stderr
        .lines()
        .any(|line| line.contains("\"stage\":\"proxy_engine_init\""));
    DaemonRun {
        stdout,
        stderr,
        exit_code,
        alive,
        startup_failure,
    }
}

/// 从 stderr 取 `stage=proxy_engine_init` 单行 JSON 的 `error` 对象。
fn startup_error_body(stderr: &str) -> Option<Value> {
    stderr.lines().find_map(|line| {
        let value: Value = serde_json::from_str(line.trim()).ok()?;
        if value.get("stage").and_then(Value::as_str) == Some("proxy_engine_init") {
            value.get("error").cloned()
        } else {
            None
        }
    })
}

fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| e.to_string())
}

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
