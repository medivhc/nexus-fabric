//! E4：daemon 以 Shadowsocks 出站启动 → 启动日志 / LocalAPI stats / `nexus status`
//! 五载体警示一致（outbound-adapter-wiring 步骤 3；spec v1.4 §5.3 载体 2/3/4）。
//!
//! 场景 `scenarios/product/outbound_warning_status.toml` 的可执行验证：
//! - 临时配置目录：`daemon.toml`（临时 LocalAPI 端口 + `[tun] enabled=false`）+
//!   `proxy.yaml`（shadowsocks 出站，`partial / USABLE_WITH_GAPS`）；
//! - 启动真实 `nexusd <dir>` 二进制；
//! - 断言：stderr 含 `outbound ... label=partial` 与 `WARN outbound ... code=SHADOWSOCKS_*`；
//!   LocalAPI `/dataplane/stats` 的 `outbound.label=partial` 且
//!   `interop_warnings.partial >= 1`；`/status` 的 `summary.outbound` 与 stats 块
//!   逐字段一致；`nexus status` 的人读投影含 `outbound.label: partial`。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
  - tag: ss-a
    kind: shadowsocks
    method: chacha20-ietf-poly1305
    locator: 127.0.0.1:8388
    password: secret
";

fn run() -> Result<Value, String> {
    let port = free_port()?;
    let dir = std::env::temp_dir().join(format!(
        "nexus-outbound-warning-{}-{port}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create config dir: {e}"))?;
    let result = run_daemon(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_daemon(dir: &std::path::Path, port: u16) -> Result<Value, String> {
    std::fs::write(
        dir.join("daemon.toml"),
        format!("localapi_addr = \"127.0.0.1:{port}\"\n[tun]\nenabled = false\n"),
    )
    .map_err(|e| format!("write daemon.toml: {e}"))?;
    std::fs::write(dir.join("proxy.yaml"), PROXY_YAML)
        .map_err(|e| format!("write proxy.yaml: {e}"))?;
    let token_path = dir.join("localapi.token");

    let mut child = Command::new(nexusd_binary()?)
        .arg(dir)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", &token_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nexusd: {e}"))?;

    // READY 行（stdout）→ LocalAPI 实际地址。daemon 启动先打印 boot-reconcile
    // JSON，READY 在其后；用读线程 + 超时避免卡死。
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let addr = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = line_rx
            .recv_timeout(remaining)
            .map_err(|_| "nexusd produced no READY line within 20s".to_string())?;
        if let Ok(addr) = parse_ready_addr(&line) {
            break addr;
        }
    };
    let token = std::fs::read_to_string(&token_path)
        .map_err(|e| format!("read token {}: {e}", token_path.display()))?
        .trim()
        .to_string();

    let mut failures = Vec::new();
    let stats = http_get(&addr, "/localapi/v0/dataplane/stats", &token)
        .and_then(|body| serde_json::from_str::<Value>(&body).map_err(|e| e.to_string()))?;
    let status = http_get(&addr, "/localapi/v0/status", &token)
        .and_then(|body| serde_json::from_str::<Value>(&body).map_err(|e| e.to_string()))?;

    let outbound = &stats["outbound"];
    if outbound["label"] != Value::String("partial".to_string()) {
        failures.push(format!("stats outbound.label={}", outbound["label"]));
    }
    if outbound["tag"] != Value::String("ss-a".to_string()) {
        failures.push(format!("stats outbound.tag={}", outbound["tag"]));
    }
    if outbound["claim"] != Value::String("USABLE_WITH_GAPS".to_string()) {
        failures.push(format!("stats outbound.claim={}", outbound["claim"]));
    }
    let partial = stats["interop_warnings"]["partial"].as_u64().unwrap_or(0);
    if partial < 1 {
        failures.push(format!("interop_warnings.partial={partial}"));
    }
    // 载体 4：status.summary.outbound 与 stats.outbound 同一序列化。
    if status["summary"]["outbound"] != *outbound {
        failures.push(format!(
            "status.summary.outbound != stats.outbound ({} vs {})",
            status["summary"]["outbound"], outbound
        ));
    }
    let projected = nexus::control_service::render_text(&status);
    if !projected
        .iter()
        .any(|line| line == "summary.outbound.label: partial")
    {
        failures.push(format!(
            "nexus status projection missing label: {projected:?}"
        ));
    }

    // R2-F12（Q-3）：reload 被拒 → 原样恢复 → 标记清除（同一 daemon，真实 watcher）。
    let broken = format!("{PROXY_YAML}    password r2f12marker multi word\n");
    std::fs::write(dir.join("proxy.yaml"), &broken)
        .map_err(|e| format!("write broken proxy.yaml: {e}"))?;
    let rejected = wait_outbound(&addr, &token, |outbound| {
        outbound["file_rejected"] == true && outbound["stale"] == true
    })?;
    std::fs::write(dir.join("proxy.yaml"), PROXY_YAML)
        .map_err(|e| format!("restore proxy.yaml: {e}"))?;
    let restored = wait_outbound(&addr, &token, |outbound| {
        outbound["file_rejected"] == false && outbound["stale"] == false
    })?;

    // 收尾：杀 daemon，读完整 stderr。
    let _ = child.kill();
    let _ = child.wait();
    let stderr = read_pipe(&mut child)?;
    let log_line = stderr.lines().any(|line| {
        line.contains("outbound kind=shadowsocks tag=ss-a verdict=PARTIAL label=partial")
    });
    let warn_line = stderr.lines().any(|line| {
        line.contains("WARN outbound tag=ss-a code=SHADOWSOCKS_STD_DERIVE_NONCOMPLIANT")
    });
    let selected_line = stderr.lines().any(|line| {
        line.contains("outbound selected kind=shadowsocks tag=ss-a verdict=PARTIAL label=partial")
    });
    if !log_line {
        failures.push("stderr missing outbound label=partial line".to_string());
    }
    if !selected_line {
        failures.push("stderr missing outbound selected line".to_string());
    }
    if !warn_line {
        failures.push("stderr missing SHADOWSOCKS_* WARN line".to_string());
    }
    if !failures.is_empty() {
        return Err(format!(
            "assertions failed: {}; stderr={}",
            failures.join(", "),
            stderr.trim()
        ));
    }

    Ok(json!({
        "verdict": "PASS",
        "outbound_tag": outbound["tag"],
        "outbound_kind": outbound["kind"],
        "outbound_label": outbound["label"],
        "outbound_claim": outbound["claim"],
        "interop_warnings_partial": partial,
        "status_matches_stats": true,
        "status_projection_has_label": true,
        "startup_log_has_partial": log_line,
        "startup_log_has_selected": selected_line,
        "startup_warn_code": "SHADOWSOCKS_STD_DERIVE_NONCOMPLIANT",
        "rejected.file_rejected": rejected["file_rejected"],
        "rejected.stale": rejected["stale"],
        "restored.file_rejected": restored["file_rejected"],
        "restored.stale": restored["stale"],
    }))
}

fn parse_ready_addr(line: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(line).map_err(|e| format!("READY line not JSON: {e}"))?;
    value
        .get("daemon")
        .and_then(|d| d.get("localapi"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("READY line missing daemon.localapi: {line}"))
}

fn read_pipe(child: &mut Child) -> Result<String, String> {
    let mut text = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut text)
            .map_err(|e| format!("read stderr: {e}"))?;
    }
    Ok(text)
}

/// 轮询 LocalAPI `outbound` 块直到谓词成立（≤15s）。
fn wait_outbound(
    addr: &str,
    token: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        if let Ok(body) = http_get(addr, "/localapi/v0/dataplane/stats", token)
            && let Ok(stats) = serde_json::from_str::<Value>(&body)
        {
            let outbound = stats["outbound"].clone();
            if predicate(&outbound) {
                return Ok(outbound);
            }
            last = outbound;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("timeout waiting for outbound state; last={last}"))
}

fn http_get(addr: &str, path: &str, token: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .map_err(|e| e.to_string())?;
                if let Err(error) = write!(
                    stream,
                    "GET {path} HTTP/1.0\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\r\n"
                ) {
                    if Instant::now() >= deadline {
                        return Err(format!("write: {error}"));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                let mut response = String::new();
                match stream.read_to_string(&mut response) {
                    Ok(_) => {
                        return response
                            .split_once("\r\n\r\n")
                            .map(|(_, body)| body.to_string())
                            .ok_or_else(|| format!("no body in response: {response}"));
                    }
                    Err(error) => {
                        if Instant::now() >= deadline {
                            return Err(format!("read: {error}"));
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(format!("connect {addr}: {error}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("addr: {e}"))
}

fn nexusd_binary() -> Result<std::path::PathBuf, String> {
    let name = if cfg!(windows) {
        "nexusd.exe"
    } else {
        "nexusd"
    };
    let path = std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))?
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join(name))
        .ok_or("cannot resolve nexusd path")?;
    if !path.exists() {
        return Err(format!("nexusd not found at {}", path.display()));
    }
    Ok(path)
}
