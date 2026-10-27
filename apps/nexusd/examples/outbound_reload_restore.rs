//! A10（E4）：reload 被拒 → 原样恢复 → status 清标记（R2-F12）。
//!
//! 真实 `nexusd <dir>` + 配置 watcher + LocalAPI：断言
//! 1. 磁盘 proxy.yaml 被覆盖为畸形文件后，`outbound.file_rejected=true` 且 `stale=true`；
//! 2. 把文件原样改回（与 active 逐字节相同）后，`file_rejected=false`、`stale=false`。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

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

fn main() {
    let output = match run() {
        Ok(value) => value,
        Err(reason) => json!({"verdict": "FAIL", "reason": reason}),
    };
    println!("{output}");
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run() -> Result<Value, String> {
    let port = free_port()?;
    let dir = std::env::temp_dir().join(format!(
        "nexus-outbound-reload-{}-{port}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    let outcome = drive(&dir, port);
    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

fn drive(dir: &std::path::Path, port: u16) -> Result<Value, String> {
    std::fs::write(
        dir.join("daemon.toml"),
        format!("localapi_addr = \"127.0.0.1:{port}\"\n[tun]\nenabled = false\n"),
    )
    .map_err(|e| format!("daemon.toml: {e}"))?;
    std::fs::write(dir.join("proxy.yaml"), PROXY_YAML).map_err(|e| format!("proxy.yaml: {e}"))?;
    let token_path = dir.join("localapi.token");

    let mut child = Command::new(nexusd_binary()?)
        .arg(dir)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", &token_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn nexusd: {e}"))?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let addr = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = rx
            .recv_timeout(remaining)
            .map_err(|_| "no READY line within 20s".to_string())?;
        if let Ok(value) = serde_json::from_str::<Value>(&line)
            && let Some(addr) = value
                .get("daemon")
                .and_then(|d| d.get("localapi"))
                .and_then(Value::as_str)
        {
            break addr.to_string();
        }
    };
    let token = std::fs::read_to_string(&token_path)
        .map_err(|e| format!("token: {e}"))?
        .trim()
        .to_string();

    let result = (|| {
        // 1) 覆盖为畸形文件（含口令 marker）：watcher 拒绝 → file_rejected=true。
        let broken = format!("{PROXY_YAML}    password r2f12marker multi word\n");
        std::fs::write(dir.join("proxy.yaml"), &broken).map_err(|e| format!("broken: {e}"))?;
        let rejected = wait_for(&addr, &token, |outbound| {
            outbound["file_rejected"] == true && outbound["stale"] == true
        })?;

        // 2) 原样恢复（与 active 逐字节相同）→ Applied 刷新 → 标记清空、stale=false。
        std::fs::write(dir.join("proxy.yaml"), PROXY_YAML).map_err(|e| format!("restore: {e}"))?;
        let restored = wait_for(&addr, &token, |outbound| {
            outbound["file_rejected"] == false && outbound["stale"] == false
        })?;
        Ok::<(Value, Value), String>((rejected, restored))
    })();

    let _ = child.kill();
    let _ = child.wait();
    let (rejected, restored) = result?;

    let verdict = rejected["file_rejected"] == true
        && rejected["stale"] == true
        && restored["file_rejected"] == false
        && restored["stale"] == false;
    Ok(json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "rejected": {
            "file_rejected": rejected["file_rejected"],
            "stale": rejected["stale"],
        },
        "restored": {
            "file_rejected": restored["file_rejected"],
            "stale": restored["stale"],
        },
    }))
}

/// 轮询 LocalAPI，直到 `outbound` 块满足谓词（≤15s）。
fn wait_for(addr: &str, token: &str, predicate: impl Fn(&Value) -> bool) -> Result<Value, String> {
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
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    .map_err(|e| format!("write: {e}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {e}"))?;
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .ok_or_else(|| format!("no body: {response}"))
}

fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| e.to_string())
}

fn nexusd_binary() -> Result<std::path::PathBuf, String> {
    let path = std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))?
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("nexusd"))
        .ok_or("cannot resolve nexusd path")?;
    if !path.exists() {
        return Err(format!("nexusd not found at {}", path.display()));
    }
    Ok(path)
}
