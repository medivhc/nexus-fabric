//! E4: Trojan 无显式 TLS 声明 → daemon 启动硬失败（spec §3.5 / §6.5）。
//!
//! 场景 `scenarios/product/proxy_fwd_trojan_plaintext_rejected.toml` 的可执行验证：
//! - 临时配置目录：`daemon.toml`（TUN 启用 + 空闲 LocalAPI 端口）+ `proxy.yaml`
//!   （trojan 出站，缺 `skip_cert_verify` 与 `alpn`）；
//! - 启动真实 `nexusd <dir>` 二进制；
//! - 断言：exit code = 1；stderr 单行 JSON
//!   `variant=SELECTED_OUTBOUND_INVALID` + `cause=PLAINTEXT_TROJAN_UNSUPPORTED`；
//!   LocalAPI 端口无监听；TUN 未创建（engine init 先于 TUN）。
//!
//! `nexus config check` 的同类断言属于步骤 3，本 example 不提前实现。

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn main() {
    let outcome = run();
    match outcome {
        Ok(summary) => println!("{summary}"),
        Err(reason) => {
            println!("{}", json!({"verdict": "FAIL", "reason": reason}));
            std::process::exit(1);
        }
    }
}

fn run() -> Result<Value, String> {
    let port = free_port()?;
    let config_dir = std::env::temp_dir().join(format!(
        "nexusd-trojan-plaintext-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&config_dir).map_err(|e| format!("create config dir: {e}"))?;
    let result = run_in_dir(&config_dir, port);
    let _ = std::fs::remove_dir_all(&config_dir);
    result
}

fn run_in_dir(config_dir: &std::path::Path, port: u16) -> Result<Value, String> {
    std::fs::write(
        config_dir.join("daemon.toml"),
        format!("localapi_addr = \"127.0.0.1:{port}\"\n[tun]\nenabled = true\n"),
    )
    .map_err(|e| format!("write daemon.toml: {e}"))?;
    std::fs::write(
        config_dir.join("proxy.yaml"),
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: trojan-a\noutbounds:\n  - tag: trojan-a\n    kind: trojan\n    locator: 127.0.0.1:443\n    password: secret\n",
    )
    .map_err(|e| format!("write proxy.yaml: {e}"))?;

    let nexusd_bin = nexusd_binary()?;
    let mut child = Command::new(&nexusd_bin)
        .arg(config_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nexusd: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait().map_err(|e| format!("try_wait: {e}"))? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("nexusd did not exit within 15s".to_string());
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)
            .map_err(|e| format!("read stderr: {e}"))?;
    }
    let exit_code = status.code().ok_or("nexusd terminated by signal")?;
    let error = startup_error(&stderr).ok_or_else(|| {
        format!(
            "stderr has no proxy_engine_init JSON (exit={exit_code}): {}",
            stderr.lines().next_back().unwrap_or("")
        )
    })?;

    let socket_open = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse()
            .map_err(|e| format!("parse localapi addr: {e}"))?,
        Duration::from_millis(300),
    )
    .is_ok();
    let tun_created = stderr.contains("dataplane: TUN");

    let mut failures = Vec::new();
    if exit_code != 1 {
        failures.push(format!("exit_code={exit_code}"));
    }
    if error.get("variant").and_then(Value::as_str) != Some("SELECTED_OUTBOUND_INVALID") {
        failures.push(format!(
            "variant={}",
            error.get("variant").unwrap_or(&Value::Null)
        ));
    }
    if error.get("cause").and_then(Value::as_str) != Some("PLAINTEXT_TROJAN_UNSUPPORTED") {
        failures.push(format!(
            "cause={}",
            error.get("cause").unwrap_or(&Value::Null)
        ));
    }
    if socket_open {
        failures.push("localapi socket is listening".to_string());
    }
    if tun_created {
        failures.push("TUN was created before engine init failed".to_string());
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
        "exit_code": exit_code,
        "error": {
            "variant": error.get("variant"),
            "cause": error.get("cause"),
        },
        "socket_open": socket_open,
        "tun_created": tun_created,
    }))
}

/// 从 stderr 找 `stage=proxy_engine_init` 的单行 JSON，返回其 `error` 对象。
fn startup_error(stderr: &str) -> Option<Value> {
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
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind free port: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("free port addr: {e}"))
}

/// `nexusd` 二进制与本 example 同目录的上一级（`target/<profile>/`）。
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
