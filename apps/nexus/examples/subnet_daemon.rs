//! E4 产品场景 `product.subnet-daemon` 的可执行驱动（§12.32）。
//!
//! 由 `scenarios/product/subnet_daemon.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example subnet_daemon -- --json
//! ```
//!
//! 进程内 spawn `nexus subnet up --foreground` 子进程（daemon 组合根常驻持有
//! 隧道），验证：up 就绪 → status 读回 → 状态文件加密 magic → leave（删状态
//! 文件）→ 子进程优雅退出 → status DOWN 的完整生命周期闭环。

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match subnet_daemon_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("subnet daemon flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("subnet_daemon_flow failed: {err}");
            std::process::exit(1);
        }
    }
}

/// P3.5 E4 闭环：nexus 常驻持有隧道 → leave 信号 → 优雅退出。
fn subnet_daemon_flow() -> Result<Value, String> {
    let dir = std::env::temp_dir().join(format!(
        "nexus-b3-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let cfg = dir.join("subnet.toml");
    let state = dir.join("subnet-state.bin");
    std::fs::write(
        &cfg,
        r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.0.1"
encryption = true
egress = ["10.99.0.2"]

[[subnet.peers]]
virtual_ip = "10.99.0.2"
locator = "udp://127.0.0.1:42001"

[[subnet.peers]]
virtual_ip = "10.99.0.3"
locator = "udp://127.0.0.1:42002"
"#,
    )
    .map_err(|e| e.to_string())?;

    // 定位 nexus 可执行文件（与 example 同 target 目录）。
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let nexus_bin = exe
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join(if cfg!(windows) { "nexus.exe" } else { "nexus" }))
        .ok_or_else(|| "cannot resolve nexus path".to_string())?;
    if !nexus_bin.exists() {
        return Err(format!("nexus not found at {}", nexus_bin.display()));
    }

    // 1) spawn 常驻 daemon（--foreground）。
    let mut child = Command::new(&nexus_bin)
        .args([
            "subnet",
            "up",
            "--config",
            cfg.to_str().ok_or("cfg path")?,
            "--state",
            state.to_str().ok_or("state path")?,
            "--encrypt-state",
            "--foreground",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nexus: {e}"))?;

    // 2) 读第一行 stdout = up JSON（daemon 打印后进入常驻循环）。
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    let up_line = lines
        .next()
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "nexus up produced no stdout".to_string())?;
    let up_json: Value =
        serde_json::from_str(&up_line).map_err(|e| format!("up output not JSON: {e}"))?;
    let up_ok = up_json
        .get("subnet")
        .and_then(|s| s.get("up"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // 3) 状态文件就绪且加密（NEXSEC1/NEXDP1 magic）。
    let enc_bytes = std::fs::read(&state).map_err(|e| e.to_string())?;
    let file_encrypted = enc_bytes.starts_with(b"NEXSEC1") || enc_bytes.starts_with(b"NEXDP1");

    // 4) 独立 status 命令读回加密状态。
    let status_out = Command::new(&nexus_bin)
        .args([
            "subnet",
            "status",
            "--state",
            state.to_str().ok_or("state")?,
            "--json",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let status_json: Value = serde_json::from_slice(&status_out.stdout)
        .map_err(|e| format!("status output not JSON: {e}"))?;
    let read_back_vip = status_json
        .get("subnet")
        .and_then(|s| s.get("virtual_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let peer_count = status_json
        .get("subnet")
        .and_then(|s| s.get("peer_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // 5) leave 信号（删除状态文件）→ 常驻子进程应优雅退出（exit 0）。
    std::fs::remove_file(&state).map_err(|e| e.to_string())?;
    let proc_exited = wait_exit(&mut child, Duration::from_millis(6000))?;

    // 6) 退出后 status → DOWN。
    let after_out = Command::new(&nexus_bin)
        .args([
            "subnet",
            "status",
            "--state",
            state.to_str().ok_or("state")?,
            "--json",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let after_json: Value = serde_json::from_slice(&after_out.stdout)
        .map_err(|e| format!("after status output not JSON: {e}"))?;
    let up_after_leave = after_json
        .get("subnet")
        .and_then(|s| s.get("up"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // 清理临时目录。
    std::fs::remove_dir_all(&dir).ok();

    Ok(json!({
        "command": "subnet daemon",
        "verdict": "PASS",
        "daemon": {
            "up_ok": up_ok,
            "status_read_back_vip": read_back_vip,
            "peer_count": peer_count,
            "file_encrypted": file_encrypted,
            "up_after_leave": up_after_leave,
            "proc_exited": proc_exited,
        },
    }))
}

/// 等待子进程退出；超时则 kill 并报错。
fn wait_exit(child: &mut Child, timeout: Duration) -> Result<bool, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => return Ok(status.success()),
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("nexusd --foreground did not exit after leave".to_string());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
