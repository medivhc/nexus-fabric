//! E4 产品场景 `product.daemon-tun-dataplane` 的可执行驱动（PRODUCT §12.38）。
//!
//! 由 `scenarios/product/daemon_tun_dataplane.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example daemon_tun_daemon -- --json
//! ```
//!
//! 进程内 spawn `nexusd subnet up --foreground --tun` 子进程，验证 daemon 常驻
//! 真实数据面（wintun/tun + UDP）的两条确定性路径：
//!
//! - **无权限 / 无驱动环境**（本机常态）：第一行 stdout 为结构化 `TUN_ERROR`，
//!   子进程自行退出（exit 0），不写状态文件，绝不静默降级回 mock 常驻。
//! - **管理员环境**：第一行 stdout 为 `PASS` 且含 `local_locator`；删状态文件
//!   触发 leave → 常驻子进程优雅退出 0 → status → DOWN。

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match daemon_tun_flow() {
        Ok(out) => {
            if as_json {
                println!("{out}");
            } else {
                println!("daemon tun flow OK: {out}");
            }
        }
        Err(err) => {
            eprintln!("daemon_tun_flow failed: {err}");
            std::process::exit(1);
        }
    }
}

/// P3.8 E4 闭环：daemon --tun 常驻真实数据面（失败结构化 / 成功 leave）。
fn daemon_tun_flow() -> Result<Value, String> {
    let dir = std::env::temp_dir().join(format!(
        "nexus-b3tun-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let cfg = dir.join("subnet.toml");
    let state = dir.join("subnet-state.json");
    // 与 subnet_daemon 同形配置，但不启用加密（数据面是本场景焦点；
    // 状态加密由 product.subnet-daemon 覆盖）。
    std::fs::write(
        &cfg,
        r#"[subnet]
cidr = "10.99.0.0/24"
virtual_ip = "10.99.0.1"
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

    // 定位 nexusd 可执行文件（与 example 同 target 目录）。
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let nexusd = exe
        .parent()
        .and_then(|p| p.parent())
        .map(|p| {
            p.join(if cfg!(windows) {
                "nexusd.exe"
            } else {
                "nexusd"
            })
        })
        .ok_or_else(|| "cannot resolve nexusd path".to_string())?;
    if !nexusd.exists() {
        return Err(format!("nexusd not found at {}", nexusd.display()));
    }

    // 1) spawn 常驻 daemon（--foreground --tun）。
    let mut child = Command::new(&nexusd)
        .args([
            "subnet",
            "up",
            "--config",
            cfg.to_str().ok_or("cfg path")?,
            "--state",
            state.to_str().ok_or("state path")?,
            "--foreground",
            "--tun",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nexusd: {e}"))?;

    // 2) 读第一行 stdout（成功 = up JSON；失败 = TUN_ERROR JSON）。
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    let first_line = lines
        .next()
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "nexusd --tun produced no stdout".to_string())?;
    let first_json: Value = serde_json::from_str(&first_line)
        .map_err(|e| format!("first output not JSON: {e}: {first_line}"))?;
    let verdict = first_json
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let verdict_ok: bool;
    let mut exited_ok = false;
    match verdict.as_str() {
        // 3a) 无权限 / 无驱动：TUN_ERROR 结构化，子进程应已退出，不写状态文件。
        "TUN_ERROR" => {
            exited_ok = wait_exit(&mut child, Duration::from_millis(4000))?;
            // 失败路径绝不写状态文件（也绝不降级 mock 常驻，否则子进程不会退出）。
            verdict_ok = exited_ok && !state.exists();
        }
        // 3b) 管理员环境：真实 up 含 local_locator；删状态文件触发 leave → 优雅退出。
        "PASS" => {
            let has_local_locator = first_json.get("local_locator").is_some();
            // 状态文件已写（up 成功路径）。
            let state_written = state.exists();
            std::fs::remove_file(&state).map_err(|e| e.to_string())?;
            exited_ok = wait_exit(&mut child, Duration::from_millis(6000))?;
            // 退出后 status → DOWN。
            let after_out = Command::new(&nexusd)
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
            verdict_ok = has_local_locator && state_written && exited_ok && !up_after_leave;
        }
        // 其它 verdict（FAIL / 未知）→ 不符合契约。
        _ => {
            // 兜底：确保子进程退出并清理。
            let _ = wait_exit(&mut child, Duration::from_millis(2000));
            verdict_ok = false;
        }
    }

    // 4) 兜底清理：任何分支都确保子进程已回收。
    match child.try_wait().map_err(|e| e.to_string())? {
        Some(_) => {}
        None => {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    // 5) 状态文件不得残留。
    let no_state_left = !state.exists();

    std::fs::remove_dir_all(&dir).ok();

    Ok(json!({
        "command": "daemon tun daemon",
        "verdict": if verdict_ok { "PASS" } else { "FAIL" },
        "daemon_tun": {
            "verdict_ok": verdict_ok,
            "exited_ok": exited_ok,
            "no_state_left": no_state_left,
            "first_verdict": verdict,
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
                    return Err("nexusd --tun --foreground did not exit in time".to_string());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
