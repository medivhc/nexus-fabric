//! P4.2 E4 驱动：CLI 层真实 UDP 打洞接线（PRODUCT §12.9.6）。
//!
//! 双端 loopback 闭环：
//! - resp 线程：真实 UDP carrier bind（pick_port 空闲 loopback 端口）→
//!   VirtualSubnetTunnel 接收循环（收 ph 自动回 pa，NAT 会话回程）；
//! - 主线程：spawn `nexus subnet punch 10.0.0.2 <resp_locator> --config <toml>
//!   --listen <cli_port> --attempts 30 --json`（真实 CLI 接线）→ 校验
//!   verdict=PASS + state=Connected + events 链（started 含 targets、
//!   succeeded 含目标）。
//!
//! 退出码 0 = verdict PASS；非 0 = FAIL。

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::mpsc;

use nexus_connectivity::virtual_subnet::{
    MemoryVpi, TunnelPeer, VirtualSubnetConfig, VirtualSubnetTunnel,
};
use nexus_platform::{PacketCarrier, UdpCarrier};

fn main() -> ExitCode {
    // ---------- 1. resp 侧：真实 UDP 监听 + 回 pa ----------
    let resp_port = pick_port();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut carrier = UdpCarrier::new();
        let bound = carrier
            .bind(&format!("udp://127.0.0.1:{resp_port}"))
            .expect("resp bind");
        tx.send(bound).expect("send bound");
        let mut tunnel = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(carrier),
        );
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.1", "udp://127.0.0.1:0"))
            .expect("resp add_peer");
        let mut buf = [0u8; 4096];
        for _ in 0..400 {
            match tunnel.recv_and_deliver(&mut buf) {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(_) => break,
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });
    let resp_locator = rx.recv().expect("recv resp bound");

    // ---------- 2. 发起侧：spawn CLI `subnet punch` ----------
    let cfg_dir = std::env::temp_dir().join("nexus-p426");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir cfg");
    let cfg_path = cfg_dir.join("punch-cli.toml");
    let cfg = format!(
        "[subnet]\n\
         virtual_ip = \"10.0.0.1\"\n\
         cidr = \"10.0.0.0/24\"\n\
         encryption = false\n\n\
         [[subnet.peers]]\n\
         virtual_ip = \"10.0.0.2\"\n\
         locator = \"{resp_locator}\"\n"
    );
    std::fs::write(&cfg_path, cfg).expect("write cfg");
    let state_path = cfg_dir.join("punch-cli.state.json");
    let _ = std::fs::remove_file(&state_path);

    let exe_path = std::env::current_exe().expect("current_exe");
    // example 二进制在 target/debug/examples/，nexus CLI 在 target/debug/。
    let bin_dir = exe_path
        .parent()
        .expect("exe parent")
        .parent()
        .expect("target dir")
        .to_path_buf();
    let cli = bin_dir.join(if cfg!(windows) { "nexus.exe" } else { "nexus" });
    // 先 `subnet up` 创建状态文件（打洞结果写入/复查依赖它）。
    let up = std::process::Command::new(&cli)
        .args(["subnet", "up", "--config"])
        .arg(&cfg_path)
        .args(["--state"])
        .arg(&state_path)
        .arg("--json")
        .output()
        .expect("spawn nexus subnet up");
    let up_v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&up.stdout).trim())
        .unwrap_or(serde_json::json!({ "verdict": "FAIL" }));
    if up_v["verdict"] != "PASS" {
        eprintln!("subnet up failed: {up_v}");
        println!(
            "{}",
            serde_json::json!({
                "verdict": "FAIL",
                "command": "subnet punch cli",
                "up": up_v,
            })
        );
        return ExitCode::from(1);
    }
    let cli_listen = format!("udp://127.0.0.1:{}", pick_port());
    let out = std::process::Command::new(&cli)
        .args(["subnet", "punch", "10.0.0.2", &resp_locator, "--config"])
        .arg(&cfg_path)
        .args(["--listen", &cli_listen, "--attempts", "30", "--state"])
        .arg(&state_path)
        .arg("--json")
        .output()
        .expect("spawn nexus subnet punch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        eprintln!(
            "JSON parse failed: {e}\nstdout={stdout}\nstderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::json!({ "verdict": "FAIL", "json_error": e.to_string() })
    });

    // ---------- 3. 判定 ----------
    let events_ok = parsed["events"]
        .as_array()
        .map(|evs| {
            evs.iter().any(|e| {
                e.as_str()
                    .map(|s| s.starts_with("started(") && s.contains(&resp_locator))
                    .unwrap_or(false)
            }) && evs.iter().any(|e| {
                e.as_str()
                    .map(|s| s.starts_with("succeeded(") && s.contains(&resp_locator))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    let punch_ok = parsed["verdict"] == "PASS"
        && parsed["state"] == "Connected"
        && parsed["locator"] == resp_locator
        && events_ok;

    // ---------- 4. `subnet status` 复查（observability 通道） ----------
    let status = std::process::Command::new(&cli)
        .args(["subnet", "status", "--json"])
        .arg("--state")
        .arg(&state_path)
        .output()
        .expect("spawn nexus subnet status");
    let status_v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&status.stdout).trim())
            .unwrap_or(serde_json::json!({ "verdict": "FAIL" }));
    let status_ok = status_v["verdict"] == "PASS"
        && status_v["subnet"]["punch"]["state"] == "Connected"
        && status_v["subnet"]["punch"]["succeeded"] == true;

    let out = serde_json::json!({
        "verdict": if punch_ok && status_ok { "PASS" } else { "FAIL" },
        "command": "subnet punch cli",
        "punch": serde_json::json!({
            "verdict": parsed["verdict"],
            "state": parsed["state"],
            "succeeded": punch_ok,
            "events_nonempty": parsed["events"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
        }),
        "status_recheck": status_v,
    });
    println!("{out}");
    if punch_ok && status_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// 系统分配一个空闲 loopback UDP 端口（std socket bind 0 → 取端口 → 释放；
/// 短竞态窗口内 UdpCarrier 再 bind，失败由外层重试/换端口兜底）。
fn pick_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("pick port");
    let port = s.local_addr().expect("local addr").port();
    drop(s);
    port
}
