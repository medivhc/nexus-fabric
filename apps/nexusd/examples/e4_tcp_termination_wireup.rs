//! TCP 终结接线 E4：真实 TUN + 真实内核 TCP 栈全流程。
//!
//! 场景 `scenarios/product/tcp_termination_wireup.toml` T1 的可执行验证：
//! - 创建真实 TUN（nexus0，10.200.0.1/24），dataplane 终结 TCP；
//! - 内核 TCP 栈 `TcpStream::connect(10.200.0.5:80)` → 终结器完成握手；
//! - 发送数据 → STREAM DATA 帧被捕获 N1Sender 收到；
//! - 关闭 → STREAM FIN；
//! - 输出 JSON verdict。
//!
//! 运行（需 root / cap_net_admin）：
//!   sudo -E ./e4_tcp_termination_wireup
//! 清理：TUN 设备随进程退出自动删除；路由需手动确认（见输出）。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_projection::TunDevice;
use nexus_projection::tun_rs_device::TunRsDevice;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use serde_json::json;

/// 捕获的 STREAM 帧（目标地址，原始包）。
type CapturedFrames = Vec<(Ipv4Addr, Vec<u8>)>;

/// 捕获 N1Sender：记录 STREAM 帧（E4 验证 S4/S5/S6）。
struct CaptureSender {
    frames: Arc<Mutex<CapturedFrames>>,
}

impl nexus_network::n1::bridge::N1Sender for CaptureSender {
    fn send_to_mesh(&self, dst: Ipv4Addr, packet: &[u8]) -> Result<(), nexus_network::n1::N1Error> {
        self.frames.lock().unwrap().push((dst, packet.to_vec()));
        Ok(())
    }
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
}

fn run() -> serde_json::Value {
    // 1. 创建真实 TUN。
    let tun: Box<dyn TunDevice> = match TunRsDevice::create("nexus%d", 1500) {
        Ok(dev) => Box::new(dev),
        Err(e) => {
            return json!({"verdict": "FAIL", "error": format!("tun create failed: {e}")});
        }
    };
    let tun_name = tun.name().to_string();
    eprintln!("[e4] TUN created: {tun_name}");

    // 2. 配置 IP + 路由（需 root）。
    if let Err(e) = setup_net(&tun_name) {
        return json!({"verdict": "FAIL", "error": format!("net setup failed: {e}")});
    }
    eprintln!("[e4] net setup done");

    // 3. Dataplane（mesh 10.200.0.0/24，N1 捕获）。
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".to_string()],
        bypass_cidrs: vec![],
        dns_enabled: false,
        dns_config: None,
        qos_enabled: false,
        qos_config: Default::default(),
        boost_enabled: false,
        n1_configured: true,
        proxy_configured: false,
        ..Default::default()
    };
    let mut dp = match Dataplane::new(tun, config) {
        Ok(dp) => dp,
        Err(e) => {
            return json!({"verdict": "FAIL", "error": format!("dataplane init failed: {e}")});
        }
    };
    let frames = Arc::new(Mutex::new(Vec::new()));
    dp.set_n1_sender(Arc::new(CaptureSender {
        frames: Arc::clone(&frames),
    }));
    let stats_handle = dp.stats_handle();

    // 4. dataplane 循环线程。
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let pump = std::thread::spawn(move || {
        let mut dp = dp;
        let mut processed = 0u64;
        while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
            match dp.process_one() {
                Ok(true) => {
                    processed += 1;
                    if processed <= 5 {
                        eprintln!("[e4] pump processed packet #{processed}");
                    }
                }
                Ok(false) => std::thread::sleep(Duration::from_millis(1)),
                Err(_) => break,
            }
        }
        eprintln!("[e4] pump done, processed={processed}");
        dp.stats()
    });

    // 5. 内核 TCP 连接 10.200.0.5:80（经 nexus0 路由）。
    let target = SocketAddr::from(([10, 200, 0, 5], 80));
    eprintln!("[e4] connecting to {target}...");
    let t0 = Instant::now();
    let mut stream = match TcpStream::connect_timeout(&target, Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            return json!({"verdict": "FAIL", "error": format!("connect failed: {e}")});
        }
    };
    eprintln!("[e4] connected!");
    let connect_ms = t0.elapsed().as_millis();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // 6. 发送数据。
    if let Err(e) = stream.write_all(b"hello-e4") {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        return json!({"verdict": "FAIL", "error": format!("write failed: {e}")});
    }
    // 等待 Data 事件被处理。
    std::thread::sleep(Duration::from_millis(500));

    // 7. 关闭（FIN）。
    drop(stream);
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let stats = pump.join().unwrap_or_default();
    let frames = frames.lock().unwrap();

    // 8. 断言（S4/S5/S6/S10）。
    let mut checks = vec![];
    let mut ok = true;
    let mut check = |name: &str, cond: bool| {
        checks.push(json!({"name": name, "pass": cond}));
        if !cond {
            ok = false;
        }
    };
    check("tcp_handshakes==1", stats.tcp_handshakes == 1);
    check("mesh_tcp_bytes==8", stats.mesh_tcp_bytes == 8);
    check("frames>=3 (SYN+DATA+FIN)", frames.len() >= 3);
    check("tun_written>0 (SYN-ACK)", stats.tun_written > 0);

    // 清理路由（TUN 设备随进程退出自动删除）。
    let _ = cleanup_net(&tun_name);

    json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "connect_ms": connect_ms,
        "stats": {
            "tcp_handshakes": stats.tcp_handshakes,
            "mesh_tcp_frames": stats.mesh_tcp_frames,
            "mesh_tcp_bytes": stats.mesh_tcp_bytes,
            "tun_written": stats.tun_written,
            "mesh_dropped_no_n1": stats.mesh_dropped_no_n1,
        },
        "frames_captured": frames.len(),
        "checks": checks,
        "stats_handle_used": stats_handle.lock().is_ok(),
    })
}

/// 配置 TUN IP + 路由（10.200.0.0/24 走 TUN）。
///
/// 使用 `sudo -n ip`（xc-pc-linux 已配置 NOPASSWD）。
fn setup_net(tun_name: &str) -> Result<(), String> {
    let sudo_ip = |args: &[&str]| -> Result<(), String> {
        let out = std::process::Command::new("sudo")
            .arg("-n")
            .arg("ip")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    };
    sudo_ip(&["addr", "add", "10.200.0.1/24", "dev", tun_name])?;
    sudo_ip(&["link", "set", tun_name, "up"])?;
    // 10.200.0.0/24 直连路由（dev 路由，内核自动添加；显式确认）。
    Ok(())
}

fn cleanup_net(tun_name: &str) -> Result<(), String> {
    let _ = std::process::Command::new("sudo")
        .arg("-n")
        .arg("ip")
        .args(["addr", "del", "10.200.0.1/24", "dev", tun_name])
        .output();
    Ok(())
}

#[allow(dead_code)]
fn _read_unused(_s: &mut TcpStream) {
    let mut buf = [0u8; 1024];
    let _ = _s.read(&mut buf);
}
