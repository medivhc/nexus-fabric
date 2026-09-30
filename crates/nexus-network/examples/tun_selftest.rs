//! TUN 自检：隔离验证 内核→TUN 路径（不依赖 QUIC/泵）。
//!
//! unshare → lo up → 建 TUN → 配 IP → 读线程阻塞收 → 主线程 UDP 发包到 TUN 子网。
//! 期望：读线程收到 IP 包。

use nexus_platform::VirtualPacketInterface;
use nexus_platform_linux::TunVpi;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn ip(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("/usr/bin/ip")
        .args(args)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn main() {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    assert_eq!(ret, 0, "unshare failed");
    ip(&["link", "set", "lo", "up"]).unwrap();
    let tun = TunVpi::create("testtun0").expect("tun create");
    ip(&["addr", "add", "10.99.0.1/24", "dev", "testtun0"]).unwrap();
    ip(&["link", "set", "testtun0", "up"]).unwrap();
    // 看路由表。
    let out = std::process::Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/bin/ip", "route", "show"])
        .output()
        .unwrap();
    eprintln!("routes:\n{}", String::from_utf8_lossy(&out.stdout));

    let tun = Arc::new(Mutex::new(tun));
    let tun_c = Arc::clone(&tun);
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        let mut got = 0;
        let t0 = std::time::Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            let n = {
                let mut g = tun_c.lock().unwrap();
                match g.receive(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("receive err: {e}");
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                }
            };
            if n == 0 {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            got += 1;
            eprintln!("got packet len={n} first_bytes={:02x?}", &buf[..n.min(20)]);
            if got >= 3 {
                break;
            }
        }
        got
    });

    std::thread::sleep(Duration::from_millis(500));
    let sock = UdpSocket::bind("10.99.0.1:0").expect("bind");
    for i in 0..3 {
        let payload = format!("hello-{i}");
        sock.send_to(payload.as_bytes(), "10.99.0.2:1234")
            .expect("send_to");
        eprintln!("sent {payload}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let got = reader.join().unwrap();
    println!("{{\"verdict\":\"{}\",\"packets_received\":{got}}}", if got >= 3 {
        "PASS"
    } else {
        "FAIL"
    });
}
