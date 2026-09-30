//! 最小 fabric IP 变更测试：无 N1、无 watcher，只有 fabric dial + rebind。
//! 验证 fabric (QUIC) 本身是否处理 IP 变更。

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, PeerId};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const UNDERLAY_A: &str = "10.200.0.1";
const UNDERLAY_B: &str = "10.200.0.2";
const UNDERLAY_B_NEW: &str = "10.200.0.3";
const PORT: u16 = 19200;

fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("/usr/bin/ip")
        .args(args)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("ip {} failed", args.join(" ")))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "child_a" => child_a(),
            "child_b" => child_b(),
            _ => {}
        }
        return;
    }
    parent();
}

fn parent() {
    ip(&["link", "add", "veth-xa", "type", "veth", "peer", "name", "veth-xb"]).expect("veth");
    let mut ca = Command::new(std::env::current_exe().unwrap())
        .arg("child_a").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("a");
    let mut cb = Command::new(std::env::current_exe().unwrap())
        .arg("child_b").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("b");
    let (pa, pb) = (ca.id(), cb.id());
    std::thread::sleep(Duration::from_millis(500));
    ip(&["link", "set", "veth-xa", "netns", &pa.to_string()]).expect("mova");
    ip(&["link", "set", "veth-xb", "netns", &pb.to_string()]).expect("movb");
    
    let _ain = ca.stdin.take().unwrap();
    let mut bin = cb.stdin.take().unwrap();
    let mut aout = BufReader::new(ca.stdout.take().unwrap());
    let mut bout = BufReader::new(cb.stdout.take().unwrap());
    let mut line = String::new();
    
    aout.read_line(&mut line).expect("A listen");
    let peer_hex = line.trim().strip_prefix("LISTEN ").unwrap().to_string();
    println!("A up, peer {}...", &peer_hex[..8]);
    line.clear();
    bin.write_all(format!("DIAL {peer_hex}\n").as_bytes()).unwrap();
    bin.flush().unwrap();
    line.clear();
    bout.read_line(&mut line).expect("B dial");
    println!("B: {}", line.trim());
    
    // B 发数据，A 收
    line.clear();
    bin.write_all(b"GO\n").unwrap();
    bin.flush().unwrap();
    line.clear();
    bout.read_line(&mut line).expect("B go");
    println!("B: {}", line.trim());
    line.clear();
    aout.read_line(&mut line).expect("A recv1");
    println!("A: {}", line.trim());
    
    // ROAM: B 改 IP + rebind
    line.clear();
    bin.write_all(b"ROAM\n").unwrap();
    bin.flush().unwrap();
    line.clear();
    bout.read_line(&mut line).expect("B roam");
    println!("B: {}", line.trim());
    
    // B 继续发，A 收
    line.clear();
    bin.write_all(b"GO2\n").unwrap();
    bin.flush().unwrap();
    line.clear();
    bout.read_line(&mut line).expect("B go2");
    println!("B: {}", line.trim());
    assert!(line.contains("B_SENT2_NEWSTREAM"));
    line.clear();
    aout.read_line(&mut line).expect("A recv2");
    println!("A: {}", line.trim());
    
    if line.contains("RECV2_OK") {
        println!("RESULT: PASS - fabric handles IP change");
    } else {
        println!("RESULT: FAIL - {line}");
    }
    let _ = ca.kill();
    let _ = cb.kill();
    let _ = ip(&["link", "del", "veth-xa"]);
}

fn setup(veth: &str, ip_addr: &str) {
    unsafe extern "C" {
        fn unshare(flags: i32) -> i32;
    }
    unsafe { assert_eq!(unshare(0x40000000), 0); }
    std::thread::sleep(Duration::from_millis(1000));
    ip(&["link", "set", "lo", "up"]).expect("lo");
    ip(&["link", "set", veth, "up"]).expect("up");
    ip(&["addr", "add", &format!("{ip_addr}/24"), "dev", veth]).expect("addr");
}

fn child_a() {
    setup("veth-xa", UNDERLAY_A);
    let listener = FabricListener::bind(format!("{UNDERLAY_A}:{PORT}").parse().unwrap()).expect("bind");
    let hex: String = listener.peer_id().0.iter().map(|b| format!("{b:02x}")).collect();
    println!("LISTEN {hex}");
    std::io::stdout().flush().unwrap();
    let conn = listener.accept().expect("accept");
    let (_s, mut r) = conn.accept_bi().expect("accept_bi");
    let mut buf = [0u8; 1024];
    // 收第一批（旧流）
    let n = r.read(&mut buf).expect("read1");
    println!("A_RECV1: {} bytes: {}", n, String::from_utf8_lossy(&buf[..n]));
    std::io::stdout().flush().unwrap();
    // 收第二批（新流，roam 后 B 开新流）
    let (_s2, mut r2) = conn.accept_bi().expect("accept_bi2");
    let n2 = r2.read(&mut buf).expect("read2");
    println!("A_RECV2_OK: {} bytes", n2);
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(2));
}

fn child_b() {
    setup("veth-xb", UNDERLAY_B);
    let stdin = std::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let dial_line = lines.next().unwrap().unwrap();
    let peer_hex = dial_line.strip_prefix("DIAL ").unwrap();
    let mut bytes = [0u8; 32];
    for (i, c) in peer_hex.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap();
    }
    let peer = PeerId(bytes);
    
    // 显式绑定到 10.200.0.2
    let sock = std::net::UdpSocket::bind(format!("{UNDERLAY_B}:0")).expect("bind");
    let transport = nexus_fabric::StdUdpTransport(sock);
    let mut cfg = ConnConfig::default();
    cfg.addrs = vec![format!("{UNDERLAY_A}:{PORT}").parse().unwrap()];
    let conn = FabricConn::connect_with_transport(peer, &cfg, Box::new(transport)).expect("dial");
    println!("B_DIALED cid={}", conn.id().0);
    std::io::stdout().flush().unwrap();
    
    let (mut s, _r) = conn.open_bi().expect("open_bi");
    
    for cmd in lines {
        let cmd = cmd.unwrap();
        match cmd.trim() {
            "GO" => {
                s.write(b"hello1").expect("write1");
                println!("B_SENT1");
                std::io::stdout().flush().unwrap();
            }
            "ROAM" => {
                ip(&["addr", "del", &format!("{UNDERLAY_B}/24"), "dev", "veth-xb"]).expect("del");
                ip(&["addr", "add", &format!("{UNDERLAY_B_NEW}/24"), "dev", "veth-xb"]).expect("add");
                conn.rebind().expect("rebind");
                println!("B_REBOUND");
                std::io::stdout().flush().unwrap();
            }
            "GO2" => {
                // 开新流（模拟 N1 watcher 的行为），立即发送。
                let (mut s2, _r2) = conn.open_bi().expect("open_bi2");
                s2.write(b"hello2").expect("write2");
                println!("B_SENT2_NEWSTREAM");
                std::io::stdout().flush().unwrap();
            }
            _ => {}
        }
    }
}
