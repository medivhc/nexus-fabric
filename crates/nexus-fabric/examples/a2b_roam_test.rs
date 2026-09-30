//! 验证 A→B (server→client) 在 B rebind 后是否工作。
//! 如果 B→A 通但 A→B 不通，说明是 quinn-proto server 端发送路径迁移问题。

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, PeerId};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const UNDERLAY_A: &str = "10.200.0.1";
const UNDERLAY_B: &str = "10.200.0.2";
const UNDERLAY_B_NEW: &str = "10.200.0.3";
const PORT: u16 = 19201;

fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("/usr/bin/sudo").arg("-n").arg("/usr/bin/ip").args(args)
        .output().map_err(|e| format!("spawn: {e}"))?;
    if out.status.success() { Ok(()) } else { Err(format!("ip {} failed", args.join(" "))) }
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
    ip(&["link", "add", "veth-ya", "type", "veth", "peer", "name", "veth-yb"]).expect("veth");
    let mut ca = Command::new(std::env::current_exe().unwrap())
        .arg("child_a").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("a");
    let mut cb = Command::new(std::env::current_exe().unwrap())
        .arg("child_b").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("b");
    let (pa, pb) = (ca.id(), cb.id());
    std::thread::sleep(Duration::from_millis(500));
    ip(&["link", "set", "veth-ya", "netns", &pa.to_string()]).expect("mova");
    ip(&["link", "set", "veth-yb", "netns", &pb.to_string()]).expect("movb");
    
    let mut bin = cb.stdin.take().unwrap();
    let mut aout = BufReader::new(ca.stdout.take().unwrap());
    let mut bout = BufReader::new(cb.stdout.take().unwrap());
    let mut line = String::new();
    
    aout.read_line(&mut line).expect("A listen");
    let peer_hex = line.trim().strip_prefix("LISTEN ").unwrap().to_string();
    line.clear();
    bin.write_all(format!("DIAL {peer_hex}\n").as_bytes()).unwrap();
    bin.flush().unwrap();
    line.clear();
    bout.read_line(&mut line).expect("B dial");
    
    // B 发给 A (B→A, 应该通)
    line.clear();
    bin.write_all(b"GO_B2A\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B b2a");
    line.clear(); aout.read_line(&mut line).expect("A recv_b2a");
    println!("B→A: {}", line.trim());
    
    // ROAM
    line.clear();
    bin.write_all(b"ROAM\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B roam");
    
    // B 再发给 A (B→A roam 后, 应该通)
    line.clear();
    bin.write_all(b"GO_B2A2\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B b2a2");
    line.clear(); aout.read_line(&mut line).expect("A recv_b2a2");
    println!("B→A (roam后): {}", line.trim());
    
    // A 发给 B (A→B roam 后, 测试 server→client)
    line.clear();
    bin.write_all(b"GO_A2B\n").unwrap(); bin.flush().unwrap();
    // A 需要被通知发送，给 A 发指令
    // (A 的 stdin 还在 parent 手里吗？不，A 的 stdin 给了 parent 的 ain)
    // 简化：A 在收到 B2A2 后自动发 A2B
    line.clear(); bout.read_line(&mut line).expect("B recv_a2b");
    println!("A→B (roam后): {}", line.trim());
    
    if line.contains("A2B_OK") {
        println!("RESULT: PASS - A→B works after B roam");
    } else {
        println!("RESULT: FAIL - A→B broken: {}", line.trim());
    }
    let _ = ca.kill(); let _ = cb.kill();
    let _ = ip(&["link", "del", "veth-ya"]);
}

fn setup(veth: &str, ip_addr: &str) {
    unsafe extern "C" { fn unshare(flags: i32) -> i32; }
    unsafe { assert_eq!(unshare(0x40000000), 0); }
    std::thread::sleep(Duration::from_millis(1000));
    ip(&["link", "set", "lo", "up"]).expect("lo");
    ip(&["link", "set", veth, "up"]).expect("up");
    ip(&["addr", "add", &format!("{ip_addr}/24"), "dev", veth]).expect("addr");
}

fn child_a() {
    setup("veth-ya", UNDERLAY_A);
    let listener = FabricListener::bind(format!("{UNDERLAY_A}:{PORT}").parse().unwrap()).expect("bind");
    let hex: String = listener.peer_id().0.iter().map(|b| format!("{b:02x}")).collect();
    println!("LISTEN {hex}"); std::io::stdout().flush().unwrap();
    let conn = listener.accept().expect("accept");
    
    // 收 B→A (roam 前)
    let (_s1, mut r1) = conn.accept_bi().expect("accept1");
    let mut buf = [0u8; 1024];
    r1.read(&mut buf).expect("read1");
    println!("A_RECV_B2A_OK"); std::io::stdout().flush().unwrap();
    
    // 收 B→A (roam 后)
    let (_s2, mut r2) = conn.accept_bi().expect("accept2");
    r2.read(&mut buf).expect("read2");
    println!("A_RECV_B2A2_OK"); std::io::stdout().flush().unwrap();
    
    // A→B (roam 后)：A 主动开流发给 B
    std::thread::sleep(Duration::from_millis(500));
    let (mut s3, _r3) = conn.open_bi().expect("open3");
    s3.write(b"a2b-data").expect("write3");
    println!("A_SENT_A2B"); std::io::stdout().flush().unwrap();
    
    std::thread::sleep(Duration::from_secs(3));
}

fn child_b() {
    setup("veth-yb", UNDERLAY_B);
    let stdin = std::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let dial_line = lines.next().unwrap().unwrap();
    let peer_hex = dial_line.strip_prefix("DIAL ").unwrap();
    let mut bytes = [0u8; 32];
    for (i, c) in peer_hex.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap();
    }
    let peer = PeerId(bytes);
    
    let sock = std::net::UdpSocket::bind(format!("{UNDERLAY_B}:0")).expect("bind");
    let transport = nexus_fabric::StdUdpTransport(sock);
    let mut cfg = ConnConfig::default();
    cfg.addrs = vec![format!("{UNDERLAY_A}:{PORT}").parse().unwrap()];
    let conn = FabricConn::connect_with_transport(peer, &cfg, Box::new(transport)).expect("dial");
    println!("B_DIALED"); std::io::stdout().flush().unwrap();
    
    for cmd in lines {
        let cmd = cmd.unwrap();
        match cmd.trim() {
            "GO_B2A" => {
                let (mut s, _r) = conn.open_bi().expect("open");
                s.write(b"b2a").expect("w");
                println!("B_SENT_B2A"); std::io::stdout().flush().unwrap();
            }
            "ROAM" => {
                ip(&["addr", "del", &format!("{UNDERLAY_B}/24"), "dev", "veth-yb"]).expect("del");
                ip(&["addr", "add", &format!("{UNDERLAY_B_NEW}/24"), "dev", "veth-yb"]).expect("add");
                conn.rebind().expect("rebind");
                println!("B_REBOUND"); std::io::stdout().flush().unwrap();
            }
            "GO_B2A2" => {
                let (mut s, _r) = conn.open_bi().expect("open2");
                s.write(b"b2a2").expect("w2");
                println!("B_SENT_B2A2"); std::io::stdout().flush().unwrap();
            }
            "GO_A2B" => {
                // 等 A 发过来
                let (_s, mut r) = conn.accept_bi().expect("accept_a2b");
                let mut buf = [0u8; 1024];
                match r.read(&mut buf) {
                    Ok(n) => println!("B_RECV_A2B_OK: {n} bytes"),
                    Err(e) => println!("B_RECV_A2B_FAIL: {e:?}"),
                }
                std::io::stdout().flush().unwrap();
            }
            _ => {}
        }
    }
}
