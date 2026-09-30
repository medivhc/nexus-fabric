//! 验证 QUIC datagram 在 B rebind 后 A→B 是否工作。
//! N1 pump 用 datagram 传文件数据，如果 datagram 迁移有问题，E4 就卡死。

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, PeerId};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const UNDERLAY_A: &str = "10.200.0.1";
const UNDERLAY_B: &str = "10.200.0.2";
const UNDERLAY_B_NEW: &str = "10.200.0.3";
const PORT: u16 = 19202;

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
    ip(&["link", "add", "veth-za", "type", "veth", "peer", "name", "veth-zb"]).expect("veth");
    let mut ca = Command::new(std::env::current_exe().unwrap())
        .arg("child_a").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("a");
    let mut cb = Command::new(std::env::current_exe().unwrap())
        .arg("child_b").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn().expect("b");
    let (pa, pb) = (ca.id(), cb.id());
    std::thread::sleep(Duration::from_millis(500));
    ip(&["link", "set", "veth-za", "netns", &pa.to_string()]).expect("mova");
    ip(&["link", "set", "veth-zb", "netns", &pb.to_string()]).expect("movb");
    
    let mut bin = cb.stdin.take().unwrap();
    let mut aout = BufReader::new(ca.stdout.take().unwrap());
    let mut bout = BufReader::new(cb.stdout.take().unwrap());
    let mut line = String::new();
    
    aout.read_line(&mut line).expect("A listen");
    let peer_hex = line.trim().strip_prefix("LISTEN ").unwrap().to_string();
    line.clear();
    bin.write_all(format!("DIAL {peer_hex}\n").as_bytes()).unwrap();
    bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B dial");
    
    // B→A datagram (roam 前)
    line.clear(); bin.write_all(b"GO_B2A\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B b2a");
    line.clear(); aout.read_line(&mut line).expect("A recv");
    println!("B→A dgram: {}", line.trim());
    
    // ROAM
    line.clear(); bin.write_all(b"ROAM\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B roam");
    
    // B→A datagram (roam 后)
    line.clear(); bin.write_all(b"GO_B2A2\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B b2a2");
    line.clear(); aout.read_line(&mut line).expect("A recv2");
    println!("B→A dgram (roam后): {}", line.trim());
    
    // A→B datagram (roam 后)
    line.clear(); bin.write_all(b"GO_A2B\n").unwrap(); bin.flush().unwrap();
    line.clear(); bout.read_line(&mut line).expect("B recv_a2b");
    println!("A→B dgram (roam后): {}", line.trim());
    
    if line.contains("A2B_OK") {
        println!("RESULT: PASS - datagram A→B works");
    } else {
        println!("RESULT: FAIL - datagram A→B broken");
    }
    let _ = ca.kill(); let _ = cb.kill();
    let _ = ip(&["link", "del", "veth-za"]);
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
    setup("veth-za", UNDERLAY_A);
    let listener = FabricListener::bind(format!("{UNDERLAY_A}:{PORT}").parse().unwrap()).expect("bind");
    let hex: String = listener.peer_id().0.iter().map(|b| format!("{b:02x}")).collect();
    println!("LISTEN {hex}"); std::io::stdout().flush().unwrap();
    let conn = listener.accept().expect("accept");
    
    // 收 B→A datagram
    let d1 = conn.recv_datagram().expect("recv1");
    println!("A_RECV_DGRAM1: {}", String::from_utf8_lossy(&d1)); std::io::stdout().flush().unwrap();
    
    let d2 = conn.recv_datagram().expect("recv2");
    println!("A_RECV_DGRAM2: {}", String::from_utf8_lossy(&d2)); std::io::stdout().flush().unwrap();
    
    // A→B datagram (roam 后)
    std::thread::sleep(Duration::from_millis(500));
    conn.send_datagram(b"a2b-dgram").expect("send_a2b");
    println!("A_SENT_DGRAM"); std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(3));
}

fn child_b() {
    setup("veth-zb", UNDERLAY_B);
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
        match cmd.unwrap().trim() {
            "GO_B2A" => {
                conn.send_datagram(b"b2a").expect("s");
                println!("B_SENT_DGRAM1"); std::io::stdout().flush().unwrap();
            }
            "ROAM" => {
                ip(&["addr", "del", &format!("{UNDERLAY_B}/24"), "dev", "veth-zb"]).expect("del");
                ip(&["addr", "add", &format!("{UNDERLAY_B_NEW}/24"), "dev", "veth-zb"]).expect("add");
                conn.rebind().expect("rebind");
                // 触发迁移
                conn.send_datagram(b"migrate").expect("m");
                println!("B_REBOUND"); std::io::stdout().flush().unwrap();
            }
            "GO_B2A2" => {
                conn.send_datagram(b"b2a2").expect("s2");
                println!("B_SENT_DGRAM2"); std::io::stdout().flush().unwrap();
            }
            "GO_A2B" => {
                match conn.recv_datagram() {
                    Ok(d) => println!("B_RECV_A2B_OK: {}", String::from_utf8_lossy(&d)),
                    Err(e) => println!("B_RECV_A2B_FAIL: {e:?}"),
                }
                std::io::stdout().flush().unwrap();
            }
            _ => {}
        }
    }
}
