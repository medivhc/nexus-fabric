//! E4: product.fabric-turn-relay
//!
//! TURN server S on 127.0.0.1:0；clients A/B 在 S 上分配中继地址。
//! B 经 `TurnSocket` 在 relay_b 上监听 QUIC；A 经 `TurnSocket` 拨号 relay_b。
//! A 开 QUIC bi 流发 N 字节，B 回显。PASS 要求往返完整 **且**
//! `S.stats().turn_relayed_bytes > 0`（流量真实经过 TURN 中继，非直连）。
//!
//! 沙箱 UDP `send_to` 被拦截（EPERM）时输出 `{"verdict":"SKIP"}`，exit 0。

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, UdpTransport};
use nexus_turn::{TurnClient, TurnCredentials, TurnServer, TurnSocket};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

const N: usize = 65536;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn creds() -> TurnCredentials {
    TurnCredentials {
        username: "nexus".into(),
        password: "turn-test".into(),
        realm: "nexus".into(),
    }
}

/// 沙箱拦截未连接 UDP socket 的 send_to（EPERM），但放行 connect+send；
/// 用裸 send_to 探测真实可用性。
fn udp_usable() -> bool {
    let probe = match UdpSocket::bind("127.0.0.1:0").and_then(|s| {
        let t = UdpSocket::bind("127.0.0.1:0")?;
        let ta = t.local_addr()?;
        match s.send_to(b"probe", ta) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
            Err(_) => Ok(false),
        }
    }) {
        Ok(v) => v,
        Err(_) => false,
    };
    probe
}

fn payload() -> Vec<u8> {
    (0..N as u32).map(|i| (i % 251) as u8).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let _json = args.iter().any(|a| a == "--json");
    if !udp_usable() {
        println!("{{\"verdict\":\"SKIP\",\"reason\":\"udp send_to not permitted (sandbox)\"}}");
        return;
    }
    let (json, pass) = match run() {
        Ok(x) => x,
        Err(e) => (
            format!("{{\"verdict\":\"FAIL\",\"detail\":\"{}\"}}", esc(&e)),
            false,
        ),
    };
    println!("{json}");
    if !pass {
        std::process::exit(1);
    }
}

fn run() -> Result<(String, bool), String> {
    // 1. TURN server.
    let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds())
        .map_err(|e| format!("server bind: {e}"))?;
    let saddr = server.main_addr();

    // 2. A/B 分配中继地址。
    let client_a = TurnClient::allocate(saddr, creds()).map_err(|e| format!("A allocate: {e}"))?;
    let client_b = TurnClient::allocate(saddr, creds()).map_err(|e| format!("B allocate: {e}"))?;
    let relay_a = client_a.relayed_addr();
    let relay_b = client_b.relayed_addr();
    if relay_a == relay_b {
        return Err("relay addresses must differ".into());
    }

    // 3. 权限：A→B 走 ChannelData（bind_channel），B→A 走 Send indication。
    client_a
        .create_permission(relay_b)
        .map_err(|e| format!("A permission: {e}"))?;
    client_b
        .create_permission(relay_a)
        .map_err(|e| format!("B permission: {e}"))?;
    let ch = client_a.bind_channel(relay_b);
    if !(0x4000..=0x7FFF).contains(&ch) {
        return Err(format!("bad channel {ch:#x}"));
    }

    // 4. B：经 TurnSocket 监听。
    // 注意：B 线程在 A 确认收完回显前不得退出——FabricConn drop 会 shutdown
    // driver 线程，若 echo 数据还在 app buffer 未 pump 进 QUIC 就会丢（无背压，
    // 见 SendStream 文档）。用 channel 做显式握手。
    let transport_b: Box<dyn UdpTransport> = Box::new(TurnSocket::new(client_b.clone()));
    let listener =
        FabricListener::bind_with_transport(transport_b).map_err(|e| format!("B listen: {e}"))?;
    let peer_b = listener.peer_id();

    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let server_thread = thread::spawn(move || -> Result<usize, String> {
        let conn = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let (mut send, mut recv) = conn.accept_bi().map_err(|e| format!("accept_bi: {e}"))?;
        let mut data = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = recv.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        let mut off = 0;
        while off < data.len() {
            off += send
                .write(&data[off..])
                .map_err(|e| format!("echo write: {e}"))?;
        }
        send.finish().map_err(|e| format!("echo finish: {e}"))?;
        // 等 A 确认收完后再退出，保持 driver 存活以 pump 完 echo。
        let _ = done_rx.recv();
        Ok(data.len())
    });

    // 5. A：经 TurnSocket 拨号 relay_b。
    let transport_a: Box<dyn UdpTransport> = Box::new(TurnSocket::new(client_a.clone()));
    let config = ConnConfig {
        addrs: vec![relay_b],
        handshake_timeout: Duration::from_secs(15),
    };
    let conn = FabricConn::connect_with_transport(peer_b, &config, transport_a)
        .map_err(|e| format!("A connect: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().map_err(|e| format!("open_bi: {e}"))?;
    let payload = payload();
    let mut off = 0;
    while off < payload.len() {
        off += send
            .write(&payload[off..])
            .map_err(|e| format!("write: {e}"))?;
    }
    send.finish().map_err(|e| format!("finish: {e}"))?;
    let mut echo = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = recv.read(&mut buf).map_err(|e| format!("echo read: {e}"))?;
        if n == 0 {
            break;
        }
        echo.extend_from_slice(&buf[..n]);
    }
    // 6. 断言（先通知 B 线程可以退出了，再 join，避免死锁）。
    let roundtrip_ok = echo == payload;
    let relayed_bytes = server.stats().relayed_bytes;
    let relayed_ok = relayed_bytes > 0;
    let pass = roundtrip_ok && relayed_ok;
    // 通知 B 线程退出（此时才允许 drop 连接）。
    let _ = done_tx.send(());
    let server_len = server_thread
        .join()
        .map_err(|_| "server thread panicked".to_string())?
        .map_err(|e| format!("server: {e}"))?;
    let pass = pass && server_len == N;
    let verdict = if pass { "PASS" } else { "FAIL" };
    let json = format!(
        "{{\"verdict\":\"{verdict}\",\"roundtrip_ok\":{roundtrip_ok},\"relayed_bytes\":{relayed_bytes},\"channel_a_to_b\":\"{ch:#x}\"}}"
    );
    Ok((json, pass))
}
