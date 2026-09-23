//! 回归场景：trojan 出站中继终止语义（独立 Review 阻塞项）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_trojan_teardown -- --json
//! ```
//!
//! 构造"client 主动断开、节点保活且不发 close_notify"的情况：本地 trojan TLS 节点完成
//! TLS 握手并解析 trojan 请求头后，**保持连接不关闭**（不发 close_notify，不发 EOF）。
//! 原始 SOCKS5 客户端经 proxy 完成握手与 CONNECT 后立即 drop。若中继终止语义正确，
//! proxy_serve_once 应在有限时间内返回；通过 channel recv_timeout(5s) 判定。
//! 超时即视为中继挂起（FAIL），此时不再 join proxy 线程（避免测试进程被挂死）。
//! 离线、确定性。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nexus::proxy_serve_once;
use nexus_outbound_trojan::{generate_loopback_identity, parse_request, server_config};

const PASSWORD: &str = "demo";

/// 从 TLS stream 读到第二个 CRLF（trojan 请求头结束）。
fn read_trojan_header(
    tls: &mut rustls::Stream<'_, rustls::ServerConnection, TcpStream>,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(128);
    let mut one = [0u8; 1];
    loop {
        tls.read_exact(&mut one)
            .map_err(|e| format!("trojan header read: {e}"))?;
        buf.push(one[0]);
        let crlf_count = buf.windows(2).filter(|w| **w == *b"\r\n").count();
        if crlf_count >= 2 {
            break;
        }
        if buf.len() > 4096 {
            return Err("trojan header too large".to_string());
        }
    }
    Ok(buf)
}

fn main() {
    let _as_json = std::env::args().skip(1).any(|a| a == "--json");

    // 自签证书 + 本地 trojan 节点：握手、读请求头后**保活不关闭**。
    let identity = generate_loopback_identity().expect("self-signed identity");
    let srv_cfg = Arc::new(server_config(&identity).expect("server config"));

    let node_listener = TcpListener::bind("127.0.0.1:0").expect("bind node");
    let node_addr = node_listener.local_addr().expect("node addr");
    let node_locator = format!("127.0.0.1:{}", node_addr.port());

    // 节点线程：accept -> TLS 握手 -> 读请求头解析 -> 阻塞读（保活，不发 close_notify）。
    let node_thread = thread::spawn(move || -> Result<(), String> {
        let (mut tcp, _) = node_listener.accept().map_err(|e| e.to_string())?;
        tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
        let mut conn = rustls::ServerConnection::new(Arc::clone(&srv_cfg))
            .map_err(|e| format!("tls server conn: {e}"))?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let header = read_trojan_header(&mut tls)?;
        let _target = parse_request(PASSWORD, &header).map_err(|e| format!("{e:?}"))?;
        // 保活：阻塞读，模拟"节点不发 close_notify"。
        let mut sink = [0u8; 1024];
        let _ = tls.read(&mut sink);
        Ok(())
    });

    // proxy 数据面：outbound=trojan-node -> 本地保活节点。
    let config = format!(
        concat!(
            "schema_version: 1\n",
            "inbounds:\n",
            "  - tag: socks5-in\n",
            "    kind: socks5\n",
            "    listen: 127.0.0.1:0\n",
            "rules:\n",
            "  - tag: rule-match\n",
            "    kind: match\n",
            "    match: \"\"\n",
            "    action:\n",
            "      - kind: select_outbound\n",
            "        tag: trojan-node\n",
            "outbounds:\n",
            "  - tag: trojan-node\n",
            "    kind: trojan\n",
            "    locator: \"{0}\"\n",
            "    password: {1}\n",
            "    skip_cert_verify: true\n",
            "    header_format: standard\n",
        ),
        node_locator, PASSWORD
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_clone = proxy_listener.try_clone().expect("clone proxy");

    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let proxy_join = thread::spawn(move || {
        let _ = proxy_serve_once(&proxy_clone, &config);
        let _ = tx.send(());
    });

    // 原始 SOCKS5 客户端：握手 + CONNECT 到一个 loopback 端口，完成后立即 drop。
    // 所有读均带 2s 超时，避免在 proxy 行为异常时测试进程自身挂死。
    let target_port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind dummy target");
        l.local_addr().expect("dummy addr").port()
    };
    let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let mut auth_reply = [0u8; 2];
    let _ = client.write_all(&[0x05, 0x01, 0x00]);
    let auth_ok = client.read_exact(&mut auth_reply).is_ok();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&target_port.to_be_bytes());
    let mut connect_reply = [0u8; 10];
    let connect_ok = client
        .write_all(&connect_req)
        .is_ok_and(|()| client.read_exact(&mut connect_reply).is_ok());
    // 立即断开 client——节点保活不发 close_notify，proxy 必须自行终止中继。
    drop(client);

    // 5s 内 proxy 必须返回；否则视为中继挂起（回归失败）。
    let terminated = rx.recv_timeout(Duration::from_secs(5)).is_ok();
    // 不回收挂起的 proxy/node 线程，直接退出进程（进程退出即回收线程）。
    let out = serde_json::json!({
        "verdict": if terminated { "PASS" } else { "FAIL" },
        "teardown": {
            "auth_ok": auth_ok,
            "connect_ok": connect_ok,
            "client_disconnected": true,
            "node_kept_alive": true,
            "proxy_returned_within_5s": terminated,
        }
    });
    println!("{out}");
    let _ = node_thread;
    let _ = proxy_join;
}
