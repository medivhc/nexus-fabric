//! E4 产品场景 product.proxy-trojan-fallback-rejected 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_trojan_fallback_flow -- --json
//! ```
//!
//! loopback 127.0.0.1 同一进程内起：
//! - 本地 HTTP 404 服务（模拟 sing-box fallback 目标，`interop-404-body`）；
//! - 本地 trojan TLS 节点：密码与产品配置**不一致**时把连接（含已读的 56B 头）
//!   交给 404 服务，把 404 响应原样回给客户端——与 sing-box 1.13.16 的 fallback
//!   缓存回塞行为同构；
//! - nexus proxy 数据面（outbound=trojan 指向该节点）+ 原始 SOCKS5 客户端。
//!
//! 断言（spec AC-1 的本地形态）：
//! 1. 客户端在收到任何隧道载荷前观察到失败：CONNECT 应答 `REP != 0x00`，或应答前 EOF；
//! 2. 失败后 500ms 内读到 EOF，且 EOF 前隧道字节数 = 0（404 页面绝不上交）；
//! 3. 404 服务确实被访问（参照端真的走了 fallback 路径）；
//! 4. 失败 reason 使用 §6 固定前缀 `trojan fallback signature detected`。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nexus::proxy_serve_once;
use nexus_outbound_trojan::{generate_loopback_identity, parse_request, server_config};

/// 产品侧配置的密码（与节点期望**不同** => 节点走 fallback）。
const PRODUCT_PASSWORD: &str = "wrong-password";
/// 节点期望的密码。
const NODE_PASSWORD: &str = "right-password";

const NOT_FOUND_BODY: &str = "interop-404-body";

/// 读满 trojan 头（第二个 CRLF），返回 (header, 头部之后的剩余字节)。
fn read_header<R: Read>(tls: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(128);
    let mut one = [0u8; 1];
    loop {
        tls.read_exact(&mut one)
            .map_err(|e| format!("header: {e}"))?;
        buf.push(one[0]);
        if buf.windows(2).filter(|w| **w == *b"\r\n").count() >= 2 {
            return Ok((buf, Vec::new()));
        }
        if buf.len() > 4096 {
            return Err("header too large".into());
        }
    }
}

fn main() {
    let _as_json = std::env::args().skip(1).any(|a| a == "--json");

    // ---- 本地 HTTP 404 fallback 目标 ----
    let fallback_listener = TcpListener::bind("127.0.0.1:0").expect("bind fallback");
    let fallback_addr = fallback_listener.local_addr().expect("fallback addr");
    fallback_listener
        .set_nonblocking(true)
        .expect("nonblocking");
    let (fallback_tx, fallback_rx) = mpsc::channel::<()>();
    let fallback_thread = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut conn = None;
        while Instant::now() < deadline {
            match fallback_listener.accept() {
                Ok((c, _)) => {
                    conn = Some(c);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(format!("fallback accept: {e}")),
            }
        }
        let Some(mut c) = conn else {
            return Ok(());
        };
        c.set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| e.to_string())?;
        // 参照端 fallback 目标不校验请求行：读到一点（或超时）就回 404。
        let mut sink = [0u8; 1024];
        let _ = c.read(&mut sink);
        let body = NOT_FOUND_BODY.as_bytes();
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        c.write_all(response.as_bytes())
            .map_err(|e| e.to_string())?;
        c.write_all(body).map_err(|e| e.to_string())?;
        let _ = c.flush();
        let _ = fallback_tx.send(());
        Ok(())
    });

    // ---- 本地 trojan 节点：错密码 => 转交 fallback ----
    let identity = generate_loopback_identity().expect("identity");
    let srv_cfg = Arc::new(server_config(&identity).expect("server config"));
    let node_listener = TcpListener::bind("127.0.0.1:0").expect("bind node");
    let node_addr = node_listener.local_addr().expect("node addr");
    node_listener.set_nonblocking(true).expect("nonblocking");
    let node_thread = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tcp = None;
        while Instant::now() < deadline {
            match node_listener.accept() {
                Ok((c, _)) => {
                    tcp = Some(c);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(format!("node accept: {e}")),
            }
        }
        let Some(tcp) = tcp else {
            return Ok(());
        };
        tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
        let mut srv = rustls::ServerConnection::new(Arc::clone(&srv_cfg))
            .map_err(|e| format!("tls server conn: {e}"))?;
        let mut tcp = tcp;
        let mut tls = rustls::Stream::new(&mut srv, &mut tcp);
        let (header, _rest) = read_header(&mut tls)?;
        if parse_request(NODE_PASSWORD, &header).is_ok() {
            return Err("test setup error: node accepted the product password".into());
        }
        // 与 sing-box 一致：把已读字节塞回流后交给 fallback 目标。
        let mut fb = TcpStream::connect(fallback_addr).map_err(|e| e.to_string())?;
        fb.write_all(&header).map_err(|e| e.to_string())?;
        fb.set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        let mut back = Vec::new();
        fb.read_to_end(&mut back).map_err(|e| e.to_string())?;
        tls.write_all(&back).map_err(|e| e.to_string())?;
        let _ = tls.flush();
        Ok(())
    });

    // ---- 产品 proxy（一个会话）----
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
            "    locator: \"127.0.0.1:{0}\"\n",
            "    password: {1}\n",
            "    skip_cert_verify: true\n",
            "    header_format: standard\n",
        ),
        node_addr.port(),
        PRODUCT_PASSWORD
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_thread = thread::spawn(move || proxy_serve_once(&proxy_listener, &config));

    // ---- 原始 SOCKS5 客户端：CONNECT 后观察失败形态与隧道字节 ----
    let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut greeting_ok = false;
    if client.write_all(&[0x05, 0x01, 0x00]).is_ok() {
        let mut reply = [0u8; 2];
        greeting_ok = client.read_exact(&mut reply).is_ok() && reply == [0x05, 0x00];
    }
    // 目标任意（节点不接受凭据，目标不会被真正连接）。
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&26200u16.to_be_bytes());
    let mut reply = [0u8; 10];
    let mut reply_len = 0usize;
    let connect_ok = if client.write_all(&req).is_ok() {
        match client.read_exact(&mut reply) {
            Ok(()) => {
                reply_len = 10;
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };

    let rep = if reply_len >= 2 { Some(reply[1]) } else { None };
    let eof_before_reply = !connect_ok;
    let refused = rep.is_some_and(|r| r != 0x00) || eof_before_reply;

    // EOF-drain（spec AC-1.2）：t_fail 起以单次 500ms 读超时循环读到 EOF。
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let t_fail = Instant::now();
    let mut tunnel_bytes = 0usize;
    let mut eof = false;
    loop {
        let mut buf = [0u8; 4096];
        match client.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => tunnel_bytes += n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => {
                eof = true;
                break;
            }
        }
        if t_fail.elapsed() > Duration::from_millis(2000) {
            break;
        }
    }
    let eof_ms = t_fail.elapsed().as_millis() as u64;

    let fallback_visited = fallback_rx.recv_timeout(Duration::from_secs(3)).is_ok();
    let node_result = node_thread.join();
    let _ = fallback_thread.join();
    // 产品会话：失败是 Err（reason 里必须带 §6 固定前缀）。
    let (session_json, session_error) = match proxy_thread.join() {
        Ok(Ok(json)) => (Some(json), None),
        Ok(Err(e)) => (None, Some(e.to_string())),
        Err(_) => (None, Some("proxy thread panicked".to_string())),
    };
    let failure_prefix_ok = session_error
        .as_deref()
        .is_some_and(|r| r.contains("trojan fallback signature detected"));

    let verdict = if refused
        && tunnel_bytes == 0
        && eof
        && eof_ms <= 500
        && fallback_visited
        && greeting_ok
        && node_result.is_ok()
        && session_error.is_some()
        && failure_prefix_ok
    {
        "PASS"
    } else {
        "FAIL"
    };

    println!(
        "{}",
        serde_json::json!({
            "verdict": verdict,
            "inbound": {"kind": "socks5"},
            "client": {
                "greeting_ok": greeting_ok,
                "refused_before_tunnel": refused,
                "socks5_rep": rep,
                "eof_before_reply": eof_before_reply,
                "tunnel_bytes": tunnel_bytes,
                "eof_within_500ms": eof && eof_ms <= 500,
                "eof_after_fail_ms": eof_ms,
            },
            "fallback": {
                "visited": fallback_visited,
                "status_line": "HTTP/1.1 404 Not Found",
                "body_bytes": NOT_FOUND_BODY.len(),
            },
            "proxy_session": session_json,
            "session_error": session_error,
            "error_prefix_ok": failure_prefix_ok,
        })
    );
}
