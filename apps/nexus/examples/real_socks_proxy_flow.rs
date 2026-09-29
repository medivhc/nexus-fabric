//! 真实 SOCKS5 代理全链路 E4：本地 HTTP 目标 + 代理线程（握手 → 规则路由 →
//! Session → 真实出站 → 字节中继）+ 原始 SOCKS5 客户端（问候 / CONNECT / HTTP GET）。
//!
//! 输出单个 JSON 对象（场景求值器要求）。

use nexus::proxy_serve_once;
use std::io::{Read, Write};

fn main() {
    // 本地 HTTP 目标（等价于“代理出口可访问的公网服务”）。
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let http_addr = http_listener.local_addr().expect("http addr");
    let http = std::thread::spawn(move || {
        let (mut conn, _) = http_listener.accept().expect("http accept");
        let mut req = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = conn.read(&mut buf).expect("http read");
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let _ = conn
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    });

    // 代理线程（nexus 真实 SOCKS5 单会话闭环）。
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_clone = proxy_listener.try_clone().expect("clone proxy listener");
    let proxy =
        std::thread::spawn(move || proxy_serve_once(&proxy_clone, nexus::DEFAULT_PROXY_CONFIG));

    // 原始 SOCKS5 客户端：NO-AUTH 问候 + CONNECT 127.0.0.1:port + HTTP GET。
    let mut client = std::net::TcpStream::connect(proxy_addr).expect("connect proxy");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .expect("write greeting");
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).expect("read greeting reply");
    let auth_ok = reply == [0x05, 0x00];

    let port = http_addr.port();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&port.to_be_bytes());
    client.write_all(&connect_req).expect("write connect");
    let mut connect_reply = [0u8; 10];
    client
        .read_exact(&mut connect_reply)
        .expect("read connect reply");
    let connect_ok = connect_reply[0] == 0x05 && connect_reply[1] == 0x00;

    client
        .write_all(b"GET / HTTP/1.0\r\nHost: local\r\n\r\n")
        .expect("write http get");
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf).expect("read http response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|w| w == b"\r\n\r\n") && response.ends_with(b"hello") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&response).to_string();
    let http_ok = text.contains("200 OK") && text.contains("hello");
    let _ = client.shutdown(std::net::Shutdown::Both);

    let proxy_json = proxy
        .join()
        .expect("join proxy thread")
        .expect("proxy serve once");

    let mut out = proxy_json;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "client".into(),
            serde_json::json!({
                "auth_ok": auth_ok,
                "connect_ok": connect_ok,
                "http_ok": http_ok,
                "http_status_line": text.lines().next().unwrap_or(""),
            }),
        );
        if !(auth_ok && connect_ok && http_ok) {
            obj.insert("verdict".into(), serde_json::json!("FAIL"));
        }
    }
    let _ = http.join();
    println!("{out}");
}
