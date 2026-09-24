//! HTTP/混合代理入站 E4（PRODUCT §11.19）：本地 HTTP origin + Nexus 混合入站，
//! 同端口按首字节分流三种客户端：(i) HTTP 绝对形式 GET；(ii) CONNECT 隧道；
//! (iii) SOCKS5 握手。三种均经代理真实访问 loopback origin 并获得 HTTP 200。
//!
//! 输出单个 JSON 对象（场景求值器要求）。

use nexus::proxy_serve_once;
use std::io::{Read, Write};

/// 读满整个响应（直到对端关闭），返回文本。
fn read_until_close(client: &mut std::net::TcpStream) -> String {
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&resp).into_owned()
}

fn main() {
    // 本地 HTTP origin：先取地址，再把 listener 移入服务线程。
    let origin_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let origin_addr = origin_listener.local_addr().expect("origin addr");
    let origin_port = origin_addr.port();
    let _origin = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut conn, _) = match origin_listener.accept() {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = conn.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            );
        }
    });

    // 混合入站监听（同一端口，按首字节分流）。
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_clone = proxy_listener.try_clone().expect("clone listener");
    // 代理线程：依次 accept 3 个会话（forward GET / CONNECT 隧道 / SOCKS5）。
    let proxy = std::thread::spawn(move || {
        let mut jsons = Vec::new();
        for _ in 0..3 {
            jsons.push(proxy_serve_once(&proxy_clone, nexus::DEFAULT_PROXY_CONFIG));
        }
        jsons
    });

    // ---- (i) HTTP 绝对形式 GET 经混合端口 ----
    let hostport = format!("127.0.0.1:{origin_port}");
    let mut c1 = std::net::TcpStream::connect(proxy_addr).expect("c1 connect");
    c1.write_all(
        format!(
            "GET http://{hostport}/path HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .expect("c1 write");
    let fwd_text = read_until_close(&mut c1);
    let http_forward_ok = fwd_text.contains("200 OK") && fwd_text.contains("hello");
    let http_forward_status = fwd_text.lines().next().unwrap_or("").to_string();
    drop(c1);

    // ---- (ii) CONNECT 隧道：先读 200 Connection Established，再隧道内 GET ----
    let mut c2 = std::net::TcpStream::connect(proxy_addr).expect("c2 connect");
    c2.write_all(format!("CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n\r\n").as_bytes())
        .expect("c2 write connect");
    // 读响应首行直到 \r\n\r\n。
    let mut handshake_resp = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = c2.read(&mut buf).expect("c2 handshake read");
        if n == 0 {
            break;
        }
        handshake_resp.extend_from_slice(&buf[..n]);
        if handshake_resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let connect_reply = String::from_utf8_lossy(&handshake_resp)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    c2.write_all(b"GET / HTTP/1.0\r\nHost: local\r\nConnection: close\r\n\r\n")
        .expect("c2 tunnel get");
    let tunnel_text = read_until_close(&mut c2);
    let http_connect_tunnel_ok = tunnel_text.contains("200 OK") && tunnel_text.contains("hello");
    drop(c2);

    // ---- (iii) 同端口 SOCKS5（mixed 共存零回归）----
    let mut c3 = std::net::TcpStream::connect(proxy_addr).expect("c3 connect");
    c3.write_all(&[0x05, 0x01, 0x00]).expect("c3 greeting");
    let mut greeting_reply = [0u8; 2];
    c3.read_exact(&mut greeting_reply)
        .expect("c3 greeting reply");
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&origin_port.to_be_bytes());
    c3.write_all(&connect_req).expect("c3 socks connect");
    let mut socks_reply = [0u8; 10];
    c3.read_exact(&mut socks_reply).expect("c3 socks reply");
    c3.write_all(b"GET / HTTP/1.0\r\nHost: local\r\nConnection: close\r\n\r\n")
        .expect("c3 get");
    let socks_text = read_until_close(&mut c3);
    let socks5_ok = greeting_reply == [0x05, 0x00]
        && socks_reply[1] == 0x00
        && socks_text.contains("200 OK")
        && socks_text.contains("hello");
    drop(c3);

    let jsons = proxy.join().expect("join proxy");
    // 最后一个会话（SOCKS5）的 routing/session 作为基准断言。
    let last = jsons[2].as_ref().expect("third session ok").clone();
    let mut out = last;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "client".into(),
            serde_json::json!({
                "http_forward_ok": http_forward_ok,
                "http_forward_status": http_forward_status,
                "http_connect_reply": connect_reply,
                "http_connect_tunnel_ok": http_connect_tunnel_ok,
                "socks5_ok": socks5_ok,
            }),
        );
        if !(http_forward_ok && http_connect_tunnel_ok && socks5_ok) {
            obj.insert("verdict".into(), serde_json::json!("FAIL"));
        }
    }
    println!("{out}");
}
