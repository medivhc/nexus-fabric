//! HTTP/混合代理入站 E4（PRODUCT §11.19）：本地 HTTP origin + Nexus 混合入站，
//! 同端口按首字节分流四种客户端：(i) HTTP 绝对形式 GET；(ii) CONNECT 隧道；
//! (iii) SOCKS5 握手；(iv) CONNECT 经 trojan 出站失败（fail-closed 502）。
//! 前三者经代理真实访问 loopback origin 并获得 HTTP 200（既有断言零放宽）；
//! 第四者只命中该失败会话的规则，trojan 出站 locator 指向已关闭的 loopback 端口，
//! 断言 `HTTP/1.1 502 Bad Gateway` 且 502 后的隧道字节 = 0（spec AC-11.2/11.3）。
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

    // 第四条会话的目标端口：先占位再释放 => 已关闭的 loopback 端口。
    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind closed");
    let fail_target_port = closed_listener.local_addr().expect("closed addr").port();
    drop(closed_listener);
    // trojan 出站的 locator 指向另一个同样已关闭的端口（TunnelConnectFailed）。
    let dead_node_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dead node");
    let dead_node_port = dead_node_listener.local_addr().expect("dead addr").port();
    drop(dead_node_listener);
    // 仅命中失败会话目标端口的规则 => 该端口走 trojan 出站，其余保持 direct。
    let trojan_fail_config = format!(
        concat!(
            "schema_version: 1\n",
            "inbounds:\n",
            "  - tag: socks5-in\n",
            "    kind: socks5\n",
            "    listen: 127.0.0.1:0\n",
            "rules:\n",
            "  - tag: trojan-fail\n",
            "    kind: dst_port\n",
            "    match: \"{0}\"\n",
            "    action:\n",
            "      - kind: select_outbound\n",
            "        tag: trojan-fail\n",
            "  - tag: rule-match\n",
            "    kind: match\n",
            "    match: \"\"\n",
            "    action:\n",
            "      - kind: select_outbound\n",
            "        tag: direct\n",
            "outbounds:\n",
            "  - tag: trojan-fail\n",
            "    kind: trojan\n",
            "    locator: \"127.0.0.1:{1}\"\n",
            "    password: mixed-inbound-fail-password\n",
            "    skip_cert_verify: true\n",
            "  - tag: direct\n",
            "    kind: direct\n",
        ),
        fail_target_port, dead_node_port
    );

    // 混合入站监听（同一端口，按首字节分流）。
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_clone = proxy_listener.try_clone().expect("clone listener");
    // 代理线程：依次 accept 4 个会话（forward GET / CONNECT 隧道 / SOCKS5 / 失败 CONNECT）。
    let proxy = std::thread::spawn(move || {
        let mut jsons = Vec::new();
        for i in 0..4 {
            let cfg = if i == 3 {
                trojan_fail_config.as_str()
            } else {
                nexus::DEFAULT_PROXY_CONFIG
            };
            jsons.push(proxy_serve_once(&proxy_clone, cfg));
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

    // ---- (iv) 同端口 CONNECT 经 trojan 出站失败：502 + 零隧道字节（AC-11）----
    let mut c4 = std::net::TcpStream::connect(proxy_addr).expect("c4 connect");
    c4.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("c4 timeout");
    let fail_target = format!("127.0.0.1:{fail_target_port}");
    c4.write_all(
        format!("CONNECT {fail_target} HTTP/1.1\r\nHost: {fail_target}\r\n\r\n").as_bytes(),
    )
    .expect("c4 write connect");
    let mut fail_resp = Vec::new();
    let mut again = [0u8; 1024];
    loop {
        match c4.read(&mut again) {
            Ok(0) => break,
            Ok(n) => {
                fail_resp.extend_from_slice(&again[..n]);
                if fail_resp.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let fail_reply = String::from_utf8_lossy(&fail_resp)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    // 502 之后的隧道字节必须为 0，且连接应在 500ms 内 EOF。
    c4.set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("c4 drain timeout");
    let mut fail_tunnel_bytes = 0usize;
    let mut fail_eof = false;
    loop {
        let mut buf = [0u8; 4096];
        match c4.read(&mut buf) {
            Ok(0) => {
                fail_eof = true;
                break;
            }
            Ok(n) => fail_tunnel_bytes += n,
            Err(_) => break,
        }
    }
    drop(c4);

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
                "http_connect_failure_reply": fail_reply,
                "http_connect_failure_tunnel_bytes": fail_tunnel_bytes,
                "http_connect_failure_eof": fail_eof,
            }),
        );
        if !(http_forward_ok
            && http_connect_tunnel_ok
            && socks5_ok
            && fail_reply == "HTTP/1.1 502 Bad Gateway"
            && fail_tunnel_bytes == 0
            && fail_eof)
        {
            obj.insert("verdict".into(), serde_json::json!("FAIL"));
        }
    }
    println!("{out}");
}
