//! E4 产品场景 product.proxy-outbound-shadowsocks-flow 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_shadowsocks_flow -- --json
//! ```
//!
//! loopback 127.0.0.1 同一进程内起：echo 目标 + 本地 SS server（扮演订阅节点）+
//! nexus proxy 数据面（配置 outbound=shadowsocks 指向本地 SS server）+ 原始 SOCKS5 客户端。
//! 客户端经 proxy 的加密隧道访问 echo；断言 SS server 实际收到加密连接、
//! request header 目标送达、payload 经隧道往返、routing 选定 ss-node 且 outbound_kind=shadowsocks。
//! 离线、确定性；server/echo/proxy 任务用 std::thread 并 join 回收，不丢 JoinHandle。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use nexus::proxy_serve_once;
use nexus_outbound_shadowsocks::{Role, SsMethod, SsStream, SsTarget, parse_request};

const PASSWORD: &str = "demo";
const METHOD: SsMethod = SsMethod::Chacha20IetfPoly1305;
const PAYLOAD: &[u8] = b"ping-via-ss-tunnel";

/// 已收字节里 request header 的完整长度（不足返回 None）。
fn header_len(buf: &[u8]) -> Option<usize> {
    match *buf.first()? {
        0x01 => Some(7).filter(|need| buf.len() >= *need),
        0x03 => {
            let dlen = *buf.get(1)? as usize;
            let need = 2 + dlen + 2;
            (buf.len() >= need).then_some(need)
        }
        _ => Some(0),
    }
}

/// 流式读完 SS request header：返回 (target, header 之后剩余明文)。
fn read_request(sess: &mut SsStream, cli: &mut TcpStream) -> Result<(SsTarget, Vec<u8>), String> {
    let mut wire = [0u8; 4096];
    let mut plain = Vec::new();
    loop {
        if let Some(need) = header_len(&plain) {
            let target = parse_request(&plain[..need]).map_err(|e| format!("{e:?}"))?;
            return Ok((target, plain[need..].to_vec()));
        }
        let n = cli.read(&mut wire).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("eof before complete request header".into());
        }
        plain.extend(sess.open(&wire[..n]).map_err(|e| format!("{e:?}"))?);
    }
}

fn main() {
    // 场景总是输出 JSON（E4 断言消费）；示例同时支持显式 --json 参数。
    let _as_json = std::env::args().skip(1).any(|a| a == "--json");

    // --- echo 目标：读一次、原样回写 ---
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    let echo_thread = thread::spawn(move || -> std::io::Result<()> {
        let (mut conn, _) = echo_listener.accept()?;
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf)?;
        conn.write_all(&buf[..n])
    });

    // --- 本地 SS server（扮演订阅节点，PRODUCT §11.6.1 server 侧） ---
    // 非阻塞轮询 accept：旧实现（数据面直连）不会连接 SS server，轮询超时后正常返回
    // Err（不永久阻塞），由 example 映射为 server_connected=false -> verdict FAIL。
    let ss_listener = TcpListener::bind("127.0.0.1:0").expect("bind ss");
    let ss_addr = ss_listener.local_addr().expect("ss addr");
    let server_connected = Arc::new(AtomicBool::new(false));
    let server_connected_clone = Arc::clone(&server_connected);
    let ss_thread = thread::spawn(move || -> Result<(String, u16), String> {
        ss_listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        let mut cli = None;
        for _ in 0..10 {
            match ss_listener.accept() {
                Ok((c, _)) => {
                    cli = Some(c);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(e) => return Err(format!("ss accept: {e}")),
            }
        }
        let mut cli = cli.ok_or("no ss connection within window")?;
        server_connected_clone.store(true, Ordering::SeqCst);
        let mut sess =
            SsStream::new(PASSWORD, METHOD, Role::Server).map_err(|e| format!("{e:?}"))?;

        // 1) 流式读 request header（salt + 首 chunk 明文）-> 解析目标
        let (target, mut payload) = read_request(&mut sess, &mut cli)?;

        // 2) 真实 connect 到 loopback echo 目标
        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;

        // 3) 继续流式读到完整 payload，解密后明文写给 echo
        let mut wire = [0u8; 4096];
        while payload.len() < PAYLOAD.len() {
            let n = cli.read(&mut wire).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("eof before complete payload".into());
            }
            payload.extend(sess.open(&wire[..n]).map_err(|e| format!("{e:?}"))?);
        }
        echo.write_all(&payload[..PAYLOAD.len()])
            .map_err(|e| e.to_string())?;

        // 4) 读 echo 回显 -> seal 回写 client（服务端自己的 TX salt）
        let mut back = vec![0u8; PAYLOAD.len()];
        echo.read_exact(&mut back).map_err(|e| e.to_string())?;
        let reply = sess.seal(&back).map_err(|e| format!("{e:?}"))?;
        cli.write_all(&reply).map_err(|e| e.to_string())?;

        Ok((target.host_label(), target.port()))
    });

    // --- nexus proxy 数据面：outbound=ss-node -> 本地 SS server（§11.16） ---
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
            "        tag: ss-node\n",
            "outbounds:\n",
            "  - tag: ss-node\n",
            "    kind: shadowsocks\n",
            "    locator: \"{0}\"\n",
            "    method: chacha20-ietf-poly1305\n",
            "    password: {1}\n",
        ),
        ss_addr, PASSWORD
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_clone = proxy_listener.try_clone().expect("clone proxy");
    let proxy_thread = thread::spawn(move || proxy_serve_once(&proxy_clone, &config));

    // --- 原始 SOCKS5 客户端：NO-AUTH 问候 + CONNECT echo + payload + 回显比对 ---
    let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .expect("write greeting");
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).expect("read greeting reply");
    let auth_ok = reply == [0x05, 0x00];

    let port = echo_addr.port();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&port.to_be_bytes());
    client.write_all(&connect_req).expect("write connect");
    let mut connect_reply = [0u8; 10];
    client
        .read_exact(&mut connect_reply)
        .expect("read connect reply");
    let connect_ok = connect_reply[0] == 0x05 && connect_reply[1] == 0x00;

    client.write_all(PAYLOAD).expect("write payload");
    let mut back = vec![0u8; PAYLOAD.len()];
    client.read_exact(&mut back).expect("read echo");
    let roundtrip_ok = back.as_slice() == PAYLOAD;

    // 关闭客户端连接，让 proxy 数据面中继循环读到 EOF 后退出（否则 join 永久阻塞）。
    drop(client);

    let proxy_json = proxy_thread
        .join()
        .expect("join proxy")
        .expect("proxy once");
    // ss 线程允许超时退出（旧实现不会连接 SS server）；超时路径 target_delivered_ok 为 false。
    let ss_res = ss_thread.join().expect("join ss");
    let (ss_host, ss_port) = match ss_res {
        Ok((h, p)) => (h, p),
        Err(_) => (String::new(), 0),
    };
    echo_thread.join().expect("join echo").expect("echo once");

    let mut out = proxy_json;
    if let Some(obj) = out.as_object_mut() {
        let target_delivered_ok = ss_host == "127.0.0.1" && ss_port == echo_addr.port();
        obj.insert(
            "client".into(),
            serde_json::json!({
                "auth_ok": auth_ok,
                "connect_ok": connect_ok,
                "payload_roundtrip_ok": roundtrip_ok,
            }),
        );
        obj.insert(
            "ss_server".into(),
            serde_json::json!({
                "connected": server_connected.load(Ordering::SeqCst),
                "target_delivered_ok": target_delivered_ok,
            }),
        );
        let ok = auth_ok
            && connect_ok
            && roundtrip_ok
            && server_connected.load(Ordering::SeqCst)
            && target_delivered_ok;
        if !ok {
            obj.insert("verdict".into(), serde_json::json!("FAIL"));
        }
    }
    println!("{out}");
}
