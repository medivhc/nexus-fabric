//! E4 产品场景 product.proxy-outbound-trojan-flow 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_trojan_flow -- --json
//! ```
//!
//! loopback 127.0.0.1 同一进程内起：echo 目标 + 本地 trojan TLS 节点（rcgen 自签证书，
//! 扮演订阅节点）+ nexus proxy 数据面（配置 outbound=trojan 指向本地节点）+ 原始
//! SOCKS5 客户端。客户端经 proxy 的 TLS+trojan 隧道访问 echo；断言 trojan 节点实际
//! 收到 TLS 连接、trojan 请求头目标送达、payload 经隧道往返、routing 选定 trojan-node
//! 且 outbound_kind=trojan。
//!
//! 离线、确定性；server/echo/proxy 任务用 std::thread 并 join 回收，不丢 JoinHandle。
//! 旧实现（trojan 仍走 ConnectivityEstablishmentFailed 兜底）下 proxy 直接返回结构化
//! 失败 -> 本 example 映射为 verdict=FAIL（Red Evidence）。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use nexus::proxy_serve_once;
use nexus_outbound_trojan::{generate_loopback_identity, parse_request, server_config};

const PASSWORD: &str = "demo";
const PAYLOAD: &[u8] = b"ping-via-trojan-tunnel";

/// 从 TLS stream 读到第二个 CRLF（trojan 请求头结束），返回头字节（含 CRLF）。
/// rustls 会把后续已解密 payload 缓存在连接内，后续 read 不会丢字节。
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

    // --- echo 目标：读满 PAYLOAD.len() 字节、原样回写 ---
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    // 非阻塞轮询 accept：旧实现下无人连接 echo，轮询超时后正常退出（不永久阻塞 join）。
    let echo_thread = thread::spawn(move || -> std::io::Result<()> {
        echo_listener.set_nonblocking(true)?;
        let mut conn = None;
        for _ in 0..15 {
            match echo_listener.accept() {
                Ok((c, _)) => {
                    conn = Some(c);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(e) => return Err(e),
            }
        }
        let Some(mut conn) = conn else {
            return Ok(());
        };
        let mut buf = vec![0u8; PAYLOAD.len()];
        conn.read_exact(&mut buf)?;
        conn.write_all(&buf)
    });

    // --- 自签证书 + 本地 trojan TLS 节点（扮演订阅节点，PRODUCT §11.9） ---
    // 非阻塞轮询 accept：旧实现（trojan 兜底失败）不会连接节点，轮询超时后正常返回
    // Err（不永久阻塞），由 example 映射为 node_connected=false -> verdict FAIL。
    let identity = generate_loopback_identity().expect("self-signed identity");
    let srv_cfg = Arc::new(server_config(&identity).expect("server config"));

    let node_listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan node");
    let node_addr = node_listener.local_addr().expect("node addr");
    // 节点监听在 127.0.0.1；locator 用 127.0.0.1 避免 localhost 优先解析到 ::1。
    // skip-cert-verify=true 下 SNI=IP 不影响握手（证书校验被跳过）。
    let node_locator = format!("127.0.0.1:{}", node_addr.port());
    let node_connected = Arc::new(AtomicBool::new(false));
    let node_connected_clone = Arc::clone(&node_connected);
    let node_thread = thread::spawn(move || -> Result<(String, u16), String> {
        node_listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        let mut cli = None;
        for _ in 0..10 {
            match node_listener.accept() {
                Ok((c, _)) => {
                    cli = Some(c);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(e) => return Err(format!("trojan node accept: {e}")),
            }
        }
        let mut tcp = cli.ok_or("no trojan node connection within window")?;
        // Windows: accepted socket inherits listener nonblocking; restore blocking for TLS/header IO.
        tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
        node_connected_clone.store(true, Ordering::SeqCst);

        // TLS 握手（服务端）
        let mut conn = rustls::ServerConnection::new(Arc::clone(&srv_cfg))
            .map_err(|e| format!("tls server conn: {e}"))?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        // trojan 请求头 -> 解析目标
        let header = read_trojan_header(&mut tls)?;
        let target = parse_request(PASSWORD, &header).map_err(|e| match e {
            nexus_outbound_trojan::TrojanError::AuthDenied => "AUTH_DENIED".to_string(),
            other => format!("{other:?}"),
        })?;

        // 真实 connect 到 loopback echo 目标
        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;

        // 读 payload（proxy 中继自 SOCKS5 client）-> 明文写给 echo
        let mut payload = vec![0u8; PAYLOAD.len()];
        tls.read_exact(&mut payload)
            .map_err(|e| format!("payload read: {e}"))?;
        echo.write_all(&payload).map_err(|e| e.to_string())?;

        // 读 echo 回显 -> 经 TLS 回写 client
        let mut back = vec![0u8; PAYLOAD.len()];
        echo.read_exact(&mut back).map_err(|e| e.to_string())?;
        tls.write_all(&back).map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;

        Ok((target.host_label(), target.port()))
    });

    // --- nexus proxy 数据面：outbound=trojan-node -> 本地 trojan 节点（§11.16） ---
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
    let proxy_thread = thread::spawn(move || proxy_serve_once(&proxy_clone, &config));

    // --- 原始 SOCKS5 客户端：NO-AUTH 问候 + CONNECT echo + payload + 回显比对 ---
    // 旧实现（trojan 兜底失败）下 proxy 发完 CONNECT 成功回复后即返回结构化失败、关闭
    // 连接；客户端后续读回显会失败 -> 映射为 roundtrip_ok=false（Red Evidence），不 panic。
    let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
    let auth_ok = client.write_all(&[0x05, 0x01, 0x00]).is_ok_and(|()| {
        let mut reply = [0u8; 2];
        client
            .read_exact(&mut reply)
            .is_ok_and(|()| reply == [0x05, 0x00])
    });

    let port = echo_addr.port();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&port.to_be_bytes());
    let connect_ok = client.write_all(&connect_req).is_ok_and(|()| {
        let mut connect_reply = [0u8; 10];
        client
            .read_exact(&mut connect_reply)
            .is_ok_and(|()| connect_reply[0] == 0x05 && connect_reply[1] == 0x00)
    });

    let roundtrip_ok = client.write_all(PAYLOAD).is_ok_and(|()| {
        let mut back = vec![0u8; PAYLOAD.len()];
        client
            .read_exact(&mut back)
            .is_ok_and(|()| back.as_slice() == PAYLOAD)
    });

    // 关闭客户端连接，让 proxy 数据面中继循环读到 EOF 后退出（否则 join 永久阻塞）。
    drop(client);

    // 旧实现下 proxy_serve_once 返回 ConnectivityEstablishmentFailed -> 映射为 FAIL。
    let proxy_result = proxy_thread.join().expect("join proxy");
    let mut out = match proxy_result {
        Ok(v) => v,
        Err(e) => {
            let reason = format!("{e:?}");
            serde_json::json!({
                "verdict": "FAIL",
                "outbound": { "kind": "trojan" },
                "routing": { "outbound_kind": "trojan" },
                "error": { "kind": "ConnectivityEstablishmentFailed", "reason": reason },
            })
        }
    };

    // trojan 节点线程允许超时退出（旧实现不会连接节点）；超时路径 target_delivered_ok 为 false。
    let node_res = node_thread.join().expect("join node");
    let (node_host, node_port) = match node_res {
        Ok((h, p)) => (h, p),
        Err(_) => (String::new(), 0),
    };
    echo_thread.join().expect("join echo").expect("echo once");

    if let Some(obj) = out.as_object_mut() {
        let target_delivered_ok = node_host == "127.0.0.1" && node_port == echo_addr.port();
        obj.insert(
            "client".into(),
            serde_json::json!({
                "auth_ok": auth_ok,
                "connect_ok": connect_ok,
                "payload_roundtrip_ok": roundtrip_ok,
            }),
        );
        obj.insert(
            "trojan_server".into(),
            serde_json::json!({
                "connected": node_connected.load(Ordering::SeqCst),
                "target_delivered_ok": target_delivered_ok,
            }),
        );
        let ok = auth_ok
            && connect_ok
            && roundtrip_ok
            && node_connected.load(Ordering::SeqCst)
            && target_delivered_ok;
        if !ok {
            obj.insert("verdict".into(), serde_json::json!("FAIL"));
        }
    }
    println!("{out}");
}
