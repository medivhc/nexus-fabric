//! E4 产品场景 product.proxy-outbound-vless-flow 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_outbound_vless_flow -- --json
//! ```
//!
//! loopback 127.0.0.1 同一进程内起：echo 目标 + 本地 VLESS 明文节点（`tls: false`，
//! 扮演订阅节点）+ nexus proxy 数据面（配置 outbound=vless 指向本地节点）+ 原始
//! SOCKS5 客户端。客户端经 proxy 的 VLESS 隧道访问 echo；断言 VLESS 节点实际收到
//! 连接、请求头目标送达、payload 经隧道往返、routing 选定 vless-node 且
//! outbound_kind=vless。
//!
//! 明文路径（`tls: false`）：TCP 直连后只交换 VLESS 请求头（UUID + flow addon +
//! TCP 命令 + 目标地址）与响应头（version 0 + 空 addon），随后双向透明中继。
//!
//! 离线、确定性；server/echo/proxy 任务用 std::thread 并 join 回收，不丢 JoinHandle。
//! 旧实现（vless 走 ConnectivityEstablishmentFailed 兜底）下 proxy 返回结构化失败
//! -> 本 example 映射为 verdict=FAIL（Red Evidence）。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use nexus::proxy_serve_once;
use nexus_outbound_vless::{
    VlessCommand, VlessRequest, VlessResponse, VlessTarget, VlessUuid, decode_request,
    encode_response,
};

const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const PAYLOAD: &[u8] = b"ping-via-vless-tunnel";

/// VLESS 请求头增量解析：读到完整请求头为止，返回 `(req, consumed)`。
/// 只使用公开 API（decode_request），不假设 TCP 分段边界。
fn read_vless_header(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<(VlessRequest, usize), String> {
    let mut chunk = [0u8; 256];
    loop {
        match decode_request(buf) {
            Ok((req, consumed)) => return Ok((req, consumed)),
            Err(nexus_outbound_vless::VlessError::TruncatedHeader) => {
                let n = stream
                    .read(&mut chunk)
                    .map_err(|e| format!("vless node read header: {e}"))?;
                if n == 0 {
                    return Err("vless: client closed before request header complete".to_string());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(format!("vless: bad request header: {e}")),
        }
    }
}

fn main() {
    let _as_json = std::env::args().skip(1).any(|a| a == "--json");

    // --- echo 目标：读满 PAYLOAD.len() 字节、原样回写 ---
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
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

    // --- 本地 VLESS 明文节点（PRODUCT §11.20；tls: false） ---
    let uuid = VlessUuid::parse(UUID).expect("parse vless uuid");
    let node_listener = TcpListener::bind("127.0.0.1:0").expect("bind vless node");
    let node_addr = node_listener.local_addr().expect("node addr");
    let node_locator = format!("127.0.0.1:{}", node_addr.port());
    let node_connected = Arc::new(AtomicBool::new(false));
    let node_connected_clone = Arc::clone(&node_connected);
    let node_thread = thread::spawn(move || -> Result<(u16, String), String> {
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
                Err(e) => return Err(format!("vless node accept: {e}")),
            }
        }
        let mut tcp = cli.ok_or("no vless node connection within window")?;
        // Windows: accepted socket inherits listener nonblocking; restore blocking.
        tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
        node_connected_clone.store(true, Ordering::SeqCst);

        // VLESS 请求头 -> 解析目标
        let mut buf = Vec::new();
        let (req, _consumed) = read_vless_header(&mut tcp, &mut buf)?;
        if req.uuid != uuid {
            return Err("vless: uuid mismatch".to_string());
        }
        if req.command != VlessCommand::Tcp {
            return Err("vless: expected TCP command".to_string());
        }
        let target_port = req.port;
        let target_label = match req.target.as_ref().ok_or("vless: missing target")? {
            VlessTarget::Ipv4(ip) => format!("ipv4:{ip}"),
            VlessTarget::Ipv6(ip) => format!("ipv6:{ip}"),
            VlessTarget::Domain(d) => format!("domain:{d}"),
        };

        // 回送 VLESS 响应头（version 0 + 空 addon），随后进入中继。
        let resp = encode_response(&VlessResponse {
            version: 0,
            addon: Vec::new(),
        });
        tcp.write_all(&resp).map_err(|e| e.to_string())?;
        tcp.flush().map_err(|e| e.to_string())?;

        // 真实 connect 到 loopback echo 目标
        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;

        // 读 payload（proxy 中继自 SOCKS5 client）-> 明文写给 echo
        let mut payload = vec![0u8; PAYLOAD.len()];
        tcp.read_exact(&mut payload)
            .map_err(|e| format!("vless payload read: {e}"))?;
        echo.write_all(&payload).map_err(|e| e.to_string())?;

        // 读 echo 回显 -> 回写 client
        let mut back = vec![0u8; PAYLOAD.len()];
        echo.read_exact(&mut back).map_err(|e| e.to_string())?;
        tcp.write_all(&back).map_err(|e| e.to_string())?;
        tcp.flush().map_err(|e| e.to_string())?;

        Ok((target_port, target_label))
    });

    // --- nexus proxy 数据面：outbound=vless-node -> 本地 VLESS 节点（§11.20） ---
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
            "        tag: vless-node\n",
            "outbounds:\n",
            "  - tag: vless-node\n",
            "    kind: vless\n",
            "    locator: \"{0}\"\n",
            "    uuid: \"{1}\"\n",
            "    tls: false\n",
            "    flow: \"\"\n",
        ),
        node_locator, UUID
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
    let proxy_clone = proxy_listener.try_clone().expect("clone proxy");
    let proxy_thread = thread::spawn(move || proxy_serve_once(&proxy_clone, &config));

    // --- 原始 SOCKS5 客户端：NO-AUTH 问候 + CONNECT echo + payload + 回显比对 ---
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

    let proxy_result = proxy_thread.join().expect("join proxy");
    let mut out = match proxy_result {
        Ok(v) => v,
        Err(e) => {
            let reason = format!("{e:?}");
            serde_json::json!({
                "verdict": "FAIL",
                "outbound": { "kind": "vless" },
                "routing": { "outbound_kind": "vless" },
                "error": { "kind": "ConnectivityEstablishmentFailed", "reason": reason },
            })
        }
    };

    // VLESS 节点线程允许超时退出（旧实现不会连接节点）；超时路径 target_delivered_ok 为 false。
    let node_res = node_thread.join().expect("join node");
    let (node_port, node_label) = match node_res {
        Ok((p, l)) => (p, l),
        Err(_) => (0, String::new()),
    };
    echo_thread.join().expect("join echo").expect("echo once");

    if let Some(obj) = out.as_object_mut() {
        let target_delivered_ok = node_port == echo_addr.port();
        obj.insert(
            "client".into(),
            serde_json::json!({
                "auth_ok": auth_ok,
                "connect_ok": connect_ok,
                "payload_roundtrip_ok": roundtrip_ok,
            }),
        );
        obj.insert(
            "vless_server".into(),
            serde_json::json!({
                "connected": node_connected.load(Ordering::SeqCst),
                "target_delivered_ok": target_delivered_ok,
                "target_label": node_label,
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
