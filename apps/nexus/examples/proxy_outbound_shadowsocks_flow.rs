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
use nexus_outbound_shadowsocks::{
    Role, SsMethod, SsStream, parse_request, read_record, write_record,
};

const PASSWORD: &str = "demo";
const METHOD: SsMethod = SsMethod::Chacha20IetfPoly1305;
const PAYLOAD: &[u8] = b"ping-via-ss-tunnel";

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

        // 1) 加密 request header -> 解析目标
        let req_frame = read_record(&mut cli).map_err(|e| e.to_string())?;
        let req = sess.open(&req_frame).map_err(|e| format!("{e:?}"))?;
        let target = parse_request(&req).map_err(|e| format!("{e:?}"))?;

        // 2) 真实 connect 到 loopback echo 目标
        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;

        // 3) 加密 payload -> 明文写给 echo
        let pay_frame = read_record(&mut cli).map_err(|e| e.to_string())?;
        let payload = sess.open(&pay_frame).map_err(|e| format!("{e:?}"))?;
        echo.write_all(&payload).map_err(|e| e.to_string())?;

        // 4) 读 echo 回显 -> 加密回写 client
        let mut back = vec![0u8; payload.len()];
        echo.read_exact(&mut back).map_err(|e| e.to_string())?;
        let reply = sess.seal(&back).map_err(|e| format!("{e:?}"))?;
        write_record(&mut cli, &reply).map_err(|e| e.to_string())?;

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
