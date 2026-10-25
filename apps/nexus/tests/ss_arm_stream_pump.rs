//! E2/E3 回归：`apps/nexus` SS arm 用 SIP004 流式 codec + PendingWrite 背压，
//! 且客户端关闭后能通过半关闭传播在 5s 内让 `proxy_serve_once` 返回。
//!
//! 覆盖点：
//! - SOCKS5 CONNECT 成功、payload 经 SS 隧道往返；
//! - proxy JSON `routing.outbound_kind = shadowsocks`、`bytes.to_upstream/to_client > 0`；
//! - fake SS server 走真实 SIP004 线格式（salt + chunk，无 u32 记录头）；
//! - 客户端 drop 后 proxy 线程在 5s 内返回（防半关闭回归）。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use nexus::proxy_serve_once;
use nexus_outbound_shadowsocks::{Role, SsMethod, SsStream, SsTarget, parse_request};

const PASSWORD: &str = "stream-pump-password";
const METHOD: SsMethod = SsMethod::Chacha20IetfPoly1305;
const PAYLOAD: &[u8] = b"ss-stream-pump-payload";

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

/// 流式读完 request header，返回 (target, header 之后剩余明文)。
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

fn spawn_echo() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("echo accept");
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).expect("echo read");
        conn.write_all(&buf[..n]).expect("echo write");
    });
    (addr, handle)
}

fn spawn_ss_server(
    echo_addr: std::net::SocketAddr,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ss");
    let addr = listener.local_addr().expect("ss addr");
    let handle = thread::spawn(move || {
        let (mut cli, _) = listener.accept().expect("ss accept");
        cli.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("ss read timeout");
        let mut sess = SsStream::new(PASSWORD, METHOD, Role::Server).expect("ss server session");
        let (target, mut payload) = read_request(&mut sess, &mut cli).expect("ss request header");
        assert_eq!(target.port(), echo_addr.port(), "request target port");

        let mut wire = [0u8; 4096];
        while payload.len() < PAYLOAD.len() {
            let n = cli.read(&mut wire).expect("ss payload read");
            assert_ne!(n, 0, "eof before complete payload");
            payload.extend(sess.open(&wire[..n]).expect("ss payload open"));
        }

        let mut echo = TcpStream::connect(echo_addr).expect("ss -> echo connect");
        echo.write_all(&payload[..PAYLOAD.len()])
            .expect("ss -> echo write");
        let mut back = vec![0u8; PAYLOAD.len()];
        echo.read_exact(&mut back).expect("ss <- echo read");
        cli.write_all(&sess.seal(&back).expect("ss reply seal"))
            .expect("ss reply write");

        // 读到 proxy 半关闭产生的 FIN（验证 shutdown(Write) 传播）。
        loop {
            match cli.read(&mut wire) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    (addr, handle)
}

#[test]
fn ss_arm_stream_pump_and_half_close() {
    let (echo_addr, echo_thread) = spawn_echo();
    let (ss_addr, ss_thread) = spawn_ss_server(echo_addr);

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

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let (tx, rx) = mpsc::channel();
    let proxy_thread = thread::spawn(move || {
        let _ = tx.send(proxy_serve_once(&listener, &config));
    });

    // --- SOCKS5 client ---
    let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client read timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).expect("greeting reply");
    assert_eq!(reply, [0x05, 0x00], "SOCKS5 no-auth");

    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&connect_req).expect("connect req");
    let mut connect_reply = [0u8; 10];
    client
        .read_exact(&mut connect_reply)
        .expect("connect reply");
    assert_eq!(&connect_reply[..2], &[0x05, 0x00], "CONNECT succeeded");

    client.write_all(PAYLOAD).expect("payload");
    let mut back = vec![0u8; PAYLOAD.len()];
    client.read_exact(&mut back).expect("echo back");
    assert_eq!(back.as_slice(), PAYLOAD, "payload roundtrip");

    // 客户端关闭 -> SS arm 半关闭传播 -> proxy_serve_once 必须在 5s 内返回。
    drop(client);
    let proxy_json = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("proxy_serve_once returned within 5s after client close")
        .expect("proxy_serve_once ok");

    proxy_thread.join().expect("proxy thread");
    ss_thread.join().expect("ss server thread");
    echo_thread.join().expect("echo thread");

    assert_eq!(
        proxy_json["routing"]["outbound_kind"], "shadowsocks",
        "routing outbound kind"
    );
    assert_eq!(proxy_json["verdict"], "PASS");
    assert!(
        proxy_json["bytes"]["to_upstream"].as_u64().unwrap_or(0) > 0,
        "to_upstream counted"
    );
    assert!(
        proxy_json["bytes"]["to_client"].as_u64().unwrap_or(0) > 0,
        "to_client counted"
    );
}
