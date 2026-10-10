//! E4 产品场景 product.proxy-shadowsocks-real-tcp 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/proxy_shadowsocks_real_tcp.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_shadowsocks_real_tcp -- --json
//! ```
//!
//! 同一进程内 loopback 127.0.0.1 起：echo 目标端 + SS server 端 + SS client 端，走真实
//! `std::net::TcpStream` + 真实 AEAD 封装（§11.6.1）。客户端发加密 request header（目标=echo），
//! server 解密并解析目标后真实 connect 到 echo，中继一段 payload 往返。离线、确定性。
//! server/echo 任务用 std::thread 并 join 回收，不丢 JoinHandle。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use nexus_outbound_shadowsocks::{
    Role, SsMethod, SsStream, SsTarget, encode_request, parse_request, read_record, write_record,
};

const PASSWORD: &str = "demo";
const METHOD: SsMethod = SsMethod::Chacha20IetfPoly1305;
const PAYLOAD: &[u8] = b"ping-payload-real-tcp";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // --- echo 目标端：读一次、原样回写 ---
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo local addr");
    let echo_thread = thread::spawn(move || -> std::io::Result<()> {
        let (mut conn, _) = echo_listener.accept()?;
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf)?;
        conn.write_all(&buf[..n])
    });

    // --- SS server 端：accept 一个 SS 客户端会话 ---
    let ss_listener = TcpListener::bind("127.0.0.1:0").expect("bind ss");
    let ss_addr = ss_listener.local_addr().expect("ss local addr");
    let ss_thread = thread::spawn(move || -> Result<(String, u16), String> {
        let (mut cli, _) = ss_listener.accept().map_err(|e| e.to_string())?;
        let mut sess =
            SsStream::new(PASSWORD, METHOD, Role::Server).map_err(|e| format!("{e:?}"))?;

        // 1) 加密 request header
        let req_frame = read_record(&mut cli).map_err(|e| e.to_string())?;
        let req = sess.open(&req_frame).map_err(|e| format!("{e:?}"))?;
        let target = parse_request(&req).map_err(|e| format!("{e:?}"))?;

        // 2) 真实 connect 到 loopback echo 目标
        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;

        // 3) 读加密 payload，解密后明文写给 echo
        let pay_frame = read_record(&mut cli).map_err(|e| e.to_string())?;
        let payload = sess.open(&pay_frame).map_err(|e| format!("{e:?}"))?;
        echo.write_all(&payload).map_err(|e| e.to_string())?;

        // 4) 读 echo 回显，加密回写 client
        let mut back = vec![0u8; payload.len()];
        echo.read_exact(&mut back).map_err(|e| e.to_string())?;
        let reply = sess.seal(&back).map_err(|e| format!("{e:?}"))?;
        write_record(&mut cli, &reply).map_err(|e| e.to_string())?;

        Ok((target.host_label(), target.port()))
    });

    // --- SS client ---
    let mut cli = TcpStream::connect(ss_addr).expect("connect ss");
    let mut sess = SsStream::new(PASSWORD, METHOD, Role::Client).expect("client session");

    // request header 指向 loopback echo（IPv4）
    let target = SsTarget::Ipv4([127, 0, 0, 1], echo_addr.port());
    let req_frame = sess.seal(&encode_request(&target)).expect("seal req");
    write_record(&mut cli, &req_frame).expect("write req record");

    // 加密 payload
    let pay_frame = sess.seal(PAYLOAD).expect("seal payload");
    write_record(&mut cli, &pay_frame).expect("write payload record");

    // 读回加密回显并解密比对
    let reply_frame = read_record(&mut cli).expect("read reply record");
    let back = sess.open(&reply_frame).expect("open reply");

    let (server_host, server_port) = ss_thread.join().expect("join ss").expect("ss serve once");
    echo_thread.join().expect("join echo").expect("echo once");

    let handshake_ok = true;
    let target_delivered_ok = server_host == "127.0.0.1" && server_port == echo_addr.port();
    let payload_roundtrip_ok = back.as_slice() == PAYLOAD;

    let verdict = handshake_ok && target_delivered_ok && payload_roundtrip_ok;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"method\":\"chacha20-ietf-poly1305\",",
                "\"handshake_ok\":{},",
                "\"target_delivered_ok\":{},",
                "\"payload_roundtrip_ok\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            handshake_ok,
            target_delivered_ok,
            payload_roundtrip_ok
        );
    } else {
        println!(
            "ss real tcp ok: handshake={}, target_ok={} ({}:{}), payload_ok={}",
            handshake_ok, target_delivered_ok, server_host, server_port, payload_roundtrip_ok
        );
    }
}
