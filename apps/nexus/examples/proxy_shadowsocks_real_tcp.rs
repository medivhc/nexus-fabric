//! E4 产品场景 product.proxy-shadowsocks-real-tcp 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/proxy_shadowsocks_real_tcp.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_shadowsocks_real_tcp -- --json
//! ```
//!
//! 同一进程内 loopback 127.0.0.1 起：echo 目标端 + SS server 端 + SS client 端，走真实
//! `std::net::TcpStream` + 真实 **SIP004** 流式 AEAD（`salt(32) || chunk*`，无外层记录头；
//! §11.6.1）。客户端 seal request header（目标=echo），server 流式 open 并解析目标后真实
//! connect 到 echo，中继一段 payload 往返。离线、确定性。
//! server/echo 任务用 std::thread 并 join 回收，不丢 JoinHandle。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use nexus_outbound_shadowsocks::{
    Role, SsMethod, SsStream, SsTarget, encode_request, parse_request,
};

const PASSWORD: &str = "demo";
const METHOD: SsMethod = SsMethod::Chacha20IetfPoly1305;
const PAYLOAD: &[u8] = b"ping-payload-real-tcp";

/// 已收字节里 request header 的完整长度（不足返回 None）。
fn header_len(buf: &[u8]) -> Option<usize> {
    match *buf.first()? {
        0x01 => Some(7).filter(|need| buf.len() >= *need),
        0x03 => {
            let dlen = *buf.get(1)? as usize;
            let need = 2 + dlen + 2;
            (buf.len() >= need).then_some(need)
        }
        // 非法 ATYP：把 0 长度交给 parse_request 报 InvalidFrame。
        _ => Some(0),
    }
}

/// 流式读完一个 SS 会话的 request header：返回 (target, header 之后的剩余明文)。
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

    // --- SS server 端：accept 一个 SS 客户端会话（流式 SIP004） ---
    let ss_listener = TcpListener::bind("127.0.0.1:0").expect("bind ss");
    let ss_addr = ss_listener.local_addr().expect("ss local addr");
    let ss_thread = thread::spawn(move || -> Result<(String, u16), String> {
        let (mut cli, _) = ss_listener.accept().map_err(|e| e.to_string())?;
        let mut sess =
            SsStream::new(PASSWORD, METHOD, Role::Server).map_err(|e| format!("{e:?}"))?;

        // 1) 流式读 request header（salt + 首 chunk 明文）
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

        // 4) 读 echo 回显，seal 回写 client（服务端自己的 TX salt）
        let mut back = vec![0u8; PAYLOAD.len()];
        echo.read_exact(&mut back).map_err(|e| e.to_string())?;
        let reply = sess.seal(&back).map_err(|e| format!("{e:?}"))?;
        cli.write_all(&reply).map_err(|e| e.to_string())?;

        Ok((target.host_label(), target.port()))
    });

    // --- SS client ---
    let mut cli = TcpStream::connect(ss_addr).expect("connect ss");
    let mut sess = SsStream::new(PASSWORD, METHOD, Role::Client).expect("client session");

    // request header 指向 loopback echo（IPv4）；首写含客户端 salt。
    let target = SsTarget::Ipv4([127, 0, 0, 1], echo_addr.port());
    cli.write_all(&sess.seal(&encode_request(&target)).expect("seal req"))
        .expect("write req");

    // 加密 payload（后续 chunk，不再带 salt）
    cli.write_all(&sess.seal(PAYLOAD).expect("seal payload"))
        .expect("write payload");

    // 流式读回加密回显并解密比对
    let mut back = Vec::new();
    let mut wire = [0u8; 4096];
    while back.len() < PAYLOAD.len() {
        let n = cli.read(&mut wire).expect("read reply");
        if n == 0 {
            break;
        }
        back.extend(sess.open(&wire[..n]).expect("open reply"));
    }

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
