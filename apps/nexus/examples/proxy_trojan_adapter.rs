//! E4 产品场景 product.proxy-trojan-adapter / product.proxy-trojan-auth-rejected 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_trojan_adapter -- --json
//! cargo run --quiet -p nexus --example proxy_trojan_adapter -- --json --scenario rejected
//! ```
//!
//! 同一进程内 loopback 127.0.0.1：rcgen 自签证书（客户端把它作为唯一信任根=公钥 pin），
//! 起 TLS server + TLS client（rustls 0.23/ring）。客户端在 TLS 内发 trojan 请求头
//! `hex(SHA-224(password))|CRLF|ATYP+ADDR+PORT|CRLF`；server 校验密码后连 loopback echo 中继。
//! 离线、确定性；server/echo 线程 join 回收，不丢 JoinHandle。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use nexus_outbound_trojan::{
    TrojanTarget, client_config, encode_request, generate_loopback_identity, parse_request,
    server_config,
};

const PASSWORD: &str = "demo";
const WRONG_PASSWORD: &str = "intruder";
const PAYLOAD: &[u8] = b"trojan-payload-loopback";

fn write_record<S: Read + Write>(stream: &mut S, record: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(record.len() as u32).to_be_bytes())?;
    stream.write_all(record)
}

fn read_record<S: Read + Write>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");
    let rejected = args.iter().any(|a| a == "--scenario") && args.iter().any(|a| a == "rejected");

    // --- 自签证书（客户端唯一信任根 = 公钥 pin） ---
    let identity = generate_loopback_identity().expect("self-signed identity");
    let srv_cfg = Arc::new(server_config(&identity).expect("server config"));
    let cli_cfg = Arc::new(client_config(&identity).expect("client config"));

    // --- echo 目标：读一条 record，原样回写 ---
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    let echo_thread = thread::spawn(move || -> std::io::Result<()> {
        let (mut conn, _) = echo_listener.accept()?;
        let req = read_record(&mut conn)?;
        write_record(&mut conn, &req)
    });

    // --- TLS server：accept 一个 trojan 客户端会话 ---
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan");
    let srv_addr = srv_listener.local_addr().expect("trojan addr");
    let srv_password = PASSWORD.to_string();
    let srv_thread = thread::spawn(move || -> Result<(String, u16), String> {
        let (mut tcp, _) = srv_listener.accept().map_err(|e| e.to_string())?;
        let mut conn = rustls::ServerConnection::new(srv_cfg).map_err(|e| e.to_string())?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        // TLS 握手 + 读 trojan 请求头（一条 record）
        let header = read_record(&mut tls).map_err(|e| e.to_string())?;
        let target = parse_request(&srv_password, &header).map_err(|e| match e {
            nexus_outbound_trojan::TrojanError::AuthDenied => "AUTH_DENIED".to_string(),
            other => format!("{other:?}"),
        })?;

        // 密码正确：连 echo 中继 payload
        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;
        let pay = read_record(&mut tls).map_err(|e| e.to_string())?;
        write_record(&mut echo, &pay).map_err(|e| e.to_string())?;
        let back = read_record(&mut echo).map_err(|e| e.to_string())?;
        write_record(&mut tls, &back).map_err(|e| e.to_string())?;

        Ok((target.host_label(), target.port()))
    });

    // --- TLS client ---
    let sni = rustls::pki_types::ServerName::try_from("localhost".to_string())
        .map_err(|_| ())
        .expect("sni");
    let mut conn = rustls::ClientConnection::new(cli_cfg, sni).expect("client conn");
    let mut tcp = TcpStream::connect(srv_addr).expect("connect trojan");
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let client_password = if rejected { WRONG_PASSWORD } else { PASSWORD };
    let target = TrojanTarget::Ipv4([127, 0, 0, 1], echo_addr.port());
    let header = encode_request(client_password, &target);
    // 写首条 record 触发 TLS 握手
    let handshake_ok = write_record(&mut tls, &header).is_ok();

    // 成功路径：发 payload 并读回显；失败路径（错密码）server 已拒绝/关流，读会失败。
    let mut payload_roundtrip_ok = false;
    let mut payload_relayed = false;
    if !rejected
        && write_record(&mut tls, PAYLOAD).is_ok()
        && let Ok(back) = read_record(&mut tls)
    {
        payload_roundtrip_ok = back == PAYLOAD;
        payload_relayed = true;
    }

    let server_result = srv_thread.join().expect("join server");
    if rejected {
        // server 未中继到 echo；连一次空连接以解除 echo 的 accept 阻塞。
        let _ = TcpStream::connect(echo_addr);
    }
    echo_thread.join().expect("join echo").ok();

    let (auth_accepted, reject_reason, target_delivered_ok) = match &server_result {
        Ok((host, port)) => (
            true,
            "OK".to_string(),
            host == "127.0.0.1" && *port == echo_addr.port(),
        ),
        Err(reason) => (false, reason.clone(), false),
    };

    let verdict = if rejected {
        handshake_ok && !auth_accepted && reject_reason == "AUTH_DENIED" && !payload_relayed
    } else {
        handshake_ok && auth_accepted && target_delivered_ok && payload_roundtrip_ok
    };

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"kind\":\"trojan\",",
                "\"handshake_ok\":{},",
                "\"auth_accepted\":{},",
                "\"reject_reason\":\"{}\",",
                "\"target_delivered_ok\":{},",
                "\"payload_roundtrip_ok\":{},",
                "\"payload_relayed\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            handshake_ok,
            auth_accepted,
            reject_reason,
            target_delivered_ok,
            payload_roundtrip_ok,
            payload_relayed
        );
    } else {
        println!(
            "trojan loopback: handshake={} auth={} target_ok={} payload_ok={}",
            handshake_ok, auth_accepted, target_delivered_ok, payload_roundtrip_ok
        );
    }
}
