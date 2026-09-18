//! E4 产品场景 product.proxy-trojan-real-tls-params 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_trojan_real_tls_params -- --json
//! ```
//!
//! 同一进程内 loopback 127.0.0.1：rcgen 自签证书起 TLS server（下发 ALPN 列表
//! `h2` / `http/1.1`），客户端用 `client_config_dangerous_skip_verify`（跳过证书链
//! 校验）下发 ALPN。确定性断言：握手通过、ALPN 协商命中 `http/1.1`、认证后数据往返成功。
//! 不连公网；线程 join 回收。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use nexus_outbound_trojan::{
    TrojanTarget, client_config_dangerous_skip_verify, encode_request, generate_loopback_identity,
    parse_request, server_config,
};

const PASSWORD: &str = "demo";
const PAYLOAD: &[u8] = b"trojan-real-tls-params";

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

    // --- 自签证书；server 配置 ALPN 列表 ---
    let identity = generate_loopback_identity().expect("self-signed identity");
    let mut srv_cfg = server_config(&identity).expect("server config");
    srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let srv_cfg = Arc::new(srv_cfg);

    // --- echo 目标 ---
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    let echo_thread = thread::spawn(move || -> std::io::Result<()> {
        let (mut conn, _) = echo_listener.accept()?;
        let req = read_record(&mut conn)?;
        write_record(&mut conn, &req)
    });

    // --- TLS server（配 ALPN）---
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan");
    let srv_addr = srv_listener.local_addr().expect("trojan addr");
    let srv_password = PASSWORD.to_string();
    let srv_thread = thread::spawn(move || -> Result<(), String> {
        let (mut tcp, _) = srv_listener.accept().map_err(|e| e.to_string())?;
        let mut conn = rustls::ServerConnection::new(srv_cfg).map_err(|e| e.to_string())?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        let header = read_record(&mut tls).map_err(|e| e.to_string())?;
        let _target = parse_request(&srv_password, &header).map_err(|e| match e {
            nexus_outbound_trojan::TrojanError::AuthDenied => "AUTH_DENIED".to_string(),
            other => format!("{other:?}"),
        })?;

        let mut echo = TcpStream::connect(echo_addr).map_err(|e| e.to_string())?;
        let pay = read_record(&mut tls).map_err(|e| e.to_string())?;
        write_record(&mut echo, &pay).map_err(|e| e.to_string())?;
        let back = read_record(&mut echo).map_err(|e| e.to_string())?;
        write_record(&mut tls, &back).map_err(|e| e.to_string())?;
        Ok(())
    });

    // --- TLS client：skip-cert-verify + ALPN ---
    let cli_cfg = client_config_dangerous_skip_verify(&[b"http/1.1".as_slice(), b"h2".as_slice()])
        .expect("skip-verify client config");
    let sni = rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("sni");
    let mut conn = rustls::ClientConnection::new(Arc::new(cli_cfg), sni).expect("client conn");
    let mut tcp = TcpStream::connect(srv_addr).expect("connect trojan");

    let (tls_ok, data_roundtrip_ok, auth_accepted) = {
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        let target = TrojanTarget::Ipv4([127, 0, 0, 1], echo_addr.port());
        let header = encode_request(PASSWORD, &target);
        let tls_ok = write_record(&mut tls, &header).is_ok();

        let mut data_roundtrip_ok = false;
        let mut auth_accepted = false;
        if tls_ok
            && write_record(&mut tls, PAYLOAD).is_ok()
            && let Ok(back) = read_record(&mut tls)
        {
            data_roundtrip_ok = back == PAYLOAD;
            auth_accepted = true;
        }
        (tls_ok, data_roundtrip_ok, auth_accepted)
    };
    // 块结束后 tls 借用释放，可读协商 ALPN。
    let alpn = conn.alpn_protocol().map(|b| b.to_vec());

    let server_ok = srv_thread.join().expect("join server").is_ok();
    let _ = TcpStream::connect(echo_addr);
    echo_thread.join().expect("join echo").ok();

    let alpn_negotiated = alpn.unwrap_or_default();
    let alpn_negotiated = String::from_utf8_lossy(&alpn_negotiated).into_owned();

    let verdict =
        tls_ok && alpn_negotiated == "http/1.1" && auth_accepted && data_roundtrip_ok && server_ok;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"kind\":\"trojan\",",
                "\"tls_ok\":{},",
                "\"alpn_negotiated\":\"{}\",",
                "\"auth_accepted\":{},",
                "\"data_roundtrip_ok\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            tls_ok,
            alpn_negotiated,
            auth_accepted,
            data_roundtrip_ok
        );
    } else {
        println!(
            "trojan real tls: tls={} alpn={} auth={} roundtrip={}",
            tls_ok, alpn_negotiated, auth_accepted, data_roundtrip_ok
        );
    }
}
