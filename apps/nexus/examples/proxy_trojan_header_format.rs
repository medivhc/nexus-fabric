//! E4 产品场景 product.proxy-trojan-header-format 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_trojan_header_format -- --json
//! ```
//!
//! 同一进程内 loopback 127.0.0.1：rcgen 自签证书，TLS server + client。同一进程内跑两段：
//! (a) Singbox：本地 server 用 Singbox 解析器（期待 `0x01` CONNECT 命令字节），客户端切
//!     `TrojanHeaderFormat::Singbox` → 握手+认证+往返；
//! (b) Standard 回归：本地 server 用标准解析器，客户端切 `Standard`（无命令字节）→ 往返。
//! 离线、确定性；线程 join 回收。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use nexus_outbound_trojan::{
    TrojanHeaderFormat, TrojanTarget, client_config, encode_request_fmt,
    generate_loopback_identity, parse_request_fmt, server_config,
};

const PASSWORD: &str = "demo";
const PAYLOAD: &[u8] = b"trojan-header-format";

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

/// 跑一次 loopback 会话：server 按 `server_fmt` 解析，client 按 `client_fmt` 编码。
/// 成功返回数据往返是否 PASS。
fn run_session(
    identity: &nexus_outbound_trojan::LoopbackIdentity,
    client_fmt: TrojanHeaderFormat,
    server_fmt: TrojanHeaderFormat,
) -> bool {
    let srv_cfg = Arc::new(server_config(identity).expect("server config"));
    let cli_cfg = Arc::new(client_config(identity).expect("client config"));

    // echo 目标
    let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo addr");
    let echo_thread = thread::spawn(move || -> std::io::Result<()> {
        let (mut conn, _) = echo_listener.accept()?;
        let req = read_record(&mut conn)?;
        write_record(&mut conn, &req)
    });

    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan");
    let srv_addr = srv_listener.local_addr().expect("trojan addr");
    let srv_password = PASSWORD.to_string();
    let srv_thread = thread::spawn(move || -> Result<(), String> {
        let (mut tcp, _) = srv_listener.accept().map_err(|e| e.to_string())?;
        let mut conn = rustls::ServerConnection::new(srv_cfg).map_err(|e| e.to_string())?;
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

        let header = read_record(&mut tls).map_err(|e| e.to_string())?;
        let _target =
            parse_request_fmt(&srv_password, &header, server_fmt).map_err(|e| match e {
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

    // client
    let sni = rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("sni");
    let mut conn = rustls::ClientConnection::new(cli_cfg, sni).expect("client conn");
    let mut tcp = TcpStream::connect(srv_addr).expect("connect trojan");
    let roundtrip = {
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let target = TrojanTarget::Ipv4([127, 0, 0, 1], echo_addr.port());
        let header = encode_request_fmt(PASSWORD, &target, client_fmt);
        let ok = write_record(&mut tls, &header).is_ok();
        let echo_ok = write_record(&mut tls, PAYLOAD).is_ok()
            && matches!(read_record(&mut tls), Ok(ref back) if back == PAYLOAD);
        ok && echo_ok
    };

    let server_ok = srv_thread.join().expect("join server").is_ok();
    let _ = TcpStream::connect(echo_addr);
    echo_thread.join().expect("join echo").ok();

    roundtrip && server_ok
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let identity = generate_loopback_identity().expect("self-signed identity");

    // (a) Singbox：server 期待命令字节，client 切 Singbox。
    let singbox_roundtrip_ok = run_session(
        &identity,
        TrojanHeaderFormat::Singbox,
        TrojanHeaderFormat::Singbox,
    );
    // (b) Standard 回归：server 用标准解析，client 切 Standard。
    let standard_roundtrip_ok = run_session(
        &identity,
        TrojanHeaderFormat::Standard,
        TrojanHeaderFormat::Standard,
    );

    let verdict = singbox_roundtrip_ok && standard_roundtrip_ok;

    if as_json {
        println!(
            "{{\"verdict\":\"{}\",\"kind\":\"trojan\",\"singbox_roundtrip_ok\":{},\"standard_roundtrip_ok\":{}}}",
            if verdict { "PASS" } else { "FAIL" },
            singbox_roundtrip_ok,
            standard_roundtrip_ok
        );
    } else {
        println!(
            "trojan header format: singbox={} standard={}",
            singbox_roundtrip_ok, standard_roundtrip_ok
        );
    }
}
