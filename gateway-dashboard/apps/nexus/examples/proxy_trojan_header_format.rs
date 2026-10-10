//! E4 产品场景 product.proxy-trojan-header-format 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_trojan_header_format -- --json
//! ```
//!
//! 同一进程内 loopback 127.0.0.1：rcgen 自签证书，TLS server + client。
//! (a) 同格式往返：本地 server 与 client 同格式（Standard / Singbox 各跑一次）→ 握手+认证+往返；
//! (b) 字节级互操作断言（PRODUCT §11.9.2）：`encode(Standard)` 在 hex(56B)+CRLF(2B) 之后
//!     紧接 `0x01` CMD 字节（其后才是 ATYP），且 `encode(Standard) == encode(Singbox)` 逐字节相同。
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

    // (a) 同格式往返：Standard 与 Singbox 各跑一次（server 与 client 同格式）。
    let singbox_roundtrip_ok = run_session(
        &identity,
        TrojanHeaderFormat::Singbox,
        TrojanHeaderFormat::Singbox,
    );
    let standard_roundtrip_ok = run_session(
        &identity,
        TrojanHeaderFormat::Standard,
        TrojanHeaderFormat::Standard,
    );

    // (b) 字节级互操作断言（PRODUCT §11.9.2）：官方线上布局为
    //   hex(56B) | CRLF(2B) | CMD(0x01) | ATYP | ADDR | PORT(BE) | CRLF
    // 对 IPv4 目标（ATYP=0x01），头部总长 = 56+2+1(CMD)+1(ATYP)+4+2+2 = 68：
    //   offset 56..58 = CRLF；offset 58 = 0x01(CMD)；offset 59 = 0x01(ATYP=IPv4)；
    //   offset 60..64 = 目标 octets。Standard 与 Singbox 必须逐字节相同。
    let probe = TrojanTarget::Ipv4([127, 0, 0, 1], 8388);
    let std_enc = encode_request_fmt(PASSWORD, &probe, TrojanHeaderFormat::Standard);
    let sbx_enc = encode_request_fmt(PASSWORD, &probe, TrojanHeaderFormat::Singbox);
    let standard_header_has_cmd_byte = std_enc.len() == 68
        && std_enc[56..58] == [0x0du8, 0x0a]
        && std_enc[58] == 0x01 // CMD = CONNECT
        && std_enc[59] == 0x01 // ATYP = IPv4
        && std_enc[60..64] == [127u8, 0, 0, 1];
    let header_formats_byte_identical = std_enc == sbx_enc;

    let verdict = singbox_roundtrip_ok
        && standard_roundtrip_ok
        && standard_header_has_cmd_byte
        && header_formats_byte_identical;

    if as_json {
        println!(
            "{{\"verdict\":\"{}\",\"kind\":\"trojan\",\"singbox_roundtrip_ok\":{},\"standard_roundtrip_ok\":{},\"standard_header_has_cmd_byte\":{},\"header_formats_byte_identical\":{}}}",
            if verdict { "PASS" } else { "FAIL" },
            singbox_roundtrip_ok,
            standard_roundtrip_ok,
            standard_header_has_cmd_byte,
            header_formats_byte_identical
        );
    } else {
        println!(
            "trojan header format: singbox={} standard={} std_cmd_byte={} byte_identical={}",
            singbox_roundtrip_ok,
            standard_roundtrip_ok,
            standard_header_has_cmd_byte,
            header_formats_byte_identical
        );
    }
}
