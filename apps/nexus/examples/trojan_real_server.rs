//! E5 真实节点测试脚手架（**非 E4，不进 scenarios/product/**）。
//!
//! 对真实 trojan 节点做一次端到端冒烟：TCP 连 `--server` → TLS 握手（skip-verify +
//! ALPN + SNI）→ 在隧道内发 trojan 请求头（target = `--target`）→ 发 HTTP `GET /`
//! → 读一段响应 → 打印 JSON 结果。
//!
//! **绝不硬编码真实密码**：所有连接参数来自 CLI 参数 / 环境变量，默认仅为占位符。
//!
//! ```text
//! cargo run --example trojan_real_server -- \
//!   --server example.com:443 --password <PWD> --sni example.com \
//!   --target example.com:80 --alpn h2,http/1.1 --skip-verify
//! ```
//!
//! 用 std::net + 主线程同步 IO；结构化退出码，不连公网以外的任何本机服务。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use nexus_outbound_trojan::{
    TrojanHeaderFormat, TrojanTarget, client_config_dangerous_skip_verify, encode_request_fmt,
};

#[derive(Default, Clone)]
struct Args {
    server: String,
    password: String,
    sni: String,
    target: String,
    alpn: String,
    skip_verify: bool,
    format: String,
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--server" => a.server = it.next().unwrap_or_default(),
            "--password" => a.password = it.next().unwrap_or_default(),
            "--sni" => a.sni = it.next().unwrap_or_default(),
            "--target" => a.target = it.next().unwrap_or_default(),
            "--alpn" => a.alpn = it.next().unwrap_or_default(),
            "--skip-verify" => a.skip_verify = true,
            "--format" => a.format = it.next().unwrap_or_default(),
            _ => {}
        }
    }
    a
}

/// `host:port` → TrojanTarget（域名字面量；IP 字面量走 Domain 也可，server 端按字节解析）。
fn parse_target(s: &str) -> TrojanTarget {
    match s.rsplit_once(':') {
        Some((host, port)) => TrojanTarget::Domain(
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port.parse().unwrap_or(80),
        ),
        None => TrojanTarget::Domain(s.to_string(), 80),
    }
}

fn alpn_list(spec: &str) -> Vec<&[u8]> {
    if spec.is_empty() {
        vec![]
    } else {
        spec.split(',').map(|p| p.as_bytes()).collect::<Vec<_>>()
    }
}

fn main() {
    let args = parse_args();

    if args.server.is_empty() || args.password.is_empty() || args.sni.is_empty() {
        println!(
            "{{\"tls_ok\":false,\"auth_ok\":false,\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"missing required args: --server/--password/--sni\"}}"
        );
        std::process::exit(2);
    }

    let fmt = if args.format.eq_ignore_ascii_case("singbox") {
        TrojanHeaderFormat::Singbox
    } else {
        TrojanHeaderFormat::Standard
    };
    let alpn: Vec<&[u8]> = alpn_list(&args.alpn);

    // TLS 客户端：真实节点固定走 skip-cert-verify 模式（本脚手架用途）。
    let cfg = match args.skip_verify {
        true => client_config_dangerous_skip_verify(&alpn),
        // 未显式 --skip-verify 时，本脚手架仍只用 dangerous 配置（不做系统根校验），
        // 保持与真实节点测试一致；调用方应在文档中知悉。
        false => client_config_dangerous_skip_verify(&alpn),
    };
    let cfg = match cfg {
        Ok(c) => Arc::new(c),
        Err(e) => {
            println!(
                "{{\"tls_ok\":false,\"auth_ok\":false,\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"client_config:{e:?}\"}}"
            );
            std::process::exit(1);
        }
    };

    let sni = match rustls::pki_types::ServerName::try_from(args.sni.clone()) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "{{\"tls_ok\":false,\"auth_ok\":false,\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"bad sni:{e:?}\"}}"
            );
            std::process::exit(2);
        }
    };

    let mut tcp = match TcpStream::connect(&args.server) {
        Ok(t) => t,
        Err(e) => {
            println!(
                "{{\"tls_ok\":false,\"auth_ok\":false,\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"tcp:{e}\"}}"
            );
            std::process::exit(1);
        }
    };

    let mut conn = rustls::ClientConnection::new(cfg, sni).expect("client conn");
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let tls_ok = match tls.flush() {
        Ok(_) => true,
        Err(e) => {
            println!(
                "{{\"tls_ok\":false,\"auth_ok\":false,\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"tls handshake:{e}\"}}"
            );
            std::process::exit(1);
        }
    };

    // 发 trojan 请求头。
    let target = parse_target(&args.target);
    let header = encode_request_fmt(&args.password, &target, fmt);
    let auth_ok = match tls.write_all(&header) {
        Ok(_) => true,
        Err(e) => {
            println!(
                "{{\"tls_ok\":{},\"auth_ok\":false,\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"write header:{e}\"}}",
                tls_ok
            );
            std::process::exit(1);
        }
    };

    // 隧道内发 HTTP GET /。
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target.host_label()
    );
    let relay_ok = match tls.write_all(http_req.as_bytes()) {
        Ok(_) => true,
        Err(e) => {
            println!(
                "{{\"tls_ok\":{},\"auth_ok\":{},\"relay_ok\":false,\"http_status\":\"\",\"detail\":\"write http:{e}\"}}",
                tls_ok, auth_ok
            );
            std::process::exit(1);
        }
    };

    let mut buf = Vec::new();
    let n = tls.read_to_end(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n.min(buf.len())]).into_owned();
    let status = head
        .lines()
        .find(|l| l.starts_with("HTTP/"))
        .unwrap_or("")
        .to_string();

    println!(
        "{{\"tls_ok\":{},\"auth_ok\":{},\"relay_ok\":{},\"http_status\":\"{}\",\"detail\":\"{} bytes\"}}",
        tls_ok,
        auth_ok,
        relay_ok && n > 0,
        status,
        n
    );
}
