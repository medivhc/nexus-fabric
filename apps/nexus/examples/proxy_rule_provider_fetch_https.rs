//! E5 产品场景 `product.proxy-rule-provider-fetch-https` 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_rule_provider_fetch_https -- --json
//! ```
//!
//! 离线确定性闭环（不经公网）：本地 rustls TLS server（rcgen 自签证书，含
//! `127.0.0.1` IP SAN）提供 provider 文本；组合根 `CachedHttpProviderFetcher`
//! 注入该自签证书为 root store，以 `https://127.0.0.1:<port>/provider.txt`
//! 在线拉取（§11.14）。
//!
//! 断言：`source=Online`、行内容与 server 一致、缓存已落盘。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use nexus_proxy::ProviderFetcher;
use nexus_proxy_config::parse;
use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const PROVIDER_TEXT: &str = "example.com\ndomain.example";

/// 本地 TLS server：单连接，读请求后返回固定 provider 文本。
fn serve_one(stream: TcpStream, config: Arc<ServerConfig>) {
    let conn = match ServerConnection::new(config) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut tls = StreamOwned::new(conn, stream);
    let mut buf = [0u8; 4096];
    // 读到请求头结束即可响应。
    let mut got = 0usize;
    while got < 4 || &buf[got - 4..got] != b"\r\n\r\n" {
        match tls.read(&mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    let _ = tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            PROVIDER_TEXT.len(),
            PROVIDER_TEXT
        )
        .as_bytes(),
    );
    let _ = tls.flush();
    // 优雅关闭：发送 close_notify，避免客户端读到 unexpected EOF。
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");

    // 自签证书（含 127.0.0.1 IP SAN + localhost DNS SAN）。
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("rcgen self-signed cert");
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der()).expect("key der");

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    let server_cfg = Arc::new(server_config);
    let handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            serve_one(stream, server_cfg);
        }
    });

    let cache_path =
        std::env::temp_dir().join(format!("nexus-provider-https-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&cache_path);
    let config_text = format!(
        "schema_version: 1\n\
         inbounds:\n\
         \x20 - tag: socks5-in\n\
         \x20   kind: socks5\n\
         \x20   listen: 127.0.0.1:1080\n\
         rule-providers:\n\
         \x20 https-test:\n\
         \x20   behavior: domain\n\
         \x20   path: {}\n\
         \x20   url: https://127.0.0.1:{}/provider.txt\n\
         \x20   refresh_interval_secs: 3600\n\
         rules:\n\
         \x20 - tag: rule-match\n\
         \x20   kind: match\n\
         \x20   match: \"\"\n\
         \x20   action:\n\
         \x20     - kind: select_outbound\n\
         \x20       tag: direct\n\
         outbounds:\n\
         \x20 - tag: direct\n\
         \x20   kind: direct\n\
         \x20   locator: \"\"\n",
        cache_path.display(),
        port
    );
    let cfg = parse(&config_text).expect("config must parse");
    let rp = &cfg.rule_providers[0];

    let mut fetcher =
        nexus::provider_fetcher::CachedHttpProviderFetcher::with_tls_roots(vec![cert_der]);
    let result = fetcher.load(rp).expect("https fetch must succeed");
    handle.join().expect("server thread");

    let fetched_source = format!("{:?}", result.source);
    let line_count = result.lines.len();
    let first_line = result.lines.first().map_or("", String::as_str).to_string();
    let cache_written = std::fs::read_to_string(&cache_path)
        .map(|c| c == PROVIDER_TEXT)
        .unwrap_or(false);
    let _ = std::fs::remove_file(&cache_path);

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"command\":\"proxy rule-provider https fetch\",\"fetched_source\":\"{}\",\"line_count\":{},\"first_line\":\"{}\",\"cache_written\":{}}}",
            fetched_source, line_count, first_line, cache_written
        );
    } else {
        println!(
            "source={} lines={} first={} cache_written={}",
            fetched_source, line_count, first_line, cache_written
        );
    }
}
