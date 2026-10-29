//! Post-success late guard (PRODUCT §11.9.3, `late fallback response discarded`).
//!
//! The guard discards a first downstream `HTTP/` chunk that arrives after the
//! SOCKS5 success only while the client has not sent anything yet (the
//! fallback answering the Trojan header on its own). Once the client has sent
//! a request, an HTTP status line is the origin's answer and must be relayed:
//! plain HTTP over a correct-password Trojan node.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nexus::proxy_serve_once;
use nexus_outbound_trojan::{
    TrojanTarget, generate_loopback_identity, parse_request, server_config,
};

const NODE_PASSWORD: &str = "late-guard-password";
const HTTP_200: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
const HTTP_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn read_header<R: Read>(tls: &mut R) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    let mut one = [0u8; 1];
    while buf.windows(2).filter(|w| **w == *b"\r\n").count() < 2 {
        tls.read_exact(&mut one).expect("trojan header");
        buf.push(one[0]);
        assert!(buf.len() <= 4096, "header too large");
    }
    buf
}

/// One-connection TLS Trojan node. Right password: relay one request/response
/// to the 127.0.0.1 target port. Wrong password: act as a fallback that answers
/// `HTTP_404` on its own after `fallback_delay` (no client bytes needed).
fn spawn_node(fallback_delay: Duration) -> (u16, thread::JoinHandle<()>) {
    let identity = generate_loopback_identity().expect("identity");
    let cfg = Arc::new(server_config(&identity).expect("server config"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind node");
    let port = listener.local_addr().expect("node addr").port();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("node accept");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut srv = rustls::ServerConnection::new(cfg).expect("tls server");
        let mut tls = rustls::Stream::new(&mut srv, &mut tcp);
        let header = read_header(&mut tls);
        match parse_request(NODE_PASSWORD, &header) {
            Ok(target) => {
                let (TrojanTarget::Ipv4(_, p) | TrojanTarget::Domain(_, p)) = target;
                let mut origin = TcpStream::connect(("127.0.0.1", p)).expect("origin");
                let mut buf = [0u8; 1024];
                let n = tls.read(&mut buf).expect("client request");
                origin.write_all(&buf[..n]).expect("to origin");
                let mut back = Vec::new();
                let _ = origin.read_to_end(&mut back);
                tls.write_all(&back).expect("to client");
            }
            Err(_) => {
                thread::sleep(fallback_delay);
                tls.write_all(HTTP_404).expect("fallback response");
            }
        }
        let _ = tls.flush();
    });
    (port, handle)
}

/// Origin that answers `HTTP_200` to whatever request it reads.
fn spawn_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let port = listener.local_addr().expect("origin addr").port();
    thread::spawn(move || {
        if let Ok((mut c, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf);
            let _ = c.write_all(HTTP_200);
        }
    });
    port
}

fn config(node_port: u16, password: &str) -> String {
    format!(
        "schema_version: 1\n\
         inbounds:\n  - tag: s\n    kind: socks5\n    listen: 127.0.0.1:0\n\
         rules:\n  - tag: m\n    kind: match\n    match: \"\"\n    action:\n      \
         - kind: select_outbound\n        tag: t\n\
         outbounds:\n  - tag: t\n    kind: trojan\n    locator: \"127.0.0.1:{node_port}\"\n    \
         password: {password}\n    skip_cert_verify: true\n    ready_window_ms: 50\n"
    )
}

/// SOCKS5 CONNECT to 127.0.0.1:`dest_port`; returns the reply code and the client.
fn socks5_connect(proxy: std::net::SocketAddr, dest_port: u16) -> (u8, TcpStream) {
    let mut c = TcpStream::connect(proxy).expect("connect proxy");
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    c.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
    let mut method = [0u8; 2];
    c.read_exact(&mut method).expect("method reply");
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&dest_port.to_be_bytes());
    c.write_all(&req).expect("connect request");
    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).expect("connect reply");
    (reply[1], c)
}

#[test]
fn http_response_after_client_request_is_relayed() {
    let origin_port = spawn_origin();
    let (node_port, node) = spawn_node(Duration::ZERO);
    let cfg = config(node_port, NODE_PASSWORD);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let session = thread::spawn(move || proxy_serve_once(&listener, &cfg));

    let (rep, mut client) = socks5_connect(proxy_addr, origin_port);
    assert_eq!(rep, 0x00, "CONNECT must succeed with the right password");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: origin\r\n\r\n")
        .expect("request");
    let mut got = Vec::new();
    let _ = client.read_to_end(&mut got);
    drop(client);
    node.join().expect("node");
    let result = session.join().expect("session thread");
    assert_eq!(
        got, HTTP_200,
        "the origin's HTTP response must reach the client; session: {result:?}"
    );
    assert!(result.is_ok(), "session must succeed: {result:?}");
}

#[test]
fn late_http_fallback_before_any_client_bytes_is_still_discarded() {
    // 300 ms > the 50 ms window: the fallback answers after the success.
    let (node_port, node) = spawn_node(Duration::from_millis(300));
    let cfg = config(node_port, "wrong-password");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let session = thread::spawn(move || proxy_serve_once(&listener, &cfg));

    let (rep, mut client) = socks5_connect(proxy_addr, 9);
    assert_eq!(rep, 0x00, "window expires before the slow fallback answers");
    let mut got = Vec::new();
    let _ = client.read_to_end(&mut got);
    node.join().expect("node");
    let result = session.join().expect("session thread");
    assert!(
        got.is_empty(),
        "late fallback bytes reached the client: {got:?}"
    );
    let err = result.expect_err("session must fail");
    assert!(
        err.to_string().contains("late fallback response discarded"),
        "{err}"
    );
}

/// Right-password node that is its own origin: after the window it sends the
/// first two bytes of its status line (`HT`), waits for the client's request,
/// then sends the rest. The held prefix must reach the client in order.
fn spawn_split_status_node() -> (u16, thread::JoinHandle<()>) {
    let identity = generate_loopback_identity().expect("identity");
    let cfg = Arc::new(server_config(&identity).expect("server config"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind node");
    let port = listener.local_addr().expect("node addr").port();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("node accept");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut srv = rustls::ServerConnection::new(cfg).expect("tls server");
        let mut tls = rustls::Stream::new(&mut srv, &mut tcp);
        let header = read_header(&mut tls);
        parse_request(NODE_PASSWORD, &header).expect("password accepted");
        thread::sleep(Duration::from_millis(150));
        tls.write_all(&HTTP_200[..2]).expect("status prefix");
        let _ = tls.flush();
        let mut buf = [0u8; 1024];
        let _ = tls.read(&mut buf).expect("client request");
        tls.write_all(&HTTP_200[2..]).expect("status rest");
        let _ = tls.flush();
    });
    (port, handle)
}

#[test]
fn held_status_prefix_is_delivered_once_the_client_speaks() {
    let (node_port, node) = spawn_split_status_node();
    let cfg = config(node_port, NODE_PASSWORD);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let session = thread::spawn(move || proxy_serve_once(&listener, &cfg));

    let (rep, mut client) = socks5_connect(proxy_addr, 9);
    assert_eq!(rep, 0x00);
    // Let the 2-byte prefix arrive while the client is still silent.
    thread::sleep(Duration::from_millis(300));
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: origin\r\n\r\n")
        .expect("request");
    let mut got = Vec::new();
    let _ = client.read_to_end(&mut got);
    drop(client);
    node.join().expect("node");
    let result = session.join().expect("session thread");
    assert_eq!(
        got, HTTP_200,
        "held prefix must be delivered in order; session: {result:?}"
    );
    assert!(result.is_ok(), "session must succeed: {result:?}");
}

/// Right-password node that sends `HT` after the window and then only reads
/// until the connection ends.
fn spawn_prefix_then_wait_node() -> (u16, thread::JoinHandle<()>) {
    let identity = generate_loopback_identity().expect("identity");
    let cfg = Arc::new(server_config(&identity).expect("server config"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind node");
    let port = listener.local_addr().expect("node addr").port();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("node accept");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut srv = rustls::ServerConnection::new(cfg).expect("tls server");
        let mut tls = rustls::Stream::new(&mut srv, &mut tcp);
        let header = read_header(&mut tls);
        parse_request(NODE_PASSWORD, &header).expect("password accepted");
        thread::sleep(Duration::from_millis(150));
        tls.write_all(&HTTP_200[..2]).expect("status prefix");
        let _ = tls.flush();
        let mut buf = [0u8; 64];
        while matches!(tls.read(&mut buf), Ok(n) if n > 0) {}
    });
    (port, handle)
}

/// A client FIN is not client payload: the guard stays on and a held prefix
/// is never delivered.
#[test]
fn held_prefix_is_not_flushed_by_a_client_half_close() {
    let (node_port, node) = spawn_prefix_then_wait_node();
    let cfg = config(node_port, NODE_PASSWORD);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("proxy addr");
    let session = thread::spawn(move || proxy_serve_once(&listener, &cfg));

    let (rep, mut client) = socks5_connect(proxy_addr, 9);
    assert_eq!(rep, 0x00);
    thread::sleep(Duration::from_millis(300));
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("half-close");
    let mut got = Vec::new();
    let _ = client.read_to_end(&mut got);
    node.join().expect("node");
    let _ = session.join().expect("session thread");
    assert!(
        got.is_empty(),
        "a held prefix must not reach a client that never sent payload: {got:?}"
    );
}
