//! End-to-end gateway tests: HTTPS page, WSS signaling, WebRTC DataChannel to
//! two mesh nodes, and SSH terminal TCP forwarding to a mock sshd.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::Browser;
use nexus_web_gateway::config::{GatewayConfig, IceServer, MeshConfig, MeshNodeInfo, SshConfig, TlsConfig};
use nexus_web_gateway::protocol::{BrowserMessage, NodeMessage, SshAuth};
use nexus_web_gateway::Gateway;

const TEST_PASSWORD: &str = "hunter2";

fn test_config(node_id: &str, node_name: &str, listen: SocketAddr, ssh_target: SocketAddr) -> GatewayConfig {
    let node_list = vec![
        MeshNodeInfo {
            peer_id: "node-a".into(),
            name: "node-a".into(),
            addrs: vec!["127.0.0.1:8443".into()],
            services: vec!["ssh".into()],
        },
        MeshNodeInfo {
            peer_id: "node-b".into(),
            name: "node-b".into(),
            addrs: vec!["127.0.0.1:8444".into()],
            services: vec!["ssh".into()],
        },
    ];
    GatewayConfig {
        listen_addr: listen,
        node_id: node_id.into(),
        node_name: node_name.into(),
        node_list,
        ice_servers: vec![IceServer {
            urls: vec!["stun:stun.l.google.com:19302".into()],
            username: None,
            credential: None,
        }],
        tls: TlsConfig::AutoGenerate {
            names: vec!["localhost".into()],
            ips: vec!["127.0.0.1".parse().unwrap()],
        },
        ssh: SshConfig {
            target: ssh_target,
            auth_prologue: Some("AUTH {password}\n".into()),
            max_terminals: 5,
            idle_timeout_secs: 600,
        },
        mesh: MeshConfig::InMemory,
    }
}

fn spawn_mock_sshd() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock sshd");
    let addr = listener.local_addr().expect("local addr");
    let auth_count = Arc::new(AtomicUsize::new(0));
    let auth_count2 = auth_count.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut tcp = match conn {
                Ok(t) => t,
                Err(_) => continue,
            };
            let auth_count = auth_count2.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let mut line = Vec::new();
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            line.extend_from_slice(&buf[..n]);
                            if line.contains(&b'\n') {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let text = String::from_utf8_lossy(&line);
                if text.starts_with("AUTH ") {
                    auth_count.fetch_add(1, Ordering::SeqCst);
                    if tcp.write_all(b"AUTH_OK\n").is_err() {
                        return;
                    }
                }
                // Echo subsequent bytes back (mock shell).
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if tcp.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, auth_count)
}

/// Minimal HTTPS GET over rustls pinned to the gateway's self-signed cert.
fn https_get(cert_der: &[u8], addr: SocketAddr, path: &str) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error>> {
    use rustls::pki_types::{CertificateDer, ServerName};
    let cert = CertificateDer::from(cert_der.to_vec());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr)?;
    let sni = ServerName::try_from("localhost")?;
    let conn = rustls::ClientConnection::new(Arc::new(config), sni)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    write!(
        tls,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut resp = Vec::new();
    tls.read_to_end(&mut resp)?;
    let head_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = String::from_utf8_lossy(&resp[..head_end]).to_string();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .ok_or("no status")?
        .parse()?;
    Ok((status, resp[head_end + 4..].to_vec()))
}

#[test]
fn https_serves_page_and_config() {
    let (sshd_addr, _) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let handle = Gateway::start(cfg).expect("start gateway");
    let addr = handle.local_addr;

    let (status, body) = https_get(&handle.cert_der, addr, "/").expect("GET /");
    assert_eq!(status, 200);
    let page = String::from_utf8_lossy(&body);
    assert!(page.contains("Nexus Web Gateway"));
    assert!(page.contains("xterm.js"));

    let (status, body) = https_get(&handle.cert_der, addr, "/api/config").expect("GET /api/config");
    assert_eq!(status, 200);
    let cfg_json: serde_json::Value = serde_json::from_slice(&body).expect("config json");
    assert_eq!(cfg_json["node_id"], "node-a");
    assert_eq!(cfg_json["node_list"].as_array().map(|a| a.len()), Some(2));

    let (status, _) = https_get(&handle.cert_der, addr, "/nope").expect("GET /nope");
    assert_eq!(status, 404);
}

#[test]
fn wss_signaling_establishes_data_channel_and_node_list() {
    let (sshd_addr, _) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let handle = Gateway::start(cfg).expect("start gateway");
    let addr = handle.local_addr;

    let mut browser =
        Browser::connect_first(&handle.cert_der, addr, "node-a", "sess-1").expect("connect first");
    browser
        .drive_all(Duration::from_secs(5))
        .expect("drive");

    assert!(browser.peers[0].connected, "peer 0 should connect");
    // The gateway pushes HelloAck immediately; the browser should receive it.
    let ack = browser.peers[0]
        .take_message(|m| matches!(m, NodeMessage::HelloAck { .. }))
        .expect("hello_ack");
    match ack {
        NodeMessage::HelloAck {
            node_id,
            node_list,
            ice_servers,
            ..
        } => {
            assert_eq!(node_id, "node-a");
            assert_eq!(node_list.len(), 2);
            assert_eq!(ice_servers.len(), 1);
        }
        _ => unreachable!(),
    }
}

#[test]
fn two_mesh_nodes_data_channels() {
    let (sshd_addr, _) = spawn_mock_sshd();
    let mesh = Arc::new(nexus_web_gateway::mesh::InMemoryMeshSignaler::new());

    let cfg_a = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let handle_a = Gateway::start_with_mesh(cfg_a, mesh.clone()).expect("start node-a");

    let cfg_b = test_config("node-b", "node-b", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let _handle_b = Gateway::start_with_mesh(cfg_b, mesh).expect("start node-b");

    let mut browser = Browser::connect_first(
        &handle_a.cert_der,
        handle_a.local_addr,
        "node-a",
        "sess-2",
    )
    .expect("connect first");
    browser
        .drive_all(Duration::from_secs(5))
        .expect("drive first");

    browser
        .connect_node("node-b", "node-b")
        .expect("connect node-b");
    browser
        .drive_all(Duration::from_secs(5))
        .expect("drive all");

    assert!(browser.peers[0].connected, "peer A should be connected");
    assert!(browser.peers[1].connected, "peer B should be connected");

    // Node B's gateway also sends HelloAck with the node list.
    let ack_b = browser.peers[1]
        .take_message(|m| matches!(m, NodeMessage::HelloAck { .. }))
        .expect("node-b hello_ack");
    match ack_b {
        NodeMessage::HelloAck { node_id, .. } => assert_eq!(node_id, "node-b"),
        _ => unreachable!(),
    }
}

#[test]
fn ssh_terminal_forwarding_with_auth() -> TestResult {
    let (sshd_addr, auth_count) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let handle = Gateway::start(cfg).expect("start gateway");
    let addr = handle.local_addr;

    let mut browser =
        Browser::connect_first(&handle.cert_der, addr, "node-a", "sess-3").expect("connect first");
    browser
        .drive_all(Duration::from_secs(5))
        .expect("drive");

    // Open an SSH terminal on node A.
    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-1".into(),
            target: "node-a".into(),
            auth: Some(SshAuth::Password {
                username: "root".into(),
                password: TEST_PASSWORD.into(),
            }),
        })
        .expect("send ssh_open");

    // Drive until the ack arrives.
    let ack = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { session_id, status, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            break (session_id, status);
        }
    };
    assert_eq!(ack.0, "term-1");
    assert_eq!(ack.1, "ok");
    assert_eq!(auth_count.load(Ordering::SeqCst), 1, "mock sshd saw AUTH");

    // The mock sshd's "AUTH_OK" arrives as the first ssh_data.
    let auth_ok = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshData { data, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshData { .. }))
        {
            break data;
        }
    };
    let auth_ok = String::from_utf8(b64decode_for_test(&auth_ok)).expect("utf8");
    assert!(auth_ok.contains("AUTH_OK"), "got {auth_ok:?}");

    // Send terminal input; the mock sshd echoes it back.
    browser.peers[0]
        .send(&BrowserMessage::SshData {
            session_id: "term-1".into(),
            data: b64encode_for_test(b"echo hello\n"),
        })
        .expect("send ssh_data");

    let echo = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshData { data, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshData { .. }))
        {
            break data;
        }
    };
    let echo = String::from_utf8(b64decode_for_test(&echo)).expect("utf8");
    assert!(echo.contains("echo hello"), "got {echo:?}");

    // Close the terminal.
    browser.peers[0]
        .send(&BrowserMessage::SshClose {
            session_id: "term-1".into(),
        })
        .expect("send ssh_close");
    Ok(())
}

#[test]
fn ssh_target_unreachable_returns_error() -> TestResult {
    // Point at a closed port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let dead_addr = listener.local_addr().expect("addr");
    drop(listener);

    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), dead_addr);
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-4")
            .expect("connect first");
    browser
        .drive_all(Duration::from_secs(5))
        .expect("drive");

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-x".into(),
            target: "node-a".into(),
            auth: None,
        })
        .expect("send ssh_open");

    let ack = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { status, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            break status;
        }
    };
    assert_eq!(ack, "error");
    Ok(())
}

#[test]
fn max_terminals_limit() -> TestResult {
    let (sshd_addr, _) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    // Override max_terminals to 1.
    let mut cfg = cfg;
    cfg.ssh.max_terminals = 1;
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-5")
            .expect("connect first");
    browser
        .drive_all(Duration::from_secs(5))
        .expect("drive");

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "t1".into(),
            target: "node-a".into(),
            auth: None,
        })
        .expect("send t1");
    let first = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { status, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            break status;
        }
    };
    assert_eq!(first, "ok");

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "t2".into(),
            target: "node-a".into(),
            auth: None,
        })
        .expect("send t2");
    let second = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { status, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            break status;
        }
    };
    assert_eq!(second, "error");
    Ok(())
}

/// WSS handshake probe: connect to `/ws` and read the 101 response status.
#[test]
fn wss_endpoint_upgrades() {
    let (sshd_addr, _) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let handle = Gateway::start(cfg).expect("start gateway");

    // A raw WSS handshake with a random Sec-WebSocket-Key should get 101.
    use rustls::pki_types::{CertificateDer, ServerName};
    let cert = CertificateDer::from(handle.cert_der.clone());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add root");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(handle.local_addr).expect("connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let conn = rustls::ClientConnection::new(Arc::new(config), sni).expect("client conn");
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    write!(
        tls,
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .expect("write request");
    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    // Read until the end of the response head.
    while !resp.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => resp.push(byte[0]),
            Err(e) => panic!("read response: {e}"),
        }
    }
    let head = String::from_utf8_lossy(&resp);
    assert!(head.starts_with("HTTP/1.1 101"), "got: {head}");
}

fn b64encode_for_test(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64decode_for_test(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .expect("valid base64")
}

type TestResult = Result<(), Box<dyn std::error::Error>>;