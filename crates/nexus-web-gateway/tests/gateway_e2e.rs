//! End-to-end gateway tests: HTTPS page, WSS signaling, WebRTC DataChannel to
//! two mesh nodes, and SSH terminal TCP forwarding to a mock sshd.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::Browser;
use nexus_web_gateway::config::{
    GatewayConfig, IceServer, MeshConfig, MeshNodeInfo, MeshPeer, SshConfig, TlsConfig,
};
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

fn spawn_mock_sshd() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock sshd");
    let addr = listener.local_addr().expect("local addr");
    let auth_count = Arc::new(AtomicUsize::new(0));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let auth_count2 = auth_count.clone();
    let active2 = active_connections.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut tcp = match conn {
                Ok(t) => t,
                Err(_) => continue,
            };
            let auth_count = auth_count2.clone();
            let active = active2.clone();
            std::thread::spawn(move || {
                active.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let mut line = Vec::new();
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) => {
                            active.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                        Ok(n) => {
                            line.extend_from_slice(&buf[..n]);
                            if line.contains(&b'\n') {
                                break;
                            }
                        }
                        Err(_) => {
                            active.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&line);
                if text.starts_with("AUTH ") {
                    auth_count.fetch_add(1, Ordering::SeqCst);
                    if tcp.write_all(b"AUTH_OK\n").is_err() {
                        active.fetch_sub(1, Ordering::SeqCst);
                        return;
                    }
                }
                // Echo subsequent bytes back (mock shell).
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) | Err(_) => {
                            active.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                        Ok(n) => {
                            if tcp.write_all(&buf[..n]).is_err() {
                                active.fetch_sub(1, Ordering::SeqCst);
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, auth_count, active_connections)
}

/// Reserve a loopback TCP port by binding then releasing a listener.
fn reserve_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
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
    let (sshd_addr, _, _) = spawn_mock_sshd();
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
    let (sshd_addr, _, _) = spawn_mock_sshd();
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
    let (sshd_addr, _, _) = spawn_mock_sshd();
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
    let (sshd_addr, auth_count, _) = spawn_mock_sshd();
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
    let (sshd_addr, _, _) = spawn_mock_sshd();
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

#[test]
fn ssh_idle_timeout_closes_terminal() -> TestResult {
    let (sshd_addr, _, _) = spawn_mock_sshd();
    let mut cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    cfg.ssh.idle_timeout_secs = 1;
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-idle")
            .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-idle".into(),
            target: "node-a".into(),
            auth: None,
        })
        .expect("send ssh_open");
    loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { status, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            assert_eq!(status, "ok");
            break;
        }
    }

    // The bridge is idle; the gateway must close it after ~1s.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshClose {
            session_id,
            reason,
        }) = browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshClose { .. }))
        {
            assert_eq!(session_id, "term-idle");
            assert!(reason.contains("idle"), "reason: {reason}");
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for idle ssh_close".into());
        }
    }
    Ok(())
}

#[test]
fn ssh_reader_thread_exits_on_session_close() -> TestResult {
    let (sshd_addr, _, active) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-leak")
            .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-1".into(),
            target: "node-a".into(),
            auth: None,
        })
        .expect("send ssh_open");
    loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { status, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            assert_eq!(status, "ok");
            break;
        }
    }
    assert_eq!(active.load(Ordering::SeqCst), 1, "mock sshd has one active conn");

    // Drop the browser session via the WSS signaling channel. The event loop
    // removes the Session, which must stop the reader thread and close TCP.
    browser.ws.send(tungstenite::Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "close",
            "session_id": browser.session_id,
        }))
        .expect("close json"),
    ))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        browser.drive_all(Duration::from_millis(100))?;
        if active.load(Ordering::SeqCst) == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for ssh reader thread to exit".into());
        }
    }
    Ok(())
}

#[test]
fn wss_mesh_relay_between_two_gateways() -> TestResult {
    let (sshd_addr, _, _) = spawn_mock_sshd();
    let port_a = reserve_port();
    let port_b = reserve_port();
    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let node_list = vec![
        MeshNodeInfo {
            peer_id: "node-a".into(),
            name: "node-a".into(),
            addrs: vec![format!("127.0.0.1:{port_a}")],
            services: vec!["ssh".into()],
        },
        MeshNodeInfo {
            peer_id: "node-b".into(),
            name: "node-b".into(),
            addrs: vec![format!("127.0.0.1:{port_b}")],
            services: vec!["ssh".into()],
        },
    ];

    let cfg_a = GatewayConfig {
        listen_addr: addr_a,
        node_id: "node-a".into(),
        node_name: "node-a".into(),
        node_list: node_list.clone(),
        ice_servers: vec![],
        tls: TlsConfig::AutoGenerate {
            names: vec!["localhost".into()],
            ips: vec!["127.0.0.1".parse().unwrap()],
        },
        ssh: SshConfig {
            target: sshd_addr,
            auth_prologue: None,
            max_terminals: 5,
            idle_timeout_secs: 600,
        },
        mesh: MeshConfig::Wss {
            token: "token-a".into(),
            peers: vec![MeshPeer {
                peer_id: "node-b".into(),
                url: format!("wss://127.0.0.1:{port_b}/mesh"),
                token: "token-b".into(),
            }],
        },
    };
    let cfg_b = GatewayConfig {
        listen_addr: addr_b,
        node_id: "node-b".into(),
        node_name: "node-b".into(),
        node_list,
        ice_servers: vec![],
        tls: TlsConfig::AutoGenerate {
            names: vec!["localhost".into()],
            ips: vec!["127.0.0.1".parse().unwrap()],
        },
        ssh: SshConfig {
            target: sshd_addr,
            auth_prologue: None,
            max_terminals: 5,
            idle_timeout_secs: 600,
        },
        mesh: MeshConfig::Wss {
            token: "token-b".into(),
            peers: vec![MeshPeer {
                peer_id: "node-a".into(),
                url: format!("wss://127.0.0.1:{port_a}/mesh"),
                token: "token-a".into(),
            }],
        },
    };

    let handle_a = Gateway::start(cfg_a)?;
    let _handle_b = Gateway::start(cfg_b)?;

    let mut browser = Browser::connect_first(
        &handle_a.cert_der,
        handle_a.local_addr,
        "node-a",
        "sess-wss-mesh",
    )
    .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;

    browser
        .connect_node("node-b", "node-b")
        .expect("connect node-b");
    browser.drive_all(Duration::from_secs(5))?;

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
    Ok(())
}

/// WSS handshake probe: connect to `/ws` and read the 101 response status.
#[test]
fn wss_endpoint_upgrades() {
    let (sshd_addr, _, _) = spawn_mock_sshd();
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

/// Raw WSS upgrade request with an extra header; returns the response head.
fn wss_upgrade_head(
    cert_der: &[u8],
    addr: SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> String {
    use rustls::pki_types::{CertificateDer, ServerName};
    let cert = CertificateDer::from(cert_der.to_vec());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("add root");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).expect("connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let conn = rustls::ClientConnection::new(Arc::new(config), sni).expect("client conn");
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    write!(tls, "{head}").expect("write request");
    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => resp.push(byte[0]),
            Err(e) => panic!("read response: {e}"),
        }
    }
    String::from_utf8_lossy(&resp).to_string()
}

#[test]
fn mesh_endpoint_rejects_bad_token() {
    let (sshd_addr, _, _) = spawn_mock_sshd();
    let cfg = test_config("node-a", "node-a", "127.0.0.1:0".parse().unwrap(), sshd_addr);
    let mut cfg = cfg;
    cfg.mesh = MeshConfig::Wss {
        token: "token-a".into(),
        peers: vec![],
    };
    let handle = Gateway::start(cfg).expect("start gateway");

    // Wrong token -> 401.
    let head = wss_upgrade_head(
        &handle.cert_der,
        handle.local_addr,
        "/mesh",
        &[("Authorization", "Bearer wrong")],
    );
    assert!(head.starts_with("HTTP/1.1 401"), "got: {head}");

    // Missing token -> 401.
    let head = wss_upgrade_head(&handle.cert_der, handle.local_addr, "/mesh", &[]);
    assert!(head.starts_with("HTTP/1.1 401"), "got: {head}");

    // Correct token -> 101.
    let head = wss_upgrade_head(
        &handle.cert_der,
        handle.local_addr,
        "/mesh",
        &[("Authorization", "Bearer token-a")],
    );
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