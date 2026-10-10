//! End-to-end gateway tests: HTTPS page, WSS signaling, WebRTC DataChannel to
//! two mesh nodes, and SSH terminal against a real sshd subprocess.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{Browser, TestSshd};
use nexus_web_gateway::Gateway;
use nexus_web_gateway::config::{
    GatewayConfig, IceServer, MeshConfig, MeshNodeInfo, MeshPeer, SshConfig, TlsConfig,
};
use nexus_web_gateway::protocol::{BrowserMessage, NodeMessage};

static CERT_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Serializes WSS gateway port reservation + startup. `reserve_port()`
/// reserves a loopback port by binding then releasing a listener, so two WSS
/// mesh tests running in parallel could otherwise grab the same port before
/// the gateway binds it (observed as intermittent `AddrInUse` in full
/// workspace runs). Holding this lock across reserve + `Gateway::start` makes
/// the bind-drop-bind reservation race-free.
static GATEWAY_START_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Unique per-test certificate directory (tests run in parallel in one process).
fn unique_cert_dir(node_id: &str) -> String {
    let seq = CERT_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join("nexus-web-gateway-test-certs")
        .join(format!("{node_id}-{}-{seq}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

fn test_config(
    node_id: &str,
    node_name: &str,
    listen: SocketAddr,
    ssh_target: SocketAddr,
) -> GatewayConfig {
    let cert_dir = unique_cert_dir(node_id);
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
            cert_dir: Some(cert_dir),
        },
        ssh: SshConfig {
            target: ssh_target,
            max_terminals: 5,
            idle_timeout_secs: 600,
        },
        mesh: MeshConfig::InMemory,
    }
}

/// Reserve a loopback port and return its address (no listener stays bound).
fn dead_ssh_target() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("local addr");
    drop(l);
    addr
}

/// Minimal HTTPS GET over rustls pinned to the gateway's self-signed cert.
fn https_get(
    cert_der: &[u8],
    addr: SocketAddr,
    path: &str,
) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error>> {
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
    let status: u16 = head.split_whitespace().nth(1).ok_or("no status")?.parse()?;
    Ok((status, resp[head_end + 4..].to_vec()))
}

#[test]
fn https_serves_page_config_and_cert() {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");
    let addr = handle.local_addr;

    let (status, body) = https_get(&handle.cert_der, addr, "/").expect("GET /");
    assert_eq!(status, 200);
    let page = String::from_utf8_lossy(&body);
    assert!(page.contains("Nexus Web Gateway"));
    assert!(page.contains("xterm.js"));
    // Error banner elements: layered, dismissible, retry/back actions
    assert!(page.contains("id=\"first-node-error\""));
    assert!(page.contains("id=\"error-badge\""));
    assert!(page.contains("id=\"error-close-btn\""));
    assert!(page.contains("id=\"banner-retry-btn\""));
    assert!(page.contains("id=\"banner-back-btn\""));
    // B4 CA Certificate guidance card: independent section with download link
    assert!(page.contains("id=\"cert-guidance-card\""));
    assert!(page.contains("href=\"/cert\""));

    let (status, body) = https_get(&handle.cert_der, addr, "/api/config").expect("GET /api/config");
    assert_eq!(status, 200);
    let cfg_json: serde_json::Value = serde_json::from_slice(&body).expect("config json");
    assert_eq!(cfg_json["node_id"], "node-a");
    assert_eq!(cfg_json["node_list"].as_array().map(|a| a.len()), Some(2));

    // The local CA must be downloadable so the "install the local CA" guidance
    // is not a dead end.
    let (status, body) = https_get(&handle.cert_der, addr, "/cert").expect("GET /cert");
    assert_eq!(status, 200);
    let pem = String::from_utf8_lossy(&body);
    assert!(pem.contains("BEGIN CERTIFICATE"), "got: {pem}");

    let (status, _) = https_get(&handle.cert_der, addr, "/nope").expect("GET /nope");
    assert_eq!(status, 404);
}

#[test]
fn unspecified_listen_addr_derives_concrete_page_addr() {
    let cfg = test_config(
        "node-a",
        "node-a",
        "0.0.0.0:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway with 0.0.0.0");

    // The HTTPS listener is still on the unspecified address...
    assert!(handle.local_addr.ip().is_unspecified());
    // ...but the browser-facing page address must be concrete (never
    // `https://0.0.0.0:.../`, which real browsers cannot open).
    assert!(!handle.page_addr.ip().is_unspecified());
    // The page address must carry the actual bound port (ephemeral here).
    assert_eq!(handle.page_addr.port(), handle.local_addr.port());
}

#[test]
fn wss_signaling_establishes_data_channel_and_node_list() {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");
    let addr = handle.local_addr;

    let mut browser =
        Browser::connect_first(&handle.cert_der, addr, "node-a", "sess-1").expect("connect first");
    browser.drive_all(Duration::from_secs(5)).expect("drive");

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
fn wss_signaling_stays_open_after_offer() -> TestResult {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser = Browser::connect_first(
        &handle.cert_der,
        handle.local_addr,
        "node-a",
        "sess-keepalive",
    )
    .expect("connect first");
    browser.drive_all(Duration::from_secs(2))?;

    // The browser sends exactly one offer and then goes silent over WSS (the
    // data plane runs on WebRTC DataChannels). The gateway must NOT impose its
    // HTTP-read timeout on the upgraded WebSocket: a healthy connection has to
    // stay open well past the old 15s cutoff, otherwise the frontend surfaces
    // a bogus "Signaling closed" error that also covers the B4 ICE guidance.
    std::thread::sleep(Duration::from_secs(16));

    // The socket must still be readable (i.e. not closed by the server).
    browser
        .ws
        .get_mut()
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(500)))?;
    match browser.ws.read() {
        Err(tungstenite::Error::Io(e))
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(tungstenite::Error::ConnectionClosed) => {
            return Err("signaling WebSocket was closed after offer".into());
        }
        Err(e) => return Err(format!("unexpected read result: {e}").into()),
        Ok(_) => {}
    }

    // And it must still accept writes (send a session close).
    browser.ws.send(tungstenite::Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "close",
            "session_id": browser.session_id,
        }))
        .expect("close json"),
    ))?;

    Ok(())
}

#[test]
fn two_mesh_nodes_data_channels() {
    let mesh = Arc::new(nexus_web_gateway::mesh::InMemoryMeshSignaler::new());

    let cfg_a = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle_a = Gateway::start_with_mesh(cfg_a, mesh.clone()).expect("start node-a");

    let cfg_b = test_config(
        "node-b",
        "node-b",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let _handle_b = Gateway::start_with_mesh(cfg_b, mesh).expect("start node-b");

    let mut browser =
        Browser::connect_first(&handle_a.cert_der, handle_a.local_addr, "node-a", "sess-2")
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
fn ssh_terminal_against_real_sshd() -> TestResult {
    let sshd = TestSshd::spawn()?;
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
    );
    let handle = Gateway::start(cfg).expect("start gateway");
    let addr = handle.local_addr;

    let mut browser =
        Browser::connect_first(&handle.cert_der, addr, "node-a", "sess-3").expect("connect first");
    browser.drive_all(Duration::from_secs(5)).expect("drive");

    // Open an SSH terminal on node A with a real key over a real sshd.
    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-1".into(),
            target: "node-a".into(),
            auth: Some(sshd.key_auth()),
        })
        .expect("send ssh_open");

    let ack = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck {
            session_id, status, ..
        }) = browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            break (session_id, status);
        }
    };
    assert_eq!(ack.0, "term-1");
    assert_eq!(ack.1, "ok", "SSH terminal should open on the real sshd");

    // The shell starts; send a command and expect its echoed output back.
    browser.peers[0]
        .send(&BrowserMessage::SshData {
            session_id: "term-1".into(),
            data: b64encode_for_test(b"echo SSH_REAL_TEST_42\n"),
        })
        .expect("send ssh_data");

    let echo = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshData { data, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshData { .. }))
        {
            if String::from_utf8_lossy(&b64decode_for_test(&data)).contains("SSH_REAL_TEST_42") {
                break data;
            }
        }
    };
    let echo = String::from_utf8(b64decode_for_test(&echo)).expect("utf8");
    assert!(echo.contains("SSH_REAL_TEST_42"), "got {echo:?}");

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
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-4")
            .expect("connect first");
    browser.drive_all(Duration::from_secs(5)).expect("drive");

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-x".into(),
            target: "node-a".into(),
            auth: None,
        })
        .expect("send ssh_open");

    let ack = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck { status, error, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            assert_eq!(status, "error");
            assert!(error.is_some(), "expected an error string");
            break status;
        }
    };
    assert_eq!(ack, "error");
    Ok(())
}

#[test]
fn max_terminals_limit() -> TestResult {
    let sshd = TestSshd::spawn()?;
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
    );
    // Override max_terminals to 1.
    let mut cfg = cfg;
    cfg.ssh.max_terminals = 1;
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-5")
            .expect("connect first");
    browser.drive_all(Duration::from_secs(5)).expect("drive");

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "t1".into(),
            target: "node-a".into(),
            auth: Some(sshd.key_auth()),
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
            auth: Some(sshd.key_auth()),
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
    let sshd = TestSshd::spawn()?;
    let mut cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
    );
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
            auth: Some(sshd.key_auth()),
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
        if let Some(NodeMessage::SshClose { session_id, reason }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshClose { .. }))
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
fn ssh_worker_exits_on_session_close() -> TestResult {
    let sshd = TestSshd::spawn()?;
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        sshd.addr,
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser =
        Browser::connect_first(&handle.cert_der, handle.local_addr, "node-a", "sess-leak")
            .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;

    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-1".into(),
            target: "node-a".into(),
            auth: Some(sshd.key_auth()),
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

    // Drop the browser session via the WSS signaling channel. The event loop
    // removes the Session, which must stop the SSH worker thread and close the
    // connection to the sshd.
    browser.ws.send(tungstenite::Message::Text(
        serde_json::to_string(&serde_json::json!({
            "type": "close",
            "session_id": browser.session_id,
        }))
        .expect("close json"),
    ))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if established_connections(sshd.addr.port()) == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for ssh worker thread to exit".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Count established TCP connections to a loopback port (via `ss`).
fn established_connections(port: u16) -> usize {
    let out = std::process::Command::new("ss")
        .args([
            "-tn",
            "state",
            "established",
            "( sport = :",
            &port.to_string(),
            ")",
        ])
        .output();
    let Ok(out) = out else { return 0 };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter(|l| l.trim_start().starts_with("ESTAB"))
        .count()
}

#[test]
fn unknown_ssh_data_returns_ssh_close() -> TestResult {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser = Browser::connect_first(
        &handle.cert_der,
        handle.local_addr,
        "node-a",
        "sess-unknown",
    )
    .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;

    // Send terminal bytes for a session that was never opened. The gateway must
    // not silently swallow them: it must answer with an explicit ssh_close.
    browser.peers[0]
        .send(&BrowserMessage::SshData {
            session_id: "no-such-session".into(),
            data: b64encode_for_test(b"x"),
        })
        .expect("send ssh_data");

    let close = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshClose { session_id, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshClose { .. }))
        {
            break session_id;
        }
    };
    assert_eq!(close, "no-such-session");
    Ok(())
}

#[test]
fn reoffer_to_existing_session_returns_error_not_bogus_answer() -> TestResult {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser = Browser::connect_first(
        &handle.cert_der,
        handle.local_addr,
        "node-a",
        "sess-reoffer",
    )
    .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;

    // Try to reconnect node-a with the same session id (the old behaviour that
    // triggered the reconnect storm). The gateway must reject loudly instead of
    // returning an answer whose mid does not match the new offer.
    let (rtc, udp, offer, pending) = common::create_rtc_with_channel()?;
    let sdp = nexus_web_gateway::protocol::SdpPayload {
        kind: "offer".into(),
        sdp: offer.to_sdp_string(),
    };
    browser.peers[0].send(&BrowserMessage::RelayOffer {
        target: "node-a".into(),
        session_id: browser.session_id.clone(),
        sdp,
    })?;

    let err = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::RelayError { error, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::RelayError { .. }))
        {
            break error;
        }
    };
    assert!(
        err.contains("already exists"),
        "expected session-already-exists error, got {err:?}"
    );
    let _ = pending;
    let _ = rtc;
    let _ = udp;
    Ok(())
}

#[test]
fn two_nodes_reoffer_storm_returns_error() -> TestResult {
    let mesh = Arc::new(nexus_web_gateway::mesh::InMemoryMeshSignaler::new());
    let cfg_a = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle_a = Gateway::start_with_mesh(cfg_a, mesh.clone()).expect("start node-a");
    let cfg_b = test_config(
        "node-b",
        "node-b",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let _handle_b = Gateway::start_with_mesh(cfg_b, mesh).expect("start node-b");

    let mut browser = Browser::connect_first(
        &handle_a.cert_der,
        handle_a.local_addr,
        "node-a",
        "sess-storm",
    )
    .expect("connect first");
    browser.drive_all(Duration::from_secs(5))?;
    browser
        .connect_node("node-b", "node-b")
        .expect("connect node-b");
    browser.drive_all(Duration::from_secs(5))?;
    assert!(browser.peers[1].connected, "node B should be connected");

    // Simulate the old app.js reconnect storm: after node-b's hello_ack the
    // browser reconnects to node-b with the same session_id and a fresh offer.
    // The gateway must reject loudly instead of returning a bogus old-mid
    // answer, and the existing node-b channel must stay healthy.
    let (rtc, udp, offer, pending) = common::create_rtc_with_channel()?;
    let sdp = nexus_web_gateway::protocol::SdpPayload {
        kind: "offer".into(),
        sdp: offer.to_sdp_string(),
    };
    browser.peers[0].send(&BrowserMessage::RelayOffer {
        target: "node-b".into(),
        session_id: browser.session_id.clone(),
        sdp,
    })?;

    let err = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::RelayError { error, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::RelayError { .. }))
        {
            break error;
        }
    };
    assert!(
        err.contains("already exists"),
        "expected session-already-exists error, got {err:?}"
    );
    assert!(
        browser.peers[1].connected,
        "existing peer B should stay connected"
    );
    let _ = pending;
    let _ = rtc;
    let _ = udp;
    Ok(())
}

#[test]
fn wss_mesh_relay_between_two_gateways() -> TestResult {
    let _gate_lock = GATEWAY_START_LOCK.lock().expect("gateway start lock");
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

    let cfg_a = gateway_cfg_wss(
        "node-a",
        addr_a,
        node_list.clone(),
        "token-a",
        "node-b",
        format!("wss://127.0.0.1:{port_b}/mesh"),
        "token-b",
        dead_ssh_target(),
    );
    let cfg_b = gateway_cfg_wss(
        "node-b",
        addr_b,
        node_list,
        "token-b",
        "node-a",
        format!("wss://127.0.0.1:{port_a}/mesh"),
        "token-a",
        dead_ssh_target(),
    );

    let handle_a = Gateway::start(cfg_a)?;
    let _handle_b = Gateway::start(cfg_b)?;
    drop(_gate_lock);

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

#[test]
fn wss_mesh_ssh_relay_between_two_gateways() -> TestResult {
    let sshd = TestSshd::spawn()?;
    let _gate_lock = GATEWAY_START_LOCK.lock().expect("gateway start lock");
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

    let cfg_a = gateway_cfg_wss(
        "node-a",
        addr_a,
        node_list.clone(),
        "token-a",
        "node-b",
        format!("wss://127.0.0.1:{port_b}/mesh"),
        "token-b",
        sshd.addr,
    );
    let cfg_b = gateway_cfg_wss(
        "node-b",
        addr_b,
        node_list,
        "token-b",
        "node-a",
        format!("wss://127.0.0.1:{port_a}/mesh"),
        "token-a",
        sshd.addr,
    );

    let handle_a = Gateway::start(cfg_a)?;
    let _handle_b = Gateway::start(cfg_b)?;
    drop(_gate_lock);

    // Browser joins only node-a (no direct DataChannel to node-b).
    let mut browser = Browser::connect_first(
        &handle_a.cert_der,
        handle_a.local_addr,
        "node-a",
        "sess-ssh-relay",
    )
    .expect("connect first");
    let t0 = std::time::Instant::now();
    browser.drive_all(Duration::from_secs(5))?;
    eprintln!("[timing] connect_first done: {:?}", t0.elapsed());

    // Open an SSH terminal on node-b through the mesh relay. The target node
    // runs a real SSH client against the real sshd.
    browser.peers[0]
        .send(&BrowserMessage::SshOpen {
            session_id: "term-relay".into(),
            target: "node-b".into(),
            auth: Some(sshd.key_auth()),
        })
        .expect("send ssh_open");

    let ack = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshOpenAck {
            session_id, status, ..
        }) = browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshOpenAck { .. }))
        {
            break (session_id, status);
        }
    };
    assert_eq!(ack.0, "term-relay");
    assert_eq!(ack.1, "ok", "relayed SSH terminal should open");
    eprintln!("[timing] ssh_open ack: {:?}", t0.elapsed());

    // Terminal input is relayed to node-b's sshd and echoed back.
    browser.peers[0]
        .send(&BrowserMessage::SshData {
            session_id: "term-relay".into(),
            data: b64encode_for_test(b"echo RELAYED_SSH_7\n"),
        })
        .expect("send ssh_data");
    let echo = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(NodeMessage::SshData { data, .. }) =
            browser.peers[0].take_message(|m| matches!(m, NodeMessage::SshData { .. }))
        {
            if String::from_utf8_lossy(&b64decode_for_test(&data)).contains("RELAYED_SSH_7") {
                break data;
            }
        }
    };
    let echo = String::from_utf8(b64decode_for_test(&echo)).expect("utf8");
    assert!(echo.contains("RELAYED_SSH_7"), "got {echo:?}");
    eprintln!("[timing] echo data: {:?}", t0.elapsed());

    // Close the relayed terminal.
    browser.peers[0]
        .send(&BrowserMessage::SshClose {
            session_id: "term-relay".into(),
        })
        .expect("send ssh_close");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn gateway_cfg_wss(
    node_id: &str,
    listen: SocketAddr,
    node_list: Vec<MeshNodeInfo>,
    token: &str,
    peer_id: &str,
    peer_url: String,
    peer_token: &str,
    ssh_target: SocketAddr,
) -> GatewayConfig {
    let cert_dir = unique_cert_dir(node_id);
    GatewayConfig {
        listen_addr: listen,
        node_id: node_id.into(),
        node_name: node_id.into(),
        node_list,
        ice_servers: vec![],
        tls: TlsConfig::AutoGenerate {
            names: vec!["localhost".into()],
            ips: vec!["127.0.0.1".parse().unwrap()],
            cert_dir: Some(cert_dir),
        },
        ssh: SshConfig {
            target: ssh_target,
            max_terminals: 5,
            idle_timeout_secs: 600,
        },
        mesh: MeshConfig::Wss {
            token: token.into(),
            peers: vec![MeshPeer {
                peer_id: peer_id.into(),
                url: peer_url,
                token: peer_token.into(),
            }],
        },
    }
}

/// WSS handshake probe: connect to `/ws` and read the 101 response status.
#[test]
fn wss_endpoint_upgrades() {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
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
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
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

#[test]
fn wss_signaling_heartbeat_ping_pong() -> TestResult {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let url = format!("wss://127.0.0.1:{}/ws", handle.local_addr.port());
    let mut ws = common::connect_wss(&handle.cert_der, &url)?;

    // Send heartbeat ping over WSS signaling
    ws.send(tungstenite::Message::Text(r#"{"type":"ping"}"#.into()))?;

    let pong = common::read_ws_json(&mut ws)?;
    assert_eq!(
        pong.get("type").and_then(|v| v.as_str()),
        Some("pong"),
        "expected pong response, got {pong:?}"
    );
    Ok(())
}

#[test]
fn control_channel_heartbeat_ping_pong() -> TestResult {
    let cfg = test_config(
        "node-a",
        "node-a",
        "127.0.0.1:0".parse().unwrap(),
        dead_ssh_target(),
    );
    let handle = Gateway::start(cfg).expect("start gateway");

    let mut browser = Browser::connect_first(
        &handle.cert_der,
        handle.local_addr,
        "node-a",
        "sess-pingpong",
    )?;
    browser.drive_all(Duration::from_secs(5))?;
    assert!(browser.peers[0].connected, "peer 0 should connect");

    // Send Ping over control DataChannel
    browser.peers[0].send(&BrowserMessage::Ping)?;

    let pong = loop {
        browser.drive_all(Duration::from_millis(100))?;
        if let Some(msg) = browser.peers[0].take_message(|m| matches!(m, NodeMessage::Pong)) {
            break msg;
        }
    };
    assert_eq!(pong, NodeMessage::Pong);
    Ok(())
}

/// Reserve a loopback TCP port by binding then releasing a listener.
fn reserve_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
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
