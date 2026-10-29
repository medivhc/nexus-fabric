//! WP1b / spec §19 acceptance evidence: a real `nexusd` process with
//! `[network.n1] enabled` must print the exact TLS-rejection log line when an
//! unlisted identity dials its mTLS listener.
//!
//! This is intentionally a black-box process test: it reads the daemon's
//! captured stderr, so "the string exists in code" cannot pass.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nexus_fabric::{ConnConfig, FabricConn, FabricIdentity};

const REJECTION_LINE: &str =
    "[n1-listen] tls handshake rejected (peer unauthenticated or protocol error)";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "nexusd-n1-reject-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kill the daemon even when an assertion panics, so a failing run cannot
/// leave a stray listener behind.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_config(
    dir: &Path,
    server: &FabricIdentity,
    allowed: &FabricIdentity,
    n1_addr: SocketAddr,
    api_addr: SocketAddr,
) {
    let seed = dir.join("seed.hex");
    // Test-only deterministic seed (never a real key).
    std::fs::write(&seed, "5a".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    std::fs::write(
        dir.join("network.toml"),
        format!(
            "peer_id = \"{}\"\n\
             [[peers]]\n\
             id = \"{}\"\n\
             addrs = [\"127.0.0.1:1\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             mtu = 1200\n",
            hex32(&server.peer_id().0),
            hex32(&allowed.peer_id().0),
        ),
    )
    .unwrap();

    std::fs::write(
        dir.join("daemon.toml"),
        format!(
            "[tun]\n\
             enabled = false\n\
             [localapi]\n\
             addr = \"{api_addr}\"\n\
             [network.identity]\n\
             seed_file = \"{}\"\n\
             [network.n1]\n\
             enabled = true\n\
             listen_addr = \"{n1_addr}\"\n",
            seed.display(),
        ),
    )
    .unwrap();

    let token = dir.join("localapi.token");
    std::fs::write(&token, "a".repeat(64)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn next_line(rx: &mpsc::Receiver<String>, deadline: Instant, captured: &[String]) -> String {
    let left = deadline.saturating_duration_since(Instant::now());
    rx.recv_timeout(left).unwrap_or_else(|_| {
        panic!("daemon stderr did not produce the expected line; captured:\n{captured:#?}")
    })
}

#[test]
fn unlisted_peer_rejection_is_captured_on_daemon_stderr() {
    let dir = TempDir::new("stderr");
    let server = FabricIdentity::from_ed25519_seed([0x5a; 32]).unwrap();
    let allowed = FabricIdentity::from_ed25519_seed([0x5b; 32]).unwrap();
    let stranger = FabricIdentity::from_ed25519_seed([0x5c; 32]).unwrap();
    let n1_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_udp_port()));
    let api_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_tcp_port()));
    write_config(dir.path(), &server, &allowed, n1_addr, api_addr);

    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_nexusd"))
            .arg(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nexusd"),
    );
    let stderr = daemon.0.stderr.take().expect("stderr piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    // Wait for the N1 listener to be up (not just process start).
    let mut captured = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let line = next_line(&rx, deadline, &captured);
        let listening = line.starts_with("[n1-listener] listening addr=");
        captured.push(line);
        if listening {
            break;
        }
    }

    // Negative admission attempt: an identity absent from the allowlist.
    let config = ConnConfig {
        addrs: vec![n1_addr],
        handshake_timeout: Duration::from_millis(700),
    };
    assert!(
        FabricConn::connect_mtls(server.peer_id(), &stranger, &config).is_err(),
        "unlisted identity must not complete the mTLS handshake"
    );

    // The exact §19 sentence must appear on the daemon's real stderr.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let line = next_line(&rx, deadline, &captured);
        let matched = line == REJECTION_LINE;
        captured.push(line);
        if matched {
            break;
        }
    }
    // Optional reproducible artifact for the WP1b report: dump the captured
    // daemon stderr to a caller-chosen file so it can be grepped.
    if let Ok(path) = std::env::var("NEXUSD_N1_REJECT_CAPTURE") {
        std::fs::write(&path, format!("{}\n", captured.join("\n")))
            .expect("write captured daemon stderr");
    }
    eprintln!("captured real daemon stderr line: {REJECTION_LINE}");
    assert_eq!(
        captured.last().map(String::as_str),
        Some(REJECTION_LINE),
        "rejection log line missing from real daemon stderr; captured:\n{captured:#?}"
    );
}
