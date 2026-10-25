//! NAT readiness integration tests (Wave A).
//!
//! Scope (spec-frozen §3.6/§4.7 Wave A):
//! - `p3_daemon_allocates_with_configured_bind`: real `nexusd` daemon + real
//!   in-process `TurnServer`; the allocation log must show the configured
//!   `[network.turn].bind_addr` and a refresh must follow.
//! - `p3_config_invalid_bind_exits_1`: invalid `bind_addr` is a config error
//!   (daemon exits 1 with `CONFIG`), not a silent runtime fallback.
//!
//! Daemon spawn uses `nexusd <config-dir>` (the `run_daemon` entry) because
//! `nexusd serve` does not start nat-switch. Readiness is the JSON line
//! `{"verdict":"READY",...,"daemon":{"localapi":"..."}}`.
//!
//! Environment rules: loopback UDP and `127.0.0.2` must be usable; otherwise
//! the test prints `SKIP: ...` and returns (never a fake PASS).

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use nexus_turn::client::TurnCredentials;
use nexus_turn::server::TurnServer;

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PEER_ID: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

fn creds() -> TurnCredentials {
    TurnCredentials {
        username: "nexus".into(),
        password: "test-secret".into(),
        realm: "nexus".into(),
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "nexusd-nat-readiness-{tag}-{}-{nanos}",
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

fn write_token(dir: &Path) -> PathBuf {
    let token = dir.join("localapi.token");
    std::fs::write(&token, TOKEN).expect("write localapi token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
            .expect("chmod localapi token");
    }
    token
}

fn udp_loopback_available() -> bool {
    let Ok(a) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let Ok(b) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = b.set_read_timeout(Some(Duration::from_secs(1)));
    if a.send_to(b"probe", b.local_addr().expect("b addr"))
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 8];
    b.recv_from(&mut buf).is_ok()
}

fn bindable(addr: &str) -> bool {
    UdpSocket::bind(addr).is_ok()
}

fn write_daemon_toml(dir: &Path, server: SocketAddr, bind_addr: &str, refresh_sec: u64) {
    let text = format!(
        r#"localapi_addr = "127.0.0.1:0"

[tun]
enabled = false

[network.turn]
server = "{server}"
realm = "nexus"
username = "nexus"
password = "test-secret"
refresh_interval_sec = {refresh_sec}
bind_addr = "{bind_addr}"

[network.punch]
relay_provider_enabled = false
"#
    );
    std::fs::write(dir.join("daemon.toml"), text).expect("write daemon.toml");
}

fn write_network_toml(dir: &Path) {
    let text = format!(
        r#"peer_id = "{PEER_ID}"

[vpi]
interface = "nxtun0"
address = "10.144.0.1"
"#
    );
    std::fs::write(dir.join("network.toml"), text).expect("write network.toml");
}

/// A spawned `nexusd <config-dir>` with its stderr collected line by line.
struct Daemon {
    child: Child,
    lines: Receiver<String>,
    collected: Vec<String>,
}

impl Daemon {
    fn spawn(dir: &Path) -> Self {
        let token = write_token(dir);
        let mut child = Command::new(env!("CARGO_BIN_EXE_nexusd"))
            .arg(dir)
            .env("NEXUS_CONFIG_DIR", dir)
            .env("NEXUS_LOCALAPI_TOKEN_FILE", &token)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nexusd");

        let stderr = child.stderr.take().expect("stderr piped");
        let (line_tx, line_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = line_tx.send(line);
            }
        });

        let stdout = child.stdout.take().expect("stdout piped");
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                    if value["verdict"] == "READY" {
                        if let Some(addr) = value["daemon"]["localapi"].as_str() {
                            let _ = ready_tx.send(addr.to_string());
                            break;
                        }
                    }
                }
            }
        });

        let mut daemon = Self {
            child,
            lines: line_rx,
            collected: Vec::new(),
        };
        match ready_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(_) => daemon,
            Err(_) => {
                daemon.drain_available();
                panic!(
                    "daemon did not reach READY within 20s; stderr:\n{}",
                    daemon.snapshot()
                );
            }
        }
    }

    fn drain_available(&mut self) {
        while let Ok(line) = self.lines.try_recv() {
            self.collected.push(line);
        }
    }

    /// Wait until a collected stderr line matches `pred`, up to `timeout`.
    fn wait_for(&mut self, pred: impl Fn(&str) -> bool, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.collected.iter().find(|line| pred(line)) {
                return Some(line.clone());
            }
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                self.drain_available();
                return self.collected.iter().find(|line| pred(line)).cloned();
            }
            match self.lines.recv_timeout(remain) {
                Ok(line) => self.collected.push(line),
                Err(_) => {
                    self.drain_available();
                    return self.collected.iter().find(|line| pred(line)).cloned();
                }
            }
        }
    }

    fn snapshot(&self) -> String {
        self.collected.join("\n")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// P3-AC3: the daemon's warm-backup allocation uses `127.0.0.2:0` and refreshes.
#[test]
fn p3_daemon_allocates_with_configured_bind() {
    if !udp_loopback_available() {
        eprintln!("SKIP: loopback UDP unavailable in this environment");
        return;
    }
    if !bindable("127.0.0.2:0") {
        eprintln!("SKIP: 127.0.0.2 is not bindable in this environment");
        return;
    }

    let server = TurnServer::bind("127.0.0.1:0".parse().expect("valid addr"), creds())
        .expect("bind in-process TURN server");
    let dir = TempDir::new("p3-alloc");
    write_daemon_toml(dir.path(), server.main_addr(), "127.0.0.2:0", 65);
    write_network_toml(dir.path());

    let mut daemon = Daemon::spawn(dir.path());
    let allocation = daemon
        .wait_for(
            |line| {
                line.contains("[nat-switch] TURN allocation active:")
                    && line.contains("relayed=127.0.0.1:")
                    && line.contains("mapped=127.0.0.2:")
                    && line.contains("bind=127.0.0.2:0")
                    && line.contains("refresh_in=65s")
            },
            Duration::from_secs(15),
        )
        .unwrap_or_else(|| {
            panic!(
                "configured-bind allocation line not observed within 15s; stderr:\n{}",
                daemon.snapshot()
            )
        });
    assert!(
        !allocation.contains("mapped=none"),
        "TURN mapping must exist: {allocation}"
    );

    daemon
        .wait_for(
            |line| line.contains("[nat-switch] TURN refresh ok relayed=127.0.0.1:"),
            Duration::from_secs(10),
        )
        .unwrap_or_else(|| {
            panic!(
                "TURN refresh ok line not observed within 10s; stderr:\n{}",
                daemon.snapshot()
            )
        });
}

/// P3-AC5 (config surface): a non-`IP:port` `bind_addr` rejects startup.
#[test]
fn p3_config_invalid_bind_exits_1() {
    let dir = TempDir::new("p3-bad-bind");
    write_daemon_toml(
        dir.path(),
        "127.0.0.1:3478".parse().expect("valid addr"),
        "not-an-addr",
        65,
    );

    let token = write_token(dir.path());
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexusd"))
        .arg(dir.path())
        .env("NEXUS_CONFIG_DIR", dir.path())
        .env("NEXUS_LOCALAPI_TOKEN_FILE", token)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nexusd");
    let stderr = child.stderr.take().expect("stderr piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut text);
        text
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait().expect("wait daemon") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => break None,
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stderr = stderr_reader.join().expect("stderr reader");
    let status = status.unwrap_or_else(|| {
        panic!("daemon must exit within 5s for invalid bind_addr; stderr:\n{stderr}")
    });
    assert_eq!(status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("\"code\":\"CONFIG\""),
        "config error code missing; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("bind_addr invalid"),
        "specific bind_addr error missing; stderr:\n{stderr}"
    );
}
