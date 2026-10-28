//! NAT readiness integration tests (Wave A + Wave B).
//!
//! Scope:
//! - Wave A: `p3_daemon_allocates_with_configured_bind` (P3-AC3),
//!   `p3_config_invalid_bind_exits_1` (P3-AC5), and
//!   `p1_prediction_hint_from_production_samples` (P1-AC3).
//! - Wave B: P1-AC1 (daemon samples on the punch socket), P1-AC4 (sampling
//!   does not break punch), P3-AC7(a)(b)(e) state surface, P5-AC2/AC4
//!   (LocalAPI `direct` through the production write point), and the F2
//!   text gate (P3-AC2).
//!
//! Daemon spawn uses `nexusd <config-dir>` (the `run_daemon` entry) because
//! `nexusd serve` does not start nat-switch. Readiness is the JSON line
//! `{"verdict":"READY",...,"daemon":{"localapi":"..."}}`.
//!
//! Environment rules: loopback UDP and `127.0.0.2` must be usable; otherwise
//! the test prints `SKIP: ...` and returns (never a fake PASS).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use nexus_domain::nat::NatType;
use nexus_fabric::{Driver, PeerId as FabricPeerId};
use nexus_nat_traversal::{
    DefaultPredictor, LocalCandidates, PortSample, Predictability, PunchConfig, PunchPredictor,
    PunchResult,
};
use nexus_nat_wireup::{PunchManager, SystemPunchClock, TunnelProto};
use nexus_turn::client::TurnCredentials;
use nexus_turn::server::TurnServer;
use nexus_turn::stun::{Attribute, StunMessage};
use nexusd::nat_status::{NatStatusSource, connectivity_nat, publish_nat_status_source};
use nexusd::nat_stun::{DriverStunTransport, StunProber, UdpStunTransport};

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
    write_daemon_toml_full(dir, server, bind_addr, refresh_sec, None, None);
}

fn write_daemon_toml_full(
    dir: &Path,
    server: SocketAddr,
    bind_addr: &str,
    refresh_sec: u64,
    stun1: Option<SocketAddr>,
    stun2: Option<SocketAddr>,
) {
    let mut stun_lines = String::new();
    if let Some(s) = stun1 {
        stun_lines.push_str(&format!("stun_server = \"{s}\"\n"));
    }
    if let Some(s) = stun2 {
        stun_lines.push_str(&format!("stun_server2 = \"{s}\"\n"));
    }
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
{stun_lines}
[network.punch]
relay_provider_enabled = false
"#
    );
    std::fs::write(dir.join("daemon.toml"), text).expect("write daemon.toml");
}

/// Variant without `[network.turn]` (P3-AC7(b): `unconfigured`).
fn write_daemon_toml_no_turn(dir: &Path) {
    let text = r#"localapi_addr = "127.0.0.1:0"

[tun]
enabled = false

[network.punch]
relay_provider_enabled = false
"#;
    std::fs::write(dir.join("daemon.toml"), text).expect("write daemon.toml (no turn)");
}

/// A minimal valid `proxy.yaml` so the daemon has a configured subsystem
/// while `network.toml` (and therefore nat-switch) stays absent.
fn write_proxy_yaml(dir: &Path) {
    let text = "schema_version: 1\nrules:\n  - tag: r\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
    std::fs::write(dir.join("proxy.yaml"), text).expect("write proxy.yaml");
}

/// Minimal LocalAPI GET (same wire shape as `tests/nat_localapi.rs`).
fn get_json(addr: &str, path: &str) -> (u16, serde_json::Value) {
    let Ok(mut s) = TcpStream::connect(addr) else {
        return (0, serde_json::Value::Null);
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    if write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return (0, serde_json::Value::Null);
    }
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    let status = buf
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = buf
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    let value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// Parse `key=value` out of one stderr line (whitespace-delimited).
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
}

fn hex32(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
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
    localapi_addr: String,
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
            localapi_addr: String::new(),
        };
        match ready_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(addr) => {
                daemon.localapi_addr = addr;
                daemon
            }
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

    /// Accumulate lines until `pred` is satisfied (or timeout). Unlike
    /// `wait_for`, this keeps every line so callers can count matches.
    fn wait_until(&mut self, pred: impl Fn(&Daemon) -> bool, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain_available();
            if pred(self) {
                return true;
            }
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                self.drain_available();
                return pred(self);
            }
            match self.lines.recv_timeout(remain) {
                Ok(line) => self.collected.push(line),
                Err(_) => {
                    self.drain_available();
                    return pred(self);
                }
            }
        }
    }

    fn count_matching(&self, pred: impl Fn(&str) -> bool) -> usize {
        self.collected.iter().filter(|l| pred(l)).count()
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

/// Sequential-allocation STUN responder: every Binding response advances the
/// shared public port by 1 (starting at 40000).
fn spawn_stun_responder(counter: Arc<AtomicU16>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind STUN responder");
    let addr = socket.local_addr().expect("responder addr");
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let Ok(request) = nexus_turn::stun::decode(&buf[..n]) else {
                continue;
            };
            if request.msg_type != 0x0001 {
                continue;
            }
            let port = counter.fetch_add(1, Ordering::SeqCst);
            let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let response = StunMessage {
                msg_type: 0x0101, // Binding Success Response
                txn: request.txn,
                attrs: vec![Attribute::XorMappedAddress(public)],
            }
            .encode();
            let _ = socket.send_to(&response, from);
        }
    });
    addr
}

/// P1-AC3 (Wave A): production `probe_pair` samples -> Predictable -> a punch
/// attempt emits at least one prediction hint.
///
/// The production `sample_round` lives in `main.rs` (Wave B); Wave A reproduces
/// its fixed rule in-test (two samples per round, `s1,s2` interleaved, one
/// `observed_from`). The punch result may be `StayedOnRelay{Timeout}` — the
/// assertion is the hint emission, not a successful migration.
#[test]
fn p1_prediction_hint_from_production_samples() {
    if !udp_loopback_available() {
        eprintln!("SKIP: loopback UDP unavailable in this environment");
        return;
    }

    let counter = Arc::new(AtomicU16::new(40_000));
    let server1 = spawn_stun_responder(counter.clone());
    let server2 = spawn_stun_responder(counter.clone());

    let transport = UdpStunTransport::new("127.0.0.1:0".parse().expect("valid bind"))
        .expect("bind STUN transport");
    let mut prober = StunProber::new(Box::new(transport));
    let mut samples = Vec::new();
    for round in 0..3u64 {
        let (m1, m2, _nat) = prober.probe_pair(server1, server2).expect("probe pair");
        assert_eq!(m1.local, m2.local, "samples must share one observed_from");
        for (mapping, target) in [(&m1, server1), (&m2, server2)] {
            samples.push(PortSample {
                port: mapping.public.port(),
                at_ms: round * 100,
                target,
                observed_from: mapping.local,
            });
        }
    }
    let ports: Vec<u16> = samples.iter().map(|s| s.port).collect();
    assert_eq!(ports, vec![40_000, 40_001, 40_002, 40_003, 40_004, 40_005]);
    let observed = samples[0].observed_from;
    assert!(samples.iter().all(|s| s.observed_from == observed));
    assert_eq!(
        DefaultPredictor.assess(&samples),
        Predictability::Predictable {
            base_port: 40_005,
            delta: 1,
        }
    );

    // Real loopback relay connection between two fabric drivers.
    let driver_b =
        Driver::new_server("127.0.0.1:0".parse().expect("valid addr")).expect("bind driver B");
    let b_addr = *driver_b.shared().local_addr.lock().expect("B local addr");
    let b_id = driver_b.shared().peer_id.expect("B has identity");
    let driver_a = Driver::new_client().expect("driver A");
    let a_addr = *driver_a.shared().local_addr.lock().expect("A local addr");
    // Larger than any random server identity → deterministic "we win" tie-break
    // (avoids the 10s adopt-verified-direct wait; the hint assertion is the point).
    let a_id = FabricPeerId([0xFF; 32]);

    let accept_driver = driver_b.clone();
    let accept = std::thread::spawn(move || accept_driver.accept_conn());
    let conn_a = driver_a
        .connect(b_id, b_addr, Duration::from_secs(10))
        .expect("A relay connect");
    let conn_b = accept
        .join()
        .expect("accept thread")
        .expect("B relay accept");

    let manager_a = PunchManager::new(driver_a.clone(), a_id, Arc::new(SystemPunchClock::new()));
    let manager_b = PunchManager::new(driver_b.clone(), b_id, Arc::new(SystemPunchClock::new()));
    let local_a = LocalCandidates {
        host: vec![a_addr],
        srflx: None,
        srflx_stun: None,
        srflx_turn: None,
        nat_type: NatType::RestrictedCone,
    };
    let local_b = LocalCandidates {
        host: vec![b_addr],
        srflx: None,
        srflx_stun: None,
        srflx_turn: None,
        nat_type: NatType::RestrictedCone,
    };
    manager_a.set_local(local_a, samples);
    manager_b.set_local(local_b, Vec::new());
    manager_b.register_relay(&conn_b, a_id);

    let config = PunchConfig {
        punch_timeout: Duration::from_millis(500),
        ..PunchConfig::default()
    };
    let _ = manager_a.punch_peer(&conn_a, b_id, NatType::RestrictedCone, config);

    let status = manager_a
        .status(&b_id)
        .expect("punch attempt must publish peer status");
    assert!(
        status.prediction_hints_sent_total >= 1,
        "production samples must produce a prediction hint; status={status:?}"
    );
}

// ---------------------------------------------------------------------------
// Wave B
// ---------------------------------------------------------------------------

fn wait_for_nat(
    daemon: &mut Daemon,
    pred: impl Fn(&serde_json::Value) -> bool,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        daemon.drain_available();
        let (status, value) = get_json(&daemon.localapi_addr, "/localapi/v0/connectivity/nat");
        if status == 200 && pred(&value) {
            return value;
        }
        if Instant::now() >= deadline {
            panic!(
                "connectivity/nat did not match within {timeout:?}; status={status} body={value}\nstderr:\n{}",
                daemon.snapshot()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// P1-AC1: the daemon's STUN prober runs on the punch driver socket.
#[test]
fn p1_daemon_samples_on_punch_socket() {
    if !udp_loopback_available() {
        eprintln!("SKIP: loopback UDP unavailable in this environment");
        return;
    }
    let counter = Arc::new(AtomicU16::new(40_000));
    let server1 = spawn_stun_responder(counter.clone());
    let server2 = spawn_stun_responder(counter);
    let turn = TurnServer::bind("127.0.0.1:0".parse().expect("valid addr"), creds())
        .expect("bind in-process TURN server");
    let dir = TempDir::new("p1-tap");
    write_daemon_toml_full(
        dir.path(),
        turn.main_addr(),
        "127.0.0.1:0",
        300,
        Some(server1),
        Some(server2),
    );
    write_network_toml(dir.path());

    let mut daemon = Daemon::spawn(dir.path());
    let tap_line = daemon
        .wait_for(
            |line| line.contains("[nat-stun] tap_installed driver="),
            Duration::from_secs(20),
        )
        .unwrap_or_else(|| {
            panic!(
                "tap_installed not observed within 20s; stderr:\n{}",
                daemon.snapshot()
            )
        });
    let driver = field(&tap_line, "driver")
        .expect("driver= in tap line")
        .to_string();

    assert!(
        daemon.wait_until(
            |d| d.count_matching(|l| l.contains("[nat-stun] sample ")) >= 6,
            Duration::from_secs(20)
        ),
        "expected >=6 samples; stderr:\n{}",
        daemon.snapshot()
    );

    let sample_lines: Vec<&str> = daemon
        .collected
        .iter()
        .map(String::as_str)
        .filter(|l| l.contains("[nat-stun] sample "))
        .collect();
    assert_eq!(
        daemon.count_matching(|l| l.contains("[nat-stun] tap_installed")),
        1,
        "exactly one tap per process"
    );
    let targets: std::collections::HashSet<&str> = sample_lines
        .iter()
        .filter_map(|l| field(l, "target"))
        .collect();
    assert_eq!(targets.len(), 2, "two distinct STUN targets: {targets:?}");
    assert!(
        sample_lines
            .iter()
            .all(|l| field(l, "observed_from") == Some(driver.as_str())),
        "every sample must come from the punch driver socket {driver}; lines={sample_lines:?}"
    );

    let summary = daemon
        .wait_for(
            |line| line.contains("[nat-switch] STUN sample:"),
            Duration::from_secs(10),
        )
        .unwrap_or_else(|| panic!("STUN summary missing; stderr:\n{}", daemon.snapshot()));
    assert!(
        summary.contains(&format!("(local={driver})")),
        "summary local must equal the driver socket; summary={summary}"
    );
}

/// P1-AC4: sampling on the punch socket does not break hole punching.
#[test]
fn p1_sampling_does_not_break_punch() {
    if !udp_loopback_available() {
        eprintln!("SKIP: loopback UDP unavailable in this environment");
        return;
    }
    let counter = Arc::new(AtomicU16::new(50_000));
    let server1 = spawn_stun_responder(counter.clone());
    let server2 = spawn_stun_responder(counter);

    let driver_a = Driver::new_server("127.0.0.1:0".parse().expect("addr")).expect("driver A");
    let a_addr = *driver_a.shared().local_addr.lock().expect("A addr");
    let a_id = driver_a.shared().peer_id.expect("A id");
    let driver_b = Driver::new_server("127.0.0.1:0".parse().expect("addr")).expect("driver B");
    let b_addr = *driver_b.shared().local_addr.lock().expect("B addr");
    let b_id = driver_b.shared().peer_id.expect("B id");

    let accept_driver = Arc::clone(&driver_b);
    let accept = std::thread::spawn(move || accept_driver.accept_conn());
    let conn_a = driver_a
        .connect(b_id, b_addr, Duration::from_secs(10))
        .expect("A relay connect");
    let conn_b = accept
        .join()
        .expect("accept thread")
        .expect("B relay accept");

    let manager_a = PunchManager::new(
        Arc::clone(&driver_a),
        a_id,
        Arc::new(SystemPunchClock::new()),
    );
    let manager_b = PunchManager::new(
        Arc::clone(&driver_b),
        b_id,
        Arc::new(SystemPunchClock::new()),
    );
    let candidates = |host| LocalCandidates {
        host: vec![host],
        srflx: None,
        srflx_stun: None,
        srflx_turn: None,
        nat_type: NatType::RestrictedCone,
    };
    manager_a.set_local(candidates(a_addr), Vec::new());
    manager_b.set_local(candidates(b_addr), Vec::new());
    manager_b.register_relay(&conn_b, a_id);

    let (tx, rx) = mpsc::channel();
    let sampling_driver = Arc::clone(&driver_a);
    let sampler = std::thread::spawn(move || {
        let transport = DriverStunTransport::new(sampling_driver).expect("install tap on A driver");
        let mut prober = StunProber::new(Box::new(transport));
        let mut samples = Vec::new();
        for round in 0..2u64 {
            let (m1, m2, _) = prober.probe_pair(server1, server2).expect("probe pair");
            for (mapping, target) in [(&m1, server1), (&m2, server2)] {
                samples.push(PortSample {
                    port: mapping.public.port(),
                    at_ms: round * 100,
                    target,
                    observed_from: mapping.local,
                });
            }
        }
        let _ = tx.send(samples);
    });

    let result = manager_a.punch_peer(
        &conn_a,
        b_id,
        NatType::RestrictedCone,
        PunchConfig::default(),
    );
    let samples = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("sampler finished");
    sampler.join().expect("sampler thread");
    assert!(
        matches!(result, PunchResult::Migrated { .. }),
        "punch must migrate while sampling; got {result:?}"
    );
    assert!(samples.len() >= 4, "at least two sampled rounds");
    assert!(
        samples.iter().all(|s| s.observed_from == a_addr),
        "all samples must share the A driver socket {a_addr}"
    );
}

/// P3-AC7(a): bind failure surfaces as degraded + bind_failed + one WARN.
#[test]
fn p3_degraded_status_surface() {
    if !udp_loopback_available() {
        eprintln!("SKIP: loopback UDP unavailable in this environment");
        return;
    }
    if bindable("192.0.2.1:0") {
        eprintln!("SKIP: 192.0.2.1 is bindable in this environment");
        return;
    }
    let turn = TurnServer::bind("127.0.0.1:0".parse().expect("addr"), creds())
        .expect("bind in-process TURN server");
    let dir = TempDir::new("p3-degraded");
    write_daemon_toml(dir.path(), turn.main_addr(), "192.0.2.1:0", 300);
    write_network_toml(dir.path());

    let mut daemon = Daemon::spawn(dir.path());
    let value = wait_for_nat(
        &mut daemon,
        |v| v["turn"]["warm_backup"]["health"] == "degraded",
        Duration::from_secs(10),
    );
    assert_eq!(value["turn"]["warm_backup"]["bind_addr"], "192.0.2.1:0");
    assert_eq!(value["turn"]["warm_backup"]["last_error"], "bind_failed");
    assert_eq!(value["runtime"], "enabled");
    assert!(value["turn"].get("provider").is_some());

    assert!(
        daemon.wait_until(
            |d| d.collected.iter().any(
                |l| l.contains("[nat-switch] WARN: TURN allocate failed bind=192.0.2.1:0 err=")
            ),
            Duration::from_secs(10)
        ),
        "degraded WARN missing; stderr:\n{}",
        daemon.snapshot()
    );
    let warns = daemon.count_matching(|l| {
        l.contains("[nat-switch] WARN: TURN allocate failed bind=192.0.2.1:0 err=")
    });
    assert_eq!(
        warns,
        1,
        "exactly one degraded WARN; stderr:\n{}",
        daemon.snapshot()
    );
    assert!(
        daemon
            .collected
            .iter()
            .any(|l| l.contains("disabling turn, falling back to peer relay")),
        "fallback WARN text missing"
    );
}

/// P3-AC7(b): no `[network.turn]` -> unconfigured, null bind/error, disabled.
#[test]
fn p3_unconfigured_status_surface() {
    let dir = TempDir::new("p3-unconfigured");
    write_daemon_toml_no_turn(dir.path());
    write_network_toml(dir.path());

    let mut daemon = Daemon::spawn(dir.path());
    let value = wait_for_nat(
        &mut daemon,
        |v| v["turn"]["warm_backup"]["health"] == "unconfigured",
        Duration::from_secs(10),
    );
    assert!(value["turn"]["warm_backup"]["bind_addr"].is_null());
    assert!(value["turn"]["warm_backup"]["last_error"].is_null());
    assert_eq!(value["runtime"], "disabled");
}

/// P3-AC7(e): TURN configured but nat-switch never starts.
#[test]
fn p3_not_started_status_surface() {
    if !bindable("127.0.0.2:0") {
        eprintln!("SKIP: 127.0.0.2 is not bindable in this environment");
        return;
    }
    let dir = TempDir::new("p3-not-started");
    write_daemon_toml(
        dir.path(),
        "127.0.0.1:3478".parse().expect("addr"),
        "127.0.0.2:0",
        300,
    );
    // No `network.toml`: no authoritative identity -> no nat-switch worker.
    // proxy.yaml keeps the daemon at READY (it needs at least one subsystem).
    write_proxy_yaml(dir.path());

    let mut daemon = Daemon::spawn(dir.path());
    let value = wait_for_nat(
        &mut daemon,
        |v| v["turn"]["warm_backup"]["health"] == "not_started",
        Duration::from_secs(10),
    );
    assert_eq!(value["turn"]["warm_backup"]["bind_addr"], "127.0.0.2:0");
    assert!(value["turn"]["warm_backup"]["last_error"].is_null());
    assert_eq!(value["runtime"], "disabled");
}

/// P5-AC2/AC4: the production `LinkSink` write point makes LocalAPI report
/// `direct` after the monitor fails over (test-driven production entry).
#[test]
fn p5_localapi_json_direct() {
    if !udp_loopback_available() {
        eprintln!("SKIP: loopback UDP unavailable in this environment");
        return;
    }
    let driver_a = Driver::new_server("127.0.0.1:0".parse().expect("addr")).expect("driver A");
    let a_addr = *driver_a.shared().local_addr.lock().expect("A addr");
    let a_id = driver_a.shared().peer_id.expect("A id");
    let driver_b = Driver::new_server("127.0.0.1:0".parse().expect("addr")).expect("driver B");
    let b_addr = *driver_b.shared().local_addr.lock().expect("B addr");
    let b_id = driver_b.shared().peer_id.expect("B id");

    let accept_driver = Arc::clone(&driver_b);
    let accept = std::thread::spawn(move || accept_driver.accept_conn());
    let conn_a = driver_a
        .connect(b_id, b_addr, Duration::from_secs(10))
        .expect("A relay connect");
    let conn_b = accept
        .join()
        .expect("accept thread")
        .expect("B relay accept");

    let candidates = |host| LocalCandidates {
        host: vec![host],
        srflx: None,
        srflx_stun: None,
        srflx_turn: None,
        nat_type: NatType::RestrictedCone,
    };
    let sw_a = nexusd::nat_switch::NatSwitching::new(
        Arc::clone(&driver_a),
        a_id,
        candidates(a_addr),
        Vec::new(),
        Arc::new(SystemPunchClock::new()),
    );
    let sw_b = nexusd::nat_switch::NatSwitching::new(
        Arc::clone(&driver_b),
        b_id,
        candidates(b_addr),
        Vec::new(),
        Arc::new(SystemPunchClock::new()),
    );

    // Relay candidates are keyed by their remote address in `PathManager`.
    // Production uses the peer's TURN relayed address (never the punch
    // target); using the driver address here would collide with the direct
    // candidate and overwrite the relay path state. Distinct book addresses
    // keep the two candidates separate, as in production.
    let relay_key_a: SocketAddr = "127.0.0.1:1".parse().expect("relay key");
    let relay_key_b: SocketAddr = "127.0.0.1:2".parse().expect("relay key");
    sw_a.on_relay_connected(nexusd::nat_switch::RelayInfo {
        peer: b_id,
        relay: Arc::clone(&conn_a),
        kind: nexus_path::PathKind::Turn,
        local: a_addr,
        remote: relay_key_a,
        remote_nat: NatType::RestrictedCone,
        auto_punch: true,
    });
    sw_b.on_relay_connected(nexusd::nat_switch::RelayInfo {
        peer: a_id,
        relay: Arc::clone(&conn_b),
        kind: nexus_path::PathKind::Turn,
        local: b_addr,
        remote: relay_key_b,
        remote_nat: NatType::RestrictedCone,
        // Both sides initiate in production; the wireup tie-break resolves the
        // race. B must also run `on_direct_ready` so its direct probe endpoint
        // exists — otherwise A's direct-path probes have no responder and the
        // path never scores (empirically required; see implement report).
        auto_punch: true,
    });

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut migrated = None;
    while Instant::now() < deadline {
        if let Some(status) = sw_a.peers().into_iter().find(|s| s.peer == b_id) {
            if matches!(status.last_result, Some(PunchResult::Migrated { .. })) {
                migrated = Some(status);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let migrated = migrated.unwrap_or_else(|| {
        panic!(
            "A side did not migrate; A={:?} B={:?}",
            sw_a.peers(),
            sw_b.peers()
        )
    });
    assert_eq!(
        migrated.tunnel_proto,
        TunnelProto::Turn,
        "P5-AC3: Migrated alone must not write Direct"
    );

    // Let the direct path be probed as a Backup (5s cadence, <=2s deadline).
    std::thread::sleep(Duration::from_secs(12));
    let _ = conn_a.tx.send(nexus_fabric::Cmd::Close {
        conn: conn_a.id.0,
        code: 0,
        reason: b"p5-degrade".to_vec(),
    });

    let peer_hex = hex32(&b_id.0);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut switched = false;
    while Instant::now() < deadline {
        let direct = sw_a.active_direct_conn(&peer_hex).is_some();
        let proto = sw_a
            .peers()
            .into_iter()
            .find(|s| s.peer == b_id)
            .map(|s| s.tunnel_proto)
            .unwrap_or(TunnelProto::Turn);
        if direct && sw_a.stats().path_active_switches >= 1 && proto == TunnelProto::Direct {
            switched = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        switched,
        "monitor did not fail over to direct; stats={:?} peers={:?}",
        sw_a.stats(),
        sw_a.peers()
    );

    publish_nat_status_source(Box::new(Arc::clone(&sw_a)));
    let value = connectivity_nat().expect("connectivity snapshot");
    assert!(
        value["schema_version"] == 1 || value["schema_version"] == 2,
        "schema_version additive: {}",
        value["schema_version"]
    );
    assert!(value["turn"].is_object(), "turn key must exist (additive)");
    let peer = value["peers"]
        .as_array()
        .expect("peers array")
        .iter()
        .find(|p| p["peer_id"] == peer_hex)
        .unwrap_or_else(|| panic!("peer {peer_hex} missing from {value}"));
    assert_eq!(peer["tunnel_proto"], "direct");

    sw_a.shutdown();
    sw_b.shutdown();
}

/// P3-AC2 (F2 in-repo text gate): exactly two production construction points
/// and one `real_factory` definition.
#[test]
fn p3_ac2_production_construction_points() {
    let main_rs =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
            .expect("read main.rs");
    // Split at the first test *module*, not the first `#[cfg(test)]`
    // attribute: Wave B's `#[cfg(test)] last_local` field is production code.
    let prod = main_rs
        .split("#[cfg(test)]\nmod ")
        .next()
        .expect("production part");
    assert_eq!(
        prod.matches("TurnManager::new").count(),
        2,
        "P3-AC2: production TurnManager::new sites must be exactly 2"
    );
    let turn_rs =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nat_turn.rs"))
            .expect("read nat_turn.rs");
    assert_eq!(
        turn_rs.matches("fn real_factory").count(),
        1,
        "P3-AC2: real_factory definition must be unique"
    );
}
