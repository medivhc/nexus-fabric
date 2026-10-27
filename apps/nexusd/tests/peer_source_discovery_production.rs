//! Production-assembly regressions for product-review r1 MAJOR-1 / MAJOR-2.
//!
//! These tests deliberately drive the **daemon composition root** (the built
//! `nexusd` binary reading a real config folder) instead of constructing
//! `DiscoveryRuntimeConfig` / `PeerSourceFeed` by hand. The r1 review's MAJOR
//! findings were exactly about behaviour that only existed in unit-constructed
//! objects and never in the production wiring, so a unit-level assertion would
//! reproduce the same blind spot.
//!
//! - `no_advertise_ip_degrades_through_production_daemon`: runs the daemon in a
//!   private network namespace (`unshare -Urn`) that only has `lo`; the
//!   production auto-selection therefore finds no usable IPv4 and the frozen
//!   WARN + `last_error` must appear.
//! - `default_per_self_book_is_visible_and_reports_coverage`: two daemons with
//!   the default (per-self) relay book discover/subscribe each other via the
//!   static source; the start-up book line and the book coverage fields must be
//!   observable (the r1 MAJOR-2 "why is nothing triggering?" dead end).
//!
//! Hosts without unprivileged user namespaces skip the first test loudly; the
//! second test needs no special privileges.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_fabric::FabricIdentity;

const FROZEN_NO_IP_WARN: &str = "[discovery-mdns] WARN: no advertise IPv4; mdns disabled";

fn peer_id_hex(seed: u8) -> String {
    FabricIdentity::from_ed25519_seed([seed; 32])
        .expect("ed25519 identity")
        .peer_id()
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn seed_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind tcp")
        .local_addr()
        .expect("tcp addr")
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind udp")
        .local_addr()
        .expect("udp addr")
        .port()
}

struct ConfigDir {
    root: PathBuf,
}

impl ConfigDir {
    fn new(name: &str) -> Self {
        static SEQ: Mutex<u64> = Mutex::new(0);
        let seq = {
            let mut guard = SEQ.lock().expect("seq lock");
            *guard += 1;
            *guard
        };
        let root =
            std::env::temp_dir().join(format!("nexusd-psdw-{name}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&root).expect("config dir");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, name: &str, body: &str) {
        std::fs::write(self.root.join(name), body).expect("write config file");
    }

    fn write_seed(&self, seed: u8) {
        let path = self.root.join("seed.hex");
        std::fs::write(&path, seed_hex(seed)).expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("seed mode");
        }
    }

    fn token_file(&self) -> PathBuf {
        self.root.join("token")
    }
}

impl Drop for ConfigDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Daemon {
    child: Child,
    token: String,
    localapi: String,
    stderr: Arc<Mutex<Vec<String>>>,
    _dir: ConfigDir,
}

impl Daemon {
    fn spawn(dir: ConfigDir, prefix: &[&str]) -> Option<Self> {
        let exe = env!("CARGO_BIN_EXE_nexusd");
        let mut command = if prefix.is_empty() {
            let mut c = Command::new(exe);
            c.arg(dir.path());
            c
        } else {
            let mut c = Command::new(prefix[0]);
            c.args(&prefix[1..]).arg(exe).arg(dir.path());
            c
        };
        let mut child = command
            .env("NEXUS_LOCALAPI_TOKEN_FILE", dir.token_file())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        let stderr = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&stderr);
        let pipe = child.stderr.take().expect("stderr piped");
        std::thread::spawn(move || {
            let mut reader = BufReader::new(pipe);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                sink.lock()
                    .expect("stderr lock")
                    .push(line.trim_end().to_string());
                line.clear();
            }
        });

        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout);
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut line = String::new();
        loop {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                Ok(_) => {
                    if line.contains("\"verdict\":\"READY\"") {
                        let ready: serde_json::Value =
                            serde_json::from_str(line.trim()).expect("READY json");
                        let localapi = ready["daemon"]["localapi"]
                            .as_str()
                            .expect("localapi addr")
                            .to_string();
                        // Give the pump/feed a moment to reach its steady state.
                        std::thread::sleep(Duration::from_millis(1500));
                        let token = std::fs::read_to_string(dir.token_file()).unwrap_or_default();
                        return Some(Self {
                            child,
                            token,
                            localapi,
                            stderr,
                            _dir: dir,
                        });
                    }
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    fn stderr_lines(&self) -> Vec<String> {
        self.stderr.lock().expect("stderr lock").clone()
    }

    fn stderr_text(&self) -> String {
        self.stderr_lines().join("\n")
    }

    fn nat_status(&self) -> serde_json::Value {
        let mut stream = TcpStream::connect(&self.localapi).expect("connect localapi");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        write!(
            stream,
            "GET /localapi/v0/connectivity/nat HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            self.localapi, self.token
        )
        .expect("write request");
        let mut raw = String::new();
        stream.read_to_string(&mut raw).expect("read response");
        let body = raw.split("\r\n\r\n").nth(1).expect("http body");
        serde_json::from_str(body).expect("nat status json")
    }

    /// Poll until `pred` holds on the nat snapshot, or panic after `timeout`.
    fn wait_nat(
        &self,
        timeout: Duration,
        what: &str,
        pred: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let deadline = Instant::now() + timeout;
        loop {
            let value = self.nat_status();
            if pred(&value) {
                return value;
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for {what}; last snapshot: {value}");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn network_toml(self_seed: u8, peer: Option<u8>, vip: &str) -> String {
    let mut text = format!(
        "peer_id = \"{}\"\n\n[vpi]\ninterface = \"nxtun0\"\naddress = \"{vip}\"\nmtu = 1200\n",
        peer_id_hex(self_seed)
    );
    if let Some(peer_seed) = peer {
        text = format!(
            "peer_id = \"{}\"\n\n[[peers]]\nid = \"{}\"\naddrs = [\"127.0.0.1:9\"]\n\n[vpi]\ninterface = \"nxtun0\"\naddress = \"{vip}\"\nmtu = 1200\n",
            peer_id_hex(self_seed),
            peer_id_hex(peer_seed)
        );
    }
    text
}

fn discovery_section(gossip_port: u16, mdns: bool) -> String {
    format!(
        "[network.discovery]\nmdns = {mdns}\nlsa = true\ngossip_port = {gossip_port}\nbook_poll_ms = 1000\n"
    )
}

fn turn_section(seed_file: &Path) -> String {
    format!(
        "[network.turn]\nserver = \"127.0.0.1:9\"\nrealm = \"nexus\"\nusername = \"u\"\npassword = \"p\"\nrefresh_interval_sec = 300\n\n[network.identity]\nseed_file = \"{}\"\n",
        seed_file.display()
    )
}

fn tun_section() -> &'static str {
    "[tun]\nenabled = false\n"
}

/// MAJOR-1: no usable IPv4 must reach the frozen WARN + `last_error` through
/// the production daemon, not just a hand-built `DiscoveryRuntimeConfig`.
#[test]
#[cfg(target_os = "linux")]
fn no_advertise_ip_degrades_through_production_daemon() {
    // Unprivileged user namespaces are the only way to get a loopback-only
    // network without host changes. Skip loudly where unavailable.
    let probe = Command::new("unshare")
        .args(["-Urn", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(probe, Ok(status) if status.success()) {
        eprintln!(
            "SKIP no_advertise_ip_degrades_through_production_daemon: unshare -Urn unavailable on this host"
        );
        return;
    }

    let dir = ConfigDir::new("major1");
    let api_port = free_tcp_port();
    dir.write(
        "daemon.toml",
        &format!(
            "localapi_addr = \"127.0.0.1:{api_port}\"\n\n{}{}",
            discovery_section(free_udp_port(), true),
            tun_section()
        ),
    );
    dir.write("network.toml", &network_toml(1, None, "10.144.0.9"));

    // The daemon lives in its own netns, so its 127.0.0.1 is not reachable from
    // the test process: start it, query LocalAPI and shut it down inside the
    // same namespace with one shell script.
    let exe = env!("CARGO_BIN_EXE_nexusd");
    let root_path = dir.path();
    let root = root_path.display();
    let script = format!(
        r#"set -e
ip link set lo up
"{exe}" "{root}" >"{root}/daemon.out" 2>"{root}/daemon.err" &
pid=$!
trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true' EXIT
i=0
while [ "$i" -lt 200 ]; do
  grep -q '"verdict":"READY"' "{root}/daemon.out" && break
  i=$((i+1))
  sleep 0.1
done
grep -q '"verdict":"READY"' "{root}/daemon.out"
sleep 1
tok=$(cat "{root}/token")
curl -s --max-time 5 -H "Authorization: Bearer $tok" \
  "http://127.0.0.1:{api_port}/localapi/v0/connectivity/nat" > "{root}/status.json"
sleep 1
"#
    );
    let mut command = Command::new("unshare");
    command
        .args(["-Urn", "sh", "-c", &script])
        .env("NEXUS_LOCALAPI_TOKEN_FILE", dir.token_file())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .expect("run daemon in a loopback-only netns");
    let stderr = std::fs::read_to_string(root_path.join("daemon.err")).unwrap_or_default();
    assert!(
        output.status.success(),
        "in-namespace daemon rig failed: {}\nrig stderr:\n{}\ndaemon stderr:\n{stderr}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let status: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root_path.join("status.json")).expect("status"),
    )
    .expect("nat status json");

    assert_eq!(
        status["discovery"]["mdns"], "disabled",
        "mDNS must be disabled (not degraded) when auto-selection finds no IPv4"
    );
    assert_eq!(
        status["discovery"]["last_error"], "advertise-ip-unavailable",
        "frozen last_error must be published through the production wiring"
    );

    let lines: Vec<&str> = stderr.lines().map(str::trim_end).collect();
    let warns: Vec<&&str> = lines.iter().filter(|l| **l == FROZEN_NO_IP_WARN).collect();
    assert_eq!(
        warns.len(),
        1,
        "exactly one frozen WARN line expected; stderr was:\n{stderr}"
    );

    let summary = lines
        .iter()
        .find(|l| l.starts_with("[discovery] advertise_ip="))
        .unwrap_or_else(|| {
            panic!("missing effective discovery summary line; stderr was:\n{stderr}")
        });
    assert!(
        summary.contains("advertise_ip=none") && summary.contains("source=auto"),
        "summary must name the (missing) auto address: {summary}"
    );
    assert!(
        summary.contains("lsa_locator=none"),
        "summary must state that the LSA locator is empty without an advertise IP: {summary}"
    );
}

/// MAJOR-2: with the default per-self book, the daemon must say which book mode
/// it uses and the status block must expose "subscribed but no book address".
#[test]
fn default_per_self_book_is_visible_and_reports_coverage() {
    let a = ConfigDir::new("major2-a");
    let b = ConfigDir::new("major2-b");
    let (port_a, port_b) = (free_udp_port(), free_udp_port());
    let (api_a, api_b) = (free_tcp_port(), free_tcp_port());

    a.write_seed(11);
    b.write_seed(12);
    a.write(
        "daemon.toml",
        &format!(
            "localapi_addr = \"127.0.0.1:{api_a}\"\n\n{}{}{}",
            discovery_section(port_a, false),
            turn_section(&a.path().join("seed.hex")),
            tun_section()
        ),
    );
    b.write(
        "daemon.toml",
        &format!(
            "localapi_addr = \"127.0.0.1:{api_b}\"\n\n{}{}{}",
            discovery_section(port_b, false),
            turn_section(&b.path().join("seed.hex")),
            tun_section()
        ),
    );
    a.write("network.toml", &network_toml(11, Some(12), "10.144.0.11"));
    b.write("network.toml", &network_toml(12, Some(11), "10.144.0.12"));

    let daemon_a = Daemon::spawn(a, &[]).expect("daemon A");
    let daemon_b = Daemon::spawn(b, &[]).expect("daemon B");

    let wait_subscribed = |daemon: &Daemon, name: &str| -> serde_json::Value {
        daemon.wait_nat(Duration::from_secs(30), name, |v| {
            v["peer_source"]["state"] == "running"
                && v["peer_source"]["subscribed_peers"].as_u64().unwrap_or(0) >= 1
                && v["peer_source"]["book_reloads_total"].as_u64().unwrap_or(0) >= 1
        })
    };
    wait_subscribed(&daemon_a, "A subscribed");
    wait_subscribed(&daemon_b, "B subscribed");
    // Mutual discovery is real in this rig: both sides exchange LSA traffic in
    // the same run (the subscription itself is labelled `static` by the
    // static-wins rule). Timing of the *LSDB* merge depends on the 30s Hello
    // cycle, so assert the observable traffic rather than the merge instant.
    let a_status = daemon_a.wait_nat(Duration::from_secs(15), "A LSA traffic", |v| {
        v["discovery"]["lsa_adverts_recv"].as_u64().unwrap_or(0) >= 1
    });
    let b_status = daemon_b.wait_nat(Duration::from_secs(15), "B LSA traffic", |v| {
        v["discovery"]["lsa_adverts_recv"].as_u64().unwrap_or(0) >= 1
    });
    for (name, status) in [("A", &a_status), ("B", &b_status)] {
        assert!(
            status["discovery"]["lsa_hellos_sent"].as_u64().unwrap_or(0) >= 1,
            "{name}: LSA pump must be sending Hello frames"
        );
    }

    for (name, status, daemon) in [("A", &a_status, &daemon_a), ("B", &b_status, &daemon_b)] {
        assert_eq!(
            status["peer_source"]["trigger_attempts_total"], 0,
            "{name}: per-self book has no peer address, trigger attempts must stay 0"
        );
        assert_eq!(
            status["peer_source"]["book_entries"], 0,
            "{name}: default per-self book is empty (no TURN allocation in this rig)"
        );
        assert!(
            status["peer_source"]["subscribed_peers_without_book_addr"]
                .as_u64()
                .unwrap_or(0)
                >= 1,
            "{name}: the subscribed-but-unaddressable peer must be counted; status: {status}"
        );
        assert!(
            daemon
                .stderr_text()
                .contains("[nat-relay] book mode=per-self path="),
            "{name}: start-up must name the book mode/path; stderr was:\n{}",
            daemon.stderr_text()
        );
    }

    // MAJOR-1: the effective summary names the auto-selected address on a
    // multi-NIC host (this rig always has a non-loopback interface).
    let expected = nexusd::discovery_runtime::select_advertise_ipv4()
        .expect("this rig has a non-loopback IPv4 (multi-NIC host)");
    for (name, daemon, gossip_port) in [("A", &daemon_a, port_a), ("B", &daemon_b, port_b)] {
        let summary = daemon
            .stderr_lines()
            .into_iter()
            .find(|l| l.starts_with("[discovery] advertise_ip="))
            .unwrap_or_else(|| {
                panic!(
                    "{name}: missing discovery summary; stderr:\n{}",
                    daemon.stderr_text()
                )
            });
        assert!(
            summary.contains(&format!("advertise_ip={expected} source=auto")),
            "{name}: summary must name the selected auto IP ({expected}): {summary}"
        );
        assert!(
            summary.contains(&format!("gossip_port={gossip_port}")),
            "{name}: summary must name the gossip port: {summary}"
        );
        assert!(
            summary.contains("mdns=disabled") && summary.contains("lsa=enabled"),
            "{name}: summary must name the protocol switches: {summary}"
        );
    }
}
