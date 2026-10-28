//! DNS production E4：从生产装配路径出发验证 AC1/AC2/AC3/AC4/AC5/AC8/AC8a/AC8b/AC12/AC13。
//!
//! 装配链（plan §7.1 铁律）：
//! `ConfigDir::new` → `config::load` → `assembly::build_dataplane_config`
//! → `DnsService::start` → `Dataplane::new(SharedTun, cfg, Some(handle))`。
//!
//! 真实上游：本机 `dnsmasq 2.90` 子进程（动态端口、结束 kill+wait；不留进程）。
//!
//! 用法：
//! ```text
//! cargo run --quiet -p nexusd --example dns_production_e4 -- --json --suite upstream
//! ```
//! `--suite` ∈ `upstream|mesh|fakeip|degradation|aaaa|all`（默认 all）。

#![forbid(unsafe_code)]

use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_projection::{MockTun, TunDevice};
use nexusd::config::ConfigDir;
use nexusd::dataplane::Dataplane;
use nexusd::dns_service::DnsService;
use nexusd::dns_status::{DnsStatus, DnsStatusSnapshot};
use serde_json::{Value, json};

const PEER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }
    fn name(&self) -> &str {
        "mockdns0"
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "nexusd-dns-e4-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Dnsmasq {
    child: Child,
    log: PathBuf,
    port: u16,
    _dir: TempDir,
}

impl Dnsmasq {
    fn start(tag: &str) -> Result<Self, String> {
        let port = free_udp_port()?;
        let dir = TempDir::new(&format!("dnsmasq-{tag}"));
        let log = dir.0.join("dnsmasq.log");
        let stderr = File::create(&log).map_err(|e| format!("dnsmasq log: {e}"))?;
        let child = Command::new("/usr/sbin/dnsmasq")
            .args([
                "--no-daemon",
                &format!("--port={port}"),
                "--listen-address=127.0.0.1",
                "--no-resolv",
                "--address=/example.com/93.184.216.34",
                "--address=/v6.example.com/2001:db8::1",
                "--address=/proxied.example/93.184.216.35",
                "--address=/proxied.example/2001:db8::2",
                "--address=/direct.example/93.184.216.36",
                "--address=/nx.example.com/",
                "--local-ttl=60",
                "--log-queries",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|e| format!("spawn dnsmasq: {e}"))?;
        wait_dnsmasq(port)?;
        Ok(Self {
            child,
            log,
            port,
            _dir: dir,
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn query_count(&self, name: &str) -> usize {
        self.log_text()
            .lines()
            .filter(|line| line.contains(&format!("query[A] {name} from 127.0.0.1")))
            .count()
    }
}

impl Drop for Dnsmasq {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_dnsmasq(port: u16) -> Result<(), String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let query = build_query("readiness.example", 1, 1, 0x5151);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let _ = socket.send_to(&query, format!("127.0.0.1:{port}"));
        let mut buf = [0u8; 512];
        if socket.recv_from(&mut buf).is_ok() {
            return Ok(());
        }
    }
    Err("dnsmasq did not become ready".to_string())
}

fn free_udp_port() -> Result<u16, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = socket.local_addr().map_err(|e| e.to_string())?.port();
    drop(socket);
    Ok(port)
}

struct Env {
    _dir: TempDir,
    dp: Dataplane,
    mock: Arc<Mutex<MockTun>>,
    status: Arc<DnsStatus>,
}

fn daemon_toml(tun_enabled: bool) -> String {
    format!("[tun]\nenabled = {tun_enabled}\n[localapi]\naddr = \"127.0.0.1:0\"\n")
}

fn network_toml(with_v6: bool) -> String {
    let mut text = format!(
        "peer_id = \"{PEER_ID}\"\n\
         [[peers]]\n\
         id = \"{PEER_ID}\"\n\
         addrs = [\"127.0.0.1:19001\"]\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"10.144.144.1\"\n\
         mtu = 1200\n\
         [[vpi.routes]]\n\
         subnet = \"10.144.144.0/24\"\n\
         peer = \"{PEER_ID}\"\n"
    );
    if with_v6 {
        text.push_str(&format!(
            "address6 = \"fd00:144::1\"\n\
             [[vpi.routes6]]\n\
             subnet = \"fd00:144::/64\"\n\
             peer = \"{PEER_ID}\"\n"
        ));
    }
    text
}

fn base_dns_toml(upstream: &[String], fake_ip: bool) -> String {
    format!(
        "[dns]\n\
         upstream = [{}]\n\
         fake_ip_enabled = {fake_ip}\n\
         fake_ip_range = \"198.18.0.0/15\"\n\
         mesh_suffix = \"mesh\"\n\
         fake_ip_ttl_secs = 300\n\
         ip_preference = \"prefer_v4\"\n\
         unmatched = \"auto\"\n\
         unevaluable = \"proxied\"\n\
         attempt_timeout_ms = 200\n\
         attempts_per_server = 1\n\
         total_budget_ms = 1500\n\
         edns_udp_size = 0\n\
         tcp_fallback = true\n\
         tcp_timeout_ms = 500\n\
         cache_max_entries = 64\n\
         cache_max_ttl_secs = 60\n\
         negative_ttl_secs = 60\n\
         max_inflight = 16\n",
        upstream
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn proxy_yaml(rules: &str) -> String {
    format!(
        "schema_version: 1\nrules:\n{rules}outbounds:\n  - tag: proxy\n    kind: socks5\n    locator: 127.0.0.1:9\n  - tag: direct\n    kind: direct\n    locator: \"\"\n"
    )
}

fn three_rule_yaml() -> String {
    proxy_yaml(
        "  - tag: r1\n    kind: domain\n    match: proxied.example\n    action:\n      - kind: select_outbound\n        tag: proxy\n  - tag: r2\n    kind: domain_suffix\n    match: proxied.org\n    action:\n      - kind: select_outbound\n        tag: proxy\n  - tag: r3\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\n",
    )
}

fn aaaa_rule_yaml() -> String {
    proxy_yaml(
        "  - tag: r1\n    kind: domain\n    match: proxied.example\n    action:\n      - kind: select_outbound\n        tag: proxy\n  - tag: r2\n    kind: domain_suffix\n    match: proxied.org\n    action:\n      - kind: select_outbound\n        tag: proxy\n  - tag: r3\n    kind: geosite\n    match: category-ads-all\n    action:\n      - kind: select_outbound\n        tag: proxy\n  - tag: r4\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\n",
    )
}

fn build_env(
    tag: &str,
    dns_toml: Option<&str>,
    network: Option<&str>,
    proxy: Option<&str>,
    tun_enabled: bool,
) -> Result<Env, String> {
    let dir = TempDir::new(tag);
    std::fs::write(dir.0.join("daemon.toml"), daemon_toml(tun_enabled))
        .map_err(|e| e.to_string())?;
    if let Some(text) = dns_toml {
        std::fs::write(dir.0.join("dns.toml"), text).map_err(|e| e.to_string())?;
    }
    if let Some(text) = network {
        std::fs::write(dir.0.join("network.toml"), text).map_err(|e| e.to_string())?;
    }
    if let Some(text) = proxy {
        std::fs::write(dir.0.join("proxy.yaml"), text).map_err(|e| e.to_string())?;
    }
    let config_dir = ConfigDir::new(&dir.0).map_err(|e| e.to_string())?;
    let loaded = nexusd::config::load(&config_dir).map_err(|e| e.to_string())?;
    let config = nexusd::assembly::build_dataplane_config(&loaded)?;
    let dns_config = config
        .dns_config
        .clone()
        .ok_or("dns.toml missing in production config")?;
    let status = Arc::new(DnsStatus::new(DnsStatusSnapshot::disabled()));
    let handle = DnsService::start(
        dns_config,
        loaded.proxy_yaml.as_deref(),
        Arc::clone(&status),
    )
    .map_err(|e| e.to_string())?;
    let mock = Arc::new(Mutex::new(MockTun::new("mockdns0")));
    let mut dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, Some(handle))
        .map_err(|e| e.to_string())?;
    // No proxy engine is injected in this E4; classify everything as Proxy so
    // the fake-IP datapath observes `proxy_dropped_no_proxy`.
    dp.set_default_simple_engine().map_err(|e| e.to_string())?;
    Ok(Env {
        _dir: dir,
        dp,
        mock,
        status,
    })
}

struct ReplyView {
    rcode: u8,
    qtype: u16,
    answers: Vec<IpAddr>,
    src_port: u16,
    ip_checksum_ok: bool,
    udp_checksum_ok: bool,
}

impl Env {
    fn query(&mut self, name: &str, qtype: u16) -> Result<ReplyView, String> {
        let txid = 0x4000 | qtype;
        let packet = dns_query_packet(name, qtype, txid);
        self.mock.lock().unwrap().inject(packet);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            self.dp.tick(now_millis()).map_err(|e| e.to_string())?;
            let written = self.mock.lock().unwrap().take_written();
            for reply in written {
                if let Some(view) = parse_reply(&reply, txid) {
                    return Ok(view);
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(format!("no DNS reply for {name}/{qtype}"))
    }

    fn stats(&self) -> nexusd::dataplane::DataplaneStats {
        self.dp.stats()
    }

    fn status_snapshot(&self) -> DnsStatusSnapshot {
        self.status.snapshot()
    }

    fn inject_fake_ip_packet(&mut self, dest: Ipv4Addr) -> (u64, u64) {
        let before = self.stats();
        self.mock.lock().unwrap().inject(udp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            dest,
            40_000,
            9_999,
            b"proxied",
        ));
        for _ in 0..50 {
            let _ = self.dp.tick(now_millis());
            if self.dp.stats().proxy_dropped_no_proxy > before.proxy_dropped_no_proxy
                || self.dp.stats().proxy_forwarded > before.proxy_forwarded
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let after = self.stats();
        (
            after.proxy_dropped_no_proxy - before.proxy_dropped_no_proxy,
            after.proxy_forwarded - before.proxy_forwarded,
        )
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let suite = args
        .iter()
        .position(|a| a == "--suite")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| "all".to_string());
    let output = run(&suite);
    if json_mode {
        println!("{}", serde_json::to_string(&output).expect("json"));
    } else {
        println!("{output:#}");
    }
    if output.get("verdict").and_then(Value::as_str) != Some("PASS") {
        std::process::exit(1);
    }
}

fn run(suite: &str) -> Value {
    if suite == "all" {
        let mut merged = json!({});
        for name in ["upstream", "mesh", "fakeip", "degradation", "aaaa"] {
            let part = run_suite(name);
            if let (Some(dst), Some(src)) = (merged.as_object_mut(), part.as_object()) {
                for (key, value) in src {
                    dst.insert(key.clone(), value.clone());
                }
            }
        }
        let failed = merged
            .as_object()
            .map(|object| {
                object.values().any(|value| {
                    value.get("ok").and_then(Value::as_bool) == Some(false)
                        || value.get("verdict").and_then(Value::as_str) == Some("FAIL")
                })
            })
            .unwrap_or(true);
        merged["verdict"] = json!(if failed { "FAIL" } else { "PASS" });
        return merged;
    }
    run_suite(suite)
}

fn run_suite(suite: &str) -> Value {
    let result = match suite {
        "upstream" => suite_upstream(),
        "mesh" => suite_mesh(),
        "fakeip" => suite_fakeip(),
        "degradation" => suite_degradation(),
        "aaaa" => suite_aaaa(),
        other => Err(format!("unknown suite {other}")),
    };
    match result {
        Ok(mut value) => {
            let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(true);
            value["verdict"] = json!(if ok { "PASS" } else { "FAIL" });
            value
        }
        Err(error) => json!({"ok": false, "verdict": "FAIL", "error": error}),
    }
}

fn suite_upstream() -> Result<Value, String> {
    let dnsmasq = Dnsmasq::start("upstream")?;
    let port = dnsmasq.port();
    let dns = base_dns_toml(&[format!("127.0.0.1:{port}")], false);
    let mut env = build_env("upstream", Some(&dns), None, None, true)?;

    // AC1
    let reply = env.query("example.com", 1)?;
    let ac1_ok = reply.rcode == 0
        && reply.qtype == 1
        && reply.answers == vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        && reply.src_port == 53
        && reply.ip_checksum_ok
        && reply.udp_checksum_ok
        && env.stats().dns_answered == 1;
    let snapshot = env.status_snapshot();
    let ac1_ok = ac1_ok
        && snapshot.classes.upstream
        && snapshot
            .upstream
            .servers
            .first()
            .map(|s| s.ok >= 1)
            .unwrap_or(false)
        && dnsmasq.query_count("example.com") >= 1;

    // AC2: blackhole first, then dnsmasq. Cache + negative cache.
    let blackhole = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let blackhole_port = blackhole.local_addr().map_err(|e| e.to_string())?.port();
    let dns = base_dns_toml(
        &[
            format!("127.0.0.1:{blackhole_port}"),
            format!("127.0.0.1:{port}"),
        ],
        false,
    );
    let mut env2 = build_env("ac2", Some(&dns), None, None, true)?;
    let started = Instant::now();
    let first = env2.query("example.com", 1)?;
    let elapsed = started.elapsed();
    let status = env2.status_snapshot();
    let failover_ok = first.rcode == 0
        && status.counters.upstream_failovers >= 1
        && elapsed <= Duration::from_millis(1500 + 500);
    let before = dnsmasq.query_count("example.com");
    let second = env2.query("example.com", 1)?;
    let cache_ok = second.rcode == 0
        && env2.status_snapshot().counters.cache_hits >= 1
        && dnsmasq.query_count("example.com") == before;

    let nx = env2.query("nx.example.com", 1)?;
    let nxdomain_first_count = env2.stats().dns_nxdomain;
    let nxdomain_first = nx.rcode == 3 && nxdomain_first_count == 1;
    let nx_again = env2.query("nx.example.com", 1)?;
    let negative_cached = nx_again.rcode == 3 && env2.status_snapshot().counters.cache_hits >= 2;

    // AC12: status/cache come from the production handle, not the demo runtime.
    let final_status = env.status_snapshot();
    let cache = nexusd::dns_status::cache_entries();
    let ac12_ok = final_status.enabled
        && final_status.service.as_str() == "running"
        && final_status.upstream.plaintext
        && !cache.is_empty();

    // AC5 (enabled side): all classes true and service running.
    let mut ac5_dns = base_dns_toml(&[format!("127.0.0.1:{port}")], false);
    ac5_dns.push_str(
        "[dns.hosts]\n\"local5.example\" = \"10.9.9.9\"\n[dns.mesh.hosts]\n\"peer.mesh\" = \"10.144.144.6\"\n",
    );
    let ac5_env = build_env(
        "ac5",
        Some(&ac5_dns),
        Some(&network_toml(false)),
        Some(&three_rule_yaml()),
        true,
    )?;
    let ac5_status = ac5_env.status_snapshot();
    let ac5_ok = ac5_status.enabled
        && ac5_status.service.as_str() == "running"
        && ac5_status.classes.hosts
        && ac5_status.classes.mesh
        && ac5_status.classes.proxy_classifier
        && ac5_status.classes.upstream
        && snapshot.enabled
        && dnsmasq
            .log_text()
            .contains("query[A] example.com from 127.0.0.1");

    Ok(json!({
        "ac1": {
            "rcode": reply.rcode,
            "qtype": reply.qtype,
            "answer": reply.answers.first().map(ToString::to_string).unwrap_or_default(),
            "src_port": reply.src_port,
            "ip_checksum_ok": reply.ip_checksum_ok,
            "udp_checksum_ok": reply.udp_checksum_ok,
        },
        "dataplane": {"dns_answered": env.stats().dns_answered},
        "dns": {
            "classes": {"upstream": snapshot.classes.upstream},
            "upstream": {"servers": [{"ok": snapshot.upstream.servers.first().map(|s| s.ok).unwrap_or(0)}]},
        },
        "ac2": {
            "rcode": first.rcode,
            "elapsed_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "failovers": status.counters.upstream_failovers,
            "second_rcode": second.rcode,
            "cache_hits": env2.status_snapshot().counters.cache_hits,
            "dnsmasq_unchanged": dnsmasq.query_count("example.com") == before,
            "nx_rcode": nx.rcode,
            "dns_nxdomain": nxdomain_first_count,
            "negative_cached": negative_cached,
        },
        "ac5": {"ok": ac5_ok && dnsmasq.port() != 0},
        "ac12": {"ok": ac12_ok, "cache_entries": cache.len()},
        "ok": ac1_ok && failover_ok && cache_ok && nxdomain_first && negative_cached && ac12_ok && ac5_ok,
    }))
}

fn suite_mesh() -> Result<Value, String> {
    let dnsmasq = Dnsmasq::start("mesh")?;
    let port = dnsmasq.port();
    let mut dns = base_dns_toml(&[format!("127.0.0.1:{port}")], false);
    dns.push_str(
        "[dns.mesh.hosts]\n\"peer.mesh\" = \"10.144.144.6\"\n\"v6.mesh\" = \"fd00:144::9\"\n",
    );
    let mut env = build_env("mesh", Some(&dns), Some(&network_toml(true)), None, true)?;
    let peer = env.query("peer.mesh", 1)?;
    let status = env.status_snapshot();
    let upstream_delta = status.upstream.servers.first().map(|s| s.ok).unwrap_or(0);
    let ghost = env.query("ghost.mesh", 1)?;
    let ghost_delta = env
        .status_snapshot()
        .upstream
        .servers
        .first()
        .map(|s| s.ok)
        .unwrap_or(0)
        .saturating_sub(upstream_delta);
    let v6 = env.query("v6.mesh", 28)?;
    let v6_a = env.query("v6.mesh", 1)?;
    let ok = peer.rcode == 0
        && peer.answers == vec![IpAddr::V4(Ipv4Addr::new(10, 144, 144, 6))]
        && status.classes.mesh
        && upstream_delta == 0
        && ghost.rcode == 3
        && ghost_delta == 0
        && v6.rcode == 0
        && v6.answers == vec![IpAddr::V6(Ipv6Addr::new(0xfd00, 0x144, 0, 0, 0, 0, 0, 9))]
        && v6_a.rcode == 0
        && v6_a.answers.is_empty();
    Ok(json!({
        "ac3": {
            "answer": peer.answers.first().map(ToString::to_string).unwrap_or_default(),
            "class": "Mesh",
            "upstream_delta": upstream_delta,
            "ghost_rcode": ghost.rcode,
            "ghost_upstream_delta": ghost_delta,
        },
        "ac8": {
            "group3_aaaa": v6.answers.first().map(ToString::to_string).unwrap_or_default(),
            "group3_a_nodata": v6_a.answers.is_empty(),
        },
        "ok": ok,
    }))
}

fn suite_fakeip() -> Result<Value, String> {
    let dnsmasq = Dnsmasq::start("fakeip")?;
    let port = dnsmasq.port();
    let dns = base_dns_toml(&[format!("127.0.0.1:{port}")], true);
    let yaml = three_rule_yaml();
    let mut env = build_env("fakeip", Some(&dns), None, Some(&yaml), true)?;
    let first = env.query("proxied.example", 1)?;
    let status = env.status_snapshot();
    let fake = match first.answers.first() {
        Some(IpAddr::V4(v4)) => *v4,
        _ => return Err("fake-ip answer missing".to_string()),
    };
    let in_range = {
        let v = u32::from_be_bytes(fake.octets());
        (v & 0xFFFE_0000) == 0xC612_0000
    };
    let allocated_first = status.fake_ip.allocated;
    let second = env.query("proxied.example", 1)?;
    let stable = second.answers.first() == first.answers.first();
    let direct = env.query("direct.example", 1)?;
    let direct_ip = direct
        .answers
        .first()
        .map(ToString::to_string)
        .unwrap_or_default();
    let allocated_after_direct = env.status_snapshot().fake_ip.allocated;
    let reverse = env
        .dp
        .dns_cache_handle()
        .lock()
        .unwrap()
        .lookup(&IpAddr::V4(fake))
        .unwrap_or_default();
    let (dropped_delta, forwarded_delta) = env.inject_fake_ip_packet(fake);
    let status = env.status_snapshot();
    let ok = first.rcode == 0
        && in_range
        && first.qtype == 1
        && status.classes.proxy_classifier
        && allocated_first == 1
        && stable
        && direct.rcode == 0
        && direct_ip == "93.184.216.36"
        && allocated_after_direct == 1
        && reverse == "proxied.example"
        && status.proxy_policy.rules == 3
        && (dropped_delta + forwarded_delta) >= 1;
    Ok(json!({
        "ac4": {
            "fakeip": {
                "in_range": in_range,
                "class": "FakeIp",
                "allocated": allocated_first,
                "stable": stable,
                "reverse_lookup": reverse,
            },
            "direct_ip": direct_ip,
            "allocated_after_direct": allocated_after_direct,
            "proxy_dropped_delta": dropped_delta,
            "proxy_forwarded_delta": forwarded_delta,
            "proxy_policy": {"rules": status.proxy_policy.rules},
            "classes": {"proxy_classifier": status.classes.proxy_classifier},
        },
        "ok": ok,
    }))
}

fn suite_degradation() -> Result<Value, String> {
    // AC13: all upstreams dead -> SERVFAIL + state=failed + dns_servfail.
    let dead_port = free_udp_port()?;
    let dns = base_dns_toml(&[format!("127.0.0.1:{dead_port}")], false);
    let mut env = build_env("degradation", Some(&dns), None, None, true)?;
    let mut servfails = 0;
    for i in 0..3 {
        let reply = env.query(&format!("dead{i}.example"), 1)?;
        if reply.rcode == 2 {
            servfails += 1;
        }
    }
    let status = env.status_snapshot();
    let all_dead_ok =
        servfails == 3 && env.stats().dns_servfail >= 3 && status.upstream.state == "failed";

    // AC13: TCP/53 -> RST + dns_tcp_refused.
    let tcp_query = tcp_syn_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(8, 8, 8, 8),
        40_000,
        53,
    );
    env.mock.lock().unwrap().inject(tcp_query);
    let mut rst = false;
    for _ in 0..100 {
        let _ = env.dp.tick(now_millis());
        for packet in env.mock.lock().unwrap().take_written() {
            if packet.len() >= 40 && packet[9] == 6 && packet[33] & 0x04 != 0 {
                rst = true;
            }
        }
        if rst {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let tcp_ok = rst && env.stats().dns_tcp_refused == 1 && env.stats().dns_answered >= 1;

    // AC13: fake-ip pool exhaustion (/30 -> 2 hosts) -> SERVFAIL + exhausted.
    let dns = base_dns_toml(&[format!("127.0.0.1:{dead_port}")], true).replace(
        "fake_ip_range = \"198.18.0.0/15\"",
        "fake_ip_range = \"198.18.0.0/30\"",
    );
    let mut pool_env = build_env("pool", Some(&dns), None, Some(&three_rule_yaml()), true)?;
    let _ = pool_env.query("a.proxied.org", 1)?;
    let _ = pool_env.query("b.proxied.org", 1)?;
    let third = pool_env.query("c.proxied.org", 1)?;
    let pool_ok = third.rcode == 2 && pool_env.status_snapshot().fake_ip.exhausted >= 1;

    // AC5 (disabled side): no dns.toml -> enabled=false, no interception.
    let mut off = build_env_without_dns("off")?;
    let before = off.stats().dns_answered;
    off.mock
        .lock()
        .unwrap()
        .inject(dns_query_packet("example.com", 1, 0x7777));
    for _ in 0..20 {
        let _ = off.dp.tick(now_millis());
        std::thread::sleep(Duration::from_millis(1));
    }
    let disabled_ok = !off.dp.dns_service_ready()
        && off.status_snapshot().enabled == false
        && off.status_snapshot().service.as_str() == "disabled"
        && off.stats().dns_answered == before;

    // AC8b: invalid dns.toml + no-tun starts, tun-enabled exits 1 CONFIG.
    let ac8b = ac8b_subprocess()?;

    let ok = all_dead_ok && tcp_ok && pool_ok && disabled_ok && ac8b.ok;
    Ok(json!({
        "ac13": {
            "all_dead_ok": all_dead_ok,
            "dns_servfail": env.stats().dns_servfail,
            "upstream_state": status.upstream.state,
            "tcp_refused": tcp_ok,
            "dns_tcp_refused": env.stats().dns_tcp_refused,
            "pool_exhausted": pool_ok,
            "dns_enabled_off": disabled_ok,
        },
        "ac8b": {"ok": ac8b.ok, "detail": ac8b.detail},
        "ok": ok,
    }))
}

struct Ac8b {
    ok: bool,
    detail: Value,
}

fn ac8b_subprocess() -> Result<Ac8b, String> {
    let bin = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("nexusd"))
        .ok_or("cannot locate nexusd binary")?;
    let bad_dns = "[dns]\nupstream = []\nunknown_key = 1\n";
    let no_tun = TempDir::new("ac8b-notun");
    std::fs::write(no_tun.0.join("daemon.toml"), daemon_toml(false)).unwrap();
    std::fs::write(no_tun.0.join("dns.toml"), bad_dns).unwrap();
    std::fs::write(no_tun.0.join("network.toml"), network_toml(false)).unwrap();
    let no_tun_out = Command::new("timeout")
        .args(["--preserve-status", "-s", "TERM", "2"])
        .arg(&bin)
        .arg(&no_tun.0)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    let no_tun_text = format!(
        "{}{}",
        String::from_utf8_lossy(&no_tun_out.stdout),
        String::from_utf8_lossy(&no_tun_out.stderr)
    );
    let no_tun_ok = no_tun_out.status.success() && !no_tun_text.contains("\"code\":\"CONFIG\"");

    let tun = TempDir::new("ac8b-tun");
    std::fs::write(tun.0.join("daemon.toml"), daemon_toml(true)).unwrap();
    std::fs::write(tun.0.join("dns.toml"), bad_dns).unwrap();
    std::fs::write(tun.0.join("network.toml"), network_toml(false)).unwrap();
    let tun_out = Command::new(&bin)
        .arg(&tun.0)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    let tun_text = format!(
        "{}{}",
        String::from_utf8_lossy(&tun_out.stdout),
        String::from_utf8_lossy(&tun_out.stderr)
    );
    let tun_ok = tun_out.status.code() == Some(1) && tun_text.contains("\"code\":\"CONFIG\"");

    Ok(Ac8b {
        ok: no_tun_ok && tun_ok,
        detail: json!({
            "no_tun_exit": no_tun_out.status.code(),
            "no_tun_has_config": no_tun_text.contains("\"code\":\"CONFIG\""),
            "tun_exit": tun_out.status.code(),
            "tun_has_config": tun_text.contains("\"code\":\"CONFIG\""),
            "channel": "stdout+stderr",
        }),
    })
}

fn build_env_without_dns(tag: &str) -> Result<Env, String> {
    let dir = TempDir::new(tag);
    std::fs::write(dir.0.join("daemon.toml"), daemon_toml(true)).map_err(|e| e.to_string())?;
    let config_dir = ConfigDir::new(&dir.0).map_err(|e| e.to_string())?;
    let loaded = nexusd::config::load(&config_dir).map_err(|e| e.to_string())?;
    let config = nexusd::assembly::build_dataplane_config(&loaded)?;
    if config.dns_enabled {
        return Err("dns unexpectedly enabled".to_string());
    }
    let status = Arc::new(DnsStatus::new(DnsStatusSnapshot::disabled()));
    nexusd::dns_status::publish(Arc::clone(&status));
    let mock = Arc::new(Mutex::new(MockTun::new("mockdns0")));
    let dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)
        .map_err(|e| e.to_string())?;
    Ok(Env {
        _dir: dir,
        dp,
        mock,
        status,
    })
}

fn suite_aaaa() -> Result<Value, String> {
    let dnsmasq = Dnsmasq::start("aaaa")?;
    let port = dnsmasq.port();

    // AC8a: three proxied categories, fake-ip on, AAAA always NODATA.
    let dns = base_dns_toml(&[format!("127.0.0.1:{port}")], true);
    let mut env = build_env(
        "aaaa-nodata",
        Some(&dns),
        None,
        Some(&aaaa_rule_yaml()),
        true,
    )?;
    let mut nodata_ok = true;
    let mut a_ok = true;
    let mut aaaa_allocation_unchanged = true;
    for name in ["proxied.example", "corp.proxied.org", "geo.example"] {
        let before = env.status_snapshot().fake_ip.allocated;
        let aaaa = env.query(name, 28)?;
        let after = env.status_snapshot().fake_ip.allocated;
        if aaaa.rcode != 0 || !aaaa.answers.is_empty() || before != after {
            nodata_ok = false;
            aaaa_allocation_unchanged = false;
        }
        let a = env.query(name, 1)?;
        if a.rcode != 0 || a.answers.is_empty() {
            a_ok = false;
        }
    }
    let allocated_after = env.status_snapshot().fake_ip.allocated;
    let ac8a_ok = nodata_ok && aaaa_allocation_unchanged && allocated_after == 3;

    // AC8 group1: upstream AAAA (classifier catch-all direct -> Upstream).
    let mut group1_env = build_env(
        "aaaa-group1",
        Some(&dns),
        None,
        Some(&three_rule_yaml()),
        true,
    )?;
    let group1 = group1_env.query("v6.example.com", 28)?;
    let group1_ok = group1.rcode == 0
        && group1.qtype == 28
        && group1.answers == vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))];

    // AC8 group4: v4_only gates upstream/mesh/hosts, fake-ip A unaffected.
    let mut v4dns = base_dns_toml(&[format!("127.0.0.1:{port}")], true).replace(
        "ip_preference = \"prefer_v4\"",
        "ip_preference = \"v4_only\"",
    );
    v4dns.push_str("[dns.mesh.hosts]\n\"peer.mesh\" = \"10.144.144.6\"\n");
    let mut v4 = build_env(
        "aaaa-v4only",
        Some(&v4dns),
        Some(&network_toml(false)),
        Some(&three_rule_yaml()),
        true,
    )?;
    let upstream_aaaa = v4.query("example.com", 28)?;
    let upstream_a = v4.query("example.com", 1)?;
    let proxied_a = v4.query("proxied.example", 1)?;
    let group4_ok = upstream_aaaa.rcode == 0
        && upstream_aaaa.answers.is_empty()
        && upstream_a.rcode == 0
        && upstream_a.answers == vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        && proxied_a.answers.len() == 1
        && v4.status_snapshot().fake_ip.allocated >= 1;

    // AC8 group5: non-A/AAAA qtype is forwarded unchanged; proxied -> NODATA.
    let https_upstream = v4.query("example.com", 65)?;
    let https_proxied = v4.query("proxied.example", 65)?;
    let group5_ok = https_upstream.qtype == 65
        && matches!(https_upstream.rcode, 0 | 2 | 5)
        && https_proxied.rcode == 0
        && https_proxied.qtype == 65
        && https_proxied.answers.is_empty();

    // AC8 group6: fake-ip off -> real A/AAAA; allocation unchanged.
    let off_dns = base_dns_toml(&[format!("127.0.0.1:{port}")], false);
    let mut off = build_env(
        "aaaa-off",
        Some(&off_dns),
        None,
        Some(&three_rule_yaml()),
        true,
    )?;
    let off_a = off.query("proxied.example", 1)?;
    let off_aaaa = off.query("proxied.example", 28)?;
    let group6_ok = off_a.answers == vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))]
        && off_aaaa.answers == vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))]
        && off.status_snapshot().fake_ip.allocated == 0;

    // group6's v6 datapath classification depends on C18 (ipv6.* counters).
    let ok = ac8a_ok && group1_ok && group4_ok && group5_ok && group6_ok;
    Ok(json!({
        "ac8a": {
            "nodata": nodata_ok,
            "allocated_unchanged_for_aaaa": aaaa_allocation_unchanged,
            "a_still_fakeip": a_ok,
            "allocated": allocated_after,
        },
        "ac8": {
            "group1": group1_ok,
            "group1_rcode": group1.rcode,
            "group1_qtype": group1.qtype,
            "group1_answers": group1.answers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "group5_upstream_qtype": https_upstream.qtype,
            "group5_upstream_rcode": https_upstream.rcode,
            "group5_upstream_answers": https_upstream.answers.len(),
            "group5_proxied_rcode": https_proxied.rcode,
            "group5_proxied_answers": https_proxied.answers.len(),
            "group4": group4_ok,
            "group5": group5_ok,
            "group6": group6_ok,
            "group6_v6_datapath": "pending C18 (ipv6.classified_proxy/proxy_dropped)",
        },
        "ok": ok,
    }))
}

// ---------- packet helpers ----------

fn now_millis() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn build_query(name: &str, qtype: u16, class: u16, txid: u16) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&txid.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00]);
    dns.extend_from_slice(&[0x00, 0x01]);
    dns.extend_from_slice(&[0x00, 0x00]);
    dns.extend_from_slice(&[0x00, 0x00]);
    dns.extend_from_slice(&[0x00, 0x00]);
    for label in name.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&qtype.to_be_bytes());
    dns.extend_from_slice(&class.to_be_bytes());
    dns
}

fn dns_query_packet(name: &str, qtype: u16, txid: u16) -> Vec<u8> {
    let dns = build_query(name, qtype, 1, txid);
    udp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(8, 8, 8, 8),
        40_000,
        53,
        &dns,
    )
}

fn udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let checksum = udp_checksum(IpAddr::V4(src), IpAddr::V4(dst), &packet[20..]);
    packet[26..28].copy_from_slice(&checksum.to_be_bytes());
    let c = ip_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&c.to_be_bytes());
    packet
}

fn tcp_syn_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&7u32.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02; // SYN
    let tcp_sum = tcp_checksum_v4(src, dst, &tcp);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let sum = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&tcp);
    ip
}

fn parse_reply(packet: &[u8], txid: u16) -> Option<ReplyView> {
    if packet.len() < 28 || packet[9] != 17 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < 20 || total > packet.len() || total < ihl + 8 {
        return None;
    }
    let dns = &packet[ihl + 8..total];
    if dns.len() < 12 || u16::from_be_bytes([dns[0], dns[1]]) != txid {
        return None;
    }
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    let mut off = 12;
    if qdcount != 1 {
        return None;
    }
    let mut labels = Vec::new();
    loop {
        let len = *dns.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        off += 1;
        labels.push(String::from_utf8_lossy(dns.get(off..off + len)?).to_string());
        off += len;
    }
    let qtype = u16::from_be_bytes([*dns.get(off)?, *dns.get(off + 1)?]);
    off += 4;
    let mut answers = Vec::new();
    for _ in 0..ancount {
        off = skip_name(dns, off)?;
        let rtype = u16::from_be_bytes([*dns.get(off)?, *dns.get(off + 1)?]);
        let rdlen = usize::from(u16::from_be_bytes([*dns.get(off + 8)?, *dns.get(off + 9)?]));
        let start = off + 10;
        let end = start + rdlen;
        let rdata = dns.get(start..end)?;
        match (rtype, rdlen) {
            (1, 4) => answers.push(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                answers.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        off = end;
    }
    let udp = &packet[ihl..total];
    Some(ReplyView {
        rcode,
        qtype,
        answers,
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        ip_checksum_ok: ip_checksum(&packet[..ihl]) == 0,
        udp_checksum_ok: udp_checksum(
            IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            udp,
        ) == 0,
    })
}

fn skip_name(data: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *data.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        off += 1 + len;
    }
}

fn ip_checksum(header: &[u8]) -> u16 {
    fold(add_words(0, header))
}

fn tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut sum = add_words(0, &src.octets());
    sum = add_words(sum, &dst.octets());
    sum += 6 + tcp.len() as u32;
    fold(add_words(sum, tcp))
}

fn udp_checksum(src: IpAddr, dst: IpAddr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            sum = add_words(sum, &src.octets());
            sum = add_words(sum, &dst.octets());
            sum += 17 + udp.len() as u32;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            sum = add_words(sum, &src.octets());
            sum = add_words(sum, &dst.octets());
            sum += ((udp.len() as u32) >> 16) + ((udp.len() as u32) & 0xFFFF) + 17;
        }
        _ => return 0,
    }
    fold(add_words(sum, udp))
}

fn add_words(mut sum: u32, data: &[u8]) -> u32 {
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
