//! IPv6 数据面 E4（R3 C19）：AC6 / AC7 / AC10 / AC16。
//!
//! 装配链（plan §7.1 铁律）：
//! `ConfigDir::new` → `config::load` → `assembly::build_dataplane_config`
//! → `Dataplane::new(SharedTun(MockTun), cfg, None)`。
//!
//! 每个 section 在**独立子进程**里跑（父进程 spawn 自身 `--child --section <s>`），
//! 这样 stderr 的限流日志可以按 section 精确计数（AC7/AC10 的"行数 ≤1"断言
//! 需要可判定的日志捕获，而 harness 只对 stdout JSON 做断言）。
//!
//! 用法：
//! ```text
//! cargo run --quiet -p nexusd --example ipv6_dataplane_e4 -- --json
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use nexus_network::n1::N1Error;
use nexus_network::n1::bridge::N1Sender;
use nexus_projection::ip::build_udp_packet;
use nexus_projection::{MockTun, TunDevice};
use nexusd::config::ConfigDir;
use nexusd::dataplane::{Dataplane, Ipv6Paths, Ipv6Stats};
use serde_json::{Value, json};

const PEER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// fake N1 sender 记录到的帧：`(目的地址, 原始包字节)`。
type Frames = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

/// `MockTun` 读回范式（N-11）。
struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }

    fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(packet)
    }

    fn name(&self) -> &str {
        "mockv6"
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "nexusd-ipv6-e4-{tag}-{}-{}",
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

/// 记录 N1 原始转发的 fake sender（AC6：dst 必须是 `IpAddr::V6`，字节逐字一致）。
struct RecordingSender {
    frames: Frames,
    /// true = 模拟"bridge 无该 v6 路由"（send_to_mesh 失败）。
    fail: bool,
}

impl N1Sender for RecordingSender {
    fn send_to_mesh(&self, dst: IpAddr, packet: &[u8]) -> Result<(), N1Error> {
        if self.fail {
            return Err(N1Error::PeerUnknown);
        }
        self.frames.lock().unwrap().push((dst, packet.to_vec()));
        Ok(())
    }
}

fn daemon_toml() -> String {
    "[tun]\nenabled = true\n[localapi]\naddr = \"127.0.0.1:0\"\n".to_string()
}

fn network_toml(with_routes6: bool) -> String {
    // `[vpi]` 的标量键必须写在任何 `[[vpi.routes*]]` 表之前，否则 TOML 会把
    // 它们算作上一个表的键（`address6` 曾被解析成 routes 的未知键）。
    let address6 = if with_routes6 {
        "address6 = \"fd00:144::1\"\n"
    } else {
        ""
    };
    let mut text = format!(
        "peer_id = \"{PEER_ID}\"\n\
         [[peers]]\n\
         id = \"{PEER_ID}\"\n\
         addrs = [\"127.0.0.1:19001\"]\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"10.144.144.1\"\n\
         {address6}\
         mtu = 1200\n\
         [[vpi.routes]]\n\
         subnet = \"10.144.144.0/24\"\n\
         peer = \"{PEER_ID}\"\n"
    );
    if with_routes6 {
        text.push_str(&format!(
            "[[vpi.routes6]]\n\
             subnet = \"fd00:144::/64\"\n\
             peer = \"{PEER_ID}\"\n"
        ));
    }
    text
}

/// 生产装配：临时 config 目录 → `config::load` → `build_dataplane_config`。
struct Env {
    _dir: TempDir,
    dp: Dataplane,
    mock: Arc<Mutex<MockTun>>,
    paths: Ipv6Paths,
}

fn assemble(tag: &str, with_routes6: bool) -> Result<Env, String> {
    let dir = TempDir::new(tag);
    std::fs::write(dir.0.join("daemon.toml"), daemon_toml()).map_err(|e| e.to_string())?;
    std::fs::write(dir.0.join("network.toml"), network_toml(with_routes6))
        .map_err(|e| e.to_string())?;
    let config_dir = ConfigDir::new(&dir.0).map_err(|e| e.to_string())?;
    let loaded = nexusd::config::load(&config_dir).map_err(|e| e.to_string())?;
    let config = nexusd::assembly::build_dataplane_config(&loaded)?;
    let paths = Ipv6Paths::from_capabilities(!config.mesh_cidrs6.is_empty());
    let mock = Arc::new(Mutex::new(MockTun::new("mockv6")));
    let dp = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)?;
    Ok(Env {
        _dir: dir,
        dp,
        mock,
        paths,
    })
}

impl Env {
    /// 注入一个包并推进一轮（v6 分支同步完成，不需要等待）。
    fn inject(&mut self, packet: Vec<u8>) -> Result<(), String> {
        self.mock.lock().unwrap().inject(packet);
        self.dp.process_one().map(|_| ()).map_err(|e| e.to_string())
    }
}

fn stats_json(stats: &Ipv6Stats) -> Value {
    json!({
        "packets": stats.packets,
        "udp": stats.udp,
        "tcp": stats.tcp,
        "classified_mesh": stats.classified_mesh,
        "classified_direct": stats.classified_direct,
        "classified_proxy": stats.classified_proxy,
        "mesh_forwarded": stats.mesh_forwarded,
        "mesh_no_route": stats.mesh_no_route,
        "proxy_dropped": stats.proxy_dropped,
        "multicast": stats.multicast,
        "dropped_truncated": stats.dropped_truncated,
        "dropped_extension": stats.dropped_extension,
        "fragments": stats.fragments,
    })
}

/// 构造 v6/UDP 包（校验和由 `build_udp_packet` 写全；AC6 要求 ≤1200 总长）。
fn v6_udp(dst: &str, payload: &[u8]) -> Vec<u8> {
    build_udp_packet(
        "[fd00:144::1]:40000".parse().expect("v6 src"),
        format!("[{dst}]:8080").parse().expect("v6 dst"),
        payload,
    )
    .expect("v6 udp packet")
}

/// 构造 v6/TCP SYN（最小 20B 段）。
fn v6_tcp(dst: &str) -> Vec<u8> {
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
    pkt[6] = 6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&"fd00:144::1".parse::<Ipv6Addr>().unwrap().octets());
    pkt[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
    pkt[40..42].copy_from_slice(&40000u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&80u16.to_be_bytes());
    pkt[44..48].copy_from_slice(&1000u32.to_be_bytes());
    pkt[52] = 0x50;
    pkt[53] = 0x02;
    pkt
}

/// 构造 v6 非 TCP/UDP 包（ICMPv6 58 / ESP 50 等；无 L4 端口）。
fn v6_proto(dst: &str, protocol: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
    pkt[6] = protocol;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&"fd00:144::1".parse::<Ipv6Addr>().unwrap().octets());
    pkt[24..40].copy_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
    pkt
}

/// 在 v6 包上插入一个 8B 扩展头（`extension`=44 时为 Fragment 头）。
fn with_extension(inner: Vec<u8>, extension: u8, next: u8) -> Vec<u8> {
    let mut pkt = inner[..40].to_vec();
    pkt.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&inner[40..]);
    pkt[6] = extension;
    let payload_len = (pkt.len() - 40) as u16;
    pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
    pkt
}

fn truncated() -> Vec<u8> {
    let mut pkt = vec![0u8; 24];
    pkt[0] = 0x60;
    pkt[6] = 17;
    pkt
}

// ===== sections =====

/// AC6：v6/UDP → Mesh 原始转发（fake N1 记录 dst + 字节）。
fn section_ac6() -> Result<Value, String> {
    let mut env = assemble("ac6", true)?;
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    env.dp.set_n1_sender(Arc::new(RecordingSender {
        frames: Arc::clone(&frames),
        fail: false,
    }));
    let packet = v6_udp("fd00:144::6", b"mesh-udp");
    env.inject(packet.clone())?;

    let stats = env.dp.stats();
    let captured = frames.lock().unwrap().clone();
    let recorded_dst = captured.first().map(|(dst, _)| dst.to_string());
    let bytes_match = captured.first().is_some_and(|(_, bytes)| bytes == &packet);
    let ok = stats.ipv6.packets == 1
        && stats.ipv6.udp == 1
        && stats.ipv6.classified_mesh == 1
        && stats.ipv6.mesh_forwarded == 1
        && stats.dropped == 0
        && recorded_dst.as_deref() == Some("fd00:144::6")
        && bytes_match;
    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "ipv6": stats_json(&stats.ipv6),
        "dropped": stats.dropped,
        "mesh_dropped_no_n1": stats.mesh_dropped_no_n1,
        "sender": {
            "frames": captured.len(),
            "dst": recorded_dst,
            "bytes_match": bytes_match,
            "total_len": captured.first().map(|(_, b)| b.len()),
        },
        "paths": env.paths.json(),
    }))
}

/// AC6 反例：mesh 分类但 N1 无 v6 路由 → `ipv6.mesh_no_route` 且
/// `mesh_dropped_no_n1` 同步 +1。
///
/// 说明：v6 路由（`[[vpi.routes6]]`）同时决定 mesh CIDR 与桥接路由表；
/// 从配置里删掉它会让包**不再分类为 Mesh**（见 `ac6_no_routes6`），因此
/// "有 CIDR、无路由"这一态由 fake sender 的失败表达（N1 桥无该目的路由）。
fn section_ac6_no_route() -> Result<Value, String> {
    let mut env = assemble("ac6nr", true)?;
    env.dp.set_n1_sender(Arc::new(RecordingSender {
        frames: Arc::new(Mutex::new(Vec::new())),
        fail: true,
    }));
    env.inject(v6_udp("fd00:144::6", b"mesh-no-route"))?;

    let stats = env.dp.stats();
    let ok = stats.ipv6.classified_mesh == 1
        && stats.ipv6.mesh_no_route == 1
        && stats.ipv6.mesh_forwarded == 0
        && stats.mesh_dropped_no_n1 == 1
        && stats.dropped == 0;
    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "ipv6": stats_json(&stats.ipv6),
        "dropped": stats.dropped,
        "mesh_dropped_no_n1": stats.mesh_dropped_no_n1,
    }))
}

/// AC6 补充：删掉 `[[vpi.routes6]]` 后同一目的不再分类为 Mesh（如实记录）。
///
/// `fd00:144::6` 是 ULA，落在 v6 bypass 默认集合 `fc00::/7` → Direct（只计数）。
/// 这解释了为什么 AC6 的"无路由"必须用 N1 桥的路由态表达：配置层面删路由会同时
/// 删掉 mesh CIDR，包会改走 bypass，而不是落 `mesh_no_route`。
fn section_ac6_no_routes6() -> Result<Value, String> {
    let mut env = assemble("ac6nor6", false)?;
    env.dp.set_n1_sender(Arc::new(RecordingSender {
        frames: Arc::new(Mutex::new(Vec::new())),
        fail: false,
    }));
    env.inject(v6_udp("fd00:144::6", b"mesh-no-cidr"))?;

    let stats = env.dp.stats();
    let ok = stats.ipv6.packets == 1
        && stats.ipv6.classified_mesh == 0
        && stats.ipv6.mesh_no_route == 0
        && stats.ipv6.classified_direct == 1
        && stats.ipv6.classified_proxy == 0
        && stats.dropped == 0
        && env.paths.mesh == "unsupported";
    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "ipv6": stats_json(&stats.ipv6),
        "paths": env.paths.json(),
    }))
}

/// AC7：Direct 计数、Proxy 阻断（N=10 burst）、多播只计数、能力表。
fn section_ac7() -> Result<Value, String> {
    let mut env = assemble("ac7", true)?;
    let direct_before = env.dp.stats().direct_forwarded;

    env.inject(v6_udp("fc00::5", b"direct"))?;
    // 同一 dst 连续 burst 共 10 个包（含首包；不等待 wall-clock 60 s）。
    for i in 0..10 {
        env.inject(v6_udp("2001:db8::20", &[i as u8]))?;
    }
    env.inject(v6_udp("ff02::1", b"mcast"))?;

    let stats = env.dp.stats();
    let direct_forwarded_delta = stats.direct_forwarded - direct_before;
    let ok = stats.ipv6.packets == 12
        && stats.ipv6.classified_direct == 1
        && direct_forwarded_delta == 1
        && stats.ipv6.classified_proxy == 10
        && stats.ipv6.proxy_dropped == 10
        && stats.ipv6.multicast == 1
        && stats.dropped == 0
        && env.paths.proxy_udp == "blocked"
        && env.paths.proxy_tcp == "supported";
    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "ipv6": stats_json(&stats.ipv6),
        "dropped": stats.dropped,
        "direct_forwarded_delta": direct_forwarded_delta,
        "paths": env.paths.json(),
        "burst": 10,
    }))
}

/// AC10：6 类包 × 10 = 60 个；每类只命中各自维度的计数，通用 dropped 不增。
fn section_ac10() -> Result<Value, String> {
    let mut env = assemble("ac10", true)?;
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    env.dp.set_n1_sender(Arc::new(RecordingSender {
        frames,
        fail: false,
    }));

    let first_fragment = with_extension(v6_udp("fd00:144::7", b"frag"), 44, 17);
    let mut non_first_fragment = first_fragment.clone();
    non_first_fragment[42..44].copy_from_slice(&8u16.to_be_bytes()); // offset = 1

    // 1–4 + 6：每类 10 个包。
    for _ in 0..10 {
        // 1. 正常 UDP（Mesh）
        env.inject(v6_udp("fd00:144::6", b"udp"))?;
        // 2. 正常 TCP（Proxy）
        env.inject(v6_tcp("2001:db8::20"))?;
        // 3. ICMPv6（Proxy）
        env.inject(v6_proto("2001:db8::21", 58))?;
        // 4. 未知扩展头 ESP（Proxy；不解析 L4，按目的分类）
        env.inject(v6_proto("2001:db8::22", 50))?;
        // 6. 截断
        env.inject(truncated())?;
    }
    // 5. 分片：首片 + 非首片成对，5 对 = 10 个包（Mesh）。
    for _ in 0..5 {
        env.inject(first_fragment.clone())?;
        env.inject(non_first_fragment.clone())?;
    }

    let stats = env.dp.stats();
    let v6 = stats.ipv6;
    let ok = v6.packets == 60
        && v6.udp == 15 // 10 正常 UDP + 5 首片
        && v6.tcp == 10
        && v6.classified_mesh == 20 // 10 正常 UDP + 10 分片
        && v6.classified_direct == 0
        && v6.classified_proxy == 30 // TCP + ICMPv6 + ESP
        && v6.mesh_forwarded == 20
        && v6.mesh_no_route == 0
        && v6.proxy_dropped == 30
        && v6.multicast == 0
        && v6.dropped_truncated == 10
        && v6.dropped_extension == 0
        && v6.fragments == 10
        && stats.dropped == 0;
    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "ipv6": stats_json(&v6),
        "dropped": stats.dropped,
        "classes": {
            "udp_mesh": 10,
            "tcp_proxy": 10,
            "icmpv6_proxy": 10,
            "esp_proxy": 10,
            "fragment_mesh": 10,
            "truncated": 10,
            "packets": 60,
        },
    }))
}

/// AC16：能力表（无 routes6 → unsupported；有 → supported）与 `/dataplane/stats` 暴露。
fn section_ac16() -> Result<Value, String> {
    let without = assemble("ac16no", false)?;
    let with = assemble("ac16yes", true)?;

    // 生产读口：发布能力表后从 dataplane_stats_json 读回。
    nexusd::dataplane::publish_runtime_basics("system-level", with.paths);
    let json = nexusd::dataplane::dataplane_stats_json(
        true,
        &nexusd::dataplane::runtime_status_snapshot(),
        &with.dp.stats(),
        serde_json::json!({}),
    );

    let ok = without.paths.mesh == "unsupported"
        && with.paths.mesh == "supported"
        && with.paths.direct == "supported"
        && with.paths.proxy_tcp == "supported"
        && with.paths.proxy_udp == "blocked"
        && with.paths.tun_address == "unassigned"
        && with.paths.nat == "unsupported"
        && json["ipv6_paths"]["mesh"] == "supported"
        && json["ipv6_paths"]["nat"] == "unsupported"
        && json["ingress_ip_family"] == "dual-stack";
    Ok(json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "without_routes6": without.paths.json(),
        "with_routes6": with.paths.json(),
        "stats": {
            "ipv6_paths": json["ipv6_paths"],
            "ingress_ip_family": json["ingress_ip_family"],
        },
    }))
}

fn run_section(name: &str) -> Result<Value, String> {
    match name {
        "ac6" => section_ac6(),
        "ac6_no_route" => section_ac6_no_route(),
        "ac6_no_routes6" => section_ac6_no_routes6(),
        "ac7" => section_ac7(),
        "ac10" => section_ac10(),
        "ac16" => section_ac16(),
        other => Err(format!("unknown section: {other}")),
    }
}

// ===== 日志捕获（AC7/AC10 的限流断言） =====

/// 统计 `[nexusd] ipv6` 日志行：事件总数、每 `(event, 判别字段)` 的最大行数。
fn analyze_logs(stderr: &str) -> Value {
    let mut by_event: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_key: BTreeMap<String, u64> = BTreeMap::new();
    let mut samples: Vec<String> = Vec::new();
    for line in stderr.lines() {
        if !line.contains("[nexusd] ipv6") {
            continue;
        }
        let event = line
            .split("event=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("unknown")
            .to_string();
        let discriminator = ["proto=", "hdr=", "path="]
            .iter()
            .find_map(|field| {
                line.split(field)
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .map(|value| format!("{field}{value}"))
            })
            .unwrap_or_else(|| "-".to_string());
        *by_event.entry(event.clone()).or_insert(0) += 1;
        *by_key
            .entry(format!("{event}|{discriminator}"))
            .or_insert(0) += 1;
        if samples.len() < 4 {
            samples.push(line.trim().to_string());
        }
    }
    let max_per_event_key = by_key.values().copied().max().unwrap_or(0);
    json!({
        "lines_total": by_event.values().sum::<u64>(),
        "by_event": by_event,
        "by_event_key": by_key,
        "max_per_event_key": max_per_event_key,
        "samples": samples,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") {
        let section = args
            .iter()
            .position(|a| a == "--section")
            .and_then(|idx| args.get(idx + 1))
            .cloned()
            .unwrap_or_else(|| "ac6".to_string());
        let output = match run_section(&section) {
            Ok(value) => value,
            Err(e) => json!({"verdict": "FAIL", "error": e}),
        };
        println!("{}", serde_json::to_string(&output).unwrap());
        return;
    }

    let exe = std::env::current_exe().expect("current exe");
    let mut sections = serde_json::Map::new();
    let mut ok = true;
    for name in [
        "ac6",
        "ac6_no_route",
        "ac6_no_routes6",
        "ac7",
        "ac10",
        "ac16",
    ] {
        let output = Command::new(&exe)
            .args(["--child", "--section", name])
            .stdin(Stdio::null())
            .output();
        let (mut value, logs) = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                let parsed: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
                    json!({"verdict": "FAIL", "error": format!("child JSON: {e}; stderr: {stderr}")})
                });
                (parsed, analyze_logs(&stderr))
            }
            Err(e) => (
                json!({"verdict": "FAIL", "error": format!("spawn child: {e}")}),
                json!({"lines_total": 0, "max_per_event_key": 0}),
            ),
        };
        if value["verdict"] != "PASS" {
            ok = false;
        }
        if let Value::Object(ref mut map) = value {
            map.insert("log".to_string(), logs);
        }
        sections.insert(name.to_string(), value);
    }

    let output = json!({
        "verdict": if ok { "PASS" } else { "FAIL" },
        "sections": Value::Object(sections),
    });
    println!("{}", serde_json::to_string(&output).unwrap());
}
