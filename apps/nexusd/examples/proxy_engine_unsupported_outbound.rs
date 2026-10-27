//! A11 + Q-2（E4）：非首个 wired 非法（启动可见 + 运行期结构化错误 + RST），
//! 以及 `NoUsableOutbound` 降级分支（daemon 存活、无 engine、Proxy 包按 D2 回 RST）。
//!
//! 三段：
//! 1. 真实 `nexusd` 子进程：两个 wired，第二个 trojan 未声明 TLS →
//!    启动 warn `engine=unsupported cause=PLAINTEXT_TROJAN_UNSUPPORTED`，daemon 存活；
//! 2. 装配级（MockTun + 真实 Dataplane）：规则选中坏 tag → 恰好一个 RST、无 SYN-ACK、
//!    不回退 direct（`direct_forwarded == 0`）；SUG-5：运行期结构化事件行
//!    `event=outbound_unavailable` 的内容（cause/kind/tag/`suppressed`）必须被断言。
//!    该行由 `eprintln!` 发到进程 stderr，进程内无法捕获 → 本 example 以隐藏参数
//!    `--runtime-invalid-child` 重执行自身，父进程读子进程 stderr 提取该行；
//! 3. Q-2 降级组：只有 direct 的配置 → daemon 存活且不输出启动失败 JSON，
//!    in-process 无 engine 的 Proxy SYN 仍回 RST（D2）。

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_projection::MockTun;
use nexus_proxy::domain_engine::DomainRuleEngine;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;
use serde_json::{Value, json};

const TWO_WIRED_YAML: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: ok
outbounds:
  - tag: ok
    kind: socks5
    locator: 127.0.0.1:9
  - tag: bad
    kind: trojan
    locator: 127.0.0.1:443
    password: secret
";

const DIRECT_ONLY_YAML: &str = "\
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: d
outbounds:
  - tag: d
    kind: direct
";

fn main() {
    // SUG-5：运行期用例的隐藏子进程模式（stderr 可被父进程捕获）。
    if std::env::args().any(|arg| arg == "--runtime-invalid-child") {
        let output = runtime_invalid_case();
        println!("{}", serde_json::to_string(&output).expect("json"));
        return;
    }
    let output = run();
    println!("{}", serde_json::to_string(&output).expect("json"));
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run() -> Value {
    let base = std::env::temp_dir().join(format!("nexusd-a11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);

    let startup = match nexusd_binary() {
        Ok(bin) => startup_warn_case(&bin, &base.join("two-wired"), TWO_WIRED_YAML),
        Err(error) => json!({"present": false, "error": error}),
    };
    let runtime = runtime_invalid_subprocess();
    let degraded = match nexusd_binary() {
        Ok(bin) => degrade_case(&bin, &base.join("direct-only"), DIRECT_ONLY_YAML),
        Err(error) => json!({"alive_without_engine": false, "error": error}),
    };

    let verdict = if startup["present"] == true
        && runtime["rst_count"] == 1
        && runtime["no_synack"] == true
        && runtime["direct_forwarded"] == 0
        && runtime["event_line_present"] == true
        && runtime["event_cause"] == "PLAINTEXT_TROJAN_UNSUPPORTED"
        && runtime["event_kind"] == "trojan"
        && runtime["event_tag"] == "bad"
        && degraded["alive_without_engine"] == true
        && degraded["no_startup_failure_json"] == true
        && degraded["proxy_rst_on_no_engine"] == true
    {
        "PASS"
    } else {
        "FAIL"
    };

    let _ = std::fs::remove_dir_all(&base);
    json!({
        "verdict": verdict,
        "startup_warn": startup,
        "runtime_invalid": runtime,
        "degraded": degraded,
    })
}

/// 1. 启动 warn：daemon 必须打印 `engine=unsupported` 且继续存活。
fn startup_warn_case(bin: &std::path::Path, dir: &std::path::Path, yaml: &str) -> Value {
    let mut child = match spawn_daemon(bin, dir, yaml) {
        Ok(child) => child,
        Err(error) => return json!({"present": false, "error": error}),
    };
    let stderr = child.stderr.take().expect("stderr");
    let collected = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&collected);
    let reader = std::thread::spawn(move || {
        let mut reader = stderr;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut guard) = sink.lock() {
                        guard.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });

    let needle = "engine=unsupported cause=PLAINTEXT_TROJAN_UNSUPPORTED";
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut seen = false;
    while Instant::now() < deadline {
        if collected
            .lock()
            .map(|g| g.contains(needle))
            .unwrap_or(false)
        {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let alive = matches!(child.try_wait(), Ok(None));
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    json!({"present": seen, "daemon_alive": alive})
}

/// 2. 运行期（父进程侧）：重执行自身 `--runtime-invalid-child`，捕获 stderr 中的
///    `event=outbound_unavailable` 结构化行并解析字段。
fn runtime_invalid_subprocess() -> Value {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => return json!({"error": format!("current_exe: {error}")}),
    };
    let mut child = match Command::new(exe)
        .arg("--runtime-invalid-child")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return json!({"error": format!("spawn child: {error}")}),
    };
    let stderr_pipe = child.stderr.take().expect("child stderr");
    let sink = Arc::new(Mutex::new(String::new()));
    let sink_handle = Arc::clone(&sink);
    let reader = std::thread::spawn(move || {
        let mut reader = stderr_pipe;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut guard) = sink_handle.lock() {
                        guard.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    let _ = child.wait();
    let _ = reader.join();
    let stderr = sink.lock().map(|g| g.clone()).unwrap_or_default();

    let child_json: Value = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .unwrap_or(Value::Null);
    let event = parse_unavailable_event(&stderr, "bad");
    json!({
        "rst_count": child_json["rst_count"],
        "no_synack": child_json["no_synack"],
        "direct_forwarded": child_json["direct_forwarded"],
        "proxy_dropped_no_proxy": child_json["proxy_dropped_no_proxy"],
        "event_line_present": event["present"],
        "event_cause": event["cause"],
        "event_kind": event["kind"],
        "event_tag": event["tag"],
        "event_suppressed": event["suppressed"],
    })
}

/// 从 stderr 提取 `event=outbound_unavailable` 行（首个匹配 tag 的行）的字段。
fn parse_unavailable_event(stderr: &str, expected_tag: &str) -> Value {
    for line in stderr.lines() {
        if !line.contains("event=outbound_unavailable") {
            continue;
        }
        let mut cause = Value::Null;
        let mut kind = Value::Null;
        let mut tag = Value::Null;
        let mut suppressed = Value::Null;
        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("cause=") {
                cause = json!(value);
            } else if let Some(value) = token.strip_prefix("kind=") {
                kind = json!(value);
            } else if let Some(value) = token.strip_prefix("tag=") {
                tag = json!(value);
            } else if let Some(value) = token.strip_prefix("suppressed=") {
                suppressed = value.parse::<u64>().map_or(Value::Null, |n| json!(n));
            }
        }
        if tag.as_str() != Some(expected_tag) {
            continue;
        }
        return json!({
            "present": true,
            "cause": cause,
            "kind": kind,
            "tag": tag,
            "suppressed": suppressed,
        });
    }
    json!({"present": false})
}

/// 2. 运行期：规则选中坏 tag → 单 RST、无 SYN-ACK、不回退 direct。
fn runtime_invalid_case() -> Value {
    let mock = Arc::new(Mutex::new(MockTun::new("a11x0")));
    struct Shared(Arc<Mutex<MockTun>>);
    impl nexus_projection::TunDevice for Shared {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(buf)
        }
        fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(packet)
        }
        fn name(&self) -> &str {
            "a11x0"
        }
    }
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".to_string()],
        proxy_configured: true,
        ..Default::default()
    };
    let mut dp = match Dataplane::new(Box::new(Shared(Arc::clone(&mock))), config) {
        Ok(dp) => dp,
        Err(error) => return json!({"error": format!("dataplane: {error}")}),
    };
    let rule_yaml = TWO_WIRED_YAML.replace(
        "        tag: ok\noutbounds:",
        "        tag: bad\noutbounds:",
    );
    dp.set_rule_engine(Box::new(
        DomainRuleEngine::from_yaml(&rule_yaml).expect("rule engine"),
    ));
    let engine = match ProxyEngine::new(Some(TWO_WIRED_YAML)) {
        Ok(Some(engine)) => engine,
        _ => return json!({"error": "engine not constructed"}),
    };
    dp.set_proxy_engine(engine);

    let syn = craft_syn([203, 0, 113, 10], 18080);
    mock.lock().unwrap().inject(syn);
    let _ = dp.tick(1);
    let written = mock.lock().unwrap().take_written();
    let rst_count = written
        .iter()
        .filter(|pkt| pkt.len() > 33 && pkt[33] & 0x04 != 0)
        .count();
    let synack = written
        .iter()
        .any(|pkt| pkt.len() > 33 && pkt[33] & 0x12 == 0x12);
    let stats = dp.stats();
    json!({
        "rst_count": rst_count,
        "no_synack": !synack,
        "direct_forwarded": stats.direct_forwarded,
        "proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
    })
}

/// 3. Q-2：只有 direct 的配置 → 降级（daemon 存活、无启动失败 JSON、Proxy SYN 仍 RST）。
fn degrade_case(bin: &std::path::Path, dir: &std::path::Path, yaml: &str) -> Value {
    let mut child = match spawn_daemon(bin, dir, yaml) {
        Ok(child) => child,
        Err(error) => {
            return json!({"alive_without_engine": false, "error": error});
        }
    };
    let stderr = child.stderr.take().expect("stderr");
    let collected = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&collected);
    let reader = std::thread::spawn(move || {
        let mut reader = stderr;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut guard) = sink.lock() {
                        guard.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
    std::thread::sleep(Duration::from_millis(1200));
    let alive = matches!(child.try_wait(), Ok(None));
    let text = collected.lock().map(|g| g.clone()).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    let no_usable = text.contains("ProxyEngine unavailable (NO_USABLE_OUTBOUND)");
    let startup_failure = text
        .lines()
        .any(|line| line.contains("\"stage\":\"proxy_engine_init\""));
    let proxy_rst = no_engine_rst_emitted();

    json!({
        "alive_without_engine": alive && no_usable,
        "no_startup_failure_json": !startup_failure,
        "proxy_rst_on_no_engine": proxy_rst,
    })
}

/// in-process：无 engine 的 Proxy SYN → 直接 RST（D2=C）。
fn no_engine_rst_emitted() -> bool {
    let mock = Arc::new(Mutex::new(MockTun::new("a11x1")));
    struct Shared(Arc<Mutex<MockTun>>);
    impl nexus_projection::TunDevice for Shared {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(buf)
        }
        fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(packet)
        }
        fn name(&self) -> &str {
            "a11x1"
        }
    }
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.200.0.0/24".to_string()],
        proxy_configured: true,
        ..Default::default()
    };
    let Ok(mut dp) = Dataplane::new(Box::new(Shared(Arc::clone(&mock))), config) else {
        return false;
    };
    // 规则指向 proxy 类出站（tag=ok），但不注入 engine → 必须走 D2 的 NoEngine RST。
    dp.set_rule_engine(Box::new(
        DomainRuleEngine::from_yaml(TWO_WIRED_YAML).expect("rule engine"),
    ));
    mock.lock()
        .unwrap()
        .inject(craft_syn([203, 0, 113, 10], 18080));
    let _ = dp.tick(1);
    mock.lock()
        .unwrap()
        .take_written()
        .iter()
        .any(|pkt| pkt.len() > 33 && pkt[33] & 0x04 != 0)
}

fn spawn_daemon(
    bin: &std::path::Path,
    dir: &std::path::Path,
    yaml: &str,
) -> Result<std::process::Child, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::write(dir.join("proxy.yaml"), yaml).map_err(|e| format!("write proxy: {e}"))?;
    // LocalAPI 端口随进程变化，避免与并行 run 的 18080 冲突。
    let port = 20000 + (std::process::id() % 20000) as u16;
    std::fs::write(
        dir.join("daemon.toml"),
        format!("localapi_addr = \"127.0.0.1:{port}\"\n"),
    )
    .map_err(|e| format!("write daemon.toml: {e}"))?;
    Command::new(bin)
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nexusd: {e}"))
}

fn craft_syn(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 200, 1, 2]);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x02;
    pkt
}

fn nexusd_binary() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    if let Some(debug_dir) = exe.parent().and_then(|p| p.parent()) {
        let candidate = debug_dir.join("nexusd");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("nexusd not found next to {exe:?}"))
}
