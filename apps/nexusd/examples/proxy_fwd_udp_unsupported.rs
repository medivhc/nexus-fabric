//! E4: TLS Trojan 作为 active outbound 时 UDP fail-closed。
//!
//! 场景 `scenarios/product/proxy_fwd_udp_unsupported.toml`：
//! - 生产 `Dataplane::process_one()` + MockTun（无真实 TUN 权限也可跑）；
//! - TLS Trojan 注入 2 个业务 UDP 包（VLESS / AnyTLS 的 UDP 已接线，见
//!   PRODUCT §11.18.1 与 `proxy_fwd_udp_vless_anytls`；requirement-change 2026-10-28）；
//! - 断言：包全部丢弃、`udp_unsupported` 与分协议计数 > 0、`udp_sent == 0`、
//!   限频日志抑制计数 > 0、无直连（`direct_forwarded == 0`）。
//! - Trojan 轮（MAJOR-5）：TLS Trojan 的 `udp_capability` 恒为
//!   `Unsupported{TlsVariantNotSupported}` → 落 `udp_unsupported_other`。
//! - Trojan 轮（SUG-2）：另取 MockTun 写侧（`take_written`），断言为空——
//!   「不伪造回包」从文档说法变成机器可判（`udp.trojan_tun_written == 0`）。

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_projection::{MockTun, TunDevice};
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;
use serde_json::json;

struct SharedTun(Arc<Mutex<MockTun>>);

impl TunDevice for SharedTun {
    fn name(&self) -> &str {
        "udp-unsupported-tun"
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
}

fn udp_packet(id: u16) -> Vec<u8> {
    let payload = format!("business-udp-{id}").into_bytes();
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    pkt[0] = 0x45;
    let total = (20 + 8 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
    pkt[16..20].copy_from_slice(&[203, 0, 113, 9]);
    pkt[20..22].copy_from_slice(&(40000 + id).to_be_bytes());
    pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[28..].copy_from_slice(&payload);
    pkt
}

fn proxy_yaml(kind: &str) -> String {
    let outbound = match kind {
        // TLS Trojan：`skip_cert_verify` 字段出现即 TLS 声明（不是明文 Trojan）。
        "trojan" => {
            "  - tag: proxy\n    kind: trojan\n    locator: 127.0.0.1:18445\n    password: e4-password\n    skip_cert_verify: true\n"
        }
        other => panic!("unexpected kind {other}"),
    };
    format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: proxy\noutbounds:\n{outbound}"
    )
}

struct Phase {
    unsupported: u64,
    sent: u64,
    dropped_no_proxy: u64,
    direct_forwarded: u64,
    log_suppressed: u64,
    unsupported_other: u64,
    active_kind: String,
    /// MockTun 写侧（us → OS）包数：Trojan 轮必须为 0（不伪造回包）。
    tun_written_packets: usize,
}

fn run_phase(kind: &str) -> Result<Phase, String> {
    let mock = Arc::new(Mutex::new(MockTun::new("udp0")));
    let config = DataplaneConfig {
        mesh_cidrs: Vec::new(),
        bypass_cidrs: Vec::new(),
        proxy_configured: true,
        ..Default::default()
    };
    let mut dataplane = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config, None)
        .map_err(|error| format!("dataplane init: {error}"))?;
    let yaml_for_dp = proxy_yaml(kind);
    let engine = match ProxyEngine::new(Some(&yaml_for_dp)) {
        Ok(Some(engine)) => engine,
        Ok(None) => return Err("engine is None".to_string()),
        Err(error) => return Err(format!("engine init: {}", error.variant())),
    };
    let active_kind = match engine.registry().selected_tag() {
        Some(tag) => engine
            .registry()
            .dialer(tag)
            .map(|d| d.kind())
            .unwrap_or(nexus_proxy_config::OutboundKind::Socks5),
        None => nexus_proxy_config::OutboundKind::Socks5,
    };
    dataplane.set_proxy_engine(engine);
    // 生产装配同源：显式规则引擎（否则 fail-closed 判 Drop，UDP 不会进 Proxy 分支）。
    dataplane.set_rule_engine(Box::new(
        nexus_proxy::domain_engine::DomainRuleEngine::from_yaml(&yaml_for_dp)
            .expect("dataplane rule engine"),
    ));

    for id in 0..2u16 {
        mock.lock().unwrap().inject(udp_packet(id));
        let _ = dataplane.tick(now_ticks());
    }
    // 排水若干轮，保证计数/日志路径走完。
    for _ in 0..5 {
        let _ = dataplane.tick(now_ticks());
        std::thread::sleep(Duration::from_millis(1));
    }

    // stats 同步点在 tick 头部（poll 之后）：再泵一次让 udp_send_failed 增量落账。
    let _ = dataplane.tick(now_ticks());
    // 写侧观测（SUG-2）：排空 MockTun 的 us→OS 队列。Trojan 轮必须为空。
    let tun_written_packets = mock.lock().unwrap().take_written().len();
    let proxy = dataplane
        .proxy_stats()
        .ok_or_else(|| "proxy stats missing".to_string())?;
    let stats = dataplane.stats();
    Ok(Phase {
        unsupported: proxy.udp_unsupported,
        sent: proxy.udp_sent,
        dropped_no_proxy: stats.proxy_dropped_no_proxy,
        direct_forwarded: stats.direct_forwarded,
        log_suppressed: proxy.udp_unsupported_log_suppressed,
        unsupported_other: proxy.udp_unsupported_other,
        active_kind: active_kind.as_str().to_string(),
        tun_written_packets,
    })
}

fn main() {
    let trojan = match run_phase("trojan") {
        Ok(phase) => phase,
        Err(error) => {
            println!("{}", json!({"verdict": "FAIL", "error": error}));
            std::process::exit(1);
        }
    };

    let verdict = trojan.unsupported >= 2
        && trojan.unsupported_other > 0
        && trojan.sent == 0
        && trojan.direct_forwarded == 0
        && trojan.dropped_no_proxy >= 2
        && trojan.log_suppressed >= 1
        && trojan.active_kind == "trojan"
        && trojan.tun_written_packets == 0;

    let output = json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "udp.unsupported": trojan.unsupported,
        "udp.unsupported_positive": trojan.unsupported > 0,
        "udp.unsupported_trojan": trojan.unsupported,
        "udp.unsupported_trojan_positive": trojan.unsupported > 0,
        "udp.unsupported_trojan_other": trojan.unsupported_other,
        "udp.unsupported_trojan_other_positive": trojan.unsupported_other > 0,
        "udp.sent": trojan.sent,
        "udp.direct_forwarded": trojan.direct_forwarded,
        "udp.log_suppressed": trojan.log_suppressed,
        "udp.log_suppressed_positive": trojan.log_suppressed > 0,
        "udp.trojan_tun_written": trojan.tun_written_packets,
        "proxy.dropped_no_proxy": trojan.dropped_no_proxy,
        "outbound.trojan_kind": trojan.active_kind,
    });
    println!("{}", serde_json::to_string(&output).expect("json"));
    if !verdict {
        std::process::exit(1);
    }
}

/// 单调毫秒时间源（example 内允许直接用 std）。
fn now_ticks() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(std::time::Instant::now);
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}
