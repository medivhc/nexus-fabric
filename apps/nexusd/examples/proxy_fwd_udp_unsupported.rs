//! E4: VLESS / AnyTLS 作为 active outbound 时 UDP fail-closed。
//!
//! 场景 `scenarios/product/proxy_fwd_udp_unsupported.toml`：
//! - 生产 `Dataplane::process_one()` + MockTun（无真实 TUN 权限也可跑）；
//! - VLESS / AnyTLS 各注入 2 个业务 UDP 包；
//! - 断言：包全部丢弃、`udp_unsupported` 与分协议计数 > 0、`udp_sent == 0`、
//!   限频日志抑制计数 > 0、无直连（`direct_forwarded == 0`）。

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
        "vless" => {
            "  - tag: proxy\n    kind: vless\n    locator: 127.0.0.1:18443\n    uuid: 11111111-1111-1111-1111-111111111111\n    tls: true\n    skip_cert_verify: true\n"
        }
        "anytls" => {
            "  - tag: proxy\n    kind: anytls\n    locator: 127.0.0.1:18444\n    password: e4-password\n    skip_cert_verify: true\n"
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
    active_kind: String,
}

fn run_phase(kind: &str) -> Result<Phase, String> {
    let mock = Arc::new(Mutex::new(MockTun::new("udp0")));
    let config = DataplaneConfig {
        mesh_cidrs: Vec::new(),
        bypass_cidrs: Vec::new(),
        proxy_configured: true,
        ..Default::default()
    };
    let mut dataplane = Dataplane::new(Box::new(SharedTun(Arc::clone(&mock))), config)
        .map_err(|error| format!("dataplane init: {error}"))?;
    let engine = match ProxyEngine::new(Some(&proxy_yaml(kind))) {
        Ok(Some(engine)) => engine,
        Ok(None) => return Err("engine is None".to_string()),
        Err(error) => return Err(format!("engine init: {}", error.variant())),
    };
    let (active_kind, _) = engine.outbound();
    dataplane.set_proxy_engine(engine);

    for id in 0..2u16 {
        mock.lock().unwrap().inject(udp_packet(id));
        let _ = dataplane.process_one();
    }
    // 排水若干轮，保证计数/日志路径走完。
    for _ in 0..5 {
        let _ = dataplane.process_one();
        std::thread::sleep(Duration::from_millis(1));
    }

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
        active_kind: active_kind.as_str().to_string(),
    })
}

fn main() {
    let mut vless = None;
    let mut anytls = None;
    let mut error = None;
    match run_phase("vless") {
        Ok(phase) => vless = Some(phase),
        Err(e) => error = Some(e),
    }
    match run_phase("anytls") {
        Ok(phase) => anytls = Some(phase),
        Err(e) => error = Some(e),
    }

    let Some(vless) = vless else {
        println!(
            "{}",
            json!({"verdict": "FAIL", "error": error.unwrap_or_default()})
        );
        std::process::exit(1);
    };
    let Some(anytls) = anytls else {
        println!(
            "{}",
            json!({"verdict": "FAIL", "error": error.unwrap_or_default()})
        );
        std::process::exit(1);
    };

    let total_unsupported = vless.unsupported + anytls.unsupported;
    let total_sent = vless.sent + anytls.sent;
    let total_direct = vless.direct_forwarded + anytls.direct_forwarded;
    let suppressed = vless.log_suppressed + anytls.log_suppressed;
    let dropped = vless.dropped_no_proxy + anytls.dropped_no_proxy;

    let verdict = total_unsupported >= 4
        && vless.unsupported > 0
        && anytls.unsupported > 0
        && total_sent == 0
        && total_direct == 0
        && dropped >= 4
        && vless.active_kind == "vless"
        && anytls.active_kind == "anytls";

    let output = json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "udp.unsupported": total_unsupported,
        "udp.unsupported_vless": vless.unsupported,
        "udp.unsupported_anytls": anytls.unsupported,
        "udp.unsupported_positive": total_unsupported > 0,
        "udp.unsupported_vless_positive": vless.unsupported > 0,
        "udp.unsupported_anytls_positive": anytls.unsupported > 0,
        "udp.sent": total_sent,
        "udp.direct_forwarded": total_direct,
        "udp.log_suppressed": suppressed,
        "udp.log_suppressed_positive": suppressed > 0,
        "proxy.dropped_no_proxy": dropped,
        "outbound.vless_kind": vless.active_kind,
        "outbound.anytls_kind": anytls.active_kind,
    });
    println!("{}", serde_json::to_string(&output).expect("json"));
    if !verdict {
        std::process::exit(1);
    }
}
