//! QoS 启用路径 E4（生产装配）：`config::load` → `build_dataplane_config` → `Dataplane`。
//!
//! 场景 `scenarios/product/qos_cake_enabled_path.toml` 的可执行验证。
//! 禁止自证：本 example 不解析 TOML、不重实现 `[qos]` 映射，只走生产函数。

use std::net::Ipv4Addr;

use nexus_projection::MockTun;
use nexusd::assembly;
use nexusd::config::{self, ConfigDir};
use nexusd::dataplane::Dataplane;
use serde_json::json;

/// 注入包数（1000 × 1400 B = 1.4 MB ≫ burst 125000 B，保证出现真实整形丢弃）。
const PACKETS: usize = 1000;
/// 单包总长（IPv4 头 20 + UDP 头 8 + 载荷 1372）。
const PACKET_BYTES: usize = 1400;

fn main() {
    println!("{}", serde_json::to_string(&run()).unwrap());
}

fn run() -> serde_json::Value {
    // 1. 临时 config dir：只写 daemon.toml（其余小节缺省即默认值）。
    let dir_path = std::env::temp_dir().join(format!("nexusd-qos-e4-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir_path) {
        return fail(&format!("create temp config dir: {e}"));
    }
    let daemon_toml = "[qos]\nenabled = true\nmesh_upload_mbps = 1\nproxy_upload_mbps = 0\nquantum = 1514\nhigh_priority_ports = \"22,53,3389\"\n";
    if let Err(e) = std::fs::write(dir_path.join("daemon.toml"), daemon_toml) {
        return fail(&format!("write daemon.toml: {e}"));
    }

    // 2. 生产解析（apps/nexusd/src/config.rs）。
    let dir = match ConfigDir::new(&dir_path) {
        Ok(d) => d,
        Err(e) => return fail(&format!("config dir: {e}")),
    };
    let loaded = match config::load(&dir) {
        Ok(l) => l,
        Err(e) => return fail(&format!("config::load: {e}")),
    };

    // 3. 生产装配（apps/nexusd/src/assembly.rs）。
    let cfg = match assembly::build_dataplane_config(&loaded) {
        Ok(c) => c,
        Err(e) => return fail(&format!("build_dataplane_config: {e}")),
    };

    // 4. Mock TUN：先 inject 再装箱（MockTun 无界）。
    let mut tun = MockTun::new("qos-e4");
    let payload = vec![0x41u8; PACKET_BYTES - 28];
    for _ in 0..PACKETS {
        tun.inject(build_udp_packet(
            Ipv4Addr::new(10, 1, 2, 3),
            40000,
            9999,
            &payload,
        ));
    }

    // 5. 生产数据面（apps/nexusd/src/dataplane.rs）。
    let mut dp = match Dataplane::new(Box::new(tun), cfg) {
        Ok(dp) => dp,
        Err(e) => return fail(&format!("Dataplane::new: {e}")),
    };
    for _ in 0..(PACKETS + 100) {
        if let Err(e) = dp.tick(now_ticks()) {
            return fail(&format!("tick: {e}"));
        }
    }

    let stats = dp.stats();
    // 5 个回显值取自生产解析结果（非本文件字面量）。
    let qos = &loaded.daemon.qos;
    let qos_bypassed = dp.qos_bypassed();
    let verdict = if !qos_bypassed && stats.qos_dropped > 0 {
        "PASS"
    } else {
        "FAIL"
    };

    json!({
        "verdict": verdict,
        "production": {
            "qos_enabled": !qos_bypassed,
            "qos_bypassed": qos_bypassed,
            "qos_dropped_positive": stats.qos_dropped > 0,
            "qos_dropped": stats.qos_dropped,
            "quantum": qos.quantum,
            "high_priority_ports": qos
                .high_priority_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            "mesh_upload_mbps": qos.mesh_upload_mbps,
        }
    })
}

fn fail(message: &str) -> serde_json::Value {
    json!({
        "verdict": "FAIL",
        "error": message,
    })
}

/// 构造最小 IPv4/UDP 包（含合法 UDP 头；UDP 校验和置零，测试桩不校验）。
fn build_udp_packet(dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // 版本 4，IHL 5
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[192, 168, 1, 100]); // src
    pkt[16..20].copy_from_slice(&dst.octets()); // dst
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// 单调毫秒时间源（example 内允许直接用 std）。
fn now_ticks() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(std::time::Instant::now);
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}
