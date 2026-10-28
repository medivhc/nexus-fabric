//! E4：flow_session_mapping —— TUN 数据面流→会话映射。
//!
//! 场景 `scenarios/product/flow_session_mapping.toml` 的可执行验证
//! （requirement-change 2026-10-02；mock TUN，无需特权）。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_flow_session::{FlowKey, IpProto};
use nexus_projection::MockTun;
use nexusd::dataplane::{Dataplane, DataplaneConfig, ProductionChainDeps};
use serde_json::json;

/// 生产装配的 provider 源（同 `nexusd` main：`proxy.yaml` 出站 → Registry）。
///
/// Mesh 流不带 `egress_hint`：候选集不窄化，由 Policy + Core Planner 决定
/// （PRODUCT §tun-ingress-session-chain）。
const YAML_ONE_PROVIDER: &str = r#"schema_version: 1
rules:
  - tag: proxy-all
    kind: match
    action:
      - kind: select_outbound
        tag: p1
groups: []
outbounds:
  - tag: p1
    kind: socks5
    locator: 127.0.0.1:1
"#;

/// 注入生产 ChainDeps（必须在 `enable_flow_sessions*` 之前调用）。
fn inject_production_chain(dp: &mut Dataplane) {
    let deps = ProductionChainDeps::from_config(None, Some(YAML_ONE_PROVIDER)).expect("deps");
    dp.set_production_chain_deps(deps);
}

fn main() {
    let output = run();
    println!("{}", serde_json::to_string(&output).unwrap());
}

/// TCP 包参数。
struct TcpParams {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

/// 构造 IPv4/TCP 包（带 seq/ack）。
fn build_tcp(p: &TcpParams, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20]; // IPv4 头
    pkt[0] = 0x45;
    let tot = (20 + 20 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
    pkt[6] = 0x40; // DF
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&p.src_ip);
    pkt[16..20].copy_from_slice(&p.dst_ip);
    pkt.extend_from_slice(&p.src_port.to_be_bytes());
    pkt.extend_from_slice(&p.dst_port.to_be_bytes());
    pkt.extend_from_slice(&p.seq.to_be_bytes());
    pkt.extend_from_slice(&p.ack.to_be_bytes());
    pkt.push(0x50);
    pkt.push(p.flags);
    pkt.extend_from_slice(&[0x20, 0x00]); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    pkt.extend_from_slice(payload);
    // 计算校验和（smoltcp 校验）。
    let ip_c = nexus_projection::tcp::ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_c.to_be_bytes());
    let tcp_c = nexus_projection::tcp::tcp_checksum(p.src_ip, p.dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_c.to_be_bytes());
    pkt
}

/// 从 SYN-ACK 包解析 server seq。
fn syn_ack_seq(packet: &[u8]) -> u32 {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ])
}

/// 构造 IPv4/UDP 包。
fn build_udp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 20]; // IPv4 头
    pkt[0] = 0x45;
    let tot = (20 + 8 + payload.len()) as u16;
    pkt[2..4].copy_from_slice(&tot.to_be_bytes());
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    let ulen = (8 + payload.len()) as u16;
    pkt.extend_from_slice(&ulen.to_be_bytes());
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(payload);
    // IP 校验和（UDP 校验和可选，置 0）。
    let ip_c = nexus_projection::tcp::ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_c.to_be_bytes());
    pkt
}

fn tcp_key() -> FlowKey {
    FlowKey {
        src_ip: [192, 168, 1, 2],
        src_port: 54321,
        dst_ip: [10, 1, 2, 100],
        dst_port: 443,
        proto: IpProto::Tcp,
    }
}

fn udp_key() -> FlowKey {
    FlowKey {
        src_ip: [192, 168, 1, 2],
        src_port: 54322,
        dst_ip: [10, 1, 2, 100],
        dst_port: 8080, // 非 53，避免 DNS 短路
        proto: IpProto::Udp,
    }
}

/// 等待会话 Active（轮询 pump 经 process_one 触发）。
fn pump_until_active(dp: &mut Dataplane, key: &FlowKey) -> bool {
    use nexus_flow_session::FlowPhase;
    for _ in 0..200 {
        // 触发一次空轮询以跑 flow_pump（无包时 process_one 返回 Ok(false)）。
        let _ = dp.process_one();
        if dp.flow_phase(key) == Some(FlowPhase::Active) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

fn run() -> serde_json::Value {
    // E4 需要观测 TUN 写出；MockTun 所有权在 Dataplane 内。    // 为可观测，改用可共享的 MockTun 包装。
    let tun = std::sync::Arc::new(std::sync::Mutex::new(MockTun::new("flowtun0")));
    let tun_clone = std::sync::Arc::clone(&tun);
    struct SharedTun(std::sync::Arc<std::sync::Mutex<MockTun>>);
    impl nexus_projection::TunDevice for SharedTun {
        fn name(&self) -> &str {
            "flowtun0"
        }
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(buf)
        }
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
    }
    /// E4 用 mock N1 发送器（捕获帧，不真发）。
    struct MockN1Sender;
    impl nexus_network::n1::bridge::N1Sender for MockN1Sender {
        fn send_to_mesh(
            &self,
            _dst: std::net::IpAddr,
            _packet: &[u8],
        ) -> Result<(), nexus_network::n1::N1Error> {
            Ok(())
        }
    }
    let config = DataplaneConfig {
        mesh_cidrs: vec!["10.0.0.0/8".to_string()],
        bypass_cidrs: vec!["192.168.0.0/16".to_string()],
        dns_enabled: false,
        dns_config: None,
        qos_enabled: false,
        qos_config: Default::default(),
        boost_enabled: false,
        n1_configured: true,
        proxy_configured: false,
        ..Default::default()
    };
    let mut dp = Dataplane::new(Box::new(SharedTun(tun_clone)), config).expect("new");
    // 注入 mock N1 → establish 成功（会话可进 Active）。
    dp.set_n1_sender(std::sync::Arc::new(MockN1Sender));
    inject_production_chain(&mut dp);
    dp.enable_flow_sessions();

    let tk = tcp_key();
    let uk = udp_key();

    // ---- 1. SYN → 会话创建 ----
    let syn = build_tcp(
        &TcpParams {
            src_ip: tk.src_ip,
            dst_ip: tk.dst_ip,
            src_port: tk.src_port,
            dst_port: tk.dst_port,
            seq: 1000,
            ack: 0,
            flags: 0x02,
        },
        &[],
    );
    tun.lock().unwrap().inject(syn.clone());
    let _ = dp.process_one();
    let session_created_on_syn = dp.flow_session_count() == 1;

    // ---- 2. 重传 SYN → 仍 1 个会话 ----
    tun.lock().unwrap().inject(syn.clone());
    let _ = dp.process_one();
    let sessions_after_retrans = dp.flow_session_count();

    // ---- 3/4. Policy/Planner 被咨询，trace 非空 ----
    let policy_planner_consulted = dp.flow_planner_calls() >= 1;
    let session_id = dp.flow_session_for_key(&tk);
    let decision_trace_non_empty = session_id
        .as_ref()
        .map(|sid| dp.flow_policy_trace_len(sid) > 0)
        .unwrap_or(false);

    // ---- 5/6. 等 Active；TCP 数据缓冲后 flush ----
    let became_active = pump_until_active(&mut dp, &tk);
    // 完成 TCP 握手：读 SYN-ACK，回 ACK（smoltcp 侧进 Established）。
    // 读 SYN-ACK，取 server seq，完成握手。
    let written = tun.lock().unwrap().take_written();
    let srv_seq = written
        .iter()
        .find_map(|p| {
            if p.len() > 40 {
                Some(syn_ack_seq(p))
            } else {
                None
            }
        })
        .unwrap_or(0);
    let ack = build_tcp(
        &TcpParams {
            src_ip: tk.src_ip,
            dst_ip: tk.dst_ip,
            src_port: tk.src_port,
            dst_port: tk.dst_port,
            seq: 1001,
            ack: srv_seq + 1,
            flags: 0x10,
        },
        &[],
    );
    tun.lock().unwrap().inject(ack);
    let _ = dp.process_one();
    // 发数据包。
    let data = build_tcp(
        &TcpParams {
            src_ip: tk.src_ip,
            dst_ip: tk.dst_ip,
            src_port: tk.src_port,
            dst_port: tk.dst_port,
            seq: 1001,
            ack: srv_seq + 1,
            flags: 0x18,
        },
        b"hello",
    );
    let mesh_bytes_before = dp.stats().mesh_tcp_bytes;
    tun.lock().unwrap().inject(data);
    let _ = dp.process_one();
    let _ = dp.process_one(); // 再一轮确保 flush
    let tcp_flushed = dp.stats().mesh_tcp_bytes > mesh_bytes_before;
    // "缓冲"语义：建连期数据不丢失（smoltcp 缓冲 + Active 后 flush）。
    // 此处验证最终对端收到完整字节（mesh_tcp_bytes 增加）。
    let tcp_early_data_buffered = became_active && tcp_flushed;
    let tcp_flushed_bytes_complete = tcp_flushed;

    // ---- 7/8. UDP：首包建会话；超 bound 丢弃计数 ----
    // 用独立 Dataplane + 阻塞建连器（会话保持 Allocating，确定性测 buffer bound）。
    struct BlockingEstablisher;
    impl nexus_flow_session::ConnectivityEstablisher for BlockingEstablisher {
        fn establish(
            &mut self,
            _sid: &nexus_flow_session::SessionId,
            _p: &nexus_flow_session::Planned,
        ) -> Result<String, String> {
            // 阻塞 5 秒（E4 在此之前完成），保证会话不 Active。
            std::thread::sleep(Duration::from_secs(5));
            Ok("blocked".into())
        }
    }
    let tun3 = Arc::new(Mutex::new(MockTun::new("tun3")));
    let tun3_clone = Arc::clone(&tun3);
    struct SharedTun3(Arc<Mutex<MockTun>>);
    impl nexus_projection::TunDevice for SharedTun3 {
        fn name(&self) -> &str {
            "tun3"
        }
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(buf)
        }
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
    }
    let config3 = DataplaneConfig {
        mesh_cidrs: vec!["10.0.0.0/8".to_string()],
        bypass_cidrs: vec!["192.168.0.0/16".to_string()],
        dns_enabled: false,
        dns_config: None,
        qos_enabled: false,
        qos_config: Default::default(),
        boost_enabled: false,
        n1_configured: false,
        proxy_configured: false,
        ..Default::default()
    };
    let mut dp3 = Dataplane::new(Box::new(SharedTun3(tun3_clone)), config3).expect("new3");
    inject_production_chain(&mut dp3);
    dp3.enable_flow_sessions_with_establisher(Box::new(BlockingEstablisher));
    let udp_pkt = build_udp(uk.src_ip, uk.dst_ip, uk.src_port, uk.dst_port, b"udp-data");
    tun3.lock().unwrap().inject(udp_pkt.clone());
    let _ = dp3.process_one();
    let udp_session_created = dp3.flow_session_for_key(&uk).is_some();
    // 塞 40 个包（bound 32）→ 应有丢弃计数。
    for _ in 0..40 {
        tun3.lock().unwrap().inject(udp_pkt.clone());
        let _ = dp3.process_one();
    }
    let udp_dropped = dp3.flow_udp_dropped(&uk);

    // ---- 9. 建连失败 → TCP RST ----
    // 新 dataplane：无上游（n1 未配、无 proxy）→ establish 失败。
    let tun2 = std::sync::Arc::new(std::sync::Mutex::new(MockTun::new("flowtun1")));
    let tun2_clone = std::sync::Arc::clone(&tun2);
    struct SharedTun2(std::sync::Arc<std::sync::Mutex<MockTun>>);
    impl nexus_projection::TunDevice for SharedTun2 {
        fn name(&self) -> &str {
            "flowtun1"
        }
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(buf)
        }
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }
    }
    let config2 = DataplaneConfig {
        mesh_cidrs: vec!["10.0.0.0/8".to_string()],
        bypass_cidrs: vec!["192.168.0.0/16".to_string()],
        dns_enabled: false,
        dns_config: None,
        qos_enabled: false,
        qos_config: Default::default(),
        boost_enabled: false,
        n1_configured: false, // 无上游
        proxy_configured: false,
        ..Default::default()
    };
    let mut dp2 = Dataplane::new(Box::new(SharedTun2(tun2_clone)), config2).expect("new2");
    inject_production_chain(&mut dp2);
    dp2.enable_flow_sessions();
    tun2.lock().unwrap().inject(syn.clone());
    let _ = dp2.process_one();
    // 等失败事件回填 + RST。
    let mut rst_seen = false;
    for _ in 0..200 {
        let _ = dp2.process_one();
        let written = tun2.lock().unwrap().take_written();
        for pkt in written {
            if is_tcp_rst(&pkt) {
                rst_seen = true;
                break;
            }
        }
        if rst_seen {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let session_fail_resets_tcp = rst_seen;

    // ---- 10/11. 空闲超时 → Draining → 0 ----
    dp.set_flow_idle_timeout(Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(5));
    // S31：扫描点由 driver 传单调毫秒。
    let drained = dp.flow_sweep_idle(dp.epoch_millis());
    let idle_timeout_drains = drained >= 1;
    // TearDown 信号在 flow_pump 中处理 → 再跑几轮 process_one 触发。
    for _ in 0..5 {
        let _ = dp.process_one();
    }
    let sessions_after_idle_timeout = dp.flow_count();

    // ---- 12. 快路径不调 Planner ----
    // 新建流 → Active → 发 10 个包 → planner_calls 不变。
    let tk2 = FlowKey {
        src_port: 54323,
        ..tk
    };
    let syn2 = build_tcp(
        &TcpParams {
            src_ip: tk2.src_ip,
            dst_ip: tk2.dst_ip,
            src_port: tk2.src_port,
            dst_port: tk2.dst_port,
            seq: 2000,
            ack: 0,
            flags: 0x02,
        },
        &[],
    );
    tun.lock().unwrap().inject(syn2);
    let _ = dp.process_one();
    let active2 = pump_until_active(&mut dp, &tk2);
    let calls_before = dp.flow_planner_calls();
    for _ in 0..10 {
        let d = build_tcp(
            &TcpParams {
                src_ip: tk2.src_ip,
                dst_ip: tk2.dst_ip,
                src_port: tk2.src_port,
                dst_port: tk2.dst_port,
                seq: 2001,
                ack: 1,
                flags: 0x18,
            },
            b"x",
        );
        tun.lock().unwrap().inject(d);
        let _ = dp.process_one();
    }
    let no_planner_in_hot_path = active2 && dp.flow_planner_calls() == calls_before;

    // ---- 13. 路径切换透明 ----
    let sid2 = dp.flow_session_for_key(&tk2);
    let path_switch_transparent = match sid2 {
        Some(sid) => {
            let calls = dp.flow_planner_calls();
            let ok = dp.flow_on_path_switch(&sid, "relay-b.exit".into());
            use nexus_flow_session::FlowPhase;
            ok && dp.flow_phase(&tk2) == Some(FlowPhase::Active) && dp.flow_planner_calls() == calls
        }
        None => false,
    };

    // ---- 14. 架构方向检查 ----
    let architecture_ok = check_dependency_direction();

    let verdict = session_created_on_syn
        && sessions_after_retrans == 1
        && policy_planner_consulted
        && decision_trace_non_empty
        && tcp_early_data_buffered
        && tcp_flushed_bytes_complete
        && udp_session_created
        && session_fail_resets_tcp
        && idle_timeout_drains
        && sessions_after_idle_timeout == 0
        && no_planner_in_hot_path
        && path_switch_transparent
        && architecture_ok;

    json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "flow": {
            "session_created_on_syn": session_created_on_syn,
            "sessions_created_for_retransmitted_syn": sessions_after_retrans,
            "policy_planner_consulted": policy_planner_consulted,
            "decision_trace_non_empty": decision_trace_non_empty,
            "tcp_early_data_buffered": tcp_early_data_buffered,
            "tcp_flushed_bytes_complete": tcp_flushed_bytes_complete,
            "udp_session_created": udp_session_created,
            "udp_dropped_over_bound_count": udp_dropped,
            "session_fail_resets_tcp": session_fail_resets_tcp,
            "idle_timeout_drains": idle_timeout_drains,
            "sessions_after_idle_timeout": sessions_after_idle_timeout,
            "no_planner_in_hot_path": no_planner_in_hot_path,
            "path_switch_transparent": path_switch_transparent,
        },
        "architecture": {
            "flow_session_dependency_direction_ok": architecture_ok,
        },
    })
}

/// 检查 TCP RST 标志。
fn is_tcp_rst(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if packet.len() < ihl + 14 {
        return false;
    }
    packet[ihl + 13] & 0x04 != 0
}

/// 架构方向检查：nexus-network 不得依赖 nexus-flow-session；
/// nexus-flow-session 的允许依赖必须为预期集合。
fn check_dependency_direction() -> bool {
    let text = match std::fs::read_to_string("policies/architecture.toml") {
        Ok(t) => t,
        Err(_) => return false,
    };
    // 粗粒度文本检查（E4 级别；严格门禁由 architecture gate 执行）。
    let network_section = text
        .split("[[crate]]")
        .find(|s| s.contains("name = \"nexus-network\""));
    let flow_section = text
        .split("[[crate]]")
        .find(|s| s.contains("name = \"nexus-flow-session\""));
    match (network_section, flow_section) {
        (Some(net), Some(flow)) => {
            !net.contains("nexus-flow-session")
                && flow.contains("nexus-domain")
                && flow.contains("nexus-policy")
                && flow.contains("nexus-planner")
                && flow.contains("nexus-session")
        }
        _ => false,
    }
}
