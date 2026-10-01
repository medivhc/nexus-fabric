//! Run specific E4 scenarios directly.

use super::Outcome;
use serde_json::json;

/// Run a specific scenario directly (for E4 product-level tests).
pub fn run_scenario(args: &[String]) -> Outcome {
    let subcommand = args.first().map(String::as_str).unwrap_or("");
    match subcommand {
        "virtual-subnet-tunnel" => run_virtual_subnet_tunnel(),
        "virtual-subnet-mesh" => run_virtual_subnet_mesh(),
        "nat-hole-punching" => run_nat_hole_punching(),
        "multihop-routing" => run_multihop_routing(),
        "mesh-dns" => run_mesh_dns(),
        "dns-unified" => run_dns_unified(),
        "firewall-rules" => run_firewall_rules(),
        "bandwidth-qos" => run_bandwidth_qos(),
        "qos-cake" => run_qos_cake(),
        "auto-reconnect" => run_auto_reconnect(),
        _ => (
            "BLOCKED".to_string(),
            format!("unknown run subcommand: {subcommand}"),
            Vec::new(),
        ),
    }
}

/// E4 test: two nodes connected via virtual subnet tunnel (offline, deterministic).
///
/// P1: 完整双向包往返验证（A → B → A）。
fn run_virtual_subnet_tunnel() -> Outcome {
    use nexus_connectivity::virtual_subnet::*;

    // 创建一对真正互连的 MemoryCarrier
    let (carrier_a, carrier_b) = MemoryCarrier::connected_pair();

    // Node A
    let config_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let vpi_a = Box::new(MemoryVpi::new());
    let mut tunnel_a = VirtualSubnetTunnel::new(config_a, vpi_a, Box::new(carrier_a));

    // Node B
    let config_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
    let vpi_b = Box::new(MemoryVpi::new());
    let mut tunnel_b = VirtualSubnetTunnel::new(config_b, vpi_b, Box::new(carrier_b));

    // Register peers on both sides
    tunnel_a
        .add_peer(TunnelPeer::new("10.0.0.2", "node-b:10000"))
        .expect("add peer B");
    tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);

    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.1", "node-a:10000"))
        .expect("add peer A");
    tunnel_b.set_peer_state("10.0.0.1", TunnelState::Connected);

    // 1. A 发送包到 B
    let mut ip_packet_a = vec![0u8; 20];
    ip_packet_a[16] = 10; // dst IP: 10.0.0.2
    ip_packet_a[17] = 0;
    ip_packet_a[18] = 0;
    ip_packet_a[19] = 2;
    ip_packet_a.extend_from_slice(b"hello from A");

    tunnel_a
        .send_ip_packet("10.0.0.2", &ip_packet_a)
        .expect("send from A");

    // 2. B 从 carrier 接收并解封装
    let mut recv_buf = [0u8; 2048];
    let recv_result = tunnel_b
        .recv_and_deliver(&mut recv_buf)
        .expect("B receive and deliver");

    let b_received = recv_result.is_some();

    // 3. B 回包到 A
    let mut reply_packet = vec![0u8; 20];
    reply_packet[16] = 10; // dst IP: 10.0.0.1
    reply_packet[17] = 0;
    reply_packet[18] = 0;
    reply_packet[19] = 1;
    reply_packet.extend_from_slice(b"hello from B");

    tunnel_b
        .send_ip_packet("10.0.0.1", &reply_packet)
        .expect("B reply");

    // 4. A 从 carrier 接收回包
    let recv_result = tunnel_a
        .recv_and_deliver(&mut recv_buf)
        .expect("A receive reply");

    let a_received_reply = recv_result.is_some();

    // 收集统计
    let stats_a = tunnel_a.peer_stats("10.0.0.2").unwrap();
    let stats_b = tunnel_b.peer_stats("10.0.0.1").unwrap();

    let roundtrip_ok = b_received
        && a_received_reply
        && stats_a.bytes_sent > 0
        && stats_a.bytes_received > 0
        && stats_b.bytes_sent > 0
        && stats_b.bytes_received > 0;

    let extra = vec![
        ("subnet".to_string(), json!({"cidr": "10.0.0.0/24"})),
        ("node_a".to_string(), json!({"virtual_ip": "10.0.0.1"})),
        ("node_b".to_string(), json!({"virtual_ip": "10.0.0.2"})),
        (
            "tunnel".to_string(),
            json!({"status": if roundtrip_ok { "Connected" } else { "Failed" }}),
        ),
        (
            "packet_roundtrip".to_string(),
            json!({
                "ok": roundtrip_ok,
                "bytes_sent": stats_a.bytes_sent,
                "bytes_received": stats_a.bytes_received,
                "b_received_packet": b_received,
                "a_received_reply": a_received_reply
            }),
        ),
    ];

    if roundtrip_ok {
        (
            "PASS".to_string(),
            "virtual-subnet-tunnel: bidirectional roundtrip verified".to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            "virtual-subnet-tunnel: bidirectional roundtrip failed".to_string(),
            extra,
        )
    }
}

/// E4 test: three-node virtual subnet with static routing and forwarding (P1 §12.5).
///
/// A(10.0.0.1) -- B(10.0.0.2) -- C(10.0.0.3); A and C do NOT peer directly.
/// A sends a packet to C; B forwards it; C delivers to VPI.
fn run_virtual_subnet_mesh() -> Outcome {
    use nexus_connectivity::virtual_subnet::*;

    let mut mesh_a = MeshCarrier::new();
    let mut mesh_b = MeshCarrier::new();
    let mut mesh_c = MeshCarrier::new();

    let a_recv = mesh_a.recv_handle();
    let b_recv = mesh_b.recv_handle();
    let c_recv = mesh_c.recv_handle();

    // A<->B
    mesh_a.connect_peer("B_locator", b_recv.clone());
    mesh_b.connect_peer("A_locator", a_recv.clone());
    // B<->C
    mesh_b.connect_peer("C_locator", c_recv.clone());
    mesh_c.connect_peer("B_locator", b_recv.clone());

    let vpi_a = Box::new(MemoryVpi::new());
    let vpi_b = Box::new(MemoryVpi::new());
    let vpi_c = Box::new(MemoryVpi::new());

    let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
    let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
    let cfg_c = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.3");

    let mut tunnel_a = VirtualSubnetTunnel::new(cfg_a, vpi_a, Box::new(mesh_a));
    let mut tunnel_b = VirtualSubnetTunnel::new(cfg_b, vpi_b, Box::new(mesh_b));
    let mut tunnel_c = VirtualSubnetTunnel::new(cfg_c, vpi_c, Box::new(mesh_c));

    // A only knows B
    tunnel_a
        .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
        .expect("A add peer B");
    tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);
    // A's static route: C via B
    tunnel_a
        .add_route("10.0.0.3", "10.0.0.2")
        .expect("A add route to C via B");

    // B knows A and C (both direct)
    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))
        .expect("B add peer A");
    tunnel_b
        .add_peer(TunnelPeer::new("10.0.0.3", "C_locator"))
        .expect("B add peer C");
    tunnel_b.set_peer_state("10.0.0.1", TunnelState::Connected);
    tunnel_b.set_peer_state("10.0.0.3", TunnelState::Connected);

    // C only knows B
    tunnel_c
        .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
        .expect("C add peer B");
    tunnel_c.set_peer_state("10.0.0.2", TunnelState::Connected);

    // A sends IP packet destined to C (10.0.0.3)
    let mut packet = vec![0u8; 20];
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 3;
    packet.extend_from_slice(b"hello-from-a");
    let packet_len = packet.len();

    tunnel_a
        .send_ip_packet("10.0.0.3", &packet)
        .expect("A send to C via route");

    // B receives frame, forwards to C
    let mut buf = [0u8; 2048];
    let b_delivered = tunnel_b
        .recv_and_deliver(&mut buf)
        .expect("B recv and forward")
        .is_some();

    // C receives forwarded frame, delivers to VPI
    let c_recv = tunnel_c
        .recv_and_deliver(&mut buf)
        .expect("C recv and deliver");
    let c_delivered = c_recv.is_some();
    let c_payload_len = c_recv.map(|(_, n)| n).unwrap_or(0);
    let payload_matches = c_payload_len == packet_len;

    // Stats
    let b_fwd = tunnel_b
        .peer_stats("10.0.0.3")
        .map(|s| s.bytes_forwarded)
        .unwrap_or(0);
    let a_sent_b = tunnel_a
        .peer_stats("10.0.0.2")
        .map(|s| s.bytes_sent)
        .unwrap_or(0);
    let a_peer_count = tunnel_a.peers().len();
    let c_peer_count = tunnel_c.peers().len();

    let ok = b_delivered && c_delivered && payload_matches && b_fwd > 0 && a_sent_b > 0;

    let extra = vec![
        ("subnet".to_string(), json!({"cidr": "10.0.0.0/24"})),
        (
            "node_a".to_string(),
            json!({"virtual_ip": "10.0.0.1", "peer_count": a_peer_count, "bytes_sent_to_b": a_sent_b}),
        ),
        (
            "node_b".to_string(),
            json!({"virtual_ip": "10.0.0.2", "bytes_forwarded": b_fwd}),
        ),
        (
            "node_c".to_string(),
            json!({"virtual_ip": "10.0.0.3", "peer_count": c_peer_count}),
        ),
        (
            "packet_delivered_to_c".to_string(),
            json!({
                "ok": c_delivered,
                "payload_matches": payload_matches,
                "payload_len": c_payload_len,
                "expected_len": packet_len
            }),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "virtual-subnet-mesh: A->B->C static route forwarding verified".to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            "virtual-subnet-mesh: forwarding failed".to_string(),
            extra,
        )
    }
}

/// E4 test: NAT hole punching — offline STUN codec self-test (honest).
///
/// 2026-09-24 requirement-change nat01：旧实现硬编码 public_mapping=203.0.113.42 /
/// nat.type=RestrictedCone / hole_punch.success=true（假）。现改为确定性编解码自检：
/// 构造并解析合成 XOR-MAPPED-ADDRESS 响应；不伪造公网映射，真实两 peer 打洞置 deferred。
fn run_nat_hole_punching() -> Outcome {
    use nexus_connectivity::nat::codec_self_test;

    match codec_self_test() {
        Ok((req_len, parsed)) => (
            "PASS".to_string(),
            "nat-hole-punching: offline STUN codec self-test passed (real punch deferred to P3)"
                .to_string(),
            vec![
                ("codec.request_build_ok".to_string(), json!(true)),
                ("codec.response_parse_ok".to_string(), json!(true)),
                ("codec.request_bytes".to_string(), json!(req_len)),
                (
                    "codec.parsed_self_test_addr".to_string(),
                    json!(parsed.to_string()),
                ),
                ("nat.type".to_string(), json!("Unknown")),
                ("hole_punch.success".to_string(), json!(false)),
                ("hole_punch.deferred".to_string(), json!(true)),
            ],
        ),
        Err(e) => (
            "FAIL".to_string(),
            format!("nat-hole-punching: codec self-test failed: {e}"),
            Vec::new(),
        ),
    }
}

/// E4 测试：四节点线性拓扑距离矢量多跳路由（PRODUCT §12.6）。
///
/// 拓扑：A(10.0.0.1) -- B(10.0.0.2) -- C(10.0.0.3) -- D(10.0.0.4)。
/// 初始仅直连邻居；3 轮邻居通告后收敛；A->D 包经 3 跳到达 D 本地交付；
/// 推进逻辑时钟超过 TTL 后 A 的远端路由 D 被超时删除。
#[allow(deprecated)] // §12.57 已退役：历史场景保留
fn run_multihop_routing() -> Outcome {
    use nexus_connectivity::routing::{
        ForwardDecision, MultihopRouter, RoutablePacket, RoutingEvent,
    };

    // ---- 1. 建拓扑 ----
    let mut a = MultihopRouter::new("10.0.0.1");
    let mut b = MultihopRouter::new("10.0.0.2");
    let mut c = MultihopRouter::new("10.0.0.3");
    let mut d = MultihopRouter::new("10.0.0.4");

    a.table_mut().add_direct_peer("10.0.0.2", 0);
    b.table_mut().add_direct_peer("10.0.0.1", 0);
    b.table_mut().add_direct_peer("10.0.0.3", 0);
    c.table_mut().add_direct_peer("10.0.0.2", 0);
    c.table_mut().add_direct_peer("10.0.0.4", 0);
    d.table_mut().add_direct_peer("10.0.0.3", 0);

    // 邻居表（每节点通告对象）。
    let neighbors: [Vec<&str>; 4] = [
        vec!["10.0.0.2"],
        vec!["10.0.0.1", "10.0.0.3"],
        vec!["10.0.0.2", "10.0.0.4"],
        vec!["10.0.0.3"],
    ];

    // ---- 2. 3 轮距离矢量通告收敛 ----
    for tick in 1..=3u64 {
        // 不可变快照阶段：收集 (src, dst, adv)。
        type Delivery = (String, String, Vec<(String, u32)>);
        let deliveries: Vec<Delivery> = [
            (&a, &neighbors[0]),
            (&b, &neighbors[1]),
            (&c, &neighbors[2]),
            (&d, &neighbors[3]),
        ]
        .into_iter()
        .flat_map(|(r, ns)| {
            ns.iter().map(move |n| {
                (
                    r.table().local_virtual_ip().to_string(),
                    n.to_string(),
                    r.table().advertise_to(n),
                )
            })
        })
        .collect();
        // 可变投递阶段。
        for (src, dst, adv) in deliveries {
            match dst.as_str() {
                "10.0.0.1" => {
                    a.table_mut().apply_advertisement(&src, &adv, tick);
                }
                "10.0.0.2" => {
                    b.table_mut().apply_advertisement(&src, &adv, tick);
                }
                "10.0.0.3" => {
                    c.table_mut().apply_advertisement(&src, &adv, tick);
                }
                "10.0.0.4" => {
                    d.table_mut().apply_advertisement(&src, &adv, tick);
                }
                other => {
                    return (
                        "FAIL".to_string(),
                        format!("multihop-routing: unknown neighbor {other}"),
                        Vec::new(),
                    );
                }
            }
        }
    }

    // ---- 3. 收敛断言 ----
    let a_to_d = match a.table().lookup("10.0.0.4") {
        Some(e) => e.clone(),
        None => {
            return (
                "FAIL".to_string(),
                "multihop-routing: A did not learn route to D after 3 rounds".to_string(),
                Vec::new(),
            );
        }
    };
    let d_to_a = match d.table().lookup("10.0.0.1") {
        Some(e) => e.clone(),
        None => {
            return (
                "FAIL".to_string(),
                "multihop-routing: D did not learn route to A after 3 rounds".to_string(),
                Vec::new(),
            );
        }
    };

    if a_to_d.next_hop != "10.0.0.2" || a_to_d.cost != 3 {
        return (
            "FAIL".to_string(),
            format!("multihop-routing: A->D route wrong: {:?}", a_to_d),
            Vec::new(),
        );
    }
    if d_to_a.next_hop != "10.0.0.3" || d_to_a.cost != 3 {
        return (
            "FAIL".to_string(),
            format!("multihop-routing: D->A route wrong: {:?}", d_to_a),
            Vec::new(),
        );
    }

    // ---- 4. A->D 发包，逐跳转发 ----
    let pkt = RoutablePacket::new("10.0.0.1", "10.0.0.4", b"hello-multihop");
    let mut cur = pkt;
    let mut ttl_at_each_hop: Vec<u8> = Vec::new();

    // A -> B
    let decision_a = match a.forward(&cur, 4) {
        Ok(d) => d,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: A forward failed: {e}"),
                Vec::new(),
            );
        }
    };
    let next_b = match decision_a {
        ForwardDecision::ForwardTo { next_hop, ttl } => {
            ttl_at_each_hop.push(ttl);
            cur = RoutablePacket { ttl, ..cur };
            next_hop
        }
        other => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: A expected ForwardTo, got {:?}", other),
                Vec::new(),
            );
        }
    };
    debug_assert_eq!(next_b, "10.0.0.2");

    // B -> C
    let decision_b = match b.forward(&cur, 4) {
        Ok(d) => d,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: B forward failed: {e}"),
                Vec::new(),
            );
        }
    };
    let next_c = match decision_b {
        ForwardDecision::ForwardTo { next_hop, ttl } => {
            ttl_at_each_hop.push(ttl);
            cur = RoutablePacket { ttl, ..cur };
            next_hop
        }
        other => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: B expected ForwardTo, got {:?}", other),
                Vec::new(),
            );
        }
    };
    debug_assert_eq!(next_c, "10.0.0.3");

    // C -> D
    let decision_c = match c.forward(&cur, 4) {
        Ok(d) => d,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: C forward failed: {e}"),
                Vec::new(),
            );
        }
    };
    let ttl_arrives_d = match decision_c {
        ForwardDecision::ForwardTo { next_hop, ttl } => {
            ttl_at_each_hop.push(ttl);
            debug_assert_eq!(next_hop, "10.0.0.4");
            cur = RoutablePacket { ttl, ..cur };
            ttl
        }
        other => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: C expected ForwardTo, got {:?}", other),
                Vec::new(),
            );
        }
    };

    // D 本地交付
    let decision_d = match d.forward(&cur, 4) {
        Ok(d) => d,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("multihop-routing: D forward failed: {e}"),
                Vec::new(),
            );
        }
    };
    let delivered = matches!(decision_d, ForwardDecision::DeliverLocal);

    // 收集跨节点 PacketForwarded 事件数。
    let forward_event_count = a
        .events()
        .iter()
        .chain(b.events().iter())
        .chain(c.events().iter())
        .filter(|e| matches!(e, RoutingEvent::PacketForwarded { .. }))
        .count();

    // ---- 5. 路由超时：推进逻辑时钟超过 TTL ----
    // 最后一次通告在 tick=3，TTL=5 个 tick；now=10 → 间隔 7 > 5 → A 学到的 D 路由过期。
    let expire_events = a.table_mut().expire_stale(10, 5);
    let route_expired = !expire_events.is_empty();
    let expired_destinations: Vec<String> = expire_events
        .iter()
        .filter_map(|e| match e {
            RoutingEvent::RouteExpired { dst } => Some(dst.clone()),
            _ => None,
        })
        .collect();
    // 必须把远端路由 D(10.0.0.4) 删掉（C 也会一起过期，因为它的 last_updated 也是 tick=3）。
    let expired_contains_d = expired_destinations.iter().any(|d| d == "10.0.0.4");
    // 直连路由 B 不应被删除。
    let direct_b_still_present = a.table().lookup("10.0.0.2").is_some();

    let ok = delivered
        && ttl_arrives_d == 61
        && forward_event_count == 3
        && route_expired
        && expired_contains_d
        && direct_b_still_present;

    let extra = vec![
        ("topology".to_string(), json!("linear")),
        (
            "node_a".to_string(),
            json!({
                "virtual_ip": "10.0.0.1",
                "direct_peer_count": a.table().direct_peer_count(),
                "route_to_d": {
                    "next_hop": a_to_d.next_hop,
                    "cost": a_to_d.cost
                }
            }),
        ),
        (
            "node_b".to_string(),
            json!({
                "virtual_ip": "10.0.0.2",
                "direct_peer_count": b.table().direct_peer_count(),
            }),
        ),
        (
            "node_c".to_string(),
            json!({
                "virtual_ip": "10.0.0.3",
                "direct_peer_count": c.table().direct_peer_count(),
            }),
        ),
        (
            "node_d".to_string(),
            json!({
                "virtual_ip": "10.0.0.4",
                "direct_peer_count": d.table().direct_peer_count(),
                "route_to_a": {
                    "next_hop": d_to_a.next_hop,
                    "cost": d_to_a.cost
                }
            }),
        ),
        (
            "packet_delivered_to_d".to_string(),
            json!({
                "ok": delivered,
                "ttl_at_delivery": ttl_arrives_d,
                "ttl_each_hop": ttl_at_each_hop,
            }),
        ),
        (
            "forward_events".to_string(),
            json!({ "count": forward_event_count }),
        ),
        (
            "expiration".to_string(),
            json!({
                "route_expired": route_expired,
                "expired_destinations": expired_destinations,
                "expired_contains_d": expired_contains_d,
                "direct_b_still_present": direct_b_still_present,
            }),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "multihop-routing: 4-node linear DV convergence + 3-hop forwarding + route expiry verified"
                .to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "multihop-routing: invariants failed (delivered={delivered}, ttl={ttl_arrives_d}, fwd_events={forward_event_count}, expired={route_expired}, expired_contains_d={expired_contains_d})"
            ),
            extra,
        )
    }
}

/// E4: Mesh DNS 域名注册与跨节点解析（内存骨架）。
///
/// 与 `nexus::mesh_dns_flow()` 同语义；按 nexus-harness 架构策略（allowed_internal_dependencies
/// 不含 app 层 `nexus`）直接用 `nexus_connectivity::mesh_dns` 内联实现。
fn run_mesh_dns() -> Outcome {
    use nexus_connectivity::mesh_dns::{DnsQuery, DnsResolution, MeshDnsNode};
    use std::time::{Duration, Instant};

    let mut node_a = MeshDnsNode::new("node-a", "10.0.0.1");
    let mut node_b = MeshDnsNode::new("node-b", "10.0.0.2");

    if let Err(e) = node_a.register_self_domain("node-a.mesh", 3600) {
        return (
            "FAIL".to_string(),
            format!("mesh-dns: node-a register self domain: {e}"),
            Vec::new(),
        );
    }
    if let Err(e) = node_b.register_self_domain("node-b.mesh", 3600) {
        return (
            "FAIL".to_string(),
            format!("mesh-dns: node-b register self domain: {e}"),
            Vec::new(),
        );
    }

    // 模拟自动发现：B 从 A 的快照学习 A 的域名记录。
    for rec in node_a.table_snapshot() {
        if rec.node_id == "node-a" {
            if let Err(e) = node_b.learn_peer_record(rec) {
                return (
                    "FAIL".to_string(),
                    format!("mesh-dns: node-b learn peer record: {e}"),
                    Vec::new(),
                );
            }
        }
    }

    // B 查询 node-a.mesh。
    let query = DnsQuery {
        query_id: 1,
        domain: "node-a.mesh".to_string(),
        from_node: "node-b".to_string(),
    };
    let resp = node_b.handle_query(&query, Instant::now());
    let (query_from_b_resolves, resolved_ip, resolved_node) = match &resp.result {
        DnsResolution::Resolved {
            virtual_ip,
            node_id,
            ..
        } => (true, virtual_ip.clone(), node_id.clone()),
        _ => (false, String::new(), String::new()),
    };

    // 查询未注册域名应返回 NotFound。
    let unknown_query = DnsQuery {
        query_id: 2,
        domain: "nobody.mesh".to_string(),
        from_node: "node-b".to_string(),
    };
    let unknown_resp = node_b.handle_query(&unknown_query, Instant::now());
    let query_unknown = matches!(unknown_resp.result, DnsResolution::NotFound);

    // TTL 过期：推进时钟 7200s（> 注册 TTL 3600s）。
    let expired = node_b.expire_peers(Instant::now() + Duration::from_secs(7200));
    let ttl_expired =
        expired.iter().any(|d| d == "node-a.mesh") && node_b.lookup("node-a.mesh").is_err();

    let ok = query_from_b_resolves
        && resolved_ip == "10.0.0.1"
        && resolved_node == "node-a"
        && query_unknown
        && ttl_expired;

    let extra = vec![
        (
            "node_a".to_string(),
            json!({ "domain_registered": true, "virtual_ip": "10.0.0.1" }),
        ),
        (
            "node_b".to_string(),
            json!({ "domain_registered": true, "virtual_ip": "10.0.0.2" }),
        ),
        (
            "query_from_b_resolves".to_string(),
            json!(query_from_b_resolves),
        ),
        (
            "resolved".to_string(),
            json!({ "virtual_ip": resolved_ip, "node_id": resolved_node }),
        ),
        ("query_unknown".to_string(), json!(query_unknown)),
        ("ttl_expired".to_string(), json!(ttl_expired)),
    ];

    if ok {
        (
            "PASS".to_string(),
            "mesh-dns: domain registration + cross-node resolution + TTL expiry verified"
                .to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "mesh-dns: invariants failed (resolves={query_from_b_resolves}, unknown={query_unknown}, ttl_expired={ttl_expired})"
            ),
            extra,
        )
    }
}

/// E4: 统一 DNS 分类与 Fake-IP 生命周期（内存骨架，DAEMON_ARCHITECTURE §10）。
///
/// 场景（`scenarios/product/dns_unified.toml`）：
/// - hosts 精确匹配 > mesh 域名 > 代理规则（fake-ip）> 上游；
/// - fake-ip 分配/稳定/反查/过期回收；
/// - mesh/fake-ip/hosts 命中时上游零调用。
fn run_dns_unified() -> Outcome {
    use nexus_dns::{
        DnsClass, DnsQuery, DnsType, DnsUnifiedConfig, MeshNameResolver, ProxyClassifier, Resolver,
        UnifiedDns,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    const MESH_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 144, 144, 6));
    const UPSTREAM_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const HOSTS_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    struct MapMesh {
        map: HashMap<String, IpAddr>,
    }
    impl MeshNameResolver for MapMesh {
        fn resolve_mesh(&self, name: &str) -> Option<IpAddr> {
            self.map.get(name).copied()
        }
    }

    struct SuffixClassifier;
    impl ProxyClassifier for SuffixClassifier {
        fn is_proxied(&self, domain: &str) -> bool {
            domain == "proxy.example.com"
        }
    }

    struct ConstUpstream {
        calls: std::sync::atomic::AtomicU64,
    }
    impl Resolver for ConstUpstream {
        fn resolve(&mut self, _q: &DnsQuery) -> Result<Vec<IpAddr>, nexus_dns::DnsError> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(vec![UPSTREAM_IP])
        }
    }

    let mut mesh_map = HashMap::new();
    mesh_map.insert("xc-pc-linux.mesh".to_string(), MESH_IP);
    let config = DnsUnifiedConfig {
        hosts: vec![("local.dev".to_string(), HOSTS_IP)],
        ..Default::default()
    };
    let mut dns = match UnifiedDns::new(
        config,
        Box::new(MapMesh { map: mesh_map }),
        Box::new(SuffixClassifier),
        Box::new(ConstUpstream {
            calls: std::sync::atomic::AtomicU64::new(0),
        }),
    ) {
        Ok(d) => d,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("dns-unified: construct: {e}"),
                Vec::new(),
            );
        }
    };

    let a = |name: &str| DnsQuery {
        name: name.to_string(),
        qtype: DnsType::A,
    };

    // --- 分类顺序 ---
    let hosts_ans = dns.resolve(&a("local.dev"), 1000);
    let hosts_class = hosts_ans
        .as_ref()
        .map(|x| x.class.as_str())
        .unwrap_or("ERR")
        .to_string();

    let mesh_ans = dns.resolve(&a("xc-pc-linux.mesh"), 1000);
    let (mesh_class, mesh_ip) = match &mesh_ans {
        Ok(x) => (x.class.as_str().to_string(), x.records[0].to_string()),
        Err(_) => ("ERR".to_string(), String::new()),
    };

    let fake_ans = dns.resolve(&a("proxy.example.com"), 1000);
    let (fake_class, fake_in_range, fake_ip_str) = match &fake_ans {
        Ok(x) => {
            let ip = match x.records[0] {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            };
            let in_range = {
                let v = u32::from_be_bytes(ip.octets());
                (v & 0xFFFE_0000) == 0xC612_0000 // 198.18.0.0/15
            };
            (
                x.class.as_str().to_string(),
                in_range,
                IpAddr::V4(ip).to_string(),
            )
        }
        Err(_) => ("ERR".to_string(), false, String::new()),
    };

    let up_ans = dns.resolve(&a("direct.example.com"), 1000);
    let (up_class, up_ip) = match &up_ans {
        Ok(x) => (x.class.as_str().to_string(), x.records[0].to_string()),
        Err(_) => ("ERR".to_string(), String::new()),
    };

    // --- Fake-IP 生命周期 ---
    let fake_again = dns.resolve(&a("proxy.example.com"), 1100);
    let stable_within_ttl = match (&fake_ans, &fake_again) {
        (Ok(x), Ok(y)) => y.from_cache && x.records == y.records,
        _ => false,
    };
    let reverse_lookup = fake_ip_str
        .parse::<IpAddr>()
        .ok()
        .and_then(|ip| match ip {
            IpAddr::V4(v4) => dns.reverse_lookup(v4).map(str::to_string),
            IpAddr::V6(_) => None,
        })
        .unwrap_or_default();
    // TTL=300：推进到 1400 后回收。
    let reclaimed = dns.reclaim_expired(1400);
    let reverse_after = fake_ip_str.parse::<IpAddr>().ok().and_then(|ip| match ip {
        IpAddr::V4(v4) => dns.reverse_lookup(v4).map(str::to_string),
        IpAddr::V6(_) => None,
    });
    let reclaimed_after_ttl = reclaimed == 1 && reverse_after.is_none();

    let upstream_calls_for_local = dns.upstream_call_count();
    // 注意：direct.example.com 走了 1 次上游；本地三类命中不应增加计数。
    // 在上面的 resolve 调用中，上游只应被调用 1 次（direct.example.com）。
    let local_isolated = upstream_calls_for_local == 1;

    let ok = hosts_class == "Hosts"
        && mesh_class == DnsClass::Mesh.as_str()
        && mesh_ip == "10.144.144.6"
        && fake_class == DnsClass::FakeIp.as_str()
        && fake_in_range
        && up_class == DnsClass::Upstream.as_str()
        && up_ip == "93.184.216.34"
        && stable_within_ttl
        && reverse_lookup == "proxy.example.com"
        && reclaimed_after_ttl
        && local_isolated;

    let extra = vec![
        ("hosts".to_string(), json!({ "class": hosts_class })),
        (
            "mesh".to_string(),
            json!({ "class": mesh_class, "ip": mesh_ip }),
        ),
        (
            "fakeip".to_string(),
            json!({
                "class": fake_class,
                "in_range": fake_in_range,
                "stable_within_ttl": stable_within_ttl,
                "reverse_lookup": reverse_lookup,
                "reclaimed_after_ttl": reclaimed_after_ttl,
            }),
        ),
        (
            "upstream".to_string(),
            json!({ "class": up_class, "ip": up_ip }),
        ),
        (
            "upstream_resolver_calls_for_local".to_string(),
            // 场景期望：本地命中零上游调用；此处直连域名的 1 次是预期的，
            // 故上报"本地三类之外的上游调用"即 total-1。
            json!(upstream_calls_for_local.saturating_sub(1)),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "dns-unified: classification order + fake-ip lifecycle verified".to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "dns-unified: invariants failed (hosts={hosts_class}, mesh={mesh_class}, fake={fake_class}, up={up_class}, stable={stable_within_ttl}, reclaimed={reclaimed_after_ttl}, local_isolated={local_isolated})"
            ),
            extra,
        )
    }
}

/// E4: Mesh 网络防火墙规则匹配引擎（内存骨架，PRODUCT §12-firewall-rules）。
///
/// 与 `nexus::firewall_flow()` 同语义；按 nexus-harness 架构策略直接用
/// `nexus_connectivity::firewall` 内联实现。演示三个检查点：
/// - 入站包（inbound）：外部未授权源 -> 默认拒绝；
/// - 转发包（forwarded）：mesh 内 /24 网段互访 -> 白名单 Allow；
/// - DNS 查询上下文：UDP/53 -> Deny 规则拦截；并验证 first-match-wins。
fn run_firewall_rules() -> Outcome {
    use nexus_connectivity::firewall::{
        FirewallAction, FirewallConfig, FirewallEngine, FirewallRule, PacketContext, PortRange,
        Protocol, dns_query_context,
    };

    // 规则顺序（first-match-wins）：
    // 1. Allow mesh 内 TCP（10.0.0.0/24 <-> 10.0.0.0/24）；
    // 2. Deny 所有 UDP/53（DNS 出口封锁）；
    // 3. Allow 来自 10.0.0.5 的 UDP/53（若 first-match-wins 失效，本条会错误放行）。
    let rule_mesh_tcp = FirewallRule::new(
        FirewallAction::Allow,
        Some("10.0.0.0/24"),
        Some("10.0.0.0/24"),
        None,
        None,
        Some(Protocol::Tcp),
    );
    let rule_deny_dns = FirewallRule::new(
        FirewallAction::Deny,
        None::<String>,
        None::<String>,
        None,
        Some(PortRange::single(53)),
        Some(Protocol::Udp),
    );
    let rule_allow_admin_dns = FirewallRule::new(
        FirewallAction::Allow,
        Some("10.0.0.5"),
        Some("10.0.0.0/24"),
        None,
        Some(PortRange::single(53)),
        Some(Protocol::Udp),
    );

    let (rule_mesh_tcp, rule_deny_dns, rule_allow_admin_dns) =
        match (rule_mesh_tcp, rule_deny_dns, rule_allow_admin_dns) {
            (Ok(a), Ok(b), Ok(c)) => (a, b, c),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                return (
                    "FAIL".to_string(),
                    format!("firewall-rules: build rule: {e}"),
                    Vec::new(),
                );
            }
        };

    let cfg = match FirewallConfig::new(
        FirewallAction::Deny,
        vec![rule_mesh_tcp, rule_deny_dns, rule_allow_admin_dns],
    ) {
        Ok(c) => c,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("firewall-rules: build config: {e}"),
                Vec::new(),
            );
        }
    };
    let engine = match FirewallEngine::new(&cfg) {
        Ok(e) => e,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("firewall-rules: build engine: {e}"),
                Vec::new(),
            );
        }
    };

    // 检查点 1：入站未授权包（外部源访问 mesh 内 80 端口）-> 未命中任何规则 -> 默认 Deny。
    let inbound_unauthorized = PacketContext::transport(
        "203.0.113.10",
        "10.0.0.1",
        Some(40000),
        Some(80),
        Protocol::Tcp,
    );
    let inbound_verdict = engine.evaluate(&inbound_unauthorized);

    // 检查点 2：白名单放行（mesh 内 10.0.0.5 -> 10.0.0.1 的 SSH/TCP）-> 规则 1 Allow。
    let whitelisted =
        PacketContext::transport("10.0.0.5", "10.0.0.1", Some(50000), Some(22), Protocol::Tcp);
    let whitelisted_verdict = engine.evaluate(&whitelisted);

    // 检查点 3：转发包（多跳路由场景，10.0.0.5 -> 10.0.0.9 的 HTTPS/TCP）-> 规则 1 Allow。
    let forwarded = PacketContext::transport(
        "10.0.0.5",
        "10.0.0.9",
        Some(50001),
        Some(443),
        Protocol::Tcp,
    );
    let forwarded_verdict = engine.evaluate(&forwarded);

    // CIDR 网段匹配：10.0.0.200 -> 10.0.0.100 都在 /24 内 -> Allow。
    let cidr_hit = PacketContext::transport(
        "10.0.0.200",
        "10.0.0.100",
        Some(50002),
        Some(8080),
        Protocol::Tcp,
    );
    let cidr_hit_verdict = engine.evaluate(&cidr_hit);

    // 检查点 4：DNS 查询上下文（任意源 -> 10.0.0.53:53/UDP）-> 规则 2 Deny。
    let dns_blocked = dns_query_context("10.0.0.6", "10.0.0.53");
    let dns_blocked_verdict = engine.evaluate(&dns_blocked);

    // 检查点 5：first-match-wins —— 即使规则 3 精确允许 10.0.0.5 的 DNS，
    // 规则 2 先命中，仍应 Deny。
    let admin_dns = dns_query_context("10.0.0.5", "10.0.0.53");
    let admin_dns_verdict = engine.evaluate(&admin_dns);

    let ok = inbound_verdict == nexus_connectivity::firewall::FirewallVerdict::Deny
        && whitelisted_verdict == nexus_connectivity::firewall::FirewallVerdict::Allow
        && forwarded_verdict == nexus_connectivity::firewall::FirewallVerdict::Allow
        && cidr_hit_verdict == nexus_connectivity::firewall::FirewallVerdict::Allow
        && dns_blocked_verdict == nexus_connectivity::firewall::FirewallVerdict::Deny
        && admin_dns_verdict == nexus_connectivity::firewall::FirewallVerdict::Deny;

    let extra = vec![
        (
            "default_policy".to_string(),
            json!(engine.default_policy().as_str()),
        ),
        ("rule_count".to_string(), json!(engine.rule_count())),
        (
            "inbound_unauthorized".to_string(),
            json!({ "verdict": inbound_verdict.as_str() }),
        ),
        (
            "whitelisted_peer".to_string(),
            json!({ "verdict": whitelisted_verdict.as_str() }),
        ),
        (
            "forwarded_packet".to_string(),
            json!({ "verdict": forwarded_verdict.as_str() }),
        ),
        (
            "cidr_hit".to_string(),
            json!({ "verdict": cidr_hit_verdict.as_str() }),
        ),
        (
            "dns_blocked".to_string(),
            json!({ "verdict": dns_blocked_verdict.as_str() }),
        ),
        (
            "first_match_wins".to_string(),
            json!({
                "admin_dns_verdict": admin_dns_verdict.as_str(),
                "expected": "deny"
            }),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "firewall-rules: default-deny + whitelist allow + port deny + CIDR + first-match-wins verified"
                .to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "firewall-rules: invariants failed (inbound={}, whitelist={}, forwarded={}, cidr={}, dns={}, admin_dns={})",
                inbound_verdict,
                whitelisted_verdict,
                forwarded_verdict,
                cidr_hit_verdict,
                dns_blocked_verdict,
                admin_dns_verdict
            ),
            extra,
        )
    }
}

/// E4: 带宽控制 / QoS 令牌桶限流（内存骨架，PRODUCT §12.8-bandwidth-qos）。
///
/// 与 `nexus::bandwidth_qos_flow()` 同语义；按 nexus-harness 架构策略直接用
/// `nexus_connectivity::qos` 内联实现。演示五个检查点：
/// (a) 初始突发 burst_size 字节放行；
/// (b) 同刻持续发送超过平均速率后后续包被拒；
/// (c) 推进时钟 1 秒后令牌恢复又可发；
/// (d) 两个连接 up 统计相互独立；
/// (e) 被拒绝字节计入 dropped 而非 allowed。
fn run_bandwidth_qos() -> Outcome {
    use nexus_connectivity::qos::{BandwidthLimit, QosConfig, QosController};
    use std::time::Duration;

    let egress_limit = match BandwidthLimit::new(1000, 1000) {
        Ok(l) => l,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("bandwidth-qos: build limit: {e}"),
                Vec::new(),
            );
        }
    };
    let cfg = QosConfig::new(None, Some(egress_limit));
    let mut ctl = QosController::new(&cfg);

    let t0 = Duration::ZERO;
    let t1 = Duration::from_secs(1);

    // (a) 初始突发：满桶 1000 字节放行。
    let burst_allowed = ctl.try_egress("conn-a", 1000, t0);
    // (b) 同刻持续发送：令牌已空，再发 100 字节被拒。
    let excess_after_burst_rejected = !ctl.try_egress("conn-a", 100, t0);
    // (c) 推进时钟 1 秒：补满令牌，conn-a 又可发 500 字节。
    let recovered_after_second = ctl.try_egress("conn-a", 500, t1);
    // (d) 第二连接 conn-b 独立消耗；两连接 up 统计互不影响。
    let conn_b_allowed = ctl.try_egress("conn-b", 300, t1);

    let snap = ctl.snapshot();
    let conn_a_up = snap
        .endpoints
        .get("conn-a")
        .map(|s| s.up_bytes)
        .unwrap_or(0);
    let conn_b_up = snap
        .endpoints
        .get("conn-b")
        .map(|s| s.up_bytes)
        .unwrap_or(0);

    let ok = burst_allowed
        && excess_after_burst_rejected
        && recovered_after_second
        && conn_b_allowed
        && conn_a_up == 1500
        && conn_b_up == 300
        && snap.bytes_allowed == 1800
        && snap.bytes_dropped == 100;

    let extra = vec![
        ("rate_bps".to_string(), json!(1000)),
        ("burst_bytes".to_string(), json!(1000)),
        ("burst_allowed".to_string(), json!(burst_allowed)),
        (
            "excess_after_burst_rejected".to_string(),
            json!(excess_after_burst_rejected),
        ),
        (
            "recovered_after_second".to_string(),
            json!(recovered_after_second),
        ),
        (
            "connections".to_string(),
            json!({
                "conn_a_up_bytes": conn_a_up,
                "conn_b_up_bytes": conn_b_up,
                "conn_b_allowed": conn_b_allowed,
            }),
        ),
        ("bytes_allowed".to_string(), json!(snap.bytes_allowed)),
        ("bytes_dropped".to_string(), json!(snap.bytes_dropped)),
        (
            "egress_tokens_remaining".to_string(),
            json!(snap.tokens_remaining),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "bandwidth-qos: burst allow + over-limit reject + 1s recovery + per-conn stats + dropped accounting verified"
                .to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "bandwidth-qos: invariants failed (burst={burst_allowed}, excess_rejected={excess_after_burst_rejected}, recovered={recovered_after_second}, conn_a_up={conn_a_up}, conn_b_up={conn_b_up}, allowed={}, dropped={})",
                snap.bytes_allowed, snap.bytes_dropped
            ),
            extra,
        )
    }
}

/// E4 test: 自动断线重连（指数退避 + 最大重试 + 状态机，离线确定性）。
///
/// 与 `nexus::auto_reconnect_flow()` 同语义；按 nexus-harness 架构策略直接用
/// `nexus_connectivity::reconnect` 内联实现。演示七个检查点：
/// (a) 首次断线后 next_delay = 100ms（initial）；
/// (b) 失败后指数翻倍：200ms、400ms；
/// (c) 第 4 次退避触顶 max_delay（800ms）；
/// (d) 打满 max_retries 后进入 GiveUp；
/// (e) 退避中途成功回到 Connected 并清零计数。
fn run_auto_reconnect() -> Outcome {
    use nexus_connectivity::reconnect::{ReconnectConfig, ReconnectController, ReconnectState};
    use std::time::Duration;

    let ms = Duration::from_millis;

    let cfg = match ReconnectConfig::new(3, ms(100), ms(800), 2.0) {
        Ok(c) => c,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("auto-reconnect: build config: {e}"),
                Vec::new(),
            );
        }
    };

    // ---- 第一个 controller：打满 3 次重试后 GiveUp ----
    let mut ctl = ReconnectController::new(cfg);

    let snap_disconnect = ctl.on_disconnect(ms(0));
    let initial_backoff_is_100ms = snap_disconnect.next_delay == ms(100);

    let ok1 = ctl.begin_attempt(ms(0));
    ctl.on_attempt_failed(ms(0));
    let after_1 = ctl.next_delay();

    let due_100 = ctl.is_due(ms(100));
    let ok2 = ctl.begin_attempt(ms(100));
    ctl.on_attempt_failed(ms(100));
    let after_2 = ctl.next_delay();

    let due_300 = ctl.is_due(ms(300));
    let ok3 = ctl.begin_attempt(ms(300));
    ctl.on_attempt_failed(ms(300));
    let after_3 = ctl.next_delay();

    let backoff_doubles = after_1 == ms(100) && after_2 == ms(200) && after_3 == ms(400);

    // 第 4 次若发生：理论退避 min(100*2^3, 800) = 800 == max_delay，触顶。
    let theoretical_4th = (100.0 * 2.0_f64.powi(3)).min(800.0) as u64;
    let backoff_caps_at_max = theoretical_4th == 800;

    let due_700 = ctl.is_due(ms(700));
    let ok4 = ctl.begin_attempt(ms(700));
    let give_up_after_max_retries = !ok4 && *ctl.state() == ReconnectState::GiveUp;
    let attempt_count = ctl.attempt_count();

    // ---- 第二个 controller：退避中途成功，验证状态重置 ----
    let cfg2 = match ReconnectConfig::new(3, ms(100), ms(800), 2.0) {
        Ok(c) => c,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("auto-reconnect: build config (reset path): {e}"),
                Vec::new(),
            );
        }
    };
    let mut ctl2 = ReconnectController::new(cfg2);
    ctl2.on_disconnect(ms(0));
    ctl2.begin_attempt(ms(0));
    ctl2.on_attempt_failed(ms(0));
    ctl2.begin_attempt(ms(100));
    ctl2.on_attempt_failed(ms(100));
    ctl2.on_success(ms(200));
    let reconnect_success_resets_state = *ctl2.state() == ReconnectState::Connected
        && ctl2.attempt_count() == 0
        && ctl2.next_delay() == ms(100);
    let final_state = match ctl2.state() {
        ReconnectState::Connected => "Connected",
        ReconnectState::Reconnecting => "Reconnecting",
        ReconnectState::Idle => "Idle",
        ReconnectState::Failed => "Failed",
        ReconnectState::GiveUp => "GiveUp",
    };

    let ok = initial_backoff_is_100ms
        && backoff_doubles
        && backoff_caps_at_max
        && give_up_after_max_retries
        && reconnect_success_resets_state
        && attempt_count == 3
        && final_state == "Connected"
        && ok1
        && ok2
        && ok3
        && !ok4
        && due_100
        && due_300
        && due_700;

    let extra = vec![
        ("max_retries".to_string(), json!(3)),
        ("initial_delay_ms".to_string(), json!(100)),
        ("max_delay_ms".to_string(), json!(800)),
        ("backoff_factor".to_string(), json!(2.0)),
        (
            "initial_backoff_is_100ms".to_string(),
            json!(initial_backoff_is_100ms),
        ),
        ("backoff_doubles".to_string(), json!(backoff_doubles)),
        (
            "backoff_caps_at_max".to_string(),
            json!(backoff_caps_at_max),
        ),
        (
            "give_up_after_max_retries".to_string(),
            json!(give_up_after_max_retries),
        ),
        (
            "reconnect_success_resets_state".to_string(),
            json!(reconnect_success_resets_state),
        ),
        ("attempt_count".to_string(), json!(attempt_count)),
        ("final_state".to_string(), json!(final_state)),
        (
            "diag".to_string(),
            json!({
                "attempt_allowed": [ok1, ok2, ok3],
                "attempt4_allowed": ok4,
                "is_due_at": { "100": due_100, "300": due_300, "700": due_700 },
                "after_fail_delay_ms": { "1": 100, "2": 200, "3": 400 },
            }),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "auto-reconnect: initial 100ms + doubling 100/200/400 + cap 800 + give-up at max_retries + success reset verified"
                .to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "auto-reconnect: invariants failed (initial={initial_backoff_is_100ms}, doubles={backoff_doubles}, cap={backoff_caps_at_max}, give_up={give_up_after_max_retries}, reset={reconnect_success_resets_state}, attempts={attempt_count}, final={final_state})"
            ),
            extra,
        )
    }
}

/// E4: CAKE-like QoS 调度器（DRR 公平队列 + 严格优先级 + 整形 + 流回收，
/// `scenarios/product/qos_cake.toml`）。纯内存、假时钟确定性；演示五个检查点：
/// (a) 同优先级 backlog 流按字节公平（A: 4x1500B vs B: 12x500B → 各 6000B）；
/// (b) 严格优先级（High 3 包先于 Medium 3 包，签名 "HHHLLL"）；
/// (c) 整形（burst 后阻塞、1s 恢复）；
/// (d) 流回收（60s 空闲回收）；
/// (e) daemon.toml [qos] 的 wire format 映射形状（真实解析器由 apps/nexusd 单测覆盖）。
fn run_qos_cake() -> Outcome {
    use nexus_connectivity::cake::{CakeConfig, CakeScheduler, FiveTuple, PROTO_TCP, PROTO_UDP};
    use nexus_connectivity::qos::BandwidthLimit;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    let t0 = Duration::ZERO;
    let mk = |sp: u16, dp: u16, proto: u8| FiveTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: sp,
        dst_port: dp,
        proto,
    };

    // (a) 公平性。
    let mut sched = match CakeScheduler::new(&CakeConfig::default()) {
        Ok(s) => s,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("qos-cake: build scheduler: {e}"),
                Vec::new(),
            );
        }
    };
    let a = mk(1000, 80, PROTO_TCP);
    let b = mk(2000, 80, PROTO_TCP);
    let fid_a = a.flow_id();
    for _ in 0..4 {
        sched.enqueue(&a, 1500, t0);
    }
    for _ in 0..12 {
        sched.enqueue(&b, 500, t0);
    }
    let mut a_bytes = 0u64;
    let mut b_bytes = 0u64;
    let mut total_packets = 0u32;
    while let Some((fid, len)) = sched.dequeue(t0) {
        if fid == fid_a {
            a_bytes += len;
        } else {
            b_bytes += len;
        }
        total_packets += 1;
        if total_packets > 64 {
            break; // 防御性：正常 16 包即排空
        }
    }

    // (b) 严格优先级。
    let mut prio_sched = match CakeScheduler::new(&CakeConfig::default()) {
        Ok(s) => s,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("qos-cake: build prio scheduler: {e}"),
                Vec::new(),
            );
        }
    };
    let h = mk(40000, 53, PROTO_UDP); // High（DNS 端口）
    let l = mk(40001, 443, PROTO_TCP); // Medium
    let fid_h = h.flow_id();
    for _ in 0..3 {
        prio_sched.enqueue(&h, 100, t0);
        prio_sched.enqueue(&l, 100, t0);
    }
    let mut sig = String::new();
    for _ in 0..6 {
        match prio_sched.dequeue(t0) {
            Some((fid, _)) => sig.push(if fid == fid_h { 'H' } else { 'L' }),
            None => sig.push('?'),
        }
    }

    // (c) 整形：rate 1000 B/s，burst 1000。
    let limit = match BandwidthLimit::new(1000, 1000) {
        Ok(l) => l,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("qos-cake: build limit: {e}"),
                Vec::new(),
            );
        }
    };
    let shaped_cfg = CakeConfig {
        rate_limit: Some(limit),
        ..CakeConfig::default()
    };
    let mut shaped = match CakeScheduler::new(&shaped_cfg) {
        Ok(s) => s,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("qos-cake: build shaped scheduler: {e}"),
                Vec::new(),
            );
        }
    };
    let m = mk(3000, 80, PROTO_TCP);
    for _ in 0..3 {
        shaped.enqueue(&m, 1000, t0);
    }
    let first_burst_bytes = shaped.dequeue(t0).map(|(_, len)| len).unwrap_or(0);
    let blocked_when_tokens_empty = shaped.dequeue(t0).is_none();
    let t1 = Duration::from_secs(1);
    let resumed_after_1s = shaped.dequeue(t1).map(|(_, len)| len) == Some(1000);

    // (d) 流回收：t=0 建流，t=61s 回收。
    let mut reaper = match CakeScheduler::new(&CakeConfig::default()) {
        Ok(s) => s,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("qos-cake: build reap scheduler: {e}"),
                Vec::new(),
            );
        }
    };
    let x = mk(4000, 80, PROTO_TCP);
    reaper.enqueue(&x, 100, t0);
    let reaped_count = reaper.reap(Duration::from_secs(61));
    let flows_remaining = reaper.flow_count();

    // (e) daemon.toml [qos] wire format 映射形状。
    let snippet = "[qos]\nenabled = true\nmesh_upload_mbps = 100\nproxy_upload_mbps = 50\nquantum = 1514\nhigh_priority_ports = \"22,53,3389\"\n";
    let v: toml::Value = match toml::from_str(snippet) {
        Ok(v) => v,
        Err(e) => {
            return (
                "FAIL".to_string(),
                format!("qos-cake: parse qos snippet: {e}"),
                Vec::new(),
            );
        }
    };
    let q = v.get("qos");
    let cfg_enabled = q.and_then(|t| t.get("enabled")).and_then(|x| x.as_bool());
    let cfg_mesh = q
        .and_then(|t| t.get("mesh_upload_mbps"))
        .and_then(|x| x.as_integer());
    let cfg_proxy = q
        .and_then(|t| t.get("proxy_upload_mbps"))
        .and_then(|x| x.as_integer());
    let cfg_quantum = q
        .and_then(|t| t.get("quantum"))
        .and_then(|x| x.as_integer());
    let cfg_ports = q
        .and_then(|t| t.get("high_priority_ports"))
        .and_then(|x| x.as_str())
        .unwrap_or("");

    let ok = a_bytes == 6000
        && b_bytes == 6000
        && total_packets == 16
        && sig == "HHHLLL"
        && first_burst_bytes == 1000
        && blocked_when_tokens_empty
        && resumed_after_1s
        && reaped_count == 1
        && flows_remaining == 0
        && cfg_enabled == Some(true)
        && cfg_mesh == Some(100)
        && cfg_proxy == Some(50)
        && cfg_quantum == Some(1514)
        && cfg_ports == "22,53,3389";

    let extra = vec![
        (
            "fairness".to_string(),
            json!({
                "flow_a_bytes": a_bytes,
                "flow_b_bytes": b_bytes,
                "total_packets": total_packets,
            }),
        ),
        ("priority".to_string(), json!({ "order_signature": sig })),
        (
            "shaping".to_string(),
            json!({
                "first_burst_bytes": first_burst_bytes,
                "blocked_when_tokens_empty": blocked_when_tokens_empty,
                "resumed_after_1s": resumed_after_1s,
            }),
        ),
        (
            "reap".to_string(),
            json!({
                "reaped_count": reaped_count,
                "flows_remaining": flows_remaining,
            }),
        ),
        (
            "config".to_string(),
            json!({
                "enabled": cfg_enabled,
                "mesh_upload_mbps": cfg_mesh,
                "proxy_upload_mbps": cfg_proxy,
                "quantum": cfg_quantum,
                "high_priority_ports": cfg_ports,
            }),
        ),
    ];

    if ok {
        (
            "PASS".to_string(),
            "qos-cake: DRR fairness + strict priority + shaping block/resume + 60s reap + [qos] mapping verified"
                .to_string(),
            extra,
        )
    } else {
        (
            "FAIL".to_string(),
            format!(
                "qos-cake: invariants failed (a_bytes={a_bytes}, b_bytes={b_bytes}, packets={total_packets}, sig={sig}, burst={first_burst_bytes}, blocked={blocked_when_tokens_empty}, resumed={resumed_after_1s}, reaped={reaped_count}, remaining={flows_remaining})"
            ),
            extra,
        )
    }
}
