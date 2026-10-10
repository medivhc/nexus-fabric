//! E4 产品场景 `product.multihop-routing` 的可执行示例（Composition Root）。
//!
//! 与 `nexus-harness run multihop-routing --json` 跑同一份内存 4 节点线性拓扑：
//! A(10.0.0.1) -- B(10.0.0.2) -- C(10.0.0.3) -- D(10.0.0.4)。
//!
//! 本示例不调用 harness（harness 在 engineering/ 下，apps/nexus 不依赖它）；
//! 直接使用 `nexus_connectivity::routing` 的公开 API 演示：
//! 1. 直连邻居注册；
//! 2. 3 轮距离矢量通告收敛；
//! 3. A->D 包经 3 跳转发，TTL 从 64 递减到 61；
//! 4. 推进逻辑时钟超过 TTL 后非直连路由被超时删除。
//!
//! 不带 `--json` 时打印人类可读摘要；带 `--json` 时打印单个 JSON 对象.

#![forbid(unsafe_code)]
#![allow(deprecated)] // §12.57 已退役：历史示例保留

use nexus_connectivity::routing::{ForwardDecision, MultihopRouter, RoutablePacket};

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");

    let result = run_demo();
    match result {
        Ok(summary) => {
            if as_json {
                println!("{summary}");
            } else {
                println!("multihop routing demo OK:");
                // 非 JSON 模式下重新打印为人类可读行。
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&summary) {
                    println!("  topology: {}", v["topology"]);
                    println!(
                        "  A->D: next_hop={}, cost={}",
                        v["node_a"]["route_to_d"]["next_hop"], v["node_a"]["route_to_d"]["cost"]
                    );
                    println!(
                        "  packet delivered to D: ok={}, ttl_at_delivery={}",
                        v["packet_delivered_to_d"]["ok"],
                        v["packet_delivered_to_d"]["ttl_at_delivery"]
                    );
                    println!(
                        "  route expired: {} (dst={})",
                        v["expiration"]["route_expired"], v["expiration"]["expired_destination"]
                    );
                }
            }
        }
        Err(err) => {
            eprintln!("multihop_routing demo failed: {err}");
            std::process::exit(1);
        }
    }
}

/// 跑一遍 4 节点线性拓扑 demo，返回 JSON 字符串。
fn run_demo() -> Result<String, String> {
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

    let neighbors: [Vec<&str>; 4] = [
        vec!["10.0.0.2"],
        vec!["10.0.0.1", "10.0.0.3"],
        vec!["10.0.0.2", "10.0.0.4"],
        vec!["10.0.0.3"],
    ];

    // 3 轮距离矢量通告。
    for tick in 1..=3u64 {
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
        for (src, dst, adv) in deliveries {
            match dst.as_str() {
                "10.0.0.1" => a.table_mut().apply_advertisement(&src, &adv, tick),
                "10.0.0.2" => b.table_mut().apply_advertisement(&src, &adv, tick),
                "10.0.0.3" => c.table_mut().apply_advertisement(&src, &adv, tick),
                "10.0.0.4" => d.table_mut().apply_advertisement(&src, &adv, tick),
                other => return Err(format!("unknown neighbor {other}")),
            };
        }
    }

    let a_to_d = a
        .table()
        .lookup("10.0.0.4")
        .ok_or("A did not learn D")?
        .clone();
    let d_to_a = d
        .table()
        .lookup("10.0.0.1")
        .ok_or("D did not learn A")?
        .clone();

    // A->D 发包，逐跳：A 发出 ttl=64，B->C 63，C->D 62，D 本地交付看到 61。
    let pkt = RoutablePacket::new("10.0.0.1", "10.0.0.4", b"hello");
    let mut cur = pkt;
    let ttl_arrives_d: u8;

    // A 先转发给 B（ttl 64 -> 63）。
    match a.forward(&cur, 4) {
        Ok(ForwardDecision::ForwardTo { next_hop, ttl }) => {
            debug_assert_eq!(next_hop, "10.0.0.2");
            cur = RoutablePacket { ttl, ..cur };
        }
        other => return Err(format!("A must ForwardTo, got {other:?}")),
    }
    // B 转发给 C（63 -> 62）。
    match b.forward(&cur, 4) {
        Ok(ForwardDecision::ForwardTo { next_hop, ttl }) => {
            debug_assert_eq!(next_hop, "10.0.0.3");
            cur = RoutablePacket { ttl, ..cur };
        }
        other => return Err(format!("B must ForwardTo, got {other:?}")),
    }
    // C 转发给 D（62 -> 61）。
    match c.forward(&cur, 4) {
        Ok(ForwardDecision::ForwardTo { next_hop, ttl }) => {
            debug_assert_eq!(next_hop, "10.0.0.4");
            ttl_arrives_d = ttl;
            cur = RoutablePacket { ttl, ..cur };
        }
        other => return Err(format!("C must ForwardTo, got {other:?}")),
    }
    // D 本地交付。
    let delivered = matches!(d.forward(&cur, 4), Ok(ForwardDecision::DeliverLocal));

    // 超时。
    let expired = a.table_mut().expire_stale(10, 5);

    let out = serde_json::json!({
        "topology": "linear",
        "node_a": {
            "virtual_ip": "10.0.0.1",
            "direct_peer_count": a.table().direct_peer_count(),
            "route_to_d": { "next_hop": a_to_d.next_hop, "cost": a_to_d.cost }
        },
        "node_d": {
            "virtual_ip": "10.0.0.4",
            "direct_peer_count": d.table().direct_peer_count(),
            "route_to_a": { "next_hop": d_to_a.next_hop, "cost": d_to_a.cost }
        },
        "packet_delivered_to_d": { "ok": delivered, "ttl_at_delivery": ttl_arrives_d },
        "expiration": { "expired_count": expired.len() }
    });
    Ok(out.to_string())
}
