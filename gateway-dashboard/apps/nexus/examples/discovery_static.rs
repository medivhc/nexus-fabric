//! E4 产品场景 `product.discovery-static` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/discovery_static.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example discovery_static -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//! 本场景无网络：只 exercised 静态表 + LSA 只读提取 + 聚合 + 可观测计数。
//! verdict 仅当全部内部断言通过时为 PASS（否则为 FAIL，harness 据此判 FAIL）。

#![forbid(unsafe_code)]

use nexus_discovery::lsa::{Lsa, LsaDiscovery, Lsdb};
use nexus_discovery::mdns::MdnsDiscovery;
use nexus_discovery::{AggregateDiscovery, Discovery, DiscoverySource, PeerId, StaticDiscovery};
use serde_json::json;
use std::net::SocketAddr;

fn peer(id: &str) -> PeerId {
    PeerId(id.to_string())
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn lsa(id: &str, locator: Option<&str>) -> Lsa {
    Lsa {
        node_id: peer(id),
        vip: "10.9.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: locator.map(str::to_string),
        neighbors: Vec::new(),
    }
}

fn run() -> serde_json::Value {
    let mut failed: Vec<&str> = Vec::new();
    let check = |failed: &mut Vec<&str>, name: &'static str, ok: bool| {
        if !ok {
            failed.push(name);
        }
    };

    // ---- 装配：静态表 + LSDB + 空 mDNS 缓存 ----
    let static_disc = StaticDiscovery::new([
        (peer("peer-a"), addr("10.0.0.1:5001")),
        (peer("peer-b"), addr("10.0.0.9:5009")),
    ]);
    let mut db = Lsdb::new(peer("self"));
    db.update(lsa("peer-b", Some("udp://10.0.0.2:5002")));
    db.update(lsa("peer-c", Some("udp://10.0.0.3:5003")));
    db.update(lsa("peer-d", Some("bogus://not-an-addr")));
    db.update(lsa("peer-e", None));
    let mdns = MdnsDiscovery::new(peer("self"), 5999, "127.0.0.1".parse().unwrap()).unwrap();
    let lsa_disc = LsaDiscovery::new(&db);
    let agg = AggregateDiscovery::new(static_disc, &db, mdns);

    // ---- D2：静态解析（经 UFCS 调用 trait 方法，与 inherent Result 版区分） ----
    let demo_static = StaticDiscovery::new([(peer("peer-a"), addr("10.0.0.1:5001"))]);
    let static_addrs = Discovery::resolve(&demo_static, &peer("peer-a"));
    let static_resolve = static_addrs
        .first()
        .map(|a| a.to_string())
        .unwrap_or_default();
    check(
        &mut failed,
        "static_resolve",
        static_resolve == "10.0.0.1:5001",
    );

    // ---- D4：LSA locator 解析 ----
    let lsa_b = Discovery::resolve(&lsa_disc, &peer("peer-b"));
    let lsa_resolve = lsa_b.first().map(|a| a.to_string()).unwrap_or_default();
    check(&mut failed, "lsa_resolve", lsa_resolve == "10.0.0.2:5002");
    let lsa_invalid_skipped = Discovery::resolve(&lsa_disc, &peer("peer-d")).is_empty();
    check(&mut failed, "lsa_invalid_skipped", lsa_invalid_skipped);
    let lsa_missing_skipped = Discovery::resolve(&lsa_disc, &peer("peer-e")).is_empty();
    check(&mut failed, "lsa_missing_skipped", lsa_missing_skipped);

    // ---- D5：聚合优先级 + 去重 + 来源标注 ----
    let rb = agg.resolve_with_sources(&peer("peer-b"));
    let aggregate_addrs = rb.len();
    check(&mut failed, "aggregate_addrs", aggregate_addrs == 2);
    let aggregate_first_source = rb
        .first()
        .map(|r| r.source.as_str().to_string())
        .unwrap_or_default();
    check(
        &mut failed,
        "aggregate_first_source",
        aggregate_first_source == "static"
            && rb.first().map(|r| r.addr) == Some(addr("10.0.0.9:5009")),
    );
    check(
        &mut failed,
        "aggregate_second",
        rb.get(1).map(|r| (r.addr, r.source))
            == Some((addr("10.0.0.2:5002"), DiscoverySource::Lsa)),
    );
    let rc = agg.resolve_with_sources(&peer("peer-c"));
    let aggregate_peer_c_source = rc
        .first()
        .map(|r| r.source.as_str().to_string())
        .unwrap_or_default();
    check(
        &mut failed,
        "aggregate_peer_c",
        rc.len() == 1 && aggregate_peer_c_source == "lsa",
    );

    // ---- D1/D6：未知 peer 为空 + metrics ----
    // 注意：只有 AggregateDiscovery::resolve（trait 方法）更新计数器。
    let v_b = Discovery::resolve(&agg, &peer("peer-b")); // static + lsa 命中
    let v_c = Discovery::resolve(&agg, &peer("peer-c")); // lsa 命中
    let v_unknown = Discovery::resolve(&agg, &peer("peer-unknown")); // miss
    check(&mut failed, "trait_vec_b", v_b.len() == 2);
    check(
        &mut failed,
        "trait_vec_c",
        v_c == vec![addr("10.0.0.3:5003")],
    );
    let unknown_empty = v_unknown.is_empty();
    check(&mut failed, "unknown_empty", unknown_empty);
    let snap = agg.metrics().snapshot();
    check(&mut failed, "metrics_hits_static", snap.hits_static == 1);
    check(&mut failed, "metrics_hits_lsa", snap.hits_lsa == 2);
    check(&mut failed, "metrics_hits_mdns", snap.hits_mdns == 0);
    check(&mut failed, "metrics_miss", snap.miss == 1);

    let verdict = if failed.is_empty() { "PASS" } else { "FAIL" };
    json!({
        "verdict": verdict,
        "command": "discovery-static",
        "static_resolve": static_resolve,
        "lsa_resolve": lsa_resolve,
        "lsa_invalid_skipped": lsa_invalid_skipped,
        "lsa_missing_skipped": lsa_missing_skipped,
        "aggregate_addrs": aggregate_addrs,
        "aggregate_first_source": aggregate_first_source,
        "aggregate_peer_c_source": aggregate_peer_c_source,
        "unknown_empty": unknown_empty,
        "metrics_hits_static": snap.hits_static,
        "metrics_hits_lsa": snap.hits_lsa,
        "metrics_hits_mdns": snap.hits_mdns,
        "metrics_miss": snap.miss,
        "failed_checks": failed,
    })
}

fn main() {
    let v = run();
    if std::env::args().any(|a| a == "--json") {
        println!("{}", serde_json::to_string(&v).unwrap());
    } else {
        println!("{v:#}");
    }
    if v["verdict"] != "PASS" {
        std::process::exit(1);
    }
}
