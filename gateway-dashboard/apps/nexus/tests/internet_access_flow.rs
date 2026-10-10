//! E3 集成测试：InternetAccess 纵切的端到端契约。
//!
//! 与 scenarios/product/internet_access_flow.toml（E4）共享同一组合根函数，
//! 在进程内断言事件顺序、Plan、Session 双轨状态与架构禁止边。

use nexus::{
    EV_FLOW_SUBMITTED, EV_PLAN_SELECTED, EV_POLICY_EVALUATED, EV_SESSION_CREATED,
    internet_access_flow,
};
use serde_json::Value;

fn run() -> Value {
    internet_access_flow("https://example.invalid/", "Balanced")
        .expect("deterministic in-memory flow must succeed")
}

#[test]
fn ordered_event_chain() {
    let report = run();
    let events = report["events"].as_array().unwrap();
    let names: Vec<&str> = events
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()
        .unwrap();
    assert_eq!(
        names,
        vec![
            EV_FLOW_SUBMITTED,
            EV_POLICY_EVALUATED,
            EV_PLAN_SELECTED,
            EV_SESSION_CREATED,
        ]
    );
}

#[test]
fn plan_is_concrete_and_picks_lowest_rtt() {
    let report = run();
    assert_eq!(report["plan"]["provider_id"], "provider-edge-a");
    assert_eq!(report["plan"]["placement"], "local-edge");
    assert!(report["plan"]["path"].as_array().unwrap().len() == 1);
    assert_eq!(report["plan"]["execution_strategy"], "direct");
    assert_eq!(report["trace"]["selected"], "provider-edge-a");
}

#[test]
fn session_active_with_unfinished_outcome() {
    let report = run();
    assert_eq!(report["session"]["phase"], "Active");
    assert_eq!(report["session"]["outcome"], "Unfinished");
}

#[test]
fn network_must_not_depend_on_ingress() {
    let report = run();
    assert_eq!(report["architecture"]["network_depends_on_ingress"], false);
}

#[test]
fn flow_is_deterministic() {
    assert_eq!(
        internet_access_flow("https://example.invalid/", "Balanced").unwrap(),
        internet_access_flow("https://example.invalid/", "Balanced").unwrap()
    );
}
