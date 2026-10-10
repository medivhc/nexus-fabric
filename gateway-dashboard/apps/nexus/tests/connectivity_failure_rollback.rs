//! E3 集成测试：Connectivity 建连失败的逆序回滚契约。
//!
//! 与 scenarios/product/connectivity_failure_rollback.toml（E4）共享同一组合根函数，
//! 在进程内断言：事件顺序、认证门控失败、逆序幂等回滚、Session 双轨终态。

use nexus::{
    EV_CONNECTIVITY_ESTABLISHMENT, EV_CONNECTIVITY_FAILED, EV_FLOW_SUBMITTED, EV_PLAN_SELECTED,
    EV_POLICY_EVALUATED, EV_SESSION_CREATED, EV_TERMINAL_OUTCOME_COMMITTED,
    connectivity_failure_rollback,
};
use serde_json::Value;

fn run() -> Value {
    connectivity_failure_rollback("https://relay.example.invalid/", "Balanced")
        .expect("deterministic rollback flow must succeed")
}

#[test]
fn ordered_event_chain_includes_connectivity_failure() {
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
            EV_CONNECTIVITY_ESTABLISHMENT,
            EV_CONNECTIVITY_FAILED,
            EV_TERMINAL_OUTCOME_COMMITTED,
        ]
    );
}

#[test]
fn establishment_failed_on_unauthenticated_link() {
    let report = run();
    assert_eq!(report["connectivity"]["state"], "Failed");
    let reason = report["connectivity"]["reason"].as_str().unwrap();
    assert!(reason.contains("authentication"), "reason = {reason}");
}

#[test]
fn rollback_is_idempotent_and_reaches_disposed() {
    let report = run();
    assert_eq!(report["rollback"]["idempotent"], true);
    assert_eq!(report["rollback"]["drained_to_disposed"], true);
}

#[test]
fn session_terminated_failed_and_disposed() {
    let report = run();
    assert_eq!(report["session"]["phase"], "Disposed");
    assert_eq!(report["session"]["outcome"], "Failed");
}

#[test]
fn rollback_flow_is_deterministic() {
    assert_eq!(
        connectivity_failure_rollback("https://relay.example.invalid/", "Balanced").unwrap(),
        connectivity_failure_rollback("https://relay.example.invalid/", "Balanced").unwrap()
    );
}
