//! E3 集成测试：Resource 生命周期顺序与 Exactly-One Terminal Outcome。
//!
//! 与 scenarios/product/resource_session_lifecycle.toml（E4）共享同一组合根。

use nexus::service_session_lifecycle;
use serde_json::Value;

fn run() -> Value {
    service_session_lifecycle("service://example", "Default")
        .expect("deterministic in-memory lifecycle must succeed")
}

#[test]
fn plan_and_session_precede_connectivity() {
    let r = run();
    assert_eq!(r["invariants"]["plan_before_connectivity"], true);
    assert_eq!(r["invariants"]["session_before_connectivity"], true);

    let events = r["events"].as_array().unwrap();
    let pos = |name: &str| {
        events
            .iter()
            .position(|e| e == name)
            .expect("event present")
    };
    let plan = pos("plan_selected");
    let session = pos("session_created");
    let conn = pos("connectivity_establishment");
    let execute = pos("execute");
    assert!(plan < conn);
    assert!(session < conn);
    assert!(conn < execute);
}

#[test]
fn terminal_outcome_committed_exactly_once() {
    let r = run();
    assert_eq!(r["terminal_outcome_commit_count"], 1);
    assert_eq!(r["redundant_commit_rejected"], true);
    assert_eq!(r["terminal_outcome"], "Completed");
}

#[test]
fn cleanup_reaches_disposed_while_outcome_holds() {
    let r = run();
    assert_eq!(r["session"]["phase"], "Disposed");
    assert_eq!(r["session"]["outcome"], "Completed");
}

#[test]
fn resolves_two_candidates_and_picks_primary() {
    let r = run();
    assert_eq!(r["candidate_providers"], 2);
    assert_eq!(r["plan"]["provider_id"], "svc-primary");
}

#[test]
fn lifecycle_is_deterministic() {
    assert_eq!(
        service_session_lifecycle("service://example", "Default").unwrap(),
        service_session_lifecycle("service://example", "Default").unwrap()
    );
}
