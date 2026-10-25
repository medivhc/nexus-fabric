use nexus_nat_traversal::PunchConfig;
use nexus_nat_wireup::repunch::{RepunchTrigger, Scheduler};

fn sched() -> Scheduler {
    Scheduler::new(&PunchConfig::default())
}

#[test]
fn g10_repunch_periodic_300s() {
    let mut s = sched();
    assert_eq!(s.on_tick(299_000, false), None, "299s: no periodic repunch");
    assert_eq!(
        s.on_tick(300_000, false),
        Some(RepunchTrigger::Periodic),
        "300s: exactly one periodic repunch"
    );
}

#[test]
fn repunch_after_300s() {
    let mut s = sched();
    s.note_attempt(0);
    assert_eq!(s.on_tick(299_999, false), None);
    assert_eq!(s.on_tick(300_000, false), Some(RepunchTrigger::Periodic));
}

#[test]
fn coalesces_event_triggers() {
    let mut s = sched();
    s.note_event(1_000, RepunchTrigger::ReflexiveChanged);
    s.note_event(1_500, RepunchTrigger::RelayDegraded);
    let first = s.on_tick(2_000, false);
    assert!(first.is_some(), "queued event fires");
    assert_eq!(s.on_tick(2_500, false), None, "5s coalescing window");
    assert_eq!(s.on_tick(6_500, false), None, "no duplicate after window");
}

#[test]
fn symmetric_never_repunches() {
    let mut s = sched();
    s.note_event(1_000, RepunchTrigger::ReflexiveChanged);
    assert_eq!(
        s.on_tick(300_000, true),
        None,
        "any symmetric side disables auto repunch"
    );
    assert_eq!(s.on_tick(301_000, true), None);
}
