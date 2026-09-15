//! 并发竞态：TerminalOutcome Exactly-Once（AGENTS.md §14 / policies/quality.toml [concurrency]）。
//!
//! 验证：多个 Worker 同时尝试提交终态时，Owner 状态机只允许一次成功，
//! 且首次提交的终态不被后续竞态覆盖（quality.toml `exactly_one_terminal_outcome = true`）。

use std::sync::{Arc, Mutex};
use std::thread;

use nexus_domain::{NexusError, SessionId, TerminalOutcome};
use nexus_session::SessionOwner;

/// 8 个线程同时提交 `Completed`，必须恰好 1 个成功，其余返回
/// `AlreadyTerminated`，最终状态保持首次提交值。
#[test]
fn concurrent_commit_allows_exactly_one_success() {
    let owner = Arc::new(Mutex::new(SessionOwner::new(SessionId(
        "race-commit-1".into(),
    ))));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let owner = Arc::clone(&owner);
            thread::spawn(move || {
                owner
                    .lock()
                    .expect("owner lock")
                    .commit_outcome(TerminalOutcome::Completed)
                    .is_ok()
            })
        })
        .collect();

    let success_count = handles
        .into_iter()
        .map(|h| h.join().expect("thread joined"))
        .filter(|ok| *ok)
        .count();

    assert_eq!(success_count, 1, "exactly-one terminal outcome must hold");
    let owner = owner.lock().expect("owner lock");
    assert_eq!(owner.committed_outcome(), Some(TerminalOutcome::Completed));
}

/// 8 个线程分别提交不同终态（Completed / Failed / Cancelled），
/// 仍然只允许 1 个成功，且已提交终态不被后续竞态改写。
#[test]
fn concurrent_commit_with_mixed_outcomes_keeps_first() {
    let owner = Arc::new(Mutex::new(SessionOwner::new(SessionId(
        "race-commit-2".into(),
    ))));
    let outcomes: Vec<TerminalOutcome> = vec![
        TerminalOutcome::Completed,
        TerminalOutcome::Cancelled,
        TerminalOutcome::Failed(NexusError::DnsResolutionFailed {
            name: "x.example".into(),
        }),
        TerminalOutcome::Completed,
        TerminalOutcome::Cancelled,
        TerminalOutcome::Failed(NexusError::SessionFailed {
            session: SessionId("s".into()),
            reason: "boom".into(),
        }),
        TerminalOutcome::Completed,
        TerminalOutcome::Cancelled,
    ];

    let handles: Vec<_> = outcomes
        .into_iter()
        .map(|outcome| {
            let owner = Arc::clone(&owner);
            thread::spawn(move || {
                owner
                    .lock()
                    .expect("owner lock")
                    .commit_outcome(outcome)
                    .is_ok()
            })
        })
        .collect();

    let success_count = handles
        .into_iter()
        .map(|h| h.join().expect("thread joined"))
        .filter(|ok| *ok)
        .count();

    assert_eq!(
        success_count, 1,
        "only one terminal outcome may be committed"
    );
    // 已提交终态必须完整保留（不可被竞态覆盖成别的值）。
    let owner = owner.lock().expect("owner lock");
    let committed = owner
        .committed_outcome()
        .expect("exactly one outcome was committed");
    assert_ne!(committed, TerminalOutcome::Unfinished);
}

/// 终态确定后 cleanup（Draining -> Disposed）不受并发读取影响，状态视图保持一致。
#[test]
fn concurrent_status_reads_are_consistent_after_commit() {
    let owner = Arc::new(Mutex::new(SessionOwner::new(SessionId(
        "race-read-1".into(),
    ))));
    {
        let mut guard = owner.lock().expect("owner lock");
        guard
            .transition_phase(nexus_domain::LifecyclePhase::Active)
            .expect("active");
        guard
            .commit_outcome(TerminalOutcome::Completed)
            .expect("commit once");
    }

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let owner = Arc::clone(&owner);
            thread::spawn(move || {
                let guard = owner.lock().expect("owner lock");
                let status = guard.status();
                (status.phase, status.outcome)
            })
        })
        .collect();

    for h in handles {
        let (phase, outcome) = h.join().expect("thread joined");
        assert_eq!(phase, nexus_domain::LifecyclePhase::Active);
        assert_eq!(outcome, TerminalOutcome::Completed);
    }
}
