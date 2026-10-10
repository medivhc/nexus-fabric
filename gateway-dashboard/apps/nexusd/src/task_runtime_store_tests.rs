use super::*;
use nexus_compute::task::AcceptanceResult;
use nexus_compute::task::{AcceptanceContext, TaskAcceptanceStore, TaskOwner};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "nexus-n3-3-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn root(&self) -> PathBuf {
        self.0.join("store")
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn owner(root: &Path) -> TaskOwner<FileTaskAcceptanceStore> {
    TaskOwner::new(
        FileTaskAcceptanceStore::open(root).unwrap(),
        sha256,
        new_task_id,
    )
}
fn accept(root: &Path, key: &str) -> AcceptedTask {
    let mut r: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
        "../../../docs/contracts/n3-submit.example.json"
    ))
    .unwrap();
    r.idempotency_key = key.into();
    r.success_exit_codes = vec![0, 42];
    let c = AcceptanceContext {
        authenticated_principal: "verified-fixture".into(),
        provider: r.provider.clone(),
        environment_evidence: r.environment.clone(),
        capacity_reservation_id: "fixture-capacity".into(),
        now_unix: 100,
        prepare_deadline_unix: 110,
        delivery_deadline_unix: 200,
    };
    owner(root).accept_verified(r, c).unwrap().task
}
fn event(
    root: &Path,
    id: &TaskId,
    sequence: u64,
    action: RuntimeAction,
) -> Result<RuntimeUpdate, TaskError> {
    owner(root).record_event(id, RuntimeEvent { sequence, action })
}
fn start(root: &Path, id: &TaskId) {
    event(root, id, 1, RuntimeAction::Prepare).unwrap();
    event(
        root,
        id,
        2,
        RuntimeAction::StartIntent {
            handle: format!("container-{}", id.as_str()),
        },
    )
    .unwrap();
    event(root, id, 3, RuntimeAction::Started { at_unix: 101 }).unwrap();
}

#[test]
fn durable_exit_preserves_real_code_and_waits_for_delivery_even_without_outputs() {
    let dir = Dir::new();
    let root = dir.root();
    for (i, code, success) in [(0, 0, true), (1, 42, true), (2, 9, false)] {
        let task = accept(&root, &format!("key-{i}"));
        let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
        start(&root, &task.view.task_id);
        let result = event(
            &root,
            &task.view.task_id,
            4,
            RuntimeAction::Exited { exit_code: code },
        )
        .unwrap();
        assert_eq!(result.state.view.execution.exit_code, Some(code));
        assert_eq!(
            result.state.view.execution.workload_succeeded,
            Some(success)
        );
        assert_eq!(result.state.view.phase, TaskPhase::Finalizing);
        assert_eq!(result.state.view.outcome, TaskOutcome::Unfinished);
        assert_eq!(result.state.view.delivery.state, DeliveryState::Pending);
        assert_eq!(
            owner(&root).runtime(&task.view.task_id).unwrap(),
            result.state
        );
        assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
    }
}
#[test]
fn replayed_start_intent_never_grants_a_second_spawn_after_restart() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    let action = RuntimeAction::StartIntent {
        handle: "durable-container-identity".into(),
    };
    assert!(event(&root, id, 2, action.clone()).unwrap().applied);
    let replay = event(&root, id, 2, action).unwrap();
    assert!(!replay.applied);
    assert_eq!(
        replay.state.view.observation,
        Observation::PendingVerification
    );
    assert_eq!(
        replay.state.view.execution.state,
        ExecutionState::NotStarted
    );
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::StartIntent {
                handle: "second-container".into()
            }
        )
        .is_err()
    );
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::PrepareDeadline { now_unix: 500 }
        )
        .is_err()
    );
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::PreparationFailed {
                error: TaskError::new(TaskErrorCode::InputUnavailable, "missing", false)
            }
        )
        .is_err()
    );
    // Only adapter confirmation recovers the existing start, without spawning.
    event(&root, id, 3, RuntimeAction::Started { at_unix: 105 }).unwrap();
    assert_eq!(
        owner(&root)
            .runtime(id)
            .unwrap()
            .view
            .execution
            .started_at_unix,
        Some(105)
    );
}
#[test]
fn cancellation_before_start_finishes_without_a_process_and_is_idempotent() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    let action = RuntimeAction::Cancel {
        reason: "User".into(),
        at_unix: 101,
    };
    let first = event(&root, id, 1, action.clone()).unwrap();
    assert_eq!(first.state.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(first.state.view.execution.state, ExecutionState::NotStarted);
    assert!(!event(&root, id, 1, action.clone()).unwrap().applied);
    let again = event(
        &root,
        id,
        2,
        RuntimeAction::Cancel {
            reason: "User".into(),
            at_unix: 108,
        },
    )
    .unwrap();
    assert_eq!(again.state.view.cancellation.requested_at_unix, Some(101));
    assert!(event(&root, id, 3, RuntimeAction::Prepare).is_err());
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::Cancel {
                reason: "Revoked".into(),
                at_unix: 109
            }
        )
        .is_err()
    );
}
#[test]
fn ambiguous_spawn_cancel_requires_never_started_confirmation() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    event(
        &root,
        id,
        2,
        RuntimeAction::StartIntent {
            handle: "container".into(),
        },
    )
    .unwrap();
    let pending = event(
        &root,
        id,
        3,
        RuntimeAction::Cancel {
            reason: "Revoked".into(),
            at_unix: 102,
        },
    )
    .unwrap();
    assert_eq!(pending.state.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(
        pending.state.view.cancellation.state,
        CancellationState::Requested
    );
    let done = event(&root, id, 4, RuntimeAction::NeverStarted).unwrap();
    assert_eq!(done.state.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(done.state.view.observation, Observation::Confirmed);
}
#[test]
fn running_cancel_needs_matching_stop_reap_and_late_exit_wins() {
    let dir = Dir::new();
    let root = dir.root();
    for reason in ["User", "Revoked"] {
        let task = accept(&root, reason);
        let id = &task.view.task_id;
        start(&root, id);
        event(
            &root,
            id,
            4,
            RuntimeAction::Cancel {
                reason: reason.into(),
                at_unix: 102,
            },
        )
        .unwrap();
        assert_eq!(
            owner(&root).runtime(id).unwrap().view.cancellation.state,
            CancellationState::Requested
        );
        assert!(
            event(
                &root,
                id,
                5,
                RuntimeAction::Stopped {
                    reason: "Other".into(),
                    signal: Some("SIGKILL".into())
                }
            )
            .is_err()
        );
        let result = event(
            &root,
            id,
            5,
            RuntimeAction::Stopped {
                reason: reason.into(),
                signal: Some("SIGKILL".into()),
            },
        )
        .unwrap();
        assert_eq!(result.state.view.outcome, TaskOutcome::Cancelled);
        assert_eq!(result.state.view.execution.exit_code, None);
        assert_eq!(
            result.state.view.cancellation.state,
            CancellationState::Confirmed
        );
    }
    let task = accept(&root, "late");
    let id = &task.view.task_id;
    start(&root, id);
    event(
        &root,
        id,
        4,
        RuntimeAction::Cancel {
            reason: "User".into(),
            at_unix: 102,
        },
    )
    .unwrap();
    let result = event(&root, id, 5, RuntimeAction::Exited { exit_code: 9 }).unwrap();
    assert_eq!(
        result.state.view.cancellation.state,
        CancellationState::TooLate
    );
    assert_eq!(result.state.view.execution.exit_code, Some(9));
    assert_eq!(result.state.view.outcome, TaskOutcome::Unfinished);
    assert!(
        event(
            &root,
            id,
            6,
            RuntimeAction::Stopped {
                reason: "User".into(),
                signal: None
            }
        )
        .is_err()
    );
}
#[test]
fn confirmed_timeout_finishes_once_and_preserves_start_on_observation_loss() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    start(&root, id);
    event(&root, id, 4, RuntimeAction::ObservationLost).unwrap();
    let state = owner(&root).runtime(id).unwrap();
    assert_eq!(state.view.execution.started_at_unix, Some(101));
    assert_eq!(state.view.execution.state, ExecutionState::Running);
    assert!(
        event(
            &root,
            id,
            5,
            RuntimeAction::DeliveryDeadline { now_unix: 500 }
        )
        .is_err()
    );
    let terminal = event(
        &root,
        id,
        5,
        RuntimeAction::Stopped {
            reason: "Timeout".into(),
            signal: Some("SIGKILL".into()),
        },
    )
    .unwrap()
    .state;
    assert_eq!(terminal.view.outcome, TaskOutcome::Failed);
    assert_eq!(
        terminal.view.error.as_ref().unwrap().code,
        TaskErrorCode::Timeout
    );
    assert!(event(&root, id, 6, RuntimeAction::Exited { exit_code: 0 }).is_err());
    let uncertain = event(&root, id, 6, RuntimeAction::ObservationLost)
        .unwrap()
        .state;
    assert_eq!(uncertain.view.execution, terminal.view.execution);
    assert_eq!(uncertain.view.error, terminal.view.error);
    assert_eq!(uncertain.view.outcome, TaskOutcome::Failed);
}
#[test]
fn deadlines_are_exact_and_do_not_erase_confirmed_exit() {
    let dir = Dir::new();
    let root = dir.root();
    let waiting = accept(&root, "waiting");
    assert!(
        event(
            &root,
            &waiting.view.task_id,
            1,
            RuntimeAction::PrepareDeadline { now_unix: 109 }
        )
        .is_err()
    );
    let failed = event(
        &root,
        &waiting.view.task_id,
        1,
        RuntimeAction::PrepareDeadline { now_unix: 110 },
    )
    .unwrap();
    assert_eq!(
        failed.state.view.error.unwrap().code,
        TaskErrorCode::PrepareDeadlineExceeded
    );
    let running = accept(&root, "running");
    let id = &running.view.task_id;
    start(&root, id);
    event(&root, id, 4, RuntimeAction::Exited { exit_code: 42 }).unwrap();
    assert!(
        event(
            &root,
            id,
            5,
            RuntimeAction::DeliveryDeadline { now_unix: 199 }
        )
        .is_err()
    );
    let failed = event(
        &root,
        id,
        5,
        RuntimeAction::DeliveryDeadline { now_unix: 200 },
    )
    .unwrap();
    assert_eq!(failed.state.view.execution.exit_code, Some(42));
    assert_eq!(failed.state.view.execution.workload_succeeded, Some(true));
    assert_eq!(failed.state.view.delivery.state, DeliveryState::Failed);
}
#[test]
fn event_sequences_conflicts_and_unknown_tasks_fail_without_writing() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    let bytes = fs::read(root.join(IMAGE)).unwrap();
    assert!(event(&root, id, 2, RuntimeAction::Prepare).is_err());
    assert!(event(&root, id, 0, RuntimeAction::Prepare).is_err());
    assert!(
        event(
            &root,
            &TaskId::new("missing".into()).unwrap(),
            1,
            RuntimeAction::Prepare
        )
        .is_err()
    );
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), bytes);
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    assert!(event(&root, id, 1, RuntimeAction::ObservationLost).is_err());
    assert!(event(&root, id, 2, RuntimeAction::Started { at_unix: 101 }).is_err());
}

#[test]
fn preparation_failure_preserves_typed_error_and_cannot_forge_a_deadline() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    let before = fs::read(root.join(IMAGE)).unwrap();
    assert!(
        event(
            &root,
            id,
            2,
            RuntimeAction::PreparationFailed {
                error: TaskError::new(TaskErrorCode::PrepareDeadlineExceeded, "too early", false),
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), before);
    let error = TaskError::new(
        TaskErrorCode::UnsupportedCapability,
        "hard storage limit unavailable",
        false,
    );
    let result = event(
        &root,
        id,
        2,
        RuntimeAction::PreparationFailed {
            error: error.clone(),
        },
    )
    .unwrap();
    assert_eq!(result.state.view.outcome, TaskOutcome::Failed);
    assert_eq!(result.state.view.error, Some(error));
    assert_eq!(
        result.state.view.execution.state,
        ExecutionState::NotStarted
    );
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::Cancel {
                reason: "User".into(),
                at_unix: 103
            }
        )
        .is_err()
    );
}

#[test]
fn start_and_cancel_invalid_times_or_timeout_intent_do_not_change_history() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    event(
        &root,
        id,
        2,
        RuntimeAction::StartIntent {
            handle: "container".into(),
        },
    )
    .unwrap();
    let bytes = fs::read(root.join(IMAGE)).unwrap();
    assert!(event(&root, id, 3, RuntimeAction::Started { at_unix: 99 }).is_err());
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::Started {
                at_unix: MAX_INTEGER + 1
            }
        )
        .is_err()
    );
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::Cancel {
                reason: "User".into(),
                at_unix: 99
            }
        )
        .is_err()
    );
    assert!(
        event(
            &root,
            id,
            3,
            RuntimeAction::Cancel {
                reason: "Timeout".into(),
                at_unix: 103
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), bytes);
}
#[test]
fn handle_cannot_be_reused_across_tasks() {
    let dir = Dir::new();
    let root = dir.root();
    for key in ["one", "two"] {
        let task = accept(&root, key);
        let id = &task.view.task_id;
        event(&root, id, 1, RuntimeAction::Prepare).unwrap();
        let result = event(
            &root,
            id,
            2,
            RuntimeAction::StartIntent {
                handle: "one-run".into(),
            },
        );
        if key == "one" {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
        }
    }
}
#[test]
fn missing_or_torn_runtime_blocks_reopen_acceptance_and_gc_lock() {
    for damage in ["missing", "torn", "receipt"] {
        let dir = Dir::new();
        let root = dir.root();
        let task = accept(&root, "key");
        let store = FileTaskAcceptanceStore::open(&root).unwrap();
        start(&root, &task.view.task_id);
        let accepted = fs::read(root.join("acceptance-v1.json")).unwrap();
        match damage {
            "missing" => fs::remove_file(root.join(IMAGE)).unwrap(),
            "torn" => fs::write(root.join(IMAGE), b"{\"schema_version\":").unwrap(),
            _ => fs::write(root.join(RECEIPT), b"torn").unwrap(),
        }
        assert_eq!(
            FileTaskAcceptanceStore::open(&root).unwrap_err().code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(store.read().unwrap_err().code, TaskErrorCode::StateCorrupt);
        assert_eq!(
            store.with_locked_ledger(|_, _| Ok(())).unwrap_err().code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), accepted);
    }
}
#[test]
fn valid_checksum_cannot_hide_reordered_events_or_wrong_contract() {
    for damage in ["reorder", "contract", "task", "duplicate"] {
        let dir = Dir::new();
        let root = dir.root();
        let task = accept(&root, "key");
        let id = &task.view.task_id;
        start(&root, id);
        let ledger = FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap();
        let mut image = load_and_validate(&root, &ledger).unwrap();
        match damage {
            "reorder" => image.journals[0].events.swap(0, 1),
            "contract" => image.journals[0].contract_digest = Sha256Digest::from_bytes([0; 32]),
            "task" => image.journals[0].task_id = TaskId::new("missing".into()).unwrap(),
            _ => image.journals.push(image.journals[0].clone()),
        }
        save(&root, &image).unwrap();
        assert_eq!(
            FileTaskAcceptanceStore::open(&root).unwrap_err().code,
            TaskErrorCode::StateCorrupt
        );
    }
}
#[test]
fn symlink_fifo_and_public_runtime_authorities_are_rejected() {
    for damage in ["symlink", "fifo", "mode"] {
        let dir = Dir::new();
        let root = dir.root();
        accept(&root, "key");
        let path = root.join(IMAGE);
        if damage == "mode" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
            if damage == "symlink" {
                std::os::unix::fs::symlink("acceptance-v1.json", &path).unwrap();
            } else {
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
        assert!(FileTaskAcceptanceStore::open(&root).is_err());
    }
}
#[test]
fn migration_preserves_old_acceptance_bytes_and_publishes_empty_runtime() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    fs::remove_file(root.join(IMAGE)).unwrap();
    fs::remove_file(root.join(RECEIPT)).unwrap();
    // A genuine N3-2 root still has its original receipt, with no runtime bit.
    fs::write(
        root.join("acceptance-initialized-v1"),
        b"n3-acceptance-initialized-v1\n",
    )
    .unwrap();
    let state = owner(&root).runtime(&task.view.task_id).unwrap();
    assert_eq!(state.view, task.view);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
    assert!(root.join(RECEIPT).is_file());
}

#[test]
fn upgraded_authority_rejects_loss_of_both_runtime_files() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    start(&root, &task.view.task_id);
    fs::remove_file(root.join(IMAGE)).unwrap();
    fs::remove_file(root.join(RECEIPT)).unwrap();
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert!(!root.join(IMAGE).exists());
    assert!(!root.join(RECEIPT).exists());
}

#[test]
fn storage_rejects_rewriting_history_and_fabricating_transaction_results() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    start(&root, id);
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join(IMAGE)).unwrap();
    let error = store.runtime_transact(id, &mut |accepted, journal| {
        let state = journal.replay(accepted, sha256)?;
        journal.events.clear();
        Ok(RuntimeUpdate {
            state,
            applied: true,
        })
    });
    assert_eq!(error.unwrap_err().code, TaskErrorCode::StateCorrupt);
    let error = store.runtime_transact(id, &mut |accepted, journal| {
        let mut state = journal.replay(accepted, sha256)?;
        state.view.outcome = TaskOutcome::Completed;
        Ok(RuntimeUpdate {
            state,
            applied: true,
        })
    });
    assert_eq!(error.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), bytes);
}

#[test]
fn review_regression_unchanged_transaction_cannot_grant_spawn_permission() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    event(
        &root,
        id,
        2,
        RuntimeAction::StartIntent {
            handle: "container".into(),
        },
    )
    .unwrap();
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join(IMAGE)).unwrap();
    let error = store.runtime_transact(id, &mut |accepted, journal| {
        Ok(RuntimeUpdate {
            state: journal.replay(accepted, sha256)?,
            applied: true,
        })
    });
    assert_eq!(error.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), bytes);
    assert!(
        !event(
            &root,
            id,
            2,
            RuntimeAction::StartIntent {
                handle: "container".into()
            }
        )
        .unwrap()
        .applied
    );
}

#[test]
fn review_regression_appended_event_cannot_be_reported_as_a_replay() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join(IMAGE)).unwrap();
    let error = store.runtime_transact(id, &mut |accepted, journal| {
        journal.events.push(RuntimeEvent {
            sequence: 1,
            action: RuntimeAction::Prepare,
        });
        Ok(RuntimeUpdate {
            state: journal.replay(accepted, sha256)?,
            applied: false,
        })
    });
    assert_eq!(error.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), bytes);
}

fn lost_acceptance_does_not_reset_runtime_authority(started: bool, survivor: &str) {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    if started {
        start(&root, &task.view.task_id);
    }
    assert!(!root.join("content-sha256-v1").exists());
    let runtime = fs::read(root.join(IMAGE)).unwrap();
    let runtime_receipt = fs::read(root.join(RECEIPT)).unwrap();
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    if survivor == "image" {
        fs::remove_file(root.join(RECEIPT)).unwrap();
    }
    if survivor == "receipt" {
        fs::remove_file(root.join(IMAGE)).unwrap();
    }
    fs::remove_file(root.join("acceptance-v1.json")).unwrap();
    fs::remove_file(root.join("acceptance-initialized-v1")).unwrap();
    assert_eq!(store.read().unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(
        store.with_locked_ledger(|_, _| Ok(())).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        FileTaskAcceptanceStore::open(&root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert!(
        !root.join("acceptance-v1.json").exists(),
        "must not publish a replacement empty acceptance image"
    );
    assert!(!root.join("acceptance-initialized-v1").exists());
    if survivor != "receipt" {
        assert_eq!(fs::read(root.join(IMAGE)).unwrap(), runtime);
    } else {
        assert!(!root.join(IMAGE).exists());
    }
    if survivor != "image" {
        assert_eq!(fs::read(root.join(RECEIPT)).unwrap(), runtime_receipt);
    } else {
        assert!(!root.join(RECEIPT).exists());
    }
}

#[test]
fn review_regression_empty_runtime_still_proves_acceptance_authority_existed() {
    lost_acceptance_does_not_reset_runtime_authority(false, "both");
}

#[test]
fn review_regression_recovery_error_cannot_write_empty_acceptance_before_replay() {
    lost_acceptance_does_not_reset_runtime_authority(true, "both");
}

#[test]
fn review_regression_either_surviving_runtime_file_blocks_empty_acceptance() {
    for started in [false, true] {
        for survivor in ["image", "receipt"] {
            lost_acceptance_does_not_reset_runtime_authority(started, survivor);
        }
    }
}

#[test]
fn review_regression_transaction_cannot_batch_two_events_into_one_application() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join(IMAGE)).unwrap();
    let error = store.runtime_transact(&task.view.task_id, &mut |accepted, journal| {
        journal.events.push(RuntimeEvent {
            sequence: 1,
            action: RuntimeAction::Prepare,
        });
        journal.events.push(RuntimeEvent {
            sequence: 2,
            action: RuntimeAction::ObservationLost,
        });
        Ok(RuntimeUpdate {
            state: journal.replay(accepted, sha256)?,
            applied: true,
        })
    });
    assert_eq!(error.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), bytes);
}

fn acceptance_removal_is_rejected(started: bool) {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    if started {
        start(&root, &task.view.task_id);
    }
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let before = fs::read(root.join("acceptance-v1.json")).unwrap();
    let runtime = fs::read(root.join(IMAGE)).unwrap();
    let result = store.transact(&mut |ledger| {
        ledger.tasks.clear();
        ledger.idempotency.clear();
        Ok(AcceptanceResult {
            task: task.clone(),
            replayed: true,
        })
    });
    assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), before);
    assert_eq!(fs::read(root.join(IMAGE)).unwrap(), runtime);
    assert_eq!(store.read().unwrap().tasks, vec![task]);
    FileTaskAcceptanceStore::open(&root).unwrap();
}

#[test]
fn review_r2_regression_acceptance_cannot_remove_a_task_with_start_intent() {
    acceptance_removal_is_rejected(true);
}

#[test]
fn review_r2_regression_acceptance_is_immutable_before_first_runtime_event() {
    acceptance_removal_is_rejected(false);
}

#[test]
fn review_r2_regression_valid_accepted_contract_cannot_replace_the_original() {
    let dir = Dir::new();
    let root = dir.root();
    accept(&root, "key");
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    let result = store.transact(&mut |ledger| {
        let task = &mut ledger.tasks[0];
        let contract = &mut task.view.accepted_contract;
        contract.request.limits.log_bytes += 1;
        contract.request_digest = contract.request.request_digest(sha256)?;
        task.view.contract_digest = contract.contract_digest(sha256)?;
        ledger.idempotency[0].request_digest = contract.request_digest.clone();
        // This is structurally/digest valid. Immutability must still reject it.
        let task = task.clone();
        ledger.validate(sha256)?;
        Ok(AcceptanceResult {
            task,
            replayed: true,
        })
    });
    assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
}

#[test]
fn review_r2_regression_acceptance_cannot_acknowledge_an_unstored_task() {
    let dir = Dir::new();
    let root = dir.root();
    let mut task = accept(&root, "key");
    task.view.task_id = TaskId::new("unsaved-task".into()).unwrap();
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    let result = store.transact(&mut |_| {
        Ok(AcceptanceResult {
            task: task.clone(),
            replayed: false,
        })
    });
    assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
}

#[test]
fn acceptance_transaction_cannot_call_an_existing_task_new() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    let result = store.transact(&mut |_| {
        Ok(AcceptanceResult {
            task: task.clone(),
            replayed: false,
        })
    });
    assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
}

#[test]
fn acceptance_replay_uses_current_scoped_index_while_retaining_old_task() {
    let dir = Dir::new();
    let root = dir.root();
    let old = accept(&root, "key");
    let contract = &old.view.accepted_contract;
    let now = contract.idempotency_expires_at_unix;
    let context = AcceptanceContext {
        authenticated_principal: contract.authenticated_principal.clone(),
        provider: contract.request.provider.clone(),
        environment_evidence: contract.environment_evidence.clone(),
        capacity_reservation_id: contract.capacity_reservation_id.clone(),
        now_unix: now,
        prepare_deadline_unix: now + 10,
        delivery_deadline_unix: now + 100,
    };
    let current = owner(&root)
        .accept_verified(contract.request.clone(), context.clone())
        .unwrap();
    assert!(!current.replayed);
    assert_ne!(current.task.view.task_id, old.view.task_id);
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let bytes = fs::read(root.join("acceptance-v1.json")).unwrap();
    let result = store.transact(&mut |_| {
        Ok(AcceptanceResult {
            task: old.clone(),
            replayed: true,
        })
    });
    assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert_eq!(fs::read(root.join("acceptance-v1.json")).unwrap(), bytes);
    assert!(store.read().unwrap().tasks.contains(&old));
    let replay = owner(&root)
        .accept_verified(contract.request.clone(), context)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.task, current.task);
}
#[test]
fn fault_boundaries_return_errors_and_replay_ambiguous_start_without_spawn_permission() {
    for boundary in [
        "after_write",
        "after_file_sync",
        "after_rename",
        "after_directory_sync",
    ] {
        let dir = Dir::new();
        let root = dir.root();
        let task = accept(&root, "key");
        let id = &task.view.task_id;
        event(&root, id, 1, RuntimeAction::Prepare).unwrap();
        let ledger = FileTaskAcceptanceStore::open(&root)
            .unwrap()
            .read()
            .unwrap();
        let mut image = load_and_validate(&root, &ledger).unwrap();
        let action = RuntimeAction::StartIntent {
            handle: "container".into(),
        };
        image.journals[0].events.push(RuntimeEvent {
            sequence: 2,
            action: action.clone(),
        });
        let error = save_with(&root, &image, &mut |point| {
            if point == boundary {
                Err(TaskError::new(
                    TaskErrorCode::PersistenceFailed,
                    "injected",
                    true,
                ))
            } else {
                Ok(())
            }
        });
        assert!(error.is_err());
        let committed = ["after_rename", "after_directory_sync"].contains(&boundary);
        let replay = event(&root, id, 2, action).unwrap();
        assert_eq!(replay.applied, !committed);
        assert_eq!(
            replay.state.view.observation,
            Observation::PendingVerification
        );
    }
}

fn child(root: &Path, mode: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "task_runtime_store::tests::subprocess_worker",
            "--ignored",
            "--exact",
        ])
        .env("NEXUS_N3_RUNTIME_ROOT", root)
        .env("NEXUS_N3_RUNTIME_MODE", mode)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}
#[test]
fn real_process_crashes_preserve_monotonic_start_authority() {
    for boundary in [
        "after_write",
        "after_file_sync",
        "after_rename",
        "after_directory_sync",
    ] {
        let dir = Dir::new();
        let root = dir.root();
        let task = accept(&root, "key");
        let id = &task.view.task_id;
        event(&root, id, 1, RuntimeAction::Prepare).unwrap();
        assert_eq!(child(&root, boundary).wait().unwrap().code(), Some(91));
        let committed = ["after_rename", "after_directory_sync"].contains(&boundary);
        let state = owner(&root).runtime(id).unwrap();
        assert_eq!(state.view.last_event_seq, if committed { 2 } else { 1 });
        assert_eq!(
            event(
                &root,
                id,
                2,
                RuntimeAction::StartIntent {
                    handle: "container".into()
                }
            )
            .unwrap()
            .applied,
            !committed
        );
    }
}
#[test]
fn eight_processes_race_one_durable_start_intent() {
    let dir = Dir::new();
    let root = dir.root();
    let task = accept(&root, "key");
    let id = &task.view.task_id;
    event(&root, id, 1, RuntimeAction::Prepare).unwrap();
    let mut workers: Vec<_> = (0..8).map(|_| child(&root, "race")).collect();
    let results: Vec<_> = workers
        .iter_mut()
        .map(|c| c.wait().unwrap().code().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|&&code| code == 10).count(), 1);
    assert_eq!(results.iter().filter(|&&code| code == 11).count(), 7);
    assert_eq!(owner(&root).runtime(id).unwrap().view.last_event_seq, 2);
}
#[test]
#[ignore = "subprocess fixture explicitly invoked 12 times by parent tests"]
fn subprocess_worker() {
    let root = PathBuf::from(std::env::var_os("NEXUS_N3_RUNTIME_ROOT").unwrap());
    let mode = std::env::var("NEXUS_N3_RUNTIME_MODE").unwrap();
    let store = FileTaskAcceptanceStore::open(&root).unwrap();
    let task = store.read().unwrap().tasks[0].clone();
    if mode == "race" {
        let update = event(
            &root,
            &task.view.task_id,
            2,
            RuntimeAction::StartIntent {
                handle: "container".into(),
            },
        )
        .unwrap();
        std::process::exit(if update.applied { 10 } else { 11 });
    }
    store
        .with_locked_ledger(|root, accepted| {
            let mut image = load_and_validate(root, accepted)?;
            image.journals[0].events.push(RuntimeEvent {
                sequence: 2,
                action: RuntimeAction::StartIntent {
                    handle: "container".into(),
                },
            });
            save_with(root, &image, &mut |point| {
                if point == mode {
                    std::process::exit(91)
                } else {
                    Ok(())
                }
            })
        })
        .unwrap();
    panic!("fault point not reached");
}
