use super::*;
fn waiting() -> TaskView {
    let digest = Sha256Digest::from_bytes([0; 32]);
    let env = EnvironmentRequirement {
        os: "linux".into(),
        architecture: "x86_64".into(),
        image_digest: digest.clone(),
        isolation: "container".into(),
        network: "none".into(),
    };
    TaskView {
        schema_version: 1,
        task_id: TaskId::new("test-task".into()).unwrap(),
        contract_digest: digest.clone(),
        accepted_contract: AcceptedContract {
            request: SubmitTaskRequest {
                schema_version: 1,
                workspace: "ws".into(),
                resource: "compute".into(),
                provider: "provider".into(),
                input_snapshot: SnapshotRef {
                    schema_version: 1,
                    snapshot_id: digest.clone(),
                    workspace: "ws".into(),
                    commit_id: "commit".into(),
                    root_manifest_id: "manifest".into(),
                    manifest_sha256: digest.clone(),
                    selection_digest: digest.clone(),
                    file_count: 0,
                    total_bytes: 0,
                },
                command: vec!["test".into()],
                cwd: ".".into(),
                environment: env.clone(),
                limits: TaskLimits {
                    timeout_seconds: 10,
                    cpu_millis: 1000,
                    memory_bytes: 1024,
                    storage_bytes: 1024,
                    log_bytes: 1024,
                },
                outputs: vec![],
                success_exit_codes: vec![0],
                idempotency_key: "key".into(),
                idempotency_ttl_seconds: 60,
            },
            request_digest: digest,
            authenticated_principal: "verified".into(),
            environment_evidence: env,
            capacity_reservation_id: "reserved".into(),
            accepted_at_unix: 100,
            idempotency_expires_at_unix: 160,
            prepare_deadline_unix: 110,
            delivery_deadline_unix: 200,
        },
        phase: TaskPhase::Waiting,
        outcome: TaskOutcome::Unfinished,
        error: None,
        execution: TaskExecution {
            state: ExecutionState::NotStarted,
            started_at_unix: None,
            exit_code: None,
            signal: None,
            stop_reason: None,
            result_confirmed: false,
            workload_succeeded: None,
        },
        delivery: TaskDelivery {
            state: DeliveryState::Pending,
            error: None,
        },
        cancellation: TaskCancellation {
            state: CancellationState::None,
            reason: None,
            requested_at_unix: None,
        },
        cancel_request: CancelRequestIntent {
            origin: IntentOrigin::RequesterIntent,
            state: CancelRequestState::None,
            requested_at_unix: None,
            reason: None,
            error: None,
        },
        observation: Observation::Confirmed,
        last_event_seq: 0,
        session_ids: vec![],
        artifact_ids: vec![],
    }
}
fn execution(state: ExecutionState) -> TaskExecution {
    match state {
        ExecutionState::NotStarted => waiting().execution,
        ExecutionState::Running => TaskExecution {
            state,
            started_at_unix: Some(101),
            exit_code: None,
            signal: None,
            stop_reason: None,
            result_confirmed: false,
            workload_succeeded: None,
        },
        ExecutionState::Exited => TaskExecution {
            state,
            started_at_unix: Some(101),
            exit_code: Some(0),
            signal: None,
            stop_reason: None,
            result_confirmed: true,
            workload_succeeded: Some(true),
        },
        ExecutionState::Stopped => TaskExecution {
            state,
            started_at_unix: Some(101),
            exit_code: None,
            signal: Some("SIGTERM".into()),
            stop_reason: Some("Timeout".into()),
            result_confirmed: true,
            workload_succeeded: None,
        },
    }
}
#[test]
fn phase_outcome_execution_delivery_matrix_has_exact_legal_combinations() {
    let phases = [
        TaskPhase::Waiting,
        TaskPhase::Preparing,
        TaskPhase::Running,
        TaskPhase::Finalizing,
        TaskPhase::Finished,
    ];
    let outcomes = [
        TaskOutcome::Unfinished,
        TaskOutcome::Completed,
        TaskOutcome::Failed,
        TaskOutcome::Cancelled,
    ];
    let execs = [
        ExecutionState::NotStarted,
        ExecutionState::Running,
        ExecutionState::Exited,
        ExecutionState::Stopped,
    ];
    let deliveries = [
        DeliveryState::Pending,
        DeliveryState::Complete,
        DeliveryState::Failed,
        DeliveryState::NotRequired,
    ];
    let allowed = [
        (
            TaskPhase::Waiting,
            TaskOutcome::Unfinished,
            ExecutionState::NotStarted,
            DeliveryState::Pending,
        ),
        (
            TaskPhase::Preparing,
            TaskOutcome::Unfinished,
            ExecutionState::NotStarted,
            DeliveryState::Pending,
        ),
        (
            TaskPhase::Running,
            TaskOutcome::Unfinished,
            ExecutionState::Running,
            DeliveryState::Pending,
        ),
        (
            TaskPhase::Finalizing,
            TaskOutcome::Unfinished,
            ExecutionState::Exited,
            DeliveryState::Pending,
        ),
        (
            TaskPhase::Finalizing,
            TaskOutcome::Unfinished,
            ExecutionState::Stopped,
            DeliveryState::Pending,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Completed,
            ExecutionState::Exited,
            DeliveryState::Complete,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Failed,
            ExecutionState::Exited,
            DeliveryState::Complete,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Failed,
            ExecutionState::Exited,
            DeliveryState::Failed,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Failed,
            ExecutionState::NotStarted,
            DeliveryState::NotRequired,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Failed,
            ExecutionState::Stopped,
            DeliveryState::NotRequired,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Cancelled,
            ExecutionState::NotStarted,
            DeliveryState::NotRequired,
        ),
        (
            TaskPhase::Finished,
            TaskOutcome::Cancelled,
            ExecutionState::Stopped,
            DeliveryState::NotRequired,
        ),
    ];
    for phase in phases {
        for outcome in outcomes {
            for ex in execs {
                for delivery in deliveries {
                    let mut v = waiting();
                    v.phase = phase;
                    v.outcome = outcome;
                    v.execution = execution(ex);
                    v.delivery.state = delivery;
                    if outcome == TaskOutcome::Failed {
                        let code = match ex {
                            ExecutionState::NotStarted => TaskErrorCode::PrepareDeadlineExceeded,
                            ExecutionState::Stopped => TaskErrorCode::Timeout,
                            ExecutionState::Exited if delivery == DeliveryState::Complete => {
                                v.execution.exit_code = Some(7);
                                v.execution.workload_succeeded = Some(false);
                                TaskErrorCode::WorkloadExit
                            }
                            _ => TaskErrorCode::ArtifactMissing,
                        };
                        v.error = Some(TaskError::new(code, "test failure", false));
                    }
                    if delivery == DeliveryState::Failed {
                        v.delivery.error = Some(TaskError::new(
                            TaskErrorCode::ArtifactMissing,
                            "missing required output",
                            false,
                        ));
                    }
                    if outcome == TaskOutcome::Cancelled {
                        if ex == ExecutionState::Stopped {
                            v.execution.stop_reason = Some("User".into());
                        }
                        v.cancellation = TaskCancellation {
                            state: CancellationState::Confirmed,
                            reason: Some("User".into()),
                            requested_at_unix: Some(102),
                        };
                    }
                    assert_eq!(
                        v.validate().is_ok(),
                        allowed.contains(&(phase, outcome, ex, delivery)),
                        "{phase:?}/{outcome:?}/{ex:?}/{delivery:?}"
                    );
                }
            }
        }
    }
}
#[test]
fn execution_state_facts_are_never_invented() {
    for state in [
        ExecutionState::NotStarted,
        ExecutionState::Running,
        ExecutionState::Exited,
        ExecutionState::Stopped,
    ] {
        let base = execution(state);
        base.validate().unwrap();
        for mutate in [
            |e: &mut TaskExecution| e.exit_code = Some(7),
            |e: &mut TaskExecution| e.result_confirmed = !e.result_confirmed,
            |e: &mut TaskExecution| e.started_at_unix = None,
            |e: &mut TaskExecution| e.signal = Some("SIGKILL".into()),
            |e: &mut TaskExecution| e.workload_succeeded = Some(false),
        ] {
            let mut e = base.clone();
            mutate(&mut e);
            match state {
                ExecutionState::NotStarted | ExecutionState::Running => {
                    if e != base {
                        assert!(e.validate().is_err());
                    }
                }
                ExecutionState::Exited => {
                    if e.exit_code.is_none()
                        || !e.result_confirmed
                        || e.started_at_unix.is_none()
                        || e.signal.is_some()
                    {
                        assert!(e.validate().is_err());
                    }
                }
                ExecutionState::Stopped => {
                    if e.exit_code.is_some()
                        || !e.result_confirmed
                        || e.workload_succeeded.is_some()
                        || e.started_at_unix.is_none()
                    {
                        assert!(e.validate().is_err());
                    }
                }
            }
        }
    }
}
#[test]
fn nonzero_exit_requires_failed_result_and_retryable_delivery_remains_unfinished() {
    let mut v = waiting();
    v.phase = TaskPhase::Finalizing;
    v.execution = execution(ExecutionState::Exited);
    v.execution.exit_code = Some(7);
    v.execution.workload_succeeded = Some(false);
    v.delivery.error = Some(TaskError::new(
        TaskErrorCode::ArtifactUnavailable,
        "retry upload",
        true,
    ));
    v.validate().unwrap();
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Completed;
    v.delivery = TaskDelivery {
        state: DeliveryState::Complete,
        error: None,
    };
    assert!(v.validate().is_err());
    v.outcome = TaskOutcome::Failed;
    v.error = Some(TaskError::new(TaskErrorCode::WorkloadExit, "exit 7", false));
    v.validate().unwrap();
    v.execution.workload_succeeded = Some(true);
    assert!(v.validate().is_err());
    v.execution.workload_succeeded = Some(false);
    v.accepted_contract.request.success_exit_codes.push(7);
    assert!(v.validate().is_err());
}
#[test]
fn requester_cancel_and_observation_do_not_override_provider_facts() {
    let mut v = waiting();
    v.observation = Observation::PendingVerification;
    v.cancel_request = CancelRequestIntent {
        origin: IntentOrigin::RequesterIntent,
        state: CancelRequestState::Queued,
        requested_at_unix: Some(101),
        reason: Some("User".into()),
        error: None,
    };
    v.validate().unwrap();
    assert_eq!(v.outcome, TaskOutcome::Unfinished);
    assert_eq!(v.cancellation.state, CancellationState::None);
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Cancelled;
    v.delivery.state = DeliveryState::NotRequired;
    assert!(v.validate().is_err());
    v.cancellation = TaskCancellation {
        state: CancellationState::Confirmed,
        reason: Some("User".into()),
        requested_at_unix: Some(101),
    };
    v.validate().unwrap();
    v.cancel_request.state = CancelRequestState::Rejected;
    assert!(v.validate().is_err());
    v.cancel_request.error = Some(TaskError::new(TaskErrorCode::AuthDenied, "revoked", false));
    v.validate().unwrap();
}
#[test]
fn provider_events_are_monotonic_and_terminal_results_cannot_be_rewritten() {
    let first = waiting();
    let mut running = first.clone();
    running.phase = TaskPhase::Running;
    running.execution = execution(ExecutionState::Running);
    running.last_event_seq = 2;
    validate_provider_transition(&first, &running).unwrap();
    assert!(validate_provider_transition(&running, &first).is_err());
    let mut finished = running.clone();
    finished.phase = TaskPhase::Finished;
    finished.outcome = TaskOutcome::Completed;
    finished.execution = execution(ExecutionState::Exited);
    finished.delivery.state = DeliveryState::Complete;
    finished.last_event_seq = 3;
    validate_provider_transition(&running, &finished).unwrap();
    validate_provider_transition(&finished, &finished).unwrap();
    let mut changed = finished.clone();
    changed.last_event_seq = 4;
    changed.outcome = TaskOutcome::Failed;
    changed.error = Some(TaskError::new(
        TaskErrorCode::DeliveryDeadlineExceeded,
        "late failure",
        false,
    ));
    assert!(validate_provider_transition(&finished, &changed).is_err());
    let mut late = finished.clone();
    late.last_event_seq = 4;
    late.cancellation = TaskCancellation {
        state: CancellationState::TooLate,
        reason: Some("User".into()),
        requested_at_unix: Some(102),
    };
    validate_provider_transition(&finished, &late).unwrap();
    let mut reset = running.clone();
    reset.last_event_seq = 3;
    reset.execution.started_at_unix = Some(102);
    assert!(validate_provider_transition(&running, &reset).is_err());
}

#[test]
fn stopped_start_identity_cancellation_and_failure_reason_must_agree() {
    let mut stopped = execution(ExecutionState::Stopped);
    stopped.started_at_unix = None;
    stopped.signal = None;
    assert!(stopped.validate().is_err());
    let mut v = waiting();
    v.cancellation = TaskCancellation {
        state: CancellationState::TooLate,
        reason: Some("User".into()),
        requested_at_unix: Some(101),
    };
    assert!(v.validate().is_err());
    v.cancellation.state = CancellationState::None;
    v.cancellation.reason = None;
    v.cancellation.requested_at_unix = None;
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Failed;
    v.execution = execution(ExecutionState::Stopped);
    v.delivery.state = DeliveryState::NotRequired;
    v.error = Some(TaskError::new(TaskErrorCode::Timeout, "timeout", false));
    v.validate().unwrap();
    v.execution.stop_reason = Some("Revoked".into());
    assert!(v.validate().is_err());
    let mut v = waiting();
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Failed;
    v.execution = execution(ExecutionState::Exited);
    v.delivery.state = DeliveryState::Complete;
    v.error = Some(TaskError::new(
        TaskErrorCode::ArtifactMissing,
        "missing",
        false,
    ));
    assert!(v.validate().is_err());
}

#[test]
fn timeout_cannot_be_reclassified_by_a_cancel_race_or_generic_failure() {
    let mut v = waiting();
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Cancelled;
    v.execution = execution(ExecutionState::Stopped);
    v.delivery.state = DeliveryState::NotRequired;
    v.cancellation = TaskCancellation {
        state: CancellationState::Confirmed,
        reason: Some("User".into()),
        requested_at_unix: Some(102),
    };
    assert!(v.validate().is_err());
    v.outcome = TaskOutcome::Failed;
    v.error = Some(TaskError::new(
        TaskErrorCode::CapacityUnavailable,
        "unrelated",
        false,
    ));
    assert!(v.validate().is_err());
    v.error = Some(TaskError::new(
        TaskErrorCode::Timeout,
        "confirmed timeout",
        false,
    ));
    v.validate().unwrap();
    v.outcome = TaskOutcome::Cancelled;
    v.error = None;
    v.execution.stop_reason = Some("User".into());
    v.validate().unwrap();
    v.execution.stop_reason = Some("Revoked".into());
    assert!(v.validate().is_err());
    v.cancellation.reason = Some("Revoked".into());
    v.validate().unwrap();
    v.execution.stop_reason = Some("Signal".into());
    assert!(v.validate().is_err());
}
