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

fn hash(_: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes([0; 32])
}

fn state() -> RuntimeState {
    RuntimeState {
        view: waiting(),
        execution_handle: None,
    }
}
#[test]
fn attached_session_is_a_deduplicated_link_not_execution_or_outcome() {
    let mut state = state();
    let original = state.view.accepted_contract.clone();
    for sequence in [1, 2] {
        apply(
            &mut state,
            &RuntimeEvent {
                sequence,
                action: RuntimeAction::SessionAttached {
                    session_id: "sess-real".into(),
                },
            },
            hash,
        )
        .unwrap();
    }
    assert_eq!(state.view.session_ids, ["sess-real"]);
    assert_eq!(state.view.last_event_seq, 2);
    assert_eq!(state.view.accepted_contract, original);
    assert_eq!(state.view.phase, TaskPhase::Waiting);
    assert_eq!(state.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(state.execution_handle, None);
    assert!(
        apply(
            &mut state,
            &RuntimeEvent {
                sequence: 3,
                action: RuntimeAction::StartIntent {
                    handle: "not-prepared".into()
                }
            },
            hash
        )
        .is_err()
    );
}
#[test]
fn attached_session_codec_is_strict_and_rejects_invalid_identity() {
    let action = RuntimeAction::SessionAttached {
        session_id: "sess-real".into(),
    };
    assert_eq!(
        RuntimeAction::from_value(action.to_value()).unwrap(),
        action
    );
    let mut object = match action.to_value() {
        Value::Object(object) => object,
        _ => unreachable!(),
    };
    object.insert("provider".into(), "forged".to_owned().to_value());
    assert!(RuntimeAction::from_value(Value::Object(object)).is_err());
    let mut state = state();
    for invalid in ["", "bad\0id"] {
        assert!(
            apply(
                &mut state,
                &RuntimeEvent {
                    sequence: 1,
                    action: RuntimeAction::SessionAttached {
                        session_id: invalid.into()
                    }
                },
                hash
            )
            .is_err()
        );
    }
    assert!(state.view.session_ids.is_empty());
}
#[test]
fn terminal_task_cannot_acquire_a_new_session() {
    let mut state = state();
    apply(
        &mut state,
        &RuntimeEvent {
            sequence: 1,
            action: RuntimeAction::Cancel {
                reason: "User".into(),
                at_unix: 101,
            },
        },
        hash,
    )
    .unwrap();
    let original = state.clone();
    assert!(
        apply(
            &mut state,
            &RuntimeEvent {
                sequence: 2,
                action: RuntimeAction::SessionAttached {
                    session_id: "sess-too-late".into()
                }
            },
            hash
        )
        .is_err()
    );
    assert_eq!(state, original);
}
