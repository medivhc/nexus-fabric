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
fn scope() -> RequesterScope<'static> {
    RequesterScope {
        principal: "verified",
        provider: "provider",
        workspace: "ws",
    }
}
#[test]
fn cancel_and_ack_never_write_provider_facts() {
    let original = waiting();
    let mut m = RequesterMirror::new(original.clone(), scope(), hash).unwrap();
    m.queue_cancel(scope(), CancelReason::User, 101).unwrap();
    assert_eq!(m.provider_view(), &original);
    assert_eq!(m.view().cancellation.state, CancellationState::None);
    assert_eq!(m.view().outcome, TaskOutcome::Unfinished);
    assert_eq!(m.view().observation, Observation::PendingVerification);
    m.queue_cancel(scope(), CancelReason::User, 102).unwrap();
    assert_eq!(m.view().cancel_request.requested_at_unix, Some(101));
    m.settle_cancel(scope(), &waiting().task_id, None).unwrap();
    m.settle_cancel(scope(), &waiting().task_id, None).unwrap();
    assert_eq!(
        m.view().cancel_request.state,
        CancelRequestState::Acknowledged
    );
    assert_eq!(m.provider_view(), &original);
    m.validate(hash).unwrap();
}
#[test]
fn same_sequence_conflicts_and_identity_mutation_fail_closed() {
    let mut m = RequesterMirror::new(waiting(), scope(), hash).unwrap();
    m.disconnected();
    m.receive(waiting(), scope(), hash).unwrap();
    assert_eq!(m.view().observation, Observation::Confirmed);
    let mut v = waiting();
    v.observation = Observation::PendingVerification;
    assert!(m.receive(v, scope(), hash).is_err());
    let mut v = waiting();
    v.last_event_seq = 1;
    v.phase = TaskPhase::Preparing;
    m.receive(v.clone(), scope(), hash).unwrap();
    assert!(m.receive(waiting(), scope(), hash).is_err());
    v.accepted_contract.authenticated_principal = "other".into();
    assert!(m.receive(v, scope(), hash).is_err());
}
#[test]
fn rejection_is_durable_intent_state_not_task_failure() {
    let mut m = RequesterMirror::new(waiting(), scope(), hash).unwrap();
    assert!(m.settle_cancel(scope(), &waiting().task_id, None).is_err());
    m.queue_cancel(scope(), CancelReason::Revoked, 101).unwrap();
    assert!(m.queue_cancel(scope(), CancelReason::User, 102).is_err());
    let e = TaskError::new(TaskErrorCode::AuthDenied, "revoked request rejected", false);
    m.settle_cancel(scope(), &waiting().task_id, Some(e.clone()))
        .unwrap();
    m.settle_cancel(scope(), &waiting().task_id, Some(e.clone()))
        .unwrap();
    assert!(m.settle_cancel(scope(), &waiting().task_id, None).is_err());
    assert_eq!(m.view().cancel_request.error, Some(e));
    assert_eq!(m.view().outcome, TaskOutcome::Unfinished);
    assert_eq!(m.view().cancellation.state, CancellationState::None);
    let decoded = RequesterMirror::from_value(m.to_value()).unwrap();
    decoded.validate(hash).unwrap();
    assert_eq!(decoded, m);
}
#[test]
fn disconnect_preserves_execution_result_and_terminal_cancel_remains_pending() {
    let mut v = waiting();
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Completed;
    v.execution = TaskExecution {
        state: ExecutionState::Exited,
        started_at_unix: Some(101),
        exit_code: Some(0),
        signal: None,
        stop_reason: None,
        result_confirmed: true,
        workload_succeeded: Some(true),
    };
    v.delivery.state = DeliveryState::Complete;
    v.last_event_seq = 5;
    let mut m = RequesterMirror::new(v.clone(), scope(), hash).unwrap();
    m.queue_cancel(scope(), CancelReason::User, 105).unwrap();
    m.disconnected();
    assert_eq!(m.view().execution, v.execution);
    assert_eq!(m.view().outcome, v.outcome);
    m.receive(v.clone(), scope(), hash).unwrap();
    assert!(m.cancel_pending());
    let mut overwrite = v;
    overwrite.last_event_seq = 6;
    overwrite.execution.exit_code = Some(42);
    assert!(m.receive(overwrite, scope(), hash).is_err());
}
#[test]
fn malformed_persisted_intent_and_scope_are_rejected() {
    let mut m = RequesterMirror::new(waiting(), scope(), hash).unwrap();
    let wrong = RequesterScope {
        principal: "forged",
        ..scope()
    };
    assert!(m.queue_cancel(wrong, CancelReason::User, 101).is_err());
    assert!(m.queue_cancel(scope(), CancelReason::User, 99).is_err());
    assert!(
        m.queue_cancel(scope(), CancelReason::User, MAX_INTEGER + 1)
            .is_err()
    );
    m.intent.reason = Some("Timeout".into());
    m.intent.state = CancelRequestState::Queued;
    m.intent.requested_at_unix = Some(101);
    assert!(m.validate(hash).is_err());
}
#[test]
fn cross_task_cancel_response_and_wrong_provider_preserve_pending_intent() {
    let mut m = RequesterMirror::new(waiting(), scope(), hash).unwrap();
    m.queue_cancel(scope(), CancelReason::User, 101).unwrap();
    let before = m.clone();
    let other = TaskId::new("different-task".into()).unwrap();
    let e = TaskError::new(TaskErrorCode::AuthDenied, "provider rejected", false);
    assert!(m.settle_cancel(scope(), &other, Some(e.clone())).is_err());
    assert!(m.settle_cancel(scope(), &other, None).is_err());
    assert_eq!(m, before);
    let wrong = RequesterScope {
        provider: "foreign-provider",
        ..scope()
    };
    assert_eq!(
        m.settle_cancel(wrong, &waiting().task_id, Some(e))
            .unwrap_err()
            .code,
        TaskErrorCode::AuthDenied
    );
    assert_eq!(m, before);
}
