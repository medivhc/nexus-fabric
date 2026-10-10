use super::*;

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_waiting_does_not_create_execution_authority() {
    let f = Fixture::new(&["/bin/sleep", "1"], |_| {});
    let before = f.executor.owner.runtime(&f.id).unwrap();
    assert_eq!(f.executor.reconcile(&f.id).unwrap(), before);
    assert!(!f.root.join("executions-v1").exists());
}

fn child(f: &Fixture, pause: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "task_executor::tests::executor_process_fixture",
        ])
        .env("NEXUS_N3_FIXTURE_ROOT", &f.root)
        .env("NEXUS_N3_FIXTURE_TASK", f.id.as_str())
        .env("NEXUS_N3_RECOVERY_PAUSE", pause)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}
fn wait(f: &Fixture, child: &mut std::process::Child, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        if child.try_wait().unwrap().is_some() {
            panic!("owner fixture exited before boundary");
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("recovery boundary was not reached");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = f;
}
fn kill(child: &mut std::process::Child) {
    use std::os::unix::process::ExitStatusExt;
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(9));
}
fn execution_logs(f: &Fixture) -> Logs {
    let state = f.executor.owner.runtime(&f.id).unwrap();
    Logs::open(
        &f.root,
        &f.id,
        &state.view.contract_digest,
        f.contract.request.limits.log_bytes,
    )
    .unwrap()
}
fn one_start(f: &Fixture, handle: &Option<String>) {
    use nexus_compute::task_runtime::TaskRuntimeStore;
    let (_, journal) = FileTaskAcceptanceStore::open(&f.root)
        .unwrap()
        .runtime_read(&f.id)
        .unwrap();
    assert_eq!(
        journal
            .events
            .iter()
            .filter(|e| matches!(e.action, RuntimeAction::StartIntent { .. }))
            .count(),
        1
    );
    assert_eq!(
        f.executor.owner.runtime(&f.id).unwrap().execution_handle,
        *handle
    );
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_owner_sigkill_keeps_unknown_then_reaps_original_cancel() {
    let f = Fixture::new(&["/bin/sh", "-c", "printf retained; sleep 60"], |_| {});
    let mut process = child(&f, "");
    wait(&f, &mut process, || {
        f.executor.owner.runtime(&f.id).unwrap().view.phase == TaskPhase::Running
    });
    let original = f.executor.owner.runtime(&f.id).unwrap();
    let original_budget = fs::read(execution_logs(&f).directory.join("started-v1.json")).unwrap();
    assert_eq!(
        f.executor.reconcile(&f.id).unwrap_err().code,
        TaskErrorCode::CapacityUnavailable
    );
    kill(&mut process);
    let recovered = LinuxTaskExecutor::open(&f.root, f.executor.images.clone()).unwrap();
    let unknown = recovered.reconcile(&f.id).unwrap();
    assert_eq!(unknown.view.execution.state, ExecutionState::Running);
    assert_eq!(unknown.view.observation, Observation::PendingVerification);
    assert_eq!(unknown.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(
        Docker.inspect(&f.container()).unwrap()["State"]["Running"],
        true
    );
    one_start(&f, &original.execution_handle);
    assert_eq!(
        fs::read(execution_logs(&f).directory.join("started-v1.json")).unwrap(),
        original_budget
    );
    recovered.cancel(&f.id, "Revoked").unwrap();
    let stopped = recovered.reconcile(&f.id).unwrap();
    assert_eq!(stopped.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(
        stopped.view.cancellation.state,
        CancellationState::Confirmed
    );
    assert_eq!(stopped.view.execution.state, ExecutionState::Stopped);
    assert_eq!(
        stopped.view.execution.stop_reason.as_deref(),
        Some("Revoked")
    );
    assert_eq!(stopped.view.execution.exit_code, None);
    f.assert_reaped();
    assert!(
        !recovered
            .logs(&f.id, LogStream::Stdout, 0, 65536)
            .unwrap()
            .eof
    );
    assert_eq!(recovered.reconcile(&f.id).unwrap(), stopped);
    assert_eq!(
        LinuxTaskExecutor::open(&f.root, f.executor.images.clone())
            .unwrap()
            .owner
            .runtime(&f.id)
            .unwrap(),
        stopped
    );
    let next = TaskId::new("another-request".into()).unwrap();
    recovered.validate_admission(&next).unwrap();
    fs::remove_file(execution_logs(&f).directory.join("reaped-v1.json")).unwrap();
    assert_eq!(
        recovered.validate_admission(&next).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    one_start(&f, &original.execution_handle);
    println!(
        "SIGKILL owner: original Engine identity retained, active lease refused; unknown did not restart; Revoked stopped/reaped same namespace; lost EOF remains false; missing reap blocks new admission"
    );
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_startintent_sigkill_real_exec_remains_pending_without_restart() {
    let f = Fixture::new(&["/bin/sleep", "60"], |_| {});
    let mut process = child(&f, "before_started_event");
    let path = f
        .root
        .join("executions-v1")
        .join(&sha256(f.id.as_str().as_bytes()).as_str()[7..])
        .join("recovery-test-ready");
    wait(&f, &mut process, || path.exists());
    let original = f.executor.owner.runtime(&f.id).unwrap();
    assert_eq!(original.view.execution.state, ExecutionState::NotStarted);
    let exec = original
        .execution_handle
        .as_ref()
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap();
    assert_eq!(Docker.exec_inspect(exec).unwrap()["Running"], true);
    kill(&mut process);
    let recovered = LinuxTaskExecutor::open(&f.root, f.executor.images.clone()).unwrap();
    let unknown = recovered.reconcile(&f.id).unwrap();
    assert_eq!(unknown.view.execution.state, ExecutionState::NotStarted);
    assert_eq!(unknown.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(unknown.view.observation, Observation::PendingVerification);
    assert_eq!(Docker.exec_inspect(exec).unwrap()["Running"], true);
    assert_eq!(
        recovered.run(&f.id, &mut |_| Ok(())).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    one_start(&f, &original.execution_handle);
    Docker.stop(&f.container()).unwrap();
    f.assert_reaped();
    println!(
        "SIGKILL between started proof and Started journal: real original exec running, runtime remains ambiguous, no second exec/start intent; operator fixture cleanup only"
    );
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_exit_outbox_sigkill_replays_exit_and_publishes_same_bytes() {
    let f = Fixture::new(
        &[
            "/bin/sh",
            "-c",
            "printf original > result.txt; printf original-log; sleep 0.1; exit 42",
        ],
        |r| {
            r.success_exit_codes = vec![42];
            r.outputs[0].required = true;
        },
    );
    let mut process = child(&f, "before_exit_event");
    let path = f
        .root
        .join("executions-v1")
        .join(&sha256(f.id.as_str().as_bytes()).as_str()[7..])
        .join("recovery-test-ready");
    wait(&f, &mut process, || path.exists());
    let original = f.executor.owner.runtime(&f.id).unwrap();
    assert_eq!(original.view.execution.state, ExecutionState::Running);
    f.assert_reaped();
    kill(&mut process);
    let recovered = LinuxTaskExecutor::open(&f.root, f.executor.images.clone()).unwrap();
    let exited = recovered.reconcile(&f.id).unwrap();
    assert_eq!(exited.view.execution.state, ExecutionState::Exited);
    assert_eq!(exited.view.execution.exit_code, Some(42));
    assert_eq!(exited.view.phase, TaskPhase::Finalizing);
    assert_eq!(exited.view.delivery.state, DeliveryState::Pending);
    assert_eq!(exited.view.observation, Observation::Confirmed);
    assert_eq!(exited.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(recovered.reconcile(&f.id).unwrap(), exited);
    let artifacts = crate::task_artifacts::FileTaskArtifacts::open(&f.root).unwrap();
    let completed = artifacts.publish(&f.id, 3600).unwrap();
    assert_eq!(completed.view.outcome, TaskOutcome::Completed);
    recovered
        .record(&f.id, RuntimeAction::ObservationLost)
        .unwrap();
    let confirmed = recovered.reconcile(&f.id).unwrap();
    assert_eq!(confirmed.view.outcome, completed.view.outcome);
    assert_eq!(confirmed.view.execution, completed.view.execution);
    assert_eq!(confirmed.view.delivery, completed.view.delivery);
    assert_eq!(confirmed.view.observation, Observation::Confirmed);
    assert_eq!(
        recovered
            .logs(&f.id, LogStream::Stdout, 0, 65536)
            .unwrap()
            .bytes,
        b"original-log"
    );
    let access = crate::task_artifacts::ArtifactAccess {
        principal: &f.contract.authenticated_principal,
        workspace: &f.contract.request.workspace,
    };
    let records = artifacts.list(&f.id, access, &mut |_| Ok(())).unwrap();
    assert_eq!(
        artifacts
            .get(&records[0].artifact_id, access, 0, 65536, &mut |_| Ok(()))
            .unwrap()
            .bytes,
        b"original"
    );
    one_start(&f, &original.execution_handle);
    println!(
        "SIGKILL after sealed exit/reap but before Exited event: same actual exit 42 and original log/output recovered, original Artifact bytes published, terminal observation restored without changing outcome"
    );
}

#[test]
fn recovery_lease_detects_replaced_missing_and_hardlinked_lock() {
    for mode in ["replace", "missing", "hardlink"] {
        let dir = Dir::new();
        let logs = log_fixture(&dir, 100);
        let lease = logs.lock("owner.lock", true).unwrap();
        let path = logs.directory.join("owner.lock");
        if mode == "hardlink" {
            fs::hard_link(&path, logs.directory.join("alias")).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
            if mode == "replace" {
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
            }
        }
        assert_eq!(
            logs.check_lock("owner.lock", &lease).unwrap_err().code,
            TaskErrorCode::StateCorrupt
        );
        if mode == "replace" {
            assert_eq!(
                logs.lock("owner.lock", true).unwrap_err().code,
                TaskErrorCode::StateCorrupt
            );
        }
        if mode == "hardlink" {
            assert_eq!(
                logs.lock("owner.lock", true).unwrap_err().code,
                TaskErrorCode::StateCorrupt
            );
        }
    }
}

#[test]
fn recovery_missing_or_corrupt_owner_binding_never_rebinds_current_lock() {
    let dir = Dir::new();
    let logs = log_fixture(&dir, 100);
    let path = logs.directory.join("owner-lease-v1.json");
    fs::write(&path, b"corrupt").unwrap();
    assert_eq!(
        logs.lock("owner.lock", true).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(fs::read(&path).unwrap(), b"corrupt");
    fs::remove_file(&path).unwrap();
    assert_eq!(
        logs.lock("owner.lock", true).unwrap_err().code,
        TaskErrorCode::UnsupportedCapability
    );
    assert!(!path.exists());
    // No false EOF or truncation is needed to reject an unbound owner claim.
    assert!(!logs.page(LogStream::Stdout, 0, 10).unwrap().eof);
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_replaced_owner_lock_cannot_take_over_live_original_exec() {
    let f = Fixture::new(&["/bin/sleep", "60"], |_| {});
    let mut process = child(&f, "before_started_event");
    let path = f
        .root
        .join("executions-v1")
        .join(&sha256(f.id.as_str().as_bytes()).as_str()[7..])
        .join("recovery-test-ready");
    wait(&f, &mut process, || path.exists());
    let logs = execution_logs(&f);
    let original = f.executor.owner.runtime(&f.id).unwrap();
    let original_receipt = fs::read(logs.directory.join("owner-lease-v1.json")).unwrap();
    let lock = logs.directory.join("owner.lock");
    fs::remove_file(&lock).unwrap();
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&lock)
        .unwrap();
    assert!(process.try_wait().unwrap().is_none());
    assert_eq!(
        f.executor.reconcile(&f.id).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    let exec = original
        .execution_handle
        .as_ref()
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap();
    assert_eq!(Docker.exec_inspect(exec).unwrap()["Running"], true);
    assert_eq!(
        fs::read(logs.directory.join("owner-lease-v1.json")).unwrap(),
        original_receipt
    );
    one_start(&f, &original.execution_handle);
    kill(&mut process);
    Docker.stop(&f.container()).unwrap();
    f.assert_reaped();
    println!(
        "live original owner held replaced lock inode: durable original lease binding rejects second recovery and remains unchanged, no second exec"
    );
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_live_owner_detects_lock_loss_without_fabricating_terminal() {
    let f = Fixture::new(&["/bin/sleep", "60"], |_| {});
    let mut process = child(&f, "");
    wait(&f, &mut process, || {
        f.executor.owner.runtime(&f.id).unwrap().view.phase == TaskPhase::Running
    });
    let original = f.executor.owner.runtime(&f.id).unwrap();
    let logs = execution_logs(&f);
    fs::remove_file(logs.directory.join("owner.lock")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if Instant::now() > deadline {
            kill(&mut process);
            panic!("live owner did not detect lost lease");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let unknown = f.executor.owner.runtime(&f.id).unwrap();
    assert_eq!(unknown.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(unknown.view.observation, Observation::PendingVerification);
    assert_eq!(unknown.view.execution.state, ExecutionState::Running);
    assert_eq!(unknown.view.execution.exit_code, None);
    assert!(!logs.directory.join("owner.lock").exists());
    f.assert_reaped();
    one_start(&f, &original.execution_handle);
    println!(
        "live original owner detected missing lease, stopped original container as cleanup, kept outcome unfinished/observation pending and did not recreate lock"
    );
}

#[test]
fn recovery_confirmation_requires_original_completed_handle_and_preserves_outcome() {
    use nexus_domain::task::codec::CanonicalDto;
    let dir = Dir::new();
    let root = dir.0.join("store");
    let owner = TaskOwner::new(
        FileTaskAcceptanceStore::open(&root).unwrap(),
        sha256,
        new_task_id,
    );
    let request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
        "../../../docs/contracts/n3-submit.example.json"
    ))
    .unwrap();
    let context = AcceptanceContext {
        authenticated_principal: "fixture".into(),
        provider: request.provider.clone(),
        environment_evidence: request.environment.clone(),
        capacity_reservation_id: "fixture".into(),
        now_unix: 100,
        prepare_deadline_unix: 110,
        delivery_deadline_unix: 200,
    };
    let task = owner.accept_verified(request, context).unwrap().task;
    let id = &task.view.task_id;
    let mut sequence = 0;
    let mut send = |action: RuntimeAction| {
        let result = owner.record_event(
            id,
            RuntimeEvent {
                sequence: sequence + 1,
                action,
            },
        );
        if result.is_ok() {
            sequence += 1;
        }
        result
    };
    let confirm = RuntimeAction::ObservationConfirmed {
        handle: "original-handle".into(),
    };
    assert_eq!(
        RuntimeAction::from_value(confirm.to_value()).unwrap(),
        confirm
    );
    assert!(send(confirm.clone()).is_err());
    send(RuntimeAction::Prepare).unwrap();
    send(RuntimeAction::StartIntent {
        handle: "original-handle".into(),
    })
    .unwrap();
    assert!(send(confirm.clone()).is_err());
    send(RuntimeAction::Started { at_unix: 101 }).unwrap();
    send(RuntimeAction::ObservationLost).unwrap();
    assert!(send(confirm.clone()).is_err());
    send(RuntimeAction::Exited { exit_code: 42 }).unwrap();
    let original = send(RuntimeAction::ObservationLost).unwrap().state;
    assert!(
        send(RuntimeAction::ObservationConfirmed {
            handle: "another-handle".into()
        })
        .is_err()
    );
    let restored = send(confirm.clone()).unwrap().state;
    assert_eq!(restored.view.execution, original.view.execution);
    assert_eq!(restored.view.outcome, original.view.outcome);
    assert_eq!(restored.view.delivery, original.view.delivery);
    assert_eq!(restored.view.observation, Observation::Confirmed);
    send(RuntimeAction::DeliveryDeadline { now_unix: 200 }).unwrap();
    let terminal = send(RuntimeAction::ObservationLost).unwrap().state;
    let restored = send(confirm).unwrap().state;
    assert_eq!(restored.view.outcome, TaskOutcome::Failed);
    assert_eq!(restored.view.outcome, terminal.view.outcome);
    assert_eq!(restored.view.error, terminal.view.error);
    assert_eq!(restored.view.execution, terminal.view.execution);
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_missing_engine_keeps_pending_instead_of_executionlost() {
    let f = Fixture::new(&["/bin/sleep", "60"], |_| {});
    let mut process = child(&f, "");
    wait(&f, &mut process, || {
        f.executor.owner.runtime(&f.id).unwrap().view.phase == TaskPhase::Running
    });
    let original = f.executor.owner.runtime(&f.id).unwrap();
    kill(&mut process);
    Docker.stop(&f.container()).unwrap();
    Docker
        .request(
            "DELETE",
            &format!("/containers/{}", f.container()),
            Json::Null,
        )
        .unwrap();
    let recovered = LinuxTaskExecutor::open(&f.root, f.executor.images.clone()).unwrap();
    let pending = recovered.reconcile(&f.id).unwrap();
    assert_eq!(pending.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(pending.view.execution.state, ExecutionState::Running);
    assert_eq!(pending.view.observation, Observation::PendingVerification);
    assert_eq!(pending.view.error, None);
    one_start(&f, &original.execution_handle);
    println!(
        "original Engine container deliberately absent: HTTP 404 is uncertainty, no ExecutionLost fabricated, no second start"
    );
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_corrupt_cross_task_and_output_proofs_fail_closed() {
    let f = Fixture::new(
        &["/bin/sh", "-c", "printf original > result.txt; sleep 0.1"],
        |r| r.outputs[0].required = true,
    );
    let original = f.run();
    let logs = execution_logs(&f);
    let path = logs.directory.join("engine-v1.json");
    let saved = fs::read(&path).unwrap();
    let engine = crate::artifact_fs::load(&path).unwrap();
    for field in [
        "task_id",
        "contract_digest",
        "container",
        "exec",
        "argv",
        "cwd",
    ] {
        let mut changed = engine.clone();
        changed[field] = if field == "argv" {
            json!(["different"])
        } else {
            json!("different")
        };
        proof(&logs, "engine-v1.json", changed).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            f.executor.reconcile(&f.id).unwrap_err().code,
            TaskErrorCode::StateCorrupt
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(f.executor.owner.runtime(&f.id).unwrap(), original);
    }
    fs::write(&path, b"corrupt").unwrap();
    assert_eq!(
        f.executor.reconcile(&f.id).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    fs::write(&path, &saved).unwrap();
    let output = logs.directory.join("outputs-unregistered-v1/result.txt");
    fs::write(&output, b"tampered").unwrap();
    assert_eq!(
        f.executor.reconcile(&f.id).unwrap_err().code,
        TaskErrorCode::ArtifactIntegrityFailed
    );
    assert_eq!(f.executor.owner.runtime(&f.id).unwrap(), original);
}

#[test]
#[ignore = "requires qualified local Engine and fixed NEXUS_N3_TEST_IMAGE_ID"]
fn recovery_stop_outbox_sigkill_finishes_original_requested_cancel() {
    let f = Fixture::new(&["/bin/sleep", "60"], |_| {});
    let mut process = child(&f, "");
    wait(&f, &mut process, || {
        f.executor.owner.runtime(&f.id).unwrap().view.phase == TaskPhase::Running
    });
    kill(&mut process);
    let recovered = LinuxTaskExecutor::open(&f.root, f.executor.images.clone()).unwrap();
    recovered.cancel(&f.id, "User").unwrap();
    let mut recoverer = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "task_executor::tests::recovery_tests::recovery_process_fixture",
        ])
        .env("NEXUS_N3_FIXTURE_ROOT", &f.root)
        .env("NEXUS_N3_FIXTURE_TASK", f.id.as_str())
        .env("NEXUS_N3_RECOVERY_PAUSE", "before_stopped_event")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let path = execution_logs(&f).directory.join("recovery-test-ready");
    wait(&f, &mut recoverer, || path.exists());
    f.assert_reaped();
    assert_eq!(
        recovered.owner.runtime(&f.id).unwrap().view.execution.state,
        ExecutionState::Running
    );
    kill(&mut recoverer);
    let stopped = recovered.reconcile(&f.id).unwrap();
    assert_eq!(stopped.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(stopped.view.execution.stop_reason.as_deref(), Some("User"));
    assert_eq!(
        stopped.view.cancellation.state,
        CancellationState::Confirmed
    );
    assert_eq!(recovered.reconcile(&f.id).unwrap(), stopped);
    println!(
        "SIGKILL recovery owner after original namespace reap: durable stop intent resumes original User cancellation, no new workload execution"
    );
}

#[test]
#[ignore = "child recovery process invoked by parent physical test only"]
fn recovery_process_fixture() {
    let root = PathBuf::from(std::env::var("NEXUS_N3_FIXTURE_ROOT").unwrap());
    let id = TaskId::new(std::env::var("NEXUS_N3_FIXTURE_TASK").unwrap()).unwrap();
    let image = Sha256Digest::parse(std::env::var("NEXUS_N3_TEST_IMAGE_ID").unwrap()).unwrap();
    LinuxTaskExecutor::open(&root, vec![image])
        .unwrap()
        .reconcile(&id)
        .unwrap();
}
