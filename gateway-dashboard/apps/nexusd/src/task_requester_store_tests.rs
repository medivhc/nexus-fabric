use super::*;
use crate::task_store::FileTaskAcceptanceStore;
use nexus::n3_acceptance::{decode_dto, new_task_id};
use nexus_compute::task::{AcceptanceContext, TaskOwner};
use nexus_domain::task::*;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Child, Command},
    sync::atomic::{AtomicU64, Ordering},
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "n35-requester-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn scope() -> RequesterScope<'static> {
    RequesterScope {
        principal: "test-principal",
        provider: "provider-linux-1",
        workspace: "workspace-1",
    }
}
fn setup(dir: &Dir) -> (FileTaskRequesterStore, TaskView) {
    let mut r: SubmitTaskRequest = decode_dto(include_bytes!(
        "../../../docs/contracts/n3-submit.example.json"
    ))
    .unwrap();
    r.provider = scope().provider.into();
    r.workspace = scope().workspace.into();
    r.input_snapshot.workspace = r.workspace.clone();
    r.outputs.clear();
    // SnapshotRef's identity includes workspace; preserve canonical integrity.
    let Value::Object(mut ref_fields) =
        serde_json::from_slice::<Value>(&r.input_snapshot.to_value().canonical_bytes()).unwrap()
    else {
        panic!()
    };
    ref_fields.remove("snapshot_id");
    r.input_snapshot.snapshot_id = sha256(&disk::canonical(&Value::Object(ref_fields)).unwrap());
    let c = AcceptanceContext {
        authenticated_principal: scope().principal.into(),
        provider: r.provider.clone(),
        environment_evidence: r.environment.clone(),
        capacity_reservation_id: "test-reservation".into(),
        now_unix: 100,
        prepare_deadline_unix: 110,
        delivery_deadline_unix: 200,
    };
    let owner = TaskOwner::new(
        FileTaskAcceptanceStore::open(&dir.0.join("provider")).unwrap(),
        sha256,
        new_task_id,
    );
    let view = owner.accept_verified(r, c).unwrap().task.view;
    let s = FileTaskRequesterStore::open(&dir.0.join("requester")).unwrap();
    s.receive(view.clone(), scope()).unwrap();
    (s, view)
}
#[test]
fn restart_retry_ack_does_not_claim_stopped() {
    let d = Dir::new();
    let (s, v) = setup(&d);
    let id = &v.task_id;
    let q = s
        .queue_cancel(id, scope(), CancelReason::User, 101)
        .unwrap();
    assert_eq!(q.cancel_request.state, CancelRequestState::Queued);
    assert_eq!(q.cancellation.state, CancellationState::None);
    let cold = FileTaskRequesterStore::open(&s.root).unwrap();
    assert_eq!(cold.pending(scope()).unwrap().len(), 1);
    assert_eq!(
        cold.queue_cancel(id, scope(), CancelReason::User, 102)
            .unwrap(),
        q
    );
    cold.settle_cancel(id, scope(), id, None).unwrap();
    let cold = FileTaskRequesterStore::open(&s.root).unwrap();
    let ack = cold.read(id, scope()).unwrap();
    assert_eq!(ack.cancel_request.state, CancelRequestState::Acknowledged);
    assert_eq!(ack.outcome, TaskOutcome::Unfinished);
    assert_eq!(ack.cancellation, v.cancellation);
    assert!(cold.pending(scope()).unwrap().is_empty());
}
#[test]
fn rejected_cancel_scope_and_sequence_preserve_authority() {
    let d = Dir::new();
    let (s, v) = setup(&d);
    let id = &v.task_id;
    let bad = RequesterScope {
        principal: "forged",
        ..scope()
    };
    assert_eq!(
        s.queue_cancel(id, bad, CancelReason::User, 101)
            .unwrap_err()
            .code,
        TaskErrorCode::AuthDenied
    );
    let original = fs::read(s.root.join(IMAGE)).unwrap();
    let mut conflict = v.clone();
    conflict.observation = Observation::PendingVerification;
    assert!(s.receive(conflict, scope()).is_err());
    assert_eq!(fs::read(s.root.join(IMAGE)).unwrap(), original);
    s.queue_cancel(id, scope(), CancelReason::Revoked, 101)
        .unwrap();
    let e = TaskError::new(TaskErrorCode::AuthDenied, "cancel rejected", false);
    s.settle_cancel(id, scope(), id, Some(e.clone())).unwrap();
    let cold = FileTaskRequesterStore::open(&s.root).unwrap();
    let r = cold.read(id, scope()).unwrap();
    assert_eq!(r.cancel_request.error, Some(e));
    assert_eq!(r.outcome, TaskOutcome::Unfinished);
}
#[test]
fn terminal_provider_facts_never_discard_queued_outbox() {
    let d = Dir::new();
    let (s, mut v) = setup(&d);
    s.queue_cancel(&v.task_id, scope(), CancelReason::User, 102)
        .unwrap();
    v.phase = TaskPhase::Finished;
    v.outcome = TaskOutcome::Completed;
    v.last_event_seq = 5;
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
    s.receive(v.clone(), scope()).unwrap();
    s.disconnected(&v.task_id, scope()).unwrap();
    let r = s.read(&v.task_id, scope()).unwrap();
    assert_eq!(r.execution, v.execution);
    assert_eq!(r.outcome, v.outcome);
    assert_eq!(r.observation, Observation::PendingVerification);
    assert_eq!(s.pending(scope()).unwrap().len(), 1);
}
#[test]
fn authority_loss_corruption_links_and_empty_root_refuse_reset() {
    for names in [vec![IMAGE], vec![RECEIPT], vec![IMAGE, RECEIPT], vec![LOCK]] {
        let d = Dir::new();
        let (s, _) = setup(&d);
        for n in names {
            fs::remove_file(s.root.join(n)).unwrap();
        }
        assert!(FileTaskRequesterStore::open(&s.root).is_err());
    }
    let d = Dir::new();
    let empty = d.0.join("empty");
    fs::create_dir(&empty).unwrap();
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(FileTaskRequesterStore::open(&empty).is_err());
    let (s, _) = setup(&d);
    fs::write(s.root.join(IMAGE), b"torn").unwrap();
    assert!(FileTaskRequesterStore::open(&s.root).is_err());
    assert_eq!(fs::read(s.root.join(IMAGE)).unwrap(), b"torn");
    let d = Dir::new();
    let (s, _) = setup(&d);
    fs::hard_link(s.root.join(IMAGE), d.0.join("hardlink")).unwrap();
    assert!(FileTaskRequesterStore::open(&s.root).is_err());
    let d = Dir::new();
    let (s, _) = setup(&d);
    fs::remove_file(s.root.join(IMAGE)).unwrap();
    std::os::unix::fs::symlink(s.root.join(RECEIPT), s.root.join(IMAGE)).unwrap();
    assert!(FileTaskRequesterStore::open(&s.root).is_err());
}
#[test]
fn write_failures_never_report_queued_success() {
    for boundary in [
        "after_write",
        "after_file_sync",
        "after_rename",
        "after_directory_sync",
    ] {
        let d = Dir::new();
        let (s, v) = setup(&d);
        let e = s
            .queue_with(&v.task_id, scope(), CancelReason::User, 101, &mut |p| {
                if p == boundary {
                    Err(TaskError::new(
                        TaskErrorCode::PersistenceFailed,
                        "injected",
                        true,
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(e.code, TaskErrorCode::PersistenceFailed);
        let recovered = FileTaskRequesterStore::open(&s.root)
            .unwrap()
            .read(&v.task_id, scope())
            .unwrap();
        assert_eq!(
            recovered.cancel_request.state,
            if boundary == "after_write" || boundary == "after_file_sync" {
                CancelRequestState::None
            } else {
                CancelRequestState::Queued
            }
        );
    }
}
fn child(s: &FileTaskRequesterStore, id: &TaskId, mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "task_requester_store::tests::child_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("N35_REQUESTER_ROOT", &s.root)
        .env("N35_REQUESTER_TASK", id.as_str())
        .env("N35_REQUESTER_MODE", mode)
        .spawn()
        .unwrap()
}
#[test]
#[ignore = "invoked by isolated parent tests"]
fn child_fixture() {
    let Ok(root) = std::env::var("N35_REQUESTER_ROOT") else {
        return;
    };
    let id = TaskId::new(std::env::var("N35_REQUESTER_TASK").unwrap()).unwrap();
    let mode = std::env::var("N35_REQUESTER_MODE").unwrap();
    let s = FileTaskRequesterStore::open(Path::new(&root)).unwrap();
    if mode == "concurrent" {
        s.queue_cancel(&id, scope(), CancelReason::User, 101)
            .unwrap();
        return;
    }
    s.queue_with(&id, scope(), CancelReason::User, 101, &mut |p| {
        if p == mode {
            Command::new("kill")
                .args(["-KILL", &std::process::id().to_string()])
                .status()
                .unwrap();
            panic!("SIGKILL failed");
        }
        Ok(())
    })
    .unwrap();
    panic!("crash boundary not reached");
}
#[test]
fn sigkill_at_atomic_boundaries_preserves_retry_intent() {
    for mode in ["after_file_sync", "after_rename", "after_directory_sync"] {
        let d = Dir::new();
        let (s, v) = setup(&d);
        let status = child(&s, &v.task_id, mode).wait().unwrap();
        assert!(!status.success());
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let cold = FileTaskRequesterStore::open(&s.root).unwrap();
        assert_eq!(
            cold.read(&v.task_id, scope()).unwrap().cancel_request.state,
            if mode == "after_file_sync" {
                CancelRequestState::None
            } else {
                CancelRequestState::Queued
            }
        );
        cold.queue_cancel(&v.task_id, scope(), CancelReason::User, 101)
            .unwrap();
        assert_eq!(cold.pending(scope()).unwrap().len(), 1);
    }
}
#[test]
fn independent_process_cancel_is_single_durable_intent() {
    let d = Dir::new();
    let (s, v) = setup(&d);
    let children: Vec<_> = (0..6)
        .map(|_| child(&s, &v.task_id, "concurrent"))
        .collect();
    for mut c in children {
        assert!(c.wait().unwrap().success());
    }
    assert_eq!(s.pending(scope()).unwrap().len(), 1);
    assert_eq!(
        s.read(&v.task_id, scope())
            .unwrap()
            .cancel_request
            .requested_at_unix,
        Some(101)
    );
}
#[test]
fn live_lock_replacement_is_detected() {
    let d = Dir::new();
    let (s, v) = setup(&d);
    let result = s.queue_with(&v.task_id, scope(), CancelReason::User, 101, &mut |p| {
        if p == "after_file_sync" {
            fs::remove_file(s.root.join(LOCK)).unwrap();
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(s.root.join(LOCK))
                .unwrap();
            f.write_all(b"replacement").unwrap();
        }
        Ok(())
    });
    assert_eq!(result.unwrap_err().code, TaskErrorCode::StateCorrupt);
    assert!(FileTaskRequesterStore::open(&s.root).is_err());
}
#[test]
fn oversized_image_and_public_permissions_preserve_previous_state() {
    let d = Dir::new();
    let (s, mut v) = setup(&d);
    let previous = fs::read(s.root.join(IMAGE)).unwrap();
    v.last_event_seq = 1;
    v.phase = TaskPhase::Preparing;
    v.session_ids = (0..45000)
        .map(|i| format!("session-{i:05}-{}", "x".repeat(180)))
        .collect();
    assert_eq!(
        s.receive(v, scope()).unwrap_err().code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(fs::read(s.root.join(IMAGE)).unwrap(), previous);
    fs::set_permissions(s.root.join(IMAGE), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        FileTaskRequesterStore::open(&s.root).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
}
#[test]
fn independent_provider_task_id_collision_keeps_scoped_intents_separate() {
    let d = Dir::new();
    let (s, a) = setup(&d);
    let b_scope = RequesterScope {
        principal: "second-principal",
        provider: "second-provider",
        workspace: scope().workspace,
    };
    let mut b = a.clone();
    b.accepted_contract.request.provider = b_scope.provider.into();
    b.accepted_contract.authenticated_principal = b_scope.principal.into();
    b.accepted_contract.request_digest =
        b.accepted_contract.request.request_digest(sha256).unwrap();
    b.contract_digest = b.accepted_contract.contract_digest(sha256).unwrap();
    s.receive(b.clone(), b_scope).unwrap();
    assert_eq!(s.read(&a.task_id, scope()).unwrap(), a);
    assert_eq!(s.read(&b.task_id, b_scope).unwrap(), b);
    s.queue_cancel(&a.task_id, scope(), CancelReason::User, 101)
        .unwrap();
    assert_eq!(
        s.read(&b.task_id, b_scope).unwrap().cancel_request.state,
        CancelRequestState::None
    );
    s.queue_cancel(&b.task_id, b_scope, CancelReason::Revoked, 102)
        .unwrap();
    s.settle_cancel(&a.task_id, scope(), &a.task_id, None)
        .unwrap();
    let cold = FileTaskRequesterStore::open(&s.root).unwrap();
    assert!(cold.pending(scope()).unwrap().is_empty());
    assert_eq!(cold.pending(b_scope).unwrap().len(), 1);
    assert_eq!(
        cold.read(&b.task_id, b_scope)
            .unwrap()
            .cancel_request
            .reason
            .as_deref(),
        Some("Revoked")
    );
    let wrong = RequesterScope {
        principal: "second-principal",
        ..scope()
    };
    assert_eq!(
        cold.read(&a.task_id, wrong).unwrap_err().code,
        TaskErrorCode::AuthDenied
    );
    assert_eq!(
        cold.queue_cancel(&a.task_id, wrong, CancelReason::User, 103)
            .unwrap_err()
            .code,
        TaskErrorCode::AuthDenied
    );
    let mut replacement = a.clone();
    replacement.accepted_contract.authenticated_principal = wrong.principal.into();
    replacement.contract_digest = replacement
        .accepted_contract
        .contract_digest(sha256)
        .unwrap();
    assert_eq!(
        cold.receive(replacement, wrong).unwrap_err().code,
        TaskErrorCode::AuthDenied
    );
    let wrong_workspace = RequesterScope {
        workspace: "foreign-workspace",
        ..scope()
    };
    assert_eq!(
        cold.read(&a.task_id, wrong_workspace).unwrap_err().code,
        TaskErrorCode::AuthDenied
    );
}
#[test]
fn mismatched_cancel_response_never_attaches_foreign_error() {
    let d = Dir::new();
    let (s, v) = setup(&d);
    s.queue_cancel(&v.task_id, scope(), CancelReason::User, 101)
        .unwrap();
    let previous = fs::read(s.root.join(IMAGE)).unwrap();
    let other = TaskId::new("unrelated-task".into()).unwrap();
    let e = TaskError::new(TaskErrorCode::AuthDenied, "foreign Task rejection", false);
    assert!(
        s.settle_cancel(&v.task_id, scope(), &other, Some(e))
            .is_err()
    );
    assert!(s.settle_cancel(&v.task_id, scope(), &other, None).is_err());
    assert_eq!(fs::read(s.root.join(IMAGE)).unwrap(), previous);
    assert_eq!(
        s.read(&v.task_id, scope()).unwrap().cancel_request.state,
        CancelRequestState::Queued
    );
}

#[test]
fn requester_task_id_is_provider_scoped_regression() {
    let d = Dir::new();
    let (store, first) = setup(&d);
    let mut second = first.clone();
    second.accepted_contract.request.provider = "provider-linux-2".into();
    second.accepted_contract.request_digest = second
        .accepted_contract
        .request
        .request_digest(sha256)
        .unwrap();
    second.contract_digest = second.accepted_contract.contract_digest(sha256).unwrap();
    let other = RequesterScope {
        provider: "provider-linux-2",
        ..scope()
    };
    second.verify_digests(sha256).unwrap();
    assert!(
        store.receive(second.clone(), other).is_ok(),
        "two authenticated providers may choose the same opaque TaskId"
    );
    assert_eq!(store.read(&first.task_id, scope()).unwrap(), first);
    assert_eq!(store.read(&second.task_id, other).unwrap(), second);
}
