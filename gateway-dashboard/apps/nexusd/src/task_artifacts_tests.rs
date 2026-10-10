use super::*;
use nexus_compute::task::{AcceptanceContext, TaskAcceptanceStore};
use std::fs::File;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p =
            std::env::temp_dir().join(format!("n3-artifacts-{}", new_task_id().unwrap().as_str()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    dir: Dir,
    root: PathBuf,
    id: TaskId,
    store: FileTaskArtifacts,
    contract: AcceptedContract,
}
impl Fixture {
    fn new(outputs: Vec<OutputSpec>, files: &[(&str, &[u8])], exit: u8, success: Vec<u8>) -> Self {
        Self::aged(outputs, files, exit, success, false)
    }
    fn aged(
        outputs: Vec<OutputSpec>,
        files: &[(&str, &[u8])],
        exit: u8,
        success: Vec<u8>,
        expired: bool,
    ) -> Self {
        let dir = Dir::new();
        let root = dir.0.join("provider");
        let acceptance = FileTaskAcceptanceStore::open(&root).unwrap();
        let mut request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
            "../../../docs/contracts/n3-submit.example.json"
        ))
        .unwrap();
        request.outputs = outputs;
        request.success_exit_codes = success;
        let time = now().unwrap() - if expired { 10 } else { 0 };
        let context = AcceptanceContext {
            authenticated_principal: "test-principal".into(),
            provider: request.provider.clone(),
            environment_evidence: request.environment.clone(),
            capacity_reservation_id: "fixture-capacity".into(),
            now_unix: time,
            prepare_deadline_unix: time + if expired { 1 } else { 60 },
            delivery_deadline_unix: time + if expired { 2 } else { 600 },
        };
        let owner = TaskOwner::new(acceptance, sha256, new_task_id);
        let accepted = owner.accept_verified(request, context).unwrap().task;
        let id = accepted.view.task_id;
        let contract = accepted.view.accepted_contract;
        for (index, action) in [
            RuntimeAction::Prepare,
            RuntimeAction::StartIntent {
                handle: format!("docker:{}:{}", "a".repeat(64), "b".repeat(64)),
            },
            RuntimeAction::Started { at_unix: time },
            RuntimeAction::Exited { exit_code: exit },
        ]
        .into_iter()
        .enumerate()
        {
            owner
                .record_event(
                    &id,
                    RuntimeEvent {
                        sequence: index as u64 + 1,
                        action,
                    },
                )
                .unwrap();
        }
        crate::task_executor::stage_fixture(&root, &owner.runtime(&id).unwrap(), &tar(files))
            .unwrap();
        let store = FileTaskArtifacts::open(&root).unwrap();
        Self {
            dir,
            root,
            id,
            store,
            contract,
        }
    }
    fn simple() -> Self {
        Self::new(
            vec![OutputSpec {
                path: "result".into(),
                required: true,
            }],
            &[("result", b"result bytes")],
            0,
            vec![0],
        )
    }
    fn access(&self) -> ArtifactAccess<'_> {
        ArtifactAccess {
            principal: &self.contract.authenticated_principal,
            workspace: &self.contract.request.workspace,
        }
    }
    fn state(&self) -> RuntimeState {
        TaskOwner::new(self.store.store.clone(), sha256, new_task_id)
            .runtime(&self.id)
            .unwrap()
    }
    fn records(&self) -> Vec<ArtifactRecord> {
        self.store
            .list(&self.id, self.access(), &mut |_| Ok(()))
            .unwrap()
    }
}
fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    fn entry(out: &mut Vec<u8>, name: &str, bytes: &[u8], kind: u8) {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000600\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[148..156].fill(b' ');
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        out.extend(h);
        out.extend(bytes);
        let padding = (512 - bytes.len() % 512) % 512;
        out.resize(out.len() + padding, 0);
    }
    let mut out = Vec::new();
    entry(&mut out, "work/", b"", b'5');
    for (name, b) in files {
        entry(&mut out, &format!("work/{name}"), b, b'0');
    }
    out.resize(out.len() + 1024, 0);
    out
}
#[test]
fn publication_finishes_only_after_verified_outputs_and_both_logs() {
    let f = Fixture::simple();
    assert_eq!(f.state().view.outcome, TaskOutcome::Unfinished);
    assert!(f.records().is_empty());
    let s = f.store.publish(&f.id, 3600).unwrap();
    assert_eq!(s.view.outcome, TaskOutcome::Completed);
    assert_eq!(s.view.delivery.state, DeliveryState::Complete);
    assert_eq!(s.view.execution.exit_code, Some(0));
    let records = f.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].publication_state, PublicationState::Published);
    assert_eq!(records[0].content_sha256, sha256(b"result bytes"));
    assert_eq!(s.view.artifact_ids, vec![records[0].artifact_id.clone()]);
    let page = f
        .store
        .get(&records[0].artifact_id, f.access(), 0, 4, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(page.bytes, b"resu");
    assert_eq!(page.next_offset, 4);
    assert!(!page.eof);
    assert_eq!(
        page,
        f.store
            .get(&records[0].artifact_id, f.access(), 0, 4, &mut |_| Ok(()))
            .unwrap()
    );
    assert_eq!(
        f.store
            .logs(
                &f.id,
                f.access(),
                crate::task_executor::LogStream::Stderr,
                0,
                100,
                &mut |_| Ok(())
            )
            .unwrap()
            .bytes,
        b"stderr\n"
    );
    let before = f.state();
    assert_eq!(f.store.publish(&f.id, 100).unwrap(), before);
    let reopened = FileTaskArtifacts::open(&f.root).unwrap();
    assert_eq!(
        reopened.list(&f.id, f.access(), &mut |_| Ok(())).unwrap(),
        records
    );
}
#[test]
fn publication_retains_real_nonzero_and_obeys_success_exit_codes() {
    for (code, allowed, outcome) in [
        (42, vec![0, 42], TaskOutcome::Completed),
        (42, vec![0], TaskOutcome::Failed),
    ] {
        let f = Fixture::new(vec![], &[], code, allowed);
        let s = f.store.publish(&f.id, 60).unwrap();
        assert_eq!(s.view.outcome, outcome);
        assert_eq!(s.view.execution.exit_code, Some(code));
        assert_eq!(s.view.delivery.state, DeliveryState::Complete);
        if outcome == TaskOutcome::Failed {
            assert_eq!(s.view.error.unwrap().code, TaskErrorCode::WorkloadExit);
        }
    }
}
#[test]
fn missing_required_fails_but_optional_missing_and_zero_outputs_register_logs() {
    let f = Fixture::new(
        vec![OutputSpec {
            path: "missing".into(),
            required: true,
        }],
        &[],
        0,
        vec![0],
    );
    let s = f.store.publish(&f.id, 60).unwrap();
    assert_eq!(s.view.outcome, TaskOutcome::Failed);
    assert_eq!(s.view.error.unwrap().code, TaskErrorCode::ArtifactMissing);
    assert_eq!(s.view.execution.exit_code, Some(0));
    assert_eq!(s.view.delivery.state, DeliveryState::Failed);
    for outputs in [
        vec![],
        vec![OutputSpec {
            path: "optional".into(),
            required: false,
        }],
    ] {
        let f = Fixture::new(outputs, &[], 0, vec![0]);
        assert_eq!(
            f.store.publish(&f.id, 60).unwrap().view.outcome,
            TaskOutcome::Completed
        );
        assert!(f.records().is_empty());
        assert!(
            f.store
                .logs(
                    &f.id,
                    f.access(),
                    crate::task_executor::LogStream::Stdout,
                    0,
                    100,
                    &mut |_| Ok(())
                )
                .unwrap()
                .eof
        );
    }
}
#[test]
fn partial_publication_stays_pending_and_retries_same_ids_without_reexecution() {
    let f = Fixture::simple();
    let mut fail = true;
    let e = f
        .store
        .publish_with(&f.id, 60, &mut |point| {
            if point == "after_content" && fail {
                fail = false;
                Err(TaskError::new(
                    TaskErrorCode::ArtifactUnavailable,
                    "interrupted transfer",
                    true,
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(e.retryable);
    let pending = f.state();
    assert_eq!(pending.view.phase, TaskPhase::Finalizing);
    assert_eq!(pending.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(pending.view.delivery.state, DeliveryState::Pending);
    assert!(pending.view.delivery.error.unwrap().retryable);
    assert_eq!(pending.view.execution.exit_code, Some(0));
    let before = f.records()[0].clone();
    assert_eq!(before.publication_state, PublicationState::Pending);
    assert_eq!(
        f.store
            .get(&before.artifact_id, f.access(), 0, 10, &mut |_| Ok(()))
            .unwrap_err()
            .code,
        TaskErrorCode::ArtifactUnavailable
    );
    let s = f.store.publish(&f.id, 60).unwrap();
    assert_eq!(s.view.outcome, TaskOutcome::Completed);
    assert_eq!(f.records()[0].artifact_id, before.artifact_id);
    let (_, journal) = f.store.store.runtime_read(&f.id).unwrap();
    assert_eq!(
        journal
            .events
            .iter()
            .filter(|e| matches!(e.action, RuntimeAction::StartIntent { .. }))
            .count(),
        1
    );
}
#[test]
fn every_read_rechecks_scope_grant_and_durably_audits_denials() {
    let f = Fixture::simple();
    f.store.publish(&f.id, 60).unwrap();
    let r = &f.records()[0];
    let mut calls = 0;
    f.store
        .get(&r.artifact_id, f.access(), 0, 4, &mut |_| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    let err = f
        .store
        .get(&r.artifact_id, f.access(), 0, 4, &mut |_| {
            calls += 1;
            Err(TaskError::new(
                TaskErrorCode::AuthDenied,
                "grant revoked",
                false,
            ))
        })
        .unwrap_err();
    assert_eq!(err.code, TaskErrorCode::AuthDenied);
    assert_eq!(calls, 2);
    for access in [
        ArtifactAccess {
            principal: "other",
            workspace: &r.workspace,
        },
        ArtifactAccess {
            principal: &r.owner_principal,
            workspace: "other-workspace",
        },
    ] {
        assert_eq!(
            f.store
                .get(&r.artifact_id, access, 0, 4, &mut |_| panic!(
                    "scope rejection must precede callback"
                ))
                .unwrap_err()
                .code,
            TaskErrorCode::AuthDenied
        );
    }
    assert_eq!(
        f.store
            .list(&f.id, f.access(), &mut |_| Err(TaskError::new(
                TaskErrorCode::AuthDenied,
                "list denied",
                false
            )))
            .unwrap_err()
            .code,
        TaskErrorCode::AuthDenied
    );
    let audit = nexus_storage::FileKvStore::open(&f.root.join("artifact-audit-v1")).unwrap();
    assert_eq!(audit.journal_replay().unwrap().len(), 4);
    // Grant callbacks run outside acceptance flock and can reenter service APIs.
    let page = f
        .store
        .get(&r.artifact_id, f.access(), 0, 4, &mut |_| {
            assert_eq!(f.records().len(), 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(page.bytes, b"resu");
}
#[test]
fn content_corruption_is_not_republished_or_hidden_by_cached_records() {
    let f = Fixture::simple();
    f.store.publish(&f.id, 60).unwrap();
    let r = f.records()[0].clone();
    let path = catalog::object(&f.root, &r.content_sha256);
    fs::write(&path, b"wrong bytes!").unwrap();
    assert_eq!(
        f.store
            .get(&r.artifact_id, f.access(), 0, 20, &mut |_| Ok(()))
            .unwrap_err()
            .code,
        TaskErrorCode::ArtifactIntegrityFailed
    );
    assert!(FileTaskArtifacts::open(&f.root).is_err());
    assert_eq!(fs::read(path).unwrap(), b"wrong bytes!");
}
#[test]
fn staged_bytes_and_linked_parents_cannot_be_registered() {
    for link in [false, true] {
        let f = Fixture::simple();
        let directory = f
            .root
            .join("executions-v1")
            .join(&sha256(f.id.as_str().as_bytes()).as_str()[7..])
            .join("outputs-unregistered-v1");
        if link {
            let old = directory.with_extension("old");
            fs::rename(&directory, &old).unwrap();
            symlink(&old, &directory).unwrap();
        } else {
            fs::write(directory.join("result"), b"mutated data").unwrap();
        }
        assert!(f.store.publish(&f.id, 60).is_err());
        assert_eq!(f.state().view.outcome, TaskOutcome::Unfinished);
        assert!(f.records().is_empty());
    }
}
#[test]
fn lost_or_damaged_artifact_authority_blocks_reopen_acceptance_and_gc() {
    for variant in 0..4 {
        let f = Fixture::simple();
        f.store.publish(&f.id, 60).unwrap();
        match variant {
            0 => fs::remove_file(f.root.join(IMAGE)).unwrap(),
            1 => {
                fs::remove_file(f.root.join(IMAGE)).unwrap();
                fs::remove_file(f.root.join(RECEIPT)).unwrap();
            }
            2 => {
                fs::write(f.root.join(IMAGE), b"torn").unwrap();
            }
            _ => {
                let p = f.root.join(IMAGE);
                fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        assert!(f.store.store.read().is_err());
        assert!(FileTaskArtifacts::open(&f.root).is_err());
        let snapshot = crate::snapshot_store::FileSnapshotStore::open(&f.root);
        assert!(snapshot.is_err());
    }
}
#[test]
fn delivery_completion_cannot_be_forged_without_published_catalog() {
    let f = Fixture::new(vec![], &[], 0, vec![0]);
    let owner = TaskOwner::new(f.store.store.clone(), sha256, new_task_id);
    let logs = vec![
        RegisteredLog {
            stream: "stdout".into(),
            size_bytes: 0,
            content_sha256: sha256(b""),
            truncated: false,
        },
        RegisteredLog {
            stream: "stderr".into(),
            size_bytes: 0,
            content_sha256: sha256(b""),
            truncated: false,
        },
    ];
    let before = f.state();
    assert_eq!(
        owner
            .record_event(
                &f.id,
                RuntimeEvent {
                    sequence: 5,
                    action: RuntimeAction::DeliveryReady {
                        artifacts: vec![],
                        logs,
                        at_unix: now().unwrap()
                    }
                }
            )
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(f.state(), before);
}
#[test]
fn retention_overflow_and_unknown_execution_preserve_unfinished() {
    let f = Fixture::simple();
    assert!(f.store.publish(&f.id, MAX_INTEGER).is_err());
    assert_eq!(f.state().view.outcome, TaskOutcome::Unfinished);
    let owner = TaskOwner::new(f.store.store.clone(), sha256, new_task_id);
    owner
        .record_event(
            &f.id,
            RuntimeEvent {
                sequence: 5,
                action: RuntimeAction::ObservationLost,
            },
        )
        .unwrap();
    assert!(f.store.publish(&f.id, 60).is_err());
    assert_eq!(f.state().view.observation, Observation::PendingVerification);
}
#[test]
fn real_sigkill_during_publication_resumes_registration_not_execution() {
    use std::os::unix::process::ExitStatusExt;
    for point in [
        "after_manifest",
        "after_content",
        "after_registration",
        "after_log_content",
        "before_outcome",
    ] {
        let f = Fixture::simple();
        let marker = f.dir.0.join("crash-ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "task_artifacts::tests::artifact_process_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("NEXUS_ARTIFACT_FIXTURE_ROOT", &f.root)
            .env("NEXUS_ARTIFACT_FIXTURE_TASK", f.id.as_str())
            .env("NEXUS_ARTIFACT_FIXTURE_POINT", point)
            .env("NEXUS_ARTIFACT_FIXTURE_MARKER", &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("fixture exited early: {status}");
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fixture never reached {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        let recovered = FileTaskArtifacts::open(&f.root).unwrap();
        assert_eq!(f.state().view.outcome, TaskOutcome::Unfinished);
        assert_eq!(
            recovered.publish(&f.id, 60).unwrap().view.outcome,
            TaskOutcome::Completed
        );
        let (_, j) = recovered.store.runtime_read(&f.id).unwrap();
        assert_eq!(
            j.events
                .iter()
                .filter(|e| matches!(e.action, RuntimeAction::StartIntent { .. }))
                .count(),
            1
        );
    }
}
#[test]
#[ignore = "child fixture invoked by real SIGKILL parent"]
fn artifact_process_fixture() {
    let root = PathBuf::from(std::env::var("NEXUS_ARTIFACT_FIXTURE_ROOT").unwrap());
    let id = TaskId::new(std::env::var("NEXUS_ARTIFACT_FIXTURE_TASK").unwrap()).unwrap();
    let point = std::env::var("NEXUS_ARTIFACT_FIXTURE_POINT").unwrap();
    let marker = PathBuf::from(std::env::var("NEXUS_ARTIFACT_FIXTURE_MARKER").unwrap());
    FileTaskArtifacts::open(&root)
        .unwrap()
        .publish_with(&id, 60, &mut |p| {
            if p == point {
                fs::write(&marker, b"ready").unwrap();
                File::open(&marker).unwrap().sync_all().unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn pending_artifact_metadata_loss_cannot_masquerade_as_legacy_migration() {
    let f = Fixture::simple();
    f.store
        .publish_with(&f.id, 60, &mut |p| {
            if p == "after_manifest" {
                Err(TaskError::new(
                    TaskErrorCode::ArtifactUnavailable,
                    "pause",
                    true,
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    for name in [IMAGE, RECEIPT, "acceptance-initialized-v1"] {
        fs::remove_file(f.root.join(name)).unwrap();
    }
    assert!(
        FileTaskAcceptanceStore::open(&f.root).is_err(),
        "existing Artifact content directory proves prior state"
    );
    assert!(!f.root.join(IMAGE).exists());
}

#[test]
fn expired_delivery_never_promotes_confirmed_exit_to_completed() {
    let f = Fixture::aged(
        vec![OutputSpec {
            path: "result".into(),
            required: true,
        }],
        &[("result", b"bytes")],
        0,
        vec![0],
        true,
    );
    let state = f.store.publish(&f.id, 60).unwrap();
    assert_eq!(state.view.outcome, TaskOutcome::Failed);
    assert_eq!(state.view.execution.exit_code, Some(0));
    assert_eq!(
        state.view.error.unwrap().code,
        TaskErrorCode::DeliveryDeadlineExceeded
    );
    assert_eq!(state.view.delivery.state, DeliveryState::Failed);
    assert!(f.records().is_empty());
}
