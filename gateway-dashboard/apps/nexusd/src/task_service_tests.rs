use super::*;
use nexus::{
    n2_store::N2Store,
    n3_acceptance::{new_task_id, sha256},
};
use nexus_compute::{
    task::{AcceptanceContext, TaskAcceptanceStore, TaskOwner},
    task_runtime::{RuntimeAction, RuntimeEvent},
};
use nexus_domain::task::*;
use std::{fs, os::unix::fs::PermissionsExt};
struct Fixture {
    config: PathBuf,
    root: PathBuf,
    id: TaskId,
    request: SubmitTaskRequest,
    service: LocalTaskService,
    principal: String,
}
impl Fixture {
    fn new() -> Self {
        Self::with_outputs(vec![])
    }
    fn with_outputs(outputs: Vec<OutputSpec>) -> Self {
        let config =
            std::env::temp_dir().join(format!("n36-service-{}", new_task_id().unwrap().as_str()));
        fs::create_dir(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let mut request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
            "../../../docs/contracts/n3-submit.example.json"
        ))
        .unwrap();
        request.outputs = outputs;
        fs::write(
            config.join("task-api.toml"),
            format!(
                "provider = {:?}\nworkspace = {:?}\n",
                request.provider, request.workspace
            ),
        )
        .unwrap();
        let principal = nexus::task_authorization::authenticated_principal(&config).unwrap();
        let root = config.join("data/n3/tasks");
        // Explicit test-origin provisioning precedes the existing-only service.
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root.parent().unwrap())
            .unwrap();
        let snapshots = crate::snapshot_store::FileSnapshotStore::open(&root).unwrap();
        let mut workspace = nexus_workspace::Workspace::init(
            nexus_workspace::WorkspaceId(request.workspace.clone()),
            nexus_storage::InMemoryContentStore::new(),
            nexus_workspace::AuthorId("test".into()),
        )
        .unwrap();
        let base = workspace.heads().heads[0].clone();
        let commit = workspace
            .commit_changes(
                &base,
                &[nexus_workspace::Change {
                    path: "input.txt".into(),
                    content: b"fixed input".to_vec(),
                }],
            )
            .unwrap();
        request.input_snapshot = snapshots
            .stage_snapshot(
                &workspace,
                &commit,
                &nexus_workspace::snapshot::SnapshotSelection {
                    include: vec![".".into()],
                    exclude: vec![],
                    executable: vec![],
                },
            )
            .unwrap()
            .reference;
        let owner = TaskOwner::new(
            crate::task_store::FileTaskAcceptanceStore::open(&root).unwrap(),
            sha256,
            new_task_id,
        );
        let now = nexus::n2_store::now_unix_pub();
        let accepted = owner
            .accept_verified(
                request.clone(),
                AcceptanceContext {
                    authenticated_principal: principal.clone(),
                    provider: request.provider.clone(),
                    environment_evidence: request.environment.clone(),
                    capacity_reservation_id: "test-explicit-fixture-not-service-reservation".into(),
                    now_unix: now,
                    prepare_deadline_unix: now + 60,
                    delivery_deadline_unix: now + 600,
                },
            )
            .unwrap();
        let service = LocalTaskService::open(&config);
        let fixture = Self {
            config,
            root,
            id: accepted.task.view.task_id,
            request,
            service,
            principal,
        };
        fixture.grant(false, None);
        fixture
    }
    fn grant(&self, revoked: bool, expiry: Option<u64>) {
        let key = format!(
            "n2/grant/{}/{}/{}",
            self.request.workspace, self.request.resource, self.principal
        );
        let grant = serde_json::json!({"workspace":self.request.workspace,"name":self.request.resource,"principal":self.principal,"operations":["use"],"not_after":expiry,"revoked":revoked});
        N2Store::open(&self.config)
            .unwrap()
            .kv()
            .put(&key, &serde_json::to_vec(&grant).unwrap())
            .unwrap();
    }
    fn get(&self) -> TaskEnvelope {
        self.service.execute(TaskRequest::Get {
            task_id: self.id.clone(),
        })
    }
    fn state(&self) -> TaskView {
        let TaskEnvelope::Success(TaskResponse::Task(state)) = self.get() else {
            panic!("{:?}", self.get())
        };
        *state
    }
    fn owner(&self) -> TaskOwner<crate::task_store::FileTaskAcceptanceStore> {
        TaskOwner::new(
            crate::task_store::FileTaskAcceptanceStore::open(&self.root).unwrap(),
            sha256,
            new_task_id,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.config);
    }
}
fn error(envelope: TaskEnvelope) -> TaskError {
    match envelope {
        TaskEnvelope::Error { error, .. } => error,
        other => panic!("expected error: {other:?}"),
    }
}
#[test]
fn real_current_grants_revoke_expire_and_durable_audit() {
    let f = Fixture::new();
    assert_eq!(f.state().task_id, f.id);
    let before = N2Store::open(&f.config)
        .unwrap()
        .replay_journal()
        .unwrap()
        .len();
    f.grant(true, None);
    assert_eq!(error(f.get()).code, TaskErrorCode::AuthDenied);
    f.grant(false, Some(1));
    assert_eq!(error(f.get()).code, TaskErrorCode::AuthDenied);
    f.grant(false, None);
    assert_eq!(f.state().task_id, f.id);
    assert_eq!(
        N2Store::open(&f.config)
            .unwrap()
            .replay_journal()
            .unwrap()
            .len(),
        before + 3
    );
}
#[test]
fn service_cancel_is_durable_repeated_and_cold_reopen_preserves_authority() {
    let f = Fixture::new();
    let first = f.service.execute(TaskRequest::Cancel {
        task_id: f.id.clone(),
    });
    let TaskEnvelope::Success(TaskResponse::Task(first)) = first else {
        panic!("cancel failed")
    };
    assert_eq!(first.outcome, TaskOutcome::Cancelled);
    assert_eq!(first.cancellation.state, CancellationState::Confirmed);
    let second = f.service.execute(TaskRequest::Cancel {
        task_id: f.id.clone(),
    });
    let TaskEnvelope::Success(TaskResponse::Task(second)) = second else {
        panic!("repeat failed")
    };
    assert_eq!(first.outcome, second.outcome);
    let reopened = LocalTaskService::open(&f.config);
    assert_eq!(
        reopened.execute(TaskRequest::Get {
            task_id: f.id.clone()
        }),
        f.get()
    );
}
#[test]
fn service_waiting_logs_artifacts_and_submit_gate_do_not_accept() {
    let f = Fixture::new();
    let TaskEnvelope::Success(TaskResponse::Logs(page)) =
        f.service.execute(TaskRequest::ReadLogs {
            task_id: f.id.clone(),
            stream: nexus_control_api::task::LogStream::Stdout,
            offset: 0,
            max_bytes: 4,
        })
    else {
        panic!("logs failed")
    };
    assert!(page.bytes.is_empty() && !page.eof);
    let TaskEnvelope::Success(TaskResponse::Artifacts(list)) =
        f.service.execute(TaskRequest::ListArtifacts {
            task_id: f.id.clone(),
        })
    else {
        panic!("artifacts failed")
    };
    assert!(list.records.is_empty());
    let bytes = fs::read(f.root.join("acceptance-v1.json")).unwrap();
    assert_eq!(
        error(f.service.execute(TaskRequest::Submit {
            request: Box::new(f.request.clone())
        }))
        .code,
        TaskErrorCode::UnsupportedCapability
    );
    assert_eq!(bytes, fs::read(f.root.join("acceptance-v1.json")).unwrap());
}
#[test]
fn scope_mismatch_is_real_adapter_refusal_even_if_grant_would_allow() {
    let f = Fixture::new();
    let service = f.service.provider.as_ref().unwrap().as_ref().unwrap();
    let context =
        TaskCallContext::from_authenticated("other-principal".into(), f.request.workspace.clone())
            .unwrap();
    use nexus_control_api::task::TaskApplicationService;
    assert_eq!(
        service
            .execute(
                &context,
                TaskRequest::Get {
                    task_id: f.id.clone()
                }
            )
            .unwrap_err()
            .code,
        TaskErrorCode::AuthDenied
    );
    let records = N2Store::open(&f.config).unwrap().replay_journal().unwrap();
    let event: serde_json::Value = serde_json::from_slice(records.last().unwrap()).unwrap();
    assert_eq!(event["event"], "n3.adapter_refusal");
    assert_eq!(event["principal"], "other-principal");
    assert!(event.get("decision").is_none());
}
#[test]
fn lost_authority_is_never_recreated_and_audit_failure_refuses() {
    let f = Fixture::new();
    let bytes = fs::read(f.root.join("acceptance-v1.json")).unwrap();
    fs::remove_file(f.root.join("acceptance-v1.json")).unwrap();
    assert_eq!(error(f.get()).code, TaskErrorCode::StateCorrupt);
    assert!(!f.root.join("acceptance-v1.json").exists());
    fs::write(f.root.join("acceptance-v1.json"), bytes).unwrap();
    let journal = f.config.join("n2/journal.log");
    fs::remove_file(&journal).unwrap();
    fs::create_dir(&journal).unwrap();
    assert_eq!(error(f.get()).code, TaskErrorCode::PersistenceFailed);
}
#[test]
fn natural_exit_cancel_too_late_preserves_real_exit() {
    let f = Fixture::new();
    let owner = f.owner();
    for (sequence, action) in [
        RuntimeAction::Prepare,
        RuntimeAction::StartIntent {
            handle: "test-handle".into(),
        },
        RuntimeAction::Started {
            at_unix: nexus::n2_store::now_unix_pub(),
        },
        RuntimeAction::Exited { exit_code: 7 },
    ]
    .into_iter()
    .enumerate()
    {
        owner
            .record_event(
                &f.id,
                RuntimeEvent {
                    sequence: sequence as u64 + 1,
                    action,
                },
            )
            .unwrap();
    }
    let TaskEnvelope::Success(TaskResponse::Task(view)) = f.service.execute(TaskRequest::Cancel {
        task_id: f.id.clone(),
    }) else {
        panic!("late cancel failed")
    };
    assert_eq!(view.cancellation.state, CancellationState::TooLate);
    assert_eq!(view.execution.exit_code, Some(7));
    assert_eq!(view.outcome, TaskOutcome::Unfinished);
}
#[test]
fn damaged_config_disabled_and_missing_task_have_distinct_errors() {
    let f = Fixture::new();
    let unknown = TaskId::new("missing".into()).unwrap();
    assert!(matches!(
        f.service.execute(TaskRequest::Get { task_id: unknown }),
        TaskEnvelope::Error { .. }
    ));
    fs::write(
        f.config.join("task-api.toml"),
        "provider='x'\nworkspace='y'\nprincipal='forged'\n",
    )
    .unwrap();
    assert_eq!(
        error(LocalTaskService::open(&f.config).execute(TaskRequest::Get {
            task_id: f.id.clone()
        }))
        .code,
        TaskErrorCode::InvalidRequest
    );
    fs::remove_file(f.config.join("task-api.toml")).unwrap();
    assert_eq!(
        error(LocalTaskService::open(&f.config).execute(TaskRequest::Get {
            task_id: f.id.clone()
        }))
        .code,
        TaskErrorCode::UnsupportedCapability
    );
    assert_eq!(
        crate::task_store::FileTaskAcceptanceStore::open(&f.root)
            .unwrap()
            .read()
            .unwrap()
            .tasks
            .len(),
        1
    );
}

#[test]
fn registered_artifact_pages_bind_record_task_and_original_bytes() {
    let f = Fixture::with_outputs(vec![OutputSpec {
        path: "result".into(),
        required: true,
    }]);
    let owner = f.owner();
    for (index, action) in [
        RuntimeAction::Prepare,
        RuntimeAction::StartIntent {
            handle: format!("docker:{}:{}", "a".repeat(64), "b".repeat(64)),
        },
        RuntimeAction::Started {
            at_unix: nexus::n2_store::now_unix_pub(),
        },
        RuntimeAction::Exited { exit_code: 0 },
    ]
    .into_iter()
    .enumerate()
    {
        owner
            .record_event(
                &f.id,
                RuntimeEvent {
                    sequence: index as u64 + 1,
                    action,
                },
            )
            .unwrap();
    }
    // Explicit local sealed-evidence fixture, not physical Engine evidence.
    let mut tar = vec![0u8; 512];
    let name = b"work/result";
    tar[..name.len()].copy_from_slice(name);
    for (range, value) in [
        (100..108, 0o644u64),
        (108..116, 0),
        (116..124, 0),
        (124..136, 6),
        (136..148, 0),
    ] {
        let width = range.len() - 1;
        tar[range].copy_from_slice(format!("{value:0width$o}\0").as_bytes());
    }
    tar[156] = b'0';
    tar[148..156].fill(b' ');
    let checksum: u64 = tar.iter().map(|b| u64::from(*b)).sum();
    tar[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    tar.extend_from_slice(b"result");
    tar.resize(2048, 0);
    crate::task_executor::stage_fixture(&f.root, &owner.runtime(&f.id).unwrap(), &tar).unwrap();
    crate::task_artifacts::FileTaskArtifacts::open(&f.root)
        .unwrap()
        .publish(&f.id, 60)
        .unwrap();
    let TaskEnvelope::Success(TaskResponse::Artifacts(list)) =
        f.service.execute(TaskRequest::ListArtifacts {
            task_id: f.id.clone(),
        })
    else {
        panic!("registered catalog failed")
    };
    assert_eq!(list.records.len(), 1);
    let record = list.records[0].clone();
    let TaskEnvelope::Success(TaskResponse::Artifact(page)) =
        f.service.execute(TaskRequest::GetArtifact {
            artifact_id: record.artifact_id.clone(),
            offset: 2,
            max_bytes: 3,
        })
    else {
        panic!("artifact page failed")
    };
    assert_eq!(page.record, record);
    assert_eq!(page.record.task_id, f.id);
    assert_eq!(page.bytes, b"sul");
    assert_eq!(page.next_offset, 5);
    assert!(!page.eof);
    let TaskEnvelope::Success(TaskResponse::Logs(page)) =
        f.service.execute(TaskRequest::ReadLogs {
            task_id: f.id.clone(),
            stream: nexus_control_api::task::LogStream::Stdout,
            offset: 1,
            max_bytes: 4,
        })
    else {
        panic!("published logs failed")
    };
    assert_eq!(page.bytes, b"tdou");
    assert_eq!(page.next_offset, 5);
    assert!(!page.eof);
    f.grant(true, None);
    assert_eq!(
        error(f.service.execute(TaskRequest::GetArtifact {
            artifact_id: record.artifact_id,
            offset: 0,
            max_bytes: 6
        }))
        .code,
        TaskErrorCode::AuthDenied
    );
}
#[test]
fn public_or_symlinked_identity_never_becomes_authenticated_context() {
    let f = Fixture::new();
    let store = N2Store::open(&f.config).unwrap();
    let path = store
        .kv()
        .dir()
        .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(error(f.get()).code, TaskErrorCode::PersistenceFailed);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let other = f.config.join("identity-replacement");
    fs::rename(&path, &other).unwrap();
    std::os::unix::fs::symlink(&other, &path).unwrap();
    assert_eq!(error(f.get()).code, TaskErrorCode::PersistenceFailed);
}
