//! Local authority E2/E3 only. No Submit, workload or full-N3 success is claimed.
use super::*;
use crate::{
    task_capacity::{CapacityBudget, ExecutorBackendOverhead, ProviderCapacityPolicy},
    task_capacity_recovery::{begin_capacity_owner_recovery, finish_capacity_owner_recovery},
    task_executor::LinuxTaskExecutor,
    task_service::LocalTaskService,
};
use nexus::n2_store::{N2Store, NameEntry};
use nexus_compute::task::AcceptanceContext;
use nexus_control_api::task::{TaskEnvelope, TaskRequest, TaskResponse};
use nexus_domain::{
    Constraint, Intent, PlanSnapshot, ProviderId, ResourceId, ResourceName, WorkspaceId, task::*,
};
use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionRecord};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

struct Fixture {
    config: PathBuf,
    root: PathBuf,
    id: TaskId,
    sid: SessionId,
    request: SubmitTaskRequest,
    sessions: SharedSessionManager,
    fail_next_save: Arc<AtomicBool>,
    service: Option<LocalTaskService>,
    retain: bool,
}
struct FailOnceStore {
    store: nexus::n2_store::KvSessionRecordStore,
    fail: Arc<AtomicBool>,
}
impl SessionRecordStore for FailOnceStore {
    fn load(&self) -> Result<Vec<SessionRecord>, String> {
        self.store.load()
    }
    fn save(&mut self, record: &SessionRecord) -> Result<(), String> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err("injected Session persistence failure before publish".into());
        }
        self.store.save(record)
    }
}
impl Fixture {
    fn new() -> Self {
        let config =
            std::env::temp_dir().join(format!("n38-session-{}", new_task_id().unwrap().as_str()));
        Self::at(config, false)
    }
    fn at(config: PathBuf, retain: bool) -> Self {
        fs::create_dir_all(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let root = config.join("data/n3/tasks");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root.parent().unwrap())
            .unwrap();
        let store = FileTaskAcceptanceStore::provision_capacity(&root, &policy()).unwrap();
        let guard = begin_capacity_owner_recovery(&store).unwrap();
        let executor = LinuxTaskExecutor::open(&root, vec![]).unwrap();
        let snapshots = crate::snapshot_store::FileSnapshotStore::open(&root).unwrap();
        finish_capacity_owner_recovery(&store, &executor, guard.as_ref()).unwrap();
        let mut request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
            "../../../docs/contracts/n3-submit.example.json"
        ))
        .unwrap();
        request.workspace = "explicit-workspace".into();
        request.resource = "actual-compute".into();
        request.provider = "actual-provider".into();
        request.outputs = vec![];
        request.limits = TaskLimits {
            timeout_seconds: 60,
            cpu_millis: 1000,
            memory_bytes: 16 * 1024 * 1024,
            storage_bytes: 64 * 1024,
            log_bytes: 4096,
        };
        let mut workspace = nexus_workspace::Workspace::init(
            nexus_workspace::WorkspaceId(request.workspace.clone()),
            nexus_storage::InMemoryContentStore::new(),
            nexus_workspace::AuthorId("session-test".into()),
        )
        .unwrap();
        let base = workspace.heads().heads[0].clone();
        let commit = workspace
            .commit_changes(
                &base,
                &[nexus_workspace::Change {
                    path: "input.txt".into(),
                    content: b"immutable actual input".to_vec(),
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
        let principal = nexus::task_authorization::authenticated_principal(&config).unwrap();
        let owner = TaskOwner::new(store.clone(), sha256, new_task_id);
        let accepted = owner
            .accept_verified(request.clone(), context(&request, &principal))
            .unwrap();
        let n2 = N2Store::open(&config).unwrap();
        let resource = ResourceId("opaque-resource-id".into());
        let provider = ProviderId(request.provider.clone());
        n2.upsert_name(NameEntry {
            workspace: WorkspaceId(request.workspace.clone()),
            name: ResourceName::new(&request.resource).unwrap(),
            resource_id: resource.clone(),
            kind: Some(nexus_domain::ResourceKind::Compute),
        })
        .unwrap();
        n2.save_ad(&nexus_registry::ProviderAdvertisement {
            provider: provider.clone(),
            resource: resource.clone(),
            capabilities: vec!["task-test".into()],
            locators: vec!["local-provider".into()],
            discoverable_by: nexus_registry::Discoverability::Public,
            use_grants: vec![],
            unavailable: None,
            issued_at_secs: nexus::n2_store::now_unix_pub(),
            ttl_secs: 0,
        })
        .unwrap();
        let candidate = nexus_registry::ProviderRecord {
            id: provider.clone(),
            resource: resource.clone(),
            placement: "local".into(),
            locator: "local-provider".into(),
            capabilities: vec!["task-test".into()],
            present: true,
        };
        let planned = nexus_planner::plan(
            &resource,
            &Intent {
                profile: "task-test".into(),
            },
            &[Constraint {
                key: "capability".into(),
                value: "task-test".into(),
            }],
            &[candidate],
            |_| None,
        )
        .unwrap();
        let snapshot = PlanSnapshot::from_planned(planned.plan, planned.trace);
        let fail_next_save = Arc::new(AtomicBool::new(false));
        // Exactly one Manager in this composition, with an injectable storage failure.
        let mut manager = SessionManager::new(
            Box::new(FailOnceStore {
                store: n2.sessions(),
                fail: fail_next_save.clone(),
            }),
            DEFAULT_ATTACH_WINDOW_SECS,
        );
        manager.load_from_store().unwrap();
        let sid = manager.open(resource, provider, snapshot).unwrap();
        let sessions = Arc::new(Mutex::new(Some(manager)));
        let grant_key = format!(
            "n2/grant/{}/{}/{}",
            request.workspace, request.resource, principal
        );
        n2.kv().put(&grant_key, &serde_json::to_vec(&json!({"workspace":request.workspace,"name":request.resource,"principal":principal,"operations":["use"],"not_after":null,"revoked":false})).unwrap()).unwrap();
        fs::write(
            config.join("task-api.toml"),
            format!(
                "provider = {:?}\nworkspace = {:?}\n",
                request.provider, request.workspace
            ),
        )
        .unwrap();
        drop(guard);
        let service = LocalTaskService::open_with_sessions(&config, sessions.clone());
        let fixture = Self {
            config,
            root,
            id: accepted.task.view.task_id,
            sid,
            request,
            sessions,
            fail_next_save,
            service: Some(service),
            retain,
        };
        assert_eq!(fixture.view().outcome, TaskOutcome::Unfinished);
        fixture
    }
    fn service(&self) -> &LocalTaskService {
        self.service.as_ref().unwrap()
    }
    fn owner(&self) -> TaskOwner<FileTaskAcceptanceStore> {
        TaskOwner::new(
            FileTaskAcceptanceStore::open(&self.root).unwrap(),
            sha256,
            new_task_id,
        )
    }
    fn view(&self) -> TaskView {
        match self.service().execute(TaskRequest::Get {
            task_id: self.id.clone(),
        }) {
            TaskEnvelope::Success(TaskResponse::Task(view)) => *view,
            other => panic!("real Task service refused: {other:?}"),
        }
    }
    fn bind(&self) -> RuntimeState {
        self.service()
            .prepare_with_existing_session(&self.id, &self.sid)
            .unwrap()
    }
    fn cancel(&self) -> TaskEnvelope {
        self.service().execute(TaskRequest::Cancel {
            task_id: self.id.clone(),
        })
    }
    fn durable_session(&self) -> SessionRecord {
        N2Store::open(&self.config)
            .unwrap()
            .sessions()
            .load()
            .unwrap()
            .into_iter()
            .find(|record| record.session == self.sid)
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.service.take();
        if !self.retain {
            let _ = fs::remove_dir_all(&self.config);
        }
    }
}
fn policy() -> ProviderCapacityPolicy {
    ProviderCapacityPolicy {
        total: CapacityBudget {
            cpu_millis: 10000,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            pids: 2000,
            runtime_storage_bytes: 256 * 1024 * 1024,
            backend_disk_bytes: 2 * 1024 * 1024 * 1024,
            slots: 10,
        },
        fixed: CapacityBudget {
            cpu_millis: 100,
            memory_bytes: 16 * 1024 * 1024,
            pids: 4,
            runtime_storage_bytes: 4096,
            backend_disk_bytes: 16 * 1024 * 1024,
            slots: 1,
        },
        overhead: ExecutorBackendOverhead {
            cpu_millis: 10,
            memory_bytes: 8 * 1024 * 1024,
            pids: 2,
            backend_disk_bytes: 1024 * 1024,
        },
    }
}
fn context(request: &SubmitTaskRequest, principal: &str) -> AcceptanceContext {
    let now = nexus::n2_store::now_unix_pub();
    AcceptanceContext {
        authenticated_principal: principal.into(),
        provider: request.provider.clone(),
        environment_evidence: request.environment.clone(),
        capacity_reservation_id: new_task_id().unwrap().as_str().into(),
        now_unix: now,
        prepare_deadline_unix: now + 60,
        delivery_deadline_unix: now + 600,
    }
}

#[test]
fn existing_actual_plan_binding_deduplicates_and_refuses_cross_task_reuse() {
    let fixture = Fixture::new();
    let bound = fixture.bind();
    assert_eq!(
        bound.view.session_ids.as_slice(),
        std::slice::from_ref(&fixture.sid.0)
    );
    assert_eq!(fixture.bind(), bound);
    assert_eq!(
        fixture
            .owner()
            .accepted(&fixture.id)
            .unwrap()
            .unwrap()
            .view
            .session_ids,
        Vec::<String>::new()
    );
    let mut other = fixture.request.clone();
    other.idempotency_key = "different-task-key".into();
    let principal = nexus::task_authorization::authenticated_principal(&fixture.config).unwrap();
    let second = fixture
        .owner()
        .accept_verified(other.clone(), context(&other, &principal))
        .unwrap();
    assert_eq!(
        fixture
            .service()
            .prepare_with_existing_session(&second.task.view.task_id, &fixture.sid)
            .unwrap_err()
            .code,
        TaskErrorCode::InvalidRequest
    );
    assert_eq!(
        fixture.durable_session().outcome,
        TerminalOutcome::Unfinished
    );
}

#[test]
fn tampered_plan_hash_and_explicit_workspace_mismatch_are_rejected() {
    let fixture = Fixture::new();
    let mut bad = fixture
        .sessions
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .get(&fixture.sid)
        .unwrap()
        .plan_snapshot
        .unwrap();
    bad.plan_id.0 = "forged-plan".into();
    let bad_id = fixture
        .sessions
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .open(
            bad.plan.resource_id.clone(),
            bad.plan.provider_id.clone(),
            bad,
        )
        .unwrap();
    assert_eq!(
        fixture
            .service()
            .prepare_with_existing_session(&fixture.id, &bad_id)
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    let n2 = N2Store::open(&fixture.config).unwrap();
    let mut names = n2.load_names().unwrap();
    names[0].workspace = WorkspaceId("default".into());
    n2.save_names(&names).unwrap();
    assert_eq!(
        fixture
            .service()
            .prepare_with_existing_session(&fixture.id, &fixture.sid)
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert!(
        fixture
            .owner()
            .runtime(&fixture.id)
            .unwrap()
            .view
            .session_ids
            .is_empty()
    );
}

#[test]
fn confirmed_never_started_cancel_closes_only_after_durable_intent_and_retries_failed_save() {
    let fixture = Fixture::new();
    fixture.bind();
    fixture.fail_next_save.store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture.cancel(),
        TaskEnvelope::Error {
            error: TaskError {
                code: TaskErrorCode::PersistenceFailed,
                ..
            },
            ..
        }
    ));
    let task = fixture.owner().runtime(&fixture.id).unwrap();
    assert_eq!(task.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(task.view.cancellation.state, CancellationState::Confirmed);
    assert_eq!(
        fixture.durable_session().outcome,
        TerminalOutcome::Unfinished
    );
    let pending = disk::load(&fixture.root.join("session-cleanup-v1").join(INTENTS)).unwrap();
    assert_eq!(pending["intents"].as_array().unwrap().len(), 1);
    assert_eq!(fixture.view().outcome, TaskOutcome::Cancelled); // production GET replays confirmed intent, without creating Session
    let record = fixture.durable_session();
    assert_eq!(record.phase, LifecyclePhase::Disposed);
    assert_eq!(record.outcome, TerminalOutcome::Cancelled);
    assert!(
        disk::load(&fixture.root.join("session-cleanup-v1").join(INTENTS)).unwrap()["intents"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .owner()
            .runtime(&fixture.id)
            .unwrap()
            .execution_handle,
        None
    );
}

#[test]
fn failed_orphan_session_on_boot_does_not_fail_task_or_create_another_session() {
    let mut fixture = Fixture::new();
    fixture.bind();
    fixture.service.take();
    fixture.sessions = Arc::new(Mutex::new(None));
    let restored = crate::assembly::assemble_n2_session_manager(&fixture.config).unwrap();
    assert!(matches!(
        restored.get(&fixture.sid).unwrap().outcome,
        TerminalOutcome::Failed(_)
    ));
    let sessions = Arc::new(Mutex::new(Some(restored)));
    let service = LocalTaskService::open_with_sessions(&fixture.config, sessions.clone());
    let TaskEnvelope::Success(TaskResponse::Task(view)) = service.execute(TaskRequest::Get {
        task_id: fixture.id.clone(),
    }) else {
        panic!("intact historical Session binding must recover")
    };
    assert_eq!(view.outcome, TaskOutcome::Unfinished);
    assert_eq!(view.session_ids, [fixture.sid.0.clone()]);
    assert_eq!(sessions.lock().unwrap().as_ref().unwrap().len(), 1);
    assert_eq!(
        fixture
            .owner()
            .runtime(&fixture.id)
            .unwrap()
            .execution_handle,
        None
    );
}

#[test]
fn missing_cleanup_authority_blocks_recovery_without_erasing_task() {
    let mut fixture = Fixture::new();
    fixture.bind();
    fixture.service.take();
    fs::remove_file(fixture.root.join("session-cleanup-v1").join(INTENTS)).unwrap();
    let service = LocalTaskService::open_with_sessions(&fixture.config, fixture.sessions.clone());
    assert!(matches!(
        service.execute(TaskRequest::Get {
            task_id: fixture.id.clone()
        }),
        TaskEnvelope::Error {
            error: TaskError {
                code: TaskErrorCode::StateCorrupt,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        fixture.owner().runtime(&fixture.id).unwrap().view.outcome,
        TaskOutcome::Unfinished
    );
}

#[test]
fn session_bind_cancel_and_recovery_use_independent_process_authority() {
    let root = std::env::temp_dir().join(format!(
        "n38-session-e3-{}",
        new_task_id().unwrap().as_str()
    ));
    for mode in ["create", "recover"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "task_sessions::tests::session_authority_child",
                "--nocapture",
            ])
            .env("NEXUS_N38_SESSION_CHILD_ROOT", &root)
            .env("NEXUS_N38_SESSION_CHILD_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let store = FileTaskAcceptanceStore::open(&root.join("data/n3/tasks")).unwrap();
    let accepted = store.read().unwrap().tasks;
    assert_eq!(accepted.len(), 1);
    let owner = TaskOwner::new(store, sha256, new_task_id);
    let runtime = owner.runtime(&accepted[0].view.task_id).unwrap();
    assert_eq!(runtime.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(runtime.view.session_ids.len(), 1);
    assert_eq!(runtime.execution_handle, None);
    let record = N2Store::open(&root)
        .unwrap()
        .sessions()
        .load()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(record.phase, LifecyclePhase::Disposed);
    assert_eq!(record.outcome, TerminalOutcome::Cancelled);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn session_authority_child() {
    let Some(root) = std::env::var_os("NEXUS_N38_SESSION_CHILD_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    match std::env::var("NEXUS_N38_SESSION_CHILD_MODE")
        .unwrap()
        .as_str()
    {
        "create" => {
            let fixture = Fixture::at(root, true);
            fixture.bind();
            let TaskEnvelope::Success(TaskResponse::Task(view)) = fixture.cancel() else {
                panic!("actual local cancellation rejected")
            };
            assert_eq!(view.outcome, TaskOutcome::Cancelled);
        }
        "recover" => {
            let manager = crate::assembly::assemble_n2_session_manager(&root).unwrap();
            let sessions = Arc::new(Mutex::new(Some(manager)));
            let service = LocalTaskService::open_with_sessions(&root, sessions);
            let accepted = FileTaskAcceptanceStore::open(&root.join("data/n3/tasks"))
                .unwrap()
                .read()
                .unwrap()
                .tasks
                .pop()
                .unwrap();
            let TaskEnvelope::Success(TaskResponse::Task(view)) =
                service.execute(TaskRequest::Get {
                    task_id: accepted.view.task_id,
                })
            else {
                panic!("cold original Task authority failed")
            };
            assert_eq!(view.outcome, TaskOutcome::Cancelled);
        }
        _ => panic!("unknown authority child mode"),
    }
}
