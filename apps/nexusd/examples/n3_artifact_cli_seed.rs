//! Verification-only seed: a real executor creates a retained Artifact for an
//! ordinary daemon/CLI delivery probe. This is not the public Submit pipeline.
//! Usage: n3_artifact_cli_seed --config <fresh nonexistent directory>
//! Requires the already installed immutable image below; never pulls images.

#[cfg(target_os = "linux")]
mod linux {
    use nexus::{
        n2_store::{N2Store, now_unix_pub},
        n3_acceptance::{decode_dto, new_task_id, sha256},
        task_authorization::{authenticated_principal, authorize_contract},
    };
    use nexus_compute::{
        task::{AcceptanceContext, TaskOwner},
        task_runtime::{RuntimeAction, TaskRuntimeStore},
    };
    use nexus_control_api::task::{TaskEnvelope, TaskRequest, TaskResponse};
    use nexus_domain::task::{
        Observation, OutputSpec, Sha256Digest, SubmitTaskRequest, TaskLimits, TaskOutcome,
        codec::CanonicalDto,
    };
    use nexus_session::{DEFAULT_ATTACH_WINDOW_SECS, SessionManager};
    use nexus_storage::InMemoryContentStore;
    use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId, snapshot::SnapshotSelection};
    use nexusd::{
        snapshot_store::FileSnapshotStore,
        task_artifacts::{ArtifactAccess, FileTaskArtifacts},
        task_capacity::{CapacityBudget, ExecutorBackendOverhead, ProviderCapacityPolicy},
        task_executor::LinuxTaskExecutor,
        task_service::LocalTaskService,
        task_store::FileTaskAcceptanceStore,
    };
    use serde_json::{Value, json};
    use std::{
        error::Error,
        fs,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    const IMAGE: &str = "sha256:30ecbe1509090b38ef3260f3609d64d8261230464eaa4d235901db496e9647fb";
    const ZERO_BYTES: usize = 25 * 4096;

    pub fn run() -> Result<Value, Box<dyn Error>> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        let (operation, flag, directory) = match args.as_slice() {
            [flag, directory] => ("seed", flag, directory),
            [operation, flag, directory] => (operation.as_str(), flag, directory),
            _ => {
                return Err(
                    "usage: n3_artifact_cli_seed [seed|grant|revoke] --config <directory>".into(),
                );
            }
        };
        if flag != "--config" {
            return Err("only --config is accepted".into());
        }
        let config = PathBuf::from(directory);
        if matches!(operation, "grant" | "revoke") {
            let principal = authenticated_principal(&config)?;
            write_grant(&config, &principal, operation == "revoke")?;
            return Ok(json!({"verdict": "PASS", "revoked": operation == "revoke"}));
        }
        if operation != "seed" {
            return Err("unknown seed operation".into());
        }
        // Refuse existing roots, even empty ones. Failed runs retain their
        // evidence and must be inspected rather than silently rerun/reset.
        fs::DirBuilder::new().mode(0o700).create(&config)?;
        let config = config.canonicalize()?;
        let root = config.join("data/n3/tasks");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root.parent().ok_or("task root parent missing")?)?;
        let store = FileTaskAcceptanceStore::provision_capacity(&root, &policy())?;
        let snapshots = FileSnapshotStore::open(&root)?;
        let mut request: SubmitTaskRequest = decode_dto(include_bytes!(
            "../../../docs/contracts/n3-submit.example.json"
        ))?;
        request.workspace = "n39-delivery-workspace".into();
        request.resource = "n39-delivery-compute".into();
        request.provider = "n39-delivery-provider".into();
        request.command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "set -eu; dd if=/dev/zero of=result.bin bs=4096 count=25 2>/dev/null; printf 'n39-end\\n' >>result.bin; printf 'n39-executed\\n'; sleep 0.1".into(),
        ];
        request.cwd = ".".into();
        request.environment.image_digest = Sha256Digest::parse(IMAGE.into())?;
        request.limits = TaskLimits {
            timeout_seconds: 10,
            cpu_millis: 1000,
            memory_bytes: 64 * 1024 * 1024,
            storage_bytes: 1024 * 1024,
            log_bytes: 16384,
        };
        request.outputs = vec![OutputSpec {
            path: "result.bin".into(),
            required: true,
        }];
        request.idempotency_key = "n39-delivery-seed".into();
        let mut workspace = Workspace::init(
            WorkspaceId(request.workspace.clone()),
            InMemoryContentStore::new(),
            AuthorId("n39-verifier".into()),
        )?;
        let base = workspace.heads().heads[0].clone();
        let commit = workspace.commit_changes(
            &base,
            &[Change {
                path: "input.txt".into(),
                content: b"immutable N3-9 verification input\n".to_vec(),
            }],
        )?;
        request.input_snapshot = snapshots
            .stage_snapshot(
                &workspace,
                &commit,
                &SnapshotSelection {
                    include: vec!["input.txt".into()],
                    exclude: vec![],
                    executable: vec![],
                },
            )?
            .reference;
        let principal = authenticated_principal(&config)?;
        let n2 = N2Store::open(&config)?;
        write_grant(&config, &principal, false)?;
        fs::write(
            config.join("task-api.toml"),
            format!(
                "provider = {:?}\nworkspace = {:?}\n",
                request.provider, request.workspace
            ),
        )?;
        let mut manager = SessionManager::new(Box::new(n2.sessions()), DEFAULT_ATTACH_WINDOW_SECS);
        manager.load_from_store()?;
        // The ordinary service owns the genuine private recovery/Ready lease.
        // No public fixture API, fabricated capacity epoch or resource Session.
        let service =
            LocalTaskService::open_with_sessions(&config, Arc::new(Mutex::new(Some(manager))));
        let executor =
            LinuxTaskExecutor::open(&root, vec![request.environment.image_digest.clone()])?;
        executor.verify_environment(&request.environment, &request.limits)?;
        let owner = TaskOwner::new(store.clone(), sha256, new_task_id);
        let now = now_unix_pub();
        let accepted = owner.accept_verified(
            request.clone(),
            AcceptanceContext {
                authenticated_principal: principal.clone(),
                provider: request.provider.clone(),
                environment_evidence: request.environment.clone(),
                capacity_reservation_id: "n39-real-allocation".into(),
                now_unix: now,
                prepare_deadline_unix: now + 60,
                delivery_deadline_unix: now + 3600,
            },
        )?;
        let id = accepted.task.view.task_id;
        executor.run(&id, &mut |contract| {
            authorize_contract(
                &config,
                &principal,
                &request.workspace,
                &request.provider,
                contract,
                id.as_str(),
            )
        })?;
        let artifacts = FileTaskArtifacts::open(&root)?;
        let completed = artifacts.publish(&id, 3600)?;
        if completed.view.outcome != TaskOutcome::Completed
            || completed.view.observation != Observation::Confirmed
            || completed.view.execution.exit_code != Some(0)
        {
            return Err("real execution/publication did not complete successfully".into());
        }
        let TaskEnvelope::Success(TaskResponse::Task(observed)) =
            service.execute(TaskRequest::Get {
                task_id: id.clone(),
            })
        else {
            return Err("ordinary Task service could not authorize the seeded Task".into());
        };
        if *observed != completed.view {
            return Err("service view differs from executor/publication authority".into());
        }
        let records = artifacts.list(
            &id,
            ArtifactAccess {
                principal: &principal,
                workspace: &request.workspace,
            },
            &mut |contract| {
                authorize_contract(
                    &config,
                    &principal,
                    &request.workspace,
                    &request.provider,
                    contract,
                    id.as_str(),
                )
            },
        )?;
        let [record] = records.as_slice() else {
            return Err("expected one retained Artifact".into());
        };
        let mut expected = vec![0; ZERO_BYTES];
        expected.extend_from_slice(b"n39-end\n");
        if record.content_sha256 != sha256(&expected) || record.size_bytes != expected.len() as u64
        {
            return Err("actual Artifact differs from the executed byte recipe".into());
        }
        let (_, journal) = store.runtime_read(&id)?;
        let starts = journal
            .events
            .iter()
            .filter(|event| matches!(event.action, RuntimeAction::Started { .. }))
            .count();
        if starts != 1 {
            return Err("expected exactly one durable real execution start".into());
        }
        let record: Value = serde_json::from_slice(&record.to_value().canonical_bytes())?;
        drop(service);
        Ok(json!({"verdict": "PASS", "config_root": config,
            "task_id": id.as_str(), "artifact": record,
            "execution_handle": completed.execution_handle,
            "contract_digest": completed.view.contract_digest.as_str(),
            "event_sequence": completed.view.last_event_seq,
            "command_start_count": starts, "qualified_image": IMAGE,
            "scope": "real internal executor and publication seed; public Submit remains unsupported"}))
    }

    fn write_grant(
        config: &std::path::Path,
        principal: &str,
        revoked: bool,
    ) -> Result<(), Box<dyn Error>> {
        let n2 = N2Store::open(config)?;
        let workspace = "n39-delivery-workspace";
        let resource = "n39-delivery-compute";
        n2.kv().put(
            &format!("n2/grant/{workspace}/{resource}/{principal}"),
            &serde_json::to_vec(&json!({"workspace": workspace, "name": resource,
                "principal": principal, "operations": ["use"],
                "not_after": null, "revoked": revoked}))?,
        )?;
        Ok(())
    }

    fn policy() -> ProviderCapacityPolicy {
        ProviderCapacityPolicy {
            total: CapacityBudget {
                cpu_millis: 4000,
                memory_bytes: 1024 * 1024 * 1024,
                pids: 1024,
                runtime_storage_bytes: 8 * 1024 * 1024,
                backend_disk_bytes: 512 * 1024 * 1024,
                slots: 2,
            },
            fixed: CapacityBudget {
                cpu_millis: 10,
                memory_bytes: 1024 * 1024,
                pids: 1,
                runtime_storage_bytes: 4096,
                backend_disk_bytes: 1024 * 1024,
                slots: 1,
            },
            overhead: ExecutorBackendOverhead {
                cpu_millis: 10,
                memory_bytes: 256 * 1024 * 1024,
                pids: 8,
                backend_disk_bytes: 1024 * 1024,
            },
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    let result = linux::run().unwrap_or_else(
        |error| serde_json::json!({"verdict": "FAIL", "reason": error.to_string()}),
    );
    #[cfg(not(target_os = "linux"))]
    let result = serde_json::json!({"verdict": "UNKNOWN", "reason": "Linux executor required"});
    println!("{result}");
    if result["verdict"] != "PASS" {
        std::process::exit(1);
    }
}
