use super::*;
use crate::{
    task_artifacts::{ArtifactAccess, FileTaskArtifacts},
    task_executor::{LinuxTaskExecutor, LogStream},
    task_store::FileTaskAcceptanceStore,
};
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_compute::{
    task::{TaskAcceptanceStore, TaskOwner},
    task_runtime::RuntimeState,
};
use nexus_control_api::task::{
    TaskApplicationService, TaskArtifactList, TaskArtifactPage, TaskLogsPage,
};
use nexus_domain::task::{AcceptedContract, ExecutionState};
use std::fs;

pub(super) struct ProviderService {
    config_root: PathBuf,
    root: PathBuf,
    provider: String,
    workspace: String,
    owner: TaskOwner<FileTaskAcceptanceStore>,
    executor: LinuxTaskExecutor,
    artifacts: FileTaskArtifacts,
}
impl ProviderService {
    pub(super) fn open(
        config_root: &Path,
        provider: &str,
        workspace: &str,
    ) -> Result<Self, TaskError> {
        let metadata = fs::symlink_metadata(config_root).map_err(io)?;
        use std::os::unix::fs::PermissionsExt;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(TaskError::new(
                TaskErrorCode::PersistenceFailed,
                "N3 config directory must be private and real",
                false,
            ));
        }
        let root = config_root.join("data/n3/tasks");
        // Preserve the fixed-root ancestor checks without provisioning them.
        let mut path = config_root.to_owned();
        for component in ["data", "n3"] {
            path.push(component);
            let metadata = fs::symlink_metadata(&path).map_err(|_| {
                TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    "existing Task root ancestor is missing",
                    false,
                )
            })?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    "Task root ancestors must be private real directories",
                    false,
                ));
            }
        }
        // This batch serves previously accepted Tasks. It cannot provision a
        // provider authority or infer a fresh provider from a missing directory.
        let store = FileTaskAcceptanceStore::open_existing(&root)?;
        let owner = TaskOwner::new(store.clone(), sha256, new_task_id);
        let artifacts = FileTaskArtifacts::open(&root)?;
        let executor = LinuxTaskExecutor::open(&root, Vec::new())?;
        let snapshots = crate::snapshot_store::FileSnapshotStore::open(&root)?;
        for task in store.read()?.tasks {
            snapshots.verify_inputs(
                &task.view.accepted_contract.request.input_snapshot,
                &task.view.accepted_contract.request.cwd,
            )?;
            match executor.reconcile(&task.view.task_id) {
                Ok(_) => {}
                Err(e) if e.code == TaskErrorCode::CapacityUnavailable => {} // original live owner remains sole authority
                Err(e) => return Err(e),
            }
        }
        Ok(Self {
            config_root: config_root.to_owned(),
            root,
            provider: provider.to_owned(),
            workspace: workspace.to_owned(),
            owner,
            executor,
            artifacts,
        })
    }
    pub(super) fn workspace(&self) -> &str {
        &self.workspace
    }
    fn authorize(
        &self,
        context: &TaskCallContext,
        contract: &AcceptedContract,
        id: &TaskId,
    ) -> Result<(), TaskError> {
        nexus::task_authorization::authorize_contract(
            &self.config_root,
            context.principal(),
            context.workspace(),
            &self.provider,
            contract,
            id.as_str(),
        )
    }
    fn state(&self, context: &TaskCallContext, id: &TaskId) -> Result<RuntimeState, TaskError> {
        match self.owner.runtime(id) {
            Ok(state) => {
                self.authorize(context, &state.view.accepted_contract, id)?;
                Ok(state)
            }
            Err(error) => {
                nexus::task_authorization::audit_refusal(
                    &self.config_root,
                    context.principal(),
                    context.workspace(),
                    Some(id.as_str()),
                    &format!("Task authority lookup refused: {}", error.code.as_str()),
                )?;
                Err(error)
            }
        }
    }
}
impl TaskApplicationService for ProviderService {
    fn execute(
        &self,
        context: &TaskCallContext,
        request: TaskRequest,
    ) -> Result<TaskResponse, TaskError> {
        request.validate()?;
        match request {
            TaskRequest::Submit { request } => {
                if request.workspace != context.workspace() || request.provider != self.provider {
                    nexus::task_authorization::audit_refusal(
                        &self.config_root,
                        context.principal(),
                        context.workspace(),
                        None,
                        "Submit scope mismatch",
                    )?;
                    return Err(TaskError::new(
                        TaskErrorCode::AuthDenied,
                        "Submit scope mismatch",
                        false,
                    ));
                }
                nexus::task_authorization::authorize_use(
                    &self.config_root,
                    context.principal(),
                    context.workspace(),
                    &request.resource,
                )?;
                nexus::task_authorization::audit_refusal(
                    &self.config_root,
                    context.principal(),
                    context.workspace(),
                    None,
                    "Submit prerequisites are not assembled",
                )?;
                Err(unsupported(
                    "Submit requires real capacity, Session and authenticated input transport; not assembled",
                ))
            }
            TaskRequest::Get { task_id } => Ok(TaskResponse::Task(Box::new(
                self.state(context, &task_id)?.view,
            ))),
            TaskRequest::Cancel { task_id } => {
                self.state(context, &task_id)?;
                Ok(TaskResponse::Task(Box::new(
                    self.executor.cancel(&task_id, "User")?.view,
                )))
            }
            TaskRequest::ReadLogs {
                task_id,
                stream,
                offset,
                max_bytes,
            } => {
                let state = self.state(context, &task_id)?;
                let selected = match stream {
                    nexus_control_api::task::LogStream::Stdout => LogStream::Stdout,
                    nexus_control_api::task::LogStream::Stderr => LogStream::Stderr,
                };
                let access = ArtifactAccess {
                    principal: context.principal(),
                    workspace: context.workspace(),
                };
                let page = if self.artifacts.logs_registered(&task_id)? {
                    self.artifacts.logs(
                        &task_id,
                        access,
                        selected,
                        offset,
                        max_bytes as usize,
                        &mut |contract| self.authorize(context, contract, &task_id),
                    )?
                } else {
                    let directory = self
                        .root
                        .join("executions-v1")
                        .join(&sha256(task_id.as_str().as_bytes()).as_str()[7..]);
                    if state.view.execution.state == ExecutionState::NotStarted
                        && state.execution_handle.is_none()
                        && !directory.try_exists().map_err(io)?
                    {
                        if offset != 0 {
                            return Err(TaskError::invalid("offset beyond not-started logs"));
                        }
                        crate::task_executor::LogPage {
                            bytes: Vec::new(),
                            next_offset: 0,
                            eof: false,
                            truncated: false,
                        }
                    } else {
                        self.executor
                            .logs(&task_id, selected, offset, max_bytes as usize)?
                    }
                };
                Ok(TaskResponse::Logs(TaskLogsPage {
                    task_id,
                    stream,
                    offset,
                    bytes: page.bytes,
                    next_offset: page.next_offset,
                    eof: page.eof,
                    truncated: page.truncated,
                }))
            }
            TaskRequest::ListArtifacts { task_id } => {
                self.state(context, &task_id)?;
                let records = self.artifacts.list(
                    &task_id,
                    ArtifactAccess {
                        principal: context.principal(),
                        workspace: context.workspace(),
                    },
                    &mut |contract| self.authorize(context, contract, &task_id),
                )?;
                Ok(TaskResponse::Artifacts(TaskArtifactList {
                    task_id,
                    records,
                }))
            }
            TaskRequest::GetArtifact {
                artifact_id,
                offset,
                max_bytes,
            } => {
                let mut record = None;
                let result = self.artifacts.get(
                    &artifact_id,
                    ArtifactAccess {
                        principal: context.principal(),
                        workspace: context.workspace(),
                    },
                    offset,
                    max_bytes as usize,
                    &mut |found| {
                        self.state(context, &found.task_id)?;
                        record = Some(found.clone());
                        Ok(())
                    },
                );
                let page = match result {
                    Ok(page) => page,
                    Err(error) => {
                        nexus::task_authorization::audit_refusal(
                            &self.config_root,
                            context.principal(),
                            context.workspace(),
                            None,
                            &format!("Artifact operation refused: {}", error.code.as_str()),
                        )?;
                        return Err(error);
                    }
                };
                let record = record.ok_or_else(|| {
                    TaskError::new(
                        TaskErrorCode::StateCorrupt,
                        "Artifact authorization record absent",
                        false,
                    )
                })?;
                Ok(TaskResponse::Artifact(Box::new(TaskArtifactPage {
                    record,
                    offset,
                    bytes: page.bytes,
                    next_offset: page.next_offset,
                    eof: page.eof,
                })))
            }
        }
    }
}
fn io(error: std::io::Error) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}
