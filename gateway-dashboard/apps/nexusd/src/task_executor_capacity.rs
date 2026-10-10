//! Original execution evidence, never a Task outcome or a free owner lock alone.
use super::*;
use crate::artifact_fs as disk;
use std::collections::BTreeSet;

pub(crate) struct CapacityExecutionWitness {
    state: RuntimeState,
    lease: Option<File>,
    releasable: bool,
    preparation_reaped: bool,
}
impl CapacityExecutionWitness {
    pub(crate) fn preparation_reaped(&self) -> bool {
        self.preparation_reaped
    }
    pub(crate) fn into_parts(self) -> (RuntimeState, Option<File>, bool) {
        (self.state, self.lease, self.releasable)
    }
}

impl LinuxTaskExecutor {
    pub(crate) fn capacity_store(&self) -> Result<FileTaskAcceptanceStore, TaskError> {
        FileTaskAcceptanceStore::open_existing(&self.root)
    }
    pub(crate) fn capacity_recovery_witnesses(
        &self,
    ) -> Result<Vec<CapacityExecutionWitness>, TaskError> {
        let ledger = self.capacity_store()?.read()?;
        let expected: BTreeSet<_> = ledger
            .tasks
            .iter()
            .map(|task| sha256(task.view.task_id.as_str().as_bytes()).as_str()[7..].to_owned())
            .collect();
        let parent = self.root.join("executions-v1");
        match fs::symlink_metadata(&parent) {
            Ok(_) => {
                check_dir(&parent)?;
                for entry in fs::read_dir(&parent).map_err(io_error)? {
                    let entry = entry.map_err(io_error)?;
                    let name = entry.file_name();
                    if !name.to_str().is_some_and(|name| expected.contains(name)) {
                        return Err(corrupt(
                            "execution directory has no accepted Task authority",
                        ));
                    }
                    check_dir(&entry.path())?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        ledger
            .tasks
            .iter()
            .map(|task| self.capacity_witness(&task.view.task_id, None))
            .collect()
    }
    pub(crate) fn capacity_release_witness(
        &self,
        id: &TaskId,
        lease: Option<&File>,
    ) -> Result<CapacityExecutionWitness, TaskError> {
        self.capacity_witness(id, lease)
    }
    pub(crate) fn release_verified_capacity(&self, id: &TaskId) -> Result<(), TaskError> {
        crate::task_capacity_recovery::release_capacity_from_executor(self, id, None)
    }
    pub(super) fn release_reaped_capacity(
        &self,
        state: &RuntimeState,
        lease: &File,
    ) -> Result<(), TaskError> {
        crate::task_capacity_recovery::release_capacity_from_executor(
            self,
            &state.view.task_id,
            Some(lease),
        )
    }
    fn capacity_witness(
        &self,
        id: &TaskId,
        held_lease: Option<&File>,
    ) -> Result<CapacityExecutionWitness, TaskError> {
        let state = self.owner.runtime(id)?;
        let directory = self
            .root
            .join("executions-v1")
            .join(&sha256(id.as_str().as_bytes()).as_str()[7..]);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if state.execution_handle.is_some()
                    || state.view.execution.state != ExecutionState::NotStarted
                    || state.view.observation != Observation::Confirmed
                {
                    return Err(unresolved("missing original execution authority"));
                }
                return Ok(CapacityExecutionWitness {
                    releasable: state.view.outcome == TaskOutcome::Cancelled
                        && state.view.cancellation.state == CancellationState::Confirmed,
                    state,
                    lease: None,
                    preparation_reaped: false,
                });
            }
            Err(error) => return Err(io_error(error)),
            Ok(_) => check_dir(&directory)?,
        }
        let logs = Logs::open(
            &self.root,
            id,
            &state.view.contract_digest,
            state.view.accepted_contract.request.limits.log_bytes,
        )?;
        let lease = match held_lease {
            Some(lease) => {
                logs.check_lock("owner.lock", lease)?;
                lease.try_clone().map_err(io_error)?
            }
            None => logs.lock("owner.lock", true)?,
        };
        let state = self.owner.runtime(id)?;
        if state.execution_handle.is_none()
            && state.view.execution.state == ExecutionState::NotStarted
            && state.view.outcome == TaskOutcome::Cancelled
            && state.view.cancellation.state == CancellationState::Confirmed
            && state.view.observation == Observation::Confirmed
        {
            if !logs.sealed()?
                || !logs
                    .directory
                    .join("reaped-v1.json")
                    .try_exists()
                    .map_err(io_error)?
            {
                return Err(unresolved(
                    "preparation has no sealed original reap evidence",
                ));
            }
            let reaped = disk::load(&logs.directory.join("reaped-v1.json"))?;
            if reaped["schema_version"] != 1
                || reaped["task_id"] != id.as_str()
                || reaped["contract_digest"] != state.view.contract_digest.as_str()
                || reaped["exec"] != Json::Null
                || reaped["subtree_stopped"] != true
            {
                return Err(corrupt(
                    "preparation reap differs from original Task authority",
                ));
            }
            let container = docker::string(&reaped, "container")?;
            docker::engine_id(container)?;
            let actual = self
                .docker
                .inspect(container)
                .map_err(|_| unresolved("original preparation namespace is unavailable"))?;
            let contract = &state.view.accepted_contract;
            let tmpfs = format!(
                "rw,exec,nosuid,nodev,size={},mode=0700,uid=65534,gid=65534",
                contract.request.limits.storage_bytes
            );
            verify_container(
                &actual,
                id,
                &state.view.contract_digest,
                contract,
                &tmpfs,
                &logs.directory.join("input-readonly-v1"),
            )?;
            if actual["Id"] != container
                || actual["State"]["Running"] != false
                || actual["State"]["Pid"] != 0
                || actual["State"]["Dead"] != false
            {
                return Err(corrupt(
                    "original preparation subtree has not been verified stopped",
                ));
            }
            logs.check_lock("owner.lock", &lease)?;
            return Ok(CapacityExecutionWitness {
                state,
                lease: Some(lease),
                releasable: true,
                preparation_reaped: true,
            });
        }
        if state.view.observation != Observation::Confirmed
            || ![ExecutionState::Exited, ExecutionState::Stopped]
                .contains(&state.view.execution.state)
        {
            return Err(unresolved(
                "original preparation or execution remains unverified",
            ));
        }
        let engine = disk::load(&logs.directory.join("engine-v1.json"))?;
        let container = docker::string(&engine, "container")?;
        let exec = docker::string(&engine, "exec")?;
        docker::engine_id(container)?;
        docker::engine_id(exec)?;
        if engine["schema_version"] != 1
            || engine["task_id"] != id.as_str()
            || engine["contract_digest"] != state.view.contract_digest.as_str()
            || state.execution_handle.as_deref()
                != Some(format!("docker:{container}:{exec}").as_str())
            || engine["argv"] != json!(state.view.accepted_contract.request.command)
            || engine["cwd"] != recovery_cwd(&state.view.accepted_contract.request.cwd)
        {
            return Err(corrupt(
                "capacity proof differs from original accepted execution",
            ));
        }
        let reaped = bound(&logs, "reaped-v1.json", &state, &engine)?;
        if reaped["subtree_stopped"] != true {
            return Err(corrupt("capacity release has no original subtree reap"));
        }
        match state.view.execution.state {
            ExecutionState::Exited => {
                // Includes sealed EOF, the frozen output archive and original
                // exit code; container deletion is unnecessary to verify it.
                results::sealed_results_with_lease(&self.root, &state, &lease)?;
            }
            ExecutionState::Stopped => {
                let intent = bound(&logs, "stop-intent-v1.json", &state, &engine)?;
                if intent["reason"].as_str() != state.view.execution.stop_reason.as_deref() {
                    return Err(corrupt("capacity reap differs from original stop intent"));
                }
            }
            _ => {
                return Err(corrupt(
                    "capacity release execution changed during verification",
                ));
            }
        }
        logs.check_lock("owner.lock", &lease)?;
        Ok(CapacityExecutionWitness {
            state,
            lease: Some(lease),
            releasable: true,
            preparation_reaped: false,
        })
    }
}
fn bound(logs: &Logs, name: &str, state: &RuntimeState, engine: &Json) -> Result<Json, TaskError> {
    let proof = disk::load(&logs.directory.join(name))?;
    if proof["schema_version"] != 1
        || proof["task_id"] != state.view.task_id.as_str()
        || proof["contract_digest"] != state.view.contract_digest.as_str()
        || proof["container"] != engine["container"]
        || proof["exec"] != engine["exec"]
    {
        return Err(corrupt(
            "capacity evidence belongs to another original execution",
        ));
    }
    Ok(proof)
}
fn recovery_cwd(cwd: &str) -> String {
    if cwd == "." {
        "/work".into()
    } else {
        format!("/work/{cwd}")
    }
}
fn unresolved(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::CapacityUnavailable, reason, true)
}

#[cfg(test)]
#[path = "task_capacity_recovery_tests.rs"]
mod tests;
