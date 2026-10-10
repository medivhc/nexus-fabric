//! Reconcile the original Engine identity. Never creates or starts any exec.
use super::*;
use crate::artifact_fs as disk;
use nexus_compute::task_runtime::TaskRuntimeStore;

impl LinuxTaskExecutor {
    /// Provider-internal cold reconciliation. An active original owner refuses
    /// takeover. Unsealed natural-exit logs and ambiguous starts remain unknown;
    /// no reconnect can reset or extend the original monotonic timeout budget.
    pub fn reconcile(&self, id: &TaskId) -> Result<RuntimeState, TaskError> {
        let state = self.owner.runtime(id)?;
        let directory = self
            .root
            .join("executions-v1")
            .join(&sha256(id.as_str().as_bytes()).as_str()[7..]);
        if !directory.try_exists().map_err(io_error)? && state.execution_handle.is_none() {
            return Ok(state);
        }
        let logs = Logs::open(
            &self.root,
            id,
            &state.view.contract_digest,
            state.view.accepted_contract.request.limits.log_bytes,
        )?;
        let lease = logs.lock("owner.lock", true)?;
        // Reload after acquiring the sole adapter lease, since the previous
        // owner could have committed a final event while this call opened logs.
        let state = self.owner.runtime(id)?;
        let Some(handle) = state.execution_handle.as_ref() else {
            if state.view.outcome == TaskOutcome::Cancelled
                && state.view.observation == Observation::Confirmed
            {
                match self.capacity_release_witness(id, Some(&lease)) {
                    Ok(witness) if witness.preparation_reaped() => {
                        self.release_reaped_capacity(&state, &lease)?;
                        return Ok(state);
                    }
                    Ok(_) => {}
                    Err(error) if error.code == TaskErrorCode::CapacityUnavailable => {}
                    Err(error) => return Err(error),
                }
            }
            return self.unknown(id, state);
        };
        let engine = disk::load(&logs.directory.join("engine-v1.json"))?;
        bind(&engine, &state)?;
        let container = docker::string(&engine, "container")?;
        let exec = docker::string(&engine, "exec")?;
        docker::engine_id(container)?;
        docker::engine_id(exec)?;
        if handle != &format!("docker:{container}:{exec}")
            || engine["argv"] != json!(state.view.accepted_contract.request.command)
            || engine["cwd"] != cwd(&state.view.accepted_contract.request.cwd)
        {
            return Err(corrupt(
                "original execution proof differs from accepted contract",
            ));
        }
        // An intact durable exit/reap outbox survives removal of the stopped
        // container. It is checked against the original immutable Engine handle.
        if logs
            .directory
            .join("exit-proof-v1.json")
            .try_exists()
            .map_err(io_error)?
            && logs
                .directory
                .join("reaped-v1.json")
                .try_exists()
                .map_err(io_error)?
            && logs.sealed()?
        {
            let exited = bound_proof(&logs, "exit-proof-v1.json", &state, &engine)?;
            let reaped = bound_proof(&logs, "reaped-v1.json", &state, &engine)?;
            if reaped["subtree_stopped"] != true {
                return Err(corrupt("original subtree reap not confirmed"));
            }
            let code = exited["exit_code"]
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| corrupt("invalid original exit code"))?;
            let action = match state.view.execution.state {
                ExecutionState::Running => RuntimeAction::Exited { exit_code: code },
                ExecutionState::Exited if state.view.execution.exit_code == Some(code) => {
                    RuntimeAction::ObservationConfirmed {
                        handle: handle.clone(),
                    }
                }
                _ => return Err(corrupt("exit proof conflicts with original runtime")),
            };
            let candidate = self.preview(id, action.clone())?;
            results::sealed_results_with_lease(&self.root, &candidate, &lease)?;
            logs.check_lock("owner.lock", &lease)?;
            if state.view.execution.state == ExecutionState::Exited
                && state.view.observation == Observation::Confirmed
            {
                self.release_reaped_capacity(&state, &lease)?;
                return Ok(state);
            }
            let recovered = self.record(id, action)?;
            self.release_reaped_capacity(&recovered, &lease)?;
            return Ok(recovered);
        }
        // Absence/unavailability is not proof of ExecutionLost. Engine 404,
        // daemon failure or missing inspect cannot invent a terminal outcome.
        let Ok(actual) = self.docker.inspect(container) else {
            return self.unknown(id, state);
        };
        let limits = &state.view.accepted_contract.request.limits;
        let tmpfs = format!(
            "rw,exec,nosuid,nodev,size={},mode=0700,uid=65534,gid=65534",
            limits.storage_bytes
        );
        verify_container(
            &actual,
            id,
            &state.view.contract_digest,
            &state.view.accepted_contract,
            &tmpfs,
            &logs.directory.join("input-readonly-v1"),
        )?;
        if actual["Id"] != container {
            return Err(corrupt("original container identity changed"));
        }
        let Ok(observed) = self.docker.exec_inspect(exec) else {
            return self.unknown(id, state);
        };
        if observed["ContainerID"] != container || observed["ID"] != exec {
            return Err(corrupt("original Engine exec identity changed"));
        }
        // A Started proof written before the journal event confirms original
        // start, but cannot make an unsealed dead owner resume workload/log I/O.
        if state.view.execution.state == ExecutionState::NotStarted {
            return self.unknown(id, state);
        }
        if state.view.execution.state == ExecutionState::Stopped {
            let reaped = bound_proof(&logs, "reaped-v1.json", &state, &engine)?;
            if reaped["subtree_stopped"] != true
                || actual["State"]["Running"] != false
                || actual["State"]["Pid"] != 0
                || actual["State"]["Dead"] != false
            {
                return Err(corrupt(
                    "stopped execution lacks original reap confirmation",
                ));
            }
            if state.view.observation == Observation::Confirmed {
                self.release_reaped_capacity(&state, &lease)?;
                return Ok(state);
            }
            logs.check_lock("owner.lock", &lease)?;
            let recovered = self.record(
                id,
                RuntimeAction::ObservationConfirmed {
                    handle: handle.clone(),
                },
            )?;
            self.release_reaped_capacity(&recovered, &lease)?;
            return Ok(recovered);
        }
        if state.view.execution.state == ExecutionState::Running
            && state.view.cancellation.state == CancellationState::Requested
            && observed["Running"] == true
        {
            let reason = state
                .view
                .cancellation
                .reason
                .clone()
                .ok_or_else(|| corrupt("missing cancellation cause"))?;
            if !["User", "Revoked"].contains(&reason.as_str()) {
                return Err(corrupt("unsupported cold cancellation cause"));
            }
            logs.check_lock("owner.lock", &lease)?;
            proof(
                &logs,
                "stop-intent-v1.json",
                json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":state.view.contract_digest.as_str(),"container":container,"exec":exec,"reason":reason}),
            )?;
            self.docker.stop(container)?;
            proof(
                &logs,
                "reaped-v1.json",
                json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":state.view.contract_digest.as_str(),"container":container,"exec":exec,"subtree_stopped":true}),
            )?;
            logs.check_lock("owner.lock", &lease)?;
            #[cfg(test)]
            checkpoint(&logs, "before_stopped_event")?;
            let recovered = self.record(
                id,
                RuntimeAction::Stopped {
                    reason,
                    signal: Some("SIGKILL".into()),
                },
            )?;
            self.release_reaped_capacity(&recovered, &lease)?;
            return Ok(recovered);
        }
        // Recover a cancellation event gap only from its original durable stop
        // intent AND original stopped Engine namespace, never a wall clock/PID.
        if state.view.execution.state == ExecutionState::Running
            && actual["State"]["Running"] == false
            && actual["State"]["Pid"] == 0
            && actual["State"]["Dead"] == false
            && logs
                .directory
                .join("stop-intent-v1.json")
                .try_exists()
                .map_err(io_error)?
        {
            let intent = bound_proof(&logs, "stop-intent-v1.json", &state, &engine)?;
            let reason = docker::string(&intent, "reason")?.to_owned();
            if state.view.cancellation.state == CancellationState::Requested
                && state.view.cancellation.reason.as_ref() == Some(&reason)
                && ["User", "Revoked"].contains(&reason.as_str())
            {
                self.docker.stop(container)?;
                proof(
                    &logs,
                    "reaped-v1.json",
                    json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":state.view.contract_digest.as_str(),"container":container,"exec":exec,"subtree_stopped":true}),
                )?;
                logs.check_lock("owner.lock", &lease)?;
                let recovered = self.record(
                    id,
                    RuntimeAction::Stopped {
                        reason,
                        signal: Some("SIGKILL".into()),
                    },
                )?;
                self.release_reaped_capacity(&recovered, &lease)?;
                return Ok(recovered);
            }
        }
        self.unknown(id, state)
    }
    fn unknown(&self, id: &TaskId, state: RuntimeState) -> Result<RuntimeState, TaskError> {
        if state.view.observation == Observation::PendingVerification {
            Ok(state)
        } else {
            self.record(id, RuntimeAction::ObservationLost)
        }
    }
    fn preview(&self, id: &TaskId, action: RuntimeAction) -> Result<RuntimeState, TaskError> {
        let (accepted, mut journal) =
            FileTaskAcceptanceStore::open(&self.root)?.runtime_read(id)?;
        let sequence = journal
            .events
            .last()
            .map_or(Some(1), |event| event.sequence.checked_add(1))
            .ok_or_else(|| corrupt("runtime preview sequence overflow"))?;
        journal.events.push(RuntimeEvent { sequence, action });
        journal.replay(&accepted, sha256)
    }
}
fn cwd(path: &str) -> String {
    if path == "." {
        "/work".into()
    } else {
        format!("/work/{path}")
    }
}
fn bind(proof: &Json, state: &RuntimeState) -> Result<(), TaskError> {
    if proof["schema_version"] != 1
        || proof["task_id"] != state.view.task_id.as_str()
        || proof["contract_digest"] != state.view.contract_digest.as_str()
    {
        Err(corrupt("recovery proof belongs to another Task/contract"))
    } else {
        Ok(())
    }
}
fn bound_proof(
    logs: &Logs,
    name: &str,
    state: &RuntimeState,
    engine: &Json,
) -> Result<Json, TaskError> {
    let p = disk::load(&logs.directory.join(name))?;
    bind(&p, state)?;
    if p["container"] != engine["container"] || p["exec"] != engine["exec"] {
        return Err(corrupt(
            "recovery proof differs from original Engine identity",
        ));
    }
    Ok(p)
}

/// Admission cannot trust a caller-authored Stopped event alone. Its original
/// durable stop/reap evidence and current Engine namespace must also agree.
pub(super) fn verify_stopped(
    executor: &LinuxTaskExecutor,
    state: &RuntimeState,
    logs: &Logs,
) -> Result<(), TaskError> {
    let lease = logs.lock("owner.lock", true)?;
    let engine = disk::load(&logs.directory.join("engine-v1.json"))?;
    bind(&engine, state)?;
    let container = docker::string(&engine, "container")?;
    let exec = docker::string(&engine, "exec")?;
    docker::engine_id(container)?;
    docker::engine_id(exec)?;
    if state.execution_handle.as_deref() != Some(&format!("docker:{container}:{exec}")) {
        return Err(corrupt("stopped authority belongs to another execution"));
    }
    let reaped = bound_proof(logs, "reaped-v1.json", state, &engine)?;
    let intent = bound_proof(logs, "stop-intent-v1.json", state, &engine)?;
    if reaped["subtree_stopped"] != true
        || intent["reason"].as_str() != state.view.execution.stop_reason.as_deref()
    {
        return Err(corrupt("stopped runtime lacks original stop/reap evidence"));
    }
    let actual = executor.docker.inspect(container)?;
    if actual["Id"] != container
        || actual["Config"]["Labels"]["nexus.task_id"] != state.view.task_id.as_str()
        || actual["Config"]["Labels"]["nexus.contract_digest"]
            != state.view.contract_digest.as_str()
        || actual["State"]["Running"] != false
        || actual["State"]["Pid"] != 0
        || actual["State"]["Dead"] != false
    {
        return Err(corrupt("original stopped namespace is not verified"));
    }
    logs.check_lock("owner.lock", &lease)
}

#[cfg(test)]
pub(super) fn checkpoint(logs: &Logs, boundary: &str) -> Result<(), TaskError> {
    if std::env::var("NEXUS_N3_RECOVERY_PAUSE").ok().as_deref() == Some(boundary) {
        publish(&logs.directory, "recovery-test-ready", boundary.as_bytes())?;
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
