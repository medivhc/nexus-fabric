//! N3 Linux composition adapter. TaskOwner alone writes state/outcome.
//! No transport, public routes, Artifact registration or delivery completion.
use crate::{snapshot_store::FileSnapshotStore, task_store::FileTaskAcceptanceStore};
use nexus::n3_acceptance::{new_task_id, parse_canonical_json, sha256};
use nexus_compute::{
    task::{TaskAcceptanceStore, TaskOwner},
    task_runtime::{RuntimeAction, RuntimeEvent, RuntimeState},
};
use nexus_domain::task::*;
use serde_json::{Value as Json, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "task_executor_archive.rs"]
mod archive;
#[path = "task_executor_docker.rs"]
mod docker;
#[path = "task_executor_logs.rs"]
mod logs;
#[path = "task_executor_run.rs"]
mod run;
use docker::{Docker, Frames};
use logs::{Logs, publish};

/// Provider-private byte stream selector; external reads need service authorization.
#[derive(Clone, Copy)]
pub enum LogStream {
    Stdout,
    Stderr,
}
/// Retained byte offsets remain stable after reconnect, separately per stream.
#[derive(Debug, PartialEq, Eq)]
pub struct LogPage {
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
    pub truncated: bool,
}
/// Only operator-approved immutable images with POSIX preparation utilities.
/// Synchronous owner keeps all I/O and kernel resources within one call. The
/// mandatory callback must recheck current grants and the actual reservation;
/// this adapter does not infer these facts from AcceptedContract fields.
pub struct LinuxTaskExecutor {
    root: PathBuf,
    owner: TaskOwner<FileTaskAcceptanceStore>,
    snapshots: FileSnapshotStore,
    images: Vec<Sha256Digest>,
    docker: Docker,
}
impl LinuxTaskExecutor {
    pub fn open(root: &Path, approved_images: Vec<Sha256Digest>) -> Result<Self, TaskError> {
        let root = root.canonicalize().map_err(io_error)?;
        let store = FileTaskAcceptanceStore::open(&root)?;
        let executor = Self {
            snapshots: FileSnapshotStore::open(&root)?,
            owner: TaskOwner::new(store, sha256, new_task_id),
            root,
            images: approved_images,
            docker: Docker,
        };
        executor.mark_orphans()?;
        Ok(executor)
    }
    /// Resolves an image by content ID, never pulls or resolves a mutable tag.
    pub fn verify_environment(
        &self,
        environment: &EnvironmentRequirement,
        limits: &TaskLimits,
    ) -> Result<(), TaskError> {
        environment.validate()?;
        limits.validate()?;
        if !self.images.contains(&environment.image_digest) {
            return Err(TaskError::new(
                TaskErrorCode::EnvironmentMismatch,
                "image is not operator-approved",
                false,
            ));
        }
        if limits.cpu_millis < 10
            || limits.storage_bytes > 64 * 1024 * 1024
            || limits.storage_bytes % 4096 != 0
            || limits.memory_bytes < 6 * 1024 * 1024
        {
            return Err(unsupported(
                "exact tmpfs page quota / Docker minimum memory cannot represent these limits",
            ));
        }
        let info = self.docker.request("GET", "/info", Json::Null)?;
        if info["OSType"] != "linux"
            || !["MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota"]
                .iter()
                .all(|k| info[k] == true)
            || !info["SecurityOptions"].as_array().is_some_and(|a| {
                a.iter()
                    .any(|x| x.as_str().is_some_and(|s| s.starts_with("name=seccomp")))
            })
        {
            return Err(unsupported(
                "required kernel isolation and hard quotas are unavailable",
            ));
        }
        if ![
            environment.architecture.as_str(),
            match environment.architecture.as_str() {
                "x86_64" => "amd64",
                _ => "arm64",
            },
        ]
        .iter()
        .any(|arch| info["Architecture"] == *arch)
        {
            return Err(TaskError::new(
                TaskErrorCode::EnvironmentMismatch,
                "provider architecture differs from accepted environment",
                false,
            ));
        }
        let image = self.docker.request(
            "GET",
            &format!("/images/{}/json", environment.image_digest.as_str()),
            Json::Null,
        )?;
        let arch = match environment.architecture.as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => return Err(unsupported("unsupported architecture")),
        };
        if image["Id"] != environment.image_digest.as_str()
            || image["Os"] != environment.os
            || image["Architecture"] != arch
        {
            return Err(TaskError::new(
                TaskErrorCode::EnvironmentMismatch,
                "resolved image differs from accepted environment",
                false,
            ));
        }
        if image["Config"]["Volumes"]
            .as_object()
            .is_some_and(|x| !x.is_empty())
        {
            return Err(unsupported(
                "image-declared writable volumes bypass the storage quota",
            ));
        }
        Ok(())
    }
    /// Provider-internal entry. Existing StartIntent, prior execution/log
    /// authority or ambiguity always requires reconciliation, never reexecution.
    pub fn run(
        &self,
        id: &TaskId,
        verify_start: &mut dyn FnMut(&AcceptedContract) -> Result<(), TaskError>,
    ) -> Result<RuntimeState, TaskError> {
        self.validate_admission(id)?;
        let state = self.owner.runtime(id)?;
        if state.execution_handle.is_some()
            || state.view.outcome != TaskOutcome::Unfinished
            || ![TaskPhase::Waiting, TaskPhase::Preparing].contains(&state.view.phase)
            || state.view.cancellation.state != CancellationState::None
        {
            return Err(corrupt(
                "task cannot acquire a new execution; reconcile existing authority",
            ));
        }
        let contract = state.view.accepted_contract.clone();
        verify_start(&contract)?;
        self.verify_environment(&contract.environment_evidence, &contract.request.limits)?;
        let frozen = self
            .snapshots
            .verify_inputs(&contract.request.input_snapshot, &contract.request.cwd)?;
        let prepared = self
            .snapshots
            .prepare_inputs(&contract.request.input_snapshot, &contract.request.cwd)?;
        if state.view.phase == TaskPhase::Waiting {
            self.record(id, RuntimeAction::Prepare)?;
        }
        let logs = Logs::create(
            &self.root,
            id,
            &state.view.contract_digest,
            contract.request.limits.log_bytes,
        )?;
        let _lease = logs.lock("owner.lock", true)?;
        let result = self.execute(
            id,
            &contract,
            &prepared.directory,
            &frozen,
            &logs,
            verify_start,
        );
        if result.is_err() {
            // Cleanup never fabricates a terminal outcome. Keep all durable
            // execution/Engine evidence for the service's cold reconciliation.
            if self
                .owner
                .runtime(id)
                .is_ok_and(|s| s.execution_handle.is_some())
            {
                let _ = self.record(id, RuntimeAction::ObservationLost);
            }
        }
        result
    }
    fn validate_admission(&self, requested: &TaskId) -> Result<(), TaskError> {
        // A released owner lease is not evidence that its kernel workload
        // exited. Until explicit reconciliation, prevent new work globally.
        let ledger = FileTaskAcceptanceStore::open(&self.root)?.read()?;
        for accepted in &ledger.tasks {
            let id = &accepted.view.task_id;
            let state = self.owner.runtime(id)?;
            let directory = self
                .root
                .join("executions-v1")
                .join(&sha256(id.as_str().as_bytes()).as_str()[7..]);
            match fs::symlink_metadata(&directory) {
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && state.execution_handle.is_none() =>
                {
                    continue;
                }
                Err(_) => {
                    return Err(corrupt(
                        "execution authority missing; reconciliation required",
                    ));
                }
                Ok(_) => {}
            }
            let logs = Logs::open(
                &self.root,
                id,
                &state.view.contract_digest,
                state.view.accepted_contract.request.limits.log_bytes,
            )?;
            if id == requested {
                return Err(corrupt("existing execution authority cannot be reset"));
            }
            if !logs.sealed()? || state.view.execution.state == ExecutionState::Running {
                match logs.lock("owner.lock", true) {
                    Err(e) if e.code == TaskErrorCode::CapacityUnavailable => {}
                    Ok(_) => {
                        return Err(corrupt(
                            "orphan execution requires reconciliation before new work",
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
    fn mark_orphans(&self) -> Result<(), TaskError> {
        let ledger = FileTaskAcceptanceStore::open(&self.root)?.read()?;
        for accepted in ledger.tasks {
            let id = &accepted.view.task_id;
            let state = self.owner.runtime(id)?;
            let directory = self
                .root
                .join("executions-v1")
                .join(&sha256(id.as_str().as_bytes()).as_str()[7..]);
            match fs::symlink_metadata(&directory) {
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && state.execution_handle.is_none() =>
                {
                    continue;
                }
                Err(_) => return Err(corrupt("execution authority missing on reopen")),
                Ok(_) => {}
            }
            let logs = Logs::open(
                &self.root,
                id,
                &state.view.contract_digest,
                state.view.accepted_contract.request.limits.log_bytes,
            )?;
            if !logs.sealed()? || state.view.execution.state == ExecutionState::Running {
                match logs.lock("owner.lock", true) {
                    Err(e) if e.code == TaskErrorCode::CapacityUnavailable => {}
                    Ok(_lease) if state.view.observation == Observation::Confirmed => {
                        self.record(id, RuntimeAction::ObservationLost)?;
                    }
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
    /// Service must authorize before calling; durable requests are polled by
    /// run(). This is distinct from confirmation of stopped/reaped resources.
    pub fn cancel(&self, id: &TaskId, reason: &str) -> Result<RuntimeState, TaskError> {
        if !["User", "Revoked"].contains(&reason) {
            return Err(TaskError::invalid("invalid cancellation cause"));
        }
        let state = self.owner.runtime(id)?;
        let directory = self
            .root
            .join("executions-v1")
            .join(&sha256(id.as_str().as_bytes()).as_str()[7..]);
        let logs = if directory.exists() {
            Some(Logs::open(
                &self.root,
                id,
                &state.view.contract_digest,
                state.view.accepted_contract.request.limits.log_bytes,
            )?)
        } else {
            None
        };
        // Serialize durable cancellation with the first OS start. This gate is
        // released as soon as start is sent, never held during workload polling.
        let _gate = logs
            .as_ref()
            .map(|logs| logs.lock("start.lock", false))
            .transpose()?;
        self.record(
            id,
            RuntimeAction::Cancel {
                reason: reason.into(),
                at_unix: now()?,
            },
        )
    }
    /// External reads require the accepted principal/workspace and current grant.
    pub fn logs(
        &self,
        id: &TaskId,
        stream: LogStream,
        offset: u64,
        max_bytes: usize,
    ) -> Result<LogPage, TaskError> {
        let s = self.owner.runtime(id)?;
        Logs::open(
            &self.root,
            id,
            &s.view.contract_digest,
            s.view.accepted_contract.request.limits.log_bytes,
        )?
        .page(stream, offset, max_bytes)
    }
    fn record(&self, id: &TaskId, action: RuntimeAction) -> Result<RuntimeState, TaskError> {
        for _ in 0..16 {
            let state = self.owner.runtime(id)?;
            let sequence = state
                .view
                .last_event_seq
                .checked_add(1)
                .ok_or_else(|| corrupt("runtime sequence overflow"))?;
            match self.owner.record_event(
                id,
                RuntimeEvent {
                    sequence,
                    action: action.clone(),
                },
            ) {
                Ok(update) => return Ok(update.state),
                Err(e)
                    if e.code == TaskErrorCode::InvalidRequest
                        && self.owner.runtime(id)?.view.last_event_seq
                            != state.view.last_event_seq =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(TaskError::new(
            TaskErrorCode::PersistenceFailed,
            "runtime changed too frequently",
            true,
        ))
    }
}
fn verify_container(
    value: &Json,
    id: &TaskId,
    digest: &Sha256Digest,
    contract: &AcceptedContract,
    tmpfs: &str,
    transfer: &Path,
) -> Result<(), TaskError> {
    let h = &value["HostConfig"];
    let c = &value["Config"];
    let l = &contract.request.limits;
    let checks = [
        h["ReadonlyRootfs"] == true,
        h["Privileged"] == false,
        h["NetworkMode"] == "none",
        h["IpcMode"] == "none",
        h["PidMode"] == "",
        h["CgroupnsMode"] == "private",
        h["Memory"] == l.memory_bytes,
        h["MemorySwap"] == l.memory_bytes,
        h["CpuPeriod"] == 100000,
        h["CpuQuota"] == l.cpu_millis * 100,
        h["PidsLimit"] == 256,
        h["CapDrop"] == json!(["ALL"]),
        h["CapAdd"].is_null() || h["CapAdd"] == json!([]),
        h["SecurityOpt"] == json!(["no-new-privileges"]),
        h["LogConfig"]["Type"] == "none",
        h["Tmpfs"] == json!({"/work":tmpfs}),
        c["User"] == "65534:65534",
        c["Entrypoint"] == json!(["/bin/sleep"]),
        c["Cmd"] == json!(["2147483647"]),
        c["Labels"]["nexus.task_id"] == id.as_str(),
        c["Labels"]["nexus.contract_digest"] == digest.as_str(),
        value["Image"] == contract.environment_evidence.image_digest.as_str(),
    ];
    let mounts = h["Mounts"]
        .as_array()
        .ok_or_else(|| corrupt("missing readonly input mount"))?;
    if checks.iter().any(|x| !x)
        || mounts.len() != 1
        || mounts[0]["Type"] != "bind"
        || mounts[0]["Source"] != transfer.to_str().unwrap_or("")
        || mounts[0]["Target"] != "/input"
        || mounts[0]["ReadOnly"] != true
    {
        return Err(unsupported(
            "actual container configuration differs from the accepted isolation/limits",
        ));
    }
    Ok(())
}
fn proof(logs: &Logs, name: &str, value: Json) -> Result<(), TaskError> {
    let raw =
        parse_canonical_json(&serde_json::to_vec(&value).map_err(json_error)?)?.canonical_bytes();
    publish(
        &logs.directory,
        name,
        &serde_json::to_vec(&json!({"payload":value,"checksum":sha256(&raw).as_str()}))
            .map_err(json_error)?,
    )
}
fn transfer_input(
    logs: &Logs,
    input: &Path,
    frozen: &nexus_workspace::snapshot::FrozenSnapshot,
) -> Result<PathBuf, TaskError> {
    let directory = logs.directory.join("input-readonly-v1");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(io_error)?;
    for file in &frozen.files {
        let mut source = safe_file(input, &file.path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut source)
            .take(file.size_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 != file.size_bytes || sha256(&bytes) != file.sha256 {
            return Err(TaskError::new(
                TaskErrorCode::InputIntegrityFailed,
                "prepared bytes changed before transfer",
                false,
            ));
        }
        let path = directory.join(&file.path);
        let parent = path
            .parent()
            .ok_or_else(|| corrupt("missing transfer parent"))?;
        let mut current = directory.clone();
        for component in parent
            .strip_prefix(&directory)
            .map_err(|_| corrupt("transfer escaped"))?
            .components()
        {
            current.push(component);
            match fs::DirBuilder::new().mode(0o755).create(&current) {
                Ok(()) => {
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
                        .map_err(io_error)?;
                    sync_dir(&current)?;
                    sync_dir(current.parent().ok_or_else(|| corrupt("missing parent"))?)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_error(e)),
            }
        }
        let mut dest = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(if file.executable { 0o755 } else { 0o644 })
            .open(&path)
            .map_err(io_error)?;
        dest.write_all(&bytes).map_err(io_error)?;
        dest.set_permissions(fs::Permissions::from_mode(if file.executable {
            0o755
        } else {
            0o644
        }))
        .map_err(io_error)?;
        dest.sync_all().map_err(io_error)?;
        sync_dir(parent)?;
    }
    // Only the mounted subtree is readable by the non-root container. Its
    // host parents remain private; Engine bind mount is kernel read-only.
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).map_err(io_error)?;
    sync_dir(&directory)?;
    sync_dir(&logs.directory)?;
    Ok(directory)
}
fn safe_file(root: &Path, name: &str) -> Result<File, TaskError> {
    relative_path(name)?;
    let mut path = root.to_path_buf();
    for component in Path::new(name).components() {
        path.push(component);
        let meta = fs::symlink_metadata(&path).map_err(io_error)?;
        if meta.file_type().is_symlink() || (!meta.is_file() && !meta.is_dir()) {
            return Err(TaskError::new(
                TaskErrorCode::InvalidPath,
                "nonregular file or link in container path",
                false,
            ));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(&path)
        .map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(TaskError::new(
            TaskErrorCode::InvalidPath,
            "output is not a regular file",
            false,
        ));
    }
    Ok(file)
}
fn stage_outputs(
    logs: &Logs,
    raw: &[u8],
    contract: &AcceptedContract,
    task: &TaskId,
    digest: &Sha256Digest,
) -> Result<(), TaskError> {
    let entries = archive::parse(raw)?;
    let directory = logs.directory.join("outputs-unregistered-v1");
    private_dir(&directory)?;
    let mut records = Vec::new();
    for output in &contract.request.outputs {
        let source = match archive::regular(&entries, &output.path) {
            Ok(f) => f,
            Err(error) => {
                records.push(json!({"path":output.path,"required":output.required,"status":"Unavailable","error":error.code.as_str()}));
                continue;
            }
        };
        let size = source.bytes.len() as u64;
        if size > contract.request.limits.storage_bytes {
            return Err(corrupt("output exceeds observed storage bound"));
        }
        let path = directory.join(&output.path);
        let parent = path
            .parent()
            .ok_or_else(|| corrupt("missing output parent"))?;
        let mut current = directory.clone();
        for component in parent
            .strip_prefix(&directory)
            .map_err(|_| corrupt("escaped output"))?
            .components()
        {
            current.push(component);
            private_dir(&current)?;
        }
        let mut dest = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(io_error)?;
        dest.write_all(source.bytes).map_err(io_error)?;
        dest.sync_all().map_err(io_error)?;
        sync_dir(parent)?;
        records.push(json!({"path":output.path,"required":output.required,"status":"StagedUnregistered","size_bytes":size}));
    }
    sync_dir(&directory)?;
    proof(
        logs,
        "outputs-v1.json",
        json!({"schema_version":1,"task_id":task.as_str(),"contract_digest":digest.as_str(),"files":records}),
    )
}
fn monotonic_ns() -> Result<u64, TaskError> {
    #[repr(C)]
    struct Timespec {
        seconds: std::ffi::c_long,
        nanos: std::ffi::c_long,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: std::ffi::c_int, time: *mut Timespec) -> std::ffi::c_int;
    }
    let mut time = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // SAFETY: valid writable Linux timespec, CLOCK_MONOTONIC=1, no retained pointer.
    if unsafe { clock_gettime(1, &mut time) } != 0
        || time.seconds < 0
        || !(0..1_000_000_000).contains(&time.nanos)
    {
        return Err(corrupt("monotonic clock unavailable"));
    }
    (time.seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(time.nanos as u64))
        .ok_or_else(|| corrupt("monotonic clock overflow"))
}
fn now() -> Result<u64, TaskError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| corrupt("wall clock predates epoch"))
}
fn sync_dir(path: &Path) -> Result<(), TaskError> {
    File::open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}
fn check_dir(path: &Path) -> Result<(), TaskError> {
    let m = fs::symlink_metadata(path).map_err(io_error)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.permissions().mode() & 0o077 != 0 {
        return Err(corrupt("execution directory must be private and real"));
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<(), TaskError> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_error(e)),
    }
    check_dir(path)
}
fn io_error(error: std::io::Error) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}
fn json_error(_: serde_json::Error) -> TaskError {
    corrupt("invalid executor metadata")
}
fn corrupt(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::StateCorrupt, reason, false)
}
fn unsupported(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::UnsupportedCapability, reason, false)
}

#[cfg(test)]
#[path = "task_executor_tests.rs"]
mod tests;
