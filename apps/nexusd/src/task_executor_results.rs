//! Read sealed execution evidence without spawning or resolving an image.
use super::*;
use crate::artifact_fs as disk;
use nexus_compute::task_artifact::RegisteredLog;

pub(crate) struct SealedResults {
    pub(crate) outputs: Vec<(OutputSpec, Option<Vec<u8>>)>,
    pub(crate) logs: Vec<(RegisteredLog, Vec<u8>)>,
}
pub(crate) fn sealed_results(
    root: &Path,
    state: &RuntimeState,
) -> Result<SealedResults, TaskError> {
    let v = &state.view;
    if v.execution.state != ExecutionState::Exited || v.observation != Observation::Confirmed {
        return Err(TaskError::invalid(
            "publication requires a confirmed natural exit",
        ));
    }
    let logs = Logs::open(
        root,
        &v.task_id,
        &v.contract_digest,
        v.accepted_contract.request.limits.log_bytes,
    )?;
    let _lease = logs.lock("owner.lock", true)?;
    if !logs.sealed()? {
        return Err(corrupt("execution logs are not sealed"));
    }
    let reaped = disk::load(&logs.directory.join("reaped-v1.json"))?;
    let exited = disk::load(&logs.directory.join("exit-proof-v1.json"))?;
    for proof in [&reaped, &exited] {
        if proof["schema_version"] != 1
            || proof["task_id"] != v.task_id.as_str()
            || proof["contract_digest"] != v.contract_digest.as_str()
        {
            return Err(corrupt("execution proof belongs to another Task"));
        }
    }
    let handle = format!(
        "docker:{}:{}",
        reaped["container"]
            .as_str()
            .ok_or_else(|| corrupt("missing container identity"))?,
        reaped["exec"]
            .as_str()
            .ok_or_else(|| corrupt("missing exec identity"))?
    );
    if state.execution_handle.as_deref() != Some(&handle)
        || reaped["subtree_stopped"] != true
        || exited["container"] != reaped["container"]
        || exited["exec"] != reaped["exec"]
        || exited["exit_code"].as_u64() != v.execution.exit_code.map(u64::from)
    {
        return Err(corrupt("exit/reap evidence differs from durable runtime"));
    }
    let raw = disk::read(
        &logs.directory.join("working-tree-unregistered-v1.tar"),
        disk::MAX_BYTES,
    )?;
    let inventory = archive::parse(&raw)?;
    let staged = disk::load(&logs.directory.join("outputs-v1.json"))?;
    let files = staged["files"]
        .as_array()
        .ok_or_else(|| corrupt("missing output inventory"))?;
    if staged.as_object().map(|m| m.len()) != Some(4)
        || staged["schema_version"] != 1
        || staged["task_id"] != v.task_id.as_str()
        || staged["contract_digest"] != v.contract_digest.as_str()
        || files.len() != v.accepted_contract.request.outputs.len()
    {
        return Err(corrupt("output inventory differs from contract"));
    }
    let mut outputs = Vec::new();
    for (spec, entry) in v.accepted_contract.request.outputs.iter().zip(files) {
        if entry["path"] != spec.path || entry["required"] != spec.required {
            return Err(corrupt("output identity changed"));
        }
        let bytes = match archive::regular(&inventory, &spec.path) {
            Ok(source) => {
                if entry["status"] != "StagedUnregistered"
                    || entry["size_bytes"] != source.bytes.len() as u64
                {
                    return Err(corrupt("staging differs from captured work tree"));
                }
                // Validate every parent before any read; the archive remains frozen.
                let _ = safe_file(&logs.directory.join("outputs-unregistered-v1"), &spec.path)?;
                let bytes = disk::read(
                    &logs
                        .directory
                        .join("outputs-unregistered-v1")
                        .join(&spec.path),
                    disk::MAX_BYTES,
                )?;
                if bytes != source.bytes {
                    return Err(TaskError::new(
                        TaskErrorCode::ArtifactIntegrityFailed,
                        "staged output differs from frozen work tree",
                        false,
                    ));
                }
                Some(bytes)
            }
            Err(_) if entry["status"] == "Unavailable" => None,
            Err(_) => return Err(corrupt("unavailable output lacks evidence")),
        };
        outputs.push((spec.clone(), bytes));
    }
    let mut registered = Vec::new();
    for (stream, name) in [(LogStream::Stdout, "stdout"), (LogStream::Stderr, "stderr")] {
        let mut bytes = Vec::new();
        let truncated = loop {
            let page = logs.page(stream, bytes.len() as u64, 65536)?;
            bytes.extend(page.bytes);
            if bytes.len() as u64 > disk::MAX_BYTES {
                return Err(unsupported("log publication exceeds adapter bound"));
            }
            if page.eof {
                break page.truncated;
            }
        };
        registered.push((
            RegisteredLog {
                stream: name.into(),
                size_bytes: bytes.len() as u64,
                content_sha256: sha256(&bytes),
                truncated,
            },
            bytes,
        ));
    }
    if registered.iter().map(|(l, _)| l.size_bytes).sum::<u64>() > disk::MAX_BYTES {
        return Err(unsupported(
            "registered logs exceed adapter publication capacity",
        ));
    }
    Ok(SealedResults {
        outputs,
        logs: registered,
    })
}

#[cfg(test)]
pub(crate) fn stage_fixture(
    root: &Path,
    state: &RuntimeState,
    raw: &[u8],
) -> Result<(), TaskError> {
    let v = &state.view;
    let logs = Logs::create(
        root,
        &v.task_id,
        &v.contract_digest,
        v.accepted_contract.request.limits.log_bytes,
    )?;
    let handle = state
        .execution_handle
        .as_ref()
        .ok_or_else(|| corrupt("fixture handle missing"))?;
    let parts: Vec<_> = handle.split(':').collect();
    proof(
        &logs,
        "exit-proof-v1.json",
        json!({"schema_version":1,"task_id":v.task_id.as_str(),"contract_digest":v.contract_digest.as_str(),"container":parts[1],"exec":parts[2],"exit_code":v.execution.exit_code}),
    )?;
    proof(
        &logs,
        "reaped-v1.json",
        json!({"schema_version":1,"task_id":v.task_id.as_str(),"contract_digest":v.contract_digest.as_str(),"container":parts[1],"exec":parts[2],"subtree_stopped":true}),
    )?;
    publish(&logs.directory, "working-tree-unregistered-v1.tar", raw)?;
    stage_outputs(
        &logs,
        raw,
        &v.accepted_contract,
        &v.task_id,
        &v.contract_digest,
    )?;
    logs.append(0, b"stdout\n")?;
    logs.append(1, b"stderr\n")?;
    logs.seal()
}
