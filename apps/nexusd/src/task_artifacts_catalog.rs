//! Durable catalog, strong content and coupling to runtime authority.
use super::*;
pub(super) fn publication<'a>(image: &'a Image, id: &TaskId) -> Result<&'a Publication, TaskError> {
    image
        .publications
        .iter()
        .find(|p| &p.task_id == id)
        .ok_or_else(|| disk::corrupt("Task publication missing"))
}
pub(super) fn publication_mut<'a>(
    image: &'a mut Image,
    id: &TaskId,
) -> Result<&'a mut Publication, TaskError> {
    image
        .publications
        .iter_mut()
        .find(|p| &p.task_id == id)
        .ok_or_else(|| disk::corrupt("Task publication missing"))
}
pub(super) fn now() -> Result<u64, TaskError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| disk::corrupt("clock predates epoch"))
}
pub(super) fn integrity(reason: impl Into<String>) -> TaskError {
    TaskError::new(TaskErrorCode::ArtifactIntegrityFailed, reason, false)
}
pub(super) fn object(root: &Path, digest: &Sha256Digest) -> PathBuf {
    root.join(CONTENT).join(&digest.as_str()[7..])
}
pub(super) fn get(root: &Path, digest: &Sha256Digest, size: u64) -> Result<Vec<u8>, TaskError> {
    let bytes = disk::read(&object(root, digest), disk::MAX_BYTES)?;
    if bytes.len() as u64 != size || sha256(&bytes) != *digest {
        return Err(integrity(
            "registered Artifact content differs from SHA-256/length",
        ));
    }
    Ok(bytes)
}
pub(super) fn put(root: &Path, digest: &Sha256Digest, bytes: &[u8]) -> Result<(), TaskError> {
    if bytes.len() as u64 > disk::MAX_BYTES || sha256(bytes) != *digest {
        return Err(integrity("Artifact upload digest/length mismatch"));
    }
    let path = object(root, digest);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            get(root, digest, bytes.len() as u64)?;
            disk::sync(&root.join(CONTENT))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            disk::atomic(&root.join(CONTENT), &digest.as_str()[7..], bytes)
        }
        Err(e) => Err(disk::io(e)),
    }
}
pub(super) fn save(root: &Path, image: &Image, ledger: &AcceptanceLedger) -> Result<(), TaskError> {
    validate(root, image, ledger)?;
    let value: serde_json::Value = serde_json::from_slice(&image.to_value().canonical_bytes())
        .map_err(|e| disk::corrupt(e.to_string()))?;
    disk::save(root, IMAGE, &value)
}
pub(super) fn load(root: &Path, ledger: &AcceptanceLedger) -> Result<Option<Image>, TaskError> {
    let authority = disk::read(&root.join("acceptance-initialized-v1"), 1024)?;
    let required = authority == AUTHORITY_RECEIPT;
    let receipt = match fs::symlink_metadata(root.join(RECEIPT)) {
        Ok(_) => Some(disk::read(&root.join(RECEIPT), 1024)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(disk::io(e)),
    };
    if receipt.as_deref().is_some_and(|r| r != RECEIPT_BYTES) || (required && receipt.is_none()) {
        return Err(disk::corrupt(
            "Artifact initialization receipt missing/corrupt",
        ));
    }
    match fs::symlink_metadata(root.join(IMAGE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required && receipt.is_none() => {
            for name in [CONTENT, "artifact-audit-v1"] {
                match fs::symlink_metadata(root.join(name)) {
                    Ok(_) => {
                        return Err(disk::corrupt(
                            "missing Artifact catalog beside existing authority",
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(disk::io(e)),
                }
            }
            return Ok(None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(disk::corrupt("initialized Artifact catalog missing"));
        }
        Err(e) => return Err(disk::io(e)),
        Ok(_) => {}
    }
    disk::check_directory(&root.join(CONTENT))?;
    let value = disk::load(&root.join(IMAGE))?;
    let image = Image::from_value(nexus::n3_acceptance::parse_canonical_json(
        &disk::canonical(&value)?,
    )?)
    .map_err(|e| disk::corrupt(e.to_string()))?;
    validate(root, &image, ledger)?;
    disk::sync(root)?;
    Ok(Some(image))
}
pub(super) fn initialize(root: &Path, ledger: &AcceptanceLedger) -> Result<(), TaskError> {
    let image = load(root, ledger)?;
    if image.is_none() {
        if fs::symlink_metadata(root.join(CONTENT)).is_ok()
            || fs::symlink_metadata(root.join("artifact-audit-v1")).is_ok()
        {
            return Err(disk::corrupt(
                "Artifact catalog lost beside existing authority",
            ));
        }
        disk::directory(&root.join(CONTENT))?;
        save(
            root,
            &Image {
                schema_version: 1,
                publications: Vec::new(),
            },
            ledger,
        )?;
    }
    disk::directory(&root.join(CONTENT))?;
    if !root.join(RECEIPT).exists() {
        disk::atomic(root, RECEIPT, RECEIPT_BYTES)?;
    }
    disk::atomic(root, "acceptance-initialized-v1", AUTHORITY_RECEIPT)?;
    load(root, ledger)?;
    Ok(())
}
pub(super) fn validate(
    root: &Path,
    image: &Image,
    ledger: &AcceptanceLedger,
) -> Result<(), TaskError> {
    if image.schema_version != 1 {
        return Err(disk::corrupt("unsupported Artifact catalog"));
    }
    let mut tasks = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for p in &image.publications {
        let accepted = ledger
            .tasks
            .iter()
            .find(|t| t.view.task_id == p.task_id)
            .ok_or_else(|| disk::corrupt("Artifact Task has no acceptance"))?;
        let v = &accepted.view;
        let c = &v.accepted_contract;
        if !tasks.insert(&p.task_id) || p.contract_digest != v.contract_digest {
            return Err(disk::corrupt("Artifact catalog Task identity mismatch"));
        }
        let mut paths = BTreeSet::new();
        let mut total = 0u64;
        for r in &p.artifacts {
            r.validate().map_err(|e| disk::corrupt(e.to_string()))?;
            total = total
                .checked_add(r.size_bytes)
                .ok_or_else(|| disk::corrupt("output length overflow"))?;
            let expected = Value::Array(vec![
                p.task_id.to_value(),
                r.path.to_value(),
                r.content_sha256.to_value(),
            ]);
            if r.task_id != p.task_id
                || r.snapshot_id != c.request.input_snapshot.snapshot_id
                || r.workspace != c.request.workspace
                || r.owner_principal != c.authenticated_principal
                || r.producer_node != c.request.provider
                || r.environment_digest
                    != sha256(&c.environment_evidence.to_value().canonical_bytes())
                || r.created_at_unix < c.accepted_at_unix
                || r.size_bytes > disk::MAX_BYTES
                || r.storage_ref != format!("artifact-v1:{}", &r.content_sha256.as_str()[7..])
                || r.artifact_id.as_str()
                    != format!(
                        "artifact:{}",
                        &sha256(&expected.canonical_bytes()).as_str()[7..]
                    )
                || !c.request.outputs.iter().any(|o| o.path == r.path)
                || !paths.insert(r.path.clone())
                || !ids.insert(&r.artifact_id)
            {
                return Err(disk::corrupt(
                    "Artifact record differs from immutable contract",
                ));
            }
            if r.publication_state == PublicationState::Published {
                get(root, &r.content_sha256, r.size_bytes)?;
            }
        }
        if total > c.request.limits.storage_bytes {
            return Err(disk::corrupt("Artifact total exceeds accepted storage"));
        }
        let mut missing = BTreeSet::new();
        if p.missing.iter().any(|path| {
            !missing.insert(path.clone())
                || paths.contains(path)
                || !c
                    .request
                    .outputs
                    .iter()
                    .any(|o| o.required && &o.path == path)
        }) || c
            .request
            .outputs
            .iter()
            .any(|o| o.required && !paths.contains(&o.path) && !missing.contains(&o.path))
        {
            return Err(disk::corrupt("required output inventory incomplete"));
        }
        if p.logs.len() != 2
            || p.logs[0].stream != "stdout"
            || p.logs[1].stream != "stderr"
            || p.logs[0]
                .size_bytes
                .checked_add(p.logs[1].size_bytes)
                .is_none_or(|n| n > c.request.limits.log_bytes || n > disk::MAX_BYTES)
        {
            return Err(disk::corrupt("invalid registered log inventory"));
        }
        if p.logs_published {
            for l in &p.logs {
                get(root, &l.content_sha256, l.size_bytes)?;
            }
        }
    }
    Ok(())
}
/// Called under the shared acceptance lock on every read/GC/transaction. No IO
/// callbacks or lock recursion: a forged delivery event needs durable evidence.
pub(crate) fn validate_runtime(
    root: &Path,
    ledger: &AcceptanceLedger,
    runtime: &crate::task_runtime_store::RuntimeImage,
) -> Result<(), TaskError> {
    let image = load(root, ledger)?;
    for journal in &runtime.journals {
        for event in &journal.events {
            match &event.action {
                RuntimeAction::DeliveryReady {
                    artifacts, logs, ..
                } => {
                    let image = image.as_ref().ok_or_else(|| {
                        disk::corrupt("delivery completion lacks Artifact authority")
                    })?;
                    let p = publication(image, &journal.task_id)?;
                    if !p.logs_published
                        || !p.missing.is_empty()
                        || &p.artifacts != artifacts
                        || &p.logs != logs
                    {
                        return Err(disk::corrupt(
                            "delivery event differs from durable publication",
                        ));
                    }
                    let accepted = ledger
                        .tasks
                        .iter()
                        .find(|t| t.view.task_id == journal.task_id)
                        .ok_or_else(|| disk::corrupt("Task missing"))?;
                    validate_registration(&accepted.view, artifacts, logs, sha256)
                        .map_err(|e| disk::corrupt(e.to_string()))?;
                }
                RuntimeAction::ArtifactsMissing { paths } => {
                    let image = image
                        .as_ref()
                        .ok_or_else(|| disk::corrupt("missing-output event lacks authority"))?;
                    if &publication(image, &journal.task_id)?.missing != paths {
                        return Err(disk::corrupt("missing outputs differ from sealed evidence"));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
