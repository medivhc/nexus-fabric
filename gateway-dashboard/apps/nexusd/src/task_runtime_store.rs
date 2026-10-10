//! Linux runtime journal adapter. Acceptance, event updates and Snapshot GC use
//! the same stable flock; an invalid runtime authority blocks new work and GC.
use crate::task_store::FileTaskAcceptanceStore;
use nexus::n3_acceptance::{new_task_id, parse_canonical_json, sha256};
use nexus_compute::{
    task::{AcceptanceLedger, AcceptedTask},
    task_runtime::*,
};
use nexus_domain::task::{
    codec::{CanonicalDto, Value},
    *,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const IMAGE: &str = "task-runtime-v1.json";
const RECEIPT: &str = "task-runtime-initialized-v1";
const RECEIPT_BYTES: &[u8] = b"n3-task-runtime-initialized-v1\n";
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeImage {
    schema_version: u64,
    pub(crate) journals: Vec<RuntimeJournal>,
}
// Local envelope codec; this is not a public wire DTO.
impl CanonicalDto for RuntimeImage {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("schema_version".into(), self.schema_version.to_value()),
            ("journals".into(), self.journals.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut f) = value else {
            return Err(corrupt("invalid runtime image"));
        };
        let result = Self {
            schema_version: u64::from_value(
                f.remove("schema_version")
                    .ok_or_else(|| corrupt("missing runtime version"))?,
            )?,
            journals: Vec::<RuntimeJournal>::from_value(
                f.remove("journals")
                    .ok_or_else(|| corrupt("missing journals"))?,
            )?,
        };
        if !f.is_empty() {
            return Err(corrupt("unknown runtime image field"));
        }
        Ok(result)
    }
}
impl RuntimeImage {
    pub(crate) fn validate(&self, accepted: &AcceptanceLedger) -> Result<(), TaskError> {
        if self.schema_version != 1 {
            return Err(corrupt("unsupported runtime image version"));
        }
        let mut ids = BTreeSet::new();
        let mut handles = BTreeSet::new();
        for journal in &self.journals {
            if !ids.insert(&journal.task_id) {
                return Err(corrupt("duplicate runtime TaskId"));
            }
            let task = find(accepted, &journal.task_id)
                .map_err(|_| corrupt("runtime journal has no acceptance"))?;
            let state = journal.replay(task, sha256)?;
            if let Some(handle) = state.execution_handle {
                if !handles.insert(handle) {
                    return Err(corrupt("execution handle reused across Tasks"));
                }
            }
        }
        Ok(())
    }
}
fn find<'a>(ledger: &'a AcceptanceLedger, id: &TaskId) -> Result<&'a AcceptedTask, TaskError> {
    ledger
        .tasks
        .iter()
        .find(|t| &t.view.task_id == id)
        .ok_or_else(|| TaskError::invalid("unknown accepted TaskId"))
}
pub(crate) fn initialize(root: &Path, accepted: &AcceptanceLedger) -> Result<(), TaskError> {
    let receipt = read_private(&root.join(RECEIPT), false)?;
    let authority = read_private(&root.join("acceptance-initialized-v1"), true)?;
    let required = authority
        .as_deref()
        .is_some_and(crate::task_capacity::is_capacity_receipt)
        || authority.as_deref() == Some(crate::task_store::RUNTIME_AUTHORITY_RECEIPT)
        || read_private(&root.join("acceptance-initialized-v1"), true)?.as_deref()
            == Some(crate::task_artifacts::AUTHORITY_RECEIPT);
    if required && receipt.is_none() {
        return Err(corrupt(
            "required runtime initialization receipt is missing",
        ));
    }
    if receipt
        .as_deref()
        .is_some_and(|bytes| bytes != RECEIPT_BYTES)
    {
        return Err(corrupt("corrupt runtime initialization receipt"));
    }
    match read_private(&root.join(IMAGE), false)? {
        None if receipt.is_some() => return Err(corrupt("initialized runtime image missing")),
        None => {
            // Upgrade N3-2's immutable Waiting records without rewriting their
            // authority. No runtime handle is exposed before image + receipt sync.
            save(
                root,
                &RuntimeImage {
                    schema_version: 1,
                    journals: Vec::new(),
                },
            )?;
        }
        Some(bytes) => {
            decode(&bytes, accepted)?;
        }
    }
    if receipt.is_none() {
        atomic_publish(root, &root.join(RECEIPT), RECEIPT_BYTES, &mut |_| Ok(()))?;
    }
    load_and_validate(root, accepted)?;
    // Upgrade the existing authority receipt only after both new files are
    // durable. This distinguishes genuine N3-2 migration from loss of both
    // runtime files; it never rewrites the immutable acceptance image.
    if !required {
        atomic_publish(
            root,
            &root.join("acceptance-initialized-v1"),
            crate::task_store::RUNTIME_AUTHORITY_RECEIPT,
            &mut |_| Ok(()),
        )?;
    }
    sync(root)
}
pub(crate) fn load_and_validate(
    root: &Path,
    accepted: &AcceptanceLedger,
) -> Result<RuntimeImage, TaskError> {
    let receipt = read_private(&root.join(RECEIPT), true)?
        .ok_or_else(|| corrupt("missing runtime receipt"))?;
    if receipt != RECEIPT_BYTES {
        return Err(corrupt("corrupt runtime receipt"));
    }
    let bytes =
        read_private(&root.join(IMAGE), true)?.ok_or_else(|| corrupt("missing runtime image"))?;
    let image = decode(&bytes, accepted)?;
    crate::task_artifacts::validate_runtime(root, accepted, &image)?;
    Ok(image)
}
fn decode(bytes: &[u8], accepted: &AcceptanceLedger) -> Result<RuntimeImage, TaskError> {
    let decode = || {
        let Value::Object(mut f) = parse_canonical_json(bytes)? else {
            return Err(corrupt("invalid runtime envelope"));
        };
        let version = u64::from_value(
            f.remove("schema_version")
                .ok_or_else(|| corrupt("missing runtime envelope version"))?,
        )?;
        let checksum = Sha256Digest::from_value(
            f.remove("payload_sha256")
                .ok_or_else(|| corrupt("missing runtime checksum"))?,
        )?;
        let value = f
            .remove("runtime")
            .ok_or_else(|| corrupt("missing runtime payload"))?;
        if version != 1 || !f.is_empty() || sha256(&value.canonical_bytes()) != checksum {
            return Err(corrupt("corrupt runtime envelope/checksum"));
        }
        let image = RuntimeImage::from_value(value)?;
        image.validate(accepted)?;
        Ok(image)
    };
    decode().map_err(|e: TaskError| corrupt(format!("runtime journal: {e}")))
}
fn read_private(path: &Path, required: bool) -> Result<Option<Vec<u8>>, TaskError> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(corrupt(format!("missing {}", path.display())));
        }
        Err(e) => return Err(io(path, e)),
    };
    let meta = file.metadata().map_err(|e| io(path, e))?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(corrupt("runtime authority must be a private regular file"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| io(path, e))?;
    // A prior rename may have been followed by a failed fsync. Reuse repairs
    // durability before returning a replay acknowledgment, without spawning.
    file.sync_all().map_err(|e| io(path, e))?;
    Ok(Some(bytes))
}
fn save(root: &Path, image: &RuntimeImage) -> Result<(), TaskError> {
    save_with(root, image, &mut |_| Ok(()))
}
fn save_with(
    root: &Path,
    image: &RuntimeImage,
    boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
) -> Result<(), TaskError> {
    let value = image.to_value();
    let bytes = Value::Object(BTreeMap::from([
        ("schema_version".into(), 1u64.to_value()),
        (
            "payload_sha256".into(),
            sha256(&value.canonical_bytes()).to_value(),
        ),
        ("runtime".into(), value),
    ]))
    .canonical_bytes();
    atomic_publish(root, &root.join(IMAGE), &bytes, boundary)
}
fn atomic_publish(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    boundary: &mut dyn FnMut(&str) -> Result<(), TaskError>,
) -> Result<(), TaskError> {
    let tmp = root.join(format!(".runtime-{}.tmp", new_task_id()?.as_str()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(0x20000)
            .open(&tmp)
            .map_err(|e| io(&tmp, e))?;
        file.write_all(bytes).map_err(|e| io(&tmp, e))?;
        boundary("after_write")?;
        file.sync_all().map_err(|e| io(&tmp, e))?;
        boundary("after_file_sync")?;
        fs::rename(&tmp, path).map_err(|e| io(path, e))?;
        boundary("after_rename")?;
        sync(root)?;
        boundary("after_directory_sync")?;
        Ok(())
    })();
    if result.is_err() {
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => { /* retain orphan evidence; it never replaces authority */ }
        }
    }
    result
}
fn sync(root: &Path) -> Result<(), TaskError> {
    fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| io(root, e))
}
fn io(path: &Path, e: std::io::Error) -> TaskError {
    TaskError::new(
        TaskErrorCode::PersistenceFailed,
        format!("{}: {e}", path.display()),
        true,
    )
}
fn corrupt(detail: impl Into<String>) -> TaskError {
    TaskError::new(TaskErrorCode::StateCorrupt, detail, false)
}

impl TaskRuntimeStore for FileTaskAcceptanceStore {
    fn runtime_read(&self, id: &TaskId) -> Result<(AcceptedTask, RuntimeJournal), TaskError> {
        self.with_locked_ledger(|root, accepted| {
            let image = load_and_validate(root, accepted)?;
            let task = find(accepted, id)?.clone();
            let journal = image
                .journals
                .into_iter()
                .find(|j| &j.task_id == id)
                .unwrap_or_else(|| RuntimeJournal::initial(&task));
            Ok((task, journal))
        })
    }
    fn runtime_transact(
        &self,
        id: &TaskId,
        update: &mut dyn FnMut(
            &AcceptedTask,
            &mut RuntimeJournal,
        ) -> Result<RuntimeUpdate, TaskError>,
    ) -> Result<RuntimeUpdate, TaskError> {
        self.with_locked_ledger(|root, accepted| {
            let mut image = load_and_validate(root, accepted)?;
            let task = find(accepted, id)?;
            let index = match image.journals.iter().position(|j| &j.task_id == id) {
                Some(i) => i,
                None => {
                    image.journals.push(RuntimeJournal::initial(task));
                    image.journals.len() - 1
                }
            };
            let original = image.journals[index].clone();
            let result = update(task, &mut image.journals[index])?;
            if !image.journals[index].events.starts_with(&original.events) {
                return Err(corrupt("runtime history cannot be removed or rewritten"));
            }
            image.validate(accepted)?;
            crate::task_artifacts::validate_runtime(root, accepted, &image)?;
            if result.state != image.journals[index].replay(task, sha256)? {
                return Err(corrupt("runtime transaction result differs from journal"));
            }
            let changed = original != image.journals[index];
            if result.applied != changed
                || (changed && image.journals[index].events.len() != original.events.len() + 1)
            {
                return Err(corrupt(
                    "runtime applied marker must match exactly one appended event",
                ));
            }
            if changed {
                if image.journals[index].events.last().is_some_and(|event| {
                    matches!(
                        event.action,
                        RuntimeAction::Prepare | RuntimeAction::StartIntent { .. }
                    )
                }) {
                    crate::task_capacity::verify_action(root, accepted, id)?;
                }
                save(root, &image)?;
            } else {
                sync(root)?;
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
#[path = "task_runtime_store_tests.rs"]
mod tests;
