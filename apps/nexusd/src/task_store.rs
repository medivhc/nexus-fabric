//! N3-1 Linux provider persistence adapter (composition root).
#[cfg(target_os = "linux")]
use nexus::n3_acceptance::{new_task_id, parse_canonical_json, sha256};
use nexus_compute::task::{AcceptanceLedger, AcceptanceResult, TaskAcceptanceStore};
#[cfg(target_os = "linux")]
use nexus_domain::task::{
    Sha256Digest,
    codec::{CanonicalDto, Value},
};
use nexus_domain::task::{TaskError, TaskErrorCode};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
pub(crate) const RUNTIME_AUTHORITY_RECEIPT: &[u8] =
    b"n3-acceptance-initialized-v1\nruntime-v1-required\n";

/// Linux provider acceptance store. All handles/processes lock one stable inode.
/// The parent must already exist; one image atomically publishes Task/index/pin.
/// Directory sync errors are returned, including after rename (ambiguous commit).
/// Cold restart reloads the committed image, ignoring uncommitted temp files.
#[derive(Debug, Clone)]
pub struct FileTaskAcceptanceStore {
    #[cfg(target_os = "linux")]
    root: PathBuf,
}
impl FileTaskAcceptanceStore {
    /// Composition-root operations on N3 content/roots share the acceptance
    /// lock. GC cannot race a newly published Task pin or scoped key reuse.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_locked_ledger<R>(
        &self,
        operation: impl FnOnce(&Path, &AcceptanceLedger) -> Result<R, TaskError>,
    ) -> Result<R, TaskError> {
        let _lock = self.lock()?;
        let ledger = self.load()?;
        crate::task_runtime_store::load_and_validate(&self.root, &ledger)?;
        sync_directory(&self.root)?;
        operation(&self.root, &ledger)
    }
    pub fn open(root: &Path) -> Result<Self, TaskError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            Err(TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "durable N3 provider acceptance is supported on Linux only",
                false,
            ))
        }
        #[cfg(target_os = "linux")]
        {
            Self::open_with_parent_sync(root, sync_directory)
        }
    }
    #[cfg(target_os = "linux")]
    fn open_with_parent_sync(
        root: &Path,
        mut parent_sync: impl FnMut(&Path) -> Result<(), TaskError>,
    ) -> Result<Self, TaskError> {
        use std::fs;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_error(root, e)),
        }
        let meta = fs::symlink_metadata(root).map_err(|e| io_error(root, e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0
        {
            return Err(TaskError::new(
                TaskErrorCode::PersistenceFailed,
                "acceptance root must be a private real directory (0700)",
                false,
            ));
        }
        let store = Self {
            root: fs::canonicalize(root).map_err(|e| io_error(root, e))?,
        };
        // AlreadyExists is not durability evidence: another creator may still
        // be before fsync, or a prior open may have failed at this boundary.
        // Sync each ancestor so a newly created existing parent is also covered.
        for parent in store.root.ancestors().skip(1) {
            parent_sync(parent)?;
        }
        let _lock = store.lock()?;
        store.initialize()?;
        let ledger = store.load()?;
        crate::task_runtime_store::initialize(&store.root, &ledger)?;
        sync_directory(&store.root)?;
        Ok(store)
    }
    #[cfg(target_os = "linux")]
    fn initialize(&self) -> Result<(), TaskError> {
        use std::{
            fs,
            io::{Read, Write},
            os::unix::fs::OpenOptionsExt,
        };
        const RECEIPT: &[u8] = b"n3-acceptance-initialized-v1\n";
        let receipt = self.root.join("acceptance-initialized-v1");
        let initialized = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(&receipt)
        {
            Ok(mut file) => {
                if !file
                    .metadata()
                    .map_err(|e| io_error(&receipt, e))?
                    .is_file()
                {
                    return Err(TaskError::new(
                        TaskErrorCode::StateCorrupt,
                        "acceptance initialization receipt is not regular",
                        false,
                    ));
                }
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .map_err(|e| io_error(&receipt, e))?;
                if bytes != RECEIPT
                    && bytes != RUNTIME_AUTHORITY_RECEIPT
                    && bytes != crate::task_artifacts::AUTHORITY_RECEIPT
                {
                    return Err(TaskError::new(
                        TaskErrorCode::StateCorrupt,
                        "corrupt acceptance initialization receipt",
                        false,
                    ));
                }
                file.sync_all().map_err(|e| io_error(&receipt, e))?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(io_error(&receipt, e)),
        };
        let image = self.root.join("acceptance-v1.json");
        match fs::symlink_metadata(&image) {
            Ok(_) => {
                self.load()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Initialize a fresh empty image before exposing any handle. A
                // published receipt, N3 content or runtime authority proves prior state;
                // missing authority there is corruption, never a new provider.
                let mut has_authority = false;
                for name in [
                    "content-sha256-v1",
                    "task-runtime-v1.json",
                    "task-runtime-initialized-v1",
                    "artifacts-v1.json",
                    "artifacts-initialized-v1",
                    "artifact-content-sha256-v1",
                ] {
                    let path = self.root.join(name);
                    match fs::symlink_metadata(&path) {
                        Ok(_) => {
                            has_authority = true;
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(io_error(&path, e)),
                    }
                }
                if initialized || has_authority {
                    return Err(TaskError::new(
                        TaskErrorCode::StateCorrupt,
                        "initialized acceptance image is missing",
                        false,
                    ));
                }
                self.publish(&AcceptanceLedger::default())?;
            }
            Err(e) => return Err(io_error(&image, e)),
        }
        if !initialized {
            for name in [
                "artifacts-v1.json",
                "artifacts-initialized-v1",
                "artifact-content-sha256-v1",
                "artifact-audit-v1",
            ] {
                match fs::symlink_metadata(self.root.join(name)) {
                    Ok(_) => {
                        return Err(TaskError::new(
                            TaskErrorCode::StateCorrupt,
                            "acceptance receipt missing beside existing Artifact authority",
                            false,
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(io_error(&receipt, e)),
                }
            }
            // Existing N3-1 images migrate without changing their bytes/schema.
            // The receipt is itself atomic; a crash before its publication can
            // safely retry using the already durable, validated image.
            let tmp = self
                .root
                .join(format!(".initialized-{}.tmp", new_task_id()?.as_str()));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| io_error(&tmp, e))?;
            file.write_all(RECEIPT).map_err(|e| io_error(&tmp, e))?;
            file.sync_all().map_err(|e| io_error(&tmp, e))?;
            fs::rename(&tmp, &receipt).map_err(|e| io_error(&receipt, e))?;
        }
        sync_directory(&self.root)
    }
    #[cfg(target_os = "linux")]
    fn lock(&self) -> Result<std::fs::File, TaskError> {
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        let path = self.root.join("acceptance.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(0x20000 | 0x800)
            .open(&path)
            .map_err(|e| io_error(&path, e))?;
        if !file.metadata().map_err(|e| io_error(&path, e))?.is_file() {
            return Err(TaskError::new(
                TaskErrorCode::StateCorrupt,
                "acceptance lock is not regular",
                false,
            ));
        }
        // Linux flock is process-independent and released when this File is dropped.
        // The lock inode is never renamed/deleted, including on cold restart.
        unsafe extern "C" {
            fn flock(fd: std::ffi::c_int, operation: std::ffi::c_int) -> std::ffi::c_int;
        }
        loop {
            // SAFETY: fd is owned/live for this call; LOCK_EX=2 takes no pointer.
            let result = unsafe { flock(file.as_raw_fd(), 2) };
            if result == 0 {
                return Ok(file);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(io_error(&path, error));
            }
        }
    }
    #[cfg(target_os = "linux")]
    fn load(&self) -> Result<AcceptanceLedger, TaskError> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.root.join("acceptance-v1.json");
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    "durable acceptance image is missing",
                    false,
                ));
            }
            Err(e) => return Err(io_error(&path, e)),
        };
        if !file.metadata().map_err(|e| io_error(&path, e))?.is_file() {
            return Err(TaskError::new(
                TaskErrorCode::StateCorrupt,
                "acceptance image is not regular",
                false,
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| io_error(&path, e))?;
        let decode = || {
            let Value::Object(mut envelope) = parse_canonical_json(&bytes)? else {
                return Err(TaskError::invalid("invalid acceptance envelope"));
            };
            let version = u64::from_value(
                envelope
                    .remove("schema_version")
                    .ok_or_else(|| TaskError::invalid("missing envelope version"))?,
            )?;
            if version != 1 {
                return Err(TaskError::invalid(
                    "unsupported acceptance envelope version",
                ));
            }
            let checksum = Sha256Digest::from_value(
                envelope
                    .remove("payload_sha256")
                    .ok_or_else(|| TaskError::invalid("missing acceptance checksum"))?,
            )?;
            let value = envelope
                .remove("ledger")
                .ok_or_else(|| TaskError::invalid("missing acceptance ledger"))?;
            if !envelope.is_empty() || sha256(&value.canonical_bytes()) != checksum {
                return Err(TaskError::invalid("corrupt acceptance image/checksum"));
            }
            let ledger = AcceptanceLedger::from_value(value)?;
            ledger.validate(sha256)?;
            Ok(ledger)
        };
        decode().map_err(|e: TaskError| {
            TaskError::new(
                TaskErrorCode::StateCorrupt,
                format!("{}: {e}", path.display()),
                false,
            )
        })
    }
    #[cfg(target_os = "linux")]
    fn publish(&self, ledger: &AcceptanceLedger) -> Result<(), TaskError> {
        self.publish_with(ledger, |_| Ok(()))
    }
    // Fault injection is private; production always performs each boundary.
    #[cfg(target_os = "linux")]
    fn publish_with(
        &self,
        ledger: &AcceptanceLedger,
        mut boundary: impl FnMut(&str) -> Result<(), TaskError>,
    ) -> Result<(), TaskError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        ledger.validate(sha256)?;
        let value = ledger.to_value();
        let envelope = Value::Object(BTreeMap::from([
            ("schema_version".into(), Value::Integer(1)),
            (
                "payload_sha256".into(),
                sha256(&value.canonical_bytes()).to_value(),
            ),
            ("ledger".into(), value),
        ]));
        let tmp = self
            .root
            .join(format!(".acceptance-{}.tmp", new_task_id()?.as_str()));
        let path = self.root.join("acceptance-v1.json");
        let mut operation = || {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| io_error(&tmp, e))?;
            f.write_all(&envelope.canonical_bytes())
                .map_err(|e| io_error(&tmp, e))?;
            boundary("after-write")?;
            f.sync_all().map_err(|e| io_error(&tmp, e))?;
            boundary("after-file-sync")?;
            std::fs::rename(&tmp, &path).map_err(|e| io_error(&path, e))?;
            boundary("after-rename")?;
            sync_directory(&self.root)?;
            boundary("after-directory-sync")?;
            Ok(())
        };
        let result = operation();
        if result.is_err() {
            match std::fs::remove_file(&tmp) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => { /* Orphan uncommitted tmp is not loaded; retain evidence on cleanup failure. */
                }
            }
        }
        result
    }
}
#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), TaskError> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_error(path, e))
}
#[cfg(target_os = "linux")]
fn io_error(path: &Path, error: std::io::Error) -> TaskError {
    TaskError::new(
        TaskErrorCode::PersistenceFailed,
        format!("{}: {error}", path.display()),
        true,
    )
}
impl TaskAcceptanceStore for FileTaskAcceptanceStore {
    fn read(&self) -> Result<AcceptanceLedger, TaskError> {
        #[cfg(target_os = "linux")]
        {
            let _lock = self.lock()?;
            let ledger = self.load()?;
            crate::task_runtime_store::load_and_validate(&self.root, &ledger)?;
            sync_directory(&self.root)?;
            Ok(ledger)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "Linux provider store unavailable",
                false,
            ))
        }
    }
    fn transact(
        &self,
        update: &mut dyn FnMut(&mut AcceptanceLedger) -> Result<AcceptanceResult, TaskError>,
    ) -> Result<AcceptanceResult, TaskError> {
        #[cfg(target_os = "linux")]
        {
            let _lock = self.lock()?;
            let mut ledger = self.load()?;
            let runtime = crate::task_runtime_store::load_and_validate(&self.root, &ledger)?;
            let original = ledger.clone();
            let result = update(&mut ledger)?;
            ledger.validate(sha256)?;
            let tasks: BTreeMap<_, _> = ledger.tasks.iter().map(|t| (&t.view.task_id, t)).collect();
            if original
                .tasks
                .iter()
                .any(|t| tasks.get(&t.view.task_id).copied() != Some(t))
            {
                return Err(TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    "accepted records cannot be removed or replaced",
                    false,
                ));
            }
            let previously_accepted = original
                .tasks
                .iter()
                .any(|t| t.view.task_id == result.task.view.task_id);
            if tasks.get(&result.task.view.task_id).copied() != Some(&result.task)
                || !ledger
                    .idempotency
                    .iter()
                    .any(|entry| entry.task_id == result.task.view.task_id)
                || result.replayed != previously_accepted
                || (result.replayed && ledger != original)
                || (!result.replayed && ledger.tasks.len() != original.tasks.len() + 1)
            {
                return Err(TaskError::new(
                    TaskErrorCode::StateCorrupt,
                    "acceptance acknowledgment differs from one new record or unchanged replay",
                    false,
                ));
            }
            // Recheck the coupled authority after the callback, before writing.
            // The common flock keeps this loaded runtime image stable throughout.
            runtime.validate(&ledger)?;
            if ledger != original {
                self.publish(&ledger)?;
            } else {
                sync_directory(&self.root)?;
            }
            Ok(result)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = update;
            Err(TaskError::new(
                TaskErrorCode::UnsupportedCapability,
                "Linux provider store unavailable",
                false,
            ))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "task_store_tests.rs"]
mod tests;
