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
        store.load()?;
        sync_directory(&store.root)?;
        Ok(store)
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
            .custom_flags(0x20000)
            .open(&path)
            .map_err(|e| io_error(&path, e))?;
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
            .custom_flags(0x20000)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AcceptanceLedger::default());
            }
            Err(e) => return Err(io_error(&path, e)),
        };
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
            let original = ledger.clone();
            let result = update(&mut ledger)?;
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
