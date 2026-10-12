//! N3-2 Linux composition root: strong content, durable roots and private input
//! materialization. It never creates a process or advances TaskOutcome.
#[cfg(target_os = "linux")]
use crate::task_store::FileTaskAcceptanceStore;
use nexus_domain::task::{Sha256Digest, SnapshotRef, TaskError, TaskErrorCode};
use nexus_storage::ContentStore;
use nexus_workspace::{
    CommitId, Workspace,
    snapshot::{FrozenSnapshot, SnapshotSelection},
};
use std::path::{Path, PathBuf};

/// Shares the stable acceptance lock across handles and processes. All accepted
/// Tasks (including expired keys) are roots; their release awaits N3-3's durable
/// authoritative finalization. Explicit roots and staged previews are separate.
#[derive(Debug, Clone)]
pub struct FileSnapshotStore {
    #[cfg(target_os = "linux")]
    acceptance: FileTaskAcceptanceStore,
}

/// Verified private input tree. Not evidence of container isolation or execution.
#[derive(Debug)]
pub struct PreparedSnapshot {
    pub directory: PathBuf,
    pub snapshot_id: Sha256Digest,
}

/// Two-phase strong-namespace GC observations, unrelated to legacy FNV GC.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SnapshotGcReport {
    pub marked: u64,
    pub deleted: u64,
    pub protected: u64,
}

impl FileSnapshotStore {
    /// Caller already owns the original acceptance lease. No open/initialize,
    /// directory sync, root publication or GC is performed by this validation.
    #[cfg(target_os = "linux")]
    pub(crate) fn validate_existing_roots(
        root: &Path,
        ledger: &nexus_compute::task::AcceptanceLedger,
    ) -> Result<(), TaskError> {
        linux::validate_roots_readonly(root, ledger)
    }
    /// `root` is the same private root used for Task acceptance.
    pub fn open(root: &Path) -> Result<Self, TaskError> {
        #[cfg(target_os = "linux")]
        {
            let store = Self {
                acceptance: FileTaskAcceptanceStore::open(root)?,
            };
            #[cfg(target_os = "linux")]
            store.acceptance.with_locked_ledger(|root, _| {
                linux::initialize_catalog(root)?;
                linux::content_dir(root)?;
                linux::load_catalog(root)?;
                Ok(())
            })?;
            Ok(store)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            Err(unsupported())
        }
    }
    /// Publish selected committed bytes and a durable preview root before
    /// returning the SnapshotRef. No mutable Head or local directory is scanned.
    pub fn stage_snapshot<S: ContentStore>(
        &self,
        workspace: &Workspace<S>,
        commit: &CommitId,
        selection: &SnapshotSelection,
    ) -> Result<FrozenSnapshot, TaskError> {
        #[cfg(target_os = "linux")]
        return self.acceptance.with_locked_ledger(|root, _| {
            let mut catalog = linux::load_catalog(root)?;
            let mut content = linux::Content::open(root)?;
            let snapshot = workspace.freeze_snapshot(
                commit,
                selection,
                &mut content,
                nexus::n3_acceptance::sha256,
            )?;
            linux::add_root(&mut catalog.staged, &snapshot.reference)?;
            linux::revoke_tombstones(&mut catalog, &snapshot);
            linux::save_catalog(root, &catalog)?;
            Ok(snapshot)
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (workspace, commit, selection);
            Err(unsupported())
        }
    }
    /// An explicit retained Snapshot is independent of preview/Task retention.
    pub fn retain_snapshot(&self, snapshot: &SnapshotRef) -> Result<(), TaskError> {
        #[cfg(target_os = "linux")]
        return self.acceptance.with_locked_ledger(|root, _| {
            let mut catalog = linux::load_catalog(root)?;
            let frozen = linux::read_snapshot(root, snapshot)?;
            frozen.verify_inputs(
                &linux::Content::open(root)?,
                nexus::n3_acceptance::sha256,
                ".",
            )?;
            linux::add_root(&mut catalog.retained, snapshot)?;
            linux::revoke_tombstones(&mut catalog, &frozen);
            linux::save_catalog(root, &catalog)
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = snapshot;
            Err(unsupported())
        }
    }
    /// Release only the staging preview. Accepted/explicit Snapshot roots remain.
    /// This operation grants no authority to release a Task or other owner pin.
    pub fn release_preview(&self, snapshot_id: &Sha256Digest) -> Result<(), TaskError> {
        #[cfg(target_os = "linux")]
        return self.acceptance.with_locked_ledger(|root, _| {
            let mut catalog = linux::load_catalog(root)?;
            catalog.staged.retain(|s| &s.snapshot_id != snapshot_id);
            linux::save_catalog(root, &catalog)
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = snapshot_id;
            Err(unsupported())
        }
    }
    /// Verify the manifest and every selected content byte against the caller's
    /// authenticated accepted SnapshotRef. An untrusted replacement is rejected.
    pub fn verify_inputs(
        &self,
        snapshot: &SnapshotRef,
        cwd: &str,
    ) -> Result<FrozenSnapshot, TaskError> {
        #[cfg(target_os = "linux")]
        return self.acceptance.with_locked_ledger(|root, _| {
            linux::load_catalog(root)?;
            let frozen = linux::read_snapshot(root, snapshot)?;
            frozen.verify_inputs(
                &linux::Content::open(root)?,
                nexus::n3_acceptance::sha256,
                cwd,
            )?;
            Ok(frozen)
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (snapshot, cwd);
            Err(unsupported())
        }
    }
    /// Prepare a fresh tree below the private provider root. Names cannot follow
    /// existing symlinks; all bytes are checked before creating any input tree.
    pub fn prepare_inputs(
        &self,
        snapshot: &SnapshotRef,
        cwd: &str,
    ) -> Result<PreparedSnapshot, TaskError> {
        #[cfg(target_os = "linux")]
        return self
            .acceptance
            .with_locked_ledger(|root, ledger| linux::prepare(root, ledger, snapshot, cwd));
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (snapshot, cwd);
            Err(unsupported())
        }
    }
    /// Validate every durable Snapshot root during boot without GC mutation.
    #[cfg(target_os = "linux")]
    pub(crate) fn verify_recovery_roots(&self) -> Result<(), TaskError> {
        self.acceptance.with_locked_ledger(|root, ledger| {
            linux::recovered_roots(root, ledger, &linux::load_catalog(root)?)?;
            Ok(())
        })
    }
    /// Reconstruct Task + preview + explicit roots under the acceptance lock,
    /// fail closed on incomplete/corrupt root manifests, then tombstone/sweep.
    pub fn collect_garbage(
        &self,
        now_unix: u64,
        retention_seconds: u64,
    ) -> Result<SnapshotGcReport, TaskError> {
        #[cfg(target_os = "linux")]
        return self.acceptance.with_gc_locked_ledger(|root, ledger| {
            linux::collect(root, ledger, now_unix, retention_seconds)
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (now_unix, retention_seconds);
            Err(unsupported())
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn unsupported() -> TaskError {
    TaskError::new(
        TaskErrorCode::UnsupportedCapability,
        "N3 provider content requires Linux",
        false,
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nexus::n3_acceptance::{new_task_id, parse_canonical_json, sha256};
    use nexus_compute::task::AcceptanceLedger;
    use nexus_domain::task::{
        MAX_INTEGER,
        codec::{CanonicalDto, Value},
    };
    use nexus_storage::strong::{StrongContentStore, verify_content};
    use nexus_workspace::snapshot::SnapshotFile;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    };

    // Directory ownership is the same trusted provider boundary as acceptance.
    // Same-uid malicious mutation is outside it; request-controlled paths never
    // choose these roots. O_NOFOLLOW|O_NONBLOCK prevents links and special-file hangs.
    const NOFOLLOW_NONBLOCK: i32 = 0x20000 | 0x800;
    fn io_error(path: &Path, e: std::io::Error) -> TaskError {
        TaskError::new(
            TaskErrorCode::PersistenceFailed,
            format!("{}: {e}", path.display()),
            true,
        )
    }
    fn corrupt(message: impl Into<String>) -> TaskError {
        TaskError::new(TaskErrorCode::StateCorrupt, message, false)
    }
    fn sync_dir(path: &Path) -> Result<(), TaskError> {
        File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| io_error(path, e))
    }
    fn private_dir(path: &Path) -> Result<(), TaskError> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_error(path, e)),
        }
        let meta = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0
        {
            return Err(corrupt("N3 directory must be a private real directory"));
        }
        sync_dir(path)?;
        sync_dir(
            path.parent()
                .ok_or_else(|| corrupt("N3 directory lacks parent"))?,
        )
    }
    pub(super) fn content_dir(root: &Path) -> Result<PathBuf, TaskError> {
        let dir = root.join("content-sha256-v1");
        private_dir(&dir)?;
        Ok(dir)
    }
    fn regular_read(path: &Path) -> Result<Vec<u8>, TaskError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    TaskError::new(
                        TaskErrorCode::InputUnavailable,
                        format!("missing {}", path.display()),
                        true,
                    )
                } else {
                    io_error(path, e)
                }
            })?;
        let metadata = file.metadata().map_err(|e| io_error(path, e))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(corrupt("N3 content/state must be a private regular file"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| io_error(path, e))?;
        Ok(bytes)
    }
    fn atomic_publish(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), TaskError> {
        atomic_publish_with(root, path, bytes, |_| Ok(()))
    }
    fn atomic_publish_with(
        root: &Path,
        path: &Path,
        bytes: &[u8],
        mut boundary: impl FnMut(&str) -> Result<(), TaskError>,
    ) -> Result<(), TaskError> {
        let tmp = root.join(format!(".n3-{}.tmp", new_task_id()?.as_str()));
        let operation = || {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| io_error(&tmp, e))?;
            file.write_all(bytes).map_err(|e| io_error(&tmp, e))?;
            boundary("after-write")?;
            file.sync_all().map_err(|e| io_error(&tmp, e))?;
            boundary("after-file-sync")?;
            fs::rename(&tmp, path).map_err(|e| io_error(path, e))?;
            boundary("after-rename")?;
            sync_dir(root)?;
            boundary("after-directory-sync")?;
            Ok(())
        };
        let mut operation = operation;
        let result = operation();
        if result.is_err() {
            let _ = fs::remove_file(&tmp); /* Only uncommitted temp; never a published object. */
        }
        result
    }
    pub(super) struct Content {
        dir: PathBuf,
        readonly: bool,
    }
    impl Content {
        pub(super) fn open(root: &Path) -> Result<Self, TaskError> {
            Ok(Self {
                dir: content_dir(root)?,
                readonly: false,
            })
        }
        fn path(&self, digest: &Sha256Digest) -> PathBuf {
            self.dir.join(&digest.as_str()[7..])
        }
        fn read(&self, digest: &Sha256Digest) -> Result<Vec<u8>, TaskError> {
            let bytes = if self.readonly {
                crate::artifact_fs::read(&self.path(digest), crate::artifact_fs::MAX_BYTES)?
            } else {
                regular_read(&self.path(digest))?
            };
            verify_content(digest, bytes.len() as u64, &bytes, sha256)?;
            Ok(bytes)
        }
    }
    impl StrongContentStore for Content {
        fn get_verified(
            &self,
            digest: &Sha256Digest,
            size_bytes: u64,
        ) -> Result<Vec<u8>, TaskError> {
            let bytes = self.read(digest)?;
            verify_content(digest, size_bytes, &bytes, sha256)?;
            Ok(bytes)
        }
        fn put_verified(&mut self, digest: &Sha256Digest, bytes: &[u8]) -> Result<(), TaskError> {
            verify_content(digest, bytes.len() as u64, bytes, sha256)?;
            let path = self.path(digest);
            match self.read(digest) {
                Ok(existing) => {
                    if existing != bytes {
                        return Err(corrupt("distinct bytes share a strong address"));
                    }
                    // Do not reuse a rename whose first directory fsync failed.
                    File::open(&path)
                        .and_then(|f| f.sync_all())
                        .map_err(|e| io_error(&path, e))?;
                    sync_dir(&self.dir)
                }
                Err(e) if e.code == TaskErrorCode::InputUnavailable => {
                    atomic_publish(&self.dir, &path, bytes)
                }
                Err(e) => Err(e),
            }
        }
    }
    #[derive(Default, Clone)]
    pub(super) struct Catalog {
        pub staged: Vec<SnapshotRef>,
        pub retained: Vec<SnapshotRef>,
        tombstones: BTreeMap<Sha256Digest, u64>,
    }
    impl Catalog {
        fn value(&self) -> Value {
            Value::Object(BTreeMap::from([
                ("schema_version".into(), Value::Integer(1)),
                ("staged".into(), self.staged.to_value()),
                ("retained".into(), self.retained.to_value()),
                (
                    "tombstones".into(),
                    Value::Array(
                        self.tombstones
                            .iter()
                            .map(|(d, t)| {
                                Value::Object(BTreeMap::from([
                                    ("sha256".into(), d.to_value()),
                                    ("at_unix".into(), t.to_value()),
                                ]))
                            })
                            .collect(),
                    ),
                ),
            ]))
        }
        fn decode(value: Value) -> Result<Self, TaskError> {
            let Value::Object(mut fields) = value else {
                return Err(corrupt("invalid root catalog"));
            };
            let mut take = |key: &str| {
                fields
                    .remove(key)
                    .ok_or_else(|| corrupt(format!("missing roots {key}")))
            };
            if u64::from_value(take("schema_version")?)? != 1 {
                return Err(corrupt("unsupported roots version"));
            }
            let staged = Vec::<SnapshotRef>::from_value(take("staged")?)?;
            let retained = Vec::<SnapshotRef>::from_value(take("retained")?)?;
            let Value::Array(tombs) = take("tombstones")? else {
                return Err(corrupt("invalid tombstones"));
            };
            if !fields.is_empty() {
                return Err(corrupt("unknown root catalog field"));
            }
            let mut tombstones = BTreeMap::new();
            for t in tombs {
                let Value::Object(mut f) = t else {
                    return Err(corrupt("invalid tombstone"));
                };
                let d = Sha256Digest::from_value(
                    f.remove("sha256")
                        .ok_or_else(|| corrupt("missing tombstone digest"))?,
                )?;
                let at = u64::from_value(
                    f.remove("at_unix")
                        .ok_or_else(|| corrupt("missing tombstone timestamp"))?,
                )?;
                if !f.is_empty() || tombstones.insert(d, at).is_some() {
                    return Err(corrupt("duplicate or unknown tombstone"));
                }
            }
            for roots in [&staged, &retained] {
                let mut ids = BTreeSet::new();
                for r in roots {
                    r.verify_digest(sha256)?;
                    if !ids.insert(&r.snapshot_id) {
                        return Err(corrupt("duplicate root"));
                    }
                }
            }
            Ok(Self {
                staged,
                retained,
                tombstones,
            })
        }
    }
    pub(super) fn load_catalog(root: &Path) -> Result<Catalog, TaskError> {
        let bytes = match regular_read(&root.join("snapshot-roots-v1.json")) {
            Ok(b) => b,
            Err(e) if e.code == TaskErrorCode::InputUnavailable => {
                return Err(corrupt("durable snapshot root catalog is missing"));
            }
            Err(e) => return Err(e),
        };
        let decode = || {
            let Value::Object(mut e) = parse_canonical_json(&bytes)? else {
                return Err(corrupt("invalid root envelope"));
            };
            let payload = e
                .remove("roots")
                .ok_or_else(|| corrupt("missing roots payload"))?;
            let digest = Sha256Digest::from_value(
                e.remove("payload_sha256")
                    .ok_or_else(|| corrupt("missing roots digest"))?,
            )?;
            if !e.is_empty() || sha256(&payload.canonical_bytes()) != digest {
                return Err(corrupt("root checksum mismatch"));
            }
            Catalog::decode(payload)
        };
        decode().map_err(|e: TaskError| corrupt(e.to_string()))
    }
    pub(super) fn initialize_catalog(root: &Path) -> Result<(), TaskError> {
        let path = root.join("snapshot-roots-v1.json");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                load_catalog(root)?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Publish the initial empty catalog BEFORE creating its content
                // namespace. Once that namespace exists, losing the catalog is
                // corruption, never permission to forget preview/explicit roots.
                match fs::symlink_metadata(root.join("content-sha256-v1")) {
                    Ok(_) => Err(corrupt("root catalog missing from initialized namespace")),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        save_catalog(root, &Catalog::default())
                    }
                    Err(e) => Err(io_error(root, e)),
                }
            }
            Err(e) => Err(io_error(&path, e)),
        }
    }
    pub(super) fn save_catalog(root: &Path, catalog: &Catalog) -> Result<(), TaskError> {
        let payload = catalog.value();
        Catalog::decode(payload.clone())?;
        let envelope = Value::Object(BTreeMap::from([
            (
                "payload_sha256".into(),
                sha256(&payload.canonical_bytes()).to_value(),
            ),
            ("roots".into(), payload),
        ]));
        atomic_publish(
            root,
            &root.join("snapshot-roots-v1.json"),
            &envelope.canonical_bytes(),
        )
    }
    pub(super) fn add_root(
        roots: &mut Vec<SnapshotRef>,
        snapshot: &SnapshotRef,
    ) -> Result<(), TaskError> {
        snapshot.verify_digest(sha256)?;
        if let Some(previous) = roots.iter().find(|s| s.snapshot_id == snapshot.snapshot_id) {
            if previous != snapshot {
                return Err(corrupt("conflicting snapshot root"));
            }
        } else {
            roots.push(snapshot.clone());
            roots.sort_by(|a, b| a.snapshot_id.cmp(&b.snapshot_id));
        }
        Ok(())
    }
    pub(super) fn revoke_tombstones(catalog: &mut Catalog, snapshot: &FrozenSnapshot) {
        catalog
            .tombstones
            .remove(&snapshot.reference.manifest_sha256);
        for file in &snapshot.files {
            catalog.tombstones.remove(&file.sha256);
        }
    }
    pub(super) fn read_snapshot(
        root: &Path,
        snapshot: &SnapshotRef,
    ) -> Result<FrozenSnapshot, TaskError> {
        snapshot.verify_digest(sha256)?;
        let bytes = Content::open(root)?.read(&snapshot.manifest_sha256)?;
        let files = Vec::<SnapshotFile>::from_value(parse_canonical_json(&bytes)?)?;
        let frozen = FrozenSnapshot {
            reference: snapshot.clone(),
            files,
        };
        frozen.validate(sha256)?;
        Ok(frozen)
    }
    pub(super) fn recovered_roots(
        root: &Path,
        ledger: &AcceptanceLedger,
        catalog: &Catalog,
    ) -> Result<BTreeSet<Sha256Digest>, TaskError> {
        let mut roots = BTreeSet::new();
        let content = Content::open(root)?;
        for snapshot in catalog
            .staged
            .iter()
            .chain(&catalog.retained)
            .chain(ledger.tasks.iter().map(|t| &t.input_pin_intent))
        {
            let frozen = read_snapshot(root, snapshot)?;
            // Incomplete recovery blocks GC rather than dropping a pin. Missing
            // inputs may still be imported later through normal staging.
            frozen.verify_inputs(&content, sha256, ".")?;
            roots.insert(snapshot.manifest_sha256.clone());
            roots.extend(frozen.files.into_iter().map(|f| f.sha256));
        }
        Ok(roots)
    }
    /// Validation uses an already-existing content namespace. It must never
    /// create the missing namespace as the writable Content::open does.
    pub(super) fn validate_roots_readonly(
        root: &Path,
        ledger: &AcceptanceLedger,
    ) -> Result<(), TaskError> {
        let catalog = load_catalog(root)?;
        let dir = root.join("content-sha256-v1");
        crate::artifact_fs::check_directory(&dir)?;
        let content = Content {
            dir,
            readonly: true,
        };
        for snapshot in catalog
            .staged
            .iter()
            .chain(&catalog.retained)
            .chain(ledger.tasks.iter().map(|task| &task.input_pin_intent))
        {
            snapshot.verify_digest(sha256)?;
            let files = Vec::<SnapshotFile>::from_value(parse_canonical_json(
                &content.read(&snapshot.manifest_sha256)?,
            )?)?;
            let frozen = FrozenSnapshot {
                reference: snapshot.clone(),
                files,
            };
            frozen.validate(sha256)?;
            frozen.verify_inputs(&content, sha256, ".")?;
        }
        Ok(())
    }
    pub(super) fn prepare(
        root: &Path,
        ledger: &AcceptanceLedger,
        snapshot: &SnapshotRef,
        cwd: &str,
    ) -> Result<PreparedSnapshot, TaskError> {
        let mut catalog = load_catalog(root)?;
        let content = Content::open(root)?;
        let frozen = read_snapshot(root, snapshot)?;
        frozen.validate_cwd(cwd)?;
        let bytes = frozen
            .files
            .iter()
            .map(|f| content.get_verified(&f.sha256, f.size_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        // Preparing also durably retains a preview when not yet accepted. A
        // caller releasing it later cannot erase an acceptance-derived pin.
        if !ledger.tasks.iter().any(|t| t.input_pin_intent == *snapshot) {
            add_root(&mut catalog.staged, snapshot)?;
        }
        revoke_tombstones(&mut catalog, &frozen);
        save_catalog(root, &catalog)?;
        let dir = root.join(format!("input-{}", new_task_id()?.as_str()));
        // Fresh exclusive directory, beneath a private root, not a caller path.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| io_error(&dir, e))?;
        for (file, data) in frozen.files.iter().zip(bytes) {
            let path = dir.join(&file.path);
            let parent = path.parent().ok_or_else(|| corrupt("input lacks parent"))?;
            let mut current = dir.clone();
            for component in parent
                .strip_prefix(&dir)
                .map_err(|_| corrupt("input escaped root"))?
                .components()
            {
                current.push(component);
                private_dir(&current)?;
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(if file.executable { 0o700 } else { 0o600 })
                .custom_flags(NOFOLLOW_NONBLOCK)
                .open(&path)
                .map_err(|e| io_error(&path, e))?;
            output.write_all(&data).map_err(|e| io_error(&path, e))?;
            output.sync_all().map_err(|e| io_error(&path, e))?;
            sync_dir(parent)?;
        }
        sync_dir(&dir)?;
        sync_dir(root)?;
        Ok(PreparedSnapshot {
            directory: dir,
            snapshot_id: snapshot.snapshot_id.clone(),
        })
    }
    pub(super) fn collect(
        root: &Path,
        ledger: &AcceptanceLedger,
        now: u64,
        retention: u64,
    ) -> Result<SnapshotGcReport, TaskError> {
        if now > MAX_INTEGER || retention > MAX_INTEGER {
            return Err(TaskError::invalid(
                "GC clock/retention exceeds exact integer range",
            ));
        }
        let mut catalog = load_catalog(root)?;
        let roots = recovered_roots(root, ledger, &catalog)?;
        let dir = content_dir(root)?;
        let mut report = SnapshotGcReport {
            protected: roots.len() as u64,
            ..Default::default()
        };
        catalog.tombstones.retain(|d, _| !roots.contains(d));
        let mut candidates = BTreeSet::new();
        for entry in fs::read_dir(&dir).map_err(|e| io_error(&dir, e))? {
            let entry = entry.map_err(|e| io_error(&dir, e))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| corrupt("non-UTF8 strong address"))?;
            if name.starts_with('.') {
                continue;
            } // uncommitted temps are never inputs
            let digest = Sha256Digest::parse(format!("sha256:{name}"))
                .map_err(|_| corrupt("invalid strong content filename"))?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|e| io_error(&entry.path(), e))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(corrupt("non-regular strong content"));
            }
            if roots.contains(&digest) {
                continue;
            }
            candidates.insert(digest.clone());
            if let std::collections::btree_map::Entry::Vacant(slot) =
                catalog.tombstones.entry(digest)
            {
                slot.insert(now);
                report.marked += 1;
            }
        }
        // Intent must be durable before deletion; lock remains held throughout
        // reachability revalidation, candidate enumeration and physical sweep.
        save_catalog(root, &catalog)?;
        for digest in candidates {
            let at = catalog.tombstones[&digest];
            if now.saturating_sub(at) < retention {
                continue;
            }
            let path = dir.join(&digest.as_str()[7..]);
            fs::remove_file(&path).map_err(|e| io_error(&path, e))?;
            report.deleted += 1;
            catalog.tombstones.remove(&digest);
        }
        sync_dir(&dir)?;
        save_catalog(root, &catalog)?;
        Ok(report)
    }
    #[cfg(test)]
    mod tests {
        include!("snapshot_store_tests.rs");
    }
}
