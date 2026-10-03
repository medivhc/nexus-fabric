//! Immutable N3 input selection, separate from mutable Heads and WorkingSet.
use std::collections::{BTreeMap, BTreeSet};

use nexus_domain::task::{
    MAX_INTEGER, Sha256Digest, SnapshotRef, TaskError, TaskErrorCode,
    codec::{CanonicalDto, DigestFn, Value},
    relative_path,
};
use nexus_storage::{ContentStore, object_id_of, strong::StrongContentStore};

use super::{CommitId, Manifest, Workspace};

/// v1 rules match exact files or directory prefixes, without globs or implicit
/// traversal. Nonempty include is mandatory; `.` explicitly includes all files.
/// Executable paths are explicit because the legacy manifest has no mode bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSelection {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub executable: Vec<String>,
}
impl SnapshotSelection {
    fn validate(&self) -> Result<(), TaskError> {
        if self.include.is_empty() {
            return Err(TaskError::invalid(
                "snapshot needs an explicit include selection",
            ));
        }
        for rules in [&self.include, &self.exclude, &self.executable] {
            let mut seen = BTreeSet::new();
            for path in rules {
                if path != "." {
                    relative_path(path)?;
                }
                if !seen.insert(path) {
                    return Err(TaskError::invalid("duplicate selection rule"));
                }
            }
        }
        if self.executable.iter().any(|p| p == ".") {
            return Err(TaskError::invalid("executable selection must name files"));
        }
        Ok(())
    }
    /// Digest covers rule version, matching semantics and executable selection.
    pub fn digest(&self, hash: DigestFn) -> Result<Sha256Digest, TaskError> {
        self.validate()?;
        let sorted = |rules: &[String]| {
            let mut paths = rules.to_vec();
            paths.sort();
            paths.to_value()
        };
        Ok(hash(
            &Value::Object(BTreeMap::from([
                ("schema_version".into(), Value::Integer(1)),
                (
                    "matching".into(),
                    "exact-or-directory-prefix".to_string().to_value(),
                ),
                ("include".into(), sorted(&self.include)),
                ("exclude".into(), sorted(&self.exclude)),
                ("executable".into(), sorted(&self.executable)),
            ]))
            .canonical_bytes(),
        ))
    }
    fn selected(&self, path: &str) -> bool {
        let matches = |rule: &String| {
            rule == "."
                || path == rule
                || path
                    .strip_prefix(rule)
                    .is_some_and(|rest| rest.starts_with('/'))
        };
        self.include.iter().any(matches) && !self.exclude.iter().any(matches)
    }
}

/// Exactly the frozen manifest_v1 entry; no symlink/device entry is representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFile {
    pub path: String,
    pub sha256: Sha256Digest,
    pub size_bytes: u64,
    pub executable: bool,
}
impl CanonicalDto for SnapshotFile {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("path".into(), self.path.to_value()),
            ("sha256".into(), self.sha256.to_value()),
            ("size_bytes".into(), self.size_bytes.to_value()),
            ("executable".into(), self.executable.to_value()),
        ]))
    }
    fn from_value(value: Value) -> Result<Self, TaskError> {
        let Value::Object(mut fields) = value else {
            return Err(TaskError::invalid("manifest entry must be an object"));
        };
        let mut take = |key: &str| {
            fields
                .remove(key)
                .ok_or_else(|| TaskError::invalid(format!("missing manifest {key}")))
        };
        let file = Self {
            path: String::from_value(take("path")?)?,
            sha256: Sha256Digest::from_value(take("sha256")?)?,
            size_bytes: u64::from_value(take("size_bytes")?)?,
            executable: bool::from_value(take("executable")?)?,
        };
        if !fields.is_empty() {
            return Err(TaskError::invalid("unknown manifest field"));
        }
        Ok(file)
    }
}

/// A frozen preview. Its files and byte count are identical to runtime inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenSnapshot {
    pub reference: SnapshotRef,
    pub files: Vec<SnapshotFile>,
}
impl FrozenSnapshot {
    /// Verify identity, sorted/unique paths, file/directory collisions and totals.
    /// Linux v1 uses exact UTF-8 names (case-sensitive, no Unicode normalization).
    pub fn validate(&self, hash: DigestFn) -> Result<(), TaskError> {
        self.reference.verify_digest(hash)?;
        let mut names = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        let mut previous: Option<&str> = None;
        let mut total = 0u64;
        for file in &self.files {
            relative_path(&file.path)?;
            if previous.is_some_and(|p| p >= file.path.as_str()) || file.size_bytes > MAX_INTEGER {
                return Err(TaskError::invalid(
                    "manifest must be sorted, unique and exact-integer sized",
                ));
            }
            previous = Some(&file.path);
            names.insert(file.path.as_str());
            for (i, _) in file.path.match_indices('/') {
                dirs.insert(&file.path[..i]);
            }
            total = total
                .checked_add(file.size_bytes)
                .filter(|v| *v <= MAX_INTEGER)
                .ok_or_else(|| TaskError::invalid("snapshot byte count exceeds exact range"))?;
        }
        if names.iter().any(|p| dirs.contains(p)) {
            return Err(TaskError::new(
                TaskErrorCode::InvalidPath,
                "file/directory name collision",
                false,
            ));
        }
        if self.files.len() as u64 != self.reference.file_count
            || total != self.reference.total_bytes
            || hash(&self.files.to_value().canonical_bytes()) != self.reference.manifest_sha256
        {
            return Err(TaskError::new(
                TaskErrorCode::InputIntegrityFailed,
                "manifest differs from frozen snapshot",
                false,
            ));
        }
        Ok(())
    }
    /// cwd must be a directory actually formed by the selected files.
    pub fn validate_cwd(&self, cwd: &str) -> Result<(), TaskError> {
        if cwd == "." {
            return Ok(());
        }
        relative_path(cwd)?;
        if !self.files.iter().any(|f| {
            f.path
                .strip_prefix(cwd)
                .is_some_and(|rest| rest.starts_with('/'))
        }) {
            return Err(TaskError::new(
                TaskErrorCode::InvalidPath,
                "cwd is not a snapshot directory",
                false,
            ));
        }
        Ok(())
    }
    /// Recheck every target byte against the authenticated frozen description.
    /// Missing/corrupt content fails before any command can be started.
    pub fn verify_inputs(
        &self,
        store: &impl StrongContentStore,
        hash: DigestFn,
        cwd: &str,
    ) -> Result<(), TaskError> {
        self.validate(hash)?;
        self.validate_cwd(cwd)?;
        for file in &self.files {
            store.get_verified(&file.sha256, file.size_bytes)?;
        }
        Ok(())
    }
}

impl<S: ContentStore> Workspace<S> {
    /// Freeze files from one explicit immutable Commit; never read a Head or
    /// WorkingSet. Only logical regular file entries exist in this legacy CAS.
    /// The caller must serialize staging/retention with N3 GC and durably retain
    /// the returned snapshot before exposing it for submission.
    pub fn freeze_snapshot(
        &self,
        commit_id: &CommitId,
        selection: &SnapshotSelection,
        target: &mut impl StrongContentStore,
        hash: DigestFn,
    ) -> Result<FrozenSnapshot, TaskError> {
        selection.validate()?;
        let unavailable =
            |message: String| TaskError::new(TaskErrorCode::InputUnavailable, message, true);
        let commit = self
            .commit(commit_id)
            .ok_or_else(|| unavailable("selected Commit is unavailable".into()))?;
        let manifest_bytes = self
            .store
            .get(&commit.root_manifest_id)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("selected manifest is unavailable".into()))?;
        if object_id_of(&manifest_bytes) != commit.root_manifest_id {
            return Err(TaskError::new(
                TaskErrorCode::InputIntegrityFailed,
                "legacy manifest locator mismatch",
                false,
            ));
        }
        let manifest =
            Manifest::from_bytes(&commit.root_manifest_id, &manifest_bytes).map_err(|e| {
                TaskError::new(TaskErrorCode::InputIntegrityFailed, e.to_string(), false)
            })?;
        let mut files = Vec::new();
        let mut contents = Vec::new();
        for (path, id) in &manifest.entries {
            if !selection.selected(path) {
                continue;
            }
            relative_path(path)?;
            let bytes = self
                .store
                .get(id)
                .map_err(unavailable)?
                .ok_or_else(|| unavailable(format!("selected input {path} is unavailable")))?;
            if object_id_of(&bytes) != *id {
                return Err(TaskError::new(
                    TaskErrorCode::InputIntegrityFailed,
                    "legacy content locator mismatch",
                    false,
                ));
            }
            files.push(SnapshotFile {
                path: path.clone(),
                sha256: hash(&bytes),
                size_bytes: bytes.len() as u64,
                executable: selection.executable.contains(path),
            });
            contents.push(bytes);
        }
        // Mistyped includes/executable paths must not silently omit intended data.
        for rule in &selection.include {
            if !manifest.entries.iter().any(|(p, _)| {
                rule == "." || p == rule || p.strip_prefix(rule).is_some_and(|r| r.starts_with('/'))
            }) {
                return Err(unavailable(format!(
                    "include rule {rule} matches no committed file"
                )));
            }
        }
        if selection
            .executable
            .iter()
            .any(|p| !files.iter().any(|f| &f.path == p))
        {
            return Err(TaskError::invalid(
                "executable path is outside selected files",
            ));
        }
        let total_bytes = files
            .iter()
            .try_fold(0u64, |sum, f| sum.checked_add(f.size_bytes))
            .ok_or_else(|| TaskError::invalid("snapshot byte count overflow"))?;
        let manifest_bytes = files.to_value().canonical_bytes();
        let mut reference = SnapshotRef {
            schema_version: 1,
            snapshot_id: Sha256Digest::from_bytes([0; 32]),
            workspace: self.id.0.clone(),
            commit_id: commit_id.0.clone(),
            root_manifest_id: commit.root_manifest_id.0.clone(),
            manifest_sha256: hash(&manifest_bytes),
            selection_digest: selection.digest(hash)?,
            file_count: files.len() as u64,
            total_bytes,
        };
        let Value::Object(mut fields) = reference.to_value() else {
            unreachable!()
        };
        fields.remove("snapshot_id");
        reference.snapshot_id = hash(&Value::Object(fields).canonical_bytes());
        let snapshot = FrozenSnapshot { reference, files };
        snapshot.validate(hash)?;
        for (file, bytes) in snapshot.files.iter().zip(contents) {
            target.put_verified(&file.sha256, &bytes)?;
        }
        target.put_verified(&snapshot.reference.manifest_sha256, &manifest_bytes)?;
        Ok(snapshot)
    }
}
