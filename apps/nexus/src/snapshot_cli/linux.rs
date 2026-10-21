//! Read-only legacy Workspace input and immutable private bundle IO.
use super::{failure, request};
use crate::n3_acceptance::{parse_canonical_json, sha256, sha256_reader};
use nexus_control_api::snapshot::{
    CanonicalDto, MAX_CHUNK_BYTES, MAX_MANIFEST_BYTES, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_FILES,
    SnapshotEnvelope, SnapshotRequest, TaskError, TaskErrorCode, UploadState, UploadView, Value,
};
use nexus_domain::task::{Sha256Digest, SnapshotRef};
use nexus_storage::{ContentStore, ObjectId, object_id_of, strong::StrongContentStore};
use nexus_workspace::{
    AuthorId, CommitId, Workspace, WorkspaceId,
    snapshot::{FrozenSnapshot, SnapshotFile, SnapshotLimits, SnapshotSelection},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const SAFE_OPEN: i32 = 0x20000 | 0x800; // Linux O_NOFOLLOW | O_NONBLOCK.
fn error(code: TaskErrorCode, reason: impl Into<String>) -> TaskError {
    TaskError::new(code, reason, false)
}
fn integrity(reason: impl Into<String>) -> TaskError {
    error(TaskErrorCode::InputIntegrityFailed, reason)
}
fn capacity(reason: &str) -> TaskError {
    error(TaskErrorCode::CapacityUnavailable, reason)
}
fn persistence(e: impl std::fmt::Display) -> TaskError {
    TaskError::new(TaskErrorCode::PersistenceFailed, e.to_string(), true)
}
fn unavailable(e: impl std::fmt::Display) -> TaskError {
    TaskError::new(TaskErrorCode::InputUnavailable, e.to_string(), true)
}
fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn signature(metadata: &Metadata) -> (u64, u64, u32, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}
fn ancestors(path: &Path) -> Result<(), TaskError> {
    for parent in path.ancestors() {
        let m = fs::symlink_metadata(parent).map_err(unavailable)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(integrity("input ancestor must be a real directory"));
        }
    }
    Ok(())
}
struct Directory {
    path: PathBuf,
    file: File,
    private: bool,
}
impl Directory {
    fn open(path: &Path, private: bool) -> Result<Self, TaskError> {
        ancestors(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(SAFE_OPEN | 0x10000)
            .open(path)
            .map_err(unavailable)?;
        let this = Self {
            path: path.into(),
            file,
            private,
        };
        this.check()?;
        Ok(this)
    }
    fn check(&self) -> Result<(), TaskError> {
        ancestors(&self.path)?;
        let fd = self.file.metadata().map_err(unavailable)?;
        let named = fs::symlink_metadata(&self.path).map_err(unavailable)?;
        if !fd.is_dir()
            || named.file_type().is_symlink()
            || identity(&fd) != identity(&named)
            || fd.mode() & if self.private { 0o077 } else { 0o022 } != 0
        {
            return Err(integrity("directory binding or permissions changed"));
        }
        Ok(())
    }
    fn sync(&self) -> Result<(), TaskError> {
        self.check()?;
        self.file.sync_all().map_err(persistence)
    }
}
struct Input {
    path: PathBuf,
    file: File,
    metadata: Metadata,
    private: bool,
}
impl Input {
    fn open(path: &Path, private: bool, limit: u64) -> Result<Self, TaskError> {
        ancestors(
            path.parent()
                .ok_or_else(|| integrity("missing file parent"))?,
        )?;
        let named = fs::symlink_metadata(path).map_err(unavailable)?;
        if !named.is_file() || named.file_type().is_symlink() {
            return Err(integrity("input must be a regular file"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(SAFE_OPEN)
            .open(path)
            .map_err(unavailable)?;
        let metadata = file.metadata().map_err(unavailable)?;
        let this = Self {
            path: path.into(),
            file,
            metadata,
            private,
        };
        this.check()?;
        if this.metadata.len() > limit {
            return Err(capacity("input exceeds bounded adapter size"));
        }
        Ok(this)
    }
    fn check(&self) -> Result<(), TaskError> {
        let fd = self.file.metadata().map_err(unavailable)?;
        let named = fs::symlink_metadata(&self.path).map_err(unavailable)?;
        if !fd.is_file()
            || fd.nlink() != 1
            || named.file_type().is_symlink()
            || signature(&fd) != signature(&self.metadata)
            || signature(&named) != signature(&fd)
            || fd.mode() & if self.private { 0o077 } else { 0o022 } != 0
        {
            return Err(integrity(
                "input inode, bytes metadata, type or permissions changed",
            ));
        }
        Ok(())
    }
    fn bytes(&mut self, limit: u64) -> Result<Vec<u8>, TaskError> {
        self.check()?;
        self.file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() as u64 > limit {
            return Err(capacity("input grew beyond adapter bound"));
        }
        self.check()?;
        if bytes.len() as u64 != self.metadata.len() {
            return Err(integrity("input length changed"));
        }
        Ok(bytes)
    }
    fn hash(&mut self) -> Result<Sha256Digest, TaskError> {
        self.check()?;
        self.file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
        let digest = sha256_reader(Read::by_ref(&mut self.file).take(self.metadata.len()))
            .map_err(unavailable)?;
        self.check()?;
        Ok(digest)
    }
}

struct Source {
    cas: Directory,
    metadata_ids: RefCell<BTreeSet<ObjectId>>,
    first_error: std::rc::Rc<RefCell<Option<TaskError>>>,
}
impl Source {
    fn take_error(&self, fallback: TaskError) -> TaskError {
        self.first_error.borrow_mut().take().unwrap_or(fallback)
    }
    fn load(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, TaskError> {
        self.cas.check()?;
        if id.0.len() != 16
            || !id
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(integrity("invalid legacy content locator"));
        }
        let path = self.cas.path.join(&id.0);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(unavailable(e)),
            _ => {}
        }
        let limit = if self.metadata_ids.borrow().contains(id) {
            8 * 1024 * 1024
        } else {
            MAX_SNAPSHOT_BYTES
        };
        let mut input = Input::open(&path, false, limit)?;
        let digest = input.hash()?;
        let bytes = input.bytes(limit)?;
        if object_id_of(&bytes) != *id || sha256(&bytes) != digest {
            return Err(integrity("legacy CAS locator or content changed"));
        }
        self.cas.check()?;
        Ok(Some(bytes))
    }
}
impl ContentStore for Source {
    fn contains(&self, id: &ObjectId) -> Result<bool, String> {
        self.get(id).map(|v| v.is_some())
    }
    fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, String> {
        self.load(id).map_err(|e| {
            let message = e.to_string();
            let mut slot = self.first_error.borrow_mut();
            if slot.is_none() {
                *slot = Some(e);
            }
            message
        })
    }
    fn put(&mut self, _: &[u8]) -> Result<ObjectId, String> {
        Err("snapshot source is read-only".into())
    }
    fn object_ids(&self) -> Result<Vec<ObjectId>, String> {
        Err("snapshot source cannot enumerate unanchored CAS".into())
    }
}

struct Temporary {
    path: PathBuf,
    root: Directory,
    blobs: Directory,
    owned: Vec<(PathBuf, (u64, u64))>,
    published: bool,
}
impl Temporary {
    fn new(parent: &Directory) -> Result<Self, TaskError> {
        use std::os::unix::fs::DirBuilderExt;
        parent.check()?;
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).map_err(persistence)?;
        let name = sha256(&random);
        let path = parent
            .path
            .join(format!(".nexus-snapshot-{}", &name.as_str()[7..]));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(persistence)?;
        let root = Directory::open(&path, true)?;
        let blobs_path = path.join("blobs");
        if let Err(e) = fs::DirBuilder::new().mode(0o700).create(&blobs_path) {
            let _ = fs::remove_dir(&path);
            return Err(persistence(e));
        }
        let blobs = Directory::open(&blobs_path, true)?;
        Ok(Self {
            path,
            root,
            blobs,
            owned: Vec::new(),
            published: false,
        })
    }
    fn write(&mut self, path: PathBuf, bytes: &[u8]) -> Result<(), TaskError> {
        self.root.check()?;
        self.blobs.check()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(SAFE_OPEN)
            .open(&path)
            .map_err(persistence)?;
        self.owned
            .push((path, identity(&file.metadata().map_err(persistence)?)));
        file.write_all(bytes).map_err(persistence)?;
        file.sync_all().map_err(persistence)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if self.published || self.root.check().is_err() {
            return;
        }
        for (path, id) in &self.owned {
            if fs::symlink_metadata(path)
                .is_ok_and(|m| identity(&m) == *id && m.is_file() && m.nlink() == 1)
            {
                let _ = fs::remove_file(path);
            }
        }
        if self.blobs.check().is_ok() {
            let _ = fs::remove_dir(&self.blobs.path);
        }
        let _ = fs::remove_dir(&self.path);
    }
}
impl StrongContentStore for Temporary {
    fn get_verified(&self, digest: &Sha256Digest, size: u64) -> Result<Vec<u8>, TaskError> {
        let mut input = Input::open(
            &self.blobs.path.join(&digest.as_str()[7..]),
            true,
            MAX_SNAPSHOT_BYTES,
        )?;
        let bytes = input.bytes(MAX_SNAPSHOT_BYTES)?;
        nexus_storage::strong::verify_content(digest, size, &bytes, sha256)?;
        Ok(bytes)
    }
    fn put_verified(&mut self, digest: &Sha256Digest, bytes: &[u8]) -> Result<(), TaskError> {
        nexus_storage::strong::verify_content(digest, bytes.len() as u64, bytes, sha256)?;
        let path = self.blobs.path.join(&digest.as_str()[7..]);
        if fs::symlink_metadata(&path).is_ok() {
            self.get_verified(digest, bytes.len() as u64)?;
            return Ok(());
        }
        self.write(path, bytes)
    }
}

pub(super) fn freeze(
    workspace: &str,
    config: &Path,
    commit: &str,
    selection: &SnapshotSelection,
    output: &Path,
) -> Result<(SnapshotRef, PathBuf), TaskError> {
    match fs::symlink_metadata(output) {
        Ok(_) => {
            return Err(error(
                TaskErrorCode::OutputExists,
                "snapshot output already exists",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(persistence(e)),
    }
    if output.starts_with(config) {
        return Err(error(
            TaskErrorCode::InvalidPath,
            "bundle output cannot mutate its read-only source config",
        ));
    }
    let config_root = Directory::open(config, true)?;
    let mut input = Input::open(&config.join("workspace.toml"), false, 65_536)?;
    let bytes = input.bytes(65_536)?;
    let value: toml::Value = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| integrity("workspace config is not UTF-8"))?,
    )
    .map_err(|e| integrity(e.to_string()))?;
    let entries = value
        .get("workspace")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| integrity("missing regular [[workspace]] config"))?;
    let mut ids = BTreeSet::new();
    let mut author = None;
    for entry in entries {
        let id = entry
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| integrity("missing Workspace ID"))?;
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !ids.insert(id)
        {
            return Err(integrity("invalid or duplicate configured Workspace"));
        }
        if id == workspace {
            author = Some(
                entry
                    .get("author")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(id)
                    .to_owned(),
            );
        }
    }
    let author = author
        .filter(|s| !s.is_empty())
        .ok_or_else(|| unavailable("Workspace is not configured"))?;
    let workspace_dir = Directory::open(&config.join("data/workspaces").join(workspace), false)?;
    let mut anchor = Input::open(&workspace_dir.path.join("state_root"), false, 256)?;
    let anchor_bytes = anchor.bytes(256)?;
    let root = ObjectId(
        std::str::from_utf8(&anchor_bytes)
            .map_err(|_| integrity("anchor is not UTF-8"))?
            .trim()
            .to_owned(),
    );
    let source_error = std::rc::Rc::new(RefCell::new(None));
    let source = Source {
        cas: Directory::open(&config.join("data/cas"), false)?,
        metadata_ids: RefCell::new(BTreeSet::from([root.clone()])),
        first_error: source_error.clone(),
    };
    let ws = Workspace::open(
        WorkspaceId(workspace.into()),
        source,
        &root,
        AuthorId(author),
    );
    // Preserve the adapter error across the consuming, String-based open API.
    let ws = ws.map_err(|e| {
        source_error.borrow_mut().take().unwrap_or_else(|| match e {
            nexus_workspace::WorkspaceError::MissingObject { .. } => unavailable(e),
            _ => integrity(e.to_string()),
        })
    })?;
    let selected = ws
        .commit(&CommitId(commit.into()))
        .ok_or_else(|| unavailable("selected Commit is unavailable"))?;
    ws.store()
        .metadata_ids
        .borrow_mut()
        .insert(selected.root_manifest_id.clone());
    let parent = Directory::open(
        output
            .parent()
            .ok_or_else(|| integrity("output parent missing"))?,
        false,
    )?;
    let mut target = Temporary::new(&parent)?;
    let frozen = ws
        .freeze_snapshot_bounded(
            &CommitId(commit.into()),
            selection,
            &mut target,
            sha256,
            SnapshotLimits {
                max_files: MAX_SNAPSHOT_FILES,
                max_total_bytes: MAX_SNAPSHOT_BYTES,
                max_manifest_bytes: MAX_MANIFEST_BYTES,
            },
        )
        .map_err(|e| ws.store().take_error(e))?;
    config_root.check()?;
    workspace_dir.check()?;
    let manifest = frozen.files.to_value().canonical_bytes();
    let manifest_blob = target
        .blobs
        .path
        .join(&frozen.reference.manifest_sha256.as_str()[7..]);
    if !frozen
        .files
        .iter()
        .any(|f| f.sha256 == frozen.reference.manifest_sha256)
    {
        fs::remove_file(manifest_blob).map_err(persistence)?;
    }
    target.write(target.path.join("manifest-v1.json"), &manifest)?;
    let metadata = Value::Object(BTreeMap::from([
        ("schema_version".into(), 1u64.to_value()),
        ("snapshot".into(), frozen.reference.to_value()),
    ]));
    target.write(
        target.path.join("bundle-v1.json"),
        &metadata.canonical_bytes(),
    )?;
    Bundle::open(&target.path)?;
    target.blobs.sync()?;
    target.root.sync()?;
    parent.check()?;
    nexus_platform_linux::directory_publish::publish_directory_no_replace(&target.path, output)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => error(
                TaskErrorCode::OutputExists,
                "snapshot output already exists",
            ),
            std::io::ErrorKind::Unsupported => error(
                TaskErrorCode::UnsupportedCapability,
                "atomic no-replace publication unavailable",
            ),
            _ => persistence(e),
        })?;
    target.published = true;
    parent.sync()?;
    Ok((frozen.reference, output.into()))
}

struct Blob {
    path: PathBuf,
    signature: Metadata,
    size: u64,
}
pub(super) struct Bundle {
    root: Directory,
    blobs_dir: Directory,
    metadata: Input,
    manifest: Input,
    snapshot: FrozenSnapshot,
    manifest_json: String,
    blobs: BTreeMap<Sha256Digest, Blob>,
}
impl Bundle {
    pub(super) fn open(path: &Path) -> Result<Self, TaskError> {
        Self::load(path).map_err(|e| integrity(format!("invalid immutable bundle: {}", e.reason)))
    }
    fn load(path: &Path) -> Result<Self, TaskError> {
        let root = Directory::open(path, true)?;
        exact_names(
            path,
            &BTreeSet::from([
                "bundle-v1.json".into(),
                "manifest-v1.json".into(),
                "blobs".into(),
            ]),
        )?;
        let blobs_dir = Directory::open(&path.join("blobs"), true)?;
        let mut metadata = Input::open(&path.join("bundle-v1.json"), true, 1024 * 1024)?;
        let bytes = metadata.bytes(1024 * 1024)?;
        let value = parse_canonical_json(&bytes)?;
        if value.canonical_bytes() != bytes {
            return Err(integrity("metadata is not canonical"));
        }
        let Value::Object(mut fields) = value else {
            return Err(integrity("metadata must be object"));
        };
        if fields.len() != 2 || fields.remove("schema_version") != Some(1u64.to_value()) {
            return Err(integrity("metadata fields or schema differ"));
        }
        let reference = SnapshotRef::from_value(
            fields
                .remove("snapshot")
                .ok_or_else(|| integrity("missing SnapshotRef"))?,
        )?;
        let mut manifest = Input::open(
            &path.join("manifest-v1.json"),
            true,
            MAX_MANIFEST_BYTES as u64,
        )?;
        let bytes = manifest.bytes(MAX_MANIFEST_BYTES as u64)?;
        let files = Vec::<SnapshotFile>::from_value(parse_canonical_json(&bytes)?)?;
        if files.to_value().canonical_bytes() != bytes {
            return Err(integrity("manifest is not canonical"));
        }
        let snapshot = FrozenSnapshot { reference, files };
        snapshot.validate(sha256)?;
        if snapshot.files.len() as u64 > MAX_SNAPSHOT_FILES
            || snapshot.reference.total_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(capacity("bundle exceeds v1 limits"));
        }
        let mut blobs = BTreeMap::new();
        for entry in &snapshot.files {
            if let Some(blob) = blobs.get(&entry.sha256) {
                let blob: &Blob = blob;
                if blob.size != entry.size_bytes {
                    return Err(integrity("duplicate digest has inconsistent size"));
                }
                continue;
            }
            let path = blobs_dir.path.join(&entry.sha256.as_str()[7..]);
            let mut input = Input::open(&path, true, MAX_SNAPSHOT_BYTES)?;
            if input.metadata.len() != entry.size_bytes || input.hash()? != entry.sha256 {
                return Err(integrity("blob size or SHA-256 differs"));
            }
            blobs.insert(
                entry.sha256.clone(),
                Blob {
                    path,
                    signature: input.metadata,
                    size: entry.size_bytes,
                },
            );
        }
        exact_names(
            &blobs_dir.path,
            &blobs.keys().map(|d| d.as_str()[7..].to_owned()).collect(),
        )?;
        Ok(Self {
            root,
            blobs_dir,
            metadata,
            manifest,
            snapshot,
            manifest_json: String::from_utf8(bytes)
                .map_err(|_| integrity("manifest is not UTF-8"))?,
            blobs,
        })
    }
    fn check(&self) -> Result<(), TaskError> {
        self.root.check()?;
        self.blobs_dir.check()?;
        self.metadata.check()?;
        self.manifest.check()?;
        exact_names(
            &self.root.path,
            &BTreeSet::from([
                "bundle-v1.json".into(),
                "manifest-v1.json".into(),
                "blobs".into(),
            ]),
        )?;
        exact_names(
            &self.blobs_dir.path,
            &self
                .blobs
                .keys()
                .map(|d| d.as_str()[7..].to_owned())
                .collect(),
        )
    }
    fn chunk(&self, digest: &Sha256Digest, offset: u64) -> Result<Vec<u8>, TaskError> {
        self.check()?;
        let blob = self
            .blobs
            .get(digest)
            .ok_or_else(|| integrity("unknown requested blob"))?;
        let mut input = Input::open(&blob.path, true, MAX_SNAPSHOT_BYTES)?;
        if signature(&input.metadata) != signature(&blob.signature) || offset >= blob.size {
            return Err(integrity("original blob changed or invalid offset"));
        }
        input
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(unavailable)?;
        let mut bytes = vec![0; (blob.size - offset).min(MAX_CHUNK_BYTES as u64) as usize];
        input.file.read_exact(&mut bytes).map_err(unavailable)?;
        input.check()?;
        self.check()?;
        Ok(bytes)
    }
    fn check_all_blobs(&self) -> Result<(), TaskError> {
        self.check()?;
        for (digest, blob) in &self.blobs {
            let mut input = Input::open(&blob.path, true, MAX_SNAPSHOT_BYTES)?;
            if signature(&input.metadata) != signature(&blob.signature) || input.hash()? != *digest
            {
                return Err(integrity("original bundle blob changed during upload"));
            }
        }
        self.check()
    }
}
fn exact_names(path: &Path, expected: &BTreeSet<String>) -> Result<(), TaskError> {
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(unavailable)? {
        let entry = entry.map_err(unavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| integrity("bundle filename is not UTF-8"))?;
        if !expected.contains(&name) || !found.insert(name) || found.len() > expected.len() {
            return Err(integrity("unexpected bundle entry"));
        }
    }
    if &found != expected {
        return Err(integrity("bundle entry is missing"));
    }
    Ok(())
}

fn check_upload(
    bundle: &Bundle,
    previous: &UploadView,
    current: &UploadView,
) -> Result<(), TaskError> {
    if current.provider != previous.provider
        || current.workspace != previous.workspace
        || current.resource != previous.resource
        || current.snapshot != bundle.snapshot.reference
        || current.upload_id != previous.upload_id
        || current.reserved_bytes != previous.reserved_bytes
    {
        return Err(TaskError::invalid(
            "upload response changed original binding or reservation",
        ));
    }
    if current.blobs.len() != bundle.blobs.len() {
        return Err(TaskError::invalid("upload progress blob set differs"));
    }
    for blob in &current.blobs {
        if bundle
            .blobs
            .get(&blob.sha256)
            .is_none_or(|b| b.size != blob.size_bytes)
            || previous
                .blobs
                .iter()
                .find(|b| b.sha256 == blob.sha256)
                .is_none_or(|b| b.durable_offset > blob.durable_offset)
        {
            return Err(TaskError::invalid(
                "upload progress is not the original monotonic blob set",
            ));
        }
    }
    Ok(())
}
pub(super) fn upload(
    bundle: &mut Bundle,
    target: crate::localapi_client::LocalApiTarget,
    provider: String,
    resource: String,
    key: String,
) -> SnapshotEnvelope {
    let begin = SnapshotRequest::Begin {
        provider,
        workspace: bundle.snapshot.reference.workspace.clone(),
        resource,
        upload_key: key,
        snapshot: Box::new(bundle.snapshot.reference.clone()),
        manifest_json: bundle.manifest_json.clone(),
    };
    let mut view = match request(&target, &begin) {
        SnapshotEnvelope::Upload(view) => view,
        fail => return fail,
    };
    let run = (|| {
        if matches!(view.state, UploadState::Cancelled | UploadState::Cancelling) {
            return Ok(SnapshotEnvelope::Upload(view.clone()));
        }
        check_upload(bundle, &view, &view)?;
        let original = view.clone();
        let digests: Vec<_> = bundle.blobs.keys().cloned().collect();
        for digest in digests {
            loop {
                let blob = view
                    .blobs
                    .iter()
                    .find(|b| b.sha256 == digest)
                    .ok_or_else(|| TaskError::invalid("response lost blob"))?;
                if blob.durable_offset == blob.size_bytes {
                    break;
                }
                let offset = blob.durable_offset;
                let bytes = bundle
                    .chunk(&digest, offset)
                    .map_err(|e| integrity(e.reason))?;
                let put = SnapshotRequest::PutChunk {
                    upload_id: view.upload_id.clone(),
                    blob_sha256: digest.clone(),
                    offset,
                    chunk_sha256: sha256(&bytes),
                    bytes,
                };
                let next = match request(&target, &put) {
                    SnapshotEnvelope::Upload(next) => next,
                    fail => return Ok(fail),
                };
                check_upload(bundle, &view, &next)?;
                view = next;
            }
        }
        bundle.check_all_blobs().map_err(|e| integrity(e.reason))?;
        let seal = SnapshotRequest::Seal {
            upload_id: original.upload_id.clone(),
        };
        let result = request(&target, &seal);
        if let SnapshotEnvelope::Upload(next) = &result {
            check_upload(bundle, &view, next)?;
        }
        Ok(result)
    })();
    run.and_then(|response| {
        // Every successful exit follows a network wait, including Begin's
        // Cancelling/Cancelled shortcuts. Recheck the original bundle after
        // that wait; provider state is preserved even when local input changed.
        if matches!(response, SnapshotEnvelope::Upload(_)) {
            bundle.check_all_blobs().map_err(|e| integrity(e.reason))?;
        }
        Ok(response)
    })
    .unwrap_or_else(|error| failure(error, Some(view.upload_id.clone())))
}
