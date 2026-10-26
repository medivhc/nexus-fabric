//! Black-box E3 tests: expectations come from N3-12 §§2–5,7–9.
//! Fixtures provision the original real N3-11 authority and persisted grants.
use super::*;
use crate::task_capacity::{CapacityBudget, ExecutorBackendOverhead, ProviderCapacityPolicy};
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_control_api::snapshot::{UploadId, UploadState};
use nexus_domain::task::{
    MAX_INTEGER, SnapshotRef,
    codec::{CanonicalDto, Value},
};
use nexus_workspace::snapshot::{FrozenSnapshot, SnapshotFile, SnapshotSelection};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
};

const GLOBAL: u64 = 16_777_216;
const WORKSPACE: &str = "n312-source";
const PROVIDER: &str = "provider/a";
const RESOURCE: &str = "compute-local";
const OTHER: &str = "ed25519:00000000000000000000000000000000";

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    budget: PathBuf,
    principal: String,
}
impl Fixture {
    fn new(max_bytes: u64, max_active: u64) -> Self {
        let base =
            std::env::temp_dir().join(format!("n312-stage-{}", new_task_id().unwrap().as_str()));
        private_dir(&base);
        let root = base.join("provider");
        private_dir(&root);
        let execution = base.join("execution.json");
        let cap = ProviderCapacityPolicy {
            total: CapacityBudget {
                cpu_millis: 10000,
                memory_bytes: 1 << 30,
                pids: 1024,
                runtime_storage_bytes: 1 << 28,
                backend_disk_bytes: 1 << 30,
                slots: 8,
            },
            fixed: CapacityBudget {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
                runtime_storage_bytes: 1,
                backend_disk_bytes: 1,
                slots: 1,
            },
            overhead: ExecutorBackendOverhead {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
                backend_disk_bytes: 1,
            },
        };
        private_file(&execution, &cap.to_value().canonical_bytes());
        let original = crate::task_provider_init::init(&root, PROVIDER, WORKSPACE, &execution)
            .expect("real N3-11 fixture provision");
        let budget = base.join("budget.json");
        private_file(&budget, format!("{{\"max_active_uploads\":{max_active},\"max_reserved_bytes\":{max_bytes},\"schema_version\":1}}").as_bytes());
        let f = Self {
            base,
            root,
            budget,
            principal: original.principal,
        };
        f.grant("add", &f.principal, None);
        f
    }
    fn standard() -> Self {
        Self::new(256 << 20, 8)
    }
    fn grant(&self, operation: &str, principal: &str, expiry: Option<u64>) {
        self.grant_resource(operation, principal, RESOURCE, expiry);
    }
    fn grant_resource(
        &self,
        operation: &str,
        principal: &str,
        resource: &str,
        expiry: Option<u64>,
    ) {
        let mut args = vec![
            "grant".into(),
            operation.into(),
            "--config".into(),
            self.root.display().to_string(),
            "--resource".into(),
            resource.into(),
            "--principal".into(),
            principal.into(),
        ];
        if let Some(expiry) = expiry {
            args.extend(["--not-after".into(), expiry.to_string()]);
        }
        assert_eq!(
            nexus::task_provider_grant::run(&args, true),
            0,
            "existing persisted grant entry"
        );
        if operation == "add" && expiry.is_none() {
            nexus::task_authorization::authorize_use(&self.root, principal, WORKSPACE, resource)
                .expect("grant setup really allows Use");
        }
    }
    fn initialize(&self) -> StagingStatus {
        initialize(&self.root, &self.budget).expect("N3-12 staging initialization contract")
    }
    fn open(&self) -> FileSnapshotStaging {
        FileSnapshotStaging::open(&self.root)
            .expect("cold open valid staging")
            .expect("explicit provision enabled")
    }
    fn service(&self) -> FileSnapshotStaging {
        self.initialize();
        self.open()
    }
    fn context(&self) -> TaskCallContext {
        self.context_for(&self.principal)
    }
    fn context_for(&self, principal: &str) -> TaskCallContext {
        TaskCallContext::from_authenticated(principal.into(), WORKSPACE.into()).unwrap()
    }
    fn namespace(&self) -> PathBuf {
        self.root.join("data/n3/snapshot-staging-v1")
    }
    fn tasks(&self) -> PathBuf {
        self.root.join("data/n3/tasks")
    }
    fn payload(&self, id: &UploadId, digest: &nexus_domain::task::Sha256Digest) -> PathBuf {
        self.namespace()
            .join("uploads")
            .join(id.as_str())
            .join("blobs")
            .join(digest.as_str().trim_start_matches("sha256:"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn private_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    relative: PathBuf,
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    bytes: Option<Vec<u8>>,
}
fn inventory(root: &Path) -> Vec<Entry> {
    fn scan(root: &Path, path: &Path, out: &mut Vec<Entry>) {
        let m = fs::symlink_metadata(path).unwrap();
        out.push(Entry {
            relative: path.strip_prefix(root).unwrap().into(),
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            nlink: m.nlink(),
            bytes: m.is_file().then(|| fs::read(path).unwrap()),
        });
        if m.is_dir() {
            let mut children = fs::read_dir(path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect::<Vec<_>>();
            children.sort();
            for p in children {
                scan(root, &p, out);
            }
        }
    }
    let mut out = vec![];
    if root.exists() {
        scan(root, root, &mut out);
    }
    out
}

struct Input {
    snapshot: SnapshotRef,
    manifest: String,
    files: Vec<SnapshotFile>,
    payloads: BTreeMap<nexus_domain::task::Sha256Digest, Vec<u8>>,
}
impl Input {
    fn new(entries: &[(&str, &[u8])]) -> Self {
        let mut files = entries
            .iter()
            .map(|(path, bytes)| SnapshotFile {
                path: (*path).into(),
                sha256: sha256(bytes),
                size_bytes: bytes.len() as u64,
                executable: false,
            })
            .collect::<Vec<_>>();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let manifest = String::from_utf8(files.to_value().canonical_bytes()).unwrap();
        let mut snapshot = SnapshotRef {
            schema_version: 1,
            snapshot_id: sha256(b"placeholder"),
            workspace: WORKSPACE.into(),
            commit_id: "b06b020a76caf915".into(),
            root_manifest_id: "6a9e12a170547cc6".into(),
            manifest_sha256: sha256(manifest.as_bytes()),
            selection_digest: SnapshotSelection {
                include: vec![".".into()],
                exclude: vec![],
                executable: vec![],
            }
            .digest(sha256)
            .unwrap(),
            file_count: files.len() as u64,
            total_bytes: files.iter().map(|f| f.size_bytes).sum(),
        };
        let Value::Object(mut fields) = snapshot.to_value() else {
            unreachable!()
        };
        fields.remove("snapshot_id");
        snapshot.snapshot_id = sha256(&Value::Object(fields).canonical_bytes());
        FrozenSnapshot {
            reference: snapshot.clone(),
            files: files.clone(),
        }
        .validate(sha256)
        .unwrap();
        let payloads = entries
            .iter()
            .map(|(_, bytes)| (sha256(bytes), bytes.to_vec()))
            .collect();
        Self {
            snapshot,
            manifest,
            files,
            payloads,
        }
    }
    fn small() -> Self {
        Self::new(&[("input.txt", b"abcdef")])
    }
    fn empty() -> Self {
        Self::new(&[])
    }
    fn fixture_blob() -> Self {
        Self::new(&[(
            "inputs/data.bin",
            include_bytes!(
                "../../../scenarios/fixtures/n3-12-requester/config/data/cas/59b545e938ad7f6b"
            ),
        )])
    }
    fn begin(&self, key: &str) -> SnapshotRequest {
        SnapshotRequest::Begin {
            provider: PROVIDER.into(),
            workspace: WORKSPACE.into(),
            resource: RESOURCE.into(),
            upload_key: key.into(),
            snapshot: Box::new(self.snapshot.clone()),
            manifest_json: self.manifest.clone(),
        }
    }
    fn redeclare(&mut self) {
        self.manifest = String::from_utf8(self.files.to_value().canonical_bytes()).unwrap();
        self.snapshot.file_count = self.files.len() as u64;
        self.snapshot.total_bytes = self.files.iter().map(|f| f.size_bytes).sum();
        self.snapshot.manifest_sha256 = sha256(self.manifest.as_bytes());
        let Value::Object(mut fields) = self.snapshot.to_value() else {
            unreachable!()
        };
        fields.remove("snapshot_id");
        self.snapshot.snapshot_id = sha256(&Value::Object(fields).canonical_bytes());
    }
    fn charge(&self) -> u64 {
        // Independent equation from contract §4; only declared unique blobs count.
        let a = |x: u64| x.div_ceil(4096) * 4096;
        let unique = self
            .files
            .iter()
            .map(|f| (f.sha256.clone(), f.size_bytes))
            .collect::<BTreeMap<_, _>>();
        2 * unique.values().map(|b| a(*b)).sum::<u64>()
            + 2 * a(self.manifest.len() as u64)
            + 2 * 524_288
            + 65_536
            + 4096 * (unique.len() as u64 + 6)
    }
    fn chunk(&self, id: &UploadId, offset: u64, bytes: &[u8]) -> SnapshotRequest {
        SnapshotRequest::PutChunk {
            upload_id: id.clone(),
            blob_sha256: self.files[0].sha256.clone(),
            offset,
            bytes: bytes.to_vec(),
            chunk_sha256: sha256(bytes),
        }
    }
    fn upload_all(&self, s: &FileSnapshotStaging, c: &TaskCallContext, id: &UploadId) {
        for (digest, bytes) in &self.payloads {
            for (i, chunk) in bytes.chunks(65_536).enumerate() {
                s.execute(
                    c,
                    SnapshotRequest::PutChunk {
                        upload_id: id.clone(),
                        blob_sha256: digest.clone(),
                        offset: (i * 65_536) as u64,
                        bytes: chunk.to_vec(),
                        chunk_sha256: sha256(chunk),
                    },
                )
                .unwrap();
            }
        }
    }
}
fn get(s: &FileSnapshotStaging, c: &TaskCallContext, id: &UploadId) -> UploadView {
    s.execute(
        c,
        SnapshotRequest::Get {
            upload_id: id.clone(),
        },
    )
    .unwrap()
}
fn assert_code<T: std::fmt::Debug>(result: Result<T, TaskError>, code: TaskErrorCode) {
    assert_eq!(result.unwrap_err().code, code);
}

#[path = "snapshot_staging_tests/authority.rs"]
mod authority;
#[path = "snapshot_staging_tests/baseline.rs"]
mod baseline;
#[path = "snapshot_staging_tests/core.rs"]
mod core;
#[path = "snapshot_staging_tests/pressure.rs"]
mod pressure;
#[path = "snapshot_staging_tests/recovery.rs"]
mod recovery;
