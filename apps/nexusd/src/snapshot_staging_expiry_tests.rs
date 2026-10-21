//! Independent N3-12 §§3–5,7,9 TTL classification regression (E3).
//! Only the instance provider clock changes at the expiry boundary. Provider
//! authority and grants use real provisioning; input uses Workspace freeze.
use super::*;
use crate::task_capacity::{CapacityBudget, ExecutorBackendOverhead, ProviderCapacityPolicy};
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_control_api::snapshot::{UploadId, UploadState};
use nexus_domain::task::{Sha256Digest, SnapshotRef, codec::CanonicalDto};
use nexus_storage::{InMemoryContentStore, strong::StrongContentStore};
use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId, snapshot::SnapshotSelection};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
};

const WORKSPACE: &str = "expiry-regression";
const PROVIDER: &str = "provider/a";
const RESOURCE: &str = "compute-local";
const FOREIGN: &str = "ed25519:00000000000000000000000000000000";
const START: u64 = 1_000_000;
const TTL: u64 = 86_400;
const CONTENT: &[u8] = b"abcdef";

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    principal: String,
    snapshot: SnapshotRef,
    manifest: String,
}
impl Fixture {
    fn new() -> Self {
        let base =
            std::env::temp_dir().join(format!("n312-expiry-{}", new_task_id().unwrap().as_str()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let root = base.join("provider");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let execution = base.join("execution.json");
        let policy = ProviderCapacityPolicy {
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
        private_file(&execution, &policy.to_value().canonical_bytes());
        let provisioned = crate::task_provider_init::init(&root, PROVIDER, WORKSPACE, &execution)
            .expect("real managed N3-11 provision");
        let budget = base.join("budget.json");
        private_file(
            &budget,
            br#"{"max_active_uploads":8,"max_reserved_bytes":268435456,"schema_version":1}"#,
        );
        initialize(&root, &budget).unwrap();
        let mut workspace = Workspace::init(
            WorkspaceId(WORKSPACE.into()),
            InMemoryContentStore::new(),
            AuthorId("expiry-author".into()),
        )
        .unwrap();
        let parent = workspace.heads().heads[0].clone();
        let commit = workspace
            .commit_changes(
                &parent,
                &[Change {
                    path: "input.txt".into(),
                    content: CONTENT.to_vec(),
                }],
            )
            .unwrap();
        let mut target = FrozenContent::default();
        let frozen = workspace
            .freeze_snapshot(
                &commit,
                &SnapshotSelection {
                    include: vec![".".into()],
                    exclude: vec![],
                    executable: vec![],
                },
                &mut target,
                sha256,
            )
            .unwrap();
        assert_eq!(
            target
                .get_verified(&sha256(CONTENT), CONTENT.len() as u64)
                .unwrap(),
            CONTENT
        );
        let fixture = Self {
            base,
            root,
            principal: provisioned.principal,
            snapshot: frozen.reference,
            manifest: String::from_utf8(frozen.files.to_value().canonical_bytes()).unwrap(),
        };
        fixture.grant("add", &fixture.principal);
        fixture
    }
    fn grant(&self, operation: &str, principal: &str) {
        let args = [
            "grant",
            operation,
            "--config",
            self.root.to_str().unwrap(),
            "--resource",
            RESOURCE,
            "--principal",
            principal,
        ]
        .map(str::to_owned);
        assert_eq!(nexus::task_provider_grant::run(&args, true), 0);
        if operation == "add" {
            nexus::task_authorization::authorize_use(&self.root, principal, WORKSPACE, RESOURCE)
                .unwrap();
        }
    }
    fn open(&self, now: u64) -> FileSnapshotStaging {
        FileSnapshotStaging::open_with_test_time(&self.root, now)
            .unwrap()
            .unwrap()
    }
    fn context(&self, principal: &str) -> TaskCallContext {
        TaskCallContext::from_authenticated(principal.into(), WORKSPACE.into()).unwrap()
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
    fn namespace(&self) -> PathBuf {
        self.root.join("data/n3/snapshot-staging-v1")
    }
    fn payload(&self, id: &UploadId) -> PathBuf {
        self.namespace()
            .join("uploads")
            .join(id.as_str())
            .join("blobs")
            .join(sha256(CONTENT).as_str().trim_start_matches("sha256:"))
    }
    fn audit(&self) -> Vec<Vec<u8>> {
        nexus::n2_store::N2Store::open(&self.root)
            .unwrap()
            .replay_journal()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

// This tiny requester-side sink is only for the real Workspace freeze API;
// it never writes provider identity, grant, staging authority or receipts.
#[derive(Default)]
struct FrozenContent(BTreeMap<Sha256Digest, Vec<u8>>);
impl StrongContentStore for FrozenContent {
    fn get_verified(&self, digest: &Sha256Digest, size: u64) -> Result<Vec<u8>, TaskError> {
        let bytes = self.0.get(digest).unwrap();
        nexus_storage::strong::verify_content(digest, size, bytes, sha256)?;
        Ok(bytes.clone())
    }
    fn put_verified(&mut self, digest: &Sha256Digest, bytes: &[u8]) -> Result<(), TaskError> {
        nexus_storage::strong::verify_content(digest, bytes.len() as u64, bytes, sha256)?;
        self.0.insert(digest.clone(), bytes.to_vec());
        Ok(())
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

// Exclude atime because reads are allowed; include mtime/ctime to catch staging
// writes even when bytes are rewritten unchanged. Stable inodes are observed.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    path: PathBuf,
    identity: (u64, u64, u32, u64),
    modified: (i64, i64, i64, i64),
    bytes: Option<Vec<u8>>,
}
fn image(root: &Path) -> Vec<Entry> {
    fn visit(root: &Path, path: &Path, out: &mut Vec<Entry>) {
        let m = fs::symlink_metadata(path).unwrap();
        out.push(Entry {
            path: path.strip_prefix(root).unwrap().into(),
            identity: (m.dev(), m.ino(), m.mode(), m.nlink()),
            modified: (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
            bytes: m.is_file().then(|| fs::read(path).unwrap()),
        });
        if m.is_dir() {
            let mut paths = fs::read_dir(path)
                .unwrap()
                .map(|x| x.unwrap().path())
                .collect::<Vec<_>>();
            paths.sort();
            for p in paths {
                visit(root, &p, out);
            }
        }
    }
    let mut out = vec![];
    visit(root, root, &mut out);
    out
}
#[derive(Clone, Copy, Debug)]
enum Mutation {
    Cancel,
    Seal,
    PutChunk,
}
impl Mutation {
    fn request(self, id: &UploadId) -> SnapshotRequest {
        match self {
            Self::Cancel => SnapshotRequest::Cancel {
                upload_id: id.clone(),
            },
            Self::Seal => SnapshotRequest::Seal {
                upload_id: id.clone(),
            },
            Self::PutChunk => chunk(id, 0, CONTENT),
        }
    }
}
const MUTATIONS: [Mutation; 3] = [Mutation::Cancel, Mutation::Seal, Mutation::PutChunk];
fn chunk(id: &UploadId, offset: u64, bytes: &[u8]) -> SnapshotRequest {
    SnapshotRequest::PutChunk {
        upload_id: id.clone(),
        blob_sha256: sha256(CONTENT),
        offset,
        bytes: bytes.to_vec(),
        chunk_sha256: sha256(bytes),
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
fn code<T: std::fmt::Debug>(result: Result<T, TaskError>, expected: TaskErrorCode) {
    assert_eq!(result.unwrap_err().code, expected);
}
fn cancelled(f: &Fixture, s: &FileSnapshotStaging, c: &TaskCallContext) -> UploadView {
    let target = s.execute(c, f.begin("expired-target")).unwrap();
    let full = s.execute(c, chunk(&target.upload_id, 0, CONTENT)).unwrap();
    assert_eq!(full.blobs[0].durable_offset, CONTENT.len() as u64);
    assert_eq!(
        s.execute(c, Mutation::Seal.request(&target.upload_id))
            .unwrap()
            .state,
        UploadState::Staged
    );
    let terminal = s
        .execute(c, Mutation::Cancel.request(&target.upload_id))
        .unwrap();
    assert_eq!(terminal.state, UploadState::Cancelled);
    assert_eq!(terminal.reserved_bytes, 0);
    terminal
}

// Get is the independent, zero-write observation of optional pruning. Never
// infer absence from the mutation error being tested or from elapsed time.
fn retained(
    f: &Fixture,
    s: &FileSnapshotStaging,
    c: &TaskCallContext,
    terminal: &UploadView,
) -> bool {
    let before = image(&f.namespace());
    let result = s.execute(
        c,
        SnapshotRequest::Get {
            upload_id: terminal.upload_id.clone(),
        },
    );
    assert_eq!(
        image(&f.namespace()),
        before,
        "observing retention cannot write staging"
    );
    match result {
        Ok(view) => {
            assert_eq!(&view, terminal);
            true
        }
        Err(error) => {
            assert_eq!(error.code, TaskErrorCode::AuthDenied);
            false
        }
    }
}
fn terminal_result(
    mutation: Mutation,
    result: Result<UploadView, TaskError>,
    terminal: &UploadView,
    remains: bool,
) {
    if !remains {
        code(result, TaskErrorCode::AuthDenied);
    } else {
        match mutation {
            Mutation::Cancel => assert_eq!(&result.unwrap(), terminal),
            _ => code(result, TaskErrorCode::InvalidRequest),
        }
    }
}
fn metadata_after_expiry(s: &FileSnapshotStaging, original: (u64, usize), remains: bool) {
    let observed = s.test_metadata_allowance().unwrap();
    if remains {
        assert_eq!(observed, original);
    } else {
        assert_eq!(observed.1, original.1 - 1);
        assert!(
            observed.0 < original.0,
            "only removed tombstone releases metadata allowance"
        );
    }
}

fn expired_target(mutation: Mutation) {
    let f = Fixture::new();
    let s = f.open(START);
    let c = f.context(&f.principal);
    let terminal = cancelled(&f, &s, &c);
    let active = s.execute(&c, f.begin("active-prefix")).unwrap();
    let active = s.execute(&c, chunk(&active.upload_id, 0, b"abc")).unwrap();
    assert_eq!(active.state, UploadState::Receiving);
    assert_eq!(active.blobs[0].durable_offset, 3);
    let active_tree = f
        .namespace()
        .join("uploads")
        .join(active.upload_id.as_str());
    let active_image = image(&active_tree);
    let active_observation = s.test_observe(&active.upload_id).unwrap();
    let allowance = s.test_metadata_allowance().unwrap();
    assert!(
        s.test_observe(&terminal.upload_id)
            .unwrap()
            .future_ceiling_bytes
            > 0
    );
    let request = mutation.request(&terminal.upload_id);
    request.validate().unwrap(); // PutChunk uses the valid original bytes/hash/range.
    s.set_time(START + TTL - 1);
    match mutation {
        Mutation::Cancel => assert_eq!(s.execute(&c, request.clone()).unwrap(), terminal),
        // Cancelled does not permit Seal/PutChunk. Their successful Receiving
        // controls ran above; before TTL the unchanged request is InvalidRequest.
        _ => code(
            s.execute(&c, request.clone()),
            TaskErrorCode::InvalidRequest,
        ),
    }
    assert_eq!(s.test_metadata_allowance().unwrap(), allowance);
    assert_eq!(get(&s, &c, &terminal.upload_id), terminal);
    s.set_time(START + TTL);
    let before_get = image(&f.namespace());
    assert_eq!(get(&s, &c, &terminal.upload_id), terminal);
    assert_eq!(
        image(&f.namespace()),
        before_get,
        "Get at TTL cannot prune or rewrite staging"
    );
    let audit_before = f.audit().len();
    let first = s.execute(&c, request.clone());
    assert!(
        f.audit().len() > audit_before,
        "expired request must remain audited"
    );
    let first_retained = retained(&f, &s, &c, &terminal);
    // Check safety/repeat/restart before reporting the first classification RED.
    assert_eq!(get(&s, &c, &active.upload_id), active);
    assert_eq!(image(&active_tree), active_image);
    assert_eq!(fs::read(f.payload(&active.upload_id)).unwrap(), b"abc");
    metadata_after_expiry(&s, allowance, first_retained);
    assert_eq!(
        s.test_observe(&active.upload_id).unwrap(),
        active_observation
    );
    let before_repeat = image(&f.namespace());
    let repeat = s.execute(&c, request.clone());
    let repeat_retained = retained(&f, &s, &c, &terminal);
    assert!(
        first_retained || !repeat_retained,
        "removed ID cannot reappear"
    );
    terminal_result(mutation, repeat, &terminal, repeat_retained);
    metadata_after_expiry(&s, allowance, repeat_retained);
    if !first_retained {
        assert_eq!(image(&f.namespace()), before_repeat);
    }
    s.set_time(START + TTL + 1);
    let before_later = image(&f.namespace());
    let later = s.execute(&c, request.clone());
    let later_retained = retained(&f, &s, &c, &terminal);
    assert!(
        repeat_retained || !later_retained,
        "removed ID cannot reappear"
    );
    terminal_result(mutation, later, &terminal, later_retained);
    metadata_after_expiry(&s, allowance, later_retained);
    if !repeat_retained {
        assert_eq!(image(&f.namespace()), before_later);
    }
    let before_boot = image(&f.namespace());
    drop(s);
    let cold = f.open(START + TTL + 1);
    let boot_retained = retained(&f, &cold, &c, &terminal);
    assert!(
        later_retained || !boot_retained,
        "boot cannot recreate removed ID"
    );
    if !later_retained {
        assert_eq!(
            image(&f.namespace()),
            before_boot,
            "already pruned healthy state needs no repair"
        );
    }
    metadata_after_expiry(&cold, allowance, boot_retained);
    let after_boot = cold.execute(&c, request);
    let cold_retained = retained(&f, &cold, &c, &terminal);
    assert!(boot_retained || !cold_retained);
    terminal_result(mutation, after_boot, &terminal, cold_retained);
    metadata_after_expiry(&cold, allowance, cold_retained);
    assert_eq!(get(&cold, &c, &active.upload_id), active);
    assert_eq!(
        cold.test_observe(&active.upload_id).unwrap(),
        active_observation
    );
    assert_eq!(image(&active_tree), active_image);
    let replacement = cold.execute(&c, f.begin("expired-target")).unwrap();
    let begin_retained = retained(&f, &cold, &c, &terminal);
    assert!(
        cold_retained || !begin_retained,
        "Begin cannot recreate removed ID"
    );
    if begin_retained {
        assert_eq!(replacement, terminal);
        metadata_after_expiry(&cold, allowance, true);
    } else {
        assert_ne!(replacement.upload_id, terminal.upload_id);
        assert_eq!(replacement.state, UploadState::Receiving);
    }
    assert_eq!(get(&cold, &c, &active.upload_id), active);
    assert_eq!(
        cold.test_observe(&active.upload_id).unwrap(),
        active_observation
    );
    assert_eq!(image(&active_tree), active_image);
    terminal_result(mutation, first, &terminal, first_retained);
}
#[test]
fn cancel_at_ttl_never_reports_corruption_and_preserves_live_prefix() {
    expired_target(Mutation::Cancel);
}
#[test]
fn seal_at_ttl_never_reports_corruption_and_preserves_live_prefix() {
    expired_target(Mutation::Seal);
}
#[test]
fn put_chunk_at_ttl_never_reports_corruption_and_preserves_live_prefix() {
    expired_target(Mutation::PutChunk);
}

#[test]
fn expired_get_and_rejected_mutators_never_prune() {
    let f = Fixture::new();
    let s = f.open(START);
    let c = f.context(&f.principal);
    let terminal = cancelled(&f, &s, &c);
    f.grant("add", FOREIGN);
    let foreign = f.context(FOREIGN);
    let foreign_upload = s.execute(&foreign, f.begin("foreign-positive")).unwrap();
    s.execute(&foreign, chunk(&foreign_upload.upload_id, 0, CONTENT))
        .unwrap();
    s.execute(&foreign, Mutation::Seal.request(&foreign_upload.upload_id))
        .unwrap();
    let foreign_terminal = s
        .execute(
            &foreign,
            Mutation::Cancel.request(&foreign_upload.upload_id),
        )
        .unwrap();
    s.set_time(START + TTL);
    let before = image(&f.namespace());
    let allowance = s.test_metadata_allowance().unwrap();
    for _ in 0..2 {
        assert_eq!(get(&s, &c, &terminal.upload_id), terminal);
        assert_eq!(image(&f.namespace()), before);
    }
    for mutation in MUTATIONS {
        let count = f.audit().len();
        code(
            s.execute(&foreign, mutation.request(&terminal.upload_id)),
            TaskErrorCode::AuthDenied,
        );
        assert!(f.audit().len() > count);
        assert_eq!(
            image(&f.namespace()),
            before,
            "foreign {mutation:?} cannot prune"
        );
    }
    f.grant("revoke", &f.principal);
    for mutation in MUTATIONS {
        let count = f.audit().len();
        code(
            s.execute(&c, mutation.request(&terminal.upload_id)),
            TaskErrorCode::AuthDenied,
        );
        assert!(f.audit().len() > count);
        assert_eq!(
            image(&f.namespace()),
            before,
            "revoked {mutation:?} cannot prune"
        );
    }
    assert_eq!(s.test_metadata_allowance().unwrap(), allowance);
    f.grant("add", &f.principal);
    assert_eq!(get(&s, &c, &terminal.upload_id), terminal);
    assert_eq!(image(&f.namespace()), before);
    // Boot may prune either tombstone; it need not remove either one.
    drop(s);
    let cold = f.open(START + TTL);
    let owner_retained = retained(&f, &cold, &c, &terminal);
    let foreign_retained = retained(&f, &cold, &foreign, &foreign_terminal);
    let remaining = cold.test_metadata_allowance().unwrap();
    assert_eq!(
        remaining.1,
        usize::from(owner_retained) + usize::from(foreign_retained)
    );
    if owner_retained && foreign_retained {
        assert_eq!(remaining, allowance);
    } else {
        assert!(remaining.0 < allowance.0);
    }
}

#[test]
fn authorization_and_refusal_audit_precede_the_staging_lease() {
    let f = Fixture::new();
    let s = f.open(START);
    let c = f.context(&f.principal);
    let terminal = cancelled(&f, &s, &c);
    let before = image(&f.namespace());
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.namespace().join("staging.lock"))
        .unwrap();
    nexus_platform_linux::file_lease::try_lock_exclusive(&held).unwrap();
    let count = f.audit().len();
    code(
        s.execute(
            &c,
            SnapshotRequest::Get {
                upload_id: terminal.upload_id.clone(),
            },
        ),
        TaskErrorCode::CapacityUnavailable,
    );
    assert!(
        f.audit().len() > count,
        "Use audit happens before competing for lease"
    );
    let foreign = f.context(FOREIGN);
    for mutation in MUTATIONS {
        let count = f.audit().len();
        code(
            s.execute(&foreign, mutation.request(&terminal.upload_id)),
            TaskErrorCode::AuthDenied,
        );
        assert!(
            f.audit().len() > count,
            "refusal audit must not require staging lease"
        );
    }
    let unknown = UploadId::new("absent-upload".into()).unwrap();
    let count = f.audit().len();
    code(
        s.execute(&c, Mutation::Cancel.request(&unknown)),
        TaskErrorCode::AuthDenied,
    );
    assert!(f.audit().len() > count);
    assert_eq!(image(&f.namespace()), before);
    drop(held);
    assert_eq!(get(&s, &c, &terminal.upload_id), terminal);
}

#[test]
fn failed_authorization_audit_prevents_expiry_and_missing_refusal_fails_closed() {
    let f = Fixture::new();
    let s = f.open(START);
    let c = f.context(&f.principal);
    let terminal = cancelled(&f, &s, &c);
    s.set_time(START + TTL);
    assert_eq!(get(&s, &c, &terminal.upload_id), terminal); // audit healthy at same time
    let before = image(&f.namespace());
    let journal = f.root.join("n2/journal.log");
    let saved = f.base.join("saved-journal");
    fs::rename(&journal, &saved).unwrap();
    fs::create_dir(&journal).unwrap();
    for mutation in MUTATIONS {
        code(
            s.execute(&c, mutation.request(&terminal.upload_id)),
            TaskErrorCode::PersistenceFailed,
        );
        assert_eq!(image(&f.namespace()), before);
    }
    fs::remove_dir(&journal).unwrap();
    fs::rename(&saved, &journal).unwrap();
    // This ID was never generated or admitted: absence does not rely on any
    // particular pruning policy for the expired target.
    let absent = UploadId::new("never-created-upload".into()).unwrap();
    for mutation in MUTATIONS {
        code(
            s.execute(&c, mutation.request(&absent)),
            TaskErrorCode::AuthDenied,
        );
    }
    let before = image(&f.namespace());
    fs::rename(&journal, &saved).unwrap();
    fs::create_dir(&journal).unwrap();
    for mutation in MUTATIONS {
        code(
            s.execute(&c, mutation.request(&absent)),
            TaskErrorCode::PersistenceFailed,
        );
        assert_eq!(image(&f.namespace()), before);
    }
}

#[test]
fn genuine_prefix_corruption_at_ttl_still_fails_closed_before_pruning() {
    for mutation in MUTATIONS {
        let f = Fixture::new();
        let s = f.open(START);
        let c = f.context(&f.principal);
        let terminal = cancelled(&f, &s, &c);
        let active = s.execute(&c, f.begin("corruption-control")).unwrap();
        let active = s.execute(&c, chunk(&active.upload_id, 0, b"abc")).unwrap();
        s.set_time(START + TTL);
        assert_eq!(get(&s, &c, &active.upload_id), active); // healthy at same TTL
        fs::write(f.payload(&active.upload_id), b"xbc").unwrap(); // only prefix changes
        let damaged = image(&f.namespace());
        code(
            s.execute(&c, mutation.request(&terminal.upload_id)),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(
            image(&f.namespace()),
            damaged,
            "corruption cannot prune tombstones"
        );
        code(
            FileSnapshotStaging::open_with_test_time(&f.root, START + TTL),
            TaskErrorCode::StateCorrupt,
        );
        assert_eq!(
            image(&f.namespace()),
            damaged,
            "cold recovery cannot repair corrupted prefix"
        );
    }
}
