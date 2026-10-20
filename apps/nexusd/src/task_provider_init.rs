//! Explicit local provider initialization. It never opens a live execution owner.
use crate::{task_capacity::ProviderCapacityPolicy, task_store::FileTaskAcceptanceStore};
use nexus::n3_acceptance::{new_task_id, parse_canonical_json, sha256};
use nexus_domain::task::{
    TaskError, TaskErrorCode, TaskId,
    codec::{CanonicalDto, Value},
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[path = "task_provider_init_io.rs"]
mod io;

const JOURNAL: &str = "task-provider-init-v1.json";
const RECEIPT: &str = "task-provider-initialized-v1.json";
const LOCK: &str = "task-provider-init.lock";
const OWNER: &str = "capacity-owner.lock";
const SENTINEL: &[u8] = b"n3-provider-init-v1-required\n";
const DIRS: [&str; 4] = ["n2", "data", "data/n3", "data/n3/tasks"];
const PHASES: [&str; 6] = [
    "intent",
    "directories",
    "identity",
    "capacity",
    "scope",
    "completed",
];

/// Public facts only. CLI owns the schema envelope and rendering.
#[derive(Debug, Clone)]
pub struct ProviderStatus {
    pub provider: String,
    pub workspace: String,
    pub principal: String,
    pub policy_digest: String,
    pub changed: bool,
}
#[derive(Debug)]
pub struct InitFailure {
    pub error: TaskError,
    pub phase: &'static str,
    pub mutation_may_have_applied: bool,
}
impl InitFailure {
    fn new(code: TaskErrorCode, reason: impl Into<String>, retryable: bool) -> Self {
        Self {
            error: TaskError::new(code, reason, retryable),
            phase: "preflight",
            mutation_may_have_applied: false,
        }
    }
    fn at(mut self, phase: &'static str, may_have_applied: bool) -> Self {
        self.phase = phase;
        self.mutation_may_have_applied = may_have_applied;
        self
    }
}
impl From<TaskError> for InitFailure {
    fn from(error: TaskError) -> Self {
        Self {
            error,
            phase: "preflight",
            mutation_may_have_applied: false,
        }
    }
}
type Result<T> = std::result::Result<T, InitFailure>;
fn corrupt(reason: impl Into<String>) -> InitFailure {
    InitFailure::new(TaskErrorCode::StateCorrupt, reason, false)
}
fn persistence(error: impl std::fmt::Display) -> InitFailure {
    InitFailure::new(TaskErrorCode::PersistenceFailed, error.to_string(), true)
}
macro_rules! codec {
    ($t:ident {$($field:ident:$ty:ty),+}) => {
        impl CanonicalDto for $t {
            fn to_value(&self) -> Value {
                Value::Object(BTreeMap::from([$( (stringify!($field).into(), self.$field.to_value()) ),+]))
            }
            fn from_value(value: Value) -> std::result::Result<Self,TaskError> {
                let Value::Object(mut fields) = value else { return Err(corrupt("invalid initialization object").error) };
                let result = Self { $( $field: <$ty>::from_value(fields.remove(stringify!($field)).ok_or_else(|| corrupt(concat!("missing initialization ",stringify!($field))).error)?)? ),+ };
                if !fields.is_empty() { return Err(corrupt("unknown initialization field").error); }
                Ok(result)
            }
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    device: u64,
    inode: u64,
}
codec!(Binding {
    device: u64,
    inode: u64
});
impl Binding {
    fn new(value: (u64, u64)) -> Self {
        Self {
            device: value.0,
            inode: value.1,
        }
    }
    fn pair(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryBinding {
    name: String,
    binding: Binding,
}
codec!(DirectoryBinding {
    name: String,
    binding: Binding
});
#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    schema_version: u64,
    initialization_id: String,
    phase: String,
    provider: String,
    workspace: String,
    policy_digest: String,
    principal: String,
    identity_digest: String,
    identity_binding: Binding,
    staged_identity: String,
    root: Binding,
    lease: Binding,
    directories: Vec<DirectoryBinding>,
    owner: Option<Binding>,
    acceptance_lock: Option<Binding>,
    scope: Option<Binding>,
}
codec!(State {
    schema_version: u64, initialization_id: String, phase: String, provider: String,
    workspace: String, policy_digest: String, principal: String, identity_digest: String,
    identity_binding: Binding, staged_identity: String, root: Binding, lease: Binding,
    directories: Vec<DirectoryBinding>, owner: Option<Binding>, acceptance_lock: Option<Binding>, scope: Option<Binding>
});
impl State {
    fn index(&self) -> Result<usize> {
        PHASES
            .iter()
            .position(|phase| *phase == self.phase)
            .ok_or_else(|| corrupt("invalid initialization phase"))
    }
    fn validate(&self, root: &io::Root) -> Result<()> {
        let phase = self.index()?;
        if self.schema_version != 1
            || self.root.pair() != root.binding
            || self.staged_identity
                != format!(".task-provider-init-identity-{}", self.initialization_id)
            || !self.initialization_id.starts_with("task-")
            || self.initialization_id.len() != 69
            || !self.initialization_id[5..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || (phase == 0 && !self.directories.is_empty())
            || (phase >= 1
                && (self.directories.len() != DIRS.len()
                    || self.directories.iter().zip(DIRS).any(|(d, n)| d.name != n)))
            || (self.owner.is_some() != (phase >= 3))
            || (self.acceptance_lock.is_some() != (phase >= 3))
            || (self.scope.is_some() != (phase >= 4))
        {
            return Err(corrupt("invalid managed initialization bindings or phase"));
        }
        for id in [&self.provider, &self.workspace] {
            TaskId::new(id.clone()).map_err(|_| corrupt("invalid initialization scope"))?;
        }
        for digest in [&self.policy_digest, &self.identity_digest] {
            nexus_domain::task::Sha256Digest::parse(digest.clone())
                .map_err(|_| corrupt("invalid initialization digest"))?;
        }
        if self.principal.strip_prefix("ed25519:").is_none_or(|hex| {
            hex.len() != 32
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(corrupt("invalid initialization principal"));
        }
        root.check()?;
        let lock = io::read(&root.path.join(LOCK), io::SMALL, true)?;
        if lock.binding()? != self.lease.pair() || !lock.bytes.is_empty() {
            return Err(corrupt("original initialization lease was replaced"));
        }
        for directory in &self.directories {
            if io::directory(&root.path.join(&directory.name), true)? != directory.binding.pair() {
                return Err(corrupt("original initialization directory inode changed"));
            }
        }
        Ok(())
    }
    fn status(&self, changed: bool) -> ProviderStatus {
        ProviderStatus {
            provider: self.provider.clone(),
            workspace: self.workspace.clone(),
            principal: self.principal.clone(),
            policy_digest: self.policy_digest.clone(),
            changed,
        }
    }
    fn bytes(&self) -> Vec<u8> {
        let payload = self.to_value();
        Value::Object(BTreeMap::from([
            ("payload".into(), payload.clone()),
            (
                "checksum".into(),
                sha256(&payload.canonical_bytes()).to_value(),
            ),
        ]))
        .canonical_bytes()
    }
}
fn decode_state(record: &io::Record, root: &io::Root) -> Result<State> {
    let Value::Object(mut fields) =
        parse_canonical_json(&record.bytes).map_err(|_| corrupt("invalid initialization JSON"))?
    else {
        return Err(corrupt("invalid initialization envelope"));
    };
    let payload = fields
        .remove("payload")
        .ok_or_else(|| corrupt("missing initialization payload"))?;
    let checksum = fields
        .remove("checksum")
        .ok_or_else(|| corrupt("missing initialization checksum"))?;
    if !fields.is_empty() || checksum != sha256(&payload.canonical_bytes()).to_value() {
        return Err(corrupt("initialization checksum mismatch"));
    }
    let state = State::from_value(payload).map_err(|_| corrupt("invalid initialization fields"))?;
    state.validate(root)?;
    record.check()?;
    Ok(state)
}
fn task_root(root: &io::Root) -> PathBuf {
    root.path.join("data/n3/tasks")
}
fn identity_path(root: &io::Root) -> Result<PathBuf> {
    let name = nexus_storage::FileKvStore::file_name_for("n2/auth-identity")
        .ok_or_else(|| corrupt("invalid existing N2 identity key"))?;
    Ok(root.path.join("n2").join(name))
}
fn managed(root: &io::Root) -> Result<bool> {
    for name in [LOCK, JOURNAL, RECEIPT] {
        if io::exists(&root.path.join(name))? {
            return Ok(true);
        }
    }
    // Validate ancestry before looking for the retained anti-downgrade anchor.
    for name in ["data", "data/n3", "data/n3/tasks"] {
        let path = root.path.join(name);
        if !io::exists(&path)? {
            return Ok(false);
        }
        io::directory(&path, true)?;
    }
    match io::read_optional(&task_root(root).join(OWNER), io::SMALL, true)? {
        Some(record) => {
            record.check()?;
            if record.bytes == SENTINEL {
                Ok(true)
            } else if record.bytes.is_empty() {
                Ok(false)
            } else {
                Err(corrupt("unknown capacity owner initialization marker"))
            }
        }
        None => Ok(false),
    }
}
fn verify_identity(root: &io::Root, state: &State, published: bool) -> Result<io::Record> {
    let path = if published {
        identity_path(root)?
    } else {
        root.path.join(&state.staged_identity)
    };
    let record = io::read(&path, io::SMALL, true)?;
    let principal = nexus::n2_identity::principal_from_existing_bytes(&record.bytes)
        .map_err(|_| corrupt("original N2 identity is invalid"))?;
    if record.binding()? != state.identity_binding.pair()
        || sha256(&record.bytes).as_str() != state.identity_digest
        || principal.0 != state.principal
    {
        return Err(corrupt("original N2 identity binding or material changed"));
    }
    record.check()?;
    Ok(record)
}
fn verify_scope(root: &io::Root, state: &State) -> Result<io::Record> {
    let record = io::read(&root.path.join("task-api.toml"), io::SMALL, false)?;
    let fields: toml::Table = std::str::from_utf8(&record.bytes)
        .map_err(|_| corrupt("invalid scope UTF-8"))?
        .parse()
        .map_err(|_| corrupt("invalid scope TOML"))?;
    if fields.len() != 2
        || fields.get("provider").and_then(toml::Value::as_str) != Some(&state.provider)
        || fields.get("workspace").and_then(toml::Value::as_str) != Some(&state.workspace)
        || state
            .scope
            .as_ref()
            .is_some_and(|binding| record.binding().ok() != Some(binding.pair()))
    {
        return Err(corrupt("original configured provider scope changed"));
    }
    record.check()?;
    Ok(record)
}
fn validate_capacity(root: &io::Root, state: &State, fresh: bool) -> Result<()> {
    validate_capacity_state(root, state, fresh, false)
}
fn validate_capacity_state(
    root: &io::Root,
    state: &State,
    fresh: bool,
    pending_sentinel: bool,
) -> Result<()> {
    let path = task_root(root);
    // Missing a fixed lock is authority loss, not permission to create one.
    let lock_record = io::read(&path.join("acceptance.lock"), io::SMALL, true)?;
    if !lock_record.bytes.is_empty() {
        return Err(corrupt("unexpected acceptance lock content"));
    }
    let lock = io::Lease::acquire(root, &path.join("acceptance.lock"), false)?;
    if lock.binding()? != lock_record.binding()? {
        return Err(corrupt("original acceptance lock changed while opening"));
    }
    let mut records = Vec::new();
    for (name, limit) in [
        ("acceptance-v1.json", io::AUTHORITY),
        ("task-runtime-v1.json", io::AUTHORITY),
        ("acceptance-initialized-v1", io::SMALL),
        ("task-runtime-initialized-v1", io::SMALL),
        ("capacity-initialized-v1", io::SMALL),
        (OWNER, io::SMALL),
    ] {
        records.push(io::read(&path.join(name), limit, true)?);
    }
    if state
        .acceptance_lock
        .as_ref()
        .is_some_and(|binding| lock.binding().ok() != Some(binding.pair()))
        || state
            .owner
            .as_ref()
            .is_some_and(|binding| records[5].binding().ok() != Some(binding.pair()))
        || (records[5].bytes != SENTINEL && !(pending_sentinel && records[5].bytes.is_empty()))
        || (records[2].bytes != crate::task_capacity::CAPACITY_AUTHORITY_RECEIPT
            && records[2].bytes != crate::task_capacity::CAPACITY_ARTIFACT_AUTHORITY_RECEIPT)
        || records[3].bytes != b"n3-task-runtime-initialized-v1\n"
        || records[4].bytes != b"n3-capacity-initialized-v1\n"
    {
        return Err(corrupt(
            "managed capacity receipt, sentinel or original lock changed",
        ));
    }
    let (ledger, capacity) = crate::task_store::decode_authority_bytes(&records[0].bytes)?;
    let capacity =
        capacity.ok_or_else(|| corrupt("managed provider has no coupled capacity image"))?;
    capacity.verify_init_binding(&state.policy_digest, records[5].binding()?, fresh)?;
    let runtime = crate::task_runtime_store::decode(&records[1].bytes, &ledger)?;
    if fresh
        && (!ledger.tasks.is_empty()
            || !ledger.idempotency.is_empty()
            || !runtime.journals.is_empty())
    {
        return Err(corrupt("initialization cannot enroll accepted work"));
    }
    for name in [
        "artifacts-v1.json",
        "artifacts-initialized-v1",
        "snapshot-roots-v1.json",
    ] {
        if let Some(record) = io::read_optional(&path.join(name), io::AUTHORITY, true)? {
            records.push(record);
        }
    }
    crate::task_artifacts::validate_runtime(&path, &ledger, &runtime)?;
    if io::exists(&path.join("snapshot-roots-v1.json"))? {
        io::directory(&path.join("content-sha256-v1"), true)?;
        crate::snapshot_store::FileSnapshotStore::validate_existing_roots(&path, &ledger)?;
    } else if !ledger.tasks.is_empty() || io::exists(&path.join("content-sha256-v1"))? {
        return Err(corrupt("required managed Snapshot catalog missing"));
    }
    for record in records {
        record.check()?;
    }
    lock_record.check()?;
    lock.check(root)?;
    state.validate(root)?;
    Ok(())
}
// Only an entirely empty bound directory is fresh. A full coupled image proves
// the original owner and policy; incomplete or unknown remnants prove neither.
fn capacity_checkpoint(root: &io::Root, state: &State) -> Result<bool> {
    let path = task_root(root);
    let allowed = [
        "acceptance.lock",
        "acceptance-v1.json",
        "task-runtime-v1.json",
        "acceptance-initialized-v1",
        "task-runtime-initialized-v1",
        "capacity-initialized-v1",
        OWNER,
    ];
    let mut empty = true;
    for entry in fs::read_dir(&path).map_err(persistence)? {
        let name = entry.map_err(persistence)?.file_name();
        empty = false;
        if !allowed.iter().any(|allowed| name == *allowed) {
            return Err(corrupt("unknown incomplete capacity initialization entry"));
        }
    }
    if !empty {
        validate_capacity_state(root, state, true, true)?;
    }
    root.check()?;
    Ok(empty)
}
fn complete(root: &io::Root) -> Result<(State, io::Record, io::Record)> {
    let journal = io::read(&root.path.join(JOURNAL), io::SMALL, true)?;
    let state = decode_state(&journal, root)?;
    if state.phase != "completed" {
        return Err(corrupt("managed initialization is pending"));
    }
    let receipt = io::read(&root.path.join(RECEIPT), io::SMALL, true)?;
    if decode_state(&receipt, root)? != state {
        return Err(corrupt(
            "initialization completion differs from original intent",
        ));
    }
    let identity = verify_identity(root, &state, true)?;
    let scope = verify_scope(root, &state)?;
    validate_capacity(root, &state, false)?;
    journal.check()?;
    receipt.check()?;
    identity.check()?;
    scope.check()?;
    state.validate(root)?;
    Ok((state, journal, receipt))
}

/// Check only already-completed managed state, without storage opens or writes.
pub fn check(config: &Path) -> Result<ProviderStatus> {
    let result = (|| {
        let root = io::Root::open(config)?;
        if !managed(&root)? {
            return Err(corrupt("provider is not managed and initialized"));
        }
        let (state, journal, receipt) = complete(&root)?;
        journal.check()?;
        receipt.check()?;
        root.check()?;
        Ok(state.status(false))
    })();
    result.map_err(|error: InitFailure| error.at("check", false))
}
/// Startup preflight. Historical unmanaged roots are not initialized or migrated.
pub fn validate_managed_root(config: &Path) -> std::result::Result<bool, TaskError> {
    let result = (|| {
        // Preserve the old entry's absent/non-private unmanaged root behavior.
        // Any recognizable managed companion still receives strict validation.
        let has_companion = [LOCK, JOURNAL, RECEIPT]
            .iter()
            .try_fold(false, |found, name| {
                io::exists(&config.join(name)).map(|present| found || present)
            })?;
        if !has_companion {
            let owner = config.join("data/n3/tasks").join(OWNER);
            if !io::exists(&owner)? {
                return Ok(false);
            }
            let record = io::read(&owner, io::SMALL, true)?;
            if record.bytes.is_empty() {
                return Ok(false);
            }
            if record.bytes != SENTINEL {
                return Err(corrupt("unknown managed-required owner content"));
            }
        }
        // Startup accepts relative config roots; keep symlinks and .. visible
        // to the existing strict managed-root checks.
        let config = std::path::absolute(config).map_err(persistence)?;
        let root = io::Root::open(&config)?;
        let (_, journal, receipt) = complete(&root)?;
        journal.check()?;
        receipt.check()?;
        Ok(true)
    })();
    result.map_err(|failure: InitFailure| failure.error)
}
// Policy is caller input, not managed authority. Preserve actual IO errors,
// while classifying malformed or replaced input as an invalid request.
fn invalid_policy(mut failure: InitFailure) -> InitFailure {
    if failure.error.code == TaskErrorCode::StateCorrupt {
        failure.error.code = TaskErrorCode::InvalidRequest;
    }
    failure
}
fn check_policy(record: &io::Record) -> Result<()> {
    record.check().map_err(invalid_policy)
}
fn policy(path: &Path) -> Result<(ProviderCapacityPolicy, io::Record)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(InitFailure::new(
            TaskErrorCode::InvalidRequest,
            "capacity requires an absolute path without ..",
            false,
        ));
    }
    for ancestor in path
        .parent()
        .ok_or_else(|| invalid_policy(corrupt("capacity input lacks parent")))?
        .ancestors()
    {
        io::directory(ancestor, false).map_err(invalid_policy)?;
    }
    let record = io::read(path, io::SMALL, false).map_err(invalid_policy)?;
    let parsed = parse_canonical_json(&record.bytes)
        .and_then(ProviderCapacityPolicy::from_value)
        .map_err(|_| {
            InitFailure::new(
                TaskErrorCode::InvalidRequest,
                "invalid exact capacity policy",
                false,
            )
        })?;
    parsed.validate()?;
    check_policy(&record)?;
    Ok((parsed, record))
}
fn fresh(root: &io::Root, allow_lock: bool) -> Result<Option<io::Record>> {
    for entry in fs::read_dir(&root.path).map_err(persistence)? {
        let name = entry.map_err(persistence)?.file_name();
        if name != "daemon.toml" && !(allow_lock && name == LOCK) {
            return Err(corrupt("fresh provider root contains existing entries"));
        }
    }
    let config = io::read_optional(&root.path.join("daemon.toml"), io::SMALL, false)?;
    if let Some(record) = &config {
        let table: toml::Table = std::str::from_utf8(&record.bytes)
            .map_err(|_| corrupt("invalid daemon config UTF-8"))?
            .parse()
            .map_err(|_| corrupt("invalid daemon config TOML"))?;
        if table
            .get("tun")
            .and_then(toml::Value::as_table)
            .and_then(|tun| tun.get("enabled"))
            .and_then(toml::Value::as_bool)
            != Some(false)
        {
            return Err(corrupt(
                "provider initialization requires explicit no-TUN daemon config",
            ));
        }
        let dir = crate::config::ConfigDir {
            root: root.path.clone(),
        };
        crate::config::load(&dir).map_err(|_| corrupt("daemon config is not valid"))?;
        record.check()?;
    }
    root.check()?;
    Ok(config)
}
struct Transaction<'a> {
    root: &'a io::Root,
    lease: io::Lease,
    policy_record: &'a io::Record,
    operator_config: Option<io::Record>,
    state: State,
    journal: io::Record,
}
impl Transaction<'_> {
    fn check(&self) -> Result<()> {
        self.lease.check(self.root)?;
        check_policy(self.policy_record)?;
        if let Some(record) = &self.operator_config {
            record.check()?;
        }
        self.state.validate(self.root)?;
        self.journal.check()
    }
    fn save(&mut self, next: State) -> Result<()> {
        next.validate(self.root)?;
        let record = io::replace(
            self.root,
            &self.root.path.join(JOURNAL),
            Some(&self.journal),
            &next.bytes(),
            || {
                self.check()?;
                next.validate(self.root)
            },
        )?;
        self.state = next;
        self.journal = record;
        self.check()
    }
    fn run(&mut self, allocation: &ProviderCapacityPolicy) -> Result<ProviderStatus> {
        let result = self.advance(allocation);
        result.map_err(|error| error.at(PHASES[self.state.index().unwrap_or(0)], true))
    }
    fn advance(&mut self, allocation: &ProviderCapacityPolicy) -> Result<ProviderStatus> {
        self.check()?;
        if self.state.index()? == 0 {
            verify_identity(self.root, &self.state, false)?;
            let mut next = self.state.clone();
            for name in DIRS {
                // A directory created before its durable binding is not a
                // qualified checkpoint: refuse rather than adopt an inode.
                if io::exists(&self.root.path.join(name))? {
                    return Err(corrupt("unbound initialization directory exists"));
                }
                let binding = io::create_directory(self.root, &self.root.path.join(name))?;
                next.directories.push(DirectoryBinding {
                    name: name.into(),
                    binding: Binding::new(binding),
                });
            }
            next.phase = "directories".into();
            self.save(next)?;
        }
        if self.state.index()? == 1 {
            let target = identity_path(self.root)?;
            if io::exists(&target)? {
                verify_identity(self.root, &self.state, true)?;
                if io::exists(&self.root.path.join(&self.state.staged_identity))? {
                    return Err(corrupt(
                        "identity exists in contradictory initialization locations",
                    ));
                }
            } else {
                let staged = verify_identity(self.root, &self.state, false)?;
                io::publish_identity(self.root, &staged, &target, || self.check())?;
            }
            let mut next = self.state.clone();
            next.phase = "identity".into();
            self.save(next)?;
        }
        verify_identity(self.root, &self.state, true)?;
        if self.state.index()? == 2 {
            self.check()?;
            if capacity_checkpoint(self.root, &self.state)? {
                FileTaskAcceptanceStore::provision_capacity(&task_root(self.root), allocation)?;
            }
            self.check()?;
            let owner = io::sentinel(self.root, &task_root(self.root).join(OWNER), SENTINEL)?;
            let acceptance_lock = io::read(
                &task_root(self.root).join("acceptance.lock"),
                io::SMALL,
                true,
            )?;
            let mut next = self.state.clone();
            next.owner = Some(Binding::new(owner.binding()?));
            next.acceptance_lock = Some(Binding::new(acceptance_lock.binding()?));
            next.phase = "capacity".into();
            self.save(next)?;
        }
        validate_capacity(self.root, &self.state, true)?;
        if self.state.index()? == 3 {
            let path = self.root.path.join("task-api.toml");
            let scope = if io::exists(&path)? {
                verify_scope(self.root, &self.state)?
            } else {
                let text = toml::to_string(&BTreeMap::from([
                    ("provider", &self.state.provider),
                    ("workspace", &self.state.workspace),
                ]))
                .map_err(persistence)?;
                io::replace(self.root, &path, None, text.as_bytes(), || self.check())?
            };
            let mut next = self.state.clone();
            next.scope = Some(Binding::new(scope.binding()?));
            next.phase = "scope".into();
            self.save(next)?;
        }
        let identity = verify_identity(self.root, &self.state, true)?;
        let scope = verify_scope(self.root, &self.state)?;
        self.check()?;
        let mut completed = self.state.clone();
        completed.phase = "completed".into();
        let receipt_path = self.root.path.join(RECEIPT);
        let receipt = match io::read_optional(&receipt_path, io::SMALL, true)? {
            Some(record) => {
                if decode_state(&record, self.root)? != completed {
                    return Err(corrupt("contradictory initialization completion receipt"));
                }
                record
            }
            None => io::replace(self.root, &receipt_path, None, &completed.bytes(), || {
                self.check()?;
                identity.check()?;
                scope.check()?;
                validate_capacity(self.root, &self.state, true)
            })?,
        };
        receipt.check()?;
        self.save(completed)?;
        let (state, journal, receipt) = complete(self.root)?;
        journal.check()?;
        receipt.check()?;
        check_policy(self.policy_record)?;
        Ok(state.status(true))
    }
}
/// Explicit fresh or qualified same-intent initialization. Completed repeats
/// perform validation only, including while the original daemon owner is live.
pub fn init(
    config: &Path,
    provider: &str,
    workspace: &str,
    capacity: &Path,
) -> Result<ProviderStatus> {
    TaskId::new(provider.to_owned())?;
    TaskId::new(workspace.to_owned())?;
    let root = io::Root::open(config)?;
    let (allocation, policy_record) = policy(capacity)?;
    let digest = sha256(&allocation.to_value().canonical_bytes())
        .as_str()
        .to_owned();
    if managed(&root)? {
        if !io::exists(&root.path.join(JOURNAL))? && io::exists(&root.path.join(LOCK))? {
            let _lease = io::Lease::acquire(&root, &root.path.join(LOCK), false)?;
            return Err(corrupt("managed initialization journal is missing"));
        }
        let journal = io::read(&root.path.join(JOURNAL), io::SMALL, true)?;
        let state = decode_state(&journal, &root)?;
        if state.provider != provider
            || state.workspace != workspace
            || state.policy_digest != digest
        {
            return Err(corrupt(
                "scope or capacity policy cannot replace original initialization",
            ));
        }
        // Both recovery and completed repeats serialize on the original init
        // inode. This never creates the lease or takes the live Ready owner.
        let lease = io::Lease::acquire(&root, &root.path.join(LOCK), false)?;
        if state.phase == "completed" {
            let (verified, journal, receipt) = complete(&root)?;
            check_policy(&policy_record)?;
            journal.check()?;
            receipt.check()?;
            lease.check(&root)?;
            return Ok(verified.status(false));
        }
        // No creates on damaged managed roots. Only its original lease is used.
        if state.index()? == 2 {
            capacity_checkpoint(&root, &state)?;
        }
        let operator_config = io::read_optional(&root.path.join("daemon.toml"), io::SMALL, false)?;
        let mut transaction = Transaction {
            root: &root,
            lease,
            policy_record: &policy_record,
            operator_config,
            state,
            journal,
        };
        return transaction.run(&allocation);
    }
    let operator_config = fresh(&root, false)?;
    check_policy(&policy_record)?;
    let lease = io::Lease::acquire(&root, &root.path.join(LOCK), true)?;
    let begin = (|| {
        fresh(&root, true)?;
        lease.check(&root)?;
        check_policy(&policy_record)?;
        let id = new_task_id()?;
        let bytes =
            nexus::n2_identity::generate_auth_identity_record(nexus::n2_store::now_unix_pub())
                .map_err(persistence)?;
        let principal =
            nexus::n2_identity::principal_from_existing_bytes(&bytes).map_err(persistence)?;
        let staged_name = format!(".task-provider-init-identity-{}", id.as_str());
        let staged = io::create_file(&root, &root.path.join(&staged_name), &bytes)?;
        let state = State {
            schema_version: 1,
            initialization_id: id.as_str().into(),
            phase: "intent".into(),
            provider: provider.into(),
            workspace: workspace.into(),
            policy_digest: digest,
            principal: principal.0,
            identity_digest: sha256(&bytes).as_str().into(),
            identity_binding: Binding::new(staged.binding()?),
            staged_identity: staged_name,
            root: Binding::new(root.binding),
            lease: Binding::new(lease.binding()?),
            directories: Vec::new(),
            owner: None,
            acceptance_lock: None,
            scope: None,
        };
        let journal = io::replace(
            &root,
            &root.path.join(JOURNAL),
            None,
            &state.bytes(),
            || {
                lease.check(&root)?;
                check_policy(&policy_record)?;
                staged.check()?;
                if let Some(record) = &operator_config {
                    record.check()?;
                }
                Ok(())
            },
        )?;
        let mut transaction = Transaction {
            root: &root,
            lease,
            policy_record: &policy_record,
            operator_config,
            state,
            journal,
        };
        transaction.run(&allocation)
    })();
    begin.map_err(|error: InitFailure| {
        if error.mutation_may_have_applied {
            error
        } else {
            error.at("intent", true)
        }
    })
}

#[cfg(test)]
#[path = "task_provider_init_tests.rs"]
mod tests;
