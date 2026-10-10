//! Production CLI subprocesses against the existing N2 authority layout.
//! SDK writes are confined to initial, valid fixture provisioning.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use nexus::{
    n2_identity::ensure_auth_identity,
    n2_store::N2Store,
    n3_acceptance::{new_task_id, sha256},
};
use nexus_auth::{Grant, Principal};
use nexus_domain::{ResourceName, ResourceOperation, ResourceRef, WorkspaceId};
use nexus_storage::FileKvStore;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, FileTimes},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

const PROVIDER: &str = "operator-provider";
const WORKSPACE: &str = "operator-workspace";
const RESOURCE: &str = "compute-result";
const AUDIT: &str = "task-provider-grant-audit-v1.jsonl";
const OTHER: &str = "ed25519:0123456789abcdef0123456789abcdef";
const ABSENT: &str = "ed25519:abcdef0123456789abcdef0123456789";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("n310-{label}-{}", new_task_id().unwrap().as_str()));
        fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    directory: Directory,
    principal: Principal,
}
impl Fixture {
    fn new() -> Self {
        let directory = Directory::new("authority");
        fs::create_dir(directory.0.join("n2")).unwrap();
        mode(&directory.0.join("n2"), 0o700);
        fs::write(
            directory.0.join("task-api.toml"),
            format!("provider = '{PROVIDER}'\nworkspace = '{WORKSPACE}'\n"),
        )
        .unwrap();
        mode(&directory.0.join("task-api.toml"), 0o644);
        let store = N2Store::open(&directory.0).unwrap();
        let (_, principal) = ensure_auth_identity(&store).unwrap();
        Self {
            directory,
            principal,
        }
    }

    fn root(&self) -> &Path {
        &self.directory.0
    }

    fn n2(&self) -> PathBuf {
        self.root().join("n2")
    }

    fn identity(&self) -> PathBuf {
        self.n2()
            .join(FileKvStore::file_name_for("n2/auth-identity").unwrap())
    }

    fn grant(&self, workspace: &str, resource: &str, principal: &str) -> PathBuf {
        self.n2().join(
            FileKvStore::file_name_for(&format!("n2/grant/{workspace}/{resource}/{principal}"))
                .unwrap(),
        )
    }

    fn own_grant(&self) -> PathBuf {
        self.grant(WORKSPACE, RESOURCE, &self.principal.0)
    }

    fn audit(&self) -> PathBuf {
        self.n2().join(AUDIT)
    }

    fn seed(&self, workspace: &str, resource: &str, principal: &str, ops: Vec<ResourceOperation>) {
        let store = N2Store::open(self.root()).unwrap();
        store
            .save_grant(&Grant::new(
                ResourceRef::new(
                    WorkspaceId::new(workspace),
                    ResourceName::new(resource).unwrap(),
                ),
                Principal(principal.into()),
                ops,
                None,
            ))
            .unwrap();
        mode(&self.grant(workspace, resource, principal), 0o644);
    }

    fn seed_self(&self) {
        self.seed(
            WORKSPACE,
            RESOURCE,
            &self.principal.0,
            vec![ResourceOperation::Use],
        );
    }

    fn invoke(&self, op: &str, extra: &[&str]) -> Value {
        let mut args = vec![
            "--json".to_string(),
            "task-provider".into(),
            "grant".into(),
            op.into(),
            "--config".into(),
            self.root().to_str().unwrap().into(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn mutate_self(&self, op: &str, extra: &[&str]) -> Value {
        let mut options = vec!["--resource", RESOURCE, "--self"];
        options.extend_from_slice(extra);
        self.invoke(op, &options)
    }
}

fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}

/// Every spawned process has a deadline and an owner which kills and reaps on
/// panic. File-backed output avoids a pipe filling before the owner can wait.
struct ProcessOwner {
    child: Child,
    reaped: bool,
}
impl Drop for ProcessOwner {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn process(mut command: Command) -> Output {
    let capture = Directory::new("capture");
    let stdout = capture.0.join("stdout");
    let stderr = capture.0.join("stderr");
    let child = command
        .stdin(Stdio::null())
        .stdout(File::create(&stdout).unwrap())
        .stderr(File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let mut owner = ProcessOwner {
        child,
        reaped: false,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while owner.child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "subprocess timed out; owner reaps it"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let status = owner.child.wait().unwrap();
    owner.reaped = true;
    Output {
        status,
        stdout: fs::read(stdout).unwrap(),
        stderr: fs::read(stderr).unwrap(),
    }
}
fn cli(args: &[String]) -> Output {
    let binary = std::env::var_os("NEXUS_N3_TEST_CLI_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nexus").into());
    let mut command = Command::new(binary);
    command.args(args);
    process(command)
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    inode: u64,
    mode: u32,
    links: u64,
    modified: SystemTime,
    bytes: Vec<u8>,
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let bytes = if metadata.is_file() {
            fs::read(path).unwrap()
        } else if metadata.file_type().is_symlink() {
            fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            Vec::new()
        };
        out.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            Entry {
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                modified: metadata.modified().unwrap(),
                bytes,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), out);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn pass(value: &Value, op: &str) {
    assert_eq!(value["schema_version"], 1, "{value}");
    assert_eq!(value["verdict"], "PASS", "{value}");
    assert_eq!(value["command"], format!("task-provider grant {op}"));
    assert_eq!(
        value["scope"],
        json!({"provider": PROVIDER, "workspace": WORKSPACE})
    );
}
fn failure(value: &Value, code: Option<&str>) {
    assert_eq!(value["schema_version"], 1, "{value}");
    assert_eq!(value["verdict"], "FAIL", "{value}");
    assert!(
        value["error"]["reason"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert!(value["error"]["retryable"].is_boolean());
    assert!(value["phase"].is_string());
    assert_eq!(value["mutation_may_have_applied"], false, "{value}");
    if let Some(code) = code {
        assert_eq!(value["error"]["code"], code, "{value}");
    }
}
fn record(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn digest(bytes: &[u8]) -> String {
    sha256(bytes).as_str().to_string()
}

/// Independent reconstruction from actual CLI-produced bytes, with exact field
/// sets, hashes, chain links, and intent/applied correlation.
fn audit_records(fixture: &Fixture, expected: usize) -> Vec<Value> {
    let bytes = fs::read(fixture.audit()).unwrap();
    assert!(bytes.ends_with(b"\n"));
    let records: Vec<Value> = bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(records.len(), expected * 2);
    let fields: BTreeSet<&str> = [
        "schema_version",
        "mutation_id",
        "phase",
        "operation",
        "scope",
        "resource",
        "principal",
        "actor",
        "changed",
        "before_sha256",
        "after_sha256",
        "at_unix",
        "previous_sha256",
        "record_sha256",
    ]
    .into_iter()
    .collect();
    let mut previous = Value::Null;
    let mut ids = BTreeSet::new();
    for entry in &records {
        let mut content = entry.as_object().unwrap().clone();
        assert_eq!(
            content.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            fields
        );
        let claimed = content.remove("record_sha256").unwrap();
        assert_eq!(claimed, digest(&serde_json::to_vec(&content).unwrap()));
        assert_eq!(entry["previous_sha256"], previous);
        previous = claimed;
        assert_eq!(entry["actor"], fixture.principal.0);
        assert_eq!(
            entry["scope"],
            json!({"provider": PROVIDER, "workspace": WORKSPACE})
        );
        assert_eq!(entry["schema_version"], 1);
        assert_eq!(entry["changed"], true);
        assert!(
            entry["at_unix"]
                .as_u64()
                .is_some_and(|v| v <= 9_007_199_254_740_991)
        );
    }
    for pair in records.chunks_exact(2) {
        assert_eq!(pair[0]["phase"], "intent");
        assert_eq!(pair[1]["phase"], "applied");
        assert!(ids.insert(pair[0]["mutation_id"].as_str().unwrap()));
        assert_ne!(pair[0]["before_sha256"], pair[0]["after_sha256"]);
        for field in [
            "mutation_id",
            "operation",
            "scope",
            "resource",
            "principal",
            "actor",
            "changed",
            "before_sha256",
            "after_sha256",
        ] {
            assert_eq!(pair[0][field], pair[1][field]);
        }
    }
    let metadata = fs::metadata(fixture.audit()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    records
}

#[test]
fn binary_mutations_use_the_real_table_and_preserve_noop_bytes_and_tombstones() {
    let fixture = Fixture::new();
    fixture.seed_self();
    // Valid noncanonical bytes must survive an identical request.
    let initial = serde_json::to_vec_pretty(&record(&fixture.own_grant())).unwrap();
    fs::write(fixture.own_grant(), &initial).unwrap();
    let identity = fs::read(fixture.identity()).unwrap();
    let value = fixture.mutate_self("add", &[]);
    pass(&value, "add");
    assert_eq!(value["operation"], "add");
    assert_eq!(value["changed"], false);
    assert_eq!(fs::read(fixture.own_grant()).unwrap(), initial);
    assert!(!fixture.audit().exists());

    let value = fixture.mutate_self("revoke", &[]);
    pass(&value, "revoke");
    assert_eq!(value["changed"], true);
    assert_eq!(value["grant"]["revoked"], true);
    assert_eq!(value["grant"]["not_after"], Value::Null);
    let tombstone = fs::read(fixture.own_grant()).unwrap();
    assert_eq!(record(&fixture.own_grant())["revoked"], true);
    let audit = fs::read(fixture.audit()).unwrap();
    let value = fixture.mutate_self("revoke", &[]);
    pass(&value, "revoke");
    assert_eq!(value["changed"], false);
    assert_eq!(fs::read(fixture.own_grant()).unwrap(), tombstone);
    assert_eq!(fs::read(fixture.audit()).unwrap(), audit);

    let value = fixture.mutate_self("add", &["--not-after", "0"]);
    pass(&value, "add");
    assert_eq!(value["changed"], true);
    assert_eq!(value["grant"]["revoked"], false);
    assert_eq!(value["grant"]["not_after"], 0);
    let expired = fs::read(fixture.own_grant()).unwrap();
    let audit = fs::read(fixture.audit()).unwrap();
    let value = fixture.mutate_self("add", &["--not-after", "0"]);
    assert_eq!(value["changed"], false);
    assert_eq!(fs::read(fixture.own_grant()).unwrap(), expired);
    assert_eq!(fs::read(fixture.audit()).unwrap(), audit);
    let value = fixture.mutate_self("add", &[]);
    pass(&value, "add");
    assert_eq!(value["changed"], true);
    assert_eq!(value["grant"]["not_after"], Value::Null);

    let value = fixture.invoke("add", &["--resource", RESOURCE, "--principal", OTHER]);
    pass(&value, "add");
    assert_eq!(value["changed"], true);
    assert_eq!(value["grant"]["principal"], OTHER);
    let before_absent = snapshot(fixture.root());
    let value = fixture.invoke("revoke", &["--resource", RESOURCE, "--principal", ABSENT]);
    pass(&value, "revoke");
    assert_eq!(value["changed"], false);
    assert_eq!(value["grant"], Value::Null);
    assert_eq!(snapshot(fixture.root()), before_absent);

    let records = audit_records(&fixture, 4);
    assert_eq!(records[0]["before_sha256"], digest(&initial));
    assert_eq!(records[2]["before_sha256"], digest(&tombstone));
    assert_eq!(records[4]["before_sha256"], digest(&expired));
    assert_eq!(records[6]["before_sha256"], Value::Null);
    assert_eq!(
        records[4]["after_sha256"],
        digest(&fs::read(fixture.own_grant()).unwrap())
    );
    assert_eq!(
        records[6]["after_sha256"],
        digest(&fs::read(fixture.grant(WORKSPACE, RESOURCE, OTHER)).unwrap())
    );
    assert_eq!(fs::read(fixture.identity()).unwrap(), identity);
    assert!(!fixture.n2().join("journal.log").exists());
    for path in [
        fixture.own_grant(),
        fixture.grant(WORKSPACE, RESOURCE, OTHER),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn binary_list_without_identity_is_readonly_sorted_scoped_and_does_not_clean_old_tmp() {
    let fixture = Fixture::new();
    fixture.seed_self();
    fixture.seed(WORKSPACE, RESOURCE, OTHER, vec![ResourceOperation::Manage]);
    fixture.seed(
        WORKSPACE,
        "aaa-resource",
        OTHER,
        vec![ResourceOperation::Use, ResourceOperation::Manage],
    );
    fixture.seed(
        "other-workspace",
        RESOURCE,
        &fixture.principal.0,
        vec![ResourceOperation::Use],
    );
    fs::remove_file(fixture.identity()).unwrap();
    let orphan = fixture.n2().join(".tmp-foreign-orphan");
    fs::write(&orphan, b"owned by someone else").unwrap();
    File::open(&orphan)
        .unwrap()
        .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
        .unwrap();
    let before = snapshot(fixture.root());
    let value = fixture.invoke("list", &[]);
    pass(&value, "list");
    let grants = value["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 3);
    assert_eq!(grants[0]["resource"], "aaa-resource");
    assert_eq!(grants[0]["operations"], json!(["use", "manage"]));
    let keys: Vec<_> = grants
        .iter()
        .map(|grant| {
            (
                grant["resource"].as_str().unwrap(),
                grant["principal"].as_str().unwrap(),
            )
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    let value = fixture.invoke("list", &["--resource", RESOURCE]);
    pass(&value, "list");
    assert_eq!(value["grants"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot(fixture.root()), before);
    assert!(!fixture.root().join("task-provider-grants.lock").exists());
    assert!(!fixture.audit().exists());
}

#[test]
fn binary_mutation_changes_only_requested_workspace_resource_and_principal() {
    let fixture = Fixture::new();
    fixture.seed_self();
    fixture.seed(
        "other-workspace",
        RESOURCE,
        &fixture.principal.0,
        vec![ResourceOperation::Use],
    );
    fixture.seed(
        WORKSPACE,
        "other-resource",
        &fixture.principal.0,
        vec![ResourceOperation::Use],
    );
    fixture.seed(WORKSPACE, RESOURCE, OTHER, vec![ResourceOperation::Use]);
    let untouched: Vec<_> = [
        fixture.grant("other-workspace", RESOURCE, &fixture.principal.0),
        fixture.grant(WORKSPACE, "other-resource", &fixture.principal.0),
        fixture.grant(WORKSPACE, RESOURCE, OTHER),
    ]
    .into_iter()
    .map(|path| {
        let bytes = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        (path, bytes, inode)
    })
    .collect();
    pass(&fixture.mutate_self("revoke", &[]), "revoke");
    pass(&fixture.mutate_self("add", &["--not-after", "1"]), "add");
    for (path, bytes, inode) in untouched {
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
    }
}

#[test]
fn binary_ttl_accepts_past_zero_and_max_exactly_and_revoke_retains_it() {
    let fixture = Fixture::new();
    for ttl in ["0", "1", "9007199254740991"] {
        let value = fixture.mutate_self("add", &["--not-after", ttl]);
        pass(&value, "add");
        let expected: u64 = ttl.parse().unwrap();
        assert_eq!(value["grant"]["not_after"], expected);
        assert_eq!(record(&fixture.own_grant())["not_after"], expected);
        let value = fixture.mutate_self("revoke", &[]);
        pass(&value, "revoke");
        assert_eq!(value["grant"]["not_after"], expected);
        assert_eq!(value["grant"]["revoked"], true);
        let listed = fixture.invoke("list", &["--resource", RESOURCE]);
        pass(&listed, "list");
        assert_eq!(listed["grants"][0]["not_after"], expected);
        assert_eq!(listed["grants"][0]["revoked"], true);
    }
}

#[test]
fn binary_invalid_syntax_and_remote_options_exit_two_before_any_authority_io() {
    let fixture = Fixture::new();
    fixture.seed_self();
    // A FIFO makes an accidental configuration read observable as a timeout.
    fs::remove_file(fixture.root().join("task-api.toml")).unwrap();
    fifo(&fixture.root().join("task-api.toml"));
    let before = snapshot(fixture.root());
    let config = fixture.root().to_str().unwrap();
    let base = ["task-provider", "grant"];
    let invalid: Vec<Vec<&str>> = vec![
        vec![],
        vec!["unknown"],
        vec!["add"],
        vec!["list", "--config", config, "--unknown", "value"],
        vec!["list", "--config", config, "--config", config],
        vec!["list", "--config"],
        vec!["list", "--config", config, "--resource"],
        vec!["list", "--config", config, "--self"],
        vec!["list", "--config", config, "--principal", OTHER],
        vec!["list", "--config", config, "--not-after", "0"],
        vec!["add", "--config", config, "--resource", RESOURCE],
        vec!["add", "--config", config, "--self"],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--self",
            "--self",
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--self",
            "--principal",
            OTHER,
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--principal",
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--principal",
            OTHER,
            "--principal",
            OTHER,
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            "bad/name",
            "--self",
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--resource",
            RESOURCE,
            "--self",
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--principal",
            "ed25519:ABCDEF0123456789abcdef0123456789",
        ],
        vec![
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--principal",
            "ed25519:00",
        ],
        vec![
            "revoke",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--self",
            "--not-after",
            "0",
        ],
        vec!["list", "--config", "relative"],
        vec!["list", "--config", "/tmp/../tmp"],
        vec!["list", "--config", config, "extra"],
    ];
    for suffix in invalid {
        let args: Vec<String> = ["--json"]
            .into_iter()
            .chain(base)
            .chain(suffix)
            .map(String::from)
            .collect();
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "args={args:?}, {output:?}");
        assert_eq!(snapshot(fixture.root()), before, "args={args:?}");
    }
    for ttl in [
        "-1",
        "+1",
        "1.0",
        "1e3",
        "9007199254740992",
        "18446744073709551616",
        "invalid",
        "",
    ] {
        let args = [
            "--json",
            "task-provider",
            "grant",
            "add",
            "--config",
            config,
            "--resource",
            RESOURCE,
            "--self",
            "--not-after",
            ttl,
        ]
        .map(String::from);
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "ttl={ttl:?}, {output:?}");
        assert_eq!(snapshot(fixture.root()), before);
    }
    for remote in [
        vec!["--addr", "127.0.0.1:1"],
        vec!["--socket", "/tmp/n310-never.sock"],
        vec!["--addr"],
        vec!["--socket"],
        vec!["--addr=127.0.0.1:1"],
        vec!["--socket=/tmp/n310-never.sock"],
        vec!["--json"],
    ] {
        for prefix in [false, true] {
            let local = vec![
                "--json",
                "task-provider",
                "grant",
                "list",
                "--config",
                config,
            ];
            let combined = if prefix {
                [remote.clone(), local].concat()
            } else {
                [local, remote.clone()].concat()
            };
            let args = combined.into_iter().map(String::from).collect::<Vec<_>>();
            let output = cli(&args);
            assert_eq!(output.status.code(), Some(2), "args={args:?}, {output:?}");
            assert_eq!(snapshot(fixture.root()), before);
        }
    }
}

#[test]
fn binary_missing_identity_never_provisions_it_even_with_an_explicit_target() {
    let fixture = Fixture::new();
    fixture.seed_self();
    fs::remove_file(fixture.identity()).unwrap();
    let grant = fs::read(fixture.own_grant()).unwrap();
    for op in ["add", "revoke"] {
        for target in [vec!["--self"], vec!["--principal", OTHER]] {
            let value = fixture.invoke(op, &[vec!["--resource", RESOURCE], target].concat());
            failure(&value, None);
            assert!(!fixture.identity().exists());
            assert!(!fixture.audit().exists());
            assert_eq!(fs::read(fixture.own_grant()).unwrap(), grant);
            assert!(!fixture.grant(WORKSPACE, RESOURCE, OTHER).exists());
        }
    }
    pass(&fixture.invoke("list", &[]), "list");
}

#[test]
fn binary_manage_and_mixed_grants_are_visible_but_never_rewritten() {
    for operations in [
        vec![ResourceOperation::Manage],
        vec![ResourceOperation::Use, ResourceOperation::Manage],
    ] {
        let fixture = Fixture::new();
        fixture.seed(
            WORKSPACE,
            RESOURCE,
            &fixture.principal.0,
            operations.clone(),
        );
        let original = serde_json::to_vec_pretty(&record(&fixture.own_grant())).unwrap();
        fs::write(fixture.own_grant(), &original).unwrap();
        let inode = fs::metadata(fixture.own_grant()).unwrap().ino();
        for op in ["add", "revoke"] {
            failure(&fixture.mutate_self(op, &[]), Some("AUTH_DENIED"));
            assert_eq!(fs::read(fixture.own_grant()).unwrap(), original);
            assert_eq!(fs::metadata(fixture.own_grant()).unwrap().ino(), inode);
            assert!(!fixture.audit().exists());
        }
        let value = fixture.invoke("list", &[]);
        pass(&value, "list");
        assert_eq!(
            value["grants"][0]["operations"],
            json!(
                operations
                    .iter()
                    .map(ResourceOperation::as_str)
                    .collect::<Vec<_>>()
            )
        );
    }
}

fn fifo(path: &Path) {
    let mut command = Command::new("mkfifo");
    command.arg("-m").arg("600").arg(path);
    let output = process(command);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn binary_rejects_symlink_hardlink_and_fifo_files_without_hanging() {
    for target in ["config", "identity", "grant"] {
        for kind in ["symlink", "hardlink", "fifo"] {
            let fixture = Fixture::new();
            fixture.seed_self();
            let path = match target {
                "config" => fixture.root().join("task-api.toml"),
                "identity" => fixture.identity(),
                _ => fixture.own_grant(),
            };
            let original = fs::read(&path).unwrap();
            let outside = Directory::new("external");
            let external = outside.0.join("record");
            fs::write(&external, &original).unwrap();
            mode(&external, 0o600);
            fs::remove_file(&path).unwrap();
            match kind {
                "symlink" => symlink(&external, &path).unwrap(),
                "hardlink" => fs::hard_link(&external, &path).unwrap(),
                _ => fifo(&path),
            }
            // List must not read identity, even if it is a hostile file type.
            if target == "identity" {
                let before = snapshot(fixture.root());
                pass(&fixture.invoke("list", &[]), "list");
                assert_eq!(snapshot(fixture.root()), before);
            } else {
                let before = snapshot(fixture.root());
                failure(&fixture.invoke("list", &[]), None);
                assert_eq!(snapshot(fixture.root()), before);
            }
            failure(&fixture.mutate_self("add", &[]), None);
            assert_eq!(fs::read(&external).unwrap(), original);
            assert!(!fixture.audit().exists());
            assert_eq!(
                fs::symlink_metadata(&path).unwrap().file_type().is_fifo(),
                kind == "fifo"
            );
        }
    }
}

#[test]
fn binary_refuses_insecure_roots_and_config_records_and_missing_roots() {
    for target in ["root", "n2", "config"] {
        let fixture = Fixture::new();
        fixture.seed_self();
        let path = match target {
            "root" => fixture.root().to_path_buf(),
            "n2" => fixture.n2(),
            _ => fixture.root().join("task-api.toml"),
        };
        mode(&path, if target == "config" { 0o666 } else { 0o755 });
        let before = snapshot(fixture.root());
        failure(&fixture.invoke("list", &[]), None);
        failure(&fixture.mutate_self("add", &[]), None);
        assert_eq!(snapshot(fixture.root()), before);
    }
    for content in [
        "provider = 'operator-provider'\n",
        "provider = 'operator-provider'\nworkspace = 'operator-workspace'\nextra = 'x'\n",
        "provider = 1\nworkspace = 'operator-workspace'\n",
        "provider = ''\nworkspace = 'operator-workspace'\n",
    ] {
        let fixture = Fixture::new();
        fs::write(fixture.root().join("task-api.toml"), content).unwrap();
        let before = snapshot(fixture.root());
        failure(&fixture.invoke("list", &[]), None);
        failure(&fixture.mutate_self("add", &[]), None);
        assert_eq!(snapshot(fixture.root()), before);
    }
    let parent = Directory::new("missing");
    let nonexistent = parent.0.join("never-created");
    let args = [
        "--json",
        "task-provider",
        "grant",
        "add",
        "--config",
        nonexistent.to_str().unwrap(),
        "--resource",
        RESOURCE,
        "--self",
    ]
    .map(String::from);
    let before = snapshot(&parent.0);
    let output = cli(&args);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    failure(&serde_json::from_slice(&output.stdout).unwrap(), None);
    assert_eq!(snapshot(&parent.0), before);
}

#[test]
fn binary_scope_preserves_identifiers_allowed_by_the_existing_task_id_contract() {
    let fixture = Fixture::new();
    let provider = "provider/identifier";
    assert!(nexus_domain::task::TaskId::new(provider.into()).is_ok());
    fs::write(
        fixture.root().join("task-api.toml"),
        format!("provider = '{provider}'\nworkspace = '{WORKSPACE}'\n"),
    )
    .unwrap();
    let before = snapshot(fixture.root());
    let value = fixture.invoke("list", &[]);
    assert_eq!(value["verdict"], "PASS");
    assert_eq!(value["scope"]["provider"], provider);
    assert_eq!(snapshot(fixture.root()), before);
}

#[test]
fn binary_corrupt_audit_and_dangling_intent_block_noops_but_list_preserves_forensics() {
    for corruption in ["checksum", "torn", "dangling", "json"] {
        let fixture = Fixture::new();
        fixture.seed_self();
        pass(&fixture.mutate_self("revoke", &[]), "revoke");
        let audit = fs::read(fixture.audit()).unwrap();
        let corrupt = match corruption {
            "checksum" => {
                let mut records = audit_records(&fixture, 1);
                records[0]["actor"] = OTHER.into();
                records
                    .into_iter()
                    .flat_map(|record| {
                        let mut line = serde_json::to_vec(&record).unwrap();
                        line.push(b'\n');
                        line
                    })
                    .collect()
            }
            "torn" => audit[..audit.len() - 1].to_vec(),
            "dangling" => audit[..=audit.iter().position(|byte| *byte == b'\n').unwrap()].to_vec(),
            _ => b"invalid-json\n".to_vec(),
        };
        fs::write(fixture.audit(), &corrupt).unwrap();
        let before = snapshot(fixture.root());
        failure(&fixture.mutate_self("revoke", &[]), Some("STATE_CORRUPT"));
        failure(&fixture.mutate_self("add", &[]), Some("STATE_CORRUPT"));
        assert_eq!(snapshot(fixture.root()), before);
        let value = fixture.invoke("list", &[]);
        pass(&value, "list");
        assert_eq!(value["grants"][0]["revoked"], true);
        assert_eq!(snapshot(fixture.root()), before);
        assert_eq!(fs::read(fixture.audit()).unwrap(), corrupt);
    }
}

#[test]
fn binary_human_mode_renders_the_same_structured_local_result() {
    let fixture = Fixture::new();
    fixture.seed_self();
    let value = fixture.invoke("list", &[]);
    let args = [
        "task-provider",
        "grant",
        "list",
        "--config",
        fixture.root().to_str().unwrap(),
    ]
    .map(String::from);
    let output = cli(&args);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        value
    );
}

#[test]
fn binary_overlapping_workspace_names_keep_queries_and_mutations_isolated() {
    for workspace in ["a", "a/b"] {
        let other_workspace = if workspace == "a" { "a/b" } else { "a" };
        for damage in ["valid", "json", "permissions", "fifo"] {
            let fixture = Fixture::new();
            fs::write(
                fixture.root().join("task-api.toml"),
                format!("provider = '{PROVIDER}'\nworkspace = '{workspace}'\n"),
            )
            .unwrap();
            for scope in [workspace, other_workspace] {
                fixture.seed(
                    scope,
                    RESOURCE,
                    &fixture.principal.0,
                    vec![ResourceOperation::Use],
                );
            }
            let other = fixture.grant(other_workspace, RESOURCE, &fixture.principal.0);
            match damage {
                "json" => fs::write(&other, b"invalid JSON\n").unwrap(),
                "permissions" => mode(&other, 0o666),
                "fifo" => {
                    fs::remove_file(&other).unwrap();
                    fifo(&other);
                }
                _ => {}
            }
            let before = snapshot(fixture.root());
            let expected = json!([{"resource": RESOURCE, "principal": fixture.principal.0,
                "operations": ["use"], "not_after": null, "revoked": false}]);
            for options in [vec![], vec!["--resource", RESOURCE]] {
                let result = fixture.invoke("list", &options);
                assert_eq!(result["verdict"], "PASS", "{workspace}/{damage}: {result}");
                assert_eq!(
                    result["scope"],
                    json!({"provider": PROVIDER, "workspace": workspace})
                );
                assert_eq!(result["grants"], expected);
                assert_eq!(snapshot(fixture.root()), before);
            }
            let result = fixture.mutate_self("revoke", &[]);
            assert_eq!(result["verdict"], "PASS", "{workspace}/{damage}: {result}");
            assert_eq!(result["changed"], true);
            assert_eq!(result["grant"]["revoked"], true);
            let after = snapshot(fixture.root());
            let other_key = other.strip_prefix(fixture.root()).unwrap();
            assert_eq!(after.get(other_key), before.get(other_key));
            let current = record(&fixture.grant(workspace, RESOURCE, &fixture.principal.0));
            assert_eq!(current["workspace"], workspace);
            assert_eq!(current["revoked"], true);
        }
    }
}
