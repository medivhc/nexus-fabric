#![cfg(target_os = "linux")]

use nexus::n3_acceptance::sha256;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const BINARY: &str = env!("CARGO_BIN_EXE_nexusd");
const PROVIDER: &str = "binary-provider";
const WORKSPACE: &str = "binary-workspace";
const JOURNAL: &str = "task-provider-init-v1.json";
const RECEIPT: &str = "task-provider-initialized-v1.json";
const INIT_LOCK: &str = "task-provider-init.lock";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn policy() -> Value {
    json!({
        "total": {"cpu_millis":10000,"memory_bytes":2147483648u64,"pids":2000,
            "runtime_storage_bytes":268435456,"backend_disk_bytes":2147483648u64,"slots":10},
        "fixed": {"cpu_millis":100,"memory_bytes":16777216,"pids":4,
            "runtime_storage_bytes":4096,"backend_disk_bytes":16777216,"slots":1},
        "overhead": {"cpu_millis":10,"memory_bytes":8388608,"pids":2,"backend_disk_bytes":1048576}
    })
}

fn identity_path(root: &Path) -> PathBuf {
    // FileKv keys are encoded filenames. This pure address conversion does not
    // open the store, create authority, or run its recovery/cleanup paths.
    root.join("n2")
        .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap())
}

fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    policy: PathBuf,
    decoy: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "n311-binary-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let root = base.join("provider");
        let decoy = base.join("decoy");
        for path in [&root, &decoy] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        private_write(
            &root.join("daemon.toml"),
            b"localapi_addr = \"127.0.0.1:0\"\n[tun]\nenabled = false\n",
        );
        let policy = base.join("capacity.json");
        private_write(&policy, &serde_json::to_vec(&self::policy()).unwrap());
        Self {
            base,
            root,
            policy,
            decoy,
        }
    }
    fn args(&self, operation: &str) -> Vec<String> {
        let mut args = vec![
            "task-provider".into(),
            operation.into(),
            "--config".into(),
            self.root.to_string_lossy().into_owned(),
            "--json".into(),
        ];
        if operation == "init" {
            args.extend([
                "--provider".into(),
                PROVIDER.into(),
                "--workspace".into(),
                WORKSPACE.into(),
                "--capacity".into(),
                self.policy.to_string_lossy().into_owned(),
            ]);
        }
        args
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(BINARY);
        cmd.env("NEXUS_CONFIG_DIR", &self.decoy).env(
            "NEXUS_LOCALAPI_TOKEN_FILE",
            self.root.join("localapi.token"),
        );
        cmd
    }
    fn invoke(&self, operation: &str) -> Reply {
        run(self.command().args(self.args(operation)))
    }
    fn initialize(&self) -> Value {
        let response = self.invoke("init");
        response.pass("init");
        assert_eq!(response.json["changed"], true);
        response.json
    }
    fn assert_no_authority(&self) {
        for name in ["n2", "data", "task-api.toml", RECEIPT, "localapi.token"] {
            assert!(
                !self.root.join(name).exists(),
                "invalid input published {name}"
            );
        }
        assert!(fs::read_dir(&self.decoy).unwrap().next().is_none());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.base).unwrap();
    }
}

struct Reply {
    code: i32,
    json: Value,
    ready: bool,
}
impl Reply {
    fn pass(&self, operation: &str) {
        assert_eq!(self.code, 0);
        assert_eq!(self.json["schema_version"], 1);
        assert_eq!(self.json["verdict"], "PASS");
        assert_eq!(self.json["command"], format!("task-provider {operation}"));
        assert_eq!(
            self.json["scope"],
            json!({"provider":PROVIDER,"workspace":WORKSPACE})
        );
        assert!(
            self.json["principal"]
                .as_str()
                .is_some_and(|p| p.starts_with("ed25519:") && p.len() == 40)
        );
    }
    fn fail(&self, code: Option<&str>, retryable: bool) {
        assert_eq!(self.code, 0);
        assert_eq!(self.json["schema_version"], 1);
        assert_eq!(self.json["verdict"], "FAIL");
        if let Some(code) = code {
            assert_eq!(self.json["error"]["code"], code);
        } else {
            assert!(
                self.json["error"]["code"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty())
            );
        }
        assert_eq!(self.json["error"]["retryable"], retryable);
        assert!(
            self.json["error"]["reason"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
        );
        assert!(self.json["phase"].as_str().is_some_and(|v| !v.is_empty()));
        assert_eq!(self.json["mutation_may_have_applied"], false);
        assert_ne!(self.json["initialized"], true);
    }
}

fn run(command: &mut Command) -> Reply {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let read = |stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            stream
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            bytes
        })
    };
    let out = read(Box::new(stdout));
    let err = read(Box::new(stderr));
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            let _ = out.join();
            let _ = err.join();
            panic!("real binary exceeded bounded command deadline");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let out = out.join().unwrap();
    let err = err.join().unwrap();
    assert!(out.len() <= 1024 * 1024 && err.len() <= 1024 * 1024);
    // Never include raw stdout/stderr in assertions: identity material is private.
    for bytes in [&out, &err] {
        assert!(!bytes.windows(b"seed_hex".len()).any(|v| v == b"seed_hex"));
        assert!(
            !bytes
                .windows(b"public_key_hex".len())
                .any(|v| v == b"public_key_hex")
        );
    }
    let ready = out.split(|b| *b == b'\n').any(|line| {
        serde_json::from_slice::<Value>(line).is_ok_and(|value| value["verdict"] == "READY")
    });
    let json = serde_json::from_slice(&out).unwrap_or(Value::Null);
    Reply {
        code: status.code().unwrap_or(-1),
        json,
        ready,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    digest: Option<String>,
}
fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        let meta = fs::symlink_metadata(path).unwrap();
        let digest = if meta.is_file() {
            Some(sha256(&fs::read(path).unwrap()).as_str().to_owned())
        } else if meta.file_type().is_symlink() {
            Some(fs::read_link(path).unwrap().to_string_lossy().into_owned())
        } else {
            None
        };
        entries.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            Entry {
                device: meta.dev(),
                inode: meta.ino(),
                mode: meta.mode(),
                links: meta.nlink(),
                digest,
            },
        );
        if meta.is_dir() {
            for child in fs::read_dir(path).unwrap() {
                visit(root, &child.unwrap().path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn invalid_arguments_are_usage_errors_before_any_host_io() {
    let f = Fixture::new();
    let mut cases = Vec::new();
    for flag in [
        "--config",
        "--provider",
        "--workspace",
        "--capacity",
        "--json",
    ] {
        let mut args = f.args("init");
        args.push(flag.into());
        if flag != "--json" {
            args.push("ignored".into());
        }
        cases.push(args);
    }
    for tail in [
        vec!["--unknown", "x"],
        vec!["--addr", "127.0.0.1:1"],
        vec!["--socket", "/tmp/x"],
    ] {
        let mut args = f.args("init");
        args.extend(tail.into_iter().map(String::from));
        cases.push(args);
    }
    for flag in ["--config", "--provider", "--workspace", "--capacity"] {
        let mut args = f.args("init");
        let at = args.iter().position(|v| v == flag).unwrap();
        args.drain(at..at + 2);
        cases.push(args);
    }
    for (flag, value) in [
        ("--config", "relative-root"),
        ("--capacity", "relative-policy"),
        ("--config", "/tmp/../invalid"),
        ("--capacity", "/tmp/../policy"),
        ("--provider", ""),
        ("--workspace", ""),
    ] {
        let mut args = f.args("init");
        let at = args.iter().position(|v| v == flag).unwrap();
        args[at + 1] = value.into();
        cases.push(args);
    }
    let mut args = f.args("check");
    args.extend(["--provider".into(), PROVIDER.into()]);
    cases.push(args);
    let before = tree(&f.base);
    for args in cases {
        assert_eq!(run(f.command().args(args)).code, 2);
        assert_eq!(tree(&f.base), before);
    }
}

#[test]
fn policy_rejects_nonexact_integers_duplicate_fields_and_invalid_shape() {
    let mut cases = Vec::new();
    for value in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!(9007199254740992u64),
        json!("10"),
    ] {
        let mut p = policy();
        p["total"]["slots"] = value;
        cases.push(serde_json::to_vec(&p).unwrap());
    }
    for field in ["total", "fixed", "overhead"] {
        let mut p = policy();
        p.as_object_mut().unwrap().remove(field);
        cases.push(serde_json::to_vec(&p).unwrap());
        let mut p = policy();
        p[field]["extra"] = json!(1);
        cases.push(serde_json::to_vec(&p).unwrap());
    }
    let mut p = policy();
    p["fixed"]["slots"] = json!(11);
    cases.push(serde_json::to_vec(&p).unwrap());
    let bytes = serde_json::to_string(&policy()).unwrap();
    cases.push(format!("{{\"total\":{},{}", policy()["total"], &bytes[1..]).into_bytes());
    let mut p = policy();
    p["extra"] = json!(1);
    cases.push(serde_json::to_vec(&p).unwrap());
    cases.push(
        bytes
            .replacen("\"slots\":10", "\"slots\":1e1", 1)
            .into_bytes(),
    );
    cases.push(
        bytes
            .replacen("\"slots\":10", "\"slots\":10,\"slots\":10", 1)
            .into_bytes(),
    );
    cases.extend([b"[]".to_vec(), vec![0xff], vec![b' '; 16385]]);
    for bytes in cases {
        let f = Fixture::new();
        fs::write(&f.policy, bytes).unwrap();
        f.invoke("init").fail(Some("INVALID_REQUEST"), false);
        f.assert_no_authority();
    }
}

#[test]
fn exact_max_integer_and_16k_policy_boundary_use_operator_budget_without_host_measurement() {
    let f = Fixture::new();
    let mut p = policy();
    p["total"]["slots"] = json!(9007199254740991u64);
    let mut bytes = serde_json::to_vec(&p).unwrap();
    bytes.resize(16384, b' ');
    fs::write(&f.policy, bytes).unwrap();
    f.initialize();
    let checked = f.invoke("check");
    checked.pass("check");
    assert_eq!(
        checked.json["policy_digest"],
        sha256(&serde_json::to_vec(&p).unwrap()).as_str()
    );
    assert!(!f.root.join("localapi.token").exists());
}

#[test]
fn policy_file_fifo_hardlink_symlink_and_writable_permissions_refuse_without_authority() {
    for fault in ["fifo", "hardlink", "symlink", "writable"] {
        let f = Fixture::new();
        match fault {
            "fifo" => {
                fs::remove_file(&f.policy).unwrap();
                assert!(
                    Command::new("mkfifo")
                        .arg(&f.policy)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            "hardlink" => fs::hard_link(&f.policy, f.base.join("alias")).unwrap(),
            "symlink" => {
                let original = f.base.join("original");
                fs::rename(&f.policy, &original).unwrap();
                symlink(original, &f.policy).unwrap();
            }
            "writable" => {
                fs::set_permissions(&f.policy, fs::Permissions::from_mode(0o666)).unwrap()
            }
            _ => unreachable!(),
        }
        f.invoke("init").fail(None, false);
        f.assert_no_authority();
    }
}

#[test]
fn readonly_check_and_canonical_policy_replay_preserve_original_authority() {
    let f = Fixture::new();
    let initialized = f.initialize();
    let before = tree(&f.root);
    let checked = f.invoke("check");
    checked.pass("check");
    assert_eq!(checked.json["initialized"], true);
    assert_eq!(checked.json["principal"], initialized["principal"]);
    assert_eq!(
        checked.json["policy_digest"],
        sha256(&serde_json::to_vec(&policy()).unwrap()).as_str()
    );
    assert_eq!(tree(&f.root), before);
    fs::write(&f.policy, serde_json::to_vec_pretty(&policy()).unwrap()).unwrap();
    let repeated = f.invoke("init");
    repeated.pass("init");
    assert_eq!(repeated.json["changed"], false);
    assert_eq!(repeated.json["principal"], initialized["principal"]);
    assert_eq!(tree(&f.root), before);
    assert!(!f.root.join("localapi.token").exists());
    assert!(!f.root.join("data/n3/tasks/snapshot-roots-v1.json").exists());
    assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
}

#[test]
fn provider_and_workspace_slashes_remain_opaque_ids_not_paths() {
    let f = Fixture::new();
    let mut args = f.args("init");
    for flag in ["--provider", "--workspace"] {
        let at = args.iter().position(|v| v == flag).unwrap();
        args[at + 1] = "opaque/id".into();
    }
    let response = run(f.command().args(args));
    assert_eq!(response.code, 0);
    assert_eq!(response.json["verdict"], "PASS");
    assert_eq!(
        response.json["scope"],
        json!({"provider":"opaque/id","workspace":"opaque/id"})
    );
    assert!(!f.root.join("opaque").exists());
}

#[test]
fn completed_scope_or_policy_change_is_refused_without_writes() {
    let f = Fixture::new();
    f.initialize();
    let before = tree(&f.root);
    for flag in ["--provider", "--workspace"] {
        let mut args = f.args("init");
        let at = args.iter().position(|v| v == flag).unwrap();
        args[at + 1] = "different".into();
        run(f.command().args(args)).fail(Some("STATE_CORRUPT"), false);
        assert_eq!(tree(&f.root), before);
    }
    let mut p = policy();
    p["total"]["slots"] = json!(11);
    fs::write(&f.policy, serde_json::to_vec(&p).unwrap()).unwrap();
    f.invoke("init").fail(Some("STATE_CORRUPT"), false);
    assert_eq!(tree(&f.root), before);
}

#[test]
fn missing_or_corrupt_managed_authority_never_recreates_identity_or_pool() {
    for name in [
        "n2/auth-identity",
        JOURNAL,
        RECEIPT,
        "task-api.toml",
        "data/n3/tasks/acceptance-v1.json",
        "data/n3/tasks/capacity-initialized-v1",
        "data/n3/tasks/task-runtime-v1.json",
        "data/n3/tasks/capacity-owner.lock",
    ] {
        let f = Fixture::new();
        f.initialize();
        let path = if name == "n2/auth-identity" {
            identity_path(&f.root)
        } else {
            f.root.join(name)
        };
        fs::remove_file(path).unwrap();
        let before = tree(&f.root);
        f.invoke("check").fail(Some("STATE_CORRUPT"), false);
        f.invoke("init").fail(Some("STATE_CORRUPT"), false);
        assert_eq!(tree(&f.root), before);
    }
    for name in [JOURNAL, RECEIPT, "data/n3/tasks/acceptance-v1.json"] {
        let f = Fixture::new();
        f.initialize();
        fs::write(f.root.join(name), b"corrupt\n").unwrap();
        let before = tree(&f.root);
        f.invoke("check").fail(Some("STATE_CORRUPT"), false);
        f.invoke("init").fail(Some("STATE_CORRUPT"), false);
        assert_eq!(tree(&f.root), before);
    }
}

#[test]
fn original_identity_bytes_inode_permissions_and_public_key_are_protected() {
    for fault in ["public_key", "inode", "permissions", "symlink", "hardlink"] {
        let f = Fixture::new();
        f.initialize();
        let path = identity_path(&f.root);
        match fault {
            "public_key" => {
                let mut record: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                record["public_key_hex"] = json!("00".repeat(32));
                fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            }
            "inode" => {
                let bytes = fs::read(&path).unwrap();
                fs::rename(&path, f.base.join("original-identity")).unwrap();
                private_write(&path, &bytes);
            }
            "permissions" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                let original = f.base.join("original-identity");
                fs::rename(&path, &original).unwrap();
                symlink(original, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, f.base.join("identity-alias")).unwrap(),
            _ => unreachable!(),
        }
        let before = tree(&f.base);
        f.invoke("check").fail(Some("STATE_CORRUPT"), false);
        f.invoke("init").fail(Some("STATE_CORRUPT"), false);
        assert_eq!(tree(&f.base), before);
    }
}

#[test]
fn root_and_fixed_lock_inode_replacement_refuse_same_bytes() {
    for name in [INIT_LOCK, "data/n3/tasks/capacity-owner.lock"] {
        let f = Fixture::new();
        f.initialize();
        let path = f.root.join(name);
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, f.base.join("original-lock")).unwrap();
        private_write(&path, &bytes);
        let before = tree(&f.base);
        f.invoke("check").fail(Some("STATE_CORRUPT"), false);
        f.invoke("init").fail(Some("STATE_CORRUPT"), false);
        assert_eq!(tree(&f.base), before);
    }
    let f = Fixture::new();
    f.initialize();
    let original = f.base.join("original-root");
    fs::rename(&f.root, &original).unwrap();
    assert!(
        Command::new("cp")
            .args(["-a"])
            .arg(&original)
            .arg(&f.root)
            .status()
            .unwrap()
            .success()
    );
    let before = tree(&f.base);
    f.invoke("check").fail(Some("STATE_CORRUPT"), false);
    f.invoke("init").fail(Some("STATE_CORRUPT"), false);
    assert_eq!(tree(&f.base), before);
}

#[test]
fn pristine_checks_and_legacy_enrollment_never_create_authority() {
    let f = Fixture::new();
    let before = tree(&f.base);
    f.invoke("check").fail(Some("STATE_CORRUPT"), false);
    assert_eq!(tree(&f.base), before);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(f.root.join("n2"))
        .unwrap();
    private_write(
        &f.root.join("n2/operator-existing-record"),
        b"legacy-node-evidence",
    );
    let original = fs::read(f.root.join("n2/operator-existing-record")).unwrap();
    f.invoke("init").fail(Some("STATE_CORRUPT"), false);
    assert_eq!(
        fs::read(f.root.join("n2/operator-existing-record")).unwrap(),
        original
    );
    assert!(!identity_path(&f.root).exists());
    assert!(!f.root.join("data").exists());
    assert!(!f.root.join(RECEIPT).exists());
}

#[test]
fn fresh_root_bad_permissions_symlink_ancestors_and_unsafe_daemon_config_refuse() {
    for fault in [
        "root_permissions",
        "root_symlink",
        "ancestor_symlink",
        "tun",
        "config",
    ] {
        let mut f = Fixture::new();
        match fault {
            "root_permissions" => {
                fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap()
            }
            "root_symlink" => {
                let original = f.base.join("original-root");
                fs::rename(&f.root, &original).unwrap();
                symlink(original, &f.root).unwrap();
            }
            "ancestor_symlink" => {
                let original = f.base.join("real-parent");
                fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
                fs::rename(&f.root, original.join("provider")).unwrap();
                let alias = f.base.join("alias-parent");
                symlink(&original, &alias).unwrap();
                f.root = alias.join("provider");
            }
            "tun" => fs::write(f.root.join("daemon.toml"), b"[tun]\nenabled=true\n").unwrap(),
            "config" => fs::write(f.root.join("daemon.toml"), b"this is not toml\n").unwrap(),
            _ => unreachable!(),
        }
        let before = tree(&f.base);
        f.invoke("init").fail(None, false);
        assert_eq!(tree(&f.base), before);
    }
}

#[test]
fn no_daemon_config_allows_offline_init_without_creating_a_runtime_token() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("daemon.toml")).unwrap();
    f.initialize();
    f.invoke("check").pass("check");
    assert!(!f.root.join("daemon.toml").exists());
    assert!(!f.root.join("localapi.token").exists());
    let before = tree(&f.root);
    let boot = run(f.command().arg(&f.root));
    assert_ne!(boot.code, 0);
    assert!(!boot.ready);
    assert_eq!(tree(&f.root), before);
}

struct HeldLease {
    child: Child,
}
impl HeldLease {
    fn acquire(path: &Path) -> Self {
        let script = "import fcntl,sys; f=open(sys.argv[1],'rb'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('READY',flush=True); sys.stdin.read()";
        let mut child = Command::new("python3")
            .args(["-c", script])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let lease = Self { child };
        assert_eq!(ready.trim(), "READY");
        lease
    }
}
impl Drop for HeldLease {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn busy_init_lease_refuses_nonblocking_while_check_remains_readonly() {
    let f = Fixture::new();
    f.initialize();
    let before = tree(&f.root);
    let _lease = HeldLease::acquire(&f.root.join(INIT_LOCK));
    f.invoke("init").fail(Some("CAPACITY_UNAVAILABLE"), true);
    f.invoke("check").pass("check");
    assert_eq!(tree(&f.root), before);
}

#[test]
fn busy_original_acceptance_lock_never_certifies_a_mixed_snapshot_or_writes_state() {
    let f = Fixture::new();
    f.initialize();
    let before = tree(&f.root);
    let _lease = HeldLease::acquire(&f.root.join("data/n3/tasks/acceptance.lock"));
    f.invoke("check").fail(Some("CAPACITY_UNAVAILABLE"), true);
    f.invoke("init").fail(Some("CAPACITY_UNAVAILABLE"), true);
    assert_eq!(tree(&f.root), before);
}

#[test]
fn damaged_identity_blocks_config_folder_and_serve_before_identity_ensure_or_token_creation() {
    let f = Fixture::new();
    f.initialize();
    fs::remove_file(identity_path(&f.root)).unwrap();
    let before = tree(&f.root);
    let boot = run(f.command().arg(&f.root));
    assert_ne!(boot.code, 0);
    assert!(!boot.ready);
    assert_eq!(tree(&f.root), before);
    let served =
        run(f
            .command()
            .env("NEXUS_CONFIG_DIR", &f.root)
            .args(["serve", "--addr", "127.0.0.1:0"]));
    assert_ne!(served.code, 0);
    assert!(!served.ready);
    assert_eq!(tree(&f.root), before);
    assert!(!f.root.join("localapi.token").exists());
}

#[test]
fn missing_top_level_markers_keep_sentinel_managed_and_boot_fails_before_writes() {
    let f = Fixture::new();
    f.initialize();
    for name in [INIT_LOCK, JOURNAL, RECEIPT] {
        fs::remove_file(f.root.join(name)).unwrap();
    }
    assert_eq!(
        fs::read(f.root.join("data/n3/tasks/capacity-owner.lock")).unwrap(),
        b"n3-provider-init-v1-required\n"
    );
    let before = tree(&f.root);
    f.invoke("check").fail(Some("STATE_CORRUPT"), false);
    f.invoke("init").fail(Some("STATE_CORRUPT"), false);
    let boot = run(f.command().arg(&f.root));
    assert_ne!(boot.code, 0);
    assert!(!boot.ready);
    assert_eq!(tree(&f.root), before);
}

// External observation stops and kills the real process on a naturally published
// journal. No product pause/fault injection or fixture authority is used.
const KILL_CHECKPOINT: &str = r#"
import ctypes,json,os,select,signal,subprocess,sys,time
root,binary,policy,mode=sys.argv[1:]
libc=ctypes.CDLL(None,use_errno=True)
fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
if fd<0 or libc.inotify_add_watch(fd,os.fsencode(root),0x8|0x80)<0:
    raise RuntimeError('inotify unavailable')
signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
child=subprocess.Popen([binary,'task-provider','init','--config',root,'--provider','binary-provider','--workspace','binary-workspace','--capacity',policy,'--json'],stdout=subprocess.PIPE if mode=='io' else subprocess.DEVNULL,stderr=subprocess.DEVNULL,restore_signals=False)
captured=False
business=None
qualified=('scope',) if mode=='kill' else ('directories','identity','capacity','scope')
try:
    deadline=time.monotonic()+5
    while time.monotonic()<deadline and child.poll() is None:
        select.select([fd],[],[],0.02)
        try: os.read(fd,65536)
        except BlockingIOError: continue
        try:
            with open(root+'/task-provider-init-v1.json') as stream: journal=json.load(stream)
        except (OSError,ValueError): continue
        phase=journal.get('phase',journal.get('payload',{}).get('phase'))
        if phase in qualified:
            os.kill(child.pid,signal.SIGSTOP)
            until=time.monotonic()+1
            while time.monotonic()<until:
                with open('/proc/'+str(child.pid)+'/status') as stream: status=stream.read()
                if '\nState:\tT' in status: break
                time.sleep(0.001)
            else: raise RuntimeError('child did not stop')
            with open(root+'/task-provider-init-v1.json') as stream: journal=json.load(stream)
            phase=journal.get('phase',journal.get('payload',{}).get('phase'))
            captured=phase in qualified
            break
    if captured and mode=='io':
        class Limit(ctypes.Structure):
            _fields_=[('current',ctypes.c_ulonglong),('maximum',ctypes.c_ulonglong)]
        limit=Limit(1,1)
        if libc.prlimit64(child.pid,1,ctypes.byref(limit),None)!=0:
            raise RuntimeError('child file limit unavailable')
        os.kill(child.pid,signal.SIGCONT)
        output,_=child.communicate(timeout=5)
        business=json.loads(output)
finally:
    if child.poll() is None: os.kill(child.pid,signal.SIGKILL)
    code=child.wait(timeout=5)
    os.close(fd)
print(json.dumps({'captured':captured,'phase':phase if captured else None,'killed':code == -signal.SIGKILL,'business_exit_code':code,'business':business}))
"#;

fn identity_digests(root: &Path) -> Vec<String> {
    let mut digests = Vec::new();
    for path in tree(root).keys() {
        let path = root.join(path);
        if fs::symlink_metadata(&path).unwrap().is_file() {
            let bytes = fs::read(&path).unwrap();
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                if value.get("seed_hex").is_some() && value.get("public_key_hex").is_some() {
                    digests.push(sha256(&bytes).as_str().to_owned());
                }
            }
        }
    }
    digests.sort();
    digests.dedup();
    digests
}

#[test]
fn sigkill_at_original_natural_checkpoint_resumes_same_identity_and_pending_check_is_readonly() {
    let f = Fixture::new();
    let mut watcher = Command::new("python3");
    watcher
        .args(["-c", KILL_CHECKPOINT])
        .arg(&f.root)
        .arg(BINARY)
        .arg(&f.policy)
        .arg("kill")
        .env("NEXUS_CONFIG_DIR", &f.decoy)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", f.root.join("localapi.token"));
    let interrupted = run(&mut watcher);
    assert_eq!(interrupted.code, 0);
    assert_eq!(
        interrupted.json["captured"], true,
        "no qualified natural checkpoint captured"
    );
    assert_eq!(interrupted.json["killed"], true);
    let original = identity_digests(&f.root);
    assert_eq!(
        original.len(),
        1,
        "original private staged/published identity must exist"
    );
    let before = tree(&f.root);
    f.invoke("check").fail(Some("STATE_CORRUPT"), false);
    let boot = run(f.command().arg(&f.root));
    assert_ne!(boot.code, 0);
    assert!(!boot.ready);
    assert_eq!(tree(&f.root), before);
    let resumed = f.invoke("init");
    resumed.pass("init");
    assert_eq!(resumed.json["changed"], true);
    assert_eq!(
        sha256(&fs::read(identity_path(&f.root)).unwrap()).as_str(),
        original[0]
    );
    f.invoke("check").pass("check");
    let complete = tree(&f.root);
    let repeated = f.invoke("init");
    repeated.pass("init");
    assert_eq!(repeated.json["changed"], false);
    assert_eq!(tree(&f.root), complete);
}

#[test]
fn actual_file_limit_error_after_publication_reports_phase_and_possible_applied_mutation() {
    let f = Fixture::new();
    let mut watcher = Command::new("python3");
    watcher
        .args(["-c", KILL_CHECKPOINT])
        .arg(&f.root)
        .arg(BINARY)
        .arg(&f.policy)
        .arg("io")
        .env("NEXUS_CONFIG_DIR", &f.decoy)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", f.root.join("localapi.token"));
    let observed = run(&mut watcher);
    assert_eq!(observed.code, 0);
    assert_eq!(
        observed.json["captured"], true,
        "no qualified publication checkpoint captured"
    );
    assert_eq!(observed.json["business_exit_code"], 0);
    let business = &observed.json["business"];
    assert_eq!(business["schema_version"], 1);
    assert_eq!(business["verdict"], "FAIL");
    assert_eq!(business["error"]["code"], "PERSISTENCE_FAILED");
    assert!(business["phase"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(business["mutation_may_have_applied"], true);
    assert_ne!(business["initialized"], true);
    let before = tree(&f.root);
    f.invoke("check").fail(Some("STATE_CORRUPT"), false);
    assert_eq!(tree(&f.root), before);
}

// Independent resource pressure on the real child, including failures after
// create_new published the first anchor but before its directory sync succeeds.
const FILE_DESCRIPTOR_LIMIT: &str = r#"
import json,resource,subprocess,sys
binary,limit,*arguments=sys.argv[1:]
def constrain(): resource.setrlimit(resource.RLIMIT_NOFILE,(int(limit),int(limit)))
child=subprocess.Popen([binary,*arguments],stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=constrain)
try:
    output,_=child.communicate(timeout=5)
    business=json.loads(output)
finally:
    if child.poll() is None: child.kill()
    child.wait(timeout=5)
print(json.dumps({'business_exit_code':child.returncode,'business':business}))
"#;

#[test]
fn actual_descriptor_exhaustion_preserves_anchors_and_reports_applied_mutation() {
    let mut before_anchor = 0;
    let mut after_anchor = 0;
    // Root::open holds ancestor directory descriptors. Calibrate a bounded
    // sweep to this fixture depth instead of assuming a host-specific fd count.
    let probe = Fixture::new();
    let ancestors = probe.root.ancestors().count();
    drop(probe);
    for limit in ancestors + 3..=ancestors + 7 {
        let f = Fixture::new();
        // Exercise valid offline init so unrelated config-loader descriptors
        // cannot mask the first-anchor publication failure.
        fs::remove_file(f.root.join("daemon.toml")).unwrap();
        let before = tree(&f.root);
        let original_policy = tree(&f.base)
            .remove(&PathBuf::from("capacity.json"))
            .unwrap();
        let mut limiter = Command::new("python3");
        limiter
            .args(["-c", FILE_DESCRIPTOR_LIMIT, BINARY])
            .arg(limit.to_string())
            .args(f.args("init"))
            .env("NEXUS_CONFIG_DIR", &f.decoy)
            .env("NEXUS_LOCALAPI_TOKEN_FILE", f.root.join("localapi.token"));
        let observed = run(&mut limiter);
        assert_eq!(observed.code, 0, "resource-pressure observer must complete");
        assert_eq!(observed.json["business_exit_code"], 0);
        let business = &observed.json["business"];
        assert_eq!(business["schema_version"], 1);
        assert_eq!(business["verdict"], "FAIL");
        assert_eq!(business["error"]["code"], "PERSISTENCE_FAILED");
        assert_eq!(business["error"]["retryable"], true);
        assert_ne!(business["initialized"], true);
        let after = tree(&f.root);
        let published = after.keys().any(|path| !before.contains_key(path));
        if published {
            after_anchor += 1;
            assert_eq!(business["mutation_may_have_applied"], true);
            assert_ne!(business["phase"], "preflight");
            assert!(business["phase"].as_str().is_some_and(|p| !p.is_empty()));
            assert!(f.root.join(INIT_LOCK).is_file());
            // Failed publication retains evidence and existing operator files.
            for (path, entry) in &before {
                if entry.digest.is_some() {
                    assert_eq!(after.get(path), Some(entry));
                }
            }
        } else {
            before_anchor += 1;
            assert_eq!(business["mutation_may_have_applied"], false);
            assert_eq!(business["phase"], "preflight");
            assert_eq!(after, before);
        }
        assert_eq!(
            tree(&f.base).get(&PathBuf::from("capacity.json")),
            Some(&original_policy)
        );
        let retained = tree(&f.root);
        f.invoke("check").fail(Some("STATE_CORRUPT"), false);
        assert_eq!(tree(&f.root), retained);
        assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
    }
    assert!(
        before_anchor > 0,
        "must observe a real failure before creation"
    );
    assert!(
        after_anchor > 0,
        "must observe a real failure after creation"
    );
}

fn coupled_identity_checkpoint(f: &Fixture) {
    f.initialize();
    // Explicit review-negative fixture: preserve genuine CLI-produced identity,
    // root/directory/lease bindings and capacity image, then independently model
    // the durable image published before the journal advances to capacity.
    // This is not a normal E4 fixture and does not manufacture identity seeds.
    let path = f.root.join(JOURNAL);
    let mut journal: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let payload = journal.get_mut("payload").unwrap();
    payload["phase"] = json!("identity");
    for field in ["owner", "acceptance_lock", "scope"] {
        payload[field] = Value::Null;
    }
    journal["checksum"] = json!(sha256(&serde_json::to_vec(&payload).unwrap()).as_str());
    fs::write(path, serde_json::to_vec(&journal).unwrap()).unwrap();
    fs::remove_file(f.root.join(RECEIPT)).unwrap();
    fs::remove_file(f.root.join("task-api.toml")).unwrap();
}

fn missing_coupled_lock_refuses_without_writes(name: &str) {
    let f = Fixture::new();
    coupled_identity_checkpoint(&f);
    fs::remove_file(f.root.join("data/n3/tasks").join(name)).unwrap();
    let before = tree(&f.root);
    let refused = f.invoke("init");
    assert_eq!(tree(&f.root), before);
    refused.fail(Some("STATE_CORRUPT"), false);
    assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
}

#[test]
fn published_coupled_capacity_missing_owner_never_recreates_lock() {
    missing_coupled_lock_refuses_without_writes("capacity-owner.lock");
}

#[test]
fn published_coupled_capacity_missing_acceptance_lock_never_recreates_lock() {
    missing_coupled_lock_refuses_without_writes("acceptance.lock");
}

#[test]
fn complete_coupled_capacity_resumes_original_inodes_and_identity_without_reprovisioning() {
    let f = Fixture::new();
    coupled_identity_checkpoint(&f);
    let owner = f.root.join("data/n3/tasks/capacity-owner.lock");
    // The normal capacity publication precedes writing the N3 init sentinel.
    // Preserve the original authority-bound inode while modelling that window.
    fs::write(&owner, b"").unwrap();
    let before = tree(&f.root);
    let identity = before.get(
        &identity_path(&f.root)
            .strip_prefix(&f.root)
            .unwrap()
            .to_owned(),
    );
    let resumed = f.invoke("init");
    resumed.pass("init");
    assert_eq!(resumed.json["changed"], true);
    let after = tree(&f.root);
    assert_eq!(
        after.get(
            &identity_path(&f.root)
                .strip_prefix(&f.root)
                .unwrap()
                .to_owned()
        ),
        identity
    );
    for name in [
        "acceptance-v1.json",
        "capacity-initialized-v1",
        "task-runtime-v1.json",
        "acceptance.lock",
    ] {
        let path = PathBuf::from("data/n3/tasks").join(name);
        assert_eq!(after.get(&path), before.get(&path));
    }
    let owner_key = PathBuf::from("data/n3/tasks/capacity-owner.lock");
    let old_owner = before.get(&owner_key).unwrap();
    let new_owner = after.get(&owner_key).unwrap();
    assert_eq!(new_owner.device, old_owner.device);
    assert_eq!(new_owner.inode, old_owner.inode);
    assert_eq!(new_owner.mode, old_owner.mode);
    assert_eq!(new_owner.links, old_owner.links);
    assert_eq!(fs::read(owner).unwrap(), b"n3-provider-init-v1-required\n");
    f.invoke("check").pass("check");
    let complete = tree(&f.root);
    let repeated = f.invoke("init");
    repeated.pass("init");
    assert_eq!(repeated.json["changed"], false);
    assert_eq!(tree(&f.root), complete);
}
