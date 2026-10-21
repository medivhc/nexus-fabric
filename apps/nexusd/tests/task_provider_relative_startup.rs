#![cfg(target_os = "linux")]

use nexus::n3_acceptance::sha256;
use nexus_control_api::task::{CanonicalDto, TaskId, TaskRequest};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::TcpStream,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const BINARY: &str = env!("CARGO_BIN_EXE_nexusd");
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    decoy: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "n311-relative-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let root = base.join("nested/provider");
        let decoy = base.join("decoy");
        for path in [base.join("nested"), root.clone(), decoy.clone()] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        private_write(
            &root.join("daemon.toml"),
            b"localapi_addr = \"127.0.0.1:0\"\n[tun]\nenabled = false\n",
        );
        Self { base, root, decoy }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(BINARY);
        command.env("NEXUS_CONFIG_DIR", &self.decoy).env(
            "NEXUS_LOCALAPI_TOKEN_FILE",
            self.root.join("localapi.token"),
        );
        command
    }
    fn initialize(&self) -> Value {
        let policy = json!({
            "total":{"cpu_millis":10000,"memory_bytes":2147483648u64,"pids":2000,"runtime_storage_bytes":268435456,"backend_disk_bytes":2147483648u64,"slots":10},
            "fixed":{"cpu_millis":100,"memory_bytes":16777216,"pids":4,"runtime_storage_bytes":4096,"backend_disk_bytes":16777216,"slots":1},
            "overhead":{"cpu_millis":10,"memory_bytes":8388608,"pids":2,"backend_disk_bytes":1048576}
        });
        let path = self.base.join("capacity.json");
        private_write(&path, &serde_json::to_vec(&policy).unwrap());
        let mut child = Process::spawn(
            self.command()
                .args(["task-provider", "init", "--config"])
                .arg(&self.root)
                .args([
                    "--provider",
                    "relative-provider",
                    "--workspace",
                    "relative-workspace",
                    "--capacity",
                ])
                .arg(path)
                .arg("--json"),
            &self.base,
        );
        assert_eq!(child.wait(), 0);
        let reply = serde_json::from_slice::<Value>(&child.stdout()).unwrap();
        assert_eq!(reply["verdict"], "PASS");
        assert_eq!(reply["changed"], true);
        reply
    }
    fn identity(&self) -> PathBuf {
        self.root
            .join("n2")
            .join(nexus_storage::FileKvStore::file_name_for("n2/auth-identity").unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

// File-backed child output avoids pipe deadlocks. Every exit path reaps the
// actual daemon, including assertions and READY/deadline failures.
struct Process {
    child: Child,
    out: PathBuf,
    err: PathBuf,
}
impl Process {
    fn spawn(command: &mut Command, base: &Path) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let out = base.join(format!("stdout-{sequence}"));
        let err = base.join(format!("stderr-{sequence}"));
        let open = |path: &Path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap()
        };
        let child = command
            .stdout(Stdio::from(open(&out)))
            .stderr(Stdio::from(open(&err)))
            .spawn()
            .unwrap();
        Self { child, out, err }
    }
    fn read(path: &Path) -> Vec<u8> {
        let metadata = fs::metadata(path).unwrap();
        assert!(
            metadata.len() <= 1024 * 1024,
            "bounded child output exceeded"
        );
        let bytes = fs::read(path).unwrap();
        // Never print identity records or bearer material on test failures.
        for field in [b"seed_hex".as_slice(), b"public_key_hex".as_slice()] {
            assert!(!bytes.windows(field.len()).any(|v| v == field));
        }
        bytes
    }
    fn stdout(&self) -> Vec<u8> {
        Self::read(&self.out)
    }
    fn stderr(&self) -> Vec<u8> {
        Self::read(&self.err)
    }
    fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(Instant::now() < deadline, "child exit deadline exceeded");
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn ready(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            for value in self
                .stdout()
                .split(|b| *b == b'\n')
                .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            {
                if value["verdict"] == "READY" {
                    return value["daemon"]["localapi"]
                        .as_str()
                        .or_else(|| value["daemon"]["addr"].as_str())
                        .unwrap()
                        .to_owned();
                }
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "daemon exited before READY"
            );
            assert!(Instant::now() < deadline, "daemon READY deadline exceeded");
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn shutdown(&mut self) {
        self.terminate(0);
    }
    fn terminate(&mut self, expected_code: i32) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(self.wait(), expected_code);
        assert!(self.child.try_wait().unwrap().is_some());
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http(addr: &str, token: &str, body: Option<&[u8]>) -> Value {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (method, path) = if body.is_some() {
        ("POST", "/localapi/v1/task")
    } else {
        ("GET", "/localapi/v0/n2/session/list")
    };
    let body = body.unwrap_or_default();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream
        .take(1024 * 1024 + 1)
        .read_to_end(&mut response)
        .unwrap();
    assert!(response.len() <= 1024 * 1024);
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    let split = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    serde_json::from_slice(&response[split + 4..]).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    content: Option<String>,
}
fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        let meta = fs::symlink_metadata(path).unwrap();
        let content = if meta.is_file() {
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
                content,
            },
        );
        if meta.is_dir() {
            for child in fs::read_dir(path).unwrap() {
                walk(root, &child.unwrap().path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries);
    entries
}

#[test]
fn managed_dot_and_nested_relative_startup_share_original_authority_and_manager() {
    for dot in [true, false] {
        let f = Fixture::new();
        let initialized = f.initialize();
        let identity = tree(&f.root)[f.identity().strip_prefix(&f.root).unwrap()]
            .content
            .clone();
        let mut command = f.command();
        if dot {
            command.current_dir(&f.root).arg(".");
        } else {
            command.current_dir(&f.base).arg("nested/provider");
        }
        let mut daemon = Process::spawn(&mut command, &f.base);
        let addr = daemon.ready();
        let token = fs::read_to_string(f.root.join("localapi.token")).unwrap();
        let sessions = http(&addr, token.trim(), None);
        assert_eq!(sessions["verdict"], "PASS");
        assert_eq!(sessions["owner"], "daemon");
        let request = TaskRequest::Get {
            task_id: TaskId::new("relative-missing-task".to_owned()).unwrap(),
        }
        .to_value()
        .canonical_bytes();
        let reply = http(&addr, token.trim(), Some(&request));
        assert_eq!(reply["error"]["code"], "INVALID_REQUEST");
        assert_eq!(reply["error"]["reason"], "unknown accepted TaskId");
        assert_eq!(reply["error"]["retryable"], false);
        let authority: Value = serde_json::from_slice(
            &fs::read(f.root.join("data/n3/tasks/acceptance-v1.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(authority["capacity"]["ready"], true);
        assert!(authority["capacity"]["epoch"].as_u64().unwrap() > 0);
        assert_eq!(
            tree(&f.root)[f.identity().strip_prefix(&f.root).unwrap()].content,
            identity
        );
        assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
        daemon.shutdown();
        assert_eq!(
            daemon
                .stderr()
                .windows(b"N2 SessionManager assembled".len())
                .filter(|bytes| *bytes == b"N2 SessionManager assembled")
                .count(),
            1
        );
        let mut checked = Process::spawn(
            f.command()
                .args(["task-provider", "check", "--config"])
                .arg(&f.root)
                .arg("--json"),
            &f.base,
        );
        assert_eq!(checked.wait(), 0);
        let reply: Value = serde_json::from_slice(&checked.stdout()).unwrap();
        assert_eq!(reply["verdict"], "PASS");
        assert_eq!(reply["scope"], initialized["scope"]);
        assert_eq!(reply["principal"], initialized["principal"]);
    }
}

#[test]
fn managed_serve_relative_environment_uses_original_identity_and_task_service() {
    let f = Fixture::new();
    let initialized = f.initialize();
    let identity = tree(&f.root)[f.identity().strip_prefix(&f.root).unwrap()]
        .content
        .clone();
    // Use the existing serve entry with a relative environment config root.
    // Token placement is derived from that same root, with no explicit override.
    let mut command = f.command();
    command
        .current_dir(&f.base)
        .env("NEXUS_CONFIG_DIR", "nested/provider")
        .env_remove("NEXUS_LOCALAPI_TOKEN_FILE")
        .args(["serve", "--addr", "127.0.0.1:0"]);
    let mut daemon = Process::spawn(&mut command, &f.base);
    let addr = daemon.ready();
    let token = fs::read_to_string(f.root.join("localapi.token")).unwrap();
    let sessions = http(&addr, token.trim(), None);
    assert_eq!(sessions["verdict"], "PASS");
    assert_eq!(sessions["owner"], "daemon");
    let request = TaskRequest::Get {
        task_id: TaskId::new("relative-serve-missing-task".to_owned()).unwrap(),
    }
    .to_value()
    .canonical_bytes();
    let reply = http(&addr, token.trim(), Some(&request));
    assert_eq!(
        reply["error"]["code"], "INVALID_REQUEST",
        "{}",
        reply["error"]["reason"]
    );
    assert_eq!(reply["error"]["reason"], "unknown accepted TaskId");
    assert_eq!(reply["error"]["retryable"], false);
    assert_eq!(
        tree(&f.root)[f.identity().strip_prefix(&f.root).unwrap()].content,
        identity
    );
    assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
    // Legacy serve uses the default SIGTERM action; its child is still reaped.
    daemon.terminate(-1);
    assert_eq!(
        daemon
            .stderr()
            .windows(b"N2 SessionManager assembled".len())
            .filter(|bytes| *bytes == b"N2 SessionManager assembled")
            .count(),
        1
    );
    let mut checked = Process::spawn(
        f.command()
            .args(["task-provider", "check", "--config"])
            .arg(&f.root)
            .arg("--json"),
        &f.base,
    );
    assert_eq!(checked.wait(), 0);
    let reply: Value = serde_json::from_slice(&checked.stdout()).unwrap();
    assert_eq!(reply["verdict"], "PASS");
    assert_eq!(reply["scope"], initialized["scope"]);
    assert_eq!(reply["principal"], initialized["principal"]);
}

#[test]
fn managed_relative_symlink_and_parent_paths_fail_before_startup_mutation() {
    for path in ["alias", "nested/../nested/provider"] {
        let f = Fixture::new();
        f.initialize();
        symlink(&f.root, f.base.join("alias")).unwrap();
        let before = tree(&f.root);
        let mut child = Process::spawn(f.command().current_dir(&f.base).arg(path), &f.base);
        assert_eq!(child.wait(), 1);
        assert!(
            !child
                .stdout()
                .split(|b| *b == b'\n')
                .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                .any(|v| v["verdict"] == "READY")
        );
        let failure = child
            .stderr()
            .split(|b| *b == b'\n')
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .find(|v| v["phase"] == "managed-provider-preflight")
            .unwrap();
        assert_eq!(failure["error"]["code"], "STATE_CORRUPT");
        assert_eq!(failure["mutation_may_have_applied"], false);
        assert_eq!(tree(&f.root), before);
        assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
    }
}

#[test]
fn unmanaged_relative_empty_root_keeps_legacy_subsystem_rejection() {
    let f = Fixture::new();
    let mut child = Process::spawn(f.command().current_dir(&f.root).arg("."), &f.base);
    assert_eq!(child.wait(), 1);
    assert!(
        !child
            .stdout()
            .split(|b| *b == b'\n')
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .any(|v| v["verdict"] == "READY")
    );
    let failure = child
        .stderr()
        .split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .find(|v| v["error"]["code"] == "CONFIG")
        .unwrap();
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("no subsystem configured:")
    );
    for name in [
        "task-provider-init.lock",
        "task-provider-init-v1.json",
        "task-provider-initialized-v1.json",
        "task-api.toml",
        "localapi.token",
        "data/n3",
    ] {
        assert!(!f.root.join(name).exists());
    }
    assert!(fs::read_dir(&f.decoy).unwrap().next().is_none());
}
