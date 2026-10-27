#![allow(dead_code)]
use nexus_control_api::task::{CanonicalDto, TaskEnvelope, TaskRequest};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::JoinHandle,
    time::Duration,
};
pub const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub struct Dir(pub PathBuf);
impl Dir {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "n36-localapi-{}",
            nexus::n3_acceptance::new_task_id().unwrap().as_str()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub struct Daemon {
    pub child: Child,
    pub addr: String,
    reader: Option<JoinHandle<()>>,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
pub fn spawn(exe: &Path, config: &Path, bind: &str) -> Daemon {
    let token = config.join("localapi.token");
    fs::write(&token, TOKEN.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut child = Command::new(exe)
        .arg("serve")
        .arg(format!("--addr={bind}"))
        .env("NEXUS_CONFIG_DIR", config)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", &token)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        while let Some(Ok(line)) = lines.next() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(addr) = value["daemon"]["addr"].as_str() {
                    let _ = tx.send(addr.to_owned());
                    break;
                }
            }
        }
    });
    let mut guard = Daemon {
        child,
        addr: String::new(),
        reader: Some(reader),
    };
    guard.addr = rx
        .recv_timeout(Duration::from_secs(12))
        .expect("bounded daemon READY");
    guard
}
pub fn exchange(addr: &str, raw: &[u8], half_close: bool) -> (u16, TaskEnvelope) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(7)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(raw).unwrap();
    if half_close {
        // An early refusal writes the full response and closes with the request
        // body unread, so the kernel may RST before this half-close (ENOTCONN);
        // the response is still read and checked in full below.
        if let Err(e) = stream.shutdown(std::net::Shutdown::Write) {
            assert_eq!(e.kind(), std::io::ErrorKind::NotConnected, "{e}");
        }
    }
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let count = stream
            .read(&mut chunk)
            .expect("response before complete Content-Length");
        assert_ne!(count, 0, "truncated response");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
            let header = std::str::from_utf8(&bytes[..end]).unwrap();
            let size: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert!(size <= 2_097_152);
            if bytes.len() >= end + 4 + size {
                assert_eq!(bytes.len(), end + 4 + size);
                break;
            }
        }
    }
    let end = bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .expect("HTTP headers");
    let status = std::str::from_utf8(&bytes[..end])
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let response = nexus::n3_acceptance::decode_dto(&bytes[end + 4..]).unwrap();
    (status, response)
}
pub fn request(addr: &str, request: TaskRequest) -> (u16, TaskEnvelope) {
    let bytes = request.to_value().canonical_bytes();
    let mut raw = format!("POST /localapi/v1/task HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", bytes.len()).into_bytes();
    raw.extend(bytes);
    exchange(addr, &raw, false)
}
pub fn is_error(
    response: &(u16, TaskEnvelope),
    status: u16,
    code: nexus_domain::task::TaskErrorCode,
) -> bool {
    response.0 == status
        && matches!(&response.1, TaskEnvelope::Error { error, .. } if error.code == code)
}
pub fn boundary(exe: &Path) -> serde_json::Value {
    use nexus_domain::task::{TaskErrorCode, TaskId};
    let dir = Dir::new();
    let daemon = spawn(exe, &dir.0, "127.0.0.1:0");
    let unauthorized = exchange(&daemon.addr, b"POST /localapi/v1/task HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n", false);
    let version = r#"{"schema_version":2,"operation":"GetTask","task_id":"unknown"}"#;
    let unknown = format!(
        "POST /localapi/v1/task HTTP/1.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{version}",
        version.len()
    );
    let unknown_version = exchange(&daemon.addr, unknown.as_bytes(), false);
    let oversize = format!(
        "POST /localapi/v1/task HTTP/1.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 1048577\r\n\r\n"
    );
    let oversize = exchange(&daemon.addr, oversize.as_bytes(), false);
    let ambiguous = format!(
        "POST /localapi/v1/task HTTP/1.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{{}}"
    );
    let ambiguous = exchange(&daemon.addr, ambiguous.as_bytes(), false);
    let disabled = request(
        &daemon.addr,
        TaskRequest::Get {
            task_id: TaskId::new("unknown".into()).unwrap(),
        },
    );
    let mut result = serde_json::json!({"unauthorized_denied":is_error(&unauthorized,401,TaskErrorCode::AuthDenied),"unknown_version_rejected":is_error(&unknown_version,400,TaskErrorCode::InvalidRequest),"oversize_rejected":is_error(&oversize,413,TaskErrorCode::CapacityUnavailable),"ambiguous_framing_rejected":is_error(&ambiguous,400,TaskErrorCode::InvalidRequest),"disabled_service_explicit":is_error(&disabled,200,TaskErrorCode::UnsupportedCapability),"acceptance_unchanged":!dir.0.join("data/n3/tasks").exists(),"scope":"LocalAPI protocol/capability boundary only; not complete N3"});
    let pass = [
        "unauthorized_denied",
        "unknown_version_rejected",
        "oversize_rejected",
        "ambiguous_framing_rejected",
        "disabled_service_explicit",
        "acceptance_unchanged",
    ]
    .iter()
    .all(|key| result[key] == true);
    result["verdict"] = if pass { "PASS" } else { "FAIL" }.into();
    result
}

#[cfg(target_os = "linux")]
pub struct ProviderFixture {
    pub dir: Dir,
    pub id: nexus_domain::task::TaskId,
    pub request: nexus_domain::task::SubmitTaskRequest,
    pub principal: String,
}
#[cfg(target_os = "linux")]
impl ProviderFixture {
    pub fn new() -> Self {
        use nexus_compute::task::{AcceptanceContext, TaskOwner};
        let dir = Dir::new();
        let mut request: nexus_domain::task::SubmitTaskRequest = nexus::n3_acceptance::decode_dto(
            include_bytes!("../../../docs/contracts/n3-submit.example.json"),
        )
        .unwrap();
        fs::write(
            dir.0.join("task-api.toml"),
            format!(
                "provider = {:?}\nworkspace = {:?}\n",
                request.provider, request.workspace
            ),
        )
        .unwrap();
        let principal = nexus::task_authorization::authenticated_principal(&dir.0).unwrap();
        let root = dir.0.join("data/n3/tasks");
        // Provision only through the original test-origin persistence adapter.
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root.parent().unwrap())
            .unwrap();
        let snapshots = nexusd::snapshot_store::FileSnapshotStore::open(&root).unwrap();
        let mut workspace = nexus_workspace::Workspace::init(
            nexus_workspace::WorkspaceId(request.workspace.clone()),
            nexus_storage::InMemoryContentStore::new(),
            nexus_workspace::AuthorId("test".into()),
        )
        .unwrap();
        let base = workspace.heads().heads[0].clone();
        let commit = workspace
            .commit_changes(
                &base,
                &[nexus_workspace::Change {
                    path: "input.txt".into(),
                    content: b"fixed input".to_vec(),
                }],
            )
            .unwrap();
        request.input_snapshot = snapshots
            .stage_snapshot(
                &workspace,
                &commit,
                &nexus_workspace::snapshot::SnapshotSelection {
                    include: vec![".".into()],
                    exclude: vec![],
                    executable: vec![],
                },
            )
            .unwrap()
            .reference;
        let owner = TaskOwner::new(
            nexusd::task_store::FileTaskAcceptanceStore::open(&root).unwrap(),
            nexus::n3_acceptance::sha256,
            nexus::n3_acceptance::new_task_id,
        );
        let now = nexus::n2_store::now_unix_pub();
        let accepted = owner
            .accept_verified(
                request.clone(),
                AcceptanceContext {
                    authenticated_principal: principal.clone(),
                    provider: request.provider.clone(),
                    environment_evidence: request.environment.clone(),
                    capacity_reservation_id: "explicit-test-fixture-not-service-reservation".into(),
                    now_unix: now,
                    prepare_deadline_unix: now + 60,
                    delivery_deadline_unix: now + 600,
                },
            )
            .unwrap();
        let fixture = Self {
            dir,
            id: accepted.task.view.task_id,
            request,
            principal,
        };
        fixture.grant(false);
        fixture
    }
    pub fn grant(&self, revoked: bool) {
        let key = format!(
            "n2/grant/{}/{}/{}",
            self.request.workspace, self.request.resource, self.principal
        );
        let grant = serde_json::json!({"workspace":self.request.workspace,"name":self.request.resource,"principal":self.principal,"operations":["use"],"not_after":null,"revoked":revoked});
        nexus::n2_store::N2Store::open(&self.dir.0)
            .unwrap()
            .kv()
            .put(&key, &serde_json::to_vec(&grant).unwrap())
            .unwrap();
    }
}
