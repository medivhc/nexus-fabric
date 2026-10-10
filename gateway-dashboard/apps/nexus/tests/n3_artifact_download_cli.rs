//! Real CLI subprocess and framed loopback HTTP. These peers exercise receiver
//! composition; they do not stand in for the real-provider product scenario.
#![cfg(target_os = "linux")]
use nexus::n3_acceptance::{new_task_id, sha256};
use nexus_control_api::task::{CanonicalDto, TaskArtifactPage, TaskEnvelope, TaskResponse};
use nexus_domain::task::{
    ArtifactId, ArtifactRecord, PublicationState, TaskError, TaskErrorCode, TaskId,
};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("n39-cli-{}", new_task_id().unwrap().as_str()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("token"), "a".repeat(64)).unwrap();
        fs::set_permissions(root.join("token"), fs::Permissions::from_mode(0o600)).unwrap();
        Self(root)
    }
    fn output(&self) -> PathBuf {
        self.0.join("out")
    }
    fn receiver(&self) -> PathBuf {
        self.0.join(format!(
            ".nexus-artifact-{}",
            &sha256(self.output().as_os_str().as_encoded_bytes()).as_str()[7..]
        ))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn record(bytes: &[u8]) -> ArtifactRecord {
    ArtifactRecord {
        schema_version: 1,
        artifact_id: ArtifactId::new("artifact-test".into()).unwrap(),
        task_id: TaskId::new("task-test".into()).unwrap(),
        snapshot_id: sha256(b"snapshot"),
        environment_digest: sha256(b"environment"),
        producer_node: "provider".into(),
        workspace: "workspace".into(),
        owner_principal: "principal".into(),
        path: "result".into(),
        size_bytes: bytes.len() as u64,
        content_sha256: sha256(bytes),
        storage_ref: "private-locator".into(),
        created_at_unix: 100,
        retain_until_unix: 200,
        publication_state: PublicationState::Published,
    }
}
fn json(envelope: TaskEnvelope) -> Value {
    serde_json::from_slice(&envelope.to_value().canonical_bytes()).unwrap()
}
fn page(record: &ArtifactRecord, offset: u64, bytes: &[u8]) -> Value {
    let next_offset = offset + bytes.len() as u64;
    json(TaskEnvelope::Success(TaskResponse::Artifact(Box::new(
        TaskArtifactPage {
            record: record.clone(),
            offset,
            bytes: bytes.to_vec(),
            next_offset,
            eof: next_offset == record.size_bytes,
        },
    ))))
}
fn denied() -> Value {
    json(TaskEnvelope::Error {
        error: TaskError::new(TaskErrorCode::AuthDenied, "current Use revoked", false),
        task_id: None,
    })
}
struct Reply {
    offset: u64,
    value: Option<Value>,
}
fn reply(offset: u64, value: Value) -> Reply {
    Reply {
        offset,
        value: Some(value),
    }
}
fn interrupted(offset: u64) -> Reply {
    Reply {
        offset,
        value: None,
    }
}

/// Parse the real request within one absolute budget, rather than rely on a
/// possibly incomplete first socket read. A stopped child cannot strand this owner.
fn request(stream: &mut TcpStream) -> Value {
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16384);
        stream
            .set_read_timeout(Some(
                deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1)),
            ))
            .unwrap();
        stream.read_exact(&mut byte).unwrap();
        assert!(Instant::now() < deadline);
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    assert!(header.starts_with("POST /localapi/v1/task HTTP/1.1\r\n"));
    assert!(header.contains(&format!("Authorization: Bearer {}\r\n", "a".repeat(64))));
    let length: usize = header
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(length <= 1048576);
    let mut body = vec![0; length];
    stream
        .set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))
        .unwrap();
    stream.read_exact(&mut body).unwrap();
    assert!(Instant::now() < deadline);
    serde_json::from_slice(&body).unwrap()
}
struct Server {
    address: String,
    stop: Arc<AtomicBool>,
    owner: Option<thread::JoinHandle<Vec<u64>>>,
}
impl Server {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let owner = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut offsets = Vec::new();
            for reply in replies {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopped.load(Ordering::Relaxed) || Instant::now() >= deadline {
                                return offsets;
                            }
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("loopback accept: {e}"),
                    }
                };
                let request = request(&mut stream);
                assert_eq!(request["schema_version"], 1);
                assert_eq!(request["operation"], "GetArtifact");
                assert_eq!(request["artifact_id"], "artifact-test");
                assert_eq!(request["offset"], reply.offset);
                assert_eq!(request["max_bytes"], 65536);
                assert!(request.get("principal").is_none());
                assert!(request.get("output").is_none());
                offsets.push(reply.offset);
                if let Some(value) = reply.value {
                    let body = serde_json::to_vec(&value).unwrap();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
            offsets
        });
        Self {
            address,
            stop,
            owner: Some(owner),
        }
    }
    fn finish(mut self) -> Vec<u64> {
        self.stop.store(true, Ordering::Relaxed);
        self.owner.take().unwrap().join().unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}
fn cli(fixture: &Fixture, replies: Vec<Reply>) -> (Value, Vec<u64>) {
    let server = Server::start(replies);
    let expected = Instant::now() + Duration::from_secs(8);
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args([
            "--addr",
            &server.address,
            "--json",
            "artifact",
            "get",
            "artifact-test",
            "--output",
        ])
        .arg(fixture.output())
        .env("NEXUS_LOCALAPI_TOKEN_FILE", fixture.0.join("token"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= expected {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("download CLI timed out; killed and reaped");
        }
        thread::sleep(Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    let offsets = server.finish();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    (serde_json::from_slice(&output.stdout).unwrap(), offsets)
}
fn error(value: &Value, code: &str) {
    assert_eq!(value["error"]["code"], code, "{value}");
}
fn success(value: &Value, size: u64) {
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["verdict"], "PASS");
    // Check the stable wire response via its actual DTO, not guessed JSON nesting.
    let envelope: TaskEnvelope =
        nexus::n3_acceptance::decode_dto(&serde_json::to_vec(value).unwrap()).unwrap();
    let TaskEnvelope::Success(TaskResponse::Artifact(page)) = envelope else {
        panic!("{value}")
    };
    assert_eq!(page.offset, size);
    assert_eq!(page.next_offset, size);
    assert!(page.eof);
    assert!(page.bytes.is_empty());
}

#[test]
fn multipage_binary_download_and_published_replay_have_fresh_final_authorization() {
    let fixture = Fixture::new();
    let bytes: Vec<_> = (0..65553).map(|i| (i % 256) as u8).collect();
    let r = record(&bytes);
    let (value, offsets) = cli(
        &fixture,
        vec![
            reply(0, page(&r, 0, &bytes[..65536])),
            reply(65536, page(&r, 65536, &bytes[65536..])),
            reply(r.size_bytes, page(&r, r.size_bytes, b"")),
        ],
    );
    success(&value, r.size_bytes);
    assert_eq!(offsets, [0, 65536, r.size_bytes]);
    assert_eq!(fs::read(fixture.output()).unwrap(), bytes);
    assert_eq!(
        fs::metadata(fixture.output()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let inode = fs::metadata(fixture.output()).unwrap().ino();
    let (value, offsets) = cli(
        &fixture,
        vec![
            reply(0, page(&r, 0, &bytes[..65536])),
            reply(r.size_bytes, denied()),
        ],
    );
    error(&value, "AUTH_DENIED");
    assert_eq!(offsets, [0, r.size_bytes]);
    assert_eq!(fs::metadata(fixture.output()).unwrap().ino(), inode);
    assert_eq!(fs::read(fixture.output()).unwrap(), bytes);
    let (value, offsets) = cli(
        &fixture,
        vec![
            reply(0, page(&r, 0, &bytes[..65536])),
            reply(r.size_bytes, page(&r, r.size_bytes, b"")),
        ],
    );
    success(&value, r.size_bytes);
    assert_eq!(offsets, [0, r.size_bytes]);
    assert_eq!(fs::metadata(fixture.output()).unwrap().ino(), inode);
}

#[test]
fn interrupted_transfer_resumes_at_real_durable_offset() {
    let fixture = Fixture::new();
    let r = record(b"abcdef");
    let (value, offsets) = cli(
        &fixture,
        vec![reply(0, page(&r, 0, b"abc")), interrupted(3)],
    );
    error(&value, "INVALID_REQUEST");
    assert_eq!(offsets, [0, 3]);
    assert!(!fixture.output().exists());
    assert_eq!(
        fs::read(fixture.receiver().join("partial")).unwrap(),
        b"abc"
    );
    let (value, offsets) = cli(
        &fixture,
        vec![
            reply(0, page(&r, 0, b"abc")),
            reply(3, page(&r, 3, b"def")),
            reply(6, page(&r, 6, b"")),
        ],
    );
    success(&value, 6);
    assert_eq!(offsets, [0, 3, 6]);
    assert_eq!(fs::read(fixture.output()).unwrap(), b"abcdef");
}

#[test]
fn complete_partial_and_zero_bytes_still_require_an_extra_eof() {
    for bytes in [b"abcdef".as_slice(), b"".as_slice()] {
        let fixture = Fixture::new();
        let r = record(bytes);
        let (value, offsets) = cli(
            &fixture,
            vec![reply(0, page(&r, 0, bytes)), reply(r.size_bytes, denied())],
        );
        error(&value, "AUTH_DENIED");
        assert_eq!(offsets, [0, r.size_bytes]);
        assert!(!fixture.output().exists());
        assert_eq!(fs::read(fixture.receiver().join("partial")).unwrap(), bytes);
        let (value, offsets) = cli(
            &fixture,
            vec![
                reply(0, page(&r, 0, bytes)),
                reply(r.size_bytes, page(&r, r.size_bytes, b"")),
            ],
        );
        success(&value, r.size_bytes);
        assert_eq!(offsets, [0, r.size_bytes]);
        assert_eq!(fs::read(fixture.output()).unwrap(), bytes);
    }
}

#[test]
fn full_record_is_pinned_on_every_data_page_and_final_eof() {
    let r = record(b"abcdef");
    let mut changed = Vec::new();
    let mut next = r.clone();
    next.storage_ref = "other-locator".into();
    changed.push(next);
    let mut next = r.clone();
    next.task_id = TaskId::new("other-task".into()).unwrap();
    changed.push(next);
    let mut next = r.clone();
    next.snapshot_id = sha256(b"other-snapshot");
    changed.push(next);
    let mut next = r.clone();
    next.environment_digest = sha256(b"other-environment");
    changed.push(next);
    let mut next = r.clone();
    next.owner_principal = "other-principal".into();
    changed.push(next);
    let mut next = r.clone();
    next.retain_until_unix += 1;
    changed.push(next);
    for other in changed {
        for final_eof in [false, true] {
            let fixture = Fixture::new();
            let replies = if final_eof {
                vec![
                    reply(0, page(&r, 0, b"abcdef")),
                    reply(6, page(&other, 6, b"")),
                ]
            } else {
                vec![
                    reply(0, page(&r, 0, b"abc")),
                    reply(3, page(&other, 3, b"def")),
                ]
            };
            let (value, offsets) = cli(&fixture, replies);
            error(&value, "INVALID_REQUEST");
            assert_eq!(offsets, [0, if final_eof { 6 } else { 3 }]);
            assert!(!fixture.output().exists());
            assert_eq!(
                fs::read(fixture.receiver().join("partial")).unwrap(),
                if final_eof {
                    b"abcdef".as_slice()
                } else {
                    b"abc".as_slice()
                }
            );
        }
    }
}

#[test]
fn corrupt_content_or_durable_prefix_is_never_published_or_reset() {
    let fixture = Fixture::new();
    let r = record(b"abcdef");
    let (value, offsets) = cli(
        &fixture,
        vec![reply(0, page(&r, 0, b"abcdeg")), reply(6, page(&r, 6, b""))],
    );
    error(&value, "ARTIFACT_INTEGRITY_FAILED");
    assert_eq!(offsets, [0, 6]);
    assert!(!fixture.output().exists());
    assert_eq!(
        fs::read(fixture.receiver().join("partial")).unwrap(),
        b"abcdeg"
    );
    let fixture = Fixture::new();
    cli(
        &fixture,
        vec![reply(0, page(&r, 0, b"abc")), interrupted(3)],
    );
    fs::write(fixture.receiver().join("partial"), b"xyz").unwrap();
    let before = fs::read(fixture.receiver().join("progress-v1.json")).unwrap();
    let (value, offsets) = cli(&fixture, vec![reply(0, page(&r, 0, b"abc"))]);
    error(&value, "ARTIFACT_INTEGRITY_FAILED");
    assert_eq!(offsets, [0]);
    assert!(!fixture.output().exists());
    assert_eq!(
        fs::read(fixture.receiver().join("partial")).unwrap(),
        b"xyz"
    );
    assert_eq!(
        fs::read(fixture.receiver().join("progress-v1.json")).unwrap(),
        before
    );
}

#[test]
fn probe_business_or_protocol_failure_has_zero_output_io_and_existing_output_is_not_replaced() {
    let r = record(b"abc");
    for code in [
        TaskErrorCode::AuthDenied,
        TaskErrorCode::UnsupportedCapability,
    ] {
        let fixture = Fixture::new();
        let failure = json(TaskEnvelope::Error {
            error: TaskError::new(code, "probe refused", false),
            task_id: None,
        });
        let (value, offsets) = cli(&fixture, vec![reply(0, failure)]);
        error(&value, code.as_str());
        assert_eq!(offsets, [0]);
        assert!(!fixture.output().exists());
        assert!(!fixture.receiver().exists());
    }
    let fixture = Fixture::new();
    let (value, offsets) = cli(&fixture, vec![reply(0, page(&r, 0, b""))]);
    error(&value, "INVALID_REQUEST");
    assert_eq!(offsets, [0]);
    assert!(!fixture.receiver().exists());
    fs::write(fixture.output(), b"existing").unwrap();
    let (value, offsets) = cli(&fixture, vec![reply(0, page(&r, 0, b"abc"))]);
    error(&value, "OUTPUT_EXISTS");
    assert_eq!(offsets, [0]);
    assert_eq!(fs::read(fixture.output()).unwrap(), b"existing");
    assert!(!fixture.receiver().exists());
}

#[test]
fn malformed_continuation_pages_preserve_only_the_committed_prefix() {
    let r = record(b"abcdef");
    let variants = [
        page(&r, 4, b"de"), // request offset mismatch
        page(&r, 3, b""),   // non-EOF stall
        {
            let mut other = r.clone();
            other.artifact_id = ArtifactId::new("other-artifact".into()).unwrap();
            page(&other, 3, b"def")
        },
        {
            let mut other = r.clone();
            other.size_bytes = 3;
            page(&other, 3, b"x")
        }, // beyond size
        {
            let mut value = page(&r, 3, b"def");
            value["artifact"]["next_offset"] = 5.into();
            value
        },
        {
            let mut value = page(&r, 3, b"d");
            value["artifact"]["eof"] = true.into();
            value
        },
        {
            let mut value = page(&r, 3, b"def");
            value["schema_version"] = 2.into();
            value
        },
        page(&r, 3, &vec![0; 65537]),
        json(TaskEnvelope::Success(TaskResponse::Artifacts(
            nexus_control_api::task::TaskArtifactList {
                task_id: r.task_id.clone(),
                records: vec![],
            },
        ))),
    ];
    for malformed in variants {
        let fixture = Fixture::new();
        let (value, offsets) = cli(
            &fixture,
            vec![reply(0, page(&r, 0, b"abc")), reply(3, malformed)],
        );
        error(&value, "INVALID_REQUEST");
        assert_eq!(offsets, [0, 3]);
        assert!(!fixture.output().exists());
        assert_eq!(
            fs::read(fixture.receiver().join("partial")).unwrap(),
            b"abc"
        );
    }
}
