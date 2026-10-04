use super::*;
use nexus_compute::task::AcceptanceContext;
use nexus_storage::InMemoryContentStore;
use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId, snapshot::SnapshotSelection};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "nexus-executor-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn log_fixture(dir: &Dir, limit: u64) -> Logs {
    Logs::create(
        &dir.0,
        &TaskId::new("task".into()).unwrap(),
        &sha256(b"contract"),
        limit,
    )
    .unwrap()
}
#[test]
fn logs_share_hard_quota_drain_and_preserve_repeatable_byte_pages() {
    let dir = Dir::new();
    let logs = log_fixture(&dir, 5);
    logs.append(0, b"abc").unwrap();
    logs.append(1, b"DEFGHI").unwrap();
    logs.append(0, b"lost but drained").unwrap();
    let page = logs.page(LogStream::Stdout, 0, 2).unwrap();
    assert_eq!(page.bytes, b"ab");
    assert_eq!(page.next_offset, 2);
    assert!(!page.eof);
    assert!(page.truncated);
    logs.seal().unwrap();
    let reopened = Logs::open(
        &dir.0,
        &TaskId::new("task".into()).unwrap(),
        &sha256(b"contract"),
        5,
    )
    .unwrap();
    assert_eq!(reopened.page(LogStream::Stdout, 0, 2).unwrap(), page);
    let end = reopened.page(LogStream::Stderr, 0, 100).unwrap();
    assert_eq!(end.bytes, b"DE");
    assert!(end.truncated && end.eof);
    assert!(reopened.append(0, b"x").is_err());
    assert!(reopened.page(LogStream::Stdout, 4, 1).is_err());
}
#[test]
fn logs_refuse_reset_binding_loss_torn_progress_links_and_public_permissions() {
    let dir = Dir::new();
    let logs = log_fixture(&dir, 10);
    assert!(
        Logs::create(
            &dir.0,
            &TaskId::new("task".into()).unwrap(),
            &sha256(b"contract"),
            10
        )
        .is_err()
    );
    assert!(
        Logs::open(
            &dir.0,
            &TaskId::new("task".into()).unwrap(),
            &sha256(b"other"),
            10
        )
        .is_err()
    );
    fs::write(logs.directory.join("stdout"), b"ahead-of-authority").unwrap();
    assert!(logs.page(LogStream::Stdout, 0, 10).is_err());
    fs::write(logs.directory.join("stdout"), b"").unwrap();
    fs::set_permissions(
        logs.directory.join("stderr"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(logs.page(LogStream::Stdout, 0, 10).is_err());
    fs::set_permissions(
        logs.directory.join("stderr"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::remove_file(logs.directory.join("stderr")).unwrap();
    std::os::unix::fs::symlink(logs.directory.join("stdout"), logs.directory.join("stderr"))
        .unwrap();
    assert!(logs.page(LogStream::Stdout, 0, 10).is_err());
}
#[test]
fn multiplex_frames_are_binary_fragment_safe_and_reject_invalid_or_torn_data() {
    let mut f = Frames::default();
    let mut got = Vec::new();
    let raw = [1, 0, 0, 0, 0, 0, 0, 3, 0, 255, 3, 2, 0, 0, 0, 0, 0, 0, 1, 9];
    for byte in raw {
        f.push(&[byte], |i, b| {
            got.push((i, b.to_vec()));
            Ok(())
        })
        .unwrap();
    }
    f.complete().unwrap();
    assert_eq!(got, [(0, vec![0, 255, 3]), (1, vec![9])]);
    let mut bad = Frames::default();
    assert!(bad.push(&[3, 0, 0, 0, 0, 0, 0, 0], |_, _| Ok(())).is_err());
    let mut torn = Frames::default();
    torn.push(&[1, 0, 0, 0, 0, 0, 0, 1], |_, _| Ok(())).unwrap();
    assert!(torn.complete().is_err());
}
#[test]
fn output_staging_rejects_symlink_components_and_nonregular_files() {
    let dir = Dir::new();
    fs::write(dir.0.join("real"), b"data").unwrap();
    std::os::unix::fs::symlink("real", dir.0.join("link")).unwrap();
    assert!(safe_file(&dir.0, "link").is_err());
    assert!(safe_file(&dir.0, "../real").is_err());
    assert!(safe_file(&dir.0, ".").is_err());
    assert!(safe_file(&dir.0, "real").is_ok());
}
fn tar_member(bytes: &mut Vec<u8>, name: &str, kind: u8, data: &[u8]) {
    let mut h = [0; 512];
    assert!(name.len() <= 100);
    h[..name.len()].copy_from_slice(name.as_bytes());
    for (range, value) in [
        (100..108, 0o644u64),
        (108..116, 0),
        (116..124, 0),
        (124..136, data.len() as u64),
        (136..148, 0),
    ] {
        let n = range.len();
        h[range].copy_from_slice(format!("{:0width$o}\0", value, width = n - 1).as_bytes());
    }
    h[148..156].fill(b' ');
    h[156] = kind;
    let sum: u64 = h.iter().map(|b| *b as u64).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    bytes.extend_from_slice(&h);
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len() + (512 - data.len() % 512) % 512, 0);
}
#[test]
fn archive_inventory_rejects_traversal_duplicates_links_and_checksum_damage() {
    for member in ["work/../escape", "other/file"] {
        let mut bytes = Vec::new();
        tar_member(&mut bytes, member, b'0', b"data");
        bytes.resize(bytes.len() + 1024, 0);
        assert!(archive::parse(&bytes).is_err());
    }
    let mut bytes = Vec::new();
    tar_member(&mut bytes, "work/link", b'2', b"");
    tar_member(&mut bytes, "work/link/file", b'0', b"secret");
    bytes.resize(bytes.len() + 1024, 0);
    let inventory = archive::parse(&bytes).unwrap();
    assert!(archive::regular(&inventory, "link").is_err());
    assert!(archive::regular(&inventory, "link/file").is_err());
    let mut duplicate = Vec::new();
    tar_member(&mut duplicate, "work/file", b'0', b"one");
    tar_member(&mut duplicate, "work/file", b'0', b"two");
    duplicate.resize(duplicate.len() + 1024, 0);
    assert!(archive::parse(&duplicate).is_err());
    bytes[0] ^= 1;
    assert!(archive::parse(&bytes).is_err());
}
#[test]
fn archive_inventory_supports_long_unicode_paths_and_rejects_torn_data() {
    let name = format!("work/{}", "文件".repeat(40));
    let mut bytes = Vec::new();
    let mut path = name.as_bytes().to_vec();
    path.push(0);
    tar_member(&mut bytes, "long", b'L', &path);
    tar_member(&mut bytes, "placeholder", b'0', b"data");
    bytes.resize(bytes.len() + 1024, 0);
    let entries = archive::parse(&bytes).unwrap();
    assert_eq!(
        archive::regular(&entries, &name[5..]).unwrap().bytes,
        b"data"
    );
    assert!(archive::parse(&bytes[..bytes.len() - 600]).is_err());
}
struct Fixture {
    dir: Dir,
    root: PathBuf,
    id: TaskId,
    executor: LinuxTaskExecutor,
    contract: AcceptedContract,
}
impl Fixture {
    fn new(argv: &[&str], mutate: impl FnOnce(&mut SubmitTaskRequest)) -> Self {
        let image = std::env::var("NEXUS_N3_TEST_IMAGE_ID")
            .expect("supply operator-qualified immutable image ID");
        let dir = Dir::new();
        let root = dir.0.join("provider");
        let snapshots = FileSnapshotStore::open(&root).unwrap();
        let mut ws = Workspace::init(
            WorkspaceId("executor-project".into()),
            InMemoryContentStore::new(),
            AuthorId("test".into()),
        )
        .unwrap();
        let base = ws.heads().heads[0].clone();
        let commit = ws
            .commit_changes(
                &base,
                &[Change {
                    path: "input.txt".into(),
                    content: b"fixed-input\n".to_vec(),
                }],
            )
            .unwrap();
        let frozen = snapshots
            .stage_snapshot(
                &ws,
                &commit,
                &SnapshotSelection {
                    include: vec!["input.txt".into()],
                    exclude: vec![],
                    executable: vec![],
                },
            )
            .unwrap();
        let mut request: SubmitTaskRequest = nexus::n3_acceptance::decode_dto(include_bytes!(
            "../../../docs/contracts/n3-submit.example.json"
        ))
        .unwrap();
        request.workspace = frozen.reference.workspace.clone();
        request.input_snapshot = frozen.reference;
        request.cwd = ".".into();
        request.command = argv.iter().map(|s| (*s).into()).collect();
        request.environment.image_digest = Sha256Digest::parse(image).unwrap();
        request.limits = TaskLimits {
            timeout_seconds: 10,
            cpu_millis: 1000,
            memory_bytes: 67108864,
            storage_bytes: 1048576,
            log_bytes: 16384,
        };
        request.outputs = vec![OutputSpec {
            path: "result.txt".into(),
            required: false,
        }];
        mutate(&mut request);
        let time = now().unwrap();
        let context = AcceptanceContext {
            authenticated_principal: "authenticated-fixture".into(),
            provider: request.provider.clone(),
            environment_evidence: request.environment.clone(),
            capacity_reservation_id: "real-test-reservation".into(),
            now_unix: time,
            prepare_deadline_unix: time + 60,
            delivery_deadline_unix: time + 3600,
        };
        let owner = TaskOwner::new(
            FileTaskAcceptanceStore::open(&root).unwrap(),
            sha256,
            new_task_id,
        );
        let accepted = owner
            .accept_verified(request.clone(), context)
            .unwrap()
            .task;
        let executor =
            LinuxTaskExecutor::open(&root, vec![request.environment.image_digest.clone()]).unwrap();
        Self {
            dir,
            root,
            id: accepted.view.task_id.clone(),
            executor,
            contract: accepted.view.accepted_contract,
        }
    }
    fn run(&self) -> RuntimeState {
        self.executor.run(&self.id, &mut |_| Ok(())).unwrap()
    }
    fn container(&self) -> String {
        let h = self
            .executor
            .owner
            .runtime(&self.id)
            .unwrap()
            .execution_handle
            .unwrap();
        h.split(':').nth(1).unwrap().to_owned()
    }
    fn assert_reaped(&self) {
        let v = Docker.inspect(&self.container()).unwrap();
        assert_eq!(v["State"]["Running"], false);
        assert_eq!(v["State"]["Pid"], 0);
        assert_eq!(v["State"]["Dead"], false);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this fixture's deterministic name; never touches another container.
        let name = format!(
            "nexus-task-{}",
            &sha256(self.id.as_str().as_bytes()).as_str()[7..]
        );
        let _ = Docker.request(
            "DELETE",
            &format!("/containers/{name}?force=true"),
            Json::Null,
        );
        let _ = &self.dir;
    }
}
#[test]
#[ignore = "requires local Docker and NEXUS_N3_TEST_IMAGE_ID; run explicitly for executor evidence"]
fn container_actual_exit_input_output_and_reexecution_guard() {
    let f = Fixture::new(
        &[
            "/bin/sh",
            "-c",
            "cat input.txt; printf output > result.txt; printf diagnostic >&2; exit 42",
        ],
        |_| {},
    );
    let before = fs::read(f.root.join("acceptance-v1.json")).unwrap();
    let state = f.run();
    assert_eq!(state.view.execution.exit_code, Some(42));
    assert_eq!(state.view.execution.workload_succeeded, Some(false));
    assert_eq!(state.view.phase, TaskPhase::Finalizing);
    assert_eq!(state.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(state.view.delivery.state, DeliveryState::Pending);
    assert_eq!(
        f.executor
            .logs(&f.id, LogStream::Stdout, 0, 65536)
            .unwrap()
            .bytes,
        b"fixed-input\n"
    );
    assert_eq!(
        f.executor
            .logs(&f.id, LogStream::Stderr, 0, 65536)
            .unwrap()
            .bytes,
        b"diagnostic"
    );
    let logs = Logs::open(
        &f.root,
        &f.id,
        &state.view.contract_digest,
        f.contract.request.limits.log_bytes,
    )
    .unwrap();
    assert_eq!(
        fs::read(logs.directory.join("outputs-unregistered-v1/result.txt")).unwrap(),
        b"output"
    );
    assert_eq!(fs::read(f.root.join("acceptance-v1.json")).unwrap(), before);
    f.assert_reaped();
    assert_eq!(
        f.executor.run(&f.id, &mut |_| Ok(())).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_argv_is_literal_without_implicit_shell() {
    let f = Fixture::new(
        &["/bin/printf", "%s", "$(touch /work/result.txt);literal"],
        |r| r.outputs.clear(),
    );
    let s = f.run();
    assert_eq!(s.view.execution.exit_code, Some(0));
    assert_eq!(
        f.executor
            .logs(&f.id, LogStream::Stdout, 0, 65536)
            .unwrap()
            .bytes,
        b"$(touch /work/result.txt);literal"
    );
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_log_quota_continues_drain_binary_output_and_stable_pages() {
    let f = Fixture::new(
        &[
            "/bin/sh",
            "-c",
            "head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2; exit 0",
        ],
        |r| r.limits.log_bytes = 4096,
    );
    let s = f.run();
    assert_eq!(s.view.execution.exit_code, Some(0));
    let a = f.executor.logs(&f.id, LogStream::Stdout, 0, 65536).unwrap();
    let b = f.executor.logs(&f.id, LogStream::Stderr, 0, 65536).unwrap();
    assert_eq!(a.bytes.len() + b.bytes.len(), 4096);
    assert!(a.truncated && b.truncated && a.eof && b.eof);
    let page = f.executor.logs(&f.id, LogStream::Stdout, 17, 31).unwrap();
    assert_eq!(page.bytes, vec![0; 31]);
    assert_eq!(
        page,
        f.executor.logs(&f.id, LogStream::Stdout, 17, 31).unwrap()
    );
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_timeout_stops_and_reaps_entire_namespace() {
    let f = Fixture::new(
        &["/bin/sh", "-c", "(while :; do sleep 1; done) & wait"],
        |r| r.limits.timeout_seconds = 1,
    );
    let time = Instant::now();
    let s = f.run();
    assert!(time.elapsed() < Duration::from_secs(8));
    assert_eq!(s.view.execution.state, ExecutionState::Stopped);
    assert_eq!(s.view.execution.exit_code, None);
    assert_eq!(s.view.outcome, TaskOutcome::Failed);
    assert_eq!(s.view.error.unwrap().code, TaskErrorCode::Timeout);
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_durable_cancel_is_requested_then_confirmed_after_reap() {
    let f = Fixture::new(&["/bin/sh", "-c", "sleep 60 & wait"], |_| {});
    std::thread::scope(|scope| {
        let run = scope.spawn(|| f.run());
        let deadline = Instant::now() + Duration::from_secs(8);
        while f.executor.owner.runtime(&f.id).unwrap().view.phase != TaskPhase::Running {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let requested = f.executor.cancel(&f.id, "User").unwrap();
        assert_eq!(
            requested.view.cancellation.state,
            CancellationState::Requested
        );
        let ended = run.join().unwrap();
        assert_eq!(ended.view.outcome, TaskOutcome::Cancelled);
        assert_eq!(ended.view.cancellation.state, CancellationState::Confirmed);
        assert_eq!(ended.view.execution.exit_code, None);
    });
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_kernel_storage_cpu_memory_limits_and_no_root_or_shm_writes() {
    let f = Fixture::new(
        &[
            "/bin/sh",
            "-c",
            "id -u; cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/cpu.max; dd if=/dev/zero of=too-large bs=65536 count=64; c=$?; test $c -ne 0 || exit 91; touch /tmp/escape && exit 92; touch /dev/shm/escape && exit 93; i=0; while [ $i -lt 50000 ]; do i=$((i+1)); done; cat /sys/fs/cgroup/cpu.stat; exit 0",
        ],
        |r| r.limits.cpu_millis = 100,
    );
    let s = f.run();
    assert_eq!(s.view.execution.exit_code, Some(0));
    let out = String::from_utf8(
        f.executor
            .logs(&f.id, LogStream::Stdout, 0, 65536)
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(
        out.starts_with("65534\n67108864\n0\n10000 100000\n"),
        "{out}"
    );
    let count = out
        .lines()
        .find_map(|l| l.strip_prefix("nr_throttled "))
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(count > 0, "actual CPU throttling: {out}");
    let err = String::from_utf8(
        f.executor
            .logs(&f.id, LogStream::Stderr, 0, 65536)
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(err.contains("No space left on device"), "{err}");
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_memory_pressure_produces_kernel_oom_and_real_nonzero_exit() {
    let f = Fixture::new(
        &[
            "/bin/sh",
            "-c",
            "awk 'BEGIN {s=\"xxxxxxxxxxxxxxxx\";while(1){s=s s;}}'; c=$?; cat /sys/fs/cgroup/memory.events; exit $c",
        ],
        |r| r.limits.memory_bytes = 33554432,
    );
    let s = f.run();
    assert_eq!(s.view.execution.exit_code, Some(137));
    let out = String::from_utf8(
        f.executor
            .logs(&f.id, LogStream::Stdout, 0, 65536)
            .unwrap()
            .bytes,
    )
    .unwrap();
    let kills = out
        .lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(kills > 0, "actual kernel OOM: {out}");
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_authorization_rechecked_after_input_preparation_prevents_command_start() {
    let f = Fixture::new(&["/bin/touch", "/work/result.txt"], |_| {});
    let mut calls = 0;
    let e = f
        .executor
        .run(&f.id, &mut |_| {
            calls += 1;
            if calls == 2 {
                Err(TaskError::new(TaskErrorCode::AuthDenied, "revoked", false))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(e.code, TaskErrorCode::AuthDenied);
    assert_eq!(calls, 2);
    let s = f.executor.owner.runtime(&f.id).unwrap();
    assert_eq!(s.view.execution.state, ExecutionState::NotStarted);
    assert!(s.execution_handle.is_none());
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_reentrant_prestart_cancel_does_not_deadlock_or_start_command() {
    let f = Fixture::new(&["/bin/touch", "/work/result.txt"], |_| {});
    let mut calls = 0;
    let state = f
        .executor
        .run(&f.id, &mut |_| {
            calls += 1;
            if calls == 2 {
                f.executor.cancel(&f.id, "User")?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(state.view.outcome, TaskOutcome::Cancelled);
    assert_eq!(state.view.execution.state, ExecutionState::NotStarted);
    assert!(state.execution_handle.is_none());
    let name = format!(
        "nexus-task-{}",
        &sha256(f.id.as_str().as_bytes()).as_str()[7..]
    );
    assert_eq!(Docker.inspect(&name).unwrap()["State"]["Running"], false);
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_output_links_and_missing_files_are_staged_as_unavailable() {
    let f = Fixture::new(&["/bin/sh", "-c", "ln -s /etc result.txt; exit 0"], |r| {
        r.outputs = vec![
            OutputSpec {
                path: "result.txt/passwd".into(),
                required: true,
            },
            OutputSpec {
                path: "missing.txt".into(),
                required: true,
            },
        ]
    });
    let s = f.run();
    assert_eq!(s.view.execution.exit_code, Some(0));
    assert_eq!(s.view.outcome, TaskOutcome::Unfinished);
    let logs = Logs::open(
        &f.root,
        &f.id,
        &s.view.contract_digest,
        f.contract.request.limits.log_bytes,
    )
    .unwrap();
    let v: Json =
        serde_json::from_slice(&fs::read(logs.directory.join("outputs-v1.json")).unwrap()).unwrap();
    assert_eq!(v["payload"]["files"][0]["error"], "INVALID_PATH");
    assert_eq!(v["payload"]["files"][1]["error"], "ARTIFACT_MISSING");
    assert!(
        !logs
            .directory
            .join("outputs-unregistered-v1/result.txt")
            .exists()
    );
    f.assert_reaped();
}
#[test]
#[ignore = "requires qualified local Docker; run explicitly"]
fn container_owner_crash_blocks_new_work_without_reexecution() {
    use std::os::unix::process::ExitStatusExt;
    let f = Fixture::new(&["/bin/sleep", "60"], |_| {});
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "task_executor::tests::executor_process_fixture",
        ])
        .env("NEXUS_N3_FIXTURE_ROOT", &f.root)
        .env("NEXUS_N3_FIXTURE_TASK", f.id.as_str())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while f.executor.owner.runtime(&f.id).unwrap().view.phase != TaskPhase::Running {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("fixture never confirmed start");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(9));
    let recovered = LinuxTaskExecutor::open(&f.root, f.executor.images.clone()).unwrap();
    let old = recovered.owner.runtime(&f.id).unwrap();
    assert_eq!(old.view.observation, Observation::PendingVerification);
    assert_eq!(old.view.outcome, TaskOutcome::Unfinished);
    assert_eq!(
        Docker.inspect(&f.container()).unwrap()["State"]["Running"],
        true
    );
    let mut request = f.contract.request.clone();
    request.idempotency_key = "after-crash".into();
    let time = now().unwrap();
    let context = AcceptanceContext {
        authenticated_principal: f.contract.authenticated_principal.clone(),
        provider: request.provider.clone(),
        environment_evidence: request.environment.clone(),
        capacity_reservation_id: "reserved-second".into(),
        now_unix: time,
        prepare_deadline_unix: time + 60,
        delivery_deadline_unix: time + 3600,
    };
    let next = recovered
        .owner
        .accept_verified(request, context)
        .unwrap()
        .task;
    assert_eq!(
        recovered
            .run(&next.view.task_id, &mut |_| Ok(()))
            .unwrap_err()
            .code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        recovered.run(&f.id, &mut |_| Ok(())).unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        recovered.owner.runtime(&f.id).unwrap().execution_handle,
        old.execution_handle
    );
    Docker.stop(&f.container()).unwrap();
    f.assert_reaped();
    println!(
        "SIGKILL owner: same durable handle retained; original container observed alive; both repeat and new work refused; explicit fixture cleanup confirmed reap"
    );
}
#[test]
#[ignore = "child process fixture invoked by owner-crash parent, not a standalone test"]
fn executor_process_fixture() {
    let root = PathBuf::from(std::env::var("NEXUS_N3_FIXTURE_ROOT").unwrap());
    let id = TaskId::new(std::env::var("NEXUS_N3_FIXTURE_TASK").unwrap()).unwrap();
    let image = Sha256Digest::parse(std::env::var("NEXUS_N3_TEST_IMAGE_ID").unwrap()).unwrap();
    LinuxTaskExecutor::open(&root, vec![image])
        .unwrap()
        .run(&id, &mut |_| Ok(()))
        .unwrap();
}
