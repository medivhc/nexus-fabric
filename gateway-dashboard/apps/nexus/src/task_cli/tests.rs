use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}
fn temp_file() -> PathBuf {
    std::env::temp_dir().join(format!(
        "n3-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
#[test]
fn parses_all_frozen_operation_shapes_and_reorders_log_options() {
    for a in [
        vec!["task", "submit", "--request", "request.json"],
        vec!["task", "show", "t"],
        vec!["task", "cancel", "t"],
        vec!["task", "artifacts", "t"],
        vec!["task", "logs", "t", "--stream", "stdout", "--offset", "0"],
        vec!["task", "logs", "t", "--offset", "17", "--stream", "stderr"],
        vec!["artifact", "get", "a", "--output", "out"],
    ] {
        assert!(parse(&args(&a)).is_ok(), "{a:?}");
    }
}
#[test]
fn rejects_unknown_duplicate_missing_and_shell_syntax() {
    for a in [
        vec!["task", "show"],
        vec!["task", "show", "t", "--principal", "attacker"],
        vec!["task", "submit", "--request", "x", "--", "sh"],
        vec!["task", "submit", "--request", "--json"],
        vec!["task", "logs", "t", "--stream", "stdout"],
        vec!["task", "logs", "t", "--stream", "combined", "--offset", "0"],
        vec!["task", "logs", "t", "--stream", "stdout", "--offset", "-1"],
        vec!["task", "logs", "t", "--stream", "stdout", "--offset", "1e3"],
        vec![
            "task",
            "logs",
            "t",
            "--stream",
            "stdout",
            "--offset",
            "9007199254740992",
        ],
        vec![
            "task", "logs", "t", "--stream", "stdout", "--offset", "0", "--offset", "1",
        ],
        vec!["artifact", "get", "a", "--output", "out", "--force"],
    ] {
        assert!(parse(&args(&a)).is_err(), "{a:?}");
    }
}
#[test]
fn unavailable_tasks_use_versioned_business_failure_without_fabricated_acceptance() {
    let s = run_unavailable(&args(&["task", "cancel", "already-accepted"]), true).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["error"]["code"], "UNSUPPORTED_CAPABILITY");
    assert_eq!(v["error"]["task_id"], "already-accepted");
    assert_eq!(v["error"]["retryable"], false);
    assert!(v.get("accepted").is_none());
    assert!(s.contains("TaskApplicationService"));
}
#[test]
fn submit_strictly_rejects_duplicate_numbers_unknown_fields_and_versions() {
    let path = temp_file();
    let a = args(&["task", "submit", "--request", path.to_str().unwrap()]);
    let example = include_str!("../../../../docs/contracts/n3-submit.example.json");
    for bad in [
        r#"{"schema_version":1,"schema_version":1}"#.to_string(),
        example.replace(r#""schema_version": 1"#, r#""schema_version": 1e0"#),
        example.replacen("{", "{\"principal\":\"attacker\",", 1),
        example.replacen(r#""schema_version": 1"#, r#""schema_version": 2"#, 1),
    ] {
        std::fs::write(&path, bad).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&run_unavailable(&a, true).unwrap()).unwrap();
        assert_ne!(v["error"]["code"], "UNSUPPORTED_CAPABILITY");
        assert_eq!(v["error"]["task_id"], serde_json::Value::Null);
    }
    std::fs::remove_file(path).unwrap();
}
#[test]
fn valid_submit_decodes_before_capability_failure_and_retains_argv() {
    let path = temp_file();
    std::fs::write(
        &path,
        include_bytes!("../../../../docs/contracts/n3-submit.example.json"),
    )
    .unwrap();
    let c = TaskCliCommand::Submit {
        request_file: path.clone(),
    };
    let TaskRequest::Submit { request } = c.prepare().unwrap() else {
        panic!()
    };
    assert!(!request.command.is_empty());
    let v: serde_json::Value = serde_json::from_str(
        &run_unavailable(
            &args(&["task", "submit", "--request", path.to_str().unwrap()]),
            true,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(v["error"]["code"], "UNSUPPORTED_CAPABILITY");
    std::fs::remove_file(path).unwrap();
}
#[test]
fn request_file_bound_and_missing_file_are_business_errors() {
    let path = temp_file();
    let c = TaskCliCommand::Submit {
        request_file: path.clone(),
    };
    assert_eq!(c.prepare().unwrap_err().code, TaskErrorCode::InvalidRequest);
    std::fs::write(&path, vec![b' '; MAX_REQUEST_BYTES as usize + 1]).unwrap();
    let error = c.prepare().unwrap_err();
    assert_eq!(error.code, TaskErrorCode::CapacityUnavailable);
    assert!(error.reason.contains("1 MiB"));
    std::fs::remove_file(path).unwrap();
}
#[test]
fn unavailable_download_never_creates_or_overwrites_output() {
    let path = temp_file();
    let a = args(&[
        "artifact",
        "get",
        "artifact-1",
        "--output",
        path.to_str().unwrap(),
    ]);
    run_unavailable(&a, true).unwrap();
    assert!(!path.exists());
    std::fs::write(&path, b"existing").unwrap();
    run_unavailable(&a, true).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"existing");
    std::fs::remove_file(path).unwrap();
}

#[cfg(any(
    all(
        target_os = "linux",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ),
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
#[test]
fn regular_file_replaced_with_fifo_before_open_is_bounded_and_fd_checked() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let path = temp_file();
    std::fs::write(&path, b"regular before replacement").unwrap();
    assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
    std::fs::remove_file(&path).unwrap();
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    // The child calls only the post-check opener against the replaced path.
    // This deterministically exercises the check/open gap without a race timer.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "task_cli::tests::fifo_replacement_open_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("NEXUS_N3_FIFO_REPLACEMENT_TEST_PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() >= Duration::from_secs(2) {
            child.kill().unwrap();
            child.wait().unwrap();
            std::fs::remove_file(path).unwrap();
            panic!("post-check FIFO open blocked; child killed and reaped");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[cfg(any(
    all(
        target_os = "linux",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ),
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
#[test]
#[ignore = "subprocess fixture invoked by bounded replacement regression"]
fn fifo_replacement_open_child() {
    let path = std::env::var_os("NEXUS_N3_FIFO_REPLACEMENT_TEST_PATH").unwrap();
    let error = open_checked_request_file(std::path::Path::new(&path)).unwrap_err();
    assert_eq!(error.code, TaskErrorCode::InvalidRequest);
    assert!(
        error
            .reason
            .contains("opened request input must be a regular file")
    );
}
