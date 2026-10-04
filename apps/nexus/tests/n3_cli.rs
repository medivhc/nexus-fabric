//! Actual CLI process boundaries (E3 capability behavior, not N3 execution E4).
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn temp_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "n3-cli-process-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args(args)
        .output()
        .unwrap()
}
fn business(args: &[&str]) -> serde_json::Value {
    let output = cli(args);
    assert_eq!(output.status.code(), Some(0), "{:?}", output);
    assert!(output.stderr.is_empty(), "{:?}", output);
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn valid_queries_are_structured_capability_failures_and_keep_task_ids() {
    for args in [
        vec!["task", "show", "accepted-task", "--json"],
        vec!["--json", "task", "cancel", "accepted-task"],
        vec!["task", "artifacts", "accepted-task", "--json"],
        vec![
            "task",
            "logs",
            "accepted-task",
            "--stream",
            "stderr",
            "--offset",
            "17",
            "--json",
        ],
    ] {
        let v = business(&args);
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["verdict"], "FAIL");
        assert_eq!(v["error"]["code"], "UNSUPPORTED_CAPABILITY");
        assert_eq!(v["error"]["task_id"], "accepted-task");
        assert_eq!(v["error"]["retryable"], false);
        assert!(
            v["error"]["reason"]
                .as_str()
                .unwrap()
                .contains("TaskApplicationService")
        );
        assert!(v.get("task").is_none());
    }
}
#[test]
fn request_file_validation_precedes_unavailable_service() {
    let path = temp_path();
    std::fs::write(
        &path,
        include_bytes!("../../../docs/contracts/n3-submit.example.json"),
    )
    .unwrap();
    let args = [
        "task",
        "submit",
        "--request",
        path.to_str().unwrap(),
        "--json",
    ];
    let v = business(&args);
    assert_eq!(v["error"]["code"], "UNSUPPORTED_CAPABILITY");
    assert_eq!(v["error"]["task_id"], serde_json::Value::Null);
    std::fs::write(&path, br#"{"schema_version":1,"schema_version":1}"#).unwrap();
    let v = business(&args);
    assert_eq!(v["error"]["code"], "INVALID_REQUEST");
    assert!(
        v["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("duplicate JSON key")
    );
    std::fs::remove_file(path).unwrap();
}
#[test]
fn unavailable_artifact_does_not_touch_output_or_treat_it_as_access_context() {
    let path = temp_path();
    let args = [
        "artifact",
        "get",
        "artifact-id",
        "--output",
        path.to_str().unwrap(),
        "--json",
    ];
    assert_eq!(business(&args)["error"]["code"], "UNSUPPORTED_CAPABILITY");
    assert!(!path.exists());
    std::fs::write(&path, b"existing-output").unwrap();
    business(&args);
    assert_eq!(std::fs::read(&path).unwrap(), b"existing-output");
    std::fs::remove_file(path).unwrap();
}
#[test]
fn malformed_cli_is_usage_exit_two_and_legacy_run_contract_is_unchanged() {
    for args in [
        vec!["task", "show"],
        vec!["task", "logs", "t", "--stream", "stdout", "--offset", "-1"],
        vec!["task", "cancel", "t", "--principal", "attacker"],
        vec!["artifact", "get", "a", "--output", "out", "--force"],
    ] {
        assert_eq!(cli(&args).status.code(), Some(2));
    }
    let output = cli(&["run", "test-resource", "--", "echo", "test", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["error"]["code"], "UNSUPPORTED");
}

#[cfg(unix)]
#[test]
fn fifo_request_without_writer_returns_bounded_structured_failure() {
    use std::time::{Duration, Instant};
    let path = temp_path();
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args(["task", "submit", "--request"])
        .arg(&path)
        .arg("--json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Duration::from_secs(2);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            std::fs::remove_file(&path).unwrap();
            panic!("CLI blocked opening FIFO; child killed and reaped after 2 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(start.elapsed() < deadline);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["error"]["code"], "INVALID_REQUEST");
    assert!(
        v["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("regular file")
    );
    assert_eq!(v["error"]["task_id"], serde_json::Value::Null);
}
