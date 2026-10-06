//! Actual CLI offline boundaries. Real daemon service tests live in nexusd.
#![cfg(unix)]
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn fixture() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "n36-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    root
}
fn cli(root: &std::path::Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args([
            "--socket",
            root.join("absent.sock").to_str().unwrap(),
            "--json",
        ])
        .args(args)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", root.join("localapi.token"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}
#[cfg(unix)]
#[test]
fn real_cli_offline_preserves_task_id_and_reports_local_daemon_without_fake_state() {
    let root = fixture();
    for args in [
        vec!["task", "show", "task"],
        vec!["task", "cancel", "task"],
        vec!["task", "artifacts", "task"],
        vec![
            "task", "logs", "task", "--stream", "stdout", "--offset", "0",
        ],
    ] {
        let value = cli(&root, &args);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["error"]["code"], "PROVIDER_UNREACHABLE");
        assert_eq!(value["error"]["retryable"], true);
        assert_eq!(value["error"]["task_id"], "task");
        assert!(
            value["error"]["reason"]
                .as_str()
                .unwrap()
                .contains("local daemon")
        );
        assert!(value.get("task").is_none());
    }
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn artifact_get_offline_has_no_output_or_credential_io() {
    let root = fixture();
    let output = root.join("out");
    let args = ["artifact", "get", "a", "--output", output.to_str().unwrap()];
    let expected = if cfg!(target_os = "linux") {
        "PROVIDER_UNREACHABLE"
    } else {
        "UNSUPPORTED_CAPABILITY"
    };
    assert_eq!(cli(&root, &args)["error"]["code"], expected);
    assert!(!output.exists());
    assert!(!root.join("localapi.token").exists());
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::write(&output, b"existing").unwrap();
    assert_eq!(cli(&root, &args)["error"]["code"], expected);
    assert_eq!(std::fs::read(&output).unwrap(), b"existing");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

fn rejected_credential(root: &std::path::Path, secret_marker: &str) {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let start = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_secs(2) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("credential fixture did not connect: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args([
            "--addr",
            &address.to_string(),
            "--json",
            "task",
            "show",
            "accepted-task",
        ])
        .env("NEXUS_LOCALAPI_TOKEN_FILE", root.join("localapi.token"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() >= Duration::from_secs(2) {
            child.kill().unwrap();
            child.wait().unwrap();
            let _ = server.join();
            panic!("CLI blocked on credential; child killed and reaped");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        server.join().unwrap().is_empty(),
        "invalid credential must not produce HTTP headers"
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(secret_marker));
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["error"]["code"], "AUTH_DENIED");
    assert_eq!(value["error"]["retryable"], false);
    assert_eq!(value["error"]["task_id"], "accepted-task");
}
#[test]
fn actual_cli_token_fifo_is_bounded_and_no_credential_header_is_sent() {
    let root = fixture();
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(root.join("localapi.token"))
            .status()
            .unwrap()
            .success()
    );
    rejected_credential(&root, "unobservable-token-secret");
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn actual_cli_rejects_missing_newline_oversized_linked_and_nonprivate_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let root = fixture();
    let path = root.join("localapi.token");
    let secret = "secret-credential-marker";
    rejected_credential(&root, secret);
    for content in [format!("{secret}\r\nInjected: yes"), "a".repeat(4097)] {
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        rejected_credential(&root, secret);
    }
    std::fs::write(&path, secret).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    rejected_credential(&root, secret);
    std::fs::remove_file(&path).unwrap();
    let linked = root.join("linked-token");
    std::fs::write(&linked, secret).unwrap();
    std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&linked, &path).unwrap();
    rejected_credential(&root, secret);
    std::fs::remove_dir_all(root).unwrap();
}
