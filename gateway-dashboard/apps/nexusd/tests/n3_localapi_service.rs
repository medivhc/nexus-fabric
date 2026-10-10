#![cfg(target_os = "linux")]
#[path = "../test_support/n3_localapi.rs"]
mod support;
use nexus_control_api::task::{LogStream, TaskEnvelope, TaskRequest, TaskResponse};
use nexus_domain::task::{CancellationState, TaskErrorCode, TaskOutcome};
#[test]
fn actual_daemon_provider_queries_cancel_revoke_audit_and_cold_restart() {
    let fixture = support::ProviderFixture::new();
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_nexusd"));
    let daemon = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let acceptance = fixture.dir.0.join("data/n3/tasks/acceptance-v1.json");
    let before = std::fs::read(&acceptance).unwrap();
    let get = || TaskRequest::Get {
        task_id: fixture.id.clone(),
    };
    let (status, response) = support::request(&daemon.addr, get());
    assert_eq!(status, 200);
    let TaskEnvelope::Success(TaskResponse::Task(view)) = response else {
        panic!("real query failed")
    };
    assert_eq!(view.task_id, fixture.id);
    assert_eq!(
        view.accepted_contract.authenticated_principal,
        fixture.principal
    );
    let (_, response) = support::request(
        &daemon.addr,
        TaskRequest::ReadLogs {
            task_id: fixture.id.clone(),
            stream: LogStream::Stdout,
            offset: 0,
            max_bytes: 1024,
        },
    );
    let TaskEnvelope::Success(TaskResponse::Logs(page)) = response else {
        panic!("logs failed")
    };
    assert!(page.bytes.is_empty() && !page.eof);
    let (_, response) = support::request(
        &daemon.addr,
        TaskRequest::ListArtifacts {
            task_id: fixture.id.clone(),
        },
    );
    let TaskEnvelope::Success(TaskResponse::Artifacts(list)) = response else {
        panic!("catalog failed")
    };
    assert!(list.records.is_empty());
    fixture.grant(true);
    assert!(support::is_error(
        &support::request(&daemon.addr, get()),
        200,
        TaskErrorCode::AuthDenied
    ));
    fixture.grant(false);
    let (_, response) = support::request(
        &daemon.addr,
        TaskRequest::Cancel {
            task_id: fixture.id.clone(),
        },
    );
    let TaskEnvelope::Success(TaskResponse::Task(cancel)) = response else {
        panic!("cancel failed")
    };
    assert_eq!(cancel.outcome, TaskOutcome::Cancelled);
    assert_eq!(cancel.cancellation.state, CancellationState::Confirmed);
    assert_eq!(before, std::fs::read(&acceptance).unwrap());
    drop(daemon);
    let restarted = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let (_, response) = support::request(&restarted.addr, get());
    let TaskEnvelope::Success(TaskResponse::Task(view)) = response else {
        panic!("restart query failed")
    };
    assert_eq!(view, cancel);
    let journal = fixture.dir.0.join("n2/journal.log");
    std::fs::remove_file(&journal).unwrap();
    std::fs::create_dir(&journal).unwrap();
    assert!(support::is_error(
        &support::request(&restarted.addr, get()),
        200,
        TaskErrorCode::PersistenceFailed
    ));
}

#[test]
#[ignore = "requires NEXUS_N3_TEST_CLI_BIN pointing at independently built current nexus"]
fn actual_nexus_cli_provider_queries_and_cancel() {
    use std::process::Command;
    let binary = std::env::var_os("NEXUS_N3_TEST_CLI_BIN").expect("explicit current CLI binary");
    let fixture = support::ProviderFixture::new();
    let daemon = support::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")),
        &fixture.dir.0,
        "127.0.0.1:0",
    );
    for operation in ["show", "logs", "artifacts", "cancel"] {
        let output = Command::new(&binary)
            .args([
                "task",
                operation,
                fixture.id.as_str(),
                "--addr",
                &daemon.addr,
                "--json",
            ])
            .args(if operation == "logs" {
                vec!["--stream", "stdout", "--offset", "0"]
            } else {
                Vec::new()
            })
            .env(
                "NEXUS_LOCALAPI_TOKEN_FILE",
                fixture.dir.0.join("localapi.token"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "actual CLI {operation}: {:?}",
            output.status
        );
        let response: TaskEnvelope = nexus::n3_acceptance::decode_dto(&output.stdout).unwrap();
        match (operation, response) {
            ("show", TaskEnvelope::Success(TaskResponse::Task(view))) => {
                assert_eq!(view.task_id, fixture.id)
            }
            ("logs", TaskEnvelope::Success(TaskResponse::Logs(page))) => {
                assert_eq!(page.task_id, fixture.id);
                assert!(page.bytes.is_empty() && !page.eof);
            }
            ("artifacts", TaskEnvelope::Success(TaskResponse::Artifacts(list))) => {
                assert_eq!(list.task_id, fixture.id);
                assert!(list.records.is_empty());
            }
            ("cancel", TaskEnvelope::Success(TaskResponse::Task(view))) => {
                assert_eq!(view.task_id, fixture.id);
                assert_eq!(view.outcome, TaskOutcome::Cancelled);
            }
            (operation, result) => panic!("actual CLI {operation} unexpected {result:?}"),
        }
    }
}

#[test]
fn cold_missing_or_empty_replaced_authority_refuses_without_rebuilding_then_restores() {
    use std::os::unix::fs::DirBuilderExt;
    let fixture = support::ProviderFixture::new();
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_nexusd"));
    let request = || TaskRequest::Get {
        task_id: fixture.id.clone(),
    };
    let daemon = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let before = support::request(&daemon.addr, request());
    let (200, TaskEnvelope::Success(TaskResponse::Task(original))) = before else {
        panic!("original accepted Task must be readable")
    };
    drop(daemon);
    let root = fixture.dir.0.join("data/n3/tasks");
    let saved = fixture.dir.0.join("saved-original-tasks");
    let acceptance = std::fs::read(root.join("acceptance-v1.json")).unwrap();
    std::fs::rename(&root, &saved).unwrap();
    let missing = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let response = support::request(&missing.addr, request());
    assert!(
        support::is_error(&response, 200, TaskErrorCode::StateCorrupt),
        "{response:?}"
    );
    assert!(
        !root.exists(),
        "cold boot must not recreate missing authority"
    );
    drop(missing);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let replaced = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let response = support::request(&replaced.addr, request());
    assert!(
        support::is_error(&response, 200, TaskErrorCode::StateCorrupt),
        "{response:?}"
    );
    assert!(
        std::fs::read_dir(&root).unwrap().next().is_none(),
        "empty replacement must remain empty"
    );
    drop(replaced);
    std::fs::remove_dir(&root).unwrap();
    std::fs::rename(&saved, &root).unwrap();
    let restored = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let response = support::request(&restored.addr, request());
    let (200, TaskEnvelope::Success(TaskResponse::Task(view))) = response else {
        panic!("{response:?}")
    };
    assert_eq!(view, original);
    assert_eq!(
        std::fs::read(root.join("acceptance-v1.json")).unwrap(),
        acceptance
    );
    drop(restored);
    // A valid original authority behind a symlink is still outside the fixed
    // real directory chain. Validation must remain when provisioning is removed.
    let parent = root.parent().unwrap();
    let saved_parent = fixture.dir.0.join("saved-original-n3");
    std::fs::rename(parent, &saved_parent).unwrap();
    std::os::unix::fs::symlink(&saved_parent, parent).unwrap();
    let aliased = support::spawn(exe, &fixture.dir.0, "127.0.0.1:0");
    let response = support::request(&aliased.addr, request());
    assert!(
        support::is_error(&response, 200, TaskErrorCode::StateCorrupt),
        "{response:?}"
    );
    assert_eq!(
        std::fs::read(saved_parent.join("tasks/acceptance-v1.json")).unwrap(),
        acceptance
    );
    drop(aliased);
    std::fs::remove_file(parent).unwrap();
    std::fs::rename(&saved_parent, parent).unwrap();
}
