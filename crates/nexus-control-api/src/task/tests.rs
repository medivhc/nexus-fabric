use super::*;
fn id() -> TaskId {
    TaskId::new("task-1".into()).unwrap()
}
fn record() -> ArtifactRecord {
    use nexus_domain::task::{PublicationState, Sha256Digest};
    ArtifactRecord {
        schema_version: 1,
        artifact_id: ArtifactId::new("artifact-1".into()).unwrap(),
        task_id: id(),
        snapshot_id: Sha256Digest::from_bytes([1; 32]),
        environment_digest: Sha256Digest::from_bytes([2; 32]),
        producer_node: "node".into(),
        workspace: "workspace".into(),
        owner_principal: "principal".into(),
        path: "out.txt".into(),
        size_bytes: 3,
        content_sha256: Sha256Digest::from_bytes([3; 32]),
        storage_ref: "private-cas-ref".into(),
        created_at_unix: 1,
        retain_until_unix: 100,
        publication_state: PublicationState::Published,
    }
}
fn requests() -> Vec<TaskRequest> {
    vec![
        TaskRequest::Get { task_id: id() },
        TaskRequest::Cancel { task_id: id() },
        TaskRequest::ListArtifacts { task_id: id() },
        TaskRequest::ReadLogs {
            task_id: id(),
            stream: LogStream::Stderr,
            offset: 17,
            max_bytes: 1024,
        },
        TaskRequest::GetArtifact {
            artifact_id: record().artifact_id,
            offset: 0,
            max_bytes: 1,
        },
    ]
}
#[test]
fn request_messages_match_independent_wire_vector() {
    let r = TaskRequest::ReadLogs {
        task_id: id(),
        stream: LogStream::Stderr,
        offset: 17,
        max_bytes: 1024,
    };
    assert_eq!(r.to_value().canonical_bytes(), br#"{"max_bytes":1024,"offset":17,"operation":"ReadTaskLogs","schema_version":1,"stream":"stderr","task_id":"task-1"}"#);
    for r in requests() {
        assert_eq!(TaskRequest::from_value(r.to_value()).unwrap(), r);
    }
}
#[test]
fn request_rejects_principal_and_unknown_operation_or_fields() {
    for r in requests() {
        let Value::Object(mut f) = r.to_value() else {
            panic!()
        };
        f.insert("principal".into(), "attacker".to_string().to_value());
        assert!(TaskRequest::from_value(Value::Object(f)).is_err());
    }
    let Value::Object(mut f) = requests().remove(0).to_value() else {
        panic!()
    };
    f.insert("operation".into(), "SpawnHostShell".to_string().to_value());
    assert!(TaskRequest::from_value(Value::Object(f)).is_err());
}
#[test]
fn version_is_explicit_and_not_downgraded() {
    let Value::Object(mut f) = requests().remove(0).to_value() else {
        panic!()
    };
    f.insert("schema_version".into(), 2u64.to_value());
    assert_eq!(
        TaskRequest::from_value(Value::Object(f)).unwrap_err().code,
        TaskErrorCode::UnsupportedVersion
    );
}
#[test]
fn page_request_rejects_zero_oversize_negative_and_inexact_numbers() {
    let r = TaskRequest::ReadLogs {
        task_id: id(),
        stream: LogStream::Stdout,
        offset: 0,
        max_bytes: 1,
    };
    for (name, bad) in [
        ("max_bytes", 0),
        ("max_bytes", 65_537),
        ("offset", -1),
        ("offset", i128::from(MAX_INTEGER) + 1),
    ] {
        let Value::Object(mut f) = r.to_value() else {
            panic!()
        };
        f.insert(name.into(), Value::Integer(bad));
        assert!(TaskRequest::from_value(Value::Object(f)).is_err());
    }
    let Value::Object(mut f) = r.to_value() else {
        panic!()
    };
    f.insert("offset".into(), "0".to_string().to_value());
    assert!(TaskRequest::from_value(Value::Object(f)).is_err());
}
#[test]
fn logs_preserve_binary_and_independent_stream_offsets() {
    for stream in [LogStream::Stdout, LogStream::Stderr] {
        let page = TaskLogsPage {
            task_id: id(),
            stream,
            offset: 17,
            bytes: vec![0, 255, 195, 169],
            next_offset: 21,
            eof: false,
            truncated: true,
        };
        let e = TaskEnvelope::Success(TaskResponse::Logs(page));
        assert_eq!(TaskEnvelope::from_value(e.to_value()).unwrap(), e);
    }
}
#[test]
fn logs_reject_invalid_bytes_range_and_fields() {
    let page = TaskLogsPage {
        task_id: id(),
        stream: LogStream::Stdout,
        offset: 0,
        bytes: vec![1],
        next_offset: 1,
        eof: false,
        truncated: false,
    };
    for (field, value) in [
        ("next_offset", 2u64.to_value()),
        ("bytes", Value::Array(vec![256u64.to_value()])),
        ("extra", Value::Null),
    ] {
        let Value::Object(mut f) = page.to_value() else {
            panic!()
        };
        f.insert(field.into(), value);
        assert!(TaskLogsPage::from_value(Value::Object(f)).is_err());
    }
}
#[test]
fn artifact_pages_require_registered_published_record_and_exact_eof() {
    let page = TaskArtifactPage {
        record: record(),
        offset: 1,
        bytes: vec![8, 9],
        next_offset: 3,
        eof: true,
    };
    let e = TaskEnvelope::Success(TaskResponse::Artifact(Box::new(page.clone())));
    assert_eq!(TaskEnvelope::from_value(e.to_value()).unwrap(), e);
    let mut bad = page.clone();
    bad.eof = false;
    assert!(bad.validate().is_err());
    let mut bad = page.clone();
    bad.record.publication_state = nexus_domain::task::PublicationState::Pending;
    assert!(bad.validate().is_err());
    let mut bad = page;
    bad.next_offset = 4;
    assert!(bad.validate().is_err());
}
#[test]
fn artifact_list_rejects_foreign_task_and_duplicate_ids() {
    let mut list = TaskArtifactList {
        task_id: id(),
        records: vec![record()],
    };
    let e = TaskEnvelope::Success(TaskResponse::Artifacts(list.clone()));
    assert_eq!(TaskEnvelope::from_value(e.to_value()).unwrap(), e);
    list.records.push(record());
    assert!(list.validate().is_err());
    list.records.pop();
    list.task_id = TaskId::new("foreign-task".into()).unwrap();
    assert!(list.validate().is_err());
}
#[test]
fn fail_envelope_has_typed_error_and_explicit_task_id() {
    let e = TaskEnvelope::Error {
        error: TaskError::new(TaskErrorCode::UnsupportedCapability, "no adapter", false),
        task_id: Some(id()),
    };
    assert_eq!(e.to_value().canonical_bytes(), br#"{"error":{"code":"UNSUPPORTED_CAPABILITY","reason":"no adapter","retryable":false,"task_id":"task-1"},"schema_version":1,"verdict":"FAIL"}"#);
    assert_eq!(TaskEnvelope::from_value(e.to_value()).unwrap(), e);
    let Value::Object(mut f) = e.to_value() else {
        panic!()
    };
    f.insert("task".into(), Value::Null);
    assert!(TaskEnvelope::from_value(Value::Object(f)).is_err());
}
#[test]
fn authenticated_context_does_not_enter_request_wire_and_dispatch_has_no_task_owner() {
    struct Adapter;
    impl TaskApplicationService for Adapter {
        fn execute(&self, c: &TaskCallContext, r: TaskRequest) -> Result<TaskResponse, TaskError> {
            assert_eq!(c.principal(), "authenticated");
            assert_eq!(c.workspace(), "workspace");
            r.validate()?;
            Err(TaskError::new(
                TaskErrorCode::AuthDenied,
                "grant revoked",
                false,
            ))
        }
    }
    let context =
        TaskCallContext::from_authenticated("authenticated".into(), "workspace".into()).unwrap();
    assert_eq!(
        Adapter
            .execute(&context, requests().remove(0))
            .unwrap_err()
            .code,
        TaskErrorCode::AuthDenied
    );
    assert!(TaskCallContext::from_authenticated("".into(), "workspace".into()).is_err());
}

#[test]
fn live_logs_at_current_end_can_be_empty_without_eof() {
    let page = TaskLogsPage {
        task_id: id(),
        stream: LogStream::Stdout,
        offset: 17,
        bytes: vec![],
        next_offset: 17,
        eof: false,
        truncated: false,
    };
    assert_eq!(TaskLogsPage::from_value(page.to_value()).unwrap(), page);
}

#[test]
fn artifact_list_rejects_mixed_provenance_and_duplicate_output_paths() {
    for field in [
        "workspace",
        "owner_principal",
        "producer_node",
        "snapshot_id",
        "environment_digest",
        "path",
    ] {
        let mut second = record();
        second.artifact_id = ArtifactId::new("artifact-2".into()).unwrap();
        second.path = "out-2.txt".into();
        match field {
            "workspace" => second.workspace = "other".into(),
            "owner_principal" => second.owner_principal = "other".into(),
            "producer_node" => second.producer_node = "other".into(),
            "snapshot_id" => {
                second.snapshot_id = nexus_domain::task::Sha256Digest::from_bytes([9; 32])
            }
            "environment_digest" => {
                second.environment_digest = nexus_domain::task::Sha256Digest::from_bytes([9; 32])
            }
            "path" => second.path = "out.txt".into(),
            _ => unreachable!(),
        }
        assert!(
            TaskArtifactList {
                task_id: id(),
                records: vec![record(), second]
            }
            .validate()
            .is_err(),
            "{field}"
        );
    }
}
