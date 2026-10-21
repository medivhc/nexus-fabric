//! N3-12 portable contract tests; expected wire shapes come from the contract.
//! JSON duplicate keys/floats and manifest parsing belong to adapter tests.
use nexus_control_api::snapshot::*;
use nexus_control_api::task::{ArtifactId, LogStream, TaskId, TaskRequest};
use nexus_domain::task::{EnvironmentRequirement, MAX_INTEGER, SubmitTaskRequest, TaskLimits};

fn obj<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn edit(value: Value, key: &str, replacement: Value) -> Value {
    let Value::Object(mut fields) = value else {
        panic!("fixture must be object")
    };
    fields.insert(key.into(), replacement);
    Value::Object(fields)
}
fn remove(value: Value, key: &str) -> Value {
    let Value::Object(mut fields) = value else {
        panic!("fixture must be object")
    };
    fields.remove(key);
    Value::Object(fields)
}
fn digest(n: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([n; 32])
}
fn uid() -> UploadId {
    UploadId::new("upload-1".into()).unwrap()
}
fn snapshot() -> SnapshotRef {
    SnapshotRef {
        schema_version: 1,
        snapshot_id: digest(1),
        workspace: "workspace".into(),
        commit_id: "commit-1".into(),
        root_manifest_id: "root-1".into(),
        manifest_sha256: digest(2),
        selection_digest: digest(3),
        file_count: 2,
        total_bytes: 7,
    }
}
fn snapshot_value() -> Value {
    obj([
        ("schema_version", Value::Integer(1)),
        ("snapshot_id", digest(1).to_value()),
        ("workspace", "workspace".to_string().to_value()),
        ("commit_id", "commit-1".to_string().to_value()),
        ("root_manifest_id", "root-1".to_string().to_value()),
        ("manifest_sha256", digest(2).to_value()),
        ("selection_digest", digest(3).to_value()),
        ("file_count", Value::Integer(2)),
        ("total_bytes", Value::Integer(7)),
    ])
}
fn begin() -> SnapshotRequest {
    SnapshotRequest::Begin {
        provider: "provider".into(),
        workspace: "workspace".into(),
        resource: "compute".into(),
        upload_key: "retry-key".into(),
        snapshot: Box::new(snapshot()),
        manifest_json: "[]".into(),
    }
}
fn begin_value() -> Value {
    obj([
        ("schema_version", Value::Integer(1)),
        ("operation", "Begin".to_string().to_value()),
        ("provider", "provider".to_string().to_value()),
        ("workspace", "workspace".to_string().to_value()),
        ("resource", "compute".to_string().to_value()),
        ("upload_key", "retry-key".to_string().to_value()),
        ("snapshot", snapshot_value()),
        ("manifest_json", "[]".to_string().to_value()),
    ])
}
fn chunk() -> SnapshotRequest {
    SnapshotRequest::PutChunk {
        upload_id: uid(),
        blob_sha256: digest(4),
        offset: 1,
        bytes: vec![0, 255],
        chunk_sha256: digest(5),
    }
}
fn chunk_value() -> Value {
    obj([
        ("schema_version", Value::Integer(1)),
        ("operation", "PutChunk".to_string().to_value()),
        ("upload_id", "upload-1".to_string().to_value()),
        ("blob_sha256", digest(4).to_value()),
        ("offset", Value::Integer(1)),
        (
            "bytes",
            Value::Array(vec![Value::Integer(0), Value::Integer(255)]),
        ),
        ("chunk_sha256", digest(5).to_value()),
    ])
}
fn id_value(operation: &str) -> Value {
    obj([
        ("schema_version", Value::Integer(1)),
        ("operation", operation.to_string().to_value()),
        ("upload_id", "upload-1".to_string().to_value()),
    ])
}
fn vectors() -> Vec<(SnapshotRequest, Value)> {
    vec![
        (begin(), begin_value()),
        (chunk(), chunk_value()),
        (SnapshotRequest::Get { upload_id: uid() }, id_value("Get")),
        (SnapshotRequest::Seal { upload_id: uid() }, id_value("Seal")),
        (
            SnapshotRequest::Cancel { upload_id: uid() },
            id_value("Cancel"),
        ),
    ]
}
fn view() -> UploadView {
    UploadView {
        schema_version: 1,
        upload_id: uid(),
        provider: "provider".into(),
        workspace: "workspace".into(),
        resource: "compute".into(),
        snapshot: snapshot(),
        state: UploadState::Receiving,
        reserved_bytes: 1_212_416,
        blobs: vec![
            UploadBlob {
                sha256: digest(4),
                size_bytes: 3,
                durable_offset: 0,
            },
            UploadBlob {
                sha256: digest(6),
                size_bytes: 4,
                durable_offset: 2,
            },
        ],
    }
}
fn view_value() -> Value {
    obj([
        ("schema_version", Value::Integer(1)),
        ("upload_id", "upload-1".to_string().to_value()),
        ("provider", "provider".to_string().to_value()),
        ("workspace", "workspace".to_string().to_value()),
        ("resource", "compute".to_string().to_value()),
        ("snapshot", snapshot_value()),
        ("state", "Receiving".to_string().to_value()),
        ("reserved_bytes", Value::Integer(1_212_416)),
        (
            "blobs",
            Value::Array(vec![
                obj([
                    ("sha256", digest(4).to_value()),
                    ("size_bytes", Value::Integer(3)),
                    ("durable_offset", Value::Integer(0)),
                ]),
                obj([
                    ("sha256", digest(6).to_value()),
                    ("size_bytes", Value::Integer(4)),
                    ("durable_offset", Value::Integer(2)),
                ]),
            ]),
        ),
    ])
}
fn full_view() -> UploadView {
    let mut v = view();
    v.state = UploadState::Staged;
    for blob in &mut v.blobs {
        blob.durable_offset = blob.size_bytes;
    }
    v
}
fn cancelled_view() -> UploadView {
    let mut v = view();
    v.state = UploadState::Cancelled;
    v.reserved_bytes = 0;
    v.blobs.clear();
    v
}

#[test]
fn upload_id_preserves_task_id_unicode_character_grammar_and_is_a_distinct_type() {
    for valid in ["x".into(), "汉/字".into(), "\n".into(), "汉".repeat(256)] {
        let parsed = UploadId::new(valid.clone()).unwrap();
        assert_eq!(parsed.as_str(), valid);
        assert_eq!(parsed.to_value(), Value::String(valid.clone()));
        assert_eq!(UploadId::from_value(Value::String(valid)).unwrap(), parsed);
    }
    for invalid in [String::new(), "a\0b".into(), "汉".repeat(257)] {
        assert!(
            UploadId::new(invalid.clone()).is_err(),
            "invalid ID {invalid:?}"
        );
        assert!(UploadId::from_value(Value::String(invalid)).is_err());
    }
    assert!(UploadId::from_value(Value::Integer(1)).is_err());
}

#[test]
fn all_five_operations_match_independent_field_vectors_and_roundtrip() {
    for (request, expected) in vectors() {
        assert_eq!(request.to_value(), expected, "operation wire shape");
        assert_eq!(SnapshotRequest::from_value(expected).unwrap(), request);
        assert!(request.validate().is_ok());
    }
}

#[test]
fn id_only_wire_has_a_fixed_canonical_byte_vector() {
    assert_eq!(
        SnapshotRequest::Get { upload_id: uid() }
            .to_value()
            .canonical_bytes(),
        br#"{"operation":"Get","schema_version":1,"upload_id":"upload-1"}"#
    );
}

#[test]
fn requests_require_every_field_and_reject_unknown_authority_or_task_fields() {
    for (_, wire) in vectors() {
        assert!(SnapshotRequest::from_value(wire.clone()).is_ok());
        let Value::Object(fields) = &wire else {
            unreachable!()
        };
        for key in fields.keys() {
            assert!(
                SnapshotRequest::from_value(remove(wire.clone(), key)).is_err(),
                "missing {key}"
            );
        }
        for field in ["principal", "owner", "task_id", "path", "extra"] {
            assert!(
                SnapshotRequest::from_value(edit(wire.clone(), field, Value::Null)).is_err(),
                "extra {field}"
            );
        }
    }
}

#[test]
fn requests_reject_unknown_operations_scalar_arrays_and_wrong_field_types() {
    assert!(SnapshotRequest::from_value(begin_value()).is_ok());
    for bad in [
        Value::Null,
        Value::Bool(true),
        Value::Array(vec![]),
        Value::Integer(1),
    ] {
        assert!(SnapshotRequest::from_value(bad).is_err());
    }
    for op in ["begin", "SubmitTask", "Spawn", ""] {
        assert!(
            SnapshotRequest::from_value(edit(
                begin_value(),
                "operation",
                op.to_string().to_value()
            ))
            .is_err()
        );
    }
    for (_, wire) in vectors() {
        let Value::Object(fields) = &wire else {
            unreachable!()
        };
        for key in fields.keys() {
            assert!(
                SnapshotRequest::from_value(edit(wire.clone(), key, Value::Null)).is_err(),
                "null {key}"
            );
        }
    }
}

#[test]
fn unsupported_versions_are_typed_without_downgrade_for_requests_and_views() {
    for (_, wire) in vectors() {
        assert!(SnapshotRequest::from_value(wire.clone()).is_ok());
        for version in [0, 2, MAX_INTEGER] {
            assert_eq!(
                SnapshotRequest::from_value(edit(
                    wire.clone(),
                    "schema_version",
                    version.to_value()
                ))
                .unwrap_err()
                .code,
                TaskErrorCode::UnsupportedVersion
            );
        }
    }
    assert!(UploadView::from_value(view_value()).is_ok());
    assert_eq!(
        UploadView::from_value(edit(view_value(), "schema_version", 2u64.to_value()))
            .unwrap_err()
            .code,
        TaskErrorCode::UnsupportedVersion
    );
}

#[test]
fn begin_rejects_invalid_scope_key_and_foreign_snapshot_workspace() {
    assert!(begin().validate().is_ok());
    for field in ["provider", "workspace", "resource", "upload_key"] {
        for bad in [String::new(), "nul\0id".into(), "a".repeat(257)] {
            assert!(
                SnapshotRequest::from_value(edit(begin_value(), field, bad.to_value())).is_err(),
                "invalid {field}"
            );
        }
    }
    let mut wire = begin_value();
    wire = edit(
        wire,
        "snapshot",
        edit(
            snapshot_value(),
            "workspace",
            "foreign".to_string().to_value(),
        ),
    );
    assert!(SnapshotRequest::from_value(wire).is_err());
}

#[test]
fn begin_manifest_uses_utf8_byte_cap_and_accepts_exact_boundary() {
    for text in ["a".repeat(65_536), "汉".repeat(21_845) + "x"] {
        assert_eq!(text.len(), 65_536);
        assert!(
            SnapshotRequest::from_value(edit(begin_value(), "manifest_json", text.to_value()))
                .is_ok()
        );
    }
    for text in ["a".repeat(65_536 + 1), "汉".repeat(21_846)] {
        assert!(
            SnapshotRequest::from_value(edit(begin_value(), "manifest_json", text.to_value()))
                .is_err()
        );
    }
}

#[test]
fn begin_snapshot_adapter_limits_allow_empty_and_exact_maximum_but_not_oversize() {
    assert!(begin().validate().is_ok());
    for (files, bytes) in [(0u64, 0u64), (1_024, 67_108_864)] {
        let s = edit(
            edit(snapshot_value(), "file_count", files.to_value()),
            "total_bytes",
            bytes.to_value(),
        );
        assert!(SnapshotRequest::from_value(edit(begin_value(), "snapshot", s)).is_ok());
    }
    for (field, value) in [("file_count", 1_025u64), ("total_bytes", 67_108_865u64)] {
        assert!(
            SnapshotRequest::from_value(edit(
                begin_value(),
                "snapshot",
                edit(snapshot_value(), field, value.to_value())
            ))
            .is_err()
        );
    }
}

#[test]
fn nested_snapshot_reuses_strict_schema_digest_and_exact_integer_rules() {
    assert!(SnapshotRequest::from_value(begin_value()).is_ok());
    for (field, value) in [
        ("extra", Value::Null),
        ("schema_version", 2u64.to_value()),
        ("manifest_sha256", "sha256:ABC".to_string().to_value()),
        ("file_count", Value::Integer(-1)),
        ("total_bytes", Value::Integer(i128::from(MAX_INTEGER) + 1)),
    ] {
        assert!(
            SnapshotRequest::from_value(edit(
                begin_value(),
                "snapshot",
                edit(snapshot_value(), field, value)
            ))
            .is_err()
        );
    }
}

#[test]
fn chunks_preserve_binary_zero_and_255_and_accept_exact_length_cap() {
    assert_eq!(SnapshotRequest::from_value(chunk_value()).unwrap(), chunk());
    let mut c = chunk();
    let SnapshotRequest::PutChunk { bytes, offset, .. } = &mut c else {
        unreachable!()
    };
    *bytes = vec![255; 65_536];
    *offset = 0;
    assert!(c.validate().is_ok());
    assert_eq!(SnapshotRequest::from_value(c.to_value()).unwrap(), c);
}

#[test]
fn chunks_reject_empty_oversize_bad_byte_values_and_non_array_payloads() {
    assert!(SnapshotRequest::from_value(chunk_value()).is_ok());
    for bytes in [
        Value::Array(vec![]),
        Value::Array(vec![Value::Integer(0); 65_536 + 1]),
        Value::Array(vec![Value::Integer(-1)]),
        Value::Array(vec![Value::Integer(256)]),
        Value::Array(vec![Value::String("1".into())]),
        Value::String("AA==".into()),
    ] {
        assert!(SnapshotRequest::from_value(edit(chunk_value(), "bytes", bytes)).is_err());
    }
}

#[test]
fn chunks_reject_inexact_negative_or_overflowing_byte_ranges() {
    assert!(SnapshotRequest::from_value(chunk_value()).is_ok());
    for offset in [
        Value::Integer(-1),
        Value::Integer(i128::from(MAX_INTEGER) + 1),
        Value::Integer(i128::from(MAX_INTEGER)),
        Value::String("1".into()),
        Value::Bool(true),
    ] {
        assert!(SnapshotRequest::from_value(edit(chunk_value(), "offset", offset)).is_err());
    }
    let legal = edit(chunk_value(), "offset", (MAX_INTEGER - 2).to_value());
    assert!(SnapshotRequest::from_value(legal).is_ok());
}

#[test]
fn chunks_require_strong_lowercase_digest_references() {
    assert!(SnapshotRequest::from_value(chunk_value()).is_ok());
    for field in ["blob_sha256", "chunk_sha256"] {
        for bad in [
            "legacy-id".into(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "0".repeat(63)),
        ] {
            assert!(
                SnapshotRequest::from_value(edit(chunk_value(), field, Value::String(bad)))
                    .is_err()
            );
        }
    }
}

#[test]
fn typed_request_validation_independently_rejects_semantic_invalid_cases() {
    assert!(begin().validate().is_ok());
    for field in ["provider", "workspace", "resource", "upload_key"] {
        for bad in [String::new(), "nul\0id".into(), "汉".repeat(257)] {
            let mut request = begin();
            let SnapshotRequest::Begin {
                provider,
                workspace,
                resource,
                upload_key,
                ..
            } = &mut request
            else {
                unreachable!()
            };
            match field {
                "provider" => *provider = bad,
                "workspace" => *workspace = bad,
                "resource" => *resource = bad,
                _ => *upload_key = bad,
            }
            assert!(request.validate().is_err(), "typed invalid {field}");
        }
    }
    for bad_manifest in ["a".repeat(65_536 + 1), "汉".repeat(21_846)] {
        let mut request = begin();
        let SnapshotRequest::Begin { manifest_json, .. } = &mut request else {
            unreachable!()
        };
        *manifest_json = bad_manifest;
        assert!(request.validate().is_err(), "typed UTF-8 manifest cap");
    }
    for field in [
        "workspace",
        "schema_version",
        "file_count",
        "total_bytes",
        "inexact_file_count",
        "inexact_total_bytes",
        "commit_id",
        "root_manifest_id",
    ] {
        let mut request = begin();
        let SnapshotRequest::Begin { snapshot, .. } = &mut request else {
            unreachable!()
        };
        match field {
            "workspace" => snapshot.workspace = "foreign".into(),
            "schema_version" => snapshot.schema_version = 2,
            "file_count" => snapshot.file_count = 1_024 + 1,
            "total_bytes" => snapshot.total_bytes = 67_108_864 + 1,
            "inexact_file_count" => snapshot.file_count = MAX_INTEGER + 1,
            "inexact_total_bytes" => snapshot.total_bytes = MAX_INTEGER + 1,
            "commit_id" => snapshot.commit_id.clear(),
            _ => snapshot.root_manifest_id.clear(),
        }
        assert!(
            request.validate().is_err(),
            "typed invalid snapshot.{field}"
        );
    }
    let mut maximum_begin = begin();
    let SnapshotRequest::Begin {
        manifest_json,
        snapshot,
        ..
    } = &mut maximum_begin
    else {
        unreachable!()
    };
    *manifest_json = "汉".repeat(21_845) + "x";
    snapshot.file_count = 1_024;
    snapshot.total_bytes = 67_108_864;
    assert!(
        maximum_begin.validate().is_ok(),
        "all legal Begin boundaries"
    );

    assert!(chunk().validate().is_ok());
    for bad_bytes in [vec![], vec![0; 65_536 + 1]] {
        let mut request = chunk();
        let SnapshotRequest::PutChunk { bytes, .. } = &mut request else {
            unreachable!()
        };
        *bytes = bad_bytes;
        assert!(
            request.validate().is_err(),
            "typed positive bounded chunk length"
        );
    }
    for bad_offset in [MAX_INTEGER, MAX_INTEGER + 1, u64::MAX] {
        let mut request = chunk();
        let SnapshotRequest::PutChunk { offset, .. } = &mut request else {
            unreachable!()
        };
        *offset = bad_offset;
        assert!(
            request.validate().is_err(),
            "typed checked range at {bad_offset}"
        );
    }
    let mut maximum_chunk = chunk();
    let SnapshotRequest::PutChunk { bytes, offset, .. } = &mut maximum_chunk else {
        unreachable!()
    };
    *bytes = vec![255; 65_536];
    *offset = MAX_INTEGER - 65_536u64;
    assert!(
        maximum_chunk.validate().is_ok(),
        "legal maximum chunk ending at MAX_INTEGER"
    );
}

#[test]
fn view_decoder_independently_enforces_cross_field_invariants() {
    assert!(UploadView::from_value(view_value()).is_ok());
    let Value::Object(base) = view_value() else {
        unreachable!()
    };
    let Value::Array(blobs) = base["blobs"].clone() else {
        unreachable!()
    };
    let full_blobs = Value::Array(vec![
        edit(blobs[0].clone(), "durable_offset", 3u64.to_value()),
        edit(blobs[1].clone(), "durable_offset", 4u64.to_value()),
    ]);
    let staged = edit(
        edit(view_value(), "state", "Staged".to_string().to_value()),
        "blobs",
        full_blobs,
    );
    assert!(
        UploadView::from_value(staged.clone()).is_ok(),
        "legal complete Staged wire"
    );
    let cancelled = edit(
        edit(
            edit(view_value(), "state", "Cancelled".to_string().to_value()),
            "reserved_bytes",
            0u64.to_value(),
        ),
        "blobs",
        Value::Array(vec![]),
    );
    assert!(
        UploadView::from_value(cancelled.clone()).is_ok(),
        "legal tombstone wire"
    );
    assert!(
        UploadView::from_value(edit(
            view_value(),
            "snapshot",
            edit(snapshot_value(), "total_bytes", 14u64.to_value())
        ))
        .is_ok(),
        "dedup does not require equality"
    );

    for (label, invalid) in [
        (
            "unsorted digests",
            edit(
                view_value(),
                "blobs",
                Value::Array(vec![blobs[1].clone(), blobs[0].clone()]),
            ),
        ),
        (
            "duplicate digests",
            edit(
                view_value(),
                "blobs",
                Value::Array(vec![blobs[0].clone(), blobs[0].clone()]),
            ),
        ),
        (
            "offset beyond size",
            edit(
                view_value(),
                "blobs",
                Value::Array(vec![
                    edit(blobs[0].clone(), "durable_offset", 4u64.to_value()),
                    blobs[1].clone(),
                ]),
            ),
        ),
        (
            "unique count beyond file count",
            edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), "file_count", 1u64.to_value()),
            ),
        ),
        (
            "unique sizes beyond total",
            edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), "total_bytes", 6u64.to_value()),
            ),
        ),
        (
            "missing active blobs",
            edit(view_value(), "blobs", Value::Array(vec![])),
        ),
        (
            "partial Staged",
            edit(view_value(), "state", "Staged".to_string().to_value()),
        ),
        (
            "Cancelled retained blobs",
            edit(cancelled.clone(), "blobs", Value::Array(blobs.clone())),
        ),
        (
            "Cancelled retained charge",
            edit(cancelled, "reserved_bytes", 1u64.to_value()),
        ),
        (
            "foreign workspace",
            edit(view_value(), "workspace", "foreign".to_string().to_value()),
        ),
        (
            "zero files with positive total",
            edit(
                edit(view_value(), "blobs", Value::Array(vec![])),
                "snapshot",
                edit(snapshot_value(), "file_count", 0u64.to_value()),
            ),
        ),
    ] {
        assert!(
            UploadView::from_value(invalid).is_err(),
            "decoder must reject {label}"
        );
    }
    for state in ["Receiving", "Staged", "Cancelling"] {
        let valid = if state == "Staged" {
            staged.clone()
        } else {
            edit(view_value(), "state", state.to_string().to_value())
        };
        assert!(
            UploadView::from_value(valid.clone()).is_ok(),
            "legal {state} control"
        );
        let invalid = edit(valid.clone(), "reserved_bytes", 0u64.to_value());
        assert!(
            UploadView::from_value(invalid).is_err(),
            "zero charge in {state}"
        );
        assert!(
            UploadView::from_value(edit(valid, "blobs", Value::Array(vec![]))).is_err(),
            "missing declared blobs in {state}"
        );
    }
}

#[test]
fn upload_view_has_exact_independent_fields_and_no_principal_or_task_identity() {
    let v = view();
    assert_eq!(v.to_value(), view_value());
    assert_eq!(UploadView::from_value(view_value()).unwrap(), v);
    let Value::Object(fields) = view_value() else {
        unreachable!()
    };
    for key in fields.keys() {
        assert!(UploadView::from_value(remove(view_value(), key)).is_err());
    }
    for extra in ["principal", "task_id", "owner_principal", "extra"] {
        assert!(UploadView::from_value(edit(view_value(), extra, Value::Null)).is_err());
    }
    let blobs = if let Value::Array(blobs) = fields["blobs"].clone() {
        blobs
    } else {
        unreachable!()
    };
    assert!(UploadBlob::from_value(edit(blobs[0].clone(), "extra", Value::Null)).is_err());
}

#[test]
fn all_four_upload_states_have_exact_pascal_case_wire_labels() {
    for (state, label) in [
        (UploadState::Receiving, "Receiving"),
        (UploadState::Staged, "Staged"),
        (UploadState::Cancelling, "Cancelling"),
        (UploadState::Cancelled, "Cancelled"),
    ] {
        assert_eq!(state.to_value(), label.to_string().to_value());
        assert_eq!(
            UploadState::from_value(label.to_string().to_value()).unwrap(),
            state
        );
    }
    for label in ["receiving", "Completed", "Unknown", ""] {
        assert!(UploadState::from_value(label.to_string().to_value()).is_err());
    }
}

fn non_string_state_values() -> Vec<(&'static str, Value)> {
    vec![
        ("null", Value::Null),
        ("false", Value::Bool(false)),
        ("true", Value::Bool(true)),
        ("integer zero", Value::Integer(0)),
        ("integer one", Value::Integer(1)),
        ("empty array", Value::Array(vec![])),
        (
            "string array",
            Value::Array(vec![Value::String("Receiving".into())]),
        ),
        ("empty object", obj([])),
        (
            "state object",
            obj([("state", Value::String("Receiving".into()))]),
        ),
    ]
}

#[test]
fn standalone_upload_state_rejects_every_non_string_value_kind() {
    assert_eq!(
        UploadState::from_value(Value::String("Receiving".into())).unwrap(),
        UploadState::Receiving,
        "exact Receiving string control"
    );
    for (kind, wrong_type) in non_string_state_values() {
        assert!(
            UploadState::from_value(wrong_type).is_err(),
            "UploadState must reject {kind} rather than default to Receiving"
        );
    }
}

#[test]
fn upload_view_state_rejects_every_non_string_value_kind() {
    let control = view_value();
    assert_eq!(
        UploadView::from_value(control.clone()).unwrap(),
        view(),
        "complete legal Receiving View control"
    );
    // Every other field remains identical to the legal Receiving control:
    // normalizing the wrong type to Receiving would otherwise be valid.
    for (kind, wrong_type) in non_string_state_values() {
        assert!(
            UploadView::from_value(edit(control.clone(), "state", wrong_type)).is_err(),
            "UploadView state must reject {kind}"
        );
    }
}

#[test]
fn pass_envelope_state_rejects_every_non_string_value_kind() {
    let control = view_value();
    assert_eq!(
        SnapshotEnvelope::from_value(pass_value(control.clone())).unwrap(),
        SnapshotEnvelope::Upload(view()),
        "complete legal Receiving PASS control"
    );
    for (kind, wrong_type) in non_string_state_values() {
        let bad_upload = edit(control.clone(), "state", wrong_type);
        assert!(
            SnapshotEnvelope::from_value(pass_value(bad_upload)).is_err(),
            "PASS upload.state must reject {kind}"
        );
    }
}

#[test]
fn blob_ranges_are_exact_bounded_and_empty_blob_is_representable() {
    let blob = view().blobs.remove(0);
    assert!(blob.validate().is_ok());
    for (size, offset) in [(0, 0), (67_108_864, 67_108_864)] {
        assert!(
            UploadBlob {
                size_bytes: size,
                durable_offset: offset,
                ..blob.clone()
            }
            .validate()
            .is_ok()
        );
    }
    for (size, offset) in [
        (3, 4),
        (67_108_864 + 1, 0),
        (MAX_INTEGER + 1, 0),
        (0, MAX_INTEGER + 1),
    ] {
        assert!(
            UploadBlob {
                size_bytes: size,
                durable_offset: offset,
                ..blob.clone()
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn views_require_sorted_unique_blob_digests_and_do_not_claim_exact_dedup_total() {
    assert!(view().validate().is_ok());
    let mut v = view();
    v.blobs.reverse();
    assert!(v.validate().is_err());
    let mut v = view();
    v.blobs[1].sha256 = v.blobs[0].sha256.clone();
    assert!(v.validate().is_err());
    let mut v = view();
    v.snapshot.total_bytes = 14;
    assert!(v.validate().is_ok(), "duplicate files may share a blob");
    let mut v = view();
    v.snapshot.file_count = 1;
    assert!(v.validate().is_err());
    let mut v = view();
    v.snapshot.total_bytes = 6;
    assert!(v.validate().is_err());
}

#[test]
fn views_reject_foreign_workspace_invalid_scope_inexact_budget_and_nested_limits() {
    assert!(view().validate().is_ok());
    let mut v = view();
    v.workspace = "other".into();
    assert!(v.validate().is_err());
    for field in ["provider", "resource", "workspace"] {
        assert!(
            UploadView::from_value(edit(view_value(), field, "".to_string().to_value())).is_err()
        );
    }
    for budget in [
        Value::Integer(-1),
        Value::Integer(i128::from(MAX_INTEGER) + 1),
        Value::String("1".into()),
    ] {
        assert!(UploadView::from_value(edit(view_value(), "reserved_bytes", budget)).is_err());
    }
    let mut v = view();
    v.snapshot.file_count = 1_024 + 1;
    assert!(v.validate().is_err());
    let mut v = view();
    v.snapshot.total_bytes = 67_108_864 + 1;
    assert!(v.validate().is_err());
}

#[test]
fn state_charge_and_durable_offsets_cannot_forge_completion_or_cleanup() {
    assert!(view().validate().is_ok());
    assert!(full_view().validate().is_ok());
    assert!(cancelled_view().validate().is_ok());
    let mut v = view();
    v.state = UploadState::Cancelling;
    assert!(v.validate().is_ok());
    for state in [
        UploadState::Receiving,
        UploadState::Staged,
        UploadState::Cancelling,
    ] {
        let mut v = full_view();
        v.state = state;
        v.reserved_bytes = 0;
        assert!(v.validate().is_err());
    }
    let mut v = view();
    v.state = UploadState::Staged;
    assert!(v.validate().is_err());
    let mut v = cancelled_view();
    v.reserved_bytes = 1;
    assert!(v.validate().is_err());
    let mut v = cancelled_view();
    v.blobs = view().blobs;
    assert!(v.validate().is_err());
}

#[test]
fn empty_snapshot_view_still_reserves_metadata_and_has_no_blob() {
    let mut v = view();
    v.snapshot.file_count = 0;
    v.snapshot.total_bytes = 0;
    v.blobs.clear();
    assert!(v.validate().is_ok());
    v.state = UploadState::Staged;
    assert!(v.validate().is_ok());
    v.reserved_bytes = 0;
    assert!(v.validate().is_err());
}

#[test]
fn active_views_cannot_omit_declared_blobs_or_assign_payload_to_zero_files() {
    assert!(view().validate().is_ok());
    for state in [
        UploadState::Receiving,
        UploadState::Staged,
        UploadState::Cancelling,
    ] {
        let mut missing = full_view();
        missing.state = state;
        missing.blobs.clear();
        assert!(
            missing.validate().is_err(),
            "nonempty files need declared blob in {state:?}"
        );

        let mut no_files = full_view();
        no_files.state = state;
        no_files.snapshot.file_count = 0;
        no_files.blobs.clear();
        assert!(
            no_files.validate().is_err(),
            "zero files cannot retain total bytes"
        );
    }
    let mut zero_length_files = view();
    zero_length_files.snapshot.total_bytes = 0;
    zero_length_files.blobs = vec![UploadBlob {
        sha256: Sha256Digest::parse(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        )
        .unwrap(),
        size_bytes: 0,
        durable_offset: 0,
    }];
    assert!(
        zero_length_files.validate().is_ok(),
        "nonempty selection of empty files declares empty blob"
    );
    assert!(
        cancelled_view().validate().is_ok(),
        "tombstone preserves original nonempty snapshot"
    );
}

#[test]
fn envelopes_use_snapshot_upload_or_typed_error_without_fake_task_id() {
    let success = SnapshotEnvelope::Upload(view());
    let wire = obj([
        ("schema_version", Value::Integer(1)),
        ("verdict", "PASS".to_string().to_value()),
        ("upload", view_value()),
    ]);
    assert_eq!(success.to_value(), wire);
    assert_eq!(SnapshotEnvelope::from_value(wire.clone()).unwrap(), success);
    for upload_id in [None, Some(uid())] {
        let error = TaskError::new(TaskErrorCode::AuthDenied, "denied", false);
        let e = SnapshotEnvelope::Error {
            error: error.clone(),
            upload_id: upload_id.clone(),
        };
        let error_wire = obj([
            ("schema_version", Value::Integer(1)),
            ("verdict", "FAIL".to_string().to_value()),
            ("error", error.to_value()),
            (
                "upload_id",
                upload_id
                    .as_ref()
                    .map_or(Value::Null, |_| "upload-1".to_string().to_value()),
            ),
        ]);
        assert_eq!(e.to_value(), error_wire);
        assert_eq!(SnapshotEnvelope::from_value(error_wire).unwrap(), e);
    }
    assert!(
        SnapshotEnvelope::from_value(edit(
            wire.clone(),
            "error",
            TaskError::invalid("extra").to_value()
        ))
        .is_err()
    );
    assert!(SnapshotEnvelope::from_value(edit(wire, "task_id", Value::Null)).is_err());
}

#[test]
fn envelopes_reject_missing_fields_extra_fields_invalid_verdict_error_or_versions() {
    let wire = obj([
        ("schema_version", Value::Integer(1)),
        ("verdict", "PASS".to_string().to_value()),
        ("upload", view_value()),
    ]);
    assert!(SnapshotEnvelope::from_value(wire.clone()).is_ok());
    for field in ["schema_version", "verdict", "upload"] {
        assert!(SnapshotEnvelope::from_value(remove(wire.clone(), field)).is_err());
    }
    for verdict in ["pass", "Unknown", "FAIL"] {
        assert!(
            SnapshotEnvelope::from_value(edit(
                wire.clone(),
                "verdict",
                verdict.to_string().to_value()
            ))
            .is_err()
        );
    }
    assert_eq!(
        SnapshotEnvelope::from_value(edit(wire.clone(), "schema_version", 2u64.to_value()))
            .unwrap_err()
            .code,
        TaskErrorCode::UnsupportedVersion
    );
    let failed = obj([
        ("schema_version", Value::Integer(1)),
        ("verdict", "FAIL".to_string().to_value()),
        ("error", TaskError::invalid("denied").to_value()),
        ("upload_id", Value::Null),
    ]);
    assert!(SnapshotEnvelope::from_value(failed.clone()).is_ok());
    assert!(SnapshotEnvelope::from_value(remove(failed.clone(), "upload_id")).is_err());
    assert!(
        SnapshotEnvelope::from_value(edit(
            failed.clone(),
            "error",
            Value::String("denied".into())
        ))
        .is_err()
    );
    assert!(
        SnapshotEnvelope::from_value(edit(failed, "upload_id", Value::String("".into()))).is_err()
    );
}

#[test]
fn response_correlation_binds_begin_scope_and_the_entire_snapshot() {
    let mut cancelling = view();
    cancelling.state = UploadState::Cancelling;
    for repeated in [view(), full_view(), cancelling, cancelled_view()] {
        assert!(repeated.validate().is_ok(), "legal repeated Begin fixture");
        assert!(
            SnapshotEnvelope::Upload(repeated)
                .validate_for(&begin())
                .is_ok()
        );
    }
    for field in ["provider", "workspace", "resource"] {
        let mut v = view();
        match field {
            "provider" => v.provider = "other".into(),
            "workspace" => {
                v.workspace = "other".into();
                v.snapshot.workspace = "other".into();
            }
            _ => v.resource = "other".into(),
        }
        assert!(v.validate().is_ok(), "isolate valid foreign {field}");
        assert!(
            SnapshotEnvelope::Upload(v).validate_for(&begin()).is_err(),
            "foreign {field}"
        );
    }
    for field in [
        "snapshot_id",
        "commit_id",
        "root_manifest_id",
        "manifest_sha256",
        "selection_digest",
        "file_count",
        "total_bytes",
    ] {
        let mut v = view();
        match field {
            "snapshot_id" => v.snapshot.snapshot_id = digest(20),
            "commit_id" => v.snapshot.commit_id = "different-commit".into(),
            "root_manifest_id" => v.snapshot.root_manifest_id = "different-root".into(),
            "manifest_sha256" => v.snapshot.manifest_sha256 = digest(21),
            "selection_digest" => v.snapshot.selection_digest = digest(22),
            "file_count" => v.snapshot.file_count = 3,
            _ => v.snapshot.total_bytes = 8,
        }
        assert!(
            v.validate().is_ok(),
            "isolate valid different snapshot.{field}"
        );
        assert!(
            SnapshotEnvelope::Upload(v).validate_for(&begin()).is_err(),
            "different snapshot.{field}"
        );
    }
}

#[test]
fn response_correlation_binds_upload_id_and_requires_seal_and_cancel_terminal_states() {
    let get = SnapshotRequest::Get { upload_id: uid() };
    assert!(SnapshotEnvelope::Upload(view()).validate_for(&get).is_ok());
    for (request, valid) in [
        (get, view()),
        (chunk(), full_view()),
        (SnapshotRequest::Seal { upload_id: uid() }, full_view()),
        (
            SnapshotRequest::Cancel { upload_id: uid() },
            cancelled_view(),
        ),
    ] {
        assert!(valid.validate().is_ok());
        assert!(
            SnapshotEnvelope::Upload(valid.clone())
                .validate_for(&request)
                .is_ok()
        );
        let mut foreign = valid;
        foreign.upload_id = UploadId::new("foreign".into()).unwrap();
        assert!(
            foreign.validate().is_ok(),
            "foreign ID view is otherwise valid"
        );
        assert!(
            SnapshotEnvelope::Upload(foreign)
                .validate_for(&request)
                .is_err(),
            "foreign ID for {request:?}"
        );
    }
    let seal = SnapshotRequest::Seal { upload_id: uid() };
    assert!(
        SnapshotEnvelope::Upload(full_view())
            .validate_for(&seal)
            .is_ok()
    );
    let mut cancelling = view();
    cancelling.state = UploadState::Cancelling;
    for v in [view(), cancelling, cancelled_view()] {
        assert!(SnapshotEnvelope::Upload(v).validate_for(&seal).is_err());
    }
    let cancel = SnapshotRequest::Cancel { upload_id: uid() };
    assert!(
        SnapshotEnvelope::Upload(cancelled_view())
            .validate_for(&cancel)
            .is_ok()
    );
    let mut cancelling = view();
    cancelling.state = UploadState::Cancelling;
    for v in [view(), full_view(), cancelling] {
        assert!(SnapshotEnvelope::Upload(v).validate_for(&cancel).is_err());
    }
}

#[test]
fn chunk_response_confirms_the_requested_range_and_blob_without_forging_progress() {
    let mut v = view();
    v.blobs[0].durable_offset = 3;
    assert!(SnapshotEnvelope::Upload(v).validate_for(&chunk()).is_ok());
    let mut partial = view();
    partial.blobs[0].durable_offset = 2;
    assert!(
        partial.validate().is_ok(),
        "isolate incomplete [1,3) confirmation"
    );
    assert!(
        SnapshotEnvelope::Upload(partial)
            .validate_for(&chunk())
            .is_err()
    );
    let mut beyond_end = view();
    beyond_end.blobs[0].size_bytes = 4;
    beyond_end.blobs[0].durable_offset = 4;
    beyond_end.snapshot.total_bytes = 8;
    assert!(
        beyond_end.validate().is_ok(),
        "larger progress is structurally valid"
    );
    assert!(
        SnapshotEnvelope::Upload(beyond_end)
            .validate_for(&chunk())
            .is_ok(),
        "retry may return progress 4 beyond end 3"
    );
    assert!(
        SnapshotEnvelope::Upload(full_view())
            .validate_for(&chunk())
            .is_ok(),
        "Staged idempotent retry"
    );
    assert!(
        SnapshotEnvelope::Upload(view())
            .validate_for(&chunk())
            .is_err()
    );
    let mut v = full_view();
    v.blobs.remove(0);
    assert!(SnapshotEnvelope::Upload(v).validate_for(&chunk()).is_err());
    let mut v = full_view();
    v.state = UploadState::Cancelling;
    assert!(SnapshotEnvelope::Upload(v).validate_for(&chunk()).is_err());
    assert!(
        SnapshotEnvelope::Upload(cancelled_view())
            .validate_for(&chunk())
            .is_err()
    );
}

#[test]
fn failure_correlation_accepts_null_but_rejects_foreign_id_and_begin_fake_identity() {
    for request in [
        SnapshotRequest::Get { upload_id: uid() },
        chunk(),
        SnapshotRequest::Seal { upload_id: uid() },
        SnapshotRequest::Cancel { upload_id: uid() },
    ] {
        for upload_id in [None, Some(uid())] {
            let e = SnapshotEnvelope::Error {
                error: TaskError::invalid("denied"),
                upload_id,
            };
            assert!(
                e.validate_for(&request).is_ok(),
                "legal error correlation for {request:?}"
            );
        }
        let wrong = SnapshotEnvelope::Error {
            error: TaskError::invalid("denied"),
            upload_id: Some(UploadId::new("foreign".into()).unwrap()),
        };
        assert!(
            wrong.validate_for(&request).is_err(),
            "foreign error ID for {request:?}"
        );
    }
    let wrong = SnapshotEnvelope::Error {
        error: TaskError::invalid("denied"),
        upload_id: Some(UploadId::new("foreign".into()).unwrap()),
    };
    let pre_begin = SnapshotEnvelope::Error {
        error: TaskError::invalid("denied"),
        upload_id: None,
    };
    assert!(pre_begin.validate_for(&begin()).is_ok());
    assert!(
        wrong.validate_for(&begin()).is_err(),
        "Begin has no known UploadId before success"
    );
}

#[test]
fn original_six_task_operations_keep_their_original_wire_and_reject_snapshot_operations() {
    let id = TaskId::new("task-1".into()).unwrap();
    let submit = SubmitTaskRequest {
        schema_version: 1,
        workspace: "workspace".into(),
        resource: "compute".into(),
        provider: "provider".into(),
        input_snapshot: snapshot(),
        command: vec!["true".into()],
        cwd: ".".into(),
        environment: EnvironmentRequirement {
            os: "linux".into(),
            architecture: "x86_64".into(),
            image_digest: digest(7),
            isolation: "container".into(),
            network: "none".into(),
        },
        limits: TaskLimits {
            timeout_seconds: 1,
            cpu_millis: 1,
            memory_bytes: 1,
            storage_bytes: 1,
            log_bytes: 1,
        },
        outputs: vec![],
        success_exit_codes: vec![0],
        idempotency_key: "key".into(),
        idempotency_ttl_seconds: 60,
    };
    let tasks = [
        (
            TaskRequest::Submit {
                request: Box::new(submit.clone()),
            },
            obj([
                ("schema_version", 1u64.to_value()),
                ("operation", "SubmitTask".to_string().to_value()),
                ("request", submit.to_value()),
            ]),
        ),
        (
            TaskRequest::Get {
                task_id: id.clone(),
            },
            task_id_wire("GetTask"),
        ),
        (
            TaskRequest::Cancel {
                task_id: id.clone(),
            },
            task_id_wire("CancelTask"),
        ),
        (
            TaskRequest::ListArtifacts {
                task_id: id.clone(),
            },
            task_id_wire("ListTaskArtifacts"),
        ),
        (
            TaskRequest::ReadLogs {
                task_id: id,
                stream: LogStream::Stdout,
                offset: 0,
                max_bytes: 1,
            },
            obj([
                ("schema_version", 1u64.to_value()),
                ("operation", "ReadTaskLogs".to_string().to_value()),
                ("task_id", "task-1".to_string().to_value()),
                ("stream", "stdout".to_string().to_value()),
                ("offset", 0u64.to_value()),
                ("max_bytes", 1u64.to_value()),
            ]),
        ),
        (
            TaskRequest::GetArtifact {
                artifact_id: ArtifactId::new("artifact-1".into()).unwrap(),
                offset: 0,
                max_bytes: 1,
            },
            obj([
                ("schema_version", 1u64.to_value()),
                ("operation", "GetArtifact".to_string().to_value()),
                ("artifact_id", "artifact-1".to_string().to_value()),
                ("offset", 0u64.to_value()),
                ("max_bytes", 1u64.to_value()),
            ]),
        ),
    ];
    for (request, expected) in tasks {
        assert_eq!(request.to_value(), expected);
        assert_eq!(TaskRequest::from_value(expected).unwrap(), request);
    }
    for (_, wire) in vectors() {
        assert!(TaskRequest::from_value(wire).is_err());
    }
}
fn task_id_wire(operation: &str) -> Value {
    obj([
        ("schema_version", 1u64.to_value()),
        ("operation", operation.to_string().to_value()),
        ("task_id", "task-1".to_string().to_value()),
    ])
}

#[test]
fn authenticated_context_remains_separate_and_service_trait_is_object_safe() {
    struct Deny;
    impl SnapshotService for Deny {
        fn execute(
            &self,
            context: &TaskCallContext,
            _request: SnapshotRequest,
        ) -> Result<UploadView, TaskError> {
            assert_eq!(context.principal(), "principal");
            assert_eq!(context.workspace(), "workspace");
            Err(TaskError::new(TaskErrorCode::AuthDenied, "denied", false))
        }
    }
    let service: Box<dyn SnapshotService> = Box::new(Deny);
    let context =
        TaskCallContext::from_authenticated("principal".into(), "workspace".into()).unwrap();
    assert_eq!(
        service.execute(&context, begin()).unwrap_err().code,
        TaskErrorCode::AuthDenied
    );
}

// Independent wire fixtures below never call the new snapshot codec to create
// their own expectations. Every decoder negative starts from an accepted value.
fn blob_value(size: u64, offset: u64) -> Value {
    obj([
        ("sha256", digest(4).to_value()),
        ("size_bytes", size.to_value()),
        ("durable_offset", offset.to_value()),
    ])
}
fn pass_value(upload: Value) -> Value {
    obj([
        ("schema_version", 1u64.to_value()),
        ("verdict", "PASS".to_string().to_value()),
        ("upload", upload),
    ])
}

#[test]
fn adapter_public_constants_equal_frozen_contract_literals() {
    assert_eq!(MAX_INTEGER, 9_007_199_254_740_991);
    assert_eq!(MAX_SNAPSHOT_FILES, 1_024);
    assert_eq!(MAX_SNAPSHOT_BYTES, 67_108_864);
    assert_eq!(MAX_CHUNK_BYTES, 65_536);
    assert_eq!(MAX_MANIFEST_BYTES, 65_536);
}

#[test]
fn typed_view_independently_checks_version_scopes_exact_charge_and_blob_range() {
    assert!(view().validate().is_ok(), "legal Receiving control");
    for version in [0, 2, MAX_INTEGER] {
        let mut v = view();
        v.schema_version = version;
        assert_eq!(
            v.validate().unwrap_err().code,
            TaskErrorCode::UnsupportedVersion
        );
    }
    for field in ["provider", "workspace", "resource"] {
        let mut maximum = view();
        let valid_id = "汉".repeat(256);
        match field {
            "provider" => maximum.provider = valid_id,
            "resource" => maximum.resource = valid_id,
            _ => {
                maximum.workspace = valid_id.clone();
                maximum.snapshot.workspace = valid_id;
            }
        }
        assert!(maximum.validate().is_ok(), "legal Unicode maximum {field}");
        for invalid in [String::new(), "nul\0id".into(), "汉".repeat(257)] {
            let mut v = view();
            match field {
                "provider" => v.provider = invalid,
                "resource" => v.resource = invalid,
                _ => {
                    v.workspace = invalid.clone();
                    v.snapshot.workspace = invalid;
                }
            }
            assert!(v.validate().is_err(), "typed invalid {field}");
        }
    }
    let mut maximum = view();
    maximum.reserved_bytes = MAX_INTEGER;
    assert!(maximum.validate().is_ok(), "positive exact charge maximum");
    let mut inexact = maximum;
    inexact.reserved_bytes = MAX_INTEGER + 1;
    assert!(
        inexact.validate().is_err(),
        "charge outside exact integer range"
    );
    let mut bad_range = view();
    bad_range.blobs[0].durable_offset = bad_range.blobs[0].size_bytes + 1;
    assert!(
        bad_range.validate().is_err(),
        "typed Receiving offset beyond size"
    );
}

#[test]
fn standalone_blob_decoder_has_independent_valid_vectors_and_strict_boundaries() {
    for (size, offset) in [(3, 0), (0, 0), (67_108_864, 67_108_864)] {
        let expected = UploadBlob {
            sha256: digest(4),
            size_bytes: size,
            durable_offset: offset,
        };
        let wire = blob_value(size, offset);
        assert_eq!(UploadBlob::from_value(wire.clone()).unwrap(), expected);
        assert_eq!(expected.to_value(), wire);
        assert!(expected.validate().is_ok());
    }
    let legal = blob_value(3, 0);
    assert!(
        UploadBlob::from_value(legal.clone()).is_ok(),
        "standalone valid control"
    );
    for field in ["sha256", "size_bytes", "durable_offset"] {
        assert!(
            UploadBlob::from_value(remove(legal.clone(), field)).is_err(),
            "missing {field}"
        );
        assert!(
            UploadBlob::from_value(edit(legal.clone(), field, Value::Null)).is_err(),
            "null {field}"
        );
    }
    assert!(UploadBlob::from_value(edit(legal.clone(), "extra", Value::Null)).is_err());
    for (size, offset) in [
        (3, 4),
        (67_108_865, 0),
        (MAX_INTEGER + 1, 0),
        (3, MAX_INTEGER + 1),
    ] {
        assert!(
            UploadBlob::from_value(blob_value(size, offset)).is_err(),
            "invalid range {size}/{offset}"
        );
    }
    for field in ["size_bytes", "durable_offset"] {
        for invalid in [
            Value::Integer(-1),
            Value::String("1".into()),
            Value::Bool(true),
        ] {
            assert!(
                UploadBlob::from_value(edit(legal.clone(), field, invalid)).is_err(),
                "inexact {field}"
            );
        }
    }
    for invalid in [
        "legacy-id".into(),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "0".repeat(63)),
    ] {
        assert!(
            UploadBlob::from_value(edit(legal.clone(), "sha256", Value::String(invalid))).is_err()
        );
    }
}

#[test]
fn view_decoder_and_typed_validator_accept_empty_zero_blob_and_adapter_maxima() {
    for state in [
        UploadState::Receiving,
        UploadState::Staged,
        UploadState::Cancelling,
    ] {
        let label = match state {
            UploadState::Receiving => "Receiving",
            UploadState::Staged => "Staged",
            UploadState::Cancelling => "Cancelling",
            _ => unreachable!(),
        };
        let mut empty = view();
        empty.state = state;
        empty.snapshot.file_count = 0;
        empty.snapshot.total_bytes = 0;
        empty.blobs.clear();
        let empty_wire = edit(
            edit(
                edit(view_value(), "state", label.to_string().to_value()),
                "snapshot",
                edit(
                    edit(snapshot_value(), "file_count", 0u64.to_value()),
                    "total_bytes",
                    0u64.to_value(),
                ),
            ),
            "blobs",
            Value::Array(vec![]),
        );
        assert!(empty.validate().is_ok(), "typed empty {label}");
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(empty_wire.clone())).unwrap(),
            SnapshotEnvelope::Upload(empty.clone())
        );
        assert_eq!(
            UploadView::from_value(empty_wire).unwrap(),
            empty,
            "decoded empty {label}"
        );

        let mut zero_blob = empty;
        zero_blob.snapshot.file_count = 2;
        zero_blob.blobs.push(UploadBlob {
            sha256: digest(4),
            size_bytes: 0,
            durable_offset: 0,
        });
        let zero_wire = edit(
            edit(
                edit(view_value(), "state", label.to_string().to_value()),
                "snapshot",
                edit(snapshot_value(), "total_bytes", 0u64.to_value()),
            ),
            "blobs",
            Value::Array(vec![blob_value(0, 0)]),
        );
        assert!(
            zero_blob.validate().is_ok(),
            "typed zero length blob {label}"
        );
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(zero_wire.clone())).unwrap(),
            SnapshotEnvelope::Upload(zero_blob.clone())
        );
        assert_eq!(
            UploadView::from_value(zero_wire).unwrap(),
            zero_blob,
            "decoded zero length blob {label}"
        );
    }
    let mut maximum = view();
    maximum.snapshot.file_count = 1_024;
    maximum.snapshot.total_bytes = 67_108_864;
    maximum.reserved_bytes = MAX_INTEGER;
    let maximum_wire = edit(
        edit(view_value(), "reserved_bytes", MAX_INTEGER.to_value()),
        "snapshot",
        edit(
            edit(snapshot_value(), "file_count", 1_024u64.to_value()),
            "total_bytes",
            67_108_864u64.to_value(),
        ),
    );
    assert!(maximum.validate().is_ok(), "typed legal adapter maxima");
    assert_eq!(
        SnapshotEnvelope::from_value(pass_value(maximum_wire.clone())).unwrap(),
        SnapshotEnvelope::Upload(maximum.clone())
    );
    assert_eq!(UploadView::from_value(maximum_wire).unwrap(), maximum);
    for (field, invalid) in [("file_count", 1_025u64), ("total_bytes", 67_108_865u64)] {
        assert!(
            UploadView::from_value(edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), field, invalid.to_value())
            ))
            .is_err(),
            "decoded over-limit {field}"
        );
    }
}

// Single-rule mutations of valid views test the PASS envelope's nested decoder
// and typed correlation entry independently. Get's ID stays unchanged, so it
// cannot reject these solely for response/request identity mismatch.
fn invalid_nested_view_cases() -> Vec<(String, UploadView, Value)> {
    let mut cases = Vec::new();
    for version in [0, 2] {
        let mut v = view();
        v.schema_version = version;
        cases.push((
            format!("outer version {version}"),
            v,
            edit(view_value(), "schema_version", version.to_value()),
        ));
    }
    for field in ["provider", "workspace", "resource"] {
        for invalid in [String::new(), "nul\0id".into(), "汉".repeat(257)] {
            let mut v = view();
            let mut wire = edit(view_value(), field, invalid.to_value());
            match field {
                "provider" => v.provider = invalid,
                "resource" => v.resource = invalid,
                _ => {
                    v.workspace = invalid.clone();
                    v.snapshot.workspace = invalid.clone();
                    wire = edit(
                        wire,
                        "snapshot",
                        edit(snapshot_value(), "workspace", invalid.to_value()),
                    );
                }
            }
            cases.push((format!("invalid scope {field}"), v, wire));
        }
    }
    let mut v = view();
    v.workspace = "foreign".into();
    cases.push((
        "foreign snapshot workspace".into(),
        v,
        edit(view_value(), "workspace", "foreign".to_string().to_value()),
    ));
    for charge in [0, MAX_INTEGER + 1] {
        let mut v = view();
        v.reserved_bytes = charge;
        cases.push((
            format!("invalid active charge {charge}"),
            v,
            edit(view_value(), "reserved_bytes", charge.to_value()),
        ));
    }
    for (field, invalid) in [
        ("schema_version", 2u64),
        ("file_count", 1_025),
        ("total_bytes", 67_108_865),
    ] {
        let mut v = view();
        match field {
            "schema_version" => v.snapshot.schema_version = invalid,
            "file_count" => v.snapshot.file_count = invalid,
            _ => v.snapshot.total_bytes = invalid,
        }
        cases.push((
            format!("nested {field}"),
            v,
            edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), field, invalid.to_value()),
            ),
        ));
    }
    for field in ["commit_id", "root_manifest_id"] {
        for invalid in [String::new(), "nul\0id".into(), "汉".repeat(257)] {
            let mut v = view();
            if field == "commit_id" {
                v.snapshot.commit_id = invalid.clone();
            } else {
                v.snapshot.root_manifest_id = invalid.clone();
            }
            cases.push((
                format!("nested invalid {field}"),
                v,
                edit(
                    view_value(),
                    "snapshot",
                    edit(snapshot_value(), field, invalid.to_value()),
                ),
            ));
        }
    }
    let Value::Object(fields) = view_value() else {
        unreachable!()
    };
    let Value::Array(blobs) = fields["blobs"].clone() else {
        unreachable!()
    };
    let mut v = view();
    v.blobs.reverse();
    cases.push((
        "unsorted digests".into(),
        v,
        edit(
            view_value(),
            "blobs",
            Value::Array(vec![blobs[1].clone(), blobs[0].clone()]),
        ),
    ));
    let mut v = view();
    v.blobs[1].sha256 = v.blobs[0].sha256.clone();
    cases.push((
        "duplicate digest".into(),
        v,
        edit(
            view_value(),
            "blobs",
            Value::Array(vec![
                blobs[0].clone(),
                edit(blobs[1].clone(), "sha256", digest(4).to_value()),
            ]),
        ),
    ));
    let mut v = view();
    v.blobs[0].durable_offset = 4;
    cases.push((
        "offset beyond size".into(),
        v,
        edit(
            view_value(),
            "blobs",
            Value::Array(vec![blob_value(3, 4), blobs[1].clone()]),
        ),
    ));
    for (field, invalid) in [("file_count", 1u64), ("total_bytes", 6u64)] {
        let mut v = view();
        if field == "file_count" {
            v.snapshot.file_count = invalid;
        } else {
            v.snapshot.total_bytes = invalid;
        }
        cases.push((
            format!("unique blobs exceed {field}"),
            v,
            edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), field, invalid.to_value()),
            ),
        ));
    }
    for state in [
        UploadState::Receiving,
        UploadState::Staged,
        UploadState::Cancelling,
    ] {
        let label = match state {
            UploadState::Receiving => "Receiving",
            UploadState::Staged => "Staged",
            _ => "Cancelling",
        };
        let mut v = full_view();
        v.state = state;
        v.blobs.clear();
        cases.push((
            format!("missing blobs {label}"),
            v,
            edit(
                edit(view_value(), "state", label.to_string().to_value()),
                "blobs",
                Value::Array(vec![]),
            ),
        ));
    }
    let mut v = view();
    v.state = UploadState::Staged;
    cases.push((
        "partial Staged".into(),
        v,
        edit(view_value(), "state", "Staged".to_string().to_value()),
    ));
    let cancelled_wire = edit(
        edit(
            edit(view_value(), "state", "Cancelled".to_string().to_value()),
            "reserved_bytes",
            0u64.to_value(),
        ),
        "blobs",
        Value::Array(vec![]),
    );
    let mut v = cancelled_view();
    v.reserved_bytes = 1;
    cases.push((
        "Cancelled retained charge".into(),
        v,
        edit(cancelled_wire.clone(), "reserved_bytes", 1u64.to_value()),
    ));
    let mut v = cancelled_view();
    v.blobs = view().blobs;
    cases.push((
        "Cancelled retained blobs".into(),
        v,
        edit(cancelled_wire, "blobs", Value::Array(blobs)),
    ));
    let mut v = view();
    v.snapshot.file_count = 0;
    v.blobs.clear();
    cases.push((
        "zero files with positive total".into(),
        v,
        edit(
            edit(view_value(), "blobs", Value::Array(vec![])),
            "snapshot",
            edit(snapshot_value(), "file_count", 0u64.to_value()),
        ),
    ));
    cases
}

#[test]
fn success_envelope_decoder_cannot_bypass_any_nested_view_constraint() {
    assert_eq!(
        SnapshotEnvelope::from_value(pass_value(view_value())).unwrap(),
        SnapshotEnvelope::Upload(view())
    );
    for (label, _, invalid) in invalid_nested_view_cases() {
        assert!(
            SnapshotEnvelope::from_value(pass_value(invalid)).is_err(),
            "PASS decoder must reject {label}"
        );
    }
}

#[test]
fn typed_response_correlation_revalidates_intrinsic_view_constraints() {
    let get = SnapshotRequest::Get { upload_id: uid() };
    for valid in [view(), full_view(), cancelled_view()] {
        assert!(
            SnapshotEnvelope::Upload(valid).validate_for(&get).is_ok(),
            "legal matching Get control"
        );
    }
    for (label, invalid, _) in invalid_nested_view_cases() {
        assert!(
            SnapshotEnvelope::Upload(invalid)
                .validate_for(&get)
                .is_err(),
            "matching response must reject {label}"
        );
    }
}

#[test]
fn intrinsic_view_constraints_are_identical_for_typed_and_decoded_entries() {
    assert!(view().validate().is_ok());
    assert_eq!(UploadView::from_value(view_value()).unwrap(), view());
    for (label, invalid, wire) in invalid_nested_view_cases() {
        assert!(
            invalid.validate().is_err(),
            "typed view must reject {label}"
        );
        assert!(
            UploadView::from_value(wire).is_err(),
            "decoded view must reject {label}"
        );
    }
}

#[test]
fn view_and_envelope_decoders_accept_unicode_scope_boundaries_without_byte_cap() {
    for field in ["provider", "workspace", "resource"] {
        let boundary = "汉/".to_string() + &"字".repeat(254);
        assert_eq!(boundary.chars().count(), 256);
        let mut expected = view();
        let mut wire = edit(view_value(), field, boundary.to_value());
        match field {
            "provider" => expected.provider = boundary,
            "resource" => expected.resource = boundary,
            _ => {
                expected.workspace = boundary.clone();
                expected.snapshot.workspace = boundary.clone();
                wire = edit(
                    wire,
                    "snapshot",
                    edit(snapshot_value(), "workspace", boundary.to_value()),
                );
            }
        }
        assert!(expected.validate().is_ok(), "typed Unicode scope {field}");
        assert_eq!(UploadView::from_value(wire.clone()).unwrap(), expected);
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(wire)).unwrap(),
            SnapshotEnvelope::Upload(expected)
        );
    }
}

#[test]
fn view_and_pass_envelope_decoders_cannot_skip_nested_field_shapes_or_scalar_rules() {
    assert_eq!(UploadView::from_value(view_value()).unwrap(), view());
    assert_eq!(
        SnapshotEnvelope::from_value(pass_value(view_value())).unwrap(),
        SnapshotEnvelope::Upload(view())
    );
    let mut invalid = Vec::new();
    let Value::Object(snapshot_fields) = snapshot_value() else {
        unreachable!()
    };
    for field in snapshot_fields.keys() {
        invalid.push((
            format!("snapshot missing {field}"),
            edit(view_value(), "snapshot", remove(snapshot_value(), field)),
        ));
        invalid.push((
            format!("snapshot null {field}"),
            edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), field, Value::Null),
            ),
        ));
    }
    invalid.push((
        "snapshot unknown field".into(),
        edit(
            view_value(),
            "snapshot",
            edit(snapshot_value(), "extra", Value::Null),
        ),
    ));
    for field in ["snapshot_id", "manifest_sha256", "selection_digest"] {
        invalid.push((
            format!("snapshot malformed digest {field}"),
            edit(
                view_value(),
                "snapshot",
                edit(snapshot_value(), field, "legacy-id".to_string().to_value()),
            ),
        ));
    }
    for field in ["file_count", "total_bytes"] {
        for bad in [
            Value::Integer(-1),
            Value::Integer(i128::from(MAX_INTEGER) + 1),
            Value::String("1".into()),
        ] {
            invalid.push((
                format!("snapshot inexact {field}"),
                edit(view_value(), "snapshot", edit(snapshot_value(), field, bad)),
            ));
        }
    }
    for id in [String::new(), "nul\0id".into(), "汉".repeat(257)] {
        invalid.push((
            "invalid upload ID".into(),
            edit(view_value(), "upload_id", id.to_value()),
        ));
    }
    invalid.push((
        "unknown state".into(),
        edit(view_value(), "state", "Completed".to_string().to_value()),
    ));
    for field in ["sha256", "size_bytes", "durable_offset"] {
        for blob in [
            remove(blob_value(3, 0), field),
            edit(blob_value(3, 0), field, Value::Null),
        ] {
            invalid.push((
                format!("nested blob field {field}"),
                edit(
                    view_value(),
                    "blobs",
                    Value::Array(vec![
                        blob,
                        obj([
                            ("sha256", digest(6).to_value()),
                            ("size_bytes", 4u64.to_value()),
                            ("durable_offset", 2u64.to_value()),
                        ]),
                    ]),
                ),
            ));
        }
    }
    for blob in [
        edit(blob_value(3, 0), "extra", Value::Null),
        edit(
            blob_value(3, 0),
            "sha256",
            "legacy-id".to_string().to_value(),
        ),
    ] {
        invalid.push((
            "nested blob strict shape/digest".into(),
            edit(view_value(), "blobs", Value::Array(vec![blob])),
        ));
    }
    for (label, wire) in invalid {
        assert!(
            UploadView::from_value(wire.clone()).is_err(),
            "view decoder {label}"
        );
        assert!(
            SnapshotEnvelope::from_value(pass_value(wire)).is_err(),
            "PASS decoder {label}"
        );
    }
}

#[test]
fn pass_envelopes_decode_all_legal_states_and_empty_cancelled_tombstone() {
    let Value::Object(fields) = view_value() else {
        unreachable!()
    };
    let Value::Array(blobs) = fields["blobs"].clone() else {
        unreachable!()
    };
    let staged_wire = edit(
        edit(view_value(), "state", "Staged".to_string().to_value()),
        "blobs",
        Value::Array(vec![
            edit(blobs[0].clone(), "durable_offset", 3u64.to_value()),
            edit(blobs[1].clone(), "durable_offset", 4u64.to_value()),
        ]),
    );
    let mut cancelling = view();
    cancelling.state = UploadState::Cancelling;
    let cancelled_wire = edit(
        edit(
            edit(view_value(), "state", "Cancelled".to_string().to_value()),
            "reserved_bytes",
            0u64.to_value(),
        ),
        "blobs",
        Value::Array(vec![]),
    );
    let mut empty_cancelled = cancelled_view();
    empty_cancelled.snapshot.file_count = 0;
    empty_cancelled.snapshot.total_bytes = 0;
    let empty_cancelled_wire = edit(
        cancelled_wire.clone(),
        "snapshot",
        edit(
            edit(snapshot_value(), "file_count", 0u64.to_value()),
            "total_bytes",
            0u64.to_value(),
        ),
    );
    let get = SnapshotRequest::Get { upload_id: uid() };
    for (expected, wire) in [
        (view(), view_value()),
        (full_view(), staged_wire),
        (
            cancelling,
            edit(view_value(), "state", "Cancelling".to_string().to_value()),
        ),
        (cancelled_view(), cancelled_wire),
        (empty_cancelled, empty_cancelled_wire),
    ] {
        assert!(
            expected.validate().is_ok(),
            "legal {:?} fixture",
            expected.state
        );
        assert_eq!(UploadView::from_value(wire.clone()).unwrap(), expected);
        let envelope = SnapshotEnvelope::Upload(expected);
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(wire)).unwrap(),
            envelope
        );
        assert!(
            envelope.validate_for(&get).is_ok(),
            "matching legal Get response"
        );
    }
}

fn legal_generic_ids() -> Vec<String> {
    vec![
        "汉/字".into(),
        "\n".into(),
        "汉/\n".to_string() + &"字".repeat(253),
    ]
}
fn illegal_generic_ids() -> Vec<String> {
    vec![String::new(), "nul\0id".into(), "汉".repeat(257)]
}
fn requests_with_upload_id(id: &str) -> Vec<(SnapshotRequest, Value)> {
    vectors()
        .into_iter()
        .filter_map(|(mut request, wire)| {
            let upload_id = match &mut request {
                SnapshotRequest::Begin { .. } => return None,
                SnapshotRequest::PutChunk { upload_id, .. }
                | SnapshotRequest::Get { upload_id }
                | SnapshotRequest::Seal { upload_id }
                | SnapshotRequest::Cancel { upload_id } => upload_id,
            };
            *upload_id = UploadId::new(id.to_string()).unwrap();
            Some((request, edit(wire, "upload_id", id.to_string().to_value())))
        })
        .collect()
}
fn error_value(upload_id: Value) -> Value {
    obj([
        ("schema_version", 1u64.to_value()),
        ("verdict", "FAIL".to_string().to_value()),
        (
            "error",
            obj([
                ("code", "AUTH_DENIED".to_string().to_value()),
                ("reason", "denied".to_string().to_value()),
                ("retryable", Value::Bool(false)),
            ]),
        ),
        ("upload_id", upload_id),
    ])
}

#[test]
fn every_upload_id_consumer_preserves_generic_unicode_and_rejects_invalid_strings() {
    for id in legal_generic_ids() {
        assert!(id.chars().count() <= 256);
        let parsed_id = UploadId::new(id.clone()).unwrap();
        let mut expected_view = view();
        expected_view.upload_id = parsed_id.clone();
        let wire = edit(view_value(), "upload_id", id.to_value());
        assert!(expected_view.validate().is_ok(), "typed view Unicode ID");
        assert_eq!(UploadView::from_value(wire.clone()).unwrap(), expected_view);
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(wire)).unwrap(),
            SnapshotEnvelope::Upload(expected_view)
        );
        for (request, request_wire) in requests_with_upload_id(&id) {
            assert!(
                request.validate().is_ok(),
                "legal Unicode ID in {request:?}"
            );
            assert_eq!(
                SnapshotRequest::from_value(request_wire.clone()).unwrap(),
                request
            );
            assert_eq!(request.to_value(), request_wire);
            let mut response = match &request {
                SnapshotRequest::Cancel { .. } => cancelled_view(),
                SnapshotRequest::Seal { .. } | SnapshotRequest::PutChunk { .. } => full_view(),
                _ => view(),
            };
            response.upload_id = parsed_id.clone();
            assert!(
                SnapshotEnvelope::Upload(response)
                    .validate_for(&request)
                    .is_ok(),
                "correlation preserves Unicode ID"
            );
            for upload_id in [None, Some(parsed_id.clone())] {
                let expected = SnapshotEnvelope::Error {
                    error: TaskError::new(TaskErrorCode::AuthDenied, "denied", false),
                    upload_id: upload_id.clone(),
                };
                let wire = error_value(upload_id.as_ref().map_or(Value::Null, |_| id.to_value()));
                assert_eq!(
                    SnapshotEnvelope::from_value(wire.clone()).unwrap(),
                    expected
                );
                assert_eq!(expected.to_value(), wire);
                assert!(
                    expected.validate_for(&request).is_ok(),
                    "legal correlated FAIL/null ID"
                );
            }
            for bad in illegal_generic_ids() {
                assert!(
                    SnapshotRequest::from_value(edit(
                        request_wire.clone(),
                        "upload_id",
                        bad.to_value()
                    ))
                    .is_err(),
                    "invalid ID in {request:?}"
                );
            }
        }
    }
    // The complete FAIL fixture isolates ID grammar from shape and error rules.
    assert!(SnapshotEnvelope::from_value(error_value("upload-1".to_string().to_value())).is_ok());
    for bad in illegal_generic_ids() {
        let wire = edit(view_value(), "upload_id", bad.to_value());
        assert!(UploadView::from_value(wire.clone()).is_err());
        assert!(SnapshotEnvelope::from_value(pass_value(wire)).is_err());
        assert!(SnapshotEnvelope::from_value(error_value(bad.to_value())).is_err());
    }
}

#[test]
fn begin_and_nested_snapshot_id_consumers_accept_the_inherited_unicode_boundary() {
    for id in legal_generic_ids() {
        for field in [
            "provider",
            "workspace",
            "resource",
            "upload_key",
            "commit_id",
            "root_manifest_id",
        ] {
            let mut request = begin();
            let SnapshotRequest::Begin {
                provider,
                workspace,
                resource,
                upload_key,
                snapshot,
                ..
            } = &mut request
            else {
                unreachable!()
            };
            let mut wire = begin_value();
            match field {
                "provider" => {
                    *provider = id.clone();
                    wire = edit(wire, field, id.to_value());
                }
                "resource" => {
                    *resource = id.clone();
                    wire = edit(wire, field, id.to_value());
                }
                "upload_key" => {
                    *upload_key = id.clone();
                    wire = edit(wire, field, id.to_value());
                }
                "workspace" => {
                    *workspace = id.clone();
                    snapshot.workspace = id.clone();
                    wire = edit(
                        edit(wire, field, id.to_value()),
                        "snapshot",
                        edit(snapshot_value(), field, id.to_value()),
                    );
                }
                "commit_id" => {
                    snapshot.commit_id = id.clone();
                    wire = edit(
                        wire,
                        "snapshot",
                        edit(snapshot_value(), field, id.to_value()),
                    );
                }
                _ => {
                    snapshot.root_manifest_id = id.clone();
                    wire = edit(
                        wire,
                        "snapshot",
                        edit(snapshot_value(), field, id.to_value()),
                    );
                }
            }
            assert!(request.validate().is_ok(), "typed Begin generic {field}");
            assert_eq!(SnapshotRequest::from_value(wire.clone()).unwrap(), request);
            assert_eq!(request.to_value(), wire);
            let mut response = view();
            let SnapshotRequest::Begin {
                provider,
                workspace,
                resource,
                snapshot,
                ..
            } = &request
            else {
                unreachable!()
            };
            response.provider = provider.clone();
            response.workspace = workspace.clone();
            response.resource = resource.clone();
            response.snapshot = *snapshot.clone();
            let mut response_wire = view_value();
            if field != "upload_key" {
                if field == "workspace" {
                    response_wire = edit(
                        edit(response_wire, field, id.to_value()),
                        "snapshot",
                        edit(snapshot_value(), field, id.to_value()),
                    );
                } else if field == "commit_id" || field == "root_manifest_id" {
                    response_wire = edit(
                        response_wire,
                        "snapshot",
                        edit(snapshot_value(), field, id.to_value()),
                    );
                } else {
                    response_wire = edit(response_wire, field, id.to_value());
                }
            }
            assert!(
                response.validate().is_ok(),
                "typed response generic {field}"
            );
            assert_eq!(
                UploadView::from_value(response_wire.clone()).unwrap(),
                response
            );
            assert_eq!(
                SnapshotEnvelope::from_value(pass_value(response_wire)).unwrap(),
                SnapshotEnvelope::Upload(response.clone())
            );
            assert!(
                SnapshotEnvelope::Upload(response)
                    .validate_for(&request)
                    .is_ok(),
                "Begin correlates inherited {field}"
            );
            let pre_begin_failure = SnapshotEnvelope::Error {
                error: TaskError::new(TaskErrorCode::AuthDenied, "denied", false),
                upload_id: None,
            };
            assert_eq!(
                SnapshotEnvelope::from_value(error_value(Value::Null)).unwrap(),
                pre_begin_failure
            );
            assert!(pre_begin_failure.validate_for(&request).is_ok());
        }
    }
}

fn invalid_snapshot_value_cases() -> Vec<(String, Value)> {
    let mut invalid = Vec::new();
    let Value::Object(fields) = snapshot_value() else {
        unreachable!()
    };
    for field in fields.keys() {
        invalid.push((format!("missing {field}"), remove(snapshot_value(), field)));
        invalid.push((
            format!("null {field}"),
            edit(snapshot_value(), field, Value::Null),
        ));
        // Boolean is the wrong scalar type for every SnapshotRef field.
        invalid.push((
            format!("wrong type {field}"),
            edit(snapshot_value(), field, Value::Bool(true)),
        ));
    }
    invalid.push((
        "extra field".into(),
        edit(snapshot_value(), "extra", Value::Null),
    ));
    for field in ["workspace", "commit_id", "root_manifest_id"] {
        for bad in illegal_generic_ids() {
            invalid.push((
                format!("invalid ID {field}"),
                edit(snapshot_value(), field, bad.to_value()),
            ));
        }
    }
    for field in ["snapshot_id", "manifest_sha256", "selection_digest"] {
        for bad in [
            "legacy-id".into(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "0".repeat(63)),
        ] {
            invalid.push((
                format!("digest grammar {field}"),
                edit(snapshot_value(), field, Value::String(bad)),
            ));
        }
    }
    for version in [0u64, 2, MAX_INTEGER] {
        invalid.push((
            format!("unsupported schema {version}"),
            edit(snapshot_value(), "schema_version", version.to_value()),
        ));
    }
    for bad in [
        Value::Integer(-1),
        Value::Integer(i128::from(MAX_INTEGER) + 1),
        Value::String("1".into()),
    ] {
        invalid.push((
            "inexact schema_version".into(),
            edit(snapshot_value(), "schema_version", bad),
        ));
    }
    for field in ["file_count", "total_bytes"] {
        for bad in [
            Value::Integer(-1),
            Value::Integer(i128::from(MAX_INTEGER) + 1),
            Value::String("1".into()),
        ] {
            invalid.push((
                format!("inexact {field}"),
                edit(snapshot_value(), field, bad),
            ));
        }
    }
    for (field, bad) in [("file_count", 1_025u64), ("total_bytes", 67_108_865u64)] {
        invalid.push((
            format!("adapter limit {field}"),
            edit(snapshot_value(), field, bad.to_value()),
        ));
    }
    invalid
}

#[test]
fn every_nested_snapshot_decoder_preserves_the_full_inherited_strict_contract() {
    assert_eq!(SnapshotRequest::from_value(begin_value()).unwrap(), begin());
    assert_eq!(UploadView::from_value(view_value()).unwrap(), view());
    assert_eq!(
        SnapshotEnvelope::from_value(pass_value(view_value())).unwrap(),
        SnapshotEnvelope::Upload(view())
    );
    for (label, invalid) in invalid_snapshot_value_cases() {
        let mut begin_wire = begin_value();
        let mut view_wire = view_value();
        if label == "invalid ID workspace" {
            let Value::Object(fields) = &invalid else {
                unreachable!()
            };
            // Preserve scope equality so mismatch cannot hide a missing
            // inherited ID-grammar check at any nested decoder entrance.
            begin_wire = edit(begin_wire, "workspace", fields["workspace"].clone());
            view_wire = edit(view_wire, "workspace", fields["workspace"].clone());
        }
        assert!(
            SnapshotRequest::from_value(edit(begin_wire, "snapshot", invalid.clone())).is_err(),
            "Begin snapshot {label}"
        );
        let wire = edit(view_wire, "snapshot", invalid);
        assert!(
            UploadView::from_value(wire.clone()).is_err(),
            "view snapshot {label}"
        );
        assert!(
            SnapshotEnvelope::from_value(pass_value(wire)).is_err(),
            "PASS snapshot {label}"
        );
    }
}

#[test]
fn typed_begin_rejects_each_expressible_nested_id_and_schema_constraint() {
    assert!(begin().validate().is_ok());
    for field in ["workspace", "commit_id", "root_manifest_id"] {
        for bad in illegal_generic_ids() {
            let mut request = begin();
            let SnapshotRequest::Begin {
                workspace,
                snapshot,
                ..
            } = &mut request
            else {
                unreachable!()
            };
            if field == "workspace" {
                *workspace = bad.clone();
                snapshot.workspace = bad;
            } else if field == "commit_id" {
                snapshot.commit_id = bad;
            } else {
                snapshot.root_manifest_id = bad;
            }
            assert!(
                request.validate().is_err(),
                "typed Begin invalid nested {field}"
            );
        }
    }
    for version in [0, 2, MAX_INTEGER] {
        let mut request = begin();
        let SnapshotRequest::Begin { snapshot, .. } = &mut request else {
            unreachable!()
        };
        snapshot.schema_version = version;
        assert_eq!(
            request.validate().unwrap_err().code,
            TaskErrorCode::UnsupportedVersion
        );
    }
}

#[test]
fn fail_envelope_has_an_independent_exact_shape_and_strict_typed_error_decoder() {
    let error = TaskError::new(TaskErrorCode::AuthDenied, "denied", false);
    for upload_id in [None, Some(uid())] {
        let wire = error_value(
            upload_id
                .as_ref()
                .map_or(Value::Null, |_| "upload-1".to_string().to_value()),
        );
        let expected = SnapshotEnvelope::Error {
            error: error.clone(),
            upload_id,
        };
        assert_eq!(
            SnapshotEnvelope::from_value(wire.clone()).unwrap(),
            expected
        );
        assert_eq!(expected.to_value(), wire);
        for field in ["schema_version", "verdict", "error", "upload_id"] {
            assert!(
                SnapshotEnvelope::from_value(remove(wire.clone(), field)).is_err(),
                "FAIL missing {field}"
            );
        }
        for field in ["schema_version", "verdict", "error"] {
            assert!(
                SnapshotEnvelope::from_value(edit(wire.clone(), field, Value::Null)).is_err(),
                "FAIL null {field}"
            );
            assert!(
                SnapshotEnvelope::from_value(edit(wire.clone(), field, Value::Bool(true))).is_err(),
                "FAIL wrong type {field}"
            );
        }
        for field in ["extra", "principal", "owner", "task_id", "upload"] {
            assert!(
                SnapshotEnvelope::from_value(edit(wire.clone(), field, Value::Null)).is_err(),
                "FAIL unknown {field}"
            );
        }
        for version in [0, 2, MAX_INTEGER] {
            assert_eq!(
                SnapshotEnvelope::from_value(edit(
                    wire.clone(),
                    "schema_version",
                    version.to_value()
                ))
                .unwrap_err()
                .code,
                TaskErrorCode::UnsupportedVersion
            );
        }
        for verdict in ["fail", "Unknown", "", "PASS"] {
            assert!(
                SnapshotEnvelope::from_value(edit(
                    wire.clone(),
                    "verdict",
                    verdict.to_string().to_value()
                ))
                .is_err(),
                "FAIL verdict {verdict}"
            );
        }
        let Value::Object(fields) = wire.clone() else {
            unreachable!()
        };
        let error_wire = fields["error"].clone();
        for field in ["code", "reason", "retryable"] {
            assert!(
                SnapshotEnvelope::from_value(edit(
                    wire.clone(),
                    "error",
                    remove(error_wire.clone(), field)
                ))
                .is_err(),
                "FAIL error missing {field}"
            );
            assert!(
                SnapshotEnvelope::from_value(edit(
                    wire.clone(),
                    "error",
                    edit(error_wire.clone(), field, Value::Null)
                ))
                .is_err(),
                "FAIL error null {field}"
            );
            assert!(
                SnapshotEnvelope::from_value(edit(
                    wire.clone(),
                    "error",
                    edit(error_wire.clone(), field, 1u64.to_value())
                ))
                .is_err(),
                "FAIL error wrong type {field}"
            );
        }
        assert!(
            SnapshotEnvelope::from_value(edit(
                wire.clone(),
                "error",
                edit(error_wire.clone(), "extra", Value::Null)
            ))
            .is_err()
        );
        for code in ["auth_denied", "UNKNOWN", ""] {
            assert!(
                SnapshotEnvelope::from_value(edit(
                    wire.clone(),
                    "error",
                    edit(error_wire.clone(), "code", code.to_string().to_value())
                ))
                .is_err(),
                "FAIL unknown error enum {code}"
            );
        }
        for bad in [Value::Integer(1), Value::Bool(true), Value::Array(vec![])] {
            assert!(SnapshotEnvelope::from_value(edit(wire.clone(), "upload_id", bad)).is_err());
        }
        for bad in illegal_generic_ids() {
            assert!(
                SnapshotEnvelope::from_value(edit(wire.clone(), "upload_id", bad.to_value()))
                    .is_err()
            );
        }
    }
}

fn view_with_unique_blob_count(count: u64) -> (UploadView, Value) {
    let mut expected = view();
    expected.snapshot.file_count = count;
    expected.snapshot.total_bytes = count;
    expected.blobs = (0..count)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[24..].copy_from_slice(&index.to_be_bytes());
            UploadBlob {
                sha256: Sha256Digest::from_bytes(bytes),
                size_bytes: 1,
                durable_offset: 0,
            }
        })
        .collect();
    let wire_blobs = (0..count)
        .map(|index| {
            obj([
                ("sha256", Value::String(format!("sha256:{index:064x}"))),
                ("size_bytes", 1u64.to_value()),
                ("durable_offset", 0u64.to_value()),
            ])
        })
        .collect();
    let wire = edit(
        edit(
            view_value(),
            "snapshot",
            edit(
                edit(snapshot_value(), "file_count", count.to_value()),
                "total_bytes",
                count.to_value(),
            ),
        ),
        "blobs",
        Value::Array(wire_blobs),
    );
    (expected, wire)
}

#[test]
fn actual_unique_blob_collection_accepts_1024_and_rejects_1025_at_every_view_entry() {
    let get = SnapshotRequest::Get { upload_id: uid() };
    let (maximum, maximum_wire) = view_with_unique_blob_count(1_024);
    assert_eq!(maximum.blobs.len(), 1_024);
    assert_eq!(
        maximum
            .blobs
            .iter()
            .map(|blob| blob.size_bytes)
            .sum::<u64>(),
        1_024
    );
    assert!(
        maximum.validate().is_ok(),
        "1024 sorted unique blobs are legal"
    );
    assert_eq!(
        UploadView::from_value(maximum_wire.clone()).unwrap(),
        maximum
    );
    assert_eq!(
        SnapshotEnvelope::from_value(pass_value(maximum_wire)).unwrap(),
        SnapshotEnvelope::Upload(maximum.clone())
    );
    assert!(SnapshotEnvelope::Upload(maximum).validate_for(&get).is_ok());
    // Matching count and total isolate the fixed adapter cap: neither unique
    // count <= file_count nor unique sum <= total_bytes is violated here.
    let (over, over_wire) = view_with_unique_blob_count(1_025);
    assert!(over.validate().is_err(), "adapter file cap 1024");
    assert!(UploadView::from_value(over_wire.clone()).is_err());
    assert!(SnapshotEnvelope::from_value(pass_value(over_wire)).is_err());
    assert!(SnapshotEnvelope::Upload(over).validate_for(&get).is_err());
}

// Each non-integer is paired with the integer a coercing decoder might use.
// Boolean controls deliberately use 0/1, so range/state validation cannot
// conceal an incorrect boolean-to-integer conversion.
fn wrong_integer_types(value: u64) -> Vec<(&'static str, u64, Value)> {
    vec![
        ("numeric string", value, Value::String(value.to_string())),
        ("false", 0, Value::Bool(false)),
        ("true", 1, Value::Bool(true)),
        ("null", value, Value::Null),
        ("array", value, Value::Array(vec![])),
        ("object", value, obj([])),
    ]
}

fn assert_view_and_pass_decode(wire: Value, label: &str) {
    assert!(
        UploadView::from_value(wire.clone()).is_ok(),
        "View control {label}"
    );
    assert!(
        SnapshotEnvelope::from_value(pass_value(wire)).is_ok(),
        "PASS control {label}"
    );
}

fn assert_view_and_pass_reject(wire: Value, label: &str) {
    assert!(
        UploadView::from_value(wire.clone()).is_err(),
        "View {label}"
    );
    assert!(
        SnapshotEnvelope::from_value(pass_value(wire)).is_err(),
        "PASS {label}"
    );
}

#[test]
fn each_top_level_schema_consumer_requires_integer_one_without_scalar_coercion() {
    let mut invalid: Vec<_> = wrong_integer_types(1)
        .into_iter()
        .map(|(label, _, value)| (label, value))
        .collect();
    invalid.extend([
        ("negative integer", Value::Integer(-1)),
        (
            "beyond exact integer",
            Value::Integer(i128::from(MAX_INTEGER) + 1),
        ),
    ]);
    for (request, wire) in vectors() {
        assert_eq!(SnapshotRequest::from_value(wire.clone()).unwrap(), request);
        for (label, value) in &invalid {
            assert!(
                SnapshotRequest::from_value(edit(wire.clone(), "schema_version", value.clone()))
                    .is_err(),
                "request {request:?} schema {label}"
            );
        }
    }
    assert_eq!(UploadView::from_value(view_value()).unwrap(), view());
    let envelopes = [
        pass_value(view_value()),
        error_value(Value::Null),
        error_value(Value::String("upload-1".into())),
    ];
    for wire in &envelopes {
        assert!(
            SnapshotEnvelope::from_value(wire.clone()).is_ok(),
            "legal envelope schema"
        );
    }
    for (label, value) in invalid {
        assert!(
            UploadView::from_value(edit(view_value(), "schema_version", value.clone())).is_err(),
            "View schema {label}"
        );
        for wire in &envelopes {
            assert!(
                SnapshotEnvelope::from_value(edit(wire.clone(), "schema_version", value.clone()))
                    .is_err(),
                "envelope schema {label}: {wire:?}"
            );
        }
    }
}

// These independently edited wire controls preserve all collection, total,
// and scope invariants when the tested integer is 0 or 1.
fn view_with_snapshot_integer(field: &str, integer: u64) -> Value {
    let mut snapshot_wire = edit(snapshot_value(), field, integer.to_value());
    let mut wire = view_value();
    if field == "file_count" && integer == 0 {
        snapshot_wire = edit(snapshot_wire, "total_bytes", 0u64.to_value());
        wire = edit(wire, "blobs", Value::Array(vec![]));
    } else if field == "file_count" && integer == 1 {
        wire = edit(wire, "blobs", Value::Array(vec![blob_value(3, 0)]));
    } else if field == "total_bytes" && integer <= 1 {
        wire = edit(
            wire,
            "blobs",
            Value::Array(vec![
                blob_value(integer, 0),
                obj([
                    ("sha256", digest(6).to_value()),
                    ("size_bytes", 0u64.to_value()),
                    ("durable_offset", 0u64.to_value()),
                ]),
            ]),
        );
    }
    edit(wire, "snapshot", snapshot_wire)
}

#[test]
fn every_nested_snapshot_integer_consumer_rejects_all_non_integer_value_kinds() {
    for (field, integer) in [("schema_version", 1), ("file_count", 2), ("total_bytes", 7)] {
        for (kind, coerced, wrong_type) in wrong_integer_types(integer) {
            // Schema 1 has no legal zero version; true->1 remains the
            // meaningful boolean-coercion counterexample for this field.
            let control = view_with_snapshot_integer(
                field,
                if field == "schema_version" {
                    1
                } else {
                    coerced
                },
            );
            assert_view_and_pass_decode(control.clone(), &format!("snapshot {field} {kind}"));
            let Value::Object(fields) = &control else {
                unreachable!()
            };
            let snapshot_control = fields["snapshot"].clone();
            assert!(
                SnapshotRef::from_value(snapshot_control.clone()).is_ok(),
                "SnapshotRef control {field} {kind}"
            );
            let begin_control = edit(begin_value(), "snapshot", snapshot_control.clone());
            assert!(
                SnapshotRequest::from_value(begin_control.clone()).is_ok(),
                "Begin control {field} {kind}"
            );
            let bad_snapshot = edit(snapshot_control, field, wrong_type);
            assert!(
                SnapshotRef::from_value(bad_snapshot.clone()).is_err(),
                "SnapshotRef {field} {kind}"
            );
            assert!(
                SnapshotRequest::from_value(edit(begin_control, "snapshot", bad_snapshot.clone()))
                    .is_err(),
                "Begin {field} {kind}"
            );
            assert_view_and_pass_reject(
                edit(control, "snapshot", bad_snapshot),
                &format!("snapshot {field} {kind}"),
            );
        }
    }
}

#[test]
fn chunk_offset_and_each_byte_require_integer_values_without_coercion() {
    for (field, integer) in [("offset", 1), ("byte", 255)] {
        for (kind, coerced, wrong_type) in wrong_integer_types(integer) {
            let (control, bad) = if field == "offset" {
                let control = edit(chunk_value(), "offset", coerced.to_value());
                let bad = edit(control.clone(), "offset", wrong_type);
                (control, bad)
            } else {
                let control = edit(
                    chunk_value(),
                    "bytes",
                    Value::Array(vec![coerced.to_value()]),
                );
                let bad = edit(control.clone(), "bytes", Value::Array(vec![wrong_type]));
                (control, bad)
            };
            assert!(
                SnapshotRequest::from_value(control).is_ok(),
                "PutChunk {field} {kind} integer control"
            );
            assert!(
                SnapshotRequest::from_value(bad).is_err(),
                "PutChunk {field} {kind}"
            );
        }
    }
}

#[test]
fn standalone_and_nested_blob_integer_fields_reject_every_non_integer_value_kind() {
    for (field, integer) in [("size_bytes", 3), ("durable_offset", 0)] {
        for (kind, coerced, wrong_type) in wrong_integer_types(integer) {
            let blob_control = if field == "size_bytes" {
                blob_value(coerced, 0)
            } else {
                blob_value(3, coerced)
            };
            assert!(
                UploadBlob::from_value(blob_control.clone()).is_ok(),
                "blob {field} {kind} control"
            );
            let bad_blob = edit(blob_control.clone(), field, wrong_type);
            assert!(
                UploadBlob::from_value(bad_blob.clone()).is_err(),
                "blob {field} {kind}"
            );
            let wire = edit(view_value(), "blobs", Value::Array(vec![blob_control]));
            assert_view_and_pass_decode(wire.clone(), &format!("blob {field} {kind}"));
            assert_view_and_pass_reject(
                edit(wire, "blobs", Value::Array(vec![bad_blob])),
                &format!("blob {field} {kind}"),
            );
        }
    }
}

#[test]
fn view_and_pass_reserved_bytes_reject_wrong_types_in_legal_zero_and_positive_states() {
    for (kind, coerced, wrong_type) in wrong_integer_types(1_212_416) {
        let control = if coerced == 0 {
            edit(
                edit(
                    edit(view_value(), "state", Value::String("Cancelled".into())),
                    "reserved_bytes",
                    0u64.to_value(),
                ),
                "blobs",
                Value::Array(vec![]),
            )
        } else {
            edit(view_value(), "reserved_bytes", coerced.to_value())
        };
        assert_view_and_pass_decode(control.clone(), &format!("reserved_bytes {kind}"));
        assert_view_and_pass_reject(
            edit(control, "reserved_bytes", wrong_type),
            &format!("reserved_bytes {kind}"),
        );
    }
}

#[test]
fn empty_active_and_cancelled_blob_arrays_cannot_default_from_null_or_other_types() {
    for state in ["Receiving", "Staged", "Cancelling", "Cancelled"] {
        let empty = edit(
            view_with_snapshot_integer("file_count", 0),
            "state",
            Value::String(state.into()),
        );
        let mut controls = vec![if state == "Cancelled" {
            edit(empty, "reserved_bytes", 0u64.to_value())
        } else {
            empty
        }];
        if state == "Cancelled" {
            controls.push(edit(
                edit(
                    edit(view_value(), "state", Value::String(state.into())),
                    "reserved_bytes",
                    0u64.to_value(),
                ),
                "blobs",
                Value::Array(vec![]),
            ));
        }
        for control in controls {
            assert_view_and_pass_decode(control.clone(), state);
            for wrong_type in [
                Value::Null,
                Value::Bool(false),
                Value::Bool(true),
                Value::Integer(0),
                Value::String("[]".into()),
                obj([]),
            ] {
                let label = format!("{state} blobs {wrong_type:?}");
                assert_view_and_pass_reject(edit(control.clone(), "blobs", wrong_type), &label);
            }
        }
    }
}

// The String control is the text a loose JSON-to-text conversion could yield.
// All these strings are legal generic IDs and opaque manifest text. Matching
// workspace fields are set to that String before only one field is damaged.
fn non_string_text_cases() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        ("null", "null", Value::Null),
        ("false", "false", Value::Bool(false)),
        ("true", "true", Value::Bool(true)),
        ("integer zero", "0", Value::Integer(0)),
        ("integer one", "1", Value::Integer(1)),
        ("empty array", "[]", Value::Array(vec![])),
        (
            "string array",
            "[\"x\"]",
            Value::Array(vec![Value::String("x".into())]),
        ),
        (
            "unboxed string array",
            "x",
            Value::Array(vec![Value::String("x".into())]),
        ),
        ("empty object", "{}", obj([])),
        (
            "string object",
            "{\"value\":\"x\"}",
            obj([("value", Value::String("x".into()))]),
        ),
        (
            "unboxed string object",
            "x",
            obj([("value", Value::String("x".into()))]),
        ),
    ]
}

fn fixture_field(value: &Value, field: &str) -> Value {
    let Value::Object(fields) = value else {
        panic!("fixture must be object")
    };
    fields[field].clone()
}

fn wrong_text_values_including_wrapped_string(valid: Value) -> Vec<(String, Value)> {
    let mut values: Vec<_> = non_string_text_cases()
        .into_iter()
        .map(|(kind, _, value)| (kind.into(), value))
        .collect();
    values.extend([
        (
            "wrapped legal String array".into(),
            Value::Array(vec![valid.clone()]),
        ),
        (
            "wrapped legal String object".into(),
            obj([("value", valid)]),
        ),
    ]);
    values
}

#[test]
fn begin_text_fields_require_strings_without_coercion_or_defaulting() {
    for field in [
        "provider",
        "workspace",
        "resource",
        "upload_key",
        "manifest_json",
    ] {
        for (kind, text, wrong_type) in non_string_text_cases() {
            for legal_text in [
                fixture_field(&begin_value(), field),
                Value::String(text.into()),
            ] {
                let mut control = edit(begin_value(), field, legal_text.clone());
                if field == "workspace" {
                    control = edit(
                        control,
                        "snapshot",
                        edit(snapshot_value(), field, legal_text),
                    );
                }
                assert!(
                    SnapshotRequest::from_value(control.clone()).is_ok(),
                    "Begin {field} {kind} complete String control"
                );
                assert!(
                    SnapshotRequest::from_value(edit(control, field, wrong_type.clone())).is_err(),
                    "Begin {field} must reject {kind}"
                );
            }
        }
    }
}

#[test]
fn view_and_pass_scope_fields_require_strings_without_coercion_or_defaulting() {
    for field in ["provider", "workspace", "resource"] {
        for (kind, text, wrong_type) in non_string_text_cases() {
            for legal_text in [
                fixture_field(&view_value(), field),
                Value::String(text.into()),
            ] {
                let mut control = edit(view_value(), field, legal_text.clone());
                if field == "workspace" {
                    control = edit(
                        control,
                        "snapshot",
                        edit(snapshot_value(), field, legal_text),
                    );
                }
                assert_view_and_pass_decode(control.clone(), &format!("{field} {kind} String"));
                assert_view_and_pass_reject(
                    edit(control, field, wrong_type.clone()),
                    &format!("{field} {kind}"),
                );
            }
        }
    }
}

#[test]
fn every_nested_snapshot_text_field_requires_string_at_each_decoder_entry() {
    for field in [
        "workspace",
        "commit_id",
        "root_manifest_id",
        "snapshot_id",
        "manifest_sha256",
        "selection_digest",
    ] {
        for (kind, text, wrong_type) in non_string_text_cases() {
            let mut legal_texts = vec![fixture_field(&snapshot_value(), field)];
            if ["workspace", "commit_id", "root_manifest_id"].contains(&field) {
                legal_texts.push(Value::String(text.into()));
            }
            for legal_text in legal_texts {
                let snapshot_control = edit(snapshot_value(), field, legal_text.clone());
                let mut begin_control = edit(begin_value(), "snapshot", snapshot_control.clone());
                let mut view_control = edit(view_value(), "snapshot", snapshot_control.clone());
                if field == "workspace" {
                    begin_control = edit(begin_control, "workspace", legal_text.clone());
                    view_control = edit(view_control, "workspace", legal_text);
                }
                assert!(
                    SnapshotRequest::from_value(begin_control.clone()).is_ok(),
                    "Begin nested {field} {kind} String control"
                );
                assert_view_and_pass_decode(
                    view_control.clone(),
                    &format!("nested {field} {kind} String"),
                );
                // Only the nested field is replaced. The outer workspace stays
                // the legal String that a coercing decoder might produce.
                let bad_snapshot = edit(snapshot_control, field, wrong_type.clone());
                assert!(
                    SnapshotRequest::from_value(edit(
                        begin_control,
                        "snapshot",
                        bad_snapshot.clone()
                    ))
                    .is_err(),
                    "Begin nested {field} must reject {kind}"
                );
                assert_view_and_pass_reject(
                    edit(view_control, "snapshot", bad_snapshot),
                    &format!("nested {field} {kind}"),
                );
            }
        }
        // A decoder must not unwrap an array/object around a legal digest.
        // Unlike an arbitrary string, this payload passes digest grammar.
        if ["snapshot_id", "manifest_sha256", "selection_digest"].contains(&field) {
            for (kind, wrong_type) in
                wrong_text_values_including_wrapped_string(fixture_field(&snapshot_value(), field))
            {
                let bad_snapshot = edit(snapshot_value(), field, wrong_type);
                assert!(
                    SnapshotRequest::from_value(edit(
                        begin_value(),
                        "snapshot",
                        bad_snapshot.clone()
                    ))
                    .is_err(),
                    "Begin nested {field} {kind}"
                );
                assert_view_and_pass_reject(
                    edit(view_value(), "snapshot", bad_snapshot),
                    &format!("nested {field} {kind}"),
                );
            }
        }
    }
}

#[test]
fn standalone_upload_id_requires_string_for_every_non_string_value_kind() {
    for (kind, text, wrong_type) in non_string_text_cases() {
        for id in ["upload-1", text] {
            assert_eq!(
                UploadId::from_value(Value::String(id.into())).unwrap(),
                UploadId::new(id.into()).unwrap(),
                "UploadId {kind} legal String control"
            );
        }
        assert!(UploadId::from_value(wrong_type).is_err(), "UploadId {kind}");
    }
}

#[test]
fn every_request_upload_id_requires_string_for_every_non_string_value_kind() {
    for (kind, text, wrong_type) in non_string_text_cases() {
        for id in ["upload-1", text] {
            for (expected, control) in requests_with_upload_id(id) {
                assert_eq!(
                    SnapshotRequest::from_value(control.clone()).unwrap(),
                    expected,
                    "request {expected:?} {kind} String control"
                );
                assert!(
                    SnapshotRequest::from_value(edit(control, "upload_id", wrong_type.clone()))
                        .is_err(),
                    "request {expected:?} upload_id {kind}"
                );
            }
        }
    }
}

#[test]
fn view_pass_and_fail_upload_ids_require_string_with_only_fail_allowing_null() {
    for (kind, text, wrong_type) in non_string_text_cases() {
        for id in ["upload-1", text] {
            let control = edit(view_value(), "upload_id", Value::String(id.into()));
            assert_view_and_pass_decode(control.clone(), &format!("upload_id {kind} String"));
            assert_view_and_pass_reject(
                edit(control, "upload_id", wrong_type.clone()),
                &format!("upload_id {kind}"),
            );
            let fail_control = error_value(Value::String(id.into()));
            assert!(
                SnapshotEnvelope::from_value(fail_control.clone()).is_ok(),
                "FAIL upload_id {kind} String control"
            );
            let failed =
                SnapshotEnvelope::from_value(edit(fail_control, "upload_id", wrong_type.clone()));
            if wrong_type == Value::Null {
                assert_eq!(
                    failed.unwrap(),
                    SnapshotEnvelope::Error {
                        error: TaskError::new(TaskErrorCode::AuthDenied, "denied", false),
                        upload_id: None,
                    },
                    "FAIL permits null optional upload_id"
                );
            } else {
                assert!(failed.is_err(), "FAIL upload_id {kind}");
            }
        }
    }
}

#[test]
fn chunk_and_blob_digest_fields_reject_each_non_string_value_kind() {
    for field in ["blob_sha256", "chunk_sha256"] {
        assert_eq!(SnapshotRequest::from_value(chunk_value()).unwrap(), chunk());
        for (kind, wrong_type) in
            wrong_text_values_including_wrapped_string(fixture_field(&chunk_value(), field))
        {
            assert!(
                SnapshotRequest::from_value(edit(chunk_value(), field, wrong_type)).is_err(),
                "PutChunk {field} {kind}"
            );
        }
    }
    let blob_control = blob_value(3, 0);
    assert_eq!(
        UploadBlob::from_value(blob_control.clone()).unwrap(),
        view().blobs[0]
    );
    let view_control = edit(
        view_value(),
        "blobs",
        Value::Array(vec![blob_control.clone()]),
    );
    assert_view_and_pass_decode(view_control.clone(), "single valid digest blob");
    for (kind, wrong_type) in
        wrong_text_values_including_wrapped_string(fixture_field(&blob_control, "sha256"))
    {
        let bad_blob = edit(blob_control.clone(), "sha256", wrong_type);
        assert!(
            UploadBlob::from_value(bad_blob.clone()).is_err(),
            "blob sha256 {kind}"
        );
        assert_view_and_pass_reject(
            edit(view_control.clone(), "blobs", Value::Array(vec![bad_blob])),
            &format!("blob sha256 {kind}"),
        );
    }
}

#[test]
fn every_operation_requires_an_exact_string_at_request_entry() {
    for (expected, control) in vectors() {
        assert_eq!(
            SnapshotRequest::from_value(control.clone()).unwrap(),
            expected
        );
        let operation = fixture_field(&control, "operation");
        for (kind, _, wrong_type) in non_string_text_cases() {
            assert!(
                SnapshotRequest::from_value(edit(control.clone(), "operation", wrong_type))
                    .is_err(),
                "operation {operation:?} {kind}"
            );
        }
        for wrong_type in [
            Value::Array(vec![operation.clone()]),
            obj([("operation", operation.clone())]),
        ] {
            assert!(
                SnapshotRequest::from_value(edit(control.clone(), "operation", wrong_type))
                    .is_err()
            );
        }
    }
}

#[test]
fn pass_and_fail_verdicts_require_an_exact_string_at_envelope_entry() {
    for (label, control) in [
        ("PASS", pass_value(view_value())),
        ("FAIL", error_value(Value::Null)),
    ] {
        assert!(
            SnapshotEnvelope::from_value(control.clone()).is_ok(),
            "{label} control"
        );
        for (kind, _, wrong_type) in non_string_text_cases() {
            assert!(
                SnapshotEnvelope::from_value(edit(control.clone(), "verdict", wrong_type)).is_err(),
                "{label} verdict {kind}"
            );
        }
        for wrong_type in [
            Value::Array(vec![Value::String(label.into())]),
            obj([("verdict", Value::String(label.into()))]),
        ] {
            assert!(
                SnapshotEnvelope::from_value(edit(control.clone(), "verdict", wrong_type)).is_err()
            );
        }
    }
}

#[test]
fn fail_error_text_fields_require_strings_without_coercion_or_defaulting() {
    for field in ["code", "reason"] {
        for (kind, text, wrong_type) in non_string_text_cases() {
            let base = error_value(Value::Null);
            let error_control = fixture_field(&base, "error");
            let mut legal_texts = vec![fixture_field(&error_control, field)];
            if field == "reason" {
                legal_texts.push(Value::String(text.into()));
            }
            for legal_text in legal_texts {
                let error_control = edit(error_control.clone(), field, legal_text);
                let control = edit(base.clone(), "error", error_control.clone());
                assert!(
                    SnapshotEnvelope::from_value(control.clone()).is_ok(),
                    "FAIL error {field} {kind} String control"
                );
                assert!(
                    SnapshotEnvelope::from_value(edit(
                        control,
                        "error",
                        edit(error_control, field, wrong_type.clone())
                    ))
                    .is_err(),
                    "FAIL error {field} {kind}"
                );
            }
        }
    }
    let base = error_value(Value::Null);
    let error_control = fixture_field(&base, "error");
    for wrong_type in [
        Value::Array(vec![Value::String("AUTH_DENIED".into())]),
        obj([("code", Value::String("AUTH_DENIED".into()))]),
    ] {
        assert!(
            SnapshotEnvelope::from_value(edit(
                base.clone(),
                "error",
                edit(error_control.clone(), "code", wrong_type)
            ))
            .is_err()
        );
    }
}

#[test]
fn fail_error_retryable_requires_boolean_for_both_legal_boolean_controls() {
    for retryable in [false, true] {
        let base = error_value(Value::Null);
        let error_control = edit(
            fixture_field(&base, "error"),
            "retryable",
            Value::Bool(retryable),
        );
        let control = edit(base, "error", error_control.clone());
        assert_eq!(
            SnapshotEnvelope::from_value(control.clone()).unwrap(),
            SnapshotEnvelope::Error {
                error: TaskError::new(TaskErrorCode::AuthDenied, "denied", retryable),
                upload_id: None,
            }
        );
        for wrong_type in [
            Value::Null,
            Value::Integer(0),
            Value::Integer(1),
            Value::String("false".into()),
            Value::String("true".into()),
            Value::Array(vec![]),
            Value::Array(vec![Value::Bool(retryable)]),
            obj([]),
            obj([("retryable", Value::Bool(retryable))]),
        ] {
            assert!(
                SnapshotEnvelope::from_value(edit(
                    control.clone(),
                    "error",
                    edit(error_control.clone(), "retryable", wrong_type.clone())
                ))
                .is_err(),
                "FAIL retryable {retryable} rejects {wrong_type:?}"
            );
        }
    }
}

fn upload_state_view_vectors() -> Vec<(UploadView, Value)> {
    let Value::Array(blobs) = fixture_field(&view_value(), "blobs") else {
        unreachable!()
    };
    let staged = edit(
        edit(view_value(), "state", Value::String("Staged".into())),
        "blobs",
        Value::Array(vec![
            edit(blobs[0].clone(), "durable_offset", 3u64.to_value()),
            edit(blobs[1].clone(), "durable_offset", 4u64.to_value()),
        ]),
    );
    let mut cancelling = view();
    cancelling.state = UploadState::Cancelling;
    vec![
        (view(), view_value()),
        (full_view(), staged),
        (
            cancelling,
            edit(view_value(), "state", Value::String("Cancelling".into())),
        ),
        (
            cancelled_view(),
            edit(
                edit(
                    edit(view_value(), "state", Value::String("Cancelled".into())),
                    "reserved_bytes",
                    0u64.to_value(),
                ),
                "blobs",
                Value::Array(vec![]),
            ),
        ),
    ]
}

#[test]
fn state_type_rejection_cannot_be_hidden_by_another_states_charge_or_offsets() {
    for (expected, control) in upload_state_view_vectors() {
        let state = fixture_field(&control, "state");
        assert_eq!(
            UploadState::from_value(state.clone()).unwrap(),
            expected.state
        );
        assert_eq!(UploadView::from_value(control.clone()).unwrap(), expected);
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(control.clone())).unwrap(),
            SnapshotEnvelope::Upload(expected)
        );
        let mut wrong_types: Vec<_> = non_string_text_cases()
            .into_iter()
            .map(|(_, _, value)| value)
            .collect();
        wrong_types.extend([
            Value::Array(vec![state.clone()]),
            obj([("state", state.clone())]),
        ]);
        for wrong_type in wrong_types {
            assert!(
                UploadState::from_value(wrong_type.clone()).is_err(),
                "state {state:?} {wrong_type:?}"
            );
            assert_view_and_pass_reject(
                edit(control.clone(), "state", wrong_type.clone()),
                &format!("state {state:?} {wrong_type:?}"),
            );
        }
    }
}

fn cancelled_snapshot_vectors() -> Vec<(UploadView, Value)> {
    let nonempty_wire = edit(
        edit(
            edit(view_value(), "state", Value::String("Cancelled".into())),
            "reserved_bytes",
            0u64.to_value(),
        ),
        "blobs",
        Value::Array(vec![]),
    );
    vec![
        (cancelled_view(), nonempty_wire),
        empty_cancelled_snapshot_vector(),
    ]
}

fn empty_cancelled_snapshot_vector() -> (UploadView, Value) {
    let mut empty = cancelled_view();
    empty.snapshot.file_count = 0;
    empty.snapshot.total_bytes = 0;
    let empty_wire = edit(
        edit(
            edit(
                edit(view_value(), "state", Value::String("Cancelled".into())),
                "reserved_bytes",
                0u64.to_value(),
            ),
            "blobs",
            Value::Array(vec![]),
        ),
        "snapshot",
        edit(
            edit(snapshot_value(), "file_count", 0u64.to_value()),
            "total_bytes",
            0u64.to_value(),
        ),
    );
    (empty, empty_wire)
}

#[test]
fn cancelled_typed_view_cannot_keep_positive_total_when_file_count_is_zero() {
    for (control, _) in cancelled_snapshot_vectors() {
        assert!(
            control.validate().is_ok(),
            "legal Cancelled snapshot control"
        );
    }
    for total in [1, 7, MAX_SNAPSHOT_BYTES] {
        let mut invalid = empty_cancelled_snapshot_vector().0;
        invalid.snapshot.total_bytes = total;
        assert!(
            invalid.validate().is_err(),
            "Cancelled zero files, total {total}"
        );
    }
}

#[test]
fn cancelled_view_decoder_cannot_keep_positive_total_when_file_count_is_zero() {
    for (expected, control) in cancelled_snapshot_vectors() {
        assert_eq!(UploadView::from_value(control).unwrap(), expected);
    }
    let control = empty_cancelled_snapshot_vector().1;
    for total in [1, 7, MAX_SNAPSHOT_BYTES] {
        let snapshot = edit(
            fixture_field(&control, "snapshot"),
            "total_bytes",
            total.to_value(),
        );
        assert!(
            UploadView::from_value(edit(control.clone(), "snapshot", snapshot)).is_err(),
            "Cancelled zero files, total {total}"
        );
    }
}

#[test]
fn cancelled_pass_decoder_cannot_keep_positive_total_when_file_count_is_zero() {
    for (expected, control) in cancelled_snapshot_vectors() {
        assert_eq!(
            SnapshotEnvelope::from_value(pass_value(control)).unwrap(),
            SnapshotEnvelope::Upload(expected)
        );
    }
    let control = empty_cancelled_snapshot_vector().1;
    for total in [1, 7, MAX_SNAPSHOT_BYTES] {
        let snapshot = edit(
            fixture_field(&control, "snapshot"),
            "total_bytes",
            total.to_value(),
        );
        assert!(
            SnapshotEnvelope::from_value(pass_value(edit(control.clone(), "snapshot", snapshot)))
                .is_err(),
            "Cancelled zero files, total {total}"
        );
    }
}

#[test]
fn cancelled_get_correlation_revalidates_zero_files_and_total_consistency() {
    let get = SnapshotRequest::Get { upload_id: uid() };
    for (control, _) in cancelled_snapshot_vectors() {
        assert!(
            SnapshotEnvelope::Upload(control).validate_for(&get).is_ok(),
            "legal Cancelled Get control"
        );
    }
    for total in [1, 7, MAX_SNAPSHOT_BYTES] {
        let mut invalid = empty_cancelled_snapshot_vector().0;
        invalid.snapshot.total_bytes = total;
        assert!(
            SnapshotEnvelope::Upload(invalid)
                .validate_for(&get)
                .is_err(),
            "matching Cancelled Get, zero files, total {total}"
        );
    }
}

fn non_object_values(legal_object: Value) -> Vec<(&'static str, Value)> {
    vec![
        ("null", Value::Null),
        ("false", Value::Bool(false)),
        ("true", Value::Bool(true)),
        ("zero", Value::Integer(0)),
        ("one", Value::Integer(1)),
        ("object text", Value::String("{}".into())),
        ("empty array", Value::Array(vec![])),
        ("wrapped object", Value::Array(vec![legal_object])),
    ]
}

#[test]
fn structured_snapshot_dto_roots_reject_every_non_object_value_kind() {
    for (expected, control) in vectors() {
        assert_eq!(
            SnapshotRequest::from_value(control.clone()).unwrap(),
            expected
        );
        for (kind, wrong_type) in non_object_values(control) {
            assert!(
                SnapshotRequest::from_value(wrong_type).is_err(),
                "request {expected:?} root {kind}"
            );
        }
    }
    assert_eq!(
        UploadBlob::from_value(blob_value(3, 0)).unwrap(),
        view().blobs[0]
    );
    for (kind, wrong_type) in non_object_values(blob_value(3, 0)) {
        assert!(
            UploadBlob::from_value(wrong_type).is_err(),
            "blob root {kind}"
        );
    }
    assert_eq!(UploadView::from_value(view_value()).unwrap(), view());
    for (kind, wrong_type) in non_object_values(view_value()) {
        assert!(
            UploadView::from_value(wrong_type).is_err(),
            "view root {kind}"
        );
    }
    for (label, control) in [
        ("PASS", pass_value(view_value())),
        ("FAIL", error_value(Value::Null)),
    ] {
        assert!(
            SnapshotEnvelope::from_value(control.clone()).is_ok(),
            "{label} root control"
        );
        for (kind, wrong_type) in non_object_values(control) {
            assert!(
                SnapshotEnvelope::from_value(wrong_type).is_err(),
                "{label} root {kind}"
            );
        }
    }
}

#[test]
fn nested_snapshot_blob_upload_and_error_require_objects_without_unwrapping() {
    assert_eq!(SnapshotRequest::from_value(begin_value()).unwrap(), begin());
    assert_view_and_pass_decode(view_value(), "nested object controls");
    for (kind, wrong_type) in non_object_values(snapshot_value()) {
        assert!(
            SnapshotRequest::from_value(edit(begin_value(), "snapshot", wrong_type.clone()))
                .is_err(),
            "Begin snapshot {kind}"
        );
        assert_view_and_pass_reject(
            edit(view_value(), "snapshot", wrong_type),
            &format!("snapshot {kind}"),
        );
    }
    let blob_control = blob_value(3, 0);
    let view_control = edit(
        view_value(),
        "blobs",
        Value::Array(vec![blob_control.clone()]),
    );
    assert_view_and_pass_decode(view_control.clone(), "single blob object control");
    for (kind, wrong_type) in non_object_values(blob_control) {
        assert_view_and_pass_reject(
            edit(
                view_control.clone(),
                "blobs",
                Value::Array(vec![wrong_type]),
            ),
            &format!("blob item {kind}"),
        );
    }
    for (kind, wrong_type) in non_object_values(view_value()) {
        assert!(
            SnapshotEnvelope::from_value(pass_value(wrong_type)).is_err(),
            "PASS upload {kind}"
        );
    }
    let fail_control = error_value(Value::Null);
    assert!(
        SnapshotEnvelope::from_value(fail_control.clone()).is_ok(),
        "FAIL error object control"
    );
    for (kind, wrong_type) in non_object_values(fixture_field(&fail_control, "error")) {
        assert!(
            SnapshotEnvelope::from_value(edit(fail_control.clone(), "error", wrong_type)).is_err(),
            "FAIL error {kind}"
        );
    }
}

fn non_array_values(legal_array: Value) -> Vec<(&'static str, Value)> {
    vec![
        ("null", Value::Null),
        ("false", Value::Bool(false)),
        ("true", Value::Bool(true)),
        ("zero", Value::Integer(0)),
        ("one", Value::Integer(1)),
        ("array text", Value::String("[]".into())),
        ("nonempty array text", Value::String("[0]".into())),
        ("empty object", obj([])),
        ("wrapped array object", obj([("value", legal_array)])),
    ]
}

#[test]
fn chunk_bytes_and_view_blob_collections_require_arrays_without_defaulting() {
    let chunk_control = edit(chunk_value(), "bytes", Value::Array(vec![0u64.to_value()]));
    assert!(
        SnapshotRequest::from_value(chunk_control.clone()).is_ok(),
        "single byte array control"
    );
    for (kind, wrong_type) in non_array_values(Value::Array(vec![0u64.to_value()])) {
        assert!(
            SnapshotRequest::from_value(edit(chunk_control.clone(), "bytes", wrong_type)).is_err(),
            "PutChunk bytes {kind}"
        );
    }
    for state in ["Receiving", "Staged", "Cancelling", "Cancelled"] {
        let mut control = edit(
            view_with_snapshot_integer("file_count", 0),
            "state",
            Value::String(state.into()),
        );
        if state == "Cancelled" {
            control = edit(control, "reserved_bytes", 0u64.to_value());
        }
        assert_view_and_pass_decode(control.clone(), &format!("empty {state} array control"));
        for (kind, wrong_type) in non_array_values(Value::Array(vec![])) {
            assert_view_and_pass_reject(
                edit(control.clone(), "blobs", wrong_type),
                &format!("empty {state} blobs {kind}"),
            );
        }
    }
    assert_view_and_pass_decode(view_value(), "nonempty Receiving array control");
    for (kind, wrong_type) in non_array_values(fixture_field(&view_value(), "blobs")) {
        assert_view_and_pass_reject(
            edit(view_value(), "blobs", wrong_type),
            &format!("nonempty Receiving blobs {kind}"),
        );
    }
}

#[test]
fn all_four_view_states_encode_their_independent_complete_wire_vectors() {
    for (typed, expected) in upload_state_view_vectors() {
        assert_eq!(typed.to_value(), expected, "View encoder {:?}", typed.state);
    }
}

#[test]
fn all_four_pass_states_encode_their_independent_complete_wire_vectors() {
    for (typed, expected) in upload_state_view_vectors() {
        let state = typed.state;
        assert_eq!(
            SnapshotEnvelope::Upload(typed).to_value(),
            pass_value(expected),
            "PASS encoder {state:?}"
        );
    }
}

// Each side is written independently from the contract. In particular, no
// snapshot-module encoder or decoder constructs an expected wire value.
fn nondefault_snapshot_encoding_vector() -> (SnapshotRef, Value) {
    (
        SnapshotRef {
            schema_version: 1,
            snapshot_id: digest(20),
            workspace: "工作区/\"\\\n".into(),
            commit_id: "提交/next".into(),
            root_manifest_id: "根/manifest".into(),
            manifest_sha256: digest(21),
            selection_digest: digest(22),
            file_count: 3,
            total_bytes: 19,
        },
        obj([
            ("schema_version", Value::Integer(1)),
            (
                "snapshot_id",
                Value::String(format!("sha256:{}", "14".repeat(32))),
            ),
            ("workspace", Value::String("工作区/\"\\\n".into())),
            ("commit_id", Value::String("提交/next".into())),
            ("root_manifest_id", Value::String("根/manifest".into())),
            (
                "manifest_sha256",
                Value::String(format!("sha256:{}", "15".repeat(32))),
            ),
            (
                "selection_digest",
                Value::String(format!("sha256:{}", "16".repeat(32))),
            ),
            ("file_count", Value::Integer(3)),
            ("total_bytes", Value::Integer(19)),
        ]),
    )
}

fn nondefault_view_encoding_vectors() -> Vec<(UploadView, Value)> {
    let mut cases = Vec::new();
    for (state, label, offset_a, offset_b, charge) in [
        (UploadState::Receiving, "Receiving", 2, 7, 2_000_007),
        (UploadState::Staged, "Staged", 5, 8, 2_000_007),
        (UploadState::Cancelling, "Cancelling", 2, 7, 2_000_007),
        (UploadState::Cancelled, "Cancelled", 0, 0, 0),
    ] {
        let (snapshot, snapshot_wire) = nondefault_snapshot_encoding_vector();
        let mut blobs = vec![
            UploadBlob {
                sha256: digest(23),
                size_bytes: 5,
                durable_offset: offset_a,
            },
            UploadBlob {
                sha256: digest(24),
                size_bytes: 8,
                durable_offset: offset_b,
            },
        ];
        let mut blob_wire = vec![
            obj([
                (
                    "sha256",
                    Value::String(format!("sha256:{}", "17".repeat(32))),
                ),
                ("size_bytes", Value::Integer(5)),
                ("durable_offset", Value::Integer(i128::from(offset_a))),
            ]),
            obj([
                (
                    "sha256",
                    Value::String(format!("sha256:{}", "18".repeat(32))),
                ),
                ("size_bytes", Value::Integer(8)),
                ("durable_offset", Value::Integer(i128::from(offset_b))),
            ]),
        ];
        if state == UploadState::Cancelled {
            blobs.clear();
            blob_wire.clear();
        }
        cases.push((
            UploadView {
                schema_version: 1,
                upload_id: UploadId::new("上传/\"\\\n".into()).unwrap(),
                provider: "提供方/\"\\\n".into(),
                workspace: "工作区/\"\\\n".into(),
                resource: "资源/\"\\\n".into(),
                snapshot,
                state,
                reserved_bytes: charge,
                blobs,
            },
            obj([
                ("schema_version", Value::Integer(1)),
                ("upload_id", Value::String("上传/\"\\\n".into())),
                ("provider", Value::String("提供方/\"\\\n".into())),
                ("workspace", Value::String("工作区/\"\\\n".into())),
                ("resource", Value::String("资源/\"\\\n".into())),
                ("snapshot", snapshot_wire),
                ("state", Value::String(label.into())),
                ("reserved_bytes", Value::Integer(i128::from(charge))),
                ("blobs", Value::Array(blob_wire)),
            ]),
        ));
    }
    cases
}

#[test]
fn view_encoder_preserves_every_nondefault_field_in_all_four_states() {
    for (typed, expected) in nondefault_view_encoding_vectors() {
        assert_eq!(
            typed.to_value(),
            expected,
            "nondefault View {:?}",
            typed.state
        );
    }
}

#[test]
fn pass_encoder_preserves_every_nondefault_field_in_all_four_states() {
    for (typed, expected) in nondefault_view_encoding_vectors() {
        let state = typed.state;
        assert_eq!(
            SnapshotEnvelope::Upload(typed).to_value(),
            pass_value(expected),
            "nondefault PASS {state:?}"
        );
    }
}

#[test]
fn view_and_pass_encoders_preserve_empty_zero_blob_and_exact_integer_bounds() {
    for (typed, expected) in cancelled_snapshot_vectors() {
        assert_eq!(typed.to_value(), expected, "Cancelled snapshot metadata");
        assert_eq!(
            SnapshotEnvelope::Upload(typed).to_value(),
            pass_value(expected)
        );
    }
    for state in [
        UploadState::Receiving,
        UploadState::Staged,
        UploadState::Cancelling,
    ] {
        let label = match state {
            UploadState::Receiving => "Receiving",
            UploadState::Staged => "Staged",
            UploadState::Cancelling => "Cancelling",
            _ => unreachable!(),
        };
        let mut empty = view();
        empty.state = state;
        empty.snapshot.file_count = 0;
        empty.snapshot.total_bytes = 0;
        empty.blobs.clear();
        let empty_wire = edit(
            edit(
                edit(view_value(), "state", Value::String(label.into())),
                "snapshot",
                edit(
                    edit(snapshot_value(), "file_count", Value::Integer(0)),
                    "total_bytes",
                    Value::Integer(0),
                ),
            ),
            "blobs",
            Value::Array(vec![]),
        );
        assert_eq!(empty.to_value(), empty_wire, "empty {label} encoding");
        assert_eq!(
            SnapshotEnvelope::Upload(empty.clone()).to_value(),
            pass_value(empty_wire)
        );
        let mut zero_blob = empty;
        zero_blob.snapshot.file_count = 2;
        zero_blob.blobs.push(UploadBlob {
            sha256: digest(4),
            size_bytes: 0,
            durable_offset: 0,
        });
        let zero_wire = edit(
            edit(
                edit(view_value(), "state", Value::String(label.into())),
                "snapshot",
                edit(snapshot_value(), "total_bytes", Value::Integer(0)),
            ),
            "blobs",
            Value::Array(vec![blob_value(0, 0)]),
        );
        assert_eq!(
            zero_blob.to_value(),
            zero_wire,
            "zero blob {label} encoding"
        );
        assert_eq!(
            SnapshotEnvelope::Upload(zero_blob).to_value(),
            pass_value(zero_wire)
        );
    }
    let mut maximum = view();
    maximum.snapshot.file_count = 1_024;
    maximum.snapshot.total_bytes = 67_108_864;
    maximum.reserved_bytes = MAX_INTEGER;
    let maximum_wire = edit(
        edit(
            view_value(),
            "reserved_bytes",
            Value::Integer(9_007_199_254_740_991),
        ),
        "snapshot",
        edit(
            edit(snapshot_value(), "file_count", Value::Integer(1_024)),
            "total_bytes",
            Value::Integer(67_108_864),
        ),
    );
    assert_eq!(
        maximum.to_value(),
        maximum_wire,
        "exact integer adapter bounds"
    );
    assert_eq!(
        SnapshotEnvelope::Upload(maximum).to_value(),
        pass_value(maximum_wire)
    );
    for count in [0, 1, 1_024] {
        let (typed, expected) = view_with_unique_blob_count(count);
        assert_eq!(
            typed.to_value(),
            expected,
            "actual collection count {count}"
        );
        assert_eq!(
            SnapshotEnvelope::Upload(typed).to_value(),
            pass_value(expected)
        );
    }
}

#[test]
fn begin_encoder_preserves_nondefault_scope_manifest_and_complete_snapshot() {
    let (snapshot, snapshot_wire) = nondefault_snapshot_encoding_vector();
    let typed = SnapshotRequest::Begin {
        provider: "提供方/\"\\\n".into(),
        workspace: "工作区/\"\\\n".into(),
        resource: "资源/\"\\\n".into(),
        upload_key: "重试/\"\\\n".into(),
        snapshot: Box::new(snapshot),
        manifest_json: "opaque text: \"汉\"\\\n".into(),
    };
    let expected = obj([
        ("schema_version", Value::Integer(1)),
        ("operation", Value::String("Begin".into())),
        ("provider", Value::String("提供方/\"\\\n".into())),
        ("workspace", Value::String("工作区/\"\\\n".into())),
        ("resource", Value::String("资源/\"\\\n".into())),
        ("upload_key", Value::String("重试/\"\\\n".into())),
        ("snapshot", snapshot_wire),
        (
            "manifest_json",
            Value::String("opaque text: \"汉\"\\\n".into()),
        ),
    ]);
    assert_eq!(typed.to_value(), expected);
}

#[test]
fn begin_encoder_preserves_empty_snapshot_and_exact_manifest_and_metadata_bounds() {
    for (files, bytes, manifest) in [
        (0, 0, "[]".into()),
        (1_024, 67_108_864, "a".repeat(65_536)),
        (1_024, 67_108_864, "汉".repeat(21_845) + "x"),
    ] {
        let mut typed = begin();
        let SnapshotRequest::Begin {
            snapshot,
            manifest_json,
            ..
        } = &mut typed
        else {
            unreachable!()
        };
        snapshot.file_count = files;
        snapshot.total_bytes = bytes;
        *manifest_json = manifest.clone();
        let expected = edit(
            edit(begin_value(), "manifest_json", Value::String(manifest)),
            "snapshot",
            edit(
                edit(
                    snapshot_value(),
                    "file_count",
                    Value::Integer(i128::from(files)),
                ),
                "total_bytes",
                Value::Integer(i128::from(bytes)),
            ),
        );
        assert_eq!(
            typed.to_value(),
            expected,
            "Begin count={files} total={bytes}"
        );
    }
}

#[test]
fn put_chunk_encoder_preserves_nondefault_id_digests_bytes_and_large_offsets() {
    for (offset, bytes, byte_wire) in [
        (
            0,
            vec![1, 127, 128, 254, 255, 0],
            vec![
                Value::Integer(1),
                Value::Integer(127),
                Value::Integer(128),
                Value::Integer(254),
                Value::Integer(255),
                Value::Integer(0),
            ],
        ),
        (
            9_007_199_254_740_989,
            vec![9, 10],
            vec![Value::Integer(9), Value::Integer(10)],
        ),
        (
            9_007_199_254_675_455,
            vec![255; 65_536],
            vec![Value::Integer(255); 65_536],
        ),
    ] {
        let typed = SnapshotRequest::PutChunk {
            upload_id: UploadId::new("上传/\"\\\n".into()).unwrap(),
            blob_sha256: digest(24),
            offset,
            bytes,
            chunk_sha256: digest(25),
        };
        let expected = obj([
            ("schema_version", Value::Integer(1)),
            ("operation", Value::String("PutChunk".into())),
            ("upload_id", Value::String("上传/\"\\\n".into())),
            (
                "blob_sha256",
                Value::String(format!("sha256:{}", "18".repeat(32))),
            ),
            ("offset", Value::Integer(i128::from(offset))),
            ("bytes", Value::Array(byte_wire)),
            (
                "chunk_sha256",
                Value::String(format!("sha256:{}", "19".repeat(32))),
            ),
        ]);
        assert_eq!(typed.to_value(), expected, "offset {offset}");
    }
}

#[test]
fn each_id_only_operation_encoder_preserves_unicode_id_and_exact_operation() {
    for id in ["另一个-upload", "汉/\"\\\n"] {
        for (typed, label) in [
            (
                SnapshotRequest::Get {
                    upload_id: UploadId::new(id.into()).unwrap(),
                },
                "Get",
            ),
            (
                SnapshotRequest::Seal {
                    upload_id: UploadId::new(id.into()).unwrap(),
                },
                "Seal",
            ),
            (
                SnapshotRequest::Cancel {
                    upload_id: UploadId::new(id.into()).unwrap(),
                },
                "Cancel",
            ),
        ] {
            assert_eq!(
                typed.to_value(),
                obj([
                    ("schema_version", Value::Integer(1)),
                    ("operation", Value::String(label.into())),
                    ("upload_id", Value::String(id.into())),
                ]),
                "{label} Unicode ID"
            );
        }
    }
}

#[test]
fn standalone_blob_encoder_preserves_nondefault_digest_and_all_range_boundaries() {
    for (size, offset) in [(0, 0), (5, 2), (67_108_864, 67_108_864)] {
        let typed = UploadBlob {
            sha256: digest(24),
            size_bytes: size,
            durable_offset: offset,
        };
        let expected = obj([
            (
                "sha256",
                Value::String(format!("sha256:{}", "18".repeat(32))),
            ),
            ("size_bytes", Value::Integer(i128::from(size))),
            ("durable_offset", Value::Integer(i128::from(offset))),
        ]);
        assert_eq!(typed.to_value(), expected, "blob range {offset}/{size}");
    }
}

#[test]
fn fail_encoder_preserves_all_typed_codes_reason_retryability_and_optional_id() {
    for (code, label) in [
        (TaskErrorCode::InvalidRequest, "INVALID_REQUEST"),
        (TaskErrorCode::UnsupportedVersion, "UNSUPPORTED_VERSION"),
        (
            TaskErrorCode::UnsupportedCapability,
            "UNSUPPORTED_CAPABILITY",
        ),
        (TaskErrorCode::AuthDenied, "AUTH_DENIED"),
        (TaskErrorCode::ProviderUnreachable, "PROVIDER_UNREACHABLE"),
        (TaskErrorCode::EnvironmentMismatch, "ENVIRONMENT_MISMATCH"),
        (TaskErrorCode::CapacityUnavailable, "CAPACITY_UNAVAILABLE"),
        (TaskErrorCode::IdempotencyConflict, "IDEMPOTENCY_CONFLICT"),
        (TaskErrorCode::PersistenceFailed, "PERSISTENCE_FAILED"),
        (TaskErrorCode::StateCorrupt, "STATE_CORRUPT"),
        (TaskErrorCode::InputUnavailable, "INPUT_UNAVAILABLE"),
        (
            TaskErrorCode::InputIntegrityFailed,
            "INPUT_INTEGRITY_FAILED",
        ),
        (TaskErrorCode::InvalidPath, "INVALID_PATH"),
        (TaskErrorCode::OutputExists, "OUTPUT_EXISTS"),
        (TaskErrorCode::ArtifactMissing, "ARTIFACT_MISSING"),
        (
            TaskErrorCode::ArtifactIntegrityFailed,
            "ARTIFACT_INTEGRITY_FAILED",
        ),
        (TaskErrorCode::ArtifactUnavailable, "ARTIFACT_UNAVAILABLE"),
        (TaskErrorCode::WorkloadExit, "WorkloadExit"),
        (TaskErrorCode::Timeout, "Timeout"),
        (
            TaskErrorCode::PrepareDeadlineExceeded,
            "PrepareDeadlineExceeded",
        ),
        (
            TaskErrorCode::DeliveryDeadlineExceeded,
            "DeliveryDeadlineExceeded",
        ),
        (TaskErrorCode::ExecutionLost, "ExecutionLost"),
    ] {
        for retryable in [false, true] {
            for id in [None, Some("错误/\"\\\n")] {
                let typed = SnapshotEnvelope::Error {
                    error: TaskError::new(code, "原因/\"\\\n", retryable),
                    upload_id: id.map(|text| UploadId::new(text.into()).unwrap()),
                };
                let expected = obj([
                    ("schema_version", Value::Integer(1)),
                    ("verdict", Value::String("FAIL".into())),
                    (
                        "error",
                        obj([
                            ("code", Value::String(label.into())),
                            ("reason", Value::String("原因/\"\\\n".into())),
                            ("retryable", Value::Bool(retryable)),
                        ]),
                    ),
                    (
                        "upload_id",
                        id.map_or(Value::Null, |text| Value::String(text.into())),
                    ),
                ]);
                assert_eq!(
                    typed.to_value(),
                    expected,
                    "{label} retryable={retryable}, id={id:?}"
                );
                // This is a second independent direction from the hand-built
                // Value, not a roundtrip of the encoder's actual output.
                assert_eq!(SnapshotEnvelope::from_value(expected).unwrap(), typed);
            }
        }
    }
}
