use super::*;
use nexus_domain::task::*;

fn request() -> SubmitTaskRequest {
    decode_dto(include_bytes!(
        "../../../docs/contracts/n3-submit.example.json"
    ))
    .unwrap()
}
#[test]
fn frozen_canonical_vectors_match_exact_bytes_and_known_hashes() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/contracts/n3-canonical-vectors.json"
    ))
    .unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let value =
            parse_canonical_json(vector["input_json"].as_str().unwrap().as_bytes()).unwrap();
        let bytes = value.canonical_bytes();
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex, vector["canonical_utf8_hex"].as_str().unwrap());
        assert_eq!(
            &sha256(&bytes).as_str()[7..],
            vector["sha256"].as_str().unwrap()
        );
    }
}
#[test]
fn json_rejects_ambiguous_or_lossy_inputs_at_every_nesting_depth() {
    for input in [
        r#"{"a":1,"\u0061":2}"#,
        r#"{"x":[{"a":1,"a":2}]}"#,
        r#"{"x":1.0}"#,
        r#"{"x":1e0}"#,
        r#"{"x":-0.0}"#,
        r#"{"x":01}"#,
        r#"{"x":+1}"#,
        r#"{"x":NaN}"#,
        r#"{"x":"\ud800"}"#,
        r#"{"x":"\udc00"}"#,
        r#"{"x":1}{}"#,
    ] {
        assert!(
            parse_canonical_json(input.as_bytes()).is_err(),
            "accepted {input}"
        );
    }
    assert!(parse_canonical_json(&[0xff]).is_err());
    assert_eq!(
        parse_canonical_json(br#"{"n":-0,"s":"-0/1e2"}"#)
            .unwrap()
            .canonical_bytes(),
        br#"{"n":0,"s":"-0/1e2"}"#
    );
}
#[test]
fn request_validation_and_digest_cover_all_execution_inputs() {
    let r = request();
    r.input_snapshot.verify_digest(sha256).unwrap();
    let digest = r.request_digest(sha256).unwrap();
    assert_eq!(
        decode_dto::<SubmitTaskRequest>(&r.to_value().canonical_bytes()).unwrap(),
        r
    );
    let mut same = r.clone();
    same.idempotency_key = "another".into();
    same.idempotency_ttl_seconds = 1;
    assert_eq!(same.request_digest(sha256).unwrap(), digest);
    for mutate in [
        |x: &mut SubmitTaskRequest| x.command.push("changed".into()),
        |x: &mut SubmitTaskRequest| x.limits.cpu_millis += 1,
        |x: &mut SubmitTaskRequest| x.success_exit_codes.push(7),
        |x: &mut SubmitTaskRequest| {
            x.outputs.push(OutputSpec {
                path: "target/output".into(),
                required: true,
            })
        },
        |x: &mut SubmitTaskRequest| x.cwd = "src".into(),
        |x: &mut SubmitTaskRequest| x.resource = "res-other".into(),
        |x: &mut SubmitTaskRequest| x.provider = "prov-other".into(),
    ] {
        let mut changed = r.clone();
        mutate(&mut changed);
        assert_ne!(changed.request_digest(sha256).unwrap(), digest);
    }
    let mut bad = r.clone();
    bad.input_snapshot.file_count += 1;
    assert_eq!(
        bad.request_digest(sha256).unwrap_err().code,
        TaskErrorCode::InputIntegrityFailed
    );
    for mutate in [
        |x: &mut SubmitTaskRequest| x.schema_version = 2,
        |x: &mut SubmitTaskRequest| x.workspace = "other".into(),
        |x: &mut SubmitTaskRequest| x.command.clear(),
        |x: &mut SubmitTaskRequest| x.command[0] = "".into(),
        |x: &mut SubmitTaskRequest| x.command.push("bad\0arg".into()),
        |x: &mut SubmitTaskRequest| x.command = vec!["x".into(); 1025],
        |x: &mut SubmitTaskRequest| x.command[0] = "x".repeat(32769),
        |x: &mut SubmitTaskRequest| x.cwd = "a//b".into(),
        |x: &mut SubmitTaskRequest| x.cwd = "../x".into(),
        |x: &mut SubmitTaskRequest| x.environment.isolation = "host".into(),
        |x: &mut SubmitTaskRequest| x.environment.network = "host".into(),
        |x: &mut SubmitTaskRequest| x.limits.memory_bytes = 0,
        |x: &mut SubmitTaskRequest| x.limits.log_bytes = MAX_INTEGER + 1,
        |x: &mut SubmitTaskRequest| x.idempotency_ttl_seconds = 0,
        |x: &mut SubmitTaskRequest| x.idempotency_ttl_seconds = 86401,
        |x: &mut SubmitTaskRequest| {
            x.outputs = vec![
                OutputSpec {
                    path: "a".into(),
                    required: true
                };
                2
            ]
        },
        |x: &mut SubmitTaskRequest| x.success_exit_codes = vec![0, 0],
    ] {
        let mut bad = r.clone();
        mutate(&mut bad);
        assert!(bad.request_digest(sha256).is_err());
    }
    let Value::Object(mut fields) = r.to_value() else {
        panic!()
    };
    fields.insert("principal".into(), "spoof".to_string().to_value());
    assert!(SubmitTaskRequest::from_value(Value::Object(fields)).is_err());
    assert!(u64::from_value(Value::Integer(i128::from(MAX_INTEGER) + 1)).is_err());
    assert!(u64::from_value(Value::Integer(-1)).is_err());
}

#[test]
fn sha256_stream_clone_extends_a_verified_prefix() {
    let data: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
    let prefix = sha256_stream_reader(&data[..131_072]).unwrap();
    assert_eq!(prefix.clone().finish(), sha256(&data[..131_072]));
    let mut extended = prefix.clone();
    extended.update(&data[131_072..]);
    assert_eq!(extended.finish(), sha256(&data));
    assert_eq!(sha256_reader(&data[..]).unwrap(), sha256(&data));
    assert_eq!(Sha256Stream::default().finish(), sha256(b""));
}
