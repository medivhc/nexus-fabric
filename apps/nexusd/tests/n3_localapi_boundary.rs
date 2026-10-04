#[path = "../test_support/n3_localapi.rs"]
mod support;
use nexus_control_api::task::TaskRequest;
use nexus_domain::task::{TaskErrorCode, TaskId};
#[test]
fn real_daemon_versioned_boundary_and_no_acceptance() {
    let result = support::boundary(std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")));
    assert_eq!(result["verdict"], "PASS", "{result}");
}
#[test]
fn truncated_duplicate_credential_transfer_encoding_and_route_aliases_refused() {
    let dir = support::Dir::new();
    let daemon = support::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")),
        &dir.0,
        "127.0.0.1:0",
    );
    let header = format!(
        "POST /localapi/v1/task HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\n",
        support::TOKEN
    );
    for tail in [
        "Content-Length: 10\r\n\r\n{}",
        "Authorization: Bearer duplicate\r\nContent-Length: 2\r\n\r\n{}",
        "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
    ] {
        assert!(support::is_error(
            &support::exchange(&daemon.addr, format!("{header}{tail}").as_bytes(), true),
            400,
            TaskErrorCode::InvalidRequest
        ));
    }
    let raw = format!("{header}Content-Length: 2\r\n\r\n{{}}")
        .replace("/localapi/v1/task", "/localapi/v1/task?principal=forged");
    assert!(support::is_error(
        &support::exchange(&daemon.addr, raw.as_bytes(), false),
        400,
        TaskErrorCode::InvalidRequest
    ));
    assert!(support::is_error(
        &support::request(
            &daemon.addr,
            TaskRequest::Get {
                task_id: TaskId::new("x".into()).unwrap()
            }
        ),
        200,
        TaskErrorCode::UnsupportedCapability
    ));
}
#[test]
fn non_loopback_bound_listener_refuses_n3_even_for_loopback_peer() {
    let dir = support::Dir::new();
    let daemon = support::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")),
        &dir.0,
        "0.0.0.0:0",
    );
    let port = daemon.addr.rsplit(':').next().unwrap();
    let response = support::request(
        &format!("127.0.0.1:{port}"),
        TaskRequest::Get {
            task_id: TaskId::new("x".into()).unwrap(),
        },
    );
    assert!(support::is_error(&response, 401, TaskErrorCode::AuthDenied));
}

#[cfg(unix)]
#[test]
fn token_permissions_replacement_and_symlink_refuse_after_boot() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = support::Dir::new();
    let daemon = support::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")),
        &dir.0,
        "127.0.0.1:0",
    );
    let request = || TaskRequest::Get {
        task_id: TaskId::new("x".into()).unwrap(),
    };
    let token = dir.0.join("localapi.token");
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(support::is_error(
        &support::request(&daemon.addr, request()),
        401,
        TaskErrorCode::AuthDenied
    ));
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(support::is_error(
        &support::request(&daemon.addr, request()),
        200,
        TaskErrorCode::UnsupportedCapability
    ));
    let replacement = dir.0.join("replacement");
    std::fs::write(&replacement, support::TOKEN).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&replacement, &token).unwrap();
    assert!(support::is_error(
        &support::request(&daemon.addr, request()),
        401,
        TaskErrorCode::AuthDenied
    ));
    std::fs::rename(&token, &replacement).unwrap();
    symlink(&replacement, &token).unwrap();
    assert!(support::is_error(
        &support::request(&daemon.addr, request()),
        401,
        TaskErrorCode::AuthDenied
    ));
}
#[test]
fn slow_header_has_total_budget_and_does_not_starve_next_connection() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        time::{Duration, Instant},
    };
    let dir = support::Dir::new();
    let daemon = support::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")),
        &dir.0,
        "127.0.0.1:0",
    );
    let mut stream = TcpStream::connect(&daemon.addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .unwrap();
    stream
        .write_all(b"POST /localapi/v1/task HTTP/1.1\r\n")
        .unwrap();
    let start = Instant::now();
    // Progress within a per-read timeout cannot extend the overall deadline.
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(500));
        stream.write_all(b"X").unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(response.starts_with(b"HTTP/1.1 400"));
    assert!(support::is_error(
        &support::request(
            &daemon.addr,
            TaskRequest::Get {
                task_id: TaskId::new("x".into()).unwrap()
            }
        ),
        200,
        TaskErrorCode::UnsupportedCapability
    ));
}

#[test]
fn early_auth_refusal_returns_complete_response_and_fin_without_waiting_for_body() {
    use nexus_control_api::task::TaskEnvelope;
    use std::{
        io::{Read, Write},
        net::TcpStream,
        time::{Duration, Instant},
    };
    let dir = support::Dir::new();
    let daemon = support::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_nexusd")),
        &dir.0,
        "127.0.0.1:0",
    );
    for _ in 0..20 {
        let mut stream = TcpStream::connect(&daemon.addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // Leave the advertised body incomplete and do not half-close. The
        // daemon must refuse before decoding, without waiting to drain it.
        let head = b"POST /localapi/v1/task HTTP/1.1\r\nAuthorization: Bearer wrong\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n";
        let request = [head.as_slice(), &[b'x'; 4096]].concat();
        let started = Instant::now();
        stream.write_all(&request).unwrap();
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("complete response and FIN, no reset");
        assert!(started.elapsed() < Duration::from_secs(2));
        let boundary = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap();
        let header = std::str::from_utf8(&response[..boundary]).unwrap();
        assert!(header.starts_with("HTTP/1.1 401 "));
        let length: usize = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let body = &response[boundary + 4..];
        assert_eq!(body.len(), length);
        let envelope: TaskEnvelope = nexus::n3_acceptance::decode_dto(body).unwrap();
        let TaskEnvelope::Error { error, task_id } = envelope else {
            panic!("unauthenticated request succeeded")
        };
        assert_eq!(error.code, TaskErrorCode::AuthDenied);
        assert!(!error.retryable);
        assert!(task_id.is_none());
    }
    assert!(!dir.0.join("data/n3/tasks").exists());
}
