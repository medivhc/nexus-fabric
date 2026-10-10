use super::*;
use nexus_control_api::task::{LogStream, TaskId, TaskLogsPage};
use std::io::Cursor;

struct MemoryStream {
    input: Cursor<Vec<u8>>,
    written: Vec<u8>,
}
impl Read for MemoryStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}
impl Write for MemoryStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl TaskStreamIo for MemoryStream {
    fn read_timeout(&self, _: Duration) -> std::io::Result<()> {
        Ok(())
    }
    fn write_timeout(&self, _: Duration) -> std::io::Result<()> {
        Ok(())
    }
}
fn request() -> TaskRequest {
    TaskRequest::Get {
        task_id: TaskId::new("accepted-task".into()).unwrap(),
    }
}
fn failure(id: Option<&str>) -> TaskEnvelope {
    TaskEnvelope::Error {
        error: TaskError::new(
            TaskErrorCode::UnsupportedCapability,
            "TaskApplicationService adapter unavailable",
            false,
        ),
        task_id: id.map(|id| TaskId::new(id.into()).unwrap()),
    }
}
fn response(status: u16, body: &[u8], extra: &str) -> Vec<u8> {
    [format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n", body.len()).as_bytes(), body].concat()
}
fn decode(bytes: Vec<u8>) -> Result<TaskEnvelope, TaskError> {
    let request = request();
    execute_over(
        &mut MemoryStream {
            input: Cursor::new(bytes),
            written: Vec::new(),
        },
        &request.to_value().canonical_bytes(),
        &request,
        &"a".repeat(64),
        Instant::now() + IO_BUDGET,
    )
}
#[test]
fn post_uses_canonical_body_and_authentication_without_principal() {
    let req = request();
    let expected = failure(Some("accepted-task"));
    let mut stream = MemoryStream {
        input: Cursor::new(response(200, &expected.to_value().canonical_bytes(), "")),
        written: Vec::new(),
    };
    assert_eq!(
        execute_over(
            &mut stream,
            &req.to_value().canonical_bytes(),
            &req,
            &"a".repeat(64),
            Instant::now() + IO_BUDGET
        )
        .unwrap(),
        expected
    );
    let request = String::from_utf8(stream.written).unwrap();
    assert!(request.starts_with("POST /localapi/v1/task HTTP/1.1\r\n"));
    assert!(request.contains(&format!("Authorization: Bearer {}\r\n", "a".repeat(64))));
    assert!(request.ends_with(&String::from_utf8(req.to_value().canonical_bytes()).unwrap()));
    assert!(!request.contains("principal"));
}
#[test]
fn rejects_framing_and_schema_before_returning_business_success() {
    let body = failure(Some("accepted-task")).to_value().canonical_bytes();
    for raw in [
        response(200, &body, "Content-Length: 1\r\n"),
        response(200, &body, "Transfer-Encoding: chunked\r\n"),
        response(200, &body, "Content-Type: application/json\r\n"),
        response(200, &body, "Authorization: x\r\nAuthorization: y\r\n"),
        response(500, &body, ""),
        response(401, &body, ""),
        response(200, b"{\"schema_version\":1,\"schema_version\":1}", ""),
        response(200, b"{\"schema_version\":1e0}", ""),
        response(200, b"{\"schema_version\":2}", ""),
        response(200, b"{\"schema_version\":1,\"unknown\":true}", ""),
        [response(200, &body, ""), b"extra".to_vec()].concat(),
    ] {
        assert_eq!(decode(raw).unwrap_err().code, TaskErrorCode::InvalidRequest);
    }
    let mut truncated = response(200, &body, "");
    truncated.pop();
    assert_eq!(
        decode(truncated).unwrap_err().code,
        TaskErrorCode::InvalidRequest
    );
}
#[test]
fn header_and_declared_body_capacity_are_rejected_without_allocation() {
    let mut header = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
    header.extend(vec![b'a'; HEADER_LIMIT]);
    assert_eq!(
        decode(header).unwrap_err().code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        parse_header(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2097153\r\n\r\n"
        )
        .unwrap_err()
        .code,
        TaskErrorCode::CapacityUnavailable
    );
    assert_eq!(
        parse_header(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
            .unwrap_err()
            .code,
        TaskErrorCode::InvalidRequest
    );
}
#[test]
fn auth_http_error_is_strict_and_response_id_must_match() {
    let auth = TaskEnvelope::Error {
        error: TaskError::new(TaskErrorCode::AuthDenied, "denied", false),
        task_id: None,
    };
    assert_eq!(
        decode(response(401, &auth.to_value().canonical_bytes(), "")).unwrap(),
        auth
    );
    assert_eq!(
        decode(response(
            200,
            &failure(Some("foreign-task")).to_value().canonical_bytes(),
            ""
        ))
        .unwrap_err()
        .code,
        TaskErrorCode::InvalidRequest
    );
}
#[test]
fn log_response_type_stream_offset_and_requested_limit_are_correlated() {
    let req = TaskRequest::ReadLogs {
        task_id: TaskId::new("task".into()).unwrap(),
        stream: LogStream::Stdout,
        offset: 7,
        max_bytes: 1,
    };
    let page = TaskLogsPage {
        task_id: TaskId::new("task".into()).unwrap(),
        stream: LogStream::Stdout,
        offset: 7,
        bytes: vec![1],
        next_offset: 8,
        eof: false,
        truncated: false,
    };
    let ok = TaskEnvelope::Success(TaskResponse::Logs(page.clone()));
    validate_correlated_response(&req, &ok).unwrap();
    for altered in [
        TaskLogsPage {
            stream: LogStream::Stderr,
            ..page.clone()
        },
        TaskLogsPage {
            offset: 8,
            next_offset: 9,
            ..page.clone()
        },
        TaskLogsPage {
            task_id: TaskId::new("other".into()).unwrap(),
            ..page.clone()
        },
        TaskLogsPage {
            bytes: vec![1, 2],
            next_offset: 9,
            ..page.clone()
        },
    ] {
        assert_eq!(
            validate_correlated_response(&req, &TaskEnvelope::Success(TaskResponse::Logs(altered)))
                .unwrap_err()
                .code,
            TaskErrorCode::InvalidRequest
        );
    }
    assert_eq!(
        validate_correlated_response(&request(), &ok)
            .unwrap_err()
            .code,
        TaskErrorCode::InvalidRequest
    );
}
#[test]
fn an_expired_total_budget_is_not_reset_by_progress() {
    let req = request();
    let error = execute_over(
        &mut MemoryStream {
            input: Cursor::new(Vec::new()),
            written: Vec::new(),
        },
        &req.to_value().canonical_bytes(),
        &req,
        "token",
        Instant::now() - Duration::from_millis(1),
    )
    .unwrap_err();
    assert_eq!(error.code, TaskErrorCode::ProviderUnreachable);
    assert!(error.retryable);
    assert!(error.reason.contains("total IO budget"));
}
#[test]
fn actual_tcp_slow_drip_cannot_extend_the_total_read_budget() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let owner = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut input = [0; 4096];
        assert!(stream.read(&mut input).unwrap() > 0);
        for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" {
            if stream.write_all(&[*byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    });
    let mut stream = TcpStream::connect(address).unwrap();
    let req = request();
    let start = Instant::now();
    let error = execute_over(
        &mut stream,
        &req.to_value().canonical_bytes(),
        &req,
        "token",
        start + Duration::from_millis(80),
    )
    .unwrap_err();
    drop(stream);
    owner.join().unwrap();
    assert_eq!(error.code, TaskErrorCode::ProviderUnreachable);
    assert!(error.retryable);
    assert!(start.elapsed() < Duration::from_millis(400));
}
#[test]
fn nonloopback_tcp_is_rejected_before_creating_credentials() {
    let error = execute(&LocalApiTarget::Tcp("192.0.2.1:18080".into()), &request()).unwrap_err();
    assert_eq!(error.code, TaskErrorCode::AuthDenied);
}
