//! Bounded N3 LocalAPI client. No Task owner or remote plaintext transport.
use crate::localapi_client::{LocalApiTarget, token_file_path};
use nexus_control_api::task::{
    CanonicalDto, TaskEnvelope, TaskError, TaskErrorCode, TaskRequest, TaskResponse,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const HEADER_LIMIT: usize = 16 * 1024;
const REQUEST_LIMIT: usize = 1024 * 1024;
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
const IO_BUDGET: Duration = Duration::from_secs(5);

fn bad(reason: impl std::fmt::Display) -> TaskError {
    TaskError::invalid(format!("bad local daemon response: {reason}"))
}
fn unavailable(reason: impl std::fmt::Display) -> TaskError {
    TaskError::new(
        TaskErrorCode::ProviderUnreachable,
        format!("local daemon unavailable: {reason}"),
        true,
    )
}
fn capacity(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::CapacityUnavailable, reason, false)
}
fn remaining(deadline: Instant) -> Result<Duration, TaskError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| unavailable("total IO budget exhausted"))
}

pub(crate) fn execute(
    target: &LocalApiTarget,
    request: &TaskRequest,
) -> Result<TaskEnvelope, TaskError> {
    request.validate()?;
    let bytes = request.to_value().canonical_bytes();
    let (status, body) = exchange(target, "/localapi/v1/task", &bytes)?;
    decode_task(status, &body, request)
}

/// The snapshot protocol shares only bounded transport and credentials with
/// Task. Its DTO, correlation and operation semantics remain separate.
#[cfg(target_os = "linux")]
pub(crate) fn execute_snapshot(
    target: &LocalApiTarget,
    request: &nexus_control_api::snapshot::SnapshotRequest,
) -> Result<nexus_control_api::snapshot::SnapshotEnvelope, TaskError> {
    use nexus_control_api::snapshot::SnapshotEnvelope;
    request.validate()?;
    let (status, body) = exchange(
        target,
        "/localapi/v1/snapshot",
        &request.to_value().canonical_bytes(),
    )?;
    let envelope: SnapshotEnvelope = crate::n3_acceptance::decode_dto(&body).map_err(bad)?;
    envelope.validate_for(request).map_err(bad)?;
    if let SnapshotEnvelope::Upload(view) = &envelope {
        view.snapshot
            .verify_digest(crate::n3_acceptance::sha256)
            .map_err(bad)?;
    }
    if status != 200 {
        let expected = status_error(status);
        if !matches!(&envelope, SnapshotEnvelope::Error { error, .. }
            if error.code == expected && !error.retryable)
        {
            return Err(bad("HTTP status and snapshot envelope disagree"));
        }
    }
    Ok(envelope)
}

fn exchange(
    target: &LocalApiTarget,
    route: &str,
    bytes: &[u8],
) -> Result<(u16, Vec<u8>), TaskError> {
    if bytes.len() > REQUEST_LIMIT {
        return Err(capacity("LocalAPI request exceeds 1 MiB"));
    }
    // Validate TCP locality before reading credentials or opening any connection.
    let tcp = match target {
        LocalApiTarget::Tcp(address) => {
            let address: SocketAddr = address.parse().map_err(|_| {
                TaskError::invalid(
                    "N3 LocalAPI TCP target must be a numeric loopback socket address",
                )
            })?;
            if !address.ip().is_loopback() {
                return Err(TaskError::new(
                    TaskErrorCode::AuthDenied,
                    "N3 LocalAPI token cannot be sent to non-loopback TCP",
                    false,
                ));
            }
            Some(address)
        }
        _ => None,
    };
    let deadline = Instant::now() + IO_BUDGET;
    match target {
        LocalApiTarget::Tcp(_) => {
            let mut stream = TcpStream::connect_timeout(
                &tcp.ok_or_else(|| bad("missing validated address"))?,
                remaining(deadline)?,
            )
            .map_err(unavailable)?;
            let token = bearer_token()?;
            exchange_over(&mut stream, bytes, route, &token, deadline)
        }
        #[cfg(unix)]
        LocalApiTarget::Socket(path) => {
            // A full Unix listener backlog can block a blocking connect. A local
            // nonblocking connect either succeeds immediately or fails retryably;
            // never wait on an unowned helper thread or unbounded connect.
            let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
                .map_err(unavailable)?;
            socket.set_nonblocking(true).map_err(unavailable)?;
            socket
                .connect(&socket2::SockAddr::unix(path).map_err(unavailable)?)
                .map_err(unavailable)?;
            socket.set_nonblocking(false).map_err(unavailable)?;
            let descriptor: std::os::fd::OwnedFd = socket.into();
            let mut stream = std::os::unix::net::UnixStream::from(descriptor);
            let token = bearer_token()?;
            exchange_over(&mut stream, bytes, route, &token, deadline)
        }
        #[cfg(not(unix))]
        LocalApiTarget::Socket(_) => Err(TaskError::new(
            TaskErrorCode::UnsupportedCapability,
            "LocalAPI unix socket is unavailable on this platform",
            false,
        )),
    }
}

fn credential_denied() -> TaskError {
    TaskError::new(
        TaskErrorCode::AuthDenied,
        "local daemon bearer token unavailable or invalid",
        false,
    )
}
// Only daemon-created, regular private credentials are read. No token contents
// enter error messages or HTTP headers until the complete bounded value passes.
fn bearer_token() -> Result<String, TaskError> {
    let file =
        crate::task_cli::open_request_file(&token_file_path()).map_err(|_| credential_denied())?;
    let metadata = file.metadata().map_err(|_| credential_denied())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(credential_denied());
        }
    }
    if metadata.len() > 4096 {
        return Err(credential_denied());
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| credential_denied())?;
    if bytes.is_empty() || bytes.len() > 4096 || !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(credential_denied());
    }
    String::from_utf8(bytes).map_err(|_| credential_denied())
}

trait TaskStreamIo: Read + Write {
    fn read_timeout(&self, timeout: Duration) -> std::io::Result<()>;
    fn write_timeout(&self, timeout: Duration) -> std::io::Result<()>;
}
impl TaskStreamIo for TcpStream {
    fn read_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
    fn write_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}
#[cfg(unix)]
impl TaskStreamIo for std::os::unix::net::UnixStream {
    fn read_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
    fn write_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
}
fn read_some(
    stream: &mut dyn TaskStreamIo,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<usize, TaskError> {
    loop {
        stream
            .read_timeout(remaining(deadline)?)
            .map_err(unavailable)?;
        match stream.read(bytes) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => {
                let count = result.map_err(unavailable)?;
                remaining(deadline)?;
                return Ok(count);
            }
        }
    }
}
#[cfg(test)]
fn execute_over(
    stream: &mut dyn TaskStreamIo,
    bytes: &[u8],
    request: &TaskRequest,
    token: &str,
    deadline: Instant,
) -> Result<TaskEnvelope, TaskError> {
    let (status, body) = exchange_over(stream, bytes, "/localapi/v1/task", token, deadline)?;
    decode_task(status, &body, request)
}
fn exchange_over(
    stream: &mut dyn TaskStreamIo,
    bytes: &[u8],
    route: &str,
    token: &str,
    deadline: Instant,
) -> Result<(u16, Vec<u8>), TaskError> {
    let header = format!(
        "POST {route} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        bytes.len()
    );
    let data = [header.as_bytes(), bytes].concat();
    let mut written = 0;
    while written < data.len() {
        stream
            .write_timeout(remaining(deadline)?)
            .map_err(unavailable)?;
        match stream.write(&data[written..]) {
            Ok(0) => return Err(unavailable("request write made no progress")),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(unavailable(e)),
        }
    }
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == HEADER_LIMIT {
            return Err(capacity("LocalAPI response header exceeds 16 KiB"));
        }
        if read_some(stream, &mut byte, deadline)? == 0 {
            return Err(bad("truncated response header"));
        }
        header.push(byte[0]);
    }
    let (status, length) = parse_header(&header)?;
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        let n = read_some(stream, &mut body[offset..], deadline)?;
        if n == 0 {
            return Err(bad("truncated response body"));
        }
        offset += n;
    }
    if read_some(stream, &mut byte, deadline)? != 0 {
        return Err(bad("trailing bytes / pipelined response"));
    }
    Ok((status, body))
}
fn decode_task(status: u16, body: &[u8], request: &TaskRequest) -> Result<TaskEnvelope, TaskError> {
    let envelope: TaskEnvelope = crate::n3_acceptance::decode_dto(body).map_err(bad)?;
    validate_status(status, &envelope)?;
    validate_correlated_response(request, &envelope)?;
    Ok(envelope)
}
fn parse_header(bytes: &[u8]) -> Result<(u16, usize), TaskError> {
    let header = std::str::from_utf8(bytes).map_err(bad)?;
    let mut lines = header
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| bad("incomplete header"))?
        .split("\r\n");
    let status_line = lines.next().ok_or_else(|| bad("missing status"))?;
    if !status_line
        .bytes()
        .all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(bad("invalid HTTP status line bytes"));
    }
    let mut status = status_line.splitn(3, ' ');
    if status.next() != Some("HTTP/1.1") {
        return Err(bad("unsupported HTTP version"));
    }
    let code = status.next().ok_or_else(|| bad("missing status code"))?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) || status.next().is_none() {
        return Err(bad("invalid HTTP status"));
    }
    let status = code.parse::<u16>().map_err(bad)?;
    if ![200, 400, 401, 405, 413].contains(&status) {
        return Err(bad("unexpected HTTP status"));
    }
    let mut length = None;
    let mut content_type = None;
    let mut authorization = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad("malformed header"))?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f)
        {
            return Err(bad("invalid header token"));
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(bad("invalid / duplicate Content-Length"));
                }
                let count = value
                    .parse::<usize>()
                    .map_err(|_| capacity("LocalAPI response length exceeds capacity"))?;
                if count > RESPONSE_LIMIT {
                    return Err(capacity("LocalAPI response body exceeds 2 MiB"));
                }
                length = Some(count);
            }
            "content-type" => {
                if content_type.is_some() {
                    return Err(bad("duplicate Content-Type"));
                }
                content_type = Some(value);
            }
            "authorization" => {
                if authorization {
                    return Err(bad("duplicate Authorization"));
                }
                authorization = true;
            }
            "transfer-encoding" => return Err(bad("Transfer-Encoding is unsupported")),
            _ => {}
        }
    }
    if content_type != Some("application/json") {
        return Err(bad("expected Content-Type: application/json"));
    }
    Ok((status, length.ok_or_else(|| bad("missing Content-Length"))?))
}
fn validate_status(status: u16, envelope: &TaskEnvelope) -> Result<(), TaskError> {
    if status == 200 {
        return Ok(());
    }
    let expected = status_error(status);
    match envelope {
        TaskEnvelope::Error { error, .. } if error.code == expected && !error.retryable => Ok(()),
        _ => Err(bad("HTTP status and business envelope disagree")),
    }
}
fn status_error(status: u16) -> TaskErrorCode {
    match status {
        401 => TaskErrorCode::AuthDenied,
        413 => TaskErrorCode::CapacityUnavailable,
        _ => TaskErrorCode::InvalidRequest,
    }
}
fn validate_correlated_response(
    request: &TaskRequest,
    envelope: &TaskEnvelope,
) -> Result<(), TaskError> {
    let matches = match envelope {
        TaskEnvelope::Error { task_id, .. } => task_id
            .as_ref()
            .is_none_or(|id| request.task_id() == Some(id)),
        TaskEnvelope::Success(response) => match (request, response) {
            (TaskRequest::Submit { request }, TaskResponse::Task(view)) => {
                view.verify_digests(crate::n3_acceptance::sha256)
                    .map_err(bad)?;
                view.accepted_contract
                    .request
                    .request_digest(crate::n3_acceptance::sha256)
                    .map_err(bad)?
                    == request
                        .request_digest(crate::n3_acceptance::sha256)
                        .map_err(bad)?
            }
            (
                TaskRequest::Get { task_id } | TaskRequest::Cancel { task_id },
                TaskResponse::Task(view),
            ) => {
                view.verify_digests(crate::n3_acceptance::sha256)
                    .map_err(bad)?;
                &view.task_id == task_id
            }
            (
                TaskRequest::ReadLogs {
                    task_id,
                    stream,
                    offset,
                    max_bytes,
                },
                TaskResponse::Logs(page),
            ) => {
                &page.task_id == task_id
                    && &page.stream == stream
                    && &page.offset == offset
                    && page.bytes.len() as u64 <= *max_bytes
            }
            (TaskRequest::ListArtifacts { task_id }, TaskResponse::Artifacts(list)) => {
                &list.task_id == task_id
            }
            (
                TaskRequest::GetArtifact {
                    artifact_id,
                    offset,
                    max_bytes,
                },
                TaskResponse::Artifact(page),
            ) => {
                &page.record.artifact_id == artifact_id
                    && &page.offset == offset
                    && page.bytes.len() as u64 <= *max_bytes
            }
            _ => false,
        },
    };
    if matches {
        Ok(())
    } else {
        Err(bad("operation / identifier / page correlation mismatch"))
    }
}

#[cfg(test)]
mod tests;
