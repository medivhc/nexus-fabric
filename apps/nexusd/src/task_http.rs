//! Strict N3 HTTP framing with a single total read budget; v0 dispatch is retained.
use crate::task_service::LocalTaskService;
use nexus_control_api::task::{CanonicalDto, TaskEnvelope, TaskRequest};
use nexus_domain::task::{TaskError, TaskErrorCode};
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};
const MAX_HEADER: usize = 16_384;
const MAX_BODY: usize = 1_048_576;
const MAX_RESPONSE: usize = 2_097_152;
const READ_BUDGET: Duration = Duration::from_secs(3);

pub trait HttpIo: Read + Write {
    fn read_timeout(&self, timeout: Duration) -> std::io::Result<()>;
    fn write_timeout(&self, timeout: Duration) -> std::io::Result<()>;
    /// Send FIN after the complete response without consuming untrusted input.
    fn shutdown_write(&self) -> std::io::Result<()>;
}
impl HttpIo for std::net::TcpStream {
    fn read_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
    fn write_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}
#[cfg(unix)]
impl HttpIo for std::os::unix::net::UnixStream {
    fn read_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
    fn write_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}
pub struct LegacyHead {
    pub request_line: String,
    pub headers: Vec<String>,
}
struct Refusal {
    status: u16,
    error: TaskError,
}
fn invalid(reason: &str) -> Refusal {
    Refusal {
        status: 400,
        error: TaskError::invalid(reason),
    }
}
fn capacity(reason: &str) -> Refusal {
    Refusal {
        status: 413,
        error: TaskError::new(TaskErrorCode::CapacityUnavailable, reason, false),
    }
}
fn budget(stream: &dyn HttpIo, deadline: Instant) -> Result<(), Refusal> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| invalid("request read budget exhausted"))?;
    stream
        .read_timeout(remaining)
        .map_err(|_| invalid("cannot bound request read"))
}
fn read_head(stream: &mut dyn HttpIo, deadline: Instant) -> Result<LegacyHead, Refusal> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER {
            return Err(capacity("request headers exceed 16 KiB"));
        }
        budget(stream, deadline)?;
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|_| invalid("truncated headers or request deadline"))?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("headers must be UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let headers = lines
        .take_while(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(LegacyHead {
        request_line,
        headers,
    })
}
fn equal_token(left: &[u8], right: &[u8]) -> bool {
    let mut mismatch = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        mismatch |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    mismatch == 0
}
fn body(stream: &mut dyn HttpIo, deadline: Instant, size: usize) -> Result<Vec<u8>, Refusal> {
    let mut bytes = vec![0; size];
    let mut used = 0;
    while used < size {
        budget(stream, deadline)?;
        let count = stream
            .read(&mut bytes[used..])
            .map_err(|_| invalid("truncated body or request deadline"))?;
        if count == 0 {
            return Err(invalid("truncated request body"));
        }
        used += count;
    }
    Ok(bytes)
}
fn envelope(stream: &mut dyn HttpIo, status: u16, value: TaskEnvelope) -> Result<(), String> {
    let bytes = value.to_value().canonical_bytes();
    if bytes.len() > MAX_RESPONSE {
        return envelope(
            stream,
            413,
            TaskEnvelope::Error {
                error: TaskError::new(
                    TaskErrorCode::CapacityUnavailable,
                    "response exceeds 2 MiB",
                    false,
                ),
                task_id: None,
            },
        );
    }
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let response = [header.as_bytes(), &bytes].concat();
    let deadline = Instant::now() + READ_BUDGET;
    let mut written = 0;
    while written < response.len() {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|timeout| !timeout.is_zero())
            .ok_or_else(|| "response write budget exhausted".to_string())?;
        stream.write_timeout(timeout).map_err(|e| e.to_string())?;
        match stream.write(&response[written..]) {
            Ok(0) => return Err("response write made no progress".into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    stream.flush().map_err(|e| e.to_string())?;
    // Closing TCP with unread rejected body bytes may reset the response. FIN
    // makes the complete framed response observable, without reading the body,
    // waiting for its remainder, or invoking the service after refusal.
    stream.shutdown_write().map_err(|e| e.to_string())
}
/// Returns the already parsed header only for legacy routes. N3 is always closed
/// after this call; caller must not loop to accept pipelined requests.
pub fn dispatch(
    stream: &mut dyn HttpIo,
    expected_token: &str,
    local_transport: bool,
    service: &LocalTaskService,
    token_authority: &TokenAuthority,
) -> Result<Option<LegacyHead>, String> {
    let deadline = Instant::now() + READ_BUDGET;
    let head = match read_head(stream, deadline) {
        Ok(head) => head,
        Err(refusal) => {
            envelope(
                stream,
                refusal.status,
                TaskEnvelope::Error {
                    error: refusal.error,
                    task_id: None,
                },
            )?;
            return Ok(None);
        }
    };
    let parts: Vec<_> = head.request_line.split_whitespace().collect();
    let target = parts.get(1).copied().unwrap_or_default();
    if !target.starts_with("/localapi/v1/") {
        return Ok(Some(head));
    }
    let result = (|| {
        if parts.len() != 3 || parts[2] != "HTTP/1.1" || target != "/localapi/v1/task" {
            return Err(invalid(
                "N3 requires exact HTTP/1.1 route without query or aliases",
            ));
        }
        let mut authorization = None;
        let mut length = None;
        let mut content_type = None;
        for header in &head.headers {
            let (key, value) = header
                .split_once(':')
                .ok_or_else(|| invalid("malformed header"))?;
            if key.is_empty()
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
            {
                return Err(invalid("invalid header characters"));
            }
            let value = value.trim();
            match key.to_ascii_lowercase().as_str() {
                "authorization" => {
                    if authorization.replace(value).is_some() {
                        return Err(invalid("duplicate Authorization"));
                    }
                }
                "content-length" => {
                    if length.replace(value).is_some() {
                        return Err(invalid("duplicate Content-Length"));
                    }
                }
                "content-type" => {
                    if content_type.replace(value).is_some() {
                        return Err(invalid("duplicate Content-Type"));
                    }
                }
                "transfer-encoding" => return Err(invalid("Transfer-Encoding is unsupported")),
                _ => {}
            }
        }
        let authenticated = authorization
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| equal_token(token.as_bytes(), expected_token.as_bytes()));
        if !local_transport || !authenticated || !token_authority.valid() {
            return Err(Refusal {
                status: 401,
                error: TaskError::new(
                    TaskErrorCode::AuthDenied,
                    "N3 requires authenticated local transport",
                    false,
                ),
            });
        }
        if parts[0] != "POST" {
            return Err(Refusal {
                status: 405,
                error: TaskError::invalid("N3 route requires POST"),
            });
        }
        if content_type != Some("application/json") {
            return Err(invalid("Content-Type must be application/json"));
        }
        let raw_length = length.ok_or_else(|| invalid("missing Content-Length"))?;
        if raw_length.is_empty() || !raw_length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("invalid Content-Length"));
        }
        let size: usize = raw_length
            .parse()
            .map_err(|_| capacity("body exceeds 1 MiB"))?;
        if size > MAX_BODY {
            return Err(capacity("body exceeds 1 MiB"));
        }
        let bytes = body(stream, deadline, size)?;
        let request =
            nexus::n3_acceptance::decode_dto::<TaskRequest>(&bytes).map_err(|e| Refusal {
                status: 400,
                error: TaskError::invalid(format!("request DTO rejected: {}", e.reason)),
            })?;
        Ok(service.execute(request))
    })();
    match result {
        Ok(value) => envelope(stream, 200, value)?,
        Err(refusal) => envelope(
            stream,
            refusal.status,
            TaskEnvelope::Error {
                error: refusal.error,
                task_id: None,
            },
        )?,
    }
    Ok(None)
}

/// Pins the private token's initial inode and verifies it before every N3 body.
/// v0 retains its existing token behavior.
pub struct TokenAuthority {
    expected: String,
    path: std::path::PathBuf,
    #[cfg(unix)]
    identity: Option<(u64, u64)>,
}
impl TokenAuthority {
    pub fn open(expected: &str) -> Self {
        Self::open_at(expected, nexus::localapi_client::token_file_path())
    }
    /// Bind this listener to its explicit token path, keeping legacy open intact.
    pub fn open_at(expected: &str, path: std::path::PathBuf) -> Self {
        Self {
            expected: expected.to_owned(),
            #[cfg(unix)]
            identity: private_token(&path, expected).ok(),
            path,
        }
    }
    fn valid(&self) -> bool {
        #[cfg(unix)]
        {
            self.identity.is_some()
                && private_token(&self.path, &self.expected).ok() == self.identity
        }
        #[cfg(not(unix))]
        {
            let _ = (&self.path, &self.expected);
            false
        }
    }
}
#[cfg(unix)]
fn private_token(path: &std::path::Path, expected: &str) -> Result<(u64, u64), ()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    #[cfg(target_os = "linux")]
    let flags = 0x20000 | 0x800;
    #[cfg(target_os = "macos")]
    let flags = 0x100 | 0x4;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(());
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|_| ())?;
        let fd = file.metadata().map_err(|_| ())?;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
        if !fd.is_file()
            || fd.nlink() != 1
            || fd.permissions().mode() & 0o777 != 0o600
            || metadata.file_type().is_symlink()
            || metadata.dev() != fd.dev()
            || metadata.ino() != fd.ino()
            || fd.len() > 128
        {
            return Err(());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(129)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        let value = std::str::from_utf8(&bytes).map_err(|_| ())?.trim();
        if !equal_token(value.as_bytes(), expected.as_bytes()) {
            return Err(());
        }
        Ok((fd.dev(), fd.ino()))
    }
}
