//! Local Docker Engine API. No CLI context, proxy defaults or shell interpolation.
use super::*;
use std::os::unix::net::UnixStream;

const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
#[derive(Clone)]
pub(super) struct Docker;
impl Docker {
    fn connect(&self, method: &str, path: &str, body: &Json) -> Result<UnixStream, TaskError> {
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(body).map_err(json_error)?
        };
        self.connect_raw(method, path, &bytes, "application/json")
    }
    fn connect_raw(
        &self,
        method: &str,
        path: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<UnixStream, TaskError> {
        let mut stream = UnixStream::connect("/var/run/docker.sock")
            .map_err(|_| unsupported("local Docker socket unavailable"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(io_error)?;
        write!(stream, "{method} /v1.45{path} HTTP/1.1\r\nHost: docker\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).map_err(io_error)?;
        stream.write_all(bytes).map_err(io_error)?;
        Ok(stream)
    }
    pub(super) fn request(&self, method: &str, path: &str, body: Json) -> Result<Json, TaskError> {
        let mut stream = self.connect(method, path, &body)?;
        let (status, headers) = header(&mut stream)?;
        if !(200..300).contains(&status) {
            return Err(TaskError::new(
                if status == 404 {
                    TaskErrorCode::EnvironmentMismatch
                } else {
                    TaskErrorCode::UnsupportedCapability
                },
                format!("Docker operation rejected (HTTP {status})"),
                false,
            ));
        }
        let bytes = body_bytes(&mut stream, &headers, RESPONSE_LIMIT)?;
        if bytes.is_empty() {
            Ok(Json::Null)
        } else {
            serde_json::from_slice(&bytes).map_err(json_error)
        }
    }
    pub(super) fn archive(&self, id: &str) -> Result<Vec<u8>, TaskError> {
        let (bytes, code) = self.capture(
            id,
            &["/bin/tar", "-C", "/", "-cf", "-", "work"],
            80 * 1024 * 1024,
        )?;
        if code != 0 {
            return Err(corrupt("working tree export failed"));
        }
        Ok(bytes)
    }
    pub(super) fn capture(
        &self,
        id: &str,
        argv: &[&str],
        limit: usize,
    ) -> Result<(Vec<u8>, i64), TaskError> {
        let exec = self.exec_create(
            id,
            &argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "65534:65534",
            "/",
        )?;
        let mut stream = self.start_exec(&exec)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut raw = [0; 16384];
        let mut frames = Frames::default();
        let mut bytes = Vec::new();
        loop {
            match stream.read(&mut raw) {
                Ok(0) => break,
                Ok(n) => frames.push(&raw[..n], |i, data| {
                    if i == 0 {
                        if data.len() > limit.saturating_sub(bytes.len()) {
                            return Err(corrupt("oversized adapter export"));
                        }
                        bytes.extend_from_slice(data);
                    }
                    Ok(())
                })?,
                Err(e) if timeout(&e) && Instant::now() < deadline => {}
                Err(e) => return Err(io_error(e)),
            }
            if Instant::now() >= deadline {
                return Err(unsupported("container helper timed out"));
            }
        }
        frames.complete()?;
        let state = self.exec_inspect(&exec)?;
        if state["Running"] != false {
            return Err(corrupt("helper process termination not confirmed"));
        }
        let code = state["ExitCode"]
            .as_i64()
            .ok_or_else(|| corrupt("helper exit unavailable"))?;
        Ok((bytes, code))
    }
    pub(super) fn quiesce(&self, id: &str) -> Result<(), TaskError> {
        // Linux kill(-1) in this private PID namespace excludes init and the
        // sender. All workload descendants retain the unprivileged UID.
        let _status = self.capture(id, &["/bin/kill", "-KILL", "-1"], 4096)?;
        for _ in 0..20 {
            let (bytes, code) = self.capture(id, &["/bin/ps", "-o", "pid,stat"], 16384)?;
            if code != 0 {
                return Err(unsupported("image cannot verify descendant quiescence"));
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| corrupt("invalid process inventory"))?;
            let mut live = Vec::new();
            for line in text.lines().skip(1) {
                let mut fields = line.split_whitespace();
                let pid = fields
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| corrupt("invalid namespace PID"))?;
                let state = fields
                    .next()
                    .ok_or_else(|| corrupt("invalid process state"))?;
                if !state.starts_with('Z') {
                    live.push(pid);
                }
            }
            if live.len() == 2 && live.contains(&1) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(corrupt(
            "live descendants remained before output collection",
        ))
    }
    pub(super) fn start_exec(&self, id: &str) -> Result<UnixStream, TaskError> {
        engine_id(id)?;
        let mut stream = self.connect(
            "POST",
            &format!("/exec/{id}/start"),
            &json!({"Detach":false,"Tty":false}),
        )?;
        let (status, _) = header(&mut stream)?;
        if status != 200 && status != 101 {
            return Err(unsupported(
                "Docker exec start not confirmed; reconcile required",
            ));
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(io_error)?;
        Ok(stream)
    }
    pub(super) fn exec_create(
        &self,
        container: &str,
        argv: &[String],
        user: &str,
        cwd: &str,
    ) -> Result<String, TaskError> {
        let value = self.request("POST", &format!("/containers/{container}/exec"), json!({"AttachStdout":true,"AttachStderr":true,"AttachStdin":false,"Tty":false,"Privileged":false,"User":user,"WorkingDir":cwd,"Cmd":argv}))?;
        let id = string(&value, "Id")?.to_owned();
        engine_id(&id)?;
        Ok(id)
    }
    pub(super) fn exec_inspect(&self, id: &str) -> Result<Json, TaskError> {
        self.request("GET", &format!("/exec/{id}/json"), Json::Null)
    }
    pub(super) fn inspect(&self, id: &str) -> Result<Json, TaskError> {
        self.request("GET", &format!("/containers/{id}/json"), Json::Null)
    }
    pub(super) fn operation(&self, id: &str, op: &str) -> Result<(), TaskError> {
        self.request("POST", &format!("/containers/{id}/{op}"), Json::Null)?;
        Ok(())
    }
    pub(super) fn helper(&self, id: &str, argv: &[&str]) -> Result<(), TaskError> {
        let (_, code) = self.capture(id, argv, 16384)?;
        if code != 0 {
            return Err(unsupported(
                "fixed image lacks working preparation utilities or input exceeds hard storage quota",
            ));
        }
        Ok(())
    }
    /// SIGKILL PID namespace init; Engine confirms namespace shutdown and reap.
    pub(super) fn stop(&self, id: &str) -> Result<(), TaskError> {
        let state = self.inspect(id)?;
        if state["State"]["Paused"] == true {
            self.operation(id, "unpause")?;
        }
        if self.inspect(id)?["State"]["Running"] == true {
            self.operation(id, "kill?signal=KILL")?;
        }
        let state = self.inspect(id)?;
        if state["State"]["Running"] != false
            || state["State"]["Pid"] != 0
            || state["State"]["Dead"] != false
        {
            return Err(corrupt("container subtree stop/reap was not confirmed"));
        }
        Ok(())
    }
}
pub(super) fn engine_id(id: &str) -> Result<(), TaskError> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(corrupt("invalid engine execution identity"));
    }
    Ok(())
}
pub(super) fn string<'a>(v: &'a Json, key: &str) -> Result<&'a str, TaskError> {
    v[key]
        .as_str()
        .ok_or_else(|| corrupt("missing Docker identity field"))
}
pub(super) fn timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}
fn header(stream: &mut impl Read) -> Result<(u16, Vec<String>), TaskError> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 32768 {
            return Err(corrupt("oversized Docker HTTP header"));
        }
        let mut one = [0];
        stream.read_exact(&mut one).map_err(io_error)?;
        bytes.push(one[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| corrupt("invalid Docker HTTP header"))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| corrupt("invalid Docker HTTP status"))?;
    Ok((
        status,
        lines.filter(|s| !s.is_empty()).map(str::to_owned).collect(),
    ))
}
fn body_bytes(
    stream: &mut impl Read,
    headers: &[String],
    limit: usize,
) -> Result<Vec<u8>, TaskError> {
    if headers
        .iter()
        .any(|s| s.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        let mut result = Vec::new();
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                if line.len() > 128 {
                    return Err(corrupt("invalid chunk header"));
                }
                let mut b = [0];
                stream.read_exact(&mut b).map_err(io_error)?;
                line.push(b[0]);
            }
            let text = std::str::from_utf8(&line).map_err(|_| corrupt("invalid chunk header"))?;
            let length = usize::from_str_radix(text.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| corrupt("invalid chunk size"))?;
            if length == 0 {
                break;
            }
            if length > limit.saturating_sub(result.len()) {
                return Err(corrupt("oversized Docker response"));
            }
            let old = result.len();
            result.resize(old + length, 0);
            stream.read_exact(&mut result[old..]).map_err(io_error)?;
            let mut end = [0; 2];
            stream.read_exact(&mut end).map_err(io_error)?;
            if end != *b"\r\n" {
                return Err(corrupt("invalid chunk terminator"));
            }
        }
        Ok(result)
    } else {
        let mut result = Vec::new();
        stream
            .take((limit + 1) as u64)
            .read_to_end(&mut result)
            .map_err(io_error)?;
        if result.len() > limit {
            return Err(corrupt("oversized Docker response"));
        }
        Ok(result)
    }
}
/// Non-TTY Engine framing; streams retain separate byte offsets.
#[derive(Default)]
pub(super) struct Frames {
    pending: Vec<u8>,
}
impl Frames {
    pub(super) fn push(
        &mut self,
        bytes: &[u8],
        mut emit: impl FnMut(usize, &[u8]) -> Result<(), TaskError>,
    ) -> Result<(), TaskError> {
        self.pending.extend_from_slice(bytes);
        let mut used = 0;
        while self.pending.len() - used >= 8 {
            let h = &self.pending[used..used + 8];
            if ![1, 2].contains(&h[0]) || h[1..4] != [0, 0, 0] {
                return Err(corrupt("invalid Docker stream frame"));
            }
            let n = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
            if n > 1024 * 1024 {
                return Err(corrupt("oversized Docker stream frame"));
            }
            if self.pending.len() - used < 8 + n {
                break;
            }
            emit((h[0] - 1) as usize, &self.pending[used + 8..used + 8 + n])?;
            used += 8 + n;
        }
        self.pending.drain(..used);
        Ok(())
    }
    pub(super) fn complete(&self) -> Result<(), TaskError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(corrupt("torn Docker stream frame"))
        }
    }
}
