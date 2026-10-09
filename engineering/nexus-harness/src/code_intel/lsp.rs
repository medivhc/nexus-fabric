//! 手写 JSON-RPC 2.0 / LSP stdio 客户端（零新依赖）。
//!
//! 为什么不用第三方 LSP crate：`engineering/nexus-harness/Cargo.toml` 的依赖面
//! 是契约的一部分（MODULE.md Allowed Dependencies 只允许 `serde_json` + `toml`）；
//! 引入 `lsp-types`/`tower` 属 `dependency` 任务类型，需六项评审。这里只用 std +
//! `serde_json`，代价是需要自己实现 framing 与有界等待。
//!
//! 安全边界（提案 §14 / MODULE.md 只读不变量）：
//! - 只有白名单方法可以发出（`assert_read_only`）；
//! - server→client 的写请求（`workspace/applyEdit` 等）一律拒绝执行，只回
//!   `{"applied": false}` 并计数；
//! - 子进程 command/args 全部由实现固定，绝不经 shell，`--provider-binary`
//!   只作为单个可执行文件路径传入；
//! - stdout/stderr 都有大小上限；每请求有超时与 `$/cancelRequest`。

use crate::code_intel::dto::{CodeIntelError, Failure};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// 帧头大小上限（防御恶意/异常 server）。
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// 单帧 body 上限。
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// stderr 环形缓冲上限（提案 §14：输出有大小上限）。
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// 只读方法白名单（MODULE.md 冻结）。写能力 method 永不出现于此。
pub const READ_ONLY_METHODS: &[&str] = &[
    "initialize",
    "initialized",
    "shutdown",
    "exit",
    "textDocument/didOpen",
    "textDocument/didClose",
    "textDocument/documentSymbol",
    "workspace/symbol",
    "textDocument/hover",
    "textDocument/definition",
    "textDocument/typeDefinition",
    "textDocument/implementation",
    "textDocument/references",
    "textDocument/prepareCallHierarchy",
    "callHierarchy/incomingCalls",
    "callHierarchy/outgoingCalls",
    "textDocument/diagnostic",
    "$/cancelRequest",
];

/// 拒绝非只读 method。
pub fn assert_read_only(method: &str) -> Result<(), Failure> {
    if READ_ONLY_METHODS.contains(&method) {
        Ok(())
    } else {
        Err(CodeIntelError::Unsupported.with_reason(format!(
            "method {method} 不在 Code Intelligence 只读白名单内（provider 无写能力）"
        )))
    }
}

/// server→client 请求的归类（决定计数进哪个信号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRequest {
    /// 写能力请求：拒绝执行。
    WriteRefused,
    /// 只读流程需要的良性应答（进度创建、配置读取、能力注册）。
    Benign,
    /// 未识别请求：回 `null` 避免 server 阻塞，但**不**计入写拒绝。
    Unhandled,
}

/// 对 server→client 请求的纯决策函数（拆出来才能被单元测试覆盖）。
pub fn server_request_decision(method: &str, configuration_items: usize) -> (Value, ServerRequest) {
    match method {
        "workspace/applyEdit" | "workspace/executeCommand" => (
            json!({"applied": false, "refused": "read-only code intelligence provider"}),
            ServerRequest::WriteRefused,
        ),
        "window/workDoneProgress/create"
        | "client/registerCapability"
        | "workspace/codeLens/refresh" => (Value::Null, ServerRequest::Benign),
        "workspace/configuration" => (
            Value::Array(vec![Value::Null; configuration_items]),
            ServerRequest::Benign,
        ),
        _ => (Value::Null, ServerRequest::Unhandled),
    }
}

/// 协议层失败（framing/EOF/畸形响应）统一记为 PROVIDER_CRASHED。
fn protocol_failure(reason: String) -> Failure {
    CodeIntelError::ProviderCrashed.with_reason(reason)
}

/// 编码一帧：`Content-Length` + `Content-Type` 头 + JSON body。
pub fn encode_frame(message: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(message).unwrap_or_else(|_| b"{}".to_vec());
    let mut out = Vec::with_capacity(body.len() + 96);
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&body);
    out
}

/// 读一帧。header 大小与 body 长度都有硬上限。
pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Value, Failure> {
    let mut content_length: Option<usize> = None;
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| protocol_failure(format!("header read failed: {e}")))?;
        if read == 0 {
            return Err(protocol_failure(
                "stream closed while reading headers".to_string(),
            ));
        }
        header_bytes += read;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(protocol_failure("header exceeded 64KiB limit".to_string()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(protocol_failure(format!(
                "malformed header line: {trimmed}"
            )));
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| protocol_failure(format!("bad Content-Length: {e}")))?,
            );
        }
    }
    let len = content_length
        .ok_or_else(|| protocol_failure("missing Content-Length header".to_string()))?;
    if len > MAX_BODY_BYTES {
        return Err(protocol_failure(format!(
            "body length {len} exceeded limit"
        )));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| protocol_failure(format!("body read failed: {e}")))?;
    serde_json::from_slice::<Value>(&buf)
        .map_err(|e| protocol_failure(format!("body is not valid JSON-RPC: {e}")))
}

/// stderr 有界缓冲。
#[derive(Default)]
struct StderrRing {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// 一次 LSP 会话：子进程 + 读线程 + 有界请求。
pub struct LspSession {
    child: Child,
    stdin: ChildStdin,
    reader: Option<JoinHandle<()>>,
    responses: Receiver<Value>,
    /// 有界 notification 缓冲（读线程只入队，绝不无上限堆积）。
    notifications: Arc<Mutex<NoteBuffer>>,
    server_requests: Receiver<Value>,
    stderr: Arc<Mutex<StderrRing>>,
    next_id: i64,
    /// 被拒绝执行的**写能力**请求计数（applyEdit / executeCommand）。
    pub refused_writes: usize,
    /// 未识别的 server→client 请求计数；与写能力分开，否则正常只读查询
    /// 也会让 refused 恒为非 0，只读信号失真。
    pub unhandled_requests: usize,
}

/// notification 缓冲上限：读线程不能无上限堆积（RA 索引期会刷屏
/// publishDiagnostics），也不能反过来阻塞读线程（会让 server 卡在写 stdout）。
const NOTIFICATION_CAP: usize = 256;

/// 一条 notification + 是否因超容被丢弃过。
#[derive(Default)]
struct NoteBuffer {
    queue: std::collections::VecDeque<Value>,
    dropped: usize,
}

impl LspSession {
    /// 启动 language server（不经 shell；cwd 限制在 workspace 根内）。
    ///
    /// `extra_env` 用于把 server 的构建副作用（flycheck 产物）引导到仓库外，
    /// 见 `RustAnalyzerProvider::connect`。
    pub fn spawn(
        binary: &Path,
        cwd: &Path,
        extra_env: &[(&str, &str)],
    ) -> Result<LspSession, Failure> {
        let mut command = Command::new(binary);
        command
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|e| {
            CodeIntelError::ProviderUnavailable.with_reason(format!(
                "cannot spawn language server {}: {e}",
                binary.display()
            ))
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| protocol_failure("provider stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| protocol_failure("provider stdout unavailable".to_string()))?;
        let stderr_raw = child
            .stderr
            .take()
            .ok_or_else(|| protocol_failure("provider stderr unavailable".to_string()))?;

        let (rtx, rrx) = mpsc::channel::<Value>();
        let notes: Arc<Mutex<NoteBuffer>> = Arc::new(Mutex::new(NoteBuffer::default()));
        let (srx_tx, srx) = mpsc::channel::<Value>();
        let ring = Arc::new(Mutex::new(StderrRing::default()));

        let reader = {
            let note_sink = Arc::clone(&notes);
            std::thread::Builder::new()
                .name("nexus-code-intel-reader".to_string())
                .spawn(move || {
                    // 读线程只做分流：response / notification / server request。
                    let mut br = BufReader::new(stdout);
                    while let Ok(msg) = read_frame(&mut br) {
                        let has_method = msg.get("method").is_some();
                        let has_id = msg.get("id").is_some();
                        if has_method && !has_id {
                            // notification：有界入队，溢出丢最旧的并计数（不阻塞读线程）。
                            if let Ok(mut guard) = note_sink.lock() {
                                if guard.queue.len() >= NOTIFICATION_CAP {
                                    guard.queue.pop_front();
                                    guard.dropped += 1;
                                }
                                guard.queue.push_back(msg);
                            }
                            continue;
                        }
                        let target: Option<&Sender<Value>> = match (has_method, has_id) {
                            (true, true) => Some(&srx_tx),
                            (false, true) => Some(&rtx),
                            _ => None,
                        };
                        if let Some(tx) = target {
                            if tx.send(msg).is_err() {
                                break;
                            }
                        }
                    }
                })
                .map_err(|e| protocol_failure(format!("reader thread spawn failed: {e}")))?
        };

        let stderr_ring = Arc::clone(&ring);
        std::thread::Builder::new()
            .name("nexus-code-intel-stderr".to_string())
            .spawn(move || {
                let mut br = BufReader::new(stderr_raw);
                let mut buf = [0u8; 4096];
                loop {
                    match br.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut guard = match stderr_ring.lock() {
                                Ok(g) => g,
                                Err(_) => break,
                            };
                            let free = MAX_STDERR_BYTES.saturating_sub(guard.bytes.len());
                            let take = free.min(n);
                            guard.bytes.extend_from_slice(&buf[..take]);
                            if take < n {
                                guard.overflowed = true;
                            }
                        }
                    }
                }
            })
            .map_err(|e| protocol_failure(format!("stderr thread spawn failed: {e}")))?;

        Ok(LspSession {
            child,
            stdin,
            reader: Some(reader),
            responses: rrx,
            notifications: Arc::clone(&notes),
            server_requests: srx,
            stderr: ring,
            next_id: 0,
            refused_writes: 0,
            unhandled_requests: 0,
        })
    }

    /// 写一帧并 flush。
    fn write_message(&mut self, message: &Value) -> Result<(), Failure> {
        let frame = encode_frame(message);
        self.stdin
            .write_all(&frame)
            .and_then(|()| self.stdin.flush())
            .map_err(|e| CodeIntelError::ProviderCrashed.with_reason(format!("write failed: {e}")))
    }

    /// 只读请求：白名单校验 + 有界等待 + 超时取消。
    pub fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, Failure> {
        assert_read_only(method)?;
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        self.write_message(&envelope)?;

        let deadline = Instant::now() + timeout;
        loop {
            self.pump_server_requests();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = self.write_message(
                    &json!({"jsonrpc":"2.0","method":"$/cancelRequest","params":{"id":id}}),
                );
                return Err(CodeIntelError::Timeout.with_reason(format!(
                    "{method} 在 {}s 内未响应，已发送 $/cancelRequest",
                    timeout.as_secs()
                )));
            }
            match self.responses.recv_timeout(remaining) {
                Ok(msg) => {
                    if msg.get("id").and_then(Value::as_i64) == Some(id) {
                        if let Some(err) = msg.get("error") {
                            // -32601 MethodNotFound 是能力缺失，不是进程故障：
                            // 上层据此决定回退路径，绝不能和 crash 混为一谈。
                            if err.pointer("/code").and_then(Value::as_i64) == Some(-32601) {
                                return Err(CodeIntelError::Unsupported.with_reason(format!(
                                    "{method} 不被该 language server 支持: {err}"
                                )));
                            }
                            return Err(protocol_failure(format!(
                                "{method} returned JSON-RPC error: {err}"
                            )));
                        }
                        return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                    }
                    // 其它 id 的迟到响应：丢弃（我们一次只挂起一个请求）。
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(protocol_failure(
                        "provider 进程已退出（读通道关闭）".to_string(),
                    ));
                }
            }
        }
    }

    /// 只读通知。
    pub fn notify(&mut self, method: &str, params: Value) -> Result<(), Failure> {
        assert_read_only(method)?;
        self.write_message(&json!({"jsonrpc":"2.0","method":method,"params":params}))
    }

    /// 非阻塞取一条 notification（供 provider 做就绪判定）。
    pub fn try_notification(&mut self) -> Option<Value> {
        let mut guard = self.notifications.lock().ok()?;
        guard.queue.pop_front()
    }

    /// 因超出 `NOTIFICATION_CAP` 被丢弃的 notification 数（可观测性：
    /// 丢弃必须可见，不能静默）。
    pub fn dropped_notifications(&self) -> usize {
        self.notifications.lock().map_or(0, |g| g.dropped)
    }

    /// server→client 请求必须由客户端应答，否则 provider 会阻塞。
    /// 计数分两类：写能力拒绝 vs 未识别请求（见 `server_request_decision`）。
    fn pump_server_requests(&mut self) {
        while let Ok(req) = self.server_requests.try_recv() {
            let Some(id) = req.get("id").cloned() else {
                continue;
            };
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let items = req
                .pointer("/params/items")
                .and_then(Value::as_array)
                .map_or(0, |a| a.len());
            let (result, kind) = server_request_decision(method, items);
            match kind {
                ServerRequest::WriteRefused => self.refused_writes += 1,
                ServerRequest::Unhandled => self.unhandled_requests += 1,
                ServerRequest::Benign => {}
            }
            let _ = self.write_message(&json!({"jsonrpc":"2.0","id":id,"result":result}));
        }
    }

    /// provider 进程是否还活着（`try_wait` 不阻塞）。
    pub fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(_) => false,
        }
    }

    pub fn stderr_tail(&self, max: usize) -> String {
        let guard = match self.stderr.lock() {
            Ok(g) => g,
            Err(_) => return "<stderr lock poisoned>".to_string(),
        };
        let text = String::from_utf8_lossy(&guard.bytes).to_string();
        let tail = if text.len() > max {
            text[text.len() - max..].to_string()
        } else {
            text
        };
        if guard.overflowed {
            format!("{tail}…(stderr 超过 {MAX_STDERR_BYTES}B 上限，已截断)")
        } else {
            tail
        }
    }

    /// 有序关闭：shutdown 请求 -> exit 通知 -> 有限等待 -> kill。
    pub fn shutdown(mut self) {
        let _ = self.request("shutdown", Value::Null, Duration::from_secs(5));
        let _ = self.notify("exit", Value::Null);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    break;
                }
                Err(_) => break,
            }
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LspSession {
    fn drop(&mut self) {
        // Owner 语义：会话被丢弃（含 panic 路径）时保证子进程不遗留。
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
    }
}

/// `file://` URI <-> 本地路径（最小实现：覆盖盘符、`/`、百分号转义）。
///
/// Windows：`d:/x y` -> `file:///d:/x%20y`；Unix：`/work/x` -> `file:///work/x`。
/// 只转义会破坏 URI 解析的字符（`%`、空格、`#`、`?`），不做完整 RFC 3986 编码。
pub fn path_to_uri(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let with_slash_prefix = if normalized.starts_with('/') {
        normalized
    } else {
        format!("/{normalized}")
    };
    let escaped = with_slash_prefix
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('?', "%3f");
    format!("file://{escaped}")
}

pub fn uri_to_path(uri: &str) -> String {
    let stripped = uri
        .strip_prefix("file://")
        .or_else(|| uri.strip_prefix("file:"))
        .unwrap_or(uri);
    let decoded = percent_decode(stripped);
    let bytes = decoded.as_bytes();
    // `file:///d:/x` 解码后是 `/d:/x`：去掉 Windows 路径前导斜杠。
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
        return decoded[1..].to_string();
    }
    decoded
}

/// 仅解码 %XX（用于把 provider 返回的 URI 还原成本地路径）。
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn whitelist_rejects_write_methods() {
        for m in [
            "textDocument/rename",
            "workspace/applyEdit",
            "workspace/executeCommand",
            "textDocument/formatting",
            "textDocument/willSaveWaitUntil",
            "textDocument/codeAction",
        ] {
            let err = assert_read_only(m).expect_err("{m} 必须被拒绝");
            assert_eq!(err.code, CodeIntelError::Unsupported);
            assert_eq!(err.code.verdict(), "BLOCKED");
        }
        for m in [
            "workspace/symbol",
            "textDocument/references",
            "textDocument/definition",
            "textDocument/implementation",
            "textDocument/prepareCallHierarchy",
            "callHierarchy/incomingCalls",
            "callHierarchy/outgoingCalls",
            "textDocument/hover",
            "textDocument/diagnostic",
            "textDocument/didOpen",
            "initialized",
            "$/cancelRequest",
        ] {
            assert!(assert_read_only(m).is_ok(), "{m} 应在白名单内");
        }
        // 非协议 / 自造 method 同样被拒（白名单是穷举允许，不是黑名单排除）。
        assert!(assert_read_only("textDefinition").is_err());
        assert!(assert_read_only("rust-analyzer/reloadWorkspace").is_err());
    }

    #[test]
    fn server_requests_that_would_mutate_are_refused_and_counted_separately() {
        // §16.8 的 server→client 侧防线：applyEdit / executeCommand 必须被拒绝执行。
        for m in ["workspace/applyEdit", "workspace/executeCommand"] {
            let (result, kind) = super::server_request_decision(m, 0);
            assert_eq!(kind, super::ServerRequest::WriteRefused, "{m}");
            assert_eq!(result["applied"], json!(false), "{m} 必须回 applied:false");
            assert!(result.get("edit").is_none(), "{m} 的回包不能带任何编辑内容");
        }
        // 良性应答不计入写拒绝（否则只读查询的 refused 信号恒非 0）。
        for m in [
            "window/workDoneProgress/create",
            "client/registerCapability",
            "workspace/codeLens/refresh",
        ] {
            let (result, kind) = super::server_request_decision(m, 0);
            assert_eq!(kind, super::ServerRequest::Benign, "{m}");
            assert_eq!(result, Value::Null, "{m}");
        }
        let (config, kind) = super::server_request_decision("workspace/configuration", 3);
        assert_eq!(kind, super::ServerRequest::Benign);
        assert_eq!(config, json!([null, null, null]));
        // 未识别请求（如 showMessageRequest）走 Unhandled，不污染写拒绝计数。
        let (result, kind) = super::server_request_decision("window/showMessageRequest", 0);
        assert_eq!(kind, super::ServerRequest::Unhandled);
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn frame_roundtrip_is_exact() {
        let msg =
            json!({"jsonrpc":"2.0","id":7,"method":"workspace/symbol","params":{"query":"Egress"}});
        let bytes = encode_frame(&msg);
        let text = String::from_utf8(bytes.clone()).expect("frame is utf8");
        assert!(text.starts_with("Content-Length: "));
        assert!(text.contains("\r\n\r\n"));
        let mut cursor = BufReader::new(Cursor::new(bytes));
        let back = read_frame(&mut cursor).expect("frame decodes");
        assert_eq!(back, msg);
    }

    #[test]
    fn read_frame_rejects_missing_content_length() {
        let raw = b"Content-Type: application/vscode-jsonrpc\r\n\r\n{}";
        let mut cursor = BufReader::new(Cursor::new(raw.to_vec()));
        let err = read_frame(&mut cursor).expect_err("missing Content-Length must fail");
        assert_eq!(err.code, CodeIntelError::ProviderCrashed);
        assert!(err.reason.contains("missing Content-Length"));
    }

    #[test]
    fn read_frame_reports_eof_instead_of_hanging() {
        let mut cursor = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let err = read_frame(&mut cursor).expect_err("empty stream must fail");
        assert!(err.reason.contains("stream closed"));
    }

    #[test]
    fn read_frame_is_case_insensitive_on_header_name() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":null}"#;
        let raw =
            format!("content-Length: {}\r\n\r\n", body.len()) + std::str::from_utf8(body).unwrap();
        let mut cursor = BufReader::new(Cursor::new(raw.into_bytes()));
        let msg = read_frame(&mut cursor).expect("lower-case header accepted");
        assert_eq!(msg["id"], json!(1));
    }

    #[test]
    fn uri_roundtrip_handles_windows_drive_and_spaces() {
        let uri = path_to_uri(Path::new("d:/next/nexus fab#1/src/lib.rs"));
        assert!(uri.starts_with("file:///d:/next/nexus%20fab%231/"));
        let back = uri_to_path(&uri);
        assert_eq!(back, "d:/next/nexus fab#1/src/lib.rs");
    }

    #[test]
    fn uri_roundtrip_handles_unix_path() {
        let uri = path_to_uri(Path::new("/work/nexus-dev/nexus/src/lib.rs"));
        assert_eq!(uri, "file:///work/nexus-dev/nexus/src/lib.rs");
        assert_eq!(uri_to_path(&uri), "/work/nexus-dev/nexus/src/lib.rs");
    }
}
