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
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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
/// 单会话 stdout 累计读取上限：只限单帧大小不足以挡住"每帧都小但一直刷"的
/// server（提案 §14 要求 stdout/stderr 都有上限）。超限即停止读取并按崩溃处理。
const MAX_SESSION_STDOUT_BYTES: u64 = 256 * 1024 * 1024;

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
/// 一次入站读取的结果。"对端在帧边界上正常挂断"**不是一种失败**，所以它不能挤在 `Failure` 里
/// 冒充 `PROVIDER_CRASHED` —— 独立 Review 的 B1 就是这个混淆：客户端关掉 stdin 之后，
/// server 侧一切正常也会被报成 provider 崩溃。
pub enum FrameIn {
    Message(Value),
    /// 停在帧边界上的 EOF（本帧一个字节都没读到）。
    CleanEof,
    /// 半帧断开、超限、畸形 —— 只有这些才是失败。
    Failed(Failure),
}

/// `read_frame` 的实现体，多一个"帧边界 EOF"出口。
pub fn read_frame_result<R: BufRead>(reader: &mut R) -> FrameIn {
    let mut content_length: Option<usize> = None;
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let read = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(e) => {
                return FrameIn::Failed(protocol_failure(format!("header read failed: {e}")));
            }
        };
        if read == 0 {
            // header_bytes == 0 ⇒ 正好停在帧边界上 = 客户端正常挂断；
            // 否则是"头读到一半对端没了"，属畸形，必须与前者分开报告。
            return if header_bytes == 0 {
                FrameIn::CleanEof
            } else {
                FrameIn::Failed(protocol_failure("stream closed mid-headers".to_string()))
            };
        }
        header_bytes += read;
        if header_bytes > MAX_HEADER_BYTES {
            return FrameIn::Failed(protocol_failure("header exceeded 64KiB limit".to_string()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return FrameIn::Failed(protocol_failure(format!(
                "malformed header line: {trimmed}"
            )));
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            let parsed = value.trim().parse::<usize>();
            match parsed {
                Ok(v) => content_length = Some(v),
                Err(e) => {
                    return FrameIn::Failed(protocol_failure(format!("bad Content-Length: {e}")));
                }
            }
        }
    }
    let Some(len) = content_length else {
        return FrameIn::Failed(protocol_failure(
            "missing Content-Length header".to_string(),
        ));
    };
    if len > MAX_BODY_BYTES {
        return FrameIn::Failed(protocol_failure(format!(
            "body length {len} exceeded limit"
        )));
    }
    let mut buf = vec![0u8; len];
    if let Err(e) = reader.read_exact(&mut buf) {
        return FrameIn::Failed(protocol_failure(format!("body read failed: {e}")));
    }
    match serde_json::from_slice::<Value>(&buf) {
        Ok(v) => FrameIn::Message(v),
        Err(e) => FrameIn::Failed(protocol_failure(format!("body is not valid JSON-RPC: {e}"))),
    }
}

/// 客户端（LSP）侧的入口：**保持既有语义不变** —— 对 server 而言，管道在帧边界上关闭
/// 就是 server 死了，必须按 `PROVIDER_CRASHED` 处理，不能当"正常退出"。
/// 只有 MCP server 侧需要区分这两者，所以它直接用 `read_frame_result`。
pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Value, Failure> {
    match read_frame_result(reader) {
        FrameIn::Message(value) => Ok(value),
        FrameIn::Failed(failure) => Err(failure),
        FrameIn::CleanEof => Err(protocol_failure(
            "stream closed while reading headers".to_string(),
        )),
    }
}

/// stderr 有界缓冲。
#[derive(Default)]
struct StderrRing {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// 一次 LSP 会话：子进程 + 读线程 + 有界请求。
///
/// `child` / `stdin` 是抽象后的传输端点（`Option<Child>` + `Box<dyn Write>`）：
/// 生产路径由 `spawn()` 填入真实子进程，`#[cfg(test)] for_tests()` 可以喂内存缓冲，
/// 让"server 主动推写请求"这类对抗性路径有可重跑的 E2 覆盖（提案 §16.8）。
pub struct LspSession {
    child: Option<Child>,
    stdin: Box<dyn Write + Send>,
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
    /// 读线程是否因单会话 stdout 上限掐断：把"资源边界违规"与"进程普通退出"分开报。
    stdout_capped: Arc<AtomicBool>,
    /// 仅内存流测试会话为 true（此时 `child` 允许为 None）；生产会话恒 false。
    test_transport: bool,
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

/// 有界入队：满了就丢最旧的一条并计数（丢弃必须可见，不能静默）。
/// 单独成函数是为了能被单元测试直接打到上限 —— 生产路径要灌 257 条
/// `publishDiagnostics` 才能触发一次，测试里直接构造缓冲区更便宜也更确定。
fn push_notification(buffer: &mut NoteBuffer, message: Value) {
    if buffer.queue.len() >= NOTIFICATION_CAP {
        buffer.queue.pop_front();
        buffer.dropped += 1;
    }
    buffer.queue.push_back(message);
}

/// 单会话累计体积是否已越限。
fn session_over_limit(accumulated: u64, added: u64, cap: u64) -> bool {
    accumulated.saturating_add(added) > cap
}

/// 读线程主体：分流 response / notification / server→client 请求。
///
/// 单独成函数（而不是长在 `spawn` 的闭包里）是为了让**同一套分流逻辑**能被
/// `LspSession::for_tests` 的内存流复用——§16.8 要求验证"server 主动推
/// `workspace/applyEdit` 时客户端只拒绝、不落盘"，那只能用受控的假 server 做，
/// 而假 server 走的就是这条与真子进程完全相同的代码路径。
fn dispatch_stream<R: BufRead>(
    reader: &mut R,
    responses: &Sender<Value>,
    server_requests: &Sender<Value>,
    note_sink: &Arc<Mutex<NoteBuffer>>,
    stdout_capped: &Arc<AtomicBool>,
) {
    let mut session_bytes: u64 = 0;
    while let Ok(msg) = read_frame(reader) {
        let added = serde_json::to_string(&msg).map(|s| s.len()).unwrap_or(0) as u64;
        if session_over_limit(session_bytes, added, MAX_SESSION_STDOUT_BYTES) {
            // 超限：不再消费，并把"是上限掐断的"这件事记下来 —— 否则上层只能报
            // 泛化的"进程已退出"，把一个资源边界违规伪装成一次普通崩溃。
            stdout_capped.store(true, Ordering::Relaxed);
            break;
        }
        session_bytes = session_bytes.saturating_add(added);
        let has_method = msg.get("method").is_some();
        let has_id = msg.get("id").is_some();
        if has_method && !has_id {
            // notification：有界入队，溢出丢最旧的并计数（不阻塞读线程）。
            if let Ok(mut guard) = note_sink.lock() {
                push_notification(&mut guard, msg);
            }
            continue;
        }
        let target: Option<&Sender<Value>> = match (has_method, has_id) {
            (true, true) => Some(server_requests),
            (false, true) => Some(responses),
            _ => None,
        };
        if let Some(tx) = target {
            if tx.send(msg).is_err() {
                break;
            }
        }
    }
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
        let stdout_capped = Arc::new(AtomicBool::new(false));

        let reader = {
            let note_sink = Arc::clone(&notes);
            let capped = Arc::clone(&stdout_capped);
            std::thread::Builder::new()
                .name("nexus-code-intel-reader".to_string())
                .spawn(move || {
                    let mut br = BufReader::new(stdout);
                    dispatch_stream(&mut br, &rtx, &srx_tx, &note_sink, &capped);
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
            child: Some(child),
            stdin: Box::new(stdin),
            reader: Some(reader),
            responses: rrx,
            notifications: Arc::clone(&notes),
            server_requests: srx,
            stderr: ring,
            next_id: 0,
            refused_writes: 0,
            unhandled_requests: 0,
            stdout_capped,
            test_transport: false,
        })
    }

    /// 用内存流构造会话（仅测试）：让假 server 能走与真子进程相同的
    /// `dispatch_stream` 分流逻辑，从而对 §16.8（provider 无写能力）做对抗性覆盖。
    #[cfg(test)]
    fn for_tests(
        reader: std::io::BufReader<std::io::Cursor<Vec<u8>>>,
        writer: Box<dyn Write + Send>,
    ) -> LspSession {
        let (rtx, rrx) = mpsc::channel::<Value>();
        let (srx_tx, srx) = mpsc::channel::<Value>();
        let notes: Arc<Mutex<NoteBuffer>> = Arc::new(Mutex::new(NoteBuffer::default()));
        let stdout_capped = Arc::new(AtomicBool::new(false));
        let reader_handle = std::thread::spawn({
            let note_sink = Arc::clone(&notes);
            let capped = Arc::clone(&stdout_capped);
            move || {
                let mut br = reader;
                dispatch_stream(&mut br, &rtx, &srx_tx, &note_sink, &capped);
            }
        });
        LspSession {
            child: None,
            stdin: writer,
            reader: Some(reader_handle),
            responses: rrx,
            notifications: notes,
            server_requests: srx,
            stderr: Arc::new(Mutex::new(StderrRing::default())),
            next_id: 0,
            refused_writes: 0,
            unhandled_requests: 0,
            stdout_capped,
            test_transport: true,
        }
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
                        // 返回前先补一次分流：同一读线程保证 server 请求的入队早于
                        // 对应响应，所以此刻通道里可能有尚未应答的 server→client 请求。
                        // 不应答会让 language server 阻塞，也会让写拒绝计数在观测时失真。
                        self.pump_server_requests();
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
                    // 区分两种断开：被资源上限掐断 vs 进程自己退出。前者调大预算也没用，
                    // 后者才该走重启路径，混在一起会让 Retry/Abort 判断读到假原因。
                    let capped = self.stdout_capped.load(Ordering::Relaxed);
                    return Err(protocol_failure(if capped {
                        format!(
                            "provider stdout 累计超过 {}MiB 会话上限，读线程已停止（不是进程崩溃）",
                            MAX_SESSION_STDOUT_BYTES / (1024 * 1024)
                        )
                    } else {
                        "provider 进程已退出（读通道关闭）".to_string()
                    }));
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
    ///
    /// `child == None` 只可能来自内存流构造的测试会话（`test_transport = true`）。
    /// 生产会话若走到这条分支，按"已死"处理而**不是**返回保守 true：把"根本没有
    /// 子进程"说成"还活着"会让上层把就绪预算空转到超时（round 2 评审的 fail-slow 项）。
    pub fn is_alive(&mut self) -> bool {
        let Some(child) = &mut self.child else {
            return self.test_transport;
        };
        match child.try_wait() {
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
            // 无子进程（内存流构造）时没有可等待的对象，直接进入收尾让读线程退出。
            let exited = match &mut self.child {
                Some(child) => match child.try_wait() {
                    Ok(Some(_)) => true,
                    Ok(None) => false,
                    Err(_) => true,
                },
                None => true,
            };
            if exited {
                break;
            }
            if Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            if let Some(child) = &mut self.child {
                let _ = child.kill();
            }
            break;
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LspSession {
    fn drop(&mut self) {
        // Owner 语义：会话被丢弃（含 panic 路径）时保证子进程不遗留。
        if let Some(child) = &mut self.child {
            if let Ok(None) = child.try_wait() {
                let _ = child.kill();
            }
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
    use crate::code_intel::dto::ProviderMeta;
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

    /// 可回看的内存 sink：充当假 server 的 stdin，用于断言客户端**实际写出**的帧。
    #[derive(Default)]
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);

    impl Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self.0.lock() {
                Ok(mut guard) => {
                    guard.extend_from_slice(buf);
                    Ok(buf.len())
                }
                Err(_) => Err(std::io::Error::other("sink mutex poisoned")),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn drain_frames(bytes: Vec<u8>) -> Vec<Value> {
        let mut br = BufReader::new(Cursor::new(bytes));
        let mut out = Vec::new();
        while let Ok(msg) = read_frame(&mut br) {
            out.push(msg);
        }
        out
    }

    /// §16.8 的对抗性覆盖：**server 主动**推 `workspace/applyEdit`（带真实落盘意图）时，
    /// 客户端必须（1）应答它以免 server 阻塞，（2）回 `applied:false` 且不含任何编辑，
    /// （3）计入 `write_requests_refused`，（4）目标文件绝不出现。
    ///
    /// 走的是与真子进程完全相同的 `dispatch_stream` 分流 + `pump_server_requests`
    /// 应答路径，只是把两端换成内存缓冲——此前只有纯决策函数的单测，没有端到端证据。
    #[test]
    fn adversarial_server_pushed_apply_edit_is_refused_and_never_written() {
        let victim = std::env::temp_dir().join(format!(
            "nexus-code-intel-applyedit-{}.rs",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&victim);
        let victim_uri = path_to_uri(&victim);

        let server_stream: Vec<u8> = [
            encode_frame(&json!({
                "jsonrpc": "2.0",
                "id": 4242,
                "method": "workspace/applyEdit",
                "params": {
                    "label": "inject",
                    "edit": {"documentChanges": [{
                        "textDocument": {"uri": victim_uri, "version": 1},
                        "edits": [{
                            "range": {"start": {"line": 0, "character": 0},
                                      "end": {"line": 0, "character": 0}},
                            "newText": "// written by the provider\nfn injected() {}\n"
                        }]
                    }]}
                }
            })),
            encode_frame(&json!({"jsonrpc":"2.0","id":1,"result":[]})),
        ]
        .concat();

        let sink = RecordingSink::default();
        let recorded = Arc::clone(&sink.0);
        let mut session =
            LspSession::for_tests(BufReader::new(Cursor::new(server_stream)), Box::new(sink));

        let result = session
            .request(
                "textDocument/definition",
                json!({"textDocument":{"uri":victim_uri},"position":{"line":0,"character":0}}),
                Duration::from_secs(5),
            )
            .expect("假 server 的 definition 响应必须返回");
        assert_eq!(result, json!([]));
        assert_eq!(
            session.refused_writes, 1,
            "server 推来的 applyEdit 必须计入写拒绝"
        );
        assert_eq!(
            session.unhandled_requests, 0,
            "写拒绝与未识别请求必须分桶计数"
        );

        session.shutdown();

        let written = match recorded.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        };
        let frames = drain_frames(written);
        let refusal = frames
            .iter()
            .find(|f| f.get("id") == Some(&json!(4242)))
            .expect("必须应答 server 请求，否则 provider 会阻塞");
        assert_eq!(refusal["result"]["applied"], json!(false));
        assert!(
            refusal["result"].get("edit").is_none(),
            "回包不得携带任何编辑内容"
        );
        assert!(
            !victim.exists(),
            "provider 不得具备写业务代码的能力（§16.8）：{} 不应被创建",
            victim.display()
        );
        // 我们发出的请求帧里也不该出现任何写 method（白名单在出向侧同样生效）。
        assert!(
            frames
                .iter()
                .filter_map(|f| f.get("method").and_then(Value::as_str))
                .all(|m| READ_ONLY_METHODS.contains(&m)),
            "出向 method 必须全在白名单内：{frames:?}"
        );
    }

    /// notification 上限必须能在测试里被打到：生产路径要灌 257 条 publishDiagnostics
    /// 才会触发一次，直接构造缓冲区既便宜又确定。
    #[test]
    fn notification_buffer_overflow_is_bounded_and_counted() {
        let mut buffer = NoteBuffer::default();
        for i in 0..(NOTIFICATION_CAP + 3) {
            push_notification(&mut buffer, json!({"i": i}));
        }
        assert_eq!(buffer.queue.len(), NOTIFICATION_CAP, "队列不得越过上限");
        assert_eq!(buffer.dropped, 3, "丢弃必须计数，不能静默");
        assert_eq!(
            buffer
                .queue
                .front()
                .and_then(|v| v.get("i"))
                .and_then(Value::as_i64),
            Some(3),
            "溢出丢最旧的，队首应是被挤掉 3 条之后的那一条"
        );
    }

    /// round 3 待办 6：溢出计数不能只在缓冲区单元测试里成立。这里灌一条**真实的**
    /// server 输出流（`NOTIFICATION_CAP + 5` 条 publishDiagnostics 后跟一个响应），
    /// 走 `dispatch_stream` 的分流路径，确认丢弃数被记进会话，并且能被
    /// `ProviderMeta::absorb` 带到 envelope 的 `provider.dropped_notifications` 上
    /// ——那才是 Agent 看得见的地方。
    #[test]
    fn overflowing_server_notifications_are_counted_through_the_read_path() {
        let overflow = 5usize;
        let mut server_stream = Vec::new();
        for i in 0..(NOTIFICATION_CAP + overflow) {
            server_stream.extend(encode_frame(&json!({
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": "file:///x.rs", "diagnostics": []},
                "seq": i
            })));
        }
        server_stream.extend(encode_frame(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": []
        })));

        let mut session = LspSession::for_tests(
            BufReader::new(Cursor::new(server_stream)),
            Box::new(RecordingSink::default()),
        );
        let result = session
            .request(
                "textDocument/definition",
                json!({"textDocument":{"uri":"file:///x.rs"},"position":{"line":0,"character":0}}),
                Duration::from_secs(5),
            )
            .expect("响应必须在溢出之后仍然返回");
        assert_eq!(result, json!([]), "溢出不得影响响应本身");
        assert_eq!(
            session.dropped_notifications(),
            overflow,
            "读线程分流出来的丢弃数必须入账"
        );

        // 入账之后还要"看得见"：absorb 进 provider 元数据并出现在序列化字段里。
        let mut meta = ProviderMeta::default();
        meta.absorb(
            session.refused_writes,
            session.unhandled_requests,
            session.dropped_notifications(),
        );
        assert_eq!(
            meta.to_json()["dropped_notifications"],
            json!(overflow),
            "丢弃必须出现在 envelope 的 provider 字段里，不能只活在内存中"
        );
        assert_eq!(
            meta.to_json()["write_requests_refused"],
            json!(0),
            "三条计数不得互相污染：{meta:?}"
        );
        session.shutdown();
    }

    #[test]
    fn session_byte_cap_boundaries() {
        assert!(!session_over_limit(0, 1, 10));
        assert!(!session_over_limit(10, 0, 10));
        assert!(!session_over_limit(6, 4, 10), "正好等于上限不算越限");
        assert!(session_over_limit(6, 5, 10));
        // saturating 累加：反复相加不会绕回小数从而放过恶意流量。
        assert!(session_over_limit(u64::MAX, 5, 10));
    }

    /// 内存流会话（`test_transport = true`）没有子进程，`is_alive` 才允许报存活；
    /// 生产会话的 `child` 恒为 `Some`，因此"没有进程"不会被说成"还活着"。
    #[test]
    fn test_transport_session_reports_alive_by_definition() {
        let mut session = LspSession::for_tests(
            BufReader::new(Cursor::new(Vec::new())),
            Box::new(RecordingSink::default()),
        );
        assert!(session.is_alive());
        assert!(session.test_transport);
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
