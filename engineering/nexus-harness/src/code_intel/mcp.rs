//! MCP 薄适配层（提案 §10 / §15 Phase 3）。
//!
//! ```text
//! Agent ──MCP(stdio JSON-RPC)──▶ mcp serve ──▶ code_intel::run ──▶ rust-analyzer
//! ```
//!
//! 这里刻意**只做 transport**：工具集合就是 `code <verb>` 的 8 个只读能力，返回内容就是
//! 那套语言中立 envelope（含 `authority = "advisory"`、`snapshot` 绑定、10 个冻结错误码）。
//! 不在 MCP 侧新造 schema、不新造错误码、也不给任何写能力开门（提案 §3 的
//! `Agent Contract != LSP Contract`、§6 的"不得把任意 shell 参数透传给 launcher"）。
//!
//! 分帧复用 `super::lsp::{encode_frame, read_frame_result}` —— MCP stdio 与 LSP 用的是同一套
//! `Content-Length` 帧格式，而那两个函数已经带着 header/body 上限与结构化失败原因。
//! 复制一份编解码器等于复制一份安全边界，这类东西迟早漂移（round 2 的 `..` 绕过就是教训）。
//!
//! 入站读用 `read_frame_result`（区分"客户端在帧边界正常挂断"与"畸形/超限帧"），
//! provider 侧仍用 `read_frame`：那边的 EOF 真的是崩溃，两种语义不能混（round 1 的 B1）。
//!
//! **stdout 只承载 MCP 帧**：进程退出时的 CLI envelope 由 `main` 打到 stderr，
//! 否则裸 JSON 混进协议通道，严格客户端会把会话结尾读成畸形帧（round 2 的 N5）。

use super::ProviderSession;
use super::lsp::{FrameIn, encode_frame, read_frame_result};
use serde_json::{Value, json};
use std::io::{BufReader, Write};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

type Outcome = (String, String, Vec<(String, Value)>);

/// MCP 协议版本：本适配层按这一版实现握手字段。
pub const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "nexus-harness";

/// 工具白名单：**只有这 8 个**，与 CLI 一一对应。
const TOOLS: [&str; 8] = [
    "code.symbol",
    "code.definition",
    "code.references",
    "code.implementations",
    "code.callers",
    "code.callees",
    "code.hover",
    "code.diagnostics",
];

/// 明确列出的**禁止**工具名。`tools/list` 里不该出现它们（由 `write_tools_exposed` 断言），
/// 而按名请求它们时必须被拒（由 `write_call_rejected` 断言）。
/// 这条负向清单存在的意义是：将来有人往 TOOLS 里加了写能力，场景会立刻变红。
const FORBIDDEN_TOOLS: [&str; 6] = [
    "code.rename",
    "code.format",
    "code.edit",
    "workspace/applyEdit",
    "workspace/executeCommand",
    "textDocument/rename",
];

/// tools/call 允许的 argument 键。**不接受** `provider_binary`：
/// 那是启动期参数，放进 tool 参数就等于让模型给 language server launcher 注入 argv。
const ALLOWED_ARGS: [&str; 7] = [
    "target",
    "workspace",
    "max_results",
    "max_snippet_lines",
    "max_result_bytes",
    "timeout_secs",
    "ready_timeout_secs",
];

/// selftest 里真实查询用的作用域：夹具是独立 cargo workspace root（3 个源文件），
/// 因此冷启动面确定。换成仓库根会让这条 E4 变成网速竞赛。
const SELFTEST_WORKSPACE: &str = "engineering/nexus-harness/fixtures/code-intel";

/// JSON-RPC 错误码（协议层的，不是 Nexus 的错误码）。
const ERR_INVALID_REQUEST: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INVALID_PARAMS: i64 = -32602;

fn tool_descriptions(name: &str) -> &'static str {
    match name {
        "code.symbol" => "按名字在工作区内找符号定义位置",
        "code.definition" => "给定位置的符号定义",
        "code.references" => "给定位置符号的引用",
        "code.implementations" => "trait/抽象的成员实现",
        "code.callers" => "调用层次一层入边",
        "code.callees" => "调用层次一层出边",
        "code.hover" => "类型与文档提示",
        "code.diagnostics" => "结构化诊断（advisory，不拥有 correctness）",
        _ => "未知工具",
    }
}

/// 构造 `tools/list` 的 result。位置型 verb 需要 `file:line:col`。
fn tools_list_payload() -> Value {
    json!({
        "tools": TOOLS.iter().map(|name| json!({
            "name": name,
            "description": tool_descriptions(name),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "workspace": {"type": "string"},
                    "max_results": {"type": "integer"},
                    "max_snippet_lines": {"type": "integer"},
                    "max_result_bytes": {"type": "integer"},
                    "timeout_secs": {"type": "integer"},
                    "ready_timeout_secs": {"type": "integer"},
                },
                "required": ["target", "workspace"],
            },
        })).collect::<Vec<Value>>(),
    })
}

fn error_object(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn result_object(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// 把 CLI 的 `Outcome` 变成 Nexus envelope 对象（与 `--json` 输出同构）。
fn envelope_object(command: &str, outcome: &Outcome) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("schema_version".to_string(), json!(1));
    obj.insert("command".to_string(), json!(command));
    obj.insert("verdict".to_string(), json!(&outcome.0));
    obj.insert("message".to_string(), json!(&outcome.1));
    for (k, v) in &outcome.2 {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj)
}

/// `tools/call` 的参数校验 + argv 合成。返回 `Err((code, message))` 时调用方回 JSON-RPC error。
fn build_argv(name: &str, arguments: Option<&Value>) -> Result<Vec<String>, (i64, String)> {
    if !TOOLS.contains(&name) {
        // 明确拒绝，而不是"当作未知符号查一次"。白名单判定必须在 `strip_prefix` 之前：
        // `workspace/applyEdit` 这类名字压根不带 `code.` 前缀，先 strip 会让它落进
        // "未知工具"分支，把一个**越权**请求说成"你没这个名字"——客户端于是可以
        // 换个拼法重试，而契约要的是"这类能力本适配器永久不提供"。
        let hint = if FORBIDDEN_TOOLS.contains(&name) {
            "是写能力工具，本适配器永久不暴露"
        } else {
            "不是只读查询工具"
        };
        // 消息首词固定为 `UNSUPPORTED`（Nexus 冻结错误码字面量）+ `-32602`：
        // 两者一起构成"撞了白名单"的可断言形态，客户端不必匹配自然语言全文。
        return Err((
            ERR_INVALID_PARAMS,
            format!(
                "UNSUPPORTED: {name} {hint}；本适配器只暴露 {} 个只读 verb",
                TOOLS.len()
            ),
        ));
    }
    // TOOLS 里的名字必然带 `code.` 前缀；到不了这条分支说明白名单被改坏了，仍然显式拒。
    let verb = match name.strip_prefix("code.") {
        Some(verb) => verb,
        None => {
            return Err((
                ERR_INVALID_PARAMS,
                format!("UNSUPPORTED: {name} 不符合 code.* 命名约定"),
            ));
        }
    };
    let Some(args) = arguments else {
        return Err((ERR_INVALID_PARAMS, "tools/call 缺少 arguments".to_string()));
    };
    let map = args
        .as_object()
        .ok_or((ERR_INVALID_PARAMS, "arguments 必须是对象".to_string()))?;
    for key in map.keys() {
        if !ALLOWED_ARGS.contains(&key.as_str()) {
            // 未知键**报错而不是忽略**：忽略会让拼错的预算参数静默失效。
            return Err((
                ERR_INVALID_PARAMS,
                format!(
                    "不支持的 argument：{key}（可用键：{}）",
                    ALLOWED_ARGS.join(", ")
                ),
            ));
        }
    }
    let target = map
        .get("target")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or((ERR_INVALID_PARAMS, "缺少 argument：target".to_string()))?
        .to_string();
    let mut argv: Vec<String> = vec![verb.to_string(), target];
    // workspace 必须是字符串。
    if let Some(v) = map.get("workspace") {
        let text = v.as_str().filter(|s| !s.is_empty()).ok_or((
            ERR_INVALID_PARAMS,
            "argument：workspace 必须是非空字符串".to_string(),
        ))?;
        argv.push("--workspace".to_string());
        argv.push(text.to_string());
    }
    // 预算/超时类参数必须是**数字**，不接受字符串：一是 schema 声明的就是 integer，
    // 二是把任意字符串原样转成 argv 会把校验责任推到下游 argv 解析上，
    // 边界上看得见的问题不该留给后面猜。
    for (flag, key) in [
        ("--max-results", "max_results"),
        ("--max-snippet-lines", "max_snippet_lines"),
        ("--max-result-bytes", "max_result_bytes"),
        ("--timeout-secs", "timeout_secs"),
        ("--ready-timeout-secs", "ready_timeout_secs"),
    ] {
        if let Some(v) = map.get(key) {
            let n = v.as_u64().ok_or((
                ERR_INVALID_PARAMS,
                format!("argument：{key} 必须是非负整数，实得 {v}"),
            ))?;
            argv.push(flag.to_string());
            argv.push(n.to_string());
        }
    }
    Ok(argv)
}

/// 单条请求 → 响应。`None` 表示这是 notification（不回复）。
fn handle_request(
    message: &Value,
    session: &mut Option<ProviderSession>,
    provider_override: &Option<String>,
) -> Option<Value> {
    let method = message.get("method").and_then(Value::as_str)?;
    // notification（无 id）只接受并忽略；带 id 的才需要回复。
    let id = message.get("id").cloned()?;
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(error_object(
            id,
            ERR_INVALID_REQUEST,
            "缺少或错误的 jsonrpc 版本",
        ));
    }
    match method {
        "initialize" => Some(result_object(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
            }),
        )),
        "ping" => Some(result_object(id, json!({}))),
        "tools/list" => Some(result_object(id, tools_list_payload())),
        "shutdown" => Some(result_object(id, json!({}))),
        "tools/call" => {
            let params = message.get("params");
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            match build_argv(name, params.and_then(|p| p.get("arguments"))) {
                Ok(mut argv) => {
                    // 启动期的 provider 覆盖由 `serve` 的参数带来，**不经过** tool 参数
                    // （`build_argv` 的白名单里没有 provider_binary，模型给不进来）。
                    // 走的是与 `code --provider-binary` 完全相同的 argv 通道，
                    // 所以解析顺序与"指定了但不存在 ⇒ PROVIDER_UNAVAILABLE"的回退禁令一并生效。
                    if let Some(binary) = provider_override {
                        argv.push("--provider-binary".to_string());
                        argv.push(binary.clone());
                    }
                    // 契约「作用域与隔离」⑤：MCP 路径**不读不写结果缓存**，也不问 daemon。
                    // 前者关掉的是假绿通道 —— 否则 `warm_query_roundtrip` 与
                    // `provider_session_reused` 可以由回放满足，Phase 4 的复用判据就被我
                    // 自己造的缓存糊成绿。后者关掉的是环境依赖：`mcp serve` 自己持有会话，
                    // 让环境里某个别人手起的 daemon 来服务它，`session_queries` 量的就不是
                    // "这次 serve 复用了几次"，而是"那个 daemon 一共服务过谁"。
                    argv.push("--no-daemon".to_string());
                    argv.push("--no-cache".to_string());
                    let command =
                        format!("code {}", argv.first().map(String::as_str).unwrap_or(""));
                    let outcome = super::run_with_session(&argv, session);
                    let envelope = envelope_object(&command, &outcome);
                    let text =
                        serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string());
                    let is_error = outcome.0 != "PASS";
                    Some(result_object(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": text }],
                            "isError": is_error,
                            "structuredContent": envelope,
                        }),
                    ))
                }
                Err((code, message)) => Some(error_object(id, code, &message)),
            }
        }
        other => {
            if other.starts_with("notifications/") {
                return None;
            }
            Some(error_object(
                id,
                ERR_METHOD_NOT_FOUND,
                &format!("未实现的方法：{other}"),
            ))
        }
    }
}

/// 把帧写到管道（MCP stdio 与 LSP 同帧格式）。
/// 泛型化是为了同一份实现既能写子进程 stdin（selftest 当客户端），
/// 也能写自己的 stdout（serve 当服务端）—— 分帧只有一份。
fn write_frame<W: Write>(child: &mut W, message: &Value) -> Result<(), String> {
    let bytes = encode_frame(message);
    child
        .write_all(&bytes)
        .and_then(|_| child.flush())
        .map_err(|e| format!("写入 MCP 帧失败: {e}"))
}

/// 后台读线程：把帧送进 channel，EOF/出错即结束。
fn spawn_reader<R>(mut reader: R, tx: Sender<Result<Value, String>>) -> JoinHandle<()>
where
    R: std::io::BufRead + Send + 'static,
{
    std::thread::spawn(move || {
        loop {
            match read_frame_result(&mut reader) {
                FrameIn::Message(value) => {
                    if tx.send(Ok(value)).is_err() {
                        return;
                    }
                }
                FrameIn::Failed(failure) => {
                    let _ = tx.send(Err(format!("{}: {}", failure.code.code(), failure.reason)));
                    return;
                }
                // 子进程在帧边界上退出：不当成"崩溃"上报，直接让 channel 结束，
                // 等待方会收到"管道已关闭"——那是事实，比编一个错误码诚实。
                FrameIn::CleanEof => return,
            }
        }
    })
}

fn recv_frame(rx: &Receiver<Result<Value, String>>, budget: Duration) -> Result<Value, String> {
    match rx.recv_timeout(budget) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(e),
        Err(RecvTimeoutError::Timeout) => Err("等待 MCP 响应超时".to_string()),
        Err(RecvTimeoutError::Disconnected) => Err("MCP 子进程管道已关闭".to_string()),
    }
}

/// `mcp serve` 的**启动**参数解析：只认 `--provider-binary <path>`（也接 `=` 形式），
/// 其余一律 `Err` ⇒ 调用方回 BLOCKED。
///
/// 为什么单独成一个纯谓词：`mcp serve --provider-binary /不存在/的路径` 以前被 `dispatch`
/// 整个丢掉（实测与不给了完全相同的输出、exit 0）。被契约承诺的开关静默失效，比报错危险得多
/// —— 用户以为自己换了 language server。独立 Review round 2 的 N1。
fn parse_serve_args(args: &[String]) -> Result<Option<String>, String> {
    // args[0] 是子命令名 `serve`，从它之后开始看。
    let mut i = 1;
    let mut override_value: Option<String> = None;
    while i < args.len() {
        let flag = args[i].as_str();
        if let Some((name, inline)) = flag.split_once('=') {
            if name == "--provider-binary" {
                // `=` 形式同样不接受空值：空字符串会让 `resolve_binary` 拿到一个
                // 看似"给了覆盖"的路径，而调用方本意通常是"这次不给"。
                if inline.is_empty() {
                    return Err("--provider-binary 不接受空路径".to_string());
                }
                override_value = Some(inline.to_string());
                i += 1;
                continue;
            }
            return Err(format!(
                "mcp serve 不支持的参数：{flag}（唯一可用的启动参数是 --provider-binary <path>）"
            ));
        }
        if flag == "--provider-binary" {
            let Some(value) = args.get(i + 1) else {
                return Err("--provider-binary 后面要跟一个可执行文件路径".to_string());
            };
            if value.is_empty() {
                return Err("--provider-binary 不接受空路径".to_string());
            }
            override_value = Some(value.clone());
            i += 2;
            continue;
        }
        return Err(format!(
            "mcp serve 不支持的参数：{flag}（唯一可用的启动参数是 --provider-binary <path>）"
        ));
    }
    Ok(override_value)
}

/// `serve` 每条退出路径的共同字段。`authority` 恒 advisory；`handled_requests` 是
/// PASS/UNKNOWN 的判据本身；`snapshot` 让"退出/declined"也说自己绑在哪棵树上
/// （与 `code`/`context` 同一规则，round 2 的 N6：新增的 UNKNOWN 恰好就是 declined 形态）。
fn serve_exit_fields(handled: usize) -> Vec<(String, Value)> {
    vec![
        ("authority".to_string(), json!("advisory")),
        ("handled_requests".to_string(), json!(handled)),
        ("snapshot".to_string(), cli_snapshot()),
    ]
}

/// `mcp serve`：从 stdin 逐帧读到 EOF。任何超限/畸形帧都按结构化原因退出，
/// 不做"截断后继续"（提案 §14）。
///
/// **stdout 只承载 MCP 帧**：进程退出时的 CLI envelope 由 `main` 打到 stderr，
/// 否则裸 JSON 会混进协议通道（见 `MODULE.md` 的通道划分条目）。
pub fn serve(args: &[String]) -> Outcome {
    // 参数错误先于子进程与协议通道 —— 与 `code` 同一规则。
    let provider_override = match parse_serve_args(args) {
        Ok(value) => value,
        Err(reason) => {
            return ("BLOCKED".to_string(), reason, serve_exit_fields(0));
        }
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    // 会话只活在这个进程里：serve 返回即 Drop，不留孤儿 provider。
    let mut session: Option<ProviderSession> = None;
    let mut handled = 0usize;
    loop {
        // 用 read_frame_result 而不是 read_frame：客户端在帧边界上正常挂断**不是失败**，
        // 独立 Review 的 B1 就是把它混成了 PROVIDER_CRASHED（PASS 分支因此不可达）。
        match read_frame_result(&mut reader) {
            FrameIn::CleanEof => {
                // 处理过请求才谈得上 PASS；一条都没收到就 EOF ⇒ UNKNOWN。
                let verdict = if handled > 0 { "PASS" } else { "UNKNOWN" };
                let message = if handled > 0 {
                    format!("MCP stdin 已关闭，处理 {handled} 条请求后退出")
                } else {
                    "MCP stdin 立即 EOF：未收到任何请求，本结果不代表适配层可用".to_string()
                };
                return (verdict.to_string(), message, serve_exit_fields(handled));
            }
            FrameIn::Failed(failure) => {
                let code = failure.code.code();
                return (
                    "FAIL".to_string(),
                    format!("MCP 入站帧不合规：{code} - {}", failure.reason),
                    serve_exit_fields(handled),
                );
            }
            FrameIn::Message(message) => {
                if let Some(response) = handle_request(&message, &mut session, &provider_override) {
                    if let Err(e) = write_frame(&mut writer, &response) {
                        return ("BLOCKED".to_string(), e, serve_exit_fields(handled));
                    }
                    handled += 1;
                }
            }
        }
    }
}

/// 一次 selftest 步骤的结果记录。
struct Probe {
    name: &'static str,
    ok: bool,
    detail: String,
}

/// `selftest` 未跑成就退出时的公共字段（与 `code`/`serve` 的 declined 约定同形）。
/// round 3 的 N-A1：MODULE.md 声明了 selftest 的字段清单，而这几条 BLOCKED 路径原来只回
/// `Vec::new()` —— "declined 也要带 authority/snapshot"这条规矩不能只对 `code` 和 `serve` 生效。
fn decline_fields() -> Vec<(String, Value)> {
    vec![
        ("authority".to_string(), json!("advisory")),
        ("snapshot".to_string(), cli_snapshot()),
    ]
}

/// `mcp selftest`：把**自己**作为 `mcp serve` 子进程拉起来，经真实 stdio 管道跑协议。
pub fn selftest(args: &[String]) -> Outcome {
    // `selftest` 的参数面同样**不接受静默忽略**（与 N1 同一类）：只认 `--with-query`。
    // provider 覆盖不在这里给 —— 子进程会继承 `NEXUS_RUST_ANALYZER`，那已经是文档化的入口，
    // 再造一个只有 selftest 认的 flag 只会多出一条没人验证的旁路。
    if let Some(unknown) = args.iter().find(|a| a.as_str() != "--with-query") {
        return (
            "BLOCKED".to_string(),
            format!(
                "mcp selftest 不支持的参数：{unknown}（唯一可用的参数是 --with-query；\
                 要换 provider 请设 NEXUS_RUST_ANALYZER 或用 mcp serve --provider-binary）"
            ),
            decline_fields(),
        );
    }
    let with_query = args.iter().any(|a| a == "--with-query");
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("无法定位自身可执行文件，selftest 不能启动子进程: {e}"),
                decline_fields(),
            );
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let mut child = match Command::new(&exe)
        .current_dir(&cwd)
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // 子进程的 stdout 是协议通道（读线程逐帧消费）。它的**退出 envelope 从 N5 起走 stderr**，
        // 而这里从不排空 stderr —— 一条不被读取的管道迟早把写端阻塞住，所以直接丢弃。
        // 需要看 envelope 的是 `serve_exit_shape`，它自己 `wait_with_output()` 收全。
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("cannot spawn mcp serve: {e}"),
                decline_fields(),
            );
        }
    };
    let Some(stdin) = child.stdin.take() else {
        let _ = child.kill();
        return (
            "BLOCKED".to_string(),
            "子进程没有 stdin 管道".to_string(),
            decline_fields(),
        );
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return (
            "BLOCKED".to_string(),
            "子进程没有 stdout 管道".to_string(),
            decline_fields(),
        );
    };
    let mut writer = stdin;
    let (tx, rx) = channel::<Result<Value, String>>();
    let reader = spawn_reader(BufReader::new(stdout), tx);

    let started = Instant::now();
    let mut probes: Vec<Probe> = Vec::new();
    let mut protocol_version = String::new();
    let mut tools_count = 0usize;
    let mut write_tools_exposed = 0usize;
    let mut query: Vec<(String, Value)> = Vec::new();
    let mut failure: Option<String> = None;

    // 1) initialize
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "nexus-harness-selftest", "version": env!("CARGO_PKG_VERSION")}
    }});
    match drive(&mut writer, &rx, &init, Duration::from_secs(10)) {
        Ok(response) => {
            protocol_version = response
                .get("result")
                .and_then(|r| r.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let declared_write_caps = response
                .get("result")
                .and_then(|r| r.get("capabilities"))
                .and_then(|c| {
                    c.get("workspace")
                        .or(c.get("completion"))
                        .or(c.get("logging"))
                })
                .is_some();
            probes.push(Probe {
                name: "initialize",
                ok: !protocol_version.is_empty() && !declared_write_caps,
                detail: format!(
                    "protocolVersion={protocol_version} 越权能力={declared_write_caps}"
                ),
            });
        }
        Err(e) => {
            failure = Some(format!("initialize 失败：{e}"));
            probes.push(Probe {
                name: "initialize",
                ok: false,
                detail: e,
            });
        }
    }

    // 2) notifications/initialized（无 id，不该有回复）。这里只负责把 notification 写进管道，
    //    "没产生回复"这件事**不能**用"写成功了"来证明（round 2 的 N4a：那测的是管道通不通）。
    //    证明放在第 3 步：紧接着发的 `id=2` 请求，其响应必须是管道里的**下一条**帧。
    let mut note_written = false;
    let mut notification_no_reply = false;
    if failure.is_none() {
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        note_written = write_frame(&mut writer, &note).is_ok();
        if !note_written {
            failure = Some("notification 写不进管道，后续序列证明无法成立".to_string());
        }
        probes.push(Probe {
            name: "notification_written",
            ok: note_written,
            detail: "notification 已写入管道（回复性由下一条响应的 id 序列证明）".to_string(),
        });
    }

    // 3) tools/list
    if failure.is_none() {
        let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
        match drive(&mut writer, &rx, &list, Duration::from_secs(10)) {
            Ok(response) => {
                // 序列证明成立 ⇔ 这条响应就是 id=2，说明 notification 没有换来一条回复、
                // 也没有多消耗一条响应帧（多消耗会让这里的 recv 拿到上一请求的回包）。
                notification_no_reply = note_written && response["id"] == json!(2);
                probes_ok(
                    "notification_no_reply",
                    notification_no_reply,
                    format!("期望下一条响应 id=2，实得 {}", response["id"]),
                    &mut probes,
                );
                if !notification_no_reply {
                    failure = Some(format!(
                        "notification 之后第一条响应应是 id=2 的 tools/list 回复，实得 id={} \
                         —— 说明 notification 产生了回复或响应被错配",
                        response["id"]
                    ));
                }
                let tools = response
                    .get("result")
                    .and_then(|r| r.get("tools"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                tools_count = tools.len();
                write_tools_exposed = tools
                    .iter()
                    .filter(|t| {
                        let name = t.get("name").and_then(Value::as_str).unwrap_or("");
                        FORBIDDEN_TOOLS.contains(&name)
                            || !matches!(
                                name.strip_prefix("code.").unwrap_or(""),
                                "symbol"
                                    | "definition"
                                    | "references"
                                    | "implementations"
                                    | "callers"
                                    | "callees"
                                    | "hover"
                                    | "diagnostics"
                            )
                    })
                    .count();
                probes.push(Probe {
                    name: "tools_list_only_read_only",
                    ok: tools_count == TOOLS.len() && write_tools_exposed == 0,
                    detail: format!("tools={tools_count} 越权工具={write_tools_exposed}"),
                });
            }
            Err(e) => {
                failure = Some(format!("tools/list 失败：{e}"));
                probes.push(Probe {
                    name: "tools_list_only_read_only",
                    ok: false,
                    detail: e,
                });
            }
        }
    }

    // 4) 未知方法必须 -32601
    if failure.is_none() {
        let bad = json!({"jsonrpc":"2.0","id":3,"method":"nexus/not-a-method","params":{}});
        match drive(&mut writer, &rx, &bad, Duration::from_secs(10)) {
            Ok(response) => {
                let rejected = response.get("error").is_some()
                    && response["error"]["code"].as_i64() == Some(ERR_METHOD_NOT_FOUND);
                probes.push(Probe {
                    name: "unknown_method_rejected",
                    ok: rejected,
                    detail: format!(
                        "期望 JSON-RPC {ERR_METHOD_NOT_FOUND}，实得 {}",
                        response["error"]["code"]
                    ),
                });
            }
            Err(e) => {
                failure = Some(format!("未知方法探测失败：{e}"));
                probes.push(Probe {
                    name: "unknown_method_rejected",
                    ok: false,
                    detail: e,
                });
            }
        }
    }

    // 5) 非法 arguments 必须 -32602（而不是被静默忽略后跑一次全预算查询）
    if failure.is_none() {
        let bad = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
            "name":"code.symbol","arguments":{"bogus_key":1}
        }});
        match drive(&mut writer, &rx, &bad, Duration::from_secs(10)) {
            Ok(response) => {
                let rejected = response.get("error").is_some()
                    && response["error"]["code"].as_i64() == Some(ERR_INVALID_PARAMS);
                probes.push(Probe {
                    name: "bad_arguments_rejected",
                    ok: rejected,
                    detail: format!("实得 {}", response["error"]["code"]),
                });
                if !rejected {
                    failure = Some("非法 arguments 未被拒绝".to_string());
                }
            }
            Err(e) => {
                failure = Some(format!("非法参数探测失败：{e}"));
                probes.push(Probe {
                    name: "bad_arguments_rejected",
                    ok: false,
                    detail: e,
                });
            }
        }
    }

    // 6) 按名请求**每一个**写能力工具都必须被结构化拒绝（负向清单的真正落点）。
    //    逐个试而不是只试一个：白名单门外有 6 个名字，它们的拒绝路径并不天然相同
    //    （带不带 `code.` 前缀就曾分流出两种文案），只抽一个会让其余 5 个free-ride。
    if failure.is_none() {
        let mut rejected_all = true;
        let mut detail = String::new();
        let mut drive_err: Option<String> = None;
        for (i, forbidden) in FORBIDDEN_TOOLS.iter().enumerate() {
            let bad = json!({"jsonrpc":"2.0","id":50+i,"method":"tools/call","params":{
                "name":forbidden,"arguments":{"target":"x","workspace":"."}
            }});
            match drive(&mut writer, &rx, &bad, Duration::from_secs(10)) {
                Ok(response) => {
                    let code = response["error"]["code"].as_i64();
                    let message = response["error"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    // 光"回了个 error"不够：必须断言拒绝的**形态**（`-32602` + `UNSUPPORTED` 前缀）。
                    // 否则将来有人把拒绝文案改成"未知工具"这类模糊说法，探测仍然绿而契约已漂。
                    let ok = code == Some(ERR_INVALID_PARAMS) && message.starts_with("UNSUPPORTED");
                    rejected_all &= ok;
                    if !detail.is_empty() {
                        detail.push('|');
                    }
                    detail.push_str(&format!(
                        "{forbidden}=>{}:{message}",
                        code.unwrap_or_default()
                    ));
                }
                Err(e) => {
                    rejected_all = false;
                    drive_err = Some(format!("{forbidden}: {e}"));
                    break;
                }
            }
        }
        if let Some(e) = drive_err {
            failure = Some(format!("写能力拒绝探测失败：{e}"));
        } else if !rejected_all {
            failure = Some("写能力工具调用未被结构化拒绝（-32602 + UNSUPPORTED）".to_string());
        }
        probes.push(Probe {
            name: "write_call_rejected",
            ok: rejected_all,
            detail: if rejected_all {
                format!(
                    "{} 个越权名全部按 -32602 + UNSUPPORTED 拒绝",
                    FORBIDDEN_TOOLS.len()
                )
            } else {
                detail
            },
        });
    }

    // 7) 可选：**两次**真实查询（作用域限定在夹具 workspace）。
    //    第二次刻意紧跟第一次 —— 这是 Phase 4 的判定数据：同一个 `mcp serve` 进程内
    //    provider 已被 initialize/索引过一次，第二次查询是否显著便宜。
    //    数字直接写进 selftest 输出，供 Phase 4 的"要不要做跨命令缓存"判断台账引用。
    if failure.is_none() && with_query {
        let query_specs = [
            (
                "Egress",
                "code.symbol",
                6u64,
                "query_first_verdict",
                "query_first_results",
                "query_first_ms",
                "real_query_roundtrip",
            ),
            (
                "engineering/nexus-harness/fixtures/code-intel/src/transport.rs:9:8",
                "code.hover",
                7u64,
                "query_second_verdict",
                "query_second_results",
                "query_second_ms",
                "warm_query_roundtrip",
            ),
        ];
        for (target, tool, id, verdict_key, results_key, ms_key, probe_name) in query_specs {
            let call = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name": tool,
                "arguments":{"target":target,"workspace":SELFTEST_WORKSPACE,"max_results":8,
                              "max_snippet_lines":1,"ready_timeout_secs":240,"timeout_secs":120}
            }});
            let t0 = Instant::now();
            match drive(&mut writer, &rx, &call, Duration::from_secs(600)) {
                Ok(response) => {
                    let elapsed_ms = t0.elapsed().as_millis() as u64;
                    let envelope = response
                        .get("result")
                        .and_then(|r| r.get("structuredContent"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let results = envelope
                        .get("results")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let verdict = envelope["verdict"].as_str().unwrap_or("").to_string();
                    query.push((verdict_key.to_string(), json!(verdict)));
                    query.push((results_key.to_string(), json!(results)));
                    query.push((ms_key.to_string(), json!(elapsed_ms)));
                    // 结构层判据：provider 自己报有没有复用、这是会话的第几次查询。
                    let prefix = if tool == "code.symbol" {
                        "query_first"
                    } else {
                        "query_second"
                    };
                    query.push((
                        format!("{prefix}_session_reused"),
                        json!(envelope["provider"]["session_reused"]),
                    ));
                    query.push((
                        format!("{prefix}_session_queries"),
                        json!(envelope["provider"]["session_queries"]),
                    ));
                    query.push((
                        format!("{prefix}_invalidated"),
                        json!(envelope["provider"]["session_invalidated_reason"]),
                    ));
                    if tool == "code.symbol" {
                        query.push((
                            "query_provider_kind".to_string(),
                            json!(envelope["provider"]["kind"]),
                        ));
                        query.push(("query_authority".to_string(), json!(envelope["authority"])));
                        query.push((
                            "query_workspace_scope".to_string(),
                            json!(envelope["budget"]["workspace_scope"]),
                        ));
                        query.push((
                            "query_snapshot_bound".to_string(),
                            json!(
                                !envelope["snapshot"]["source_revision"]
                                    .as_str()
                                    .unwrap_or("")
                                    .is_empty()
                            ),
                        ));
                    }
                    let ok = verdict == "PASS" && !results.is_empty();
                    probes_ok(
                        probe_name,
                        ok,
                        format!(
                            "verdict={verdict} results={} ms={elapsed_ms}",
                            results.len()
                        ),
                        &mut probes,
                    );
                    if !ok {
                        failure = Some(format!("{tool} 未产出结果（{verdict}）"));
                    }
                }
                Err(e) => {
                    failure = Some(format!("{tool} 失败：{e}"));
                    probes_ok(probe_name, false, e, &mut probes);
                }
            }
            if failure.is_some() {
                break;
            }
        }
        // 复用判据用**相对**比值，不钉绝对毫秒数：绝对值随宿主负载漂移，
        // 钉死它会造出与语义无关的脆弱红（round 3 待办里同类教训）。
        // "第二次查询至少比第一次快 4 倍"只可能来自同一 provider 会话被复用
        // （冷启动那一次 initialize + 索引的钱已经付过）。
        let first_ms = query
            .iter()
            .find(|(k, _)| k == "query_first_ms")
            .and_then(|(_, v)| v.as_u64())
            .unwrap_or(0);
        let second_ms = query
            .iter()
            .find(|(k, _)| k == "query_second_ms")
            .and_then(|(_, v)| v.as_u64())
            .unwrap_or(u64::MAX);
        // 判据分两层：**结构层**（provider 自报 session_reused / session_queries）是结论；
        // 时延只是旁证，不拿来当判据 —— 绝对毫秒数随宿主负载漂移，钉死它会造出与语义
        // 无关的脆弱红（round 3 同类教训）。
        let reused = bool_of(&query, "query_second_session_reused");
        let queries = usize_of(&query, "query_second_session_queries");
        let structural = reused && queries >= 2;
        query.push(("query_warm_reused".to_string(), json!(structural)));
        probes_ok(
            "provider_session_reused",
            structural,
            format!(
                "second.session_reused={reused} queries={queries} first_ms={first_ms} second_ms={second_ms}"
            ),
            &mut probes,
        );
        if !structural {
            failure = Some(format!(
                "第二次查询未复用 provider 会话（session_reused={reused} queries={queries}）；两者都在冷启动量级就说明复用键或会话持有有问题"
            ));
        }
    } else {
        query.push(("query_skipped".to_string(), json!(!with_query)));
    }

    // 8) serve 的退出形状：干净挂断 != 崩溃；畸形帧必须 FAIL。
    //    不需要 language server，因此走 selftest 的默认路径（不加 --with-query 也跑）。
    let eof = serve_exit_shape(b"", &[]);
    let malformed = serve_exit_shape(b"Content-Length: 9\r\n\r\n{}", &[]);
    // 处理过一条请求再正常挂断：round 1 修好的那条 PASS 分支此前探针覆盖不到
    // （裸 envelope 与最后一帧粘在同一行），现在必须能自动证。
    let pass_input = initialize_frame_bytes();
    let passed = serve_exit_shape(&pass_input, &[]);
    query.push(("eof_verdict".to_string(), json!(eof.verdict)));
    query.push((
        "malformed_frame_verdict".to_string(),
        json!(malformed.verdict),
    ));
    query.push(("pass_verdict".to_string(), json!(passed.verdict)));
    query.push(("pass_handled_requests".to_string(), json!(passed.handled)));
    query.push((
        "stdout_frames_ok".to_string(),
        json!(eof.stdout_pure && malformed.stdout_pure && passed.stdout_pure),
    ));
    // 三条退出形状都要同时钉住 verdict、`handled` 与"帧数 == 已回复请求数"
    // （round 3 的 N-A3：只在 PASS 分支比帧数，零请求分支上多冒一条**格式合法**的幽灵帧
    // 仍然会绿 —— 而幽灵帧正是"把 CLI envelope 当帧发出去"这类改动的形态）。
    let eof_ok = eof.verdict == "UNKNOWN" && eof.handled == 0 && eof.frames == 0 && eof.stdout_pure;
    probes_ok(
        "clean_eof_is_not_reported_as_crash",
        eof_ok,
        eof.detail.clone(),
        &mut probes,
    );
    if !eof_ok {
        failure = Some(format!(
            "客户端一条请求都没发就挂断，serve 报成 {}；应是 UNKNOWN（既非崩溃也非 PASS）、\
             handled_requests=0 且 stdout 不得有任何帧或非帧字节。{}",
            eof.verdict, eof.detail
        ));
    }
    let malformed_ok = malformed.verdict == "FAIL"
        && malformed.handled == 0
        && malformed.frames == 0
        && malformed.stdout_pure;
    probes_ok(
        "malformed_frame_is_failure",
        malformed_ok,
        malformed.detail.clone(),
        &mut probes,
    );
    if !malformed_ok {
        failure = Some(format!(
            "畸形帧应报 FAIL、0 回复 0 帧且 stdout 纯净，实得 {}",
            malformed.detail
        ));
    }
    // PASS + 已回复计数 + stdout 恰好一帧且无多余字节。帧数与 handled_requests 必须相等：
    // 不相等就说明要么有回复没写出去，要么有裸 JSON 混进了协议通道。
    let pass_ok =
        passed.verdict == "PASS" && passed.handled == 1 && passed.frames == 1 && passed.stdout_pure;
    probes_ok(
        "handled_request_exit_is_pass_and_stdout_is_pure",
        pass_ok,
        passed.detail.clone(),
        &mut probes,
    );
    if !pass_ok {
        failure = Some(format!(
            "处理 1 条请求后正常挂断应是 PASS/handled_requests=1/1 帧纯净 stdout，实得 {}",
            passed.detail
        ));
    }

    // 9) `--provider-binary` 必须真的生效（契约承诺过它，而 round 2 实测它被静默丢弃）。
    //    **不 gate 在 failure.is_none() 上**（round 3 的 N-A6）：gate 了的话，前面一失败
    //    这里就"没跑"，而输出里记的是 `false` —— "没跑"和"跑了但没过"在消费方看来一模一样。
    //    本探针不需要 language server（RA 在 spawn 之前就被路径检查挡下），成本恒定几十毫秒。
    let (honored, detail) = provider_override_probe();
    query.push(("provider_override_honored".to_string(), json!(honored)));
    probes_ok(
        "provider_override_honored",
        honored,
        detail.clone(),
        &mut probes,
    );
    if !honored {
        failure = Some(format!(
            "`mcp serve --provider-binary` 未被端到端兑现（失败原因必须带上我传进去的那条路径）：{detail}"
        ));
    }

    // 收尾：优雅 shutdown；无论如何都要回收子进程（不留孤儿 language server 进程）。
    let shutdown = json!({"jsonrpc":"2.0","id":99,"method":"shutdown","params":{}});
    let _ = drive(&mut writer, &rx, &shutdown, Duration::from_secs(10));
    // 关掉写端：server 侧读到 EOF 才会自己退出，不靠 kill 兜底。
    drop(writer);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    let _ = reader.join();

    let all_ok = probes.iter().all(|p| p.ok) && failure.is_none();
    // 探针条数是契约里的声明（默认 11 条、`--with-query` 14 条），必须**机器可核**：
    // §N 那次把 8 记成 11 正是因为这个数只活在散文里（round 3 的 N-A6/R1）。
    let probes_before_move = probes.len();
    let extras: Vec<(String, Value)> = {
        let mut e = vec![
            ("authority".to_string(), json!("advisory")),
            ("protocol_version".to_string(), json!(protocol_version)),
            (
                "initialized_ok".to_string(),
                json!(probes.first().map(|p| p.ok).unwrap_or(false)),
            ),
            ("tools_count".to_string(), json!(tools_count)),
            (
                "notification_no_reply".to_string(),
                json!(notification_no_reply),
            ),
            (
                "write_tools_exposed".to_string(),
                json!(write_tools_exposed),
            ),
            (
                "unknown_method_rejected".to_string(),
                json!(
                    probes
                        .iter()
                        .any(|p| p.name == "unknown_method_rejected" && p.ok)
                ),
            ),
            (
                "bad_arguments_rejected".to_string(),
                json!(
                    probes
                        .iter()
                        .any(|p| p.name == "bad_arguments_rejected" && p.ok)
                ),
            ),
            (
                "write_call_rejected".to_string(),
                json!(
                    probes
                        .iter()
                        .any(|p| p.name == "write_call_rejected" && p.ok)
                ),
            ),
            ("query_skipped".to_string(), json!(!with_query)),
            (
                "probes".to_string(),
                json!(
                    probes
                        .iter()
                        .map(|p| json!({
                            "name": p.name, "ok": p.ok, "detail": p.detail,
                        }))
                        .collect::<Vec<Value>>()
                ),
            ),
            ("probe_count".to_string(), json!(probes_before_move)),
            (
                "duration_ms".to_string(),
                json!(started.elapsed().as_millis() as u64),
            ),
            ("snapshot".to_string(), cli_snapshot()),
        ];
        e.extend(query);
        e
    };
    let message = match &failure {
        Some(f) => format!("MCP selftest 未通过：{f}"),
        None => format!(
            "MCP selftest 通过：{} 个只读工具，协议 {protocol_version}{}",
            tools_count,
            if with_query {
                "（含一次真实查询）"
            } else {
                ""
            }
        ),
    };
    (
        if all_ok { "PASS" } else { "FAIL" }.to_string(),
        message,
        extras,
    )
}

/// CLI 派发：`mcp serve [--provider-binary <path>]` / `mcp selftest [--with-query]`。
/// 未知子命令**不启动任何东西**直接 BLOCKED —— 与 `code` 的"参数错误先于子进程"同一规则。
/// `serve` 的未知**启动参数**同样 BLOCKED（`parse_serve_args`）：以前 `args` 被整个丢掉，
/// 于是契约里承诺的 `--provider-binary` 静默失效，这一半此前没人堵。
pub fn dispatch(args: &[String]) -> Outcome {
    match args.first().map(String::as_str).unwrap_or("") {
        "serve" => serve(args),
        "selftest" => selftest(&args[1..]),
        other => (
            "BLOCKED".to_string(),
            format!(
                "supported mcp subcommands: serve [--provider-binary <path>], \
                 selftest [--with-query]（收到：{other}）"
            ),
            Vec::new(),
        ),
    }
}

/// selftest 的 snapshot 绑定：与 `code`/`context` 用同一套 `Bindings`。
/// 仓库发现失败时留空串而**不是**编一个值 —— 场景断言 `snapshot.source_revision` 非空，
/// 于是"没绑定"会表现为场景变红，而不是被静默吞掉。
fn cli_snapshot() -> Value {
    match crate::env::Repo::discover()
        .and_then(|repo| crate::config::Config::load(&repo).map(|config| (repo, config)))
    {
        Ok((repo, config)) => crate::evidence::Bindings::current(&repo, &config).to_json(),
        Err(e) => json!({"source_revision": "", "working_tree_digest": "", "error": e}),
    }
}

/// 一次性演练 `mcp serve` 的结果。每个量都是对外契约的一部分：
/// `verdict` 说"serve 是怎么结束的"，`handled` 就是 PASS/UNKNOWN 的判据本身，
/// `frames` + `stdout_pure` 说"stdout 上是不是只有帧、有没有多余字节"。
/// 不存 `message`：三条断言现在全部由 `detail` 承载（含 verdict/handled/帧数/纯净度），
/// 留一个没人读的字段的下场就是它和实际断言漂移而无人知。
struct ExitShape {
    verdict: String,
    handled: usize,
    frames: usize,
    stdout_pure: bool,
    detail: String,
}

/// 用一次性子进程演练 `mcp serve` 的**退出形状**（`extra_args` 用来试启动参数）。
///
/// 为什么要专门探：帧边界上的 EOF（客户端正常挂断）与畸形/半帧必须给出**不同** verdict。
/// 独立 Review round 1 抓到我把两者都判成 FAIL —— `read_frame` 把干净 EOF 也报成
/// `PROVIDER_CRASHED`，于是 PASS 分支不可达。
///
/// 为什么这里读 **stderr** 而不是 stdout：round 2 之前退出 envelope 是被 `main` 打到 stdout 的，
/// 于是它和最后一帧粘在同一行（实测 `…"}}}{"authority":…`），"取最后一行 JSON"的探针
/// 解析不出来 ⇒ `handled > 0 ⇒ PASS` 这条分支**探针覆盖不到**，只能靠人工 `printf` 看见。
/// 现在 stdout 只承载协议帧，envelope 走 stderr，本函数顺带把"stdout 可否按帧完整消费"
/// 变成断言对象（同一处改动同时解掉 N4b 与 N5）。
fn serve_exit_shape(input: &[u8], extra_args: &[String]) -> ExitShape {
    let failed = |detail: String| ExitShape {
        verdict: String::new(),
        handled: 0,
        frames: 0,
        stdout_pure: false,
        detail,
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return failed(format!("定位自身可执行文件失败：{e}")),
    };
    let mut cmd = Command::new(&exe);
    let mut argv: Vec<String> = vec!["mcp".to_string(), "serve".to_string(), "--json".to_string()];
    argv.extend(extra_args.iter().cloned());
    let mut child = match cmd
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return failed(format!("spawn mcp serve 失败：{e}")),
    };
    {
        let mut si = match child.stdin.take() {
            Some(s) => s,
            None => return failed("子进程没有 stdin 管道".to_string()),
        };
        let _ = si.write_all(input);
        // 离开作用域即关闭写端 ⇒ 子进程读到 EOF
    }
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return failed(format!("等待子进程失败：{e}")),
    };

    // stdout 必须能被**完整**消费成帧：每条都是 Message，最后恰好一次 CleanEof；
    // 出现 Failed（裸 JSON、半帧、超限）就说明协议通道被污染。
    let mut cursor = std::io::Cursor::new(output.stdout.as_slice());
    let mut reader = BufReader::new(&mut cursor);
    let mut frames = 0usize;
    let mut stdout_pure = true;
    let mut frame_detail = String::new();
    loop {
        match read_frame_result(&mut reader) {
            FrameIn::CleanEof => break,
            FrameIn::Message(_) => frames += 1,
            FrameIn::Failed(failure) => {
                stdout_pure = false;
                frame_detail = format!("{} - {}", failure.code.code(), failure.reason);
                break;
            }
        }
    }

    // 退出 envelope 在 stderr 上（stdout 是协议通道，不放裸 JSON）。
    let text = String::from_utf8_lossy(&output.stderr).to_string();
    let line = match text.lines().rev().find(|l| l.trim_start().starts_with('{')) {
        Some(l) => l,
        None => {
            return failed(format!(
                "stderr 没有退出 envelope（stdout 帧数={frames} pure={stdout_pure} {frame_detail}）"
            ));
        }
    };
    match serde_json::from_str::<Value>(line) {
        Ok(v) => {
            let mut detail = format!(
                "verdict={} handled_requests={} 帧数={} stdout_pure={stdout_pure}",
                v["verdict"].as_str().unwrap_or(""),
                v["handled_requests"].as_u64().unwrap_or(0),
                frames
            );
            if !stdout_pure {
                detail.push_str(&format!("（多余字节：{frame_detail}）"));
            }
            ExitShape {
                verdict: v["verdict"].as_str().unwrap_or("").to_string(),
                handled: v["handled_requests"].as_u64().unwrap_or(0) as usize,
                frames,
                stdout_pure,
                detail,
            }
        }
        Err(e) => failed(format!("解析 stderr envelope 失败：{e}")),
    }
}

/// `provider_override_honored` 的判据本身。抽成纯函数的原因很实际：
/// 它要能在**没有 RA、也没有子进程**的情况下被证伪（round 3 的 N-A2）。
/// RA 缺失时 `provider.rs` 的兜底文案里本来就写着 `--provider-binary`，
/// 所以"码 + flag 名"两条在 flag 根本没兑现的宿主上同样为真 —— 必须再要求
/// 原因里带上**调用方实际传入的那条路径**，兜底文案没有它。
fn override_proof_honored(code: &str, reason: &str, bogus_path: &str) -> bool {
    code == "PROVIDER_UNAVAILABLE"
        && reason.contains("--provider-binary")
        && reason.contains(bogus_path)
}

/// `mcp serve --provider-binary` 的端到端探针：证明这个启动参数**真的生效**。
///
/// 为什么用不存在的路径而不是真 server：要断言的是"失败原因点名**我传进去的那条路径**"，
/// 而不是"换了一个能用的 server"。`resolve_binary` 在 spawn 之前就失败，毫秒级返回。
/// round 2 的 N1 就是这个 flag 被 `dispatch` 整个丢掉、给了不存在的路径与不给了完全同形。
///
/// 为什么必须断言路径本身（round 3 的 N-A2，实测复现过的假绿）：只断言
/// `PROVIDER_UNAVAILABLE` + 原因含 `--provider-binary` 是**不够的** —— rust-analyzer
/// 找不到时的提示文案里也写着 `…或设置 NEXUS_RUST_ANALYZER / --provider-binary`
/// （`provider.rs` 的兜底原因），所以在**没有可解析 RA 的宿主**上，即使把
/// threading 整段删掉，这个谓词仍然为真。加上"含 bogus_text"之后，
/// 兜底文案（不含具体路径）无法满足断言，假绿被排除；代价是没有 RA 的宿主上本探针会
/// 如实变红，这是正确行为而不是缺陷 —— 它测的就是 flag 有没有被兑现。
fn provider_override_probe() -> (bool, String) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return (false, format!("定位自身可执行文件失败：{e}")),
    };
    // 与自身同目录、但任何宿主都不该存在的文件名：路径合法、文件不存在。
    let bogus = exe.with_file_name("nexus-harness-not-a-language-server");
    let bogus_text = bogus.to_string_lossy().to_string();
    let mut child = match Command::new(&exe)
        .args(["mcp", "serve", "--json", "--provider-binary", &bogus_text])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("spawn mcp serve 失败：{e}")),
    };
    let Some(stdin) = child.stdin.take() else {
        let _ = child.kill();
        return (false, "子进程没有 stdin 管道".to_string());
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return (false, "子进程没有 stdout 管道".to_string());
    };
    let (tx, rx) = channel::<Result<Value, String>>();
    let reader = spawn_reader(BufReader::new(stdout), tx);
    let mut writer = stdin;
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": "nexus-harness-provider-probe", "version": env!("CARGO_PKG_VERSION")}
    }});
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name": "code.symbol",
        "arguments": {"target": "Egress", "workspace": SELFTEST_WORKSPACE,
                      "max_results": 2, "max_snippet_lines": 1,
                      "ready_timeout_secs": 20, "timeout_secs": 20}
    }});
    let (ok, detail) = match drive(&mut writer, &rx, &init, Duration::from_secs(20))
        .and_then(|_| drive(&mut writer, &rx, &call, Duration::from_secs(60)))
    {
        Ok(response) => {
            let envelope = response
                .get("result")
                .and_then(|r| r.get("structuredContent"))
                .cloned()
                .unwrap_or(Value::Null);
            let code = envelope["error"]["code"].as_str().unwrap_or("").to_string();
            let reason = envelope["error"]["reason"]
                .as_str()
                .unwrap_or("")
                .to_string();
            // 三条同时成立才算过：
            // ① 错误码是 PROVIDER_UNAVAILABLE（不是"悄悄用别的 server 又成功了"）；
            // ② 原因点名 `--provider-binary`；③ 原因**带上我传进去的那条路径**。
            // ③ 是 round 3 的 N-A2：RA 缺失时的兜底文案也含 `--provider-binary` 字样，
            // 只断言 ①+② 在没有 RA 的宿主上会假绿（谓词为真而 flag 根本没被兑现）。
            let honored = override_proof_honored(&code, &reason, &bogus_text);
            let detail = format!(
                "verdict={} code={code} 含指定路径={} reason={}",
                envelope["verdict"].as_str().unwrap_or(""),
                reason.contains(&bogus_text),
                reason.chars().take(90).collect::<String>()
            );
            (honored, detail)
        }
        Err(e) => (false, format!("探针没拿到 tools/call 响应：{e}")),
    };
    // 关写端 ⇒ 子进程读到 EOF 自己退出；不靠 kill，也不留孤儿 provider。
    drop(writer);
    let _ = child.wait();
    let _ = reader.join();
    (ok, detail)
}
/// 构造一帧 `initialize` 请求，供退出形状探针喂给子进程。
fn initialize_frame_bytes() -> Vec<u8> {
    encode_frame(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "nexus-harness-serve-probe", "version": env!("CARGO_PKG_VERSION")}
        }
    }))
}

/// 从已收集的字段里读布尔/整数；读不到算"没发生"，不默认成 true/1。
fn bool_of(fields: &[(String, Value)], key: &str) -> bool {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_bool())
        .unwrap_or(false)
}

fn usize_of(fields: &[(String, Value)], key: &str) -> usize {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0) as usize
}

/// 一次探测的记账。独立成函数只为了循环里少写八行样板。
fn probes_ok(name: &'static str, ok: bool, detail: String, probes: &mut Vec<Probe>) {
    probes.push(Probe { name, ok, detail });
}

/// 发一帧并等一条响应。
fn drive(
    writer: &mut ChildStdin,
    rx: &Receiver<Result<Value, String>>,
    message: &Value,
    budget: Duration,
) -> Result<Value, String> {
    write_frame(writer, message)?;
    recv_frame(rx, budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tools/list` 的白名单就是安全边界本身：8 个只读 verb，写能力一个都不许出现。
    /// 这里同时钉"负向清单没有被误列进正向清单"——两份名单一旦有交集就说明有人加错了。
    #[test]
    fn tools_list_exposes_exactly_the_eight_read_only_verbs() {
        let payload = tools_list_payload();
        let tools = payload["tools"].as_array().expect("tools 必须是数组");
        assert_eq!(tools.len(), TOOLS.len(), "工具数必须与 TOOLS 一致");
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t["name"].as_str().unwrap_or(""))
            .collect();
        for expected in TOOLS {
            assert!(names.contains(&expected), "缺少工具 {expected}：{names:?}");
        }
        for forbidden in FORBIDDEN_TOOLS {
            assert!(
                !names.contains(&forbidden),
                "写能力工具 {forbidden} 不得出现在 tools/list 里：{names:?}"
            );
        }
        // 每个工具都得自带 schema，否则客户端只能猜参数（提案 §4 的"版本化 DTO"要求）。
        for tool in tools.iter() {
            assert!(!tool["description"].as_str().unwrap_or("").is_empty());
            let required = tool["inputSchema"]["required"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(
                required.contains(&json!("target")) && required.contains(&json!("workspace")),
                "{:?} 必须声明 target/workspace 为必填",
                tool["name"]
            );
        }
    }

    /// 正向：tool 参数映射成 CLI argv 时，`snake_case` 键要变成 `--kebab-case` 选项，
    /// 且数值以字符串传（`run()` 那侧统一走 parse_usize 的校验与错误码）。
    #[test]
    fn build_argv_maps_tool_arguments_onto_cli_options() {
        let argv = build_argv(
            "code.references",
            Some(&json!({
                "target": "crates/nexus-domain/src/lib.rs:938:5",
                "workspace": "crates/nexus-domain",
                "max_results": 12,
                "ready_timeout_secs": 300
            })),
        )
        .expect("合法参数必须通过");
        assert_eq!(argv[0], "references", "verb 必须是 code. 前缀之后的部分");
        assert_eq!(argv[1], "crates/nexus-domain/src/lib.rs:938:5");
        let joined = argv.join(" ");
        assert!(
            joined.contains("--workspace crates/nexus-domain"),
            "{joined}"
        );
        assert!(joined.contains("--max-results 12"), "{joined}");
        assert!(joined.contains("--ready-timeout-secs 300"), "{joined}");
    }

    /// 安全边界：可执行文件路径**不能**从 tool 参数进来。放进来就等于让模型给
    /// language server launcher 注入 argv（提案 §6 明令禁止），所以必须被拒。
    #[test]
    fn build_argv_refuses_provider_binary_and_unknown_keys() {
        for (arguments, why) in [
            (
                json!({"target": "X", "workspace": ".", "provider_binary": "/tmp/evil"}),
                "provider_binary 不在白名单",
            ),
            (
                json!({"target": "X", "workspace": ".", "max_results": "8; rm -rf /"}),
                "数值型 argument 必须是数字，不接受任意字符串",
            ),
            (
                json!({"workspace": "."}),
                "缺 target 必须拒，不能查空字符串",
            ),
            (json!({"target": "", "workspace": "."}), "空 target 必须拒"),
            (
                json!({"target": "X", "workspace": ".", "arguments": {"nested": 1}}),
                "未知键一律拒（不接受嵌套对象）",
            ),
        ] {
            let err = build_argv("code.symbol", Some(&arguments))
                .expect_err(&format!("{} 必须被拒", why));
            assert_eq!(
                err.0, ERR_INVALID_PARAMS,
                "{why} 应返回 JSON-RPC {ERR_INVALID_PARAMS}：{err:?}"
            );
            assert!(!err.1.is_empty(), "拒绝必须给原因：{err:?}");
        }
    }

    /// 按名请求写能力工具时必须被拒 —— 而且拒绝发生在**任何** provider 启动之前。
    /// 这条是 §16.8（provider 无写业务代码能力）在 MCP 面上的等价物。
    ///
    /// 断言的是**拒绝形态**（`-32602` + `UNSUPPORTED` 前缀），不只是"回了个 error"：
    /// `workspace/applyEdit` 曾经因为不带 `code.` 前缀而落进"未知工具"文案，
    /// 只断言"有错误"时探测是绿的，而对外契约已经把越权说成了拼写问题。
    #[test]
    fn forbidden_tool_names_are_refused_not_executed() {
        for name in FORBIDDEN_TOOLS {
            let err = build_argv(name, Some(&json!({"target": "Egress", "workspace": "."})))
                .expect_err("{name} 不是只读工具，必须被拒");
            assert_eq!(err.0, ERR_INVALID_PARAMS, "{name} → {err:?}");
            assert!(
                err.1.starts_with("UNSUPPORTED"),
                "{name} 的拒绝必须以 Nexus 错误码 UNSUPPORTED 开头，实得 {:?}",
                err.1
            );
        }
        // 未知工具名同样拒，不"当作符号查一次"；形状与越权名一致。
        let unknown = build_argv(
            "code.teleport",
            Some(&json!({"target": "x", "workspace": "."})),
        )
        .expect_err("白名单外的名字必须被拒");
        assert_eq!(unknown.0, ERR_INVALID_PARAMS);
        assert!(
            unknown.1.starts_with("UNSUPPORTED"),
            "未知 verb 也必须走同一条结构化拒绝，实得 {:?}",
            unknown.1
        );
        // 不带 `code.` 前缀的陌生名同样落进白名单门，而不是命名约定门。
        let odd = build_argv(
            "workspace/whatever",
            Some(&json!({"target": "x", "workspace": "."})),
        )
        .expect_err("前缀外的名字必须被拒");
        assert_eq!(odd.0, ERR_INVALID_PARAMS);
        assert!(odd.1.starts_with("UNSUPPORTED"), "实得 {:?}", odd.1);
    }

    /// `initialize` 只声明 tools 能力。声明 workspace/completion/logging 之类
    /// 就等于对外承诺本适配器有那些面 —— 契约不能靠"反正客户端不用"糊过去。
    #[test]
    fn initialize_declares_only_tools_capability() {
        let response = handle_request(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            &mut None,
            &None,
        )
        .expect("initialize 必须有回复");
        assert_eq!(
            response["result"]["protocolVersion"],
            json!(PROTOCOL_VERSION)
        );
        assert_eq!(response["result"]["serverInfo"]["name"], json!(SERVER_NAME));
        let caps = &response["result"]["capabilities"];
        assert!(caps["tools"].is_object(), "tools 能力必须声明：{caps}");
        for over in ["workspace", "completion", "logging", "prompts"] {
            assert!(caps.get(over).is_none(), "不得声明 {over} 能力：{caps}");
        }
    }

    /// notification（无 id）不回复；带 id 的非法/未知请求必须有 JSON-RPC 错误码。
    /// 关键是"没有回复"与"回复了错误"不能混为一谈：前者是协议规定，后者是失败可见。
    #[test]
    fn notifications_are_silent_while_errors_are_structured() {
        assert!(
            handle_request(
                &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
                &mut None,
                &None,
            )
            .is_none(),
            "notification 不该产生回复"
        );
        let unknown = handle_request(
            &json!({"jsonrpc":"2.0","id":7,"method":"nexus/not-a-method","params":{}}),
            &mut None,
            &None,
        )
        .expect("带 id 的请求必须有回复");
        assert_eq!(unknown["error"]["code"], json!(ERR_METHOD_NOT_FOUND));
        // 缺 jsonrpc 版本 = 无效请求，不能当合法请求处理。
        for bad in [
            json!({"id": 8, "method": "tools/list"}),
            json!({"jsonrpc": "1.0", "id": 9, "method": "tools/list"}),
        ] {
            let response = handle_request(&bad, &mut None, &None).expect("必须有回复");
            assert_eq!(
                response["error"]["code"],
                json!(ERR_INVALID_REQUEST),
                "jsonrpc 版本不合法必须 -32600：{bad}"
            );
        }
    }

    /// 工具结果里必须原样带上 Nexus envelope（含 `authority = "advisory"`）。
    /// 适配层最容易做坏的地方就是把 advisory 洗成"看起来像最终结论"，这条钉住不洗。
    #[test]
    fn envelope_object_keeps_authority_and_all_extra_fields() {
        let outcome: Outcome = (
            "PASS".to_string(),
            "2 条结果".to_string(),
            vec![
                ("authority".to_string(), json!("advisory")),
                ("count".to_string(), json!(2)),
                ("results".to_string(), json!([{"symbol": "Egress"}])),
            ],
        );
        let envelope = envelope_object("code symbol", &outcome);
        assert_eq!(envelope["verdict"], json!("PASS"));
        assert_eq!(
            envelope["authority"],
            json!("advisory"),
            "advisory 不得被适配层丢掉"
        );
        assert_eq!(envelope["schema_version"], json!(1));
        assert_eq!(envelope["command"], json!("code symbol"));
        assert_eq!(envelope["count"], json!(2));
        assert_eq!(envelope["results"][0]["symbol"], json!("Egress"));
    }

    /// 启动期的 provider 覆盖必须**被线程化到查询里**（round 3 的 N-A2）。
    /// 其余 `handle_request` 测试一律传 `&None`，所以这条是唯一直接盯 threading 的单测：
    /// 断言的是"失败原因带上我传进去的那条路径"，而不是只看错误码 ——
    /// `PROVIDER_UNAVAILABLE` 在 rust-analyzer 缺失的宿主上本来就会出现，
    /// 连兜底文案里都写着 `--provider-binary` 字样，只看码或只看 flag 名都会假绿。
    #[test]
    fn tools_call_threads_startup_provider_override() {
        let bogus = std::env::current_exe()
            .expect("定位自身")
            .with_file_name("nexus-harness-not-a-language-server")
            .to_string_lossy()
            .to_string();
        let response = handle_request(
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"code.symbol",
                "arguments":{"target":"Egress","workspace":".","max_results":1}
            }}),
            &mut None,
            &Some(bogus.clone()),
        )
        .expect("带 id 的 tools/call 必须有回复");
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(
            envelope["error"]["code"],
            json!("PROVIDER_UNAVAILABLE"),
            "指定了不存在的 provider 必须显式失败，实得 {envelope}"
        );
        let reason = envelope["error"]["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains(&bogus),
            "原因必须点名**传进去的那条路径**，否则无法区分'flag 生效了'与'宿主本来就缺 RA'：{reason}"
        );
        assert!(reason.contains("--provider-binary"), "{reason}");
    }

    /// 判据必须能被**没有 RA 的宿主**证伪（round 3 的 N-A2 的实质）。
    /// 这里不启动任何子进程：直接拿 `provider.rs` 兜底文案的真身当输入，
    /// 展示"码 + flag 名"两条会为真、加上"含实际路径"第三条才把它否掉。
    #[test]
    fn override_predicate_rejects_the_rust_analyzer_missing_fallback() {
        let bogus = "D:\\anywhere\\nexus-harness-not-a-language-server";
        // provider.rs 找不到 rust-analyzer 时的兜底原因（含 "--provider-binary" 字样）。
        let fallback = "找不到 rust-analyzer：请安装 `rustup component add rust-analyzer`，\
                        或设置 NEXUS_RUST_ANALYZER / --provider-binary";
        assert!(
            fallback.contains("--provider-binary"),
            "前提：兜底文案确实含 flag 名 —— 这正是旧判据假绿的来源"
        );
        assert!(
            !override_proof_honored("PROVIDER_UNAVAILABLE", fallback, bogus),
            "RA 缺失的兜底原因不得被当成 flag 兑现的证据"
        );
        // flag 真正生效时，原因里带的是调用方传入的那条路径。
        let honored = "--provider-binary 指定的可执行文件不存在：D:\\anywhere\\nexus-harness-not-a-language-server";
        assert!(
            override_proof_honored("PROVIDER_UNAVAILABLE", honored, bogus),
            "真兑现的形态必须为真：{honored}"
        );
        // 错误码不对时，即便文案含路径也不算过。
        assert!(!override_proof_honored("QUERY_INVALID", honored, bogus));
    }

    /// 帧编码必须与 `code_intel/lsp.rs` 的实现同源：MCP stdio 与 LSP 共用一套
    /// `Content-Length` 分帧，复制一份就等于复制一份安全边界。
    #[test]
    fn frames_use_the_shared_lsp_codec() {
        let bytes = encode_frame(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
        let text = String::from_utf8(bytes).expect("帧是 utf8");
        assert!(
            text.starts_with("Content-Length: "),
            "分帧头必须一致：{text}"
        );
        assert!(text.contains("\r\n\r\n"), "头与体之间必须是空行");
    }

    /// `serve` 的启动参数面：`--provider-binary` 是唯一入口，且**不接受**的必须报错。
    /// 这条测试是 N1 的回归护栏 —— 原来的 `dispatch` 把 `args` 整个丢掉，
    /// 于是"文档承诺了但实现不认"这种形状可以长期存在而没有任何信号。
    #[test]
    fn serve_args_accept_only_provider_binary_and_reject_everything_else() {
        let argv =
            |items: &[&str]| -> Vec<String> { items.iter().map(|s| s.to_string()).collect() };
        // 只给子命令 ⇒ 没有覆盖，走 NEXUS_RUST_ANALYZER/PATH 的解析顺序。
        assert_eq!(parse_serve_args(&argv(&["serve"])).unwrap(), None);
        // 空格形式与 `=` 形式都认。
        assert_eq!(
            parse_serve_args(&argv(&["serve", "--provider-binary", "/x/ra"])).unwrap(),
            Some("/x/ra".to_string())
        );
        assert_eq!(
            parse_serve_args(&argv(&["serve", "--provider-binary=/x/ra"])).unwrap(),
            Some("/x/ra".to_string())
        );
        // 未知参数、缺值、空值 ⇒ 报错（错误里要说清可用参数，不然调用方只能猜）。
        for bad in [
            argv(&["serve", "--totally-made-up"]),
            argv(&["serve", "--provider-binary"]),
            argv(&["serve", "--provider-binary="]),
            argv(&["serve", "--provider-binary", ""]),
            argv(&["serve", "--max-results", "8"]),
            argv(&["serve", "--provider-binary=/x", "--bogus"]),
        ] {
            let err = parse_serve_args(&bad).expect_err("不该被静默接受");
            assert!(
                err.contains("--provider-binary"),
                "拒绝原因必须指出唯一可用参数：{err}"
            );
        }
    }

    /// `selftest` 也只认自己那一个参数：静默忽略未知 flag 属于 N1 的同一类失效形状。
    /// 这里断言 BLOCKED 而**不启动子进程** —— 参数错误先于任何 provider/管道动作。
    #[test]
    fn selftest_rejects_unknown_arguments_before_spawning_anything() {
        let args: Vec<String> = ["--max-results", "8"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (verdict, message, _) = selftest(&args);
        assert_eq!(verdict, "BLOCKED", "未知参数必须被拒，实得 {verdict}");
        assert!(
            message.contains("--with-query"),
            "拒绝原因要指出唯一可用参数：{message}"
        );
        assert!(
            message.contains("NEXUS_RUST_ANALYZER"),
            "还要把换 provider 的正确入口说出来：{message}"
        );
    }

    /// 每条 `serve` 退出路径的共同字段：advisory + 判据本身（handled_requests）+ 绑定。
    /// 少一个字段就等于对外少承诺一件事（round 2 的 N6：新增的 UNKNOWN 正是 declined 形态，
    /// declined 也要说清绑在哪棵树上）。
    #[test]
    fn serve_exit_fields_carry_authority_counter_and_snapshot() {
        let fields = serve_exit_fields(3);
        let get = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null)
        };
        assert_eq!(get("authority"), json!("advisory"));
        assert_eq!(get("handled_requests"), json!(3));
        let snapshot = get("snapshot");
        assert!(
            snapshot.is_object(),
            "snapshot 必须是对象（取不到仓库时也是带 error 的对象，不是缺字段）：{snapshot}"
        );
        // 只钉"字段在不在"，不钉"取没取到"：单测的 cwd 可能是仓库也可能不是，
        // 取不到时 `cli_snapshot()` 会给出 `source_revision: ""` + `error`，
        // 两种形态都必须让消费方看得见（后者正是它不假装绑定的方式）。
        assert!(
            snapshot.get("source_revision").is_some(),
            "snapshot 必须自述有没有绑定上：{snapshot}"
        );
    }
}
