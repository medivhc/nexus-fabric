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
//! 分帧复用 `super::lsp::{encode_frame, read_frame}` —— MCP stdio 与 LSP 用的是同一套
//! `Content-Length` 帧格式，而那两个函数已经带着 header/body 上限与结构化失败原因。
//! 复制一份编解码器等于复制一份安全边界，这类东西迟早漂移（round 2 的 `..` 绕过就是教训）。

use super::ProviderSession;
use super::lsp::{encode_frame, read_frame};
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
    let verb = name
        .strip_prefix("code.")
        .ok_or((ERR_INVALID_PARAMS, format!("未知工具：{name}")))?;
    if !TOOLS.contains(&name) {
        // 明确拒绝，而不是"当作未知符号查一次"。
        return Err((
            ERR_INVALID_PARAMS,
            format!(
                "{name} 不是只读查询工具；本适配器只暴露 {} 个只读 verb",
                TOOLS.len()
            ),
        ));
    }
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
fn handle_request(message: &Value, session: &mut Option<ProviderSession>) -> Option<Value> {
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
                Ok(argv) => {
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
            match read_frame(&mut reader) {
                Ok(value) => {
                    if tx.send(Ok(value)).is_err() {
                        return;
                    }
                }
                Err(failure) => {
                    let _ = tx.send(Err(format!("{}: {}", failure.code.code(), failure.reason)));
                    return;
                }
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

/// `mcp serve`：从 stdin 逐帧读到 EOF。任何超限/畸形帧都按结构化原因退出，
/// 不做"截断后继续"（提案 §14）。
pub fn serve() -> Outcome {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    // 会话只活在这个进程里：serve 返回即 Drop，不留孤儿 provider。
    let mut session: Option<ProviderSession> = None;
    let mut handled = 0usize;
    loop {
        match read_frame(&mut reader) {
            Ok(message) => {
                if let Some(response) = handle_request(&message, &mut session) {
                    if let Err(e) = write_frame(&mut writer, &response) {
                        return (
                            "BLOCKED".to_string(),
                            e,
                            vec![
                                ("authority".to_string(), json!("advisory")),
                                ("handled_requests".to_string(), json!(handled)),
                            ],
                        );
                    }
                    handled += 1;
                }
            }
            // 客户端关管道 = 正常退出；畸形帧 = PROVIDER/协议层失败，不伪装成 PASS。
            Err(failure) => {
                let code = failure.code.code();
                if code == "PROVIDER_CRASHED" || code == "UNSUPPORTED" {
                    return (
                        "FAIL".to_string(),
                        format!("MCP 入站帧不合规：{code} - {}", failure.reason),
                        vec![
                            ("authority".to_string(), json!("advisory")),
                            ("handled_requests".to_string(), json!(handled)),
                        ],
                    );
                }
                return (
                    "PASS".to_string(),
                    format!("MCP stdin 已关闭，处理 {handled} 条请求后退出"),
                    vec![
                        ("authority".to_string(), json!("advisory")),
                        ("handled_requests".to_string(), json!(handled)),
                    ],
                );
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

/// `mcp selftest`：把**自己**作为 `mcp serve` 子进程拉起来，经真实 stdio 管道跑协议。
pub fn selftest(args: &[String]) -> Outcome {
    let with_query = args.iter().any(|a| a == "--with-query");
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("无法定位自身可执行文件，selftest 不能启动子进程: {e}"),
                Vec::new(),
            );
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    let mut child = match Command::new(&exe)
        .current_dir(&cwd)
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                "BLOCKED".to_string(),
                format!("cannot spawn mcp serve: {e}"),
                Vec::new(),
            );
        }
    };
    let Some(stdin) = child.stdin.take() else {
        return (
            "BLOCKED".to_string(),
            "子进程没有 stdin 管道".to_string(),
            Vec::new(),
        );
    };
    let Some(stdout) = child.stdout.take() else {
        return (
            "BLOCKED".to_string(),
            "子进程没有 stdout 管道".to_string(),
            Vec::new(),
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

    // 2) notifications/initialized（无 id，不该有回复）
    if failure.is_none() {
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        let ok = write_frame(&mut writer, &note).is_ok();
        probes.push(Probe {
            name: "notification_accepted_silently",
            ok,
            detail: "notification 不应产生回复".to_string(),
        });
    }

    // 3) tools/list
    if failure.is_none() {
        let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
        match drive(&mut writer, &rx, &list, Duration::from_secs(10)) {
            Ok(response) => {
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

    // 6) 按名请求写能力工具必须被拒（负向清单的真正落点）
    if failure.is_none() {
        let bad = json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
            "name":"workspace/applyEdit","arguments":{"target":"x","workspace":"."}
        }});
        match drive(&mut writer, &rx, &bad, Duration::from_secs(10)) {
            Ok(response) => {
                let rejected = response.get("error").is_some();
                probes.push(Probe {
                    name: "write_call_rejected",
                    ok: rejected,
                    detail: format!("实得 {}", response["error"]["code"]),
                });
                if !rejected {
                    failure = Some("写能力工具调用未被拒绝".to_string());
                }
            }
            Err(e) => {
                failure = Some(format!("写能力拒绝探测失败：{e}"));
                probes.push(Probe {
                    name: "write_call_rejected",
                    ok: false,
                    detail: e,
                });
            }
        }
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

/// CLI 派发：`mcp serve` / `mcp selftest [--with-query]`。
/// 未知子命令**不启动任何东西**直接 BLOCKED —— 与 `code` 的"参数错误先于子进程"同一规则。
pub fn dispatch(args: &[String]) -> Outcome {
    match args.first().map(String::as_str).unwrap_or("") {
        "serve" => serve(),
        "selftest" => selftest(&args[1..]),
        other => (
            "BLOCKED".to_string(),
            format!("supported mcp subcommands: serve, selftest [--with-query]（收到：{other}）"),
            Vec::new(),
        ),
    }
}

/// selftest 的 snapshot 绑定：与 `code`/`context` 用同一套 `Bindings`。
/// 仓库发现失败时留空串而**不是**编一个值 —— 场景断言 `snapshot.source_revision` 非空，
/// 于是"没绑定"会表现为场景变红，而不是被静默吞掉。
fn cli_snapshot() -> Value {
    match crate::env::Repo::discover() {
        Ok(repo) => crate::evidence::Bindings::current(&repo).to_json(),
        Err(e) => json!({"source_revision": "", "working_tree_digest": "", "error": e}),
    }
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
    #[test]
    fn forbidden_tool_names_are_refused_not_executed() {
        for name in FORBIDDEN_TOOLS {
            let err = build_argv(name, Some(&json!({"target": "Egress", "workspace": "."})))
                .expect_err("{name} 不是只读工具，必须被拒");
            assert_eq!(err.0, ERR_INVALID_PARAMS, "{name} → {err:?}");
        }
        // 未知工具名同样拒，不"当作符号查一次"。
        assert!(
            build_argv(
                "code.teleport",
                Some(&json!({"target": "x", "workspace": "."}))
            )
            .is_err()
        );
    }

    /// `initialize` 只声明 tools 能力。声明 workspace/completion/logging 之类
    /// 就等于对外承诺本适配器有那些面 —— 契约不能靠"反正客户端不用"糊过去。
    #[test]
    fn initialize_declares_only_tools_capability() {
        let response = handle_request(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            &mut None,
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
            )
            .is_none(),
            "notification 不该产生回复"
        );
        let unknown = handle_request(
            &json!({"jsonrpc":"2.0","id":7,"method":"nexus/not-a-method","params":{}}),
            &mut None,
        )
        .expect("带 id 的请求必须有回复");
        assert_eq!(unknown["error"]["code"], json!(ERR_METHOD_NOT_FOUND));
        // 缺 jsonrpc 版本 = 无效请求，不能当合法请求处理。
        for bad in [
            json!({"id": 8, "method": "tools/list"}),
            json!({"jsonrpc": "1.0", "id": 9, "method": "tools/list"}),
        ] {
            let response = handle_request(&bad, &mut None).expect("必须有回复");
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
}
