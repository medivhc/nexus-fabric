#![forbid(unsafe_code)]

use std::process::ExitCode;

use serde_json::{Value, json};

/// nexusd：桌面/服务端主 Runtime Composition Root（内部 daemon 入口）。
///
/// 用法：
///   nexusd serve [--addr <ip:port> | --socket <path>]  -> 常驻 daemon，提供 HTTP LocalAPI
///
/// 用户命令已统一迁移到 `nexus`（refactor: CLI 统一，见 v9 规范"正式 CLI 是 `nexus`"）：
///   nexus proxy ...         <- 原 nexusd proxy
///   nexus proxy run/host/relay ... <- 原 nexusd run/host/relay
///   nexus system-proxy ...  <- 原 nexusd system-proxy
///   nexus autostart ...     <- 原 nexusd autostart
///   nexus status/dns/...    <- 瘦客户端（需 daemon 运行）
///
/// 语义：本 app 只承担 CLI 解析与装配（MODULE.md 冻结契约）；全部闭环与快照复用
/// `nexus` SDK 组合根函数，不复制领域逻辑。无效 CLI 用法 exit 非 0。
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve_resource(&args[1..]),
        _ => {
            eprintln!(
                "usage: nexusd serve [--addr <ip:port> | --socket <path>]\n\
                 \n\
                 用户命令已迁移到 `nexus`：\n\
                 \x20 nexus proxy [--addr <ip:port>] [--config <path>] [--tun]\n\
                 \x20 nexus proxy speedtest\n\
                 \x20 nexus proxy run|host|relay ...\n\
                 \x20 nexus system-proxy <status|set|clear|e2e>\n\
                 \x20 nexus autostart <install|remove|status>"
            );
            ExitCode::from(2)
        }
    }
}

/// 解析 `--flag <value>` / `--flag`（布尔）形式；非 flag token 忽略。
fn parse_flags(args: &[String]) -> std::collections::HashMap<String, Option<String>> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            if let Some(value) = args.get(i + 1).filter(|v| !v.starts_with("--")) {
                map.insert(arg.clone(), Some(value.clone()));
                i += 2;
                continue;
            }
            map.insert(arg.clone(), None);
        }
        i += 1;
    }
    map
}

/// serve 子命令：常驻 daemon，提供 HTTP LocalAPI，CLI 通过 socket 查询状态。
///
/// 用法：
///   nexusd serve --addr <ip:port>      -> TCP loopback（默认 127.0.0.1:0）
///   nexusd serve --socket <path>       -> 平台 socket（Unix: Unix domain socket；
///                                         Windows: named pipe，当前未实现 -> UNSUPPORTED）
///
/// 优先级：`--addr` 显式给出时走 TCP（即便同时给了 `--socket`）；仅给 `--socket`
/// 时走 socket；二者都不给时走 TCP 默认。
///
/// 路由：
///   GET /localapi/v0/status             → 总览快照
///   GET /localapi/v0/dns/status         → DNS 状态
///   GET /localapi/v0/dns/cache          → DNS 正/负缓存
///   GET /localapi/v0/session/watch      → Session 双轨状态
///   GET /localapi/v0/plan/explain       → Plan + DecisionTrace
///   GET /localapi/v0/connectivity/status → 建连状态
///   GET /localapi/v0/platform/capabilities → 平台能力
fn serve_resource(args: &[String]) -> ExitCode {
    let flags = parse_flags(args);
    // --addr 显式优先；否则 --socket；否则 TCP 默认。
    match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => serve_over_tcp(raw),
        None => match flags.get("--socket").and_then(|v| v.as_deref()) {
            Some(path) => serve_over_socket(path),
            None => serve_over_tcp("127.0.0.1:0"),
        },
    }
}

/// TCP loopback 监听 + 服务循环（既有行为，READY 报告 `addr`）。
fn serve_over_tcp(addr_raw: &str) -> ExitCode {
    let addr: std::net::SocketAddr = match addr_raw.parse() {
        Ok(a) => a,
        Err(_) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {addr_raw}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind {addr} failed: {e}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    let actual_addr = listener.local_addr().expect("local_addr");
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"addr\":\"{actual_addr}\"}}}}"
    );
    // 服务循环：逐连接 accept，解析 HTTP 请求行，路由到 observability 函数。
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(e) = handle_localapi_request(&mut stream) {
                    eprintln!("serve connection error: {e}");
                }
            }
            Err(e) => {
                eprintln!("serve accept error: {e}");
                break;
            }
        }
    }
    ExitCode::SUCCESS
}

/// Unix domain socket 监听 + 服务循环（READY 报告 `socket` 路径）。
#[cfg(unix)]
fn serve_over_socket(path: &str) -> ExitCode {
    use std::os::unix::net::UnixListener;
    // 幂等清理可能残留的同名 socket 文件（崩溃后重启）。
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind socket {path} failed: {e}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"serve\",\"socket\":\"{path}\"}}}}"
    );
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(e) = handle_localapi_request(&mut stream) {
                    eprintln!("serve connection error: {e}");
                }
            }
            Err(e) => {
                eprintln!("serve accept error: {e}");
                break;
            }
        }
    }
    ExitCode::SUCCESS
}

/// Windows named-pipe 监听：当前未实现。
///
/// std 不提供 named-pipe server；按 AGENTS.md §11/§18，平台专有 I/O 应收敛到
/// `nexus-platform-windows`（集中 `unsafe` + 每处 Safety Invariant），经 capability
/// adapter 注入，而非在 composition root 里散落 Win32 FFI。当前先按 PRODUCT §9
/// 「领域未就绪」模式显式返回 UNSUPPORTED，不静默降级；`--addr` TCP loopback 仍可用。
#[cfg(windows)]
fn serve_over_socket(path: &str) -> ExitCode {
    let pipe = derive_named_pipe_name(path);
    println!(
        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"message\":\"named-pipe transport not yet implemented on Windows (would listen at {pipe}); use --addr TCP loopback\"}}}}"
    );
    ExitCode::SUCCESS
}

/// 把 `--socket <path>` 推导为 Windows named pipe 全名（`\\.\pipe\<name>`）。
/// 路径中的目录分隔符与 `.` 段被剥离，只保留最后一个文件名段作为 pipe 名。
#[cfg(windows)]
fn derive_named_pipe_name(path: &str) -> String {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("nexusd");
    format!(r"\\.\pipe\{name}")
}

/// 已接受连接的双向字节流抽象（TCP / Unix domain socket 统一）。
///
/// Rust 不允许 `dyn Read + Write` 这种多 trait 对象组合，故定义一个空 marker trait
/// 同时继承二者；TcpStream / UnixStream 经 blanket impl 自动满足。
trait LocalIo: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> LocalIo for T {}

/// 处理单个 LocalAPI HTTP 请求：读请求行，路由，写 JSON 响应。
///
/// 流类型抽象为 `&mut dyn LocalIo`，使同一 HTTP 处理逻辑同时服务于
/// TCP 与 Unix domain socket 连接（Windows named pipe 落地后亦复用）。
fn handle_localapi_request(stream: &mut dyn LocalIo) -> Result<(), String> {
    use std::io::BufRead;
    // 读请求行（GET /localapi/v0/status HTTP/1.1）。BufReader 仅在块内借用 stream，
    // 出块即释放可变借用，随后可直接写响应。
    let request_line: String = {
        let mut reader = std::io::BufReader::new(&mut *stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read request line: {e}"))?;
        line
    };
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        write_http_json(
            &mut *stream,
            405,
            &json!({"verdict":"FAIL","error":{"code":"METHOD_NOT_ALLOWED"}}),
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let path = parts[1].to_string();
    // 路由
    let result: Result<Value, (String, String)> = match path.as_str() {
        "/localapi/v0/status" => nexus::observability::status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/dns/status" => nexus::observability::dns_status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/dns/cache" => nexus::observability::dns_cache()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/session/watch" => nexus::observability::session_watch()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/plan/explain" => nexus::observability::plan_explain()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/connectivity/status" => nexus::observability::connectivity_status()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        "/localapi/v0/platform/capabilities" => nexus::observability::platform_capabilities()
            .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
        _ => {
            write_http_json(
                stream,
                404,
                &json!({"verdict":"FAIL","error":{"code":"NOT_FOUND","path":path}}),
            )
            .map_err(|e| e.to_string())?;
            return Ok(());
        }
    };
    let body = match result {
        Ok(v) => v,
        Err((code, msg)) => json!({"verdict":"FAIL","error":{"code":code,"message":msg}}),
    };
    write_http_json(stream, 200, &body).map_err(|e| e.to_string())?;
    Ok(())
}

/// 写一个 JSON HTTP 响应（流类型抽象为 `&mut dyn Write`）。
fn write_http_json(
    stream: &mut dyn std::io::Write,
    status: u16,
    body: &Value,
) -> Result<(), std::io::Error> {
    let body_str = serde_json::to_string(body)?;
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// 把 `SystemProxyState` 转成 JSON（cfg(windows) 实现类型可见）。
#[cfg(windows)]
fn proxy_state_json(s: &nexus_platform::SystemProxyState) -> Value {
    json!({"enabled": s.enabled, "server": s.server})
}
