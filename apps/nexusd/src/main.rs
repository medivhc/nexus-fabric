#![forbid(unsafe_code)]

use std::process::ExitCode;

use serde_json::{Value, json};

/// nexusd：桌面/服务端主 Runtime Composition Root。
///
/// 用法：
///   nexusd run <service|internet-access|compute> [--json]          -> 进程内组合根闭环
///   nexusd run <resource> --endpoint <ip:port> [--relay <ip:port>]
///              [--direct <ip:port>] [--token <t>] --json            -> 真实网络访问（real transport）
///   nexusd host <service|internet-access|compute> --addr <ip:port>
///              [--token <t>]                                       -> 提供方：服务端 AUTH 门控 + 业务
///   nexusd relay --addr <ip:port>                                  -> 真实 relay：DIAL + 字节中继
///   nexusd proxy --addr <ip:port> [--config <path>]                -> 真实 SOCKS5 数据面
///   nexusd run <unknown> --json            -> 结构化拒绝（UNKNOWN_RESOURCE，exit 0）
///   nexusd status --json                   -> §9 可观察性总览
///   nexusd dns status --json / dns cache --json / dns resolve --json / dns providers --json
///   nexusd session watch --json
///   nexusd connectivity status --json / candidates --json / probe --json / links --json
///   nexusd plan explain --json
///   nexusd platform capabilities --json
///   nexusd <workspace|compute|diagnose> ... --json
///                                          -> 领域未就绪：UNSUPPORTED（exit 0）
///
/// 语义：本 app 只承担 CLI 解析与装配（MODULE.md 冻结契约）；全部闭环与快照复用
/// `nexus` SDK 组合根函数，不复制领域逻辑。无效 CLI 用法 exit 非 0。
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run_resource(&args[1..]),
        Some("serve") => serve_resource(&args[1..]),
        Some("host") => host_resource(&args[1..]),
        Some("relay") => relay_resource(&args[1..]),
        Some("proxy") => proxy_resource(&args[1..]),
        // §9 可观察性子命令：首个 token 命中即路由（透传完整命令，含 verb）。
        Some(verb) if is_observability_verb(verb) => dispatch_observability(&args),
        _ => {
            eprintln!(
                "usage: nexusd run <service|internet-access|compute> [--json] | \
                 nexusd run <resource> --endpoint <ip:port> [--relay <ip:port>] [--direct <ip:port>] [--token <t>] --json | \
                 nexusd serve --addr <ip:port> | \
                 nexusd host <resource> --addr <ip:port> [--token <t>] | \
                 nexusd relay --addr <ip:port> | \
                 nexusd proxy --addr <ip:port> [--config <path>] | \
                 <status|dns|session|connectivity|plan|platform> ... --json"
            );
            ExitCode::FAILURE
        }
    }
}

/// 可观察性子命令首 token（PRODUCT §9）。
fn is_observability_verb(verb: &str) -> bool {
    matches!(
        verb,
        "status"
            | "dns"
            | "session"
            | "connectivity"
            | "plan"
            | "platform"
            | "workspace"
            | "compute"
            | "diagnose"
    )
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

/// 路由 §9 可观察性子命令到 SDK `observability` 模块。
fn dispatch_observability(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["status", "--json"] => nexus::observability::status(),
        ["dns", "status", "--json"] => nexus::observability::dns_status(),
        ["dns", "cache", "--json"] => nexus::observability::dns_cache(),
        ["dns", "resolve", "--json"] => nexus::observability::dns_resolve(),
        ["dns", "providers", "--json"] => nexus::observability::dns_providers(),
        ["session", "watch", "--json"] => nexus::observability::session_watch(),
        ["connectivity", "status", "--json"] => nexus::observability::connectivity_status(),
        ["connectivity", "candidates", "--json"] => nexus::observability::connectivity_candidates(),
        ["connectivity", "probe", "--json"] => nexus::observability::connectivity_probe(),
        ["connectivity", "links", "--json"] => nexus::observability::connectivity_links(),
        ["plan", "explain", "--json"] => nexus::observability::plan_explain(),
        ["platform", "capabilities", "--json"] => nexus::observability::platform_capabilities(),
        ["workspace", "heads", "--json"] => nexus::observability::workspace_heads(),
        ["workspace", "conflicts", "--json"] => nexus::observability::workspace_conflicts(),
        ["workspace", "cache", "--json"] => nexus::observability::workspace_cache(),
        ["compute", "jobs", "--json"] => nexus::observability::compute_jobs(),
        ["diagnose", "--json"] => nexus::observability::diagnose(),
        // 领域未就绪命令：显式 UNSUPPORTED（禁止静默降级，exit 0 = 请求已被处理）。
        cmd => {
            let name = cmd
                .iter()
                .take_while(|s| **s != "--json")
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"command\":\"{name}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    print_json_result(result.map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())))
}

/// 路由资源名到 SDK 组合根闭环；带 `--endpoint` 时走真实网络访问（real transport）。
fn run_resource(args: &[String]) -> ExitCode {
    let Some(resource) = args.first() else {
        eprintln!(
            "usage: nexusd run <service|internet-access|compute> [--endpoint <ip:port>] [--relay <ip:port>] [--token <t>] [--json]"
        );
        return ExitCode::FAILURE;
    };
    let flags = parse_flags(args);
    let result: Result<Value, (String, String)> = match flags
        .get("--endpoint")
        .and_then(|v| v.as_deref())
    {
        Some(endpoint) => {
            let endpoint: std::net::SocketAddr = match endpoint.parse() {
                Ok(a) => a,
                Err(_) => {
                    println!(
                        "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid endpoint {endpoint}\"}}}}"
                    );
                    return ExitCode::SUCCESS;
                }
            };
            let token = flags
                .get("--token")
                .and_then(|v| v.as_deref())
                .unwrap_or("nexus-preshared-token")
                .to_string();
            match flags.get("--relay").and_then(|v| v.as_deref()) {
                Some(relay) => {
                    let relay: std::net::SocketAddr = match relay.parse() {
                        Ok(a) => a,
                        Err(_) => {
                            println!(
                                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid relay {relay}\"}}}}"
                            );
                            return ExitCode::SUCCESS;
                        }
                    };
                    // 直连候选：默认等于 endpoint；真实 NAT 场景下候选与 relay 可达地址不同。
                    let direct: std::net::SocketAddr = match flags
                        .get("--direct")
                        .and_then(|v| v.as_deref())
                    {
                        Some(raw) => match raw.parse() {
                            Ok(a) => a,
                            Err(_) => {
                                println!(
                                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid direct {raw}\"}}}}"
                                );
                                return ExitCode::SUCCESS;
                            }
                        },
                        None => endpoint,
                    };
                    nexus::remote_real_flow_with_relay(&direct, &endpoint, &relay, &token, resource)
                        .map(|v| enrich("real-transport", v))
                        .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string()))
                }
                None => nexus::remote_real_flow(&endpoint, &token, resource)
                    .map(|v| enrich("real-transport", v))
                    .map_err(|e| (nexus::error_code(&e).to_string(), e.to_string())),
            }
        }
        None => match resource.as_str() {
            "service" => nexus::remote_service_access_flow()
                .map(|v| enrich("service", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            "internet-access" => nexus::remote_internet_access_flow()
                .map(|v| enrich("internet-access", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            "compute" => nexus::remote_compute_job_flow()
                .map(|v| enrich("compute", v))
                .map_err(|e| ("INTERNAL".to_string(), e.to_string())),
            other => {
                // 未知资源：结构化拒绝（exit 0 = 请求已被 daemon 处理，拒绝也是处理结果）。
                println!(
                    "{{\"verdict\":\"REJECTED\",\"error\":{{\"code\":\"UNKNOWN_RESOURCE\",\"resource\":\"{other}\"}},\"daemon\":{{\"entry\":\"nexusd\"}}}}"
                );
                return ExitCode::SUCCESS;
            }
        },
    };
    print_json_result(result)
}

/// serve 子命令：常驻 daemon，提供 HTTP LocalAPI，CLI 通过 socket 查询状态。
///
/// 用法：nexusd serve --addr <ip:port>
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
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return ExitCode::SUCCESS;
            }
        },
        None => match "127.0.0.1:0".parse() {
            Ok(a) => a,
            Err(_) => return ExitCode::FAILURE,
        },
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

/// 处理单个 LocalAPI HTTP 请求：读请求行，路由，写 JSON 响应。
fn handle_localapi_request(stream: &mut std::net::TcpStream) -> Result<(), String> {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    // 读请求行（GET /localapi/v0/status HTTP/1.1）
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read request line: {e}"))?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        write_http_json(
            stream,
            405,
            &json!({"verdict":"FAIL","error":{"code":"METHOD_NOT_ALLOWED"}}),
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let path = parts[1];
    // 路由
    let result: Result<Value, (String, String)> = match path {
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

/// 写一个 JSON HTTP 响应。
fn write_http_json(
    stream: &mut std::net::TcpStream,
    status: u16,
    body: &Value,
) -> Result<(), std::io::Error> {
    use std::io::Write;
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
    Ok(())
}

/// 提供方入口：真实地址持续监听，服务端 AUTH 门控 + 按资源执行业务（服务循环）。
fn host_resource(args: &[String]) -> ExitCode {
    let Some(resource) = args.first() else {
        eprintln!(
            "usage: nexusd host <service|internet-access|compute> --addr <ip:port> [--token <t>]"
        );
        return ExitCode::FAILURE;
    };
    let flags = parse_flags(args);
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return ExitCode::SUCCESS;
            }
        },
        None => match "127.0.0.1:8787".parse() {
            Ok(a) => a,
            Err(_) => return ExitCode::FAILURE,
        },
    };
    let token = flags
        .get("--token")
        .and_then(|v| v.as_deref())
        .unwrap_or("nexus-preshared-token")
        .to_string();
    let listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"bind {addr} failed: {e}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"host\",\"resource\":\"{resource}\",\"addr\":\"{addr}\"}}}}"
    );
    // 服务循环：逐连接 accept，每连接独立 AUTH 门控 + 业务闭环
    // （SDK serve_loop 打印每连接结果；认证拒绝输出 AUTH_DENIED 后继续服务）。
    if let Err(e) = nexus::remote_host_serve_loop(&listener, &token, resource) {
        println!(
            "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// relay 入口：真实监听，DIAL + 双向字节中继（单会话）。
fn relay_resource(args: &[String]) -> ExitCode {
    let flags = parse_flags(args);
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return ExitCode::SUCCESS;
            }
        },
        None => match "127.0.0.1:8788".parse() {
            Ok(a) => a,
            Err(_) => return ExitCode::FAILURE,
        },
    };
    let result: Result<Value, (String, String)> = (|| {
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|e| ("INTERNAL".to_string(), format!("bind {addr} failed: {e}")))?;
        nexus::relay_serve_once(&listener).map_err(|e| ("INTERNAL".to_string(), e.to_string()))
    })();
    print_json_result(result.map(|v| {
        let mut json = v;
        if let Some(obj) = json.as_object_mut() {
            obj.insert(
                "daemon".into(),
                serde_json::json!({
                    "entry": "nexusd",
                    "command": "relay",
                    "addr": addr.to_string(),
                }),
            );
        }
        json
    }))
}

/// 真实 SOCKS5 数据面入口：监听后逐会话完成握手 → 规则路由 → Session →
/// 真实出站 → 字节中继；每会话输出一条结构化 JSON（Ctrl-C 停止）。
fn proxy_resource(args: &[String]) -> ExitCode {
    // 节点测速子命令（PRODUCT §11.10）：loopback 自检真实 TcpLatencyProbe。
    if args.first().map(|a| a.as_str()) == Some("speedtest") {
        match nexus::proxy_speedtest() {
            Ok(json) => println!("{json}"),
            Err(e) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            ),
        }
        return ExitCode::SUCCESS;
    }
    let flags = parse_flags(args);
    let addr: std::net::SocketAddr = match flags.get("--addr").and_then(|v| v.as_deref()) {
        Some(raw) => match raw.parse() {
            Ok(a) => a,
            Err(_) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid addr {raw}\"}}}}"
                );
                return ExitCode::SUCCESS;
            }
        },
        None => match "127.0.0.1:1080".parse() {
            Ok(a) => a,
            Err(_) => return ExitCode::FAILURE,
        },
    };
    let config_yaml = match flags.get("--config").and_then(|v| v.as_deref()) {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"read config {path} failed: {e}\"}}}}"
                );
                return ExitCode::SUCCESS;
            }
        },
        None => nexus::DEFAULT_PROXY_CONFIG.to_string(),
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
    println!(
        "{{\"verdict\":\"READY\",\"daemon\":{{\"entry\":\"nexusd\",\"command\":\"proxy\",\"addr\":\"{addr}\"}}}}"
    );
    // 服务循环：逐会话阻塞 accept；每会话独立闭环（结构化并发：会话内线程 join）。
    loop {
        match nexus::proxy_serve_once(&listener, &config_yaml) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
                );
            }
        }
    }
}

/// 在 SDK 输出的 JSON 对象上附加 daemon 入口元数据（场景断言 daemon.entry / daemon.resource）。
fn enrich(resource: &str, mut json: Value) -> Value {
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "daemon".into(),
            serde_json::json!({ "entry": "nexusd", "resource": resource }),
        );
    }
    json
}

/// 输出结构化 JSON；无论成功/失败均 exit 0（请求已被 daemon 处理）。
fn print_json_result(result: Result<Value, (String, String)>) -> ExitCode {
    match result {
        Ok(json) => {
            println!("{json}");
        }
        Err((code, message)) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}"
            );
        }
    }
    ExitCode::SUCCESS
}
