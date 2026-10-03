//! nexusd serve LocalAPI thin HTTP client（nexus CLI 瘦客户端层）。
//!
//! CLI 不再在进程内装配 SDK 来回答 §9 观察命令；而是通过 LocalAPI 向
//! `nexusd serve` 发起最小 HTTP/1.1 GET，把 daemon 返回的 JSON 原文渲染出来。
//!
//! 传输（D8，N2 P0-1）：默认 unix socket（`default_socket_path`）；`--addr`
//! 切到 TCP loopback。两种传输都要求 bearer token 鉴权
//!（`Authorization: Bearer <token>`，token 由 daemon/CLI 共享
//! `token_file_path`，0600）。
//!
//! 职责：
//! - 把 [`ControlCommand`] 映射到 daemon LocalAPI 路由（无路由则本地合成 UNSUPPORTED）；
//! - 建连（unix socket / TCP）、发请求、读响应、按 `Content-Length` 切出 body；
//! - 连接失败 / 坏响应 → 类型化 [`ClientError`]，由 main 层映射为结构化 FAIL JSON。
//!
//! 不做：不解析业务 JSON 语义（verdict/error 由 daemon 决定），不重试，不做 TLS。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use nexus_control_api::ControlCommand;
use serde_json::Value;

/// 默认 daemon LocalAPI TCP 地址（`--addr` 未指定且显式要求 TCP 时）。
pub const DEFAULT_LOCALAPI_ADDR: &str = "127.0.0.1:18080";

/// 客户端超时：daemon 在本机上立即应答；挂起视为异常，避免无限等待。
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// LocalAPI 传输目标（D8：默认 unix socket）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalApiTarget {
    /// unix socket（默认）。
    Socket(PathBuf),
    /// TCP（`--addr <ip:port>` 显式指定）。
    Tcp(String),
}

/// 默认 unix socket 路径：`$XDG_RUNTIME_DIR/nexus-localapi.sock`，
/// 未设置时退到 `temp_dir()/nexus-localapi.sock`。
/// 注意与 `nexusd serve`（无 `--addr`/`--socket` 时）保持一致。
#[must_use]
pub fn default_socket_path() -> PathBuf {
    runtime_socket_path().unwrap_or_else(|| std::env::temp_dir().join("nexus-localapi.sock"))
}

/// 只在 `$XDG_RUNTIME_DIR` 已设置时给出 unix socket 路径（P1-15）。
///
/// **daemon 侧必须用这个**：未设置 `XDG_RUNTIME_DIR` 时回落到
/// `temp_dir()/nexus-localapi.sock` 是可预测＋世界可写的路径——同机其他用户
/// 可以抢占或替换该路径（socket 劫持）。daemon 因此拒绝该回退，改用 TCP
/// loopback 并告警（见 `nexusd serve`）；bearer token 是剩下的唯一屏障。
#[must_use]
pub fn runtime_socket_path() -> Option<PathBuf> {
    runtime_socket_path_in(std::env::var_os("XDG_RUNTIME_DIR"))
}

/// [`runtime_socket_path`] 的纯函数内核（`xdg = $XDG_RUNTIME_DIR` 的取值）。
///
/// 未设置 / 空串 → `None`（调用方必须拒绝可预测的 `/tmp` 回落）。
#[must_use]
pub fn runtime_socket_path_in(xdg: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let rt = xdg?;
    if rt.is_empty() {
        return None;
    }
    Some(PathBuf::from(rt).join("nexus-localapi.sock"))
}

/// 默认传输目标（unix 上为 socket；Windows 上 named pipe 未实现，退 TCP）。
#[must_use]
pub fn default_target() -> LocalApiTarget {
    #[cfg(unix)]
    {
        LocalApiTarget::Socket(default_socket_path())
    }
    #[cfg(not(unix))]
    {
        LocalApiTarget::Tcp(DEFAULT_LOCALAPI_ADDR.to_string())
    }
}

/// bearer token 文件路径（daemon 与 CLI 共享；0600）。
///
/// `NEXUS_LOCALAPI_TOKEN_FILE` 可覆盖（测试用）。
#[must_use]
pub fn token_file_path() -> PathBuf {
    if let Some(p) = std::env::var_os("NEXUS_LOCALAPI_TOKEN_FILE") {
        return PathBuf::from(p);
    }
    crate::node_cli::node_dir().join("localapi.token")
}

/// 读取 bearer token；不存在则生成（32 随机字节 hex）并 0600 落盘。
///
/// daemon `serve` 的三种形态（tcp/socket/后台线程）与 CLI 共用此函数，
/// 保证同一用户下的两端 token 一致。
pub fn load_or_create_bearer_token() -> Result<String, String> {
    let path = token_file_path();
    match std::fs::read(&path) {
        Ok(bytes) if !bytes.is_empty() => {
            let token = String::from_utf8(bytes)
                .map_err(|e| format!("token file {} is not utf-8: {e}", path.display()))?;
            let token = token.trim().to_string();
            if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
                Ok(token)
            } else {
                Err(format!(
                    "token file {} corrupt (delete it to regenerate)",
                    path.display()
                ))
            }
        }
        Ok(_) => Err(format!("token file {} is empty", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_bearer_token(&path),
        Err(e) => Err(format!("read token file {}: {e}", path.display())),
    }
}

/// 生成 32 随机字节 hex token 并 0600 落盘。
fn create_bearer_token(path: &std::path::Path) -> Result<String, String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| format!("getrandom for bearer token: {e}"))?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create token dir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, token.as_bytes())
        .map_err(|e| format!("write token file {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    Ok(token)
}

/// 客户端侧错误（可恢复：daemon 没起 / 协议异常；main 层转成结构化 FAIL JSON）。
#[derive(Debug)]
pub enum ClientError {
    /// 建连失败（daemon 未运行 / addr 错误 / socket 文件不存在）。
    Unreachable(String),
    /// daemon 返回了无法解析的 HTTP 响应。
    BadResponse(String),
    /// 本地 bearer token 不可用（文件损坏等；先修 token 再重试）。
    TokenUnavailable(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unreachable(msg) => write!(f, "daemon unreachable: {msg}"),
            ClientError::BadResponse(msg) => write!(f, "bad daemon response: {msg}"),
            ClientError::TokenUnavailable(msg) => write!(f, "bearer token unavailable: {msg}"),
        }
    }
}

/// 把 [`ControlCommand`] 映射到 daemon LocalAPI 路由路径。
///
/// 返回 `None` 表示 daemon 尚未提供该路由（CLI 本地合成 UNSUPPORTED），或该命令
/// 不走 LocalAPI（`Run` 仍走进程内 SDK 路径）。
///
/// N2 P0-1 bugfix：带位置参数的命令（`SessionWatch`/`PlanExplain`）不再走静态路由
/// 丢参数，改走 [`route_for_dynamic`]（query string）。
#[must_use]
pub fn route_for(command: &ControlCommand) -> Option<&'static str> {
    match command {
        ControlCommand::Status => Some("/localapi/v0/status"),
        ControlCommand::DnsStatus => Some("/localapi/v0/dns/status"),
        ControlCommand::DnsCache => Some("/localapi/v0/dns/cache"),
        ControlCommand::ConnectivityStatus => Some("/localapi/v0/connectivity/status"),
        ControlCommand::PlatformCapabilities => Some("/localapi/v0/platform/capabilities"),
        // 带参数命令走动态路由（query string），静态路由无。
        ControlCommand::SessionWatch { .. }
        | ControlCommand::PlanExplain { .. }
        | ControlCommand::WorkspaceCommit { .. } => None,
        // 以下命令 daemon 暂无 LocalAPI 路由：
        ControlCommand::ConnectivityCandidates
        | ControlCommand::ConnectivityProbe { .. }
        | ControlCommand::ConnectivityLinks
        | ControlCommand::DnsResolve { .. }
        | ControlCommand::DnsProviders
        | ControlCommand::WorkspaceHeads { .. }
        | ControlCommand::WorkspaceConflicts { .. }
        | ControlCommand::WorkspaceCache { .. }
        | ControlCommand::ComputeJobs
        | ControlCommand::Diagnose => None,
        // Run 保持进程内 SDK 路径（LocalAPI 无对应路由）。
        ControlCommand::Run { .. } => None,
        // N1 装配命令由 CLI 进程内 Composition Root 直接执行（M6；无 daemon 路由）。
        ControlCommand::NetworkUp { .. } | ControlCommand::NetworkStatus => None,
    }
}

/// query 参数值编码（RFC 3986 unreserved 原样，其余 `%XX` 大写）。
fn pct_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit(u32::from(b >> 4), 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit(u32::from(b & 0x0f), 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

/// 把 [`ControlCommand`] 映射到 daemon LocalAPI 路由路径（动态路径段 / query 版本）。
///
/// `route_for` 只能表达静态路径；带位置参数的命令走这个函数：
/// - `workspace commit <id>` → 路径段 `/localapi/v0/workspace/commit/<id>`；
/// - `session watch <id>` → `/localapi/v0/session/watch?session=<id>`；
/// - `plan explain <resource>` → `/localapi/v0/plan/explain?resource=<name>`。
///
/// 返回 `None` 表示该命令无动态路由。
#[must_use]
pub fn route_for_dynamic(command: &ControlCommand) -> Option<String> {
    match command {
        ControlCommand::WorkspaceCommit { workspace } => Some(format!(
            "/localapi/v0/workspace/commit/{}",
            pct_encode(workspace)
        )),
        ControlCommand::SessionWatch { session } => Some(format!(
            "/localapi/v0/session/watch?session={}",
            pct_encode(&session.0)
        )),
        ControlCommand::PlanExplain { resource } => Some(format!(
            "/localapi/v0/plan/explain?resource={}",
            pct_encode(&resource.0)
        )),
        _ => None,
    }
}

/// 命令的人类可读名称（与 observability JSON 的 `command` 字段同形）。
#[must_use]
pub fn command_name(command: &ControlCommand) -> &'static str {
    match command {
        ControlCommand::Status => "status",
        ControlCommand::PlanExplain { .. } => "plan explain",
        ControlCommand::SessionWatch { .. } => "session watch",
        ControlCommand::ConnectivityStatus => "connectivity status",
        ControlCommand::ConnectivityCandidates => "connectivity candidates",
        ControlCommand::ConnectivityProbe { .. } => "connectivity probe",
        ControlCommand::ConnectivityLinks => "connectivity links",
        ControlCommand::DnsStatus => "dns status",
        ControlCommand::DnsResolve { .. } => "dns resolve",
        ControlCommand::DnsProviders => "dns providers",
        ControlCommand::DnsCache => "dns cache",
        ControlCommand::WorkspaceHeads { .. } => "workspace heads",
        ControlCommand::WorkspaceConflicts { .. } => "workspace conflicts",
        ControlCommand::WorkspaceCache { .. } => "workspace cache",
        ControlCommand::WorkspaceCommit { .. } => "workspace commit",
        ControlCommand::ComputeJobs => "compute jobs",
        ControlCommand::Diagnose => "diagnose",
        ControlCommand::PlatformCapabilities => "platform capabilities",
        ControlCommand::Run { .. } => "run",
        ControlCommand::NetworkUp { .. } => "network up",
        ControlCommand::NetworkStatus => "network status",
    }
}

/// 本地合成的 UNSUPPORTED FAIL JSON（与 nexusd `dispatch_observability` 兜底同形）。
///
/// 形状：`{"verdict":"FAIL","error":{"code":"UNSUPPORTED","command":"<name>"}}`。
/// 用于 daemon 尚未提供路由的命令——CLI 不回退到进程内 observability（PRODUCT §9 禁止静默降级）。
#[must_use]
pub fn unsupported_json(command: &ControlCommand) -> Value {
    serde_json::json!({
        "verdict": "FAIL",
        "error": {
            "code": "UNSUPPORTED",
            "command": command_name(command),
        },
    })
}

/// 连接失败时的结构化 FAIL JSON（机器消费者据此区分"daemon 没起"与"领域拒绝"）。
#[must_use]
pub fn unreachable_json(addr: &str, cause: &str) -> Value {
    serde_json::json!({
        "verdict": "FAIL",
        "error": {
            "code": "DAEMON_UNREACHABLE",
            "message": format!("cannot reach nexusd serve at {addr}: {cause}"),
        },
    })
}

/// daemon 返回非法 JSON body 时的结构化 FAIL JSON。
#[must_use]
pub fn bad_response_json(addr: &str, cause: &str) -> Value {
    serde_json::json!({
        "verdict": "FAIL",
        "error": {
            "code": "BAD_DAEMON_RESPONSE",
            "message": format!("nexusd serve at {addr} returned an invalid response: {cause}"),
        },
    })
}

/// 在 `target` 上发起一次 HTTP GET `path`，返回响应 body 字符串。
///
/// 两种传输都携带 `Authorization: Bearer <token>`（D8；daemon 无条件校验）。
/// daemon 使用最小 HTTP/1.1：发完响应即 `Connection: close`。这里读到 EOF 后按
/// `Content-Length` 切出精确 body（防止 keep-alive 残留；当前 daemon 总是 close）。
///
/// # Errors
///
/// - [`ClientError::Unreachable`]：建连失败（daemon 未运行 / socket 不存在）。
/// - [`ClientError::BadResponse`]：读写 / 编码 / 协议头解析失败。
/// - [`ClientError::TokenUnavailable`]：本地 bearer token 读不到或损坏。
pub fn http_get(target: &LocalApiTarget, path: &str) -> Result<String, ClientError> {
    let token = load_or_create_bearer_token().map_err(ClientError::TokenUnavailable)?;
    match target {
        LocalApiTarget::Tcp(addr) => {
            let mut stream = TcpStream::connect(addr)
                .map_err(|e| ClientError::Unreachable(format!("connect {addr}: {e}")))?;
            http_get_over(&mut stream, addr, path, &token)
        }
        #[cfg(unix)]
        LocalApiTarget::Socket(sock) => {
            use std::os::unix::net::UnixStream;
            let mut stream = UnixStream::connect(sock).map_err(|e| {
                ClientError::Unreachable(format!("connect socket {}: {e}", sock.display()))
            })?;
            let label = sock.display().to_string();
            http_get_over(&mut stream, &label, path, &token)
        }
        #[cfg(not(unix))]
        LocalApiTarget::Socket(_) => Err(ClientError::Unreachable(
            "unix socket transport not supported on this platform".to_string(),
        )),
    }
}

/// 经已建连的流完成一次带 bearer 鉴权的 GET（TCP / unix socket 共用）。
fn http_get_over(
    stream: &mut dyn StreamIo,
    host_label: &str,
    path: &str,
    token: &str,
) -> Result<String, ClientError> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| ClientError::BadResponse(format!("set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| ClientError::BadResponse(format!("set write timeout: {e}")))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_label}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| ClientError::BadResponse(format!("write request: {e}")))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| ClientError::BadResponse(format!("read response: {e}")))?;
    let raw = String::from_utf8(buf)
        .map_err(|e| ClientError::BadResponse(format!("response is not utf-8: {e}")))?;

    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| ClientError::BadResponse("missing header/body separator".to_string()))?;
    extract_body(headers, body)
}

/// `http_get_over` 的流抽象（`TcpStream` / `UnixStream` 统一）。
trait StreamIo: Read + Write {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

impl StreamIo for TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_write_timeout(self, dur)
    }
}

#[cfg(unix)]
impl StreamIo for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, dur)
    }
}

/// 从读到的 raw 响应里按 `Content-Length` 切出 body。
///
/// 没有 `Content-Length` 时直接返回整个 body（daemon 用 `Connection: close`，read_to_end
/// 已吃到 EOF，不存在 chunked 残留）。
fn extract_body(headers: &str, body: &str) -> Result<String, ClientError> {
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    match content_length {
        Some(len) => {
            if body.len() < len {
                return Err(ClientError::BadResponse(format!(
                    "truncated body: expected {len} bytes, got {}",
                    body.len()
                )));
            }
            Ok(body[..len].to_string())
        }
        None => Ok(body.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_control_api::{ResourceId, SessionId};

    #[test]
    fn five_static_routes_map_to_localapi_paths() {
        assert_eq!(
            route_for(&ControlCommand::Status),
            Some("/localapi/v0/status")
        );
        assert_eq!(
            route_for(&ControlCommand::DnsStatus),
            Some("/localapi/v0/dns/status")
        );
        assert_eq!(
            route_for(&ControlCommand::DnsCache),
            Some("/localapi/v0/dns/cache")
        );
        assert_eq!(
            route_for(&ControlCommand::ConnectivityStatus),
            Some("/localapi/v0/connectivity/status")
        );
        assert_eq!(
            route_for(&ControlCommand::PlatformCapabilities),
            Some("/localapi/v0/platform/capabilities")
        );
    }

    #[test]
    fn param_commands_use_dynamic_query_routes() {
        // N2 P0-1 bugfix：route_for 不再丢参数；参数经 query string 传递。
        let watch = ControlCommand::SessionWatch {
            session: SessionId("s1".into()),
        };
        assert_eq!(route_for(&watch), None);
        assert_eq!(
            route_for_dynamic(&watch),
            Some("/localapi/v0/session/watch?session=s1".to_string())
        );
        let explain = ControlCommand::PlanExplain {
            resource: ResourceId("dev-web".into()),
        };
        assert_eq!(route_for(&explain), None);
        assert_eq!(
            route_for_dynamic(&explain),
            Some("/localapi/v0/plan/explain?resource=dev-web".to_string())
        );
        // 参数值做 pct 编码。
        let weird = ControlCommand::SessionWatch {
            session: SessionId("a b/c".into()),
        };
        assert_eq!(
            route_for_dynamic(&weird),
            Some("/localapi/v0/session/watch?session=a%20b%2Fc".to_string())
        );
    }

    #[test]
    fn unsupported_commands_have_no_route() {
        for cmd in [
            ControlCommand::SessionWatch {
                session: SessionId("s1".into()),
            },
            ControlCommand::PlanExplain {
                resource: ResourceId("net".into()),
            },
            ControlCommand::ConnectivityCandidates,
            ControlCommand::ConnectivityProbe {
                target: "8.8.8.8".into(),
            },
            ControlCommand::ConnectivityLinks,
            ControlCommand::DnsResolve {
                name: "example.com".into(),
            },
            ControlCommand::DnsProviders,
            ControlCommand::WorkspaceHeads {
                workspace: "ws1".into(),
            },
            ControlCommand::WorkspaceConflicts {
                workspace: "ws1".into(),
            },
            ControlCommand::WorkspaceCache {
                workspace: "ws1".into(),
            },
            ControlCommand::WorkspaceCommit {
                workspace: "ws1".into(),
            },
            ControlCommand::ComputeJobs,
            ControlCommand::Diagnose,
        ] {
            assert!(route_for(&cmd).is_none(), "{cmd:?} should have no route");
        }
    }

    #[test]
    fn workspace_commit_has_dynamic_route() {
        // F12：CLI `nexus workspace commit <id>` 的动态路由映射（单元层；
        // 端到端走 E4 的 LocalAPI HTTP 路径）。
        assert_eq!(
            route_for_dynamic(&ControlCommand::WorkspaceCommit {
                workspace: "ws1".into()
            }),
            Some("/localapi/v0/workspace/commit/ws1".to_string())
        );
        assert_eq!(
            route_for(&ControlCommand::WorkspaceCommit {
                workspace: "ws1".into()
            }),
            None
        );
        assert_eq!(route_for_dynamic(&ControlCommand::Status), None);
    }

    #[test]
    fn run_has_no_route_stays_inprocess() {
        assert!(
            route_for(&ControlCommand::Run {
                resource: "x".into()
            })
            .is_none()
        );
    }

    #[test]
    fn unsupported_json_shape_matches_daemon_fallback() {
        let v = unsupported_json(&ControlCommand::DnsResolve {
            name: "example.com".into(),
        });
        assert_eq!(v["verdict"], "FAIL");
        assert_eq!(v["error"]["code"], "UNSUPPORTED");
        assert_eq!(v["error"]["command"], "dns resolve");
    }

    #[test]
    fn unreachable_json_carries_addr_and_cause() {
        let v = unreachable_json("127.0.0.1:18080", "connection refused");
        assert_eq!(v["verdict"], "FAIL");
        assert_eq!(v["error"]["code"], "DAEMON_UNREACHABLE");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("127.0.0.1:18080")
        );
    }

    #[test]
    fn extract_body_honors_content_length() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18";
        let body = r#"{"verdict":"PASS"}"#;
        assert_eq!(extract_body(headers, body).unwrap(), body);
    }

    #[test]
    fn extract_body_truncated_is_error() {
        let headers = "Content-Length: 100";
        let body = "short";
        assert!(extract_body(headers, body).is_err());
    }

    #[test]
    fn extract_body_without_length_returns_whole_body() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json";
        let body = r#"{"verdict":"PASS"}"#;
        assert_eq!(extract_body(headers, body).unwrap(), body);
    }

    #[test]
    fn connect_to_dead_port_is_unreachable() {
        // 0 端口 + 立即失败：选一个几乎不可能监听的高端口，connect 应立即拒绝。
        let target = LocalApiTarget::Tcp("127.0.0.1:1".to_string());
        let err = http_get(&target, "/localapi/v0/status").unwrap_err();
        assert!(
            matches!(err, ClientError::Unreachable(_)),
            "connect to closed port must be Unreachable, got {err:?}"
        );
    }

    #[test]
    fn bearer_token_create_and_reload_stable() {
        let dir = std::env::temp_dir().join(format!("nexus-token-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("localapi.token");
        let t1 = create_bearer_token(&file).unwrap();
        assert_eq!(t1.len(), 64);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
        // 经 load 路径重读：稳定不变。
        let t2 = std::fs::read_to_string(&file).unwrap();
        assert_eq!(t1, t2.trim());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_target_is_socket_on_unix() {
        #[cfg(unix)]
        assert!(matches!(default_target(), LocalApiTarget::Socket(_)));
        #[cfg(not(unix))]
        assert!(matches!(default_target(), LocalApiTarget::Tcp(_)));
    }

    #[test]
    fn runtime_socket_path_requires_xdg_runtime_dir() {
        // P1-15：daemon 不得回落到可预测的 /tmp 路径（可被同机他人抢占）。
        assert_eq!(runtime_socket_path_in(None), None);
        assert_eq!(
            runtime_socket_path_in(Some(std::ffi::OsString::new())),
            None
        );
        assert_eq!(
            runtime_socket_path_in(Some(std::ffi::OsString::from("/run/user/1000"))),
            Some(PathBuf::from("/run/user/1000").join("nexus-localapi.sock"))
        );
    }

    #[test]
    fn default_socket_path_is_never_outside_xdg_when_set() {
        // 兼容入口：有 XDG 时与 runtime_socket_path 一致。
        let expected = runtime_socket_path_in(std::env::var_os("XDG_RUNTIME_DIR"));
        if let Some(exp) = expected {
            assert_eq!(default_socket_path(), exp);
        }
    }
}
