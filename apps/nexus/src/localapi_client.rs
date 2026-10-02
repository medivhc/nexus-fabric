//! nexusd serve LocalAPI thin HTTP client（nexus CLI 瘦客户端层）。
//!
//! CLI 不再在进程内装配 SDK 来回答 §9 观察命令；而是通过裸 `std::net::TcpStream`
//! 向 `nexusd serve` 发起一条最小 HTTP/1.1 GET，把 daemon 返回的 JSON 原文渲染出来。
//!
//! 职责：
//! - 把 [`ControlCommand`] 映射到 daemon LocalAPI 路由（无路由则本地合成 UNSUPPORTED）；
//! - 裸 TCP 发请求、读响应、按 `Content-Length` 切出 body；
//! - 连接失败 / 坏响应 → 类型化 [`ClientError`]，由 main 层映射为结构化 FAIL JSON。
//!
//! 不做：不解析业务 JSON 语义（verdict/error 由 daemon 决定），不重试，不做 TLS。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use nexus_control_api::ControlCommand;
use serde_json::Value;

/// 默认 daemon LocalAPI 监听地址（与 `nexusd serve` 默认 loopback 约定一致）。
pub const DEFAULT_LOCALAPI_ADDR: &str = "127.0.0.1:18080";

/// 客户端超时：daemon 在 loopback 上立即应答；挂起视为异常，避免无限等待。
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// 客户端侧错误（可恢复：daemon 没起 / 协议异常；main 层转成结构化 FAIL JSON）。
#[derive(Debug)]
pub enum ClientError {
    /// TCP 连接失败（daemon 未运行 / addr 错误）。
    Unreachable(String),
    /// daemon 返回了无法解析的 HTTP 响应。
    BadResponse(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unreachable(msg) => write!(f, "daemon unreachable: {msg}"),
            ClientError::BadResponse(msg) => write!(f, "bad daemon response: {msg}"),
        }
    }
}

/// 把 [`ControlCommand`] 映射到 daemon LocalAPI 路由路径。
///
/// 返回 `None` 表示 daemon 尚未提供该路由（CLI 本地合成 UNSUPPORTED），或该命令
/// 不走 LocalAPI（`Run` 仍走进程内 SDK 路径）。
#[must_use]
pub fn route_for(command: &ControlCommand) -> Option<&'static str> {
    match command {
        ControlCommand::Status => Some("/localapi/v0/status"),
        ControlCommand::DnsStatus => Some("/localapi/v0/dns/status"),
        ControlCommand::DnsCache => Some("/localapi/v0/dns/cache"),
        ControlCommand::SessionWatch { .. } => Some("/localapi/v0/session/watch"),
        ControlCommand::PlanExplain { .. } => Some("/localapi/v0/plan/explain"),
        ControlCommand::ConnectivityStatus => Some("/localapi/v0/connectivity/status"),
        ControlCommand::PlatformCapabilities => Some("/localapi/v0/platform/capabilities"),
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
        // C1：workspace commit 走动态路由（route_for_dynamic），静态路由无。
        ControlCommand::WorkspaceCommit { .. } => None,
        // Run 保持进程内 SDK 路径（LocalAPI 无对应路由）。
        ControlCommand::Run { .. } => None,
        // N1 装配命令由 CLI 进程内 Composition Root 直接执行（M6；无 daemon 路由）。
        ControlCommand::NetworkUp { .. } | ControlCommand::NetworkStatus => None,
    }
}

/// 把 [`ControlCommand`] 映射到 daemon LocalAPI 路由路径（动态路径段版本）。
///
/// `route_for` 只能表达静态路径；`workspace commit <id>` 的 id 是动态的，
/// 走这个函数。返回 `None` 表示该命令无动态路由。
#[must_use]
pub fn route_for_dynamic(command: &ControlCommand) -> Option<String> {
    match command {
        ControlCommand::WorkspaceCommit { workspace } => {
            Some(format!("/localapi/v0/workspace/commit/{workspace}"))
        }
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

/// 在 `addr` 上发起一次裸 HTTP GET `path`，返回响应 body 字符串。
///
/// daemon 使用最小 HTTP/1.1：发完响应即 `Connection: close`。这里读到 EOF 后按
/// `Content-Length` 切出精确 body（防止 keep-alive 残留；当前 daemon 总是 close）。
///
/// # Errors
///
/// - [`ClientError::Unreachable`]：TCP connect 失败（daemon 未运行 / 端口未监听）。
/// - [`ClientError::BadResponse`]：读写 / 编码 / 协议头解析失败。
pub fn http_get(addr: &str, path: &str) -> Result<String, ClientError> {
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| ClientError::Unreachable(format!("connect {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| ClientError::BadResponse(format!("set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| ClientError::BadResponse(format!("set write timeout: {e}")))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
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
    fn seven_routes_map_to_localapi_paths() {
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
            route_for(&ControlCommand::SessionWatch {
                session: SessionId("s1".into())
            }),
            Some("/localapi/v0/session/watch")
        );
        assert_eq!(
            route_for(&ControlCommand::PlanExplain {
                resource: ResourceId("net".into())
            }),
            Some("/localapi/v0/plan/explain")
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
    fn unsupported_commands_have_no_route() {
        for cmd in [
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
        let err = http_get("127.0.0.1:1", "/localapi/v0/status").unwrap_err();
        assert!(
            matches!(err, ClientError::Unreachable(_)),
            "connect to closed port must be Unreachable, got {err:?}"
        );
    }
}
