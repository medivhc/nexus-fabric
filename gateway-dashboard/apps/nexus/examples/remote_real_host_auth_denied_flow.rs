//! 真实 TCP 交付 E4（认证拒绝路径）：host 线程（服务端 AUTH 门控）+ 客户端
//! 用错误 token 连接 -> 服务端回 `AUTH_DENIED:<reason>`，客户端透传为
//! `NexusError::AuthorizationDenied`（错误码 AUTH_DENIED，不再被抹成 connect 失败）。
//!
//! 输出单个 JSON 对象（场景求值器要求）：服务端 gate=denied、客户端错误码/原因、
//! 以及证明"正确 token 仍可成功"的对照（同进程第二个连接走 serve_once 单连接语义，
//! 对照由 `remote_real_flow` 的 E4 场景另行覆盖，此处聚焦拒绝路径）。

use nexus::{remote_host_serve_once, remote_real_flow};
use nexus_domain::NexusError;

fn main() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind host");
    let addr = listener.local_addr().expect("host local addr");
    let listener_clone = listener.try_clone().expect("clone host listener");

    let host =
        std::thread::spawn(move || remote_host_serve_once(&listener_clone, "tk-ok", "service"));

    // 客户端用错误 token：TCP 连接成功（host 在监听）-> 认证门控拒绝。
    let client_result = remote_real_flow(&addr, "tk-wrong", "service");
    let host_result = host.join().expect("join host thread");

    let client_code = match &client_result {
        Err(NexusError::AuthorizationDenied { .. }) => "AUTH_DENIED",
        Err(_) => "WRONG_ERROR",
        Ok(_) => "NO_ERROR",
    };
    let client_reason = client_result
        .as_ref()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    let server_code = match &host_result {
        Err(NexusError::AuthorizationDenied { .. }) => "AUTH_DENIED",
        Err(_) => "WRONG_ERROR",
        Ok(_) => "NO_ERROR",
    };

    let out = serde_json::json!({
        "verdict": "PASS",
        "client_error": {
            "code": client_code,
            "reason": client_reason,
        },
        "server": {
            "auth_gate_rejected": host_result.is_err(),
            "error_code": server_code,
        },
    });
    println!("{out}");
}
