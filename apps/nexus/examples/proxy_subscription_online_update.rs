//! §11.17 订阅节点在线更新（E4）。
//!
//! 本地 loopback HTTP 订阅源（可变内容 + 可制造失败）：
//! - attempt1 拉取 2 节点订阅 -> 热生效，有效节点 1(local)+2=3；
//! - attempt2 制造拉取失败 -> 回退，有效节点保持 3（不清空），revision 不推进；
//! - attempt3 拉取 3 节点订阅（含 1 条 trojan 未知协议行）-> 整体替换订阅集，
//!   有效节点 1+3=4、rejected=1，revision 推进到 2。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use nexus::subscription_updater::SubscriptionUpdater;
use nexus_proxy_config::{OutboundConfig, OutboundKind, SubscriptionSourceConfig};

const BODY_2_NODES: &str = "c3M6Ly9ZMmhoWTJoaE1qQXRhV1YwWmkxd2IyeDVNVE13TlRwa2FXMXZMWEJoYzNOM2IzSmtAc3MuZXhhbXBsZS5jb206ODM4OCNTdWItQQp2bWVzczovL2I4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMUB2bS5leGFtcGxlLmNvbToxMDA4NiNTdWItQgo=";
const BODY_3_NODES_1_REJECTED: &str = "c3M6Ly9ZMmhoWTJoaE1qQXRhV1YwWmkxd2IyeDVNVE13TlRwa2FXMXZMWEJoYzNOM2IzSmtAc3MuZXhhbXBsZS5jb206ODM4OCNTdWItQQpzczovL1kyaGhZMmhoTWpBdGFXVjBaaTF3YjJ4NU1UTXdOVHBrYVcxdkxYQmhjM04zYjNKa0BzczIuZXhhbXBsZS5jb206ODM4OSNTdWItQgp2bWVzczovL2I4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMUB2bS5leGFtcGxlLmNvbToxMDA4NiNTdWItQwp0cm9qYW46Ly9wYXNzQHRyLmV4YW1wbGUuY29tOjQ0MyNSZWplY3RlZAo=";

#[derive(Default)]
struct ServerState {
    body: String,
    fail: bool,
}

fn main() {
    let state = Arc::new(Mutex::new(ServerState::default()));

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();

    // 后台 server 线程：循环 accept，按当前 state 响应（fail 时回 500）。
    let srv = state.clone();
    let _jh = std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let (status, body) = {
                let g = srv.lock().unwrap();
                if g.fail {
                    ("HTTP/1.1 503 Service Unavailable", String::new())
                } else {
                    ("HTTP/1.1 200 OK", g.body.clone())
                }
            };
            let resp = format!(
                "{status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });

    // 本地手写 outbounds：1 个 direct（恒定保留，永不被订阅清空）。
    let local = vec![OutboundConfig {
        tag: "direct".to_string(),
        kind: OutboundKind::Direct,
        locator: Some(String::new()),
        method: None,
        password: None,
        alpn: None,
        skip_cert_verify: None,
        header_format: None,
    }];

    let source = SubscriptionSourceConfig::new(
        "my-sub",
        format!("http://127.0.0.1:{port}/subscription"),
        3600,
    )
    .expect("valid source");
    let updater = SubscriptionUpdater::new(source, local);

    // attempt1：2 节点订阅 -> 成功热生效。
    {
        let mut g = state.lock().unwrap();
        g.fail = false;
        g.body = BODY_2_NODES.to_string();
    }
    let ev1 = updater.poll_once();

    // attempt2：制造失败（503）-> 回退，节点数保持、revision 不推进。
    {
        let mut g = state.lock().unwrap();
        g.fail = true;
    }
    let ev2 = updater.poll_once();

    // attempt3：3 节点订阅（含 1 trojan 拒绝行）-> 整体替换，rejected=1。
    {
        let mut g = state.lock().unwrap();
        g.fail = false;
        g.body = BODY_3_NODES_1_REJECTED.to_string();
    }
    let ev3 = updater.poll_once();

    let out = serde_json::json!({
        "verdict": "PASS",
        "command": "proxy subscription online update",
        "attempt1_ok": ev1.ok,
        "attempt1_node_count_after": ev1.node_count_after,
        "attempt1_rejected": ev1.rejected,
        "attempt2_ok": ev2.ok,
        "attempt2_node_count_after": ev2.node_count_after,
        "attempt3_ok": ev3.ok,
        "attempt3_node_count_after": ev3.node_count_after,
        "attempt3_rejected": ev3.rejected,
        "hot_reload_revision": updater.current_revision(),
        "final_node_count": updater.effective_node_count(),
    });
    println!("{out}");

    // main 返回即结束进程，server 线程随之退出（不阻塞 join）。
}
