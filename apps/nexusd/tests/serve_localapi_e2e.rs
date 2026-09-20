//! 端到端测试：`nexusd serve` 常驻 daemon + 裸 TcpStream HTTP 客户端。
//!
//! 模式对齐 Tailscale tstest/integration：
//!   1. 通过 `CARGO_BIN_EXE_nexusd` 定位已构建的 nexusd 二进制；
//!   2. 真起子进程 `nexusd serve --addr=127.0.0.1:0`；
//!   3. 轮询子进程 stdout，直到看到 READY JSON（解析出实际绑定 addr）；
//!   4. 用 std::net::TcpStream 发裸 HTTP GET，解析状态行 + body；
//!   5. t.Cleanup（Drop guard）杀子进程、wait，避免僵尸。
//!
//! 不引入 reqwest/hyper；与 daemon 端一样只用 std。

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// 子进程句柄：Drop 时 kill + wait，确保测试结束不留僵尸。
struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // kill 已退出的进程在 Windows 上会失败，忽略即可；随后 wait 回收。
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 启动 `nexusd serve --addr=127.0.0.1:0`，等到 READY 后返回 (guard, actual_addr)。
///
/// 不传具体端口：让内核选临时端口，从 READY JSON 里读实际 addr，避免
/// "先 bind 再 drop 再让 daemon bind" 的 TOCTOU 竞态。
fn spawn_serve() -> (DaemonGuard, String) {
    let exe = env!("CARGO_BIN_EXE_nexusd");
    let mut child = Command::new(exe)
        .arg("serve")
        .arg("--addr=127.0.0.1:0")
        .stdout(Stdio::piped())
        // stderr 继承到测试进程，便于 --nocapture 下排查；不管道化避免写满阻塞 daemon。
        .spawn()
        .expect("spawn nexusd serve");

    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();

    let actual_addr = loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "timed out after 10s waiting for READY line from nexusd serve; last stdout line: {line:?}"
            );
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // 子进程在打印 READY 之前就退出了。
                let _ = child.kill();
                let _ = child.wait();
                panic!("nexusd serve exited before printing READY; stdout so far: {line:?}");
            }
            Ok(_n) => {
                let trimmed = line.trim_end();
                if trimmed.contains("\"verdict\":\"READY\"") {
                    let v: serde_json::Value =
                        serde_json::from_str(trimmed).expect("parse READY line as JSON");
                    let addr = v["daemon"]["addr"]
                        .as_str()
                        .expect("READY daemon.addr field")
                        .to_string();
                    break addr;
                }
                // 其它行（理论上不会有）忽略，继续等 READY。
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("read nexusd serve stdout failed: {e}");
            }
        }
    };

    // reader 持有子进程 stdout 的读端；这里 drop 它，避免 daemon 后续 stdout 写阻塞。
    // daemon 进入 accept 循环后不再写 stdout，关闭读端安全。
    drop(reader);

    (DaemonGuard { child }, actual_addr)
}

/// 发一次裸 HTTP GET，返回 (status_code, body)。
///
/// 不解析完整 header 集，只切出 status line 和 \r\n\r\n 之后的 body。
/// daemon 响应固定带 Content-Length + Connection: close，读至 EOF 即可。
fn http_get(addr: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write request");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("read response");
    let text = String::from_utf8(buf).expect("response is utf8");

    // 分离 head / body
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => panic!("response missing CRLF CRLF separator: {text:?}"),
    };

    let status_line = head.lines().next().expect("status line present");
    // 形如 "HTTP/1.1 200 OK"
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code token")
        .parse()
        .expect("status code parse as u16");

    (status_code, body.to_string())
}

#[test]
fn status_route_returns_200_with_verdict() {
    let (_guard, addr) = spawn_serve();
    let (status, body) = http_get(&addr, "/localapi/v0/status");
    assert_eq!(status, 200, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("status body is JSON");
    assert!(v.get("verdict").is_some(), "body missing verdict: {v}");
}

#[test]
fn dns_cache_route_returns_200_with_verdict() {
    let (_guard, addr) = spawn_serve();
    let (status, body) = http_get(&addr, "/localapi/v0/dns/cache");
    assert_eq!(status, 200, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("dns/cache body is JSON");
    assert!(v.get("verdict").is_some(), "body missing verdict: {v}");
}

#[test]
fn plan_explain_route_returns_200_with_verdict() {
    let (_guard, addr) = spawn_serve();
    let (status, body) = http_get(&addr, "/localapi/v0/plan/explain");
    assert_eq!(status, 200, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("plan/explain body is JSON");
    assert!(v.get("verdict").is_some(), "body missing verdict: {v}");
}

#[test]
fn unknown_route_returns_404_not_found() {
    let (_guard, addr) = spawn_serve();
    let (status, body) = http_get(&addr, "/localapi/v0/nonexistent");
    assert_eq!(status, 404, "body: {body}");
    assert!(
        body.contains("NOT_FOUND"),
        "404 body missing NOT_FOUND: {body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("404 body is JSON");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["error"]["code"], "NOT_FOUND");
}
