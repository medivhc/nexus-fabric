//! E4 helper：为路由类 observability 场景提供自包含的 daemon 生命周期。
//!
//! 背景：CLI 统一重构（01e5114）后 `nexus <cmd> --json` 为瘦客户端，观察命令
//! 经 LocalAPI 查 daemon；但 product-scenarios harness 的 [when].command 是单
//! 个程序调用，不负责起 daemon。本 probe 做最小闭环：
//!
//! ```text
//! spawn `nexusd serve`（127.0.0.1:0 临时端口，READY 行带回实际地址）
//!   -> HTTP GET <path>
//!   -> 打印响应 body（即 observability JSON）
//!   -> 杀掉 daemon
//! ```
//!
//! 用法：
//!
//! ```text
//! cargo run --quiet -p nexusd --example localapi_probe -- --path /localapi/v0/status
//! ```

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("localapi_probe failed: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                path = args.get(i + 1).cloned();
                i += 2;
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    let path = path.ok_or("missing --path <localapi-path>")?;

    // nexusd 二进制与本 example 同目录（target/debug/）。
    let nexusd_bin = std::env::current_exe()
        .map_err(|e| format!("current_exe: {e}"))?
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("nexusd"))
        .ok_or("cannot resolve nexusd path")?;
    if !nexusd_bin.exists() {
        return Err(format!("nexusd not found at {}", nexusd_bin.display()));
    }

    let mut child = Command::new(&nexusd_bin)
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn nexusd serve: {e}"))?;

    // READY 行：{"verdict":"READY","daemon":{"entry":"nexusd","command":"serve","addr":"..."}}。
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    let ready_line = lines
        .next()
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or("nexusd serve produced no stdout")?;
    let addr = parse_ready_addr(&ready_line)?;

    let body = http_get(&addr, &path);

    // 收尾：杀 daemon，不留进程。
    let _ = child.kill();
    let _ = child.wait();

    let body = body?;
    println!("{body}");
    Ok(())
}

fn parse_ready_addr(line: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("READY line not JSON: {e}"))?;
    v.get("daemon")
        .and_then(|d| d.get("addr"))
        .and_then(|a| a.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("READY line missing daemon.addr: {line}"))
}

fn http_get(addr: &str, path: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match TcpStream::connect(addr) {
            Ok(mut s) => {
                s.set_read_timeout(Some(Duration::from_secs(10)))
                    .map_err(|e| e.to_string())?;
                write!(s, "GET {path} HTTP/1.0\r\nHost: {addr}\r\n\r\n")
                    .map_err(|e| format!("write: {e}"))?;
                let mut resp = String::new();
                s.read_to_string(&mut resp)
                    .map_err(|e| format!("read: {e}"))?;
                return resp
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_string())
                    .ok_or_else(|| format!("no body in response: {resp}"));
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("connect {addr}: {e}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
