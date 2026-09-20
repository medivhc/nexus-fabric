//! E4 产品场景 `product.proxy-speedtest-http204-bad-status` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_speedtest_http204_bad_status -- --json
//! ```
//!
//! 负向路径：loopback HTTP 服务返回 `HTTP/1.1 500 Internal Server Error`，
//! 真实 `Http204LatencyProbe` 应把它分类为 `unreachable`（非 204 状态码）。
//! 进程内 join 回收服务线程，不遗留监听。

#![forbid(unsafe_code)]

use nexus_measurement::ProbeTarget;
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();

    let server_handle = std::thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().expect("accept once");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).expect("read request");
        // 故意返回 500，触发 Http204LatencyProbe 的 "unexpected status line" 分支。
        let resp =
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes()).expect("write 500");
    });

    let target = ProbeTarget::new("http", "127.0.0.1", port, "");
    let probe = nexus::Http204LatencyProbe::default();
    let out = nexus::proxy_speedtest_with(
        &probe,
        &[("loopback", target)],
        probe.timeout,
        "http://www.gstatic.com/generate_204",
        "http204",
    )
    .expect("speedtest PASS");

    server_handle.join().expect("server thread joined");

    if as_json {
        println!("{out}");
    } else {
        let r = &out["results"][0];
        println!(
            "loopback http204 bad status: status={} latency_ms={}",
            r["status"], r["latency_ms"]
        );
    }
}
