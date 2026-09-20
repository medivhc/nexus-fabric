//! E4 产品场景 `product.proxy-speedtest-http204-loopback` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_speedtest_http204_loopback -- --json
//! ```
//!
//! 同一进程内起一个最小 loopback HTTP 服务线程：accept → 读请求行（吞掉剩余头）→
//! 回 `HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`。
//! 组合根真实 `Http204LatencyProbe`（TCP connect + 单行 GET + 读响应首行）对
//! 127.0.0.1 探测；断言 probe_kind=http204、status=ok、latency_ms 有值（本地回环，
//! 宽松阈值 0-10ms）。服务线程在响应一次后退出，主进程 drop listener，不遗留监听。

#![forbid(unsafe_code)]

use nexus_measurement::ProbeTarget;
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();

    // 后台线程：处理一个连接后退出（ deterministic，不遗留线程）。
    let server_handle = std::thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().expect("accept once");
        // 吞掉客户端请求行与请求头（直到空行）。
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).expect("read request");
            if n == 0 {
                break;
            }
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || buf[..n].contains(&b'\n') {
                // 读到了换行就认为请求头到了；一次读足够覆盖单次 GET。
                break;
            }
        }
        let resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes()).expect("write 204");
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
            "loopback http204 speedtest: status={} latency_ms={}",
            r["status"], r["latency_ms"]
        );
    }
}
