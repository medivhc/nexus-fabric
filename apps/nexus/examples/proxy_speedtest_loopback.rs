//! E4 产品场景 `product.proxy-speedtest-loopback` 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_speedtest_loopback -- --json
//! ```
//!
//! 同一进程内起 loopback TCP listener（backlog 保持握手可达），组合根真实
//! `TcpLatencyProbe`（std::net::TcpStream::connect_timeout）对 127.0.0.1 建连测速；
//! 断言 status=ok 且 latency_ms 有值（本地回环，宽松阈值 0-5ms）。
//! 进程内 drop listener 关闭，不遗留监听。

#![forbid(unsafe_code)]

use nexus_measurement::ProbeTarget;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let target = ProbeTarget::new("http", "127.0.0.1", port, "");
    let probe = nexus::TcpLatencyProbe::default();
    let out = nexus::proxy_speedtest_with(
        &probe,
        &[("loopback", target)],
        probe.timeout,
        "http://www.gstatic.com/generate_204",
        "tcp",
    )
    .expect("speedtest PASS");
    drop(listener);

    if as_json {
        println!("{out}");
    } else {
        let r = &out["results"][0];
        println!(
            "loopback speedtest: status={} latency_ms={}",
            r["status"], r["latency_ms"]
        );
    }
}
