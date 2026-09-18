//! E4 产品场景 product.proxy-clash-subscription-parse 的可执行驱动（Composition Root）。
//!
//! ```text
//! cargo run --quiet -p nexus --example proxy_clash_subscription_parse -- --json
//! ```
//!
//! 喂一段固定 base64 订阅（1 ss:// + 1 vmess:// + 1 trojan:// 未知协议行），解码逐行解析；
//! 断言解析出 2 个出站、未知 trojan 行被记录拒绝、ss/vmess 字段正确。离线确定性。

#![forbid(unsafe_code)]

use nexus_proxy_config::{OutboundKind, parse_clash_subscription};

const SUBSCRIPTION_B64: &str = concat!(
    "c3M6Ly9ZMmhoWTJoaE1qQXRhV1YwWmkxd2IyeDVNVE13TlRwa1pXMXZMWEJoYzNOM2Iz",
    "SmtAc3MuZXhhbXBsZS5jb206ODM4OCNTUy1Ob2RlCnZtZXNzOi8vYjgzMTM4MWQtNjMyNC",
    "00ZDUzLWFkNGYtOGNkYTQ4YjMwODExQHZtLmV4YW1wbGUuY29tOjEwMDg2I1ZNZXNzLU5v",
    "ZGUKdHJvamFuOi8vcGFzc0B0ci5leGFtcGxlLmNvbTo0NDMjVHJvamFuLU5vZGUK"
);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let parsed = parse_clash_subscription(SUBSCRIPTION_B64).expect("subscription parses");
    let outbounds = parsed.outbounds.len();
    let rejected = parsed.rejected.len();

    let ss = parsed
        .outbounds
        .iter()
        .find(|o| o.kind == OutboundKind::Shadowsocks)
        .expect("ss outbound present");
    let vm = parsed
        .outbounds
        .iter()
        .find(|o| o.kind == OutboundKind::Vmess)
        .expect("vmess outbound present");

    let (ss_host, ss_port) = split_locator(ss.locator.as_deref().unwrap_or(""));
    let (vm_host, vm_port) = split_locator(vm.locator.as_deref().unwrap_or(""));

    let verdict = outbounds == 2
        && rejected == 1
        && ss.kind == OutboundKind::Shadowsocks
        && ss_host == "ss.example.com"
        && ss_port == 8388
        && ss.password.as_deref() == Some("demo-password")
        && vm.kind == OutboundKind::Vmess
        && vm_host == "vm.example.com"
        && vm_port == 10086;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"outbounds\":{},",
                "\"rejected\":{},",
                "\"ss_protocol\":\"shadowsocks\",",
                "\"ss_host\":\"{}\",",
                "\"ss_port\":{},",
                "\"vm_protocol\":\"vmess\",",
                "\"vm_host\":\"{}\",",
                "\"vm_port\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            outbounds,
            rejected,
            ss_host,
            ss_port,
            vm_host,
            vm_port
        );
    } else {
        println!(
            "sub: outbounds={outbounds} rejected={rejected} ss={ss_host}:{ss_port} vm={vm_host}:{vm_port}"
        );
    }
}

fn split_locator(locator: &str) -> (String, u16) {
    match locator.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(0)),
        None => (locator.to_string(), 0),
    }
}
