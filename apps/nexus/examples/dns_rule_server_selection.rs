//! E4 产品场景 product.dns-rule-server-selection 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/dns_rule_server_selection.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example dns_rule_server_selection -- --json
//! ```
//!
//! 吸收 sing-box DNS rules：配置两个离线 DNS server（A/B），一条域名规则把
//! example.internal 路由到 A，其余 MATCH 兜底走 B。本 example：
//! - 解析带 `dns:` 段的 YAML（经 nexus-proxy-config 类型化）；
//! - 为每个 server 注入内存 mock Resolver（A 恒答 192.0.2.10，B 恒答 198.51.100.20）；
//! - 断言 example.internal 经规则命中走 server-a、other.example 经 MATCH 走 server-b，
//!   且解析结果确为被选中 server 的应答。

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

use nexus_dns::{DnsError, DnsQuery, DnsRouteRule, DnsRouter, DnsType, MultiServerDns, Resolver};
use nexus_proxy_config::parse;

/// 内存 mock：恒答构造时给定的单个 IP（离线确定性）。
struct FixedResolver {
    ip: IpAddr,
}

impl Resolver for FixedResolver {
    fn resolve(&mut self, _query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
        Ok(vec![self.ip])
    }
}

const YAML: &str = "\
schema_version: 1
rules:
  - tag: r-match
    kind: match
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
dns:
  servers:
    - tag: server-a
      address: 192.0.2.10
    - tag: server-b
      address: 198.51.100.20
  rules:
    - domain: example.internal
      server: server-a
  default_server: server-b
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(YAML).expect("proxy config parses");
    let dns = cfg.dns.expect("dns section present");

    // 为每个配置的 server 注入一个离线 mock Resolver。
    let mut servers: Vec<(String, Box<dyn Resolver>)> = Vec::new();
    for s in &dns.servers {
        let ip = match s.tag.as_str() {
            "server-a" => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            "server-b" => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            other => panic!("unknown dns server tag '{other}'"),
        };
        servers.push((s.tag.clone(), Box::new(FixedResolver { ip })));
    }

    // 由配置构造路由器：域名规则首匹配，MATCH 兜底 default_server。
    let rules: Vec<DnsRouteRule> = dns
        .rules
        .iter()
        .map(|r| DnsRouteRule {
            domain: r.domain.clone(),
            server: r.server.clone(),
        })
        .collect();
    let router = DnsRouter::new(rules, dns.default_server.clone());

    let mut md = MultiServerDns::new(servers, router).expect("wire multi-server dns");

    // example.internal -> 规则命中 -> server-a。
    let internal = md
        .resolve("example.internal", DnsType::A)
        .expect("resolve example.internal");
    // other.example -> 无规则命中 -> MATCH -> server-b。
    let other = md
        .resolve("other.example", DnsType::A)
        .expect("resolve other.example");

    let selected_server_internal = internal.server;
    let selected_server_other = other.server;
    let internal_resolved_ip = internal.addresses[0].to_string();
    let other_resolved_ip = other.addresses[0].to_string();

    let verdict = selected_server_internal == "server-a"
        && selected_server_other == "server-b"
        && internal_resolved_ip == "192.0.2.10"
        && other_resolved_ip == "198.51.100.20";

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"selected_server_internal\":\"{}\",",
                "\"selected_server_other\":\"{}\",",
                "\"internal_resolved_ip\":\"{}\",",
                "\"other_resolved_ip\":\"{}\"}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            selected_server_internal,
            selected_server_other,
            internal_resolved_ip,
            other_resolved_ip
        );
    } else {
        println!(
            "dns rule routing OK: internal={} (ip={}), other={} (ip={})",
            selected_server_internal,
            internal_resolved_ip,
            selected_server_other,
            other_resolved_ip
        );
    }
}
