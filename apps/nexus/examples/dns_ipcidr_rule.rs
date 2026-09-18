//! E4 产品场景 product.dns-ipcidr-rule 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/dns_ipcidr_rule.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example dns_ipcidr_rule -- --json
//! ```
//!
//! 两件事（§11.5.1）：
//! - IP-CIDR 规则：请求 client_ip 落在 10.0.0.0/8 -> server-a；其余 MATCH -> server-b。
//! - 缓存按 server 隔离：向 server-a 查过 `shared.cache` 后，server-b 对同名查询不得命中
//!   server-a 的缓存（必须走 server-b 自己注入的 Resolver）。
//!
//! 离线确定性：每个 server 注入内存 mock Resolver（A 恒答 192.0.2.10，B 恒答 198.51.100.20）。

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

use nexus_dns::{
    DnsError, DnsMatch, DnsQuery, DnsRouteRule, DnsRouter, DnsType, MultiServerDns, Resolver,
};
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
    - ip_cidr: 10.0.0.0/8
      server: server-a
  default_server: server-b
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let cfg = parse(YAML).expect("proxy config parses");
    let dns = cfg.dns.expect("dns section present");

    let mut servers: Vec<(String, Box<dyn Resolver>)> = Vec::new();
    for s in &dns.servers {
        let ip = match s.tag.as_str() {
            "server-a" => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            "server-b" => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            other => panic!("unknown dns server tag '{other}'"),
        };
        servers.push((s.tag.clone(), Box::new(FixedResolver { ip })));
    }

    let rules: Vec<DnsRouteRule> = dns
        .rules
        .iter()
        .map(|r| {
            let matcher = match (&r.domain, &r.ip_cidr) {
                (Some(d), _) => DnsMatch::Domain(d.clone()),
                (None, Some(c)) => DnsMatch::ip_cidr(c).expect("valid cidr"),
                (None, None) => panic!("dns rule needs domain or ip_cidr"),
            };
            DnsRouteRule {
                matcher,
                server: r.server.clone(),
            }
        })
        .collect();
    let router = DnsRouter::new(rules, dns.default_server.clone());
    let mut md = MultiServerDns::new(servers, router).expect("wire multi-server dns");

    let in_prefix = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    let out_prefix = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    // (a) IP-CIDR 路由：在 10.0.0.0/8 内 -> server-a；在外 -> MATCH -> server-b。
    let ipcidr_hit = md
        .resolve_with("cidr.internal", DnsType::A, Some(in_prefix))
        .expect("resolve in-prefix");
    let other = md
        .resolve_with("other.internal", DnsType::A, Some(out_prefix))
        .expect("resolve out-prefix");

    // (b) 按 server 缓存隔离：先让 A 解析 shared.cache，再问 A（命中 A 自己缓存），
    //     最后让 B 问同名——B 不得命中 A 的缓存（必须走 B 自己的 Resolver）。
    let _ = md
        .resolve_with("shared.cache", DnsType::A, Some(in_prefix))
        .expect("warm server-a");
    let a_again = md
        .resolve_with("shared.cache", DnsType::A, Some(in_prefix))
        .expect("server-a again");
    let b_first = md
        .resolve_with("shared.cache", DnsType::A, Some(out_prefix))
        .expect("server-b shared");

    let ipcidr_server = ipcidr_hit.server;
    let other_server = other.server;
    let a_cache_hit = a_again.from_cache;
    let b_cache_isolated = !b_first.from_cache;

    let verdict = ipcidr_server == "server-a"
        && other_server == "server-b"
        && a_cache_hit
        && b_cache_isolated;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"ipcidr_server\":\"{}\",",
                "\"other_server\":\"{}\",",
                "\"a_cache_hit\":{},",
                "\"b_cache_isolated\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            ipcidr_server,
            other_server,
            a_cache_hit,
            b_cache_isolated
        );
    } else {
        println!(
            "dns ipcidr+cache OK: cidr_server={}, other={}, a_cache_hit={}, b_isolated={}",
            ipcidr_server, other_server, a_cache_hit, b_cache_isolated
        );
    }
}
