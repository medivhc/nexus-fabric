//! E4 产品场景 product.dns-exit-binding 的可执行驱动（Composition Root）。
//!
//! 由 scenarios/product/dns_exit_binding.toml 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example dns_exit_binding -- --json
//! ```
//!
//! 驱动 `DnsRuntime`（注入内存 mock Resolver，吸收 sing-box S3/S4 与 W12）：
//! - 解析 example.com（mock 返回 v6 在前 + v4）→ PreferV4 排序后 v4 在前；
//! - 第二次解析命中缓存（singleflight：底层解析仅一次）；
//! - 环路守卫：直接查询上游地址 dns.example.internal → LoopDetected；
//! - RDRC：blacklisted.internal 解析被拒进入负缓存，再查不重试；
//! - Exit-DNS Binding：example.com -> exit-a 写入 NetworkPlanExtension v1。

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nexus_dns::{DnsError, DnsQuery, DnsRuntime, DnsType, IpPreference, Resolver};

/// 内存 mock 解析器：example.com 返回 v6 在前 + v4；blacklisted.internal 被拒。
struct MockResolver;

impl Resolver for MockResolver {
    fn resolve(&mut self, query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
        match query.name.as_str() {
            "example.com" => Ok(vec![
                IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
                )),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ]),
            other => Err(DnsError::ResolutionFailed(other.to_string())),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    // ---- 运行时装配（Composition Root）：注入 mock Resolver + 环路守卫 + exit 规则 ----
    let mut rt = DnsRuntime::new(
        Box::new(MockResolver),
        300,
        vec!["dns.example.internal".to_string()],
        vec![("example.com".to_string(), "exit-a".to_string())],
    );
    let preference = IpPreference::PreferV4;
    let now = 1000u64;

    // 1) 首次解析：miss，PreferV4 排序后 v4 在前。
    let first = rt
        .resolve(
            &DnsQuery {
                name: "example.com".into(),
                qtype: DnsType::A,
            },
            preference,
            now,
        )
        .expect("first resolve");
    let resolved_ip = first.records[0].to_string();

    // 2) 第二次解析：缓存命中；singleflight 保证底层解析仅一次。
    let second = rt
        .resolve(
            &DnsQuery {
                name: "example.com".into(),
                qtype: DnsType::A,
            },
            preference,
            now,
        )
        .expect("second resolve");
    let from_cache_second = second.from_cache;
    let singleflight_ok = rt.resolver_call_count() == 1;

    // 3) 环路守卫：直接查询上游解析器地址 → LoopDetected，不挂死。
    let loop_detected = matches!(
        rt.resolve(
            &DnsQuery {
                name: "dns.example.internal".into(),
                qtype: DnsType::A
            },
            preference,
            now,
        ),
        Err(DnsError::LoopDetected(_))
    );

    // 4) RDRC 负缓存：blacklisted.internal 被拒 → 负缓存 → 再查不重试。
    let _rejected = rt
        .resolve(
            &DnsQuery {
                name: "blacklisted.internal".into(),
                qtype: DnsType::A,
            },
            preference,
            now,
        )
        .expect_err("blacklisted should fail");
    let calls_before_rdrc = rt.resolver_call_count();
    let negative_cached = matches!(
        rt.resolve(
            &DnsQuery {
                name: "blacklisted.internal".into(),
                qtype: DnsType::A
            },
            preference,
            now,
        ),
        Err(DnsError::NegativeCached(_))
    );
    // RDRC：负缓存命中不得触发新的底层解析。
    let rdrc_no_retry = rt.resolver_call_count() == calls_before_rdrc;

    // 5) Exit-DNS Binding → NetworkPlanExtension v1。
    let decision = rt
        .resolve_exit_binding("example.com", preference, now)
        .expect("exit binding resolve");
    let exit_dns_binding = decision.exit.expect("binding decision");
    let ext = rt.to_plan_extension();
    let plan_extension_version = ext.version;

    let verdict = singleflight_ok && rdrc_no_retry && loop_detected && negative_cached;

    if as_json {
        println!(
            concat!(
                "{{\"verdict\":\"{}\",",
                "\"resolved_ip\":\"{}\",",
                "\"from_cache_second\":{},",
                "\"exit_dns_binding\":\"{}\",",
                "\"loop_detected\":{},",
                "\"negative_cached\":{},",
                "\"preference\":\"{}\",",
                "\"plan_extension_version\":{}}}"
            ),
            if verdict { "PASS" } else { "FAIL" },
            resolved_ip,
            from_cache_second,
            exit_dns_binding,
            loop_detected,
            negative_cached,
            preference.as_str(),
            plan_extension_version
        );
    } else {
        println!(
            "dns exit-binding OK: {} (cache={}, exit={}, loop={}, neg={}, singleflight={})",
            resolved_ip,
            from_cache_second,
            exit_dns_binding,
            loop_detected,
            negative_cached,
            singleflight_ok
        );
    }
}
