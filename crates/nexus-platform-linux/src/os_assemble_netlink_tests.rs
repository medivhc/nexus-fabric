//! P5-c 回归：`OsAssemble` 真实 netlink 路由创建（非 dry-run）。
//!
//! 覆盖 E5 S4（S62）暴露的缺陷面：
//! - `RTM_NEWROUTE` 缺 `NLM_F_CREATE` → exclude `/32` 创建 `ENOENT`；
//! - exclude 路由被挂到 TUN 自身而不是接管前默认路由出口（AC-G5-03）。
//!
//! 环境隔离：测试自身在 `unshare -rn`（user+net namespace）里重执行，
//! 只用 dummy 设备，绝不触碰宿主网络。无法创建 user/net namespace
//! （内核关闭 unprivileged userns、无 `unshare`）时输出 SKIP 并非假 PASS。
//!
//! 手动运行（`#[ignore]`，不进常规 `cargo test`）：
//!
//! ```text
//! cargo test -p nexus-platform-linux --lib -- --ignored --nocapture os_assemble_netlink
//! ```
//!
//! 放在 `#[cfg(test)]` lib 测试模块而不是 `tests/` 独立 target：harness 的
//! `integration_targets()` 对 workspace 测试 target 数量有断言，新增 `tests/`
//! 文件会改变该基线；本测试仍是真实 netlink 端到端，只是挂在 lib 测试二进制。

use std::net::Ipv4Addr;
use std::process::Command;

use crate::assemble::{OsAssemble, OsAssembleConfig};

/// 子进程标记：已处于一次性 netns 内。
const CHILD_ENV: &str = "NEXUS_P5_NETNS_CHILD";
/// libtest 的 `--exact` 需要模块全名（本测试位于 lib 测试二进制内）。
const TEST_NAME: &str =
    "os_assemble_netlink_tests::os_assemble_real_netlink_exclude_idempotent_cleanup";

/// 上游（“接管前默认路由”所在）设备与网关。
const UP_IFNAME: &str = "nxp5up0";
const UP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 1);
const UP_PREFIXLEN: u8 = 24;
const UP_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 2);
/// TUN 替身（dummy；OsAssemble 只关心 ifindex）。
const TUN_IFNAME: &str = "nxp5tun0";
const TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const TUN_PREFIXLEN: u8 = 24;
const TUN_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 0);
/// 代理服务器目的地址（不在任何直连子网，靠默认路由）。
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
/// 代理服务器目的地址（就在上游直连子网里 —— E5 S4 的真实形状：
/// router netns 没有默认路由，只能走 on-link 出口）。
const SERVER_ONLINK: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 99);

fn skip(reason: &str) {
    eprintln!("SKIP: {reason}");
}

fn ip_bin() -> &'static str {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if std::path::Path::new(candidate).exists() {
            return candidate;
        }
    }
    "ip"
}

fn ip(args: &[&str]) -> Result<String, String> {
    let bin = ip_bin();
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {bin} {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ip {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 确认当前网络命名空间是全新的一次性 netns：只有 `lo`。
///
/// 防御：如果有人在宿主环境里误设子进程标记，这里必须拒绝继续，
/// 不允许在宿主网络上建 dummy 设备/加路由。
fn assert_fresh_netns() -> bool {
    let links = match ip(&["-o", "link", "show"]) {
        Ok(v) => v,
        Err(e) => {
            skip(&format!("cannot enumerate links: {e}"));
            return false;
        }
    };
    let names: Vec<&str> = links
        .lines()
        .filter_map(|line| line.split(':').nth(1).map(str::trim))
        .collect();
    if names != ["lo"] {
        skip(&format!(
            "refusing to run outside a fresh netns (links={names:?})"
        ));
        return false;
    }
    true
}

fn setup_fixtures() -> Result<(), String> {
    // 上游设备 + 接管前默认路由。
    ip(&["link", "add", UP_IFNAME, "type", "dummy"])?;
    ip(&[
        "addr",
        "add",
        &format!("{UP_ADDR}/{UP_PREFIXLEN}"),
        "dev",
        UP_IFNAME,
    ])?;
    ip(&["link", "set", UP_IFNAME, "up"])?;
    // TUN 替身（OsAssemble 只按 ifname 解析 ifindex）。
    ip(&["link", "add", TUN_IFNAME, "type", "dummy"])?;
    ip(&["link", "set", TUN_IFNAME, "up"])?;
    ip(&[
        "route",
        "add",
        "default",
        "via",
        &UP_GATEWAY.to_string(),
        "dev",
        UP_IFNAME,
    ])?;
    Ok(())
}

fn config(excludes: &[Ipv4Addr]) -> OsAssembleConfig {
    config_with(excludes, false)
}

fn config_with(excludes: &[Ipv4Addr], default_route: bool) -> OsAssembleConfig {
    OsAssembleConfig {
        ifname: TUN_IFNAME.to_string(),
        tun_ip: TUN_IP.octets(),
        prefixlen: TUN_PREFIXLEN,
        subnet: (TUN_SUBNET.octets(), TUN_PREFIXLEN),
        default_route,
        dry_run: false,
        log_path: Some(std::env::temp_dir().join("os-assemble-netlink-p5.log")),
        exclude_dst_cidrs: excludes.iter().map(|ip| (ip.octets(), 32)).collect(),
        // 空 → 走 OsAssemble 的接管前快照解析路径（最长前缀 → 默认路由）。
        exclude_egress: Vec::new(),
    }
}

fn route_get(dst: Ipv4Addr) -> String {
    ip(&["route", "get", &dst.to_string()]).unwrap_or_default()
}

fn route_lines(dst: Ipv4Addr) -> Vec<String> {
    // `exact` 只返回与该前缀完全匹配的路由（`show` 对 /32 不打印前缀后缀）。
    let dst_cidr = format!("{dst}/32");
    ip(&["route", "show", "table", "main", "exact", &dst_cidr])
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// 真实 netlink 端到端：apply（含 exclude）→ AC-G5-03 出口断言 → 二次 apply
/// 幂等 → cleanup 干净。必须在一次性 netns 内执行（由父进程重执行）。
fn scenario() {
    if let Err(e) = setup_fixtures() {
        skip(&format!("fixtures unavailable: {e}"));
        return;
    }
    for dst in [SERVER, SERVER_ONLINK] {
        assert!(
            route_get(dst).contains(UP_IFNAME),
            "fixture precondition: {dst} should currently route via {UP_IFNAME}, got {:?}",
            route_get(dst)
        );
    }

    let mut assemble =
        OsAssemble::new(config(&[SERVER, SERVER_ONLINK])).expect("dummy TUN ifindex resolves");

    // 1) 完整 apply（含 exclude）成功 —— 缺 NLM_F_CREATE 时这里是 ENOENT。
    let report = assemble.apply().expect("real apply (exclude) must succeed");
    assert_eq!(
        report.excludes_added, 2,
        "both exclude routes should be created"
    );
    assert_eq!(report.addrs_added, 1, "TUN address should be assigned");

    // 2) 独立观察：每个 exclude /32 都用接管前出口（oif + 可选网关），不是 TUN。
    for (dst, expected_gateway) in [(SERVER, Some(UP_GATEWAY)), (SERVER_ONLINK, None)] {
        let lines = route_lines(dst);
        assert_eq!(lines.len(), 1, "exactly one /32 route for {dst}: {lines:?}");
        assert!(
            lines[0].contains(UP_IFNAME),
            "exclude route for {dst} must use {UP_IFNAME}: {lines:?}"
        );
        match expected_gateway {
            Some(gw) => assert!(
                lines[0].contains(&gw.to_string()),
                "exclude route for {dst} must keep gateway {gw}: {lines:?}"
            ),
            None => assert!(
                !lines[0].contains("via"),
                "on-link exclude for {dst} must not carry a gateway: {lines:?}"
            ),
        }
        let got = route_get(dst);
        assert!(
            got.contains(UP_IFNAME) && !got.contains(TUN_IFNAME),
            "AC-G5-03: `ip route get {dst}` must not use dev {TUN_IFNAME}: {got:?}"
        );
    }
    // 子网路由仍在 TUN 上。
    let subnet = ip(&["route", "show", "table", "main"]).unwrap_or_default();
    assert!(
        subnet
            .lines()
            .any(|l| l.contains(&format!("{TUN_SUBNET}/{TUN_PREFIXLEN}")) && l.contains(TUN_IFNAME)),
        "subnet route must stay on {TUN_IFNAME}: {subnet:?}"
    );

    // 3) 二次 apply 幂等：无错误、无重复路由、exclude 记为 skip。
    let second = assemble.apply().expect("second apply must be idempotent");
    assert_eq!(second.excludes_added, 0, "no duplicate exclude route");
    assert!(
        second.routes_skipped >= 1,
        "existing routes must be skipped"
    );
    for dst in [SERVER, SERVER_ONLINK] {
        assert_eq!(
            route_lines(dst).len(),
            1,
            "second apply must not duplicate the /32 route for {dst}"
        );
    }

    // 4) cleanup：本实例条目全部清除，原出口不变。
    let cleanup = assemble.cleanup().expect("cleanup must succeed");
    assert_eq!(cleanup.excludes_removed, 2);
    assert_eq!(cleanup.addrs_removed, 1);
    for dst in [SERVER, SERVER_ONLINK] {
        assert!(
            route_lines(dst).is_empty(),
            "exclude route for {dst} must be removed: {:?}",
            route_lines(dst)
        );
    }
    let addrs = ip(&["-o", "addr", "show", "dev", TUN_IFNAME]).unwrap_or_default();
    assert!(
        !addrs.contains(&TUN_IP.to_string()),
        "TUN address must be removed: {addrs:?}"
    );
    let all = ip(&["route", "show", "table", "main"]).unwrap_or_default();
    assert!(
        !all.lines()
            .any(|l| l.contains(&format!("{TUN_SUBNET}/{TUN_PREFIXLEN}"))),
        "subnet route must be removed: {all:?}"
    );
    assert!(
        route_get(SERVER).contains(UP_IFNAME),
        "pre-takeover default egress must survive cleanup: {:?}",
        route_get(SERVER)
    );

    // 5) E5 S4 形状：router netns 没有默认路由，代理服务器在直连子网里。
    ip(&["route", "del", "default"]).expect("delete fixture default route");
    let mut onlink_only =
        OsAssemble::new(config(&[SERVER_ONLINK])).expect("dummy TUN ifindex resolves");
    let report = onlink_only
        .apply()
        .expect("on-link exclude must resolve without a default route");
    assert_eq!(report.excludes_added, 1);
    let lines = route_lines(SERVER_ONLINK);
    assert_eq!(lines.len(), 1, "on-link /32 route: {lines:?}");
    assert!(
        lines[0].contains(UP_IFNAME) && !lines[0].contains("via"),
        "S4 shape: on-link exclude must be dev {UP_IFNAME} without gateway: {lines:?}"
    );
    let got = route_get(SERVER_ONLINK);
    assert!(
        got.contains(UP_IFNAME) && !got.contains(TUN_IFNAME),
        "S4 shape: `ip route get {SERVER_ONLINK}` must not use dev {TUN_IFNAME}: {got:?}"
    );
    let cleanup = onlink_only.cleanup().expect("on-link cleanup");
    assert_eq!(cleanup.excludes_removed, 1);

    // 6) 无路由可解析时必须显式报错且零写入（不许回退 dev TUN）。
    let mut unresolved = OsAssemble::new(config(&[SERVER])).expect("dummy TUN ifindex resolves");
    let err = unresolved
        .apply()
        .expect_err("exclude without any pre-takeover route must fail explicitly");
    assert!(
        err.to_string().contains("no pre-takeover route"),
        "explicit failure expected, got {err}"
    );
    let addrs = ip(&["-o", "addr", "show", "dev", TUN_IFNAME]).unwrap_or_default();
    assert!(
        !addrs.contains(&TUN_IP.to_string()),
        "unresolved exclude must not mutate the TUN: {addrs:?}"
    );

    // 7) 默认路由接管：接管前已存在默认路由时，apply(default_route) 必须能
    //    创建/更新而不是 EEXIST（NLM_F_CREATE 语义），二次 apply 幂等，
    //    cleanup 只删本实例的默认路由。
    ip(&[
        "route",
        "add",
        "default",
        "via",
        &UP_GATEWAY.to_string(),
        "dev",
        UP_IFNAME,
    ])
    .expect("restore fixture default route");
    let mut takeover = OsAssemble::new(config_with(&[], true)).expect("dummy TUN ifindex resolves");
    let report = takeover
        .apply()
        .expect("default route takeover must succeed");
    assert!(report.default_route_added, "default route should be added");
    let defaults = ip(&["route", "show", "table", "main", "default"]).unwrap_or_default();
    assert!(
        defaults.contains(TUN_IFNAME),
        "default route must move to {TUN_IFNAME}: {defaults:?}"
    );
    assert!(
        !defaults.contains(UP_IFNAME),
        "pre-takeover default must be replaced, not duplicated: {defaults:?}"
    );
    let second = takeover
        .apply()
        .expect("second apply with default route must be idempotent");
    assert_eq!(
        second.routes_added, 0,
        "second apply must not add any route"
    );
    let defaults = ip(&["route", "show", "table", "main", "default"]).unwrap_or_default();
    assert_eq!(
        defaults.lines().filter(|l| l.contains(TUN_IFNAME)).count(),
        1,
        "no duplicate default route: {defaults:?}"
    );
    let cleanup = takeover.cleanup().expect("default route cleanup");
    // 子网路由由内核随地址自动生成（本实例未显式创建），cleanup 只删自己的默认路由。
    assert_eq!(
        cleanup.routes_removed, 1,
        "default route removed by this instance: {cleanup:?}"
    );
    assert_eq!(cleanup.addrs_removed, 1, "TUN address removed: {cleanup:?}");
    let defaults = ip(&["route", "show", "table", "main", "default"]).unwrap_or_default();
    assert!(
        !defaults.contains(TUN_IFNAME),
        "default route via {TUN_IFNAME} must be removed: {defaults:?}"
    );

    eprintln!("PASS: real netlink apply/cleanup scenario completed in netns");
}

/// 父进程：探测 user/net namespace 可用性 → 在 `unshare -rn` 内重执行本测试。
fn run_in_fresh_netns() {
    let available = Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !available {
        skip("unshare -rn unavailable (no unprivileged user+net namespace)");
        return;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new("unshare")
        .args(["-rn"])
        .arg(&exe)
        .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
        .env(CHILD_ENV, "1")
        .status()
        .expect("spawn unshare child");
    assert!(status.success(), "netns child scenario failed: {status}");
}

#[test]
#[ignore = "requires user+net namespace (unshare -rn) and NET_ADMIN; run with --ignored"]
fn os_assemble_real_netlink_exclude_idempotent_cleanup() {
    if std::env::var_os(CHILD_ENV).is_some() {
        if !assert_fresh_netns() {
            return;
        }
        scenario();
        return;
    }
    run_in_fresh_netns();
}
