//! P3.x OS 装配 E4 驱动（`platform.os-assemble`）。
//!
//! 安全红线：内部 `unshare(CLONE_NEWNET)` 进隔离 netns，**绝不动主网络**。
//! 无 `CAP_SYS_ADMIN` 时输出 `{"verdict":"SKIP",...}`。
//!
//! 装配语义只走生产 API（`OsAssemble::apply` / `cleanup`）；
//! 链路拉起（`set_link_up`）与 TUN 建设备是 E4 fixture（测试环境准备），
//! 不属于被测的 OS 装配语义。

use std::ffi::c_int;
use std::net::UdpSocket;
use std::time::Duration;

use nexus_platform_linux::addr::list_if_addrs;
use nexus_platform_linux::assemble::{OsAssemble, OsAssembleConfig};
use nexus_platform_linux::netlink::{NlSocket, ifname_to_index};
use nexus_platform_linux::route::snapshot;
use nexus_platform_linux::tun::TunFd;

/// `unshare` 标志：`CLONE_NEWNET`（`0x40000000`）。
const CLONE_NEWNET: c_int = 0x40000000;

unsafe extern "C" {
    fn unshare(flags: c_int) -> c_int;
}

const IFNAME: &str = "nxstest0";
const TUN_IP: [u8; 4] = [10, 99, 0, 1];
const PREFIXLEN: u8 = 24;
const SUBNET: ([u8; 4], u8) = ([10, 99, 0, 0], 24);

fn skip(reason: &str) {
    println!("{{\"verdict\":\"SKIP\",\"reason\":\"{reason}\"}}");
}

fn fail(reason: &str) -> ! {
    println!("{{\"verdict\":\"FAIL\",\"reason\":\"{reason}\"}}");
    std::process::exit(1);
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");

    // 1. 进隔离 netns（失败 → SKIP，不碰主网络）。
    // SAFETY：CLONE_NEWNET 为常量；失败返回 -1。
    let rc = unsafe { unshare(CLONE_NEWNET) };
    if rc != 0 {
        if json {
            skip("need CAP_SYS_ADMIN for unshare(CLONE_NEWNET)");
        } else {
            eprintln!("SKIP: need CAP_SYS_ADMIN for unshare(CLONE_NEWNET)");
        }
        return;
    }
    let netns_isolated = true;

    // 1.5 拉起 lo（unshare 后 lo 是 DOWN；本地交付需要 lo UP）。
    let lo_ifindex = ifname_to_index("lo");
    if lo_ifindex != 0 {
        let mut nl_lo = match NlSocket::open() {
            Ok(n) => n,
            Err(e) => fail(&format!("open netlink for lo: {e}")),
        };
        if let Err(e) = nl_lo.set_link_up(lo_ifindex) {
            fail(&format!("set lo up: {e}"));
        }
    }

    // 2. 建 TUN 设备。
    let _tun = match TunFd::open_tun(IFNAME.as_bytes()) {
        Ok(t) => t,
        Err(e) => fail(&format!("open tun: {e}")),
    };
    let ifindex = ifname_to_index(IFNAME);
    if ifindex == 0 {
        fail("ifname_to_index returned 0");
    }

    // 3. 拉起链路（UP）。
    let mut nl = match NlSocket::open() {
        Ok(n) => n,
        Err(e) => fail(&format!("open netlink: {e}")),
    };
    if let Err(e) = nl.set_link_up(ifindex) {
        fail(&format!("set link up: {e}"));
    }

    // 4. 生产 API：apply。
    let config = OsAssembleConfig {
        ifname: IFNAME.into(),
        tun_ip: TUN_IP,
        prefixlen: PREFIXLEN,
        subnet: SUBNET,
        default_route: false,
        dry_run: false,
        log_path: None,
        exclude_dst_cidrs: Vec::new(),
        exclude_egress: Vec::new(),
    };
    let mut asm = match OsAssemble::new(config) {
        Ok(a) => a,
        Err(e) => fail(&format!("OsAssemble::new: {e}")),
    };
    if let Err(e) = asm.apply() {
        fail(&format!("apply: {e}"));
    }

    // 5. 独立断言（只读查询，非生产路径的验证视角）。
    let addrs = list_if_addrs(IFNAME).unwrap_or_default();
    let addr_assigned = addrs
        .iter()
        .any(|a| a.ip == TUN_IP && a.prefixlen == PREFIXLEN);
    let routes = nl.list_routes().unwrap_or_default();
    let route_installed = routes
        .iter()
        .any(|r| r.dst == Some(SUBNET) && r.oif == ifindex);

    // 6. UDP 回显（地址可用性）。
    let udp_ok = udp_echo();

    // 7. 幂等：重复 apply，无重复地址/路由。
    let addrs_before = list_if_addrs(IFNAME).map(|v| v.len()).unwrap_or(0);
    let routes_before = nl
        .list_routes()
        .map(|v| v.iter().filter(|r| r.oif == ifindex).count())
        .unwrap_or(0);
    if let Err(e) = asm.apply() {
        fail(&format!("second apply: {e}"));
    }
    let addrs_after = list_if_addrs(IFNAME).map(|v| v.len()).unwrap_or(0);
    let routes_after = nl
        .list_routes()
        .map(|v| v.iter().filter(|r| r.oif == ifindex).count())
        .unwrap_or(0);
    let no_dup_addrs = addrs_before == addrs_after;
    let no_dup_routes = routes_before == routes_after;

    // 8. dry-run：零 netlink 写（快照前后一致）。
    let snap_before = snapshot().map(|s| (s.addrs.len(), s.routes.len()));
    let dry_config = OsAssembleConfig {
        ifname: IFNAME.into(),
        tun_ip: TUN_IP,
        prefixlen: PREFIXLEN,
        subnet: SUBNET,
        default_route: false,
        dry_run: true,
        log_path: None,
        exclude_dst_cidrs: Vec::new(),
        exclude_egress: Vec::new(),
    };
    let mut dry_asm = match OsAssemble::new(dry_config) {
        Ok(a) => a,
        Err(e) => fail(&format!("dry OsAssemble::new: {e}")),
    };
    let dry_report = match dry_asm.apply() {
        Ok(r) => r,
        Err(e) => fail(&format!("dry apply: {e}")),
    };
    let snap_after = snapshot().map(|s| (s.addrs.len(), s.routes.len()));
    let zero_writes =
        snap_before == snap_after && dry_report.addrs_added == 0 && dry_report.routes_added == 0;

    // 9. 退出清理：删地址/路由，断言干净。
    let cleanup_report = match asm.cleanup() {
        Ok(r) => r,
        Err(e) => fail(&format!("cleanup: {e}")),
    };
    let addrs_gone = list_if_addrs(IFNAME)
        .map(|v| !v.iter().any(|a| a.ip == TUN_IP))
        .unwrap_or(false);
    let routes_gone = nl
        .list_routes()
        .map(|v| !v.iter().any(|r| r.oif == ifindex))
        .unwrap_or(false);
    let _ = cleanup_report;

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"PASS\",",
                "\"netns\":{{\"isolated\":{}}},",
                "\"addr\":{{\"assigned\":{}}},",
                "\"route\":{{\"subnet_installed\":{}}},",
                "\"echo\":{{\"udp_ok\":{}}},",
                "\"idempotent\":{{\"no_dup_addrs\":{},\"no_dup_routes\":{}}},",
                "\"dry_run\":{{\"zero_netlink_writes\":{}}},",
                "\"cleanup\":{{\"addrs_removed\":{},\"routes_removed\":{}}}}}"
            ),
            netns_isolated,
            addr_assigned,
            route_installed,
            udp_ok,
            no_dup_addrs,
            no_dup_routes,
            zero_writes,
            addrs_gone,
            routes_gone,
        );
        let ok = addr_assigned
            && route_installed
            && udp_ok
            && no_dup_addrs
            && no_dup_routes
            && zero_writes
            && addrs_gone
            && routes_gone;
        if !ok {
            std::process::exit(1);
        }
    } else {
        println!("netns.isolated={netns_isolated}");
        println!("addr.assigned={addr_assigned}");
        println!("route.subnet_installed={route_installed}");
        println!("echo.udp_ok={udp_ok}");
        println!("idempotent.no_dup_addrs={no_dup_addrs} no_dup_routes={no_dup_routes}");
        println!("dry_run.zero_netlink_writes={zero_writes}");
        println!("cleanup.addrs_removed={addrs_gone} routes_removed={routes_gone}");
    }
}

/// UDP 回显：绑 TUN 地址自发自收（验证地址可用）。
fn udp_echo() -> bool {
    let bind_addr = format!("{}.{}.{}.{}:0", TUN_IP[0], TUN_IP[1], TUN_IP[2], TUN_IP[3]);
    let sock = match UdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let local = match sock.local_addr() {
        Ok(a) => a,
        Err(_) => return false,
    };
    if sock.set_read_timeout(Some(Duration::from_secs(3))).is_err() {
        return false;
    }
    // 目标：自己的地址（内核本地交付，验证地址已生效）。
    let target = format!(
        "{}.{}.{}.{}:{}",
        TUN_IP[0],
        TUN_IP[1],
        TUN_IP[2],
        TUN_IP[3],
        local.port()
    );
    if sock.send_to(b"os-assemble-echo", &target).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => &buf[..n] == b"os-assemble-echo",
        Err(_) => false,
    }
}
