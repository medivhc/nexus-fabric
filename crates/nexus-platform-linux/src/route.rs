//! 路由表事务性装配（O1/O3/O4/O5）。
//!
//! - `snapshot()`：拍当前地址+路由快照；
//! - `apply()`：�等装配（虚拟子网路由必做；默认路由需显式 `default_route=true`）；
//!   任一步失败 → 自动 `rollback()` 到快照；
//! - `rollback()`：按快照恢复（删多余的、补缺失的）；rollback 自身失败 →
//!   类型化错误（不静默）；
//! - `dry_run=true` 时零 netlink 写操作，只返回计划。

use nexus_platform::PlatformError;

pub(crate) use crate::addr::nl_err;
use crate::netlink::{AddrEntry, NlSocket, RouteEntry, ifname_to_index};

/// 网络状态快照（地址 + 路由）。
#[derive(Debug, Clone, Default)]
pub struct NetworkSnapshot {
    /// 全系统 IPv4 地址。
    pub addrs: Vec<AddrEntry>,
    /// 全系统 IPv4 路由。
    pub routes: Vec<RouteEntry>,
}

/// 路由装配计划。
#[derive(Debug, Clone)]
pub struct RoutePlan {
    /// TUN 接口名。
    pub ifname: String,
    /// TUN 地址（如 10.99.0.1/24）。
    pub tun_ip: [u8; 4],
    /// 前缀长度。
    pub prefixlen: u8,
    /// 虚拟子网路由目标（如 10.99.0.0/24）。
    pub subnet: ([u8; 4], u8),
    /// 是否加默认路由。**显式 opt-in**（O3）：调用方（CLI）必须要求
    /// `--default-route --yes-i-know` 双标志才可置 true。
    pub default_route: bool,
    /// 默认路由网关（None = 经接口直连）。
    pub gateway: Option<[u8; 4]>,
}

/// apply 结果报告（可观测 O6）。
#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    /// 新加的地址数。
    pub addrs_added: u32,
    /// 新加的路由数。
    pub routes_added: u32,
    /// 已存在跳过的地址数（�等）。
    pub addrs_skipped: u32,
    /// 已存在跳过的路由数（�等）。
    pub routes_skipped: u32,
    /// 是否为干跑。
    pub dry_run: bool,
    /// 计划执行的操作描述（干跑时为计划，非干跑时为实际执行）。
    pub actions: Vec<String>,
    /// 新加的排除路由数。
    pub excludes_added: u32,
    /// 是否新加默认路由。
    pub default_route_added: bool,
}

/// 拍快照（只读 netlink，不修改状态）。
pub fn snapshot() -> Result<NetworkSnapshot, PlatformError> {
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
    let addrs = nl.list_addrs().map_err(nl_err("list addresses"))?;
    let routes = nl.list_routes().map_err(nl_err("list routes"))?;
    Ok(NetworkSnapshot { addrs, routes })
}

/// 事务性装配（O1）：
/// 1. 拍快照；
/// 2. �等加地址 + 路由；
/// 3. 任一步失败 → 自动 rollback 到快照，返回原始错误。
pub fn apply(plan: &RoutePlan, dry_run: bool) -> Result<ApplyReport, PlatformError> {
    let before = snapshot()?;
    let ifindex = ifname_to_index(&plan.ifname);
    if ifindex == 0 {
        return Err(PlatformError::NotFound {
            key: format!("interface {}", plan.ifname),
        });
    }

    let mut report = ApplyReport {
        dry_run,
        ..Default::default()
    };

    // 纯计算：需要加什么（�等判断）。
    let need_addr = !before
        .addrs
        .iter()
        .any(|a| a.ifindex == ifindex && a.ip == plan.tun_ip && a.prefixlen == plan.prefixlen);
    let need_subnet_route = !before
        .routes
        .iter()
        .any(|r| r.dst == Some(plan.subnet) && r.oif == ifindex && r.gateway == plan.gateway);
    let need_default_route = plan.default_route
        && !before
            .routes
            .iter()
            .any(|r| r.dst.is_none() && r.oif == ifindex && r.gateway == plan.gateway);

    if dry_run {
        // O4：零 netlink 写，只输出计划。
        if need_addr {
            report.actions.push(format!(
                "add addr {}.{}.{}.{}/{} dev {}",
                plan.tun_ip[0],
                plan.tun_ip[1],
                plan.tun_ip[2],
                plan.tun_ip[3],
                plan.prefixlen,
                plan.ifname
            ));
        }
        if need_subnet_route {
            report.actions.push(format!(
                "add route {}.{}.{}.{}/{} dev {}",
                plan.subnet.0[0],
                plan.subnet.0[1],
                plan.subnet.0[2],
                plan.subnet.0[3],
                plan.subnet.1,
                plan.ifname
            ));
        }
        if need_default_route {
            report
                .actions
                .push(format!("add default route dev {}", plan.ifname));
        }
        return Ok(report);
    }

    // 真实 apply：失败 → rollback。
    let result = apply_inner(
        plan,
        ifindex,
        need_addr,
        need_subnet_route,
        need_default_route,
        &mut report,
    );
    if let Err(e) = result {
        // O1：自动 rollback；rollback 失败 → 告警错误（不吞原始错误）。
        if let Err(rb_err) = rollback(&before) {
            return Err(PlatformError::Io {
                operation: "route apply rollback".into(),
                message: format!("apply failed: {e}; rollback ALSO failed: {rb_err}"),
            });
        }
        return Err(e);
    }
    Ok(report)
}

/// apply 的写操作部分（失败时由调用方 rollback）。
fn apply_inner(
    plan: &RoutePlan,
    ifindex: u32,
    need_addr: bool,
    need_subnet_route: bool,
    need_default_route: bool,
    report: &mut ApplyReport,
) -> Result<(), PlatformError> {
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;

    if need_addr {
        nl.new_addr(ifindex, plan.tun_ip, plan.prefixlen)
            .map_err(nl_err("add address"))?;
        report.addrs_added += 1;
        report
            .actions
            .push(format!("added addr dev {}", plan.ifname));
    } else {
        report.addrs_skipped += 1;
    }

    if need_subnet_route {
        nl.new_route(Some(plan.subnet), ifindex, None)
            .map_err(nl_err("add subnet route"))?;
        report.routes_added += 1;
        report
            .actions
            .push(format!("added subnet route dev {}", plan.ifname));
    } else {
        report.routes_skipped += 1;
    }

    if plan.default_route {
        if need_default_route {
            nl.new_route(None, ifindex, plan.gateway)
                .map_err(nl_err("add default route"))?;
            report.routes_added += 1;
            report
                .actions
                .push(format!("added default route dev {}", plan.ifname));
        } else {
            report.routes_skipped += 1;
        }
    }

    Ok(())
}

/// 回滚到快照（O1）：
/// - 删除当前有、快照没有的地址/路由；
/// - 恢复快照有、当前没有的地址/路由。
///
/// 幂等；自身失败返回类型化错误。
pub fn rollback(snapshot: &NetworkSnapshot) -> Result<(), PlatformError> {
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
    let current_addrs = nl.list_addrs().map_err(nl_err("list addresses"))?;
    let current_routes = nl.list_routes().map_err(nl_err("list routes"))?;

    // 删多余的地址。
    for a in &current_addrs {
        let in_snapshot = snapshot
            .addrs
            .iter()
            .any(|s| s.ifindex == a.ifindex && s.ip == a.ip && s.prefixlen == a.prefixlen);
        if !in_snapshot {
            nl.del_addr(a.ifindex, a.ip, a.prefixlen)
                .map_err(nl_err("rollback delete address"))?;
        }
    }
    // 补缺失的地址。
    for s in &snapshot.addrs {
        let present = current_addrs
            .iter()
            .any(|a| a.ifindex == s.ifindex && a.ip == s.ip && a.prefixlen == s.prefixlen);
        if !present {
            nl.new_addr(s.ifindex, s.ip, s.prefixlen)
                .map_err(nl_err("rollback restore address"))?;
        }
    }
    // 删多余的路由。
    for r in &current_routes {
        let in_snapshot = snapshot
            .routes
            .iter()
            .any(|s| s.dst == r.dst && s.oif == r.oif && s.gateway == r.gateway);
        if !in_snapshot {
            nl.del_route(r.dst, r.oif, r.gateway)
                .map_err(nl_err("rollback delete route"))?;
        }
    }
    // 补缺失的路由。
    for s in &snapshot.routes {
        let present = current_routes
            .iter()
            .any(|r| r.dst == s.dst && r.oif == s.oif && r.gateway == s.gateway);
        if !present {
            nl.new_route(s.dst, s.oif, s.gateway)
                .map_err(nl_err("rollback restore route"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_missing_interface_returns_not_found() {
        let plan = RoutePlan {
            ifname: "nxnonexist0".into(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: false,
            gateway: None,
        };
        let r = apply(&plan, true);
        assert!(matches!(r, Err(PlatformError::NotFound { .. })));
    }

    #[test]
    fn dry_run_reports_plan_without_writes() {
        // dry_run 纯计算：即使接口不存在也应先报 NotFound（接口检查在前）。
        // 这里只验证 RoutePlan 字段语义。
        let plan = RoutePlan {
            ifname: "lo".into(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: false,
            gateway: None,
        };
        // lo 存在；dry_run 不应写任何东西，只返回计划。
        let report = apply(&plan, true).expect("dry-run on lo should work");
        assert!(report.dry_run);
        assert_eq!(report.addrs_added, 0);
        assert_eq!(report.routes_added, 0);
    }
}
