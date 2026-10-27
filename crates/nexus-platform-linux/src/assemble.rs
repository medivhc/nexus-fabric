//! OS 装配顶层编排（`OsAssemble` 生产 API）。
//!
//! E4 驱动只调这里，不直接碰 netlink（教训：e4-must-use-production-path）。
//!
//! - `apply()`：幂等装配（地址 + 子网路由 + 可选默认路由），事务性；
//! - `cleanup()`：精确删除本实例创建的条目（�等）；
//! - `dry_run` 时零 netlink 写。

use nexus_platform::PlatformError;

use crate::addr::{AssignOutcome, assign_addr, remove_addr};
use crate::netlink::{NlSocket, RouteEntry, ifname_to_index};
use crate::op_log::OpLog;
use crate::route::{ApplyReport, NetworkSnapshot, RoutePlan, nl_err};

/// 排除路由的出口（接管前路由的接口 + 网关）。
///
/// 语义：exclude CIDR 必须沿用**接管前**该目的地址的实际出口（最长前缀匹配；
/// 没有更具体路由时用默认路由），保证代理服务器自身流量不经 TUN
/// （spec §9.8 / D4.3、AC-G5-03）。`gateway=None` 表示 on-link
/// （`dev <oif>` 直连，例如目的地址就在直连子网里）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExcludeEgress {
    /// 出口接口 index（接管前路由的 oif，非 TUN）。
    pub oif: u32,
    /// 路由网关（None = on-link 直连）。
    pub gateway: Option<[u8; 4]>,
}

/// OS 装配配置。
#[derive(Debug, Clone)]
pub struct OsAssembleConfig {
    /// TUN 接口名。
    pub ifname: String,
    /// TUN 地址（如 [10, 99, 0, 1]）。
    pub tun_ip: [u8; 4],
    /// 前缀长度（如 24）。
    pub prefixlen: u8,
    /// 虚拟子网路由目标（如 ([10, 99, 0, 0], 24)）。
    pub subnet: ([u8; 4], u8),
    /// 是否加默认路由（显式 opt-in，O3）。
    pub default_route: bool,
    /// 干跑模式（O4：零 netlink 写）。
    pub dry_run: bool,
    /// 操作日志路径（O6）；`None` → 当前目录 `os_assemble.log`。
    pub log_path: Option<std::path::PathBuf>,
    /// 需要绕开 TUN 的目的 CIDR（代理服务器 /32 / 用户排除）；默认空。
    pub exclude_dst_cidrs: Vec<([u8; 4], u8)>,
    /// exclude 路由出口覆盖：`(目的 CIDR, 接管前出口)`。
    ///
    /// nexusd 装配层在接管前用 [`capture_egress_for`] 逐项捕获真实值传入；
    /// 未提供的项由 `apply()` 从接管前路由快照解析（最长前缀 → 默认路由）。
    /// 解析不到 → `apply()` 显式失败，**绝不**静默回退 `dev <TUN>`。
    pub exclude_egress: Vec<(([u8; 4], u8), ExcludeEgress)>,
}

/// 探测**接管前**到达 `dst` 的实际出口（只读 netlink）。
///
/// 返回 `Ok(None)` 表示当前路由表既没有覆盖该目的地的具体路由、也没有默认
/// 路由；调用方必须显式处理（报错/降级），不能把 exclude 路由挂到 TUN 上。
pub fn capture_egress_for(dst: ([u8; 4], u8)) -> Result<Option<ExcludeEgress>, PlatformError> {
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
    let routes = nl.list_routes().map_err(nl_err("list routes"))?;
    Ok(pick_egress_for(&routes, dst, 0))
}

/// 路由前缀是否覆盖某个 IPv4 地址。
fn route_covers(route_dst: ([u8; 4], u8), ip: [u8; 4]) -> bool {
    let (net, plen) = route_dst;
    if plen > 32 {
        return false;
    }
    let mask = if plen == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(plen))
    };
    (u32::from_be_bytes(net) & mask) == (u32::from_be_bytes(ip) & mask)
}

/// 从路由快照里挑 `dst` 的接管前出口（纯函数）。
///
/// 规则：先做最长前缀匹配（这样直连子网里的代理服务器走 on-link 出口，
/// 例如 E5 S4 的 router netns 只有直连路由、没有默认路由）；
/// 没有具体路由时退回默认路由（带网关优先）；`tun_ifindex != 0` 时排除
/// 指向 TUN 自身的路由（防止重启后残留状态被当作“原出口”）。
fn pick_egress_for(
    routes: &[RouteEntry],
    dst: ([u8; 4], u8),
    tun_ifindex: u32,
) -> Option<ExcludeEgress> {
    let usable = |r: &RouteEntry| r.oif != 0 && r.oif != tun_ifindex;

    let specific = routes
        .iter()
        .filter(|r| usable(r))
        .filter_map(|r| r.dst.map(|d| (d, r)))
        .filter(|(d, _)| route_covers(*d, dst.0))
        .max_by_key(|(d, _)| d.1);
    if let Some((_, r)) = specific {
        return Some(ExcludeEgress {
            oif: r.oif,
            gateway: r.gateway,
        });
    }

    let mut defaults: Vec<&RouteEntry> = routes
        .iter()
        .filter(|r| r.dst.is_none() && usable(r))
        .collect();
    defaults.sort_by_key(|r| r.gateway.is_none());
    defaults.first().map(|r| ExcludeEgress {
        oif: r.oif,
        gateway: r.gateway,
    })
}

/// 解析单个 exclude 出口（纯函数，便于单测）：
/// 调用方捕获的覆盖值优先；否则从快照解析；拿不到 → 显式错误。
fn resolve_exclude_egress(
    configured: Option<ExcludeEgress>,
    routes: &[RouteEntry],
    dst: ([u8; 4], u8),
    tun_ifindex: u32,
) -> Result<ExcludeEgress, PlatformError> {
    if let Some(egress) = configured {
        if egress.oif == tun_ifindex {
            return Err(PlatformError::Io {
                operation: "os assemble exclude route".into(),
                message: format!(
                    "exclude egress oif {} is the TUN itself; refusing to route excludes via the TUN",
                    egress.oif
                ),
            });
        }
        return Ok(egress);
    }
    pick_egress_for(routes, dst, tun_ifindex).ok_or_else(|| PlatformError::Io {
        operation: "os assemble exclude route".into(),
        message: format!(
            "no pre-takeover route for {}.{}.{}.{}/{}; refusing to install the exclude route via the TUN interface",
            dst.0[0], dst.0[1], dst.0[2], dst.0[3], dst.1
        ),
    })
}

/// 清理报告（O6 可观测）。
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    /// 删除的地址数。
    pub addrs_removed: u32,
    /// 删除的路由数。
    pub routes_removed: u32,
    /// 删除的排除路由数。
    pub excludes_removed: u32,
}

/// 本实例创建的 exclude 路由（cleanup 用同一出口精确删除）。
#[derive(Debug, Clone, Copy)]
struct AddedExclude {
    dst: ([u8; 4], u8),
    egress: ExcludeEgress,
}

/// OS 装配器：`apply()` / `cleanup()` 精确配对。
pub struct OsAssemble {
    config: OsAssembleConfig,
    ifindex: u32,
    added_addr: bool,
    added_subnet_route: bool,
    added_default_route: bool,
    added_excludes: Vec<AddedExclude>,
    op_log: OpLog,
}

impl OsAssemble {
    /// 创建（解析接口 index；不存在 → NotFound）。
    pub fn new(config: OsAssembleConfig) -> Result<Self, PlatformError> {
        let ifindex = ifname_to_index(&config.ifname);
        if ifindex == 0 {
            return Err(PlatformError::NotFound {
                key: format!("interface {}", config.ifname),
            });
        }
        let op_log = OpLog::new(config.log_path.clone());
        Ok(OsAssemble {
            config,
            ifindex,
            added_addr: false,
            added_subnet_route: false,
            added_default_route: false,
            added_excludes: Vec::new(),
            op_log,
        })
    }

    /// 事务性装配（O1/O5）：
    /// 1. 拍快照；
    /// 2. �等加地址、子网路由、（可选）默认路由；
    /// 3. 任一步失败 → rollback 到快照。
    pub fn apply(&mut self) -> Result<ApplyReport, PlatformError> {
        let ip_str = format!(
            "{}.{}.{}.{}",
            self.config.tun_ip[0],
            self.config.tun_ip[1],
            self.config.tun_ip[2],
            self.config.tun_ip[3]
        );
        self.op_log.log(
            "apply_start",
            &[
                ("ifname", &self.config.ifname),
                ("tun_ip", &ip_str),
                (
                    "dry_run",
                    if self.config.dry_run { "true" } else { "false" },
                ),
            ],
        );
        let before = self.snapshot()?;
        let plan = RoutePlan {
            ifname: self.config.ifname.clone(),
            tun_ip: self.config.tun_ip,
            prefixlen: self.config.prefixlen,
            subnet: self.config.subnet,
            default_route: self.config.default_route,
            gateway: None,
        };

        if self.config.dry_run {
            let mut report = crate::route::apply(&plan, true)?;
            report.excludes_added = self.config.exclude_dst_cidrs.len() as u32;
            report.default_route_added = self.config.default_route;
            for (ip, prefix) in &self.config.exclude_dst_cidrs {
                let egress = self
                    .config
                    .exclude_egress
                    .iter()
                    .find(|(d, _)| d == &(*ip, *prefix))
                    .map(|(_, e)| *e);
                report.actions.push(format!(
                    "exclude {}.{}.{}.{}/{prefix} via {:?} oif={:?}",
                    ip[0],
                    ip[1],
                    ip[2],
                    ip[3],
                    egress.and_then(|e| e.gateway),
                    egress.map(|e| e.oif)
                ));
            }
            self.op_log.log(
                "apply_dry_run",
                &[("ifname", &self.config.ifname), ("result", "ok")],
            );
            return Ok(report);
        }

        // P5-b：exclude 路由出口必须来自**接管前**路由（快照在写入前拍摄）。
        // 每个目的 CIDR 独立解析（最长前缀 → 默认路由）；解析失败 → 在任何写入
        // 之前显式报错，绝不静默回退 `dev <TUN>`。
        let mut exclude_plan: Vec<(([u8; 4], u8), ExcludeEgress)> = Vec::new();
        for dst in &self.config.exclude_dst_cidrs {
            let configured = self
                .config
                .exclude_egress
                .iter()
                .find(|(d, _)| d == dst)
                .map(|(_, e)| *e);
            let egress = resolve_exclude_egress(configured, &before.routes, *dst, self.ifindex)
                .inspect_err(|e| {
                    self.op_log.log(
                        "exclude_egress_unresolved",
                        &[
                            ("ifname", &self.config.ifname),
                            ("dst", &format!("{dst:?}")),
                            ("reason", &e.to_string()),
                        ],
                    );
                })?;
            self.op_log.log(
                "exclude_egress_resolved",
                &[
                    ("ifname", &self.config.ifname),
                    ("dst", &format!("{dst:?}")),
                    ("oif", &egress.oif.to_string()),
                    ("gateway", &format!("{:?}", egress.gateway)),
                ],
            );
            exclude_plan.push((*dst, egress));
        }

        // 地址（�等）。
        match assign_addr(
            &self.config.ifname,
            self.config.tun_ip,
            self.config.prefixlen,
        ) {
            Ok(AssignOutcome::Added) => {
                self.added_addr = true;
                self.op_log.log(
                    "addr_added",
                    &[("ifname", &self.config.ifname), ("ip", &ip_str)],
                );
            }
            Ok(AssignOutcome::AlreadyPresent) => {
                self.op_log.log(
                    "addr_skipped",
                    &[("ifname", &self.config.ifname), ("ip", &ip_str)],
                );
            }
            Err(e) => {
                self.op_log.log(
                    "apply_failed",
                    &[("ifname", &self.config.ifname), ("stage", "assign_addr")],
                );
                return Err(e);
            }
        }

        // 路由（�等 + 失败 rollback）。
        let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
        let mut report = ApplyReport::default();

        let apply_route = |nl: &mut NlSocket,
                           dst: Option<([u8; 4], u8)>,
                           added_flag: &mut bool,
                           report: &mut ApplyReport|
         -> Result<(), PlatformError> {
            let routes = nl.list_routes().map_err(nl_err("list routes"))?;
            let exists = routes
                .iter()
                .any(|r| r.dst == dst && r.oif == self.ifindex && r.gateway.is_none());
            let dst_str = dst
                .map(|(ip, plen)| format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], plen))
                .unwrap_or_else(|| "default".to_string());
            if exists {
                report.routes_skipped += 1;
                self.op_log.log(
                    "route_skipped",
                    &[("ifname", &self.config.ifname), ("dst", &dst_str)],
                );
                return Ok(());
            }
            nl.new_route(dst, self.ifindex, None)
                .map_err(nl_err("add route"))?;
            *added_flag = true;
            report.routes_added += 1;
            self.op_log.log(
                "route_added",
                &[("ifname", &self.config.ifname), ("dst", &dst_str)],
            );
            Ok(())
        };

        let result = (|| -> Result<(), PlatformError> {
            apply_route(
                &mut nl,
                Some(self.config.subnet),
                &mut self.added_subnet_route,
                &mut report,
            )?;
            if self.config.default_route {
                apply_route(&mut nl, None, &mut self.added_default_route, &mut report)?;
            }
            // 排除路由：经接管前路由出口（oif+gateway），不经 TUN
            // （只删本实例添加项；cleanup 用同一出口精确匹配）。
            for (dst, egress) in &exclude_plan {
                let routes = nl.list_routes().map_err(nl_err("list routes"))?;
                let dst_key = Some(*dst);
                let exists = routes.iter().any(|r| {
                    r.dst == dst_key && r.oif == egress.oif && r.gateway == egress.gateway
                });
                if exists {
                    report.routes_skipped += 1;
                    self.op_log.log(
                        "exclude_route_skipped",
                        &[
                            ("ifname", &self.config.ifname),
                            ("dst", &format!("{dst:?}")),
                        ],
                    );
                    continue;
                }
                nl.new_route(dst_key, egress.oif, egress.gateway)
                    .map_err(nl_err("add exclude route"))?;
                self.added_excludes.push(AddedExclude {
                    dst: *dst,
                    egress: *egress,
                });
                report.excludes_added += 1;
                self.op_log.log(
                    "exclude_route_added",
                    &[
                        ("ifname", &self.config.ifname),
                        ("dst", &format!("{dst:?}")),
                        ("oif", &egress.oif.to_string()),
                        ("gateway", &format!("{:?}", egress.gateway)),
                    ],
                );
            }
            report.default_route_added = self.added_default_route;
            Ok(())
        })();

        if let Err(e) = result {
            self.op_log.log(
                "apply_failed",
                &[("ifname", &self.config.ifname), ("stage", "apply_route")],
            );
            // O1：回滚地址（路由还没加或已回滚逻辑内）。
            if self.added_addr {
                let _ = remove_addr(
                    &self.config.ifname,
                    self.config.tun_ip,
                    self.config.prefixlen,
                );
                self.added_addr = false;
                self.op_log
                    .log("rollback_addr_removed", &[("ifname", &self.config.ifname)]);
            }
            self.op_log
                .log("rollback_start", &[("ifname", &self.config.ifname)]);
            if let Err(rb_err) = crate::route::rollback(&before) {
                self.op_log
                    .log("rollback_failed", &[("ifname", &self.config.ifname)]);
                return Err(PlatformError::Io {
                    operation: "os assemble rollback".into(),
                    message: format!("apply failed: {e}; rollback ALSO failed: {rb_err}"),
                });
            }
            self.op_log
                .log("rollback_done", &[("ifname", &self.config.ifname)]);
            return Err(e);
        }

        report.addrs_added = u32::from(self.added_addr);
        report.addrs_skipped = u32::from(!self.added_addr);
        self.op_log.log(
            "apply_done",
            &[
                ("ifname", &self.config.ifname),
                ("addrs_added", &report.addrs_added.to_string()),
                ("routes_added", &report.routes_added.to_string()),
            ],
        );
        Ok(report)
    }

    /// 清理本实例创建的条目（�等，O2）。
    pub fn cleanup(&mut self) -> Result<CleanupReport, PlatformError> {
        self.op_log
            .log("cleanup_start", &[("ifname", &self.config.ifname)]);
        let mut report = CleanupReport::default();
        let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;

        if self.added_default_route {
            let routes = nl.list_routes().map_err(nl_err("list routes"))?;
            let exists = routes
                .iter()
                .any(|r| r.dst.is_none() && r.oif == self.ifindex);
            if exists {
                nl.del_route(None, self.ifindex, None)
                    .map_err(nl_err("delete default route"))?;
                report.routes_removed += 1;
                self.op_log.log(
                    "route_removed",
                    &[("ifname", &self.config.ifname), ("dst", "default")],
                );
            }
            self.added_default_route = false;
        }
        if !self.added_excludes.is_empty() {
            let routes = nl.list_routes().map_err(nl_err("list routes"))?;
            let excludes = std::mem::take(&mut self.added_excludes);
            for AddedExclude { dst, egress } in excludes {
                if routes
                    .iter()
                    .any(|r| r.dst == Some(dst) && r.oif == egress.oif)
                {
                    nl.del_route(Some(dst), egress.oif, egress.gateway)
                        .map_err(nl_err("delete exclude route"))?;
                    report.excludes_removed += 1;
                    self.op_log.log(
                        "exclude_route_removed",
                        &[
                            ("ifname", &self.config.ifname),
                            ("dst", &format!("{dst:?}")),
                        ],
                    );
                }
            }
        }
        if self.added_subnet_route {
            let routes = nl.list_routes().map_err(nl_err("list routes"))?;
            let exists = routes
                .iter()
                .any(|r| r.dst == Some(self.config.subnet) && r.oif == self.ifindex);
            if exists {
                nl.del_route(Some(self.config.subnet), self.ifindex, None)
                    .map_err(nl_err("delete subnet route"))?;
                report.routes_removed += 1;
                let (ip, plen) = self.config.subnet;
                let dst = format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], plen);
                self.op_log.log(
                    "route_removed",
                    &[("ifname", &self.config.ifname), ("dst", &dst)],
                );
            }
            self.added_subnet_route = false;
        }
        if self.added_addr {
            remove_addr(
                &self.config.ifname,
                self.config.tun_ip,
                self.config.prefixlen,
            )?;
            report.addrs_removed += 1;
            self.added_addr = false;
            self.op_log
                .log("addr_removed", &[("ifname", &self.config.ifname)]);
        }
        self.op_log.log(
            "cleanup_done",
            &[
                ("ifname", &self.config.ifname),
                ("addrs_removed", &report.addrs_removed.to_string()),
                ("routes_removed", &report.routes_removed.to_string()),
            ],
        );
        Ok(report)
    }

    /// 当前快照（只读）。
    fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError> {
        crate::route::snapshot()
    }

    /// 配置（只读）。
    #[must_use]
    pub fn config(&self) -> &OsAssembleConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_missing_interface_returns_not_found() {
        let config = OsAssembleConfig {
            ifname: "nxnonexist0".into(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: false,
            dry_run: true,
            log_path: None,
            exclude_dst_cidrs: Vec::new(),
            exclude_egress: Vec::new(),
        };
        let r = OsAssemble::new(config);
        assert!(matches!(r, Err(PlatformError::NotFound { .. })));
    }

    #[test]
    fn dry_run_apply_returns_plan() {
        let config = OsAssembleConfig {
            ifname: "lo".into(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: false,
            dry_run: true,
            log_path: Some(std::env::temp_dir().join("os-assemble-test.log")),
            exclude_dst_cidrs: Vec::new(),
            exclude_egress: Vec::new(),
        };
        let mut asm = OsAssemble::new(config).expect("lo exists");
        let report = asm.apply().expect("dry-run");
        assert!(report.dry_run);
        assert_eq!(report.addrs_added, 0);
        // cleanup 在 dry-run 后应无操作。
        let cleanup = asm.cleanup().expect("cleanup");
        assert_eq!(cleanup.addrs_removed, 0);
        assert_eq!(cleanup.routes_removed, 0);
    }

    #[test]
    fn os_assemble_dry_run_reports_excludes_and_default_route() {
        let config = OsAssembleConfig {
            ifname: "lo".to_string(),
            tun_ip: [10, 99, 0, 1],
            prefixlen: 24,
            subnet: ([10, 99, 0, 0], 24),
            default_route: true,
            dry_run: true,
            log_path: Some(std::env::temp_dir().join("os-assemble-excludes-test.log")),
            exclude_dst_cidrs: vec![([203, 0, 113, 7], 32), ([198, 51, 100, 9], 32)],
            exclude_egress: vec![(
                ([203, 0, 113, 7], 32),
                ExcludeEgress {
                    oif: 2,
                    gateway: Some([192, 168, 1, 1]),
                },
            )],
        };
        let mut assemble = OsAssemble::new(config).expect("lo exists");
        let report = assemble.apply().expect("dry run");
        assert!(report.dry_run);
        assert_eq!(report.excludes_added, 2);
        assert!(report.default_route_added);
        assert!(report.actions.iter().any(|a| a.contains("203.0.113.7/32")));
        assert!(report.actions.iter().any(|a| a.contains("oif=Some(2)")));
        let cleanup = assemble.cleanup().expect("dry cleanup");
        assert_eq!(cleanup.excludes_removed, 0);
    }

    /// P5-b：最长前缀优先 —— E5 S4 的 router netns 没有默认路由，
    /// 代理服务器就在直连子网里，exclude 必须走 on-link 出口而不是 TUN。
    #[test]
    fn pick_egress_prefers_specific_route_over_default() {
        let routes = vec![
            RouteEntry {
                dst: Some(([10, 200, 2, 0], 24)),
                oif: 4,
                gateway: None,
            },
            RouteEntry {
                dst: Some(([10, 200, 1, 0], 24)),
                oif: 5,
                gateway: None,
            },
            RouteEntry {
                dst: None,
                oif: 3,
                gateway: Some([10, 200, 0, 254]),
            },
        ];
        // 直连子网内 → on-link 出口（不是默认路由）。
        assert_eq!(
            pick_egress_for(&routes, ([10, 200, 2, 2], 32), 9),
            Some(ExcludeEgress {
                oif: 4,
                gateway: None
            })
        );
        // 无具体路由覆盖 → 默认路由兜底。
        assert_eq!(
            pick_egress_for(&routes, ([198, 51, 100, 7], 32), 9),
            Some(ExcludeEgress {
                oif: 3,
                gateway: Some([10, 200, 0, 254])
            })
        );
    }

    /// TUN 自身的路由（含残留的旧 exclude /32）不得被当作“接管前出口”。
    #[test]
    fn pick_egress_skips_tun_routes() {
        let routes = vec![
            // 残留的错误 exclude 路由：指向 TUN。
            RouteEntry {
                dst: Some(([198, 51, 100, 7], 32)),
                oif: 9,
                gateway: None,
            },
            RouteEntry {
                dst: Some(([10, 203, 0, 0], 24)),
                oif: 3,
                gateway: None,
            },
            RouteEntry {
                dst: None,
                oif: 9,
                gateway: Some([10, 99, 0, 254]),
            },
            RouteEntry {
                dst: None,
                oif: 3,
                gateway: Some([10, 203, 0, 2]),
            },
        ];
        // /32 指向 TUN → 跳过，回退到默认路由（oif=3）。
        assert_eq!(
            pick_egress_for(&routes, ([198, 51, 100, 7], 32), 9),
            Some(ExcludeEgress {
                oif: 3,
                gateway: Some([10, 203, 0, 2])
            })
        );
        // 唯一默认路由指向 TUN → 不选中。
        let tun_only = vec![RouteEntry {
            dst: None,
            oif: 9,
            gateway: Some([10, 0, 0, 1]),
        }];
        assert_eq!(pick_egress_for(&tun_only, ([198, 51, 100, 7], 32), 9), None);
    }

    /// P5-b：拿不到接管前出口时必须显式报错，不许回退 `dev <TUN>`。
    #[test]
    fn resolve_exclude_egress_errors_instead_of_tun_fallback() {
        let no_routes: Vec<RouteEntry> = Vec::new();
        let dst = ([198, 51, 100, 7], 32);
        let err = resolve_exclude_egress(None, &no_routes, dst, 5).expect_err("must error");
        let text = err.to_string();
        assert!(text.contains("no pre-takeover route"), "{text}");
        assert!(text.contains("198.51.100.7/32"), "{text}");
        assert!(text.contains("refusing"), "{text}");

        // 显式传入 TUN 自身作为出口 → 拒绝。
        let err = resolve_exclude_egress(
            Some(ExcludeEgress {
                oif: 5,
                gateway: Some([10, 99, 0, 254]),
            }),
            &no_routes,
            dst,
            5,
        )
        .expect_err("must reject tun egress");
        assert!(err.to_string().contains("TUN itself"), "{err}");

        // 显式值透传（nexusd 装配层捕获的真实出口）。
        let explicit = ExcludeEgress {
            oif: 3,
            gateway: Some([10, 203, 0, 2]),
        };
        assert_eq!(
            resolve_exclude_egress(Some(explicit), &no_routes, dst, 5).unwrap(),
            explicit
        );
    }
}
