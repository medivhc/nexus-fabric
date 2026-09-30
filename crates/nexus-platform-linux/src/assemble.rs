//! OS 装配顶层编排（`OsAssemble` 生产 API）。
//!
//! E4 驱动只调这里，不直接碰 netlink（教训：e4-must-use-production-path）。
//!
//! - `apply()`：幂等装配（地址 + 子网路由 + 可选默认路由），事务性；
//! - `cleanup()`：精确删除本实例创建的条目（�等）；
//! - `dry_run` 时零 netlink 写。

use nexus_platform::PlatformError;

use crate::addr::{AssignOutcome, assign_addr, remove_addr};
use crate::netlink::{NlSocket, ifname_to_index};
use crate::route::{ApplyReport, NetworkSnapshot, RoutePlan, nl_err};

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
}

/// 清理报告（O6 可观测）。
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    /// 删除的地址数。
    pub addrs_removed: u32,
    /// 删除的路由数。
    pub routes_removed: u32,
}

/// OS 装配器：`apply()` / `cleanup()` 精确配对。
pub struct OsAssemble {
    config: OsAssembleConfig,
    ifindex: u32,
    added_addr: bool,
    added_subnet_route: bool,
    added_default_route: bool,
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
        Ok(OsAssemble {
            config,
            ifindex,
            added_addr: false,
            added_subnet_route: false,
            added_default_route: false,
        })
    }

    /// 事务性装配（O1/O5）：
    /// 1. 拍快照；
    /// 2. �等加地址、子网路由、（可选）默认路由；
    /// 3. 任一步失败 → rollback 到快照。
    pub fn apply(&mut self) -> Result<ApplyReport, PlatformError> {
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
            return crate::route::apply(&plan, true);
        }

        // 地址（�等）。
        match assign_addr(
            &self.config.ifname,
            self.config.tun_ip,
            self.config.prefixlen,
        ) {
            Ok(AssignOutcome::Added) => self.added_addr = true,
            Ok(AssignOutcome::AlreadyPresent) => {}
            Err(e) => return Err(e),
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
            if exists {
                report.routes_skipped += 1;
                return Ok(());
            }
            nl.new_route(dst, self.ifindex, None)
                .map_err(nl_err("add route"))?;
            *added_flag = true;
            report.routes_added += 1;
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
            Ok(())
        })();

        if let Err(e) = result {
            // O1：回滚地址（路由还没加或已回滚逻辑内）。
            if self.added_addr {
                let _ = remove_addr(
                    &self.config.ifname,
                    self.config.tun_ip,
                    self.config.prefixlen,
                );
                self.added_addr = false;
            }
            if let Err(rb_err) = crate::route::rollback(&before) {
                return Err(PlatformError::Io {
                    operation: "os assemble rollback".into(),
                    message: format!("apply failed: {e}; rollback ALSO failed: {rb_err}"),
                });
            }
            return Err(e);
        }

        report.addrs_added = u32::from(self.added_addr);
        report.addrs_skipped = u32::from(!self.added_addr);
        Ok(report)
    }

    /// 清理本实例创建的条目（�等，O2）。
    pub fn cleanup(&mut self) -> Result<CleanupReport, PlatformError> {
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
            }
            self.added_default_route = false;
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
        }
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
}
