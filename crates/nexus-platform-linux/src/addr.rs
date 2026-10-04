//! TUN 接口 IP 地址装配（�等）。
//!
//! - `assign_addr`：先查已存在 → 已有则跳过（幂等），否则 RTM_NEWADDR；
//! - `remove_addr`：删除地址（不存在视为成功，幂等）；
//! - 错误为结构化 `PlatformError`，不吞 errno。

use nexus_platform::PlatformError;

use crate::netlink::{AddrEntry, NlSocket, ifname_to_index};

/// 地址已存在 vs 新加的区分（可观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOutcome {
    /// 已存在，跳过。
    AlreadyPresent,
    /// 新加成功。
    Added,
}

/// 给接口配 IPv4 地址（�等）。
///
/// - 接口不存在 → `PlatformError::NotFound`；
/// - 地址已存在（同 ip/同 prefixlen）→ `Ok(AlreadyPresent)`；
/// - 否则 RTM_NEWADDR → `Ok(Added)`。
pub fn assign_addr(
    ifname: &str,
    ip: [u8; 4],
    prefixlen: u8,
) -> Result<AssignOutcome, PlatformError> {
    let ifindex = ifname_to_index(ifname);
    if ifindex == 0 {
        return Err(PlatformError::NotFound {
            key: format!("interface {ifname}"),
        });
    }
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
    let addrs = nl.list_addrs().map_err(nl_err("list addresses"))?;
    let exists = addrs
        .iter()
        .any(|a| a.ifindex == ifindex && a.ip == ip && a.prefixlen == prefixlen);
    if exists {
        return Ok(AssignOutcome::AlreadyPresent);
    }
    nl.new_addr(ifindex, ip, prefixlen)
        .map_err(nl_err("add address"))?;
    Ok(AssignOutcome::Added)
}

/// 删除接口 IPv4 地址（�等，不存在视为成功）。
pub fn remove_addr(ifname: &str, ip: [u8; 4], prefixlen: u8) -> Result<(), PlatformError> {
    let ifindex = ifname_to_index(ifname);
    if ifindex == 0 {
        return Err(PlatformError::NotFound {
            key: format!("interface {ifname}"),
        });
    }
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
    let addrs = nl.list_addrs().map_err(nl_err("list addresses"))?;
    let exists = addrs
        .iter()
        .any(|a| a.ifindex == ifindex && a.ip == ip && a.prefixlen == prefixlen);
    if !exists {
        return Ok(());
    }
    nl.del_addr(ifindex, ip, prefixlen)
        .map_err(nl_err("delete address"))?;
    Ok(())
}

/// 列出某接口的 IPv4 地址（快照/断言用）。
pub fn list_if_addrs(ifname: &str) -> Result<Vec<AddrEntry>, PlatformError> {
    let ifindex = ifname_to_index(ifname);
    if ifindex == 0 {
        return Err(PlatformError::NotFound {
            key: format!("interface {ifname}"),
        });
    }
    let mut nl = NlSocket::open().map_err(nl_err("open netlink"))?;
    let addrs = nl.list_addrs().map_err(nl_err("list addresses"))?;
    Ok(addrs.into_iter().filter(|a| a.ifindex == ifindex).collect())
}

/// 把 `NlError` 映射为结构化 `PlatformError`（保留操作名，不吞原因）。
pub(crate) fn nl_err(operation: &'static str) -> impl Fn(crate::netlink::NlError) -> PlatformError {
    move |e| PlatformError::Io {
        operation: format!("netlink {operation}"),
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_to_missing_interface_returns_not_found() {
        // 不存在的接口名 → NotFound（纯逻辑，不碰 netlink）。
        let r = assign_addr("nxnonexist0", [10, 99, 0, 1], 24);
        assert!(matches!(r, Err(PlatformError::NotFound { .. })));
    }

    #[test]
    fn remove_from_missing_interface_returns_not_found() {
        let r = remove_addr("nxnonexist0", [10, 99, 0, 1], 24);
        assert!(matches!(r, Err(PlatformError::NotFound { .. })));
    }

    #[test]
    fn list_missing_interface_returns_not_found() {
        let r = list_if_addrs("nxnonexist0");
        assert!(matches!(r, Err(PlatformError::NotFound { .. })));
    }
}
