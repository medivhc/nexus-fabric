//! Mesh 名静态表（`dns.toml [dns.mesh.hosts]`）。
//!
//! 本 run 的唯一真实名源（spec §4.3）：管理员显式声明的 FQDN → 地址。
//! 不依赖 R1，不依赖 `nexus-registry`。
//!
//! 校验边界（SU-3 裁决，MSR-r3-su2-su3-20261026）：
//! - 值**拒绝 loopback**（`::1`、`127.0.0.0/8`）；
//! - **link-local 允许**（`fe80::/10`、`169.254.0.0/16`）——本 run 为 TUN
//!   单接口形态，link-local 按单接口语义解释，不做 scope/zone 建模；
//! - 拒绝 unspecified / multicast / 全局广播；
//! - 键归一化为小写并去尾点；精确匹配（`a.mesh` ≠ `b.a.mesh`）。
//!
//! 网段归属（v4 落在 `[[vpi.routes]]`、v6 落在 `[[vpi.routes6]]`）需要
//! `network.toml` 上下文，由 `nexusd` 的配置面校验（C6），不在本模块。

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::DnsError;
use crate::unified::MeshNameResolver;

/// 静态 mesh 名表；构造期完成校验与归一化。
#[derive(Debug, Clone, Default)]
pub struct StaticMeshResolver {
    entries: BTreeMap<String, IpAddr>,
}

impl StaticMeshResolver {
    /// 构造静态表。
    ///
    /// # Errors
    ///
    /// 键为空/含空标签/超长，或值是 loopback/unspecified/multicast/广播，
    /// 或同名键映射到不同地址时返回 `DnsError::InvalidQuery`。
    pub fn new(entries: impl IntoIterator<Item = (String, IpAddr)>) -> Result<Self, DnsError> {
        let mut map = BTreeMap::new();
        for (name, addr) in entries {
            let normalized = normalize_name(&name)?;
            validate_mesh_addr(addr).map_err(|reason| {
                DnsError::InvalidQuery(format!("mesh host '{normalized}': {reason}"))
            })?;
            match map.get(&normalized) {
                Some(existing) if *existing != addr => {
                    return Err(DnsError::InvalidQuery(format!(
                        "mesh host '{normalized}': conflicting addresses"
                    )));
                }
                Some(_) => {}
                None => {
                    map.insert(normalized, addr);
                }
            }
        }
        Ok(Self { entries: map })
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl MeshNameResolver for StaticMeshResolver {
    fn resolve_mesh(&self, name: &str) -> Option<IpAddr> {
        self.entries.get(&name.to_ascii_lowercase()).copied()
    }
}

fn normalize_name(name: &str) -> Result<String, DnsError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(DnsError::InvalidQuery(format!(
            "mesh host name '{name}' must be 1..=253 chars"
        )));
    }
    if trimmed.split('.').any(str::is_empty) {
        return Err(DnsError::InvalidQuery(format!(
            "mesh host name '{name}' has an empty label"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// SU-3：loopback 拒绝、link-local 接受、其它非单播拒绝。
fn validate_mesh_addr(addr: IpAddr) -> Result<(), &'static str> {
    match addr {
        IpAddr::V4(v4) => validate_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return validate_v4(v4);
            }
            if v6.is_loopback() {
                return Err("loopback address is not allowed");
            }
            if v6.is_unspecified() {
                return Err("unspecified address is not allowed");
            }
            if v6.is_multicast() {
                return Err("multicast address is not allowed");
            }
            Ok(())
        }
    }
}

fn validate_v4(v4: std::net::Ipv4Addr) -> Result<(), &'static str> {
    if v4.is_loopback() {
        return Err("loopback address is not allowed");
    }
    if v4.is_unspecified() {
        return Err("unspecified address is not allowed");
    }
    if v4.is_broadcast() {
        return Err("broadcast address is not allowed");
    }
    if v4.is_multicast() {
        return Err("multicast address is not allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address parses")
    }

    fn entry(name: &str, addr: &str) -> (String, IpAddr) {
        (name.to_string(), ip(addr))
    }

    #[test]
    fn rejects_loopback_v6_and_v4() {
        // SU-3 例 1：mesh hosts 值 ::1 / 127.0.0.1 → 拒绝。
        for value in ["::1", "127.0.0.1", "127.1.2.3"] {
            let err = StaticMeshResolver::new([entry("loop.mesh", value)]).unwrap_err();
            assert!(
                matches!(err, DnsError::InvalidQuery(ref msg) if msg.contains("loopback")),
                "unexpected error for {value}: {err}"
            );
        }
    }

    #[test]
    fn rejects_v4_mapped_loopback() {
        let err = StaticMeshResolver::new([entry("mapped.mesh", "::ffff:127.0.0.1")]).unwrap_err();
        assert!(matches!(err, DnsError::InvalidQuery(ref m) if m.contains("loopback")));
    }

    #[test]
    fn accepts_link_local_values() {
        // SU-3 例 2：fe80:: link-local 值 → 接受；v4 link-local 同样接受。
        let table = StaticMeshResolver::new([
            entry("ll6.mesh", "fe80::1"),
            entry("ll4.mesh", "169.254.10.7"),
        ])
        .expect("link-local accepted");
        assert_eq!(table.len(), 2);
        assert_eq!(table.resolve_mesh("ll6.mesh"), Some(ip("fe80::1")));
        assert_eq!(table.resolve_mesh("ll4.mesh"), Some(ip("169.254.10.7")));
    }

    #[test]
    fn normalizes_name_case_and_trailing_dot() {
        let table =
            StaticMeshResolver::new([entry("XC-PC-Linux.MESH.", "10.144.144.6")]).expect("valid");
        assert_eq!(
            table.resolve_mesh("xc-pc-linux.mesh"),
            Some(ip("10.144.144.6"))
        );
        assert_eq!(
            table.resolve_mesh("XC-PC-LINUX.MESH"),
            Some(ip("10.144.144.6"))
        );
    }

    #[test]
    fn exact_match_does_not_suffix_match() {
        let table = StaticMeshResolver::new([
            entry("a.mesh", "10.144.144.1"),
            entry("b.a.mesh", "10.144.144.2"),
        ])
        .expect("valid");
        assert_eq!(table.resolve_mesh("a.mesh"), Some(ip("10.144.144.1")));
        assert_eq!(table.resolve_mesh("b.a.mesh"), Some(ip("10.144.144.2")));
        assert_eq!(table.resolve_mesh("c.b.a.mesh"), None);
    }

    #[test]
    fn len_and_is_empty() {
        let empty = StaticMeshResolver::new(Vec::new()).expect("empty table is valid");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let one = StaticMeshResolver::new([entry("a.mesh", "10.144.144.6")]).expect("valid");
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn rejects_unspecified_multicast_broadcast() {
        for value in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"] {
            assert!(
                StaticMeshResolver::new([entry("bad.mesh", value)]).is_err(),
                "value {value} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_names() {
        for name in ["", ".", "a..mesh", "a.mesh."] {
            if name == "a.mesh." {
                // 尾点是允许的归一化输入。
                assert!(StaticMeshResolver::new([entry(name, "10.144.144.6")]).is_ok());
                continue;
            }
            assert!(
                StaticMeshResolver::new([entry(name, "10.144.144.6")]).is_err(),
                "name {name:?} should be rejected"
            );
        }
        let long = format!("{}.mesh", "a".repeat(250));
        assert!(StaticMeshResolver::new([entry(&long, "10.144.144.6")]).is_err());
    }

    #[test]
    fn duplicate_key_same_address_is_fine() {
        let addr = Ipv4Addr::new(10, 144, 144, 6);
        let table = StaticMeshResolver::new([
            ("a.mesh".to_string(), IpAddr::V4(addr)),
            ("A.MESH".to_string(), IpAddr::V4(addr)),
        ])
        .expect("same address dedupes");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn duplicate_key_conflict_is_rejected() {
        let err = StaticMeshResolver::new([
            (
                "a.mesh".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 144, 144, 6)),
            ),
            (
                "A.MESH".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 144, 144, 7)),
            ),
        ])
        .unwrap_err();
        assert!(matches!(err, DnsError::InvalidQuery(ref m) if m.contains("conflicting")));
    }

    #[test]
    fn accepts_global_v6() {
        let table = StaticMeshResolver::new([entry("v6.mesh", "fd00:144::9")]).expect("valid");
        assert_eq!(table.resolve_mesh("v6.mesh"), Some(ip("fd00:144::9")));
        // 保持 v6 类型（不是 v4-mapped）。
        assert!(matches!(table.resolve_mesh("v6.mesh"), Some(IpAddr::V6(_))));
    }
}
