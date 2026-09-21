//! CIDR 前缀解析与最长前缀匹配（P2-5 PRODUCT §12.14）。
//!
//! portable：零 I/O、零第三方依赖，可编译 WASI。纯函数、确定性。
//!
//! - `parse_cidr`：IPv4 点分十进制 + `/` + 前缀 0..=32（`0.0.0.0/0` 默认路由合法）；
//!   网络地址主机位必须全零（`192.168.5.1/24` 拒绝）；
//! - `cidr_contains`：IP 是否在该前缀内（ip 解析失败返回 false）；
//! - `longest_prefix_match`：返回包含 ip 且前缀最长的 next_hop（同长度取表内先者，
//!   顺序稳定）。
//!
//! 错误面：`CidrError` 类型化 enum（InvalidFormat / InvalidPrefixLength /
//! NotANetworkAddress），不以 panic / 字符串匹配代替。

use std::net::Ipv4Addr;

/// CIDR 前缀解析/匹配错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// 不是合法的 IPv4 点分十进制地址或缺少 `/prefix`。
    InvalidFormat {
        /// 原始输入。
        input: String,
    },
    /// 前缀长度越界（> 32）。
    InvalidPrefixLength {
        /// 原始输入。
        input: String,
        /// 非法前缀长度值。
        prefix_len: u8,
    },
    /// 网络地址主机位不全零（如 `192.168.5.1/24`）。
    NotANetworkAddress {
        /// 原始输入。
        input: String,
    },
}

impl core::fmt::Display for CidrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidFormat { input } => {
                write!(f, "CIDR_INVALID_FORMAT: {input} is not a valid IPv4 CIDR")
            }
            Self::InvalidPrefixLength { input, prefix_len } => {
                write!(
                    f,
                    "CIDR_INVALID_PREFIX_LENGTH: {input} prefix {prefix_len} > 32"
                )
            }
            Self::NotANetworkAddress { input } => {
                write!(f, "CIDR_NOT_A_NETWORK_ADDRESS: {input} host bits not zero")
            }
        }
    }
}

impl std::error::Error for CidrError {}

/// 解析后的 IPv4 前缀。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrPrefix {
    /// 网络地址（u32 BE 语义：高字节在前）。
    pub network: u32,
    /// 前缀长度（0..=32）。
    pub prefix_len: u8,
}

/// 解析 "a.b.c.d/len" 为 `CidrPrefix`。
///
/// # Errors
///
/// 格式非法 / 前缀越界 / 主机位非零 → `CidrError`。
pub fn parse_cidr(input: &str) -> Result<CidrPrefix, CidrError> {
    let (ip_part, len_part) = input
        .split_once('/')
        .ok_or_else(|| CidrError::InvalidFormat {
            input: input.into(),
        })?;
    let prefix_len: u8 = len_part.parse().map_err(|_| CidrError::InvalidFormat {
        input: input.into(),
    })?;
    if prefix_len > 32 {
        return Err(CidrError::InvalidPrefixLength {
            input: input.into(),
            prefix_len,
        });
    }
    let ip: Ipv4Addr = ip_part.parse().map_err(|_| CidrError::InvalidFormat {
        input: input.into(),
    })?;
    let network = u32::from(ip);
    // 主机位必须全零：低 (32 - len) 位为零。
    let host_mask = if prefix_len == 0 {
        u32::MAX
    } else {
        (1u32 << (32 - prefix_len)) - 1
    };
    if network & host_mask != 0 {
        return Err(CidrError::NotANetworkAddress {
            input: input.into(),
        });
    }
    Ok(CidrPrefix {
        network: network & !host_mask,
        prefix_len,
    })
}

/// ip 是否在 `prefix` 内（ip 解析失败返回 false）。
#[must_use]
pub fn cidr_contains(prefix: &CidrPrefix, ip: &str) -> bool {
    let Ok(ipv4) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let value = u32::from(ipv4);
    let host_mask = if prefix.prefix_len == 0 {
        u32::MAX
    } else {
        (1u32 << (32 - prefix.prefix_len)) - 1
    };
    value & !host_mask == prefix.network
}

/// 最长前缀匹配：返回包含 `ip` 且 `prefix_len` 最大的 next_hop。
///
/// 同长度按表内顺序取先（稳定）；空表或无命中返回 `None`。
#[must_use]
pub fn longest_prefix_match<'a>(
    routes: &'a [(CidrPrefix, String)],
    ip: &str,
) -> Option<&'a String> {
    let mut best: Option<(&'a CidrPrefix, &'a String)> = None;
    for (prefix, next_hop) in routes {
        if !cidr_contains(prefix, ip) {
            continue;
        }
        match best {
            // 同长度保留先出现者（稳定）；更长的前缀替换。
            Some((best_prefix, _)) if prefix.prefix_len <= best_prefix.prefix_len => {}
            _ => best = Some((prefix, next_hop)),
        }
    }
    best.map(|(_, next_hop)| next_hop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_cidr() {
        let p = parse_cidr("192.168.5.0/24").expect("valid");
        assert_eq!(p.network, u32::from(Ipv4Addr::new(192, 168, 5, 0)));
        assert_eq!(p.prefix_len, 24);
    }

    #[test]
    fn parse_default_route_allowed() {
        let p = parse_cidr("0.0.0.0/0").expect("default route valid");
        assert_eq!(p.network, 0);
        assert_eq!(p.prefix_len, 0);
    }

    #[test]
    fn parse_not_network_address_rejected() {
        let err = parse_cidr("192.168.5.1/24").expect_err("host bits set");
        assert_eq!(
            err,
            CidrError::NotANetworkAddress {
                input: "192.168.5.1/24".into()
            }
        );
    }

    #[test]
    fn parse_invalid_prefix_length_rejected() {
        let err = parse_cidr("10.0.0.0/33").expect_err("prefix > 32");
        assert_eq!(
            err,
            CidrError::InvalidPrefixLength {
                input: "10.0.0.0/33".into(),
                prefix_len: 33
            }
        );
    }

    #[test]
    fn parse_invalid_format_rejected() {
        assert_eq!(
            parse_cidr("not-an-ip/24"),
            Err(CidrError::InvalidFormat {
                input: "not-an-ip/24".into()
            })
        );
        assert_eq!(
            parse_cidr("10.0.0.0"),
            Err(CidrError::InvalidFormat {
                input: "10.0.0.0".into()
            })
        );
    }

    #[test]
    fn contains_true_and_false() {
        let p = parse_cidr("192.168.5.0/24").expect("valid");
        assert!(cidr_contains(&p, "192.168.5.10"));
        assert!(cidr_contains(&p, "192.168.5.255"));
        assert!(!cidr_contains(&p, "192.168.6.1"));
        assert!(!cidr_contains(&p, "10.0.0.1"));
        // ip 解析失败 → false
        assert!(!cidr_contains(&p, "not-an-ip"));
    }

    #[test]
    fn longest_prefix_prefers_longer() {
        let broad = parse_cidr("192.168.0.0/16").expect("broad");
        let office = parse_cidr("192.168.5.0/24").expect("office");
        let routes = vec![(broad, "node-b".into()), (office, "node-c".into())];
        assert_eq!(
            longest_prefix_match(&routes, "192.168.5.10"),
            Some(&"node-c".to_string())
        );
        // 不在 /24 但仍在 /16
        assert_eq!(
            longest_prefix_match(&routes, "192.168.9.1"),
            Some(&"node-b".to_string())
        );
    }

    #[test]
    fn longest_prefix_default_and_none() {
        let default = parse_cidr("0.0.0.0/0").expect("default");
        let routes = vec![(default, "node-egress".into())];
        assert_eq!(
            longest_prefix_match(&routes, "8.8.8.8"),
            Some(&"node-egress".to_string())
        );
        assert_eq!(longest_prefix_match(&[], "8.8.8.8"), None);
    }

    #[test]
    fn longest_prefix_stable_for_equal_length() {
        let a = parse_cidr("10.0.0.0/8").expect("a");
        let b = parse_cidr("10.0.0.0/8").expect("b");
        let routes = vec![(a, "first".into()), (b, "second".into())];
        // 同长度取表内先者
        assert_eq!(
            longest_prefix_match(&routes, "10.1.2.3"),
            Some(&"first".to_string())
        );
    }
}
