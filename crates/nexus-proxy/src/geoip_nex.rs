//! `geoip.nex` 二进制格式 v1 解析（PRODUCT §11.12 B）。
//!
//! 布局（小端，零第三方依赖，顺序遍历）：
//!
//! ```text
//! magic "NXGEOIP\0" (8B)
//! u32 国家数 N
//! N × [ code: 2B ASCII | cidr_count: u32
//!        | cidr_count × [base: u32] | cidr_count × [prefix: u8] ]
//! ```
//!
//! `base` 为 IPv4 地址按网络序解释的 u32（`oct[0]<<24 | ... | oct[3]`），
//! 落盘为小端字节；解析后还原为 `a.b.c.d/prefix` 文本，与
//! [`RuleData::geoip`](crate::RuleData) 兼容。纯函数零 I/O。

use std::collections::HashMap;

/// 格式 v1 魔数。
pub const MAGIC: &[u8; 8] = b"NXGEOIP\0";

/// 解析错误（结构化，尽量携带字节偏移）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// 魔数不匹配。
    BadMagic,
    /// 字节流在偏移处提前结束。
    Truncated { at: usize },
    /// 国家码非 2 个 ASCII 字母。
    InvalidCode { at: usize, code: String },
    /// CIDR 前缀超过 32。
    InvalidCidr { at: usize, base: u32, prefix: u8 },
    /// 国家码重复。
    DuplicateCode(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "GEOIP_NEX_BAD_MAGIC"),
            Self::Truncated { at } => write!(f, "GEOIP_NEX_TRUNCATED at byte {at}"),
            Self::InvalidCode { at, code } => {
                write!(f, "GEOIP_NEX_INVALID_CODE at byte {at}: {code:?}")
            }
            Self::InvalidCidr { at, base, prefix } => {
                write!(
                    f,
                    "GEOIP_NEX_INVALID_CIDR at byte {at}: base={base} prefix={prefix}"
                )
            }
            Self::DuplicateCode(code) => write!(f, "GEOIP_NEX_DUPLICATE_CODE: {code}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// 解析 `geoip.nex` 字节流为国家码 → CIDR 文本列表（顺序遍历，零 I/O）。
///
/// # Errors
///
/// 魔数不匹配 / 截断 / 国家码非法 / 前缀超限 / 国家码重复时返回对应
/// [`ParseError`]。
pub fn parse(bytes: &[u8]) -> Result<HashMap<String, Vec<String>>, ParseError> {
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err(ParseError::BadMagic);
    }
    let mut pos = MAGIC.len();
    let count = read_u32(bytes, &mut pos)? as usize;
    let mut out = HashMap::with_capacity(count);
    for _ in 0..count {
        let code = read_bytes(bytes, &mut pos, 2)?;
        if !code.iter().all(u8::is_ascii_alphabetic) {
            return Err(ParseError::InvalidCode {
                at: pos - 2,
                code: String::from_utf8_lossy(code).to_string(),
            });
        }
        let code = String::from_utf8_lossy(code).to_ascii_uppercase();
        let cidr_count = read_u32(bytes, &mut pos)? as usize;
        let bases = read_u32s(bytes, &mut pos, cidr_count)?;
        let prefixes = read_bytes(bytes, &mut pos, cidr_count)?;
        let mut cidrs = Vec::with_capacity(cidr_count);
        for i in 0..cidr_count {
            let base = bases[i];
            let prefix = prefixes[i];
            if prefix > 32 {
                return Err(ParseError::InvalidCidr {
                    at: pos,
                    base,
                    prefix,
                });
            }
            let oct = base.to_be_bytes();
            cidrs.push(format!(
                "{}.{}.{}.{}/{}",
                oct[0], oct[1], oct[2], oct[3], prefix
            ));
        }
        if out.insert(code.clone(), cidrs).is_some() {
            return Err(ParseError::DuplicateCode(code));
        }
    }
    Ok(out)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, ParseError> {
    let v = read_bytes(bytes, pos, 4)?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn read_u32s(bytes: &[u8], pos: &mut usize, n: usize) -> Result<Vec<u32>, ParseError> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(read_u32(bytes, pos)?);
    }
    Ok(out)
}

fn read_bytes<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], ParseError> {
    let end = pos
        .checked_add(n)
        .ok_or(ParseError::Truncated { at: *pos })?;
    if end > bytes.len() {
        return Err(ParseError::Truncated { at: *pos });
    }
    let slice = &bytes[*pos..end];
    *pos = end;
    Ok(slice)
}

/// 序列化 `geoip.nex` 格式 v1 字节流（与 [`parse`] 对称；生成工具/测试共享）。
///
/// 国家码必须为 2 个 ASCII 字母；CIDR 前缀 ≤ 32，否则 panic（调用方应先校验；
/// 生成工具端对非法 CIDR 拒绝并指明行）。
pub fn build<'a, C>(entries: &[(&'a str, C)]) -> Vec<u8>
where
    C: AsRef<[(&'a str, u8)]>,
{
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (code, cidrs) in entries {
        let cidrs = cidrs.as_ref();
        assert_eq!(code.len(), 2, "country code must be 2 letters");
        out.extend_from_slice(code.as_bytes());
        out.extend_from_slice(&(cidrs.len() as u32).to_le_bytes());
        for (ip, _) in cidrs.iter() {
            let oct: Vec<u8> = ip.split('.').map(|p| p.parse::<u8>().unwrap()).collect();
            assert_eq!(oct.len(), 4, "ip must be ipv4: {ip}");
            let base = u32::from_be_bytes([oct[0], oct[1], oct[2], oct[3]]);
            out.extend_from_slice(&base.to_le_bytes());
        }
        for (_, prefix) in cidrs.iter() {
            assert!(*prefix <= 32, "prefix must be <= 32");
            out.push(*prefix);
        }
    }
    out
}

/// 解析 IPv4 文本为 u32（网络字节序：`a.b.c.d` → `a<<24 | b<<16 | c<<8 | d`）。
///
/// # Errors
///
/// 非 4 段 / 段非数字 / 段 > 255 → 结构化 `String` 错误。
pub fn parse_ipv4(s: &str) -> Result<u32, String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid ipv4: {s}"));
    }
    let mut v = 0u32;
    for p in parts {
        let oct: u8 = p
            .parse()
            .map_err(|_| format!("invalid ipv4 octet {p:?} in {s}"))?;
        v = (v << 8) | u32::from(oct);
    }
    Ok(v)
}

/// u32（网络字节序）转 IPv4 文本。
#[must_use]
pub fn format_ipv4(v: u32) -> String {
    let o = v.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

/// 把 IPv4 整数区间 `[start, end]` 贪婪拆分为 CIDR 列表 `(base, prefix)`。
///
/// 纯函数零 I/O：从 `start` 起每次取当前对齐可容纳的最大 2^n 块，且不越过
/// `end`；输出按地址升序且互不重叠（§11.15 源插件区间→CIDR）。
///
/// # Panics
///
/// `start > end` 时 panic（调用方应先校验区间合法）。
#[must_use]
pub fn cidrs_from_range(start: u32, end: u32) -> Vec<(u32, u8)> {
    assert!(start <= end, "start {start} > end {end}");
    let mut out = Vec::new();
    let mut cur = u64::from(start);
    let end = u64::from(end);
    while cur <= end {
        let room = end - cur + 1;
        // 当前地址对齐允许的最大块：2^max_align（0 对齐 2^32 → /0 全段）。
        let max_align = (cur as u32).trailing_zeros();
        let mut size = 1u64 << max_align;
        while size > room {
            size >>= 1;
        }
        debug_assert!(size.is_power_of_two() && size <= room);
        let prefix = 32 - size.trailing_zeros() as u8;
        out.push((cur as u32, prefix));
        cur += size;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cn: &[(&str, u8)] = &[("1.0.1.0", 24), ("1.2.3.0", 24)];
        let us: &[(&str, u8)] = &[("8.8.8.0", 24)];
        let bytes = build(&[("CN", cn), ("US", us)]);
        let parsed = parse(&bytes).expect("parse ok");
        assert_eq!(
            parsed["CN"],
            vec!["1.0.1.0/24".to_string(), "1.2.3.0/24".to_string()]
        );
        assert_eq!(parsed["US"], vec!["8.8.8.0/24".to_string()]);
    }

    #[test]
    fn bad_magic() {
        assert_eq!(parse(b"XXXXXXX!"), Err(ParseError::BadMagic));
    }

    #[test]
    fn truncated() {
        let bytes = build(&[("CN", &[("1.0.1.0", 24)])]);
        assert!(matches!(
            parse(&bytes[..bytes.len() - 2]),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn invalid_code() {
        let mut bytes = build(&[("CN", &[("1.0.1.0", 24)])]);
        bytes[12] = b"1"[0];
        assert!(matches!(parse(&bytes), Err(ParseError::InvalidCode { .. })));
    }

    #[test]
    fn duplicate_code() {
        let mut bytes = build(&[("CN", &[("1.0.1.0", 24)])]);
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(b"CN");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&u32::from_be_bytes([9, 9, 9, 0]).to_le_bytes());
        bytes.push(24);
        assert!(matches!(parse(&bytes), Err(ParseError::DuplicateCode(_))));
    }

    #[test]
    fn ipv4_parse_and_format() {
        assert_eq!(parse_ipv4("8.8.8.8").unwrap(), 0x0808_0808);
        assert_eq!(parse_ipv4("1.0.1.0").unwrap(), 0x0100_0100);
        assert_eq!(parse_ipv4("255.255.255.255").unwrap(), u32::MAX);
        assert_eq!(format_ipv4(0x0808_0808), "8.8.8.8");
        assert!(parse_ipv4("1.2.3").is_err());
        assert!(parse_ipv4("1.2.3.256").is_err());
        assert!(parse_ipv4("1.2.3.x").is_err());
    }

    #[test]
    fn cidrs_single_ip() {
        assert_eq!(
            cidrs_from_range(0x0808_0808, 0x0808_0808),
            vec![(0x0808_0808, 32)]
        );
        assert_eq!(cidrs_from_range(0, 0), vec![(0, 32)]);
        assert_eq!(cidrs_from_range(u32::MAX, u32::MAX), vec![(u32::MAX, 32)]);
    }

    #[test]
    fn cidrs_full_range() {
        assert_eq!(cidrs_from_range(0, u32::MAX), vec![(0, 0)]);
    }

    #[test]
    fn cidrs_split_range() {
        // 1.0.1.0 - 1.0.3.255 = 1.0.1.0/24 + 1.0.2.0/23
        assert_eq!(
            cidrs_from_range(0x0100_0100, 0x0100_03ff),
            vec![(0x0100_0100, 24), (0x0100_0200, 23)]
        );
    }

    #[test]
    fn cidrs_cross_octet_boundary() {
        // 1.0.0.255 - 1.0.1.0 跨 /24 边界：两个 /32。
        assert_eq!(
            cidrs_from_range(0x0100_00ff, 0x0100_0100),
            vec![(0x0100_00ff, 32), (0x0100_0100, 32)]
        );
        // 10.0.0.0 - 10.0.0.255：单 /24。
        assert_eq!(
            cidrs_from_range(0x0a00_0000, 0x0a00_00ff),
            vec![(0x0a00_0000, 24)]
        );
    }
}
