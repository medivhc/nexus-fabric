//! `geosite.nex` 二进制格式 v1 解析（PRODUCT §11.13）。
//!
//! 布局（小端，零第三方依赖，顺序遍历）：
//!
//! ```text
//! magic "NXGEOSITE\0" (10B)
//! u32 分类数 N
//! N × [ u32 name_len | name: UTF-8 bytes
//!       | u32 domain_count
//!       | domain_count × [ u32 domain_len | domain: UTF-8 bytes ] ]
//! ```
//!
//! 解析后输出分类 → 域名列表，与 [`RuleData::geosite`](crate::RuleData) 兼容。
//! 纯函数零 I/O。

use std::collections::HashMap;

/// 格式 v1 魔数。
pub const MAGIC: &[u8; 10] = b"NXGEOSITE\0";

/// 解析错误（结构化，尽量携带字节偏移）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// 魔数不匹配。
    BadMagic,
    /// 字节流在偏移处提前结束。
    Truncated { at: usize },
    /// 名称 / 域名不是合法 UTF-8。
    InvalidUtf8 { at: usize },
    /// 分类重复。
    DuplicateCategory(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "GEOSITE_NEX_BAD_MAGIC"),
            Self::Truncated { at } => write!(f, "GEOSITE_NEX_TRUNCATED at byte {at}"),
            Self::InvalidUtf8 { at } => write!(f, "GEOSITE_NEX_INVALID_UTF8 at byte {at}"),
            Self::DuplicateCategory(name) => {
                write!(f, "GEOSITE_NEX_DUPLICATE_CATEGORY: {name}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// 解析 `geosite.nex` 字节流为分类 → 域名列表（顺序遍历，零 I/O）。
///
/// # Errors
///
/// 魔数不匹配 / 截断 / 非 UTF-8 / 分类重复时返回对应 [`ParseError`]。
pub fn parse(bytes: &[u8]) -> Result<HashMap<String, Vec<String>>, ParseError> {
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err(ParseError::BadMagic);
    }
    let mut pos = MAGIC.len();
    let count = read_u32(bytes, &mut pos)? as usize;
    let mut out = HashMap::with_capacity(count);
    for _ in 0..count {
        let name = read_utf8(bytes, &mut pos)?;
        let domain_count = read_u32(bytes, &mut pos)? as usize;
        let mut domains = Vec::with_capacity(domain_count);
        for _ in 0..domain_count {
            domains.push(read_utf8(bytes, &mut pos)?);
        }
        if out.insert(name.clone(), domains).is_some() {
            return Err(ParseError::DuplicateCategory(name));
        }
    }
    Ok(out)
}

/// 序列化 `geosite.nex` 格式 v1 字节流（与 [`parse`] 对称；生成工具/测试共享）。
///
/// 分类名 / 域名必须为合法 UTF-8（Rust `&str` 保证），调用方应先校验分类唯一性
/// 与空域名；生成工具端对重复分类拒绝并指明条目。
pub fn build<'a, C>(entries: &[(&'a str, C)]) -> Vec<u8>
where
    C: AsRef<[&'a str]>,
{
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, domains) in entries {
        let domains = domains.as_ref();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(domains.len() as u32).to_le_bytes());
        for domain in domains {
            out.extend_from_slice(&(domain.len() as u32).to_le_bytes());
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, ParseError> {
    let v = read_bytes(bytes, pos, 4)?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn read_utf8(bytes: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    let len = read_u32(bytes, pos)? as usize;
    let at = *pos;
    let slice = read_bytes(bytes, pos, len)?;
    std::str::from_utf8(slice)
        .map(str::to_string)
        .map_err(|_| ParseError::InvalidUtf8 { at })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cn: &[&str] = &["example.cn", "b.cn"];
        let ads: &[&str] = &["ads.example"];
        let bytes = build(&[("cn", cn), ("ads", ads)]);
        let parsed = parse(&bytes).expect("parse ok");
        assert_eq!(
            parsed["cn"],
            vec!["example.cn".to_string(), "b.cn".to_string()]
        );
        assert_eq!(parsed["ads"], vec!["ads.example".to_string()]);
    }

    #[test]
    fn bad_magic() {
        assert_eq!(parse(b"XXXXXXXXXX"), Err(ParseError::BadMagic));
    }

    #[test]
    fn truncated() {
        let cn: &[&str] = &["example.cn"];
        let bytes = build(&[("cn", cn)]);
        assert!(matches!(
            parse(&bytes[..bytes.len() - 2]),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn invalid_utf8() {
        let cn: &[&str] = &["example.cn"];
        let mut bytes = build(&[("cn", cn)]);
        // 破坏第一个分类名的首字节为非法 UTF-8（0xFF 单独不成 UTF-8 序列）。
        // magic(10) + count(4) + name_len(4) → 分类名内容从 18 开始。
        let name_pos = MAGIC.len() + 8;
        bytes[name_pos] = 0xFF;
        assert!(matches!(parse(&bytes), Err(ParseError::InvalidUtf8 { .. })));
    }

    #[test]
    fn duplicate_category() {
        let cn: &[&str] = &["example.cn"];
        let mut bytes = build(&[("cn", cn)]);
        // 更新 count 为 2 并追加第二个 cn 项。
        bytes[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&2u32.to_le_bytes());
        let name = "cn";
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let d = "extra.cn";
        bytes.extend_from_slice(&(d.len() as u32).to_le_bytes());
        bytes.extend_from_slice(d.as_bytes());
        assert!(matches!(
            parse(&bytes),
            Err(ParseError::DuplicateCategory(_))
        ));
    }
}
