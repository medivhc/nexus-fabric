//! 最小 QPACK 编解码（RFC 9204），仅覆盖 Hysteria2 认证所需的子集。
//!
//! 编码：只用"字面量不索引（Literal, Never Indexed）"表示全部头字段——
//! 简单可靠，且 `N` 位可防止中间节点把敏感值（`hysteria-auth`）编入索引
//! （RFC 9204 §7.1 的 CRIME 缓解建议）。
//!
//! 解码：支持字面量（字面量名 / 静态表名引用）与静态表索引引用；
//! **拒绝一切动态表引用**（Required Insert Count != 0、Base != 0、动态索引），
//! 呼应文档 §5 坑 #2；Huffman 编码（`H` 位）不在最小子集内，遇到返回
//! [`Hysteria2Error::InvalidFrame`]。
//!
//! 静态表内容逐字取自 RFC 9204 Appendix A（Table 4）。

use super::Hysteria2Error;

/// RFC 9204 §3.1 静态表（索引 0~98），`(名字, 值)`。
pub static STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// 按 `prefix_bits` 位前缀编码整数（RFC 9204 §4.1.1），首字节基值 `base`
/// 已包含模式位；`H` 位由调用方置入 `base`（本模块恒为 0，不用 Huffman）。
fn encode_prefixed_int(base: u8, prefix_bits: u8, value: usize, out: &mut Vec<u8>) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(base | value as u8);
    } else {
        out.push(base | max as u8);
        let mut rest = value - max;
        while rest >= 128 {
            out.push(0x80 | (rest as u8 & 0x7F));
            rest >>= 7;
        }
        out.push(rest as u8);
    }
}

/// 按 `prefix_bits` 位前缀解码整数，返回 `(值, 消费字节数)`。
fn decode_prefixed_int(buf: &[u8], prefix_bits: u8) -> Result<(usize, usize), Hysteria2Error> {
    let first = *buf.first().ok_or(Hysteria2Error::InvalidFrame)?;
    let max = (1u16 << prefix_bits) - 1;
    let mut value = usize::from(first & max as u8);
    if value < usize::from(max) {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    let mut consumed = 1;
    loop {
        let b = *buf.get(consumed).ok_or(Hysteria2Error::InvalidFrame)?;
        consumed += 1;
        // 防止恶意超长编码导致移位溢出：QPACK 整数上限远小于此。
        if shift >= 28 {
            return Err(Hysteria2Error::InvalidFrame);
        }
        value += usize::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok((value, consumed))
}

/// 解码一个字符串字面量（RFC 9204 §4.1.2 的 8 位前缀形式：`| H | Length(7+) |`
/// + 数据）。`H` 位（Huffman）不在最小子集内，遇到返回 [`Hysteria2Error::InvalidFrame`]。
fn decode_string(buf: &[u8]) -> Result<(Vec<u8>, usize), Hysteria2Error> {
    let first = *buf.first().ok_or(Hysteria2Error::InvalidFrame)?;
    if first & 0x80 != 0 {
        // 未确认/未实现：Huffman 编码的字符串字面量（最小子集不覆盖）。
        return Err(Hysteria2Error::InvalidFrame);
    }
    let (len, n) = decode_prefixed_int(buf, 7)?;
    let start = n;
    let end = start.checked_add(len).ok_or(Hysteria2Error::InvalidFrame)?;
    let bytes = buf.get(start..end).ok_or(Hysteria2Error::InvalidFrame)?;
    Ok((bytes.to_vec(), end))
}

/// 编码一个 field section：前缀 `[0x00, 0x00]`（Required Insert Count = 0、
/// Base = 0，动态表保持禁用，呼应文档"QPACK 动态表保持禁用"），随后每个头
/// 字段用"字面量名 + 字面量值、Never Indexed（`N`=1）"编码（RFC 9204 §4.5.4）。
#[must_use]
pub fn encode_field_section(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x00]);
    for (name, value) in headers {
        // 首字节：`001` 模式 + N=1（永不索引）+ H=0（无 Huffman）+ 3 位名字长度前缀。
        encode_prefixed_int(0x30, 3, name.len(), &mut out);
        out.extend_from_slice(name.as_bytes());
        // 值：H=0 + 7 位长度前缀。
        encode_prefixed_int(0x00, 7, value.len(), &mut out);
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// 解码一个 field section，返回有序的 `(名字, 值)` 列表。
///
/// 拒绝动态表引用（Required Insert Count / Base 非零、动态索引、Post-Base
/// 表示）；静态表索引引用（§4.5.2/§4.5.3 的 `T`=1）予以解析。
///
/// # Errors
///
/// 前缀非法、截断、动态表引用、Huffman 字符串 → [`Hysteria2Error::InvalidFrame`]。
pub fn decode_field_section(buf: &[u8]) -> Result<Vec<(String, String)>, Hysteria2Error> {
    if buf.len() < 2 {
        return Err(Hysteria2Error::InvalidFrame);
    }
    // Required Insert Count（8 位前缀）：非零 = 引用动态表，拒绝。
    let (ric, ric_len) = decode_prefixed_int(buf, 8)?;
    if ric != 0 {
        return Err(Hysteria2Error::InvalidFrame);
    }
    // Base：S 位（0x80）置位或 base 非零 = 动态表引用，拒绝。
    let base_byte = buf[ric_len];
    if base_byte & 0x80 != 0 {
        return Err(Hysteria2Error::InvalidFrame);
    }
    let (base, base_len) = decode_prefixed_int(&buf[ric_len..], 7)?;
    if base != 0 {
        return Err(Hysteria2Error::InvalidFrame);
    }
    let mut pos = ric_len + base_len;
    let mut out = Vec::new();
    while pos < buf.len() {
        let b = buf[pos];
        if b & 0x80 != 0 {
            // §4.5.2 Indexed Field Line：`| 1 | T | Index(6+) |`。
            let static_ref = b & 0x40 != 0;
            let (index, n) = decode_prefixed_int(&buf[pos..], 6)?;
            pos += n;
            if !static_ref || index >= STATIC_TABLE.len() {
                return Err(Hysteria2Error::InvalidFrame);
            }
            let (name, value) = STATIC_TABLE[index];
            out.push((name.to_string(), value.to_string()));
        } else if b & 0xC0 == 0x40 {
            // §4.5.3 Literal with Name Reference：`| 0 | 1 | N | T | Index(4+) |`。
            let static_ref = b & 0x10 != 0;
            let (index, n) = decode_prefixed_int(&buf[pos..], 4)?;
            pos += n;
            if !static_ref || index >= STATIC_TABLE.len() {
                return Err(Hysteria2Error::InvalidFrame);
            }
            let name = STATIC_TABLE[index].0.to_string();
            let (value_bytes, n) = decode_string(&buf[pos..])?;
            pos += n;
            let value = String::from_utf8(value_bytes).map_err(|_| Hysteria2Error::InvalidFrame)?;
            out.push((name, value));
        } else if b & 0xE0 == 0x20 {
            // §4.5.4 Literal with Literal Name：`| 0 | 0 | 1 | N | H | NameLen(3+) |`。
            // N 位（永不索引）两种取值都接受；H（Huffman）必须为 0。
            if b & 0x08 != 0 {
                return Err(Hysteria2Error::InvalidFrame);
            }
            let (name_len, n) = decode_prefixed_int(&buf[pos..], 3)?;
            pos += n;
            let name_bytes = buf
                .get(pos..pos + name_len)
                .ok_or(Hysteria2Error::InvalidFrame)?;
            pos += name_len;
            let name =
                String::from_utf8(name_bytes.to_vec()).map_err(|_| Hysteria2Error::InvalidFrame)?;
            let (value_bytes, n) = decode_string(&buf[pos..])?;
            pos += n;
            let value = String::from_utf8(value_bytes).map_err(|_| Hysteria2Error::InvalidFrame)?;
            out.push((name, value));
        } else {
            // `0000`/`0001` 开头：Post-Base 表示，必然引用动态表，拒绝。
            return Err(Hysteria2Error::InvalidFrame);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_spot_checks() {
        // RFC 9204 Table 4 抽查（索引位置是解码静态引用的关键）。
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(STATIC_TABLE[0], (":authority", ""));
        assert_eq!(STATIC_TABLE[1], (":path", "/"));
        assert_eq!(STATIC_TABLE[20], (":method", "POST"));
        assert_eq!(STATIC_TABLE[23], (":scheme", "https"));
        assert_eq!(STATIC_TABLE[25], (":status", "200"));
        assert_eq!(STATIC_TABLE[27], (":status", "404"));
        assert_eq!(STATIC_TABLE[98], ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn field_section_roundtrip() {
        let headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", "s3cr3t"),
            ("hysteria-cc-rx", "0"),
            ("hysteria-padding", "abcXYZ019"),
        ];
        let encoded = encode_field_section(&headers);
        // 前缀：Required Insert Count = 0, Base = 0。
        assert_eq!(&encoded[..2], &[0x00, 0x00]);
        let decoded = decode_field_section(&encoded).unwrap();
        let expected: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn long_name_uses_continuation() {
        // 名字长度超过 3 位前缀上限（7）时走续字节。
        let long_name = "x".repeat(300);
        let encoded = encode_field_section(&[(&long_name, "v")]);
        let decoded = decode_field_section(&encoded).unwrap();
        assert_eq!(decoded[0].0, long_name);
    }

    #[test]
    fn indexed_static_reference_decodes() {
        // §4.5.2：0xD9 = 1|1|011001 → 静态表索引 25 = (":status", "200")。
        let encoded = [0x00, 0x00, 0xD9];
        let decoded = decode_field_section(&encoded).unwrap();
        assert_eq!(decoded, [(":status".to_string(), "200".to_string())]);
    }

    #[test]
    fn name_reference_static_decodes() {
        // §4.5.3：0x59 = 01|0|1|1001 → N=0, T=1(静态), 索引 9 = "if-none-match"，
        // 后跟字面量值。
        let mut encoded = vec![0x00, 0x00, 0x59];
        encoded.push(0x03); // 值长度 3（H=0）
        encoded.extend_from_slice(b"xyz");
        let decoded = decode_field_section(&encoded).unwrap();
        assert_eq!(
            decoded,
            [("if-none-match".to_string(), "xyz".to_string())]
        );
    }

    #[test]
    fn dynamic_references_rejected() {
        // Required Insert Count = 1（8 位前缀 0x01）：动态表引用，拒绝。
        assert_eq!(
            decode_field_section(&[0x01, 0x00]),
            Err(Hysteria2Error::InvalidFrame)
        );
        // Base 的 S 位置位：动态表引用，拒绝。
        assert_eq!(
            decode_field_section(&[0x00, 0x80]),
            Err(Hysteria2Error::InvalidFrame)
        );
        // Indexed Field Line 动态引用（T=0）：0x01 → 索引 1 动态，拒绝。
        assert_eq!(
            decode_field_section(&[0x00, 0x00, 0x01]),
            Err(Hysteria2Error::InvalidFrame)
        );
        // Post-Base 索引（0001 开头）：必然动态，拒绝。
        assert_eq!(
            decode_field_section(&[0x00, 0x00, 0x10]),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn truncated_section_rejected() {
        assert_eq!(decode_field_section(&[0x00]), Err(Hysteria2Error::InvalidFrame));
        assert_eq!(decode_field_section(&[]), Err(Hysteria2Error::InvalidFrame));
        // 名字长度宣称 5，实际只剩 2 字节。
        assert_eq!(
            decode_field_section(&[0x00, 0x00, 0x35, b'a', b'b']),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn huffman_literal_rejected() {
        // H 位置位（0x38 = 001|1|1|000）：Huffman 不在最小子集内，拒绝。
        assert_eq!(
            decode_field_section(&[0x00, 0x00, 0x38]),
            Err(Hysteria2Error::InvalidFrame)
        );
    }
}
