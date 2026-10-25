//! 最小 QPACK 编解码（RFC 9204），仅覆盖 Hysteria2 认证所需的子集。
//!
//! 编码：只用"字面量不索引（Literal, Never Indexed）"表示全部头字段——
//! 简单可靠，且 `N` 位可防止中间节点把敏感值（`hysteria-auth`）编入索引
//! （RFC 9204 §7.1 的 CRIME 缓解建议）。
//!
//! 解码：支持字面量（字面量名 / 静态表名引用）与静态表索引引用；
//! **拒绝一切动态表引用**（Required Insert Count != 0、Base != 0、动态索引），
//! 呼应文档 §5 坑 #2；字符串解码支持 Huffman（`H` 位，RFC 7541 附录 B 码表，
//! 含 EOS 与 padding 校验，见 crate 私有 `huffman` 模块），编码侧仍恒置 `H`=0。
//!
//! 静态表内容逐字取自 RFC 9204 Appendix A（Table 4）。

use crate::huffman;

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
/// 已包含模式位；`H` 位由调用方置入 `base`，**编码侧**恒为 0。`H`=1 的解码
/// 由 crate 私有 `huffman` 模块承担，本函数不参与。
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
/// 加数据）。`Length` 是编码后的字节数；`H`=1 时按 RFC 7541 §5.2 解码 Huffman，
/// 非法 Huffman（EOS、padding 非法、截断）返回 [`Hysteria2Error::InvalidFrame`]。
fn decode_string(buf: &[u8]) -> Result<(Vec<u8>, usize), Hysteria2Error> {
    let first = *buf.first().ok_or(Hysteria2Error::InvalidFrame)?;
    let huffman = first & 0x80 != 0;
    let (len, n) = decode_prefixed_int(buf, 7)?;
    let end = n.checked_add(len).ok_or(Hysteria2Error::InvalidFrame)?;
    let bytes = buf.get(n..end).ok_or(Hysteria2Error::InvalidFrame)?;
    if huffman {
        Ok((huffman::decode(bytes)?, end))
    } else {
        Ok((bytes.to_vec(), end))
    }
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
/// 前缀非法、截断、动态表引用、**非法 Huffman** → [`Hysteria2Error::InvalidFrame`]。
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
            // N 位（永不索引）两种取值都接受；H=1 时名字按其长度前缀取编码字节后
            // 走 Huffman 解码。
            let name_huffman = b & 0x08 != 0;
            let (name_len, n) = decode_prefixed_int(&buf[pos..], 3)?;
            pos += n;
            let name_end = pos
                .checked_add(name_len)
                .ok_or(Hysteria2Error::InvalidFrame)?;
            let name_bytes = buf.get(pos..name_end).ok_or(Hysteria2Error::InvalidFrame)?;
            pos = name_end;
            let name = if name_huffman {
                huffman::decode(name_bytes)?
            } else {
                name_bytes.to_vec()
            };
            let name = String::from_utf8(name).map_err(|_| Hysteria2Error::InvalidFrame)?;
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
        assert_eq!(decoded, [("if-none-match".to_string(), "xyz".to_string())]);
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
        assert_eq!(
            decode_field_section(&[0x00]),
            Err(Hysteria2Error::InvalidFrame)
        );
        assert_eq!(decode_field_section(&[]), Err(Hysteria2Error::InvalidFrame));
        // 名字长度宣称 5，实际只剩 2 字节。
        assert_eq!(
            decode_field_section(&[0x00, 0x00, 0x35, b'a', b'b']),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn huffman_literal_name_decodes() {
        // 00 00（Required Insert Count = 0, Base = 0）
        // 29 = 001|0|1|001：§4.5.4 字面量名，N=0，H=1，NameLen=1
        // 1f = Huffman "a"（python-hpack 4.0.0 decode_huffman(1f) = b'a'）
        // 81 f8 = 值 H=1、Length=1；f8 = Huffman "&"（decode_huffman(f8) = b'&'）
        let encoded = [0x00, 0x00, 0x29, 0x1f, 0x81, 0xf8];
        assert_eq!(
            decode_field_section(&encoded).unwrap(),
            [("a".to_string(), "&".to_string())]
        );
    }

    #[test]
    fn huffman_literal_name_without_value_rejected() {
        // 0x38 = 001|1|1|000：H=1、NameLen=0，但后续没有值的长度/字节，
        // 拒绝原因是截断（不是 H 位）。
        assert_eq!(
            decode_field_section(&[0x00, 0x00, 0x38]),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn decode_string_rfc7541_c4_vectors() {
        // RFC 7541 Appendix C.4 的 Huffman 编码（独立来源：RFC 原文），
        // 加上 §4.1.2 的 `H=1 | Length(7+)` 前缀。
        let cases: [(&[u8], &[u8]); 4] = [
            (
                b"www.example.com",
                &[
                    0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ],
            ),
            (b"no-cache", &[0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
            (
                b"custom-key",
                &[0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
            ),
            (
                b"custom-value",
                &[0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            ),
        ];
        for (plain, encoded) in cases {
            let (decoded, consumed) = decode_string(encoded).unwrap();
            assert_eq!(decoded, plain);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn decode_string_huffman_empty() {
        // H=1 且 Length=0：合法空串，消费 1 字节。
        assert_eq!(decode_string(&[0x80]).unwrap(), (Vec::new(), 1));
    }

    #[test]
    fn decode_string_rejects_invalid_huffman() {
        // H=1、Length=1、payload ff：符号 0 的 13 位码只有前 8 位（截断）。
        assert_eq!(
            decode_string(&[0x81, 0xff]),
            Err(Hysteria2Error::InvalidFrame)
        );
        // H=1、Length=2、payload 1f ff：'a' + 11 位 padding（> 7 位）。
        assert_eq!(
            decode_string(&[0x82, 0x1f, 0xff]),
            Err(Hysteria2Error::InvalidFrame)
        );
    }

    #[test]
    fn decode_field_section_qpack_golden() {
        // 46 字节 QPACK 字段段，由 pylsqpack 0.3.18 `Encoder(0,0).encode` 生成
        // （独立 QPACK 实现；sha256 b7bbddd3acee2e39ad06719dd8b68f4c301428e2fe76b248fd09a567bbc4d253）。
        // 含 1 个静态索引字段 + 2 个 §4.5.4 字段，且这两个字段的名字与值均 H=1。
        let block: [u8; 46] = [
            0x00, 0x00, 0xd9, 0x2f, 0x04, 0xf2, 0xb1, 0xaa, 0x49, 0x6c, 0x3d, 0x6b, 0x26, 0xc1,
            0x90, 0xbf, 0x8b, 0x9e, 0xd9, 0x65, 0xa4, 0x75, 0x2d, 0x19, 0xd3, 0x3a, 0xc7, 0xeb,
            0x2f, 0x04, 0x21, 0xea, 0x49, 0x6a, 0x4a, 0xd4, 0x0e, 0xa9, 0xad, 0x1c, 0xc5, 0x84,
            0x2d, 0x4b, 0x70, 0xdd,
        ];
        let decoded = decode_field_section(&block).unwrap();
        let expected: Vec<(String, String)> = [
            (":status", "200"),
            ("x-interop-trace", "huffman-both-ok"),
            ("content-language", "en-US"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
        assert_eq!(decoded, expected);
        assert_eq!(&block[2..3], &[0xd9]);
        assert_eq!(block[3], 0x2f);
    }

    #[test]
    fn decode_field_section_auth_response_golden() {
        // 258 字节 QPACK 字段段，由 pylsqpack 0.3.18 对 sing-box 1.13.16 认证
        // 响应字段表编码生成（独立 QPACK 实现；sha256
        // 9def938892e691cf202ebc6b9b441b4dda4f85dd5a01cb30cce1ea3b29e9b5ba）。
        const BLOCK: [u8; 258] = [
            0x00, 0x00, 0x5f, 0x09, 0x03, 0x32, 0x33, 0x33, 0x2f, 0x02, 0x9f, 0xd2, 0x12, 0x5b,
            0x0c, 0x35, 0xad, 0x92, 0xbf, 0x83, 0x4d, 0x96, 0x97, 0x2f, 0x03, 0x9f, 0xd2, 0x12,
            0x5b, 0x0c, 0x35, 0x88, 0x45, 0xac, 0xf3, 0x01, 0x30, 0x2f, 0x05, 0x9f, 0xd2, 0x12,
            0x5b, 0x0c, 0x35, 0xab, 0x1c, 0x92, 0x1a, 0xa9, 0xbf, 0xff, 0x4e, 0xfd, 0x76, 0x58,
            0x78, 0xf3, 0xdc, 0xd3, 0xd7, 0xa3, 0xcf, 0x66, 0xf4, 0xde, 0xe5, 0xa6, 0xec, 0xd2,
            0xb8, 0x4c, 0x19, 0x76, 0x69, 0xa2, 0x6a, 0x72, 0xe3, 0x6f, 0x77, 0x9e, 0x98, 0x34,
            0xb5, 0xc7, 0x49, 0xd3, 0xea, 0x1d, 0x2e, 0x03, 0xac, 0x7e, 0x9f, 0x46, 0x74, 0x74,
            0xed, 0x95, 0x17, 0x5d, 0xf2, 0x1a, 0x71, 0x61, 0x10, 0x75, 0x51, 0xda, 0xf6, 0xe0,
            0x65, 0x73, 0xde, 0xad, 0x78, 0x7b, 0x93, 0x19, 0x28, 0x87, 0xf6, 0xc9, 0x76, 0x43,
            0xe5, 0x1c, 0x0c, 0xf6, 0xf1, 0x55, 0xc3, 0x8f, 0xeb, 0x82, 0x0f, 0xe7, 0xb6, 0xe3,
            0x06, 0xa9, 0xfd, 0x67, 0x99, 0xb7, 0xc3, 0xec, 0xc1, 0xb2, 0x3f, 0xca, 0xb8, 0xe1,
            0x67, 0xbd, 0xfc, 0x8d, 0xe8, 0x1e, 0x5d, 0x80, 0xf7, 0xbd, 0xb2, 0xd5, 0x8b, 0x33,
            0xd1, 0xfa, 0xd1, 0x97, 0x76, 0x4e, 0xb7, 0x7a, 0x9c, 0xdd, 0x53, 0x43, 0xbe, 0x77,
            0xc9, 0x50, 0xed, 0x8d, 0xed, 0xd9, 0x67, 0x24, 0xfe, 0xb7, 0xee, 0xcf, 0xf9, 0xc5,
            0xee, 0x1d, 0xb8, 0x7e, 0x5f, 0xce, 0x5a, 0x31, 0xcc, 0x8e, 0xbb, 0xdb, 0xde, 0x0c,
            0xb7, 0xf2, 0xe4, 0xd1, 0xd9, 0xb7, 0x2b, 0xd3, 0x7b, 0x96, 0x07, 0xbc, 0x43, 0x65,
            0x32, 0xd2, 0x68, 0x70, 0xc3, 0x27, 0xe7, 0xa1, 0x7e, 0xdf, 0xf6, 0xf9, 0x34, 0x5d,
            0xde, 0xdb, 0x56, 0x69, 0x8f, 0xc6, 0xf8, 0x5f, 0xb3, 0x8d, 0x24, 0x3c, 0x3f, 0x98,
            0xc6, 0x2d, 0x58, 0x8c, 0x7a, 0x3f,
        ];
        let decoded = decode_field_section(&BLOCK).unwrap();
        let get = |name: &str| {
            decoded
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get(":status"), Some("233"));
        assert_eq!(get("hysteria-udp"), Some("true"));
        assert_eq!(get("hysteria-cc-rx"), Some("0"));
        let padding = get("hysteria-padding").expect("hysteria-padding missing");
        // sing-quic padding{Min:256,Max:2048}: 256..=2047 个 [a-zA-Z0-9]。
        assert!((256..=2047).contains(&padding.len()), "{}", padding.len());
        assert!(
            padding.bytes().all(|b| b.is_ascii_alphanumeric()),
            "padding must be alphanumeric"
        );
    }
}
