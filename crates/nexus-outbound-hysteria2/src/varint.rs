//! QUIC 可变长整数编解码（RFC 9000 §16）。
//!
//! 首字节高 2 位决定总长度：`00`=1 字节（0~63）、`01`=2 字节（64~16383）、
//! `10`=4 字节、`11`=8 字节；数值部分大端（含长度位在内的整个整数大端编码）。
//! 上限为 2^62 - 1。

use super::Hysteria2Error;

/// QUIC varint 上限（2^62 - 1，RFC 9000 §16）。
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// 编码一个 QUIC varint，追加到 `out` 末尾。
///
/// # Panics
///
/// `value > VARINT_MAX` 时 panic（调用方应保证协议字段合法）。
pub fn encode(value: u64, out: &mut Vec<u8>) {
    assert!(value <= VARINT_MAX, "varint out of range");
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else if value < 1_073_741_824 {
        out.push(0x80 | (value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(0xC0 | (value >> 56) as u8);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}

/// 解码 `buf` 开头的一个 QUIC varint，返回 `(值, 消费字节数)`。
///
/// # Errors
///
/// 缓冲区不足以容纳完整 varint 时返回 [`Hysteria2Error::InvalidFrame`]。
pub fn decode(buf: &[u8]) -> Result<(u64, usize), Hysteria2Error> {
    let first = *buf.first().ok_or(Hysteria2Error::InvalidFrame)?;
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if buf.len() < len {
        return Err(Hysteria2Error::InvalidFrame);
    }
    let mut value = u64::from(first & 0x3F);
    for b in &buf[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries_roundtrip() {
        // 四个长度类的边界值（RFC 9000 §16 表 4）。
        for v in [
            0u64,
            63,
            64,
            15293,
            16383,
            16384,
            494_878_333,
            1_073_741_823,
            1_073_741_824,
            151_288_809_941_952_652,
            VARINT_MAX,
        ] {
            let mut out = Vec::new();
            encode(v, &mut out);
            let expect_len = if v < 64 {
                1
            } else if v < 16384 {
                2
            } else if v < 1_073_741_824 {
                4
            } else {
                8
            };
            assert_eq!(out.len(), expect_len, "value {v}");
            let (back, n) = decode(&out).unwrap();
            assert_eq!((back, n), (v, expect_len));
        }
    }

    #[test]
    fn varint_known_bytes() {
        // 494878333 = 0x1D7F3E7D -> 9D7F3E7D（4 字节）；
        // 151288809941952652 = 0x2197C5EFF14E88C -> C2197C5EFF14E88C（8 字节）。
        let mut out = Vec::new();
        encode(494_878_333, &mut out);
        assert_eq!(out, [0x9D, 0x7F, 0x3E, 0x7D]);
        let mut out = Vec::new();
        encode(151_288_809_941_952_652, &mut out);
        assert_eq!(
            out,
            [0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C]
        );
    }

    #[test]
    fn varint_truncated_rejected() {
        // 首字节宣称 2 字节，实际只有 1 字节。
        assert_eq!(decode(&[0x40]), Err(Hysteria2Error::InvalidFrame));
        assert_eq!(decode(&[]), Err(Hysteria2Error::InvalidFrame));
        // 8 字节宣称，只给 4 字节。
        assert_eq!(
            decode(&[0xC2, 0x19, 0x7C, 0x5E]),
            Err(Hysteria2Error::InvalidFrame)
        );
    }
}
