//! 长效认证（RFC 5389 §10.2 / RFC 5766 §2.2）。
//!
//! - key 推导：`MD5(username ":" realm ":" password)`（RFC 5389 §10.2.2）。
//! - MESSAGE-INTEGRITY：`HMAC-SHA1(key, 输入)`，输入为报文从起始到 MI 属性
//!   之前的部分（不含 MI 属性头与值，也不含 MI 之后的属性），且头 length
//!   字段调整为「计入 MI 属性」后的长度（RFC 5389 §15.4）。

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// 推导长效认证 key。
pub fn derive_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let input = format!("{username}:{realm}:{password}");
    md5::compute(input.as_bytes()).0
}

/// 计算 HMAC-SHA1。
pub fn message_integrity(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// 常量时间比较（防时序侧信道；server 验证 MI 用）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 构造 RFC 5389 §15.4 规定的 HMAC 输入。
///
/// `datagram` 为完整数据报（含 20 字节 STUN 头），`mi_value_offset` 为
/// MESSAGE-INTEGRITY 属性**值**的偏移（属性头 4 字节在其之前）。
///
/// 输入由两部分决定：
/// - 只取 `datagram[..mi_attr_offset]`，即报文中 MI 属性头之前的全部字节
///   （MI 属性头/值本身以及 MI 之后的属性都不参与）；
/// - 头 length 字段改写为「计入 MI 属性」后的长度：
///   `(mi_attr_offset - 20) + 24`，即 MI 属性头 4 字节 + 值 20 字节。
fn integrity_input(datagram: &[u8], mi_value_offset: usize) -> Option<Vec<u8>> {
    let mi_attr_offset = mi_value_offset.checked_sub(4)?;
    if mi_attr_offset < 20 || datagram.len() < mi_value_offset.checked_add(20)? {
        return None;
    }
    let adjusted_len = u16::try_from(mi_attr_offset - 20 + 24).ok()?;
    let mut input = datagram[..mi_attr_offset].to_vec();
    input[2..4].copy_from_slice(&adjusted_len.to_be_bytes());
    Some(input)
}

/// 对已编码的请求计算 MI 并回填（`mi_value_offset` 为 MI 属性值偏移）。
///
/// HMAC 输入按 RFC 5389 §15.4 构造（见 [`integrity_input`]）；报文自身的头
/// length 字段保持编码时的全量长度不变，只有 HMAC 输入里被调整。
/// 调用方保证 MI 属性值为 20 字节零（见
/// `stun::Attribute::MessageIntegrity` 编码约定）。
pub fn stamp_integrity(encoded: &mut [u8], mi_value_offset: usize, key: &[u8]) {
    let Some(input) = integrity_input(encoded, mi_value_offset) else {
        return;
    };
    let tag = message_integrity(key, &input);
    encoded[mi_value_offset..mi_value_offset + 20].copy_from_slice(&tag);
}

/// 验证收到的数据报的 MI（`raw` 为完整数据报，`mi_value_offset` 由解码给出）。
pub fn verify_integrity(raw: &[u8], mi_value_offset: usize, key: &[u8]) -> bool {
    let Some(input) = integrity_input(raw, mi_value_offset) else {
        return false;
    };
    let tag = message_integrity(key, &input);
    constant_time_eq(&tag, &raw[mi_value_offset..mi_value_offset + 20])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5766 风格的长效认证往返：推导 key → 加盖 MI → 验证通过；
    /// 篡改任一字节 → 验证失败。
    #[test]
    fn long_term_credentials_roundtrip() {
        let key = derive_key("nexus", "nexus", "turn-test");
        // key 必须是 MD5("nexus:nexus:turn-test")
        let expected = md5::compute(b"nexus:nexus:turn-test").0;
        assert_eq!(key, expected);

        let mut msg = b"\x00\x03\x00\x24\x21\x12\xa4\x42".to_vec();
        msg.extend_from_slice(&[0u8; 12]); // txn
                                           // 追加一个 MI 属性（type + len + 20 零字节）
        let mi_offset = msg.len() + 4;
        msg.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        msg.extend_from_slice(&[0u8; 20]);
        // 头长度字段 = 属性区长度
        let attr_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&attr_len.to_be_bytes());

        stamp_integrity(&mut msg, mi_offset, &key);
        assert!(verify_integrity(&msg, mi_offset, &key));

        // 篡改载荷 → 失败
        let mut bad = msg.clone();
        bad[30] ^= 0x01;
        assert!(!verify_integrity(&bad, mi_offset, &key));

        // 错误 key → 失败
        let wrong = derive_key("nexus", "nexus", "wrong-pass");
        assert!(!verify_integrity(&msg, mi_offset, &wrong));
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
