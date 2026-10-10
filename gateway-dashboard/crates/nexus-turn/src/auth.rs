//! 长效认证（RFC 5389 §10.2 / RFC 5766 §2.2）。
//!
//! - key 推导：`MD5(username ":" realm ":" password)`（RFC 5389 §10.2.2）。
//! - MESSAGE-INTEGRITY：`HMAC-SHA1(key, 消息)`，消息为 MI 属性值清零后
//!   的完整数据报（含头长度字段，按 RFC 5389 §14.5 语义）。

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

/// 对已编码的请求计算 MI 并回填（`mi_value_offset` 为 MI 属性值偏移）。
///
/// 调用方保证消息的 MI 属性是最后一个属性且值为 20 字节零（见
/// `stun::Attribute::MessageIntegrity` 编码约定）。
pub fn stamp_integrity(encoded: &mut [u8], mi_value_offset: usize, key: &[u8]) {
    let mut tmp = encoded.to_vec();
    for b in &mut tmp[mi_value_offset..mi_value_offset + 20] {
        *b = 0;
    }
    let tag = message_integrity(key, &tmp);
    encoded[mi_value_offset..mi_value_offset + 20].copy_from_slice(&tag);
}

/// 验证收到的数据报的 MI（`raw` 为完整数据报，`mi_value_offset` 由解码给出）。
pub fn verify_integrity(raw: &[u8], mi_value_offset: usize, key: &[u8]) -> bool {
    if raw.len() < mi_value_offset + 20 {
        return false;
    }
    let mut tmp = raw.to_vec();
    for b in &mut tmp[mi_value_offset..mi_value_offset + 20] {
        *b = 0;
    }
    let tag = message_integrity(key, &tmp);
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
