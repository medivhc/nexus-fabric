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

    /// 固定向量用的 transaction ID（12 字节）。
    const SAMPLE_TXN: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    /// 固定向量中 MI 属性**值**的偏移：20 字节头 + 44 字节属性 + 4 字节 MI 头。
    const SAMPLE_MI_VALUE_OFFSET: usize = 68;
    /// 独立 hmac-sha1 工具对 [`sample_rfc_input`] 计算出的参考标签。
    const SAMPLE_RFC_TAG: [u8; 20] = [
        0xa5, 0x84, 0x2e, 0xf3, 0x1e, 0xbd, 0x3c, 0xfb, 0x29, 0x8f, 0xc5, 0x9d, 0x4d, 0xcf, 0x7f,
        0xfe, 0xfc, 0xdb, 0xee, 0x19,
    ];

    /// 手工拼一条带认证属性的 Allocate 请求（MI 为最后一个属性，值为 20 零字节）。
    /// 头 length = 0x0044（68）：44 字节前置属性 + 24 字节 MI 属性。
    fn sample_allocate_request() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x00, 0x03, 0x00, 0x44, 0x21, 0x12, 0xa4, 0x42]);
        msg.extend_from_slice(&SAMPLE_TXN);
        // REQUESTED-TRANSPORT(17/UDP)
        msg.extend_from_slice(&[0x00, 0x19, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00]);
        // USERNAME "alice"（5 + 3 padding）
        msg.extend_from_slice(b"\x00\x06\x00\x05alice\x00\x00\x00");
        // REALM "nexus"（5 + 3 padding）
        msg.extend_from_slice(b"\x00\x14\x00\x05nexus\x00\x00\x00");
        // NONCE "nonce123"（8，无 padding）
        msg.extend_from_slice(b"\x00\x15\x00\x08nonce123");
        // MESSAGE-INTEGRITY 占位（属性头 + 20 零字节）
        msg.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        msg.extend_from_slice(&[0u8; 20]);
        msg
    }

    /// 按 RFC 5389 §15.4 手工拼 HMAC 输入（逐字节字面量，不经过被测实现）：
    /// 报文头（length 调整为目标值 0x0044 = 68）+ MI 属性之前的所有属性。
    fn sample_rfc_input() -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&[0x00, 0x03, 0x00, 0x44, 0x21, 0x12, 0xa4, 0x42]);
        input.extend_from_slice(&SAMPLE_TXN);
        input.extend_from_slice(&[0x00, 0x19, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00]);
        input.extend_from_slice(b"\x00\x06\x00\x05alice\x00\x00\x00");
        input.extend_from_slice(b"\x00\x14\x00\x05nexus\x00\x00\x00");
        input.extend_from_slice(b"\x00\x15\x00\x08nonce123");
        input
    }

    fn sample_key() -> [u8; 16] {
        derive_key("alice", "nexus", "secret")
    }

    /// 字节级向量：测试内独立按 RFC 规则拼输入并用 hmac/sha1 计算期望标签，
    /// 断言 `stamp_integrity` 的产物与之逐字节相等，且 `verify_integrity` 接受。
    /// 旧实现（整包清零 HMAC，包含 MI 属性头与 20 字节零值）必然得到不同标签。
    #[test]
    fn stamp_matches_rfc5389_byte_vector() {
        let key = sample_key();
        let input = sample_rfc_input();
        let mut mac = HmacSha1::new_from_slice(&key).unwrap();
        mac.update(&input);
        let expected: [u8; 20] = mac.finalize().into_bytes().into();
        // 锚定外部独立工具算出的参考向量。
        assert_eq!(expected, SAMPLE_RFC_TAG);

        let mut msg = sample_allocate_request();
        stamp_integrity(&mut msg, SAMPLE_MI_VALUE_OFFSET, &key);
        assert_eq!(
            &msg[SAMPLE_MI_VALUE_OFFSET..SAMPLE_MI_VALUE_OFFSET + 20],
            &expected
        );
        assert!(verify_integrity(&msg, SAMPLE_MI_VALUE_OFFSET, &key));
    }

    /// 负向：用旧算法（整包 MI 值清零后 HMAC，含 MI 属性头与零值）伪造的
    /// 报文，修复后的 `verify_integrity` 必须拒绝。
    #[test]
    fn verify_rejects_legacy_whole_datagram_hmac() {
        let key = sample_key();
        let mut msg = sample_allocate_request();
        let legacy_tag = message_integrity(&key, &msg); // 占位值本身是全零
        msg[SAMPLE_MI_VALUE_OFFSET..SAMPLE_MI_VALUE_OFFSET + 20].copy_from_slice(&legacy_tag);
        assert!(!verify_integrity(&msg, SAMPLE_MI_VALUE_OFFSET, &key));
    }

    /// MI 之后的属性不参与 HMAC；头 length 调整为 MI 计入后的长度
    /// （而非报文自身含尾部属性的全量长度）。
    #[test]
    fn hmac_input_excludes_attributes_after_mi_and_adjusts_length() {
        let key = sample_key();
        let mut msg = sample_allocate_request();
        // MI 之后追加 8 字节 DATA 属性，报文头 length 随之变为 0x004c（76）。
        msg[2..4].copy_from_slice(&0x004cu16.to_be_bytes());
        msg.extend_from_slice(b"\x00\x13\x00\x04tail");
        stamp_integrity(&mut msg, SAMPLE_MI_VALUE_OFFSET, &key);

        // 期望输入：MI 之前的字节 + 头 length = 0x0044（68 = 64 - 20 + 24）。
        let mut input = msg[..SAMPLE_MI_VALUE_OFFSET - 4].to_vec();
        input[2..4].copy_from_slice(&0x0044u16.to_be_bytes());
        let mut mac = HmacSha1::new_from_slice(&key).unwrap();
        mac.update(&input);
        let expected: [u8; 20] = mac.finalize().into_bytes().into();
        assert_eq!(
            &msg[SAMPLE_MI_VALUE_OFFSET..SAMPLE_MI_VALUE_OFFSET + 20],
            &expected
        );
        assert!(verify_integrity(&msg, SAMPLE_MI_VALUE_OFFSET, &key));

        // 若误用报文自身的全量 length（0x004c）计算，标签必然不同。
        input[2..4].copy_from_slice(&0x004cu16.to_be_bytes());
        let mut mac = HmacSha1::new_from_slice(&key).unwrap();
        mac.update(&input);
        let wrong: [u8; 20] = mac.finalize().into_bytes().into();
        assert_ne!(
            &msg[SAMPLE_MI_VALUE_OFFSET..SAMPLE_MI_VALUE_OFFSET + 20],
            &wrong
        );
    }

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
