//! Salamander 混淆（文档 §2.4）：可选的整包 XOR 混淆层。
//!
//! 每个 UDP 数据报（整个 QUIC 包）封装为：
//!
//! ```text
//! [8 字节] 随机 salt
//! [bytes ] payload XOR BLAKE2b-256(key || salt) 的循环密钥流
//! ```
//!
//! 即 `payload[i] ^= keystream[i % 32]`。收包时按前 8 字节取 salt 重算密钥流
//! 解开；不足 8 字节的包视为非法并丢弃。
//!
//! 注意：这是 **QUIC 包之下**的变换——在 driver 收发 UDP datagram 处做，
//! 而不是在 QUIC stream/datagram 载荷层做。

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use super::Hysteria2Error;

/// Salamander salt 长度（8 字节）。
pub const SALT_LEN: usize = 8;
/// BLAKE2b-256 输出长度（32 字节，密钥流循环周期）。
pub const KEYSTREAM_LEN: usize = 32;

/// 计算密钥流：`BLAKE2b-256(key || salt)`。
fn keystream(key: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEYSTREAM_LEN] {
    let mut h = Blake2b::<U32>::new();
    h.update(key);
    h.update(salt);
    h.finalize().into()
}

/// 混淆一个 UDP 数据报：`salt(8) || (payload XOR 循环密钥流)`。
///
/// `key` 为用户配置的 `obfs-password` 字节；`salt` 应为 8 字节随机数
/// （调用方用系统 RNG 生成）。
#[must_use]
pub fn obfuscate(key: &[u8], payload: &[u8], salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let ks = keystream(key, salt);
    let mut out = Vec::with_capacity(SALT_LEN + payload.len());
    out.extend_from_slice(salt);
    out.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ ks[i % KEYSTREAM_LEN]),
    );
    out
}

/// 解混淆一个 UDP 数据报：取前 8 字节为 salt，重算密钥流后 XOR 还原。
///
/// # Errors
///
/// 包短于 8 字节（连 salt 都放不下）→ [`Hysteria2Error::InvalidFrame`]；
/// 调用方应丢弃该包。
pub fn deobfuscate(key: &[u8], packet: &[u8]) -> Result<Vec<u8>, Hysteria2Error> {
    if packet.len() < SALT_LEN {
        return Err(Hysteria2Error::InvalidFrame);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&packet[..SALT_LEN]);
    let ks = keystream(key, &salt);
    Ok(packet[SALT_LEN..]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ ks[i % KEYSTREAM_LEN])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_roundtrip() {
        let key = b"test-obfs-password";
        let salt = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let payload = b"a QUIC packet payload, longer than 32 bytes................";
        let enc = obfuscate(key, payload, &salt);
        assert_eq!(&enc[..8], &salt);
        assert_eq!(enc.len(), 8 + payload.len());
        let dec = deobfuscate(key, &enc).unwrap();
        assert_eq!(dec, payload);
    }

    #[test]
    fn salamander_different_salt_different_ciphertext() {
        let key = b"test-obfs-password";
        let payload = b"same plaintext payload here!!!!";
        let enc1 = obfuscate(key, payload, &[0xAA; 8]);
        let enc2 = obfuscate(key, payload, &[0xBB; 8]);
        assert_ne!(enc1, enc2);
        // 但都能用同一 key 解开。
        assert_eq!(deobfuscate(key, &enc1).unwrap(), payload);
        assert_eq!(deobfuscate(key, &enc2).unwrap(), payload);
    }

    #[test]
    fn salamander_keystream_is_cyclic_32() {
        // 密钥流以 32 字节为周期：构造全零载荷，密文即密钥流本身。
        let key = b"k";
        let salt = [0u8; 8];
        let enc = obfuscate(key, &[0u8; 64], &salt);
        assert_eq!(&enc[8..40], &enc[40..72]);
    }

    #[test]
    fn salamander_short_packet_rejected() {
        assert_eq!(
            deobfuscate(b"key", &[0x01, 0x02, 0x03]),
            Err(Hysteria2Error::InvalidFrame)
        );
        assert_eq!(deobfuscate(b"key", &[]), Err(Hysteria2Error::InvalidFrame));
    }

    #[test]
    fn salamander_wrong_key_garbles() {
        let enc = obfuscate(b"right-key", b"payload-data-1234", &[0x42; 8]);
        let dec = deobfuscate(b"wrong-key", &enc).unwrap();
        assert_ne!(dec, b"payload-data-1234");
    }

    #[test]
    fn salamander_empty_payload_ok() {
        let enc = obfuscate(b"k", &[], &[0x11; 8]);
        assert_eq!(enc.len(), 8);
        assert_eq!(deobfuscate(b"k", &enc).unwrap(), b"");
    }
}
