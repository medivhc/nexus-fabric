//! SecureStore 平台无关核心：machine-id 解析、NEXSEC1 文件格式与 AEAD 记录。
//!
//! 边界（PRODUCT §12.30）：
//! - 纯逻辑/格式/算法平台无关（ring，非 portable-core 目标）；
//! - 具体平台后端（DPAPI / machine-id 文件读取）在 `nexus-platform-*`；
//! - 本模块不含 OS 专属 API，可被 E4 example 在任意宿主编译调用。

use crate::PlatformError;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::{SecureRandom, SystemRandom};

/// NEXSEC1 文件格式魔数（7 字节）。
pub const NEXSEC1_MAGIC: &[u8; 7] = b"NEXSEC1";

/// HKDF salt 标签（版本化，变更即派生不同密钥）。
const HKDF_SALT: &[u8] = b"nexus-secure-store-v1";
/// HKDF info 标签（用途区分）。
const HKDF_INFO: &[u8] = b"nexus-secure-store-key";
/// machine-id 合法长度（32 个 hex 字符 = 16 字节）。
const MACHINE_ID_HEX_LEN: usize = 32;

/// 解析 `/etc/machine-id` 格式：恰好 32 个十六进制字符（小写/大写均可）→ 16 字节。
///
/// 长度非 32 或含非 hex 字符 → `PlatformError::Invalid`（结构化，不静默降级）。
pub fn parse_machine_id(input: &str) -> Result<[u8; 16], PlatformError> {
    let trimmed = input.trim();
    if trimmed.len() != MACHINE_ID_HEX_LEN {
        return Err(PlatformError::Invalid {
            message: format!(
                "machine-id must be {MACHINE_ID_HEX_LEN} hex chars, got {}",
                trimmed.len()
            ),
        });
    }
    let mut out = [0u8; 16];
    let bytes = trimmed.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        out[i / 2] = (out[i / 2] << 4) | hex_val(*b)?;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, PlatformError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PlatformError::Invalid {
            message: format!("machine-id contains non-hex char: {:?}", b as char),
        }),
    }
}

/// 从 machine-id 派生 32 字节 ChaCha20-Poly1305 密钥：HKDF-SHA256（salt+info 版本化）。
///
/// 确定性：同一 machine-id 永远派生同一密钥（离线可复现）。
pub fn derive_key(machine_id: &[u8; 16]) -> Result<[u8; 32], PlatformError> {
    let salt = Salt::new(HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(machine_id);
    // ring 0.17：KeyType 由 &'static Algorithm 实现，输出长度 = 算法 digest 长度（32）。
    let okm = prk
        .expand(&[HKDF_INFO], HKDF_SHA256)
        .map_err(|_| PlatformError::Invalid {
            message: "hkdf expand failed".into(),
        })?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| PlatformError::Invalid {
        message: "hkdf output fill failed".into(),
    })?;
    Ok(out)
}

/// 生成 12 字节随机 nonce（系统 CSPRNG）。
fn random_nonce() -> Result<[u8; NONCE_LEN], PlatformError> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| PlatformError::Io {
        operation: "secure store nonce".into(),
        message: "system rng fill failed".into(),
    })?;
    Ok(nonce)
}

/// AEAD 记录封装：`NEXSEC1 || nonce(12B) || ciphertext || tag(16B)`。
///
/// key 必须为 32 字节（ChaCha20-Poly1305 密钥长度）；错误结构化返回。
pub fn encrypt_record(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let nonce = random_nonce()?;
    let seal_key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| {
        PlatformError::Invalid {
            message: "bad aead key".into(),
        }
    })?);
    let mut in_out = plaintext.to_vec();
    let tag = seal_key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| PlatformError::Io {
            operation: "aead seal".into(),
            message: "encryption failed".into(),
        })?;

    let mut record = Vec::with_capacity(
        NEXSEC1_MAGIC.len() + NONCE_LEN + in_out.len() + CHACHA20_POLY1305.tag_len(),
    );
    record.extend_from_slice(NEXSEC1_MAGIC);
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&in_out);
    record.extend_from_slice(tag.as_ref());
    Ok(record)
}

/// 解析并解密 AEAD 记录（`encrypt_record` 的逆）。
///
/// magic 不符 → `Invalid`；tag 校验失败 → `Io`（不暴露明文）；截断 → `Invalid`。
pub fn decrypt_record(key: &[u8; 32], record: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let min_len = NEXSEC1_MAGIC.len() + NONCE_LEN + CHACHA20_POLY1305.tag_len();
    if record.len() < min_len {
        return Err(PlatformError::Invalid {
            message: "secure store record too short".into(),
        });
    }
    if &record[..NEXSEC1_MAGIC.len()] != NEXSEC1_MAGIC {
        return Err(PlatformError::Invalid {
            message: "secure store record magic mismatch".into(),
        });
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&record[NEXSEC1_MAGIC.len()..NEXSEC1_MAGIC.len() + NONCE_LEN]);
    let mut in_out = record[NEXSEC1_MAGIC.len() + NONCE_LEN..].to_vec();

    let seal_key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| {
        PlatformError::Invalid {
            message: "bad aead key".into(),
        }
    })?);
    let plain = seal_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| PlatformError::Io {
            operation: "aead open".into(),
            message: "decryption failed (bad key or tampered record)".into(),
        })?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn parse_machine_id_ok_and_bad() {
        // "0123456789abcdef" → 每 2 个 hex 字符 1 字节：01 23 45 67 89 ab cd ef
        assert_eq!(
            parse_machine_id(GOOD).unwrap(),
            *b"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"
        );
        assert_eq!(parse_machine_id(&GOOD.to_uppercase()).unwrap().len(), 16);
        assert!(parse_machine_id("xyz").is_err());
        assert!(parse_machine_id(&GOOD[..31]).is_err());
        assert!(parse_machine_id("0123456789abcdef0123456789abcdeg").is_err());
    }

    #[test]
    fn derive_key_deterministic() {
        let mid = parse_machine_id(GOOD).unwrap();
        let mid2 = parse_machine_id(GOOD).unwrap();
        assert_eq!(mid, mid2);
        let k1 = derive_key(&mid).unwrap();
        let k2 = derive_key(&mid2).unwrap();
        assert_eq!(k1, k2);
        let other = parse_machine_id("ffffffffffffffffffffffffffffffff").unwrap();
        assert_ne!(derive_key(&other).unwrap(), k1);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mid = parse_machine_id(GOOD).unwrap();
        let key = derive_key(&mid).unwrap();
        let secret = b"nexus secure store secret";
        let rec = encrypt_record(&key, secret).unwrap();
        assert!(rec.starts_with(NEXSEC1_MAGIC));
        assert_ne!(rec, secret);
        assert_eq!(decrypt_record(&key, &rec).unwrap(), secret);
    }

    #[test]
    fn decrypt_rejects_tamper_and_bad_magic() {
        let mid = parse_machine_id(GOOD).unwrap();
        let key = derive_key(&mid).unwrap();
        let rec = encrypt_record(&key, b"payload").unwrap();
        // 篡改密文
        let mut tampered = rec.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(decrypt_record(&key, &tampered).is_err());
        // 坏 magic
        let mut bad_magic = rec.clone();
        bad_magic[0] = b'X';
        assert!(decrypt_record(&key, &bad_magic).is_err());
        // 错误密钥
        let other = parse_machine_id("ffffffffffffffffffffffffffffffff").unwrap();
        let wrong_key = derive_key(&other).unwrap();
        assert!(decrypt_record(&wrong_key, &rec).is_err());
    }
}
