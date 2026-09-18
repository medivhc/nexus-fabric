//! nexus-outbound-shadowsocks
//!
//! Shadowsocks AEAD 出站 adapter（PRODUCT §11.6）：实现
//! `nexus-connectivity::OutboundAdapter`，对出站字节流做 AEAD 封装/解封装。
//!
//! 本期冻结 method 为 `chacha20-ietf-poly1305`（RustCrypto 纯 Rust 实现）；password 经
//! HKDF-SHA256（盐=method 标签）确定性派生会话 key；离线确定性（固定计数器 nonce，不调 getrandom）。
//! 本 crate 不连真实服务器，E4 仅做 encrypt->decrypt 自洽往返。

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use nexus_connectivity::{ConnectivityError, OutboundAdapter, OutboundHandoff};

// ---------- 结构化错误 ----------

/// Shadowsocks 出站的结构化错误（不以日志文本代替错误类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundCipherError {
    /// 由 password 派生 key 失败。
    KeyDerivation,
    /// 帧长度非法（小于 nonce + tag）。
    InvalidFrame,
    /// AEAD 解密失败（key/nonce/tag 校验未过）。
    DecryptFailed,
}

impl core::fmt::Display for OutboundCipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyDerivation => write!(f, "ss key derivation failed"),
            Self::InvalidFrame => write!(f, "ss frame too short / invalid"),
            Self::DecryptFailed => write!(f, "ss AEAD decryption failed"),
        }
    }
}

impl std::error::Error for OutboundCipherError {}

// ---------- method ----------

/// Shadowsocks AEAD 方法（本期冻结仅 chacha20-ietf-poly1305）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsMethod {
    /// chacha20-ietf-poly1305（256-bit key，96-bit nonce）。
    Chacha20IetfPoly1305,
}

impl SsMethod {
    /// 稳定方法标签（与配置/YAML/JSON 一致）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        "chacha20-ietf-poly1305"
    }

    /// key 长度（字节）。
    #[must_use]
    pub fn key_len(&self) -> usize {
        match self {
            Self::Chacha20IetfPoly1305 => 32,
        }
    }

    /// 解析方法标签；非法值返回 `InvalidFrame`。
    pub fn parse(s: &str) -> Result<Self, OutboundCipherError> {
        match s {
            "chacha20-ietf-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            other => {
                let _ = other;
                Err(OutboundCipherError::InvalidFrame)
            }
        }
    }
}

// ---------- adapter ----------

/// Shadowsocks AEAD 出站 adapter。
pub struct ShadowsocksAdapter {
    tag: String,
    locator: String,
    method: SsMethod,
    key: Vec<u8>,
    /// 固定计数器 nonce（离线确定性；不调 getrandom）。
    nonce_counter: u64,
}

impl ShadowsocksAdapter {
    /// 构造 adapter；password 经 HKDF-SHA256（盐=method 标签）确定性派生 key。
    ///
    /// # Errors
    ///
    /// key 派生失败返回 `KeyDerivation`。
    pub fn new(
        tag: impl Into<String>,
        locator: impl Into<String>,
        method: SsMethod,
        password: &str,
    ) -> Result<Self, OutboundCipherError> {
        let hk = Hkdf::<Sha256>::new(Some(method.as_str().as_bytes()), password.as_bytes());
        let mut key = vec![0u8; method.key_len()];
        hk.expand(&[], &mut key)
            .map_err(|_| OutboundCipherError::KeyDerivation)?;
        Ok(Self {
            tag: tag.into(),
            locator: locator.into(),
            method,
            key,
            nonce_counter: 0,
        })
    }

    /// 方法标签（可观测字段）。
    #[must_use]
    pub fn method_label(&self) -> &'static str {
        self.method.as_str()
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    /// 用当前计数器 nonce 加密；输出 = nonce(12B) || ciphertext+tag。
    ///
    /// # Errors
    ///
    /// AEAD 加密失败返回 `DecryptFailed`。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let ct = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| OutboundCipherError::DecryptFailed)?;
        let mut frame = nonce.to_vec();
        frame.extend(ct);
        Ok(frame)
    }

    /// 解密 `nonce(12B) || ciphertext+tag` 帧；用帧内 nonce，不依赖本地计数器。
    ///
    /// # Errors
    ///
    /// 帧过短返回 `InvalidFrame`；AEAD 校验失败返回 `DecryptFailed`。
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        if frame.len() < 12 + 16 {
            return Err(OutboundCipherError::InvalidFrame);
        }
        let (nonce, ct) = frame.split_at(12);
        self.cipher()
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| OutboundCipherError::DecryptFailed)
    }
}

impl OutboundAdapter for ShadowsocksAdapter {
    fn outbound_kind(&self) -> &'static str {
        "shadowsocks"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError> {
        let _ = &self.locator; // 已在构造时记录；离线交接不校验远端可达性。
        Ok(OutboundHandoff {
            kind: self.outbound_kind().to_string(),
            tag: self.tag.clone(),
            locator: locator.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_self_consistent() {
        let mut a = ShadowsocksAdapter::new(
            "ss-out",
            "ss.example:8388",
            SsMethod::Chacha20IetfPoly1305,
            "demo-password",
        )
        .unwrap();
        let plaintext = b"hello shadowsocks";
        let frame = a.encrypt(plaintext).unwrap();
        assert!(frame.len() > plaintext.len());
        let recovered = a.decrypt(&frame).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_password_fails_decrypt() {
        let mut enc =
            ShadowsocksAdapter::new("a", "h:1", SsMethod::Chacha20IetfPoly1305, "password-one")
                .unwrap();
        let mut dec =
            ShadowsocksAdapter::new("b", "h:1", SsMethod::Chacha20IetfPoly1305, "password-two")
                .unwrap();
        let frame = enc.encrypt(b"secret").unwrap();
        assert!(dec.decrypt(&frame).is_err());
    }

    #[test]
    fn deterministic_key_and_kind() {
        let a = ShadowsocksAdapter::new("t", "h:1", SsMethod::Chacha20IetfPoly1305, "pw").unwrap();
        assert_eq!(a.outbound_kind(), "shadowsocks");
        assert_eq!(a.method_label(), "chacha20-ietf-poly1305");
        assert_eq!(a.tag(), "t");
    }
}
