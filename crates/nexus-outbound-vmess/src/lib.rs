//! nexus-outbound-vmess
//!
//! VMess AEAD 出站 adapter（PRODUCT §11.7）：实现 `nexus-connectivity::OutboundAdapter`。
//!
//! 复用已评审入仓的 RustCrypto `chacha20poly1305` + `sha2`（零新第三方依赖）。UUID 经
//! SHA-256 确定性派生会话 key；固定计数器 nonce（离线确定性，不调 getrandom）。本 crate 不连
//! 真实 server，E4 仅做 encrypt->decrypt 自洽往返。

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

use nexus_connectivity::{ConnectivityError, OutboundAdapter, OutboundHandoff};

// ---------- 结构化错误 ----------

/// VMess 出站的结构化错误（不以日志文本代替错误类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmessCipherError {
    /// UUID/key 材料非法（空）。
    InvalidKeyMaterial,
    /// 帧长度非法（小于 nonce + tag）。
    InvalidFrame,
    /// AEAD 加解密失败。
    CryptoFailed,
}

impl core::fmt::Display for VmessCipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyMaterial => write!(f, "vmess invalid key material"),
            Self::InvalidFrame => write!(f, "vmess frame too short / invalid"),
            Self::CryptoFailed => write!(f, "vmess AEAD crypto failed"),
        }
    }
}

impl std::error::Error for VmessCipherError {}

// ---------- security method ----------

/// VMess AEAD 安全方法（本期冻结仅 chacha20-poly1305）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    /// chacha20-poly1305（256-bit key，96-bit nonce）。
    Chacha20Poly1305,
}

impl VmessSecurity {
    /// 稳定方法标签（与配置/YAML/JSON 一致）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        "chacha20-poly1305"
    }

    /// key 长度（字节）。
    #[must_use]
    pub fn key_len(self) -> usize {
        32
    }

    /// 解析方法标签。
    ///
    /// # Errors
    ///
    /// 非法值返回 `InvalidFrame`。
    pub fn parse(s: &str) -> Result<Self, VmessCipherError> {
        match s {
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            _ => Err(VmessCipherError::InvalidFrame),
        }
    }
}

// ---------- adapter ----------

/// VMess AEAD 出站 adapter。
pub struct VmessAdapter {
    tag: String,
    locator: String,
    security: VmessSecurity,
    key: [u8; 32],
    /// 固定计数器 nonce（离线确定性；不调 getrandom）。
    nonce_counter: u64,
}

impl VmessAdapter {
    /// 构造 adapter；UUID 经 SHA-256 确定性派生 32 字节 key。
    ///
    /// # Errors
    ///
    /// key 材料为空返回 `InvalidKeyMaterial`。
    pub fn new(
        tag: impl Into<String>,
        locator: impl Into<String>,
        security: VmessSecurity,
        uuid: &str,
    ) -> Result<Self, VmessCipherError> {
        if uuid.is_empty() {
            return Err(VmessCipherError::InvalidKeyMaterial);
        }
        let mut h = Sha256::new();
        h.update(uuid.as_bytes());
        let digest = h.finalize();
        let mut key = [0u8; 32];
        let n = security.key_len().min(digest.len());
        key[..n].copy_from_slice(&digest[..n]);
        Ok(Self {
            tag: tag.into(),
            locator: locator.into(),
            security,
            key,
            nonce_counter: 0,
        })
    }

    /// 安全方法标签（可观测字段）。
    #[must_use]
    pub fn security_label(&self) -> &'static str {
        self.security.as_str()
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    /// 用当前计数器 nonce 加密；输出 = `nonce(12B) || ciphertext+tag`。
    ///
    /// # Errors
    ///
    /// AEAD 加密失败返回 `CryptoFailed`。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, VmessCipherError> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let ct = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| VmessCipherError::CryptoFailed)?;
        let mut frame = nonce.to_vec();
        frame.extend(ct);
        Ok(frame)
    }

    /// 解密 `nonce(12B) || ciphertext+tag` 帧；用帧内 nonce，不依赖本地计数器。
    ///
    /// # Errors
    ///
    /// 帧过短返回 `InvalidFrame`；AEAD 校验失败返回 `CryptoFailed`。
    pub fn decrypt(&self, frame: &[u8]) -> Result<Vec<u8>, VmessCipherError> {
        if frame.len() < 12 + 16 {
            return Err(VmessCipherError::InvalidFrame);
        }
        let (nonce, ct) = frame.split_at(12);
        self.cipher()
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| VmessCipherError::CryptoFailed)
    }
}

impl OutboundAdapter for VmessAdapter {
    fn outbound_kind(&self) -> &'static str {
        "vmess"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError> {
        let _ = &self.locator; // 离线交接不校验远端可达性。
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
        let mut a = VmessAdapter::new(
            "vm-out",
            "vmess.example:10086",
            VmessSecurity::Chacha20Poly1305,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
        )
        .unwrap();
        let plaintext = b"hello vmess";
        let frame = a.encrypt(plaintext).unwrap();
        assert!(frame.len() > plaintext.len());
        let recovered = a.decrypt(&frame).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_uuid_fails_decrypt() {
        let mut enc =
            VmessAdapter::new("a", "h:1", VmessSecurity::Chacha20Poly1305, "uuid-one").unwrap();
        let dec =
            VmessAdapter::new("b", "h:1", VmessSecurity::Chacha20Poly1305, "uuid-two").unwrap();
        let frame = enc.encrypt(b"secret").unwrap();
        assert!(dec.decrypt(&frame).is_err());
    }

    #[test]
    fn deterministic_kind_and_method() {
        let a = VmessAdapter::new("t", "h:1", VmessSecurity::Chacha20Poly1305, "uuid").unwrap();
        assert_eq!(a.outbound_kind(), "vmess");
        assert_eq!(a.security_label(), "chacha20-poly1305");
        assert_eq!(a.tag(), "t");
        assert!(a.decrypt(&[]).is_err());
    }
}
