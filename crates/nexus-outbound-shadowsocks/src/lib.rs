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

// ---------- 真实 TCP 会话层（§11.6.1） ----------

use std::io::{Read, Write};

/// 会话方向角色：决定 c2s / s2c 哪把 key 用于发送。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 客户端：TX=c2s key，RX=s2c key。
    Client,
    /// 服务端：TX=s2c key，RX=c2s key。
    Server,
}

/// SS 请求目标地址（ATYP 子集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsTarget {
    /// ATYP=1 IPv4。
    Ipv4([u8; 4], u16),
    /// ATYP=3 domain。
    Domain(String, u16),
}

impl SsTarget {
    /// 稳定 host 标签（观测/断言用）。
    #[must_use]
    pub fn host_label(&self) -> String {
        match self {
            Self::Ipv4(oct, _) => oct.iter().map(u8::to_string).collect::<Vec<_>>().join("."),
            Self::Domain(d, _) => d.clone(),
        }
    }

    /// 端口。
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, p) | Self::Domain(_, p) => *p,
        }
    }
}

/// 编码 SS request header：`ATYP | addr | port(2 BE)`。
///
/// IPv4 为 `0x01 | 4 字节 IP | port`；domain 为 `0x03 | len(1) | host | port`。
#[must_use]
pub fn encode_request(target: &SsTarget) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        SsTarget::Ipv4(oct, port) => {
            out.push(0x01);
            out.extend_from_slice(oct);
            out.extend_from_slice(&port.to_be_bytes());
        }
        SsTarget::Domain(host, port) => {
            out.push(0x03);
            out.push(host.len().min(255) as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out
}

/// 解码 SS request header 原始字节；ATYP/长度非法返回 `InvalidFrame`。
///
/// # Errors
///
/// 长度不足、未知 ATYP、domain 长度与实际不符返回 `InvalidFrame`。
pub fn parse_request(buf: &[u8]) -> Result<SsTarget, OutboundCipherError> {
    if buf.len() < 2 {
        return Err(OutboundCipherError::InvalidFrame);
    }
    match buf[0] {
        0x01 => {
            if buf.len() != 1 + 4 + 2 {
                return Err(OutboundCipherError::InvalidFrame);
            }
            let mut oct = [0u8; 4];
            oct.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok(SsTarget::Ipv4(oct, port))
        }
        0x03 => {
            let dlen = buf[1] as usize;
            let need = 2 + dlen + 2;
            if buf.len() != need {
                return Err(OutboundCipherError::InvalidFrame);
            }
            let host = std::str::from_utf8(&buf[2..2 + dlen])
                .map_err(|_| OutboundCipherError::InvalidFrame)?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
            Ok(SsTarget::Domain(host, port))
        }
        _ => Err(OutboundCipherError::InvalidFrame),
    }
}

/// 双向加密会话流：c2s/s2c 两把独立 key（HKDF info 区分），TX 方向固定计数 nonce。
pub struct SsStream {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_counter: u64,
}

fn derive_key(method: SsMethod, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(method.as_str().as_bytes()), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf expand 32 bytes");
    out
}

impl SsStream {
    /// 按角色构造会话：Client TX=c2s/RX=s2c；Server 相反。
    ///
    /// # Errors
    ///
    /// key 派生失败返回 `KeyDerivation`（HKDF 固定 32B 实际不会失败）。
    pub fn new(password: &str, method: SsMethod, role: Role) -> Result<Self, OutboundCipherError> {
        let ikm = password.as_bytes();
        let c2s = derive_key(method, ikm, b"ss-c2s");
        let s2c = derive_key(method, ikm, b"ss-s2c");
        let (tx, rx) = match role {
            Role::Client => (c2s, s2c),
            Role::Server => (s2c, c2s),
        };
        Ok(Self {
            tx: ChaCha20Poly1305::new(Key::from_slice(&tx)),
            rx: ChaCha20Poly1305::new(Key::from_slice(&rx)),
            tx_counter: 0,
        })
    }

    /// 加密一段明文记录：输出 `nonce(12B) || ciphertext+tag`。
    ///
    /// # Errors
    ///
    /// AEAD 加密失败返回 `DecryptFailed`。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.tx_counter.to_le_bytes());
        self.tx_counter = self.tx_counter.wrapping_add(1);
        let ct = self
            .tx
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| OutboundCipherError::DecryptFailed)?;
        let mut frame = nonce.to_vec();
        frame.extend(ct);
        Ok(frame)
    }

    /// 解密一段 `nonce(12B) || ciphertext+tag` 记录（用 RX key，帧内 nonce）。
    ///
    /// # Errors
    ///
    /// 帧过短返回 `InvalidFrame`；AEAD 校验失败返回 `DecryptFailed`。
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        if frame.len() < 12 + 16 {
            return Err(OutboundCipherError::InvalidFrame);
        }
        let (nonce, ct) = frame.split_at(12);
        self.rx
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| OutboundCipherError::DecryptFailed)
    }
}

/// 写一条记录帧：`u32 BE length || record`。
///
/// 泛型化以支持插件 wrapped 流（`Box<dyn ObfuscatedStream>`）；对 `TcpStream`
/// 的既有调用保持兼容（P6）。
///
/// # Errors
///
/// 底层 I/O 错误透传为 `std::io::Error`。
pub fn write_record<W: Write + ?Sized>(stream: &mut W, record: &[u8]) -> std::io::Result<()> {
    stream.write_all(&u32::to_be_bytes(record.len() as u32))?;
    stream.write_all(record)
}

/// 读一条记录帧：先读 `u32 BE length`，再读对应字节。
///
/// 泛型化以支持插件 wrapped 流（`Box<dyn ObfuscatedStream>`）；对 `TcpStream`
/// 的既有调用保持兼容（P6）。
///
/// # Errors
///
/// 连接过早关闭或长度非法时返回 `std::io::Error`。
pub fn read_record<R: Read + ?Sized>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "record too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
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

    #[test]
    fn request_codec_ipv4_roundtrip() {
        let t = SsTarget::Ipv4([127, 0, 0, 1], 8388);
        let enc = encode_request(&t);
        assert_eq!(parse_request(&enc).unwrap(), t);
        assert_eq!(t.host_label(), "127.0.0.1");
        assert_eq!(t.port(), 8388);
    }

    #[test]
    fn request_codec_domain_roundtrip() {
        let t = SsTarget::Domain("target.internal".to_string(), 1080);
        let enc = encode_request(&t);
        assert_eq!(parse_request(&enc).unwrap(), t);
    }

    #[test]
    fn session_client_server_seal_open() {
        let mut client = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Client).unwrap();
        let mut server = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap();
        let req = encode_request(&SsTarget::Ipv4([127, 0, 0, 1], 9000));
        let frame = client.seal(&req).unwrap();
        let plain = server.open(&frame).unwrap();
        assert_eq!(plain, req);
        // reverse direction uses s2c key.
        let reply = server.seal(b"echo").unwrap();
        assert_eq!(client.open(&reply).unwrap(), b"echo");
    }

    #[test]
    fn session_wrong_password_fails() {
        let mut client =
            SsStream::new("one", SsMethod::Chacha20IetfPoly1305, Role::Client).unwrap();
        let mut server =
            SsStream::new("two", SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap();
        let frame = client.seal(b"x").unwrap();
        assert!(server.open(&frame).is_err());
    }
}
