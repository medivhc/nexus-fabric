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

/// SIP004 加密会话流（TCP 双向同构）。
///
/// 线格式：`salt(32) || chunk*`，`chunk = AEAD(len 2B BE) || AEAD(payload)`，
/// AEAD = chacha20-ietf-poly1305，AAD 恒为空，nonce 为 12B 小端计数器（不上线）。
/// 两个方向各自生成/消耗自己的 salt：发送方 salt 由本端惰性生成
/// （或经 `with_tx_salt` 注入测试固定值），接收方 salt 从流首 32B 读取。
pub struct SsStream {
    master_key: [u8; 32],
    _role: Role,
    tx: Option<ChaCha20Poly1305>,
    tx_salt: Option<[u8; 32]>,
    tx_nonce: u64,
    rx: Option<ChaCha20Poly1305>,
    rx_buf: Vec<u8>,
    rx_pending_len: Option<usize>,
    rx_nonce: u64,
    poisoned: Option<OutboundCipherError>,
}

/// 单个 chunk 的明文长度上限（SIP004：len 字段合法域 `1..=0x3FFF`）。
const MAX_CHUNK_PLAINTEXT: usize = 0x3FFF;
/// 单个 chunk 的 len 段线长：2B 明文 + 16B tag。
const LEN_CHUNK_WIRE: usize = 2 + 16;
/// AEAD tag 长度。
const TAG_LEN: usize = 16;

/// SIP004 口令 → master key：`EVP_BytesToKey`（MD5、无 salt、1 次迭代）。
fn evp_bytes_to_key(password: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut prev: Vec<u8> = Vec::new();
    let mut filled = 0usize;
    while filled < out.len() {
        let mut input = Vec::with_capacity(prev.len() + password.len());
        input.extend_from_slice(&prev);
        input.extend_from_slice(password);
        let digest = md5::compute(&input).0;
        let take = (out.len() - filled).min(digest.len());
        out[filled..filled + take].copy_from_slice(&digest[..take]);
        filled += take;
        prev = digest.to_vec();
    }
    out
}

/// master key → 方向 subkey：HKDF-SHA1（salt = 本方向 32B salt，info = `"ss-subkey"`）。
fn derive_subkey(master: &[u8; 32], salt: &[u8; 32]) -> Result<[u8; 32], OutboundCipherError> {
    let hk = Hkdf::<sha1::Sha1>::new(Some(salt), master);
    let mut out = [0u8; 32];
    hk.expand(b"ss-subkey", &mut out)
        .map_err(|_| OutboundCipherError::KeyDerivation)?;
    Ok(out)
}

/// 12B 小端计数器 nonce（低 8 字节承载计数器，其余清零；不上线）。
fn nonce_bytes(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

impl SsStream {
    /// 构造会话：只做口令 → master key 派生，不生成 salt、不消耗随机源。
    ///
    /// `role` 保留在签名中以兼容既有调用点；SIP004 双向完全对称，
    /// 实现不再用它影响密钥派生。
    ///
    /// # Errors
    ///
    /// 派生失败返回 `KeyDerivation`（数学上不可达）。
    pub fn new(password: &str, method: SsMethod, role: Role) -> Result<Self, OutboundCipherError> {
        let _ = method;
        Ok(Self {
            master_key: evp_bytes_to_key(password.as_bytes()),
            _role: role,
            tx: None,
            tx_salt: None,
            tx_nonce: 0,
            rx: None,
            rx_buf: Vec::new(),
            rx_pending_len: None,
            rx_nonce: 0,
            poisoned: None,
        })
    }

    /// 构造会话并把发送 salt 固定为 `tx_salt`（**仅供确定性测试/金样**）。
    ///
    /// 生产代码禁止调用（review grep：调用点只在测试内）；生产路径用 [`SsStream::new`]
    /// 让发送 salt 由 `ring::rand::SystemRandom` 惰性生成。
    ///
    /// # Errors
    ///
    /// 同 [`SsStream::new`]。
    pub fn with_tx_salt(
        password: &str,
        method: SsMethod,
        role: Role,
        tx_salt: [u8; 32],
    ) -> Result<Self, OutboundCipherError> {
        let mut stream = Self::new(password, method, role)?;
        stream.tx_salt = Some(tx_salt);
        Ok(stream)
    }

    fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        let nonce = nonce_bytes(self.tx_nonce);
        self.tx_nonce = self.tx_nonce.wrapping_add(1);
        self.tx
            .as_ref()
            .expect("tx cipher initialized before encrypt_chunk")
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| OutboundCipherError::DecryptFailed)
    }

    /// 加密一段明文，返回对应的线字节增量。
    ///
    /// 首次非空调用会在输出前写入本端 32B salt（之后永不重复）；明文按
    /// `0x3FFF` 切 chunk，空输入返回空 `Vec` 且不触发 salt 发射。
    ///
    /// # Errors
    ///
    /// 随机源失败返回 `KeyDerivation`；AEAD 加密失败返回 `DecryptFailed`。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(
            plaintext.len()
                + 2 * LEN_CHUNK_WIRE
                + plaintext.len().div_ceil(MAX_CHUNK_PLAINTEXT) * TAG_LEN,
        );
        if self.tx.is_none() {
            let salt = match self.tx_salt {
                Some(salt) => salt,
                None => {
                    use ring::rand::SecureRandom;
                    let mut salt = [0u8; 32];
                    ring::rand::SystemRandom::new()
                        .fill(&mut salt)
                        .map_err(|_| OutboundCipherError::KeyDerivation)?;
                    salt
                }
            };
            let subkey = derive_subkey(&self.master_key, &salt)?;
            self.tx = Some(ChaCha20Poly1305::new(Key::from_slice(&subkey)));
            self.tx_nonce = 0;
            out.extend_from_slice(&salt);
        }
        for chunk in plaintext.chunks(MAX_CHUNK_PLAINTEXT) {
            let len = u16::try_from(chunk.len()).expect("chunk <= 0x3FFF fits u16");
            out.extend_from_slice(&self.encrypt_chunk(&len.to_be_bytes())?);
            out.extend_from_slice(&self.encrypt_chunk(chunk)?);
        }
        Ok(out)
    }

    /// 追加线字节并返回当前可解出的全部明文（流式，可为空）。
    ///
    /// salt 未满 32B、len chunk 未收齐、payload chunk 未收齐时都不产出明文。
    /// 任一错误后流进入 poisoned 状态，后续调用返回同一错误变体（不重同步）。
    ///
    /// # Errors
    ///
    /// AEAD 校验失败返回 `DecryptFailed`；解出的 len 为 `0` 或 `> 0x3FFF`
    /// 返回 `InvalidFrame`；派生失败返回 `KeyDerivation`。
    pub fn open(&mut self, data: &[u8]) -> Result<Vec<u8>, OutboundCipherError> {
        if let Some(err) = &self.poisoned {
            return Err(err.clone());
        }
        self.rx_buf.extend_from_slice(data);
        let mut out = Vec::new();

        if self.rx.is_none() {
            if self.rx_buf.len() < 32 {
                return Ok(out);
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&self.rx_buf[..32]);
            match derive_subkey(&self.master_key, &salt) {
                Ok(subkey) => {
                    self.rx = Some(ChaCha20Poly1305::new(Key::from_slice(&subkey)));
                    self.rx_nonce = 0;
                }
                Err(err) => {
                    self.poisoned = Some(err.clone());
                    return Err(err);
                }
            }
            self.rx_buf.drain(..32);
        }

        loop {
            if self.rx_pending_len.is_none() {
                if self.rx_buf.len() < LEN_CHUNK_WIRE {
                    break;
                }
                let mut ct = [0u8; LEN_CHUNK_WIRE];
                ct.copy_from_slice(&self.rx_buf[..LEN_CHUNK_WIRE]);
                let nonce = nonce_bytes(self.rx_nonce);
                let plain_len = match self
                    .rx
                    .as_ref()
                    .expect("rx cipher initialized above")
                    .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                {
                    Ok(plain) => plain,
                    Err(_) => return Err(self.poison(OutboundCipherError::DecryptFailed)),
                };
                self.rx_nonce = self.rx_nonce.wrapping_add(1);
                self.rx_buf.drain(..LEN_CHUNK_WIRE);
                if plain_len.len() != 2 {
                    return Err(self.poison(OutboundCipherError::InvalidFrame));
                }
                let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
                if len == 0 || len > MAX_CHUNK_PLAINTEXT {
                    return Err(self.poison(OutboundCipherError::InvalidFrame));
                }
                self.rx_pending_len = Some(len);
            }

            let len = self.rx_pending_len.expect("pending len set above");
            let wire = len + TAG_LEN;
            if self.rx_buf.len() < wire {
                break;
            }
            let mut ct = vec![0u8; wire];
            ct.copy_from_slice(&self.rx_buf[..wire]);
            let nonce = nonce_bytes(self.rx_nonce);
            let plain = match self
                .rx
                .as_ref()
                .expect("rx cipher initialized above")
                .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
            {
                Ok(plain) => plain,
                Err(_) => return Err(self.poison(OutboundCipherError::DecryptFailed)),
            };
            self.rx_nonce = self.rx_nonce.wrapping_add(1);
            self.rx_buf.drain(..wire);
            self.rx_pending_len = None;
            out.extend_from_slice(&plain);
        }
        Ok(out)
    }

    fn poison(&mut self, err: OutboundCipherError) -> OutboundCipherError {
        self.poisoned = Some(err.clone());
        err
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

    // ---- KAT-1 / KAT-2：独立向量（Python hashlib/hmac + cryptography 生成） ----

    /// KAT-1：EVP_BytesToKey（MD5、无 salt、1 迭代），期望值来自
    /// `tests/kat/generate_kat.py`（Python hashlib 手算 MD5 链；ASCII 向量另经
    /// `openssl dgst -md5` 交叉核对）。
    #[test]
    fn kat1_evp_bytes_to_key() {
        let vectors: [(&str, &str); 3] = [
            (
                "password",
                "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08",
            ),
            (
                "pässwörd-密码",
                "fd0dc7425473fe807455ba8a82344b98186ec57b1c431ad997ef90eae98f74bc",
            ),
            (
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "fe3a1ff59f3b89b2ad3d33f08984874bf3101797f67e6effc9b7946fbd3b8847",
            ),
        ];
        for (password, expected) in vectors {
            assert_eq!(
                hex(&evp_bytes_to_key(password.as_bytes())),
                expected,
                "{password}"
            );
        }
    }

    /// KAT-2：HKDF-SHA1 subkey（master = KAT-1#1，salt = 32×0x00，
    /// info = `"ss-subkey"`），期望值来自生成器内 RFC 5869 A.4 自检后的
    /// 独立实现（cryptography HKDF 与手写 HMAC 双方一致）。
    #[test]
    fn kat2_hkdf_sha1_subkey() {
        let master = evp_bytes_to_key(b"password");
        let subkey = derive_subkey(&master, &[0u8; 32]).unwrap();
        assert_eq!(
            hex(&subkey),
            "8c945d161c1cb5a06f884ba84d32352eecc2367284af3b975f921a67b804b69e"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- chunk 边界（spec §1.2 / §2.2 补充项） ----

    #[test]
    fn seal_empty_plaintext_is_empty_and_emits_no_salt() {
        let mut s = SsStream::with_tx_salt(
            "pw",
            SsMethod::Chacha20IetfPoly1305,
            Role::Client,
            [7u8; 32],
        )
        .unwrap();
        assert!(s.seal(&[]).unwrap().is_empty());
        // salt 仍未被发射：首个非空 seal 才带头。
        let wire = s.seal(&[0u8]).unwrap();
        assert_eq!(&wire[..32], &[7u8; 32]);
        assert_eq!(wire.len(), 67);
    }

    #[test]
    fn seal_one_byte_first_is_67_then_35() {
        let mut s = SsStream::with_tx_salt(
            "pw",
            SsMethod::Chacha20IetfPoly1305,
            Role::Client,
            [1u8; 32],
        )
        .unwrap();
        assert_eq!(s.seal(b"x").unwrap().len(), 32 + 18 + 1 + 16);
        assert_eq!(s.seal(b"y").unwrap().len(), 18 + 1 + 16);
    }

    #[test]
    fn seal_chunk_boundary_16383_and_16384() {
        let mut a = SsStream::with_tx_salt(
            "pw",
            SsMethod::Chacha20IetfPoly1305,
            Role::Client,
            [2u8; 32],
        )
        .unwrap();
        assert_eq!(a.seal(&vec![0u8; 16383]).unwrap().len(), 16449);

        let mut b = SsStream::with_tx_salt(
            "pw",
            SsMethod::Chacha20IetfPoly1305,
            Role::Client,
            [3u8; 32],
        )
        .unwrap();
        // 16384B = 16383B chunk + 1B chunk：16449 + (18 + 1 + 16)。
        assert_eq!(b.seal(&vec![0u8; 16384]).unwrap().len(), 16449 + 35);
    }

    #[test]
    fn seal_does_not_repeat_salt_across_chunks() {
        let mut s = SsStream::with_tx_salt(
            "pw",
            SsMethod::Chacha20IetfPoly1305,
            Role::Client,
            [4u8; 32],
        )
        .unwrap();
        let wire = s.seal(&vec![0u8; 0x3FFF + 1]).unwrap();
        assert_eq!(&wire[..32], &[4u8; 32]);
        let second = s.seal(&[9u8]).unwrap();
        assert_eq!(second.len(), 18 + 1 + 16);
        assert_ne!(&second[..32.min(second.len())], &[4u8; 32]);
    }

    /// 唯一允许的随机断言：两次 `new` + 同明文 seal 的 TX 首 32B（salt）不同。
    #[test]
    fn two_new_instances_use_distinct_tx_salts() {
        let mut a = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Client).unwrap();
        let mut b = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Client).unwrap();
        let wa = a.seal(b"same").unwrap();
        let wb = b.seal(b"same").unwrap();
        assert_ne!(&wa[..32], &wb[..32]);
    }

    #[test]
    fn open_partial_salt_returns_empty() {
        let wire = SsStream::with_tx_salt(
            "pw",
            SsMethod::Chacha20IetfPoly1305,
            Role::Client,
            [5u8; 32],
        )
        .unwrap()
        .seal(b"hello")
        .unwrap();
        let mut rx = SsStream::new("pw", SsMethod::Chacha20IetfPoly1305, Role::Server).unwrap();
        assert!(rx.open(&wire[..31]).unwrap().is_empty());
        assert_eq!(rx.open(&wire[31..]).unwrap(), b"hello");
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
