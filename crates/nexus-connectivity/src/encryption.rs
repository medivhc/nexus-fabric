//! 链路加密（WireGuard 风格）：节点长期 X25519 密钥对 -> 握手派生会话密钥 ->
//! ChaCha20Poly1305 AEAD 数据帧 -> 滑动窗口防重放。
//!
//! 本模块保持 portable、零真实网络：所有"传输"都是内存字节切片交换。
//! 真实线上建连、握手重传与密钥周期轮换留 TODO（见 PRODUCT.md §6 链路加密）。
//!
//! 加密基元统一使用 `ring 0.17`（已在 workspace 依赖树中）：
//! - X25519 ECDH：`ring::agreement::{X25519, EphemeralPrivateKey, agree_ephemeral}`；
//! - KDF：`ring::hkdf::HKDF_SHA256`；
//! - AEAD：`ring::aead::{CHACHA20_POLY1305, LessSafeKey, Nonce}`。
//!
//! 帧布局（wire）：
//!
//! ```text
//! [0]     version  (u8, 当前 = 1)
//! [1]     type     (u8: 1=handshake_init, 2=handshake_resp, 3=data)
//! [2..10] seq      (u64 大端；仅 data 帧使用)
//! [10..22] nonce   (12 字节，由 seq 派生，显式传输)
//! [22..N-16] ciphertext
//! [N-16..] tag     (16 字节 Poly1305)
//! ```
//!
//! 安全不变量：
//! - 握手成功前不允许发送任何业务帧；
//! - 会话密钥每次握手重新派生，不复用长期私钥；
//! - 帧头（version|type|seq|nonce，共 22 字节）作为 AEAD AAD 一并认证，
//!   攻击者篡改 seq/version/type 都会导致 tag 校验失败；
//! - 双向独立子密钥：initiator 与 responder 各自的发送/接收密钥不同，
//!   避免双向同 seq 时 nonce 复用；
//! - 接收方先校验 AEAD tag，再做防重放；tag 失败整帧丢弃（不暴露明文）。

#![forbid(unsafe_code)]

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::hkdf;
use ring::rand::SystemRandom;

/// 当前 wire 版本字节。
pub const WIRE_VERSION: u8 = 1;
/// 帧类型：握手发起（initiator -> responder，携带 initiator 公钥）。
pub const HANDSHAKE_INIT: u8 = 1;
/// 帧类型：握手响应（responder -> initiator，携带 responder 公钥）。
pub const HANDSHAKE_RESP: u8 = 2;
/// 帧类型：业务数据帧。
pub const FRAME_DATA: u8 = 3;

/// 公钥长度（X25519）。
pub const PUBLIC_KEY_LEN: usize = 32;
/// AEAD nonce 长度（96 bit）。
pub const NONCE_LEN: usize = 12;
/// AEAD tag 长度（Poly1305）。
pub const TAG_LEN: usize = 16;
/// 会话密钥长度（HKDF 输出）。
pub const SESSION_KEY_LEN: usize = 32;
/// 数据帧定长头长度：version(1) + type(1) + seq(8) + nonce(12)。
pub const FRAME_HEADER_LEN: usize = 1 + 1 + 8 + NONCE_LEN;
/// 防重放窗口宽度（帧数）。
pub const REPLAY_WINDOW: u64 = 1024;

// ---------------------------------------------------------------------------
// 错误类型
// ---------------------------------------------------------------------------

/// 链路加密面的结构化错误（typed Result，禁止 panic 表示业务失败）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionError {
    /// 密钥材料无效（长度/算法不匹配）。
    InvalidKey,
    /// 密文 tag 校验失败或 open 失败（含帧头被篡改）。
    DecryptionFailed,
    /// 防重放窗口拒绝：序号重复或过旧。
    ReplayRejected {
        /// 被拒绝的序号。
        seq: u64,
    },
    /// 握手失败（密钥交换 / KDF 失败）。
    HandshakeFailed,
    /// 帧字节长度不足。
    FrameTooShort,
    /// 不支持的 wire 版本。
    UnsupportedVersion,
    /// 帧类型与操作不匹配（如把握手帧当数据帧解密）。
    UnexpectedFrameType {
        /// 实际帧类型字节。
        actual: u8,
    },
}

impl core::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid key material"),
            Self::DecryptionFailed => {
                write!(f, "decryption failed (tag mismatch or corrupt frame)")
            }
            Self::ReplayRejected { seq } => {
                write!(f, "replay rejected: seq={seq} duplicate or too old")
            }
            Self::HandshakeFailed => write!(f, "key handshake failed"),
            Self::FrameTooShort => write!(f, "frame too short"),
            Self::UnsupportedVersion => write!(f, "unsupported wire version"),
            Self::UnexpectedFrameType { actual } => {
                write!(f, "unexpected frame type: {actual}")
            }
        }
    }
}

impl std::error::Error for EncryptionError {}

// ---------------------------------------------------------------------------
// 密钥对
// ---------------------------------------------------------------------------

/// 节点长期 X25519 密钥对。
///
/// 私钥材料保存在 `ring::agreement::EphemeralPrivateKey` 内部，不对外暴露字节
/// （ring 0.17 不公开私钥序列化）；公钥可安全导出，用于握手交换。
///
/// 注意：握手会消费私钥（`agree_ephemeral` move 语义），因此一个 `KeyPair`
/// 只能参与一次握手；长期身份持久化 / 私钥序列化留 TODO。
pub struct KeyPair {
    private: EphemeralPrivateKey,
    public: [u8; PUBLIC_KEY_LEN],
}

impl KeyPair {
    /// 使用系统 CSPRNG 生成新的 X25519 密钥对。
    pub fn generate() -> Result<Self, EncryptionError> {
        let rng = SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| EncryptionError::HandshakeFailed)?;
        let public = private
            .compute_public_key()
            .map_err(|_| EncryptionError::HandshakeFailed)?;
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        let raw = public.as_ref();
        if raw.len() != PUBLIC_KEY_LEN {
            return Err(EncryptionError::InvalidKey);
        }
        bytes.copy_from_slice(raw);
        Ok(Self {
            private,
            public: bytes,
        })
    }

    /// 公钥字节（X25519 编码，32 字节），可安全发送给对端。
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

// ---------------------------------------------------------------------------
// 会话密钥与方向子密钥
// ---------------------------------------------------------------------------

/// 单方向 AEAD 会话密钥（32 字节，ChaCha20Poly1305）。
///
/// 一次握手会派生两把方向子密钥：本端发送用 `tx`，本端接收用 `rx`。
/// 两端的 `tx` 与对端的 `rx` 是同一把密钥，从而避免双向同序号时 nonce 复用。
pub struct SessionKey {
    key: LessSafeKey,
    bytes: [u8; SESSION_KEY_LEN],
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKey")
            .field("algorithm", &"ChaCha20Poly1305")
            .field("material_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl SessionKey {
    /// 从 32 字节原始材料构造 AEAD 会话密钥。
    pub fn from_bytes(bytes: &[u8; SESSION_KEY_LEN]) -> Result<Self, EncryptionError> {
        let unbound =
            UnboundKey::new(&CHACHA20_POLY1305, bytes).map_err(|_| EncryptionError::InvalidKey)?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            bytes: *bytes,
        })
    }

    /// 会话密钥原始材料（供测试与 E4 报告）。
    #[must_use]
    pub fn material(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.bytes
    }
}

/// 一次握手派生的双向会话密钥对：
/// - `tx`：本端发送帧使用；
/// - `rx`：本端接收帧使用。
///
/// initiator 的 `tx` 与 responder 的 `rx` 相同，responder 的 `tx` 与 initiator
/// 的 `rx` 相同。
#[derive(Debug)]
pub struct DirectionalKeys {
    /// 本端发送子密钥。
    pub tx: SessionKey,
    /// 本端接收子密钥。
    pub rx: SessionKey,
}

impl DirectionalKeys {
    /// 从握手 base 材料按角色切出方向子密钥。
    fn split(base: &[u8; SESSION_KEY_LEN], initiator: bool) -> Result<Self, EncryptionError> {
        const INIT_TX_INFO: &[u8] = b"nexus-link:enc:tx-initiator";
        const RESP_TX_INFO: &[u8] = b"nexus-link:enc:tx-responder";
        let (tx_info, rx_info) = if initiator {
            (INIT_TX_INFO, RESP_TX_INFO)
        } else {
            (RESP_TX_INFO, INIT_TX_INFO)
        };
        let tx = hkdf_expand_key(base, tx_info)?;
        let rx = hkdf_expand_key(base, rx_info)?;
        Ok(Self { tx, rx })
    }
}

/// 用 HKDF-Expand 从 base 材料派生一把方向子密钥。
fn hkdf_expand_key(
    base: &[u8; SESSION_KEY_LEN],
    info: &[u8],
) -> Result<SessionKey, EncryptionError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"nexus-link-directional-v1").extract(base);
    let info_arr = [info];
    let okm = prk
        .expand(&info_arr, hkdf::HKDF_SHA256)
        .map_err(|_| EncryptionError::HandshakeFailed)?;
    let mut out = [0u8; SESSION_KEY_LEN];
    okm.fill(&mut out)
        .map_err(|_| EncryptionError::HandshakeFailed)?;
    SessionKey::from_bytes(&out)
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

/// 握手消息：自包含固定字节布局（type + 32 字节对端公钥）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    /// 消息类型：`HANDSHAKE_INIT` 或 `HANDSHAKE_RESP`。
    pub msg_type: u8,
    /// 发送方公钥。
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

impl HandshakeMessage {
    const WIRE_LEN: usize = 1 /* type */ + PUBLIC_KEY_LEN;

    /// 序列化为固定字节布局（不带 version 前缀，由承载层自行分帧）。
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.push(self.msg_type);
        out.extend_from_slice(&self.public_key);
        out
    }

    /// 从固定字节布局解析。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() != Self::WIRE_LEN {
            return Err(EncryptionError::FrameTooShort);
        }
        let msg_type = bytes[0];
        if msg_type != HANDSHAKE_INIT && msg_type != HANDSHAKE_RESP {
            return Err(EncryptionError::UnexpectedFrameType { actual: msg_type });
        }
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&bytes[1..1 + PUBLIC_KEY_LEN]);
        Ok(Self {
            msg_type,
            public_key,
        })
    }
}

/// 从 X25519 ECDH 共享密钥 + 双方公钥派生握手 base 材料（32 字节）。
///
/// HKDF info 按字典序拼接两个公钥，与谁先发起无关，保证两端 base 一致。
fn derive_base(
    local_private: EphemeralPrivateKey,
    local_pub: &[u8; PUBLIC_KEY_LEN],
    remote_pub: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; SESSION_KEY_LEN], EncryptionError> {
    let peer = UnparsedPublicKey::new(&X25519, remote_pub.as_slice());
    let shared = agree_ephemeral(local_private, &peer, |secret| secret.to_vec())
        .map_err(|_| EncryptionError::HandshakeFailed)?;

    let mut ordered = [local_pub.as_slice(), remote_pub.as_slice()];
    ordered.sort();

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"nexus-link-encryption-v1");
    let prk = salt.extract(&shared);
    let okm = prk
        .expand(&ordered, hkdf::HKDF_SHA256)
        .map_err(|_| EncryptionError::HandshakeFailed)?;
    let mut out = [0u8; SESSION_KEY_LEN];
    okm.fill(&mut out)
        .map_err(|_| EncryptionError::HandshakeFailed)?;
    Ok(out)
}

impl KeyPair {
    /// 发起握手：消费本端私钥，产出握手消息 + 双向会话密钥（initiator 视角）。
    pub fn handshake_initiate(
        self,
        peer_public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(HandshakeMessage, DirectionalKeys), EncryptionError> {
        let base = derive_base(self.private, &self.public, peer_public)?;
        let keys = DirectionalKeys::split(&base, true)?;
        let msg = HandshakeMessage {
            msg_type: HANDSHAKE_INIT,
            public_key: self.public,
        };
        Ok((msg, keys))
    }

    /// 响应握手：消费本端私钥，产出响应消息 + 双向会话密钥（responder 视角）。
    pub fn handshake_respond(
        self,
        initiator_message: &HandshakeMessage,
    ) -> Result<(HandshakeMessage, DirectionalKeys), EncryptionError> {
        if initiator_message.msg_type != HANDSHAKE_INIT {
            return Err(EncryptionError::UnexpectedFrameType {
                actual: initiator_message.msg_type,
            });
        }
        let base = derive_base(self.private, &self.public, &initiator_message.public_key)?;
        let keys = DirectionalKeys::split(&base, false)?;
        let msg = HandshakeMessage {
            msg_type: HANDSHAKE_RESP,
            public_key: self.public,
        };
        Ok((msg, keys))
    }

    /// 分步握手（纯 ephemeral 双公钥）：本端已生成临时密钥对并发出自身公钥，
    /// 收到对端公钥后完成密钥派生。
    ///
    /// `initiator=true` 取发起方视角（本端 `tx` 与对端 `rx` 相同）；`false` 取
    /// 响应方视角。与 [`Self::handshake_respond`] 派生结果一致（同一 base +
    /// 角色切分），用于对端公钥未知、需先交换公钥的场景（§12.6 虚拟子网
    /// 加密接入）。
    pub fn derive_directional(
        self,
        peer_public: &[u8; PUBLIC_KEY_LEN],
        initiator: bool,
    ) -> Result<DirectionalKeys, EncryptionError> {
        let base = derive_base(self.private, &self.public, peer_public)?;
        DirectionalKeys::split(&base, initiator)
    }
}

// ---------------------------------------------------------------------------
// 数据帧加解密
// ---------------------------------------------------------------------------

/// 由序号派生 12 字节 nonce（前 4 字节固定为 0，后 8 字节为大端序号）。
///
/// 防重放窗口保证同方向内序号不重复，方向子密钥又隔离了两个方向，
/// 因此由序号派生 nonce 是安全的。
fn nonce_from_seq(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// 构造定长帧头（version|type|seq|nonce），同时作为 AEAD AAD 认证数据。
fn build_header(seq: u64, nonce: &[u8; NONCE_LEN]) -> [u8; FRAME_HEADER_LEN] {
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = WIRE_VERSION;
    header[1] = FRAME_DATA;
    header[2..10].copy_from_slice(&seq.to_be_bytes());
    header[10..FRAME_HEADER_LEN].copy_from_slice(nonce);
    header
}

/// 用方向子密钥加密一帧业务数据，返回完整 wire 字节。
///
/// 帧头（含 seq/nonce）作为 AAD 一并认证，篡改帧头任意字节都会导致 tag 失败。
pub fn encrypt_frame(
    key: &SessionKey,
    seq: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let nonce = nonce_from_seq(seq);
    let header = build_header(seq, &nonce);

    let mut body = plaintext.to_vec();
    key.key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header[..]),
            &mut body,
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    out.extend_from_slice(&header);
    out.extend(body);
    Ok(out)
}

/// 解密一帧业务数据：先校验 version/type/AAD+tag，成功返回 `(seq, plaintext)`。
///
/// 本函数不做防重放校验；调用方应随后调用 `ReplayWindow::check_and_accept`。
pub fn decrypt_frame(key: &SessionKey, frame: &[u8]) -> Result<(u64, Vec<u8>), EncryptionError> {
    if frame.len() < FRAME_HEADER_LEN + TAG_LEN {
        return Err(EncryptionError::FrameTooShort);
    }
    if frame[0] != WIRE_VERSION {
        return Err(EncryptionError::UnsupportedVersion);
    }
    if frame[1] != FRAME_DATA {
        return Err(EncryptionError::UnexpectedFrameType { actual: frame[1] });
    }
    let header: [u8; FRAME_HEADER_LEN] = frame[..FRAME_HEADER_LEN]
        .try_into()
        .map_err(|_| EncryptionError::FrameTooShort)?;
    let seq = u64::from_be_bytes(
        header[2..10]
            .try_into()
            .map_err(|_| EncryptionError::FrameTooShort)?,
    );
    let nonce: [u8; NONCE_LEN] = header[10..FRAME_HEADER_LEN]
        .try_into()
        .map_err(|_| EncryptionError::FrameTooShort)?;

    let mut buf = frame[FRAME_HEADER_LEN..].to_vec();
    let plain = key
        .key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header[..]),
            &mut buf,
        )
        .map_err(|_| EncryptionError::DecryptionFailed)?;
    Ok((seq, plain.to_vec()))
}

// ---------------------------------------------------------------------------
// 防重放
// ---------------------------------------------------------------------------

/// 滑动窗口防重放位图（宽度 `REPLAY_WINDOW = 1024`）。
///
/// 窗口覆盖 `(max_accepted - REPLAY_WINDOW + 1) ..= max_accepted`：
/// - 序号 > max_accepted：推进窗口并接受；
/// - 序号过旧（窗口外）：拒绝；
/// - 窗口内已置位：重复帧，拒绝；
/// - 窗口内未置位：置位并接受。
#[derive(Debug)]
pub struct ReplayWindow {
    max_accepted: u64,
    has_accepted: bool,
    bits: [u64; Self::WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    const WORDS: usize = (REPLAY_WINDOW as usize) / 64;

    /// 空窗口（尚未接受任何帧）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_accepted: 0,
            has_accepted: false,
            bits: [0u64; Self::WORDS],
        }
    }

    fn bit_index(diff: u64) -> (usize, u64) {
        ((diff / 64) as usize, 1u64 << (diff % 64))
    }

    /// 校验并接受一个序号；重复或过旧返回 `ReplayRejected`。
    pub fn check_and_accept(&mut self, seq: u64) -> Result<(), EncryptionError> {
        if !self.has_accepted {
            self.max_accepted = seq;
            self.bits = [0u64; Self::WORDS];
            let (word, mask) = Self::bit_index(0);
            self.bits[word] |= mask;
            self.has_accepted = true;
            return Ok(());
        }

        if seq > self.max_accepted {
            let jump = seq - self.max_accepted;
            self.shift_left(jump);
            self.max_accepted = seq;
            let (word, mask) = Self::bit_index(0);
            self.bits[word] |= mask;
            return Ok(());
        }

        let diff = self.max_accepted - seq;
        if diff >= REPLAY_WINDOW {
            return Err(EncryptionError::ReplayRejected { seq });
        }
        let (word, mask) = Self::bit_index(diff);
        if self.bits[word] & mask != 0 {
            return Err(EncryptionError::ReplayRejected { seq });
        }
        self.bits[word] |= mask;
        Ok(())
    }

    /// 把位图整体逻辑左移 `jump` 位（低位补 0）：max 推进 jump 后，
    /// 每帧与新 max 的距离都增加 jump，故其位图位置向高位移动。
    fn shift_left(&mut self, jump: u64) {
        if jump >= REPLAY_WINDOW {
            self.bits = [0u64; Self::WORDS];
            return;
        }
        let word_shift = (jump / 64) as usize;
        let bit_shift = (jump % 64) as u32;
        let mut out = [0u64; Self::WORDS];
        for (i, slot) in out.iter_mut().enumerate() {
            let lo = if i >= word_shift {
                self.bits[i - word_shift]
            } else {
                0
            };
            let hi = if word_shift < i {
                self.bits[i - word_shift - 1]
            } else {
                0
            };
            *slot = if bit_shift == 0 {
                lo
            } else {
                (lo << bit_shift) | (hi >> (64 - bit_shift))
            };
        }
        self.bits = out;
    }
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 链路加密算法标识（P0 仅 ChaCha20Poly1305，预留扩展）。
///
/// 保留 `pub`：本类型是连接建立时的配置语义组成部分，后续接入 Aes256Gcm
/// 等算法时无需破坏公共 API；当前生产路径未消费它，仅作为配置面占位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305（IETF），P0 唯一支持。
    ChaCha20Poly1305,
}

/// 链路加密配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionConfig {
    /// 数据帧 AEAD 算法。
    pub algorithm: AeadAlgorithm,
    /// 发送多少帧后应轮换会话密钥（P0 仅记录阈值，轮换逻辑 TODO）。
    pub key_rotation_after_frames: u64,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            algorithm: AeadAlgorithm::ChaCha20Poly1305,
            key_rotation_after_frames: 1_048_576,
        }
    }
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stepped_handshake_matches_one_step() -> Result<(), EncryptionError> {
        // 纯 ephemeral 分步握手（先交换公钥再派生）与既有一步握手派生一致。
        let a = KeyPair::generate()?;
        let b = KeyPair::generate()?;
        // a 的 INIT 消息 = 自身公钥（不经 initiate，避免消费 a）。
        let init_msg = HandshakeMessage {
            msg_type: HANDSHAKE_INIT,
            public_key: *a.public_key_bytes(),
        };
        let (resp_msg, kb) = b.handshake_respond(&init_msg)?;
        // 分步：a 用 resp_msg 里的 b 公钥 + initiator 视角派生。
        let ka = a.derive_directional(&resp_msg.public_key, true)?;

        assert_eq!(ka.tx.material(), kb.rx.material());
        assert_eq!(ka.rx.material(), kb.tx.material());
        // 分步与一步走同一 base/切分逻辑：用 ka 发帧，kb 必须能解。
        let frame = encrypt_frame(&ka.tx, 5, b"stepped")?;
        let (seq, plain) = decrypt_frame(&kb.rx, &frame)?;
        assert_eq!(seq, 5);
        assert_eq!(&plain, b"stepped");
        // 篡改后的帧用对端 rx 解不开（密钥正确性由 roundtrip 覆盖）。
        Ok(())
    }

    #[test]
    fn roundtrip_encrypt_decrypt() -> Result<(), EncryptionError> {
        let a = KeyPair::generate()?;
        let b = KeyPair::generate()?;
        let (msg, ka) = a.handshake_initiate(b.public_key_bytes())?;
        let (_, kb) = b.handshake_respond(&msg)?;

        let frame = encrypt_frame(&ka.tx, 7, b"hello-nexus")?;
        let (seq, plain) = decrypt_frame(&kb.rx, &frame)?;
        assert_eq!(seq, 7);
        assert_eq!(&plain, b"hello-nexus");
        Ok(())
    }

    #[test]
    fn directional_keys_match_across_peers() -> Result<(), EncryptionError> {
        let a = KeyPair::generate()?;
        let b = KeyPair::generate()?;
        let (msg, ka) = a.handshake_initiate(b.public_key_bytes())?;
        let (_, kb) = b.handshake_respond(&msg)?;

        // initiator.tx == responder.rx；responder.tx == initiator.rx；两把不同。
        assert_eq!(ka.tx.material(), kb.rx.material());
        assert_eq!(ka.rx.material(), kb.tx.material());
        assert_ne!(ka.tx.material(), ka.rx.material());

        // A 发 seq=1，B 用 rx 解开；B 发 seq=1（同序号！），A 用 rx 解开。
        let frame_ab = encrypt_frame(&ka.tx, 1, b"a->b")?;
        let frame_ba = encrypt_frame(&kb.tx, 1, b"b->a")?;
        let (_, pa) = decrypt_frame(&kb.rx, &frame_ab)?;
        let (_, pb) = decrypt_frame(&ka.rx, &frame_ba)?;
        assert_eq!(&pa, b"a->b");
        assert_eq!(&pb, b"b->a");

        // 方向错了也解不开：用 A.rx 解 A 自己发的帧必须失败。
        assert!(matches!(
            decrypt_frame(&ka.rx, &frame_ab),
            Err(EncryptionError::DecryptionFailed)
        ));
        Ok(())
    }

    #[test]
    fn wrong_key_fails_decryption() -> Result<(), EncryptionError> {
        let a = KeyPair::generate()?;
        let b = KeyPair::generate()?;
        let (msg_ab, ka) = a.handshake_initiate(b.public_key_bytes())?;
        let (_, kb) = b.handshake_respond(&msg_ab)?;
        let frame = encrypt_frame(&ka.tx, 1, b"secret")?;

        let d = KeyPair::generate()?;
        let c = KeyPair::generate()?;
        let (msg_dc, kd) = d.handshake_initiate(c.public_key_bytes())?;
        let (_, kc) = c.handshake_respond(&msg_dc)?;
        assert!(matches!(
            decrypt_frame(&kc.rx, &frame),
            Err(EncryptionError::DecryptionFailed)
        ));
        assert!(matches!(
            decrypt_frame(&kd.tx, &frame),
            Err(EncryptionError::DecryptionFailed)
        ));

        let (seq, plain) = decrypt_frame(&kb.rx, &frame)?;
        assert_eq!(seq, 1);
        assert_eq!(&plain, b"secret");
        Ok(())
    }

    #[test]
    fn frame_header_tamper_rejected() -> Result<(), EncryptionError> {
        let a = KeyPair::generate()?;
        let b = KeyPair::generate()?;
        let (msg, ka) = a.handshake_initiate(b.public_key_bytes())?;
        let (_, kb) = b.handshake_respond(&msg)?;
        let mut frame = encrypt_frame(&ka.tx, 42, b"payload")?;

        // 篡改 seq 字节（frame[2..10]）：AAD 校验必须失败。
        frame[5] ^= 0xFF;
        assert!(matches!(
            decrypt_frame(&kb.rx, &frame),
            Err(EncryptionError::DecryptionFailed)
        ));

        // 改回 seq，再篡改 version 字节：仍必须失败。
        frame[5] ^= 0xFF;
        frame[0] = 2;
        assert!(matches!(
            decrypt_frame(&kb.rx, &frame),
            Err(EncryptionError::UnsupportedVersion)
        ));

        // 原始帧可正常解密。
        frame[0] = 1;
        let (seq, plain) = decrypt_frame(&kb.rx, &frame)?;
        assert_eq!(seq, 42);
        assert_eq!(&plain, b"payload");
        Ok(())
    }

    #[test]
    fn distinct_keypairs_distinct_sessions() -> Result<(), EncryptionError> {
        let a1 = KeyPair::generate()?;
        let b1 = KeyPair::generate()?;
        let (msg1, k1) = a1.handshake_initiate(b1.public_key_bytes())?;
        let (_, _r1) = b1.handshake_respond(&msg1)?;

        let a2 = KeyPair::generate()?;
        let b2 = KeyPair::generate()?;
        let (msg2, k2) = a2.handshake_initiate(b2.public_key_bytes())?;
        let (_, _r2) = b2.handshake_respond(&msg2)?;

        let frame = encrypt_frame(&k1.tx, 3, b"x")?;
        assert!(matches!(
            decrypt_frame(&k2.rx, &frame),
            Err(EncryptionError::DecryptionFailed)
        ));
        Ok(())
    }

    #[test]
    fn replay_window_rejects_duplicate_and_old() -> Result<(), EncryptionError> {
        let mut w = ReplayWindow::new();
        w.check_and_accept(100)?;
        w.check_and_accept(101)?;
        // 重复
        assert!(matches!(
            w.check_and_accept(100),
            Err(EncryptionError::ReplayRejected { seq: 100 })
        ));
        // 窗口大幅推进后，旧序号滑出窗口 -> 过旧拒绝
        w.check_and_accept(10_000)?;
        assert!(matches!(
            w.check_and_accept(101),
            Err(EncryptionError::ReplayRejected { seq: 101 })
        ));
        w.check_and_accept(10_001)?;
        Ok(())
    }

    #[test]
    fn replay_window_jump_across_whole_window() -> Result<(), EncryptionError> {
        let mut w = ReplayWindow::new();
        w.check_and_accept(10)?;
        w.check_and_accept(20)?;
        // 跨整窗推进（jump >= REPLAY_WINDOW），旧历史全部清零。
        w.check_and_accept(10 + REPLAY_WINDOW)?;
        // 旧帧 10 / 20 都已滑出。
        assert!(matches!(
            w.check_and_accept(10),
            Err(EncryptionError::ReplayRejected { seq: 10 })
        ));
        assert!(matches!(
            w.check_and_accept(20),
            Err(EncryptionError::ReplayRejected { seq: 20 })
        ));
        Ok(())
    }

    #[test]
    fn replay_window_out_of_order_within_window() -> Result<(), EncryptionError> {
        let mut w = ReplayWindow::new();
        w.check_and_accept(1_000)?;
        // 窗口内乱序到达：998 < 1000，未置位，应接受。
        w.check_and_accept(998)?;
        w.check_and_accept(999)?;
        // 重复乱序帧拒绝。
        assert!(matches!(
            w.check_and_accept(998),
            Err(EncryptionError::ReplayRejected { seq: 998 })
        ));
        // 后续新序号正常。
        w.check_and_accept(1_001)?;
        Ok(())
    }

    #[test]
    fn replay_window_near_u64_max() -> Result<(), EncryptionError> {
        let mut w = ReplayWindow::new();
        w.check_and_accept(u64::MAX - 5)?;
        w.check_and_accept(u64::MAX)?;
        assert!(matches!(
            w.check_and_accept(u64::MAX - 5),
            Err(EncryptionError::ReplayRejected { seq }) if seq == u64::MAX - 5
        ));
        // 紧邻的新序号接受。
        w.check_and_accept(u64::MAX - 4)?;
        Ok(())
    }

    #[test]
    fn handshake_message_roundtrip() -> Result<(), EncryptionError> {
        let msg = HandshakeMessage {
            msg_type: HANDSHAKE_INIT,
            public_key: [7u8; 32],
        };
        let bytes = msg.to_bytes();
        let parsed = HandshakeMessage::from_bytes(&bytes)?;
        assert_eq!(parsed, msg);
        assert!(HandshakeMessage::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        Ok(())
    }

    #[test]
    fn frame_too_short_and_bad_version() -> Result<(), EncryptionError> {
        let a = KeyPair::generate()?;
        let b = KeyPair::generate()?;
        let (msg, ka) = a.handshake_initiate(b.public_key_bytes())?;
        let (_, kb) = b.handshake_respond(&msg)?;
        let frame = encrypt_frame(&ka.tx, 1, b"x")?;

        assert!(matches!(
            decrypt_frame(&kb.rx, &frame[..5]),
            Err(EncryptionError::FrameTooShort)
        ));
        let mut bad = frame.clone();
        bad[0] = 9;
        assert!(matches!(
            decrypt_frame(&kb.rx, &bad),
            Err(EncryptionError::UnsupportedVersion)
        ));
        Ok(())
    }
}
