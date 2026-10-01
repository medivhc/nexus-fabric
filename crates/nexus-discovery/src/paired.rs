//! 设备配对（D7）：带外配对码 + ed25519 签名认证。
//!
//! 配对 ≠ 建连（配对只建信任，不建立 Connectivity）；
//! Identity（ed25519 公钥）≠ Locator（地址）；
//! 配对是一次性仪式，发现是持续查询。
//!
//! 协议（见 `.agents/plans/pairing-plan.md`）：
//! 1. A 生成配对码（`nexus-pair:v1:<pubkey>:<token>`），带外给 B
//! 2. B 解析码，连接 A，发送 `PairRequest { peer_id_B, token, name }`
//! 3. A 验证 token，发送 `PairAccept { peer_id_A, name, sig(token||peer_id_B) }`
//! 4. B 验证签名，双方保存对方信息到 `peers/`
//!
//! 本模块零 I/O（`#![forbid(unsafe_code)]`）；网络传输由组合根注入。

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use super::{Discovery, PeerId};

// ---------- 错误 ----------

/// 配对错误（结构化，不暴露内部细节给对端）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    /// 配对码格式非法（携带原因）。
    InvalidCode(String),
    /// 帧解码失败（携带原因）。
    Decode(String),
    /// 密码学操作失败（携带原因）。
    Crypto(String),
    /// token 过期或已使用。
    Expired,
    /// token 不匹配。
    TokenMismatch,
    /// 签名验证失败。
    BadSignature,
    /// I/O 错误（传输层，携带原因）。
    Io(String),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCode(r) => write!(f, "invalid pairing code: {r}"),
            Self::Decode(r) => write!(f, "pairing decode: {r}"),
            Self::Crypto(r) => write!(f, "pairing crypto: {r}"),
            Self::Expired => write!(f, "pairing token expired"),
            Self::TokenMismatch => write!(f, "pairing token mismatch"),
            Self::BadSignature => write!(f, "pairing signature invalid"),
            Self::Io(r) => write!(f, "pairing io: {r}"),
        }
    }
}

impl std::error::Error for PairingError {}

// ---------- base64url（手写，零依赖） ----------

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url 编码（无填充）。
fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL_ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL_ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// base64url 解码（无填充）；非法字符 → Err。
fn b64url_decode(s: &str) -> Result<Vec<u8>, PairingError> {
    let val = |c: u8| -> Result<u32, PairingError> {
        B64URL_ALPHABET
            .iter()
            .position(|&x| x == c)
            .map(|i| i as u32)
            .ok_or_else(|| PairingError::InvalidCode(format!("bad base64url char: {c}")))
    };
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(PairingError::InvalidCode("bad base64url length".into()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        let mut bits = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            bits += 6;
        }
        // 按实际字符数输出字节
        match chunk.len() {
            2 => out.push((n >> 4) as u8),
            3 => {
                out.push((n >> 10) as u8);
                out.push((n >> 2) as u8);
            }
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            _ => {}
        }
        let _ = bits;
    }
    Ok(out)
}

// ---------- hex（手写，零依赖） ----------

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// hex 编码（小写）。
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0xf) as usize] as char);
    }
    out
}

/// hex 解码；长度必须为偶数，字符必须为 hex。
pub fn hex_decode(s: &str) -> Result<Vec<u8>, PairingError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(PairingError::InvalidCode("odd hex length".into()));
    }
    let val = |c: u8| -> Result<u8, PairingError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(PairingError::InvalidCode(format!("bad hex char: {c}"))),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Ok(out)
}

// ---------- 配对码 ----------

/// 配对码版本前缀。
pub const PAIRING_CODE_PREFIX: &str = "nexus-pair:v1:";

/// 配对码：`nexus-pair:v1:<base64url(pubkey:32)>:<base64url(token:16)>`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCode {
    /// 邀请方 ed25519 公钥（32 字节）。
    pub peer_id: [u8; 32],
    /// 128-bit 配对 token。
    pub token: [u8; 16],
}

impl PairingCode {
    /// 生成新的配对码（token 为 128-bit 随机）。
    pub fn generate(peer_id: [u8; 32]) -> Result<Self, PairingError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut token = [0u8; 16];
        rng.fill(&mut token)
            .map_err(|e| PairingError::Crypto(format!("rng: {e:?}")))?;
        Ok(Self { peer_id, token })
    }

    /// 编码为字符串（带外传输用）。
    pub fn encode(&self) -> String {
        format!(
            "{}{}:{}",
            PAIRING_CODE_PREFIX,
            b64url_encode(&self.peer_id),
            b64url_encode(&self.token)
        )
    }

    /// 从字符串解析；格式非法 → `PairingError::InvalidCode`。
    pub fn decode(s: &str) -> Result<Self, PairingError> {
        let rest = s
            .strip_prefix(PAIRING_CODE_PREFIX)
            .ok_or_else(|| PairingError::InvalidCode("bad prefix".into()))?;
        let mut parts = rest.split(':');
        let pubkey_b64 = parts
            .next()
            .ok_or_else(|| PairingError::InvalidCode("missing pubkey".into()))?;
        let token_b64 = parts
            .next()
            .ok_or_else(|| PairingError::InvalidCode("missing token".into()))?;
        if parts.next().is_some() {
            return Err(PairingError::InvalidCode("trailing data".into()));
        }
        let pubkey = b64url_decode(pubkey_b64)?;
        let token = b64url_decode(token_b64)?;
        if pubkey.len() != 32 {
            return Err(PairingError::InvalidCode(format!(
                "bad pubkey len: {}",
                pubkey.len()
            )));
        }
        if token.len() != 16 {
            return Err(PairingError::InvalidCode(format!(
                "bad token len: {}",
                token.len()
            )));
        }
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&pubkey);
        let mut tok = [0u8; 16];
        tok.copy_from_slice(&token);
        Ok(Self {
            peer_id,
            token: tok,
        })
    }
}

// ---------- 节点身份（ed25519） ----------

/// 节点身份：ed25519 密钥对。`Drop` 时清零私钥。
pub struct NodeIdentity {
    peer_id: [u8; 32],
    seed: [u8; 32],
    keypair: ring::signature::Ed25519KeyPair,
}

impl NodeIdentity {
    /// 生成新的身份（随机密钥对）。
    pub fn generate() -> Result<Self, PairingError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|e| PairingError::Crypto(format!("rng: {e:?}")))?;
        Self::from_seed(&seed)
    }

    /// 从 seed（32 字节）恢复身份（用于从 `identity.toml` 加载）。
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, PairingError> {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| PairingError::Crypto(format!("from_seed: {e:?}")))?;
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(keypair.public_key().as_ref());
        Ok(Self {
            peer_id,
            seed: *seed,
            keypair,
        })
    }

    /// 公钥（即 PeerId）。
    pub fn peer_id(&self) -> [u8; 32] {
        self.peer_id
    }

    /// 导出 seed（32 字节，用于持久化到 `identity.toml`）。
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// 用消息签名（ed25519）。
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.keypair.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// 验证签名（静态方法，用公钥）。
    pub fn verify(peer_id: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        use ring::signature::{ED25519, UnparsedPublicKey};
        let pk = UnparsedPublicKey::new(&ED25519, peer_id);
        pk.verify(msg, sig).is_ok()
    }
}

// 手动实现 Debug（不泄露密钥）。
impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeIdentity(peer_id={})", hex_encode(&self.peer_id))
    }
}

// Drop 时清零 seed（AGENTS.md §18：敏感数据最小化）。
impl Drop for NodeIdentity {
    fn drop(&mut self) {
        for b in self.seed.iter_mut() {
            *b = 0;
        }
    }
}

// ---------- 配对帧 ----------

/// 配对帧类型标签（避开 DiscoveryFrame 1–4 和 AutoDiscoveryFrame 11–14）。
const TAG_PAIR_REQUEST: u8 = 21;
const TAG_PAIR_ACCEPT: u8 = 22;
const TAG_PAIR_REJECT: u8 = 23;

/// 配对协议帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingFrame {
    /// B → A：请求配对（携带 B 的公钥、token、显示名）。
    PairRequest {
        peer_id: [u8; 32],
        token: [u8; 16],
        name: String,
    },
    /// A → B：接受（携带 A 的公钥、显示名、对 `token||peer_id_B` 的签名）。
    PairAccept {
        peer_id: [u8; 32],
        name: String,
        signature: [u8; 64],
    },
    /// A → B：拒绝（通用原因，不泄露细节）。
    PairReject { reason: String },
}

/// 签名内容：`token || peer_id_B`（48 字节）。
pub fn pairing_sign_msg(token: &[u8; 16], peer_id_b: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(48);
    msg.extend_from_slice(token);
    msg.extend_from_slice(peer_id_b);
    msg
}

/// 编码配对帧（确定性、可移植）。
pub fn encode_pairing_frame(frame: &PairingFrame) -> Result<Vec<u8>, PairingError> {
    let mut out = Vec::new();
    match frame {
        PairingFrame::PairRequest {
            peer_id,
            token,
            name,
        } => {
            out.push(TAG_PAIR_REQUEST);
            out.extend_from_slice(peer_id);
            out.extend_from_slice(token);
            super::put_str(&mut out, name).map_err(|e| PairingError::Decode(e.to_string()))?;
        }
        PairingFrame::PairAccept {
            peer_id,
            name,
            signature,
        } => {
            out.push(TAG_PAIR_ACCEPT);
            out.extend_from_slice(peer_id);
            super::put_str(&mut out, name).map_err(|e| PairingError::Decode(e.to_string()))?;
            out.extend_from_slice(signature);
        }
        PairingFrame::PairReject { reason } => {
            out.push(TAG_PAIR_REJECT);
            super::put_str(&mut out, reason).map_err(|e| PairingError::Decode(e.to_string()))?;
        }
    }
    Ok(out)
}

/// 解码配对帧；截断/未知 tag/非法编码 → `PairingError::Decode`。
pub fn decode_pairing_frame(payload: &[u8]) -> Result<PairingFrame, PairingError> {
    let err = |m: &str| PairingError::Decode(m.into());
    let Some(&tag) = payload.first() else {
        return Err(err("empty frame"));
    };
    let mut pos = 1;

    // 内联辅助：读取 n 字节定长字段
    macro_rules! get_fixed {
        ($n:expr) => {{
            let n = $n;
            if pos + n > payload.len() {
                return Err(err("frame truncated"));
            }
            let v = payload[pos..pos + n].to_vec();
            pos += n;
            v
        }};
    }
    // 内联辅助：读取长度前缀字符串
    macro_rules! get_str {
        () => {
            super::get_str(payload, &mut pos).map_err(|e| PairingError::Decode(e.to_string()))?
        };
    }

    match tag {
        TAG_PAIR_REQUEST => {
            let peer_id = get_fixed!(32);
            let token = get_fixed!(16);
            let name = get_str!();
            if pos != payload.len() {
                return Err(err("trailing bytes"));
            }
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&peer_id);
            let mut tok = [0u8; 16];
            tok.copy_from_slice(&token);
            Ok(PairingFrame::PairRequest {
                peer_id: pid,
                token: tok,
                name,
            })
        }
        TAG_PAIR_ACCEPT => {
            let peer_id = get_fixed!(32);
            let name = get_str!();
            let sig = get_fixed!(64);
            if pos != payload.len() {
                return Err(err("trailing bytes"));
            }
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&peer_id);
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&sig);
            Ok(PairingFrame::PairAccept {
                peer_id: pid,
                name,
                signature,
            })
        }
        TAG_PAIR_REJECT => {
            let reason = get_str!();
            if pos != payload.len() {
                return Err(err("trailing bytes"));
            }
            Ok(PairingFrame::PairReject { reason })
        }
        other => Err(err(&format!("unknown tag: {other}"))),
    }
}

// ---------- 配对设备信息 ----------

/// 已配对设备的信息（存于 `peers/<hex>.toml`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedPeer {
    /// 对端 ed25519 公钥（32 字节）。
    pub peer_id: [u8; 32],
    /// 用户备注名。
    pub name: String,
    /// 最后已知地址（发现提示用）。
    pub addresses: Vec<SocketAddr>,
    /// 配对时间（unix 秒，由调用方注入，便于确定性测试）。
    pub paired_at: u64,
}

impl PairedPeer {
    /// 文件名：`<hex(pubkey)>.toml`（64 hex 字符）。
    pub fn filename(&self) -> String {
        format!("{}.toml", hex_encode(&self.peer_id))
    }
}

/// 编码为 TOML 子集（手写，零依赖）。
pub fn encode_peer_file(peer: &PairedPeer) -> String {
    let addrs = peer
        .addresses
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "# 配对设备信息。由 `nexus pair` 自动管理，请勿手动编辑。\n\
         peer_id = \"{}\"\n\
         name = \"{}\"\n\
         addresses = [{}]\n\
         paired_at = {}\n",
        hex_encode(&peer.peer_id),
        peer.name.replace('"', "\\\""),
        addrs,
        peer.paired_at
    )
}

/// 从 TOML 子集解码；格式非法 → `PairingError::Decode`。
pub fn decode_peer_file(text: &str) -> Result<PairedPeer, PairingError> {
    let err = |m: &str| PairingError::Decode(m.into());
    let mut peer_id: Option<[u8; 32]> = None;
    let mut name: Option<String> = None;
    let mut addresses: Vec<SocketAddr> = Vec::new();
    let mut paired_at: Option<u64> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        match k {
            "peer_id" => {
                let v = v.strip_prefix('"').unwrap_or(v);
                let hex = v.strip_suffix('"').unwrap_or(v);
                let bytes = hex_decode(hex).map_err(|_| err("bad peer_id hex"))?;
                if bytes.len() != 32 {
                    return Err(err("bad peer_id len"));
                }
                let mut pid = [0u8; 32];
                pid.copy_from_slice(&bytes);
                peer_id = Some(pid);
            }
            "name" => {
                // 只剥离首尾各一个引号（不用 trim_matches，避免误删转义序列）
                let s = v.strip_prefix('"').unwrap_or(v);
                let s = s.strip_suffix('"').unwrap_or(s);
                name = Some(s.replace("\\\"", "\""));
            }
            "addresses" => {
                // 解析 ["1.2.3.4:5678", ...]
                let inner = v.trim().trim_start_matches('[').trim_end_matches(']');
                for part in inner.split(',') {
                    let part = part.trim();
                    let part = part.strip_prefix('"').unwrap_or(part);
                    let part = part.strip_suffix('"').unwrap_or(part);
                    if part.is_empty() {
                        continue;
                    }
                    let addr: SocketAddr = part.parse().map_err(|_| err("bad address"))?;
                    addresses.push(addr);
                }
            }
            "paired_at" => {
                paired_at = Some(v.parse().map_err(|_| err("bad paired_at"))?);
            }
            _ => {}
        }
    }

    Ok(PairedPeer {
        peer_id: peer_id.ok_or_else(|| err("missing peer_id"))?,
        name: name.ok_or_else(|| err("missing name"))?,
        addresses,
        paired_at: paired_at.ok_or_else(|| err("missing paired_at"))?,
    })
}

// ---------- PairedDiscovery ----------

/// 已配对设备的发现源（实现 `Discovery` trait）。
#[derive(Debug, Clone, Default)]
pub struct PairedDiscovery {
    peers: HashMap<PeerId, Vec<SocketAddr>>,
}

impl PairedDiscovery {
    /// 空的配对发现源。
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一个已配对设备（`peer_id` 转为 `PeerId(hex)`）。
    pub fn insert(&mut self, peer: &PairedPeer) {
        let id = PeerId(hex_encode(&peer.peer_id));
        self.peers.insert(id, peer.addresses.clone());
    }

    /// 移除一个已配对设备；存在返回 true。
    pub fn remove(&mut self, peer_id: &[u8; 32]) -> bool {
        let id = PeerId(hex_encode(peer_id));
        self.peers.remove(&id).is_some()
    }

    /// 是否包含该设备。
    pub fn contains(&self, peer_id: &[u8; 32]) -> bool {
        let id = PeerId(hex_encode(peer_id));
        self.peers.contains_key(&id)
    }

    /// 已配对设备数量。
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl Discovery for PairedDiscovery {
    fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr> {
        self.peers.get(peer).cloned().unwrap_or_default()
    }
}

// ---------- 发现源集成 ----------

/// 配对源的来源标注（D7 新增，优先级最高）。
///
/// 注意：`DiscoverySource` 的新变体 `Paired` 在 `super::lib` 中定义；
/// 此处提供便捷转换。
impl PairedDiscovery {
    /// 来源标注（供 `AggregateDiscovery` 用）。
    pub fn source() -> super::DiscoverySource {
        super::DiscoverySource::Paired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    #[test]
    fn b64url_roundtrip() {
        for data in [&[][..], &[0u8][..], &[1, 2, 3][..], &[0xff; 32][..]] {
            let enc = b64url_encode(data);
            assert_eq!(b64url_decode(&enc).unwrap(), data);
        }
        // 无填充
        assert!(!b64url_encode(&[1, 2, 3]).contains('='));
    }

    #[test]
    fn b64url_rejects_bad_char() {
        assert!(b64url_decode("ab$c").is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0xabu8, 0xcd, 0xef, 0x01];
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
        assert_eq!(hex_encode(&data), "abcdef01");
    }

    #[test]
    fn pairing_code_roundtrip() {
        let peer_id = [0x42u8; 32];
        let code = PairingCode::generate(peer_id).unwrap();
        let s = code.encode();
        assert!(s.starts_with(PAIRING_CODE_PREFIX));
        let decoded = PairingCode::decode(&s).unwrap();
        assert_eq!(decoded, code);
    }

    #[test]
    fn pairing_code_rejects_bad() {
        assert!(PairingCode::decode("bad").is_err());
        assert!(PairingCode::decode("nexus-pair:v1:abc").is_err());
        assert!(PairingCode::decode("nexus-pair:v2:abc:def").is_err());
    }

    #[test]
    fn pairing_frame_roundtrip() {
        let frames = vec![
            PairingFrame::PairRequest {
                peer_id: [1u8; 32],
                token: [2u8; 16],
                name: "device-b".into(),
            },
            PairingFrame::PairAccept {
                peer_id: [3u8; 32],
                name: "device-a".into(),
                signature: [4u8; 64],
            },
            PairingFrame::PairReject {
                reason: "token expired".into(),
            },
        ];
        for f in &frames {
            let enc = encode_pairing_frame(f).unwrap();
            assert_eq!(decode_pairing_frame(&enc).unwrap(), *f);
        }
    }

    #[test]
    fn pairing_frame_rejects_truncated() {
        assert!(decode_pairing_frame(&[]).is_err());
        assert!(decode_pairing_frame(&[21, 1, 2, 3]).is_err());
        assert!(decode_pairing_frame(&[99]).is_err());
    }

    #[test]
    fn ed25519_sign_verify() {
        let id = NodeIdentity::generate().unwrap();
        let msg = b"hello pairing";
        let sig = id.sign(msg);
        assert!(NodeIdentity::verify(&id.peer_id(), msg, &sig));
        // 错误消息验证失败
        assert!(!NodeIdentity::verify(&id.peer_id(), b"wrong", &sig));
        // 错误公钥验证失败
        assert!(!NodeIdentity::verify(&[0u8; 32], msg, &sig));
    }

    #[test]
    fn pairing_sign_msg_format() {
        let token = [0x11u8; 16];
        let peer_b = [0x22u8; 32];
        let msg = pairing_sign_msg(&token, &peer_b);
        assert_eq!(msg.len(), 48);
        assert_eq!(&msg[..16], &token);
        assert_eq!(&msg[16..], &peer_b);
    }

    #[test]
    fn full_pairing_crypto_flow() {
        // 模拟完整配对加密流程：A 生成码，B 验证 A 的签名
        let id_a = NodeIdentity::generate().unwrap();
        let id_b = NodeIdentity::generate().unwrap();

        // A 生成配对码
        let code = PairingCode::generate(id_a.peer_id()).unwrap();
        let code_str = code.encode();

        // B 解析配对码
        let decoded = PairingCode::decode(&code_str).unwrap();
        assert_eq!(decoded.peer_id, id_a.peer_id());

        // B 发送 PairRequest，A 签名响应
        let msg = pairing_sign_msg(&decoded.token, &id_b.peer_id());
        let sig = id_a.sign(&msg);

        // B 验证签名
        assert!(NodeIdentity::verify(&decoded.peer_id, &msg, &sig));
    }

    #[test]
    fn peer_file_roundtrip() {
        let peer = PairedPeer {
            peer_id: [0xabu8; 32],
            name: "My \"Laptop\"".into(),
            addresses: vec![addr(4242), addr(4243)],
            paired_at: 1727740000,
        };
        let text = encode_peer_file(&peer);
        let decoded = decode_peer_file(&text).unwrap();
        assert_eq!(decoded, peer);
        assert_eq!(
            peer.filename(),
            format!("{}.toml", hex_encode(&peer.peer_id))
        );
        assert_eq!(peer.filename().len(), 69); // 64 hex + ".toml"
    }

    #[test]
    fn peer_file_rejects_bad() {
        assert!(decode_peer_file("").is_err());
        assert!(decode_peer_file("peer_id = \"abc\"\n").is_err());
    }

    #[test]
    fn paired_discovery_resolve() {
        use super::Discovery;
        let mut disc = PairedDiscovery::new();
        let peer = PairedPeer {
            peer_id: [0x11u8; 32],
            name: "a".into(),
            addresses: vec![addr(1111)],
            paired_at: 0,
        };
        disc.insert(&peer);
        let id = PeerId(hex_encode(&peer.peer_id));
        assert_eq!(Discovery::resolve(&disc, &id), vec![addr(1111)]);
        assert!(Discovery::resolve(&disc, &PeerId("unknown".into())).is_empty());
        assert!(disc.contains(&peer.peer_id));
        assert!(disc.remove(&peer.peer_id));
        assert!(!disc.contains(&peer.peer_id));
    }
}
