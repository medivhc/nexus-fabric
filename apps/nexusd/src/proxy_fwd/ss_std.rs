//! 标准 Shadowsocks AEAD（chacha20-ietf-poly1305）**UDP**。
//!
//! TCP 已切到 `nexus-outbound-shadowsocks`（SIP004 `SsStream`/`encode_request`）：
//! 本模块只保留 UDP 一侧（`TODO(deletion-gate: fixes-6)`：SsUdp 删除门归 fixes-6）。
//!
//! - UDP：每包独立 `salt || AEAD(addr || payload)`
//!
//! 密钥派生：HKDF-SHA1（标准 ss 规定 SHA1），info=`"ss-subkey"`（`derive_subkey`
//! 保留供向量测试复现）。
//! Nonce：12 字节；UDP 每包随机 salt 派生独立 key，nonce 从 0 开始。

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha1::Sha1;

/// chacha20-ietf-poly1305 的 salt 长度（32B）。
const SALT_LEN: usize = 32;
/// AEAD tag 长度（16B）。
const TAG_LEN: usize = 16;
/// Nonce 长度（12B）。
const NONCE_LEN: usize = 12;

/// 标准 ss 错误。
#[derive(Debug)]
pub enum SsStdError {
    Io(io::Error),
    BadAddress,
    DecryptFailed,
    TooLarge,
}

impl std::fmt::Display for SsStdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ss-std io: {e}"),
            Self::BadAddress => write!(f, "ss-std: bad address"),
            Self::DecryptFailed => write!(f, "ss-std: decrypt failed"),
            Self::TooLarge => write!(f, "ss-std: chunk too large"),
        }
    }
}

impl From<io::Error> for SsStdError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// 生成随机 salt（/dev/urandom；Unix）。
fn gen_salt() -> io::Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(&mut salt)?;
    Ok(salt)
}

/// 标准 ss 子密钥派生：HKDF-SHA1(salt, password, "ss-subkey")。
fn derive_subkey(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha1>::new(Some(salt), password);
    let mut out = [0u8; 32];
    hk.expand(b"ss-subkey", &mut out)
        .expect("hkdf-sha1 expand 32 bytes");
    out
}

/// 地址编码（标准 ss ATYP 格式）。
fn encode_addr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// 地址解码；返回 (addr, 消费字节数)。
fn decode_addr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let atyp = *buf.first()?;
    match atyp {
        0x01 => {
            if buf.len() < 7 {
                return None;
            }
            let ip = IpAddr::from([buf[1], buf[2], buf[3], buf[4]]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Some((SocketAddr::new(ip, port), 7))
        }
        0x04 => {
            if buf.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = IpAddr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Some((SocketAddr::new(ip, port), 19))
        }
        0x03 => {
            // 域名：本期不支持（transport 只做 IP；调用方应先解析）。
            None
        }
        _ => None,
    }
}

/// AEAD 加密一块（nonce 递增由调用方管理）。
fn seal(key: &[u8; 32], nonce: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
    cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("chacha20poly1305 encrypt")
}

/// AEAD 解密一块。
fn open(key: &[u8; 32], nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, SsStdError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
        .map_err(|_| SsStdError::DecryptFailed)
}

/// 标准 ss UDP：单包加解密（每包独立 salt）。
pub struct SsUdp;

impl SsUdp {
    /// 加密一个 UDP 包：`salt || AEAD(addr || payload)`。
    pub fn seal_packet(password: &str, target: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
        let salt = gen_salt()?;
        let key = derive_subkey(password.as_bytes(), &salt);
        let mut plain = encode_addr(target);
        plain.extend_from_slice(payload);
        // UDP nonce 从 0 开始（每包独立 key）。
        let sealed = seal(&key, 0, &plain);
        let mut out = salt.to_vec();
        out.extend(sealed);
        Ok(out)
    }

    /// 解密一个 UDP 包；返回 (源地址, 载荷)。
    pub fn open_packet(password: &str, packet: &[u8]) -> Result<(SocketAddr, Vec<u8>), SsStdError> {
        if packet.len() < SALT_LEN + TAG_LEN + 1 {
            return Err(SsStdError::DecryptFailed);
        }
        let (salt, sealed) = packet.split_at(SALT_LEN);
        let key = derive_subkey(password.as_bytes(), salt);
        let plain = open(&key, 0, sealed)?;
        let (addr, off) = decode_addr(&plain).ok_or(SsStdError::BadAddress)?;
        Ok((addr, plain[off..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_udp_roundtrip() {
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let payload = b"hello ss udp";
        let pkt = SsUdp::seal_packet("password", target, payload).unwrap();
        let (addr, data) = SsUdp::open_packet("password", &pkt).unwrap();
        assert_eq!(addr, target);
        assert_eq!(data, payload);
    }

    #[test]
    fn ss_udp_wrong_password_fails() {
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let pkt = SsUdp::seal_packet("password", target, b"hi").unwrap();
        assert!(SsUdp::open_packet("wrong", &pkt).is_err());
    }

    #[test]
    fn ss_addr_codec() {
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let enc = encode_addr(addr);
        let (dec, n) = decode_addr(&enc).unwrap();
        assert_eq!(dec, addr);
        assert_eq!(n, enc.len());
    }

    /// FU-1 证据可复现：HKDF-SHA1(SHA1) + info="ss-subkey" 的已知答案向量。
    ///
    /// `#[ignore]`：`cargo test -p nexusd ss_std:: -- --ignored` 手动跑（R14）。
    #[test]
    #[ignore]
    fn ss_subkey_known_answer_vector() {
        let key = derive_subkey(b"password", &[1u8; 32]);
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5054b44ff2adee45905b64b0a4bff0e450cbcdb5255ec7420461de8706774761"
        );
    }

    #[test]
    fn ss_key_derivation_stable() {
        let k1 = derive_subkey(b"pw", &[1u8; 32]);
        let k2 = derive_subkey(b"pw", &[1u8; 32]);
        assert_eq!(k1, k2);
        let k3 = derive_subkey(b"pw", &[2u8; 32]);
        assert_ne!(k1, k3);
    }
}
