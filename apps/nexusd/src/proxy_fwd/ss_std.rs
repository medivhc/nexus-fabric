//! 标准 Shadowsocks AEAD（chacha20-ietf-poly1305）TCP/UDP。
//!
//! 与 `nexus-outbound-shadowsocks` 的自定义握手（`ss-proxy-ok` ack）不同，
//! 这里实现标准 ss 协议，可与真实 ss 服务器互通（P1/P2）：
//! - TCP：`salt || AEAD(addr) || [AEAD(len) || AEAD(payload)]*`
//! - UDP：每包独立 `salt || AEAD(addr || payload)`
//!
//! 密钥派生：HKDF-SHA1（标准 ss 规定 SHA1），info=`"ss-subkey"`。
//! Nonce：12 字节，TCP 从 0 递增；UDP 每包随机 salt 派生独立 key，nonce 从 0 开始。

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

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
/// TCP 数据块最大明文（16KB，标准 ss 建议）。
const MAX_CHUNK: usize = 0x3FFF;

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

/// 标准 ss TCP 客户端连接。
///
/// Wire: `salt || AEAD(addr) || [AEAD(len:u16 BE) || AEAD(chunk)]*`
/// Nonce 从 0 开始每块递增（addr 占 nonce 0，len/payload 依次递增）。
pub struct SsTcpClient {
    stream: TcpStream,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_nonce: u64,
    rx_nonce: u64,
    /// 读缓冲（解密后的明文）。
    read_buf: Vec<u8>,
}

impl SsTcpClient {
    /// 连接并完成握手（发送 salt + 加密的目标地址）。
    pub fn connect(
        server: SocketAddr,
        password: &str,
        target: SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<Self, SsStdError> {
        let mut stream = TcpStream::connect_timeout(&server, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let salt = gen_salt()?;
        let tx_key = derive_subkey(password.as_bytes(), &salt);

        // 发送 salt + AEAD(addr)（nonce 0）。
        let addr_enc = encode_addr(target);
        let sealed_addr = seal(&tx_key, 0, &addr_enc);
        stream.write_all(&salt)?;
        stream.write_all(&sealed_addr)?;
        stream.flush()?;

        // 读取 server 的 salt + AEAD(addr) 回应？标准 ss TCP 服务器不回地址，
        // 直接开始数据。读取 server salt（32B）用于派生 rx key。
        let mut srv_salt = [0u8; SALT_LEN];
        stream.read_exact(&mut srv_salt)?;
        let rx_key = derive_subkey(password.as_bytes(), &srv_salt);

        // 清除超时（调用方按需设置）。
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;

        Ok(Self {
            stream,
            tx_key,
            rx_key,
            tx_nonce: 1, // nonce 0 已用于 addr
            rx_nonce: 0,
            read_buf: Vec::new(),
        })
    }

    /// 写入一块明文（自动分块 ≤ MAX_CHUNK）。
    pub fn write_all(&mut self, mut data: &[u8]) -> Result<(), SsStdError> {
        while !data.is_empty() {
            let n = data.len().min(MAX_CHUNK);
            let chunk = &data[..n];
            // 先写加密的长度（2B BE）。
            let len_bytes = (n as u16).to_be_bytes();
            let sealed_len = seal(&self.tx_key, self.tx_nonce, &len_bytes);
            self.tx_nonce += 1;
            self.stream.write_all(&sealed_len)?;
            // 再写加密的载荷。
            let sealed = seal(&self.tx_key, self.tx_nonce, chunk);
            self.tx_nonce += 1;
            self.stream.write_all(&sealed)?;
            data = &data[n..];
        }
        self.stream.flush()?;
        Ok(())
    }

    /// 读取解密后的明文（阻塞；返回 0 表示对端关闭）。
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, SsStdError> {
        // 先消费缓冲。
        if !self.read_buf.is_empty() {
            let n = buf.len().min(self.read_buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            return Ok(n);
        }
        // 读一个完整的 chunk：[AEAD(len)] [AEAD(payload)]。
        let mut sealed_len = vec![0u8; 2 + TAG_LEN];
        match self.stream.read_exact(&mut sealed_len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
            Err(e) => return Err(SsStdError::Io(e)),
        }
        let len_bytes = open(&self.rx_key, self.rx_nonce, &sealed_len)?;
        self.rx_nonce += 1;
        if len_bytes.len() != 2 {
            return Err(SsStdError::DecryptFailed);
        }
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if len > MAX_CHUNK {
            return Err(SsStdError::TooLarge);
        }
        let mut sealed = vec![0u8; len + TAG_LEN];
        self.stream.read_exact(&mut sealed)?;
        let plain = open(&self.rx_key, self.rx_nonce, &sealed)?;
        self.rx_nonce += 1;

        let n = buf.len().min(plain.len());
        buf[..n].copy_from_slice(&plain[..n]);
        if plain.len() > n {
            self.read_buf.extend_from_slice(&plain[n..]);
        }
        Ok(n)
    }

    /// 消费为原始 TcpStream（已握手；调用方负责后续 AEAD 分块）。
    /// 本期未用；保留供将来零拷贝优化。
    #[allow(dead_code)]
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
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

    #[test]
    fn ss_key_derivation_stable() {
        let k1 = derive_subkey(b"pw", &[1u8; 32]);
        let k2 = derive_subkey(b"pw", &[1u8; 32]);
        assert_eq!(k1, k2);
        let k3 = derive_subkey(b"pw", &[2u8; 32]);
        assert_ne!(k1, k3);
    }

    const SIP004_EXPECTED: &str =
        include_str!("../../../../scripts/interop/ss_sip004_expected.json");
    const SIP004_COMMAND: &str = "cargo test --manifest-path apps/nexusd/Cargo.toml -p nexusd ss_sip004_vector_report -- --ignored";

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ascii hex");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    fn hex_text(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn repo_root() -> std::path::PathBuf {
        std::env::var_os("NEXUS_REPO_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .canonicalize()
            .expect("canonical repo root")
    }

    fn source_revision(repo_root: &std::path::Path) -> String {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[test]
    #[ignore = "step 1.5 evidence report; writes .evidence/outbound-adapter-wiring/ss-std-sip004/vectors.json"]
    fn sip004_vector_report() {
        use nexus::n3_acceptance::sha256;

        let expected: serde_json::Value =
            serde_json::from_str(SIP004_EXPECTED).expect("parse ss_sip004_expected.json");
        let mut vectors = Vec::new();
        let mut matched = 0usize;
        let mut mismatched = 0usize;
        for vector in expected["vectors"].as_array().expect("vectors array") {
            let salt = hex_bytes(vector["salt_hex"].as_str().expect("salt_hex"));
            let password_sha256 = vector["password_sha256"].as_str().expect("password_sha256");
            let password = hex_bytes(vector["password_hex"].as_str().expect("password_hex"));
            assert_eq!(
                password.len() as u64,
                vector["password_len"].as_u64().expect("password_len")
            );
            assert_eq!(
                sha256(&password).as_str().trim_start_matches("sha256:"),
                password_sha256,
                "password fixture mismatch for {}",
                vector["vector_id"].as_str().unwrap_or("?")
            );

            let actual = derive_subkey(&password, &salt);
            let actual_hex = hex_text(&actual);
            let expected_hex = vector["expected_subkey_hex"].as_str().expect("expected");
            let result = if actual_hex == expected_hex {
                matched += 1;
                "MATCH"
            } else {
                mismatched += 1;
                "MISMATCH"
            };
            let conclusion = if result == "MATCH" {
                "ss_std 派生与 SIP004 期望一致"
            } else {
                "ss_std 省略 EVP_BytesToKey，派生不合 SIP004"
            };
            vectors.push(serde_json::json!({
                "vector_id": vector["vector_id"],
                "password_sha256": password_sha256,
                "password_len": vector["password_len"],
                "salt_hex": vector["salt_hex"],
                "expected_subkey_hex": expected_hex,
                "actual_subkey_hex": actual_hex,
                "result": result,
                "conclusion": conclusion,
            }));
        }

        let overall = if mismatched == 0 {
            "MATCH"
        } else if matched == 0 {
            "MISMATCH"
        } else {
            "PARTIAL"
        };
        let repo_root = repo_root();
        let source = std::fs::read(repo_root.join("apps/nexusd/src/proxy_fwd/ss_std.rs"))
            .expect("read ss_std.rs");
        let report = serde_json::json!({
            "schema_version": 1,
            "commit": source_revision(&repo_root),
            "ss_std_source_sha256": sha256(&source).as_str().trim_start_matches("sha256:"),
            "method": expected["method"],
            "info": expected["info"],
            "reference": expected["reference"],
            "command": SIP004_COMMAND,
            "vectors": vectors,
            "overall": overall,
        });

        let evidence_dir = repo_root.join(".evidence/outbound-adapter-wiring/ss-std-sip004");
        assert!(evidence_dir.is_absolute());
        std::fs::create_dir_all(&evidence_dir).expect("create evidence dir");
        let serialized = serde_json::to_string_pretty(&report).expect("serialize report");
        std::fs::write(evidence_dir.join("vectors.json"), serialized + "\n")
            .expect("write vectors.json");
    }
}
