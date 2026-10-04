//! nexus-outbound-trojan
//!
//! Trojan 出站 adapter（PRODUCT §11.9）：实现
//! `nexus-connectivity::OutboundAdapter`，在 TCP 字节流上叠加 TLS（rustls 0.23 + ring）
//! 与 trojan 请求头 `hex(SHA-224(password)) | CRLF | CMD(0x01 CONNECT) | ATYP+ADDR+PORT | CRLF`
//! （trojan-gfw 官方线上格式，PRODUCT §11.9.2）。
//!
//! 离线确定性 E4：rcgen 动态自签证书，客户端把该唯一证书作为唯一信任根（公钥 pin），
//! loopback 127.0.0.1 同一进程内 TLS server+client；不连公网。

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use nexus_connectivity::{ConnectivityError, OutboundAdapter, OutboundHandoff};
use sha2::{Digest, Sha224};

// ---------- 结构化错误 ----------

/// Trojan 出站结构化错误（不以日志文本代替类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrojanError {
    /// 密码首行 hash 不匹配（不泄露密码/hash）。
    AuthDenied,
    /// 请求头长度/格式非法。
    InvalidHeader,
    /// TLS 配置或握手失败。
    Tls,
    /// 底层 I/O 失败。
    Io,
}

impl core::fmt::Display for TrojanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthDenied => write!(f, "trojan auth denied"),
            Self::InvalidHeader => write!(f, "trojan invalid header"),
            Self::Tls => write!(f, "trojan tls error"),
            Self::Io => write!(f, "trojan io error"),
        }
    }
}

impl std::error::Error for TrojanError {}

impl From<std::io::Error> for TrojanError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

// ---------- 目标地址（ATYP 子集） ----------

/// Trojan 请求目标（ATYP 子集，与 shadowsocks 一致）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrojanTarget {
    /// ATYP=1 IPv4。
    Ipv4([u8; 4], u16),
    /// ATYP=3 domain。
    Domain(String, u16),
}

impl TrojanTarget {
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

// ---------- 密码 hash 与请求头编解码 ----------

fn to_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(char::from_digit(u32::from(*b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(*b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// 计算 trojan 密码首行：`hex(SHA-224(password))`（小写 hex，56 字符）。
#[must_use]
pub fn auth_hash(password: &str) -> String {
    let mut h = Sha224::new();
    h.update(password.as_bytes());
    to_hex(&h.finalize())
}

/// 请求头地址行格式选择（PRODUCT §11.9.2）。
///
/// 2026-09-25 requirement-change：两变体**字节完全等价**——均按 trojan-gfw 官方线上布局输出
/// `hex | CRLF | CMD(0x01 CONNECT) | ATYP+ADDR+PORT | CRLF`。`Singbox` 仅为既有配置字符串的
/// 兼容别名保留。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrojanHeaderFormat {
    /// trojan-gfw 官方线上格式：含 `CMD(0x01 CONNECT)` 命令字节（**默认**）。
    #[default]
    Standard,
    /// 与 Standard 字节等价的兼容别名（同样含 `0x01` CMD）。
    Singbox,
}

/// 编码 trojan 请求头（Standard 默认）。
#[must_use]
pub fn encode_request(password: &str, target: &TrojanTarget) -> Vec<u8> {
    encode_request_fmt(password, target, TrojanHeaderFormat::Standard)
}

/// 按指定格式编码 trojan 请求头。
///
/// Standard 与 Singbox 字节等价（PRODUCT §11.9.2）：均输出官方线上布局
/// `hex(SHA-224(pwd)) | CRLF | CMD(0x01 CONNECT) | ATYP+ADDR+PORT | CRLF`。
/// `fmt` 仅为配置兼容保留，不改变字节输出。
#[must_use]
pub fn encode_request_fmt(
    password: &str,
    target: &TrojanTarget,
    fmt: TrojanHeaderFormat,
) -> Vec<u8> {
    // 两变体字节等价（§11.9.2）：均输出 CMD(0x01 CONNECT)。
    let _ = fmt;
    let mut out = Vec::new();
    out.extend_from_slice(auth_hash(password).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.push(0x01); // CMD = CONNECT
    match target {
        TrojanTarget::Ipv4(oct, port) => {
            out.push(0x01);
            out.extend_from_slice(oct);
            out.extend_from_slice(&port.to_be_bytes());
        }
        TrojanTarget::Domain(host, port) => {
            out.push(0x03);
            out.push(host.len().min(255) as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// 解码并校验 trojan 请求头（Standard 默认）。
///
/// # Errors
///
/// hash 不匹配返回 `AuthDenied`；头部长度/格式非法返回 `InvalidHeader`。
pub fn parse_request(password: &str, buf: &[u8]) -> Result<TrojanTarget, TrojanError> {
    parse_request_fmt(password, buf, TrojanHeaderFormat::Standard)
}

/// 按指定格式解码并校验 trojan 请求头。
///
/// Standard 与 Singbox 字节等价（PRODUCT §11.9.2）：先 strip 地址行前导 `0x01`
/// CONNECT 命令字节，再读 ATYP+ADDR+PORT。`fmt` 仅为配置兼容保留。
///
/// # Errors
///
/// hash 不匹配返回 `AuthDenied`；头部长度/格式非法（含命令字节缺失/位置不符）返回
/// `InvalidHeader`。
pub fn parse_request_fmt(
    password: &str,
    buf: &[u8],
    fmt: TrojanHeaderFormat,
) -> Result<TrojanTarget, TrojanError> {
    // 找到第一个 CRLF，分隔密码行与地址行。
    let pos = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(TrojanError::InvalidHeader)?;
    let hash_line = &buf[..pos];
    let rest = &buf[pos + 2..];

    let expected = auth_hash(password);
    if hash_line.len() != expected.len() || to_hex(hash_line) != to_hex(expected.as_bytes()) {
        // 注意：不把 hash 内容写进错误。
        return Err(TrojanError::AuthDenied);
    }

    // 地址行应为 CMD(0x01 CONNECT) ATYP+ADDR+PORT，且以 CRLF 结尾。
    // Standard/Singbox 等价（§11.9.2）：统一 strip 前导 0x01 CMD 字节后再读 ATYP。
    let _ = fmt;
    let addr = rest
        .strip_suffix(b"\r\n")
        .ok_or(TrojanError::InvalidHeader)?;
    let addr = addr
        .strip_prefix(&[0x01])
        .ok_or(TrojanError::InvalidHeader)?;
    if addr.len() < 2 {
        return Err(TrojanError::InvalidHeader);
    }
    match addr[0] {
        0x01 => {
            if addr.len() != 1 + 4 + 2 {
                return Err(TrojanError::InvalidHeader);
            }
            let mut oct = [0u8; 4];
            oct.copy_from_slice(&addr[1..5]);
            let port = u16::from_be_bytes([addr[5], addr[6]]);
            Ok(TrojanTarget::Ipv4(oct, port))
        }
        0x03 => {
            let dlen = addr[1] as usize;
            let need = 2 + dlen + 2;
            if addr.len() != need {
                return Err(TrojanError::InvalidHeader);
            }
            let host = std::str::from_utf8(&addr[2..2 + dlen])
                .map_err(|_| TrojanError::InvalidHeader)?
                .to_string();
            let port = u16::from_be_bytes([addr[2 + dlen], addr[2 + dlen + 1]]);
            Ok(TrojanTarget::Domain(host, port))
        }
        _ => Err(TrojanError::InvalidHeader),
    }
}

// ---------- adapter ----------

/// Trojan 出站 adapter（离线交接；真实 TLS 会话在 example 层）。
pub struct TrojanAdapter {
    tag: String,
    locator: String,
}

impl TrojanAdapter {
    /// 构造 adapter。
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        locator: impl Into<String>,
        _password: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            locator: locator.into(),
        }
    }

    /// 配置的服务端 locator。
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }
}

impl OutboundAdapter for TrojanAdapter {
    fn outbound_kind(&self) -> &'static str {
        "trojan"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn handoff(&self, locator: &str) -> Result<OutboundHandoff, ConnectivityError> {
        Ok(OutboundHandoff {
            kind: self.outbound_kind().to_string(),
            tag: self.tag.clone(),
            locator: locator.to_string(),
        })
    }
}

// ---------- loopback TLS 材料（rcgen 自签 + 公钥 pin） ----------

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ServerConfig};

/// 自签证书材料（cert DER + PKCS8 key DER）。
pub struct LoopbackIdentity {
    /// 服务端证书 DER（同时作为客户端唯一信任根，即公钥 pin）。
    pub cert_der: Vec<u8>,
    /// 服务端私钥 PKCS8 DER。
    pub key_der: Vec<u8>,
}

/// 用 rcgen 生成一张自签证书（CN/SAN = localhost），离线、确定性可复现。
///
/// # Errors
///
/// rcgen 生成失败返回 `Tls`。
pub fn generate_loopback_identity() -> Result<LoopbackIdentity, TrojanError> {
    let key_pair = rcgen::KeyPair::generate().map_err(|_| TrojanError::Tls)?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|_| TrojanError::Tls)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| TrojanError::Tls)?;
    let key_der = key_pair.serialize_der();
    let cert_der = cert.der().to_vec();
    Ok(LoopbackIdentity { cert_der, key_der })
}

fn ring_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}

/// 构造服务端 TLS 配置（仅持有自签证书）。
///
/// # Errors
///
/// 证书/key 解析失败返回 `Tls`。
pub fn server_config(identity: &LoopbackIdentity) -> Result<ServerConfig, TrojanError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivatePkcs8KeyDer::from(identity.key_der.clone());
    let config = ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| TrojanError::Tls)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|_| TrojanError::Tls)?;
    Ok(config)
}

/// 构造客户端 TLS 配置：把自签证书作为**唯一**信任根（公钥 pin，不依赖系统根）。
///
/// # Errors
///
/// 证书加入 root store 失败返回 `Tls`。
pub fn client_config(identity: &LoopbackIdentity) -> Result<ClientConfig, TrojanError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).map_err(|_| TrojanError::Tls)?;
    let config = ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| TrojanError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

// ---------- 真实节点客户端：skip-cert-verify + ALPN（§11.9.1） ----------

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// 跳过证书链/主机名校验，但仍校验 TLS 握手签名的危险 verifier。
///
/// 仅用于内网/自签 trojan 节点的 `skip-cert-verify` 模式（§11.9.1）。本 crate 仍
/// `#![forbid(unsafe_code)]`；"dangerous" 只是 rustls API 命名。
#[derive(Debug)]
struct SkipCertVerify;

impl ServerCertVerifier for SkipCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let schemes = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let schemes = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构造面向真实节点的客户端配置：跳过证书校验 + 下发 ALPN 列表。
///
/// SNI 由调用方以 `ServerName` 传入。`alpn` 为空表示不下发 ALPN。
///
/// # Errors
///
/// 协议版本不支持返回 `Tls`。
pub fn client_config_dangerous_skip_verify(alpn: &[&[u8]]) -> Result<ClientConfig, TrojanError> {
    let mut config = ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| TrojanError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(SkipCertVerify))
        .with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }
    Ok(config)
}

// ---------- TLS 会话 IO 原语 ----------

/// 在已建立的 TLS stream 上写一段字节（flush）。
///
/// 泛型化以支持插件 wrapped 流（TLS 跑在混淆流之上）；对 `TcpStream` 的既有
/// 调用保持兼容（P6）。
///
/// # Errors
///
/// I/O 失败返回 `Io`。
pub fn tls_write<T: Read + Write>(
    tls: &mut rustls::Stream<'_, rustls::ClientConnection, T>,
    buf: &[u8],
) -> Result<(), TrojanError> {
    tls.write_all(buf)?;
    tls.flush()?;
    Ok(())
}

/// 从 TLS stream 读满 `out.len()` 字节。
///
/// 泛型化以支持插件 wrapped 流；对 `TcpStream` 的既有调用保持兼容（P6）。
///
/// # Errors
///
/// 连接过早关闭或 I/O 失败返回 `Io`。
pub fn tls_read_exact<T: Read + Write>(
    tls: &mut rustls::Stream<'_, rustls::ClientConnection, T>,
    out: &mut [u8],
) -> Result<(), TrojanError> {
    tls.read_exact(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_hash_is_56_hex() {
        let h = auth_hash("demo");
        assert_eq!(h.len(), 56);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn request_roundtrip_ipv4() {
        let t = TrojanTarget::Ipv4([127, 0, 0, 1], 8388);
        let raw = encode_request("demo", &t);
        assert!(raw.ends_with(b"\r\n"));
        assert_eq!(parse_request("demo", &raw).unwrap(), t);
    }

    #[test]
    fn request_roundtrip_domain() {
        let t = TrojanTarget::Domain("target.internal".to_string(), 1080);
        let raw = encode_request("pw", &t);
        assert_eq!(parse_request("pw", &raw).unwrap(), t);
    }

    #[test]
    fn wrong_password_is_auth_denied() {
        let t = TrojanTarget::Ipv4([127, 0, 0, 1], 9000);
        let raw = encode_request("correct", &t);
        assert_eq!(parse_request("wrong", &raw), Err(TrojanError::AuthDenied));
    }

    #[test]
    fn adapter_kind_and_handoff() {
        let a = TrojanAdapter::new("trojan-out", "troj.example:443", "pw");
        assert_eq!(a.outbound_kind(), "trojan");
        assert_eq!(a.tag(), "trojan-out");
        let h = a.handoff("10.0.0.1:443").unwrap();
        assert_eq!(h.kind, "trojan");
        assert_eq!(h.locator, "10.0.0.1:443");
    }

    #[test]
    fn loopback_identity_generates() {
        let id = generate_loopback_identity().unwrap();
        assert!(!id.cert_der.is_empty());
        assert!(!id.key_der.is_empty());
        server_config(&id).unwrap();
        client_config(&id).unwrap();
    }
}
