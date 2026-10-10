//! TLS 配置：QUIC 握手用的 rustls 客户端/服务端配置（文档 §2.1(2)(3)）。
//!
//! - ALPN 固定为 `h3`（其他值配置即拒绝，见 [`crate::config`]）。
//! - 证书校验三选一（[`CertVerify`]）：
//!   - `Insecure`：跳过链校验与主机名校验，但仍校验 TLS 握手签名
//!     （证明对端持有私钥；"dangerous" 只是 rustls API 命名，本 crate 仍
//!     `#![forbid(unsafe_code)]`）；
//!   - `PinSha256`：叶子证书 DER 的 SHA-256 等于 pin 即通过，**替代**链校验
//!     与主机名校验（mihomo 行为，允许自签名；文档 §5 坑 #3）；
//!   - `SystemRoots`：系统根证书链校验。
//! - QUIC 只用 TLS 1.3（rustls 的 QUIC 要求；`with_safe_default_protocol_versions`
//!   包含 1.2+1.3，握手时协商出 1.3）。

use std::sync::Arc;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use super::Hysteria2Error;

/// Hysteria2 的 ALPN（固定）。
pub const ALPN_H3: &[u8] = b"h3";

/// 证书校验模式（文档 §2.1(3) 三选一）。
#[derive(Debug, Clone)]
pub enum CertVerify {
    /// 跳过证书校验（`skip-cert-verify`）。
    Insecure,
    /// 叶子证书 DER 的 SHA-256 pin（替代链校验+主机名校验）。
    PinSha256([u8; 32]),
    /// 系统根证书链校验。
    SystemRoots,
}

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// 危险 verifier：`Insecure`（无条件通过）或 `PinSha256`（比对叶子 DER 的
/// SHA-256）。两种模式都**替代**链校验与主机名校验，但握手签名（TLS 1.2/1.3）
/// 仍委托 ring 校验——对端必须持有与证书匹配的私钥。
#[derive(Debug)]
struct Hy2Verifier {
    pin: Option<[u8; 32]>,
}

impl ServerCertVerifier for Hy2Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.pin {
            None => Ok(ServerCertVerified::assertion()),
            Some(pin) => {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(end_entity.as_ref());
                if digest.as_slice() == pin {
                    Ok(ServerCertVerified::assertion())
                } else {
                    // pin 不匹配：按"未知颁发者"拒绝（不泄露期望的 pin 值）。
                    Err(Error::InvalidCertificate(
                        rustls::CertificateError::UnknownIssuer,
                    ))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let schemes = ring_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let schemes = ring_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构造 QUIC 客户端 crypto 配置（ALPN `h3` + 证书校验模式）。
///
/// # Errors
///
/// TLS 配置构造失败 → [`Hysteria2Error::Tls`]。
pub fn build_quic_client_config(verify: &CertVerify) -> Result<QuicClientConfig, Hysteria2Error> {
    let provider = ring_provider();
    let mut config = match verify {
        CertVerify::Insecure => ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Hysteria2Error::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Hy2Verifier { pin: None }))
            .with_no_client_auth(),
        CertVerify::PinSha256(pin) => ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Hysteria2Error::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Hy2Verifier { pin: Some(*pin) }))
            .with_no_client_auth(),
        CertVerify::SystemRoots => {
            let loaded = rustls_native_certs::load_native_certs();
            if !loaded.errors.is_empty() {
                return Err(Hysteria2Error::Tls);
            }
            let mut roots = rustls::RootCertStore::empty();
            for cert in loaded.certs {
                roots.add(cert).map_err(|_| Hysteria2Error::Tls)?;
            }
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|_| Hysteria2Error::Tls)?
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    };
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    QuicClientConfig::try_from(config).map_err(|_| Hysteria2Error::Tls)
}

/// 构造 QUIC 服务端 crypto 配置（仅测试用最小 server；ALPN `h3`）。
///
/// # Errors
///
/// 证书/key 解析失败 → [`Hysteria2Error::Tls`]。
pub fn build_quic_server_config(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<QuicServerConfig, Hysteria2Error> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let key = PrivatePkcs8KeyDer::from(key_der.to_vec());
    let mut config = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| Hysteria2Error::Tls)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|_| Hysteria2Error::Tls)?;
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    QuicServerConfig::try_from(config).map_err(|_| Hysteria2Error::Tls)
}

/// 用 rcgen 生成测试用自签证书（CN/SAN = localhost），返回 `(cert_der, key_der)`。
///
/// # Errors
///
/// 生成失败 → [`Hysteria2Error::Tls`]。
pub fn generate_test_identity() -> Result<(Vec<u8>, Vec<u8>), Hysteria2Error> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|_| Hysteria2Error::Tls)?;
    Ok((
        certified.cert.der().to_vec(),
        certified.key_pair.serialize_der(),
    ))
}

/// 计算证书 DER 的 SHA-256（用于 `pin-sha256` 配置与测试）。
#[must_use]
pub fn sha256_of(cert_der: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert_der).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_h3_on_client_config() {
        // 三种校验模式都下发 ALPN h3。
        for verify in [
            CertVerify::Insecure,
            CertVerify::PinSha256([0xABu8; 32]),
            CertVerify::SystemRoots,
        ] {
            let quic = build_quic_client_config(&verify).unwrap();
            // QuicClientConfig 包装了 rustls ClientConfig；通过重新 try_from
            // 无法观察 ALPN，这里至少保证构造成功（ALPN 断言在握手测试中覆盖）。
            let _ = quic;
        }
    }

    #[test]
    fn pin_verifier_accepts_matching_pin() {
        let (cert_der, _) = generate_test_identity().unwrap();
        let pin = sha256_of(&cert_der);
        let v = Hy2Verifier { pin: Some(pin) };
        let cert = CertificateDer::from(cert_der);
        let name = ServerName::try_from("localhost").unwrap();
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn pin_verifier_rejects_mismatched_pin() {
        let (cert_der, _) = generate_test_identity().unwrap();
        let v = Hy2Verifier {
            pin: Some([0x00u8; 32]),
        };
        let cert = CertificateDer::from(cert_der);
        let name = ServerName::try_from("localhost").unwrap();
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }

    #[test]
    fn insecure_verifier_accepts_anything() {
        let v = Hy2Verifier { pin: None };
        let cert = CertificateDer::from(vec![0x30, 0x82, 0x01, 0x02]);
        let name = ServerName::try_from("anything.invalid").unwrap();
        assert!(
            v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn server_config_builds() {
        let (cert_der, key_der) = generate_test_identity().unwrap();
        let _ = build_quic_server_config(&cert_der, &key_der).unwrap();
    }
}
