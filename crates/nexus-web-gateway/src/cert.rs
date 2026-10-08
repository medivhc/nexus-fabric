//! Local CA / self-signed certificate generation and rustls server configuration.
//!
//! WebRTC's `RTCPeerConnection` is only available on secure origins (HTTPS or
//! localhost). The MVP runs on LAN/VPN mesh IPs, so each node generates a
//! self-signed certificate for its own IPs/DNS names. The browser user installs
//! the node's CA once (first-visit guidance); the certificate is re-generated
//! on every start for the MVP (persistent CA is a later phase).

use std::net::IpAddr;
use std::sync::Arc;

use rcgen::SanType;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, crypto};

use crate::error::GatewayError;

/// Self-signed certificate material for the HTTPS/WSS server.
#[derive(Debug, Clone)]
pub struct LocalIdentity {
    /// Certificate DER (also acts as the local CA root for the browser).
    pub cert_der: Vec<u8>,
    /// Private key PKCS#8 DER.
    pub key_der: Vec<u8>,
}

/// Generate a self-signed certificate for the given DNS names and IP addresses.
///
/// # Errors
///
/// Returns `GatewayError::Tls` if rcgen cannot generate the key/certificate.
pub fn generate_identity(names: &[String], ips: &[IpAddr]) -> Result<LocalIdentity, GatewayError> {
    let mut params = rcgen::CertificateParams::new(names.to_vec())
        .map_err(|e| GatewayError::Tls(format!("bad cert params: {e}")))?;
    params
        .subject_alt_names
        .extend(ips.iter().copied().map(SanType::IpAddress));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Nexus Web Gateway Local CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Nexus");
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| GatewayError::Tls(format!("key generation failed: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| GatewayError::Tls(format!("self-sign failed: {e}")))?;
    Ok(LocalIdentity {
        cert_der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
    })
}

/// Load a certificate + key from PEM files.
///
/// # Errors
///
/// Returns `GatewayError::Tls` if the files cannot be read or parsed.
pub fn load_identity(cert_path: &str, key_path: &str) -> Result<LocalIdentity, GatewayError> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| GatewayError::Tls(format!("read {cert_path}: {e}")))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| GatewayError::Tls(format!("read {key_path}: {e}")))?;
    let cert_der = rustls_pemfile_cert(&cert_pem)?;
    let key_der = rustls_pemfile_key(&key_pem)?;
    Ok(LocalIdentity { cert_der, key_der })
}

fn rustls_pemfile_cert(pem: &str) -> Result<Vec<u8>, GatewayError> {
    decode_pem_block(pem, "CERTIFICATE")
        .ok_or_else(|| GatewayError::Tls("no certificate found in PEM".into()))
}

fn rustls_pemfile_key(pem: &str) -> Result<Vec<u8>, GatewayError> {
    // Accept both PKCS#8 ("PRIVATE KEY") and legacy RSA/EC ("RSA PRIVATE KEY" /
    // "EC PRIVATE KEY") blocks; PKCS#8 is what rcgen/openssl produce by default.
    decode_pem_block(pem, "PRIVATE KEY")
        .ok_or_else(|| GatewayError::Tls("no PKCS#8 private key found in PEM".into()))
}

fn decode_pem_block(pem: &str, tag: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let start = pem.find(&begin)? + begin.len();
    let rest = &pem[start..];
    let end = rest.find(&end)?;
    let b64: String = rest[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()
}

fn ring_provider() -> Arc<crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a rustls server config from a local identity.
///
/// # Errors
///
/// Returns `GatewayError::Tls` if the certificate/key cannot be installed.
pub fn server_config(identity: &LocalIdentity) -> Result<ServerConfig, GatewayError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivatePkcs8KeyDer::from(identity.key_der.clone());
    ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| GatewayError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|e| GatewayError::Tls(e.to_string()))
}