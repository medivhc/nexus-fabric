//! Local CA / self-signed certificate generation and rustls server configuration.
//!
//! WebRTC's `RTCPeerConnection` is only available on secure origins (HTTPS or
//! localhost). The MVP runs on LAN/VPN mesh IPs, so each node generates a
//! self-signed certificate for its own IPs/DNS names. The certificate is
//! persisted to disk (per node) so its fingerprint is stable across restarts,
//! and the gateway serves it at `/cert` for the browser's "install the local
//! CA" first-visit guidance.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
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

impl LocalIdentity {
    /// PEM-encoded certificate (for `/cert` and for persisting to disk).
    pub fn cert_pem(&self) -> Result<String, GatewayError> {
        Ok(encode_pem_block(&self.cert_der, "CERTIFICATE"))
    }

    /// PEM-encoded PKCS#8 private key (for persisting to disk).
    pub fn key_pem(&self) -> Result<String, GatewayError> {
        Ok(encode_pem_block(&self.key_der, "PRIVATE KEY"))
    }

    /// SHA256 fingerprint of the certificate DER, as colon-separated hex (REQ-001).
    /// Use this to verify the CA out-of-band before installing.
    pub fn fingerprint_sha256(&self) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&self.cert_der);
        hash.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
    }
}

/// Default directory for persisted certificates, derived from the node id.
pub fn default_cert_dir(node_id: &str) -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("nexus-web-gateway")
        .join(sanitize_path_component(node_id))
}

fn sanitize_path_component(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
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

/// Generate a self-signed identity, reusing a persisted one when present.
///
/// When `cert_dir` is `Some`, the certificate and key are stored as
/// `cert.pem`/`key.pem` under that directory and loaded on later starts so the
/// fingerprint does not change across restarts. When `None`, a fresh identity
/// is generated in memory.
///
/// # Errors
///
/// Returns `GatewayError::Tls` on generation/loading failures and
/// `GatewayError::Io` if the persisted files cannot be written.
pub fn generate_or_load_identity(
    names: &[String],
    ips: &[IpAddr],
    cert_dir: Option<&Path>,
) -> Result<LocalIdentity, GatewayError> {
    let Some(dir) = cert_dir else {
        return generate_identity(names, ips);
    };
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.is_file() && key_path.is_file() {
        if let Ok(identity) =
            load_identity(&cert_path.to_string_lossy(), &key_path.to_string_lossy())
        {
            return Ok(identity);
        }
        tracing::warn!("stored TLS identity unreadable; regenerating");
    }
    let identity = generate_identity(names, ips)?;
    persist_identity(&identity, dir)?;
    Ok(identity)
}

/// Write a generated identity as PEM files under `dir`.
fn persist_identity(identity: &LocalIdentity, dir: &Path) -> Result<(), GatewayError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        GatewayError::Io(std::io::Error::new(
            e.kind(),
            format!("create cert dir {}: {e}", dir.display()),
        ))
    })?;
    let cert_pem = identity.cert_pem()?;
    let key_pem = identity.key_pem()?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert_pem).map_err(|e| {
        GatewayError::Io(std::io::Error::new(
            e.kind(),
            format!("write {}: {e}", cert_path.display()),
        ))
    })?;
    std::fs::write(&key_path, key_pem).map_err(|e| {
        GatewayError::Io(std::io::Error::new(
            e.kind(),
            format!("write {}: {e}", key_path.display()),
        ))
    })?;
    Ok(())
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
    let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()
}

/// Encode DER bytes as a PEM block with the given tag (e.g. `CERTIFICATE`).
fn encode_pem_block(der: &[u8], tag: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {tag}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {tag}-----\n"));
    pem
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_roundtrips_to_pem() {
        let id = generate_identity(&["localhost".to_string()], &["127.0.0.1".parse().unwrap()])
            .expect("generate");
        let cert_pem = id.cert_pem().expect("cert pem");
        let key_pem = id.key_pem().expect("key pem");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generate_or_load_identity_reuses_persisted_cert() {
        let dir = std::env::temp_dir().join(format!(
            "nexus-web-gateway-cert-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let names = ["localhost".to_string()];
        let ips = ["127.0.0.1".parse().unwrap()];

        let first = generate_or_load_identity(&names, &ips, Some(&dir)).expect("first");
        let second = generate_or_load_identity(&names, &ips, Some(&dir)).expect("second");

        assert_eq!(
            first.cert_der, second.cert_der,
            "certificate fingerprint must be stable across restarts"
        );
        assert_eq!(
            first.key_der, second.key_der,
            "private key must be stable across restarts"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
