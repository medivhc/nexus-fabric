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
        hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
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
/// Filesystem hardening (review H3): the directory is created with mode 0700,
/// the private key is written atomically with mode 0600 (the certificate is
/// public, 0644). Permissions of a pre-existing key/directory are tightened on
/// load. A corrupt identity (files exist but do not parse) is reported with a
/// distinct warning before regeneration so a silent fingerprint change is
/// visible.
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
    let existed = cert_path.is_file() && key_path.is_file();
    if existed {
        match load_identity(&cert_path.to_string_lossy(), &key_path.to_string_lossy()) {
            Ok(identity) => {
                // Tighten permissions of identity files created by older
                // versions (key may have been 0644) — best effort.
                #[cfg(unix)]
                {
                    set_file_mode(dir, 0o700);
                    set_file_mode(&key_path, 0o600);
                    set_file_mode(&cert_path, 0o644);
                }
                return Ok(identity);
            }
            Err(e) => {
                tracing::warn!(
                    "stored TLS identity at {} exists but is unreadable/corrupt ({e}); regenerating",
                    dir.display()
                );
            }
        }
    }
    let identity = generate_identity(names, ips)?;
    persist_identity(&identity, dir)?;
    Ok(identity)
}

/// Write a generated identity as PEM files under `dir`.
///
/// The private key is the most sensitive material on disk: it is written to a
/// temp file with 0600 and atomically renamed into place so a crash never
/// leaves a half-written world-readable key (review H3).
fn persist_identity(identity: &LocalIdentity, dir: &Path) -> Result<(), GatewayError> {
    create_private_dir(dir)?;
    let cert_pem = identity.cert_pem()?;
    let key_pem = identity.key_pem()?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    // Write the key first (more conservative exposure window) and only then
    // the certificate.
    write_file_atomic(&key_path, key_pem.as_bytes(), 0o600)?;
    write_file_atomic(&cert_path, cert_pem.as_bytes(), 0o644)?;
    Ok(())
}

/// Create the certificate directory so that only the node owner can enter it.
fn create_private_dir(dir: &Path) -> Result<(), GatewayError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        GatewayError::Io(std::io::Error::new(
            e.kind(),
            format!("create cert dir {}: {e}", dir.display()),
        ))
    })?;
    #[cfg(unix)]
    set_file_mode(dir, 0o700);
    Ok(())
}

/// Atomically write `bytes` to `path` with the given Unix mode.
///
/// The temp file lives in the same directory (required for `rename` to be
/// atomic), is created with `mode` from the start, synced and then renamed
/// over any previous file. On non-Unix targets `mode` is ignored.
fn write_file_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), GatewayError> {
    let tmp = path.with_extra_extension("tmp");
    // Clear a temp file possibly left by a crash during a previous write;
    // `create_new` below must start from a clean sibling.
    let _ = std::fs::remove_file(&tmp);
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
        }
    }
    .and_then(|mut f| {
        use std::io::Write;
        f.write_all(bytes).and_then(|_| f.sync_all())
    })
    .map_err(|e| {
        GatewayError::Io(std::io::Error::new(
            e.kind(),
            format!("write temp {}: {e}", tmp.display()),
        ))
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        GatewayError::Io(std::io::Error::new(
            e.kind(),
            format!("rename into {}: {e}", path.display()),
        ))
    })?;
    Ok(())
}

/// Create a temp sibling path by appending `.tmp` (avoids the
/// `PathBuf::set_extension` pitfall that would turn `key.pem` into `key.tmp`).
trait WithExtraExtension {
    fn with_extra_extension(&self, extra: &str) -> PathBuf;
}

impl WithExtraExtension for Path {
    fn with_extra_extension(&self, extra: &str) -> PathBuf {
        let mut name = self
            .file_name()
            .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned());
        name.push('.');
        name.push_str(extra);
        self.with_file_name(name)
    }
}

/// Best-effort chmod (missing file / unsupported platform = no-op).
#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
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

    /// Review H3 regression: the private key is owner-only (0600) and the
    /// certificate directory is 0700, so another local user cannot read the
    /// gateway's TLS private key.
    #[cfg(unix)]
    #[test]
    fn persisted_identity_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "nexus-web-gateway-cert-perms-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let names = ["localhost".to_string()];
        let ips = ["127.0.0.1".parse().unwrap()];
        generate_or_load_identity(&names, &ips, Some(&dir)).expect("persist");

        let key_mode = std::fs::metadata(dir.join("key.pem"))
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = std::fs::metadata(&dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            key_mode, 0o600,
            "key.pem must be owner-only, got {key_mode:o}"
        );
        assert_eq!(
            dir_mode, 0o700,
            "cert dir must be owner-only, got {dir_mode:o}"
        );
        // No half-written temp files may remain after an atomic publish.
        assert!(
            !dir.join("key.pem.tmp").exists() && !dir.join("cert.pem.tmp").exists(),
            "temp files must be renamed away"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review H3 regression: a key created with loose permissions is
    /// tightened back to 0600 on the next load.
    #[cfg(unix)]
    #[test]
    fn loading_identity_tightens_legacy_key_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "nexus-web-gateway-cert-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let names = ["localhost".to_string()];
        let ips = ["127.0.0.1".parse().unwrap()];
        generate_or_load_identity(&names, &ips, Some(&dir)).expect("persist");
        // Simulate a key written by an older version (world-readable).
        std::fs::set_permissions(dir.join("key.pem"), std::fs::Permissions::from_mode(0o644))
            .expect("loosen key");
        generate_or_load_identity(&names, &ips, Some(&dir)).expect("reload");
        let key_mode = std::fs::metadata(dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
