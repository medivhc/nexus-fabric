//! ed25519 endpoint identity and TLS peer authentication.
//!
//! Each endpoint owns an ed25519 keypair; the [`PeerId`] is the raw 32-byte
//! public key. A self-signed certificate binds the key for the TLS 1.3
//! handshake, and a custom rustls verifier pins the presented certificate's
//! public key to the expected [`PeerId`] (iroh-style). No X.509 parsing
//! dependency: a minimal DER reader extracts the SubjectPublicKeyInfo from
//! certificates we generate.
//!
//! Security notes (P0):
//! - The TLS handshake's CertificateVerify already proves possession of the
//!   private key; pinning the SPKI to the expected PeerId is what authenticates
//!   the peer. A mismatched key fails the handshake -> [`FabricError::HandshakeFailed`].
//! - Legacy endpoints authenticate only the server. Opt-in mutual TLS requires
//!   client CertificateVerify and an explicit public-key allowlist.

use std::sync::Arc;

use quinn_proto::rustls::{
    self, ClientConfig as TlsClientConfig, DigitallySignedStruct, DistinguishedName,
    Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider as ring_provider,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use quinn_proto::{ServerConfig, TransportConfig, crypto::rustls::QuicClientConfig};

use crate::{FabricError, PeerId};
#[path = "cert_strict.rs"]
mod strict;
use strict::strict_cert_peer;

/// Endpoint identity: ed25519 keypair plus a self-signed cert binding it.
pub struct Identity {
    pub peer_id: PeerId,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>, // PKCS#8
}

fn terr(msg: String) -> FabricError {
    FabricError::Transport(msg)
}

/// Generate a fresh ed25519 identity with a self-signed certificate.
pub fn generate_identity() -> Result<Identity, FabricError> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| terr(format!("ed25519 keygen failed: {e:?}")))?;
    let raw = spki_ed25519_raw(&kp.public_key_der()).map_err(terr)?;
    let cert = rcgen::CertificateParams::default()
        .self_signed(&kp)
        .map_err(|e| terr(format!("self-signed cert failed: {e:?}")))?;
    Ok(Identity {
        peer_id: PeerId(raw),
        cert_der: cert.der().to_vec(),
        key_der: kp.serialize_der(),
    })
}

/// Explicit Ed25519 identity for mutual TLS; secret material stays private.
pub struct FabricIdentity {
    pub(crate) inner: Identity,
}

impl std::fmt::Debug for FabricIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FabricIdentity")
            .field("peer_id", &self.peer_id())
            .finish_non_exhaustive()
    }
}

impl FabricIdentity {
    /// Import an Ed25519 seed. This does not persist or enroll the identity.
    pub fn from_ed25519_seed(seed: [u8; 32]) -> Result<Self, FabricError> {
        // RFC 8410 PKCS#8 v1: the privateKey contains a nested 32-byte OCTET STRING.
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&seed);
        let key = PrivatePkcs8KeyDer::from(der);
        let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)
            .map_err(|_| terr("invalid Ed25519 identity".into()))?;
        let peer_id = PeerId(spki_ed25519_raw(&kp.public_key_der()).map_err(terr)?);
        let cert = rcgen::CertificateParams::default()
            .self_signed(&kp)
            .map_err(|_| terr("cannot construct Ed25519 identity certificate".into()))?;
        Ok(Self {
            inner: Identity {
                peer_id,
                cert_der: cert.der().to_vec(),
                key_der: kp.serialize_der(),
            },
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id
    }
}

// ---------------------------------------------------------------------------
// Minimal DER reader (RFC 5280 framing only; fail-closed on anything odd)
// ---------------------------------------------------------------------------

struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

impl<'a> Der<'a> {
    fn read_tlv(&mut self) -> Result<Tlv<'a>, String> {
        let tag = *self.data.get(self.pos).ok_or("DER: eof at tag")?;
        self.pos += 1;
        let len_byte = *self.data.get(self.pos).ok_or("DER: eof at length")?;
        self.pos += 1;
        let len = if len_byte & 0x80 == 0 {
            len_byte as usize
        } else {
            let nbytes = (len_byte & 0x7f) as usize;
            if nbytes == 0 || nbytes > 4 {
                return Err("DER: bad long-form length".into());
            }
            let mut v = 0usize;
            for _ in 0..nbytes {
                let b = *self.data.get(self.pos).ok_or("DER: eof in length")?;
                self.pos += 1;
                v = (v << 8) | b as usize;
            }
            v
        };
        let end = self.pos.checked_add(len).ok_or("DER: length overflow")?;
        let content = self.data.get(self.pos..end).ok_or("DER: eof in content")?;
        self.pos = end;
        Ok(Tlv { tag, content })
    }

    fn read_seq(&mut self) -> Result<Der<'a>, String> {
        let t = self.read_tlv()?;
        if t.tag != 0x30 {
            return Err("DER: expected SEQUENCE".into());
        }
        Ok(Der {
            data: t.content,
            pos: 0,
        })
    }

    fn exhausted(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// OID 1.3.101.112 (Ed25519), DER-encoded (tag + length + value).
const ED25519_OID_TLV: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// Parse a SubjectPublicKeyInfo DER and return the raw 32-byte ed25519 key.
fn spki_ed25519_raw(spki_der: &[u8]) -> Result<[u8; 32], String> {
    let mut outer = Der {
        data: spki_der,
        pos: 0,
    };
    let spki = outer.read_seq()?;
    spki_content_ed25519_raw(spki.data)
}

/// Parse the *content* of a SubjectPublicKeyInfo SEQUENCE (outer tag already
/// consumed).
fn spki_content_ed25519_raw(content: &[u8]) -> Result<[u8; 32], String> {
    let mut spki = Der {
        data: content,
        pos: 0,
    };
    let mut alg = spki.read_seq()?;
    let oid = alg.read_tlv()?;
    if oid.tag != 0x06 || oid.content != &ED25519_OID_TLV[2..] {
        return Err("SPKI: not Ed25519".into());
    }
    if !alg.exhausted() {
        return Err("SPKI: unexpected algorithm parameters".into());
    }
    let key = spki.read_tlv()?;
    if key.tag != 0x03 {
        return Err("SPKI: expected BIT STRING".into());
    }
    if key.content.len() != 33 || key.content[0] != 0x00 {
        return Err("SPKI: bad Ed25519 key length".into());
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&key.content[1..]);
    Ok(raw)
}

/// Extract the raw ed25519 public key from a DER X.509 certificate.
///
/// Walks the fixed RFC 5280 element order
/// (tbs -> [version] -> serial -> sig-alg -> issuer -> validity -> subject -> SPKI).
/// Anything unexpected -> Err (fail closed; caller turns it into handshake failure).
fn cert_spki_ed25519_raw(cert_der: &[u8]) -> Result<[u8; 32], String> {
    let mut outer = Der {
        data: cert_der,
        pos: 0,
    };
    let mut cert = outer.read_seq()?;
    let mut tbs = cert.read_seq()?;
    // Optional [0] EXPLICIT version.
    if tbs.data.get(tbs.pos) == Some(&0xA0) {
        tbs.read_tlv()?;
    }
    tbs.read_tlv()?; // serialNumber INTEGER
    tbs.read_seq()?; // signature AlgorithmIdentifier
    tbs.read_seq()?; // issuer Name
    tbs.read_seq()?; // validity
    tbs.read_seq()?; // subject Name
    let spki = tbs.read_tlv()?; // subjectPublicKeyInfo
    if spki.tag != 0x30 {
        return Err("cert: expected SPKI SEQUENCE".into());
    }
    spki_content_ed25519_raw(spki.content)
}

// ---------------------------------------------------------------------------
// rustls verifiers
// ---------------------------------------------------------------------------

/// rustls client verifier that pins the server's certificate public key to
/// the expected [`PeerId`]. Any other key -> handshake failure.
#[derive(Debug)]
pub struct PeerPinVerifier {
    expected: [u8; 32],
    strict: bool,
}

impl PeerPinVerifier {
    pub fn new(expected: PeerId) -> Self {
        Self {
            expected: expected.0,
            strict: false,
        }
    }

    fn peer_key(&self, cert: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
        let raw = if self.strict {
            strict_cert_peer(cert.as_ref())
        } else {
            cert_spki_ed25519_raw(cert.as_ref())
        }
        .map_err(|_| TlsError::General("peer cert: cannot extract Ed25519 key".into()))?;
        if raw != self.expected {
            return Err(TlsError::General("peer id mismatch".into()));
        }
        Ok(raw)
    }

    fn verify_sig(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(TlsError::General("unexpected signature scheme".into()));
        }
        let raw = self.peer_key(cert)?;
        let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, raw);
        key.verify(message, dss.signature())
            .map_err(|_| TlsError::General("bad handshake signature".into()))?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for PeerPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.peer_key(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verify_sig(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verify_sig(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Mandatory client CertificateVerify plus explicit public-key admission.
#[derive(Debug)]
struct ClientPeerVerifier {
    allowed: Vec<PeerId>,
}

impl ClientPeerVerifier {
    fn pin(&self, cert: &CertificateDer<'_>) -> Result<PeerPinVerifier, TlsError> {
        let key = strict_cert_peer(cert.as_ref())
            .map_err(|_| TlsError::General("invalid client Ed25519 certificate".into()))?;
        let peer = PeerId(key);
        if !self.allowed.contains(&peer) {
            return Err(TlsError::General("client peer is not allowed".into()));
        }
        Ok(PeerPinVerifier {
            expected: peer.0,
            strict: true,
        })
    }
}

impl ClientCertVerifier for ClientPeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::General(
                "unexpected client certificate chain".into(),
            ));
        }
        self.pin(cert)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.pin(cert)?.verify_sig(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.pin(cert)?.verify_sig(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub(crate) fn build_mtls_client_crypto(
    expected: PeerId,
    id: &FabricIdentity,
) -> Result<QuicClientConfig, FabricError> {
    let mut cfg = TlsClientConfig::builder_with_provider(Arc::new(ring_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| terr("TLS1.3 unavailable".into()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerPinVerifier {
            expected: expected.0,
            strict: true,
        }))
        .with_client_auth_cert(
            vec![CertificateDer::from(id.inner.cert_der.clone())],
            PrivatePkcs8KeyDer::from(id.inner.key_der.clone()).into(),
        )
        .map_err(|_| terr("invalid client identity".into()))?;
    cfg.enable_early_data = false;
    cfg.resumption = rustls::client::Resumption::disabled();
    QuicClientConfig::try_from(cfg).map_err(|_| terr("invalid TLS1.3 client config".into()))
}

pub(crate) fn build_mtls_server_config(
    id: &FabricIdentity,
    allowed: &[PeerId],
) -> Result<ServerConfig, FabricError> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(ring_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| terr("TLS1.3 unavailable".into()))?
        .with_client_cert_verifier(Arc::new(ClientPeerVerifier {
            allowed: allowed.to_vec(),
        }))
        .with_single_cert(
            vec![CertificateDer::from(id.inner.cert_der.clone())],
            PrivatePkcs8KeyDer::from(id.inner.key_der.clone()).into(),
        )
        .map_err(|_| terr("invalid server identity".into()))?;
    cfg.max_early_data_size = 0;
    cfg.send_tls13_tickets = 0;
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(cfg)
        .map_err(|_| terr("invalid TLS1.3 server config".into()))?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(quic_transport_config());
    Ok(server)
}

pub(crate) fn verified_connection_peer(
    conn: &quinn_proto::Connection,
) -> Result<PeerId, FabricError> {
    let certs = conn
        .crypto_session()
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or(FabricError::HandshakeFailed(
            "mutual authentication incomplete".into(),
        ))?;
    if certs.len() != 1 {
        return Err(FabricError::HandshakeFailed(
            "mutual authentication incomplete".into(),
        ));
    }
    strict_cert_peer(certs[0].as_ref())
        .map(PeerId)
        .map_err(|_| FabricError::HandshakeFailed("mutual authentication incomplete".into()))
}

/// Build the QUIC transport config shared by client and server endpoints.
///
/// Enables unreliable datagram support (S5): without
/// `datagram_receive_buffer_size` quinn-proto negotiates
/// `max_datagram_frame_size = 0` and every `datagrams().send()` fails with
/// `Disabled`/`UnsupportedByPeer`, which the driver silently drops. The
/// 1 MiB buffer holds ~850 max-size (1200 B) datagrams.
pub fn quic_transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.datagram_receive_buffer_size(Some(1024 * 1024));
    Arc::new(t)
}

/// Build the QUIC client crypto config: TLS 1.3, peer-key pinning, no client auth (P0).
pub fn build_client_crypto(expected: PeerId) -> Result<QuicClientConfig, FabricError> {
    let provider = Arc::new(ring_provider());
    let verifier = Arc::new(PeerPinVerifier::new(expected));
    let cfg = TlsClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| terr(format!("TLS 1.3 unavailable: {e:?}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    QuicClientConfig::try_from(cfg).map_err(|e| terr(format!("quic client crypto: {e:?}")))
}

/// Build the QUIC server config: TLS 1.3, self-signed identity cert.
/// P0: no client authentication (server accepts any peer; see module docs).
pub fn build_server_config(id: &Identity) -> Result<ServerConfig, FabricError> {
    let cert = CertificateDer::from(id.cert_der.clone());
    let key = PrivatePkcs8KeyDer::from(id.key_der.clone());
    let mut cfg = ServerConfig::with_single_cert(vec![cert], key.into())
        .map_err(|e| terr(format!("quic server config: {e:?}")))?;
    cfg.transport_config(quic_transport_config());
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_certificate_requires_its_actual_ed25519_signature() {
        use ring::signature::Ed25519KeyPair;
        use rustls::internal::msgs::codec::{Codec, Reader};
        let id = FabricIdentity::from_ed25519_seed([47; 32]).unwrap();
        let cert = CertificateDer::from(id.inner.cert_der.clone());
        let verifier = ClientPeerVerifier {
            allowed: vec![id.peer_id()],
        };
        let message = b"TLS 1.3 CertificateVerify test transcript";
        let sign = |seed: u8, scheme: u16| {
            let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
            let signature = key.sign(message);
            let mut encoded = scheme.to_be_bytes().to_vec();
            encoded.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
            encoded.extend_from_slice(signature.as_ref());
            DigitallySignedStruct::read(&mut Reader::init(&encoded)).unwrap()
        };
        let valid = sign(47, 0x0807);
        assert!(
            verifier
                .verify_tls13_signature(message, &cert, &valid)
                .is_ok()
        );
        // An admitted certificate without the matching private key is insufficient.
        assert!(
            verifier
                .verify_tls13_signature(message, &cert, &sign(48, 0x0807))
                .is_err()
        );
        assert!(
            verifier
                .verify_tls13_signature(b"changed transcript", &cert, &valid)
                .is_err()
        );
        assert!(
            verifier
                .verify_tls13_signature(message, &cert, &sign(47, 0x0804))
                .is_err()
        );
        assert!(
            ClientPeerVerifier { allowed: vec![] }
                .verify_tls13_signature(message, &cert, &valid)
                .is_err()
        );
    }

    #[test]
    fn allowlisted_key_embedded_in_extensions_does_not_replace_actual_spki() {
        let admitted = FabricIdentity::from_ed25519_seed([51; 32]).unwrap();
        let foreign = FabricIdentity::from_ed25519_seed([52; 32]).unwrap();
        let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(foreign.inner.key_der.clone()),
            &rcgen::PKCS_ED25519,
        )
        .unwrap();
        let mut fake_spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0,
        ];
        fake_spki.extend_from_slice(&admitted.peer_id().0);
        let mut params = rcgen::CertificateParams::default();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 2, 3, 4],
                fake_spki,
            ));
        let certificate = params.self_signed(&key).unwrap();
        let cert = CertificateDer::from(certificate.der().to_vec());
        assert_eq!(
            strict_cert_peer(cert.as_ref()).unwrap(),
            foreign.peer_id().0
        );
        let verifier = ClientPeerVerifier {
            allowed: vec![admitted.peer_id()],
        };
        assert!(
            verifier
                .verify_client_cert(
                    &cert,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1))
                )
                .is_err()
        );
    }

    #[test]
    fn spki_round_trip() {
        let id = generate_identity().expect("keygen");
        assert_ne!(id.peer_id.0, [0u8; 32]);
        // The peer id must match what our DER parser extracts from our own cert.
        let from_cert = cert_spki_ed25519_raw(&id.cert_der).expect("parse own cert");
        assert_eq!(from_cert, id.peer_id.0);
    }

    #[test]
    fn der_rejects_garbage() {
        assert!(cert_spki_ed25519_raw(&[]).is_err());
        assert!(cert_spki_ed25519_raw(&[0x30, 0x03, 0x01, 0x02, 0x03]).is_err());
        // A valid SPKI with the wrong OID must be rejected (algorithm confusion).
        let mut bad = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x21, 0x00,
        ];
        bad.extend_from_slice(&[0xabu8; 32]);
        assert!(spki_ed25519_raw(&bad).is_err());
    }
}
