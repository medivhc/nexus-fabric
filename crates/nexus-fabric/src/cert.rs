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
//! - Only the client verifies the server (S1 needs E2E encryption, not mutual
//!   auth). Server-side client authentication is future work.

use std::sync::Arc;

use quinn_proto::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider as ring_provider,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig as TlsClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use quinn_proto::{crypto::rustls::QuicClientConfig, ServerConfig};

use crate::{FabricError, PeerId};

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
    let mut spki = outer.read_seq()?;
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
    spki_ed25519_raw(spki.content)
}

// ---------------------------------------------------------------------------
// rustls verifiers
// ---------------------------------------------------------------------------

/// rustls client verifier that pins the server's certificate public key to
/// the expected [`PeerId`]. Any other key -> handshake failure.
#[derive(Debug)]
pub struct PeerPinVerifier {
    expected: [u8; 32],
}

impl PeerPinVerifier {
    pub fn new(expected: PeerId) -> Self {
        Self {
            expected: expected.0,
        }
    }

    fn peer_key(&self, cert: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
        let raw = cert_spki_ed25519_raw(cert.as_ref())
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
    ServerConfig::with_single_cert(vec![cert], key.into())
        .map_err(|e| terr(format!("quic server config: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_round_trip() {
        let id = generate_identity().expect("keygen");
        assert_ne!(id.peer_id.0, [0u8; 32]);
        // The peer id must match what our DER parser extracts from our own cert.
        let from_cert =
            cert_spki_ed25519_raw(&id.cert_der).expect("parse own cert");
        assert_eq!(from_cert, id.peer_id.0);
    }

    #[test]
    fn der_rejects_garbage() {
        assert!(cert_spki_ed25519_raw(&[]).is_err());
        assert!(cert_spki_ed25519_raw(&[0x30, 0x03, 0x01, 0x02, 0x03]).is_err());
        // A valid SPKI with the wrong OID must be rejected (algorithm confusion).
        let mut bad = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x21, 0x00];
        bad.extend_from_slice(&[0xabu8; 32]);
        assert!(spki_ed25519_raw(&bad).is_err());
    }
}

#[cfg(test)]
mod dbg_tests {
    use super::*;
    #[test]
    fn dbg_cert_walk() {
        let id = generate_identity().expect("keygen");
        let r = cert_spki_ed25519_raw(&id.cert_der);
        println!("walk result: {:?}", r.as_ref().map(|_| "ok").map_err(|e| e.clone()));
        // dump first-level structure
        let d = &id.cert_der;
        let mut p = 0;
        p += 1; // seq tag
        let (mut len, mut hlen) = (0usize, 1usize);
        if d[1] & 0x80 == 0 { len = d[1] as usize; hlen = 2; }
        else { let n = (d[1] & 0x7f) as usize; for i in 0..n { len = (len << 8) | d[2+i] as usize; } hlen = 2 + n; }
        p = hlen;
        println!("outer seq len {len}");
        for i in 0..3 {
            if p >= d.len() { break; }
            let tag = d[p];
            let (l, h) = if d[p+1] & 0x80 == 0 { (d[p+1] as usize, 2) } else {
                let n = (d[p+1] & 0x7f) as usize;
                let mut v = 0usize;
                for j in 0..n { v = (v << 8) | d[p+2+j] as usize; }
                (v, 2+n)
            };
            println!("elem {i}: tag {tag:02x} len {l}");
            p += h + l;
        }
        // tbs walk
        let mut tbs_pos = hlen;
        // skip outer seq header already; tbs is first elem: find its content start
        let (tl, th) = if d[tbs_pos+1] & 0x80 == 0 { (d[tbs_pos+1] as usize, 2) } else { (0,0) };
        println!("tbs: tag {:02x} len {tl}", d[tbs_pos]);
        let mut q = tbs_pos + th;
        for i in 0..8 {
            if q >= d.len() { break; }
            let tag = d[q];
            let (l, h) = if d[q+1] & 0x80 == 0 { (d[q+1] as usize, 2) } else {
                let n = (d[q+1] & 0x7f) as usize;
                let mut v = 0usize;
                for j in 0..n { v = (v << 8) | d[q+2+j] as usize; }
                (v, 2+n)
            };
            println!("tbs elem {i}: tag {tag:02x} len {l}");
            q += h + l;
        }
        panic!("dump done");
    }
}
