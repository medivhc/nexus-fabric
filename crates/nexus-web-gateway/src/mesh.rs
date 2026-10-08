//! Mesh signaling: forwarding browser SDP offers/answers between gateway nodes.
//!
//! The production mesh forwards this over the existing Nexus fabric FIB. The
//! `MeshSignaler` trait is the seam: the gateway only depends on the trait, so
//! a `nexus-fabric`-backed implementation can be added later without touching
//! the gateway. Two backends ship with the MVP:
//!
//! - [`InMemoryMeshSignaler`]: in-process registry, used by tests and when
//!   multiple gateways run in one process.
//! - [`WssMeshSignaler`]: relays through each peer's gateway `/mesh` WSS
//!   endpoint (bearer-token protected, TLS end-to-end).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme, crypto};
use tungstenite::client::IntoClientRequest;

use crate::error::GatewayError;
use crate::protocol::{MeshMessage, SdpPayload};

/// TLS stream used by the mesh WSS client.
type MeshTlsStream = rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>;

/// A mesh signaling backend.
pub trait MeshSignaler: Send + Sync {
    /// Forward a browser's SDP offer to `target` and return the node's SDP answer.
    fn relay_offer(
        &self,
        target: &str,
        session_id: &str,
        sdp: &SdpPayload,
    ) -> Result<SdpPayload, GatewayError>;

    /// Register the local gateway's offer handler under `peer_id`.
    ///
    /// Only the in-memory backend supports dynamic registration; other backends
    /// return a `Mesh` error by default.
    fn register_offer_handler(
        &self,
        _peer_id: String,
        _handler: MeshOfferHandler,
    ) -> Result<(), GatewayError> {
        Err(GatewayError::Mesh(
            "this mesh backend does not support dynamic handler registration".into(),
        ))
    }
}

/// Handler registered by a gateway to answer relayed offers.
pub type MeshOfferHandler =
    Arc<dyn Fn(&str, &SdpPayload) -> Result<SdpPayload, GatewayError> + Send + Sync>;

/// In-process mesh signaling registry (multiple gateways in one process).
#[derive(Clone, Default)]
pub struct InMemoryMeshSignaler {
    handlers: Arc<Mutex<HashMap<String, MeshOfferHandler>>>,
}

impl InMemoryMeshSignaler {
    /// Create an empty in-memory mesh registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the local gateway's offer handler under `peer_id`.
    pub fn register(&self, peer_id: String, handler: MeshOfferHandler) {
        self.handlers.lock().expect("mesh lock").insert(peer_id, handler);
    }
}

impl MeshSignaler for InMemoryMeshSignaler {
    fn relay_offer(
        &self,
        target: &str,
        session_id: &str,
        sdp: &SdpPayload,
    ) -> Result<SdpPayload, GatewayError> {
        let handler = self
            .handlers
            .lock()
            .expect("mesh lock")
            .get(target)
            .cloned()
            .ok_or_else(|| {
                GatewayError::Mesh(format!("no in-memory handler for peer {target}"))
            })?;
        handler(session_id, sdp)
    }

    fn register_offer_handler(
        &self,
        peer_id: String,
        handler: MeshOfferHandler,
    ) -> Result<(), GatewayError> {
        self.register(peer_id, handler);
        Ok(())
    }
}

/// Permissive TLS verifier for the MVP mesh WSS client.
///
/// The production mesh will pin the peer's node certificate (PeerId). The MVP
/// accepts any certificate so mesh peers can be brought up without a shared CA;
/// this is acceptable for the temporary-identity/VPN phase and is explicitly a
/// placeholder (see MODULE.md invariants).
#[derive(Debug)]
struct PermissiveVerifier {
    provider: Arc<crypto::CryptoProvider>,
}

impl ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn ring_provider() -> Arc<crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a permissive rustls client config (MVP mesh peer).
fn permissive_client_config() -> ClientConfig {
    let provider = ring_provider();
    let verifier = Arc::new(PermissiveVerifier {
        provider: provider.clone(),
    });
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Connect to a peer's `/mesh` WSS endpoint.
///
/// # Errors
///
/// Returns `GatewayError::WebSocket`/`GatewayError::Io` on connection failure.
fn connect_mesh_ws(
    url: &str,
    token: &str,
) -> Result<tungstenite::WebSocket<MeshTlsStream>, GatewayError> {
    use rustls::pki_types::ServerName as TlsServerName;
    use std::net::TcpStream;
    use tungstenite::protocol::WebSocketConfig;

    let mut request = url
        .into_client_request()
        .map_err(|e| GatewayError::WebSocket(format!("bad mesh url {url}: {e}")))?;
    let host = request
        .uri()
        .host()
        .ok_or_else(|| GatewayError::WebSocket(format!("mesh url has no host: {url}")))?
        .to_string();
    let port = request
        .uri()
        .port_u16()
        .ok_or_else(|| GatewayError::WebSocket(format!("mesh url has no port: {url}")))?;

    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|e| GatewayError::WebSocket(format!("bad token header: {e}")))?,
    );

    let tcp = TcpStream::connect((host.as_str(), port)).map_err(|e| GatewayError::Io(e))?;
    let sni = TlsServerName::try_from(host.clone())
        .map_err(|e| GatewayError::WebSocket(format!("bad server name {host}: {e}")))?;
    let conn = rustls::ClientConnection::new(
        Arc::new(permissive_client_config()),
        sni,
    )
    .map_err(|e| GatewayError::WebSocket(e.to_string()))?;
    let tls = rustls::StreamOwned::new(conn, tcp);

    let ws = tungstenite::client::client_with_config(
        request,
        tls,
        Some(WebSocketConfig::default()),
    )
    .map_err(|e| GatewayError::WebSocket(format!("mesh ws handshake: {e}")))?
    .0;

    Ok(ws)
}

/// Mesh signaling relayed through peer gateways' `/mesh` WSS endpoints.
pub struct WssMeshSignaler {
    peers: HashMap<String, (String, String)>, // peer_id -> (url, token)
}

impl WssMeshSignaler {
    /// Create from a list of `(peer_id, wss_url, token)` tuples.
    pub fn new(peers: impl IntoIterator<Item = (String, String, String)>) -> Self {
        let peers = peers
            .into_iter()
            .map(|(id, url, token)| (id, (url, token)))
            .collect();
        Self { peers }
    }
}

impl MeshSignaler for WssMeshSignaler {
    fn relay_offer(
        &self,
        target: &str,
        session_id: &str,
        sdp: &SdpPayload,
    ) -> Result<SdpPayload, GatewayError> {
        let (url, token) = self
            .peers
            .get(target)
            .cloned()
            .ok_or_else(|| GatewayError::Mesh(format!("no mesh peer {target}")))?;

        let mut ws = connect_mesh_ws(&url, &token)?;
        let request = MeshMessage::RelayOffer {
            session_id: session_id.to_string(),
            sdp: sdp.clone(),
        };
        ws.send(tungstenite::Message::Text(
            serde_json::to_string(&request)
                .map_err(|e| GatewayError::Protocol(e.to_string()))?,
        ))
        .map_err(|e| GatewayError::WebSocket(e.to_string()))?;

        // Read until we get the matching answer (or an error).
        loop {
            let msg = ws
                .read()
                .map_err(|e| GatewayError::WebSocket(format!("mesh read: {e}")))?;
            match msg {
                tungstenite::Message::Text(text) => {
                    let parsed: MeshMessage = serde_json::from_str(&text)
                        .map_err(|e| GatewayError::Protocol(format!("mesh message: {e}")))?;
                    match parsed {
                        MeshMessage::RelayAnswer {
                            session_id: sid,
                            sdp: answer_sdp,
                        } if sid == session_id => return Ok(answer_sdp),
                        MeshMessage::RelayError {
                            session_id: sid,
                            error,
                        } if sid == session_id => {
                            return Err(GatewayError::Mesh(format!(
                                "target node {target}: {error}"
                            )));
                        }
                        _ => continue,
                    }
                }
                tungstenite::Message::Close(_) => {
                    return Err(GatewayError::Mesh(format!(
                        "mesh peer {target} closed connection"
                    )));
                }
                _ => continue,
            }
        }
    }
}