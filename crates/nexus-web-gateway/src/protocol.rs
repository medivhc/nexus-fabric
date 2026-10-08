//! Wire protocol between the browser and a gateway node (JSON over the
//! WebRTC DataChannel), plus the mesh-internal signaling messages.
//!
//! SDP is transported as `{"type":"offer"|"answer","sdp":"<standard SDP>"}` —
//! exactly the JSON shape str0m's `SdpOffer`/`SdpAnswer` serialize to, and the
//! shape a browser can feed straight into `setRemoteDescription`.

use serde::{Deserialize, Serialize};
use str0m::change::{SdpAnswer, SdpOffer};

use crate::config::MeshNodeInfo;
use crate::error::GatewayError;

/// SDP offer/answer payload in browser-compatible JSON form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdpPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub sdp: String,
}

impl SdpPayload {
    /// Convert a str0m `SdpOffer` into the wire payload.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::Protocol` if the offer cannot be serialized.
    pub fn from_offer(offer: &SdpOffer) -> Result<Self, GatewayError> {
        serde_json::from_value(
            serde_json::to_value(offer)
                .map_err(|e| GatewayError::Protocol(format!("serialize offer: {e}")))?,
        )
        .map_err(|e| GatewayError::Protocol(format!("offer payload shape: {e}")))
    }

    /// Convert a str0m `SdpAnswer` into the wire payload.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::Protocol` if the answer cannot be serialized.
    pub fn from_answer(answer: &SdpAnswer) -> Result<Self, GatewayError> {
        serde_json::from_value(
            serde_json::to_value(answer)
                .map_err(|e| GatewayError::Protocol(format!("serialize answer: {e}")))?,
        )
        .map_err(|e| GatewayError::Protocol(format!("answer payload shape: {e}")))
    }

    /// Parse this payload as a str0m `SdpOffer`.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::Protocol` if the SDP is invalid.
    pub fn to_offer(&self) -> Result<SdpOffer, GatewayError> {
        let value = serde_json::to_value(self)
            .map_err(|e| GatewayError::Protocol(format!("serialize payload: {e}")))?;
        serde_json::from_value(value)
            .map_err(|e| GatewayError::Protocol(format!("invalid offer SDP: {e}")))
    }

    /// Parse this payload as a str0m `SdpAnswer`.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::Protocol` if the SDP is invalid.
    pub fn to_answer(&self) -> Result<SdpAnswer, GatewayError> {
        let value = serde_json::to_value(self)
            .map_err(|e| GatewayError::Protocol(format!("serialize payload: {e}")))?;
        serde_json::from_value(value)
            .map_err(|e| GatewayError::Protocol(format!("invalid answer SDP: {e}")))
    }
}

/// SSH authentication material submitted by the page (never persisted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SshAuth {
    Password { username: String, password: String },
    Key { username: String, private_key: String },
}

/// Browser → node messages (sent over the control DataChannel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrowserMessage {
    /// Announce the browser's temporary identity after the control channel opens.
    Hello {
        peer_id: String,
        #[serde(default)]
        name: String,
    },
    /// Ask the first-touch node to relay an SDP offer to another mesh node.
    RelayOffer {
        target: String,
        session_id: String,
        sdp: SdpPayload,
    },
    /// Open an SSH terminal on the node this channel is connected to.
    SshOpen {
        session_id: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<SshAuth>,
    },
    /// Terminal bytes (base64) to forward to the local sshd.
    SshData { session_id: String, data: String },
    /// Close the SSH terminal.
    SshClose { session_id: String },
}

/// Node → browser messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeMessage {
    /// Node list + ICE server configuration after the browser's hello.
    HelloAck {
        node_id: String,
        node_name: String,
        node_list: Vec<MeshNodeInfo>,
        ice_servers: Vec<crate::config::IceServer>,
    },
    /// Answer for a previously relayed offer.
    RelayAnswer {
        target: String,
        session_id: String,
        sdp: SdpPayload,
    },
    /// Relay failed.
    RelayError {
        target: String,
        session_id: String,
        error: String,
    },
    /// SSH bridge opened / rejected.
    SshOpenAck {
        session_id: String,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Bytes (base64) read from the local sshd.
    SshData { session_id: String, data: String },
    /// SSH bridge closed.
    SshClose { session_id: String, reason: String },
}

/// Mesh-internal signaling messages (between gateway nodes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MeshMessage {
    /// Forward a browser's SDP offer to the target node.
    RelayOffer {
        session_id: String,
        sdp: SdpPayload,
    },
    /// The target node's SDP answer.
    RelayAnswer {
        session_id: String,
        sdp: SdpPayload,
    },
    /// The target node failed to accept the offer.
    RelayError { session_id: String, error: String },
    /// Open an SSH terminal on the target node (data-plane peer-relay).
    SshOpen {
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<SshAuth>,
    },
    /// The target node accepted/rejected the relayed SSH terminal.
    SshOpenAck {
        session_id: String,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Bytes (base64) read from the target node's local sshd.
    SshData { session_id: String, data: String },
    /// Close the relayed SSH terminal.
    SshClose { session_id: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdp_payload_roundtrip_offer() {
        // A minimal but structurally valid offer SDP accepted by str0m's parser.
        let sdp = "v=0\r\no=- 123 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string();
        let payload = SdpPayload {
            kind: "offer".into(),
            sdp,
        };
        let offer = payload.to_offer().expect("parse offer");
        let back = SdpPayload::from_offer(&offer).expect("serialize offer");
        assert_eq!(back.kind, "offer");
        assert!(back.sdp.contains("v=0"));
    }

    #[test]
    fn sdp_payload_rejects_wrong_type() {
        let payload = SdpPayload {
            kind: "answer".into(),
            sdp: "v=0\r\n".to_string(),
        };
        assert!(payload.to_offer().is_err());
    }

    #[test]
    fn browser_message_roundtrip() {
        let msg = BrowserMessage::SshOpen {
            session_id: "s1".into(),
            target: "node-b".into(),
            auth: Some(SshAuth::Password {
                username: "root".into(),
                password: "hunter2".into(),
            }),
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: BrowserMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, msg);
    }

    #[test]
    fn node_message_roundtrip() {
        let msg = NodeMessage::SshClose {
            session_id: "s1".into(),
            reason: "idle timeout".into(),
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: NodeMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, msg);
    }

    #[test]
    fn mesh_message_roundtrip() {
        let msg = MeshMessage::RelayOffer {
            session_id: "s1".into(),
            sdp: SdpPayload {
                kind: "offer".into(),
                sdp: "v=0".into(),
            },
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: MeshMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, msg);
    }

    #[test]
    fn mesh_ssh_message_roundtrip() {
        let msg = MeshMessage::SshOpen {
            session_id: "term-1".into(),
            auth: Some(SshAuth::Password {
                username: "root".into(),
                password: "hunter2".into(),
            }),
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: MeshMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, msg);

        let data = MeshMessage::SshData {
            session_id: "term-1".into(),
            data: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(b"hello")
            },
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let back: MeshMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, data);
    }
}