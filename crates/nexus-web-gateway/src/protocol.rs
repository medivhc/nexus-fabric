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
    Password {
        username: String,
        password: String,
    },
    Key {
        username: String,
        private_key: String,
    },
}

/// Where a file session reads and writes (REQ-005 / REQ-008).
///
/// `sftp` reuses the node-side SSH client: the node authenticates to the target
/// sshd with the browser's in-memory credentials and runs the SFTP subsystem,
/// so the gateway node never exposes its own filesystem unless an operator
/// explicitly configures a `local` root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileTarget {
    /// SFTP subsystem of the node's configured SSH target (`ssh.target`).
    Sftp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<SshAuth>,
    },
    /// A node-local sandbox root, selected by its configured name.
    Local { root: String },
}

/// One directory entry, as reported by either backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Base name (no separators).
    pub name: String,
    /// Root-relative path, `/`-separated.
    pub path: String,
    /// `file` | `dir` | `symlink` | `other`.
    pub kind: String,
    pub size: u64,
    /// Modification time in Unix seconds (`0` when the backend cannot report it).
    pub mtime: i64,
    /// Permission bits (`0` when unknown).
    pub mode: u32,
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
    /// Open a file session against a target (REQ-005). The bearer `token` is
    /// required whenever the file module is enabled (fail-closed, G12).
    FileOpen {
        session_id: String,
        token: String,
        target: FileTarget,
    },
    /// List a directory (`""` or `/` means the session root).
    FileList { session_id: String, path: String },
    /// Stat a single entry.
    FileStat { session_id: String, path: String },
    /// Request `len` bytes at `offset` of `path`. The answer arrives as a binary
    /// frame on the file DataChannel: reads are pull-based, so the browser paces
    /// the transfer and can resume at any offset.
    FileRead {
        session_id: String,
        stream_id: u32,
        path: String,
        offset: u64,
        len: u32,
    },
    /// Begin an upload of `path`; the bytes then arrive as binary frames.
    FileWriteBegin {
        session_id: String,
        stream_id: u32,
        path: String,
    },
    /// Finish an upload: the staged `.part` file is moved into place (G14).
    FileWriteEnd {
        session_id: String,
        stream_id: u32,
        path: String,
    },
    /// Create a directory.
    FileMkdir { session_id: String, path: String },
    /// Remove a file, or a directory when `recursive`.
    FileRemove {
        session_id: String,
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    /// Rename or move within the session's root.
    FileRename {
        session_id: String,
        from: String,
        to: String,
    },
    /// Close the file session.
    FileClose { session_id: String },
    /// Heartbeat ping message.
    Ping,
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
    /// File session opened (or refused). `kind` echoes the backend (`sftp` /
    /// `local`), `roots` lists the configured local root names.
    FileOpenAck {
        session_id: String,
        kind: String,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        chunk_bytes: u32,
        roots: Vec<String>,
    },
    /// Directory listing.
    FileListAck {
        session_id: String,
        path: String,
        entries: Vec<FileEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Single entry stat.
    FileStatAck {
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entry: Option<FileEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Upload progress: `received` bytes are durably staged, so the browser can
    /// resume from that offset.
    FileWriteAck {
        session_id: String,
        stream_id: u32,
        received: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Ack for mkdir / remove / rename; `op` echoes the operation name.
    FileOpAck {
        session_id: String,
        op: String,
        path: String,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// File session closed.
    FileClosed { session_id: String, reason: String },
    /// Heartbeat pong message.
    Pong,
}

/// Mesh-internal signaling messages (between gateway nodes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MeshMessage {
    /// Forward a browser's SDP offer to the target node.
    RelayOffer { session_id: String, sdp: SdpPayload },
    /// The target node's SDP answer.
    RelayAnswer { session_id: String, sdp: SdpPayload },
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

        let ping = BrowserMessage::Ping;
        let ping_json = serde_json::to_string(&ping).expect("serialize ping");
        let ping_back: BrowserMessage = serde_json::from_str(&ping_json).expect("deserialize ping");
        assert_eq!(ping_back, ping);
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

        let pong = NodeMessage::Pong;
        let pong_json = serde_json::to_string(&pong).expect("serialize pong");
        let pong_back: NodeMessage = serde_json::from_str(&pong_json).expect("deserialize pong");
        assert_eq!(pong_back, pong);
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

    #[test]
    fn file_messages_roundtrip() {
        let open_sftp = BrowserMessage::FileOpen {
            session_id: "fs-1".into(),
            token: "bearer".into(),
            target: FileTarget::Sftp {
                auth: Some(SshAuth::Password {
                    username: "root".into(),
                    password: "hunter2".into(),
                }),
            },
        };
        let json = serde_json::to_string(&open_sftp).expect("serialize");
        assert_eq!(
            serde_json::from_str::<BrowserMessage>(&json).expect("deserialize"),
            open_sftp
        );

        let open_local = BrowserMessage::FileOpen {
            session_id: "fs-2".into(),
            token: "bearer".into(),
            target: FileTarget::Local {
                root: "downloads".into(),
            },
        };
        let json = serde_json::to_string(&open_local).expect("serialize");
        assert_eq!(
            serde_json::from_str::<BrowserMessage>(&json).expect("deserialize"),
            open_local
        );

        for msg in [
            BrowserMessage::FileRead {
                session_id: "fs-1".into(),
                stream_id: 7,
                path: "/a/b.bin".into(),
                offset: 4096,
                len: 65536,
            },
            BrowserMessage::FileWriteBegin {
                session_id: "fs-1".into(),
                stream_id: 8,
                path: "/up.log".into(),
            },
            BrowserMessage::FileRemove {
                session_id: "fs-1".into(),
                path: "/tmp-dir".into(),
                recursive: true,
            },
            BrowserMessage::FileRename {
                session_id: "fs-1".into(),
                from: "/a".into(),
                to: "/b".into(),
            },
            BrowserMessage::FileClose {
                session_id: "fs-1".into(),
            },
        ] {
            let json = serde_json::to_string(&msg).expect("serialize");
            assert_eq!(
                serde_json::from_str::<BrowserMessage>(&json).expect("deserialize"),
                msg,
                "{json}"
            );
        }

        let list = NodeMessage::FileListAck {
            session_id: "fs-1".into(),
            path: "/".into(),
            entries: vec![FileEntry {
                name: "a.txt".into(),
                path: "/a.txt".into(),
                kind: "file".into(),
                size: 12,
                mtime: 1_700_000_000,
                mode: 0o644,
            }],
            error: None,
        };
        let json = serde_json::to_string(&list).expect("serialize");
        assert_eq!(
            serde_json::from_str::<NodeMessage>(&json).expect("deserialize"),
            list
        );

        for msg in [
            NodeMessage::FileOpenAck {
                session_id: "fs-1".into(),
                kind: "local".into(),
                status: "ok".into(),
                error: None,
                chunk_bytes: 65536,
                roots: vec!["downloads".into()],
            },
            NodeMessage::FileWriteAck {
                session_id: "fs-1".into(),
                stream_id: 8,
                received: 131072,
                error: None,
            },
            NodeMessage::FileOpAck {
                session_id: "fs-1".into(),
                op: "mkdir".into(),
                path: "/new".into(),
                ok: false,
                error: Some("read-only root".into()),
            },
            NodeMessage::FileClosed {
                session_id: "fs-1".into(),
                reason: "client closed".into(),
            },
        ] {
            let json = serde_json::to_string(&msg).expect("serialize");
            assert_eq!(
                serde_json::from_str::<NodeMessage>(&json).expect("deserialize"),
                msg,
                "{json}"
            );
        }
    }

    /// The wire format is a published contract: tag names are snake_case and the
    /// file target is internally tagged on `kind`.
    #[test]
    fn file_wire_format_is_stable() {
        let msg = BrowserMessage::FileOpen {
            session_id: "fs-1".into(),
            token: "bearer".into(),
            target: FileTarget::Local {
                root: "downloads".into(),
            },
        };
        let value = serde_json::to_value(&msg).expect("to_value");
        assert_eq!(
            value,
            serde_json::json!({
                "type": "file_open",
                "session_id": "fs-1",
                "token": "bearer",
                "target": { "kind": "local", "root": "downloads" },
            })
        );

        let read = serde_json::to_value(BrowserMessage::FileRead {
            session_id: "fs-1".into(),
            stream_id: 7,
            path: "/a".into(),
            offset: 0,
            len: 1024,
        })
        .expect("serialize read");
        assert_eq!(read["type"], "file_read");
        assert_eq!(read["stream_id"], 7);
    }
}
