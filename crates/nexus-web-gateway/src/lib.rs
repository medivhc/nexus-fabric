//! Nexus Web Gateway: browser zero-install WebRTC access to the mesh.
//!
//! Each Nexus node embeds this gateway: an HTTPS service (page + WSS signaling)
//! plus a node-side WebRTC endpoint. A browser opens
//! `https://<node-address>/`, generates an in-memory temporary identity, joins
//! the first-touch node over WSS + RTCPeerConnection/DataChannel, receives the
//! mesh node list, and connects to every other node by relaying SDP offers
//! through the already-established mesh (no external signaling service).
//!
//! MVP service: a web SSH terminal — browser DataChannel → target node →
//! local sshd (TCP forward).
//!
//! The crate is std-only (no async runtime), matching the repository posture.

#![forbid(unsafe_code)]

pub mod cert;
pub mod config;
pub mod error;
pub mod file;
pub mod gateway;
pub mod http;
pub mod mesh;
pub mod protocol;
pub mod ssh_client;

pub use config::{
    FileConfig, FileRoot, GatewayConfig, IceServer, MeshNodeInfo, SshConfig, TlsConfig,
};
pub use error::GatewayError;
pub use file::{FileBackend, FileCommand, FileLimits, FileReply, LocalSandbox, SftpBackend};
pub use gateway::{Gateway, GatewayHandle};
pub use protocol::{BrowserMessage, FileEntry, FileTarget, NodeMessage, SdpPayload, SshAuth};
