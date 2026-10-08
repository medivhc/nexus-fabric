//! Gateway configuration types and JSON loading.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;

/// Default SSH target: local sshd.
pub const DEFAULT_SSH_TARGET: &str = "127.0.0.1:22";
/// Default per-session concurrent terminal limit.
pub const DEFAULT_MAX_TERMINALS: usize = 5;
/// Default idle timeout for an SSH terminal.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;

/// A mesh node as exposed to the browser (PeerId, candidate addresses, service directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshNodeInfo {
    /// Ed25519 public key of the node (hex), used as stable identifier.
    pub peer_id: String,
    /// Human readable node name.
    pub name: String,
    /// Candidate addresses of the node's web gateway (host:port), in preference order.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// Service directory entries exposed by the node, e.g. `["ssh"]`.
    #[serde(default)]
    pub services: Vec<String>,
}

/// An ICE server configuration handed to the browser (`stun:` / `turn:` URLs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// TLS material source for the HTTPS/WSS server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsConfig {
    /// Generate a self-signed local-CA certificate at startup for the given
    /// DNS names and IP addresses (recommended for LAN/VPN mesh IPs).
    AutoGenerate {
        #[serde(default)]
        names: Vec<String>,
        #[serde(default)]
        ips: Vec<IpAddr>,
    },
    /// Load an existing certificate chain + private key from PEM files.
    Files {
        cert_path: String,
        key_path: String,
    },
}

/// SSH terminal bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfig {
    /// TCP target the DataChannel bytes are forwarded to (the node's local sshd).
    #[serde(default = "default_ssh_target")]
    pub target: SocketAddr,
    /// Optional prologue sent as the first bytes on the TCP connection.
    ///
    /// `{username}`, `{password}` and `{private_key}` are substituted from the
    /// browser's `ssh_open` auth payload. This is used by the mock-sshd test
    /// harness; a real sshd requires `None` (pure byte forwarding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_prologue: Option<String>,
    /// Maximum concurrent terminals per browser session.
    #[serde(default = "default_max_terminals")]
    pub max_terminals: usize,
    /// Idle timeout (seconds) after which a terminal is disconnected.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_ssh_target() -> SocketAddr {
    DEFAULT_SSH_TARGET.parse().expect("static default")
}

fn default_max_terminals() -> usize {
    DEFAULT_MAX_TERMINALS
}

fn default_idle_timeout_secs() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            target: default_ssh_target(),
            auth_prologue: None,
            max_terminals: default_max_terminals(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

/// Mesh signaling backend configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MeshConfig {
    /// No external mesh; used by tests that wire gateways in-process.
    InMemory,
    /// Relay signaling through each peer's gateway over WSS.
    Wss {
        #[serde(default)]
        peers: Vec<MeshPeer>,
    },
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self::InMemory
    }
}

/// A mesh peer gateway for WSS signaling relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeer {
    /// Peer node id (`MeshNodeInfo.peer_id` of the target).
    pub peer_id: String,
    /// `wss://host:port/mesh` URL of the peer's gateway.
    pub url: String,
    /// Shared bearer token protecting the mesh endpoint.
    pub token: String,
}

/// Top-level gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Address the HTTPS/WSS server binds to.
    pub listen_addr: SocketAddr,
    /// This node's PeerId (hex).
    pub node_id: String,
    /// Human readable name of this node.
    pub node_name: String,
    /// Full mesh node list (including this node) exposed to browsers.
    pub node_list: Vec<MeshNodeInfo>,
    /// ICE servers handed to browsers (STUN for srflx, TURN for fallback).
    #[serde(default)]
    pub ice_servers: Vec<IceServer>,
    /// TLS material.
    pub tls: TlsConfig,
    /// SSH terminal bridge configuration.
    #[serde(default)]
    pub ssh: SshConfig,
    /// Mesh signaling backend.
    #[serde(default)]
    pub mesh: MeshConfig,
}

impl GatewayConfig {
    /// Parse a gateway configuration from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::Config` for malformed JSON, a missing `listen_addr`,
    /// an empty `node_id`, an empty `node_list` or an invalid SSH target.
    pub fn from_json_str(input: &str) -> Result<Self, GatewayError> {
        let cfg: GatewayConfig = serde_json::from_str(input)
            .map_err(|e| GatewayError::Config(format!("invalid JSON: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load a gateway configuration from a JSON file.
    ///
    /// # Errors
    ///
    /// I/O or parse errors are returned as `GatewayError`.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, GatewayError> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)
            .map_err(|e| GatewayError::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::from_json_str(&data)
    }

    /// Validate configuration invariants.
    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.node_id.trim().is_empty() {
            return Err(GatewayError::Config("node_id must not be empty".into()));
        }
        if self.node_name.trim().is_empty() {
            return Err(GatewayError::Config("node_name must not be empty".into()));
        }
        if self.node_list.is_empty() {
            return Err(GatewayError::Config(
                "node_list must contain at least this node".into(),
            ));
        }
        if !self.node_list.iter().any(|n| n.peer_id == self.node_id) {
            return Err(GatewayError::Config(
                "node_list must contain an entry matching node_id".into(),
            ));
        }
        if self.ssh.max_terminals == 0 {
            return Err(GatewayError::Config(
                "ssh.max_terminals must be >= 1".into(),
            ));
        }
        if self.ssh.idle_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "ssh.idle_timeout_secs must be >= 1".into(),
            ));
        }
        Ok(())
    }

    /// Idle timeout as a `Duration`.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.ssh.idle_timeout_secs)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> GatewayConfig {
        GatewayConfig {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            node_id: "node-a".into(),
            node_name: "node-a".into(),
            node_list: vec![MeshNodeInfo {
                peer_id: "node-a".into(),
                name: "node-a".into(),
                addrs: vec!["127.0.0.1:8443".into()],
                services: vec!["ssh".into()],
            }],
            ice_servers: vec![],
            tls: TlsConfig::AutoGenerate {
                names: vec!["localhost".into()],
                ips: vec!["127.0.0.1".parse().unwrap()],
            },
            ssh: SshConfig::default(),
            mesh: MeshConfig::InMemory,
        }
    }

    #[test]
    fn valid_config_roundtrips() {
        let json = serde_json::to_string(&valid_config()).expect("serialize");
        let cfg = GatewayConfig::from_json_str(&json).expect("parse");
        assert_eq!(cfg.node_id, "node-a");
    }

    #[test]
    fn empty_node_id_rejected() {
        let mut cfg = valid_config();
        cfg.node_id = "".into();
        assert!(matches!(
            cfg.validate(),
            Err(GatewayError::Config(_))
        ));
    }

    #[test]
    fn empty_node_list_rejected() {
        let mut cfg = valid_config();
        cfg.node_list.clear();
        assert!(matches!(
            cfg.validate(),
            Err(GatewayError::Config(_))
        ));
    }

    #[test]
    fn node_list_must_contain_self() {
        let mut cfg = valid_config();
        cfg.node_list[0].peer_id = "other".into();
        assert!(matches!(
            cfg.validate(),
            Err(GatewayError::Config(_))
        ));
    }

    #[test]
    fn zero_max_terminals_rejected() {
        let mut cfg = valid_config();
        cfg.ssh.max_terminals = 0;
        assert!(matches!(
            cfg.validate(),
            Err(GatewayError::Config(_))
        ));
    }

    #[test]
    fn missing_listen_addr_rejected() {
        let json = r#"{"node_id":"a","node_name":"a","node_list":[{"peer_id":"a","name":"a"}],"tls":{"mode":"auto_generate","names":[],"ips":[]}}"#;
        assert!(matches!(
            GatewayConfig::from_json_str(json),
            Err(GatewayError::Config(_))
        ));
    }

    #[test]
    fn malformed_json_rejected() {
        assert!(matches!(
            GatewayConfig::from_json_str("{not json"),
            Err(GatewayError::Config(_))
        ));
    }
}
