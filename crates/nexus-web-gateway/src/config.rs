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
    /// Generate a self-signed local-CA certificate for the given DNS names and
    /// IP addresses. When `cert_dir` is set (or on the default path), the
    /// certificate and key are persisted to disk so the fingerprint is stable
    /// across restarts and the `/cert` endpoint can serve the CA.
    AutoGenerate {
        #[serde(default)]
        names: Vec<String>,
        #[serde(default)]
        ips: Vec<IpAddr>,
        /// Optional directory for persisting the generated certificate/key.
        /// `None` uses the default per-node cache directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cert_dir: Option<String>,
    },
    /// Load an existing certificate chain + private key from PEM files.
    Files { cert_path: String, key_path: String },
}

/// SSH terminal bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfig {
    /// TCP target the node's SSH client connects to (the node's local sshd).
    #[serde(default = "default_ssh_target")]
    pub target: SocketAddr,
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
            max_terminals: default_max_terminals(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

/// Default file-transfer chunk payload (bytes).
pub const DEFAULT_FILE_CHUNK_BYTES: usize = 64 * 1024;
/// Hard ceiling for a negotiated chunk size: a WebRTC DataChannel message must
/// stay inside the SCTP user-data limit.
pub const MAX_FILE_CHUNK_BYTES: usize = 256 * 1024;
/// Default concurrent file sessions per browser session.
pub const DEFAULT_MAX_FILE_SESSIONS: usize = 4;
/// Default upload ceiling per file session (2 GiB).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Default idle timeout for a file session.
pub const DEFAULT_FILE_IDLE_TIMEOUT_SECS: u64 = 300;

/// One node-local directory the file module may expose (REQ-008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRoot {
    /// Stable name the browser selects; unique within `files.roots`.
    pub name: String,
    /// Absolute path of the exposed directory (the sandbox root).
    pub path: String,
    /// A read-only root rejects write / mkdir / rename / remove.
    #[serde(default)]
    pub read_only: bool,
}

/// File access and upload configuration (REQ-005..REQ-008).
///
/// Disabled by default: exposing a filesystem is strictly opt-in, and enabling
/// it *requires* a bearer token, because browser identity on this node is still
/// ephemeral and unverified (G2; REQ-003 access authentication is not
/// implemented). Fail-closed: `validate()` rejects an enabled config without a
/// token rather than silently exposing files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileConfig {
    /// Master switch for the file module (control messages + data channel).
    #[serde(default)]
    pub enabled: bool,
    /// Bearer token every `file_open` must present (required when enabled).
    #[serde(default)]
    pub auth_token: String,
    /// Node-local directories exposed as roots. May be empty, which leaves the
    /// module in SFTP-only mode (targets the node's configured SSH target).
    #[serde(default)]
    pub roots: Vec<FileRoot>,
    /// Chunk payload size used for reads and writes.
    #[serde(default = "default_file_chunk_bytes")]
    pub chunk_bytes: usize,
    /// Maximum concurrent file sessions per browser session.
    #[serde(default = "default_max_file_sessions")]
    pub max_sessions: usize,
    /// Maximum accepted upload size per file session.
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,
    /// Idle timeout (seconds) after which a file session is closed.
    #[serde(default = "default_file_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_file_chunk_bytes() -> usize {
    DEFAULT_FILE_CHUNK_BYTES
}

fn default_max_file_sessions() -> usize {
    DEFAULT_MAX_FILE_SESSIONS
}

fn default_max_upload_bytes() -> u64 {
    DEFAULT_MAX_UPLOAD_BYTES
}

fn default_file_idle_timeout_secs() -> u64 {
    DEFAULT_FILE_IDLE_TIMEOUT_SECS
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auth_token: String::new(),
            roots: Vec::new(),
            chunk_bytes: default_file_chunk_bytes(),
            max_sessions: default_max_file_sessions(),
            max_upload_bytes: default_max_upload_bytes(),
            idle_timeout_secs: default_file_idle_timeout_secs(),
        }
    }
}

impl FileConfig {
    /// The node-local root exposed under `name`, if configured.
    pub fn root(&self, name: &str) -> Option<&FileRoot> {
        self.roots.iter().find(|r| r.name == name)
    }

    /// Idle timeout as a `Duration`.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs.max(1))
    }
}

/// Mesh signaling backend configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MeshConfig {
    /// No external mesh; used by tests that wire gateways in-process.
    #[default]
    InMemory,
    /// Relay signaling through each peer's gateway over WSS.
    Wss {
        /// Bearer token the local `/mesh` WSS endpoint requires from peers.
        token: String,
        #[serde(default)]
        peers: Vec<MeshPeer>,
    },
}

impl MeshConfig {
    /// Bearer token required by the local `/mesh` WSS endpoint, if any.
    pub fn local_token(&self) -> Option<&str> {
        match self {
            MeshConfig::Wss { token, .. } => Some(token),
            MeshConfig::InMemory => None,
        }
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
    /// File access / upload module (opt-in and token-protected).
    #[serde(default)]
    pub files: FileConfig,
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
        let mut seen = std::collections::HashSet::new();
        for node in &self.node_list {
            if node.peer_id.trim().is_empty() {
                return Err(GatewayError::Config(
                    "node_list entry has empty peer_id".into(),
                ));
            }
            if !seen.insert(node.peer_id.as_str()) {
                return Err(GatewayError::Config(format!(
                    "duplicate peer_id in node_list: {}",
                    node.peer_id
                )));
            }
        }
        for ice in &self.ice_servers {
            if ice.urls.is_empty() {
                return Err(GatewayError::Config(
                    "ice_servers entry has empty urls".into(),
                ));
            }
        }
        if let TlsConfig::Files {
            cert_path,
            key_path,
        } = &self.tls
        {
            if cert_path.trim().is_empty() || key_path.trim().is_empty() {
                return Err(GatewayError::Config(
                    "tls.files cert_path and key_path must not be empty".into(),
                ));
            }
        }
        if let MeshConfig::Wss { token, peers } = &self.mesh {
            if token.trim().is_empty() {
                return Err(GatewayError::Config(
                    "mesh.wss.token must not be empty".into(),
                ));
            }
            for peer in peers {
                if peer.peer_id.trim().is_empty()
                    || peer.url.trim().is_empty()
                    || peer.token.trim().is_empty()
                {
                    return Err(GatewayError::Config(
                        "mesh.wss.peers entry needs non-empty peer_id/url/token".into(),
                    ));
                }
            }
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
        // Files (REQ-005..REQ-008): fail-closed. An enabled module without a
        // token would expose the filesystem to any browser that can complete
        // ICE, since node-side browser identity is still unverified (G2).
        if self.files.enabled && self.files.auth_token.trim().is_empty() {
            return Err(GatewayError::Config(
                "files.auth_token must not be empty when files.enabled".into(),
            ));
        }
        if self.files.enabled {
            if self.files.chunk_bytes == 0 || self.files.chunk_bytes > MAX_FILE_CHUNK_BYTES {
                return Err(GatewayError::Config(format!(
                    "files.chunk_bytes must be in 1..={MAX_FILE_CHUNK_BYTES}, got {}",
                    self.files.chunk_bytes
                )));
            }
            if self.files.max_sessions == 0 {
                return Err(GatewayError::Config(
                    "files.max_sessions must be >= 1".into(),
                ));
            }
            if self.files.idle_timeout_secs == 0 {
                return Err(GatewayError::Config(
                    "files.idle_timeout_secs must be >= 1".into(),
                ));
            }
        }
        // Root hygiene is validated even while the module is disabled, so a
        // sandbox cannot be misconfigured and switched on later.
        let mut root_names = std::collections::HashSet::new();
        for root in &self.files.roots {
            if root.name.trim().is_empty() {
                return Err(GatewayError::Config(
                    "files.roots entry has empty name".into(),
                ));
            }
            if !Path::new(&root.path).is_absolute() {
                return Err(GatewayError::Config(format!(
                    "files.roots.{} path must be absolute, got {}",
                    root.name, root.path
                )));
            }
            if !root_names.insert(root.name.as_str()) {
                return Err(GatewayError::Config(format!(
                    "duplicate files.roots name: {}",
                    root.name
                )));
            }
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
                cert_dir: None,
            },
            ssh: SshConfig::default(),
            files: FileConfig::default(),
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
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn empty_node_list_rejected() {
        let mut cfg = valid_config();
        cfg.node_list.clear();
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn node_list_must_contain_self() {
        let mut cfg = valid_config();
        cfg.node_list[0].peer_id = "other".into();
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn zero_max_terminals_rejected() {
        let mut cfg = valid_config();
        cfg.ssh.max_terminals = 0;
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
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

    #[test]
    fn node_list_empty_peer_id_rejected() {
        let mut cfg = valid_config();
        cfg.node_list[0].peer_id = "".into();
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn node_list_duplicate_peer_id_rejected() {
        let mut cfg = valid_config();
        cfg.node_list.push(cfg.node_list[0].clone());
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn ice_server_empty_urls_rejected() {
        let mut cfg = valid_config();
        cfg.ice_servers.push(IceServer {
            urls: vec![],
            username: None,
            credential: None,
        });
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn tls_files_empty_paths_rejected() {
        let mut cfg = valid_config();
        cfg.tls = TlsConfig::Files {
            cert_path: "".into(),
            key_path: "".into(),
        };
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn mesh_wss_empty_token_rejected() {
        let mut cfg = valid_config();
        cfg.mesh = MeshConfig::Wss {
            token: "".into(),
            peers: vec![],
        };
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn mesh_wss_peer_missing_url_rejected() {
        let mut cfg = valid_config();
        cfg.mesh = MeshConfig::Wss {
            token: "token-a".into(),
            peers: vec![MeshPeer {
                peer_id: "node-b".into(),
                url: "".into(),
                token: "token-b".into(),
            }],
        };
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
    }

    #[test]
    fn mesh_wss_roundtrips() {
        let mut cfg = valid_config();
        cfg.mesh = MeshConfig::Wss {
            token: "token-a".into(),
            peers: vec![MeshPeer {
                peer_id: "node-b".into(),
                url: "wss://127.0.0.1:8444/mesh".into(),
                token: "token-b".into(),
            }],
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed = GatewayConfig::from_json_str(&json).expect("parse");
        assert_eq!(parsed.mesh, cfg.mesh);
    }

    #[test]
    fn files_disabled_by_default_and_needs_no_token() {
        let cfg = valid_config();
        assert!(!cfg.files.enabled);
        cfg.validate().expect("default files config is valid");
    }

    #[test]
    fn files_enabled_without_token_rejected() {
        let mut cfg = valid_config();
        cfg.files.enabled = true;
        cfg.files.auth_token = String::new();
        assert!(
            matches!(cfg.validate(), Err(GatewayError::Config(_))),
            "an enabled file module with no token must fail closed"
        );
    }

    #[test]
    fn files_enabled_with_token_accepted() {
        let mut cfg = valid_config();
        cfg.files.enabled = true;
        cfg.files.auth_token = "s3cret-token".into();
        cfg.validate().expect("valid file config");
    }

    #[test]
    fn files_chunk_bytes_bounds_rejected() {
        for bad in [0usize, MAX_FILE_CHUNK_BYTES + 1] {
            let mut cfg = valid_config();
            cfg.files.enabled = true;
            cfg.files.auth_token = "t".into();
            cfg.files.chunk_bytes = bad;
            assert!(
                matches!(cfg.validate(), Err(GatewayError::Config(_))),
                "chunk_bytes {bad} must be rejected"
            );
        }
    }

    #[test]
    fn files_root_path_must_be_absolute_and_unique() {
        let mut cfg = valid_config();
        cfg.files.roots = vec![FileRoot {
            name: "tmp".into(),
            path: "relative/dir".into(),
            read_only: false,
        }];
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));

        let mut cfg = valid_config();
        cfg.files.roots = vec![
            FileRoot {
                name: "a".into(),
                path: "/srv/a".into(),
                read_only: false,
            },
            FileRoot {
                name: "a".into(),
                path: "/srv/b".into(),
                read_only: true,
            },
        ];
        assert!(
            matches!(cfg.validate(), Err(GatewayError::Config(_))),
            "duplicate root names must be rejected"
        );
    }

    #[test]
    fn files_absent_from_json_still_parses() {
        // Configs written before the file module must keep loading.
        let json = r#"{
            "listen_addr":"127.0.0.1:8443",
            "node_id":"node-a",
            "node_name":"node-a",
            "node_list":[{"peer_id":"node-a","name":"node-a"}],
            "tls":{"mode":"auto_generate","names":["localhost"],"ips":["127.0.0.1"]}
        }"#;
        let cfg = GatewayConfig::from_json_str(json).expect("parse legacy config");
        assert!(!cfg.files.enabled);
        assert_eq!(cfg.files.chunk_bytes, DEFAULT_FILE_CHUNK_BYTES);
    }
}
