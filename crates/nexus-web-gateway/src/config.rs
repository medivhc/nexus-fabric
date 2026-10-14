//! Gateway configuration types and JSON loading.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::file_service::{FileEngine, FileLimits, SandboxRoot};

/// Default SSH target: local sshd.
pub const DEFAULT_SSH_TARGET: &str = "127.0.0.1:22";
/// Default per-session concurrent terminal limit.
pub const DEFAULT_MAX_TERMINALS: usize = 5;

/// Upper bound accepted by `validate()`. Deliberately far above the default:
/// it exists to reject a config that would open unbounded channels/threads,
/// not to tune capacity.
pub const MAX_TERMINALS_CEILING: usize = 64;
/// Default idle timeout for an SSH terminal.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;

/// Lowest `files.lockout_window_secs` the **config layer** accepts.
///
/// The engine deliberately has no lower bound — its throttle tests need a
/// millisecond window to exercise expiry and decay without sleeping for a minute
/// (G15/R3-NEW-2). That is the right call *inside* the engine and the wrong one
/// on a config file: `lockout_window` is one knob with two jobs (how long a lock
/// lasts, and how fast failures are forgotten), so a sub-second window shrinks
/// the lockout *and* lets a slow dripper escape it (G15 代价 (2)). Rejecting it
/// here is what closes G15's "随 files 配置接线一起在真实配置面上处理".
pub const MIN_FILE_LOCKOUT_WINDOW_SECS: u64 = 1;
/// Highest window/timeout the config accepts — mirrors the engine's clock
/// arithmetic bound (G12/R5-W-2), checked in both layers on purpose so a change
/// to either one has an object.
pub const MAX_FILE_WINDOW_SECS: u64 = 24 * 3600;

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

/// One exported directory of the file channel, as configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRootConfig {
    /// Stable name the browser addresses (`SandboxRoot::name`); unique within
    /// the section.
    pub alias: String,
    /// Filesystem path to canonicalize and open as the sandbox root.
    pub path: String,
    /// Read-only roots reject uploads/mkdir/rename/remove (G13/G14).
    #[serde(default)]
    pub read_only: bool,
}

/// File-channel configuration: the kill switch, the independent credential, the
/// root list, and every numeric ceiling the engine enforces.
///
/// Two deliberate choices, both from the review chain:
/// - **`enabled` defaults to `false`** (G22's "默认拒"): a config written before
///   this module existed must not gain a new attack surface by upgrading the
///   binary. The absence of a `files` section is the same as `enabled=false`.
/// - **The limits are validated even when disabled** (`disabled_still_rejects_*`
///   in `product.gateway-file-config`): a switch is a shut-off valve, not an
///   inspection waiver. Validating only the enabled path means a table that is
///   self-inconsistent *today* silently ships, and the moment someone flips the
///   switch it goes live unreviewed — the same fail-open-by-default shape this
///   crate has been asked to remove four times (r2 NEW-3, r3 R3-NEW-2, r7 R7-W-2,
///   r9 R9-W-2). Presence requirements (token, roots) *are* gated on `enabled`,
///   since those are only meaningful for a running service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesConfig {
    /// Kill switch. When false, `GatewayConfig::file_engine()` returns `None`
    /// and no engine exists to serve a file verb.
    pub enabled: bool,
    /// Channel credential, independent of the page login (G15's 凭证不落盘 rule).
    pub token: String,
    /// Exported roots. Non-empty when `enabled`.
    pub roots: Vec<FileRootConfig>,
    pub chunk_bytes: usize,
    pub max_entries_per_page: usize,
    pub max_ack_bytes: usize,
    pub max_sessions: usize,
    pub max_browser_sessions: usize,
    pub max_read_handles: usize,
    pub max_inflight_bytes_per_session: usize,
    pub max_upload_bytes: u64,
    pub max_rehash_bytes_per_stream: u64,
    /// Seconds; the engine takes a `Duration` (same unit convention as
    /// `ssh.idle_timeout_secs`).
    pub idle_timeout_secs: u64,
    pub lockout_after: usize,
    /// Seconds; bounded on **both** sides at this layer — see
    /// [`MIN_FILE_LOCKOUT_WINDOW_SECS`].
    pub lockout_window_secs: u64,
    pub max_throttle_buckets: usize,
    pub max_failures_per_source: usize,
    pub max_buffered_amount: usize,
}

impl Default for FilesConfig {
    fn default() -> Self {
        // Mirrors `FileLimits::default()` field by field; `limits_round_trip_is_exact`
        // in the E4 scenario is the object that keeps the two from drifting.
        let l = FileLimits::default();
        Self {
            enabled: false,
            token: String::new(),
            roots: Vec::new(),
            chunk_bytes: l.chunk_bytes,
            max_entries_per_page: l.max_entries_per_page,
            max_ack_bytes: l.max_ack_bytes,
            max_sessions: l.max_sessions,
            max_browser_sessions: l.max_browser_sessions,
            max_read_handles: l.max_read_handles,
            max_inflight_bytes_per_session: l.max_inflight_bytes_per_session,
            max_upload_bytes: l.max_upload_bytes,
            max_rehash_bytes_per_stream: l.max_rehash_bytes_per_stream,
            idle_timeout_secs: l.idle_timeout.as_secs(),
            lockout_after: l.lockout_after,
            lockout_window_secs: l.lockout_window.as_secs(),
            max_throttle_buckets: l.max_throttle_buckets,
            max_failures_per_source: l.max_failures_per_source,
            max_buffered_amount: l.max_buffered_amount,
        }
    }
}

impl FilesConfig {
    /// The engine-side view of this section.
    pub fn to_limits(&self) -> FileLimits {
        FileLimits {
            chunk_bytes: self.chunk_bytes,
            max_entries_per_page: self.max_entries_per_page,
            max_ack_bytes: self.max_ack_bytes,
            max_sessions: self.max_sessions,
            max_browser_sessions: self.max_browser_sessions,
            max_read_handles: self.max_read_handles,
            max_inflight_bytes_per_session: self.max_inflight_bytes_per_session,
            max_upload_bytes: self.max_upload_bytes,
            max_rehash_bytes_per_stream: self.max_rehash_bytes_per_stream,
            idle_timeout: Duration::from_secs(self.idle_timeout_secs),
            lockout_after: self.lockout_after,
            lockout_window: Duration::from_secs(self.lockout_window_secs),
            max_throttle_buckets: self.max_throttle_buckets,
            max_failures_per_source: self.max_failures_per_source,
            max_buffered_amount: self.max_buffered_amount,
        }
    }

    /// Validate the section. Numeric self-consistency is checked **regardless of
    /// `enabled`**; the presence of a credential and of at least one root is only
    /// required of a service that is being turned on.
    pub fn validate(&self) -> Result<(), GatewayError> {
        let limits = self.to_limits();
        // Config-only lower bound on the window (engine has none on purpose).
        if self.lockout_window_secs < MIN_FILE_LOCKOUT_WINDOW_SECS {
            return Err(GatewayError::Config(format!(
                "files.lockout_window_secs must be >= {MIN_FILE_LOCKOUT_WINDOW_SECS}: the same knob both holds a lock open and forgets failures, so a sub-second window shrinks the lockout and lets a slow dripper through (G15 代价 (2))"
            )));
        }
        if self.lockout_window_secs > MAX_FILE_WINDOW_SECS {
            return Err(GatewayError::Config(format!(
                "files.lockout_window_secs must be <= {MAX_FILE_WINDOW_SECS}"
            )));
        }
        if self.idle_timeout_secs < 1 {
            return Err(GatewayError::Config(
                "files.idle_timeout_secs must be >= 1".into(),
            ));
        }
        if self.idle_timeout_secs > MAX_FILE_WINDOW_SECS {
            return Err(GatewayError::Config(format!(
                "files.idle_timeout_secs must be <= {MAX_FILE_WINDOW_SECS}"
            )));
        }
        // The engine's own table — zero ceilings, the ack/inflight pairing and
        // both `max_failures_per_source` cross bounds all live here, so the
        // G12 rules run on the real config path, not only in fixtures.
        if let Err(e) = limits.validate() {
            return Err(GatewayError::Config(format!("files limits: {e}")));
        }
        if self.enabled {
            if self.token.trim().is_empty() {
                return Err(GatewayError::Config(
                    "files.token must not be empty when files.enabled is true".into(),
                ));
            }
            if self.roots.is_empty() {
                return Err(GatewayError::Config(
                    "files.roots must contain at least one entry when files.enabled is true".into(),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for root in &self.roots {
                if root.alias.trim().is_empty() {
                    return Err(GatewayError::Config(
                        "files.roots entry has an empty alias".into(),
                    ));
                }
                if root.path.trim().is_empty() {
                    return Err(GatewayError::Config(format!(
                        "files.roots entry {} has an empty path",
                        root.alias
                    )));
                }
                if !seen.insert(root.alias.as_str()) {
                    return Err(GatewayError::Config(format!(
                        "duplicate files.roots alias: {}",
                        root.alias
                    )));
                }
            }
        }
        Ok(())
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
    /// File channel: kill switch, credential, roots, and the engine ceilings.
    #[serde(default)]
    pub files: FilesConfig,
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
        // 上界同样要检查：每条 terminal 是一个 ssh channel + 一个 worker +
        // 一段发送缓冲。只检查 `== 0` 时，一个浏览器会话把这项配成 10 万也能
        // 起进程——这和文件类预算未接线是同一类资源缺陷（评审 WARN），
        // 所以两个方向都在 `validate()` 里封住。
        if self.ssh.max_terminals > MAX_TERMINALS_CEILING {
            return Err(GatewayError::Config(format!(
                "ssh.max_terminals must be <= {MAX_TERMINALS_CEILING}"
            )));
        }
        if self.ssh.idle_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "ssh.idle_timeout_secs must be >= 1".into(),
            ));
        }
        // 文件段的自洽性检查与开关无关（见 `FilesConfig` 的文档）：一份"关着但坏掉"的
        // 表如果放过，下一次有人打开就是静默上线。
        self.files.validate()?;
        Ok(())
    }

    /// Build the file engine this configuration describes, or return `None` when
    /// the kill switch is off.
    ///
    /// Returning `None` is the whole point of `enabled = false`: there is **no
    /// engine to address**, so no verb can reach a code path that has to remember
    /// to check a flag. The transport layer does not dispatch file verbs until
    /// M2, so the wire-level refusal is a registered residual (G16/M2), not
    /// something this function claims to have proven.
    ///
    /// Validates first, so a config that cannot launch fails here rather than
    /// after the caller has started serving.
    pub fn file_engine(&self) -> Result<Option<FileEngine>, GatewayError> {
        self.validate()?;
        if !self.files.enabled {
            return Ok(None);
        }
        let mut roots = Vec::with_capacity(self.files.roots.len());
        for r in &self.files.roots {
            roots.push(
                SandboxRoot::open(r.alias.clone(), Path::new(&r.path), r.read_only)
                    .map_err(|e| GatewayError::Config(format!("files.roots: {e}")))?,
            );
        }
        let engine = FileEngine::new(self.files.to_limits(), roots, self.files.token.clone())
            .map_err(|e| GatewayError::Config(format!("file engine: {e}")))?;
        Ok(Some(engine))
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
            files: FilesConfig::default(),
            mesh: MeshConfig::InMemory,
        }
    }

    fn enabled_files(dir: &Path) -> FilesConfig {
        FilesConfig {
            enabled: true,
            token: "s3cret-file-token".into(),
            roots: vec![FileRootConfig {
                alias: "downloads".into(),
                path: dir.display().to_string(),
                read_only: false,
            }],
            ..Default::default()
        }
    }

    // ---- 文件段接线（product.gateway-file-config 的同一批性质，单测这层给因果）----

    #[test]
    fn absent_files_section_is_disabled() {
        // 老配置（没有 files 段）等价于关断：升级二进制不该凭空多出一个攻击面（G22）。
        let json = r#"{"listen_addr":"127.0.0.1:8443","node_id":"a","node_name":"a",
            "node_list":[{"peer_id":"a","name":"a"}],
            "tls":{"mode":"auto_generate","names":[],"ips":[]}}"#;
        let cfg = GatewayConfig::from_json_str(json).expect("老配置必须继续可解析");
        assert!(!cfg.files.enabled, "缺段必须等价于 enabled=false");
        assert!(
            cfg.file_engine().expect("关断时不该有引擎可建").is_none(),
            "关断必须结构性地没有引擎，而不是建一个自己会拒的引擎"
        );
    }

    #[test]
    fn disabled_section_still_rejects_an_inconsistent_table() {
        // 开关是关断阀，不是免检牌：只检查启用路径等于让坏配置静默上线。
        let mut cfg = valid_config();
        cfg.files.enabled = false;
        cfg.files.max_ack_bytes = cfg.files.max_inflight_bytes_per_session + 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("max_ack_bytes"),
            "错误信息要指到那条交叉规则: {err}"
        );
    }

    #[test]
    fn sub_second_window_is_rejected_at_the_config_layer() {
        // 引擎层故意没有下界（时间夹具要毫秒窗口），配置层必须有：同一个旋钮一物两用
        // （G15 代价 (2)），亚秒窗口会把锁定缩短到无意义。
        //
        // 必须**指到是哪一层答的话**：`FilesConfig::validate` 会把整张表委托给
        // `FileLimits::validate`，而引擎那条"时长不得为 0"也会在窗口=0 时拒——只看
        // `is_err()` 的对象，把配置层这条删掉照样绿（第一版对象就是这形状，变异 MC01
        // 在它上面实测 0 红）。串里含 `files.lockout_window_secs` 只有配置层的界会给，
        // 委托层的串是 `files limits: ` + 引擎原文
        // （`lockout_window must not be zero`）。
        // 用 `contains` 不用 `starts_with`：`GatewayError::Config` 的 Display 会加
        // `config error: ` 前缀（第一次跑就踩了，基线因此两条红）。
        let mut cfg = valid_config();
        cfg.files.lockout_window_secs = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("files.lockout_window_secs"),
            "亚秒窗口要由配置层的下界拒，而不是靠委托进来的引擎零检查: {err}"
        );
        cfg.files.lockout_window_secs = MIN_FILE_LOCKOUT_WINDOW_SECS;
        assert!(cfg.validate().is_ok(), "边界本身必须可用");
    }

    #[test]
    fn over_24h_window_is_rejected_in_both_layers() {
        // 两条各钉一层：配置层看自己的上界串，引擎层直接调 `FileLimits::validate`
        // 绕过委托——所以删任一层的 24 h 都会红（引擎那半另有
        // `file_service` 的 `every_validate_rule_has_a_red_test` 表格行兜着）。
        let mut cfg = valid_config();
        cfg.files.lockout_window_secs = MAX_FILE_WINDOW_SECS + 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("files.lockout_window_secs"),
            "24h 以上要由配置层的上界拒: {err}"
        );
        let limits = cfg.files.to_limits();
        assert!(limits.validate().is_err());
    }

    #[test]
    fn enabled_without_credential_or_roots_is_rejected() {
        let dir = std::env::temp_dir().join("nexus-files-cfg-token");
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let mut cfg = valid_config();
        cfg.files = enabled_files(&dir);
        assert!(cfg.validate().is_ok(), "夹具前提：完整配置可用");
        cfg.files.token = "   ".into();
        assert!(
            matches!(cfg.validate(), Err(GatewayError::Config(_))),
            "只含空白的令牌与空令牌同罪：它会去匹配一个同样空白出示的串"
        );
        cfg.files.token = "s3cret-file-token".into();
        cfg.files.roots.clear();
        assert!(matches!(cfg.validate(), Err(GatewayError::Config(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_or_blank_root_alias_is_rejected() {
        let dir = std::env::temp_dir().join("nexus-files-cfg-alias");
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let mut cfg = valid_config();
        cfg.files = enabled_files(&dir);
        cfg.files.roots.push(FileRootConfig {
            alias: "downloads".into(),
            path: dir.display().to_string(),
            read_only: true,
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate"), "要指到重复别名: {err}");
        let mut cfg2 = valid_config();
        cfg2.files = enabled_files(&dir);
        cfg2.files.roots[0].alias = "".into();
        assert!(matches!(cfg2.validate(), Err(GatewayError::Config(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enabled_config_launches_an_engine_and_missing_path_does_not() {
        let dir = std::env::temp_dir().join("nexus-files-cfg-launch");
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let mut cfg = valid_config();
        cfg.files = enabled_files(&dir);
        let engine = cfg
            .file_engine()
            .expect("合法配置必须起得来")
            .expect("enabled=true 时必须有引擎");
        assert_eq!(engine.limits().max_sessions, cfg.files.max_sessions);
        let mut broken = valid_config();
        broken.files = enabled_files(
            std::env::temp_dir()
                .join("nexus-files-cfg-does-not-exist-9z")
                .as_path(),
        );
        // `FileEngine` 不实现 Debug，所以这里不能 `unwrap_err()`。
        let err = match broken.file_engine() {
            Err(GatewayError::Config(msg)) => msg,
            Err(other) => panic!("必须是 Config 类错误，拿到 {other:?}"),
            Ok(_) => panic!("不存在的根必须被拒，不能起出引擎"),
        };
        assert!(
            err.contains("files.roots"),
            "不存在的根要在启动前挡住，别变成随机启动失败: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_inconsistent_enabled_table_cannot_launch_an_engine() {
        // `file_engine()` 的第一句是 `self.validate()?`——这句在没有对象之前只是注释：
        // 把删掉它的变异（MC07）放到第一版对象集上跑，实测 0 条单测红、0 条期望翻转。
        // 这里钉两件事：① 不合法的开启态表**起不出**引擎；② 拒它的是委托进来的那张表
        // （错误串带 `files limits`），不是 `SandboxRoot::open` 的路径检查。
        let dir = std::env::temp_dir().join("nexus-files-cfg-bad-table");
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let mut cfg = valid_config();
        cfg.files = enabled_files(&dir);
        // 只违反"任一数值上限不得为 0"这一条（G12），其余字段保持默认。
        cfg.files.chunk_bytes = 0;
        let err = match cfg.file_engine() {
            Err(GatewayError::Config(msg)) => msg,
            Err(other) => panic!("必须是 Config 类错误，拿到 {other:?}"),
            Ok(_) => panic!("不合法的表不能起出引擎，否则 validate 那一步形同注释"),
        };
        assert!(
            err.contains("files limits"),
            "要指到委托的交叉规则表: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blank_credential_and_alias_are_refused_at_the_construction_seam() {
        // 评审 r13 W-1：`invalid_table_yields_no_engine` 的红是**词法**的——`FileEngine::new`
        // 第一句就 `limits.validate()?`（file_service.rs:1414），所以把缝里那句
        // `self.validate()?` 删掉，坏数值表仍然被拒，只是错误串换了标签。缝真正不可替代的
        // 那半是**只有配置层才有的规则**，而且必须从 `file_engine()` 走过去才成立：
        // ① `token.trim().is_empty()` —— 引擎只查 `is_empty()`，"   " 这种非空但空白的
        //    令牌引擎照收（它会去匹配一个同样空白出示的串）；
        // ② 根别名的 `trim().is_empty()` —— `SandboxRoot::open` 与 `FileEngine::new`
        //    都不检查别名是否为空白（只查重复与非空根集合）。
        // 两条各配一个对象，红因必须是配置层的串，而不是引擎的包装。
        let dir = std::env::temp_dir().join("nexus-files-cfg-seam-blank");
        std::fs::create_dir_all(&dir).expect("fixture dir");

        let mut blank_token = valid_config();
        blank_token.files = enabled_files(&dir);
        blank_token.files.token = "   ".into();
        let err = match blank_token.file_engine() {
            Err(GatewayError::Config(msg)) => msg,
            Err(other) => panic!("必须是 Config 类错误，拿到 {other:?}"),
            Ok(None) => panic!("enabled=true 不该拿到 None，那会把拒绝藏起来"),
            Ok(Some(_)) => panic!("只含空白的令牌必须在缝上就被拒，引擎不会替它拒"),
        };
        assert!(err.contains("files.token"), "要指到配置层的令牌规则: {err}");

        let mut blank_alias = valid_config();
        blank_alias.files = enabled_files(&dir);
        blank_alias.files.roots[0].alias = "  ".into();
        let err = match blank_alias.file_engine() {
            Err(GatewayError::Config(msg)) => msg,
            Err(other) => panic!("必须是 Config 类错误，拿到 {other:?}"),
            Ok(Some(_)) => panic!("空白别名必须在缝上就被拒，两处引擎都不查它"),
            Ok(None) => panic!("enabled=true 不该拿到 None"),
        };
        assert!(err.contains("empty alias"), "要指到别名规则: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_time_bounds_are_rejected_at_the_config_layer() {
        // 评审 r14 W-1：配置层这两条界先前**没有任何带层标签的对象**——评审方自己设计的
        // NEW20（把 `idle_timeout_secs > MAX_FILE_WINDOW_SECS` 拆掉）实测 0 条单测红、
        // 0 条期望翻转，因为 `FilesConfig::validate` 委托给引擎，而引擎那条
        // `idle_timeout must be <= 24h` 会替配置层答话（下界同理，引擎那条是
        // `idle_timeout must not be zero`）。所以这里钉的是"谁答的话"，不是"有没有被拒"。
        let mut cfg = valid_config();
        cfg.files.idle_timeout_secs = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("files.idle_timeout_secs"),
            "零时长要由配置层的下界拒，而不是靠委托进来的引擎检查: {err}"
        );

        let mut over = valid_config();
        over.files.idle_timeout_secs = MAX_FILE_WINDOW_SECS + 1;
        let err = over.validate().unwrap_err().to_string();
        assert!(
            err.contains("files.idle_timeout_secs"),
            "24h 以上要由配置层的上界拒: {err}"
        );
        assert!(
            over.files.to_limits().validate().is_err(),
            "引擎层那条同规则也还在——删它会让这一格红"
        );

        let mut edge = valid_config();
        edge.files.idle_timeout_secs = MAX_FILE_WINDOW_SECS;
        assert!(edge.validate().is_ok(), "边界本身必须可用");
    }

    #[test]
    fn both_duration_bounds_leave_the_boundary_value_usable() {
        // 评审 r15 R15B（上界写成 `>=`，连 24h 本身一起拒）与 r16 W-1（下界写成 `<= 1`，
        // 连合法的 1 秒一起拒）是同一族："越界必须被拒"这类断言对**反向**改动天生盲——
        // 两层判定集合相同，改一侧不改"拒什么"，差别只在边界值还在不在可用集合里。
        // 所以上下界各配对象，两层各测一次。
        let mut cfg = valid_config();
        cfg.files.lockout_window_secs = MAX_FILE_WINDOW_SECS;
        cfg.files.idle_timeout_secs = MAX_FILE_WINDOW_SECS;
        assert!(
            cfg.validate().is_ok(),
            "恰好 24 h 是合法配置：上界是排他的，不是闭的"
        );
        assert!(
            cfg.files.to_limits().validate().is_ok(),
            "引擎层同一条也得放行边界值"
        );

        cfg.files.lockout_window_secs += 1;
        assert!(cfg.validate().is_err(), "越界一格就必须拒");
        cfg.files.lockout_window_secs = MAX_FILE_WINDOW_SECS;
        cfg.files.idle_timeout_secs += 1;
        assert!(cfg.validate().is_err(), "另一侧同理");

        // 下界那一侧（r16 W-1）：MIN 本身可用，写成 `<= MIN` 的改动必须在这里红。
        let mut low = valid_config();
        low.files.lockout_window_secs = MIN_FILE_LOCKOUT_WINDOW_SECS;
        low.files.idle_timeout_secs = MIN_FILE_LOCKOUT_WINDOW_SECS;
        assert!(
            low.validate().is_ok(),
            "1 秒是合法下界值：下界也是排他的，写成 `<= 1` 会把它一起误杀"
        );
        low.files.lockout_window_secs -= 1;
        assert!(low.validate().is_err(), "窗口下界越界一格必须拒");
    }

    #[test]
    fn files_section_round_trips_through_json() {
        // 热更新写出去再读回来，文件段必须原样在——否则一次序列化就把模块静默关回默认。
        let dir = std::env::temp_dir().join("nexus-files-cfg-roundtrip");
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let mut cfg = valid_config();
        cfg.files = enabled_files(&dir);
        cfg.files.chunk_bytes = 4096;
        // 窗口也要偏离默认值：变异 MC17（给 `lockout_window_secs` 加 `skip_serializing`）
        // 在只改 `chunk_bytes` 的夹具上**零单测红**——往返后仍等于默认值，这一格就藏在
        // 默认值里（覆盖率那节实测到的分层空档：场景抓到了，单测没抓到）。
        cfg.files.lockout_window_secs = MIN_FILE_LOCKOUT_WINDOW_SECS + 7;
        let json = serde_json::to_string(&cfg).expect("serialize");
        let parsed = GatewayConfig::from_json_str(&json).expect("parse");
        assert_eq!(parsed.files, cfg.files);
        assert!(parsed.files.enabled && parsed.files.chunk_bytes == 4096);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn limits_mirror_is_field_by_field_exact() {
        // 默认值必须是 `FileLimits::default()` 的逐字段镜像：任何"顺手写的默认"都会在这里红。
        let f = FilesConfig::default();
        let l = f.to_limits();
        let d = FileLimits::default();
        assert_eq!(l.chunk_bytes, d.chunk_bytes);
        assert_eq!(l.max_entries_per_page, d.max_entries_per_page);
        assert_eq!(l.max_ack_bytes, d.max_ack_bytes);
        assert_eq!(l.max_sessions, d.max_sessions);
        assert_eq!(l.max_browser_sessions, d.max_browser_sessions);
        assert_eq!(l.max_read_handles, d.max_read_handles);
        assert_eq!(
            l.max_inflight_bytes_per_session,
            d.max_inflight_bytes_per_session
        );
        assert_eq!(l.max_upload_bytes, d.max_upload_bytes);
        assert_eq!(l.max_rehash_bytes_per_stream, d.max_rehash_bytes_per_stream);
        assert_eq!(l.idle_timeout, d.idle_timeout);
        assert_eq!(l.lockout_after, d.lockout_after);
        assert_eq!(l.lockout_window, d.lockout_window);
        assert_eq!(l.max_throttle_buckets, d.max_throttle_buckets);
        assert_eq!(l.max_failures_per_source, d.max_failures_per_source);
        assert_eq!(l.max_buffered_amount, d.max_buffered_amount);
        assert!(l.validate().is_ok(), "默认表必须自洽");
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
    fn oversized_max_terminals_rejected() {
        // 只有下界的检查等于没有检查：把上界配成 10 万照样通过。
        let mut cfg = valid_config();
        cfg.ssh.max_terminals = MAX_TERMINALS_CEILING + 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("max_terminals"), "错误信息要可执行: {err}");
        cfg.ssh.max_terminals = MAX_TERMINALS_CEILING;
        assert!(cfg.validate().is_ok(), "上界本身必须可用");
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
}
