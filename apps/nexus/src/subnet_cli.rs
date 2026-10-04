//! P3.1 子网 CLI（PRODUCT §12.28）+ P3.4 状态文件加密（§12.31）：
//! TOML 配置 → VirtualSubnetTunnel 装配 + 状态文件（明文或平台加密）。
//!
//! Composition Root 层（apps/nexus 允许 I/O）：配置校验 → 进程内装配（MeshCarrier
//! mock carrier，真实 TUN 留 P3-2）→ 状态写入本地文件（默认 `~/.nexus/subnet.json`，
//! `--state` 可覆盖）。crate 层保持零 I/O。

use std::path::{Path, PathBuf};

use nexus_connectivity::bootstrap_joiner::{
    BootstrapEndpoint, BootstrapJoiner, ClientBootstrapHook,
};
use nexus_connectivity::cidr::{cidr_contains, parse_cidr};
use nexus_connectivity::coord::derive_vip;
use nexus_connectivity::encryption::{EncryptionConfig, KeyPair};
use nexus_connectivity::virtual_subnet::{
    BootstrapHook, MemoryVpi, MeshCarrier, TunnelPeer, TunnelState, VirtualSubnetConfig,
    VirtualSubnetEvent, VirtualSubnetTunnel,
};
use nexus_platform::{PacketCarrier, UdpCarrier, VirtualPacketInterface};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Windows DPAPI 加密状态文件格式 magic（§12.31）：`NEXDP1 || DPAPI blob`。
pub const NEXDP1_MAGIC: &[u8; 6] = b"NEXDP1";

/// TUN 接口名最大字节数（对齐 Linux IFNAMSIZ-1 与 wintun 名称约束）。
pub const MAX_TUN_NAME_BYTES: usize = 15;

/// 子网 TOML 配置（`[subnet]` 表）。
#[derive(Debug, Clone, Deserialize)]
pub struct SubnetConfig {
    /// `[subnet]` 表。
    pub subnet: SubnetSection,
    /// `[routing]` 表（§12.48，可选；缺省 → 默认策略）。
    #[serde(default)]
    pub routing: RoutingSection,
}

/// `[routing]` 配置段（§12.48）：选路策略。
#[derive(Debug, Clone, Deserialize)]
pub struct RoutingSection {
    /// 选路策略（`"shortest"` / `"ecmp"`）；缺省 → `"shortest"`（向后兼容）。
    #[serde(default = "default_routing_strategy")]
    pub strategy: String,
}

fn default_routing_strategy() -> String {
    "shortest".to_string()
}

impl Default for RoutingSection {
    fn default() -> Self {
        Self {
            strategy: default_routing_strategy(),
        }
    }
}

impl SubnetConfig {
    /// 解析 `[routing] strategy` 为 `RoutingStrategy`（§12.48）。
    ///
    /// 未知策略 → `Err("ROUTING_STRATEGY: ...")`（CONFIG_ERROR 语义，fail-closed）。
    pub fn routing_strategy(&self) -> Result<nexus_discovery::routing::RoutingStrategy, String> {
        nexus_discovery::routing::RoutingStrategy::parse(&self.routing.strategy)
            .map_err(|e| format!("ROUTING_STRATEGY: {e} (want 'shortest' or 'ecmp')"))
    }
}

/// `[subnet]` 配置段。
#[derive(Debug, Clone, Deserialize)]
pub struct SubnetSection {
    /// 子网 CIDR（如 "10.99.0.0/24"）。
    pub cidr: String,
    /// 本节点虚拟 IP（须在 cidr 内）；`None` → 从身份公钥确定性派生（§12.43）。
    #[serde(default)]
    pub virtual_ip: Option<String>,
    /// 是否开启隧道加密（P2-1 §12.7），默认关。
    #[serde(default)]
    pub encryption: bool,
    /// 网络 PSK（§12.42/§12.43）；与 `network_psk_file` 互斥，按 UTF-8 字节。
    #[serde(default)]
    pub network_psk: Option<String>,
    /// 网络 PSK 文件路径（§12.43）；与 `network_psk` 互斥；要求 0600 权限。
    #[serde(default)]
    pub network_psk_file: Option<String>,
    /// Bootstrap 节点列表（§12.43 去中心化入网）；非空时 PSK 必填（fail-closed）。
    #[serde(default)]
    pub bootstrap: Vec<BootstrapConfig>,
    /// 对端节点列表（legacy 静态配置）。
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// 精确静态路由（§12.5）。
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// 前缀路由（§12.14）。
    #[serde(default)]
    pub prefix_routes: Vec<PrefixRouteConfig>,
    /// 本节点可达前缀（§12.14）。
    #[serde(default)]
    pub local_prefixes: Vec<String>,
    /// 出口节点（§12.14，必须是 peers 中的 virtual_ip）。
    #[serde(default)]
    pub egress: Vec<String>,
}

/// Bootstrap 节点（§12.43）：去中心化入网的已知入口。
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapConfig {
    /// Bootstrap 地址（如 "udp://203.0.113.10:11010"）。
    pub address: String,
    /// 节点名（可选，仅日志/显示用）。
    #[serde(default)]
    pub name: Option<String>,
}

/// 对端节点。
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// 对端虚拟 IP（须在 cidr 内）。
    pub virtual_ip: String,
    /// 对端物理 locator。
    pub locator: String,
}

/// 精确静态路由（§12.5）。
#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    /// 目的虚拟 IP。
    pub dst: String,
    /// 下一跳虚拟 IP（须是 peer）。
    pub next_hop: String,
}

/// 前缀路由（§12.14）。
#[derive(Debug, Clone, Deserialize)]
pub struct PrefixRouteConfig {
    /// CIDR 前缀（如 "192.168.5.0/24"）。
    pub cidr: String,
    /// 下一跳虚拟 IP（须是 peer）。
    pub next_hop: String,
}

/// 子网运行状态（本地状态文件，JSON）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubnetState {
    /// 隧道是否 up。
    pub up: bool,
    /// 隧道 ID。
    pub tunnel_id: String,
    /// 本节点虚拟 IP。
    pub virtual_ip: String,
    /// 子网 CIDR。
    pub cidr: String,
    /// 已注册 peer 数。
    pub peer_count: usize,
    /// 出口节点数。
    pub egress_peer_count: usize,
    /// 前缀路由数。
    pub prefix_route_count: usize,
    /// 加密是否开启。
    pub encryption: bool,
    /// 最近一次打洞结果（P4.2 §12.9.6；老状态文件无该字段 → 兼容）。
    #[serde(default)]
    pub punch: Option<PunchRecord>,
}

/// 打洞结果记录（P4.2 §12.9.6，`subnet punch` 写入，`subnet status` 复查）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PunchRecord {
    /// 对端虚拟 IP。
    pub peer_vip: String,
    /// 最终 peer 状态（Connected / Failed / Probing / Disconnected，实值）。
    pub state: String,
    /// 最终 locator（直连或 relay）。
    pub locator: String,
    /// 候选 locator 列表。
    pub targets: Vec<String>,
    /// 尝试次数。
    pub attempts: u32,
    /// 是否打洞成功。
    pub succeeded: bool,
}

/// 默认状态文件路径：`$NEXUS_HOME/subnet.json` 或 `~/.nexus/subnet.json`。
pub fn default_state_path() -> PathBuf {
    if let Ok(home) = std::env::var("NEXUS_HOME") {
        let dir = PathBuf::from(home);
        if dir.exists() {
            return dir.join("subnet.json");
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        return PathBuf::from(home).join(".nexus").join("subnet.json");
    }
    PathBuf::from("subnet.json")
}

/// 读取并校验 TOML 配置（先校验后装配）。
///
/// 校验面：cidr 格式（`cidr::parse_cidr`）、virtual_ip 在 cidr 内、
/// peer 在 cidr 内、精确/前缀路由 next_hop 与 egress 必须是 peer、
/// 前缀路由与本地前缀 cidr 格式。
fn parse_config(path: &Path) -> Result<SubnetConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("READ_CONFIG: {e}"))?;
    let config: SubnetConfig = toml::from_str(&text).map_err(|e| format!("PARSE_TOML: {e}"))?;
    validate(&config)?;
    Ok(config)
}

/// 配置校验（装配前）。
fn validate(config: &SubnetConfig) -> Result<(), String> {
    let s = &config.subnet;
    let prefix = parse_cidr(&s.cidr).map_err(|e| format!("CIDR: {e}"))?;
    // §12.43：virtual_ip 可选；显式填写时须在 cidr 内，缺省时由调用方派生。
    if let Some(vip) = &s.virtual_ip {
        if !cidr_contains(&prefix, vip) {
            return Err("VIRTUAL_IP_OUTSIDE_SUBNET: virtual_ip not in cidr".into());
        }
    }
    // §12.43：network_psk 与 network_psk_file 互斥。
    if s.network_psk.is_some() && s.network_psk_file.is_some() {
        return Err("PSK_CONFLICT: network_psk and network_psk_file are mutually exclusive".into());
    }
    // §12.43：bootstrap 非空时 PSK 必填（fail-closed，仅新路径；legacy 不受影响）。
    if !s.bootstrap.is_empty() && s.network_psk.is_none() && s.network_psk_file.is_none() {
        return Err("PSK_REQUIRED: bootstrap join requires network_psk or network_psk_file".into());
    }
    // §12.43：bootstrap 地址格式校验（udp://host:port，host 非空）。
    for b in &s.bootstrap {
        if !b.address.starts_with("udp://") {
            return Err(format!(
                "BOOTSTRAP_ADDRESS: unsupported scheme in '{}' (want udp://host:port)",
                b.address
            ));
        }
        let rest = &b.address["udp://".len()..];
        let valid = match rest.rsplit_once(':') {
            Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
            None => false,
        };
        if !valid {
            return Err(format!(
                "BOOTSTRAP_ADDRESS: invalid udp address '{}'",
                b.address
            ));
        }
    }
    let peer_vips: Vec<&str> = s.peers.iter().map(|p| p.virtual_ip.as_str()).collect();
    for peer in &s.peers {
        if !cidr_contains(&prefix, &peer.virtual_ip) {
            return Err(format!(
                "PEER_OUTSIDE_SUBNET: peer {} not in cidr {}",
                peer.virtual_ip, s.cidr
            ));
        }
    }
    for route in &s.routes {
        if !peer_vips.contains(&route.next_hop.as_str()) {
            return Err(format!(
                "ROUTE_NEXT_HOP_NOT_PEER: {} is not a peer",
                route.next_hop
            ));
        }
    }
    for route in &s.prefix_routes {
        parse_cidr(&route.cidr).map_err(|e| format!("PREFIX_CIDR: {e}"))?;
        if !peer_vips.contains(&route.next_hop.as_str()) {
            return Err(format!(
                "PREFIX_ROUTE_NEXT_HOP_NOT_PEER: {} is not a peer",
                route.next_hop
            ));
        }
    }
    for cidr in &s.local_prefixes {
        parse_cidr(cidr).map_err(|e| format!("LOCAL_PREFIX_CIDR: {e}"))?;
    }
    for vip in &s.egress {
        if !peer_vips.contains(&vip.as_str()) {
            return Err(format!("EGRESS_NOT_PEER: {vip} is not a peer"));
        }
    }
    Ok(())
}

/// 加载 network PSK（§12.43）。
///
/// - `network_psk`：内联字符串，按 UTF-8 字节（空字符串 → `PSK_EMPTY` 错误）；
/// - `network_psk_file`：读文件（去首尾空白），Unix 下要求 0600 权限，过松则拒绝；
/// - 均未配置 → `Ok(None)`（调用方按 fail-closed 规则决定是否拒绝）。
///
/// # Errors
///
/// 两者同时配置 → `PSK_CONFLICT`；文件不可读 → `PSK_FILE`；权限过松 → `PSK_FILE_PERM`。
fn load_network_psk(s: &SubnetSection) -> Result<Option<Vec<u8>>, String> {
    if s.network_psk.is_some() && s.network_psk_file.is_some() {
        return Err("PSK_CONFLICT: network_psk and network_psk_file are mutually exclusive".into());
    }
    if let Some(psk) = &s.network_psk {
        if psk.is_empty() {
            return Err("PSK_EMPTY: network_psk must not be empty".into());
        }
        return Ok(Some(psk.as_bytes().to_vec()));
    }
    if let Some(path) = &s.network_psk_file {
        let path = Path::new(path);
        // Unix 权限检查：要求 0600（owner 可读写，无组/其他权限）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path).map_err(|e| format!("PSK_FILE: {e}"))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(format!(
                    "PSK_FILE_PERM: {path:?} mode is {mode:o}, want 600"
                ));
            }
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("PSK_FILE: {e}"))?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err("PSK_FILE: empty psk file".into());
        }
        return Ok(Some(trimmed.as_bytes().to_vec()));
    }
    Ok(None)
}

/// 回读 `node init` 持久化的 x25519 seed（§12.39），重建长期身份（v2 P3：
/// 替换一次性 generate，使 node_id/VIP 在重启后稳定）。无持久身份时 Err（调用方 fallback）。
fn load_node_identity() -> Result<KeyPair, String> {
    let path = crate::node_cli::node_dir().join("identity");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read identity {path:?}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse identity: {e}"))?;
    let hex = v
        .get("x25519_seed_hex")
        .and_then(Value::as_str)
        .ok_or("identity missing x25519_seed_hex")?;
    let bytes = decode_hex(hex)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "seed must be 32 bytes".to_string())?;
    Ok(KeyPair::from_seed(&arr))
}

/// 最小 hex 解码（避免新增依赖）。
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let b: Vec<u8> = s
        .as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = hex_nibble(c[0])?;
            let lo = hex_nibble(c.get(1).copied().ok_or("odd hex len")?)?;
            Ok(hi << 4 | lo)
        })
        .collect::<Result<Vec<u8>, String>>()?;
    Ok(b)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("bad hex digit {c}")),
    }
}

/// `subnet up --config <path>`：校验 → 装配 → 写状态文件（`--encrypt-state` 加密落盘）。
pub fn subnet_up(
    config_path: &Path,
    state_path: &Path,
    encrypt_state: bool,
    foreground: bool,
) -> Result<Value, String> {
    let config = parse_config(config_path)?;
    // v2 §7.2/S6：bootstrap 入网需要常驻前台心跳/刷新循环；一次性 `subnet up`（非前台）
    // 不提供该循环，fail-closed。前台 daemon（subnet_foreground_real）传 foreground=true 越过。
    if !foreground && !config.subnet.bootstrap.is_empty() {
        return Err(
            "BOOTSTRAP_REQUIRES_FOREGROUND: bootstrap join needs the persistent foreground daemon"
                .into(),
        );
    }
    // §12.43：PSK 文件权限等在装配前校验（fail-closed）。
    let _psk = load_network_psk(&config.subnet)?;
    // T3：身份全程只获取一次（load_node_identity，缺失才 generate 一次），
    // VIP 派生、状态写与 join/assemble_with 共用同一把 KeyPair。
    let identity =
        load_node_identity().or_else(|_| KeyPair::generate().map_err(|e| e.to_string()))?;
    // §12.43：virtual_ip 缺省 → 由同一身份公钥确定性派生。
    let virtual_ip = match &config.subnet.virtual_ip {
        Some(vip) => vip.clone(),
        None => derive_vip(identity.public_key_bytes(), &config.subnet.cidr, 0)
            .map_err(|e| format!("DERIVE_VIP: {e:?}"))?
            .to_string(),
    };
    let mut config = config;
    config.subnet.virtual_ip = Some(virtual_ip.clone());
    let _tunnel = assemble_with(
        &config,
        Box::new(MemoryVpi::new()),
        Box::new(MeshCarrier::new()),
        &identity,
    )?;
    let s = &config.subnet;
    let state = SubnetState {
        up: true,
        tunnel_id: format!("tunnel-{virtual_ip}"),
        virtual_ip: virtual_ip.clone(),
        cidr: s.cidr.clone(),
        peer_count: s.peers.len(),
        egress_peer_count: s.egress.len(),
        prefix_route_count: s.prefix_routes.len(),
        encryption: s.encryption,
        punch: None,
    };
    let json = serde_json::to_string_pretty(&state).map_err(|e| format!("SERIALIZE: {e}"))?;
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("MKDIR_STATE: {e}"))?;
    }
    if encrypt_state {
        let enc = encrypt_state_bytes(json.as_bytes())?;
        std::fs::write(state_path, enc).map_err(|e| format!("WRITE_STATE_ENCRYPTED: {e}"))?;
    } else {
        std::fs::write(state_path, json).map_err(|e| format!("WRITE_STATE: {e}"))?;
    }
    Ok(serde_json::json!({
        "verdict": "PASS",
        "command": "subnet up",
        "subnet": {
            "up": state.up,
            "tunnel_id": state.tunnel_id,
            "virtual_ip": state.virtual_ip,
            "cidr": state.cidr,
            "peer_count": state.peer_count,
            "egress_peer_count": state.egress_peer_count,
            "prefix_route_count": state.prefix_route_count,
            "encryption": state.encryption,
        },
    }))
}

/// 平台保护加密状态字节（§12.31）：
/// - Windows：`NEXDP1 || DPAPI blob`（绑定当前用户+机器）；
/// - Linux：`NEXSEC1` AEAD 密文（machine-id 派生密钥）。
///   能力缺失 → 结构化错误（`SECURE_STORE_UNAVAILABLE`，不 fallback 明文）。
fn encrypt_state_bytes(plain: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        let blob = nexus_platform_windows::dpapi::protect(plain)
            .map_err(|e| format!("DPAPI_PROTECT: {e}"))?;
        let mut out = Vec::with_capacity(NEXDP1_MAGIC.len() + blob.len());
        out.extend_from_slice(NEXDP1_MAGIC);
        out.extend_from_slice(&blob);
        Ok(out)
    }
    #[cfg(target_os = "linux")]
    {
        let key = nexus_platform_linux::secure_store::derive_key_from_machine_id()
            .map_err(|_| "SECURE_STORE_UNAVAILABLE: machine-id missing or invalid".to_string())?;
        nexus_platform::secure_store::encrypt_record(&key, plain)
            .map_err(|e| format!("AEAD_ENCRYPT: {e:?}"))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("SECURE_STORE_UNAVAILABLE: no platform secure store".into())
    }
}

/// 平台保护解密状态字节（自动检测格式 magic；明文直接通过，向后兼容 P3.1）。
///
/// 解密失败（密钥变化 / 篡改 / 平台不匹配）→ 结构化错误（调用方转 STORE_ERROR）。
fn decrypt_state_bytes(enc: &[u8]) -> Result<Vec<u8>, String> {
    if enc.starts_with(nexus_platform::secure_store::NEXSEC1_MAGIC) {
        #[cfg(target_os = "linux")]
        {
            let key =
                nexus_platform_linux::secure_store::derive_key_from_machine_id().map_err(|_| {
                    "SECURE_STORE_UNAVAILABLE: machine-id missing or invalid".to_string()
                })?;
            nexus_platform::secure_store::decrypt_record(&key, enc)
                .map_err(|e| format!("AEAD_DECRYPT: {e:?}"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("STORE_ERROR: NEXSEC1 state requires Linux secure store".into())
        }
    } else if enc.starts_with(NEXDP1_MAGIC) {
        #[cfg(windows)]
        {
            nexus_platform_windows::dpapi::unprotect(&enc[NEXDP1_MAGIC.len()..])
                .map_err(|e| format!("DPAPI_UNPROTECT: {e}"))
        }
        #[cfg(not(windows))]
        {
            Err("STORE_ERROR: NEXDP1 state requires Windows DPAPI".into())
        }
    } else {
        // 明文状态（P3.1 兼容）。
        Ok(enc.to_vec())
    }
}

/// `subnet status`：读状态文件（自动检测加密格式，§12.31）。
///
/// 缺失/不可读 → DOWN；加密解密失败（篡改/密钥变化/平台不匹配）→ STORE_ERROR
/// （结构化，不 panic）；明文 JSON 损坏 → DOWN（P3.1 兼容）。
pub fn subnet_status(state_path: &Path) -> Value {
    let Ok(bytes) = std::fs::read(state_path) else {
        return serde_json::json!({
            "verdict": "DOWN",
            "command": "subnet status",
            "subnet": { "up": false },
        });
    };
    let Ok(plain) = decrypt_state_bytes(&bytes) else {
        return serde_json::json!({
            "verdict": "STORE_ERROR",
            "command": "subnet status",
            "subnet": { "up": false },
            "error": "STORE_ERROR",
        });
    };
    match serde_json::from_slice::<SubnetState>(&plain) {
        Ok(state) => serde_json::json!({
            "verdict": "PASS",
            "command": "subnet status",
            "subnet": {
                "up": state.up,
                "tunnel_id": state.tunnel_id,
                "virtual_ip": state.virtual_ip,
                "cidr": state.cidr,
                "peer_count": state.peer_count,
                "egress_peer_count": state.egress_peer_count,
                "prefix_route_count": state.prefix_route_count,
                "encryption": state.encryption,
                "punch": state.punch,
            },
        }),
        Err(_) => serde_json::json!({
            "verdict": "DOWN",
            "command": "subnet status",
            "subnet": { "up": false },
        }),
    }
}

/// `subnet leave`：删除状态文件。
pub fn subnet_leave(state_path: &Path) -> Value {
    let left = std::fs::remove_file(state_path).is_ok();
    serde_json::json!({
        "verdict": "PASS",
        "command": "subnet leave",
        "subnet": { "left": left },
    })
}

/// 校验 TUN 接口名（纯函数，P3.2）：非空、≤15 字节、不含 NUL。
pub fn validate_tun_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("INVALID_NAME: tun name is empty".into());
    }
    if name.len() > MAX_TUN_NAME_BYTES {
        return Err(format!(
            "INVALID_NAME: tun name too long: {} bytes (max {MAX_TUN_NAME_BYTES})",
            name.len()
        ));
    }
    if name.contains('\0') {
        return Err("INVALID_NAME: tun name contains NUL".into());
    }
    Ok(())
}

/// `--tun` 装配错误分类（纯函数，确定性测试）：VPI/carrier 创建错误 →
/// `{ verdict:"TUN_ERROR", command:"subnet up", error }`。
pub fn classify_tun_error(err: &str) -> Value {
    serde_json::json!({
        "verdict": "TUN_ERROR",
        "command": "subnet up",
        "error": err,
    })
}

/// 按已校验配置装配隧道（可指定 VPI 与 carrier，P3.2 真实数据面）。
/// v2 §7.2：bootstrap 入网 + 构造常驻 hook。`section.bootstrap` 为空 → `Ok(None)`；
/// 非空 → 经 DiscoveryBootstrapCodec 在 `&mut carrier` 上完成 PSK 入网，返回
/// `ClientBootstrapHook`（装箱，供 `tunnel.set_bootstrap_hook`）。抽成独立函数便于离线单测。
fn bootstrap_join_and_make_hook(
    carrier: &mut dyn PacketCarrier,
    identity: &KeyPair,
    section: &SubnetSection,
    now: u64,
) -> Result<Option<Box<dyn BootstrapHook>>, String> {
    if section.bootstrap.is_empty() {
        return Ok(None);
    }
    let psk = load_network_psk(section)?.ok_or("BOOTSTRAP_PSK_REQUIRED")?;
    let codec = crate::bootstrap_codec::DiscoveryBootstrapCodec::new();
    let eps: Vec<BootstrapEndpoint> = section
        .bootstrap
        .iter()
        .map(|b| BootstrapEndpoint {
            server_locator: b.address.clone(),
        })
        .collect();
    let mut joiner = BootstrapJoiner::new(carrier, identity, &psk, &codec);
    let (session, peers) = joiner
        .join(&eps, section.virtual_ip.as_deref(), now, 5_000)
        .map_err(|e| format!("BOOTSTRAP_JOIN: {e}"))?;
    let hook = ClientBootstrapHook::new(session, Box::new(codec), peers);
    Ok(Some(Box::new(hook)))
}

fn assemble_with(
    config: &SubnetConfig,
    vpi: Box<dyn VirtualPacketInterface>,
    carrier: Box<dyn PacketCarrier>,
    identity: &KeyPair,
) -> Result<VirtualSubnetTunnel, String> {
    let s = &config.subnet;
    // §12.43：调用方（subnet_up）须先解析 virtual_ip；此处防御性校验。
    let vip = s
        .virtual_ip
        .as_deref()
        .ok_or("VIRTUAL_IP_UNRESOLVED: virtual_ip must be resolved before assemble")?;
    // v2 §7.2：bootstrap 非空 → 在 carrier move 进隧道前，借 &mut carrier 完成 PSK 入网，
    // 得到常驻 hook；建隧道后 set_bootstrap_hook。carrier move 顺序：join(&mut carrier) → tunnel::new。
    // T3：identity 由调用方全程只获取一次传入（与 VIP 派生同一把 KeyPair）。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut carrier = carrier;
    let hook = bootstrap_join_and_make_hook(&mut *carrier, identity, s, now)?;
    // W-VIP：bootstrap 入网成功后，隧道本地 VIP 改用服务端权威租约 assigned_vip，
    // 保证本端地址与服务端分配一致（而非配置/派生的 static VIP）。
    let local_vip = hook
        .as_ref()
        .and_then(|h| h.assigned_vip().map(str::to_string))
        .unwrap_or_else(|| vip.to_string());
    let mut tunnel = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new(s.cidr.clone(), local_vip),
        vpi,
        carrier,
    );
    if let Some(h) = hook {
        tunnel.set_bootstrap_hook(Some(h));
    }
    for peer in &s.peers {
        tunnel
            .add_peer(TunnelPeer::new(
                peer.virtual_ip.clone(),
                peer.locator.clone(),
            ))
            .map_err(|e| e.to_string())?;
        tunnel.set_peer_state(&peer.virtual_ip, TunnelState::Connected);
    }
    for route in &s.routes {
        tunnel
            .add_route(route.dst.clone(), route.next_hop.clone())
            .map_err(|e| e.to_string())?;
    }
    for route in &s.prefix_routes {
        tunnel
            .add_prefix_route(&route.cidr, route.next_hop.clone())
            .map_err(|e| e.to_string())?;
    }
    for cidr in &s.local_prefixes {
        tunnel.add_local_prefix(cidr).map_err(|e| e.to_string())?;
    }
    for vip in &s.egress {
        tunnel.mark_egress(vip.clone()).map_err(|e| e.to_string())?;
    }
    if s.encryption {
        tunnel.enable_encryption(EncryptionConfig::default());
    }
    Ok(tunnel)
}

/// P3.5（§12.32）：daemon 组合根默认装配（MemoryVpi + MeshCarrier），
/// 返回隧道对象供 nexusd 常驻持有（进程为 Owner，随 drop 清理）。
pub fn assemble_default_tunnel(config_path: &Path) -> Result<VirtualSubnetTunnel, String> {
    let config = parse_config(config_path)?;
    let identity =
        load_node_identity().or_else(|_| KeyPair::generate().map_err(|e| e.to_string()))?;
    assemble_with(
        &config,
        Box::new(MemoryVpi::new()),
        Box::new(MeshCarrier::new()),
        &identity,
    )
}

/// 按已校验配置装配**真实数据面**隧道（UdpCarrier + 平台 VPI）。
///
/// 返回 `(tunnel, bound_locator)`：调用方持有 tunnel（进程为 Owner，随 drop 清理
/// wintun/tun 适配器与 UDP socket），`bound` 为 UDP 实际绑定地址。失败返回以
/// `TUN_ERROR:` 开头的错误字符串（udp bind / vpi create / assemble_with）。
#[cfg(windows)]
fn assemble_real_tunnel(
    config: &SubnetConfig,
    tun_name: &str,
    listen: &str,
) -> Result<(VirtualSubnetTunnel, String), String> {
    let mut carrier = UdpCarrier::new();
    let bound = carrier
        .bind(listen)
        .map_err(|e| format!("TUN_ERROR: udp bind: {e}"))?;
    let vpi = nexus_platform_windows::WintunVpiAdapter::create(tun_name, "Nexus")
        .map_err(|e| format!("TUN_ERROR: wintun create: {e}"))?;
    let identity =
        load_node_identity().or_else(|_| KeyPair::generate().map_err(|e| e.to_string()))?;
    let tunnel = assemble_with(config, Box::new(vpi), Box::new(carrier), &identity)?;
    Ok((tunnel, bound))
}

/// Linux 实现（/dev/net/tun + UDP 承载）。
#[cfg(target_os = "linux")]
fn assemble_real_tunnel(
    config: &SubnetConfig,
    tun_name: &str,
    listen: &str,
) -> Result<(VirtualSubnetTunnel, String), String> {
    let mut carrier = UdpCarrier::new();
    let bound = carrier
        .bind(listen)
        .map_err(|e| format!("TUN_ERROR: udp bind: {e}"))?;
    let vpi = nexus_platform_linux::TunVpi::create(tun_name)
        .map_err(|e| format!("TUN_ERROR: tun create: {e}"))?;
    let identity =
        load_node_identity().or_else(|_| KeyPair::generate().map_err(|e| e.to_string()))?;
    let tunnel = assemble_with(config, Box::new(vpi), Box::new(carrier), &identity)?;
    Ok((tunnel, bound))
}

/// `subnet up --tun`：真实 VPI（Windows wintun / Linux tun）+ 真实 UDP 承载。
///
/// 失败（dll 缺失 / 权限不足 / 驱动未安装 / 设备创建失败）→ `TUN_ERROR`
/// 结构化（exit 0）。成功输出含 `local_locator`（本地承载实际绑定地址）。
#[cfg(windows)]
pub fn subnet_up_tun(
    config_path: &Path,
    state_path: &Path,
    tun_name: &str,
    listen: &str,
) -> Result<Value, String> {
    validate_tun_name(tun_name)?;
    let config = parse_config(config_path)?;
    let (_tunnel, bound) = assemble_real_tunnel(&config, tun_name, listen)?;
    let mut out = subnet_up(config_path, state_path, false, false)?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("local_locator".into(), serde_json::json!(bound));
    }
    Ok(out)
}

/// `subnet up --tun`（Linux 实现：/dev/net/tun + UDP 承载）。
#[cfg(target_os = "linux")]
pub fn subnet_up_tun(
    config_path: &Path,
    state_path: &Path,
    tun_name: &str,
    listen: &str,
) -> Result<Value, String> {
    validate_tun_name(tun_name)?;
    let config = parse_config(config_path)?;
    let (_tunnel, bound) = assemble_real_tunnel(&config, tun_name, listen)?;
    let mut out = subnet_up(config_path, state_path, false, false)?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("local_locator".into(), serde_json::json!(bound));
    }
    Ok(out)
}

/// P3.8（§12.38）：daemon 常驻真实数据面装配。
///
/// 与 CLI `subnet_up_tun` 复用同一 `assemble_real_tunnel`，但**返回隧道对象**供
/// nexusd 常驻持有（进程为唯一 Owner，AGENTS §13/§14；函数返回 / drop 时清理
/// wintun/tun 适配器与 UDP socket）。失败返回以 `TUN_ERROR:` 开头的错误字符串
/// （tun 名校验失败为 `INVALID_NAME:`，调用方据此分类）。
#[cfg(any(windows, target_os = "linux"))]
pub fn assemble_real_tunnel_for_daemon(
    config_path: &Path,
    tun_name: &str,
    listen: &str,
) -> Result<(VirtualSubnetTunnel, String), String> {
    validate_tun_name(tun_name)?;
    let config = parse_config(config_path)?;
    assemble_real_tunnel(&config, tun_name, listen)
}

/// `subnet punch <peer_vip> <targets...>`（P4.2 §12.9.6）：真实 UDP carrier
/// 打洞——装配（UdpCarrier bind listen + MemoryVpi）→ `begin_hole_punch_multi`
/// → 本地接收循环（recv_and_deliver + punch_tick，attempts 上限）→ 输出
/// `{ verdict, command, state, locator, attempts, bound, events[] }`；结果写入
/// subnet 状态文件（`SubnetState.punch`），供 `subnet status` 复查。
pub fn subnet_punch(
    config_path: &Path,
    state_path: &Path,
    peer_vip: &str,
    targets: &[String],
    listen: &str,
    attempts: u32,
) -> Result<Value, String> {
    if targets.is_empty() {
        return Err("HOLE_PUNCH_EMPTY_TARGETS: no punch targets".into());
    }
    if attempts == 0 {
        return Err("INVALID_ATTEMPTS: attempts must be > 0".into());
    }
    let config = parse_config(config_path)?;
    let peer_known = config.subnet.peers.iter().any(|p| p.virtual_ip == peer_vip)
        || config.subnet.egress.iter().any(|e| e == peer_vip);
    if !peer_known {
        return Err(format!("PEER_NOT_FOUND: {peer_vip} not in [subnet.peers]"));
    }
    let mut carrier = UdpCarrier::new();
    let bound = carrier
        .bind(listen)
        .map_err(|e| format!("PUNCH_BIND_FAILED: {e}"))?;
    let identity =
        load_node_identity().or_else(|_| KeyPair::generate().map_err(|e| e.to_string()))?;
    let mut tunnel = assemble_with(
        &config,
        Box::new(MemoryVpi::new()),
        Box::new(carrier),
        &identity,
    )?;
    tunnel
        .add_peer(TunnelPeer::new(peer_vip, targets[0].clone()))
        .map_err(|e| e.to_string())?;
    tunnel
        .begin_hole_punch_multi(peer_vip, targets)
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 4096];
    let mut used = 0u32;
    for _ in 0..attempts {
        used += 1;
        // 收对端帧（ph/pa 处理在 tunnel 内部完成）。
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) = tunnel.recv_and_deliver(&mut buf, now_secs) {
            eprintln!("recv_and_deliver: {e}");
        }
        if tunnel.peer_state(peer_vip) == Some(TunnelState::Connected) {
            break;
        }
        if tunnel.punch_tick(peer_vip).is_err() {
            break;
        }
        if tunnel.peer_state(peer_vip) == Some(TunnelState::Connected) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let final_state = tunnel
        .peer_state(peer_vip)
        .unwrap_or(TunnelState::Disconnected);
    let final_locator = tunnel
        .peer_locator(peer_vip)
        .unwrap_or_else(|| targets[0].clone());
    let succeeded = final_state == TunnelState::Connected;
    let events: Vec<String> = tunnel
        .events()
        .iter()
        .filter_map(|e| match e {
            VirtualSubnetEvent::HolePunchStarted { targets, .. } => {
                Some(format!("started({})", targets.join(",")))
            }
            VirtualSubnetEvent::HolePunchSucceeded { target, .. } => {
                Some(format!("succeeded({target})"))
            }
            VirtualSubnetEvent::HolePunchFailed { targets, .. } => {
                Some(format!("failed({})", targets.join(",")))
            }
            _ => None,
        })
        .collect();

    let record = PunchRecord {
        peer_vip: peer_vip.to_string(),
        state: format!("{final_state:?}"),
        locator: final_locator.clone(),
        targets: targets.to_vec(),
        attempts: used,
        succeeded,
    };
    // 打洞结果持久化（observability 通道：`subnet status` 复查）。
    update_state_punch(state_path, record)?;

    Ok(serde_json::json!({
        "verdict": if succeeded { "PASS" } else { "FAIL" },
        "command": "subnet punch",
        "state": format!("{final_state:?}"),
        "locator": final_locator,
        "attempts": used,
        "bound": bound,
        "events": events,
    }))
}

/// 把打洞结果写回 subnet 状态文件（保留既有字段，`punch` 覆盖更新）。
///
/// 加密模式按**原文件 magic** 保留（NEXDP1 / NEXSEC1 → 加密重写；老明文 →
/// 保持明文），避免跨调用把加密状态文件静默降级为明文。
fn update_state_punch(state_path: &Path, punch: PunchRecord) -> Result<(), String> {
    let bytes = std::fs::read(state_path).map_err(|e| format!("STATE_READ: {e}"))?;
    let plain = decrypt_state_bytes(&bytes).map_err(|e| format!("STATE_DECRYPT: {e}"))?;
    let mut state: SubnetState =
        serde_json::from_slice(&plain).map_err(|e| format!("STATE_PARSE: {e}"))?;
    state.punch = Some(punch);
    let json = serde_json::to_string_pretty(&state).map_err(|e| format!("SERIALIZE: {e}"))?;
    let enc = if bytes.starts_with(nexus_platform::secure_store::NEXSEC1_MAGIC)
        || bytes.starts_with(NEXDP1_MAGIC)
    {
        encrypt_state_bytes(json.as_bytes())?
    } else {
        json.into_bytes()
    };
    std::fs::write(state_path, enc).map_err(|e| format!("STATE_WRITE: {e}"))
}

#[cfg(test)]
mod bootstrap_wire_tests {
    use super::*;
    use nexus_connectivity::bootstrap_server::{BootstrapServer, BootstrapServerConfig};
    use nexus_connectivity::encryption::KeyPair;
    use nexus_connectivity::virtual_subnet::MemoryCarrier;
    use nexus_platform::PacketCarrier;

    fn section_with_bootstrap(addr: &str, psk: &str) -> SubnetSection {
        SubnetSection {
            cidr: "10.144.144.0/24".into(),
            virtual_ip: None,
            encryption: false,
            network_psk: Some(psk.into()),
            network_psk_file: None,
            bootstrap: vec![BootstrapConfig {
                address: addr.into(),
                name: None,
            }],
            peers: Vec::new(),
            routes: Vec::new(),
            prefix_routes: Vec::new(),
            local_prefixes: Vec::new(),
            egress: Vec::new(),
        }
    }

    #[test]
    fn bootstrap_join_and_make_hook_offline_e2e() {
        let server_identity = KeyPair::from_seed(&[9u8; 32]);
        let client_identity = KeyPair::from_seed(&[1u8; 32]);
        let (server_carrier, client_carrier) = MemoryCarrier::connected_pair();

        let cfg = BootstrapServerConfig {
            cidr: "10.144.144.0/24".into(),
            lease_secs: 60,
            hb_interval_ms: 20_000,
            refresh_interval_ms: 60_000,
            server_vip: "10.144.144.1".into(),
            server_locator: "udp://bootstrap:11010".into(),
            max_pending_per_src: 4,
        };
        let mut server = BootstrapServer::new(
            server_identity,
            b"shared-psk".to_vec(),
            cfg,
            Box::new(crate::bootstrap_codec::DiscoveryBootstrapCodec::new()),
            None,
        )
        .unwrap();
        server.upsert_self_entry(1000);

        let mut sc = server_carrier;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            loop {
                match sc.receive_into(&mut buf) {
                    Ok(0) => std::thread::sleep(std::time::Duration::from_millis(1)),
                    Ok(n) => {
                        if let Some((dst, bytes)) =
                            server.handle_datagram("udp://client:1", &buf[..n], 1000)
                        {
                            let _ = sc.send_to(&dst, &bytes);
                        }
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                }
            }
        });

        let section = section_with_bootstrap("udp://bootstrap:11010", "shared-psk");
        let mut cc = client_carrier;
        let mut hook = bootstrap_join_and_make_hook(&mut cc, &client_identity, &section, 1000)
            .expect("join ok")
            .expect("hook present");
        // 推进到刷新间隔之后：periodic 应产出刷新/心跳 datagrams。
        let tick = hook.periodic(61_000);
        assert!(
            !tick.datagrams.is_empty(),
            "periodic should emit heartbeat/refresh"
        );
        assert!(
            tick.peers_added
                .iter()
                .any(|p| p.virtual_ip == "10.144.144.1")
        );
    }

    #[test]
    fn bootstrap_wrong_psk_returns_typed_err_no_hook() {
        let server_identity = KeyPair::from_seed(&[9u8; 32]);
        let client_identity = KeyPair::from_seed(&[1u8; 32]);
        let (server_carrier, client_carrier) = MemoryCarrier::connected_pair();
        let cfg = BootstrapServerConfig {
            cidr: "10.144.144.0/24".into(),
            lease_secs: 60,
            hb_interval_ms: 20_000,
            refresh_interval_ms: 60_000,
            server_vip: "10.144.144.1".into(),
            server_locator: "udp://bootstrap:11010".into(),
            max_pending_per_src: 4,
        };
        let mut server = BootstrapServer::new(
            server_identity,
            b"right-psk".to_vec(),
            cfg,
            Box::new(crate::bootstrap_codec::DiscoveryBootstrapCodec::new()),
            None,
        )
        .unwrap();
        server.upsert_self_entry(1000);
        let mut sc = server_carrier;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            loop {
                match sc.receive_into(&mut buf) {
                    Ok(0) => std::thread::sleep(std::time::Duration::from_millis(1)),
                    Ok(n) => {
                        if let Some((dst, bytes)) =
                            server.handle_datagram("udp://client:1", &buf[..n], 1000)
                        {
                            let _ = sc.send_to(&dst, &bytes);
                        }
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                }
            }
        });
        let section = section_with_bootstrap("udp://bootstrap:11010", "wrong-psk");
        let mut cc = client_carrier;
        let err = match bootstrap_join_and_make_hook(&mut cc, &client_identity, &section, 1000) {
            Err(e) => e,
            Ok(_) => panic!("wrong psk must not succeed"),
        };
        assert!(err.contains("BOOTSTRAP_JOIN"));
    }
}

#[cfg(test)]
mod bootstrap_guard_tests {
    use super::*;
    use std::io::Write;

    fn write_config(dir: &std::path::Path, toml: &str) -> std::path::PathBuf {
        let p = dir.join("subnet.toml");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        p
    }

    #[test]
    fn non_foreground_with_bootstrap_is_rejected() {
        let dir = std::path::PathBuf::from("/tmp/nxb_guard_dbg");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = r#"[subnet]
cidr = "10.144.144.0/24"
network_psk = "shared-psk"
[[subnet.bootstrap]]
address = "udp://bootstrap:11010"
"#;
        let cp = write_config(&dir, cfg);
        let sp = dir.join("state.json");
        let err = subnet_up(&cp, &sp, false, false).unwrap_err();
        assert!(err.contains("BOOTSTRAP_REQUIRES_FOREGROUND"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
