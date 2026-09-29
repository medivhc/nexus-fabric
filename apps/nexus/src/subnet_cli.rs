//! P3.1 子网 CLI（PRODUCT §12.28）+ P3.4 状态文件加密（§12.31）：
//! TOML 配置 → VirtualSubnetTunnel 装配 + 状态文件（明文或平台加密）。
//!
//! Composition Root 层（apps/nexus 允许 I/O）：配置校验 → 进程内装配（MeshCarrier
//! mock carrier，真实 TUN 留 P3-2）→ 状态写入本地文件（默认 `~/.nexus/subnet.json`，
//! `--state` 可覆盖）。crate 层保持零 I/O。

use std::path::{Path, PathBuf};

use nexus_connectivity::cidr::{cidr_contains, parse_cidr};
use nexus_connectivity::coord::derive_vip;
use nexus_connectivity::encryption::{EncryptionConfig, KeyPair};
use nexus_connectivity::virtual_subnet::{
    MemoryVpi, MeshCarrier, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetEvent,
    VirtualSubnetTunnel,
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

/// `subnet up --config <path>`：校验 → 装配 → 写状态文件（`--encrypt-state` 加密落盘）。
pub fn subnet_up(
    config_path: &Path,
    state_path: &Path,
    encrypt_state: bool,
) -> Result<Value, String> {
    let config = parse_config(config_path)?;
    // §12.43：PSK 文件权限等在装配前校验（fail-closed）。
    let _psk = load_network_psk(&config.subnet)?;
    // §12.43：virtual_ip 缺省 → 确定性派生。
    // E4/mock 路径用临时身份；生产 daemon 必须用 §12.39 持久身份（secure-store），见 Feature 2。
    let virtual_ip = match &config.subnet.virtual_ip {
        Some(vip) => vip.clone(),
        None => {
            let eph_id = KeyPair::generate().map_err(|e| format!("DERIVE_VIP_IDENTITY: {e:?}"))?;
            derive_vip(eph_id.public_key_bytes(), &config.subnet.cidr, 0)
                .map_err(|e| format!("DERIVE_VIP: {e:?}"))?
                .to_string()
        }
    };
    let mut config = config;
    config.subnet.virtual_ip = Some(virtual_ip.clone());
    let _tunnel = assemble_with(
        &config,
        Box::new(MemoryVpi::new()),
        Box::new(MeshCarrier::new()),
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
fn assemble_with(
    config: &SubnetConfig,
    vpi: Box<dyn VirtualPacketInterface>,
    carrier: Box<dyn PacketCarrier>,
) -> Result<VirtualSubnetTunnel, String> {
    let s = &config.subnet;
    // §12.43：调用方（subnet_up）须先解析 virtual_ip；此处防御性校验。
    let vip = s
        .virtual_ip
        .as_deref()
        .ok_or("VIRTUAL_IP_UNRESOLVED: virtual_ip must be resolved before assemble")?;
    let mut tunnel = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new(s.cidr.clone(), vip.to_string()),
        vpi,
        carrier,
    );
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
    assemble_with(
        &config,
        Box::new(MemoryVpi::new()),
        Box::new(MeshCarrier::new()),
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
    let tunnel = assemble_with(config, Box::new(vpi), Box::new(carrier))?;
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
    let tunnel = assemble_with(config, Box::new(vpi), Box::new(carrier))?;
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
    let mut out = subnet_up(config_path, state_path, false)?;
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
    let mut out = subnet_up(config_path, state_path, false)?;
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
    let mut tunnel = assemble_with(&config, Box::new(MemoryVpi::new()), Box::new(carrier))?;
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
        if let Err(e) = tunnel.recv_and_deliver(&mut buf) {
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
