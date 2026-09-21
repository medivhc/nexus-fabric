//! P3.1 子网 CLI（PRODUCT §12.16）：TOML 配置 → VirtualSubnetTunnel 装配 + 状态文件。
//!
//! Composition Root 层（apps/nexus 允许 I/O）：配置校验 → 进程内装配（MeshCarrier
//! mock carrier，真实 TUN 留 P3-2）→ 状态写入本地文件（默认 `~/.nexus/subnet.json`，
//! `--state` 可覆盖）。crate 层保持零 I/O。

use std::path::{Path, PathBuf};

use nexus_connectivity::cidr::{cidr_contains, parse_cidr};
use nexus_connectivity::encryption::EncryptionConfig;
use nexus_connectivity::virtual_subnet::{
    MemoryVpi, MeshCarrier, TunnelPeer, TunnelState, VirtualSubnetConfig, VirtualSubnetTunnel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 子网 TOML 配置（`[subnet]` 表）。
#[derive(Debug, Clone, Deserialize)]
pub struct SubnetConfig {
    /// `[subnet]` 表。
    pub subnet: SubnetSection,
}

/// `[subnet]` 配置段。
#[derive(Debug, Clone, Deserialize)]
pub struct SubnetSection {
    /// 子网 CIDR（如 "10.99.0.0/24"）。
    pub cidr: String,
    /// 本节点虚拟 IP（须在 cidr 内）。
    pub virtual_ip: String,
    /// 是否开启隧道加密（P2-1 §12.7），默认关。
    #[serde(default)]
    pub encryption: bool,
    /// 对端节点列表。
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
    if !cidr_contains(&prefix, &s.virtual_ip) {
        return Err("VIRTUAL_IP_OUTSIDE_SUBNET: virtual_ip not in cidr".into());
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

/// 按已校验配置装配隧道（MeshCarrier mock carrier）。
fn assemble(config: &SubnetConfig) -> Result<VirtualSubnetTunnel, String> {
    let s = &config.subnet;
    let mut tunnel = VirtualSubnetTunnel::new(
        VirtualSubnetConfig::new(s.cidr.clone(), s.virtual_ip.clone()),
        Box::new(MemoryVpi::new()),
        Box::new(MeshCarrier::new()),
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

/// `subnet up --config <path>`：校验 → 装配 → 写状态文件。
pub fn subnet_up(config_path: &Path, state_path: &Path) -> Result<Value, String> {
    let config = parse_config(config_path)?;
    let _tunnel = assemble(&config)?;
    let s = &config.subnet;
    let state = SubnetState {
        up: true,
        tunnel_id: format!("tunnel-{}", s.virtual_ip),
        virtual_ip: s.virtual_ip.clone(),
        cidr: s.cidr.clone(),
        peer_count: s.peers.len(),
        egress_peer_count: s.egress.len(),
        prefix_route_count: s.prefix_routes.len(),
        encryption: s.encryption,
    };
    let json = serde_json::to_string_pretty(&state).map_err(|e| format!("SERIALIZE: {e}"))?;
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("MKDIR_STATE: {e}"))?;
    }
    std::fs::write(state_path, json).map_err(|e| format!("WRITE_STATE: {e}"))?;
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

/// `subnet status`：读状态文件。
pub fn subnet_status(state_path: &Path) -> Value {
    let Ok(text) = std::fs::read_to_string(state_path) else {
        return serde_json::json!({
            "verdict": "DOWN",
            "command": "subnet status",
            "subnet": { "up": false },
        });
    };
    match serde_json::from_str::<SubnetState>(&text) {
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
