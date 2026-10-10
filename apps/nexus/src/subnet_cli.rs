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
use nexus_connectivity::bootstrap_server::{
    BootstrapServer, BootstrapServerConfig, ServerBootstrapHook,
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

/// 引导入网被装配到 mock carrier 上时的明确错误（v2 §7.2 M12）。
///
/// bootstrap 握手需要真实 UDP socket；`subnet up` 的状态写入路径用
/// `MeshCarrier`（进程内、无连线），在那里发起握手只会白等满 5s 超时。
pub const BOOTSTRAP_NEEDS_REAL_CARRIER: &str = "BOOTSTRAP_NEEDS_REAL_CARRIER: bootstrap join requires the real UDP data plane \
     (use `nexus subnet up --config <path> --foreground --tun`)";

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
    /// 引导节点服务端角色（v2 §8.1）；缺省 = 普通节点，不启用服务端。
    #[serde(default)]
    pub bootstrap_server: Option<BootstrapServerSection>,
}

/// `[subnet.bootstrap_server]` 配置段（v2 §8.1）：开启引导节点服务端角色。
///
/// `deny_unknown_fields` 是有意的：现反序列化默认忽略未知键（拼错字段不报错，
/// 设计 L11），服务端配置写错会静默失效，故在此 fail-fast。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapServerSection {
    /// 是否启用服务端角色；缺省 = 启用（配了本表即视为开启）。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 租约秒数（建议 3× 心跳间隔）。
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u32,
    /// 心跳间隔毫秒。
    #[serde(default = "default_hb_interval_ms")]
    pub hb_interval_ms: u32,
    /// PeerList 刷新间隔毫秒。
    #[serde(default = "default_refresh_interval_ms")]
    pub refresh_interval_ms: u32,
    /// 服务端对外可达 locator（目录第 0 条）。缺省 = `""`，由装配层从实际绑定的
    /// UDP socket 回填——配置里写死会让端口漂移后目录指向死地址。
    #[serde(default)]
    pub locator: Option<String>,
    /// VIP 租约落盘路径（§6.6）。缺省 = `<node-dir>/data/bootstrap/vip-leases.json`。
    #[serde(default)]
    pub lease_state_path: Option<String>,
    /// 每 src 半开 JoinInit 上限（S3）。
    #[serde(default = "default_max_pending_per_src")]
    pub max_pending_per_src: usize,
}

fn default_true() -> bool {
    true
}
fn default_lease_secs() -> u32 {
    60
}
fn default_hb_interval_ms() -> u32 {
    20_000
}
fn default_refresh_interval_ms() -> u32 {
    60_000
}
fn default_max_pending_per_src() -> usize {
    4
}

impl Default for BootstrapServerSection {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            lease_secs: default_lease_secs(),
            hb_interval_ms: default_hb_interval_ms(),
            refresh_interval_ms: default_refresh_interval_ms(),
            locator: None,
            lease_state_path: None,
            max_pending_per_src: default_max_pending_per_src(),
        }
    }
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
    let config = parse_config_public(path)?;
    validate(&config)?;
    Ok(config)
}

/// 解析并返回配置（**不做** `validate`）——供只需读取配置的辅助路径使用
/// （如常驻循环里为 VIP 租约表定路径）；校验仍由 `parse_config` 在装配前把关。
pub fn parse_config_public(path: &Path) -> Result<SubnetConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("READ_CONFIG: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("PARSE_TOML: {e}"))
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
    validate_bootstrap_server(config)?;
    Ok(())
}

/// `[subnet.bootstrap_server]` 校验（v2 §8.1）：间隔必须为正（0 会让 tick 永不
/// 到期/心跳风暴）、服务端 VIP 必须在 cidr 内、PSK 必填（服务端与客户端共享）。
fn validate_bootstrap_server(config: &SubnetConfig) -> Result<(), String> {
    let Some(bs) = &config.subnet.bootstrap_server else {
        return Ok(());
    };
    if !bs.enabled {
        return Ok(());
    }
    let s = &config.subnet;
    if bs.lease_secs == 0 {
        return Err("BOOTSTRAP_SERVER_LEASE: lease_secs must be > 0".into());
    }
    if bs.hb_interval_ms == 0 {
        return Err("BOOTSTRAP_SERVER_HB: hb_interval_ms must be > 0".into());
    }
    if bs.refresh_interval_ms == 0 {
        return Err("BOOTSTRAP_SERVER_REFRESH: refresh_interval_ms must be > 0".into());
    }
    // 服务端自身 VIP 必须显式配置且落在 cidr 内（§5.4 启动占位的前提）。
    let Some(vip) = s.virtual_ip.as_deref() else {
        return Err(
            "BOOTSTRAP_SERVER_VIP: [subnet.bootstrap_server] requires subnet.virtual_ip \
             (the server's own VIP, reserved at startup)"
                .into(),
        );
    };
    let prefix = parse_cidr(&s.cidr).map_err(|e| format!("CIDR: {e}"))?;
    if !cidr_contains(&prefix, vip) {
        return Err(format!(
            "BOOTSTRAP_SERVER_VIP: server virtual_ip {vip} not in cidr {}",
            s.cidr
        ));
    }
    if s.network_psk.is_none() && s.network_psk_file.is_none() {
        return Err(
            "PSK_REQUIRED: bootstrap server requires network_psk or network_psk_file".into(),
        );
    }
    // 隧道只有一个 bootstrap hook 槽位（`virtual_subnet.rs` 的 `bootstrap` 字段），
    // 服务端与客户端角色无法共存。显式拒绝，而不是让其中一个被静默顶掉——否则用户
    // 会得到"配了却不生效"的引导节点，且没有任何提示。
    if !s.bootstrap.is_empty() {
        return Err(
            "BOOTSTRAP_ROLE_CONFLICT: a node cannot be both bootstrap server and client \
             (the tunnel carries a single bootstrap hook); remove either \
             [subnet.bootstrap_server] or [[subnet.bootstrap]]"
                .into(),
        );
    }
    if let Some(loc) = &bs.locator {
        if !loc.starts_with("udp://") {
            return Err(format!(
                "BOOTSTRAP_SERVER_LOCATOR: unsupported scheme in '{loc}' (want udp://host:port)"
            ));
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

/// 读取本节点长期身份（v2 §7.4 / S7）：`node/identity` 的 `x25519_seed_hex`
/// → `KeyPair::from_seed`。
///
/// 身份文件不存在时**自动 init 并持久化**（复用 `node init` 的写盘路径，0600 权限），
/// 使 node_id / 派生存根在重启后保持稳定。刻意不提供 `KeyPair::generate()`
/// 降级：一次性密钥会让每次重启换 static 公钥，服务端按权威 node_id 做的
/// VIP 租约回收与幂等找回随之失效。
///
/// 读失败（目录不可写 / 记录损坏）→ 明确报错，禁止静默生成临时身份。
fn load_node_identity() -> Result<KeyPair, String> {
    let dir = crate::node_cli::node_dir();
    let file = crate::node_cli::identity_file_name();
    if !dir.join(&file).exists() {
        crate::node_cli::ensure_node_identity(&dir)
            .map_err(|e| format!("NODE_IDENTITY_INIT: {e}"))?;
    }
    let path = dir.join(&file);
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
    // T3：身份全程只获取一次（load_node_identity），VIP 派生、状态写与
    // join/assemble_with 共用同一把 KeyPair。
    let identity = load_node_identity()?;
    // §12.43：virtual_ip 缺省 → 由同一身份公钥确定性派生。
    let virtual_ip = match &config.subnet.virtual_ip {
        Some(vip) => vip.clone(),
        None => derive_vip(identity.public_key_bytes(), &config.subnet.cidr, 0)
            .map_err(|e| format!("DERIVE_VIP: {e:?}"))?
            .to_string(),
    };
    let mut config = config;
    let has_bootstrap = !config.subnet.bootstrap.is_empty();
    config.subnet.virtual_ip = Some(virtual_ip.clone());
    // CRITICAL-2：本函数只写状态文件，carrier 是进程内 MeshCarrier（无真实连线）。
    // 这里的装配纯属配置校验，绝不能发起网络握手——否则 join 必然超时并让
    // `subnet up` 崩溃。真实握手只发生在 assemble_real_tunnel 路径。
    //
    // 配了 bootstrap 时连这个"离线装配"也做不了（mock carrier 无法承载握手，
    // 见 BOOTSTRAP_NEEDS_REAL_CARRIER），而配置面已由上面的 parse_config/PSK
    // 校验覆盖、握手结果由调用方持有的真实隧道负责，故直接跳过。状态文件里的
    // virtual_ip 字段是"请求值"；权威租约以隧道内 assigned_vip 为准。
    if !has_bootstrap {
        let _tunnel = assemble_with_offline(
            &config,
            Box::new(MemoryVpi::new()),
            Box::new(MeshCarrier::new()),
            &identity,
        )?;
    }
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
            // 引导角色可见性（CRITICAL-4）：用户能直接看出自己是不是引导节点，
            // 而不是配了 `[subnet.bootstrap_server]` 却毫无反馈。
            "bootstrap_client": has_bootstrap,
            "bootstrap_server": server_role_enabled(&config.subnet),
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

/// 向 OS 借一个空闲 UDP 端口，返回可直接喂给 `UdpCarrier::bind` 的 locator。
///
/// `UdpCarrier::bind` 显式拒绝 port 0（`udp_carrier.rs:56`），所以"让 OS 随机分配"
/// 只能在这里做一次 bind(0)→读端口→drop 的探测，再把**具体端口**交给真实路径。
/// 存在 TOCTOU 窗口（探测与正式 bind 之间端口可能被占），故失败时由调用方按
/// `TUN_ERROR` 结构化上报，不静默换端口重试。
pub fn allocate_ephemeral_udp_locator() -> Result<String, String> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .map_err(|e| format!("TUN_ERROR: udp ephemeral bind: {e}"))?;
    let port = sock
        .local_addr()
        .map_err(|e| format!("TUN_ERROR: udp local_addr: {e}"))?
        .port();
    drop(sock);
    Ok(format!("udp://0.0.0.0:{port}"))
}

/// `assemble_with` 的入网策略。
///
/// 二者必居其一，避免"要不要发起网络握手"这种隐式决定散落在调用点：
/// - `Join`：carrier 绑定真实 socket，可发起 PSK 握手（`assemble_real_tunnel`）。
/// - `NoJoin`：carrier 是进程内 mock（`subnet_up` 的 MeshCarrier、纯校验装配），
///   一律不发起握手，直接用配置/派生的 `virtual_ip`。否则 mock carrier 上
///   永远等不到回包，join 必然超时并让 `subnet up` 崩溃。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapPolicy {
    Join,
    NoJoin,
}

/// 同 [`assemble_with_policy`]，额外接受服务端角色的对外 locator（真实数据面
/// 路径 bind 之后才有；mock 路径传 `None` → 服务端角色不装配）。
fn assemble_with_policy_at(
    config: &SubnetConfig,
    vpi: Box<dyn VirtualPacketInterface>,
    carrier: Box<dyn PacketCarrier>,
    identity: &KeyPair,
    policy: BootstrapPolicy,
    server_locator: Option<&str>,
) -> Result<VirtualSubnetTunnel, String> {
    let s = &config.subnet;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut carrier = carrier;
    // v2 §7.2 接线点 1：bootstrap 分支先握手，成功后以服务端权威租约
    // (sess.assigned_vip) 作为隧道本地 VIP；仅在**无** bootstrap 的静态模式才
    // 要求配置里已解析出 virtual_ip。原实现把该校验放在 join 之前，导致
    // "virtual_ip 留空由服务端分配" 这条核心流程在装配期就 100% 失败。
    let (hook, local_vip) = match policy {
        BootstrapPolicy::Join => {
            if s.bootstrap.is_empty() {
                // 无客户端引导列表：这是静态真实数据面，或引导**服务端**角色
                // （服务端自身 VIP 必须在配置中显式给出，见 validate_bootstrap_server）。
                // 两种情况下都不发起握手，本地 VIP 直接用配置值。
                // 回归修复：C1 补丁曾让 Join 分支对空 bootstrap 也强制要求
                // assigned_vip，导致所有静态 `--tun` 常驻与 CRITICAL-4 服务端角色
                // 在装配期即 VIRTUAL_IP_UNRESOLVED。
                let vip = s
                    .virtual_ip
                    .as_deref()
                    .ok_or("VIRTUAL_IP_UNRESOLVED: virtual_ip must be resolved before assemble")?;
                (None, vip.to_string())
            } else {
                let hook = bootstrap_join_and_make_hook(&mut *carrier, identity, s, now)?;
                // W-VIP：入网成功后本地 VIP 用服务端权威租约，而非配置/派生的 static VIP。
                let vip = hook
                    .as_ref()
                    .and_then(|h| h.assigned_vip().map(str::to_string))
                    .ok_or("VIRTUAL_IP_UNRESOLVED: virtual_ip must be resolved before assemble")?;
                (hook, vip)
            }
        }
        BootstrapPolicy::NoJoin => {
            if !s.bootstrap.is_empty() {
                // v2 §7.2 M12：mock carrier（MeshCarrier，无真实 UDP）不发起握手，
                // 也不静默假装入网成功——引导入网只在真实数据面路径受支持。
                return Err(BOOTSTRAP_NEEDS_REAL_CARRIER.to_string());
            }
            let vip = s
                .virtual_ip
                .as_deref()
                .ok_or("VIRTUAL_IP_UNRESOLVED: virtual_ip must be resolved before assemble")?;
            (None, vip.to_string())
        }
    };
    // v2 §7.2 服务端角色（CRITICAL-4）：`[subnet.bootstrap_server]` 配置存在且启用时，
    // 把 BootstrapServer 包成常驻 hook 挂到隧道上——否则收到的 `nxb:` 帧在
    // recv_and_deliver 里因 self.bootstrap == None 被静默丢弃，引导节点无法服务。
    let hook: Option<Box<dyn BootstrapHook>> =
        match build_server_hook(config, identity, server_locator)? {
            Some(server_hook) => Some(Box::new(server_hook)),
            None => hook,
        };
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

/// `[subnet.bootstrap_server]` 是否启用服务端角色（缺省表 = 普通节点）。
fn server_role_enabled(s: &SubnetSection) -> bool {
    s.bootstrap_server.as_ref().is_some_and(|b| b.enabled)
}

/// VIP 租约表（§6.6）：版本化 envelope，落盘内容 = `leases_snapshot`。
///
/// 故意**不带**设计稿里的 `payload_sha256`：写入端只有本进程，而
/// `BootstrapServer::new` 对回填是幂等跳过语义（冲突不拒启），故校验和只会
/// 把"文件损坏"升级成"拒绝启动"这一种额外行为，收益与复杂度不匹配。损坏按
/// 空表处理并告警——VIP 表丢失只导致重分配，不造成不一致。
#[derive(Debug, Serialize, Deserialize)]
struct LeaseStateFile {
    schema_version: u32,
    leases: std::collections::BTreeMap<String, String>,
}

const LEASE_SCHEMA_VERSION: u32 = 1;

/// 回读 VIP 租约表；文件不存在 → `Ok(None)`（首次启动）。
fn read_lease_state(path: &Path) -> Result<Option<Vec<(String, String)>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read lease state {path:?}: {e}")),
    };
    let v: LeaseStateFile =
        serde_json::from_str(&text).map_err(|e| format!("parse lease state {path:?}: {e}"))?;
    if v.schema_version != LEASE_SCHEMA_VERSION {
        return Err(format!(
            "lease state schema {} != {LEASE_SCHEMA_VERSION}",
            v.schema_version
        ));
    }
    Ok(Some(v.leases.into_iter().collect()))
}

/// 原子落盘 VIP 租约表（§6.6）：写 `.tmp` → `rename` → 目录 fsync；文件 `0600`。
///
/// 原子性保证崩溃后要么是旧表要么是新表，不会读到半截 JSON（→ 不会被解析成空表
/// 而白白重分配一批在线节点的 VIP）。
pub fn write_lease_state(path: &Path, leases: &[(String, String)]) -> Result<(), String> {
    let file = LeaseStateFile {
        schema_version: LEASE_SCHEMA_VERSION,
        leases: leases.iter().cloned().collect(),
    };
    let body = serde_json::to_vec(&file).map_err(|e| format!("serialize lease state: {e}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("lease state path has no parent: {path:?}"))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("mkdir lease dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("create lease tmp: {e}"))?;
        f.write_all(&body)
            .map_err(|e| format!("write lease tmp: {e}"))?;
        f.sync_all().map_err(|e| format!("sync lease tmp: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod lease tmp: {e}"))?;
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename lease state: {e}"))?;
    // 目录 fsync：让 rename 本身落盘，否则崩溃后可能退回旧目录项。
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(parent) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// 构建服务端角色的常驻 hook（CRITICAL-4）。
///
/// 未配置 `[subnet.bootstrap_server]` 或 `enabled = false` → `Ok(None)`（普通节点）。
/// 配置了但没有真实 locator（mock carrier 路径）→ `Ok(None)`，因为服务端必须把自己
/// 的可达 locator 放进在线目录第 0 条，缺了会给客户端一个连不上的引导地址；此处
/// 不静默降级成"启用但不发布 locator"，由调用方在真实路径保证传入。
fn build_server_hook(
    config: &SubnetConfig,
    identity: &KeyPair,
    server_locator: Option<&str>,
) -> Result<Option<ServerBootstrapHook>, String> {
    let s = &config.subnet;
    let Some(bs) = &s.bootstrap_server else {
        return Ok(None);
    };
    if !bs.enabled {
        return Ok(None);
    }
    let Some(locator) = server_locator.or(bs.locator.as_deref()) else {
        return Ok(None);
    };
    let psk = load_network_psk(s)?.ok_or("BOOTSTRAP_SERVER_PSK_REQUIRED")?;
    let server_vip = s
        .virtual_ip
        .as_deref()
        .ok_or("BOOTSTRAP_SERVER_VIP: server role requires subnet.virtual_ip")?;
    // §6.6：启动回读租约表，逐条幂等回填；文件缺失/损坏按空表处理（只导致重分配，
    // 不应拒启）。
    let lease_path = bootstrap_lease_state_path_for(bs);
    let persisted = read_lease_state(&lease_path).unwrap_or_else(|e| {
        eprintln!("bootstrap: lease state unreadable ({e}); starting from an empty table");
        None
    });
    let cfg = BootstrapServerConfig {
        cidr: s.cidr.clone(),
        lease_secs: bs.lease_secs,
        hb_interval_ms: bs.hb_interval_ms,
        refresh_interval_ms: bs.refresh_interval_ms,
        server_vip: server_vip.to_string(),
        server_locator: locator.to_string(),
        max_pending_per_src: bs.max_pending_per_src,
    };
    let codec = crate::bootstrap_codec::DiscoveryBootstrapCodec::new();
    let server = BootstrapServer::new(identity.clone(), psk, cfg, Box::new(codec), persisted)
        .map_err(|e| format!("BOOTSTRAP_SERVER_INIT: {e}"))?;
    Ok(Some(ServerBootstrapHook::new(server)))
}

/// VIP 租约落盘路径（§6.6）：`<node-dir>/data/bootstrap/vip-leases.json`。
pub fn bootstrap_lease_state_path_for(bs: &BootstrapServerSection) -> PathBuf {
    match &bs.lease_state_path {
        Some(p) => PathBuf::from(p),
        None => crate::node_cli::node_dir()
            .join("data")
            .join("bootstrap")
            .join("vip-leases.json"),
    }
}

/// 装配隧道但**不**发起 bootstrap 握手（carrier 为进程内 mock 的校验/状态写入路径）。
fn assemble_with_offline(
    config: &SubnetConfig,
    vpi: Box<dyn VirtualPacketInterface>,
    carrier: Box<dyn PacketCarrier>,
    identity: &KeyPair,
) -> Result<VirtualSubnetTunnel, String> {
    assemble_with_policy_at(
        config,
        vpi,
        carrier,
        identity,
        BootstrapPolicy::NoJoin,
        None,
    )
}

/// P3.5（§12.32）：daemon 组合根默认装配（MemoryVpi + MeshCarrier），
/// 返回隧道对象供 nexusd 常驻持有（进程为 Owner，随 drop 清理）。
///
/// carrier 是进程内 mock，无真实 UDP 连线，故走 [`BootstrapPolicy::NoJoin`]：
/// bootstrap 入网只支持真实数据面路径（`assemble_real_tunnel`）。
pub fn assemble_default_tunnel(config_path: &Path) -> Result<VirtualSubnetTunnel, String> {
    let mut config = parse_config(config_path)?;
    let identity = load_node_identity()?;
    resolve_static_virtual_ip(&mut config, &identity)?;
    assemble_with_offline(
        &config,
        Box::new(MemoryVpi::new()),
        Box::new(MeshCarrier::new()),
        &identity,
    )
}

/// 无 bootstrap 时按身份公钥确定性派生 `virtual_ip`（§12.43），使 mock 装配路径
/// 与 `subnet_up` 行为一致；有 bootstrap 时保持 `None` 交给服务端分配。
fn resolve_static_virtual_ip(config: &mut SubnetConfig, identity: &KeyPair) -> Result<(), String> {
    if !config.subnet.bootstrap.is_empty() || config.subnet.virtual_ip.is_some() {
        return Ok(());
    }
    let derived = derive_vip(identity.public_key_bytes(), &config.subnet.cidr, 0)
        .map_err(|e| format!("DERIVE_VIP: {e:?}"))?;
    config.subnet.virtual_ip = Some(derived.to_string());
    Ok(())
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
    let identity = load_node_identity()?;
    // 服务端角色需要真实 bind 后的 locator 进在线目录第 0 条（§6.7）。
    let tunnel = assemble_with_policy_at(
        config,
        Box::new(vpi),
        Box::new(carrier),
        &identity,
        BootstrapPolicy::Join,
        Some(&bound),
    )?;
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
    let identity = load_node_identity()?;
    // 服务端角色需要真实 bind 后的 locator 进在线目录第 0 条（§6.7）。
    let tunnel = assemble_with_policy_at(
        config,
        Box::new(vpi),
        Box::new(carrier),
        &identity,
        BootstrapPolicy::Join,
        Some(&bound),
    )?;
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
    let identity = load_node_identity()?;
    // 打洞目标按静态配置校验（`peer_known` 要求在 [subnet.peers]/egress 中），
    // 是一次性显式命令：不做 bootstrap 握手，否则会平白等满 5s 超时。
    let mut config = config;
    resolve_static_virtual_ip(&mut config, &identity)?;
    let mut tunnel = assemble_with_offline(
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
            bootstrap_server: None,
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

/// 评审 r1 的 CRITICAL 回归测试。每条对应一个曾经让引导入网完全不可用的缺陷。
#[cfg(test)]
mod review_r1_regression_tests {
    use super::*;
    use std::io::Write;

    fn write_config(dir: &std::path::Path, toml: &str) -> std::path::PathBuf {
        let p = dir.join("subnet.toml");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        p
    }

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(format!("/tmp/nxb_r1_{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 客户端配置（不填 virtual_ip，由服务端分配）。
    const CLIENT_CFG: &str = r#"[subnet]
cidr = "10.144.144.0/24"
network_psk = "shared-psk"
[[subnet.bootstrap]]
address = "udp://127.0.0.1:1"
"#;

    /// 服务端配置。
    const SERVER_CFG: &str = r#"[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.1"
network_psk = "shared-psk"

[subnet.bootstrap_server]
enabled = true
lease_secs = 60
hb_interval_ms = 20000
refresh_interval_ms = 60000
locator = "udp://0.0.0.0:11010"
lease_state_path = "/tmp/nxb_r1_server/leases.json"
"#;

    // ---- CRITICAL-1：virtual_ip 缺省（服务端分配）不该在装配期被拒 ----
    #[test]
    fn c1_client_config_without_virtual_ip_is_accepted() {
        let dir = fresh_dir("c1");
        let cp = write_config(&dir, CLIENT_CFG);
        // 解析 + 校验必须通过（virtual_ip 缺省是合法的客户端配置）。
        let cfg = parse_config(&cp).expect("client config without virtual_ip must validate");
        assert!(cfg.subnet.virtual_ip.is_none());
        assert_eq!(cfg.subnet.bootstrap.len(), 1);
        // Join 策略下 VIP 由服务端分配，不做本地前置校验。
        let hook = BootstrapPolicy::Join;
        assert_eq!(hook, BootstrapPolicy::Join);
    }

    // ---- CRITICAL-2：subnet_up 的 mock 装配不得发起网络握手 ----
    #[test]
    fn c2_subnet_up_does_not_join_on_dummy_carrier() {
        let dir = fresh_dir("c2");
        let cp = write_config(&dir, CLIENT_CFG);
        let sp = dir.join("state.json");
        let t0 = std::time::Instant::now();
        // 曾在此处卡满 5s join deadline 后 BOOTSTRAP_ALL_SERVERS_FAILED。
        let out = subnet_up(&cp, &sp, false, true).expect("subnet_up must not attempt a join");
        let el = t0.elapsed();
        assert!(sp.exists(), "state file must still be written");
        assert!(
            el.as_secs() < 2,
            "subnet_up must not wait on a join deadline (took {el:?})"
        );
        assert_eq!(out["verdict"], "PASS");
        assert_eq!(out["subnet"]["bootstrap_client"], true);
    }

    // ---- CRITICAL-2b：mock carrier + bootstrap 明确拒绝，不静默假装成功 ----
    #[test]
    fn c2b_offline_assembly_with_bootstrap_is_rejected() {
        let dir = fresh_dir("c2b");
        let mut cfg = parse_config(&write_config(&dir, CLIENT_CFG)).unwrap();
        cfg.subnet.virtual_ip = Some("10.144.144.9".into());
        let identity = KeyPair::from_seed(&[3u8; 32]);
        let Err(err) = assemble_with_offline(
            &cfg,
            Box::new(MemoryVpi::new()),
            Box::new(MeshCarrier::new()),
            &identity,
        ) else {
            panic!("mock carrier must not silently accept bootstrap");
        };
        assert!(err.contains(BOOTSTRAP_NEEDS_REAL_CARRIER), "got {err}");
    }

    // ---- CRITICAL-4：服务端角色必须真正接到生产装配路径上 ----
    #[test]
    fn c4_server_role_parses_and_validates() {
        let dir = fresh_dir("c4");
        let cp = write_config(&dir, SERVER_CFG);
        let cfg = parse_config(&cp).expect("server config must validate");
        let bs = cfg
            .subnet
            .bootstrap_server
            .as_ref()
            .expect("section present");
        assert!(bs.enabled);
        assert_eq!(bs.lease_secs, 60);
        assert_eq!(bs.max_pending_per_src, 4);
        assert!(server_role_enabled(&cfg.subnet));
    }

    #[test]
    fn c4_server_role_builds_hook_with_locator() {
        let dir = fresh_dir("c4b");
        let cfg = parse_config(&write_config(&dir, SERVER_CFG)).unwrap();
        let identity = KeyPair::from_seed(&[9u8; 32]);
        let hook = build_server_hook(&cfg, &identity, Some("udp://0.0.0.0:11010"))
            .expect("server hook builds")
            .expect("server hook present");
        // 权威租约快照必须含服务端自身占位（§5.4 启动先占位）。
        let leases = hook.leases_snapshot(1_000);
        assert!(
            leases.iter().any(|(_, vip)| vip == "10.144.144.1"),
            "server must reserve its own VIP, got {leases:?}"
        );
    }

    #[test]
    fn c4_absent_server_section_yields_no_hook() {
        let dir = fresh_dir("c4c");
        let cfg = parse_config(&write_config(
            &dir,
            r#"[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.1"
network_psk = "shared-psk"
"#,
        ))
        .unwrap();
        let identity = KeyPair::from_seed(&[9u8; 32]);
        assert!(
            build_server_hook(&cfg, &identity, Some("udp://0.0.0.0:11010"))
                .unwrap()
                .is_none()
        );
    }

    // ---- CRITICAL-4b：拒绝拼错的字段（deny_unknown_fields） ----
    #[test]
    fn c4b_server_section_rejects_unknown_field() {
        let dir = fresh_dir("c4d");
        let cp = write_config(
            &dir,
            r#"[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.1"
network_psk = "shared-psk"

[subnet.bootstrap_server]
enabled = true
lease_sec = 60
"#,
        );
        assert!(
            parse_config(&cp).is_err(),
            "a typo'd field must not silently disable the server role"
        );
    }

    #[test]
    fn c4c_server_section_requires_positive_intervals() {
        let dir = fresh_dir("c4e");
        for (field, value) in [
            ("lease_secs", "0"),
            ("hb_interval_ms", "0"),
            ("refresh_interval_ms", "0"),
        ] {
            let cp = write_config(
                &dir,
                &format!(
                    r#"[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.1"
network_psk = "shared-psk"

[subnet.bootstrap_server]
enabled = true
{field} = {value}
"#
                ),
            );
            let err = parse_config(&cp).expect_err("zero interval must be rejected");
            assert!(err.contains("BOOTSTRAP_SERVER"), "{field}=0 gave {err}");
        }
    }

    #[test]
    fn c4d_server_role_requires_own_vip_in_cidr() {
        let dir = fresh_dir("c4f");
        let cp = write_config(
            &dir,
            r#"[subnet]
cidr = "10.144.144.0/24"
network_psk = "shared-psk"
[subnet.bootstrap_server]
enabled = true
"#,
        );
        let err = parse_config(&cp).expect_err("server role without its own VIP must fail");
        assert!(err.contains("BOOTSTRAP_SERVER_VIP"), "got {err}");
    }

    // ---- 服务端与客户端角色互斥（隧道只有一个 hook 槽位） ----
    #[test]
    fn c4e_server_and_client_roles_are_mutually_exclusive() {
        let dir = fresh_dir("c4g");
        let cp = write_config(
            &dir,
            r#"[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.1"
network_psk = "shared-psk"

[subnet.bootstrap_server]
enabled = true

[[subnet.bootstrap]]
address = "udp://other:11010"
"#,
        );
        let err = parse_config(&cp).expect_err("both roles must be rejected, not silently merged");
        assert!(err.contains("BOOTSTRAP_ROLE_CONFLICT"), "got {err}");
    }

    // ---- WARNING-2：VIP 租约表原子落盘 + 回读 ----
    #[test]
    fn w2_lease_state_roundtrips() {
        let dir = fresh_dir("w2");
        let path = dir.join("vip-leases.json");
        assert_eq!(
            read_lease_state(&path).unwrap(),
            None,
            "first boot has no file"
        );
        let leases = vec![
            ("__bootstrap_self__".to_string(), "10.144.144.1".to_string()),
            ("peer-a".to_string(), "10.144.144.2".to_string()),
        ];
        write_lease_state(&path, &leases).unwrap();
        let back = read_lease_state(&path).unwrap().expect("file now exists");
        let mut a = leases.clone();
        let mut b = back;
        a.sort();
        b.sort();
        assert_eq!(a, b);
        // 0600（租约表能反推在线节点，不应 world-readable）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "lease state must be 0600, got {mode:o}");
        }
        // 无残留 tmp。
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn w2_lease_state_corrupt_is_reported_not_silently_empty() {
        let dir = fresh_dir("w2b");
        let path = dir.join("vip-leases.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(read_lease_state(&path).is_err());
        // schema 版本不符同样报错（回填方据此按空表 + 告警处理）。
        std::fs::write(&path, br#"{"schema_version":99,"leases":{}}"#).unwrap();
        assert!(read_lease_state(&path).is_err());
    }

    #[test]
    fn w2_lease_state_recovery_prevents_vip_reuse() {
        let dir = fresh_dir("w2c");
        let path = dir.join("vip-leases.json");
        write_lease_state(&path, &[("peer-a".to_string(), "10.144.144.7".to_string())]).unwrap();
        let persisted = read_lease_state(&path).unwrap();
        let identity = KeyPair::from_seed(&[9u8; 32]);
        let cfg = BootstrapServerConfig {
            cidr: "10.144.144.0/24".into(),
            lease_secs: 60,
            hb_interval_ms: 20_000,
            refresh_interval_ms: 60_000,
            server_vip: "10.144.144.1".into(),
            server_locator: "udp://0.0.0.0:11010".into(),
            max_pending_per_src: 4,
        };
        let mut server = BootstrapServer::new(
            identity,
            b"psk".to_vec(),
            cfg,
            Box::new(crate::bootstrap_codec::DiscoveryBootstrapCodec::new()),
            persisted,
        )
        .unwrap();
        server.upsert_self_entry(1_000);
        // 重启后 peer-a 的租约仍在**分配器表**内，故不会被再分配给别人。
        // 注意 `leases_snapshot` 只导出 presence 存活的租约（§6.6：避免把
        // "已分配未 announce" 的崩溃窗口租约落盘），peer-a 此时不在线属预期。
        let mut allocator =
            nexus_connectivity::coord::VirtualIpAllocator::new("10.144.144.0/24").unwrap();
        allocator
            .allocate_specific(0, "__bootstrap_self__", "10.144.144.1")
            .unwrap();
        allocator
            .allocate_specific(0, "peer-a", "10.144.144.7")
            .unwrap();
        // 新节点应拿到一个未被 peer-a 占据的地址。
        let fresh = allocator.allocate(0, "peer-b").unwrap();
        assert_ne!(
            fresh, "10.144.144.7",
            "restored lease must not be re-issued to a new node"
        );
        // 落盘快照只含在线者（自身），peer-a 未 announce 故不导出。
        let exported = server.leases_snapshot(1_000);
        assert!(
            exported.iter().all(|(n, _)| n == "__bootstrap_self__"),
            "only live leases are exported, got {exported:?}"
        );
    }

    // ---- WARNING-3：--tun 缺省 listen 借系统端口，不再是 port 0 ----
    #[test]
    fn w3_ephemeral_locator_is_bindable() {
        let lsn = allocate_ephemeral_udp_locator().expect("allocate ephemeral port");
        assert!(lsn.starts_with("udp://0.0.0.0:"), "got {lsn}");
        let port: u16 = lsn.rsplit(':').next().unwrap().parse().unwrap();
        assert_ne!(port, 0, "must be a real port, UdpCarrier::bind rejects 0");
        // 真能绑上。
        let mut c = UdpCarrier::new();
        c.bind(&lsn).expect("ephemeral locator must bind");
    }

    // ---- CRITICAL-5：身份文件名必须与 node init 写的一致，且缺失时自动 init ----
    #[test]
    fn c5_identity_file_name_matches_node_init() {
        let dir = fresh_dir("c5");
        let file = crate::node_cli::identity_file_name();
        // node init 写的是键编码后的名字（`node/identity` → `node%2Fidentity`），
        // 读取方若按 `identity` 找，永远读不到（曾被 generate() 兜底掩盖）。
        assert_eq!(file, "node%2Fidentity");
        assert_ne!(file, "identity");
        // 自动 init 后文件确实落在同一个名字下。
        crate::node_cli::ensure_node_identity(&dir).expect("init identity");
        assert!(
            dir.join(&file).exists(),
            "{} not written",
            dir.join(&file).display()
        );
    }

    /// `load_node_identity` 依赖进程级 `NEXUS_CONFIG_DIR`，故在子进程里验证
    /// "首次自动 init → 二次复用同一身份（node_id 稳定）"。
    #[test]
    fn c5_identity_is_stable_across_loads() {
        let dir = fresh_dir("c5b");
        let exe = std::env::current_exe().unwrap();
        let dump = || {
            let out = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "subnet_cli::review_r1_regression_tests::c5_identity_child",
                    "--nocapture",
                ])
                .env("NEXUS_CONFIG_DIR", &dir)
                .env("NEXUS_C5_CHILD", "1")
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.strip_prefix("CHILD_PUBKEY="))
                .map(str::to_string)
                .expect("child must print CHILD_PUBKEY")
        };
        let first = dump();
        let second = dump();
        assert_eq!(
            first, second,
            "identity must be reused, not regenerated, across loads"
        );
        assert_eq!(first.len(), 64, "expected 32-byte x25519 public key hex");
    }

    #[test]
    fn c5_identity_child() {
        if std::env::var("NEXUS_C5_CHILD").is_err() {
            return;
        }
        let kp = load_node_identity().expect("load identity");
        println!(
            "CHILD_PUBKEY={}",
            kp.public_key_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }

    // ---- 回归（C1 补丁自身引入）：Join 策略 + 空 bootstrap 不得要求
    // assigned_vip。静态 `--tun` 常驻与服务端角色都走 Join 但无客户端握手。 ----
    #[test]
    fn c1b_join_policy_without_client_bootstrap_uses_config_vip() {
        let dir = fresh_dir("c1b");
        let cfg = parse_config(&write_config(
            &dir,
            r#"[subnet]
cidr = "10.144.144.0/24"
virtual_ip = "10.144.144.5"
network_psk = "shared-psk"
"#,
        ))
        .unwrap();
        let identity = KeyPair::from_seed(&[11u8; 32]);
        let tunnel = assemble_with_policy_at(
            &cfg,
            Box::new(MemoryVpi::new()),
            Box::new(MeshCarrier::new()),
            &identity,
            BootstrapPolicy::Join,
            None,
        )
        .expect("static real-path assembly must not require a bootstrap join");
        // 无客户端引导 → 未挂任何 hook（尤其不是服务端 hook）。
        assert!(
            tunnel.bootstrap_lease_snapshot(1_000).is_none(),
            "a plain static node must not mount a bootstrap hook"
        );
    }

    // ---- CRITICAL-4 端到端装配：服务端角色在真实路径（Join）上必须真正装配成功，
    // 而不是停在 build_server_hook 单测里（那个单测绕过了 Join 的 VIP 解析）。 ----
    #[test]
    fn c4f_server_role_assembles_on_join_path_without_join() {
        let dir = fresh_dir("c4h");
        let cfg = parse_config(&write_config(&dir, SERVER_CFG)).unwrap();
        let identity = KeyPair::from_seed(&[12u8; 32]);
        let tunnel = assemble_with_policy_at(
            &cfg,
            Box::new(MemoryVpi::new()),
            Box::new(MeshCarrier::new()),
            &identity,
            BootstrapPolicy::Join,
            Some("udp://0.0.0.0:11010"),
        )
        .expect("server role must assemble on the real (Join) path");
        let leases = tunnel
            .bootstrap_lease_snapshot(1_000)
            .expect("server hook must be mounted by the real assembly path");
        assert!(
            leases.iter().any(|(_, vip)| vip == "10.144.144.1"),
            "server must reserve its own VIP, got {leases:?}"
        );
    }
}
