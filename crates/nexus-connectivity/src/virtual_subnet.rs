//! 铏氭嫙瀛愮綉缁勭綉锛圴irtual Subnet Networking锛?
//!
//! 鍙傝€?EasyTier / WireGuard 缁勭綉妯″紡锛?
//! - 鑺傜偣鍦ㄥ悓涓€铏氭嫙 CIDR 缃戞鍐咃紝鍚勬湁鑷繁鐨勮櫄鎷?IP
//! - 姣忎釜 Peer 鐨勭墿鐞?locator 闈欐€侀厤缃紙P0锛?
//! - 鏁版嵁闈細VPI 璇?IP 鍖?鈫?灏佽 鈫?鍙戠粰瀵圭锛涘绔敹鍒?鈫?瑙ｅ皝瑁?鈫?鍐欏洖 VPI
//!
//! P0 杈圭晫锛?
//! - 鐐瑰鐐圭洿杩烇紙涓嶅仛缃戠姸鑷姩璺敱锛?
//! - 闈欐€侀厤缃?Peer锛堜笉鍋氳嚜鍔ㄥ彂鐜帮級
//! - 鏄庢枃灏佽锛堝姞瀵嗗悗缃級
//! - 鍐呭瓨妯℃嫙 VPI/Carrier锛堢湡瀹?TUN 鏄?E5锛?

use nexus_platform::{PacketCarrier, PlatformError, VirtualPacketInterface};
use std::collections::HashMap;

/// 把 `CidrPrefix` 格式化为 "a.b.c.d/len"。
fn format_cidr(p: &crate::cidr::CidrPrefix) -> String {
    let octets = p.network.to_be_bytes();
    format!(
        "{}.{}.{}.{}/{}",
        octets[0], octets[1], octets[2], octets[3], p.prefix_len
    )
}
use std::sync::Arc;

use crate::ConnectivityError;
use crate::dataplane_pipeline::{
    self, DataplanePipelineConfig, EgressOutcome, IngressOutcome, PipelineStats,
};
use crate::encryption::{
    DirectionalKeys, EncryptionConfig, EncryptionError, HANDSHAKE_INIT, HANDSHAKE_RESP,
    HandshakeMessage, KeyPair, ReplayWindow, build_handshake_message, decrypt_frame,
    derive_authed_keys, encrypt_frame,
};
use crate::identity::{IdentityAction, IdentityManager, InMemorySecretStore, SecretStore};
use std::time::Duration;

/// 铏氭嫙瀛愮綉閰嶇疆銆?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualSubnetConfig {
    /// 瀛愮綉 CIDR锛堝 "10.0.0.0/24"锛夈€?
    pub cidr: String,
    /// 鏈妭鐐圭殑铏氭嫙 IP锛堝 "10.0.0.1"锛夈€?
    pub virtual_ip: String,
}

impl VirtualSubnetConfig {
    /// 鍒涘缓铏氭嫙瀛愮綉閰嶇疆銆?
    #[must_use]
    pub fn new(cidr: impl Into<String>, virtual_ip: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            virtual_ip: virtual_ip.into(),
        }
    }

    /// 鏍￠獙铏氭嫙 IP 鏄惁鍦ㄥ瓙缃戣寖鍥村唴锛圥0 绠€鍖栵細瀛楃涓插墠缂€鍖归厤锛夈€?
    #[must_use]
    pub fn is_valid_virtual_ip(&self, ip: &str) -> bool {
        // P0 绠€鍖栧疄鐜帮細鎻愬彇 CIDR 鐨勭綉缁滃湴鍧€閮ㄥ垎锛屾鏌?IP 鏄惁鍓嶇紑鍖归厤
        let network_prefix = self
            .cidr
            .split('/')
            .next()
            .unwrap_or("")
            .rsplit_once('.')
            .map(|x| x.0)
            .unwrap_or("");
        ip.starts_with(network_prefix)
    }
}

/// 加密会话（§12.6）：对端虚拟 IP 的链路会话状态。
struct PeerCryptoSession {
    /// 方向子密钥（tx=本端发送，rx=本端接收）。
    keys: DirectionalKeys,
    /// 本端发送序号（encrypt_frame 使用，递增防重放）。
    tx_seq: u64,
    /// 本端接收防重放窗口。
    rx_replay: ReplayWindow,
}

/// 进行中的握手（发起方视角，P4.1 §12.39）：本端 ephemeral + static 身份。
struct PendingHandshake {
    /// 本端 ephemeral 密钥对（会话材料，每握手全新）。
    eph: KeyPair,
    /// 本端 static 身份密钥（长期，参与混合 DH 与 TOFU 校验）。
    static_key: KeyPair,
}

/// 闅ч亾 Peer 閰嶇疆銆?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPeer {
    /// Peer ID锛堢敤浜庝簨浠跺叧鑱旓級銆?
    pub peer_id: String,
    /// 瀵圭铏氭嫙 IP銆?
    pub virtual_ip: String,
    /// 瀵圭鐗╃悊 locator銆?
    pub locator: String,
}

impl TunnelPeer {
    /// 鍒涘缓闅ч亾 Peer銆?
    #[must_use]
    pub fn new(virtual_ip: impl Into<String>, locator: impl Into<String>) -> Self {
        let virtual_ip = virtual_ip.into();
        Self {
            peer_id: format!("peer-{virtual_ip}"),
            virtual_ip,
            locator: locator.into(),
        }
    }
}

/// 闅ч亾鐘舵€併€?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// 鏈繛鎺ャ€?
    Disconnected,
    /// NAT hole-punch probing in progress (P2.2 §12.9).
    Probing,
    /// 鎻℃墜杩涜涓€?
    Handshaking,
    /// 宸茶繛鎺ャ€?
    Connected,
    /// 杩炴帴澶辫触銆?
    Failed,
}

/// 闅ч亾缁熻鏁版嵁銆?
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelStats {
    /// 涓婅瀛楄妭鏁帮紙鏈妭鐐瑰彂缁欏绔級銆?
    pub bytes_sent: u64,
    /// 涓嬭瀛楄妭鏁帮紙鏈妭鐐逛粠瀵圭鎺ユ敹锛夈€?
    pub bytes_received: u64,
    /// 涓㈠寘鏁般€?
    pub packets_dropped: u64,
    /// 鏈妭鐐逛綔涓轰腑闂磋浆鍙戣妭鐐圭疮璁¤浆鍙戝瓧鑺傦紙P1 搂12.5锛夈€?
    pub bytes_forwarded: u64,
}

/// 打洞重试配置（P4.2 §12.9.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HolePunchConfig {
    /// 最大尝试次数（含首次发起，默认 10）。
    pub max_attempts: u32,
    /// 单次尝试等待对端 ack 的超时（默认 500ms，总预算 ~5s）。
    pub attempt_timeout: std::time::Duration,
    /// 打洞帧 magic（4 字节，默认 b"NXHP"），防数据帧/握手帧误判。
    pub magic: [u8; 4],
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            attempt_timeout: std::time::Duration::from_millis(500),
            magic: *b"NXHP",
        }
    }
}

/// 进行中的打洞（P4.2 §12.9.3）：发起目标 + 已尝试次数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingPunch {
    /// 打洞候选 locator 列表（多候选并发，先到先用）。
    pub(crate) targets: Vec<String>,
    /// 已尝试次数（首次发起=1 后递增）。
    pub(crate) attempts: u32,
}

/// 连通性计划（P4.2 §12.9.4，NAT 类型驱动路径选择的输出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityPlan {
    /// 打洞直连（目标 locator，调用方继续 `begin_hole_punch`）。
    Direct { target: String },
    /// 走 relay（TURN 中继 locator，§12.9.2）。
    Relay { locator: String },
}

/// 铏氭嫙瀛愮綉缁撴瀯鍖栦簨浠讹紙鐢ㄤ簬鍙娴嬫€у拰閲嶆斁锛夈€?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtualSubnetEvent {
    /// 闅ч亾鍒涘缓銆?
    TunnelCreated {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// 瀛愮綉 CIDR銆?
        subnet_cidr: String,
    },
    /// Peer 宸叉敞鍐屻€?
    PeerRegistered {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// Peer ID銆?
        peer_id: String,
        /// Peer 铏氭嫙 IP銆?
        virtual_ip: String,
    },
    /// Peer 鐘舵€佸彉鏇淬€?
    PeerStateChanged {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// Peer ID銆?
        peer_id: String,
        /// 鏂扮姸鎬併€?
        new_state: TunnelState,
    },
    /// Hole-punch probe started for a peer (P2.2 §12.9).
    ProbeStarted {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer ID.
        peer_id: String,
    },
    /// Peer locator dynamically updated after successful hole punch (P2.2 §12.9).
    PeerLocatorUpdated {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer ID.
        peer_id: String,
        /// New direct locator.
        new_locator: String,
    },
    /// Peer fell back to relay after hole-punch failure (P2.2 §12.9).
    RelayFallback {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer ID.
        peer_id: String,
        /// Relay locator.
        relay_locator: String,
    },
    /// Hole punch initiated for peer (P4.2 §12.9.3).
    HolePunchStarted {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer virtual IP.
        peer_vip: String,
        /// Candidate target locators attempted (P4.2 §12.9.5).
        targets: Vec<String>,
    },
    /// Hole punch completed via pa ack (P4.2 §12.9.3).
    HolePunchSucceeded {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer virtual IP.
        peer_vip: String,
        /// Direct target locator now in use.
        target: String,
    },
    /// Hole punch exhausted attempts (P4.2 §12.9.3).
    HolePunchFailed {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer virtual IP.
        peer_vip: String,
        /// Failure reason.
        reason: String,
        /// Candidate target locators attempted (P4.2 §12.9.5).
        targets: Vec<String>,
    },
    /// Path decision emitted from NAT-type-driven selection (P4.2 §12.9.4).
    PathDecided {
        /// Tunnel ID.
        tunnel_id: String,
        /// Peer virtual IP.
        peer_vip: String,
        /// Detected NAT type.
        nat_type: crate::nat::NatType,
        /// Chosen path decision.
        decision: crate::nat::PathDecision,
    },
    /// 鏁版嵁鍖呭凡鍙戦€併€?
    PacketSent {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// Peer ID銆?
        peer_id: String,
        /// 瀛楄妭鏁般€?
        bytes: u64,
    },
    /// 鏁版嵁鍖呭凡鎺ユ敹銆?
    PacketReceived {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// Peer ID銆?
        peer_id: String,
        /// 瀛楄妭鏁般€?
        bytes: u64,
    },
    /// 鍙戠敓閿欒銆?
    Error {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// 閿欒淇℃伅銆?
        message: String,
    },
    /// 鍖呰鏈妭鐐逛綔涓轰腑闂磋烦杞彂鍒颁笅涓€璺筹紙P1 搂12.5锛夈€?
    PacketForwarded {
        /// 闅ч亾 ID銆?
        tunnel_id: String,
        /// 鍘熷婧愯櫄鎷?IP銆?
        src_virtual_ip: String,
        /// 鏈€缁堢洰鐨勮櫄鎷?IP銆?
        dst_virtual_ip: String,
        /// 涓嬩竴璺宠櫄鎷?IP銆?
        next_hop: String,
        /// 杞彂瀛楄妭鏁般€?
        bytes: u64,
    },
    /// 本地前缀递送（P2-5 §12.14）：dst 命中 local_prefixes 写 VPI。
    LocalPrefixDelivered {
        /// 隧道 ID。
        tunnel_id: String,
        /// 最终目的虚拟 IP。
        dst_virtual_ip: String,
        /// 本地递送字节数。
        bytes: u64,
    },
    /// 本端身份密钥自动生成并持久化（P4.1 §12.39）。
    IdentityKeyGenerated {
        /// 隧道 ID。
        tunnel_id: String,
        /// 本端 PeerId。
        peer_id: String,
    },
    /// 首次握手 TOFU 学习对端身份（P4.1 §12.39）。
    PeerIdentityLearned {
        /// 隧道 ID。
        tunnel_id: String,
        /// 对端 PeerId。
        peer_id: String,
    },
    /// 对端身份不匹配被拒绝（TOFU mismatch，P4.1 §12.39）。
    PeerIdentityRejected {
        /// 隧道 ID。
        tunnel_id: String,
        /// 对端 PeerId。
        peer_id: String,
    },
    /// 数据面管线：出/入向包被防火墙规则丢弃（PRODUCT §12.41）。
    PacketDroppedByFirewall {
        /// 隧道 ID。
        tunnel_id: String,
        /// 方向（"egress"/"ingress"）。
        direction: &'static str,
        /// 源虚拟 IP。
        src_virtual_ip: String,
        /// 目的虚拟 IP。
        dst_virtual_ip: String,
    },
    /// 数据面管线：出/入向包因 QoS 令牌不足被丢弃（PRODUCT §12.41）。
    QosLimited {
        /// 隧道 ID。
        tunnel_id: String,
        /// 方向（"egress"/"ingress"）。
        direction: &'static str,
        /// 关联对端 tag。
        tag: String,
        /// 被丢弃字节。
        bytes: u64,
    },
    /// 数据面管线：一个数据块被分片发出（PRODUCT §12.41）。
    FragmentSent {
        /// 隧道 ID。
        tunnel_id: String,
        /// 所属报文 ID。
        packet_id: u64,
        /// 本片序号。
        index: u16,
        /// 总分片数。
        total: u16,
    },
}

/// 闅ч亾甯уご锛圥0 绠€鍖栵細绾枃鏈爣璁帮級銆?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrameHeader {
    /// 婧愯櫄鎷?IP銆?
    pub src_virtual_ip: String,
    /// 鐩殑铏氭嫙 IP銆?
    pub dst_virtual_ip: String,
}

impl TunnelFrameHeader {
    /// 搴忓垪鍖栧抚澶达紙P0 绠€鍖栵細`src->dst:` 鍓嶇紑锛夈€?
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        format!("{}->{}:", self.src_virtual_ip, self.dst_virtual_ip).into_bytes()
    }

    /// 鍙嶅簭鍒楀寲甯уご锛圥0 绠€鍖栵細瑙ｆ瀽 `src->dst:` 鍓嶇紑锛夈€?
    pub fn deserialize(data: &[u8]) -> Option<(Self, &[u8])> {
        // 仅对头部（第一个 ':' 之前）做 UTF-8 解析；载荷为任意二进制（IP 包非 UTF-8）。
        let colon_pos = data.iter().position(|&b| b == b':')?;
        let header_text = std::str::from_utf8(&data[..colon_pos]).ok()?;
        let mut parts = header_text.split("->");
        let src = parts.next()?;
        let dst = parts.next()?;
        let header = Self {
            src_virtual_ip: src.to_string(),
            dst_virtual_ip: dst.to_string(),
        };
        let payload = &data[colon_pos + 1..];
        Some((header, payload))
    }
}

/// 铏氭嫙瀛愮綉闅ч亾锛堟暟鎹潰缂栨帓鍣級銆?
///
/// 娉ㄥ叆 VPI 鍜?PacketCarrier锛岃礋璐ｏ細
/// 1. 浠?VPI 璇?IP 鍖?
/// 2. 鏍规嵁鐩殑铏氭嫙 IP 鏌ユ壘瀵瑰簲 Peer 鐨勭墿鐞?locator
/// 3. 灏佽闅ч亾甯уご
/// 4. 閫氳繃 PacketCarrier 鍙戠粰瀵圭
/// 5. 浠?PacketCarrier 璇诲抚
/// 6. 瑙ｅ皝瑁呮彁鍙栧師濮?IP 鍖?
/// 7. 鍐欏叆 VPI
pub struct VirtualSubnetTunnel {
    /// 闅ч亾 ID锛堢敤浜庝簨浠跺叧鑱旓級銆?
    tunnel_id: String,
    /// 瀛愮綉閰嶇疆銆?
    config: VirtualSubnetConfig,
    /// Peer 琛細铏氭嫙 IP 鈫?(peer_id, locator, state, stats)銆?
    peers: HashMap<String, (String, String, TunnelState, TunnelStats)>,
    /// 闈欐€佽矾鐢辫〃锛圥1 搂12.5锛夛細鐩殑铏氭嫙 IP 鈫?涓嬩竴璺宠櫄鎷?IP銆?
    /// 浠呯敤浜庣洰鐨勯潪鐩磋繛 peer 鐨勮浆鍙戝喅绛栵紱鐩磋繛 peer 鐩村彂涓嶆煡璺敱琛ㄣ€?
    routes: HashMap<String, String>,
    /// 鍓嶇紑璺敱琛?P2-5 搂12.14锛?CIDR 鍓嶇紑 鈫?涓嬩竴璺?缂栫爜鐢?crate::cidr::parse_cidr 鏉ユ帶锛夈€?
    prefix_routes: Vec<(crate::cidr::CidrPrefix, String)>,
    /// 鏈湴鍙揪鍓嶇紑锛圥2-5 搂12.14锛夛細鎺ユ敹鏂?dst 鍛戒腑鍐?VPI 銆?
    local_prefixes: Vec<crate::cidr::CidrPrefix>,
    /// 鍑哄彛鑺傜偣锛圥2-5 搂12.14锛夛細鏍囪涓嬈″簭锛屽喅绛栧彇绗竴涓€?
    egress_peer_vips: Vec<String>,
    /// 浜嬩欢鏀堕泦锛堢敤浜庡彲瑙傛祴鎬у拰閲嶆斁锛夈€?
    events: Vec<VirtualSubnetEvent>,
    /// VPI 鎺ュ彛銆?
    vpi: Box<dyn VirtualPacketInterface>,
    /// PacketCarrier銆?
    carrier: Box<dyn PacketCarrier>,
    /// 加密模式配置（None = 明文模式，§12.1-§12.5 语义不变）。
    encryption: Option<EncryptionConfig>,
    /// 加密会话表（§12.6）：对端虚拟 IP -> 会话。
    crypto_sessions: HashMap<String, PeerCryptoSession>,
    /// 握手进行中（发起方视角，P4.1 §12.39）：对端虚拟 IP -> 本端 eph+static。
    pending_handshakes: HashMap<String, PendingHandshake>,
    /// 节点身份管理器（P4.1 §12.39）：本端长期身份 + 对端 TOFU 表。
    identity: IdentityManager,
    /// 打洞状态机（P4.2 §12.9.3）：对端虚拟 IP -> 进行中打洞（target + 已尝试次数）。
    pending_punches: HashMap<String, PendingPunch>,
    /// 打洞重试配置（P4.2 §12.9.3）。
    hole_punch_config: HolePunchConfig,
    /// 已配置 relay locator（P4.2 §12.9.3）：对端虚拟 IP -> relay locator。
    relay_locators: HashMap<String, String>,
    /// 数据面管线（PRODUCT §12.41）：None = 完全透传，wire 字节与冻结前逐字节一致。
    pipeline: Option<dataplane_pipeline::DataplanePipeline>,
    /// FIB 解析器（§12.56，可选）：动态选路替代静态 routes。
    fib_resolver: Option<crate::fib_resolver::SharedFibResolver>,
    /// Bootstrap 钩子（v2 §6.4，S5）：可选；nxb: 控制帧在此分流，回包经 carrier 代发。
    bootstrap: Option<Box<dyn BootstrapHook>>,
}

/// Bootstrap 服务端/客户端会话共同实现，挂在隧道上（v2 §6.4）。
pub trait BootstrapHook {
    /// 入参为已剥掉 `nxb:` 的 payload + NAT 源 locator + now；
    /// 返回需经同一 socket 发出的回包 (dst locator, bytes)。
    fn on_control_datagram(
        &mut self,
        src: Option<&str>,
        payload: &[u8],
        now: u64,
    ) -> Option<(String, Vec<u8>)>;

    /// 每 tick 调用：返回待发数据报与 peer 增删（心跳/刷新/服务端 sweep）。
    fn periodic(&mut self, now: u64) -> BootstrapTick;

    /// 服务端权威分配的本端 VIP（bootstrap 入网后；未入网为 None）。
    fn assigned_vip(&self) -> Option<&str> {
        None
    }
}

/// 一次 tick 产出的 bootstrap 出站数据报与 peer 增删（v2 §6.4）。
#[derive(Debug, Default)]
pub struct BootstrapTick {
    /// 待发数据报 (dst locator, bytes)。
    pub datagrams: Vec<(String, Vec<u8>)>,
    /// 新发现应打洞的 peer。
    pub peers_added: Vec<crate::bootstrap_server::BootstrapPeer>,
    /// 降级 peer（不删，仅标记）。
    pub peers_gone: Vec<String>,
    /// 结构化可观测事件（本 tick 取出，避免无界增长）。
    pub events: Vec<String>,
}

impl VirtualSubnetTunnel {
    /// 鍒涘缓铏氭嫙瀛愮綉闅ч亾銆?
    pub fn new(
        config: VirtualSubnetConfig,
        vpi: Box<dyn VirtualPacketInterface>,
        carrier: Box<dyn PacketCarrier>,
    ) -> Self {
        let tunnel_id = format!("tunnel-{}", config.virtual_ip);
        let events = vec![VirtualSubnetEvent::TunnelCreated {
            tunnel_id: tunnel_id.clone(),
            subnet_cidr: config.cidr.clone(),
        }];
        Self {
            tunnel_id,
            config,
            peers: HashMap::new(),
            routes: HashMap::new(),
            prefix_routes: Vec::new(),
            local_prefixes: Vec::new(),
            egress_peer_vips: Vec::new(),
            events,
            vpi,
            carrier,
            encryption: None,
            crypto_sessions: HashMap::new(),
            pending_handshakes: HashMap::new(),
            identity: IdentityManager::new(Box::new(InMemorySecretStore::new())),
            pending_punches: HashMap::new(),
            hole_punch_config: HolePunchConfig::default(),
            relay_locators: HashMap::new(),
            pipeline: None,
            fib_resolver: None,
            bootstrap: None,
        }
    }

    /// 注入持久化身份存储（平台 secure-store；默认进程内内存存储）。
    pub fn set_identity_store(&mut self, store: Box<dyn SecretStore>) {
        self.identity = IdentityManager::new(store);
    }

    /// 启用数据面管线（PRODUCT §12.41）：把 firewall/QoS/compression/fragmentation 挂进收发路径。
    /// 未启用前 wire 字节逐字节透传；启用后数据帧以 NXP1 魔数开头。
    pub fn enable_dataplane_pipeline(&mut self, cfg: DataplanePipelineConfig) {
        self.pipeline = Some(dataplane_pipeline::DataplanePipeline::new(cfg));
    }

    /// 注入管线逻辑时钟（QoS 确定性推进；默认 0）。
    pub fn set_dataplane_clock(&mut self, now: Duration) {
        if let Some(p) = &mut self.pipeline {
            p.set_clock(now);
        }
    }

    /// 调整管线 PacketContext 默认协议/端口（切换命中/未命中防火墙规则的流）。
    pub fn set_dataplane_defaults(
        &mut self,
        proto: crate::firewall::Protocol,
        src_port: u16,
        dst_port: u16,
    ) {
        if let Some(p) = &mut self.pipeline {
            p.set_defaults(proto, src_port, dst_port);
        }
    }

    /// 管线只读统计快照（未启用时返回全 0）。
    #[must_use]
    pub fn pipeline_stats(&self) -> PipelineStats {
        self.pipeline
            .as_ref()
            .map_or(PipelineStats::default(), |p| p.stats())
    }

    /// 确保本端身份已加载（首次自动生成并持久化，事件 IdentityKeyGenerated）。
    fn ensure_identity(&mut self) -> Result<(), ConnectivityError> {
        if self.identity.identity().is_none() {
            let generated = self.identity.load_or_generate().map_err(|e| {
                ConnectivityError::IdentityUnavailable {
                    message: e.to_string(),
                }
            })?;
            if generated {
                self.events.push(VirtualSubnetEvent::IdentityKeyGenerated {
                    tunnel_id: self.tunnel_id.clone(),
                    peer_id: self.identity.peer_id().unwrap_or_default(),
                });
            }
        }
        Ok(())
    }

    /// 娉ㄥ唽闈欐€佽矾鐢憋紙P1 搂12.5锛夈€俷ext_hop 蹇呴』鏄凡娉ㄥ唽 peer銆?
    /// 设置 FIB 解析器（§12.56）：动态选路。设为 None 则禁用，回退静态路由。
    pub fn set_fib_resolver(&mut self, resolver: Option<crate::fib_resolver::SharedFibResolver>) {
        self.fib_resolver = resolver;
    }

    /// 挂载/卸载 Bootstrap 钩子（v2 §6.4，S5）。
    pub fn set_bootstrap_hook(&mut self, hook: Option<Box<dyn BootstrapHook>>) {
        self.bootstrap = hook;
    }

    /// Bootstrap 内部发出口（v2 §6.4）：薄封装 carrier.send_to，供常驻 tick 发心跳/刷新/sweep 回执。
    pub(crate) fn send_raw(
        &mut self,
        locator: &str,
        bytes: &[u8],
    ) -> Result<(), ConnectivityError> {
        self.carrier
            .send_to(locator, bytes)
            .map_err(|e| ConnectivityError::Io {
                operation: "bootstrap send_raw".to_string(),
                message: e.to_string(),
            })
    }

    /// 驱动挂载的 Bootstrap 钩子周期性 tick（v2 §6.4）：心跳/刷新/sweep 出站数据报
    /// 统一经 [`Self::send_raw`] 发出；返回 peer 增删供 mesh 层接管打洞。
    pub fn bootstrap_tick(&mut self, now: u64) -> BootstrapTick {
        match self.bootstrap.as_mut() {
            Some(hook) => {
                let tick = hook.periodic(now);
                for (dst, bytes) in &tick.datagrams {
                    if self.send_raw(dst, bytes).is_err() {
                        break;
                    }
                }
                tick
            }
            None => BootstrapTick::default(),
        }
    }

    pub fn add_route(
        &mut self,
        dst: impl Into<String>,
        next_hop: impl Into<String>,
    ) -> Result<(), ConnectivityError> {
        let dst = dst.into();
        let next_hop = next_hop.into();
        if !self.peers.contains_key(&next_hop) {
            return Err(ConnectivityError::Invalid {
                message: format!(
                    "ROUTE_NEXT_HOP_NOT_PEER: next-hop {next_hop} is not a registered peer"
                ),
            });
        }
        self.routes.insert(dst, next_hop);
        Ok(())
    }

    /// 注册前缀路由（P2-5 §12.14）：`cidr_str`（如 "192.168.5.0/24"）→ next_hop。
    ///
    /// next_hop 必须是已注册 peer；CIDR 非法 → 结构化错误。
    pub fn add_prefix_route(
        &mut self,
        cidr_str: &str,
        next_hop: impl Into<String>,
    ) -> Result<(), ConnectivityError> {
        let next_hop = next_hop.into();
        if !self.peers.contains_key(&next_hop) {
            return Err(ConnectivityError::Invalid {
                message: format!(
                    "ROUTE_NEXT_HOP_NOT_PEER: next-hop {next_hop} is not a registered peer"
                ),
            });
        }
        let prefix = crate::cidr::parse_cidr(cidr_str).map_err(|e| ConnectivityError::Invalid {
            message: format!("CIDR_ERROR: {e}"),
        })?;
        self.prefix_routes.push((prefix, next_hop));
        Ok(())
    }

    /// 前缀路由列表（注入顺序）。
    #[must_use]
    pub fn prefix_routes(&self) -> Vec<(String, String)> {
        self.prefix_routes
            .iter()
            .map(|(p, nh)| (format_cidr(p), nh.clone()))
            .collect()
    }

    /// 声明本节点可达前缀（P2-5 §12.14，接收侧投递边界）。
    pub fn add_local_prefix(&mut self, cidr_str: &str) -> Result<(), ConnectivityError> {
        let prefix = crate::cidr::parse_cidr(cidr_str).map_err(|e| ConnectivityError::Invalid {
            message: format!("CIDR_ERROR: {e}"),
        })?;
        self.local_prefixes.push(prefix);
        Ok(())
    }

    /// 本节点可达前缀列表。
    #[must_use]
    pub fn local_prefixes(&self) -> Vec<String> {
        self.local_prefixes.iter().map(format_cidr).collect()
    }

    /// 把已注册 peer 标记为出口节点（P2-5 §12.14）。
    pub fn mark_egress(&mut self, virtual_ip: impl Into<String>) -> Result<(), ConnectivityError> {
        let vip = virtual_ip.into();
        if !self.peers.contains_key(&vip) {
            return Err(ConnectivityError::Invalid {
                message: format!("EGRESS_NOT_PEER: {vip} is not a registered peer"),
            });
        }
        if !self.egress_peer_vips.contains(&vip) {
            self.egress_peer_vips.push(vip);
        }
        Ok(())
    }

    /// 出口节点列表（标记顺序）。
    #[must_use]
    pub fn egress_peers(&self) -> Vec<String> {
        self.egress_peer_vips.clone()
    }

    /// 统一转发决策（P2-5 §12.14，§12.56 扩展）：① 直连 peer → ② FIB
    /// （`fib_resolver`，动态发现）→ ③ 精确 routes → ④ 最长前缀
    /// prefix_routes → ⑤ 出口节点（egress 顺序第一个）→ ⑥ `NO_ROUTE_TO_DST`。
    fn resolve_next_hop(
        &self,
        dst: &str,
        packet: Option<&[u8]>,
    ) -> Result<String, ConnectivityError> {
        if self.peers.contains_key(dst) {
            return Ok(dst.to_string());
        }
        // §12.56: FIB 优先于静态路由（动态发现 > 静态配置）。
        if let Some(resolver) = &self.fib_resolver {
            let flow_opt = packet.and_then(crate::fib_resolver::FlowKeyView::parse_ipv4);
            if let Some(flow) = flow_opt {
                if let Some(next_hop) = resolver.resolve(dst, &flow) {
                    if self.peers.contains_key(&next_hop) {
                        return Ok(next_hop);
                    }
                }
            }
        }
        if let Some(next_hop) = self.routes.get(dst) {
            return Ok(next_hop.clone());
        }
        if let Some(next_hop) = crate::cidr::longest_prefix_match(&self.prefix_routes, dst) {
            return Ok(next_hop.clone());
        }
        if let Some(egress) = self.egress_peer_vips.first() {
            return Ok(egress.clone());
        }
        Err(ConnectivityError::Invalid {
            message: format!("NO_ROUTE_TO_DST: no route for {dst}"),
        })
    }

    /// 开启加密模式（§12.6）：默认关闭，明文模式与 §12.1-§12.5 语义不变。
    /// 开启后数据帧整体 AEAD 加密；未完成握手的 peer 发送被拒。
    pub fn enable_encryption(&mut self, config: EncryptionConfig) {
        self.encryption = Some(config);
    }

    /// 加密模式是否开启。
    #[must_use]
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption.is_some()
    }

    /// 发起加密握手（§12.6）：生成临时密钥对，经 carrier 发 `HANDSHAKE_INIT`
    /// （虚拟子网层载体 `hs:<peer_vip>:<33B>`），暂存本端密钥等响应。
    ///
    /// # Errors
    ///
    /// peer 未注册 / 加密未开启 / 密钥生成失败时返回结构化错误。
    pub fn begin_handshake(&mut self, peer_virtual_ip: &str) -> Result<(), ConnectivityError> {
        if self.encryption.is_none() {
            return Err(ConnectivityError::Invalid {
                message: "encryption not enabled".to_string(),
            });
        }
        self.ensure_identity()?;
        let (_peer_id, locator, _state, _stats) =
            self.peers
                .get(peer_virtual_ip)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("PEER_NOT_FOUND: {peer_virtual_ip}"),
                })?;
        let locator = locator.clone();
        let eph = KeyPair::generate().map_err(encryption_err)?;
        let static_key = self.identity.identity().unwrap().clone();
        let msg = build_handshake_message(HANDSHAKE_INIT, &eph, static_key.public_key_bytes());
        let wire = handshake_wire(&self.config.virtual_ip, &msg);
        self.carrier
            .send_to(&locator, &wire)
            .map_err(|e| ConnectivityError::Io {
                operation: "handshake_send".to_string(),
                message: e.to_string(),
            })?;
        self.pending_handshakes.insert(
            peer_virtual_ip.to_string(),
            PendingHandshake { eph, static_key },
        );
        self.set_peer_state(peer_virtual_ip, TunnelState::Handshaking);
        Ok(())
    }

    /// 响应加密握手（§12.6）：生成临时密钥对，经 `handshake_respond` 派生
    /// 会话并回 `HANDSHAKE_RESP`，peer 进入 Connected。
    ///
    /// # Errors
    ///
    /// peer 未注册 / 加密未开启 / 握手失败时返回结构化错误。
    pub fn accept_handshake(
        &mut self,
        peer_virtual_ip: &str,
        msg: &HandshakeMessage,
    ) -> Result<(), ConnectivityError> {
        if self.encryption.is_none() {
            return Err(ConnectivityError::Invalid {
                message: "encryption not enabled".to_string(),
            });
        }
        self.ensure_identity()?;
        let (_peer_id, locator, _state, _stats) =
            self.peers
                .get(peer_virtual_ip)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("PEER_NOT_FOUND: {peer_virtual_ip}"),
                })?;
        let locator = locator.clone();
        // TOFU：校验发起方身份（首次学习 / 已一致 / 不匹配拒绝）。
        let peer_id = IdentityManager::peer_id_of(&msg.static_public);
        let action = self
            .identity
            .verify_peer(peer_virtual_ip, &msg.static_public)
            .map_err(|_| ConnectivityError::IdentityRejected {
                peer_id: peer_id.clone(),
            })?;
        if action == IdentityAction::PeerLearned {
            self.events.push(VirtualSubnetEvent::PeerIdentityLearned {
                tunnel_id: self.tunnel_id.clone(),
                peer_id: peer_id.clone(),
            });
        }
        // NAT 会话回程学习（P4.1 真机收尾）：TOFU 校验通过后、回包发出前，
        // 用 UDP 来源刷新对端 locator（公网响应方需回包到发起方 NAT 映射地址）。
        // 身份不匹配/帧解析失败时不会到达此处，防伪造包投毒；非 UDP 承载为 None。
        let locator = if let Some(src) = self.carrier.last_peer_locator() {
            if let Some(entry) = self.peers.get_mut(peer_virtual_ip) {
                if entry.1 != src {
                    entry.1 = src.clone();
                    self.events.push(VirtualSubnetEvent::PeerLocatorUpdated {
                        tunnel_id: self.tunnel_id.clone(),
                        peer_id: peer_id.clone(),
                        new_locator: src.clone(),
                    });
                }
            }
            src
        } else {
            locator
        };
        let eph = KeyPair::generate().map_err(encryption_err)?;
        let static_key = self.identity.identity().unwrap().clone();
        let keys = derive_authed_keys(
            &static_key,
            &eph,
            &msg.static_public,
            &msg.public_key,
            false,
        )
        .map_err(encryption_err)?;
        let resp = build_handshake_message(HANDSHAKE_RESP, &eph, static_key.public_key_bytes());
        let wire = handshake_wire(&self.config.virtual_ip, &resp);
        self.carrier
            .send_to(&locator, &wire)
            .map_err(|e| ConnectivityError::Io {
                operation: "handshake_send".to_string(),
                message: e.to_string(),
            })?;
        self.crypto_sessions.insert(
            peer_virtual_ip.to_string(),
            PeerCryptoSession {
                keys,
                tx_seq: 0,
                rx_replay: ReplayWindow::new(),
            },
        );
        self.set_peer_state(peer_virtual_ip, TunnelState::Connected);
        Ok(())
    }

    /// 完成加密握手（§12.6，发起方）：用 RESP 公钥经 `derive_directional`
    /// 派生会话，peer 进入 Connected。
    ///
    /// # Errors
    ///
    /// 无待消费的发起密钥（未 begin）/ 派生失败时返回结构化错误。
    pub fn complete_handshake(
        &mut self,
        peer_virtual_ip: &str,
        resp: &HandshakeMessage,
    ) -> Result<(), ConnectivityError> {
        let pending = self
            .pending_handshakes
            .remove(peer_virtual_ip)
            .ok_or_else(|| ConnectivityError::Invalid {
                message: format!("HANDSHAKE_IN_PROGRESS: no pending init for {peer_virtual_ip}"),
            })?;
        // TOFU：校验响应方身份（首次学习 / 已一致 / 不匹配拒绝）。
        let peer_id = IdentityManager::peer_id_of(&resp.static_public);
        let action = self
            .identity
            .verify_peer(peer_virtual_ip, &resp.static_public)
            .map_err(|_| ConnectivityError::IdentityRejected {
                peer_id: peer_id.clone(),
            })?;
        if action == IdentityAction::PeerLearned {
            self.events.push(VirtualSubnetEvent::PeerIdentityLearned {
                tunnel_id: self.tunnel_id.clone(),
                peer_id: peer_id.clone(),
            });
        }
        // NAT 会话回程学习（对称，发起方侧）：TOFU 校验通过后用 RESP 来源刷新对端
        // locator。身份不匹配时不会到达此处；非 UDP 承载为 None。
        if let Some(src) = self.carrier.last_peer_locator() {
            if let Some(entry) = self.peers.get_mut(peer_virtual_ip) {
                if entry.1 != src {
                    entry.1 = src.clone();
                    self.events.push(VirtualSubnetEvent::PeerLocatorUpdated {
                        tunnel_id: self.tunnel_id.clone(),
                        peer_id: peer_id.clone(),
                        new_locator: src,
                    });
                }
            }
        }
        let keys = derive_authed_keys(
            &pending.static_key,
            &pending.eph,
            &resp.static_public,
            &resp.public_key,
            true,
        )
        .map_err(encryption_err)?;
        self.crypto_sessions.insert(
            peer_virtual_ip.to_string(),
            PeerCryptoSession {
                keys,
                tx_seq: 0,
                rx_replay: ReplayWindow::new(),
            },
        );
        self.set_peer_state(peer_virtual_ip, TunnelState::Connected);
        Ok(())
    }

    /// 娉ㄥ唽 Peer銆?
    pub fn add_peer(&mut self, peer: TunnelPeer) -> Result<(), ConnectivityError> {
        if !self.config.is_valid_virtual_ip(&peer.virtual_ip) {
            return Err(ConnectivityError::Invalid {
                message: format!(
                    "virtual IP {} not in subnet {}",
                    peer.virtual_ip, self.config.cidr
                ),
            });
        }
        self.peers.insert(
            peer.virtual_ip.clone(),
            (
                peer.peer_id,
                peer.locator,
                TunnelState::Disconnected,
                TunnelStats::default(),
            ),
        );
        Ok(())
    }

    /// Start NAT hole-punch probing for a peer (P2.2 §12.9).
    ///
    /// Transitions the peer to `Probing` and emits `ProbeStarted`.
    pub fn probe_peer(&mut self, peer_virtual_ip: &str) -> Result<(), ConnectivityError> {
        let peer_id = self
            .peers
            .get(peer_virtual_ip)
            .map(|(id, _, _, _)| id.clone())
            .ok_or_else(|| ConnectivityError::Invalid {
                message: format!("PEER_NOT_FOUND: peer {peer_virtual_ip} not found"),
            })?;
        self.set_peer_state(peer_virtual_ip, TunnelState::Probing);
        self.events.push(VirtualSubnetEvent::ProbeStarted {
            tunnel_id: self.tunnel_id.clone(),
            peer_id,
        });
        Ok(())
    }

    /// Apply a successful hole-punch result: dynamically learn the peer's direct
    /// locator and switch the data plane to it (P2.2 §12.9).
    pub fn apply_hole_punch(
        &mut self,
        peer_virtual_ip: &str,
        direct_locator: impl Into<String>,
    ) -> Result<(), ConnectivityError> {
        let (peer_id, new_locator) = {
            let _entry =
                self.peers
                    .get_mut(peer_virtual_ip)
                    .ok_or_else(|| ConnectivityError::Invalid {
                        message: format!("PEER_NOT_FOUND: peer {peer_virtual_ip} not found"),
                    })?;
            (_entry.0.clone(), direct_locator.into())
        };
        let mut locator_new = None;
        if let Some((_, locator, _, _)) = self.peers.get_mut(peer_virtual_ip) {
            locator_new = Some(std::mem::replace(locator, new_locator.clone()));
        }
        let _ = locator_new;
        self.set_peer_state(peer_virtual_ip, TunnelState::Connected);
        self.events.push(VirtualSubnetEvent::PeerLocatorUpdated {
            tunnel_id: self.tunnel_id.clone(),
            peer_id,
            new_locator,
        });
        Ok(())
    }

    /// Fall back to a relay path after hole-punch failure (P2.2 §12.9).
    pub fn fallback_to_relay(
        &mut self,
        peer_virtual_ip: &str,
        relay_locator: impl Into<String>,
    ) -> Result<(), ConnectivityError> {
        let (peer_id, new_locator) = {
            let _entry =
                self.peers
                    .get_mut(peer_virtual_ip)
                    .ok_or_else(|| ConnectivityError::Invalid {
                        message: format!("PEER_NOT_FOUND: peer {peer_virtual_ip} not found"),
                    })?;
            (_entry.0.clone(), relay_locator.into())
        };
        let mut locator_new = None;
        if let Some((_, locator, _, _)) = self.peers.get_mut(peer_virtual_ip) {
            locator_new = Some(std::mem::replace(locator, new_locator.clone()));
        }
        let _ = locator_new;
        self.set_peer_state(peer_virtual_ip, TunnelState::Connected);
        self.events.push(VirtualSubnetEvent::RelayFallback {
            tunnel_id: self.tunnel_id.clone(),
            peer_id,
            relay_locator: new_locator,
        });
        Ok(())
    }

    /// Query the peer's current (possibly dynamically learned) locator (P2.2 §12.9).
    #[must_use]
    pub fn peer_locator(&self, peer_virtual_ip: &str) -> Option<String> {
        self.peers
            .get(peer_virtual_ip)
            .map(|(_, locator, _, _)| locator.clone())
    }

    /// 查询已配置 relay locator（P4.2 §12.9.3，TURN 中继地址）。
    #[must_use]
    pub fn relay_locator(&self, peer_virtual_ip: &str) -> Option<String> {
        self.relay_locators.get(peer_virtual_ip).cloned()
    }

    /// 配置 peer 的 relay locator（P4.2 §12.9.3，打洞失败回退用）。
    pub fn set_relay_locator(&mut self, peer_virtual_ip: &str, locator: impl Into<String>) {
        self.relay_locators
            .insert(peer_virtual_ip.to_string(), locator.into());
    }

    /// 非阻塞发起对 peer 的双向打洞（P4.2 §12.9.3）。
    ///
    /// 置 `Probing` + `HolePunchStarted` 事件，记录 pending punch，经 carrier
    /// 向 target 发第 1 个 `ph` 帧。完成由收 `pa` 帧（recv_and_deliver）落账；
    /// 重试/失败由 `punch_tick` 推进。
    ///
    /// 注意：状态迁移（Probing + 事件 + pending）先于发送发生；若 carrier
    /// `send_to` 失败返回 Err，peer 已处于 `Probing`（调用方可用 `punch_tick`
    /// 继续重试或让其耗尽）。
    pub fn begin_hole_punch(
        &mut self,
        peer_virtual_ip: &str,
        target: &str,
    ) -> Result<(), ConnectivityError> {
        self.begin_hole_punch_multi(peer_virtual_ip, &[target.to_string()])
    }

    /// 非阻塞发起对 peer 的多候选并发打洞（P4.2 §12.9.5）。
    ///
    /// 置 `Probing` + `HolePunchStarted` 事件，记录 pending
    /// `{ targets, attempts: 0 }`，经 carrier 对**每个**候选发第 1 个 `ph`
    /// 帧（同一 socket，WireGuard 风格）。任一候选收到 `pa` 确认（来源学习，
    /// NAT 会话回程）即落账 Connected（先到先用），清理 pending。
    ///
    /// 失败语义：未注册 peer → `PEER_NOT_FOUND`；空候选列表 →
    /// `HOLE_PUNCH_EMPTY_TARGETS`。
    ///
    /// 注意：状态迁移（Probing + 事件 + pending）先于发送发生；若 carrier
    /// `send_to` 失败返回 Err，peer 已处于 `Probing`（调用方可用 `punch_tick`
    /// 继续重试或让其耗尽）。
    pub fn begin_hole_punch_multi(
        &mut self,
        peer_virtual_ip: &str,
        targets: &[String],
    ) -> Result<(), ConnectivityError> {
        self.peers
            .get(peer_virtual_ip)
            .ok_or_else(|| ConnectivityError::Invalid {
                message: format!("PEER_NOT_FOUND: peer {peer_virtual_ip} not found"),
            })?;
        if targets.is_empty() {
            return Err(ConnectivityError::Invalid {
                message: format!(
                    "HOLE_PUNCH_EMPTY_TARGETS: peer {peer_virtual_ip} has no punch targets"
                ),
            });
        }
        self.pending_punches.insert(
            peer_virtual_ip.to_string(),
            PendingPunch {
                targets: targets.to_vec(),
                attempts: 0,
            },
        );
        self.set_peer_state(peer_virtual_ip, TunnelState::Probing);
        self.events.push(VirtualSubnetEvent::HolePunchStarted {
            tunnel_id: self.tunnel_id.clone(),
            peer_vip: peer_virtual_ip.to_string(),
            targets: targets.to_vec(),
        });
        let frame = hole_punch_frame(b'h', &self.config.virtual_ip, &self.hole_punch_config.magic);
        for target in targets {
            self.carrier
                .send_to(target, &frame)
                .map_err(|e| ConnectivityError::Io {
                    operation: "hole_punch_send".to_string(),
                    message: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// 推进一次打洞重试状态机（P4.2 §12.9.3）。
    ///
    /// 已 Connected → 幂等 Ok；无 pending → 幂等 Ok；attempts < max_attempts →
    /// 重发 `ph` 帧并 Ok；attempts == max_attempts → `HolePunchFailed` 事件 +
    /// 清理 pending：配置了 relay locator 则自动 `fallback_to_relay` 并 Ok，
    /// 否则返回 Err(HOLE_PUNCH_FAILED)。
    pub fn punch_tick(&mut self, peer_virtual_ip: &str) -> Result<(), ConnectivityError> {
        if self.peer_state(peer_virtual_ip) == Some(TunnelState::Connected) {
            return Ok(());
        }
        let Some(pending) = self.pending_punches.get_mut(peer_virtual_ip) else {
            return Ok(());
        };
        pending.attempts += 1;
        if pending.attempts < self.hole_punch_config.max_attempts {
            let frame =
                hole_punch_frame(b'h', &self.config.virtual_ip, &self.hole_punch_config.magic);
            for target in &pending.targets {
                self.carrier
                    .send_to(target, &frame)
                    .map_err(|e| ConnectivityError::Io {
                        operation: "hole_punch_retry".to_string(),
                        message: e.to_string(),
                    })?;
            }
            return Ok(());
        }
        // 尝试耗尽 → 失败
        let reason = format!("attempts exhausted ({})", pending.attempts);
        let tried_targets = pending.targets.clone();
        self.pending_punches.remove(peer_virtual_ip);
        self.events.push(VirtualSubnetEvent::HolePunchFailed {
            tunnel_id: self.tunnel_id.clone(),
            peer_vip: peer_virtual_ip.to_string(),
            reason: reason.clone(),
            targets: tried_targets,
        });
        if let Some(relay) = self.relay_locators.get(peer_virtual_ip).cloned() {
            self.fallback_to_relay(peer_virtual_ip, relay)?;
            Ok(())
        } else {
            Err(ConnectivityError::Invalid {
                message: format!("HOLE_PUNCH_FAILED: {reason}"),
            })
        }
    }

    /// NAT 类型驱动的路径选择（P4.2 §12.9.4）。
    ///
    /// 由决策表（`nat::nat_path_decision`）决定打洞直连还是直达 relay：
    /// - Direct → `ConnectivityPlan::Direct { target }`（调用方继续
    ///   `begin_hole_punch`）；
    /// - Relay → `ConnectivityPlan::Relay { locator }`（取 `relay_locator`
    ///   配置；未配置 → Err(`RELAY_NOT_CONFIGURED`)）。
    ///
    /// 两种决策均发 `PathDecided` 事件（tunnel_id 贯通）。
    pub fn plan_connectivity(
        &mut self,
        peer_virtual_ip: &str,
        nat_type: crate::nat::NatType,
        direct_target: &str,
    ) -> Result<ConnectivityPlan, ConnectivityError> {
        self.peers
            .get(peer_virtual_ip)
            .ok_or_else(|| ConnectivityError::Invalid {
                message: format!("PEER_NOT_FOUND: peer {peer_virtual_ip} not found"),
            })?;
        let decision = crate::nat::nat_path_decision(nat_type);
        self.events.push(VirtualSubnetEvent::PathDecided {
            tunnel_id: self.tunnel_id.clone(),
            peer_vip: peer_virtual_ip.to_string(),
            nat_type,
            decision,
        });
        match decision {
            crate::nat::PathDecision::Direct => Ok(ConnectivityPlan::Direct {
                target: direct_target.to_string(),
            }),
            crate::nat::PathDecision::Relay => {
                if let Some(locator) = self.relay_locators.get(peer_virtual_ip).cloned() {
                    Ok(ConnectivityPlan::Relay { locator })
                } else {
                    Err(ConnectivityError::Invalid {
                        message: format!(
                            "RELAY_NOT_CONFIGURED: peer {peer_virtual_ip} has no relay locator"
                        ),
                    })
                }
            }
        }
    }

    /// 处理打洞帧（P4.2 §12.9.3）：`ph` 请求 → 学习来源 + 回 `pa` 到来源；
    /// `pa` 确认 → 学习来源 + 若本端发起中（Probing）则落账 Connected。
    ///
    /// magic 校验失败视为非打洞帧（丢弃，Ok(None)），防数据帧/握手帧误判。
    fn handle_hole_punch_frame(
        &mut self,
        data: &[u8],
    ) -> Result<Option<(String, usize)>, ConnectivityError> {
        if data.len() < 3 || data[1] != b'h' && data[1] != b'a' {
            return Err(ConnectivityError::Invalid {
                message: "invalid hole punch frame".to_string(),
            });
        }
        let rest = &data[3..];
        let Some(colon) = rest.iter().position(|b| *b == b':') else {
            return Err(ConnectivityError::Invalid {
                message: "invalid hole punch frame (missing separator)".to_string(),
            });
        };
        let sender_vip = String::from_utf8_lossy(&rest[..colon]).to_string();
        let magic = &rest[colon + 1..];
        if magic.len() != self.hole_punch_config.magic.len()
            || magic != self.hole_punch_config.magic
        {
            // 非打洞帧：丢弃
            return Ok(None);
        }

        // 学习来源（NAT 会话回程）
        let source = self.carrier.last_peer_locator();
        if let Some(src) = source.clone() {
            if let Some((_, locator, _, _)) = self.peers.get_mut(&sender_vip) {
                if *locator != src {
                    *locator = src.clone();
                    self.events.push(VirtualSubnetEvent::PeerLocatorUpdated {
                        tunnel_id: self.tunnel_id.clone(),
                        peer_id: sender_vip.clone(),
                        new_locator: src,
                    });
                }
            }
        }

        match data[1] {
            b'h' => {
                // 打洞请求：回 pa 到来源（无来源则回配置 locator）
                let target = source.unwrap_or_else(|| {
                    self.peers
                        .get(&sender_vip)
                        .map(|(_, l, _, _)| l.clone())
                        .unwrap_or_default()
                });
                if !target.is_empty() {
                    let pa = hole_punch_frame(
                        b'a',
                        &self.config.virtual_ip,
                        &self.hole_punch_config.magic,
                    );
                    self.carrier
                        .send_to(&target, &pa)
                        .map_err(|e| ConnectivityError::Io {
                            operation: "hole_punch_ack".to_string(),
                            message: e.to_string(),
                        })?;
                    // 收到 ph 证明对端可达本端（回 pa 后双向可达）：置对端
                    // Connected，数据面即可经学习/配置 locator 发送。
                    self.set_peer_state(&sender_vip, TunnelState::Connected);
                }
            }
            // 打洞确认：仅本地发起中（Probing）时落账，防伪造成功
            b'a' if self.peer_state(&sender_vip) == Some(TunnelState::Probing)
                && self.pending_punches.contains_key(&sender_vip) =>
            {
                let target = {
                    let pending = self.pending_punches.get(&sender_vip).unwrap();
                    source
                        .clone()
                        .unwrap_or_else(|| pending.targets.first().cloned().unwrap_or_default())
                };
                self.pending_punches.remove(&sender_vip);
                self.apply_hole_punch(&sender_vip, target.clone())?;
                self.events.push(VirtualSubnetEvent::HolePunchSucceeded {
                    tunnel_id: self.tunnel_id.clone(),
                    peer_vip: sender_vip.clone(),
                    target,
                });
            }
            _ => {}
        }
        Ok(None)
    }
    /// 璁剧疆 Peer 鐘舵€併€?
    pub fn set_peer_state(&mut self, virtual_ip: &str, state: TunnelState) {
        if let Some(entry) = self.peers.get_mut(virtual_ip) {
            self.events.push(VirtualSubnetEvent::PeerStateChanged {
                tunnel_id: self.tunnel_id.clone(),
                peer_id: entry.0.clone(),
                new_state: state,
            });
            entry.2 = state;
        }
    }

    /// 鑾峰彇 Peer 鐘舵€併€?
    #[must_use]
    pub fn peer_state(&self, virtual_ip: &str) -> Option<TunnelState> {
        self.peers.get(virtual_ip).map(|(_, _, state, _)| *state)
    }

    /// 鑾峰彇 Peer 缁熻銆?
    #[must_use]
    pub fn peer_stats(&self, virtual_ip: &str) -> Option<&TunnelStats> {
        self.peers.get(virtual_ip).map(|(_, _, _, stats)| stats)
    }

    /// 鑾峰彇鎵€鏈?Peer 鍒楄〃銆?
    #[must_use]
    pub fn peers(&self) -> Vec<(&str, TunnelState)> {
        self.peers
            .iter()
            .map(|(ip, (_, _, state, _))| (ip.as_str(), *state))
            .collect()
    }

    /// 鍙戦€佷竴涓?IP 鍖呭埌瀵圭锛堝皝瑁?+ carrier send锛夈€?
    ///
    /// P1 搂12.5锛氳嫢 dst 鏄洿杩?Connected peer 鍒欑洿鍙戯紱鍚﹀垯鏌ラ潤鎬佽矾鐢辫〃
    /// 寰?next_hop锛屾妸鍚屼竴甯э紙鍘熷 dst 涓嶅彉锛夊彂缁?next_hop銆?
    pub fn send_ip_packet(
        &mut self,
        dst_virtual_ip: &str,
        packet: &[u8],
    ) -> Result<(), ConnectivityError> {
        // 1. 解析出下一跳（统一决策：直连 → 精确 → 最长前缀 → 出口，§12.5/§12.14）
        let next_hop = self.resolve_next_hop(dst_virtual_ip, Some(packet))?;

        // 2. 鏍￠獙 next_hop 鏄?Connected peer
        let (_peer_id, locator, state, stats) =
            self.peers
                .get_mut(&next_hop)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("next-hop peer {next_hop} not found"),
                })?;

        if *state != TunnelState::Connected {
            return Err(ConnectivityError::Invalid {
                message: format!("next-hop peer {next_hop} not connected"),
            });
        }

        // 3. 灏佽闅ч亾甯э紙dst 濮嬬粓鏄師濮?dst锛屼緵涓棿鑺傜偣鍒ゆ柇鏈€缁堢洰鐨勫湴锛?
        let header = TunnelFrameHeader {
            src_virtual_ip: self.config.virtual_ip.clone(),
            dst_virtual_ip: dst_virtual_ip.to_string(),
        };
        let mut inner = header.serialize();
        inner.extend_from_slice(packet);

        // 数据面管线（§12.41）：明文会话激活管线；门控/压缩/分片后产生 NXP1 wire 单元。
        if let Some(pipeline) = self.pipeline.as_mut() {
            if !self.crypto_sessions.contains_key(&next_hop) {
                let outcome =
                    pipeline.egress(&inner, &self.config.virtual_ip, dst_virtual_ip, &next_hop)?;
                match outcome {
                    EgressOutcome::DroppedFirewall => {
                        self.events
                            .push(VirtualSubnetEvent::PacketDroppedByFirewall {
                                tunnel_id: self.tunnel_id.clone(),
                                direction: "egress",
                                src_virtual_ip: self.config.virtual_ip.clone(),
                                dst_virtual_ip: dst_virtual_ip.to_string(),
                            });
                        return Ok(());
                    }
                    EgressOutcome::DroppedQos => {
                        self.events.push(VirtualSubnetEvent::QosLimited {
                            tunnel_id: self.tunnel_id.clone(),
                            direction: "egress",
                            tag: next_hop.clone(),
                            bytes: inner.len() as u64,
                        });
                        return Ok(());
                    }
                    EgressOutcome::Send(units) => {
                        for unit in units {
                            // 分片单元发 FragmentSent 事件（kind=2：wire[5]）。
                            if unit.len() >= 18 && unit[5] == 2 {
                                let packet_id = u64::from_be_bytes(unit[6..14].try_into().unwrap());
                                let index = u16::from_be_bytes(unit[14..16].try_into().unwrap());
                                let total = u16::from_be_bytes(unit[16..18].try_into().unwrap());
                                self.events.push(VirtualSubnetEvent::FragmentSent {
                                    tunnel_id: self.tunnel_id.clone(),
                                    packet_id,
                                    index,
                                    total,
                                });
                            }
                            self.carrier.send_to(locator, &unit).map_err(|e| {
                                ConnectivityError::Io {
                                    operation: "send_to".to_string(),
                                    message: e.to_string(),
                                }
                            })?;
                            stats.bytes_sent += unit.len() as u64;
                        }
                        return Ok(());
                    }
                }
            }
        }
        // 加密模式：整帧 AEAD 加密（会话不存在 = 未握手，拒绝发送）
        let wire = if let Some(session) = self.crypto_sessions.get_mut(&next_hop) {
            let cipher = encrypt_frame(&session.keys.tx, session.tx_seq, &inner).map_err(|e| {
                ConnectivityError::Invalid {
                    message: format!("CRYPTO_ERROR: {e}"),
                }
            })?;
            session.tx_seq += 1;
            cipher
        } else if self.encryption.is_some() {
            return Err(ConnectivityError::Invalid {
                message: format!("peer {next_hop} not handshaken"),
            });
        } else {
            inner
        };

        // 通过 carrier 发给 next_hop
        self.carrier
            .send_to(locator, &wire)
            .map_err(|e| ConnectivityError::Io {
                operation: "send_to".to_string(),
                message: e.to_string(),
            })?;

        stats.bytes_sent += wire.len() as u64;
        Ok(())
    }

    /// 鎺ユ敹涓€涓毀閬撳抚锛岃В灏佽鍚庡啓鍏?VPI锛屾垨鎸夐潤鎬佽矾鐢辫浆鍙戙€?
    ///
    /// P1 搂12.5锛氳嫢 `header.dst_virtual_ip == self.config.virtual_ip` 鈫?鍐?VPI锛?
    /// 鍚﹀垯鏌?`routes[dst]` 寰?next_hop锛屾妸鍘熷甯э紙鍚?header锛夎浆鍙戠粰 next_hop锛?
    /// 璁?`bytes_forwarded` 骞跺彂 `PacketForwarded` 浜嬩欢銆?
    pub fn recv_and_deliver(
        &mut self,
        buffer: &mut [u8],
        now_secs: u64,
    ) -> Result<Option<(String, usize)>, ConnectivityError> {
        let n = self
            .carrier
            .receive_into(buffer)
            .map_err(|e| ConnectivityError::Io {
                operation: "receive_into".to_string(),
                message: e.to_string(),
            })?;

        if n == 0 {
            return Ok(None);
        }

        let data = buffer[..n].to_vec();

        // nxb: bootstrap 控制帧分流（v2 §6.4，S5）：命中即交 hook，不进数据管线/试解密。
        if let Some(rest) = data.strip_prefix(b"nxb:") {
            if let Some(hook) = self.bootstrap.as_mut() {
                let src = self.carrier.last_peer_locator();
                if let Some((dst, bytes)) = hook.on_control_datagram(src.as_deref(), rest, now_secs)
                {
                    self.carrier
                        .send_to(&dst, &bytes)
                        .map_err(|e| ConnectivityError::Io {
                            operation: "bootstrap reply".to_string(),
                            message: e.to_string(),
                        })?;
                }
            }
            return Ok(None);
        }

        // 数据面管线（§12.41）：识别 NXP1 管线单元，逆序重组/解压/门控后还原 legacy inner。
        let data = if dataplane_pipeline::is_pipeline_unit(&data) {
            match self.pipeline.as_mut() {
                Some(pipeline) => match pipeline.ingress(&data, "")? {
                    IngressOutcome::Drop => return Ok(None),
                    IngressOutcome::NeedMore => return Ok(None),
                    IngressOutcome::Deliver(inner) => inner,
                },
                None => data,
            }
        } else {
            data
        };
        // 握手帧分流（§12.6，虚拟子网层载体 "hs:<peer_vip>:<33B>"）。
        // 握手帧不写 VPI、不计数据统计；成功/失败均返回 Ok(None) 表示非数据帧。
        if data.starts_with(b"hs:") {
            let rest = &data[3..];
            let Some(colon) = rest.iter().position(|b| *b == b':') else {
                return Err(ConnectivityError::Invalid {
                    message: "invalid handshake frame".to_string(),
                });
            };
            let sender_vip = String::from_utf8_lossy(&rest[..colon]).to_string();
            let msg = HandshakeMessage::from_bytes(&rest[colon + 1..]).map_err(|e| {
                ConnectivityError::Invalid {
                    message: format!("HANDSHAKE_FAILED: {e}"),
                }
            })?;
            match msg.msg_type {
                HANDSHAKE_INIT => self.accept_handshake(&sender_vip, &msg)?,
                HANDSHAKE_RESP => self.complete_handshake(&sender_vip, &msg)?,
                _ => {
                    return Err(ConnectivityError::Invalid {
                        message: format!("HANDSHAKE_FAILED: unexpected type {}", msg.msg_type),
                    });
                }
            }
            return Ok(None);
        }

        // 打洞帧分流（P4.2 §12.9.3）：载体 "ph:<sender_vip>:<magic4>" /
        // "pa:<sender_vip>:<magic4>"。打洞帧不写 VPI、不计数据统计；
        // 均返回 Ok(None) 表示非数据帧。
        if data.starts_with(b"ph:") || data.starts_with(b"pa:") {
            return self.handle_hole_punch_frame(&data);
        }

        // 解封装（明文模式：直接解析；加密模式：按各对端会话 rx 试解密）
        let (header, payload, plain_full) = if self.encryption.is_some() {
            let mut found: Option<(String, Vec<u8>)> = None;
            for (vip, session) in self.crypto_sessions.iter_mut() {
                if let Ok((seq, plain)) = decrypt_frame(&session.keys.rx, &data) {
                    session.rx_replay.check_and_accept(seq).map_err(|e| {
                        ConnectivityError::Invalid {
                            message: format!("REPLAY_REJECTED: {e}"),
                        }
                    })?;
                    found = Some((vip.clone(), plain));
                    break;
                }
            }
            let (sender_vip, plain) = found.ok_or_else(|| ConnectivityError::Invalid {
                message: "CRYPTO_ERROR: no matching session or bad tag".to_string(),
            })?;
            let (header, payload) = TunnelFrameHeader::deserialize(&plain).ok_or_else(|| {
                ConnectivityError::Invalid {
                    message: "invalid tunnel frame header".to_string(),
                }
            })?;
            (header, payload.to_vec(), (sender_vip, plain))
        } else {
            let (header, payload) = TunnelFrameHeader::deserialize(&data).ok_or_else(|| {
                ConnectivityError::Invalid {
                    message: "invalid tunnel frame header".to_string(),
                }
            })?;
            (header, payload.to_vec(), (String::new(), data))
        };

        // 更新发送方统计（加密模式用试解密命中的 sender；明文模式用 header.src）
        let sender_vip = if plain_full.0.is_empty() {
            header.src_virtual_ip.clone()
        } else {
            plain_full.0.clone()
        };
        if let Some((_, _, _, stats)) = self.peers.get_mut(&sender_vip) {
            stats.bytes_received += n as u64;
        }

        // 本机目的 -> 写 VPI
        if header.dst_virtual_ip == self.config.virtual_ip {
            self.vpi.send(&payload).map_err(|e| ConnectivityError::Io {
                operation: "vpi_send".to_string(),
                message: e.to_string(),
            })?;
            return Ok(Some((sender_vip, payload.len())));
        }

        // 命中本节点可达前缀（P2-5 §12.14）→ 写 VPI + LocalPrefixDelivered 事件
        if self
            .local_prefixes
            .iter()
            .any(|p| crate::cidr::cidr_contains(p, &header.dst_virtual_ip))
        {
            self.vpi.send(&payload).map_err(|e| ConnectivityError::Io {
                operation: "vpi_send".to_string(),
                message: e.to_string(),
            })?;
            self.events.push(VirtualSubnetEvent::LocalPrefixDelivered {
                tunnel_id: self.tunnel_id.clone(),
                dst_virtual_ip: header.dst_virtual_ip.clone(),
                bytes: payload.len() as u64,
            });
            return Ok(Some((sender_vip, payload.len())));
        }

        // 非本机目的 -> 转发（§12.5：先查直连 peer，再查静态路由表）
        let next_hop = self.resolve_next_hop(&header.dst_virtual_ip, Some(&payload))?;

        let (_peer_id, locator, state, _stats) =
            self.peers
                .get(&next_hop)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("next-hop peer {next_hop} not found"),
                })?;
        if *state != TunnelState::Connected {
            return Err(ConnectivityError::Invalid {
                message: format!("next-hop peer {next_hop} not connected"),
            });
        }
        let locator = locator.clone();

        // 转发：明文模式发原数据；加密模式用 next_hop 会话重新加密同一明文
        // （虚拟 IP 头内容不变，§12.5"帧头不剥不改"语义保持）。
        let wire =
            if self.encryption.is_some() {
                let session = self.crypto_sessions.get_mut(&next_hop).ok_or_else(|| {
                    ConnectivityError::Invalid {
                        message: format!("peer {next_hop} not handshaken"),
                    }
                })?;
                let cipher = encrypt_frame(&session.keys.tx, session.tx_seq, &plain_full.1)
                    .map_err(|e| ConnectivityError::Invalid {
                        message: format!("CRYPTO_ERROR: {e}"),
                    })?;
                session.tx_seq += 1;
                cipher
            } else {
                plain_full.1
            };
        self.carrier
            .send_to(&locator, &wire)
            .map_err(|e| ConnectivityError::Io {
                operation: "forward_send_to".to_string(),
                message: e.to_string(),
            })?;

        // 更新转发统计 + 发事件
        if let Some((_, _, _, stats)) = self.peers.get_mut(&next_hop) {
            stats.bytes_forwarded += wire.len() as u64;
        }
        self.events.push(VirtualSubnetEvent::PacketForwarded {
            tunnel_id: self.tunnel_id.clone(),
            src_virtual_ip: header.src_virtual_ip.clone(),
            dst_virtual_ip: header.dst_virtual_ip.clone(),
            next_hop: next_hop.clone(),
            bytes: wire.len() as u64,
        });

        // 转发后不写 VPI，返回原始 src 和帧长
        Ok(Some((sender_vip, n)))
    }
    pub fn read_vpi_and_route(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, ConnectivityError> {
        let n = self
            .vpi
            .receive(buffer)
            .map_err(|e| ConnectivityError::Io {
                operation: "vpi_receive".to_string(),
                message: e.to_string(),
            })?;

        if n == 0 {
            return Ok(None);
        }

        // P0 绠€鍖栵細浠?IP 鍖呮彁鍙栫洰鐨?IP锛堢 16-19 瀛楄妭鏄洰鐨?IP锛?
        // 鐪熷疄瀹炵幇搴旇瑙ｆ瀽 IP 澶达紝P0 绠€鍖栦负鍙栧墠 24 瀛楄妭鍐呯殑鐩殑 IP 瀛楁
        let packet = &buffer[..n];
        let dst_ip = extract_dst_ip_from_ipv4(packet).unwrap_or_default();

        self.send_ip_packet(&dst_ip, packet)?;
        Ok(Some(n))
    }

    /// 鑾峰彇瀛愮綉閰嶇疆銆?
    #[must_use]
    pub fn config(&self) -> &VirtualSubnetConfig {
        &self.config
    }

    /// 鑾峰彇闅ч亾 ID銆?
    #[must_use]
    pub fn tunnel_id(&self) -> &str {
        &self.tunnel_id
    }

    /// 鑾峰彇浜嬩欢娴侊紙鐢ㄤ簬鍙娴嬫€у拰閲嶆斁锛夈€?
    /// 本端 PeerId（P4.1 §12.39，身份自动生成后可用）。
    pub fn peer_id(&self) -> Option<String> {
        self.identity.peer_id()
    }

    #[must_use]
    pub fn events(&self) -> &[VirtualSubnetEvent] {
        &self.events
    }
}

/// 浠?IPv4 鍖呮彁鍙栫洰鐨?IP锛圥0 绠€鍖栧疄鐜帮細鍙栫 16-19 瀛楄妭锛夈€?
/// 构造虚拟子网层握手载体（§12.6）：`hs:<peer_virtual_ip>:<HandshakeMessage 33B>`。
/// 明文仅含公开公钥与类型，无机密；数据帧（密文 ≥40B）不会以 `hs:` 开头。
#[must_use]
fn handshake_wire(peer_virtual_ip: &str, msg: &HandshakeMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + peer_virtual_ip.len() + 1 + 65);
    out.extend_from_slice(b"hs:");
    out.extend_from_slice(peer_virtual_ip.as_bytes());
    out.push(b':');
    out.extend_from_slice(&msg.to_bytes());
    out
}

/// 把加密错误映射为 `ConnectivityError::Invalid`（结构化、可诊断）。
fn encryption_err(e: EncryptionError) -> ConnectivityError {
    ConnectivityError::Invalid {
        message: format!("HANDSHAKE_FAILED: {e}"),
    }
}

fn extract_dst_ip_from_ipv4(packet: &[u8]) -> Option<String> {
    if packet.len() < 20 {
        return None;
    }
    // IPv4 澶寸 16-19 瀛楄妭鏄洰鐨?IP
    let dst = &packet[16..20];
    Some(format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]))
}

// ---------- 鍐呭瓨妯℃嫙瀹炵幇锛堢绾跨‘瀹氭€?E4锛?----------

use std::sync::Mutex;

/// 鍐呭瓨妯℃嫙 VPI锛堟祴璇曞伐鍏凤紝鐢熶骇浠ｇ爜璇峰嬁浣跨敤锛夈€?
///
/// 鐢ㄤ簬鍗曞厓娴嬭瘯鍜?E4 绂荤嚎鍦烘櫙鎵ц锛屼笉瀹炵幇鐪熷疄 TUN 椹卞姩銆?
pub struct MemoryVpi {
    /// 鎺ユ敹缂撳啿鍖猴紙瀵圭鍐欏叆锛屾湰鑺傜偣璇诲彇锛夈€?
    recv_buf: Mutex<Vec<u8>>,
    /// 鍙戦€佺紦鍐插尯锛堟湰鑺傜偣鍐欏叆锛屽绔鍙栵級銆?
    send_buf: Arc<Mutex<Vec<u8>>>,
}

impl MemoryVpi {
    /// 鍒涘缓鍐呭瓨 VPI銆?
    #[must_use]
    pub fn new() -> Self {
        Self {
            recv_buf: Mutex::new(Vec::new()),
            send_buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 娉ㄥ叆涓€涓緟鎺ユ敹鐨勫寘锛堟ā鎷熷绔彂鏉ワ級銆?
    pub fn inject_recv(&self, data: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.extend_from_slice(data);
    }

    /// 璇诲彇宸插彂閫佺殑鍖咃紙妯℃嫙鏈妭鐐瑰彂鍑猴級銆?
    #[must_use]
    pub fn take_sent(&self) -> Vec<u8> {
        let mut buf = self.send_buf.lock().unwrap();
        std::mem::take(&mut *buf)
    }
    /// 娉ㄥ叆涓€涓?VPI 宸插彂閫佺殑鍖呯殑鍙ユ焺锛堢敤浜?E4 闈炲悓姝ユ祦绋嬶細VPI 琚?move 杩?tunnel 鍚庝粛鍙鍙栧彂閫佹暟鎹級銆?
    #[must_use]
    pub fn sent_handle(&self) -> Arc<Mutex<Vec<u8>>> {
        self.send_buf.clone()
    }
}

impl Default for MemoryVpi {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualPacketInterface for MemoryVpi {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let mut buf = self.recv_buf.lock().unwrap();
        let n = buf.len().min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&buf[..n]);
            buf.drain(..n);
        }
        Ok(n)
    }

    fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
        let mut buf = self.send_buf.lock().unwrap();
        buf.extend_from_slice(packet);
        Ok(())
    }
}

/// 鍐呭瓨妯℃嫙 PacketCarrier锛堟祴璇曞伐鍏凤紝鐢熶骇浠ｇ爜璇峰嬁浣跨敤锛夈€?
///
/// 鐢ㄤ簬鍗曞厓娴嬭瘯鍜?E4 绂荤嚎鍦烘櫙鎵ц锛屼笉瀹炵幇鐪熷疄 UDP 缃戠粶鏍堛€?
pub struct MemoryCarrier {
    /// 鍙戦€佺紦鍐插尯锛堟湰鑺傜偣鍙戦€侊紝瀵圭鎺ユ敹锛夆€斺€斾笌瀵圭鐨?recv_buf 鍏变韩銆?
    send_buf: Arc<Mutex<Vec<Vec<u8>>>>,
    /// 鎺ユ敹缂撳啿鍖猴紙瀵圭鍙戦€侊紝鏈妭鐐规帴鏀讹級鈥斺€斾笌瀵圭鐨?send_buf 鍏变韩銆?
    recv_buf: Arc<Mutex<Vec<Vec<u8>>>>,
    /// 缁戝畾鐨?locator銆?
    local_locator: Mutex<Option<String>>,
    /// Last frame source (NAT session-return learning test seam; None by default).
    last_source: Mutex<Option<String>>,
}

impl MemoryCarrier {
    /// 鍒涘缓绌虹殑 MemoryCarrier锛堢嫭绔嬬紦鍐插尯锛屼笉涓庝换浣曞绔繛鎺ワ級銆?
    #[must_use]
    pub fn new() -> Self {
        Self {
            send_buf: Arc::new(Mutex::new(Vec::new())),
            recv_buf: Arc::new(Mutex::new(Vec::new())),
            local_locator: Mutex::new(None),
            last_source: Mutex::new(None),
        }
    }

    /// Set the last frame source (test seam: emulate a UDP carrier NAT-mapped source).
    pub fn set_last_source(&self, locator: impl Into<String>) {
        *self.last_source.lock().unwrap() = Some(locator.into());
    }

    /// 鍒涘缓涓€瀵圭湡姝ｄ簰杩炵殑 MemoryCarrier锛欰.send <-> B.recv, B.send <-> A.recv銆?
    #[must_use]
    pub fn connected_pair() -> (Self, Self) {
        let a_send = Arc::new(Mutex::new(Vec::new()));
        let b_send = Arc::new(Mutex::new(Vec::new()));

        // A 鐨勬帴鏀?= B 鐨勫彂閫?
        // B 鐨勬帴鏀?= A 鐨勫彂閫?
        let a = Self {
            send_buf: a_send.clone(),
            recv_buf: b_send.clone(),
            last_source: Mutex::new(None),
            local_locator: Mutex::new(None),
        };
        let b = Self {
            send_buf: b_send.clone(),
            recv_buf: a_send.clone(),
            last_source: Mutex::new(None),
            local_locator: Mutex::new(None),
        };
        (a, b)
    }

    /// 鎶婂彟涓€涓?carrier 鐨勬帴鏀剁紦鍐插尯杩炲埌鏈妭鐐圭殑鍙戦€佺紦鍐插尯銆?
    pub fn connect_to(&self, other: &MemoryCarrier) {
        // 绠€鍖栵細鎶?self.send_buf 鐨勫唴瀹瑰鍒跺埌 other.recv_buf
        // 瀹為檯搴旇鐢?channel锛屼絾涓轰簡 E4 纭畾鎬э紝鎴戜滑鐩存帴鎿嶄綔
        let send = self.send_buf.lock().unwrap();
        let mut recv = other.recv_buf.lock().unwrap();
        recv.extend(send.iter().cloned());
    }

    /// 娉ㄥ叆涓€涓緟鎺ユ敹鐨勫抚銆?
    pub fn inject_recv(&self, data: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.push(data.to_vec());
    }
}

impl PacketCarrier for MemoryCarrier {
    fn bind(&mut self, local_locator: &str) -> Result<String, PlatformError> {
        *self.local_locator.lock().unwrap() = Some(local_locator.to_string());
        Ok(local_locator.to_string())
    }

    fn send_to(&mut self, _peer_locator: &str, frame: &[u8]) -> Result<(), PlatformError> {
        let mut buf = self.send_buf.lock().unwrap();
        buf.push(frame.to_vec());
        Ok(())
    }

    fn receive_into(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let mut buf = self.recv_buf.lock().unwrap();
        if buf.is_empty() {
            return Ok(0);
        }
        let frame = buf.remove(0);
        let n = frame.len().min(output.len());
        output[..n].copy_from_slice(&frame[..n]);
        Ok(n)
    }
    fn local_locator(&self) -> Option<String> {
        self.local_locator.lock().unwrap().clone()
    }

    fn last_peer_locator(&self) -> Option<String> {
        self.last_source.lock().unwrap().clone()
    }
}

impl MemoryCarrier {
    /// Inject a raw frame into the receive buffer (test seam).
    pub fn inject(&self, frame: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.push(frame.to_vec());
    }
}

impl Default for MemoryCarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// 打洞帧构造（P4.2 §12.9.3）：`p<h|a>:<peer_vip>:<magic4>`。
///
/// kind_byte 为 b'h'（ph 请求）或 b'a'（pa 确认）。
#[must_use]
fn hole_punch_frame(kind_byte: u8, peer_vip: &str, magic: &[u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + peer_vip.len() + 1 + magic.len());
    out.push(b'p');
    out.push(kind_byte);
    out.push(b':');
    out.extend_from_slice(peer_vip.as_bytes());
    out.push(b':');
    out.extend_from_slice(magic);
    out
}

/// 澶氬绔唴瀛?PacketCarrier锛圥1 搂12.5 涓夎妭鐐?mesh 娴嬭瘯鏇胯韩锛夈€?
///
/// 涓?`MemoryCarrier`锛堢偣瀵圭偣锛変笉鍚岋紝`MeshCarrier` 鎸?`peer_locator` 鎶婂抚
/// 璺敱鍒颁笉鍚屽绔殑鎺ユ敹缂撳啿鍖猴紝鐢ㄤ簬涓夎妭鐐?A鈥擝鈥擟 绂荤嚎纭畾鎬?E4銆?
/// 鐢熶骇浠ｇ爜璇峰嬁浣跨敤銆?
pub struct MeshCarrier {
    /// 鏈妭鐐规帴鏀剁紦鍐插尯锛堟墍鏈夌洿杩炲绔啓鍏ヨ繖閲岋級銆?
    recv_buf: Arc<Mutex<Vec<u8>>>,
    /// peer_locator 鈫?瀵圭鐨?recv_buf锛坰end_to 鏃舵寜 locator 鍐欏叆锛夈€?
    links: HashMap<String, Arc<Mutex<Vec<u8>>>>,
    /// 缁戝畾鐨?locator銆?
    local_locator: Mutex<Option<String>>,
}

impl MeshCarrier {
    /// 鍒涘缓绌?MeshCarrier銆?
    #[must_use]
    pub fn new() -> Self {
        Self {
            recv_buf: Arc::new(Mutex::new(Vec::new())),
            links: HashMap::new(),
            local_locator: Mutex::new(None),
        }
    }

    /// 鎶婂绔?locator 杩炲埌瀵圭鐨勬帴鏀剁紦鍐插尯銆?
    pub fn connect_peer(&mut self, peer_locator: &str, peer_recv: Arc<Mutex<Vec<u8>>>) {
        self.links.insert(peer_locator.to_string(), peer_recv);
    }

    /// 鑾峰彇鏈妭鐐规帴鏀剁紦鍐插尯锛堢敤浜庤瀵圭杩炲埌鑷繁锛夈€?
    #[must_use]
    pub fn recv_handle(&self) -> Arc<Mutex<Vec<u8>>> {
        self.recv_buf.clone()
    }

    /// 娉ㄥ叆涓€涓緟鎺ユ敹鐨勫抚锛堟祴璇曠敤锛夈€?
    pub fn inject_recv(&self, data: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.extend_from_slice(data);
    }
}

impl Default for MeshCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketCarrier for MeshCarrier {
    fn bind(&mut self, local_locator: &str) -> Result<String, PlatformError> {
        *self.local_locator.lock().unwrap() = Some(local_locator.to_string());
        Ok(local_locator.to_string())
    }

    fn send_to(&mut self, peer_locator: &str, frame: &[u8]) -> Result<(), PlatformError> {
        let peer_recv =
            self.links
                .get(peer_locator)
                .cloned()
                .ok_or_else(|| PlatformError::Invalid {
                    message: format!("no link to peer locator {peer_locator}"),
                })?;
        let mut buf = peer_recv.lock().unwrap();
        buf.extend_from_slice(frame);
        Ok(())
    }

    fn receive_into(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
        let mut buf = self.recv_buf.lock().unwrap();
        let n = buf.len().min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&buf[..n]);
            buf.drain(..n);
        }
        Ok(n)
    }

    fn local_locator(&self) -> Option<String> {
        self.local_locator.lock().unwrap().clone()
    }
}

// ---------- 娴嬭瘯 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_serialize_deserialize() {
        let header = TunnelFrameHeader {
            src_virtual_ip: "10.0.0.1".to_string(),
            dst_virtual_ip: "10.0.0.2".to_string(),
        };
        let mut frame = header.serialize();
        frame.extend_from_slice(b"hello");

        let (parsed_header, payload) = TunnelFrameHeader::deserialize(&frame).unwrap();
        assert_eq!(parsed_header.src_virtual_ip, "10.0.0.1");
        assert_eq!(parsed_header.dst_virtual_ip, "10.0.0.2");
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn test_subnet_config_validation() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        assert!(config.is_valid_virtual_ip("10.0.0.2"));
        assert!(config.is_valid_virtual_ip("10.0.0.100"));
        assert!(!config.is_valid_virtual_ip("192.168.1.1"));
    }

    #[test]
    fn test_memory_vpi_roundtrip() {
        let mut vpi = MemoryVpi::new();
        vpi.inject_recv(b"test packet");
        let mut buf = [0u8; 1024];
        let n = vpi.receive(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"test packet");
        vpi.send(b"reply packet").unwrap();
        assert_eq!(&vpi.take_sent(), b"reply packet");
    }

    #[test]
    fn test_virtual_subnet_tunnel_basic() {
        // 鑺傜偣 A
        let config_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi_a = Box::new(MemoryVpi::new());
        let carrier_a = Box::new(MemoryCarrier::new());

        let mut tunnel_a = VirtualSubnetTunnel::new(config_a, vpi_a, carrier_a);

        // 鑺傜偣 B 鐨?carrier
        let mut carrier_b = MemoryCarrier::new();
        carrier_b.bind("10.0.0.2:10000").unwrap();

        // 娉ㄥ唽 Peer B
        tunnel_a
            .add_peer(TunnelPeer::new("10.0.0.2", "10.0.0.2:10000"))
            .unwrap();
        tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);

        // 鍙戦€佷竴涓?IP 鍖咃紙鐩殑 IP 10.0.0.2锛?
        let mut ip_packet = vec![0u8; 20];
        ip_packet[16] = 10;
        ip_packet[17] = 0;
        ip_packet[18] = 0;
        ip_packet[19] = 2;
        ip_packet.extend_from_slice(b"hello");

        tunnel_a.send_ip_packet("10.0.0.2", &ip_packet).unwrap();

        // 妫€鏌ョ粺璁?
        let stats = tunnel_a.peer_stats("10.0.0.2").unwrap();
        assert!(stats.bytes_sent > 0);
    }

    #[test]
    fn test_send_to_unknown_peer_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        let packet = vec![0u8; 20];
        let result = tunnel.send_ip_packet("10.0.0.99", &packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_to_disconnected_peer_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "peer:10000"))
            .unwrap();
        // 涓嶈缃?Connected 鐘舵€?

        let packet = vec![0u8; 20];
        let result = tunnel.send_ip_packet("10.0.0.2", &packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_peer_outside_subnet_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        let result = tunnel.add_peer(TunnelPeer::new("192.168.1.2", "peer:10000"));
        assert!(result.is_err());
    }

    // ---------- P1 搂12.5 闈欐€佽矾鐢变笁鑺傜偣杞彂 ----------

    #[test]
    fn test_add_route_rejects_non_peer_next_hop() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        // next_hop 10.0.0.9 鏈敞鍐?鈫?鎷掔粷
        let err = tunnel.add_route("10.0.0.3", "10.0.0.9").unwrap_err();
        assert!(matches!(err, ConnectivityError::Invalid { .. }));
    }

    #[test]
    fn test_send_to_unknown_dst_no_route_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let vpi = Box::new(MemoryVpi::new());
        let carrier = Box::new(MemoryCarrier::new());
        let mut tunnel = VirtualSubnetTunnel::new(config, vpi, carrier);

        let packet = vec![0u8; 20];
        let err = tunnel.send_ip_packet("10.0.0.99", &packet).unwrap_err();
        assert!(matches!(err, ConnectivityError::Invalid { .. }));
    }

    #[test]
    fn test_three_node_mesh_forwarding() {
        // 涓夎妭鐐?A(10.0.0.1) -- B(10.0.0.2) -- C(10.0.0.3)
        // A 鍜?C 涓嶇洿杩烇紱A 鈫?C 缁?B 杞彂
        let mut mesh_a = MeshCarrier::new();
        let mut mesh_b = MeshCarrier::new();
        let mut mesh_c = MeshCarrier::new();

        let a_recv = mesh_a.recv_handle();
        let b_recv = mesh_b.recv_handle();
        let c_recv = mesh_c.recv_handle();

        // A鈫擝 鍙屽悜
        mesh_a.connect_peer("B_locator", b_recv.clone());
        mesh_b.connect_peer("A_locator", a_recv.clone());
        // B鈫擟 鍙屽悜
        mesh_b.connect_peer("C_locator", c_recv.clone());
        mesh_c.connect_peer("B_locator", b_recv.clone());

        // 涓変釜 MemoryVpi
        let vpi_a = Box::new(MemoryVpi::new());
        let vpi_b = Box::new(MemoryVpi::new());
        let vpi_c = Box::new(MemoryVpi::new());

        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let cfg_c = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.3");

        let mut tunnel_a = VirtualSubnetTunnel::new(cfg_a, vpi_a, Box::new(mesh_a));
        let mut tunnel_b = VirtualSubnetTunnel::new(cfg_b, vpi_b, Box::new(mesh_b));
        let mut tunnel_c = VirtualSubnetTunnel::new(cfg_c, vpi_c, Box::new(mesh_c));

        // A 鍙敞鍐?B
        tunnel_a
            .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
            .unwrap();
        tunnel_a.set_peer_state("10.0.0.2", TunnelState::Connected);
        // A 鐨勮矾鐢憋細C 缁?B
        tunnel_a.add_route("10.0.0.3", "10.0.0.2").unwrap();

        // B 娉ㄥ唽 A 鍜?C
        tunnel_b
            .add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))
            .unwrap();
        tunnel_b
            .add_peer(TunnelPeer::new("10.0.0.3", "C_locator"))
            .unwrap();
        tunnel_b.set_peer_state("10.0.0.1", TunnelState::Connected);
        tunnel_b.set_peer_state("10.0.0.3", TunnelState::Connected);
        // B 鐨勮矾鐢辫〃涓虹┖锛圓 鍜?C 閮芥槸鐩磋繛锛?

        // C 鍙敞鍐?B
        tunnel_c
            .add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))
            .unwrap();
        tunnel_c.set_peer_state("10.0.0.2", TunnelState::Connected);

        // 鏋勯€犱竴涓洰鐨勪负 C 鐨?IP 鍖?
        let mut packet = vec![0u8; 20];
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 3;
        packet.extend_from_slice(b"hello-from-a");

        // A 鍙戦€佺粰 C 鈫?璺敱鍒?B
        tunnel_a.send_ip_packet("10.0.0.3", &packet).unwrap();

        // B 鏀跺埌甯?鈫?dst 涓嶆槸 B 鈫?杞彂缁?C
        let mut buf = [0u8; 1024];
        let delivered = tunnel_b.recv_and_deliver(&mut buf, 1000).unwrap();
        assert!(delivered.is_some());
        // B 鐨?bytes_forwarded > 0
        assert!(tunnel_b.peer_stats("10.0.0.3").unwrap().bytes_forwarded > 0);

        // C 鏀跺埌杞彂鍚庣殑甯?鈫?dst == C 鈫?鍐?VPI
        let delivered_c = tunnel_c.recv_and_deliver(&mut buf, 1000).unwrap();
        assert!(delivered_c.is_some());
        // C 瑙ｅ皝瑁呭悗鎷垮埌 payload锛岄暱搴﹀簲绛変簬鍘熷 packet
        assert_eq!(delivered_c.unwrap().1, packet.len());

        // A 涓嶇煡閬?C 鐨?locator
        assert!(tunnel_a.peer_stats("10.0.0.3").is_none());
    }

    #[test]
    fn test_recv_frame_for_unknown_dst_no_route_fails() {
        // B 鏀跺埌涓€涓?dst=10.0.0.9 鐨勫抚锛屼絾 B 鏃笉鐩磋繛 10.0.0.9 涔熸病鏈夎矾鐢?
        let mesh_b = MeshCarrier::new();
        let b_recv = mesh_b.recv_handle();

        let vpi_b = Box::new(MemoryVpi::new());
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let mut tunnel_b = VirtualSubnetTunnel::new(cfg_b, vpi_b, Box::new(mesh_b));
        tunnel_b
            .add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))
            .unwrap();
        tunnel_b.set_peer_state("10.0.0.1", TunnelState::Connected);

        // 浼€犱竴涓抚锛歴rc=10.0.0.1, dst=10.0.0.9
        let fake_frame = b"10.0.0.1->10.0.0.9:hello";
        b_recv.lock().unwrap().extend_from_slice(fake_frame);

        let mut buf = [0u8; 1024];
        let err = tunnel_b.recv_and_deliver(&mut buf, 1000).unwrap_err();
        assert!(matches!(err, ConnectivityError::Invalid { .. }));
    }

    #[test]
    fn test_forward_to_disconnected_next_hop_fails() {
        // B 鏀跺埌 dst=C 鐨勫抚锛屼絾 C peer 鏈?Connected 鈫?杞彂澶辫触
        let mesh_b = MeshCarrier::new();
        let b_recv = mesh_b.recv_handle();

        let vpi_b = Box::new(MemoryVpi::new());
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let mut tunnel_b = VirtualSubnetTunnel::new(cfg_b, vpi_b, Box::new(mesh_b));
        // B 娉ㄥ唽浜?C 浣嗕笉 Connected
        tunnel_b
            .add_peer(TunnelPeer::new("10.0.0.3", "C_locator"))
            .unwrap();

        // 浼€犲抚锛歴rc=A, dst=C
        let fake_frame = b"10.0.0.1->10.0.0.3:hello";
        b_recv.lock().unwrap().extend_from_slice(fake_frame);

        let mut buf = [0u8; 1024];
        let err = tunnel_b.recv_and_deliver(&mut buf, 1000).unwrap_err();
        assert!(matches!(err, ConnectivityError::Invalid { .. }));
    }
    #[test]
    fn encrypted_pair_handshake_and_roundtrip() -> Result<(), ConnectivityError> {
        // 双节点加密：A begin → B 收 INIT accept → A 收 RESP complete → 数据收发。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b"))?;
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a"))?;
        ta.enable_encryption(EncryptionConfig::default());
        tb.enable_encryption(EncryptionConfig::default());
        assert!(ta.is_encryption_enabled());

        // 握手：A 发起
        ta.begin_handshake("10.0.0.2")?;
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Handshaking));
        let mut buf = [0u8; 4096];
        assert!(tb.recv_and_deliver(&mut buf, 1000)?.is_none()); // 握手帧不写 VPI
        assert_eq!(tb.peer_state("10.0.0.1"), Some(TunnelState::Connected));
        assert!(ta.recv_and_deliver(&mut buf, 1000)?.is_none());
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));

        // 数据：A → B
        ta.send_ip_packet("10.0.0.2", b"secret-a-to-b")?;
        let got = tb.recv_and_deliver(&mut buf, 1000)?;
        let (sender, len) = got.expect("data frame delivered");
        assert_eq!(sender, "10.0.0.1");
        assert_eq!(len, b"secret-a-to-b".len());

        // 统计按 wire 密文长度计（> 明文长度）
        assert!(
            ta.peer_stats("10.0.0.2").map(|s| s.bytes_sent).unwrap()
                > b"secret-a-to-b".len() as u64
        );
        assert!(
            tb.peer_stats("10.0.0.1").map(|s| s.bytes_received).unwrap()
                > b"secret-a-to-b".len() as u64
        );
        Ok(())
    }

    #[test]
    fn handshake_source_learning_updates_locator_and_emits_event() -> Result<(), ConnectivityError>
    {
        // NAT 会话回程（P4.1 真机收尾）：B（公网）收到 A（NAT 后）的 INIT 握手帧后，
        // 用 carrier 来源刷新 A 的发送目的地 locator，并发出 PeerLocatorUpdated 事件。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        cb.set_last_source("udp://223.166.166.161:51821"); // A 的 NAT 映射地址
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b"))?;
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a"))?;
        ta.enable_encryption(EncryptionConfig::default());
        tb.enable_encryption(EncryptionConfig::default());

        ta.begin_handshake("10.0.0.2")?;
        let mut buf = [0u8; 4096];
        assert!(tb.recv_and_deliver(&mut buf, 1000)?.is_none()); // 握手帧不写 VPI
        // 来源学习：locator 从占位刷新为 NAT 映射地址，事件可观测。
        assert_eq!(
            tb.peer_locator("10.0.0.1").as_deref(),
            Some("udp://223.166.166.161:51821")
        );
        assert!(tb.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::PeerLocatorUpdated { new_locator, .. }
                if new_locator == "udp://223.166.166.161:51821"
        )));
        Ok(())
    }

    #[test]
    fn handshake_failure_does_not_learn_source() -> Result<(), ConnectivityError> {
        // 防投毒：握手帧解析失败（非法 msg 体）→ recv_and_deliver 返回 Err，
        // 来源学习不生效，locator 保持原值、无 PeerLocatorUpdated 事件。
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (_, cb) = MemoryCarrier::connected_pair();
        cb.set_last_source("udp://223.166.166.161:51821");
        let mut wire = b"hs:10.0.0.1:".to_vec();
        wire.extend_from_slice(&[0u8; 3]); // 非法 HandshakeMessage 体
        cb.inject(&wire);
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(cb));
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a"))?;
        tb.enable_encryption(EncryptionConfig::default());

        let mut buf = [0u8; 4096];
        let err = tb.recv_and_deliver(&mut buf, 1000).unwrap_err();
        assert!(matches!(err, ConnectivityError::Invalid { .. }));
        assert_eq!(tb.peer_locator("10.0.0.1").as_deref(), Some("mem-a"));
        assert!(
            !tb.events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::PeerLocatorUpdated { .. }))
        );
        Ok(())
    }

    #[test]
    fn encrypted_replay_frame_rejected() -> Result<(), ConnectivityError> {
        // 重放同一密文帧 → ReplayWindow 拒绝（REPLAY_REJECTED）。
        let mut mesh_a = MeshCarrier::new();
        let mut mesh_b = MeshCarrier::new();
        let a_recv = mesh_a.recv_handle();
        let b_recv = mesh_b.recv_handle();
        mesh_a.connect_peer("B_locator", b_recv.clone());
        mesh_b.connect_peer("A_locator", a_recv.clone());

        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(mesh_a));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(mesh_b));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "B_locator"))?;
        tb.add_peer(TunnelPeer::new("10.0.0.1", "A_locator"))?;
        ta.enable_encryption(EncryptionConfig::default());
        tb.enable_encryption(EncryptionConfig::default());
        ta.begin_handshake("10.0.0.2")?;
        let mut buf = [0u8; 4096];
        let _ = tb.recv_and_deliver(&mut buf, 1000)?;
        let _ = ta.recv_and_deliver(&mut buf, 1000)?;

        ta.send_ip_packet("10.0.0.2", b"frame-1")?;
        let wire = b_recv.lock().unwrap().clone(); // 密文帧
        assert!(tb.recv_and_deliver(&mut buf, 1000)?.is_some());
        // 重放：注入同一密文
        b_recv.lock().unwrap().extend_from_slice(&wire);
        let err = tb
            .recv_and_deliver(&mut buf, 1000)
            .expect_err("replay must fail");
        assert!(err.to_string().contains("REPLAY_REJECTED"), "got: {err}");
        Ok(())
    }

    #[test]
    fn encrypted_plaintext_mode_regression() -> Result<(), ConnectivityError> {
        // 不开启加密：明文模式语义与 §12.1-§12.5 完全一致。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b"))?;
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a"))?;
        ta.set_peer_state("10.0.0.2", TunnelState::Connected);
        tb.set_peer_state("10.0.0.1", TunnelState::Connected);

        ta.send_ip_packet("10.0.0.2", b"plaintext-ok")?;
        let mut buf = [0u8; 4096];
        let (sender, len) = tb.recv_and_deliver(&mut buf, 1000)?.expect("delivered");
        assert_eq!(sender, "10.0.0.1");
        assert_eq!(len, b"plaintext-ok".len());
        assert!(!ta.is_encryption_enabled());
        Ok(())
    }

    #[test]
    fn test_nat_probe_success_updates_locator_and_routes_direct() {
        // A probes B: initial locator is relay; after successful hole punch the
        // data plane must switch to the dynamically learned direct locator.
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let mut carrier = MeshCarrier::new();
        let direct_buf = Arc::new(Mutex::new(Vec::new()));
        let relay_buf = Arc::new(Mutex::new(Vec::new()));
        carrier.connect_peer("udp://203.0.113.1:5000", direct_buf.clone());
        carrier.connect_peer("relay://relay.example.org:443", relay_buf.clone());
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "relay://relay.example.org:443"))
            .unwrap();

        tunnel.probe_peer("10.0.0.2").unwrap();
        assert_eq!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Probing));
        // Probing is not yet usable for data-plane send.
        assert!(tunnel.send_ip_packet("10.0.0.2", b"early").is_err());

        tunnel
            .apply_hole_punch("10.0.0.2", "udp://203.0.113.1:5000")
            .unwrap();
        assert_eq!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert_eq!(
            tunnel.peer_locator("10.0.0.2").as_deref(),
            Some("udp://203.0.113.1:5000")
        );

        tunnel.send_ip_packet("10.0.0.2", b"ping-direct").unwrap();
        let direct = direct_buf.lock().unwrap().clone();
        let relay = relay_buf.lock().unwrap().clone();
        assert!(!direct.is_empty());
        assert!(relay.is_empty());

        let events = tunnel.events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::ProbeStarted { .. }))
        );
        assert!(events
            .iter()
            .any(|e| matches!(e, VirtualSubnetEvent::PeerLocatorUpdated { new_locator, .. } if new_locator == "udp://203.0.113.1:5000")));
    }

    #[test]
    fn test_nat_probe_failure_falls_back_to_relay() {
        // A probes B with an initial direct locator; punch fails and the tunnel
        // falls back to the relay locator: data plane must route via relay.
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let mut carrier = MeshCarrier::new();
        let direct_buf = Arc::new(Mutex::new(Vec::new()));
        let relay_buf = Arc::new(Mutex::new(Vec::new()));
        carrier.connect_peer("udp://203.0.113.1:5000", direct_buf.clone());
        carrier.connect_peer("relay://relay.example.org:443", relay_buf.clone());
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "udp://203.0.113.1:5000"))
            .unwrap();

        tunnel.probe_peer("10.0.0.2").unwrap();
        assert_eq!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Probing));

        tunnel
            .fallback_to_relay("10.0.0.2", "relay://relay.example.org:443")
            .unwrap();
        assert_eq!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert_eq!(
            tunnel.peer_locator("10.0.0.2").as_deref(),
            Some("relay://relay.example.org:443")
        );

        tunnel.send_ip_packet("10.0.0.2", b"ping-relay").unwrap();
        let direct = direct_buf.lock().unwrap().clone();
        let relay = relay_buf.lock().unwrap().clone();
        assert!(relay.len() > direct.len());

        assert!(tunnel
            .events()
            .iter()
            .any(|e| matches!(e, VirtualSubnetEvent::RelayFallback { relay_locator, .. } if relay_locator == "relay://relay.example.org:443")));
    }

    #[test]
    fn test_nat_probe_unknown_peer_fails() {
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let mut tunnel = VirtualSubnetTunnel::new(
            config,
            Box::new(MemoryVpi::new()),
            Box::new(MeshCarrier::new()),
        );
        let err = tunnel.probe_peer("10.0.0.99").unwrap_err();
        assert!(err.to_string().contains("PEER_NOT_FOUND"));
        assert!(
            tunnel
                .apply_hole_punch("10.0.0.99", "udp://1.1.1.1:1")
                .is_err()
        );
        assert!(
            tunnel
                .fallback_to_relay("10.0.0.99", "relay://r:1")
                .is_err()
        );
    }

    // ---------- P4.2 §12.9.3 tunnel 级双向打洞状态机 ----------

    #[test]
    fn test_hole_punch_success_ph_pa_connects_and_routes() {
        // A 发起打洞 B（target=mem-b）：B 收 ph 自动回 pa + 置 A Connected；
        // A 收 pa 落账（locator=target + Connected）；数据帧 A→B 送达。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        let vpi_b = MemoryVpi::new();
        let vpi_b_sent = vpi_b.sent_handle();
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(vpi_b), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

        ta.begin_hole_punch("10.0.0.2", "mem-b").unwrap();
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Probing));

        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }

        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert_eq!(ta.peer_locator("10.0.0.2").as_deref(), Some("mem-b"));
        // ph 接收方：收到请求即双向可达 → 置对端 Connected
        assert_eq!(tb.peer_state("10.0.0.1"), Some(TunnelState::Connected));

        // 数据帧 A→B 走打洞后 locator 送达（写 B 的 VPI）
        ta.send_ip_packet("10.0.0.2", b"ping").unwrap();
        tb.recv_and_deliver(&mut buf, 1000).unwrap();
        let payload = {
            let mut v = vpi_b_sent.lock().unwrap();
            let p = v.clone();
            v.clear();
            p
        };
        assert_eq!(payload, b"ping");

        // 事件链：HolePunchStarted → HolePunchSucceeded
        assert!(
            ta.events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchStarted { .. }))
        );
        assert!(
            ta.events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchSucceeded { .. }))
        );
    }

    #[test]
    fn test_hole_punch_exhausted_fails_without_relay() {
        // 无监听 target：尝试耗尽 → HolePunchFailed + 无 relay 时 Err(HOLE_PUNCH_FAILED)。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "dead"))
            .unwrap();

        tunnel
            .begin_hole_punch("10.0.0.2", "udp://127.0.0.1:9")
            .unwrap();
        let mut err = None;
        for _ in 0..12 {
            match tunnel.punch_tick("10.0.0.2") {
                Ok(()) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        assert!(err.is_some(), "punch should exhaust and fail");
        assert!(err.unwrap().to_string().contains("HOLE_PUNCH_FAILED"));
        assert!(
            tunnel
                .events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchFailed { .. }))
        );
        assert_ne!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Connected));
    }

    #[test]
    fn test_hole_punch_exhausted_falls_back_to_relay() {
        // 无监听 target + 配置 relay：耗尽 → HolePunchFailed → 自动 fallback（保底）。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "dead"))
            .unwrap();
        tunnel.set_relay_locator("10.0.0.2", "relay://relay.example.org:443");

        tunnel
            .begin_hole_punch("10.0.0.2", "udp://127.0.0.1:9")
            .unwrap();
        for _ in 0..12 {
            match tunnel.punch_tick("10.0.0.2") {
                Ok(()) => {}
                Err(_) => break,
            }
            if tunnel.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
        }

        assert_eq!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert_eq!(
            tunnel.peer_locator("10.0.0.2").as_deref(),
            Some("relay://relay.example.org:443")
        );
        assert!(
            tunnel
                .events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchFailed { .. }))
        );
        assert!(
            tunnel
                .events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::RelayFallback { .. }))
        );
    }

    #[test]
    fn test_hole_punch_frames_not_written_to_vpi() {
        // ph/pa 打洞帧是控制面：不写 VPI（B 收 ph 后 send_buf 为空）。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        let vpi_b = MemoryVpi::new();
        let vpi_b_sent = vpi_b.sent_handle();
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(vpi_b), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

        ta.begin_hole_punch("10.0.0.2", "mem-b").unwrap();
        let mut buf = [0u8; 4096];
        tb.recv_and_deliver(&mut buf, 1000).unwrap(); // B 收 ph → 回 pa（控制面）
        let payload = {
            let mut v = vpi_b_sent.lock().unwrap();
            let p = v.clone();
            v.clear();
            p
        };
        assert!(payload.is_empty(), "punch frames must not reach VPI");

        ta.recv_and_deliver(&mut buf, 1000).unwrap(); // A 收 pa → 落账
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
    }

    // ---------- P4.2 §12.9.3 边界路径（Review R1 WARN 闭合） ----------

    #[test]
    fn test_hole_punch_ph_learns_source_from_carrier() {
        // B 收 ph 时 carrier.last_peer_locator()=Some(公网映射)：
        // B 侧 A locator 更新为来源（NAT 会话回程）+ 回 pa 到来源 → A 落账 Connected。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        cb.set_last_source("udp://203.0.113.1:5000");
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(MemoryVpi::new()), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "initial-a"))
            .unwrap();

        ta.begin_hole_punch("10.0.0.2", "mem-b").unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }

        // B 侧 A 的 locator 动态学习为来源（NAT 回程）
        assert_eq!(
            tb.peer_locator("10.0.0.1").as_deref(),
            Some("udp://203.0.113.1:5000")
        );
        assert_eq!(tb.peer_state("10.0.0.1"), Some(TunnelState::Connected));
        // A 侧落账 + 事件
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert!(tb.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::PeerLocatorUpdated { new_locator, .. }
                if new_locator == "udp://203.0.113.1:5000"
        )));
    }

    #[test]
    fn test_hole_punch_pa_ignored_when_not_probing() {
        // 未发起打洞（无 pending）：收到 pa 确认帧不落账（防伪造成功）。
        let cfg_a = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let (ca, _cb) = MemoryCarrier::connected_pair();
        ca.inject(b"pa:10.0.0.2:NXHP");
        let mut ta = VirtualSubnetTunnel::new(cfg_a, Box::new(MemoryVpi::new()), Box::new(ca));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();

        let mut buf = [0u8; 4096];
        let r = ta.recv_and_deliver(&mut buf, 1000).unwrap();
        assert!(r.is_none(), "unexpected pa must be swallowed");
        assert_ne!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert!(
            !ta.events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchSucceeded { .. }))
        );
    }

    #[test]
    fn test_hole_punch_magic_mismatch_dropped() {
        // magic 错配的打洞帧被丢弃：不回 pa、不置 Connected、不写 VPI。
        let cfg_b = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2");
        let (ca, cb) = MemoryCarrier::connected_pair();
        cb.inject(b"ph:10.0.0.1:BAD!");
        let vpi_b = MemoryVpi::new();
        let vpi_b_sent = vpi_b.sent_handle();
        let mut ta = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
            Box::new(MemoryVpi::new()),
            Box::new(ca),
        );
        let mut tb = VirtualSubnetTunnel::new(cfg_b, Box::new(vpi_b), Box::new(cb));
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

        let mut buf = [0u8; 4096];
        let r = tb.recv_and_deliver(&mut buf, 1000).unwrap();
        assert!(r.is_none(), "bad-magic frame must be dropped");
        assert_eq!(tb.peer_state("10.0.0.1"), Some(TunnelState::Disconnected));
        let payload = {
            let mut v = vpi_b_sent.lock().unwrap();
            let p = v.clone();
            v.clear();
            p
        };
        assert!(payload.is_empty());
        // A 无回包（B 未回 pa）
        let r2 = ta.recv_and_deliver(&mut buf, 1000).unwrap();
        assert!(r2.is_none());
    }

    // ---------- P4.2 §12.9.4 NAT 类型驱动的路径选择 ----------

    #[test]
    fn test_plan_connectivity_direct_continues_hole_punch() {
        // RestrictedCone → Direct plan：可继续 begin_hole_punch（打洞流程不受阻）。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let (ca, cb) = MemoryCarrier::connected_pair();
        let mut ta = VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(ca));
        let mut tb = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb),
        );
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

        let plan = ta
            .plan_connectivity("10.0.0.2", crate::nat::NatType::RestrictedCone, "mem-b")
            .unwrap();
        assert_eq!(
            plan,
            ConnectivityPlan::Direct {
                target: "mem-b".to_string()
            }
        );
        assert!(ta.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::PathDecided {
                peer_vip,
                nat_type,
                decision,
                ..
            } if peer_vip == "10.0.0.2"
                && *nat_type == crate::nat::NatType::RestrictedCone
                && *decision == crate::nat::PathDecision::Direct
        )));

        // Direct plan 后可继续打洞：完整 ph→pa→Connected
        ta.begin_hole_punch("10.0.0.2", "mem-b").unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
    }

    #[test]
    fn test_plan_connectivity_relay_with_configured_locator() {
        // Symmetric → Relay plan：直达 relay，不发起打洞。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "dead"))
            .unwrap();
        tunnel.set_relay_locator("10.0.0.2", "relay://relay.example.org:443");

        let plan = tunnel
            .plan_connectivity(
                "10.0.0.2",
                crate::nat::NatType::Symmetric,
                "udp://127.0.0.1:9",
            )
            .unwrap();
        assert_eq!(
            plan,
            ConnectivityPlan::Relay {
                locator: "relay://relay.example.org:443".to_string()
            }
        );
        assert!(tunnel.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::PathDecided {
                peer_vip,
                nat_type,
                decision,
                ..
            } if peer_vip == "10.0.0.2"
                && *nat_type == crate::nat::NatType::Symmetric
                && *decision == crate::nat::PathDecision::Relay
        )));
        // Symmetric 路径不发打洞帧（无 HolePunchStarted）
        assert!(
            !tunnel
                .events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchStarted { .. }))
        );
    }

    #[test]
    fn test_plan_connectivity_relay_without_locator_errors() {
        // Symmetric + 无 relay 配置 → Err(RELAY_NOT_CONFIGURED)。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "dead"))
            .unwrap();

        let err = tunnel
            .plan_connectivity(
                "10.0.0.2",
                crate::nat::NatType::Symmetric,
                "udp://127.0.0.1:9",
            )
            .unwrap_err();
        assert!(err.to_string().contains("RELAY_NOT_CONFIGURED"));
        // PathDecided 事件仍已发出（决策本身可观测；Err 路径先发事件后返回）
        assert!(tunnel.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::PathDecided {
                peer_vip,
                nat_type,
                decision,
                ..
            } if peer_vip == "10.0.0.2"
                && *nat_type == crate::nat::NatType::Symmetric
                && *decision == crate::nat::PathDecision::Relay
        )));
    }

    #[test]
    fn test_plan_connectivity_unknown_peer_rejected() {
        // 未注册 peer → PEER_NOT_FOUND。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        let err = tunnel
            .plan_connectivity("10.0.0.99", crate::nat::NatType::FullCone, "x")
            .unwrap_err();
        assert!(err.to_string().contains("PEER_NOT_FOUND"));
    }

    // ---------- P4.2 §12.9.5 多候选并发打洞 ----------

    #[test]
    fn test_begin_hole_punch_multi_success_first_ack_wins() {
        // 多候选 [dead, mem-b]：B 按来源回 pa（mem-b 为可达候选），
        // A 落账 Connected，HolePunchSucceeded{target="mem-b"}（先到先用）。
        let (ca, cb) = MemoryCarrier::connected_pair();
        ca.set_last_source("mem-b");
        cb.set_last_source("mem-b");
        let mut ta = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
            Box::new(MemoryVpi::new()),
            Box::new(ca),
        );
        let mut tb = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb),
        );
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

        ta.begin_hole_punch_multi(
            "10.0.0.2",
            &["udp://127.0.0.1:9".to_string(), "mem-b".to_string()],
        )
        .unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert!(ta.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::HolePunchSucceeded { target, .. } if target == "mem-b"
        )));
        // WARN-5：HolePunchStarted 携带候选列表。
        assert!(ta.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::HolePunchStarted { targets, .. }
                if targets == &["udp://127.0.0.1:9".to_string(), "mem-b".to_string()]
        )));
    }

    #[test]
    fn test_begin_hole_punch_multi_all_dead_falls_back_to_relay() {
        // 多候选全失败 + relay 配置：punch_tick 耗尽 → HolePunchFailed +
        // RelayFallback → Connected（relay 保底）。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "dead"))
            .unwrap();
        tunnel.set_relay_locator("10.0.0.2", "relay://relay.example.org:443");

        tunnel
            .begin_hole_punch_multi(
                "10.0.0.2",
                &[
                    "udp://127.0.0.1:9001".to_string(),
                    "udp://127.0.0.1:9002".to_string(),
                ],
            )
            .unwrap();
        for _ in 0..=10 {
            match tunnel.punch_tick("10.0.0.2") {
                Ok(()) => {
                    if tunnel.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert_eq!(tunnel.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert!(
            tunnel
                .events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::HolePunchFailed { .. }))
        );
        assert!(
            tunnel
                .events()
                .iter()
                .any(|e| matches!(e, VirtualSubnetEvent::RelayFallback { .. }))
        );
    }

    #[test]
    fn test_begin_hole_punch_multi_single_target_compatible() {
        // 单候选兼容：targets=[mem-b] 等价 begin_hole_punch。
        let (ca, cb) = MemoryCarrier::connected_pair();
        let mut ta = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
            Box::new(MemoryVpi::new()),
            Box::new(ca),
        );
        let mut tb = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb),
        );
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();

        ta.begin_hole_punch_multi("10.0.0.2", &["mem-b".to_string()])
            .unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
    }

    #[test]
    fn test_begin_hole_punch_multi_empty_targets_rejected() {
        // 空候选列表 → HOLE_PUNCH_EMPTY_TARGETS（结构化 Err）。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        tunnel
            .add_peer(TunnelPeer::new("10.0.0.2", "dead"))
            .unwrap();
        let err = tunnel.begin_hole_punch_multi("10.0.0.2", &[]).unwrap_err();
        assert!(err.to_string().contains("HOLE_PUNCH_EMPTY_TARGETS"));
    }

    #[test]
    fn test_begin_hole_punch_multi_unknown_peer_rejected() {
        // 未注册 peer → PEER_NOT_FOUND。
        let config = VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1");
        let carrier = MemoryCarrier::new();
        let mut tunnel =
            VirtualSubnetTunnel::new(config, Box::new(MemoryVpi::new()), Box::new(carrier));
        let err = tunnel
            .begin_hole_punch_multi("10.0.0.99", &["x".to_string()])
            .unwrap_err();
        assert!(err.to_string().contains("PEER_NOT_FOUND"));
    }

    #[test]
    fn test_hole_punch_multi_second_pa_after_connected_is_ignored() {
        // WARN-3：multi 落账 Connected 后，迟到 pa 幂等忽略（Succeeded 不重复）。
        let (ca, cb) = MemoryCarrier::connected_pair();
        ca.set_last_source("mem-b");
        cb.set_last_source("mem-b");
        let mut ta = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
            Box::new(MemoryVpi::new()),
            Box::new(ca),
        );
        let mut tb = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb),
        );
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();
        ta.begin_hole_punch_multi(
            "10.0.0.2",
            &["udp://127.0.0.1:9".to_string(), "mem-b".to_string()],
        )
        .unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        let succeeded_before = ta
            .events()
            .iter()
            .filter(|e| matches!(e, VirtualSubnetEvent::HolePunchSucceeded { .. }))
            .count();
        // 迟到 pa（sender = 对端 vip）：非 Probing → 守卫拒绝，幂等忽略。
        // B 侧 carrier 直发（B.send_buf 与 A.recv_buf 共享）。
        let late_pa = hole_punch_frame(b'a', "10.0.0.2", &ta.hole_punch_config.magic);
        tb.carrier.send_to("mem-a", &late_pa).unwrap();
        ta.recv_and_deliver(&mut buf, 1000).unwrap();
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        let succeeded_after = ta
            .events()
            .iter()
            .filter(|e| matches!(e, VirtualSubnetEvent::HolePunchSucceeded { .. }))
            .count();
        assert_eq!(
            succeeded_before, succeeded_after,
            "second pa after Connected must be idempotently ignored"
        );
    }

    #[test]
    fn test_hole_punch_multi_pa_without_source_falls_back_to_first_target() {
        // WARN-4：pa 无来源（last_source=None）→ 兜底 targets.first() 落账。
        let (ca, cb) = MemoryCarrier::connected_pair(); // 不 set_last_source
        let mut ta = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.1"),
            Box::new(MemoryVpi::new()),
            Box::new(ca),
        );
        let mut tb = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb),
        );
        ta.add_peer(TunnelPeer::new("10.0.0.2", "mem-b")).unwrap();
        tb.add_peer(TunnelPeer::new("10.0.0.1", "mem-a")).unwrap();
        ta.begin_hole_punch_multi("10.0.0.2", &["dead-first".to_string(), "mem-b".to_string()])
            .unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..10 {
            tb.recv_and_deliver(&mut buf, 1000).unwrap();
            ta.recv_and_deliver(&mut buf, 1000).unwrap();
            if ta.peer_state("10.0.0.2") == Some(TunnelState::Connected) {
                break;
            }
            ta.punch_tick("10.0.0.2").unwrap();
        }
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));
        assert!(ta.events().iter().any(|e| matches!(
            e,
            VirtualSubnetEvent::HolePunchSucceeded { target, .. } if target == "dead-first"
        )));
    }

    /// 记录入站、可回包的最小 BootstrapHook 测试桩（经 shared 句柄回读）。
    #[derive(Default)]
    struct RecHook {
        seen: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        reply: Option<(String, Vec<u8>)>,
    }
    impl BootstrapHook for RecHook {
        fn on_control_datagram(
            &mut self,
            _src: Option<&str>,
            payload: &[u8],
            _now: u64,
        ) -> Option<(String, Vec<u8>)> {
            self.seen.lock().unwrap().push(payload.to_vec());
            self.reply.take()
        }
        fn periodic(&mut self, _now: u64) -> BootstrapTick {
            BootstrapTick::default()
        }
    }

    #[test]
    fn nxb_magic_vs_data_frame_demux() -> Result<(), ConnectivityError> {
        // nxb: 前缀帧在隧道入口即被 bootstrap hook 截获：剥 magic、不写 VPI、不进数据管线；
        // 无 nxb 前缀的数据帧不路由到 hook。
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut buf = [0u8; 4096];

        // 隧道1：注入 nxb: + 内层 body（在构造前入队）。
        let (_, cb) = MemoryCarrier::connected_pair();
        let mut wire = b"nxb:".to_vec();
        wire.extend_from_slice(b"\x10hello-body");
        cb.inject(&wire);
        let mut tb = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb),
        );
        tb.set_bootstrap_hook(Some(Box::new(RecHook {
            seen: seen.clone(),
            reply: None,
        })));
        let delivered = tb.recv_and_deliver(&mut buf, 1000)?;
        assert!(delivered.is_none()); // 控制帧不交付数据面
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(&seen.lock().unwrap()[0][..], b"\x10hello-body");

        // 隧道2：注入普通数据帧（无 nxb 前缀）→ hook 不应被调用。
        seen.lock().unwrap().clear();
        let (_, cb2) = MemoryCarrier::connected_pair();
        cb2.inject(b"plain-data-frame");
        let mut tb2 = VirtualSubnetTunnel::new(
            VirtualSubnetConfig::new("10.0.0.0/24", "10.0.0.2"),
            Box::new(MemoryVpi::new()),
            Box::new(cb2),
        );
        tb2.set_bootstrap_hook(Some(Box::new(RecHook {
            seen: seen.clone(),
            reply: None,
        })));
        // 普通数据帧走原数据路径（可能因非法头返回 Err），但绝不应路由到 bootstrap hook。
        let _ = tb2.recv_and_deliver(&mut buf, 1000);
        assert!(seen.lock().unwrap().is_empty());
        Ok(())
    }
}
