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
use crate::encryption::{
    DirectionalKeys, EncryptionConfig, EncryptionError, HANDSHAKE_INIT, HANDSHAKE_RESP,
    HandshakeMessage, KeyPair, ReplayWindow, decrypt_frame, encrypt_frame,
};

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
        let text = std::str::from_utf8(data).ok()?;
        let colon_pos = text.find(':')?;
        let header_part = &text[..colon_pos];
        let mut parts = header_part.split("->");
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
    /// 握手进行中（发起方视角）：对端虚拟 IP -> 待消费本端密钥。
    pending_handshakes: HashMap<String, KeyPair>,
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
        }
    }

    /// 娉ㄥ唽闈欐€佽矾鐢憋紙P1 搂12.5锛夈€俷ext_hop 蹇呴』鏄凡娉ㄥ唽 peer銆?
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

    /// 统一转发决策（P2-5 §12.14）：① 直连 peer → ② 精确 routes → ③ 最长前缀
    /// prefix_routes → ④ 出口节点（egress 顺序第一个）→ ⑤ `NO_ROUTE_TO_DST`。
    fn resolve_next_hop(&self, dst: &str) -> Result<String, ConnectivityError> {
        if self.peers.contains_key(dst) {
            return Ok(dst.to_string());
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
        let (_peer_id, locator, _state, _stats) =
            self.peers
                .get(peer_virtual_ip)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("PEER_NOT_FOUND: {peer_virtual_ip}"),
                })?;
        let locator = locator.clone();
        let keypair = KeyPair::generate().map_err(encryption_err)?;
        let msg = HandshakeMessage {
            msg_type: HANDSHAKE_INIT,
            public_key: *keypair.public_key_bytes(),
        };
        let wire = handshake_wire(&self.config.virtual_ip, &msg);
        self.carrier
            .send_to(&locator, &wire)
            .map_err(|e| ConnectivityError::Io {
                operation: "handshake_send".to_string(),
                message: e.to_string(),
            })?;
        self.pending_handshakes
            .insert(peer_virtual_ip.to_string(), keypair);
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
        let (_peer_id, locator, _state, _stats) =
            self.peers
                .get(peer_virtual_ip)
                .ok_or_else(|| ConnectivityError::Invalid {
                    message: format!("PEER_NOT_FOUND: {peer_virtual_ip}"),
                })?;
        let locator = locator.clone();
        let keypair = KeyPair::generate().map_err(encryption_err)?;
        let (resp, keys) = keypair.handshake_respond(msg).map_err(encryption_err)?;
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
        let keypair = self
            .pending_handshakes
            .remove(peer_virtual_ip)
            .ok_or_else(|| ConnectivityError::Invalid {
                message: format!("HANDSHAKE_IN_PROGRESS: no pending init for {peer_virtual_ip}"),
            })?;
        let keys = keypair
            .derive_directional(&resp.public_key, true)
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
        let next_hop = self.resolve_next_hop(dst_virtual_ip)?;

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
        let next_hop = self.resolve_next_hop(&header.dst_virtual_ip)?;

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
    let mut out = Vec::with_capacity(3 + peer_virtual_ip.len() + 1 + 33);
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
    send_buf: Arc<Mutex<Vec<u8>>>,
    /// 鎺ユ敹缂撳啿鍖猴紙瀵圭鍙戦€侊紝鏈妭鐐规帴鏀讹級鈥斺€斾笌瀵圭鐨?send_buf 鍏变韩銆?
    recv_buf: Arc<Mutex<Vec<u8>>>,
    /// 缁戝畾鐨?locator銆?
    local_locator: Mutex<Option<String>>,
}

impl MemoryCarrier {
    /// 鍒涘缓绌虹殑 MemoryCarrier锛堢嫭绔嬬紦鍐插尯锛屼笉涓庝换浣曞绔繛鎺ワ級銆?
    #[must_use]
    pub fn new() -> Self {
        Self {
            send_buf: Arc::new(Mutex::new(Vec::new())),
            recv_buf: Arc::new(Mutex::new(Vec::new())),
            local_locator: Mutex::new(None),
        }
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
            local_locator: Mutex::new(None),
        };
        let b = Self {
            send_buf: b_send.clone(),
            recv_buf: a_send.clone(),
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
        recv.extend_from_slice(&send);
    }

    /// 娉ㄥ叆涓€涓緟鎺ユ敹鐨勫抚銆?
    pub fn inject_recv(&self, data: &[u8]) {
        let mut buf = self.recv_buf.lock().unwrap();
        buf.extend_from_slice(data);
    }
}

impl PacketCarrier for MemoryCarrier {
    fn bind(&mut self, local_locator: &str) -> Result<String, PlatformError> {
        *self.local_locator.lock().unwrap() = Some(local_locator.to_string());
        Ok(local_locator.to_string())
    }

    fn send_to(&mut self, _peer_locator: &str, frame: &[u8]) -> Result<(), PlatformError> {
        let mut buf = self.send_buf.lock().unwrap();
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

impl Default for MemoryCarrier {
    fn default() -> Self {
        Self::new()
    }
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
        let delivered = tunnel_b.recv_and_deliver(&mut buf).unwrap();
        assert!(delivered.is_some());
        // B 鐨?bytes_forwarded > 0
        assert!(tunnel_b.peer_stats("10.0.0.3").unwrap().bytes_forwarded > 0);

        // C 鏀跺埌杞彂鍚庣殑甯?鈫?dst == C 鈫?鍐?VPI
        let delivered_c = tunnel_c.recv_and_deliver(&mut buf).unwrap();
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
        let err = tunnel_b.recv_and_deliver(&mut buf).unwrap_err();
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
        let err = tunnel_b.recv_and_deliver(&mut buf).unwrap_err();
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
        assert!(tb.recv_and_deliver(&mut buf)?.is_none()); // 握手帧不写 VPI
        assert_eq!(tb.peer_state("10.0.0.1"), Some(TunnelState::Connected));
        assert!(ta.recv_and_deliver(&mut buf)?.is_none());
        assert_eq!(ta.peer_state("10.0.0.2"), Some(TunnelState::Connected));

        // 数据：A → B
        ta.send_ip_packet("10.0.0.2", b"secret-a-to-b")?;
        let got = tb.recv_and_deliver(&mut buf)?;
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
        let _ = tb.recv_and_deliver(&mut buf)?;
        let _ = ta.recv_and_deliver(&mut buf)?;

        ta.send_ip_packet("10.0.0.2", b"frame-1")?;
        let wire = b_recv.lock().unwrap().clone(); // 密文帧
        assert!(tb.recv_and_deliver(&mut buf)?.is_some());
        // 重放：注入同一密文
        b_recv.lock().unwrap().extend_from_slice(&wire);
        let err = tb.recv_and_deliver(&mut buf).expect_err("replay must fail");
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
        let (sender, len) = tb.recv_and_deliver(&mut buf)?.expect("delivered");
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
}
