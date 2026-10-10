//! Bootstrap 自动入网——服务端纯逻辑与 codec 解耦边界（v2 §5.5/§6）。
//!
//! **架构红线**：本模块位于 `nexus-connectivity`，**绝不直接命名/依赖**
//! `nexus-discovery` 的帧类型（见 `fib_resolver.rs`：connectivity 不能依赖
//! discovery）。外层 `nxb:` 握手帧与内层 `AutoDiscoveryFrame` 的字节编解码全部
//! 抽象为 [`BootstrapFrameCodec`] trait，具体实现在 `apps/nexus` 组合根注入——
//! 与 `FibResolver`（`virtual_subnet.rs`）完全同构。
//!
//! 服务端：PSK 会话认证（认证时点不对称，M2）、权威 node_id 派生（S2）、
//! VIP 权威分配（§5.4）、在线目录复用 [`Coordinator`]、半开有界防护（S3）。
//! 全部同步、无 tokio、无真实 I/O；时钟由 `now_secs` 注入（不用 `Instant`）。

use std::collections::HashMap;

use rand::RngCore;

use crate::coord::{CoordError, Coordinator, VirtualIpAllocator, peer_id_from_public_key};
use crate::encryption::{
    DirectionalKeys, EncryptionError, KeyPair, ReplayWindow, decrypt_frame,
    derive_authed_keys_with_psk, encrypt_frame,
};

/// 外层 magic（`nxb:` 的 ASCII 字节；与 discovery `NXB_MAGIC` 同值，此处独立固化
/// 以保持 connectivity 不依赖 discovery——首字节 `0x6E`，与数据面各类帧互斥）。
const NXB_MAGIC: &[u8] = b"nxb:";

/// 服务端自身在目录/VIP 表中的占位 owner（与普通 node_id 命名空间分开，§5.4）。
const SELF_NODE_ID: &str = "__bootstrap_self__";

// ---- 半开防护参数（v2 §5.7） ----
/// 全局 pending 上限。
const MAX_PENDING_GLOBAL: usize = 1024;
/// 每 src JoinInit 速率上限。
const RATE_PER_WINDOW: usize = 10;
/// 速率统计窗口（秒）。
const RATE_WINDOW_SECS: u64 = 60;
/// pending 握手 TTL（秒）；到期未完成首帧 AEAD 即摘除，并在孤儿检查通过后回收其预分配 VIP（§5.7 / F-01）。
const PENDING_TTL_SECS: u64 = 10;

/// Bootstrap 外层错误码（与 discovery `BootstrapErrorCode` 同值，codec 负责映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootstrapOuterCode {
    /// PSK 认证失败。
    AuthFailed = 1,
    /// 申请 VIP 不合法 / 不在 CIDR。
    BadVip = 2,
    /// VIP 冲突。
    VipConflict = 3,
    /// 对端未开启 bootstrap 服务端角色。
    NotBootstrap = 4,
    /// 半开/速率触顶。
    RateLimited = 5,
    /// 控制帧格式损坏。
    MalformedFrame = 6,
}

/// 与 discovery 帧解耦的一个 bootstrap 在线 peer（仅 bootstrap 所需子集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// 权威 node_id（由握手 static 公钥派生，非客户端自报）。
    pub node_id: String,
    /// 服务端权威分配的虚拟 IP。
    pub virtual_ip: String,
    /// NAT 源 locator（目录以此为准，忽略自报值）。
    pub locator: String,
}

/// 与 discovery `AutoDiscoveryFrame` 解耦的 bootstrap 控制消息子集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapCtrl {
    /// C -> S：注册/刷新本节点（帧内 node_id 仅作显示，服务端以权威派生值为准）。
    Register {
        /// 客户端自报 node_id（日志用；权威值由 static 公钥派生）。
        node_id: String,
        /// 客户端申请/确认的 VIP。
        virtual_ip: String,
        /// 客户端自报 locator（仅日志；目录以 NAT 源为准）。
        locator: String,
    },
    /// S -> C：注册结果确认。
    RegisterAck {
        /// 是否被接受。
        accepted: bool,
        /// 服务端认可的租约秒数。
        ttl_secs: u32,
    },
    /// C -> S：拉取在线 peer 列表。
    GetPeers {
        /// 发起方 node_id（被 exclude）。
        node_id: String,
    },
    /// S -> C：在线 peer 列表（含服务端自身，exclude 发起方）。
    PeerList {
        /// 在线 peers。
        peers: Vec<BootstrapPeer>,
    },
    /// C -> S：心跳保活。
    Heartbeat {
        /// 发起方 node_id。
        node_id: String,
        now: u64,
    },
}

/// 与 discovery 帧解耦的 JoinInit 请求字段（外层明文握手）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinInitReq {
    /// 客户端临时 ephemeral 公钥（32B）。
    pub eph_pub: [u8; 32],
    /// 客户端持久 static 公钥（32B；权威 node_id 派生来源）。
    pub static_pub: [u8; 32],
    /// VIP 申请值；`None` = 请服务端权威分配。
    pub requested_vip: Option<String>,
    /// 客户端随机 nonce（与 server_nonce 绑定进 AEAD 明文前缀，M3）。
    pub client_nonce: u64,
}

/// 与 discovery 帧解耦的 JoinReply 应答字段（外层明文握手）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinReplyResp {
    /// 服务端临时 ephemeral 公钥（32B）。
    pub eph_pub: [u8; 32],
    /// 服务端持久 static 公钥（32B）。
    pub static_pub: [u8; 32],
    /// 服务端权威确认的 VIP。
    pub assigned_vip: String,
    /// 注册租约秒数。
    pub lease_secs: u32,
    /// 心跳间隔毫秒。
    pub hb_interval_ms: u32,
    /// PeerList 刷新间隔毫秒。
    pub refresh_interval_ms: u32,
    /// 服务端随机 nonce。
    pub server_nonce: u64,
}

/// 剥掉 `nxb:` magic 后的外层判别（codec 实现）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OuterKind<'a> {
    /// 已认证会话密文：交会话 `decrypt_frame` + `ReplayWindow`。
    Secured(&'a [u8]),
    /// 明文 JoinInit。
    JoinInit(JoinInitReq),
    /// 其它明文（Error / 未知）：服务端不处理，丢弃。
    OtherPlain,
}

/// Bootstrap 服务端结构化错误（typed Result，禁止 panic 表示业务失败）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootstrapServerError {
    /// PSK 认证失败。
    AuthFailed,
    /// 申请 VIP 不合法 / 不在 CIDR。
    BadVip(String),
    /// VIP 冲突。
    VipConflict(String),
    /// 控制帧格式损坏。
    Malformed(String),
    /// 半开/速率触顶。
    RateLimited,
    /// 底层 Coordinator / VIP 分配错误。
    Coord(CoordError),
    /// 底层 AEAD / 防重放错误。
    Crypto(EncryptionError),
}

impl core::fmt::Display for BootstrapServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthFailed => write!(f, "BOOTSTRAP_AUTH_FAILED"),
            Self::BadVip(s) => write!(f, "BOOTSTRAP_BAD_VIP: {s}"),
            Self::VipConflict(s) => write!(f, "BOOTSTRAP_VIP_CONFLICT: {s}"),
            Self::Malformed(s) => write!(f, "BOOTSTRAP_MALFORMED: {s}"),
            Self::RateLimited => write!(f, "BOOTSTRAP_RATE_LIMITED"),
            Self::Coord(e) => write!(f, "BOOTSTRAP_COORD: {e}"),
            Self::Crypto(e) => write!(f, "BOOTSTRAP_CRYPTO: {e}"),
        }
    }
}

impl std::error::Error for BootstrapServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coord(e) => Some(e),
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CoordError> for BootstrapServerError {
    fn from(e: CoordError) -> Self {
        Self::Coord(e)
    }
}

impl From<EncryptionError> for BootstrapServerError {
    fn from(e: EncryptionError) -> Self {
        Self::Crypto(e)
    }
}

/// 由 `apps/nexus` 组合根实现：外层握手帧 + 内层控制帧 <-> discovery 字节。
///
/// connectivity 不依赖 discovery，故所有字节编解码抽象为 trait；具体实现内部调用
/// `nexus_discovery::bootstrap_join` 与 `encode/decode_auto_frame`。
pub trait BootstrapFrameCodec {
    /// 把一条 bootstrap 控制消息编码为内层字节（随后会被 AEAD 加密）。
    fn encode(&self, f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError>;
    /// 把一段内层明文（AEAD 解密之后）解码为 bootstrap 控制消息。
    fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError>;
    /// 解码外层明文 JoinInit（payload 已剥掉 `nxb:` magic）。
    fn decode_join_init(&self, payload: &[u8]) -> Result<JoinInitReq, BootstrapServerError>;
    /// 编码外层明文 JoinReply（不含 magic；上线路径由服务端前置 magic）。
    fn encode_join_reply(&self, r: &JoinReplyResp) -> Result<Vec<u8>, BootstrapServerError>;
    /// 编码外层明文 Error。
    fn encode_error(
        &self,
        code: BootstrapOuterCode,
        message: &str,
    ) -> Result<Vec<u8>, BootstrapServerError>;
    /// 判别外层 payload（已剥 magic）：Secured 密文 / JoinInit / 其它。
    fn split_outer<'a>(&self, payload: &'a [u8]) -> Result<OuterKind<'a>, BootstrapServerError>;
    /// 编码外层明文 JoinInit（客户端上行；不含 magic）。客户端方向，与 `decode_join_init` 互逆。
    fn encode_join_init(&self, req: &JoinInitReq) -> Result<Vec<u8>, BootstrapServerError>;
    /// 解码外层明文 JoinReply（客户端下行；payload 已剥 magic）。与 `encode_join_reply` 互逆。
    fn decode_join_reply(&self, body: &[u8]) -> Result<JoinReplyResp, BootstrapServerError>;
}

/// Bootstrap 服务端配置。
#[derive(Debug, Clone)]
pub struct BootstrapServerConfig {
    /// 子网 CIDR（VIP 权威分配范围；`allocate_specific` 不校验 CIDR，服务端自补）。
    pub cidr: String,
    /// 注册租约秒数（建议 3×心跳间隔）。
    pub lease_secs: u32,
    /// 心跳间隔毫秒。
    pub hb_interval_ms: u32,
    /// PeerList 刷新间隔毫秒。
    pub refresh_interval_ms: u32,
    /// 服务端自身 VIP（启动先占位，§5.4）。
    pub server_vip: String,
    /// 服务端对外可达 locator（目录第 0 条）。
    pub server_locator: String,
    /// 每 src 半开上限（§5.7）。
    pub max_pending_per_src: usize,
}

/// 已认证会话（服务端视角；keys.rx 收、keys.tx 发）。
struct EstablishedSession {
    keys: DirectionalKeys,
    replay: ReplayWindow,
    /// 权威 node_id（由握手 static 公钥派生，非自报，S2）。
    node_id: String,
    client_nonce: u64,
    server_nonce: u64,
    tx_seq: u64,
}

/// 半开握手（未完成首帧 AEAD 认证）。
#[derive(Clone)]
struct PendingHandshake {
    server_eph: KeyPair,
    peer_static: [u8; 32],
    peer_eph: [u8; 32],
    client_nonce: u64,
    server_nonce: u64,
    created_at: u64,
    /// 权威 node_id（预分配 VIP 的 owner key，淘汰时据此回收）。
    auth_id: String,
}

/// `sweep_expired` 报告（崩溃可收敛，M8）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// 过期摘除的 peer 名称。
    pub expired: Vec<String>,
    /// 随之回收 VIP 的 peer。
    pub released_vips: Vec<String>,
}

/// Bootstrap 自动入网服务端（纯逻辑、无 I/O、注入时钟）。
pub struct BootstrapServer {
    identity: KeyPair,
    psk: Vec<u8>,
    /// 在线目录（TTL）。
    presence: Coordinator,
    /// VIP 权威分配器。
    vip: VirtualIpAllocator,
    /// 已认证会话：src locator -> session。
    established: HashMap<String, EstablishedSession>,
    /// 半开握手：src locator -> pending 列表（每 src 有界）。
    pending: HashMap<String, Vec<PendingHandshake>>,
    /// 每 src JoinInit 速率窗口（时间戳列表）。
    rate: HashMap<String, Vec<u64>>,
    cfg: BootstrapServerConfig,
    codec: Box<dyn BootstrapFrameCodec + Send>,
}

impl BootstrapServer {
    /// 创建服务端；`persisted` 为重启恢复的 (node_id, vip) 租约。
    pub fn new(
        identity: KeyPair,
        psk: Vec<u8>,
        cfg: BootstrapServerConfig,
        codec: Box<dyn BootstrapFrameCodec + Send>,
        persisted: Option<Vec<(String, String)>>,
    ) -> Result<Self, BootstrapServerError> {
        let mut vip = VirtualIpAllocator::new(&cfg.cidr)?;
        // M5：开放分配前先占位服务端自身 VIP（否则首个客户端会与服务端撞号）。
        // G-05：占位前先过网内/网络/广播自校验，与客户端 requested_vip 同一道闸。
        vip.check_vip(&cfg.server_vip)
            .map_err(|e| BootstrapServerError::BadVip(e.to_string()))?;
        vip.allocate_specific(0, SELF_NODE_ID, &cfg.server_vip)?;
        // 持久化恢复：逐条幂等回填（冲突跳过；VIP 表丢失只导致重分配，不拒启）。
        if let Some(leases) = persisted {
            for (node, v) in leases {
                if node == SELF_NODE_ID {
                    continue;
                }
                let _ = vip.allocate_specific(0, &node, &v);
            }
        }
        let mut presence = Coordinator::new();
        presence.announce(0, SELF_NODE_ID, &cfg.server_locator, cfg.lease_secs as u64)?;
        Ok(Self {
            identity,
            psk,
            presence,
            vip,
            established: HashMap::new(),
            pending: HashMap::new(),
            rate: HashMap::new(),
            cfg,
            codec,
        })
    }

    /// 服务端自身入册（目录第 0 条）。
    pub fn upsert_self_entry(&mut self, now: u64) {
        let _ = self.presence.announce(
            now,
            SELF_NODE_ID,
            &self.cfg.server_locator,
            self.cfg.lease_secs as u64,
        );
    }

    /// VIP 租约快照（落盘内容，§6.6 / W-02）。
    /// 只导出 owner 当前在未过期 presence（含服务端自身）中的租约；未完成认证的
    /// 预分配（prealloc）一律不导出——避免在"已分配未 announce"的崩溃窗口落盘后，
    /// 重启 new() 回填成永不回收的孤儿租约。
    #[must_use]
    pub fn leases_snapshot(&self, now: u64) -> Vec<(String, String)> {
        let alive = self.presence.peer_list(now);
        self.vip
            .leases_snapshot()
            .into_iter()
            .filter(|(node, _)| node == SELF_NODE_ID || alive.iter().any(|(n, _)| n == node))
            .collect()
    }

    /// 在线 peer 数（含自身）。
    #[must_use]
    pub fn online_count(&self, now: u64) -> usize {
        self.presence.peer_list(now).len()
    }

    /// 已认证会话数（测试/观测用）。
    #[cfg(test)]
    pub(crate) fn established_session_count(&self) -> usize {
        self.established.len()
    }

    /// 处理一帧来自 `src_locator` 的完整线帧数据报（含 `nxb:` magic）；
    /// 返回 (回包 dst, 字节)，静默丢弃时 `None`。
    pub fn handle_datagram(
        &mut self,
        src_locator: &str,
        dgram: &[u8],
        now: u64,
    ) -> Option<(String, Vec<u8>)> {
        // 双保险：nxb: 前缀不符 -> 不是我的帧，交回隧道 fall-through。
        let payload = dgram.strip_prefix(NXB_MAGIC)?;
        self.handle_payload(src_locator, payload, now)
    }

    /// 处理一帧**已剥掉 `nxb:` magic** 的 payload。
    ///
    /// 隧道 `recv_and_deliver` 在 [`crate::virtual_subnet::BootstrapHook`] 分流前
    /// 已剥 magic，故服务端常驻钩子走此入口，避免二次 `strip_prefix` 丢帧。
    fn handle_payload(
        &mut self,
        src_locator: &str,
        payload: &[u8],
        now: u64,
    ) -> Option<(String, Vec<u8>)> {
        match self.codec.split_outer(payload) {
            Ok(OuterKind::Secured(blob)) => self.handle_secured(src_locator, blob, now),
            Ok(OuterKind::JoinInit(req)) => match self.handle_join_init(src_locator, req, now) {
                Ok(resp) => Some(resp),
                Err(e) => self.preauth_error_reply(src_locator, &e),
            },
            Ok(OuterKind::OtherPlain) => None,
            Err(_) => None,
        }
    }

    /// 预认证阶段错误：小体积 Error 帧；不可达/无密钥场景静默。
    fn preauth_error_reply(
        &self,
        src: &str,
        err: &BootstrapServerError,
    ) -> Option<(String, Vec<u8>)> {
        let code = match err {
            BootstrapServerError::RateLimited => BootstrapOuterCode::RateLimited,
            BootstrapServerError::BadVip(_) => BootstrapOuterCode::BadVip,
            BootstrapServerError::VipConflict(_) => BootstrapOuterCode::VipConflict,
            _ => return None,
        };
        let body = self.codec.encode_error(code, &err.to_string()).ok()?;
        Some((src.to_string(), wire_with_magic(&body)))
    }

    /// JoinInit：速率/半开防护 -> 分配 VIP -> 建 pending -> 回 JoinReply。
    fn handle_join_init(
        &mut self,
        src: &str,
        req: JoinInitReq,
        now: u64,
    ) -> Result<(String, Vec<u8>), BootstrapServerError> {
        // 1) 每 src JoinInit 速率（滑动窗口 60s）。
        let window = self.rate.entry(src.to_string()).or_default();
        window.retain(|t| now.saturating_sub(*t) < RATE_WINDOW_SECS);
        if window.len() >= RATE_PER_WINDOW {
            return Err(BootstrapServerError::RateLimited);
        }
        window.push(now);

        // 2) 全局 pending 上限；触顶淘汰全局最旧 pending（F-01：回收其预分配 VIP）。
        let global: usize = self.pending.values().map(Vec::len).sum();
        if global >= MAX_PENDING_GLOBAL {
            self.evict_oldest_pending(now);
        }
        // 3) 每 src pending 上限；触顶淘汰该 src 最旧 pending（F-01：回收其预分配 VIP）。
        if self.pending.entry(src.to_string()).or_default().len() >= self.cfg.max_pending_per_src {
            let evicted_auth = self
                .pending
                .get_mut(src)
                .and_then(|l| (!l.is_empty()).then(|| l.remove(0).auth_id.clone()));
            if let Some(id) = evicted_auth {
                self.release_pending_vip_if_orphaned(&id, now);
            }
        }

        // 4) 权威 node_id（S2）。
        let auth_id = peer_id_from_public_key(&req.static_pub);

        // 5) VIP 权威分配（§5.4）。
        let assigned = match &req.requested_vip {
            None => self.vip.allocate(now, &auth_id)?,
            Some(v) => {
                self.vip
                    .check_vip(v)
                    .map_err(|e| BootstrapServerError::BadVip(e.to_string()))?;
                match self.vip.allocate_specific(now, &auth_id, v) {
                    Ok(ip) => ip,
                    Err(CoordError::AddressInUse(_)) => {
                        // 软冲突：被别的 node 占用 -> 另取，JoinReply 返回实际值。
                        self.vip.allocate(now, &auth_id)?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };

        // 6) 服务端临时 eph + server_nonce。
        let server_eph = KeyPair::generate()?;
        let server_eph_pub = *server_eph.public_key_bytes();
        let mut nonce_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let server_nonce = u64::from_be_bytes(nonce_bytes);

        self.pending
            .entry(src.to_string())
            .or_default()
            .push(PendingHandshake {
                server_eph,
                peer_static: req.static_pub,
                peer_eph: req.eph_pub,
                client_nonce: req.client_nonce,
                server_nonce,
                created_at: now,
                auth_id: auth_id.clone(),
            });

        let resp = JoinReplyResp {
            eph_pub: server_eph_pub,
            static_pub: *self.identity.public_key_bytes(),
            assigned_vip: assigned,
            lease_secs: self.cfg.lease_secs,
            hb_interval_ms: self.cfg.hb_interval_ms,
            refresh_interval_ms: self.cfg.refresh_interval_ms,
            server_nonce,
        };
        let body = self.codec.encode_join_reply(&resp)?;
        Ok((src.to_string(), wire_with_magic(&body)))
    }

    /// 淘汰全局最旧 pending（F-01：回收其预分配 VIP）。
    fn evict_oldest_pending(&mut self, now: u64) {
        let mut victim: Option<(String, usize, u64)> = None;
        for (src, list) in &self.pending {
            for (idx, p) in list.iter().enumerate() {
                let older = victim.as_ref().is_none_or(|(_, _, t)| p.created_at < *t);
                if older {
                    victim = Some((src.clone(), idx, p.created_at));
                }
            }
        }
        let Some((src, idx, _)) = victim else {
            return;
        };
        let removed_auth = self
            .pending
            .get(&src)
            .and_then(|l| l.get(idx).map(|p| p.auth_id.clone()));
        if let Some(list) = self.pending.get_mut(&src) {
            if idx < list.len() {
                list.remove(idx);
            }
            if list.is_empty() {
                self.pending.remove(&src);
            }
        }
        if let Some(auth_id) = removed_auth {
            self.release_pending_vip_if_orphaned(&auth_id, now);
        }
    }

    /// 该 auth_id 是否仍被存活 pending 或已认证会话引用。
    fn auth_id_live_count(&self, auth_id: &str) -> usize {
        let mut n = 0usize;
        for list in self.pending.values() {
            for p in list {
                if p.auth_id == auth_id {
                    n += 1;
                }
            }
        }
        for sess in self.established.values() {
            if sess.node_id == auth_id {
                n += 1;
            }
        }
        n
    }

    /// 淘汰一条 pending 后，若该 auth_id 再无其它存活引用，则回收其预分配 VIP（F-01）。
    fn release_pending_vip_if_orphaned(&mut self, auth_id: &str, now: u64) {
        if self.auth_id_live_count(auth_id) == 0 {
            let _ = self.vip.release(now, auth_id);
        }
    }

    /// 已认证/半开密文处理：解密 + 防重放 + nonce 前缀绑定（M3）+ 分发控制帧。
    fn handle_secured(&mut self, src: &str, blob: &[u8], now: u64) -> Option<(String, Vec<u8>)> {
        // 1) 已认证会话？
        if self.established.contains_key(src) {
            let (seq, plain) = {
                let sess = self.established.get(src)?;
                match decrypt_frame(&sess.keys.rx, blob) {
                    Ok(v) => v,
                    Err(_) => return None,
                }
            };
            let (client_nonce, server_nonce) = {
                let sess = self.established.get(src)?;
                (sess.client_nonce, sess.server_nonce)
            };
            self.established
                .get_mut(src)?
                .replay
                .check_and_accept(seq)
                .ok()?;
            if !nonce_prefix_ok(&plain, client_nonce, server_nonce) {
                return None;
            }
            return self.dispatch_ctrl(src, &plain[16..], now);
        }

        // 2) 半开握手：逐 pending 试解（客户端可能重试过，选能解开的那条）。
        let list = self.pending.get(src)?.clone();
        for p in &list {
            let keys = derive_authed_keys_with_psk(
                &self.identity,
                &p.server_eph,
                &p.peer_static,
                &p.peer_eph,
                false,
                &self.psk,
            )
            .ok()?;
            let (seq, plain) = match decrypt_frame(&keys.rx, blob) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !nonce_prefix_ok(&plain, p.client_nonce, p.server_nonce) {
                return None;
            }
            let ctrl = self.codec.decode(&plain[16..]).ok()?;
            // 半开首帧必须是 Register；其余静默丢弃。
            let BootstrapCtrl::Register { .. } = ctrl else {
                return None;
            };
            let auth_id = peer_id_from_public_key(&p.peer_static);
            self.presence
                .announce(now, &auth_id, src, self.cfg.lease_secs as u64)
                .ok()?;

            let mut replay = ReplayWindow::new();
            replay.check_and_accept(seq).ok()?;
            let sess = EstablishedSession {
                keys,
                replay,
                node_id: auth_id,
                client_nonce: p.client_nonce,
                server_nonce: p.server_nonce,
                tx_seq: 0,
            };
            self.established.insert(src.to_string(), sess);
            self.remove_pending(src, p);

            let ack = BootstrapCtrl::RegisterAck {
                accepted: true,
                ttl_secs: self.cfg.lease_secs,
            };
            return self.send_ctrl(src, &ack);
        }
        None
    }

    /// 分发一条已认证控制帧。
    fn dispatch_ctrl(&mut self, src: &str, plain: &[u8], now: u64) -> Option<(String, Vec<u8>)> {
        let ctrl = self.codec.decode(plain).ok()?;
        match ctrl {
            BootstrapCtrl::Register { .. } => {
                let id = self.established.get(src)?.node_id.clone();
                self.presence
                    .announce(now, &id, src, self.cfg.lease_secs as u64)
                    .ok()?;
                let ack = BootstrapCtrl::RegisterAck {
                    accepted: true,
                    ttl_secs: self.cfg.lease_secs,
                };
                self.send_ctrl(src, &ack)
            }
            BootstrapCtrl::GetPeers { .. } => {
                let id = self.established.get(src)?.node_id.clone();
                let peers = self
                    .presence
                    .peer_list(now)
                    .into_iter()
                    .filter(|(peer, _)| peer != &id)
                    .map(|(peer, locator)| BootstrapPeer {
                        virtual_ip: self.vip.peer_vip(&peer).unwrap_or_default(),
                        node_id: peer,
                        locator,
                    })
                    .collect();
                self.send_ctrl(src, &BootstrapCtrl::PeerList { peers })
            }
            BootstrapCtrl::Heartbeat { .. } => {
                let id = self.established.get(src)?.node_id.clone();
                let _ = self
                    .presence
                    .heartbeat(now, &id, self.cfg.lease_secs as u64);
                None
            }
            // 服务端不应收到 Ack/PeerList。
            BootstrapCtrl::RegisterAck { .. } | BootstrapCtrl::PeerList { .. } => None,
        }
    }

    /// 用已认证会话的 tx 密钥加密并回包（前置 nonce 绑定前缀）。
    fn send_ctrl(&mut self, dst: &str, ctrl: &BootstrapCtrl) -> Option<(String, Vec<u8>)> {
        let (client_nonce, server_nonce, seq) = {
            let sess = self.established.get(dst)?;
            (sess.client_nonce, sess.server_nonce, sess.tx_seq)
        };
        let inner = self.codec.encode(ctrl).ok()?;
        let mut plain = Vec::with_capacity(16 + inner.len());
        plain.extend_from_slice(&client_nonce.to_be_bytes());
        plain.extend_from_slice(&server_nonce.to_be_bytes());
        plain.extend(inner);
        let blob = encrypt_frame(&self.established.get(dst)?.keys.tx, seq, &plain).ok()?;
        self.established.get_mut(dst)?.tx_seq += 1;
        Some((dst.to_string(), wire_with_magic(&blob)))
    }

    /// 移除与 `p` 匹配的 pending 条目（完成认证后）。
    fn remove_pending(&mut self, src: &str, p: &PendingHandshake) {
        if let Some(list) = self.pending.get_mut(src) {
            list.retain(|e| e.client_nonce != p.client_nonce || e.server_nonce != p.server_nonce);
            if list.is_empty() {
                self.pending.remove(src);
            }
        }
    }

    /// 固定事务顺序（W-01）：
    /// 1) prune presence 得 expired；
    /// 2) 立即按 node_id 清掉对应 established 会话（否则 stale 会话使
    ///    `auth_id_live_count` 过计数，挡住后续孤儿 VIP 释放）；
    /// 3) 逐 expired release VIP；
    /// 4) 清扫过期 pending（此时 live_count 已不含 stale established）并回收孤儿预分配 VIP；
    /// 5) 清扫速率窗口。
    pub fn sweep_expired(&mut self, now: u64) -> SweepReport {
        let expired = self.presence.prune_expired(now);
        // W-01：先摘除与过期 peer 对应的已认证会话，避免其挡住孤儿 VIP 释放。
        self.established
            .retain(|_, s| !expired.contains(&s.node_id));
        let mut released_vips = Vec::new();
        for id in &expired {
            if self.vip.release(now, id).is_ok() {
                released_vips.push(id.clone());
            }
        }
        // pending TTL 清扫（F-01）：过期即未完成认证，回收其预分配 VIP（孤儿检查）。
        let mut expired_pending: Vec<String> = Vec::new();
        for list in self.pending.values_mut() {
            list.retain(|p| {
                if now.saturating_sub(p.created_at) < PENDING_TTL_SECS {
                    true
                } else {
                    expired_pending.push(p.auth_id.clone());
                    false
                }
            });
        }
        self.pending.retain(|_, l| !l.is_empty());
        for id in &expired_pending {
            if self.auth_id_live_count(id) == 0 && self.vip.release(now, id).is_ok() {
                released_vips.push(id.clone());
            }
        }
        // G-03：清理无界增长的速率表——保留窗口内仍有记录的 src，其余摘除。
        self.rate.retain(|_, w| {
            w.retain(|t| now.saturating_sub(*t) < RATE_WINDOW_SECS);
            !w.is_empty()
        });
        SweepReport {
            expired,
            released_vips,
        }
    }
}

/// 服务端角色的常驻钩子：把隧道收到的 `nxb:` 控制帧转给 [`BootstrapServer`]，
/// 并在每个 tick 做 TTL 清扫（v2 §6.4 / §7.2 接线点 3）。
///
/// 隧道独占 carrier（`virtual_subnet.rs`），服务端不能另持 socket，因此这里
/// 只做纯逻辑转调：回包交回隧道代发，VIP 租约快照由调用方取走去落盘（§6.6）。
pub struct ServerBootstrapHook {
    server: BootstrapServer,
    /// 上次 `periodic` 的清扫结果（供观测/落盘判定变更）。
    last_sweep: SweepReport,
}

impl ServerBootstrapHook {
    /// 包装服务端状态机为隧道钩子。
    #[must_use]
    pub fn new(server: BootstrapServer) -> Self {
        Self {
            server,
            last_sweep: SweepReport {
                expired: Vec::new(),
                released_vips: Vec::new(),
            },
        }
    }

    /// 只读访问底层服务端（观测：在线数、租约快照）。
    #[must_use]
    pub fn server(&self) -> &BootstrapServer {
        &self.server
    }

    /// 当前权威租约快照（§6.6 落盘内容）。
    #[must_use]
    pub fn leases_snapshot(&self, now: u64) -> Vec<(String, String)> {
        self.server.leases_snapshot(now)
    }

    /// 最近一次清扫释放的 VIP（非空表示租约表发生变化，调用方应触发落盘）。
    #[must_use]
    pub fn released_vips(&self) -> &[String] {
        &self.last_sweep.released_vips
    }
}

impl crate::virtual_subnet::BootstrapHook for ServerBootstrapHook {
    fn on_control_datagram(
        &mut self,
        src: Option<&str>,
        payload: &[u8],
        now: u64,
    ) -> Option<(String, Vec<u8>)> {
        // 隧道已剥掉 `nxb:` magic（virtual_subnet.rs 的 strip_prefix），而
        // handle_datagram 期望带前缀的完整数据报——这里补回去再转调。
        let src = src?;
        let mut wire = Vec::with_capacity(NXB_MAGIC.len() + payload.len());
        wire.extend_from_slice(NXB_MAGIC);
        wire.extend_from_slice(payload);
        self.server.handle_datagram(src, &wire, now)
    }

    fn periodic(&mut self, now: u64) -> crate::virtual_subnet::BootstrapTick {
        // 服务端自身续期入册（§6.7）+ TTL 清扫（§6.2）。
        self.server.upsert_self_entry(now);
        self.last_sweep = self.server.sweep_expired(now);
        // 服务端是被动应答方：控制帧只在收到请求时回发，tick 不主动发包。
        crate::virtual_subnet::BootstrapTick::default()
    }

    fn lease_snapshot(&self, now: u64) -> Option<Vec<(String, String)>> {
        Some(self.server.leases_snapshot(now))
    }
}

/// AEAD 明文前 16B 必须是 client_nonce‖server_nonce（M3 握手绑定）。
fn nonce_prefix_ok(plain: &[u8], client_nonce: u64, server_nonce: u64) -> bool {
    if plain.len() < 16 {
        return false;
    }
    plain[0..8] == client_nonce.to_be_bytes()[..] && plain[8..16] == server_nonce.to_be_bytes()[..]
}

/// 给外层 body 前置 `nxb:` magic。
fn wire_with_magic(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NXB_MAGIC.len() + body.len());
    out.extend_from_slice(NXB_MAGIC);
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// pub 内存 codec：与 discovery bootstrap_join 字节格式对齐，供 harness E2E 复用
// （server 与 client 共用同一 codec 完成真实握手往返）。
// ---------------------------------------------------------------------------

/// 本地内存线格式 codec（test/harness seam；与 discovery 帧格式对齐）。
#[derive(Default)]
pub struct MemCodec;

fn mem_put_s(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn mem_get_s(b: &[u8], pos: &mut usize) -> Result<String, BootstrapServerError> {
    if b.len() < *pos + 2 {
        return Err(BootstrapServerError::Malformed("short string len".into()));
    }
    let len = u16::from_be_bytes([b[*pos], b[*pos + 1]]) as usize;
    *pos += 2;
    if b.len() < *pos + len {
        return Err(BootstrapServerError::Malformed("short string body".into()));
    }
    let s = std::str::from_utf8(&b[*pos..*pos + len])
        .map_err(|_| BootstrapServerError::Malformed("utf8".into()))?;
    *pos += len;
    Ok(s.to_string())
}

impl BootstrapFrameCodec for MemCodec {
    fn encode(&self, f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError> {
        let mut out = Vec::new();
        match f {
            BootstrapCtrl::Register {
                node_id,
                virtual_ip,
                locator,
            } => {
                out.push(11);
                mem_put_s(&mut out, node_id);
                mem_put_s(&mut out, virtual_ip);
                mem_put_s(&mut out, locator);
            }
            BootstrapCtrl::RegisterAck { accepted, ttl_secs } => {
                out.push(15);
                out.push(u8::from(*accepted));
                out.extend_from_slice(&ttl_secs.to_be_bytes());
            }
            BootstrapCtrl::GetPeers { node_id } => {
                out.push(12);
                mem_put_s(&mut out, node_id);
            }
            BootstrapCtrl::PeerList { peers } => {
                out.push(13);
                out.extend_from_slice(&(peers.len() as u16).to_be_bytes());
                for p in peers {
                    mem_put_s(&mut out, &p.node_id);
                    mem_put_s(&mut out, &p.virtual_ip);
                    mem_put_s(&mut out, &p.locator);
                }
            }
            BootstrapCtrl::Heartbeat { node_id, now } => {
                out.push(14);
                mem_put_s(&mut out, node_id);
                out.extend_from_slice(&now.to_be_bytes());
            }
        }
        Ok(out)
    }

    fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError> {
        if b.is_empty() {
            return Err(BootstrapServerError::Malformed("empty ctrl".into()));
        }
        let tag = b[0];
        let mut pos = 1usize;
        match tag {
            11 => Ok(BootstrapCtrl::Register {
                node_id: mem_get_s(b, &mut pos)?,
                virtual_ip: mem_get_s(b, &mut pos)?,
                locator: mem_get_s(b, &mut pos)?,
            }),
            15 => {
                if b.len() < 6 {
                    return Err(BootstrapServerError::Malformed("short ack".into()));
                }
                let accepted = b[1] != 0;
                let mut t = [0u8; 4];
                t.copy_from_slice(&b[2..6]);
                Ok(BootstrapCtrl::RegisterAck {
                    accepted,
                    ttl_secs: u32::from_be_bytes(t),
                })
            }
            12 => Ok(BootstrapCtrl::GetPeers {
                node_id: mem_get_s(b, &mut pos)?,
            }),
            13 => {
                if b.len() < 3 {
                    return Err(BootstrapServerError::Malformed("short peerlist".into()));
                }
                let n = u16::from_be_bytes([b[1], b[2]]) as usize;
                pos = 3;
                let mut peers = Vec::new();
                for _ in 0..n {
                    let node_id = mem_get_s(b, &mut pos)?;
                    let virtual_ip = mem_get_s(b, &mut pos)?;
                    let locator = mem_get_s(b, &mut pos)?;
                    peers.push(BootstrapPeer {
                        node_id,
                        virtual_ip,
                        locator,
                    });
                }
                Ok(BootstrapCtrl::PeerList { peers })
            }
            14 => {
                let node_id = mem_get_s(b, &mut pos)?;
                if b.len() < pos + 8 {
                    return Err(BootstrapServerError::Malformed("short heartbeat".into()));
                }
                let mut t = [0u8; 8];
                t.copy_from_slice(&b[pos..pos + 8]);
                Ok(BootstrapCtrl::Heartbeat {
                    node_id,
                    now: u64::from_be_bytes(t),
                })
            }
            _ => Err(BootstrapServerError::Malformed("tag".into())),
        }
    }

    fn decode_join_init(&self, payload: &[u8]) -> Result<JoinInitReq, BootstrapServerError> {
        if payload.len() < 1 + 32 + 32 + 1 + 8 {
            return Err(BootstrapServerError::Malformed("short join init".into()));
        }
        if payload[0] != 0x10 {
            return Err(BootstrapServerError::Malformed("not join init".into()));
        }
        let mut pos = 1;
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&payload[pos..pos + 32]);
        pos += 32;
        let mut static_pub = [0u8; 32];
        static_pub.copy_from_slice(&payload[pos..pos + 32]);
        pos += 32;
        let presence = payload[pos];
        pos += 1;
        let requested_vip = if presence == 0 {
            None
        } else {
            Some(mem_get_s(payload, &mut pos)?)
        };
        if pos + 8 > payload.len() {
            return Err(BootstrapServerError::Malformed("short client_nonce".into()));
        }
        let mut n = [0u8; 8];
        n.copy_from_slice(&payload[pos..pos + 8]);
        Ok(JoinInitReq {
            eph_pub,
            static_pub,
            requested_vip,
            client_nonce: u64::from_be_bytes(n),
        })
    }

    fn encode_join_reply(&self, r: &JoinReplyResp) -> Result<Vec<u8>, BootstrapServerError> {
        let mut out = Vec::new();
        out.push(0x11);
        out.extend_from_slice(&r.eph_pub);
        out.extend_from_slice(&r.static_pub);
        mem_put_s(&mut out, &r.assigned_vip);
        out.extend_from_slice(&r.lease_secs.to_be_bytes());
        out.extend_from_slice(&r.hb_interval_ms.to_be_bytes());
        out.extend_from_slice(&r.refresh_interval_ms.to_be_bytes());
        out.extend_from_slice(&r.server_nonce.to_be_bytes());
        Ok(out)
    }

    fn encode_error(
        &self,
        code: BootstrapOuterCode,
        message: &str,
    ) -> Result<Vec<u8>, BootstrapServerError> {
        let mut out = Vec::new();
        out.push(0x12);
        out.push(code as u8);
        mem_put_s(&mut out, message);
        Ok(out)
    }

    fn split_outer<'a>(&self, payload: &'a [u8]) -> Result<OuterKind<'a>, BootstrapServerError> {
        if payload.is_empty() {
            return Err(BootstrapServerError::Malformed("empty".into()));
        }
        if payload[0] == 0x01 && payload.len() >= 38 {
            return Ok(OuterKind::Secured(payload));
        }
        match payload[0] {
            0x10 => Ok(OuterKind::JoinInit(self.decode_join_init(payload)?)),
            _ => Ok(OuterKind::OtherPlain),
        }
    }

    fn encode_join_init(&self, req: &JoinInitReq) -> Result<Vec<u8>, BootstrapServerError> {
        let mut out = Vec::new();
        out.push(0x10);
        out.extend_from_slice(&req.eph_pub);
        out.extend_from_slice(&req.static_pub);
        match &req.requested_vip {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                mem_put_s(&mut out, v);
            }
        }
        out.extend_from_slice(&req.client_nonce.to_be_bytes());
        Ok(out)
    }

    fn decode_join_reply(&self, body: &[u8]) -> Result<JoinReplyResp, BootstrapServerError> {
        if body.len() < 1 + 32 + 32 + 2 + 4 + 4 + 4 + 8 {
            return Err(BootstrapServerError::Malformed("short join reply".into()));
        }
        if body[0] != 0x11 {
            return Err(BootstrapServerError::Malformed("not join reply".into()));
        }
        let mut pos = 1;
        let mut eph_pub = [0u8; 32];
        eph_pub.copy_from_slice(&body[pos..pos + 32]);
        pos += 32;
        let mut static_pub = [0u8; 32];
        static_pub.copy_from_slice(&body[pos..pos + 32]);
        pos += 32;
        let assigned_vip = mem_get_s(body, &mut pos)?;
        let mut take = |n: usize| -> Result<Vec<u8>, BootstrapServerError> {
            if body.len() < pos + n {
                return Err(BootstrapServerError::Malformed("short fixed field".into()));
            }
            let s: Vec<u8> = body[pos..pos + n].to_vec();
            pos += n;
            Ok(s)
        };
        let lease = u32::from_be_bytes(take(4)?.try_into().unwrap());
        let hb = u32::from_be_bytes(take(4)?.try_into().unwrap());
        let rf = u32::from_be_bytes(take(4)?.try_into().unwrap());
        let mut n = [0u8; 8];
        n.copy_from_slice(&body[pos..pos + 8]);
        Ok(JoinReplyResp {
            eph_pub,
            static_pub,
            assigned_vip,
            lease_secs: lease,
            hb_interval_ms: hb,
            refresh_interval_ms: rf,
            server_nonce: u64::from_be_bytes(n),
        })
    }
}

// ---------------------------------------------------------------------------
// 测试：本地内存 codec（与 discovery bootstrap_join 字节格式对齐），驱动完整握手。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::KeyPair;

    const CIDR: &str = "10.144.144.0/24";
    const PSK: &[u8] = b"shared-psk";

    /// 本地 codec：按 bootstrap_join.rs 的线格式手动编解码（discovery 侧已有完整
    /// 往返单测；此处只保证服务端编排正确）。
    struct MemCodec;

    impl MemCodec {
        fn decode_reply(&self, body: &[u8]) -> JoinReplyResp {
            assert_eq!(body[0], 0x11);
            let mut pos = 1;
            let mut eph_pub = [0u8; 32];
            eph_pub.copy_from_slice(&body[pos..pos + 32]);
            pos += 32;
            let mut static_pub = [0u8; 32];
            static_pub.copy_from_slice(&body[pos..pos + 32]);
            pos += 32;
            let assigned_vip = get_s(body, &mut pos).unwrap();
            let mut u = [0u8; 4];
            u.copy_from_slice(&body[pos..pos + 4]);
            let lease_secs = u32::from_be_bytes(u);
            pos += 4;
            u.copy_from_slice(&body[pos..pos + 4]);
            let hb_interval_ms = u32::from_be_bytes(u);
            pos += 4;
            u.copy_from_slice(&body[pos..pos + 4]);
            let refresh_interval_ms = u32::from_be_bytes(u);
            pos += 4;
            let mut n = [0u8; 8];
            n.copy_from_slice(&body[pos..pos + 8]);
            JoinReplyResp {
                eph_pub,
                static_pub,
                assigned_vip,
                lease_secs,
                hb_interval_ms,
                refresh_interval_ms,
                server_nonce: u64::from_be_bytes(n),
            }
        }
    }

    impl BootstrapFrameCodec for MemCodec {
        fn encode(&self, f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError> {
            let mut out = Vec::new();
            match f {
                BootstrapCtrl::Register {
                    node_id,
                    virtual_ip,
                    locator,
                } => {
                    out.push(11);
                    put_s(&mut out, node_id);
                    put_s(&mut out, virtual_ip);
                    put_s(&mut out, locator);
                }
                BootstrapCtrl::RegisterAck { accepted, ttl_secs } => {
                    out.push(15);
                    out.push(u8::from(*accepted));
                    out.extend_from_slice(&ttl_secs.to_be_bytes());
                }
                BootstrapCtrl::GetPeers { node_id } => {
                    out.push(12);
                    put_s(&mut out, node_id);
                }
                BootstrapCtrl::PeerList { peers } => {
                    out.push(13);
                    out.extend_from_slice(&(peers.len() as u16).to_be_bytes());
                    for p in peers {
                        put_s(&mut out, &p.node_id);
                        put_s(&mut out, &p.virtual_ip);
                        put_s(&mut out, &p.locator);
                    }
                }
                BootstrapCtrl::Heartbeat { node_id, now } => {
                    out.push(14);
                    put_s(&mut out, node_id);
                    out.extend_from_slice(&now.to_be_bytes());
                }
            }
            Ok(out)
        }

        fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError> {
            if b.is_empty() {
                return Err(BootstrapServerError::Malformed("empty ctrl".into()));
            }
            let tag = b[0];
            let mut pos = 1usize;
            match tag {
                11 => Ok(BootstrapCtrl::Register {
                    node_id: get_s(b, &mut pos)?,
                    virtual_ip: get_s(b, &mut pos)?,
                    locator: get_s(b, &mut pos)?,
                }),
                15 => {
                    if b.len() < 6 {
                        return Err(BootstrapServerError::Malformed("short ack".into()));
                    }
                    let accepted = b[1] != 0;
                    let mut t = [0u8; 4];
                    t.copy_from_slice(&b[2..6]);
                    Ok(BootstrapCtrl::RegisterAck {
                        accepted,
                        ttl_secs: u32::from_be_bytes(t),
                    })
                }
                12 => Ok(BootstrapCtrl::GetPeers {
                    node_id: get_s(b, &mut pos)?,
                }),
                13 => {
                    if b.len() < 3 {
                        return Err(BootstrapServerError::Malformed("short peerlist".into()));
                    }
                    let n = u16::from_be_bytes([b[1], b[2]]) as usize;
                    pos = 3;
                    let mut peers = Vec::new();
                    for _ in 0..n {
                        let node_id = get_s(b, &mut pos)?;
                        let virtual_ip = get_s(b, &mut pos)?;
                        let locator = get_s(b, &mut pos)?;
                        peers.push(BootstrapPeer {
                            node_id,
                            virtual_ip,
                            locator,
                        });
                    }
                    Ok(BootstrapCtrl::PeerList { peers })
                }
                14 => {
                    let node_id = get_s(b, &mut pos)?;
                    let mut t = [0u8; 8];
                    t.copy_from_slice(&b[pos..pos + 8]);
                    Ok(BootstrapCtrl::Heartbeat {
                        node_id,
                        now: u64::from_be_bytes(t),
                    })
                }
                _ => Err(BootstrapServerError::Malformed("tag".into())),
            }
        }

        fn decode_join_init(&self, payload: &[u8]) -> Result<JoinInitReq, BootstrapServerError> {
            if payload.len() < 1 + 32 + 32 + 1 + 8 {
                return Err(BootstrapServerError::Malformed("short join init".into()));
            }
            if payload[0] != 0x10 {
                return Err(BootstrapServerError::Malformed("not join init".into()));
            }
            let mut pos = 1;
            let mut eph_pub = [0u8; 32];
            eph_pub.copy_from_slice(&payload[pos..pos + 32]);
            pos += 32;
            let mut static_pub = [0u8; 32];
            static_pub.copy_from_slice(&payload[pos..pos + 32]);
            pos += 32;
            let presence = payload[pos];
            pos += 1;
            let requested_vip = if presence == 0 {
                None
            } else {
                Some(get_s(payload, &mut pos)?)
            };
            let mut n = [0u8; 8];
            n.copy_from_slice(&payload[pos..pos + 8]);
            Ok(JoinInitReq {
                eph_pub,
                static_pub,
                requested_vip,
                client_nonce: u64::from_be_bytes(n),
            })
        }

        fn encode_join_reply(&self, r: &JoinReplyResp) -> Result<Vec<u8>, BootstrapServerError> {
            let mut out = Vec::new();
            out.push(0x11);
            out.extend_from_slice(&r.eph_pub);
            out.extend_from_slice(&r.static_pub);
            put_s(&mut out, &r.assigned_vip);
            out.extend_from_slice(&r.lease_secs.to_be_bytes());
            out.extend_from_slice(&r.hb_interval_ms.to_be_bytes());
            out.extend_from_slice(&r.refresh_interval_ms.to_be_bytes());
            out.extend_from_slice(&r.server_nonce.to_be_bytes());
            Ok(out)
        }

        fn encode_error(
            &self,
            code: BootstrapOuterCode,
            message: &str,
        ) -> Result<Vec<u8>, BootstrapServerError> {
            let mut out = Vec::new();
            out.push(0x12);
            out.push(code as u8);
            put_s(&mut out, message);
            Ok(out)
        }

        fn split_outer<'a>(
            &self,
            payload: &'a [u8],
        ) -> Result<OuterKind<'a>, BootstrapServerError> {
            if payload.is_empty() {
                return Err(BootstrapServerError::Malformed("empty".into()));
            }
            if payload[0] == 0x01 && payload.len() >= 38 {
                return Ok(OuterKind::Secured(payload));
            }
            match payload[0] {
                0x10 => Ok(OuterKind::JoinInit(self.decode_join_init(payload)?)),
                _ => Ok(OuterKind::OtherPlain),
            }
        }

        fn encode_join_init(&self, req: &JoinInitReq) -> Result<Vec<u8>, BootstrapServerError> {
            let mut out = Vec::new();
            out.push(0x10);
            out.extend_from_slice(&req.eph_pub);
            out.extend_from_slice(&req.static_pub);
            match &req.requested_vip {
                None => out.push(0),
                Some(v) => {
                    out.push(1);
                    put_s(&mut out, v);
                }
            }
            out.extend_from_slice(&req.client_nonce.to_be_bytes());
            Ok(out)
        }

        fn decode_join_reply(&self, body: &[u8]) -> Result<JoinReplyResp, BootstrapServerError> {
            if body.len() < 1 + 32 + 32 + 2 + 4 + 4 + 4 + 8 {
                return Err(BootstrapServerError::Malformed("short join reply".into()));
            }
            if body[0] != 0x11 {
                return Err(BootstrapServerError::Malformed("not join reply".into()));
            }
            let mut pos = 1;
            let mut eph_pub = [0u8; 32];
            eph_pub.copy_from_slice(&body[pos..pos + 32]);
            pos += 32;
            let mut static_pub = [0u8; 32];
            static_pub.copy_from_slice(&body[pos..pos + 32]);
            pos += 32;
            let assigned_vip = get_s(body, &mut pos)?;
            let mut take = |n: usize| -> Result<Vec<u8>, BootstrapServerError> {
                let s: Vec<u8> = body[pos..pos + n].to_vec();
                pos += n;
                Ok(s)
            };
            let lease = u32::from_be_bytes(take(4)?.try_into().unwrap());
            let hb = u32::from_be_bytes(take(4)?.try_into().unwrap());
            let rf = u32::from_be_bytes(take(4)?.try_into().unwrap());
            let mut n = [0u8; 8];
            n.copy_from_slice(&body[pos..pos + 8]);
            Ok(JoinReplyResp {
                eph_pub,
                static_pub,
                assigned_vip,
                lease_secs: lease,
                hb_interval_ms: hb,
                refresh_interval_ms: rf,
                server_nonce: u64::from_be_bytes(n),
            })
        }
    }

    fn put_s(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }

    fn get_s(b: &[u8], pos: &mut usize) -> Result<String, BootstrapServerError> {
        let len = u16::from_be_bytes([b[*pos], b[*pos + 1]]) as usize;
        *pos += 2;
        let s = std::str::from_utf8(&b[*pos..*pos + len])
            .map_err(|_| BootstrapServerError::Malformed("utf8".into()))?;
        *pos += len;
        Ok(s.to_string())
    }

    fn make_server() -> BootstrapServer {
        let identity = KeyPair::from_seed(&[9u8; 32]);
        let cfg = BootstrapServerConfig {
            cidr: CIDR.into(),
            lease_secs: 60,
            hb_interval_ms: 20000,
            refresh_interval_ms: 60000,
            server_vip: "10.144.144.1".into(),
            server_locator: "udp://bootstrap:11010".into(),
            max_pending_per_src: 4,
        };
        BootstrapServer::new(identity, PSK.to_vec(), cfg, Box::new(MemCodec), None).unwrap()
    }

    /// 客户端侧一步：发 JoinInit，返回 (reply, 客户端 keys, client_nonce, server_nonce)。
    fn client_join_init(
        server: &mut BootstrapServer,
        src: &str,
        client_eph: &KeyPair,
        client_static: &KeyPair,
        requested_vip: Option<&str>,
        now: u64,
    ) -> Option<(JoinReplyResp, DirectionalKeys, u64)> {
        let client_nonce: u64 = 0xAABBCCDD;
        let mut body = Vec::new();
        body.push(0x10);
        body.extend_from_slice(client_eph.public_key_bytes());
        body.extend_from_slice(client_static.public_key_bytes());
        match requested_vip {
            None => body.push(0),
            Some(v) => {
                body.push(1);
                put_s(&mut body, v);
            }
        }
        body.extend_from_slice(&client_nonce.to_be_bytes());
        let mut dgram = Vec::new();
        dgram.extend_from_slice(NXB_MAGIC);
        dgram.extend(body);

        let (dst, reply_wire) = server.handle_datagram(src, &dgram, now)?;
        assert_eq!(dst, src);
        let body = &reply_wire[NXB_MAGIC.len()..];
        // 预认证错误帧（RateLimited/BadVip 等）-> 返回 None，由测试断言。
        if body[0] == 0x12 {
            return None;
        }
        let resp = MemCodec.decode_reply(body);
        let keys = derive_authed_keys_with_psk(
            client_static,
            client_eph,
            &resp.static_pub,
            &resp.eph_pub,
            true,
            PSK,
        )
        .expect("client derive keys");
        Some((resp, keys, client_nonce))
    }

    /// 客户端发加密控制帧（带 nonce 前缀），返回服务端回包。
    #[allow(clippy::too_many_arguments)]
    fn client_send_ctrl(
        server: &mut BootstrapServer,
        src: &str,
        keys: &DirectionalKeys,
        client_nonce: u64,
        server_nonce: u64,
        inner: &BootstrapCtrl,
        tx_seq: u64,
        now: u64,
    ) -> Option<(String, Vec<u8>)> {
        let inner = MemCodec.encode(inner).expect("encode inner");
        let mut plain = Vec::new();
        plain.extend_from_slice(&client_nonce.to_be_bytes());
        plain.extend_from_slice(&server_nonce.to_be_bytes());
        plain.extend(inner);
        let blob = encrypt_frame(&keys.tx, tx_seq, &plain).unwrap();
        let mut dgram = Vec::new();
        dgram.extend_from_slice(NXB_MAGIC);
        dgram.extend(blob);
        server.handle_datagram(src, &dgram, now)
    }

    fn decode_server_reply(reply_wire: &[u8], keys: &DirectionalKeys) -> (u64, Vec<u8>) {
        let blob = &reply_wire[NXB_MAGIC.len()..];
        decrypt_frame(&keys.rx, blob).expect("decrypt server reply")
    }

    #[test]
    fn full_join_peer_list_contains_self_and_peers() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);

        // 节点 A：零申请 VIP join。
        let eph_a = KeyPair::from_seed(&[3u8; 32]);
        let st_a = KeyPair::from_seed(&[1u8; 32]);
        let (ra, ka, ca_n) =
            client_join_init(&mut server, "udp://a:1", &eph_a, &st_a, None, now).expect("A join");
        // .1 被服务端占位，A 权威分配应拿 .2。
        assert_eq!(ra.assigned_vip, "10.144.144.2");

        // A 发 Register。
        let ack = client_send_ctrl(
            &mut server,
            "udp://a:1",
            &ka,
            ca_n,
            ra.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a-self".into(),
                virtual_ip: ra.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("A register ack");
        let (_, plain) = decode_server_reply(&ack.1, &ka);
        let ack_ctrl = MemCodec.decode(&plain[16..]).expect("decode ack");
        assert_eq!(
            ack_ctrl,
            BootstrapCtrl::RegisterAck {
                accepted: true,
                ttl_secs: 60
            }
        );

        // A 拉列表：只含服务端自身（A 自己被 exclude）。
        let pl = client_send_ctrl(
            &mut server,
            "udp://a:1",
            &ka,
            ca_n,
            ra.server_nonce,
            &BootstrapCtrl::GetPeers {
                node_id: "a".into(),
            },
            1,
            now,
        )
        .expect("A getpeers");
        let (_, plain) = decode_server_reply(&pl.1, &ka);
        let peers = match MemCodec.decode(&plain[16..]).expect("decode peers") {
            BootstrapCtrl::PeerList { peers } => peers,
            other => panic!("expected PeerList, got {other:?}"),
        };
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, SELF_NODE_ID);
        assert_eq!(peers[0].virtual_ip, "10.144.144.1");

        // 节点 C join + register。
        let eph_c = KeyPair::from_seed(&[5u8; 32]);
        let st_c = KeyPair::from_seed(&[2u8; 32]);
        let (rc, kc, cc_n) =
            client_join_init(&mut server, "udp://c:1", &eph_c, &st_c, None, now).expect("C join");
        assert_eq!(rc.assigned_vip, "10.144.144.3");
        client_send_ctrl(
            &mut server,
            "udp://c:1",
            &kc,
            cc_n,
            rc.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "c-self".into(),
                virtual_ip: rc.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("C register ack");

        // A 再拉列表：应含 SELF + C（exclude A）。
        let pl2 = client_send_ctrl(
            &mut server,
            "udp://a:1",
            &ka,
            ca_n,
            ra.server_nonce,
            &BootstrapCtrl::GetPeers {
                node_id: "a".into(),
            },
            2,
            now,
        )
        .expect("A getpeers2");
        let (_, plain) = decode_server_reply(&pl2.1, &ka);
        let peers2 = match MemCodec.decode(&plain[16..]).expect("decode peers2") {
            BootstrapCtrl::PeerList { peers } => peers,
            other => panic!("expected PeerList, got {other:?}"),
        };
        let ids: Vec<&str> = peers2.iter().map(|p| p.node_id.as_str()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&SELF_NODE_ID));
        assert!(ids.iter().any(|id| *id != SELF_NODE_ID));
    }

    #[test]
    fn psk_mismatch_no_directory_entry() {
        let mut server = make_server();
        let now = 1000u64;
        // 客户端用错误 PSK 派生 keys：JoinInit 明文仍成功，但 Register 解不开。
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[7u8; 32]);
        let (resp, _server_keys, client_nonce) =
            client_join_init(&mut server, "udp://evil:1", &eph, &st, None, now).expect("join ok");
        // 用错误 PSK 派生客户端 keys。
        let bad_keys = derive_authed_keys_with_psk(
            &st,
            &eph,
            &resp.static_pub,
            &resp.eph_pub,
            true,
            b"wrong-psk",
        )
        .unwrap();
        let before = server.online_count(now);
        let resp2 = client_send_ctrl(
            &mut server,
            "udp://evil:1",
            &bad_keys,
            client_nonce,
            resp.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "evil".into(),
                virtual_ip: "".into(),
                locator: "".into(),
            },
            0,
            now,
        );
        // 解密失败 -> 静默丢弃，无回包。
        assert!(resp2.is_none());
        // 目录不新增条目。
        assert_eq!(server.online_count(now), before);
    }

    #[test]
    fn vip_soft_conflict_returns_assigned() {
        let mut server = make_server();
        let now = 1000u64;
        // A 申请 .5。
        let eph_a = KeyPair::from_seed(&[3u8; 32]);
        let st_a = KeyPair::from_seed(&[1u8; 32]);
        let (ra, _, _) = client_join_init(
            &mut server,
            "udp://a:1",
            &eph_a,
            &st_a,
            Some("10.144.144.5"),
            now,
        )
        .unwrap();
        assert_eq!(ra.assigned_vip, "10.144.144.5");
        // B 也申请 .5：被 A 占用 -> 软冲突，B 另取。
        let eph_b = KeyPair::from_seed(&[4u8; 32]);
        let st_b = KeyPair::from_seed(&[2u8; 32]);
        let (rb, _, _) = client_join_init(
            &mut server,
            "udp://b:1",
            &eph_b,
            &st_b,
            Some("10.144.144.5"),
            now,
        )
        .unwrap();
        assert_ne!(rb.assigned_vip, "10.144.144.5");
        assert_eq!(rb.assigned_vip, "10.144.144.2");
    }

    #[test]
    fn lease_expiry_prunes_and_releases() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        let (r, k, cn) = client_join_init(&mut server, "udp://a:1", &eph, &st, None, now).unwrap();
        client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("ack");
        assert_eq!(server.online_count(now), 2); // self + a

        // 推进到 lease 过期（lease=60s）；服务端每 tick 刷新自身条目，故 SELF 不过期。
        server.upsert_self_entry(now + 61);
        let report = server.sweep_expired(now + 61);
        assert_eq!(report.expired.len(), 1);
        assert_eq!(report.released_vips.len(), 1);
        assert_eq!(server.online_count(now + 61), 1); // 只剩 self
    }

    #[test]
    fn replayed_secured_frame_rejected() {
        let mut server = make_server();
        let now = 1000u64;
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        let (r, k, cn) = client_join_init(&mut server, "udp://a:1", &eph, &st, None, now).unwrap();
        // 第一个 Register（seq=0）成功。
        let ack = client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("first ack");
        drop(ack);
        // 重放同一帧（用相同 blob 再喂一次）：从 ack 反推不了 blob，改为再发一次 seq=0。
        let again = client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        );
        // ReplayWindow 拒绝重复 seq=0 -> 静默 None。
        assert!(again.is_none());
    }

    #[test]
    fn rate_limits_after_burst_join_init() {
        let mut server = make_server();
        // 同 src 发 11 个 JoinInit（每个换一个 static key）。
        let mut last = None;
        for (now, i) in (1000u64..).zip(0..11) {
            let eph = KeyPair::from_seed(&[3u8; 32]);
            let st = KeyPair::from_seed(&[i as u8 + 1; 32]);
            last = client_join_init(&mut server, "udp://burst:1", &eph, &st, None, now);
        }
        // 第 11 个应被速率窗口拒绝（前 10 次成功）。
        assert!(last.is_none());
    }

    // ---- F-01/F-02：未认证预分配 VIP 必须在淘汰/超时后回池 ----

    #[test]
    fn f01_unauthed_prealloc_vip_released_after_ttl_sweep() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);
        // 攻击者只发 JoinInit、永不发 Register。
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[7u8; 32]);
        let (r, _, _) =
            client_join_init(&mut server, "udp://evil:1", &eph, &st, None, now).unwrap();
        assert_eq!(r.assigned_vip, "10.144.144.2");
        let evil_id = peer_id_from_public_key(st.public_key_bytes());
        // W-02：prealloc 未完成认证，即使 VIP 已在分配器里，也不落盘快照。
        assert!(
            !server
                .leases_snapshot(now)
                .iter()
                .any(|(id, _)| id == &evil_id)
        );
        // 推进过 pending TTL(10s)，sweep 回收。
        let report = server.sweep_expired(now + 11);
        assert!(report.released_vips.contains(&evil_id));
        // 回收后快照仍不含。
        assert!(
            !server
                .leases_snapshot(now + 11)
                .iter()
                .any(|(id, _)| id == &evil_id)
        );
        // 后续新节点复用刚回收的 .2（证明回池，非泄漏）。
        let st2 = KeyPair::from_seed(&[8u8; 32]);
        let eph2 = KeyPair::from_seed(&[4u8; 32]);
        let (r2, _, _) =
            client_join_init(&mut server, "udp://good:1", &eph2, &st2, None, now + 11).unwrap();
        assert_eq!(r2.assigned_vip, "10.144.144.2");
    }

    #[test]
    fn f01_per_src_cap_eviction_releases_prealloc_vip() {
        let mut server = make_server();
        let now = 1000u64;
        // 同 src 连续发 5 个（max_pending_per_src=4），第 5 个淘汰最旧。
        let mut vips = Vec::new();
        for i in 0..5u8 {
            let eph = KeyPair::from_seed(&[3u8; 32]);
            let st = KeyPair::from_seed(&[10 + i; 32]);
            let (r, _, _) =
                client_join_init(&mut server, "udp://s:1", &eph, &st, None, now).unwrap();
            vips.push(r.assigned_vip);
        }
        assert_eq!(vips[0], "10.144.144.2");
        // 最旧(static=[10])被淘汰 -> .2 入 free_pool -> 第 5 个 FIFO 复用 .2。
        assert_eq!(vips[4], "10.144.144.2");
        // 最旧（static=[10]）已淘汰 -> 其预分配 VIP 已回池。
        let oldest_id = peer_id_from_public_key(&[10u8; 32]);
        assert!(
            !server
                .leases_snapshot(now)
                .iter()
                .any(|(id, _)| id == &oldest_id)
        );
        // 新节点（free_pool 已空）顺延取 .6。
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[99u8; 32]);
        let (r, _, _) =
            client_join_init(&mut server, "udp://other:1", &eph, &st, None, now).unwrap();
        assert_eq!(r.assigned_vip, "10.144.144.6");
    }

    // ---- G-01：目录 key 必须是 FNV(static_pub)，不能是自报 node_id ----

    #[test]
    fn g01_catalog_key_is_derived_not_self_reported() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        let expected_id = peer_id_from_public_key(st.public_key_bytes());
        let (r, k, cn) = client_join_init(&mut server, "udp://a:1", &eph, &st, None, now).unwrap();
        // 客户端自报 node_id 为 "spoofed-name"，服务端应忽略。
        client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "spoofed-name".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("ack");
        // 落盘租约里只有派生 id，绝不出现自报名。
        assert!(
            !server
                .leases_snapshot(now)
                .iter()
                .any(|(id, _)| id == "spoofed-name")
        );
        assert!(
            server
                .leases_snapshot(now)
                .iter()
                .any(|(id, _)| id == &expected_id)
        );
    }

    // ---- G-02：BadVip 负向（网络/广播/网段外）----

    #[test]
    fn g02_bad_vip_rejected_network_broadcast_out_of_range() {
        let mut server = make_server();
        let now = 1000u64;
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        // 网络地址 .0 -> BadVip -> Error 帧 -> None。
        assert!(
            client_join_init(
                &mut server,
                "udp://a:1",
                &eph,
                &st,
                Some("10.144.144.0"),
                now,
            )
            .is_none()
        );
        // 广播地址 .255。
        assert!(
            client_join_init(
                &mut server,
                "udp://a:1",
                &eph,
                &st,
                Some("10.144.144.255"),
                now,
            )
            .is_none()
        );
        // 网段外。
        assert!(
            client_join_init(&mut server, "udp://a:1", &eph, &st, Some("10.99.0.5"), now,)
                .is_none()
        );
    }

    // ---- G-05：new() 对服务端自身 VIP 也做网内/网络/广播校验 ----

    #[test]
    fn g05_new_rejects_bad_server_vip() {
        let identity = KeyPair::from_seed(&[9u8; 32]);
        let cfg = BootstrapServerConfig {
            cidr: "10.144.144.0/24".into(),
            lease_secs: 60,
            hb_interval_ms: 1,
            refresh_interval_ms: 2,
            server_vip: "10.144.144.255".into(), // 广播地址
            server_locator: "udp://x:1".into(),
            max_pending_per_src: 4,
        };
        assert!(
            BootstrapServer::new(identity, PSK.to_vec(), cfg, Box::new(MemCodec), None).is_err()
        );
    }

    // ---- W-01：presence 过期连带清 established，杜绝 stale 会话挡住孤儿 VIP 释放 ----

    #[test]
    fn w01_stale_established_removed_and_idle_replay_vip_reclaimed() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        let id = peer_id_from_public_key(st.public_key_bytes());
        let (r, k, cn) = client_join_init(&mut server, "udp://a:1", &eph, &st, None, now).unwrap();
        client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("ack");
        assert_eq!(server.established_session_count(), 1);
        // 推进过 lease(60s)：服务端每 tick 刷新自身（故 SELF 不过期）；presence 过期 -> 连带清 established + 释放 VIP。
        server.upsert_self_entry(now + 61);
        let report = server.sweep_expired(now + 61);
        assert!(report.expired.contains(&id));
        assert!(report.released_vips.contains(&id));
        assert_eq!(server.established_session_count(), 0);
        // 闲置节点重放同一 static_pub 建 pending（不发 Register）。
        server.upsert_self_entry(now + 61);
        let (r2, _, _) =
            client_join_init(&mut server, "udp://evil:1", &eph, &st, None, now + 61).unwrap();
        // 刚回收的 .2 被复用（证明 stale established 未挡住）。
        assert_eq!(r2.assigned_vip, "10.144.144.2");
        // 再超时 -> 该 prealloc VIP 同样回池。
        let rep2 = server.sweep_expired(now + 61 + 11);
        assert!(rep2.released_vips.contains(&id));
    }

    // ---- W-02：稳态 established 节点与服务端自身仍导出快照；prealloc 不导出 ----

    #[test]
    fn w02_snapshot_exports_alive_peer_and_self_only() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        let id = peer_id_from_public_key(st.public_key_bytes());
        let (r, k, cn) = client_join_init(&mut server, "udp://a:1", &eph, &st, None, now).unwrap();
        client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("ack");
        let snap = server.leases_snapshot(now);
        // 服务端自身 + 已认证节点都在快照里。
        assert!(snap.iter().any(|(n, _)| n == SELF_NODE_ID));
        assert!(snap.iter().any(|(n, _)| n == &id));
        // 再发一个 prealloc（未认证）src，其 owner 不进快照。
        let st2 = KeyPair::from_seed(&[5u8; 32]);
        let eph2 = KeyPair::from_seed(&[6u8; 32]);
        let id2 = peer_id_from_public_key(st2.public_key_bytes());
        let _ = client_join_init(&mut server, "udp://pre:1", &eph2, &st2, None, now);
        let snap2 = server.leases_snapshot(now);
        assert!(!snap2.iter().any(|(n, _)| n == &id2));
    }

    // ---- W-05：nonce 前缀不符的已认证密文帧被静默拒绝 ----

    #[test]
    fn w05_nonce_prefix_mismatch_rejected() {
        let mut server = make_server();
        let now = 1000u64;
        server.upsert_self_entry(now);
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[1u8; 32]);
        let (r, k, cn) = client_join_init(&mut server, "udp://a:1", &eph, &st, None, now).unwrap();
        client_send_ctrl(
            &mut server,
            "udp://a:1",
            &k,
            cn,
            r.server_nonce,
            &BootstrapCtrl::Register {
                node_id: "a".into(),
                virtual_ip: r.assigned_vip.clone(),
                locator: "".into(),
            },
            0,
            now,
        )
        .expect("ack");
        // 用正确会话密钥加密，但 nonce 前缀故意写错（client_nonce=0）。
        let inner = MemCodec
            .encode(&BootstrapCtrl::GetPeers {
                node_id: "a".into(),
            })
            .unwrap();
        let mut plain = Vec::new();
        plain.extend_from_slice(&0u64.to_be_bytes()); // 错 client_nonce
        plain.extend_from_slice(&r.server_nonce.to_be_bytes());
        plain.extend(inner);
        let blob = encrypt_frame(&k.tx, 1, &plain).unwrap();
        let mut dgram = Vec::new();
        dgram.extend_from_slice(NXB_MAGIC);
        dgram.extend_from_slice(&blob);
        // nonce 前缀不符 -> 静默 None。
        assert!(server.handle_datagram("udp://a:1", &dgram, now).is_none());
    }

    // ---- W-05：全局 pending 上限（1024）淘汰时，最旧 pending 的预分配 VIP 回池可复用 ----

    #[test]
    fn w05_global_pending_cap_eviction_releases_vip() {
        // /16 以容纳 >1024 个半开握手（/24 地址数不够）。
        let identity = KeyPair::from_seed(&[9u8; 32]);
        let cfg = BootstrapServerConfig {
            cidr: "10.144.0.0/16".into(),
            lease_secs: 60,
            hb_interval_ms: 1,
            refresh_interval_ms: 2,
            server_vip: "10.144.0.1".into(),
            server_locator: "udp://x:1".into(),
            max_pending_per_src: 4,
        };
        let mut server =
            BootstrapServer::new(identity, PSK.to_vec(), cfg, Box::new(MemCodec), None)
                .expect("server");
        let now = 1000u64;
        // 第 1 个 join：占 .2。
        let eph0 = KeyPair::from_seed(&[3u8; 32]);
        let st0 = KeyPair::from_seed(&[1u8; 32]);
        let first_id = peer_id_from_public_key(st0.public_key_bytes());
        let (r0, _, _) =
            client_join_init(&mut server, "udp://s0:1", &eph0, &st0, None, now).unwrap();
        assert_eq!(r0.assigned_vip, "10.144.0.2");
        // 再填 1023 个（每 src 不同、now 递增保证 s0 确定性最旧），总数恰达全局上限 1024，尚未淘汰。
        for i in 1..MAX_PENDING_GLOBAL as u32 {
            let eph = KeyPair::from_seed(&[3u8; 32]);
            let mut seed = [0u8; 32];
            seed[0..4].copy_from_slice(&i.to_be_bytes());
            let st = KeyPair::from_seed(&seed);
            let src = format!("udp://s{i}:1");
            let _ = client_join_init(&mut server, &src, &eph, &st, None, now + u64::from(i));
        }
        // 再来一个，触发全局淘汰（最旧 s0 的 .2 回池并被本次 FIFO 复用）。
        let eph = KeyPair::from_seed(&[3u8; 32]);
        let st = KeyPair::from_seed(&[99u8; 32]);
        let (r, _, _) =
            client_join_init(&mut server, "udp://overflow:1", &eph, &st, None, now + 2000).unwrap();
        assert_eq!(r.assigned_vip, "10.144.0.2");
        assert!(
            !server
                .leases_snapshot(now + 2000)
                .iter()
                .any(|(n, _)| n == &first_id)
        );
    }
}
