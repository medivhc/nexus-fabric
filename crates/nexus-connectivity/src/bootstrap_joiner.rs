//! Bootstrap 客户端入网（v2 §7.1，纯逻辑、注入时钟与 carrier）。
//!
//! `BootstrapJoiner` 按 server 顺序做 PSK 握手：发 JoinInit → 收 JoinReply →
//! 派生会话密钥 → 加密 Register → 收 RegisterAck → GetPeers → PeerList，
//! 交接出含密钥的 [`BootstrapSession`]。`connectivity` 不依赖 discovery——外层/内层
//! 字节编解码全部经由注入的 [`BootstrapFrameCodec`]。

use std::time::Duration;

use nexus_platform::PacketCarrier;

use crate::bootstrap_server::{
    BootstrapCtrl, BootstrapFrameCodec, BootstrapPeer, BootstrapServerError, JoinInitReq,
};
use crate::encryption::{
    DirectionalKeys, KeyPair, PUBLIC_KEY_LEN, ReplayWindow, decrypt_frame,
    derive_authed_keys_with_psk, encrypt_frame,
};

/// `nxb:` 外层 magic（与 discovery/bootstrap_server 同值；客户端上行也前置）。
const NXB_MAGIC: &[u8] = b"nxb:";
/// 收包缓冲上限。
const RECV_BUF: usize = 64 * 1024;
/// 非阻塞轮询步进（毫秒）。
const POLL_STEP_MS: u64 = 1;

/// 引导节点端点（连接信息；与 mesh.rs HTTP BootstrapConfig 区分，M13）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapEndpoint {
    /// 引导节点对外可达 locator（`udp://host:port`）。
    pub server_locator: String,
}

/// 已建立的客户端会话（含密钥与重放窗口；常驻心跳/刷新据此收发，v2 L13）。
#[derive(Debug)]
pub struct BootstrapSession {
    /// 会话密钥（客户端 tx 发 / rx 收）。
    pub keys: DirectionalKeys,
    /// 收方向防重放。
    pub rx_replay: ReplayWindow,
    /// 发方向下一个序号。
    pub tx_seq: u64,
    /// 引导节点 locator。
    pub server_locator: String,
    /// 服务端权威分配的本机 VIP。
    pub assigned_vip: String,
    /// 租约秒数。
    pub lease_secs: u32,
    /// 心跳间隔毫秒。
    pub hb_interval_ms: u32,
    /// PeerList 刷新间隔毫秒。
    pub refresh_interval_ms: u32,
    /// 最近心跳时刻（注入时钟，不用 Instant）。
    pub last_hb_at: u64,
    /// 最近一次刷新时刻。
    pub last_refresh_at: u64,
    /// 可观测性事件（结构化，最小）。
    pub events: Vec<String>,
    /// 客户端随机 nonce（与 server_nonce 绑定进 AEAD 明文前缀）。
    client_nonce: u64,
    /// 服务端随机 nonce。
    server_nonce: u64,
}

/// 单端点入网失败记录（locator, 原因）。
#[derive(Debug, Clone)]
pub struct BootstrapAttemptFailure {
    /// 尝试的引导节点 locator。
    pub locator: String,
    /// 失败原因（Display 文本）。
    pub reason: String,
}

/// 客户端入网错误（typed，禁止 panic）。
#[derive(Debug)]
#[non_exhaustive]
pub enum BootstrapJoinError {
    /// 未提供 PSK。
    PskRequired,
    /// PSK 认证失败。
    AuthFailed(String),
    /// 对端不是 bootstrap 服务。
    NotBootstrap,
    /// 收包超时（截止内无回复）。
    Timeout,
    /// 帧格式损坏。
    MalformedFrame(String),
    /// 申请 VIP 非法（致命，不切节点）。
    BadVip(String),
    /// 全部引导节点均失败（携带逐端原因）。
    AllBootstrapFailed(Vec<BootstrapAttemptFailure>),
    /// 底层 I/O。
    Io(String),
    /// 加密原语错误。
    Crypto(String),
}

impl core::fmt::Display for BootstrapJoinError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PskRequired => write!(f, "BOOTSTRAP_PSK_REQUIRED"),
            Self::AuthFailed(s) => write!(f, "BOOTSTRAP_AUTH_FAILED: {s}"),
            Self::NotBootstrap => write!(f, "BOOTSTRAP_NOT_BOOTSTRAP"),
            Self::Timeout => write!(f, "BOOTSTRAP_TIMEOUT"),
            Self::MalformedFrame(s) => write!(f, "BOOTSTRAP_MALFORMED: {s}"),
            Self::BadVip(s) => write!(f, "BOOTSTRAP_BAD_VIP: {s}"),
            Self::AllBootstrapFailed(rs) => {
                write!(f, "BOOTSTRAP_ALL_SERVERS_FAILED ({} attempt(s))", rs.len())
            }
            Self::Io(s) => write!(f, "BOOTSTRAP_IO: {s}"),
            Self::Crypto(s) => write!(f, "BOOTSTRAP_CRYPTO: {s}"),
        }
    }
}

impl std::error::Error for BootstrapJoinError {}

impl From<BootstrapServerError> for BootstrapJoinError {
    fn from(e: BootstrapServerError) -> Self {
        match e {
            BootstrapServerError::AuthFailed => Self::AuthFailed(String::new()),
            BootstrapServerError::BadVip(s) => Self::BadVip(s),
            BootstrapServerError::Malformed(s) => Self::MalformedFrame(s),
            BootstrapServerError::RateLimited => Self::Timeout,
            other => Self::MalformedFrame(other.to_string()),
        }
    }
}

/// 一次性入网握手器（借用 carrier/identity/psk/codec，无 I/O 线程）。
pub struct BootstrapJoiner<'a> {
    carrier: &'a mut dyn PacketCarrier,
    identity: &'a KeyPair,
    psk: &'a [u8],
    codec: &'a dyn BootstrapFrameCodec,
    /// 结构化可观测事件（成功/切节点/全失败/心跳/刷新）。
    events: Vec<String>,
}

impl<'a> BootstrapJoiner<'a> {
    /// 创建握手器。
    pub fn new(
        carrier: &'a mut dyn PacketCarrier,
        identity: &'a KeyPair,
        psk: &'a [u8],
        codec: &'a dyn BootstrapFrameCodec,
    ) -> Self {
        Self {
            carrier,
            identity,
            psk,
            codec,
            events: Vec::new(),
        }
    }

    /// 取出结构化事件（消耗后清空）。
    pub fn drain_events(&mut self) -> Vec<String> {
        std::mem::take(&mut self.events)
    }

    /// 按 endpoints 顺序尝试；AuthFailed/NotBootstrap/Timeout 切下一个，
    /// BadVip/Io/Crypto/Malformed/PskRequired 致命直接返回；
    /// 全部耗尽 -> [`BootstrapJoinError::AllBootstrapFailed`]（携带逐端原因）。
    pub fn join(
        &mut self,
        endpoints: &[BootstrapEndpoint],
        requested_vip: Option<&str>,
        now: u64,
        deadline_ms: u64,
    ) -> Result<(BootstrapSession, Vec<BootstrapPeer>), BootstrapJoinError> {
        if self.psk.is_empty() {
            return Err(BootstrapJoinError::PskRequired);
        }
        if endpoints.is_empty() {
            return Err(BootstrapJoinError::AllBootstrapFailed(Vec::new()));
        }
        let mut failures: Vec<BootstrapAttemptFailure> = Vec::new();
        for ep in endpoints {
            match self.try_join(ep, requested_vip, now, deadline_ms) {
                Ok(v) => {
                    self.events.push(format!(
                        "bootstrap.join.ok locator={} vip={}",
                        ep.server_locator, v.0.assigned_vip
                    ));
                    return Ok(v);
                }
                Err(
                    e @ (BootstrapJoinError::AuthFailed(_)
                    | BootstrapJoinError::NotBootstrap
                    | BootstrapJoinError::Timeout),
                ) => {
                    self.events.push(format!(
                        "bootstrap.join.failover locator={} reason={e}",
                        ep.server_locator
                    ));
                    failures.push(BootstrapAttemptFailure {
                        locator: ep.server_locator.clone(),
                        reason: e.to_string(),
                    });
                    continue;
                }
                // BadVip / Io / Crypto / Malformed 致命，直接上抛。
                Err(other) => return Err(other),
            }
        }
        self.events.push(format!(
            "bootstrap.join.all_failed attempts={}",
            failures.len()
        ));
        Err(BootstrapJoinError::AllBootstrapFailed(failures))
    }

    /// 与单个引导节点完成完整握手。
    fn try_join(
        &mut self,
        ep: &BootstrapEndpoint,
        requested_vip: Option<&str>,
        now: u64,
        deadline_ms: u64,
    ) -> Result<(BootstrapSession, Vec<BootstrapPeer>), BootstrapJoinError> {
        // M1：客户端临时 eph；client_nonce 取自 eph_pub 前 8 字节（完整 OS 熵）。
        let client_eph = KeyPair::generate()?;
        let eph_pub = *client_eph.public_key_bytes();
        let client_nonce = u64::from_be_bytes(eph_pub[0..8].try_into().unwrap_or([0u8; 8]));
        let req = JoinInitReq {
            eph_pub,
            static_pub: self.identity.public_key_bytes()[..PUBLIC_KEY_LEN]
                .try_into()
                .map_err(|_| BootstrapJoinError::Crypto("identity key len".into()))?,
            requested_vip: requested_vip.map(str::to_string),
            client_nonce,
        };
        let body = self.codec.encode_join_init(&req)?;
        let mut wire = Vec::with_capacity(NXB_MAGIC.len() + body.len());
        wire.extend_from_slice(NXB_MAGIC);
        wire.extend_from_slice(&body);
        self.carrier
            .send_to(&ep.server_locator, &wire)
            .map_err(|e| BootstrapJoinError::Io(e.to_string()))?;

        // M2：在 deadline 内有界轮询收 JoinReply（或 0x12 Error）。
        let reply_wire = self.recv_wire(deadline_ms)?;
        let payload = reply_wire
            .strip_prefix(NXB_MAGIC)
            .ok_or(BootstrapJoinError::NotBootstrap)?;
        // 只接受来自当前配置服务器的回包（W5：防伪造源触发切节点）。
        self.check_source(&ep.server_locator)?;
        // 0x12 Error 帧：按内码分流（R1）——RateLimited→切下一端；BadVip/VipConflict→致命；
        // 其余（含无内码）→ 视为认证/可达性失败切下一端。
        if payload.first() == Some(&0x12) {
            return match payload.get(1).copied() {
                Some(5) => Err(BootstrapJoinError::Timeout),
                Some(2) | Some(3) => Err(BootstrapJoinError::BadVip(
                    "server rejected requested vip".into(),
                )),
                _ => Err(BootstrapJoinError::AuthFailed(String::new())),
            };
        }
        let resp = self.codec.decode_join_reply(payload)?;

        // M3：派生会话密钥（initiator=true）。
        let keys = derive_authed_keys_with_psk(
            self.identity,
            &client_eph,
            &resp.static_pub,
            &resp.eph_pub,
            true,
            self.psk,
        )
        .map_err(|e| BootstrapJoinError::Crypto(e.to_string()))?;

        // M4：加密 Register（nonce 前缀绑定）。
        let my_id = crate::coord::peer_id_from_public_key(&req.static_pub);
        let reg = BootstrapCtrl::Register {
            node_id: my_id,
            virtual_ip: resp.assigned_vip.clone(),
            locator: String::new(),
        };
        self.send_ctrl(
            &ep.server_locator,
            &keys,
            client_nonce,
            resp.server_nonce,
            0,
            &reg,
        )?;

        // 收 RegisterAck（过 rx 重放窗口）。
        let mut replay = ReplayWindow::new();
        self.recv_auth_frame(
            &ep.server_locator,
            &keys,
            &mut replay,
            client_nonce,
            resp.server_nonce,
            deadline_ms,
        )?;

        // M5：GetPeers -> PeerList（rx 过同一重放窗口）。
        let peers = self.refresh_peers_raw(
            &ep.server_locator,
            &keys,
            &mut replay,
            client_nonce,
            resp.server_nonce,
            1,
            deadline_ms,
        )?;

        let sess = BootstrapSession {
            keys,
            rx_replay: replay,
            tx_seq: 2,
            server_locator: ep.server_locator.clone(),
            assigned_vip: resp.assigned_vip,
            lease_secs: resp.lease_secs,
            hb_interval_ms: resp.hb_interval_ms,
            refresh_interval_ms: resp.refresh_interval_ms,
            last_hb_at: now,
            last_refresh_at: now,
            events: Vec::new(),
            client_nonce,
            server_nonce: resp.server_nonce,
        };
        Ok((sess, peers))
    }

    /// 收一条已认证帧：strip magic → AEAD 解密 → 重放窗口 → nonce 绑定，返回 inner。
    fn recv_auth_frame(
        &mut self,
        expected_src: &str,
        keys: &DirectionalKeys,
        replay: &mut ReplayWindow,
        client_nonce: u64,
        server_nonce: u64,
        deadline_ms: u64,
    ) -> Result<Vec<u8>, BootstrapJoinError> {
        let wire = self.recv_wire(deadline_ms)?;
        self.check_source(expected_src)?;
        let payload = self.strip(&wire)?;
        let (seq, plain) = decrypt_frame(&keys.rx, payload)
            .map_err(|e| BootstrapJoinError::Crypto(e.to_string()))?;
        replay
            .check_and_accept(seq)
            .map_err(|e| BootstrapJoinError::Crypto(e.to_string()))?;
        self.check_nonce(&plain, client_nonce, server_nonce)?;
        Ok(plain[16..].to_vec())
    }

    /// 发一条已认证控制帧（nonce 前缀 + AEAD）。
    fn send_ctrl(
        &mut self,
        dst: &str,
        keys: &DirectionalKeys,
        client_nonce: u64,
        server_nonce: u64,
        seq: u64,
        ctrl: &BootstrapCtrl,
    ) -> Result<(), BootstrapJoinError> {
        let inner = self.codec.encode(ctrl)?;
        let mut plain = Vec::with_capacity(16 + inner.len());
        plain.extend_from_slice(&client_nonce.to_be_bytes());
        plain.extend_from_slice(&server_nonce.to_be_bytes());
        plain.extend(inner);
        let blob = encrypt_frame(&keys.tx, seq, &plain)
            .map_err(|e| BootstrapJoinError::Crypto(e.to_string()))?;
        let mut wire = Vec::with_capacity(NXB_MAGIC.len() + blob.len());
        wire.extend_from_slice(NXB_MAGIC);
        wire.extend_from_slice(&blob);
        self.carrier
            .send_to(dst, &wire)
            .map_err(|e| BootstrapJoinError::Io(e.to_string()))
    }

    /// 发 GetPeers 并收 PeerList（rx 过注入的重放窗口）。
    #[allow(clippy::too_many_arguments)]
    fn refresh_peers_raw(
        &mut self,
        dst: &str,
        keys: &DirectionalKeys,
        replay: &mut ReplayWindow,
        client_nonce: u64,
        server_nonce: u64,
        seq: u64,
        deadline_ms: u64,
    ) -> Result<Vec<BootstrapPeer>, BootstrapJoinError> {
        let gp = BootstrapCtrl::GetPeers {
            node_id: String::new(),
        };
        self.send_ctrl(dst, keys, client_nonce, server_nonce, seq, &gp)?;
        let inner =
            self.recv_auth_frame(dst, keys, replay, client_nonce, server_nonce, deadline_ms)?;
        match self.codec.decode(&inner)? {
            BootstrapCtrl::PeerList { peers } => Ok(peers),
            _ => Err(BootstrapJoinError::MalformedFrame(
                "expected PeerList".into(),
            )),
        }
    }

    /// 周期心跳。
    pub fn send_heartbeat(
        &mut self,
        s: &mut BootstrapSession,
        now: u64,
    ) -> Result<(), BootstrapJoinError> {
        let hb = BootstrapCtrl::Heartbeat {
            node_id: String::new(),
            now,
        };
        let seq = s.tx_seq;
        s.tx_seq += 1;
        self.send_ctrl(
            &s.server_locator,
            &s.keys,
            s.client_nonce,
            s.server_nonce,
            seq,
            &hb,
        )?;
        s.last_hb_at = now;
        self.events
            .push(format!("bootstrap.heartbeat locator={}", s.server_locator));
        Ok(())
    }

    /// 周期刷新 peer 列表，返回 (新 peers, 移除的 node_id)。
    pub fn refresh_peers(
        &mut self,
        s: &mut BootstrapSession,
        now: u64,
        deadline_ms: u64,
    ) -> Result<(Vec<BootstrapPeer>, Vec<String>), BootstrapJoinError> {
        let seq = s.tx_seq;
        s.tx_seq += 1;
        let mut replay = std::mem::take(&mut s.rx_replay);
        let peers = self.refresh_peers_raw(
            &s.server_locator,
            &s.keys,
            &mut replay,
            s.client_nonce,
            s.server_nonce,
            seq,
            deadline_ms,
        )?;
        s.rx_replay = replay;
        s.last_refresh_at = now;
        self.events.push(format!(
            "bootstrap.refresh locator={} peers={}",
            s.server_locator,
            peers.len()
        ));
        Ok((peers, Vec::new()))
    }

    // ---- 内部小工具 ----

    /// 有界轮询收包：非阻塞 receive_into 返回 0（WouldBlock）时按步进让出，
    /// 直到收到字节或耗尽 deadline_ms；超时返回 [`BootstrapJoinError::Timeout`]。
    fn recv_wire(&mut self, deadline_ms: u64) -> Result<Vec<u8>, BootstrapJoinError> {
        let mut buf = vec![0u8; RECV_BUF];
        let mut remaining = deadline_ms;
        loop {
            let n = self
                .carrier
                .receive_into(&mut buf)
                .map_err(|e| BootstrapJoinError::Io(e.to_string()))?;
            if n > 0 {
                return Ok(buf[..n].to_vec());
            }
            if remaining < POLL_STEP_MS {
                return Err(BootstrapJoinError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(POLL_STEP_MS));
            remaining -= POLL_STEP_MS;
        }
    }

    /// 校验最近一帧来源与所连服务器属于同一端点（R3：按 host:port 归一，
    /// 容忍 DNS 解析后 carrier 回报 IP:port 与配置 hostname:port 的差异）。
    fn check_source(&self, expected: &str) -> Result<(), BootstrapJoinError> {
        let Some(got) = self.carrier.last_peer_locator() else {
            return Ok(()); // 测试桩无来源信息时放行。
        };
        let norm = |l: &str| {
            let l = l.strip_prefix("udp://").unwrap_or(l);
            l.trim_end_matches('/').to_ascii_lowercase()
        };
        let split = |l: &str| -> (String, Option<u16>) {
            match l.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
                None => (l.to_string(), None),
            }
        };
        let (got_h, got_p) = split(&norm(&got));
        let (exp_h, exp_p) = split(&norm(expected));
        // T2：端口必须匹配；host 仅在「expected 与 actual 均为 IP 字面量且不等」时才拒。
        // expected host 为域名时跳过 host 相等判定（帧真实性由 PSK/AEAD 保证，而非源地址）。
        if let (Some(gp), Some(ep)) = (got_p, exp_p) {
            if gp != ep {
                return Err(BootstrapJoinError::MalformedFrame(format!(
                    "reply port {gp} != expected {ep}"
                )));
            }
        }
        let is_ip = |h: &str| h.parse::<std::net::IpAddr>().is_ok();
        if is_ip(&exp_h) && is_ip(&got_h) && exp_h != got_h {
            return Err(BootstrapJoinError::MalformedFrame(format!(
                "reply from unexpected ip {got_h} (want {exp_h})"
            )));
        }
        Ok(())
    }

    fn strip<'b>(&self, wire: &'b [u8]) -> Result<&'b [u8], BootstrapJoinError> {
        wire.strip_prefix(NXB_MAGIC)
            .ok_or(BootstrapJoinError::NotBootstrap)
    }

    fn check_nonce(
        &self,
        plain: &[u8],
        client_nonce: u64,
        server_nonce: u64,
    ) -> Result<(), BootstrapJoinError> {
        if plain.len() < 16
            || plain[0..8] != client_nonce.to_be_bytes()[..]
            || plain[8..16] != server_nonce.to_be_bytes()[..]
        {
            return Err(BootstrapJoinError::MalformedFrame("nonce prefix".into()));
        }
        Ok(())
    }
}

impl From<crate::encryption::EncryptionError> for BootstrapJoinError {
    fn from(e: crate::encryption::EncryptionError) -> Self {
        Self::Crypto(e.to_string())
    }
}

/// 客户端常驻 Bootstrap 钩子（v2 §6.4，S5）：挂在隧道上，持有已建立会话。
///
/// **不持有 carrier**——出站数据报放进 [`crate::virtual_subnet::BootstrapTick`]，
/// 由隧道 `send_raw` 代发；入站 secured 控制帧在 `on_control_datagram` 内解密处理。
pub struct ClientBootstrapHook {
    session: BootstrapSession,
    codec: Box<dyn BootstrapFrameCodec + Send>,
    /// 已知 peer（node_id -> peer）。
    known: std::collections::HashMap<String, BootstrapPeer>,
    /// 最近 PeerList 中消失、待本 tick 降级（不删除）的 node_id。
    pending_gone: Vec<String>,
}

impl ClientBootstrapHook {
    /// 入网成功后包装会话为常驻钩子。
    #[must_use]
    pub fn new(
        session: BootstrapSession,
        codec: Box<dyn BootstrapFrameCodec + Send>,
        initial_peers: Vec<BootstrapPeer>,
    ) -> Self {
        let mut known = std::collections::HashMap::new();
        for p in initial_peers {
            known.insert(p.node_id.clone(), p);
        }
        Self {
            session,
            codec,
            known,
            pending_gone: Vec::new(),
        }
    }

    /// 本端权威 VIP（供装配层写状态/打洞）。
    #[must_use]
    pub fn assigned_vip(&self) -> Option<&str> {
        Some(&self.session.assigned_vip)
    }

    /// 把一条已认证控制帧序列化成 nxb: 线（nonce 前缀 + AEAD）。
    fn build_wire(&mut self, ctrl: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapJoinError> {
        let inner = self.codec.encode(ctrl)?;
        let mut plain = Vec::with_capacity(16 + inner.len());
        plain.extend_from_slice(&self.session.client_nonce.to_be_bytes());
        plain.extend_from_slice(&self.session.server_nonce.to_be_bytes());
        plain.extend(inner);
        let seq = self.session.tx_seq;
        self.session.tx_seq += 1;
        let blob = encrypt_frame(&self.session.keys.tx, seq, &plain)
            .map_err(|e| BootstrapJoinError::Crypto(e.to_string()))?;
        let mut wire = Vec::with_capacity(NXB_MAGIC.len() + blob.len());
        wire.extend_from_slice(NXB_MAGIC);
        wire.extend_from_slice(&blob);
        Ok(wire)
    }
}

impl crate::virtual_subnet::BootstrapHook for ClientBootstrapHook {
    fn on_control_datagram(
        &mut self,
        _src: Option<&str>,
        payload: &[u8],
        _now: u64,
    ) -> Option<(String, Vec<u8>)> {
        // 仅处理 AEAD secured 帧（首字节 0x01）。
        if payload.first() != Some(&0x01) {
            return None;
        }
        let (seq, plain) = decrypt_frame(&self.session.keys.rx, payload).ok()?;
        self.session.rx_replay.check_and_accept(seq).ok()?;
        if plain.len() < 16
            || plain[0..8] != self.session.client_nonce.to_be_bytes()[..]
            || plain[8..16] != self.session.server_nonce.to_be_bytes()[..]
        {
            return None;
        }
        let inner = &plain[16..];
        match self.codec.decode(inner).ok()? {
            BootstrapCtrl::PeerList { peers } => {
                // W-GONE：用最新 PeerList 全量替换 known；缺失的旧 node_id 填 pending_gone
                // （仅降级，不删隧道 peer）。
                let new_ids: std::collections::HashSet<String> =
                    peers.iter().map(|p| p.node_id.clone()).collect();
                for old in self.known.keys() {
                    if !new_ids.contains(old) {
                        self.pending_gone.push(old.clone());
                    }
                }
                self.known.clear();
                for p in peers {
                    self.known.insert(p.node_id.clone(), p);
                }
                None
            }
            // RegisterAck / Heartbeat 响应： solicited，无需回包。
            _ => None,
        }
    }

    fn periodic(&mut self, now: u64) -> crate::virtual_subnet::BootstrapTick {
        // W-GONE：上一 PeerList 缺失节点，本 tick 降级（不删）。
        let peers_gone = std::mem::take(&mut self.pending_gone);
        // T4：取出累积事件返回，避免无界增长。
        let events = std::mem::take(&mut self.session.events);
        let mut tick = crate::virtual_subnet::BootstrapTick {
            peers_gone,
            events,
            ..Default::default()
        };
        let hb_secs = self.session.hb_interval_ms as u64 / 1000;
        let rf_secs = self.session.refresh_interval_ms as u64 / 1000;
        // 心跳到期。
        if now.saturating_sub(self.session.last_hb_at) >= hb_secs.max(1) {
            let ctrl = BootstrapCtrl::Heartbeat {
                node_id: String::new(),
                now,
            };
            match self.build_wire(&ctrl) {
                Ok(wire) => {
                    tick.datagrams
                        .push((self.session.server_locator.clone(), wire));
                    self.session.last_hb_at = now;
                }
                Err(e) => self
                    .session
                    .events
                    .push(format!("bootstrap.hb_encode_failed: {e}")),
            }
        }
        // PeerList 刷新到期。
        if now.saturating_sub(self.session.last_refresh_at) >= rf_secs.max(1) {
            let ctrl = BootstrapCtrl::GetPeers {
                node_id: String::new(),
            };
            match self.build_wire(&ctrl) {
                Ok(wire) => {
                    tick.datagrams
                        .push((self.session.server_locator.clone(), wire));
                    self.session.last_refresh_at = now;
                    // 新发现节点（尚未在隧道 peer 表）交回 mesh 打洞。
                    tick.peers_added = self.known.values().cloned().collect();
                }
                Err(e) => self
                    .session
                    .events
                    .push(format!("bootstrap.refresh_encode_failed: {e}")),
            }
        }
        tick
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_server::{BootstrapOuterCode, JoinReplyResp, OuterKind};
    use crate::encryption::KeyPair;
    use nexus_platform::PacketCarrier;

    /// 内存 carrier：可脚本化前 N 次 Ok(0)、之后回队列入站帧；记录发出帧与最后来源。
    struct MemCarrier {
        inbox: std::collections::VecDeque<Vec<u8>>,
        drained_first: u32,
        drained_target: u32,
        sent: Vec<(String, Vec<u8>)>,
        last_src: Option<String>,
    }

    impl PacketCarrier for MemCarrier {
        fn bind(&mut self, _l: &str) -> Result<String, nexus_platform::PlatformError> {
            Ok("udp://test:1".into())
        }
        fn send_to(
            &mut self,
            peer: &str,
            frame: &[u8],
        ) -> Result<(), nexus_platform::PlatformError> {
            self.sent.push((peer.to_string(), frame.to_vec()));
            Ok(())
        }
        fn receive_into(&mut self, out: &mut [u8]) -> Result<usize, nexus_platform::PlatformError> {
            if self.drained_first < self.drained_target {
                self.drained_first += 1;
                return Ok(0); // 模拟 WouldBlock。
            }
            match self.inbox.pop_front() {
                Some(b) => {
                    let n = b.len().min(out.len());
                    out[..n].copy_from_slice(&b[..n]);
                    self.last_src = Some("udp://s1:1".into());
                    Ok(n)
                }
                None => Ok(0),
            }
        }
        fn local_locator(&self) -> Option<String> {
            Some("udp://local:1".into())
        }
        fn last_peer_locator(&self) -> Option<String> {
            self.last_src.clone()
        }
    }

    /// 极简 codec：encode_join_init 可用，其余在全失败用例不触发（畸形输入 typed Err）。
    struct JCodec;
    impl BootstrapFrameCodec for JCodec {
        fn encode(&self, _f: &BootstrapCtrl) -> Result<Vec<u8>, BootstrapServerError> {
            Ok(Vec::new())
        }
        fn decode(&self, b: &[u8]) -> Result<BootstrapCtrl, BootstrapServerError> {
            if b.is_empty() {
                return Err(BootstrapServerError::Malformed("empty".into()));
            }
            Err(BootstrapServerError::Malformed("unused".into()))
        }
        fn decode_join_init(&self, _p: &[u8]) -> Result<JoinInitReq, BootstrapServerError> {
            Err(BootstrapServerError::Malformed("unused".into()))
        }
        fn encode_join_reply(&self, _r: &JoinReplyResp) -> Result<Vec<u8>, BootstrapServerError> {
            Err(BootstrapServerError::Malformed("unused".into()))
        }
        fn encode_error(
            &self,
            _c: BootstrapOuterCode,
            _m: &str,
        ) -> Result<Vec<u8>, BootstrapServerError> {
            Err(BootstrapServerError::Malformed("unused".into()))
        }
        fn split_outer<'a>(&self, _p: &'a [u8]) -> Result<OuterKind<'a>, BootstrapServerError> {
            Err(BootstrapServerError::Malformed("unused".into()))
        }
        fn encode_join_init(&self, req: &JoinInitReq) -> Result<Vec<u8>, BootstrapServerError> {
            if req.static_pub.is_empty() || req.eph_pub.is_empty() {
                return Err(BootstrapServerError::Malformed("empty keys".into()));
            }
            let mut out = Vec::new();
            out.extend_from_slice(&req.eph_pub);
            out.extend_from_slice(&req.static_pub);
            Ok(out)
        }
        fn decode_join_reply(&self, _b: &[u8]) -> Result<JoinReplyResp, BootstrapServerError> {
            Err(BootstrapServerError::Malformed("unused".into()))
        }
    }

    #[test]
    fn all_bootstrap_servers_failed_returns_typed_error() {
        let mut carrier = MemCarrier {
            inbox: std::collections::VecDeque::new(),
            drained_first: 0,
            drained_target: 0,
            sent: Vec::new(),
            last_src: None,
        };
        let identity = KeyPair::from_seed(&[1u8; 32]);
        let codec = JCodec;
        let mut joiner = BootstrapJoiner::new(&mut carrier, &identity, b"psk", &codec);
        let eps = vec![
            BootstrapEndpoint {
                server_locator: "udp://s1:1".into(),
            },
            BootstrapEndpoint {
                server_locator: "udp://s2:1".into(),
            },
        ];
        let err = joiner.join(&eps, None, 1000, 5).unwrap_err();
        match err {
            BootstrapJoinError::AllBootstrapFailed(rs) => {
                assert_eq!(rs.len(), 2);
            }
            other => panic!("expected AllBootstrapFailed, got {other}"),
        }
        // 两端都被尝试过（都发出了 JoinInit）。
        assert_eq!(carrier.sent.len(), 2);
    }

    #[test]
    fn recv_wire_succeeds_after_wouldblock_polls() {
        // B1：前两次 receive_into 返回 Ok(0)（WouldBlock），第三次才入队回复——
        // 有界轮询应继续等待并最终取到帧，而非立即 Timeout。
        let mut carrier = MemCarrier {
            inbox: std::collections::VecDeque::from([b"nxb:REPLY".to_vec()]),
            drained_first: 0,
            drained_target: 2,
            sent: Vec::new(),
            last_src: None,
        };
        let identity = KeyPair::from_seed(&[1u8; 32]);
        let codec = JCodec;
        let mut joiner = BootstrapJoiner::new(&mut carrier, &identity, b"psk", &codec);
        let wire = joiner
            .recv_wire(500)
            .expect("should get reply after wouldblock");
        assert_eq!(&wire, b"nxb:REPLY");
    }

    #[test]
    fn recv_wire_times_out_when_no_data() {
        // 始终无数据：耗尽 deadline 返回 Timeout（有界，不空转）。
        let mut carrier = MemCarrier {
            inbox: std::collections::VecDeque::new(),
            drained_first: 0,
            drained_target: 0,
            sent: Vec::new(),
            last_src: None,
        };
        let identity = KeyPair::from_seed(&[1u8; 32]);
        let codec = JCodec;
        let mut joiner = BootstrapJoiner::new(&mut carrier, &identity, b"psk", &codec);
        let err = joiner.recv_wire(2).unwrap_err();
        assert!(matches!(err, BootstrapJoinError::Timeout));
    }

    #[test]
    fn empty_psk_is_rejected_without_io() {
        let mut carrier = MemCarrier {
            inbox: std::collections::VecDeque::new(),
            drained_first: 0,
            drained_target: 0,
            sent: Vec::new(),
            last_src: None,
        };
        let identity = KeyPair::from_seed(&[1u8; 32]);
        let codec = JCodec;
        let mut joiner = BootstrapJoiner::new(&mut carrier, &identity, b"", &codec);
        let eps = [BootstrapEndpoint {
            server_locator: "udp://s1:1".into(),
        }];
        let err = joiner.join(&eps, None, 1000, 5).unwrap_err();
        assert!(matches!(err, BootstrapJoinError::PskRequired));
        // 空 PSK 守卫在发任何帧之前。
        assert!(carrier.sent.is_empty());
    }
    #[test]
    fn t2_check_source_domain_expected_ip_actual_is_allowed() {
        let mut carrier = MemCarrier {
            inbox: std::collections::VecDeque::new(),
            drained_first: 0,
            drained_target: 0,
            sent: Vec::new(),
            // carrier 回报解析后的 IP:port；配置为域名。
            last_src: Some("udp://203.0.113.9:11010".into()),
        };
        let identity = KeyPair::from_seed(&[1u8; 32]);
        let joiner = BootstrapJoiner::new(&mut carrier, &identity, b"psk", &JCodec);
        // expected host 为域名 → 跳过 host 相等判定，仅校验端口。
        assert!(
            joiner
                .check_source("udp://bootstrap.example.internal:11010")
                .is_ok()
        );
    }

    #[test]
    fn t2_check_source_ip_literal_mismatch_is_rejected() {
        let mut carrier = MemCarrier {
            inbox: std::collections::VecDeque::new(),
            drained_first: 0,
            drained_target: 0,
            sent: Vec::new(),
            last_src: Some("udp://203.0.113.9:11010".into()),
        };
        let identity = KeyPair::from_seed(&[1u8; 32]);
        let joiner = BootstrapJoiner::new(&mut carrier, &identity, b"psk", &JCodec);
        // 两端都是 IP 字面量且不等 → 拒绝。
        assert!(joiner.check_source("udp://198.51.100.7:11010").is_err());
        // 端口不等也拒。
        assert!(joiner.check_source("udp://203.0.113.9:9999").is_err());
    }
}
