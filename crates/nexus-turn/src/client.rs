//! TURN client（RFC 5766 §2）：Allocate / CreatePermission / ChannelBind /
//! Refresh + 长效认证。同步阻塞 API（T5）。
//!
//! 并发模型：`TurnClient` 为 `Clone`（内部 `Arc<Mutex<…>>`）；控制面操作
//! （allocate/permission/channel/refresh）与数据面（`TurnSocket`）共享同一
//! UDP socket。同一时刻只应有一个线程做控制面事务（E4 即如此）；socket 的
//! read timeout 为共享状态，跨线程混用控制/数据操作时以最后一次设置为准。

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};
use std::time::{Duration, Instant};

use crate::auth::{derive_key, stamp_integrity, verify_integrity};
use crate::stun::{
    self, is_channel_data, is_stun_message, valid_channel, Attribute, StunMessage,
    ALLOCATE_REQUEST, ALLOCATE_SUCCESS, ATTR_DATA, ATTR_ERROR_CODE, ATTR_LIFETIME, ATTR_NONCE,
    ATTR_REALM, ATTR_XOR_MAPPED_ADDRESS, ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS,
    CHANNEL_BIND_REQUEST, CHANNEL_BIND_SUCCESS, CREATE_PERMISSION_FAILURE,
    CREATE_PERMISSION_REQUEST, CREATE_PERMISSION_SUCCESS, DATA_INDICATION, REFRESH_REQUEST,
    REFRESH_SUCCESS, SEND_INDICATION,
};

/// TURN 长效认证凭证。
#[derive(Debug, Clone)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub realm: String,
}

/// Client 侧计数器快照（见 MODULE.md Observability）。
#[derive(Debug, Clone, Default)]
pub struct TurnStats {
    pub allocations: u64,
    pub refreshed: u64,
    pub unauthorized_dropped: u64,
    pub relayed_bytes: u64,
    pub allocation_expired: u64,
}

#[derive(Debug, Default)]
struct AtomicStats {
    allocations: AtomicU64,
    refreshed: AtomicU64,
    unauthorized_dropped: AtomicU64,
    relayed_bytes: AtomicU64,
    allocation_expired: AtomicU64,
}

impl AtomicStats {
    fn snapshot(&self) -> TurnStats {
        TurnStats {
            allocations: self.allocations.load(Ordering::Relaxed),
            refreshed: self.refreshed.load(Ordering::Relaxed),
            unauthorized_dropped: self.unauthorized_dropped.load(Ordering::Relaxed),
            relayed_bytes: self.relayed_bytes.load(Ordering::Relaxed),
            allocation_expired: self.allocation_expired.load(Ordering::Relaxed),
        }
    }
}

/// RFC 5766 默认分配生命期。
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);
const ALLOCATE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

struct ClientInner {
    sock: UdpSocket,
    creds: TurnCredentials,
    key: [u8; 16],
    nonce: Option<String>,
    relayed: SocketAddr,
    /// 服务器观察到的本端 reflexive 地址（Allocate 响应的 XOR-MAPPED-ADDRESS，
    /// 打洞候选地址来源；NAT 后的真实出口）。
    mapped: Option<SocketAddr>,
    expires_at: Instant,
    permissions: HashSet<SocketAddr>,
    channels: HashMap<SocketAddr, u16>,
    next_channel: u16,
    /// 收到的、尚未被 `TurnSocket::recv_from` 取走的 Data indication。
    pending_data: VecDeque<(Vec<u8>, SocketAddr)>,
    stats: AtomicStats,
}

/// TURN client 句柄（`Clone` 为浅拷贝，共享同一分配）。
#[derive(Clone)]
pub struct TurnClient {
    inner: Arc<Mutex<ClientInner>>,
}

impl TurnClient {
    fn lock(&self) -> io::Result<MutexGuard<'_, ClientInner>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("turn client lock poisoned"))
    }

    /// 在 `server` 上分配中继地址（兼容入口；等价 `allocate_bound(.., 127.0.0.1:0)`）。
    pub fn allocate(server: SocketAddr, creds: TurnCredentials) -> io::Result<TurnClient> {
        Self::allocate_bound(server, creds, "127.0.0.1:0".parse().unwrap())
    }

    /// 在 `server` 上分配中继地址（生产用 `local_bind = 0.0.0.0:0`）。
    pub fn allocate_bound(
        server: SocketAddr,
        creds: TurnCredentials,
        local_bind: SocketAddr,
    ) -> io::Result<TurnClient> {
        let sock = UdpSocket::bind(local_bind)?;
        // Server 的所有消息（响应 + Data indication）都来自主 socket，
        // connect 后可用 recv/send 简化收发。
        sock.connect(server)?;
        let key = derive_key(&creds.username, &creds.realm, &creds.password);
        let client = TurnClient {
            inner: Arc::new(Mutex::new(ClientInner {
                sock,
                creds,
                key,
                nonce: None,
                relayed: "127.0.0.1:0".parse().unwrap(),
                mapped: None,
                expires_at: Instant::now(),
                permissions: HashSet::new(),
                channels: HashMap::new(),
                next_channel: 0x4000,
                pending_data: VecDeque::new(),
                stats: AtomicStats::default(),
            })),
        };
        client.allocate_once()?;
        Ok(client)
    }

    fn allocate_once(&self) -> io::Result<()> {
        let req = StunMessage::new(ALLOCATE_REQUEST)
            .attr(Attribute::RequestedTransport(17))
            .attr(Attribute::Lifetime(DEFAULT_LIFETIME.as_secs() as u32));
        let mut inner = self.lock()?;
        let resp = inner.transact(req, ALLOCATE_TIMEOUT)?;
        let resp = if is_error(&resp, 4, 1) {
            // 401：提取 REALM/NONCE，带认证重发（RFC 5766 §2.2）。
            let (realm, nonce) = realm_nonce(&resp)?;
            inner.nonce = Some(nonce);
            // realm 以 server 下发的为准（通常与配置一致）。
            inner.creds.realm = realm;
            inner.key = derive_key(
                &inner.creds.username,
                &inner.creds.realm,
                &inner.creds.password,
            );
            let req2 = StunMessage::new(ALLOCATE_REQUEST)
                .attr(Attribute::RequestedTransport(17))
                .attr(Attribute::Lifetime(DEFAULT_LIFETIME.as_secs() as u32));
            inner.transact(req2, ALLOCATE_TIMEOUT)?
        } else {
            resp
        };
        if resp.msg_type != ALLOCATE_SUCCESS {
            return Err(unexpected(&resp, "allocate"));
        }
        let relayed = match resp.get(ATTR_XOR_RELAYED_ADDRESS) {
            Some(Attribute::XorRelayedAddress(a)) => *a,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "allocate: no relayed address",
                ))
            }
        };
        let lifetime = match resp.get(ATTR_LIFETIME) {
            Some(Attribute::Lifetime(s)) => Duration::from_secs(*s as u64),
            _ => DEFAULT_LIFETIME,
        };
        inner.relayed = relayed;
        inner.mapped = match resp.get(ATTR_XOR_MAPPED_ADDRESS) {
            Some(Attribute::XorMappedAddress(a)) => Some(*a),
            _ => None,
        };
        inner.expires_at = Instant::now() + lifetime;
        inner.stats.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// 为 `peer` 创建权限（T3）。成功后 `TurnSocket::send_to` 才允许发往该对端。
    pub fn create_permission(&self, peer: SocketAddr) -> io::Result<()> {
        let req = StunMessage::new(CREATE_PERMISSION_REQUEST).attr(Attribute::XorPeerAddress(peer));
        let mut inner = self.lock()?;
        let resp = inner.transact(req, REQUEST_TIMEOUT)?;
        if resp.msg_type == CREATE_PERMISSION_FAILURE {
            return Err(unexpected(&resp, "create-permission"));
        }
        if resp.msg_type != CREATE_PERMISSION_SUCCESS {
            return Err(unexpected(&resp, "create-permission"));
        }
        inner.permissions.insert(peer);
        Ok(())
    }

    /// 为 `peer` 绑定通道（T3），返回 channel number（0x4000 起）。
    ///
    /// 已绑定则直接返回原 number。Server 拒绝时不记录绑定并返回尝试的
    /// number；`TurnSocket::send_to` 以绑定表为准，未记录的绑定会自动
    /// 回退到 Send indication（不静默黑洞）。
    pub fn bind_channel(&self, peer: SocketAddr) -> u16 {
        let mut inner = match self.lock() {
            Ok(g) => g,
            Err(_) => return 0x4000,
        };
        if let Some(&ch) = inner.channels.get(&peer) {
            return ch;
        }
        let ch = inner.next_channel;
        // channel 空间耗尽时回绕（实战中不会发生；E4 只用 1 个）。
        inner.next_channel = if ch == 0x7FFF { 0x4000 } else { ch + 1 };
        let req = StunMessage::new(CHANNEL_BIND_REQUEST)
            .attr(Attribute::ChannelNumber(ch))
            .attr(Attribute::XorPeerAddress(peer));
        let ok = match inner.transact(req, REQUEST_TIMEOUT) {
            Ok(resp) => resp.msg_type == CHANNEL_BIND_SUCCESS,
            Err(_) => false,
        };
        if ok {
            debug_assert!(valid_channel(ch));
            inner.channels.insert(peer, ch);
        }
        // 失败也不记录：send_to 回退到 Send indication。
        ch
    }

    /// 续租分配（T4）。失败 → 分配标记为过期（后续收发显式报错）。
    pub fn refresh(&self) -> io::Result<()> {
        let req = StunMessage::new(REFRESH_REQUEST)
            .attr(Attribute::Lifetime(DEFAULT_LIFETIME.as_secs() as u32));
        let mut inner = self.lock()?;
        let resp = match inner.transact(req, REQUEST_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                inner.expires_at = Instant::now();
                inner
                    .stats
                    .allocation_expired
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        if resp.msg_type != REFRESH_SUCCESS {
            inner.expires_at = Instant::now();
            inner
                .stats
                .allocation_expired
                .fetch_add(1, Ordering::Relaxed);
            return Err(unexpected(&resp, "refresh"));
        }
        let lifetime = match resp.get(ATTR_LIFETIME) {
            Some(Attribute::Lifetime(s)) => Duration::from_secs(*s as u64),
            _ => DEFAULT_LIFETIME,
        };
        inner.expires_at = Instant::now() + lifetime;
        inner.stats.refreshed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Delete the allocation (RFC 5766 §7.3): Refresh with LIFETIME = 0.
    /// Best-effort: returns Err on transport failure; the server will
    /// additionally expire the allocation on its own timer.
    pub fn deallocate(&self) -> io::Result<()> {
        let req = StunMessage::new(REFRESH_REQUEST).attr(Attribute::Lifetime(0));
        let mut inner = self.lock()?;
        let resp = match inner.transact(req, REQUEST_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                inner.expires_at = Instant::now();
                inner
                    .stats
                    .allocation_expired
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        if resp.msg_type != REFRESH_SUCCESS {
            inner.expires_at = Instant::now();
            inner
                .stats
                .allocation_expired
                .fetch_add(1, Ordering::Relaxed);
            return Err(unexpected(&resp, "refresh"));
        }
        // LIFETIME=0 成功：分配已删除，标记为立即过期（不续租）。
        inner.expires_at = Instant::now();
        Ok(())
    }

    /// 中继分配地址（`TurnSocket::local_addr` 与 E4 拨号目标用它）。
    pub fn relayed_addr(&self) -> SocketAddr {
        self.lock()
            .map(|g| g.relayed)
            .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap())
    }

    /// 服务器观察到的本端 reflexive 地址（打洞候选）。
    /// 无映射信息时返回 `None`（直连/旧服务端）。
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.lock().map(|g| g.mapped).unwrap_or(None)
    }

    /// 计数器快照。
    pub fn stats(&self) -> TurnStats {
        self.lock().map(|g| g.stats.snapshot()).unwrap_or_default()
    }

    /// 分配是否已过期（T4）。
    pub fn is_expired(&self) -> bool {
        self.lock().map(|g| g.is_expired()).unwrap_or(true)
    }

    /// 经中继发送一个数据报（T6）：权限检查 → ChannelData/Send → 直连 server。
    ///
    /// 整个操作在 client 锁内完成；`send` 本身非阻塞，持锁时间短。
    /// 返回载荷字节数（wire 上的 ChannelData 头/Send 属性开销不计入）。
    pub(crate) fn send_via_relay(&self, target: SocketAddr, payload: &[u8]) -> io::Result<usize> {
        let g = self.lock()?;
        if g.is_expired() {
            g.stats.allocation_expired.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "turn allocation expired",
            ));
        }
        if !g.permissions.contains(&target) {
            g.stats.unauthorized_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "turn: send to unauthorized peer",
            ));
        }
        let wire = match g.channels.get(&target) {
            Some(&ch) => {
                let mut v = Vec::with_capacity(4 + payload.len());
                crate::stun::encode_channel_data(ch, payload, &mut v);
                v
            }
            None => encode_send_indication(target, payload),
        };
        g.sock.send(&wire)?;
        g.stats
            .relayed_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(payload.len())
    }

    /// 经中继接收一个数据报（T6）：返回（载荷，真实对端）。
    ///
    /// 持锁做阻塞 `recv`（socket 的 read timeout 由调用方通过
    /// `set_read_timeout` 控制，与 `UdpSocket` 语义一致）；期间控制面
    /// 操作会等待，见模块文档并发模型。
    pub(crate) fn recv_via_relay(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut g = self.lock()?;
        if g.is_expired() {
            g.stats.allocation_expired.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "turn allocation expired",
            ));
        }
        if let Some((data, peer)) = g.pending_data.pop_front() {
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            g.stats.relayed_bytes.fetch_add(n as u64, Ordering::Relaxed);
            return Ok((n, peer));
        }
        loop {
            let n = g.sock.recv(buf)?;
            // ChannelData 分支：先以不可变借用解析出 (长度, peer)，再移位。
            let ch_decoded: Option<(usize, SocketAddr)> = {
                let raw = &buf[..n];
                match crate::stun::parse_channel_data(raw) {
                    Some((channel, data)) => {
                        let peer = g
                            .channels
                            .iter()
                            .find_map(|(p, &c)| (c == channel).then_some(*p));
                        peer.map(|p| (data.len().min(buf.len()), p))
                    }
                    None => None,
                }
            };
            if let Some((m, peer)) = ch_decoded {
                buf.copy_within(4..4 + m, 0);
                g.stats.relayed_bytes.fetch_add(m as u64, Ordering::Relaxed);
                return Ok((m, peer));
            }
            let raw = &buf[..n];
            if crate::stun::is_channel_data(raw) {
                continue; // 未知通道：丢弃（server 不应发送）
            }
            let d = stun::decode(raw)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad stun message"))?;
            if d.msg_type != DATA_INDICATION {
                continue; // 控制面响应：在 transact 循环外出现则丢弃
            }
            match (d.get(ATTR_DATA), d.get(ATTR_XOR_PEER_ADDRESS)) {
                (Some(Attribute::Data(data)), Some(Attribute::XorPeerAddress(peer))) => {
                    let m = data.len().min(buf.len());
                    buf[..m].copy_from_slice(&data[..m]);
                    g.stats.relayed_bytes.fetch_add(m as u64, Ordering::Relaxed);
                    return Ok((m, *peer));
                }
                _ => continue,
            }
        }
    }

    pub(crate) fn sock_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        let g = self.lock()?;
        g.sock.set_read_timeout(timeout)
    }

    /// 测试钩子：经直连 socket 向 server 裸发字节（绕过权限/通道检查，
    /// 用于 server 侧行为测试；生产路径不用）。
    #[cfg(test)]
    pub(crate) fn send_raw_to_server(&self, bytes: &[u8]) -> io::Result<usize> {
        let g = self.lock()?;
        g.sock.send(bytes)
    }
}

impl ClientInner {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// 带认证编码请求：USERNAME/REALM/NONCE/MI（MI 末位，回填）。
    /// 无 nonce（首轮）时原样编码。
    fn encode_request(&self, msg: &StunMessage) -> Vec<u8> {
        let nonce = match &self.nonce {
            Some(n) => n.clone(),
            None => return msg.encode(),
        };
        let mut m = StunMessage {
            msg_type: msg.msg_type,
            txn: msg.txn,
            attrs: msg.attrs.clone(),
        };
        m.attrs
            .push(Attribute::Username(self.creds.username.as_bytes().to_vec()));
        m.attrs
            .push(Attribute::Realm(self.creds.realm.as_bytes().to_vec()));
        m.attrs.push(Attribute::Nonce(nonce.into_bytes()));
        m.attrs.push(Attribute::MessageIntegrity([0u8; 20]));
        let mut bytes = m.encode();
        // MI 是最后一个属性：值偏移 = 尾部 20 字节起点。
        let mi_off = bytes.len() - 20;
        debug_assert_eq!(&bytes[mi_off - 4..mi_off], &[0x00, 0x08, 0x00, 0x14]);
        stamp_integrity(&mut bytes, mi_off, &self.key);
        bytes
    }

    /// 发送请求并等待匹配 txn 的响应；Data indication 暂存，无关响应按 txn 丢弃。
    fn transact(
        &mut self,
        msg: StunMessage,
        timeout: Duration,
    ) -> io::Result<stun::DecodedMessage> {
        let bytes = self.encode_request(&msg);
        let deadline = Instant::now() + timeout;
        self.sock.send(&bytes)?;
        let mut buf = vec![0u8; 65535];
        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "turn request timed out",
                ));
            }
            self.sock
                .set_read_timeout(Some(remain.min(Duration::from_secs(1))))?;
            let n = match self.sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(e) => return Err(e),
            };
            let raw = &buf[..n];
            if is_channel_data(raw) {
                continue; // 控制面不处理 ChannelData
            }
            if !is_stun_message(raw) {
                continue;
            }
            let d = stun::decode(raw)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad stun message"))?;
            if d.txn == msg.txn {
                // RFC 5766 §2.2: 验证响应的 MESSAGE-INTEGRITY（401 质询无 MI，跳过）。
                if !is_error(&d, 4, 1) && !verify_response_integrity(raw, &self.key) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "turn response integrity check failed",
                    ));
                }
                return Ok(d);
            }
            if d.msg_type == DATA_INDICATION {
                if let (Some(Attribute::Data(data)), Some(Attribute::XorPeerAddress(peer))) =
                    (d.get(ATTR_DATA), d.get(ATTR_XOR_PEER_ADDRESS))
                {
                    let peer = *peer;
                    self.pending_data.push_back((data.clone(), peer));
                }
            }
            // 其他无关响应：按 txn 丢弃（本实现同一时刻只有一个在途事务）。
        }
    }
}

/// 是否为 class/number 的错误响应。
fn is_error(d: &stun::DecodedMessage, class: u8, number: u8) -> bool {
    matches!(d.get(ATTR_ERROR_CODE), Some(Attribute::ErrorCode(c, n, _)) if *c == class && *n == number)
}

/// 验证 server 响应的 MESSAGE-INTEGRITY（RFC 5766 §2.2）。
///
/// 约定：server 总把 MI 作为最后一个属性（见 `server::send_success`/`send_error`），
/// 故 MI 值在数据报尾部 20 字节，前面是属性头 `00 08 00 14`。
fn verify_response_integrity(raw: &[u8], key: &[u8]) -> bool {
    if raw.len() < 24 {
        return false;
    }
    let mi_off = raw.len() - 20;
    if raw[mi_off - 4..mi_off] != [0x00, 0x08, 0x00, 0x14] {
        return false;
    }
    verify_integrity(raw, mi_off, key)
}

fn realm_nonce(d: &stun::DecodedMessage) -> io::Result<(String, String)> {
    let realm = match d.get(ATTR_REALM) {
        Some(Attribute::Realm(v)) => String::from_utf8(v.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad realm"))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "401 without realm",
            ))
        }
    };
    let nonce = match d.get(ATTR_NONCE) {
        Some(Attribute::Nonce(v)) => String::from_utf8(v.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad nonce"))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "401 without nonce",
            ))
        }
    };
    Ok((realm, nonce))
}

fn unexpected(d: &stun::DecodedMessage, op: &str) -> io::Error {
    let detail = match d.get(ATTR_ERROR_CODE) {
        Some(Attribute::ErrorCode(c, n, r)) => {
            format!(" {c}{n:02} {}", String::from_utf8_lossy(r))
        }
        _ => String::new(),
    };
    io::Error::other(format!(
        "turn {op}: unexpected response 0x{:04x}{detail}",
        d.msg_type
    ))
}

/// 构造无认证的 Send indication（控制面 5-tuple 即安全关联，无需 MI）。
pub(crate) fn encode_send_indication(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    StunMessage::new(SEND_INDICATION)
        .attr(Attribute::XorPeerAddress(peer))
        .attr(Attribute::Data(payload.to_vec()))
        .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> TurnCredentials {
        TurnCredentials {
            username: "u".into(),
            password: "p".into(),
            realm: "r".into(),
        }
    }

    #[test]
    fn key_derivation_matches_rfc_formula() {
        let key = derive_key("nexus", "nexus", "turn-test");
        assert_eq!(key, md5::compute(b"nexus:nexus:turn-test").0);
    }

    #[test]
    fn encode_request_stamps_integrity_last() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let inner = ClientInner {
            sock,
            creds: creds(),
            key: derive_key("u", "r", "p"),
            nonce: Some("n".into()),
            relayed: "127.0.0.1:0".parse().unwrap(),
            mapped: None,
            expires_at: Instant::now() + DEFAULT_LIFETIME,
            permissions: HashSet::new(),
            channels: HashMap::new(),
            next_channel: 0x4000,
            pending_data: VecDeque::new(),
            stats: AtomicStats::default(),
        };
        let msg = StunMessage::new(ALLOCATE_REQUEST).attr(Attribute::RequestedTransport(17));
        let bytes = inner.encode_request(&msg);
        let d = stun::decode(&bytes).unwrap();
        assert!(d.mi_value_offset.is_some());
        let off = d.mi_value_offset.unwrap();
        assert!(crate::auth::verify_integrity(&bytes, off, &inner.key));
        // USERNAME/REALM/NONCE 在 MI 之前
        assert!(d.get(crate::stun::ATTR_USERNAME).is_some());
        assert!(d.get(ATTR_NONCE).is_some());
    }

    /// 构造一个"已分配但无权限"的假 client（不连网）：未授权目标的
    /// send_to → PermissionDenied + unauthorized_dropped 计数（T3，不静默丢弃）。
    fn fake_client() -> TurnClient {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        TurnClient {
            inner: Arc::new(Mutex::new(ClientInner {
                sock,
                creds: creds(),
                key: [0u8; 16],
                nonce: None,
                relayed: "127.0.0.1:9999".parse().unwrap(),
                mapped: None,
                expires_at: Instant::now() + DEFAULT_LIFETIME,
                permissions: HashSet::new(),
                channels: HashMap::new(),
                next_channel: 0x4000,
                pending_data: VecDeque::new(),
                stats: AtomicStats::default(),
            })),
        }
    }

    #[test]
    fn unauthorized_send_is_permission_denied_and_counted() {
        let c = fake_client();
        let target = "127.0.0.1:12345".parse().unwrap();
        let err = c.send_via_relay(target, b"hello").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(c.stats().unauthorized_dropped, 1);
        // 过期分配 → ConnectionAborted（T4，不静默黑洞）
        let c2 = fake_client();
        c2.lock().unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        let err = c2.send_via_relay(target, b"hello").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(c2.is_expired());
    }
}
