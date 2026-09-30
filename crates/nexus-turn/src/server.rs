//! 最小 TURN server（仅 E4/自测用，非生产部署）。
//!
//! 单线程处理：主 socket（STUN 控制 + Send/ChannelData）+ 每个 allocation
//! 的中继 socket（原始 UDP）。分配以 client 控制地址（5-tuple 简化）为 key。
//!
//! 简化取舍（相对完整 RFC 5766，见 MODULE.md Non-Responsibilities）：
//! - 单凭证（一个 username/password/realm）；nonce 为 server 启动时生成。
//! - 不做带宽配额、TCP 中继等。
//! - 中继只做 UDP 载荷转发，不触碰上层加密（T2）。

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::auth::{derive_key, verify_integrity};
use crate::client::TurnCredentials;
use crate::stun::{
    self, decode, is_channel_data, is_stun_message, parse_channel_data, valid_channel, Attribute,
    StunMessage, ALLOCATE_FAILURE, ALLOCATE_REQUEST, ALLOCATE_SUCCESS, ATTR_CHANNEL_NUMBER,
    ATTR_DATA, ATTR_LIFETIME, ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_XOR_PEER_ADDRESS,
    CHANNEL_BIND_FAILURE, CHANNEL_BIND_REQUEST, CHANNEL_BIND_SUCCESS, CREATE_PERMISSION_FAILURE,
    CREATE_PERMISSION_REQUEST, CREATE_PERMISSION_SUCCESS, DATA_INDICATION, REFRESH_FAILURE,
    REFRESH_REQUEST, REFRESH_SUCCESS,
};

/// Server 侧计数器快照。
#[derive(Debug, Clone, Default)]
pub struct TurnServerStats {
    pub allocations: u64,
    pub relayed_bytes: u64,
    pub unauthorized_dropped: u64,
}

#[derive(Debug, Default)]
struct AtomicServerStats {
    allocations: AtomicU64,
    relayed_bytes: AtomicU64,
    unauthorized_dropped: AtomicU64,
}

struct Allocation {
    client: SocketAddr,
    relay_sock: UdpSocket,
    relay_addr: SocketAddr,
    permissions: HashSet<IpAddr>,
    channels: HashMap<u16, SocketAddr>,
    expires_at: Instant,
}

struct ServerState {
    creds: TurnCredentials,
    key: [u8; 16],
    nonce: String,
    allocs: HashMap<SocketAddr, Allocation>,
    /// relay 地址 → client 控制地址（中继投递用）。
    by_relay: HashMap<SocketAddr, SocketAddr>,
}

/// 最小 TURN server（后台线程；Drop 时停止并 join）。
pub struct TurnServer {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    main_addr: SocketAddr,
    stats: Arc<AtomicServerStats>,
}

impl TurnServer {
    /// 在 `addr` 上绑定并启动 server 线程。
    pub fn bind(addr: SocketAddr, creds: TurnCredentials) -> io::Result<TurnServer> {
        let main_sock = UdpSocket::bind(addr)?;
        main_sock.set_read_timeout(Some(Duration::from_millis(10)))?;
        let main_addr = main_sock.local_addr()?;
        let key = derive_key(&creds.username, &creds.realm, &creds.password);
        let nonce = format!(
            "nexus-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0x5eed)
        );
        let stats = Arc::new(AtomicServerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let state = ServerState {
            creds,
            key,
            nonce,
            allocs: HashMap::new(),
            by_relay: HashMap::new(),
        };
        let stats_ref = stats.clone();
        let stop_ref = stop.clone();
        let thread = thread::Builder::new()
            .name("nexus-turn-srv".into())
            .spawn(move || {
                let mut state = state;
                run_loop(main_sock, &mut state, &stop_ref, &stats_ref);
            })
            .map_err(|e| io::Error::other(format!("turn server thread: {e}")))?;
        Ok(TurnServer {
            stop,
            thread: Some(thread),
            main_addr,
            stats,
        })
    }

    /// Server 主地址（client `allocate` 用）。
    pub fn main_addr(&self) -> SocketAddr {
        self.main_addr
    }

    /// 计数器快照。
    pub fn stats(&self) -> TurnServerStats {
        TurnServerStats {
            allocations: self.stats.allocations.load(Ordering::Relaxed),
            relayed_bytes: self.stats.relayed_bytes.load(Ordering::Relaxed),
            unauthorized_dropped: self.stats.unauthorized_dropped.load(Ordering::Relaxed),
        }
    }
}

impl Drop for TurnServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run_loop(
    main_sock: UdpSocket,
    state: &mut ServerState,
    stop: &AtomicBool,
    stats: &AtomicServerStats,
) {
    let mut buf = vec![0u8; 65535];
    while !stop.load(Ordering::SeqCst) {
        match main_sock.recv_from(&mut buf) {
            Ok((n, src)) => handle_main_datagram(&main_sock, state, stats, &buf[..n], src),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // 主 socket 空闲时：排空中继 socket 的原始 UDP + 过期回收。
                drain_relays(&main_sock, state, stats, &mut buf);
                expire_allocations(state);
            }
            Err(_) => break,
        }
    }
}

fn handle_main_datagram(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    stats: &AtomicServerStats,
    raw: &[u8],
    src: SocketAddr,
) {
    if is_channel_data(raw) {
        if let Some((channel, data)) = parse_channel_data(raw) {
            let peer = state
                .allocs
                .get(&src)
                .and_then(|a| a.channels.get(&channel).copied());
            if let Some(peer) = peer {
                relay_data(main_sock, state, stats, src, peer, data);
            }
        }
        return;
    }
    if !is_stun_message(raw) {
        return;
    }
    let d = match decode(raw) {
        Ok(d) => d,
        Err(_) => return,
    };
    match d.msg_type {
        ALLOCATE_REQUEST => handle_allocate(main_sock, state, stats, raw, &d, src),
        REFRESH_REQUEST => handle_refresh(main_sock, state, raw, &d, src),
        CREATE_PERMISSION_REQUEST => handle_create_permission(main_sock, state, raw, &d, src),
        CHANNEL_BIND_REQUEST => handle_channel_bind(main_sock, state, raw, &d, src),
        stun::SEND_INDICATION if state.allocs.contains_key(&src) => {
            // indication 无响应；按 5-tuple 找分配。
            if let (Some(Attribute::XorPeerAddress(peer)), Some(Attribute::Data(data))) =
                (d.get(ATTR_XOR_PEER_ADDRESS), d.get(ATTR_DATA))
            {
                relay_data(main_sock, state, stats, src, *peer, data);
            }
        }
        _ => {}
    }
}

/// 验证长效认证（T1）：USERNAME + NONCE + MESSAGE-INTEGRITY 三者齐全且正确。
fn check_auth(state: &ServerState, raw: &[u8], d: &stun::DecodedMessage) -> bool {
    let username_ok = match d.get(crate::stun::ATTR_USERNAME) {
        Some(Attribute::Username(u)) => u == state.creds.username.as_bytes(),
        _ => false,
    };
    let nonce_ok = match d.get(ATTR_NONCE) {
        Some(Attribute::Nonce(n)) => n == state.nonce.as_bytes(),
        _ => false,
    };
    let mi_ok = d.get(ATTR_MESSAGE_INTEGRITY).is_some()
        && match d.mi_value_offset {
            Some(off) => verify_integrity(raw, off, &state.key),
            None => false,
        };
    username_ok && nonce_ok && mi_ok
}

fn send_401(
    main_sock: &UdpSocket,
    state: &ServerState,
    req: &stun::DecodedMessage,
    src: SocketAddr,
    failure_type: u16,
) {
    let mut resp = StunMessage::new(failure_type);
    resp.txn = req.txn;
    resp.attrs
        .push(Attribute::ErrorCode(4, 1, b"Unauthorized".to_vec()));
    resp.attrs
        .push(Attribute::Realm(state.creds.realm.as_bytes().to_vec()));
    resp.attrs
        .push(Attribute::Nonce(state.nonce.as_bytes().to_vec()));
    let _ = main_sock.send_to(&resp.encode(), src);
}

fn send_success(
    main_sock: &UdpSocket,
    req: &stun::DecodedMessage,
    src: SocketAddr,
    success_type: u16,
    attrs: Vec<Attribute>,
    key: &[u8; 16],
) {
    let mut resp = StunMessage::new(success_type);
    resp.txn = req.txn;
    resp.attrs = attrs;
    // RFC 5766 §2.2: 成功响应携带 MESSAGE-INTEGRITY（MI 为最后一个属性）。
    resp.attrs.push(Attribute::MessageIntegrity([0u8; 20]));
    let mut bytes = resp.encode();
    let mi_off = bytes.len() - 20;
    crate::auth::stamp_integrity(&mut bytes, mi_off, key);
    let _ = main_sock.send_to(&bytes, src);
}

#[allow(clippy::too_many_arguments)]
fn send_error(
    main_sock: &UdpSocket,
    req: &stun::DecodedMessage,
    src: SocketAddr,
    failure_type: u16,
    class: u8,
    number: u8,
    reason: &[u8],
    key: &[u8; 16],
) {
    let mut resp = StunMessage::new(failure_type);
    resp.txn = req.txn;
    resp.attrs
        .push(Attribute::ErrorCode(class, number, reason.to_vec()));
    // RFC 5766 §2.2: 错误响应也携带 MESSAGE-INTEGRITY（401 质询除外，由 send_401 单独处理）。
    resp.attrs.push(Attribute::MessageIntegrity([0u8; 20]));
    let mut bytes = resp.encode();
    let mi_off = bytes.len() - 20;
    crate::auth::stamp_integrity(&mut bytes, mi_off, key);
    let _ = main_sock.send_to(&bytes, src);
}

fn handle_allocate(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    stats: &AtomicServerStats,
    raw: &[u8],
    req: &stun::DecodedMessage,
    src: SocketAddr,
) {
    if !check_auth(state, raw, req) {
        send_401(main_sock, state, req, src, ALLOCATE_FAILURE);
        return;
    }
    // 分配中继 socket（loopback 上的真实 UDP 端口即 relayed address）。
    let relay_sock = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => {
            send_error(
                main_sock,
                req,
                src,
                ALLOCATE_FAILURE,
                5,
                0,
                b"Server Error",
                &state.key,
            );
            return;
        }
    };
    if relay_sock.set_nonblocking(true).is_err() {
        send_error(
            main_sock,
            req,
            src,
            ALLOCATE_FAILURE,
            5,
            0,
            b"Server Error",
            &state.key,
        );
        return;
    }
    let relay_addr = match relay_sock.local_addr() {
        Ok(a) => a,
        Err(_) => {
            send_error(
                main_sock,
                req,
                src,
                ALLOCATE_FAILURE,
                5,
                0,
                b"Server Error",
                &state.key,
            );
            return;
        }
    };
    // 替换同 client 的旧分配（简化语义；RFC 为 437）。
    if let Some(old) = state.allocs.remove(&src) {
        state.by_relay.remove(&old.relay_addr);
    }
    state.allocs.insert(
        src,
        Allocation {
            client: src,
            relay_sock,
            relay_addr,
            permissions: HashSet::new(),
            channels: HashMap::new(),
            expires_at: Instant::now() + Duration::from_secs(600),
        },
    );
    state.by_relay.insert(relay_addr, src);
    stats.allocations.fetch_add(1, Ordering::Relaxed);
    send_success(
        main_sock,
        req,
        src,
        ALLOCATE_SUCCESS,
        vec![
            Attribute::XorRelayedAddress(relay_addr),
            Attribute::XorMappedAddress(src),
            Attribute::Lifetime(600),
        ],
        &state.key,
    );
}

fn handle_refresh(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    raw: &[u8],
    req: &stun::DecodedMessage,
    src: SocketAddr,
) {
    if !check_auth(state, raw, req) {
        send_401(main_sock, state, req, src, REFRESH_FAILURE);
        return;
    }
    let alloc = match state.allocs.get_mut(&src) {
        Some(a) => a,
        None => {
            send_error(
                main_sock,
                req,
                src,
                REFRESH_FAILURE,
                4,
                37,
                b"Allocation Mismatch",
                &state.key,
            );
            return;
        }
    };
    match req.get(ATTR_LIFETIME) {
        // LIFETIME=0：删除分配（RFC 5766 §7）。
        Some(Attribute::Lifetime(0)) => {
            let old = state.allocs.remove(&src).unwrap();
            state.by_relay.remove(&old.relay_addr);
            send_success(
                main_sock,
                req,
                src,
                REFRESH_SUCCESS,
                vec![Attribute::Lifetime(0)],
                &state.key,
            );
        }
        Some(Attribute::Lifetime(s)) => {
            alloc.expires_at = Instant::now() + Duration::from_secs(*s as u64);
            send_success(
                main_sock,
                req,
                src,
                REFRESH_SUCCESS,
                vec![Attribute::Lifetime(*s)],
                &state.key,
            );
        }
        _ => {
            alloc.expires_at = Instant::now() + Duration::from_secs(600);
            send_success(
                main_sock,
                req,
                src,
                REFRESH_SUCCESS,
                vec![Attribute::Lifetime(600)],
                &state.key,
            );
        }
    }
}

fn handle_create_permission(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    raw: &[u8],
    req: &stun::DecodedMessage,
    src: SocketAddr,
) {
    if !check_auth(state, raw, req) {
        send_401(main_sock, state, req, src, CREATE_PERMISSION_FAILURE);
        return;
    }
    let peer = match req.get(ATTR_XOR_PEER_ADDRESS) {
        Some(Attribute::XorPeerAddress(p)) => *p,
        _ => {
            send_error(
                main_sock,
                req,
                src,
                CREATE_PERMISSION_FAILURE,
                4,
                0,
                b"Bad Request",
                &state.key,
            );
            return;
        }
    };
    match state.allocs.get_mut(&src) {
        Some(a) => {
            // RFC 5766：权限按 IP（非 IP:port）。
            a.permissions.insert(peer.ip());
            send_success(
                main_sock,
                req,
                src,
                CREATE_PERMISSION_SUCCESS,
                vec![],
                &state.key,
            );
        }
        None => send_error(
            main_sock,
            req,
            src,
            CREATE_PERMISSION_FAILURE,
            4,
            37,
            b"Allocation Mismatch",
            &state.key,
        ),
    }
}

fn handle_channel_bind(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    raw: &[u8],
    req: &stun::DecodedMessage,
    src: SocketAddr,
) {
    if !check_auth(state, raw, req) {
        send_401(main_sock, state, req, src, CHANNEL_BIND_FAILURE);
        return;
    }
    let (channel, peer) = match (req.get(ATTR_CHANNEL_NUMBER), req.get(ATTR_XOR_PEER_ADDRESS)) {
        (Some(Attribute::ChannelNumber(c)), Some(Attribute::XorPeerAddress(p))) => (*c, *p),
        _ => {
            send_error(
                main_sock,
                req,
                src,
                CHANNEL_BIND_FAILURE,
                4,
                0,
                b"Bad Request",
                &state.key,
            );
            return;
        }
    };
    if !valid_channel(channel) {
        send_error(
            main_sock,
            req,
            src,
            CHANNEL_BIND_FAILURE,
            4,
            0,
            b"Bad Request",
            &state.key,
        );
        return;
    }
    match state.allocs.get_mut(&src) {
        Some(a) => {
            // RFC 5766 §11：ChannelBind 要求已存在对该 IP 的 permission。
            if !a.permissions.contains(&peer.ip()) {
                send_error(
                    main_sock,
                    req,
                    src,
                    CHANNEL_BIND_FAILURE,
                    4,
                    3,
                    b"Forbidden",
                    &state.key,
                );
                return;
            }
            a.channels.insert(channel, peer);
            send_success(
                main_sock,
                req,
                src,
                CHANNEL_BIND_SUCCESS,
                vec![],
                &state.key,
            );
        }
        None => send_error(
            main_sock,
            req,
            src,
            CHANNEL_BIND_FAILURE,
            4,
            37,
            b"Allocation Mismatch",
            &state.key,
        ),
    }
}

/// 中继数据（T2/T3）：权限检查 → 投递到对端分配的 client（Data indication）
/// 或从本分配的中继 socket 原始发出。
fn relay_data(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    stats: &AtomicServerStats,
    from_client: SocketAddr,
    peer: SocketAddr,
    data: &[u8],
) {
    let alloc = match state.allocs.get(&from_client) {
        Some(a) => a,
        None => return,
    };
    if !alloc.permissions.contains(&peer.ip()) {
        stats.unauthorized_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let from_relay = alloc.relay_addr;
    if let Some(&target_client) = state.by_relay.get(&peer) {
        // 对端是另一个 allocation 的中继地址：Data indication 给其 client，
        // peer 填发送方的中继地址（client 侧看到的"真实对端"）。
        let mut msg = StunMessage::new(DATA_INDICATION);
        msg.attrs.push(Attribute::XorPeerAddress(from_relay));
        msg.attrs.push(Attribute::Data(data.to_vec()));
        let _ = main_sock.send_to(&msg.encode(), target_client);
    } else {
        // 非分配地址：从本分配的中继 socket 原始 UDP 发出（RFC 语义）。
        let _ = alloc.relay_sock.send_to(data, peer);
    }
    stats
        .relayed_bytes
        .fetch_add(data.len() as u64, Ordering::Relaxed);
}

/// 排空中继 socket 上的原始 UDP：有权限 → Data indication 给 client。
fn drain_relays(
    main_sock: &UdpSocket,
    state: &mut ServerState,
    stats: &AtomicServerStats,
    buf: &mut [u8],
) {
    for alloc in state.allocs.values() {
        while let Ok((n, peer)) = alloc.relay_sock.recv_from(buf) {
            if !alloc.permissions.contains(&peer.ip()) {
                stats.unauthorized_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut msg = StunMessage::new(DATA_INDICATION);
            msg.attrs.push(Attribute::XorPeerAddress(peer));
            msg.attrs.push(Attribute::Data(buf[..n].to_vec()));
            let _ = main_sock.send_to(&msg.encode(), alloc.client);
            stats.relayed_bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

fn expire_allocations(state: &mut ServerState) {
    let now = Instant::now();
    let expired: Vec<SocketAddr> = state
        .allocs
        .iter()
        .filter(|(_, a)| now >= a.expires_at)
        .map(|(c, _)| *c)
        .collect();
    for c in expired {
        if let Some(old) = state.allocs.remove(&c) {
            state.by_relay.remove(&old.relay_addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TurnSocket;
    use nexus_fabric::UdpTransport;

    fn test_creds() -> TurnCredentials {
        TurnCredentials {
            username: "nexus".into(),
            password: "turn-test".into(),
            realm: "nexus".into(),
        }
    }

    /// Server 分配往返（经 TurnSocket 公开语义，不依赖 fabric）：
    /// allocate → permission → A 用 ChannelData 发 → B 收到（peer = relay_a）；
    /// B 用 Send indication 回 → A 收到（peer = relay_b）。
    #[test]
    fn server_allocate_permission_relay_flow() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), test_creds()).unwrap();
        let saddr = server.main_addr();

        let a = crate::TurnClient::allocate(saddr, test_creds()).unwrap();
        let b = crate::TurnClient::allocate(saddr, test_creds()).unwrap();
        let relay_a = a.relayed_addr();
        let relay_b = b.relayed_addr();
        assert_ne!(relay_a, relay_b);

        a.create_permission(relay_b).unwrap();
        b.create_permission(relay_a).unwrap();
        // A→B 走 ChannelData（T3 通道语义），B→A 走 Send indication。
        let ch = a.bind_channel(relay_b);
        assert!((0x4000..=0x7FFF).contains(&ch));

        let mut sa = TurnSocket::new(a.clone());
        let mut sb = TurnSocket::new(b.clone());
        sa.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sb.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        sa.send_to(b"ping-turn", relay_b).unwrap();
        let mut buf = [0u8; 1024];
        let (n, peer) = sb.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping-turn");
        assert_eq!(peer, relay_a);

        sb.send_to(b"pong-turn", relay_a).unwrap();
        let (n, peer) = sa.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong-turn");
        assert_eq!(peer, relay_b);

        assert!(server.stats().relayed_bytes > 0);
        assert_eq!(server.stats().allocations, 2);
    }

    /// Server 侧未授权中继丢弃计数（T3）：已分配 client 发往无 permission
    /// 的 peer → server 丢弃并计数（client 侧同样会拦，这里走裸 socket
    /// 绕过 client 检查，直达 server）。
    #[test]
    fn server_drops_unauthorized_relay() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), test_creds()).unwrap();
        let saddr = server.main_addr();
        let a = crate::TurnClient::allocate(saddr, test_creds()).unwrap();

        // 用裸 UDP socket 伪造 a 的 5-tuple 源地址是不可能的（端口被占用），
        // 因此改为：a 对陌生地址 create_permission（server 记录 IP 权限），
        // 但 client 侧不记录；随后用裸 socket 直连陌生地址的"中继"——
        // 更直接的测法：a 的分配存在，向 server 发 Send indication 到无权限
        // 的 peer。client 侧 send_via_relay 会先拦，所以这里用 TurnClient
        // 的 pub(crate) 裸发通道。
        let stranger: SocketAddr = "127.0.0.1:59999".parse().unwrap();
        let mut msg = StunMessage::new(stun::SEND_INDICATION);
        msg.attrs.push(Attribute::XorPeerAddress(stranger));
        msg.attrs.push(Attribute::Data(b"x".to_vec()));
        a.send_raw_to_server(&msg.encode()).unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while server.stats().unauthorized_dropped == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            server.stats().unauthorized_dropped >= 1,
            "server must count unauthorized relay attempts"
        );
    }

    /// Refresh 真实往返（T4）：allocate → refresh 成功续租，`is_expired()` 为
    /// false；分配在 server 侧仍然有效（可继续 create_permission）。
    #[test]
    fn server_refresh_renews_allocation() {
        let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), test_creds()).unwrap();
        let saddr = server.main_addr();

        let a = crate::TurnClient::allocate(saddr, test_creds()).unwrap();
        assert!(!a.is_expired());

        // refresh 成功：续租并更新 expires_at。
        a.refresh().unwrap();
        assert!(!a.is_expired());

        // 续租后分配仍有效：permission 可建。
        let b = crate::TurnClient::allocate(saddr, test_creds()).unwrap();
        a.create_permission(b.relayed_addr()).unwrap();
        b.create_permission(a.relayed_addr()).unwrap();
    }
}
