//! N1 入站 mTLS listener 适配层（spec §5.2，WP1）。
//!
//! 组合根只把 `N1Listener` 交给 `N1SessionManager::accept_loop`；本模块负责：
//! - `FabricListener::bind_mtls`（allowlist 在 TLS 层强制）；
//! - `accept_timeout(N1_ACCEPT_POLL_MS)` 轮询 + `stop` 协作退出；
//! - `FabricConn` → `N1Connection` 适配（`N1ConnAdapter`）；
//! - allowlist 复核（深度防御；TLS 层已拒绝未知客户端）。

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use nexus_fabric::{
    FabricConn, FabricError, FabricIdentity, FabricListener, PeerId as FabricPeerId, RecvStream,
    SendStream,
};
use nexus_network::n1::{
    N1Connection, N1Error, N1KeepaliveIo, N1KeepaliveStream, N1Listener, N1PeerId,
};

use crate::log_throttle::KeyedLogThrottle;
use crate::n1_runtime::{N1InboundReject, N1Stats};

/// `accept_timeout` 轮询粒度（spec §8.1 `N1_ACCEPT_POLL_MS`）。
pub const N1_ACCEPT_POLL_MS: u64 = 500;

/// `FabricConn` → `N1Connection` 适配器（~40 行；不修改 `apps/nexus` 的私有同族类型）。
pub struct N1ConnAdapter {
    pub inner: FabricConn,
}

impl N1Connection for N1ConnAdapter {
    fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
        if data.len() > 1200 {
            return Err(N1Error::OversizeDatagram(data.len()));
        }
        self.inner.send_datagram(data).map_err(map_fabric_err)
    }

    fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
        self.inner.recv_datagram().map_err(map_fabric_err)
    }

    fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
        let (send, recv) = self.inner.open_bi().map_err(map_fabric_err)?;
        Ok(N1KeepaliveStream::new(Box::new(FabricKaStream {
            send,
            recv,
        })))
    }

    fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
        let (send, recv) = self.inner.accept_bi().map_err(map_fabric_err)?;
        Ok(N1KeepaliveStream::new(Box::new(FabricKaStream {
            send,
            recv,
        })))
    }

    fn rebind(&self) -> Result<(), N1Error> {
        self.inner.rebind().map_err(map_fabric_err)
    }

    fn connection_id(&self) -> u64 {
        self.inner.id().0
    }

    fn peer(&self) -> N1PeerId {
        N1PeerId(self.inner.peer().0)
    }

    fn close(&self) {
        self.inner.close(0, b"n1 shutdown");
    }
}

struct FabricKaStream {
    send: SendStream,
    recv: RecvStream,
}

impl N1KeepaliveIo for FabricKaStream {
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), N1Error> {
        while !buf.is_empty() {
            let n = self.send.write(buf).map_err(map_fabric_err)?;
            if n == 0 {
                return Err(N1Error::Transport("keepalive write returned 0".into()));
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), N1Error> {
        let mut off = 0;
        while off < buf.len() {
            match self.recv.read(&mut buf[off..]).map_err(map_fabric_err)? {
                0 => return Err(N1Error::Closed),
                n => off += n,
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), N1Error> {
        self.send.finish().map_err(map_fabric_err)
    }
}

/// mTLS N1 listener：`FabricListener` + allowlist 复核 + stop 协作退出。
///
/// WP1b（spec §19）：fabric 侧把被拒入站握手计入只读计数器；本类型在
/// `accept_timeout` 的 `Timeout` 分支比较增量，把拒绝变成可观测事件
/// （逐字日志句 + `rx.rejected{admission}` 计数）。`accept_timeout` 的
/// 错误形态不变（拒绝仍表现为 `Timeout`）。
pub struct FabricN1Listener {
    listener: FabricListener,
    allowed: Vec<N1PeerId>,
    stop: Arc<AtomicBool>,
    /// WP1b：`record_rx_rejected(AdmissionDenied)` 的既有 stats 句柄。
    /// `None` 只用于不关心统计的单测；生产装配经 [`Self::with_stats`] 必填。
    stats: Option<Arc<N1Stats>>,
    /// 上一次观测到的 fabric 拒绝计数（增量检测）。
    last_rejected: AtomicU64,
    /// §19 日志句限频；`KeyedLogThrottle` 保证首次出现立即发射。
    reject_log: Mutex<KeyedLogThrottle>,
}

impl FabricN1Listener {
    /// `identity` 来自 `[network.identity].seed_file`；`allowed` 来自
    /// `network.toml [[peers]].id`。`bind_mtls` 失败 → `Err`（调用方决定
    /// `bind_failed` 降级）。
    pub fn bind(
        addr: std::net::SocketAddr,
        identity: &FabricIdentity,
        allowed: Vec<N1PeerId>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, N1Error> {
        let fabric_allowed: Vec<FabricPeerId> = allowed.iter().map(|p| FabricPeerId(p.0)).collect();
        let listener =
            FabricListener::bind_mtls(addr, identity, &fabric_allowed).map_err(map_fabric_err)?;
        let last_rejected = AtomicU64::new(listener.rejected_handshakes());
        Ok(Self {
            listener,
            allowed,
            stop,
            stats: None,
            last_rejected,
            reject_log: Mutex::new(KeyedLogThrottle::new()),
        })
    }

    /// WP1b：接入生产 stats（`rx.rejected{admission}` 可观测计数）。
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<N1Stats>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// 绑定后的本地 UDP 地址（诊断/测试用）。
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, N1Error> {
        self.listener.local_addr().map_err(map_fabric_err)
    }

    /// allowlist 复核（深度防御谓词；纯函数便于单测）。
    fn allows(&self, peer: N1PeerId) -> bool {
        self.allowed.iter().any(|p| p.0 == peer.0)
    }

    fn record_admission_denied(&self) {
        if let Some(stats) = &self.stats {
            // 被拒握手从未通过 mTLS，peer 身份按 P0 既有约定为零值哨兵。
            stats.record_rx_rejected(N1InboundReject::AdmissionDenied {
                peer: N1PeerId([0u8; 32]),
            });
        }
    }

    /// WP1b：比较 fabric 拒绝计数器增量；`delta > 0` 时计数并（限频）发逐字句。
    ///
    /// 返回本次观测到的增量（0 = 纯空闲）。首次出现必定发射（限频器语义），
    /// 后续同键在窗口内只抑制输出，不丢计数。
    fn poll_rejected_handshakes(&self) -> u64 {
        let total = self.listener.rejected_handshakes();
        let last = self.last_rejected.load(Ordering::Relaxed);
        if total <= last {
            return 0;
        }
        let delta = total - last;
        self.last_rejected.store(total, Ordering::Relaxed);
        if let Some(stats) = &self.stats {
            for _ in 0..delta {
                stats.record_rx_rejected(N1InboundReject::AdmissionDenied {
                    peer: N1PeerId([0u8; 32]),
                });
            }
        }
        let decision = self.reject_log.lock().unwrap().decide(
            "n1_listen",
            "tls_handshake_rejected",
            std::time::Instant::now(),
            crate::log_throttle::OUTBOUND_UNAVAILABLE_LOG_INTERVAL,
        );
        if decision.emit {
            eprintln!(
                "[n1-listen] tls handshake rejected (peer unauthenticated or protocol error)"
            );
        }
        delta
    }
}

impl N1Listener for FabricN1Listener {
    fn accept(&self) -> Result<(N1PeerId, Box<dyn N1Connection>), N1Error> {
        loop {
            match self
                .listener
                .accept_timeout(Duration::from_millis(N1_ACCEPT_POLL_MS))
            {
                Ok(conn) => {
                    let peer = N1PeerId(conn.peer().0);
                    // 深度防御：TLS 层已按 allowlist 拒绝未知客户端。
                    if !self.allows(peer) {
                        self.record_admission_denied();
                        eprintln!(
                            "[n1-listener] rejected peer={} reason=admission",
                            short_peer(peer)
                        );
                        conn.close(0, b"n1 admission");
                        return Err(N1Error::PeerUnknown);
                    }
                    eprintln!(
                        "[n1-listener] accepted peer={} conn={}",
                        short_peer(peer),
                        conn.id().0
                    );
                    return Ok((peer, Box::new(N1ConnAdapter { inner: conn })));
                }
                Err(FabricError::Timeout) => {
                    // WP1b/§19：TLS 拒绝与空闲在 accept 错误上同形；增量在
                    // fabric 计数器里，只有 delta > 0 才是拒绝。
                    self.poll_rejected_handshakes();
                    if self.stop.load(Ordering::SeqCst) {
                        return Err(N1Error::Closed);
                    }
                }
                Err(FabricError::Closed(code)) => return Err(N1Error::PeerClosed(code)),
                Err(e) => return Err(map_fabric_err(e)),
            }
        }
    }
}

fn short_peer(peer: N1PeerId) -> String {
    peer.to_hex()[..16].to_string()
}

fn map_fabric_err(e: FabricError) -> N1Error {
    match e {
        FabricError::HandshakeFailed(s) => N1Error::Transport(format!("handshake: {s}")),
        FabricError::PathUnreachable => N1Error::PeerUnknown,
        FabricError::Closed(code) => N1Error::PeerClosed(code),
        FabricError::Timeout => N1Error::Timeout,
        FabricError::Transport(s) => N1Error::Transport(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n1_runtime::N1StatsSnapshot;
    use nexus_fabric::ConnConfig;
    use std::time::Instant;

    fn identity(seed: u8) -> FabricIdentity {
        FabricIdentity::from_ed25519_seed([seed; 32]).unwrap()
    }

    fn config(addr: std::net::SocketAddr) -> ConnConfig {
        ConnConfig {
            addrs: vec![addr],
            handshake_timeout: Duration::from_millis(700),
        }
    }

    #[test]
    fn allowlisted_peer_is_accepted_and_datagrams_flow_both_ways() {
        let server = identity(31);
        let client = identity(32);
        let listener = FabricN1Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &server,
            vec![N1PeerId(client.peer_id().0)],
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let dialer = FabricConn::connect_mtls(
            server.peer_id(),
            &client,
            &config(listener.local_addr().unwrap()),
        )
        .unwrap();
        let (peer, conn) = listener.accept().unwrap();
        assert_eq!(peer, N1PeerId(client.peer_id().0));

        conn.send_datagram(b"inbound").unwrap();
        assert_eq!(dialer.recv_datagram().unwrap(), b"inbound");
        dialer.send_datagram(b"outbound").unwrap();
        assert_eq!(conn.recv_datagram().unwrap(), b"outbound");

        conn.close();
        dialer.close(0, b"done");
    }

    #[test]
    fn stop_flag_turns_poll_timeout_into_closed() {
        let listener = FabricN1Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &identity(33),
            Vec::new(),
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
        assert!(matches!(listener.accept(), Err(N1Error::Closed)));
    }

    #[test]
    fn non_allowlisted_peer_never_reaches_accept_queue() {
        let server = identity(34);
        let stranger = identity(35);
        let listener = FabricN1Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &server,
            vec![N1PeerId(identity(36).peer_id().0)],
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(
            FabricConn::connect_mtls(
                server.peer_id(),
                &stranger,
                &config(listener.local_addr().unwrap())
            )
            .is_err()
        );
        // TLS 层拒绝后 stop 置位：accept 以 Closed 退出，未返回任何对端。
        listener.stop.store(true, Ordering::SeqCst);
        assert!(matches!(listener.accept(), Err(N1Error::Closed)));
    }

    /// WP1b 前提更新（spec §19 / MSR-n1-wp1b-ruling-20261029）：accept 的错误
    /// 形态保持 `Timeout`（被拒握手与空闲仍同形），但 fabric 计数器可区分二者；
    /// listener 的增量检测据此触发逐字句与 `rx.rejected{admission}` 计数。
    /// 旧前提「完全不可区分」已被选项 (ii) 取代，此处固化新事实。
    #[test]
    fn rejected_handshake_is_distinguishable_via_counter_while_accept_still_times_out() {
        let server = identity(40);
        let stranger = identity(41);
        let stats = Arc::new(N1Stats::default());
        let listener = FabricN1Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &server,
            vec![N1PeerId(identity(42).peer_id().0)],
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
        .with_stats(Arc::clone(&stats));

        // 纯空闲：accept 超时、计数器不动、增量 0、无 stats 计数。
        assert!(matches!(
            listener.listener.accept_timeout(Duration::from_millis(80)),
            Err(FabricError::Timeout)
        ));
        assert_eq!(listener.poll_rejected_handshakes(), 0);
        assert_eq!(listener.listener.rejected_handshakes(), 0);
        assert_eq!(stats.snapshot(), N1StatsSnapshot::default());

        // 未列名身份在 TLS 层被拒：fabric 计数器递增。
        assert!(
            FabricConn::connect_mtls(
                server.peer_id(),
                &stranger,
                &config(listener.local_addr().unwrap())
            )
            .is_err()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while listener.listener.rejected_handshakes() == 0 {
            assert!(Instant::now() < deadline, "rejection counter never moved");
            std::thread::sleep(Duration::from_millis(10));
        }

        // accept 语义不变：被拒握手仍只表现为 `Timeout`。
        assert!(matches!(
            listener.listener.accept_timeout(Duration::from_millis(80)),
            Err(FabricError::Timeout)
        ));

        // 增量检测：第一次观测 delta = 1（首次发句不被吞），第二次为 0。
        assert_eq!(listener.poll_rejected_handshakes(), 1);
        assert_eq!(listener.poll_rejected_handshakes(), 0);
        assert_eq!(
            stats.snapshot(),
            N1StatsSnapshot {
                rx_rejected: 1,
                rx_rejected_admission: 1,
                ..N1StatsSnapshot::default()
            }
        );
    }

    #[test]
    fn allowlist_predicate_is_exact() {
        let allowed = N1PeerId(identity(37).peer_id().0);
        let listener = FabricN1Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &identity(38),
            vec![allowed],
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
        assert!(listener.allows(allowed));
        assert!(!listener.allows(N1PeerId(identity(39).peer_id().0)));
    }
}
