//! N1 入站 mTLS listener 适配层（spec §5.2，WP1）。
//!
//! 组合根只把 `N1Listener` 交给 `N1SessionManager::accept_loop`；本模块负责：
//! - `FabricListener::bind_mtls`（allowlist 在 TLS 层强制）；
//! - `accept_timeout(N1_ACCEPT_POLL_MS)` 轮询 + `stop` 协作退出；
//! - `FabricConn` → `N1Connection` 适配（`N1ConnAdapter`）；
//! - allowlist 复核（深度防御；TLS 层已拒绝未知客户端）。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nexus_fabric::{
    FabricConn, FabricError, FabricIdentity, FabricListener, PeerId as FabricPeerId, RecvStream,
    SendStream,
};
use nexus_network::n1::{
    N1Connection, N1Error, N1KeepaliveIo, N1KeepaliveStream, N1Listener, N1PeerId,
};

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
pub struct FabricN1Listener {
    listener: FabricListener,
    allowed: Vec<N1PeerId>,
    stop: Arc<AtomicBool>,
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
        Ok(Self {
            listener,
            allowed,
            stop,
        })
    }

    /// 绑定后的本地 UDP 地址（诊断/测试用）。
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, N1Error> {
        self.listener.local_addr().map_err(map_fabric_err)
    }

    /// allowlist 复核（深度防御谓词；纯函数便于单测）。
    fn allows(&self, peer: N1PeerId) -> bool {
        self.allowed.iter().any(|p| p.0 == peer.0)
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
    use nexus_fabric::ConnConfig;

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

    /// WP1b 前提实测（spec §19）：TLS 层拒绝的握手在 `accept_timeout` 上只表现为
    /// `Timeout`（与空闲轮询不可区分），因此 accept 侧无法分类出
    /// `FabricError::HandshakeFailed`。本测试固化该前提，防止后续把
    /// “代码里有日志句”误当成可观测。
    #[test]
    fn rejected_handshake_is_indistinguishable_from_idle_timeout() {
        let server = identity(40);
        let stranger = identity(41);
        let listener = FabricN1Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &server,
            vec![N1PeerId(identity(42).peer_id().0)],
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
        assert!(matches!(
            listener.listener.accept_timeout(Duration::from_millis(80)),
            Err(FabricError::Timeout)
        ));
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
