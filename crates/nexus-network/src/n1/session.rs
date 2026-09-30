//! N1 会话/连接表（D3）：按 `N1PeerId` 索引的单 Connection 管理。
//!
//! 这是 v9 "Session 中实际建立的传输实例"的管理者，**不是**白皮书 Session
//! （某次实际资源使用的上下文）的替代（M4）。`N1SessionManager` 是 Connection
//! 生命周期的唯一 Owner（AGENTS.md §13）：创建、观测（每 peer 一个
//! `LinkStateWatcher`）、关闭、回收都在此收敛。
//!
//! 生命周期（AGENTS.md §14）：`Allocating → Active → Draining → Disposed`；
//! 业务结果与资源释放状态分离，本模块只管理后者。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::link::{LinkConfig, LinkStateWatcher, WatcherHandle};
use super::{N1Connection, N1Dialer, N1Discovery, N1Error, N1EventSink, N1PeerId};

/// 对端连接生命周期阶段（AGENTS.md §14）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1PeerPhase {
    /// 正在建连（dial 已发出，连接尚未就绪）。
    Allocating,
    /// 连接就绪，包泵/观测器运行中。
    Active,
    /// 正在关闭（watcher 已停，连接关闭中）。
    Draining,
    /// 资源已释放（可从表中摘除）。
    Disposed,
}

/// 单个对端的连接记录：每对端**一个** `Connection`（M4 不变量）。
pub struct N1Peer {
    conn: Arc<dyn N1Connection>,
    phase: N1PeerPhase,
    #[allow(dead_code)]
    last_progress: Instant,
    watcher: Option<WatcherHandle>,
}

impl N1Peer {
    fn new(conn: Arc<dyn N1Connection>, watcher: Option<WatcherHandle>) -> Self {
        Self {
            conn,
            phase: N1PeerPhase::Active,
            last_progress: Instant::now(),
            watcher,
        }
    }
}

/// N1 会话/连接表：`N1PeerId → N1Peer`。
///
/// `dial` 走注入的 `N1Dialer`；入向连接由调用方经 `insert_accepted` 登记
/// （`accept_loop` 的生产循环由 Composition Root 驱动，见 [`N1SessionManager::accept_loop`]）。
pub struct N1SessionManager {
    peers: Mutex<HashMap<N1PeerId, N1Peer>>,
    dialer: Arc<dyn N1Dialer>,
    discovery: Arc<dyn N1Discovery>,
    sink: Arc<dyn N1EventSink>,
    link_config: LinkConfig,
}

impl N1SessionManager {
    /// 构造管理器（不建连；`dial` / `insert_accepted` 触发建连）。
    pub fn new(
        dialer: Arc<dyn N1Dialer>,
        discovery: Arc<dyn N1Discovery>,
        sink: Arc<dyn N1EventSink>,
        link_config: LinkConfig,
    ) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            dialer,
            discovery,
            sink,
            link_config,
        }
    }

    /// 经 `N1Dialer` 向对端建连并登记；已存在时直接返回（per-peer 单 Connection
    /// 不变量：不重复建连）。
    pub fn dial(&self, peer: &N1PeerId) -> Result<(), N1Error> {
        if self.peers.lock().unwrap().contains_key(peer) {
            return Ok(());
        }
        // 建连时序（v9 §3）：先 resolve 候选 locator，再对选定地址建连；
        // 禁止先对所有候选打洞再定 Plan——dial 只打第一个可达地址。
        let addrs = self.discovery.resolve(peer)?;
        if addrs.is_empty() {
            return Err(N1Error::PeerUnknown);
        }
        let conn = self.dialer.dial(peer, &addrs)?;
        self.insert_conn(*peer, conn);
        Ok(())
    }

    /// 登记一条入向连接（`accept_loop` 收到后调用）。
    pub fn insert_accepted(&self, peer: N1PeerId, conn: Box<dyn N1Connection>) {
        if self.peers.lock().unwrap().contains_key(&peer) {
            // 已有连接：关闭新到的重复连接，保持单 Connection 不变量。
            conn.close();
            return;
        }
        self.insert_conn(peer, conn);
    }

    fn insert_conn(&self, peer: N1PeerId, conn: Box<dyn N1Connection>) {
        let conn: Arc<dyn N1Connection> = conn.into();
        // enable_watcher=false 时不启动 watcher（E4 roam 端 B：rebind 由外部主动驱动，
        // 避免 watcher 并发流操作与主动 rebind 竞态）。
        let watcher = if self.link_config.enable_watcher {
            Some(LinkStateWatcher::start(
                peer,
                Arc::clone(&conn),
                Arc::clone(&self.discovery),
                Arc::clone(&self.sink),
                self.link_config.clone(),
            ))
        } else {
            None
        };
        let mut peers = self.peers.lock().unwrap();
        peers.insert(peer, N1Peer::new(conn, watcher));
    }

    /// 入向接受循环（阻塞）：在调用方线程上运行，直到 `stop` 被置位。
    ///
    /// Composition Root 负责把本方法放到独立线程；`stop` 置位后，
    /// 当前阻塞的 `accept` 返回即退出（`N1Listener` 实现应在 stop 后
    /// 让 `accept` 返回 `Err(Closed)`，或调用方关闭 listener）。
    pub fn accept_loop(
        &self,
        listener: &dyn super::N1Listener,
        stop: &std::sync::atomic::AtomicBool,
    ) {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            match listener.accept() {
                Ok((peer, conn)) => self.insert_accepted(peer, conn),
                Err(N1Error::Closed) => break,
                Err(_) => {
                    // 短暂退避，避免 accept 热失败打满 CPU。
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }

    /// 取对端连接（包泵路由查表用）。
    #[must_use]
    pub fn connection_for(&self, peer: &N1PeerId) -> Option<Arc<dyn N1Connection>> {
        self.peers
            .lock()
            .unwrap()
            .get(peer)
            .map(|p| Arc::clone(&p.conn))
    }

    /// 当前对端列表。
    #[must_use]
    pub fn peers(&self) -> Vec<N1PeerId> {
        self.peers.lock().unwrap().keys().copied().collect()
    }

    /// 对端阶段（测试/诊断用）。
    #[must_use]
    pub fn phase_of(&self, peer: &N1PeerId) -> Option<N1PeerPhase> {
        self.peers.lock().unwrap().get(peer).map(|p| p.phase)
    }

    /// 移除对端：`Draining`（停 watcher、关连接）→ `Disposed` → 摘除。
    pub fn remove(&self, peer: &N1PeerId) {
        let entry = self.peers.lock().unwrap().remove(peer);
        if let Some(mut p) = entry {
            p.phase = N1PeerPhase::Draining;
            if let Some(w) = p.watcher.take() {
                w.shutdown();
            }
            p.conn.close();
            p.phase = N1PeerPhase::Disposed;
        }
    }

    /// 关闭全部对端（Owner 退出路径）。
    pub fn shutdown(&self) {
        let peers: Vec<N1PeerId> = self.peers();
        for peer in peers {
            self.remove(&peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n1::link::LinkConfig;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct FakeConn {
        peer: N1PeerId,
        id: u64,
        closed: AtomicBool,
        rebinds: AtomicUsize,
    }

    impl FakeConn {
        fn new(peer: N1PeerId, id: u64) -> Self {
            Self {
                peer,
                id,
                closed: AtomicBool::new(false),
                rebinds: AtomicUsize::new(0),
            }
        }
    }

    impl N1Connection for FakeConn {
        fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
            if data.len() > 1200 {
                return Err(N1Error::OversizeDatagram(data.len()));
            }
            if self.closed.load(Ordering::SeqCst) {
                return Err(N1Error::Closed);
            }
            Ok(())
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            Err(N1Error::Closed)
        }
        fn open_keepalive(&self) -> Result<super::super::N1KeepaliveStream, N1Error> {
            // 测试替身：keepalive 流立即关闭，watcher 会走错误触发路径。
            Err(N1Error::Closed)
        }
        fn accept_keepalive(&self) -> Result<super::super::N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn rebind(&self) -> Result<(), N1Error> {
            self.rebinds.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn connection_id(&self) -> u64 {
            self.id
        }
        fn peer(&self) -> N1PeerId {
            self.peer
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    struct FakeDialer {
        next_id: AtomicUsize,
    }
    impl N1Dialer for FakeDialer {
        fn dial(
            &self,
            peer: &N1PeerId,
            addrs: &[SocketAddr],
        ) -> Result<Box<dyn N1Connection>, N1Error> {
            if addrs.is_empty() {
                return Err(N1Error::PeerUnknown);
            }
            let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u64;
            Ok(Box::new(FakeConn::new(*peer, id)))
        }
    }

    struct FakeDiscovery;
    impl N1Discovery for FakeDiscovery {
        fn resolve(&self, _peer: &N1PeerId) -> Result<Vec<SocketAddr>, N1Error> {
            Ok(vec!["127.0.0.1:9000".parse().unwrap()])
        }
    }

    struct NullSink;
    impl N1EventSink for NullSink {
        fn emit(&self, _event: super::super::N1Event) {}
    }

    fn manager() -> N1SessionManager {
        N1SessionManager::new(
            Arc::new(FakeDialer {
                next_id: AtomicUsize::new(1),
            }),
            Arc::new(FakeDiscovery),
            Arc::new(NullSink),
            LinkConfig {
                // keepalive 立即失败的替身：watcher 线程会快速退出，不干扰单测。
                probe_interval: std::time::Duration::from_secs(3600),
                heartbeat_timeout: std::time::Duration::from_secs(3600),
                enable_rebind: true,
                enable_watcher: true,
            },
        )
    }

    fn peer_id(n: u8) -> N1PeerId {
        N1PeerId([n; 32])
    }

    #[test]
    fn dial_registers_single_connection_per_peer() {
        let m = manager();
        let p = peer_id(7);
        m.dial(&p).unwrap();
        m.dial(&p).unwrap(); // 重复 dial 不建第二条连接
        assert_eq!(m.peers(), vec![p]);
        assert_eq!(m.phase_of(&p), Some(N1PeerPhase::Active));
        let c1 = m.connection_for(&p).unwrap();
        let c2 = m.connection_for(&p).unwrap();
        assert_eq!(c1.connection_id(), c2.connection_id());
        m.shutdown();
    }

    #[test]
    fn insert_accepted_dedups_against_dialed() {
        let m = manager();
        let p = peer_id(9);
        m.dial(&p).unwrap();
        let before = m.connection_for(&p).unwrap().connection_id();
        // 重复入向连接被关闭丢弃，表中仍是原来那条。
        m.insert_accepted(p, Box::new(FakeConn::new(p, 999)));
        assert_eq!(m.connection_for(&p).unwrap().connection_id(), before);
        m.shutdown();
    }

    #[test]
    fn remove_closes_and_disposes() {
        let m = manager();
        let p = peer_id(3);
        m.dial(&p).unwrap();
        m.remove(&p);
        assert!(m.connection_for(&p).is_none());
        assert_eq!(m.phase_of(&p), None);
        // 重复 remove 无害。
        m.remove(&p);
    }

    #[test]
    fn phase_lifecycle_allocating_not_exposed_on_failure() {
        // discovery 返回空 → dial 失败，不留 Allocating 残留。
        struct EmptyDiscovery;
        impl N1Discovery for EmptyDiscovery {
            fn resolve(&self, _peer: &N1PeerId) -> Result<Vec<SocketAddr>, N1Error> {
                Ok(vec![])
            }
        }
        let m = N1SessionManager::new(
            Arc::new(FakeDialer {
                next_id: AtomicUsize::new(1),
            }),
            Arc::new(EmptyDiscovery),
            Arc::new(NullSink),
            LinkConfig {
                probe_interval: std::time::Duration::from_secs(3600),
                heartbeat_timeout: std::time::Duration::from_secs(3600),
                enable_rebind: true,
                enable_watcher: true,
            },
        );
        let p = peer_id(5);
        assert_eq!(m.dial(&p), Err(N1Error::PeerUnknown));
        assert!(m.peers().is_empty());
    }
}
