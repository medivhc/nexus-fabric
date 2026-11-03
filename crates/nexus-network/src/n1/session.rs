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
use super::{
    N1Connection, N1Dialer, N1Discovery, N1Disposition, N1Error, N1Event, N1EventSink, N1PeerId,
};

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
    /// 谴责表（H1）：`peer → connection_id`。
    ///
    /// 由 `Escalate` 事件（watcher 线程，只登记不摘除）与发送侧
    /// `PeerClosed`（bridge）写入；由数据面/拨号/accept 线程的入口排空。
    /// 单独一张表的原因：`emit` 在 watcher 线程内执行，而摘除要 join
    /// watcher 线程——在 emit 里同步摘除会自 join 死锁。
    condemned: Arc<Mutex<HashMap<N1PeerId, u64>>>,
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
        let condemned = Arc::new(Mutex::new(HashMap::new()));
        // 事件 sink 包一层谴责适配：转发全部事件，`Escalate` 时只登记。
        let sink: Arc<dyn N1EventSink> = Arc::new(CondemningSink {
            inner: sink,
            condemned: Arc::clone(&condemned),
        });
        Self {
            peers: Mutex::new(HashMap::new()),
            condemned,
            dialer,
            discovery,
            sink,
            link_config,
        }
    }

    /// 经 `N1Dialer` 向对端建连并登记；已存在时直接返回（per-peer 单 Connection
    /// 不变量：不重复建连）。
    pub fn dial(&self, peer: &N1PeerId) -> Result<(), N1Error> {
        // 先排空谴责：被谴责的旧条目必须先消失，重拨才有意义。
        self.drain_condemned();
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
        // 先清后纳：对端重启后的重建连接不能被自己的死条目挡在门外。
        self.drain_condemned();
        if self.peers.lock().unwrap().contains_key(&peer) {
            // 已有连接：关闭新到的重复连接，保持单 Connection 不变量。
            conn.close();
            return;
        }
        self.insert_conn(peer, conn);
    }

    fn insert_conn(&self, peer: N1PeerId, conn: Box<dyn N1Connection>) {
        let conn: Arc<dyn N1Connection> = conn.into();
        // watcher 常启动（含 responder）；enable_watcher=false 时 watcher 只运行
        // responder、不主动 ping（E4 roam 端 B：rebind 由外部主动驱动，避免
        // watcher 并发流操作与主动 rebind 竞态，但仍需回对端 ping）。
        let watcher = LinkStateWatcher::start(
            peer,
            Arc::clone(&conn),
            Arc::clone(&self.discovery),
            Arc::clone(&self.sink),
            self.link_config.clone(),
        );
        let mut peers = self.peers.lock().unwrap();
        peers.insert(peer, N1Peer::new(conn, Some(watcher)));
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
        // 数据面/拨号/accept 线程的安全排空点（非 watcher 线程，join 安全）。
        self.drain_condemned();
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

    /// 移除对端：`Draining`（关连接、停 watcher）→ `Disposed` → 摘除。
    ///
    /// 顺序关键（E-3）：必须先 `conn.close()` 再 `watcher.shutdown()`。
    /// watcher 线程可能阻塞在 `open_keepalive()`，只有 close 连接能打断它
    /// （使其收到 Closed 后退出）；若先 join watcher 会死锁。
    pub fn remove(&self, peer: &N1PeerId) {
        let entry = self.peers.lock().unwrap().remove(peer);
        if let Some(mut p) = entry {
            p.phase = N1PeerPhase::Draining;
            p.conn.close();
            if let Some(w) = p.watcher.take() {
                w.shutdown();
            }
            p.phase = N1PeerPhase::Disposed;
        }
    }

    /// 按 `connection_id` 条件摘除（单次加锁判定 + 摘除）。
    ///
    /// 与 [`Self::remove`] 的区别：只有当表里的条目仍是 `conn_id` 指向的那条
    /// 连接时才摘除。reader 退出路径与谴责排空共用本方法——任一先执行，另一
    /// 方看到的要么是条目已不存在（`false`），要么是已换的新 conn（id 不符，
    /// 不摘），因此不会误删重建后的连接。
    pub fn remove_if_conn(&self, peer: &N1PeerId, conn_id: u64) -> bool {
        let entry = {
            let mut peers = self.peers.lock().unwrap();
            match peers.get(peer) {
                Some(p) if p.conn.connection_id() == conn_id => peers.remove(peer),
                _ => None,
            }
        };
        let Some(mut p) = entry else {
            return false;
        };
        p.phase = N1PeerPhase::Draining;
        // E-3 顺序：先 close 打断阻塞中的 watcher，再 join。
        p.conn.close();
        if let Some(w) = p.watcher.take() {
            w.shutdown();
        }
        p.phase = N1PeerPhase::Disposed;
        true
    }

    /// 登记谴责（H1）：`peer` 当前那条 `conn_id` 连接已被判定死亡。
    ///
    /// 只写表、不摘除（可在 watcher 线程内安全调用）。真正的摘除发生在
    /// [`Self::connection_for`] / [`Self::dial`] / [`Self::insert_accepted`]
    /// 三个入口。
    pub(crate) fn condemn(&self, peer: &N1PeerId, conn_id: u64) {
        self.condemned.lock().unwrap().insert(*peer, conn_id);
    }

    /// 排空谴责表：id 仍匹配 → 摘除；已换新 conn（id 不符）→ 丢弃谴责。
    fn drain_condemned(&self) {
        let entries: Vec<(N1PeerId, u64)> = {
            let mut condemned = self.condemned.lock().unwrap();
            if condemned.is_empty() {
                return;
            }
            condemned.drain().collect()
        };
        for (peer, conn_id) in entries {
            self.remove_if_conn(&peer, conn_id);
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

/// 事件 sink 的谴责适配层：转发全部事件，`Escalate` 时登记谴责。
///
/// 只登记、不摘除：`emit` 在 watcher 线程内被调用，而 `remove()` 需要 join
/// watcher 线程（自 join 死锁）。
struct CondemningSink {
    inner: Arc<dyn N1EventSink>,
    condemned: Arc<Mutex<HashMap<N1PeerId, u64>>>,
}

impl N1EventSink for CondemningSink {
    fn emit(&self, event: N1Event) {
        if event.disposition == N1Disposition::Escalate {
            self.condemned
                .lock()
                .unwrap()
                .insert(event.peer, event.connection_id);
        }
        self.inner.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n1::link::LinkConfig;
    use std::net::SocketAddr;
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

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
            // 与生产契约同口径：有效载荷下限（真值由连接的 datagram_cap 给出）。
            if data.len() > crate::n1::DATAGRAM_PAYLOAD_FLOOR {
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

    /// H1：谴责命中的条目在下一个入口被摘除（数据面/拨号/accept 线程）。
    #[test]
    fn condemn_removes_the_matching_connection() {
        let m = manager();
        let p = peer_id(11);
        m.dial(&p).unwrap();
        let id = m.connection_for(&p).unwrap().connection_id();
        m.condemn(&p, id);
        assert!(
            m.connection_for(&p).is_none(),
            "condemned connection must be drained"
        );
        assert_eq!(m.phase_of(&p), None);
        m.shutdown();
    }

    /// H1 核心对冲：谴责的是旧 conn_id 时，不得误摘已重建的新连接。
    #[test]
    fn condemn_of_old_connection_does_not_remove_rebuilt_connection() {
        let m = manager();
        let p = peer_id(12);
        m.dial(&p).unwrap();
        let old_id = m.connection_for(&p).unwrap().connection_id();
        m.remove(&p);
        m.dial(&p).unwrap();
        let new_id = m.connection_for(&p).unwrap().connection_id();
        assert_ne!(
            old_id, new_id,
            "test precondition: rebuilt conn has a new id"
        );

        m.condemn(&p, old_id);
        let current = m
            .connection_for(&p)
            .expect("rebuilt connection must survive");
        assert_eq!(current.connection_id(), new_id);
        m.shutdown();
    }

    /// H1：`insert_accepted` 先清后纳——对端重启后的重建连接不被死条目挡住。
    #[test]
    fn insert_accepted_drains_condemnation_before_accepting() {
        let m = manager();
        let p = peer_id(14);
        m.dial(&p).unwrap();
        let stale_id = m.connection_for(&p).unwrap().connection_id();
        m.condemn(&p, stale_id);

        m.insert_accepted(p, Box::new(FakeConn::new(p, 999)));
        let current = m.connection_for(&p).expect("accepted connection must land");
        assert_eq!(
            current.connection_id(),
            999,
            "stale entry must be drained before dedup, not the new conn closed"
        );
        m.shutdown();
    }

    /// H1：`Escalate`（RebindFailed）后，dial 生命周期可重新拨通。
    #[test]
    fn dial_recovers_after_escalation() {
        let m = manager();
        let p = peer_id(15);
        m.dial(&p).unwrap();
        let dead_id = m.connection_for(&p).unwrap().connection_id();
        // watcher 在 RebindFailed 时发 Escalate → 适配 sink 只登记谴责。
        m.condemn(&p, dead_id);

        m.dial(&p).expect("dial must recover after condemnation");
        let current = m.connection_for(&p).expect("fresh connection");
        assert_ne!(current.connection_id(), dead_id, "a new conn was dialed");
        assert_eq!(current.connection_id(), 2, "FakeDialer allocates id 2 next");
        m.shutdown();
    }

    /// Escalate 事件经 sink 适配层登记谴责；其他 disposition 不登记。
    #[test]
    fn escalate_event_condemns_via_sink_adapter() {
        let condemned: Arc<Mutex<HashMap<N1PeerId, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let sink = CondemningSink {
            inner: Arc::new(NullSink),
            condemned: Arc::clone(&condemned),
        };
        let p = peer_id(16);
        sink.emit(N1Event {
            peer: p,
            connection_id: 77,
            kind: super::super::N1EventKind::RebindSucceeded,
            disposition: N1Disposition::Retry,
        });
        assert!(
            condemned.lock().unwrap().is_empty(),
            "Retry must not condemn"
        );
        sink.emit(N1Event {
            peer: p,
            connection_id: 77,
            kind: super::super::N1EventKind::RebindFailed {
                reason: "injected".to_string(),
            },
            disposition: N1Disposition::Escalate,
        });
        assert_eq!(condemned.lock().unwrap().get(&p), Some(&77));
    }

    /// 原子条件摘除：id 不符不摘；并发重复摘除恰好一次成功。
    #[test]
    fn remove_if_conn_is_atomic_and_id_checked() {
        let m = Arc::new(manager());
        let p = peer_id(17);
        m.dial(&p).unwrap();
        let id = m.connection_for(&p).unwrap().connection_id();
        assert!(!m.remove_if_conn(&p, id + 1), "wrong id must not remove");
        assert!(m.connection_for(&p).is_some());

        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || m.remove_if_conn(&p, id)));
        }
        let wins = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|removed| *removed)
            .count();
        assert_eq!(wins, 1, "exactly one caller may remove the connection");
        assert!(m.connection_for(&p).is_none());
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

    /// E-3 回归：watcher 阻塞在 `open_keepalive()` 时，`remove()` 必须先
    /// `conn.close()` 打断阻塞再 join。旧顺序（先 `w.shutdown()` join、后
    /// `conn.close()`）在此测试下永久 hang：主线程等 watcher 退出，
    /// watcher 等 close 打断阻塞，形成 join/close 循环等待。
    ///
    /// 替身忠实复现真实语义：`open_keepalive` 阻塞直到 `close()`（trait 契约：
    /// "关闭连接；阻塞中的调用必须随之返回 Closed"）。
    struct HangingKeepaliveConn {
        peer: N1PeerId,
        id: u64,
        closed: Mutex<bool>,
        cv: Condvar,
        entered: Arc<AtomicBool>,
    }

    impl HangingKeepaliveConn {
        fn new(peer: N1PeerId, id: u64, entered: Arc<AtomicBool>) -> Self {
            Self {
                peer,
                id,
                closed: Mutex::new(false),
                cv: Condvar::new(),
                entered,
            }
        }
    }

    impl N1Connection for HangingKeepaliveConn {
        fn send_datagram(&self, _data: &[u8]) -> Result<(), N1Error> {
            Ok(())
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            Err(N1Error::Closed)
        }
        fn open_keepalive(&self) -> Result<super::super::N1KeepaliveStream, N1Error> {
            // watcher 进入阻塞点的确定性信号：测试等它置位后再调 remove，
            // 否则旧顺序可能因"watcher 还没跑到阻塞点"而偶然通过。
            self.entered.store(true, Ordering::SeqCst);
            let guard = self.closed.lock().unwrap();
            let _guard = self.cv.wait_while(guard, |c| !*c).unwrap();
            Err(N1Error::Closed)
        }
        fn accept_keepalive(&self) -> Result<super::super::N1KeepaliveStream, N1Error> {
            // responder 线程用：立即 Closed 让它快速退出，不干扰回归判定。
            Err(N1Error::Closed)
        }
        fn rebind(&self) -> Result<(), N1Error> {
            Ok(())
        }
        fn connection_id(&self) -> u64 {
            self.id
        }
        fn peer(&self) -> N1PeerId {
            self.peer
        }
        fn close(&self) {
            *self.closed.lock().unwrap() = true;
            self.cv.notify_all();
        }
    }

    struct HangingDialer {
        entered: Arc<AtomicBool>,
    }

    impl N1Dialer for HangingDialer {
        fn dial(
            &self,
            peer: &N1PeerId,
            addrs: &[SocketAddr],
        ) -> Result<Box<dyn N1Connection>, N1Error> {
            if addrs.is_empty() {
                return Err(N1Error::PeerUnknown);
            }
            Ok(Box::new(HangingKeepaliveConn::new(
                *peer,
                1,
                Arc::clone(&self.entered),
            )))
        }
    }

    #[test]
    fn remove_wakes_watcher_blocked_in_open_keepalive() {
        let entered = Arc::new(AtomicBool::new(false));
        let m = Arc::new(N1SessionManager::new(
            Arc::new(HangingDialer {
                entered: Arc::clone(&entered),
            }),
            Arc::new(FakeDiscovery),
            Arc::new(NullSink),
            LinkConfig {
                probe_interval: Duration::from_secs(3600),
                heartbeat_timeout: Duration::from_secs(3600),
                enable_rebind: false,
                enable_watcher: true,
            },
        ));
        let p = peer_id(5);
        m.dial(&p).unwrap();
        // 确定性等待：watcher 已进入 open_keepalive 阻塞，再调 remove。
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            entered.load(Ordering::SeqCst),
            "watcher 未进入 open_keepalive 阻塞，测试前置条件不成立"
        );

        // watchdog：hang 翻译成测试失败，而不是把整个 test 二进制卡死。
        let done = Arc::new(AtomicBool::new(false));
        let done_c = Arc::clone(&done);
        let m_c = Arc::clone(&m);
        let handle = thread::spawn(move || {
            m_c.remove(&p);
            done_c.store(true, Ordering::SeqCst);
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            done.load(Ordering::SeqCst),
            "E-3: remove() hung with watcher blocked in open_keepalive"
        );
        handle.join().unwrap();
        assert!(m.connection_for(&p).is_none());
    }
}
