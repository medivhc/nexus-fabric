//! N1 入站泵（spec §5.3）：rx supervisor + per-connection reader + demux（§5.4）。
//!
//! 线程模型（spec §5.7）：
//! - `nexusd-n1-rx-sup`：每 [`N1_RX_SUPERVISOR_POLL_MS`] 扫 `sessions.peers()`，
//!   以 `(peer, connection_id())` 去重，为每条新连接起一个 reader 线程，
//!   并把 `N1Inbound::ConnUp` 交给 dataplane（入队失败下轮重发，不丢不重）；
//! - `nexusd-n1-rx-<hex8>`：每连接一个 reader，阻塞在 `recv_datagram`，
//!   经 [`demux`] 分类后推入 `N1Inbound` 队列（WP4 在 dataplane 侧消费）。
//!
//! 拒绝/丢弃一律经 §6.1 分类计入 §5.6 的 rx 计数，不做静默丢弃。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Duration;

use nexus_network::n1::session::N1SessionManager;
use nexus_network::n1::{N1Connection, N1Error, N1PeerId};

use crate::log_throttle::KeyedLogThrottle;

pub use crate::n1_runtime::{N1Inbound, N1InboundReject, N1Stats};
/// originator 侧 24-bit stream id 上界（唯一定义点在
/// `nexus_projection::tcp`；此处重导出以满足 spec §7 的 `n1_rx` 路径）。
pub use nexus_projection::tcp::N1_STREAM_ID_MASK;

/// rx supervisor 轮询粒度（spec §8.1 `N1_RX_SUPERVISOR_POLL_MS`）。
pub const N1_RX_SUPERVISOR_POLL_MS: u64 = 500;

/// 拨号退避初值（spec §8.1 `N1_DIAL_RETRY_INITIAL_MS`）。
///
/// 冻结面把本常量定在 `n1_rx.rs`；WP2（dial 生命周期）经
/// [`crate::assembly`] 重导出引用，全仓只此一处字面定义。
pub const N1_DIAL_RETRY_INITIAL_MS: u64 = 1000;

/// 拨号退避封顶（spec §8.1 `N1_DIAL_RETRY_MAX_MS`）。
pub const N1_DIAL_RETRY_MAX_MS: u64 = 30000;

/// transient 读取错误的续读退避（spec §5.3，与 `pump.rs` 同语义）。
const N1_RX_TRANSIENT_BACKOFF_MS: u64 = 10;

/// 歧义帧 WARN 限频窗口（spec §6.1：计数必到，日志限频）。
const N1_RX_AMBIGUOUS_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// demux 判定结果（spec §5.4 五规则的逐条落点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demuxed<'a> {
    /// 规则 2/3：raw IPv4/IPv6 报文。
    RawIp(&'a [u8]),
    /// 规则 4：STREAM 帧（`stream_id u32be | flags | payload`）。
    Stream(&'a [u8]),
    /// 规则 1/5：拒绝并计数（不静默丢）。
    Rejected(N1InboundReject),
}

/// 内容判别 demux（spec §5.4 逐字规则，不改 wire）。
#[must_use]
pub fn demux(datagram: &[u8]) -> Demuxed<'_> {
    // 规则 1：空 datagram。
    let Some(&first) = datagram.first() else {
        return Demuxed::Rejected(N1InboundReject::EmptyDatagram);
    };
    let version = first >> 4;
    // 规则 2：IPv4 且头长/总长谓词自洽。
    let ipv4 = version == 4
        && datagram.len() >= 20
        && datagram.len() >= usize::from(first & 0x0f) * 4
        && datagram.len() >= usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if ipv4 {
        return Demuxed::RawIp(datagram);
    }
    // 规则 3：IPv6 固定头。
    if version == 6 && datagram.len() >= 40 {
        return Demuxed::RawIp(datagram);
    }
    // 规则 4：STREAM 帧下限。
    if datagram.len() >= 5 {
        return Demuxed::Stream(datagram);
    }
    // 规则 5：其余一律歧义。
    Demuxed::Rejected(N1InboundReject::AmbiguousKind { first })
}

/// 入队结果：满/断开都不阻塞 reader（spec §5.3/§5.7）。
enum Enqueued {
    Sent,
    QueueFull,
    Disconnected,
}

fn try_enqueue(tx: &SyncSender<N1Inbound>, msg: N1Inbound) -> Enqueued {
    match tx.try_send(msg) {
        Ok(()) => Enqueued::Sent,
        Err(TrySendError::Full(_)) => Enqueued::QueueFull,
        Err(TrySendError::Disconnected(_)) => Enqueued::Disconnected,
    }
}

fn peer_hex8(peer: &N1PeerId) -> String {
    peer.to_hex().chars().take(8).collect()
}

/// 启动 rx supervisor 线程（spec §7 冻结签名）。
///
/// # Errors
/// 线程创建失败时返回 `std::io::Error`（调用方 WARN，daemon 继续）。
pub fn spawn_n1_receiver(
    sessions: Arc<N1SessionManager>,
    tx: SyncSender<N1Inbound>,
    stats: Arc<N1Stats>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("nexusd-n1-rx-sup".to_string())
        .spawn(move || {
            run_supervisor(&sessions, &tx, &stats, &shutdown, N1_RX_SUPERVISOR_POLL_MS);
        })
}

/// supervisor 主循环：按 `(peer, connection_id())` 去重起 reader，
/// 并保证 `ConnUp` 至少成功入队一次（满则下轮重发）。
fn run_supervisor(
    sessions: &Arc<N1SessionManager>,
    tx: &SyncSender<N1Inbound>,
    stats: &Arc<N1Stats>,
    shutdown: &AtomicBool,
    poll_ms: u64,
) {
    let mut readers: HashMap<N1PeerId, ReaderSlot> = HashMap::new();
    while !shutdown.load(Ordering::SeqCst) {
        for peer in sessions.peers() {
            let Some(conn) = sessions.connection_for(&peer) else {
                continue;
            };
            let conn_id = conn.connection_id();
            match readers.get_mut(&peer) {
                Some(slot) if slot.conn_id == conn_id => {
                    if !slot.conn_up_sent {
                        match try_enqueue(
                            tx,
                            N1Inbound::ConnUp {
                                peer,
                                conn: Arc::clone(&conn),
                            },
                        ) {
                            Enqueued::Sent => slot.conn_up_sent = true,
                            // 满：计数，下一轮重发（不丢、不重复起 reader）。
                            Enqueued::QueueFull => stats.record_rx_queue_full(),
                            // dataplane 侧已退出：无消费者，supervisor 收工。
                            Enqueued::Disconnected => {
                                eprintln!("[n1-rx] inbound queue disconnected; supervisor exiting");
                                return;
                            }
                        }
                    }
                }
                _ => {
                    // 新连接，或同一 peer 换了 connection_id（重拨/rebind 语义：
                    // rebind 不变 id；新 id 意味着旧 reader 所属 conn 已关闭）。
                    if let Some(old) = readers.remove(&peer) {
                        old.stop.store(true, Ordering::SeqCst);
                        // 旧 reader 阻塞在 recv_datagram；其 conn 已关闭后自然
                        // 退出。不 join（join 会阻塞 supervisor 轮询）。
                    }
                    // 先入队 ConnUp，再起 reader：保证 dataplane 在无数据时
                    // 也能先拿到回程 conn（spec §5.3）。
                    let mut conn_up_sent = false;
                    match try_enqueue(
                        tx,
                        N1Inbound::ConnUp {
                            peer,
                            conn: Arc::clone(&conn),
                        },
                    ) {
                        Enqueued::Sent => conn_up_sent = true,
                        Enqueued::QueueFull => stats.record_rx_queue_full(),
                        Enqueued::Disconnected => {
                            eprintln!("[n1-rx] inbound queue disconnected; supervisor exiting");
                            return;
                        }
                    }
                    let stop = Arc::new(AtomicBool::new(false));
                    match spawn_reader(peer, Arc::clone(&conn), conn_id, tx, stats, stop, sessions)
                    {
                        Ok((join, reader_stop)) => {
                            readers.insert(
                                peer,
                                ReaderSlot {
                                    conn_id,
                                    stop: reader_stop,
                                    join: Some(join),
                                    conn_up_sent,
                                },
                            );
                        }
                        Err(error) => {
                            eprintln!(
                                "[n1-rx] peer={} reader spawn failed reason={error}",
                                peer_hex8(&peer)
                            );
                        }
                    }
                }
            }
        }

        // 会话表里已消失的 peer：通知其 reader 停止并回收槽位。
        readers.retain(|peer, slot| {
            let live = sessions
                .connection_for(peer)
                .is_some_and(|conn| conn.connection_id() == slot.conn_id);
            if !live {
                slot.stop.store(true, Ordering::SeqCst);
            }
            live
        });

        std::thread::sleep(Duration::from_millis(poll_ms));
    }

    for slot in readers.values() {
        slot.stop.store(true, Ordering::SeqCst);
    }
}

struct ReaderSlot {
    conn_id: u64,
    stop: Arc<AtomicBool>,
    /// 仅持有以便随槽位丢弃（detach）；不在 supervisor 线程 join
    /// （reader 阻塞在 `recv_datagram`，join 会拖住轮询与 shutdown）。
    #[allow(dead_code)]
    join: Option<std::thread::JoinHandle<()>>,
    conn_up_sent: bool,
}

/// 启动 per-connection reader 线程（`nexusd-n1-rx-<hex8>`）。
fn spawn_reader(
    peer: N1PeerId,
    conn: Arc<dyn N1Connection>,
    conn_id: u64,
    tx: &SyncSender<N1Inbound>,
    stats: &Arc<N1Stats>,
    stop: Arc<AtomicBool>,
    sessions: &Arc<N1SessionManager>,
) -> std::io::Result<(std::thread::JoinHandle<()>, Arc<AtomicBool>)> {
    let name = format!("nexusd-n1-rx-{}", peer_hex8(&peer));
    let tx = tx.clone();
    let stats = Arc::clone(stats);
    let reader_stop = Arc::clone(&stop);
    let sessions = Arc::clone(sessions);
    let handle = std::thread::Builder::new().name(name).spawn(move || {
        reader_loop(peer, conn, conn_id, tx, stats, reader_stop, sessions);
    })?;
    Ok((handle, stop))
}

/// reader 主循环（spec §5.3）：
/// - `Ok(d)` → 计数 → demux → 入队；满则计 `queue_full` 丢该 datagram；
/// - `Closed/PeerClosed` → `sessions.remove` → `rx_conn_closed` → 退出；
/// - 其它错误 → `rx_transient_errors` → 10ms 后续读，不退出。
fn reader_loop(
    peer: N1PeerId,
    conn: Arc<dyn N1Connection>,
    conn_id: u64,
    tx: SyncSender<N1Inbound>,
    stats: Arc<N1Stats>,
    stop: Arc<AtomicBool>,
    sessions: Arc<N1SessionManager>,
) {
    let mut throttle = KeyedLogThrottle::new();
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match conn.recv_datagram() {
            Ok(datagram) => {
                stats.record_rx_datagram(datagram.len());
                let msg = match demux(&datagram) {
                    Demuxed::RawIp(_) => {
                        stats.record_rx_raw_ip();
                        N1Inbound::RawIp {
                            peer,
                            packet: datagram,
                        }
                    }
                    Demuxed::Stream(_) => {
                        stats.record_rx_stream_frame();
                        N1Inbound::Stream {
                            peer,
                            conn: Arc::clone(&conn),
                            frame: datagram,
                        }
                    }
                    Demuxed::Rejected(reject) => {
                        stats.record_rx_rejected(reject);
                        if let N1InboundReject::AmbiguousKind { first } = reject {
                            stats.record_rx_ambiguous();
                            let decision = throttle.decide(
                                "n1-rx",
                                "ambiguous",
                                std::time::Instant::now(),
                                N1_RX_AMBIGUOUS_LOG_INTERVAL,
                            );
                            if decision.emit {
                                eprintln!(
                                    "[n1-rx] WARN: rejected reason=ambiguous first={first:#04x} suppressed={}",
                                    decision.suppressed
                                );
                            }
                        }
                        continue;
                    }
                };
                match try_enqueue(&tx, msg) {
                    Enqueued::Sent => {}
                    Enqueued::QueueFull => stats.record_rx_queue_full(),
                    // dataplane 侧已退出：没有消费者，reader 收工并撤下回程 conn。
                    Enqueued::Disconnected => {
                        eprintln!(
                            "[n1-rx] peer={} inbound queue disconnected; reader exiting",
                            peer_hex8(&peer)
                        );
                        break;
                    }
                }
            }
            Err(N1Error::Closed) | Err(N1Error::PeerClosed(_)) => {
                stats.record_rx_conn_closed();
                remove_if_current(&sessions, peer, conn_id);
                break;
            }
            Err(_) => {
                stats.record_rx_transient_error();
                std::thread::sleep(Duration::from_millis(N1_RX_TRANSIENT_BACKOFF_MS));
            }
        }
    }
    if matches!(
        try_enqueue(&tx, N1Inbound::ConnDown { peer }),
        Enqueued::QueueFull
    ) {
        stats.record_rx_queue_full();
    }
}

/// 只移除「仍指向本 reader 连接」的会话项，避免旧 reader 误删新拨通的连接。
fn remove_if_current(sessions: &N1SessionManager, peer: N1PeerId, conn_id: u64) {
    let current_is_ours = sessions
        .connection_for(&peer)
        .is_some_and(|conn| conn.connection_id() == conn_id);
    if current_is_ours {
        sessions.remove(&peer);
    } else if sessions.connection_for(&peer).is_some() {
        eprintln!(
            "[n1-rx] peer={} stale reader for conn={conn_id} exited without removing rebound session",
            peer_hex8(&peer)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::sync_channel;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use nexus_network::n1::link::LinkConfig;
    use nexus_network::n1::session::N1SessionManager;
    use nexus_network::n1::{N1Dialer, N1Discovery, N1Event, N1EventSink, N1KeepaliveStream};
    use nexus_projection::tcp::{N1_STREAM_ID_MASK, encode_stream_frame};

    /// 可控入站队列的测试连接；`close()` 让阻塞中的 `recv_datagram` 返回 `Closed`。
    struct TestConn {
        peer: N1PeerId,
        id: u64,
        inbox: Mutex<VecDeque<Result<Vec<u8>, N1Error>>>,
        wake: Condvar,
        closed: AtomicBool,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl TestConn {
        fn new(peer: N1PeerId, id: u64) -> Arc<Self> {
            Arc::new(Self {
                peer,
                id,
                inbox: Mutex::new(VecDeque::new()),
                wake: Condvar::new(),
                closed: AtomicBool::new(false),
                sent: Mutex::new(Vec::new()),
            })
        }

        fn push(&self, item: Result<Vec<u8>, N1Error>) {
            self.inbox.lock().unwrap().push_back(item);
            self.wake.notify_all();
        }
    }

    impl N1Connection for TestConn {
        fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
            if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(N1Error::Closed);
            }
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }

        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            loop {
                let mut inbox = self.inbox.lock().unwrap();
                if let Some(item) = inbox.pop_front() {
                    return item;
                }
                if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(N1Error::Closed);
                }
                let _ = self
                    .wake
                    .wait_timeout(inbox, Duration::from_millis(20))
                    .unwrap();
            }
        }

        fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }

        fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
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
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
            self.wake.notify_all();
        }
    }

    /// 让测试同时持有 `Arc<TestConn>`（推数据）与 `Box<dyn N1Connection>`（登记会话）。
    struct Shared(Arc<TestConn>);

    impl N1Connection for Shared {
        fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
            self.0.send_datagram(data)
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            self.0.recv_datagram()
        }
        fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            self.0.open_keepalive()
        }
        fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            self.0.accept_keepalive()
        }
        fn rebind(&self) -> Result<(), N1Error> {
            self.0.rebind()
        }
        fn connection_id(&self) -> u64 {
            self.0.connection_id()
        }
        fn peer(&self) -> N1PeerId {
            self.0.peer()
        }
        fn close(&self) {
            self.0.close();
        }
    }

    struct NullDialer;
    impl N1Dialer for NullDialer {
        fn dial(
            &self,
            _peer: &N1PeerId,
            _addrs: &[std::net::SocketAddr],
        ) -> Result<Box<dyn N1Connection>, N1Error> {
            Err(N1Error::PeerUnknown)
        }
    }

    struct NullDiscovery;
    impl N1Discovery for NullDiscovery {
        fn resolve(&self, _peer: &N1PeerId) -> Result<Vec<std::net::SocketAddr>, N1Error> {
            Ok(Vec::new())
        }
    }

    struct NullSink;
    impl N1EventSink for NullSink {
        fn emit(&self, _event: N1Event) {}
    }

    fn peer_id(n: u8) -> N1PeerId {
        N1PeerId([n; 32])
    }

    fn manager() -> Arc<N1SessionManager> {
        Arc::new(N1SessionManager::new(
            Arc::new(NullDialer),
            Arc::new(NullDiscovery),
            Arc::new(NullSink),
            LinkConfig {
                probe_interval: Duration::from_secs(3600),
                heartbeat_timeout: Duration::from_secs(3600),
                enable_rebind: false,
                // 测试连接没有真 keepalive：watcher 一开就会 open_keepalive
                // 失败并 conn.close()，会抢在 reader 前把连接关掉。
                enable_watcher: false,
            },
        ))
    }

    fn ipv4_datagram() -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        pkt[9] = 17;
        pkt
    }

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !cond() {
            assert!(Instant::now() < deadline, "timeout waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn start_reader(
        conn: &Arc<TestConn>,
        sessions: &Arc<N1SessionManager>,
        tx: &std::sync::mpsc::SyncSender<N1Inbound>,
        stats: &Arc<N1Stats>,
        stop: &Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        let peer = conn.peer;
        let id = conn.id;
        let conn: Arc<dyn N1Connection> = conn.clone();
        let tx = tx.clone();
        let sessions = Arc::clone(sessions);
        let stats = Arc::clone(stats);
        let stop = Arc::clone(stop);
        std::thread::spawn(move || reader_loop(peer, conn, id, tx, stats, stop, sessions))
    }

    fn start_supervisor(
        sessions: &Arc<N1SessionManager>,
        tx: &std::sync::mpsc::SyncSender<N1Inbound>,
        stats: &Arc<N1Stats>,
        shutdown: &Arc<AtomicBool>,
        poll_ms: u64,
    ) -> std::thread::JoinHandle<()> {
        let sessions = Arc::clone(sessions);
        let stats = Arc::clone(stats);
        let shutdown = Arc::clone(shutdown);
        let tx = tx.clone();
        std::thread::spawn(move || run_supervisor(&sessions, &tx, &stats, &shutdown, poll_ms))
    }

    // ---- demux 五规则（spec §5.4）------------------------------------------

    #[test]
    fn demux_rule2_classifies_raw_ipv4() {
        let pkt = ipv4_datagram();
        assert_eq!(demux(&pkt), Demuxed::RawIp(&pkt[..]));
    }

    #[test]
    fn demux_rule3_classifies_raw_ipv6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[6] = 17;
        assert_eq!(demux(&pkt), Demuxed::RawIp(&pkt[..]));
    }

    #[test]
    fn demux_rule4_classifies_stream_frame() {
        let frame = encode_stream_frame(7, 0x00, b"hi");
        assert_eq!(frame[0], 0x00);
        assert_eq!(demux(&frame), Demuxed::Stream(&frame[..]));
    }

    #[test]
    fn demux_rule4_does_not_swallow_short_stream_frames() {
        // 4 bytes is below the 5-byte STREAM minimum and is not a valid IP
        // header either -> rule 5 ambiguous.
        let short = [0x00, 0x00, 0x00, 0x07];
        assert_eq!(
            demux(&short),
            Demuxed::Rejected(N1InboundReject::AmbiguousKind { first: 0x00 })
        );
    }

    #[test]
    fn demux_rule1_rejects_empty_datagram() {
        assert_eq!(
            demux(&[]),
            Demuxed::Rejected(N1InboundReject::EmptyDatagram)
        );
    }

    #[test]
    fn demux_rule5_rejects_ambiguous_kind() {
        // IPv4 nibble but shorter than the 20-byte minimum header, and
        // shorter than a 5-byte STREAM frame.
        let junk = [0x45, 0x00];
        assert_eq!(
            demux(&junk),
            Demuxed::Rejected(N1InboundReject::AmbiguousKind { first: 0x45 })
        );
    }

    #[test]
    fn demux_ipv4_with_inconsistent_total_length_falls_through_to_stream() {
        // Rule 2 needs the declared total length to fit in the datagram;
        // otherwise a >= 5 byte datagram is a STREAM frame (rule 4).
        let mut pkt = ipv4_datagram();
        pkt[2..4].copy_from_slice(&2000u16.to_be_bytes());
        assert_eq!(demux(&pkt), Demuxed::Stream(&pkt[..]));
    }

    #[test]
    fn demux_24_bit_stream_ids_are_never_mistaken_for_ip() {
        for id in [1, 0x0000_00FF, N1_STREAM_ID_MASK] {
            let frame = encode_stream_frame(id, 0x00, b"payload");
            assert_eq!(demux(&frame), Demuxed::Stream(&frame[..]));
        }
    }

    // ---- reader（spec §5.3）------------------------------------------------

    #[test]
    fn reader_on_closed_removes_session_and_emits_conn_down() {
        let peer = peer_id(7);
        let conn = TestConn::new(peer, 11);
        let sessions = manager();
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&conn))));
        let stats = Arc::new(N1Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel(8);
        let handle = start_reader(&conn, &sessions, &tx, &stats, &stop);

        conn.push(Err(N1Error::PeerClosed(0)));
        handle.join().expect("reader exits on Closed");

        assert!(
            sessions.connection_for(&peer).is_none(),
            "Closed must remove the peer from the session table"
        );
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rx_conn_closed, 1);
        assert_eq!(snapshot.rx_rejected, 0);
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(N1Inbound::ConnDown { peer: down }) => assert_eq!(down, peer),
            _ => panic!("expected ConnDown after reader exit"),
        }
    }

    #[test]
    fn reader_survives_transient_errors() {
        let peer = peer_id(8);
        let conn = TestConn::new(peer, 12);
        let sessions = manager();
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&conn))));
        let stats = Arc::new(N1Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel(8);
        let handle = start_reader(&conn, &sessions, &tx, &stats, &stop);

        conn.push(Err(N1Error::Transport("transient".to_string())));
        conn.push(Ok(ipv4_datagram()));
        wait_until("raw ip delivered", || stats.snapshot().rx_raw_ip == 1);
        assert_eq!(stats.snapshot().rx_transient_errors, 1);
        assert!(
            sessions.connection_for(&peer).is_some(),
            "transient errors must not tear the session down"
        );

        conn.push(Err(N1Error::Closed));
        handle.join().expect("reader exits on Closed");
        let mut saw_raw_ip = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, N1Inbound::RawIp { .. }) {
                saw_raw_ip = true;
            }
        }
        assert!(saw_raw_ip, "raw IP must reach the inbound queue");
        assert_eq!(stats.snapshot().rx_conn_closed, 1);
    }

    #[test]
    fn reader_counts_rejections_instead_of_dropping_silently() {
        let peer = peer_id(9);
        let conn = TestConn::new(peer, 13);
        let sessions = manager();
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&conn))));
        let stats = Arc::new(N1Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel(8);
        let handle = start_reader(&conn, &sessions, &tx, &stats, &stop);

        conn.push(Ok(Vec::new())); // empty
        conn.push(Ok(vec![0x45, 0x00])); // ambiguous
        conn.push(Ok(encode_stream_frame(3, 0x00, b"x")));
        wait_until("stream frame delivered", || {
            stats.snapshot().rx_stream_frames == 1
        });
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rx_datagrams, 3);
        assert_eq!(snapshot.rx_bytes, 2 + 6);
        assert_eq!(snapshot.rx_rejected, 2);
        assert_eq!(snapshot.rx_ambiguous, 1);
        assert_eq!(snapshot.rx_stream_frames, 1);
        assert_eq!(snapshot.rx_raw_ip, 0);

        conn.push(Err(N1Error::Closed));
        handle.join().expect("reader exits on Closed");
        let mut saw_stream = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, N1Inbound::Stream { .. }) {
                saw_stream = true;
            }
        }
        assert!(saw_stream, "stream frame must reach the inbound queue");
    }

    #[test]
    fn reader_counts_queue_full_and_keeps_reading() {
        let peer = peer_id(10);
        let conn = TestConn::new(peer, 14);
        let sessions = manager();
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&conn))));
        let stats = Arc::new(N1Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        // Capacity 1: pre-fill so the first datagram hits a full queue.
        let (tx, rx) = sync_channel(1);
        tx.send(N1Inbound::ConnDown { peer }).unwrap();
        let handle = start_reader(&conn, &sessions, &tx, &stats, &stop);

        conn.push(Ok(ipv4_datagram()));
        wait_until("queue full counted", || stats.snapshot().rx_queue_full == 1);
        assert_eq!(stats.snapshot().rx_rejected, 1);
        assert!(
            sessions.connection_for(&peer).is_some(),
            "a full queue must not tear the reader down"
        );

        // Drain the slot, then a later datagram must be delivered.
        assert!(matches!(rx.recv().unwrap(), N1Inbound::ConnDown { .. }));
        conn.push(Ok(ipv4_datagram()));
        wait_until("second datagram delivered", || {
            stats.snapshot().rx_raw_ip == 2
        });

        conn.push(Err(N1Error::Closed));
        handle.join().expect("reader exits on Closed");
    }

    // ---- supervisor（spec §5.3）--------------------------------------------

    #[test]
    fn supervisor_starts_one_reader_per_connection_and_sends_conn_up_once() {
        let peer = peer_id(11);
        let conn = TestConn::new(peer, 21);
        let sessions = manager();
        let stats = Arc::new(N1Stats::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel(16);

        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&conn))));
        let handle = start_supervisor(&sessions, &tx, &stats, &shutdown, 20);

        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(N1Inbound::ConnUp {
                peer: up,
                conn: up_conn,
            }) => {
                assert_eq!(up, peer);
                assert_eq!(up_conn.connection_id(), 21);
            }
            _ => panic!("expected ConnUp first"),
        }

        conn.push(Ok(ipv4_datagram()));
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(N1Inbound::RawIp { peer: from, packet }) => {
                assert_eq!(from, peer);
                assert_eq!(packet, ipv4_datagram());
            }
            _ => panic!("expected RawIp from the reader"),
        }

        // Many more supervisor polls: no duplicate reader, no duplicate ConnUp.
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            rx.try_recv().is_err(),
            "a single connection must yield a single reader/ConnUp"
        );

        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        handle.join().expect("supervisor exits on shutdown");
    }

    #[test]
    fn supervisor_retries_conn_up_while_the_queue_is_full() {
        let peer = peer_id(12);
        let conn = TestConn::new(peer, 22);
        let sessions = manager();
        let stats = Arc::new(N1Stats::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        // Capacity 1 pre-filled: the first ConnUp send must fail and be
        // retried on the next poll instead of being dropped.
        let (tx, rx) = sync_channel(1);
        tx.send(N1Inbound::ConnDown { peer }).unwrap();
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&conn))));
        let handle = start_supervisor(&sessions, &tx, &stats, &shutdown, 20);

        wait_until("queue full counted", || stats.snapshot().rx_queue_full >= 1);
        assert!(matches!(rx.recv().unwrap(), N1Inbound::ConnDown { .. }));
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(N1Inbound::ConnUp { peer: up, .. }) => assert_eq!(up, peer),
            _ => panic!("ConnUp must be retried after the queue drains"),
        }

        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        handle.join().expect("supervisor exits on shutdown");
    }

    #[test]
    fn supervisor_does_not_remove_rebound_session_from_stale_reader() {
        // A reader must only remove the session entry that still points at
        // its own connection id; otherwise a stale reader would tear down a
        // freshly re-dialed connection.
        let peer = peer_id(13);
        let old = TestConn::new(peer, 31);
        let new = TestConn::new(peer, 32);
        let sessions = manager();
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&old))));
        let stats = Arc::new(N1Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = sync_channel(8);
        let handle = start_reader(&old, &sessions, &tx, &stats, &stop);

        // Rebind: session now holds the new connection while the old reader
        // is still winding down.
        sessions.remove(&peer);
        sessions.insert_accepted(peer, Box::new(Shared(Arc::clone(&new))));
        old.push(Err(N1Error::Closed));
        handle.join().expect("reader exits on Closed");

        let current = sessions
            .connection_for(&peer)
            .expect("new connection must survive the stale reader");
        assert_eq!(current.connection_id(), 32);
        assert_eq!(stats.snapshot().rx_conn_closed, 1);
    }
}
