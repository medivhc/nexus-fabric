//! Link 状态观测器（D3/D6）：keepalive 心跳 + 失败触发 `resolve → rebind`。
//!
//! 触发器（M5）：
//! - 主：keepalive 心跳超时（可靠双向流上的 ping/pong，M2）；
//! - 辅：keepalive 流错误。
//!
//! 重要事实（D3 评审）：fabric driver 吞掉了 UDP `send_to` 的 socket 错误
//! （`let _ =`），所以"socket 错误"触发器**不能**依赖 `send_datagram` 返回
//! 错误——心跳超时是唯一的确定性主触发器。
//!
//! 触发后：`discovery.resolve(peer)` → `conn.rebind()`（CID 不变，M4），
//! 并经 `N1EventSink` 上报结构化事件（只判定+上报，不执行重规划，D6）。
//!
//! 线程模型（AGENTS.md §13）：每 peer 一个观测线程（Owner 为
//! `N1SessionManager`，经 `WatcherHandle` 取消/回收）；线程内再分
//! pinger（拥有 keepalive 流：写 ping → 阻塞读 pong）与 watchdog
//!（定时检查 `last_pong`，触发恢复）。对称设计：连接双方各开一条
//! keepalive 流、各自 ping/pong，dial 侧与 accept 侧逻辑一致。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{
    N1Connection, N1Discovery, N1Disposition, N1Error, N1Event, N1EventKind, N1EventSink,
    N1KeepaliveStream, N1PeerId,
};

/// keepalive 心跳协议：16B = 8B magic + 8B seq（大端）。
pub const KEEPALIVE_MAGIC: [u8; 8] = *b"N1KALIVE";
/// 心跳帧长度。
pub const KEEPALIVE_FRAME_LEN: usize = 16;

/// Link 观测配置。
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// 心跳发送间隔（默认 5s，可配置；E4 配 1s）。
    pub probe_interval: Duration,
    /// 心跳超时：超过此时长未收到 pong 即判定 Link 失败。
    pub heartbeat_timeout: Duration,
    /// 失败后是否执行 rebind 恢复。 stationary 端（如 E4 的 A）可关闭，
    /// 避免与 roam 端同时重绑导致 QUIC 迁移混乱。
    pub enable_rebind: bool,
    /// 是否启动 LinkStateWatcher（keepalive 观测）。默认 true。
    /// E4 的 roam 端（B）可关闭：B 在 ROAM 时由外部主动触发 rebind
    /// （模拟 OS 网络变更通知），watcher 的并发流操作会与主动 rebind
    /// 竞态导致连接状态损坏。关闭后 watcher 不启动，rebind 完全由外部驱动。
    pub enable_watcher: bool,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            heartbeat_timeout: Duration::from_secs(15),
            enable_rebind: true,
            enable_watcher: true,
        }
    }
}

/// 观测器句柄：Owner（`N1SessionManager`）持有，`shutdown` 后 join 线程
/// （AGENTS.md §13：谁创建、谁拥有、谁取消、谁回收）。
pub struct WatcherHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WatcherHandle {
    /// 请求停止并回收观测线程。
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// 每 peer 一个 Link 状态观测器。
pub struct LinkStateWatcher {
    peer: N1PeerId,
    conn: Arc<dyn N1Connection>,
    discovery: Arc<dyn N1Discovery>,
    sink: Arc<dyn N1EventSink>,
    config: LinkConfig,
    /// 上次 rebind 时间：rebind 后需要给 QUIC 的 PTO/拥塞恢复留出时间，
    /// 避免"rebind 太频繁、QUIC 来不及发包"的死循环。指数退避。
    last_rebind: Mutex<Option<Instant>>,
    /// 连续 rebind 次数（用于退避计算；心跳恢复后清零）。
    rebind_streak: Mutex<u32>,
}

impl LinkStateWatcher {
    /// 启动观测，返回 Owner 持有的句柄。
    pub fn start(
        peer: N1PeerId,
        conn: Arc<dyn N1Connection>,
        discovery: Arc<dyn N1Discovery>,
        sink: Arc<dyn N1EventSink>,
        config: LinkConfig,
    ) -> WatcherHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let w = Self {
            peer,
            conn,
            discovery,
            sink,
            config,
            last_rebind: Mutex::new(None),
            rebind_streak: Mutex::new(0),
        };
        let stop_c = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name(format!("n1-link-{}", &w.peer.to_hex()[..8]))
            .spawn(move || w.watch(stop_c))
            .expect("link watcher thread spawn");
        WatcherHandle {
            stop,
            thread: Some(thread),
        }
    }

    /// 观测主循环：常驻 responder + pinger/watchdog；流死亡时退避重开。
    /// enable_watcher=false 时只运行 responder（回对端 ping），不主动 ping。
    fn watch(self, stop: Arc<AtomicBool>) {
        // 响应器：接受对端的 keepalive 流并回 pong。生命周期与观测器一致，
        // 退出时由 conn.close() 打断其阻塞的 accept。responder 常开，
        // 即使 enable_watcher=false（E4 roam 端 B 需要回 A 的 ping）。
        let responder_stop = Arc::clone(&stop);
        let responder_conn = Arc::clone(&self.conn);
        let responder = thread::Builder::new()
            .name(format!("n1-karesp-{}", &self.peer.to_hex()[..8]))
            .spawn(move || responder_loop(responder_conn, &responder_stop))
            .expect("keepalive responder thread spawn");

        if !self.config.enable_watcher {
            // 不主动观测：等待停止信号，responder 独立工作。
            while !stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(200));
            }
        } else {
            let mut backoff = Duration::from_millis(200);
            while !stop.load(Ordering::SeqCst) {
                match self.conn.open_keepalive() {
                    Ok(stream) => {
                        backoff = Duration::from_millis(200);
                        self.ping_watch(stream, &stop);
                    }
                    Err(e) => {
                        if matches!(e, N1Error::Closed) || stop.load(Ordering::SeqCst) {
                            break;
                        }
                        // 流暂时打不开（对端响应器未就绪等）：退避重试，不热循环。
                        thread::sleep(backoff);
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                    }
                }
            }
        }
        // 退出路径：打断 responder 的阻塞 accept，保证线程回收（§13）。
        self.conn.close();
        let _ = responder.join();
    }

    /// pinger + watchdog：pinger 线程拥有流（写 ping → 阻塞读 pong，
    /// 更新 `last_pong`）；本线程做超时判定与恢复。
    fn ping_watch(&self, stream: N1KeepaliveStream, stop: &Arc<AtomicBool>) {
        let last_pong = Arc::new(Mutex::new(Instant::now()));
        let last_pong_c = Arc::clone(&last_pong);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let peer = self.peer;
        let pinger = thread::Builder::new()
            .name(format!("n1-kaping-{}", &peer.to_hex()[..8]))
            .spawn(move || pinger_loop(stream, last_pong_c, done_tx))
            .expect("keepalive pinger thread spawn");

        let poll = Duration::from_millis(200).min(self.config.probe_interval);
        loop {
            match done_rx.recv_timeout(poll) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // pinger 退出 = 流错误（辅触发器）：上报并重开流。
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    self.recover("keepalive stream error");
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if stop.load(Ordering::SeqCst) {
                        self.conn.close(); // 打断 pinger 的阻塞读
                        break;
                    }
                    let pong_age = last_pong.lock().unwrap().elapsed();
                    // 心跳健康（近期收到 pong）：重置 rebind 退避计数。
                    if pong_age < self.config.probe_interval * 2 {
                        *self.rebind_streak.lock().unwrap() = 0;
                    }
                    if pong_age > self.config.heartbeat_timeout {
                        self.recover("heartbeat timeout");
                        // FIX（rebind 死循环）：rebind 后旧 keepalive 流已不可靠
                        // （对端迁移前它处于未知状态），必须丢弃并退出，由 watch()
                        // 重开新流。继续复用旧流会导致"流错误→再 rebind"的死循环。
                        break;
                    }
                }
            }
        }
        // 回收 pinger：旧流错误时它会自行退出；若旧流侥幸存活导致阻塞，
        // 超时后分离（它会在连接关闭时退出），避免阻塞恢复流程。
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pinger.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        if pinger.is_finished() {
            let _ = pinger.join();
        }
        // 未结束则 drop JoinHandle 分离线程（Rust drop JoinHandle = detach）。
    }

    /// 恢复：`discovery.resolve(peer)` → `conn.rebind()`，全程结构化事件上报。
    fn recover(&self, reason: &str) {
        let cid = self.conn.connection_id();
        self.sink.emit(N1Event {
            peer: self.peer,
            connection_id: cid,
            kind: N1EventKind::LinkFailed {
                reason: reason.to_string(),
            },
            // 先按"本层可自愈"上报；自愈失败再升级处置。
            disposition: N1Disposition::Retry,
        });
        let addrs = match self.discovery.resolve(&self.peer) {
            Ok(a) if !a.is_empty() => a,
            Ok(_) => {
                self.sink.emit(N1Event {
                    peer: self.peer,
                    connection_id: cid,
                    kind: N1EventKind::LinkFailed {
                        reason: "discovery returned no locators".to_string(),
                    },
                    // 无 locator：本层无法自愈，建议上层尝试备用路径。
                    disposition: N1Disposition::Fallback,
                });
                return;
            }
            Err(e) => {
                self.sink.emit(N1Event {
                    peer: self.peer,
                    connection_id: cid,
                    kind: N1EventKind::LinkFailed {
                        reason: format!("discovery.resolve failed: {e}"),
                    },
                    disposition: N1Disposition::Fallback,
                });
                return;
            }
        };
        // resolve 结果用于审计与诊断；rebind 由传输层按当前 locator 执行
        // （fabric 的 rebind 语义：换本地 socket，QUIC 被动迁移）。
        let _ = addrs;
        if !self.config.enable_rebind {
            // stationary 端：不上报 RebindSucceeded，仅记录跳过。
            return;
        }
        // rebind 退避：死链路后 QUIC 的 PTO/拥塞窗口需要时间恢复，
        // 连续快速 rebind 会打断恢复。指数退避：3s, 6s, 12s, ...，上限 30s。
        let streak = *self.rebind_streak.lock().unwrap();
        let backoff_secs = (3u64 << streak.min(3)).min(30);
        let should_rebind = match *self.last_rebind.lock().unwrap() {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(backoff_secs),
        };
        if !should_rebind {
            // 退避期内：不上报重复 rebind，等待 QUIC 恢复。
            return;
        }
        match self.conn.rebind() {
            Ok(()) => {
                *self.last_rebind.lock().unwrap() = Some(Instant::now());
                *self.rebind_streak.lock().unwrap() = streak + 1;
                self.sink.emit(N1Event {
                    peer: self.peer,
                    connection_id: cid,
                    kind: N1EventKind::RebindSucceeded,
                    disposition: N1Disposition::Retry,
                })
            }
            Err(e) => self.sink.emit(N1Event {
                peer: self.peer,
                connection_id: cid,
                kind: N1EventKind::RebindFailed {
                    reason: e.to_string(),
                },
                disposition: N1Disposition::Escalate,
            }),
        }
    }
}

/// pinger：写 ping → 阻塞读 pong → 更新 `last_pong`；流结束时发 done 信号。
fn pinger_loop(
    mut stream: N1KeepaliveStream,
    last_pong: Arc<Mutex<Instant>>,
    done_tx: mpsc::Sender<()>,
) {
    let mut seq: u64 = 0;
    let mut frame = [0u8; KEEPALIVE_FRAME_LEN];
    loop {
        seq = seq.wrapping_add(1);
        frame[..8].copy_from_slice(&KEEPALIVE_MAGIC);
        frame[8..].copy_from_slice(&seq.to_be_bytes());
        if stream.write_all(&frame).is_err() {
            break;
        }
        let mut pong = [0u8; KEEPALIVE_FRAME_LEN];
        match stream.read_exact(&mut pong) {
            Ok(()) => {
                if pong[..8] == KEEPALIVE_MAGIC {
                    *last_pong.lock().unwrap() = Instant::now();
                }
            }
            Err(_) => break,
        }
    }
    let _ = done_tx.send(());
}

/// keepalive 响应器：阻塞接受对端 keepalive 流，读 ping 回 pong。
fn responder_loop(conn: Arc<dyn N1Connection>, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        let mut stream = match conn.accept_keepalive() {
            Ok(s) => s,
            Err(_) => break, // Closed：watch() 退出时的 conn.close() 会打断
        };
        let mut frame = [0u8; KEEPALIVE_FRAME_LEN];
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            match stream.read_exact(&mut frame) {
                Ok(()) => {
                    if frame[..8] != KEEPALIVE_MAGIC {
                        continue; // 非心跳帧：忽略（鲁棒性）
                    }
                    if stream.write_all(&frame).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;

    /// keepalive 流动作脚本。
    #[derive(Clone, Copy)]
    enum KaAction {
        /// write ping 后 read 返回 pong。
        Pong,
        /// write 成功，read 挂起直到连接关闭（模拟链路中断）。
        Hang,
        /// write 直接失败（模拟流错误）。
        WriteErr,
    }

    /// 可编程的测试替身 keepalive 流。
    struct FakeKaStream {
        script: VecDeque<KaAction>,
        closed: Arc<AtomicBool>,
        pending_pong: Option<u64>,
    }

    impl super::super::N1KeepaliveIo for FakeKaStream {
        fn write_all(&mut self, buf: &[u8]) -> Result<(), N1Error> {
            if self.closed.load(Ordering::SeqCst) {
                return Err(N1Error::Closed);
            }
            assert_eq!(buf.len(), KEEPALIVE_FRAME_LEN);
            assert_eq!(&buf[..8], &KEEPALIVE_MAGIC);
            let seq = u64::from_be_bytes(buf[8..].try_into().unwrap());
            match self.script.pop_front() {
                // 脚本耗尽 = 持续健康（无限 pong）；显式 WriteErr 才模拟流错误。
                Some(KaAction::Pong) | None => {
                    self.pending_pong = Some(seq);
                    Ok(())
                }
                Some(KaAction::Hang) => {
                    // 放回：read_exact 依据 front()==Hang 进入挂起。
                    self.script.push_front(KaAction::Hang);
                    Ok(())
                }
                Some(KaAction::WriteErr) => Err(N1Error::Transport("fake write err".into())),
            }
        }
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), N1Error> {
            if self.closed.load(Ordering::SeqCst) {
                return Err(N1Error::Closed);
            }
            if let Some(seq) = self.pending_pong.take() {
                buf[..8].copy_from_slice(&KEEPALIVE_MAGIC);
                buf[8..].copy_from_slice(&seq.to_be_bytes());
                return Ok(());
            }
            match self.script.front() {
                Some(KaAction::Hang) => {
                    while !self.closed.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(N1Error::Closed)
                }
                _ => Err(N1Error::Closed),
            }
        }
        fn finish(&mut self) -> Result<(), N1Error> {
            Ok(())
        }
    }

    /// 可编程的测试替身连接。
    struct FakeConn {
        peer: N1PeerId,
        id: u64,
        closed: Arc<AtomicBool>,
        rebinds: AtomicUsize,
        streams: Mutex<VecDeque<Vec<KaAction>>>,
    }

    impl N1Connection for FakeConn {
        fn send_datagram(&self, _data: &[u8]) -> Result<(), N1Error> {
            Ok(())
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            Err(N1Error::Closed)
        }
        fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            if self.closed.load(Ordering::SeqCst) {
                return Err(N1Error::Closed);
            }
            match self.streams.lock().unwrap().pop_front() {
                Some(script) => Ok(N1KeepaliveStream::new(Box::new(FakeKaStream {
                    script: script.into(),
                    closed: Arc::clone(&self.closed),
                    pending_pong: None,
                }))),
                None => Err(N1Error::Closed),
            }
        }
        fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            // 响应器无对端可接受：挂起直到关闭（由 watch 退出时的 close 打断）。
            while !self.closed.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
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

    struct FakeDiscovery;
    impl N1Discovery for FakeDiscovery {
        fn resolve(&self, _peer: &N1PeerId) -> Result<Vec<SocketAddr>, N1Error> {
            Ok(vec!["127.0.0.1:9000".parse().unwrap()])
        }
    }

    struct VecSink {
        events: Mutex<Vec<N1Event>>,
    }
    impl N1EventSink for VecSink {
        fn emit(&self, event: N1Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn heartbeat_timeout_triggers_rebind_and_events() {
        // 2 个 pong 后链路中断：watcher 必须触发 resolve → rebind 并上报事件。
        let peer = N1PeerId([7u8; 32]);
        let conn = Arc::new(FakeConn {
            peer,
            id: 42,
            closed: Arc::new(AtomicBool::new(false)),
            rebinds: AtomicUsize::new(0),
            streams: Mutex::new(vec![vec![KaAction::Pong, KaAction::Pong, KaAction::Hang]].into()),
        });
        let sink = Arc::new(VecSink {
            events: Mutex::new(vec![]),
        });
        let handle = LinkStateWatcher::start(
            peer,
            conn.clone(),
            Arc::new(FakeDiscovery),
            sink.clone(),
            LinkConfig {
                probe_interval: Duration::from_millis(50),
                heartbeat_timeout: Duration::from_millis(200),
                enable_rebind: true,
                enable_watcher: true,
            },
        );
        // 等待：2×50ms pong + 200ms 超时 + 恢复，1.5s 裕量充足。
        thread::sleep(Duration::from_millis(1500));
        assert!(
            conn.rebinds.load(Ordering::SeqCst) >= 1,
            "rebind must fire on heartbeat timeout"
        );
        let events = sink.events.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e.kind, N1EventKind::LinkFailed { .. })
                    && e.disposition == N1Disposition::Retry
                    && e.connection_id == 42
                    && e.peer == N1PeerId([7u8; 32])),
            "LinkFailed event with Retry disposition expected, got {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e.kind, N1EventKind::RebindSucceeded)),
            "RebindSucceeded expected, got {events:?}"
        );
        handle.shutdown();
    }

    #[test]
    fn stream_error_triggers_recovery_and_reopen() {
        // 流写错误 → 恢复（rebind）→ 重开流；第二个流给 pong，之后不再触发。
        let peer = N1PeerId([7u8; 32]);
        let conn = Arc::new(FakeConn {
            peer,
            id: 43,
            closed: Arc::new(AtomicBool::new(false)),
            rebinds: AtomicUsize::new(0),
            streams: Mutex::new(
                vec![
                    vec![KaAction::WriteErr],
                    vec![KaAction::Pong, KaAction::Pong, KaAction::Pong],
                ]
                .into(),
            ),
        });
        let sink = Arc::new(VecSink {
            events: Mutex::new(vec![]),
        });
        let handle = LinkStateWatcher::start(
            peer,
            conn.clone(),
            Arc::new(FakeDiscovery),
            sink.clone(),
            LinkConfig {
                probe_interval: Duration::from_millis(50),
                heartbeat_timeout: Duration::from_secs(30),
                enable_rebind: true,
                enable_watcher: true,
            },
        );
        thread::sleep(Duration::from_millis(800));
        assert!(
            conn.rebinds.load(Ordering::SeqCst) >= 1,
            "rebind must fire on keepalive stream error"
        );
        let events = sink.events.lock().unwrap();
        assert!(
            events.iter().any(|e| matches!(
                e.kind,
                N1EventKind::LinkFailed { reason: ref r } if r.contains("keepalive stream error")
            )),
            "stream-error LinkFailed expected, got {events:?}"
        );
        handle.shutdown();
    }

    #[test]
    fn shutdown_reaps_threads_without_rebind() {
        // 健康流：shutdown 不触发 rebind，线程被回收。
        let peer = N1PeerId([7u8; 32]);
        let conn = Arc::new(FakeConn {
            peer,
            id: 44,
            closed: Arc::new(AtomicBool::new(false)),
            rebinds: AtomicUsize::new(0),
            streams: Mutex::new(vec![vec![KaAction::Pong, KaAction::Pong]].into()),
        });
        let sink = Arc::new(VecSink {
            events: Mutex::new(vec![]),
        });
        let handle = LinkStateWatcher::start(
            peer,
            conn.clone(),
            Arc::new(FakeDiscovery),
            sink.clone(),
            LinkConfig {
                probe_interval: Duration::from_millis(50),
                heartbeat_timeout: Duration::from_secs(10),
                enable_rebind: true,
                enable_watcher: true,
            },
        );
        thread::sleep(Duration::from_millis(200));
        handle.shutdown();
        assert_eq!(conn.rebinds.load(Ordering::SeqCst), 0);
        assert!(sink.events.lock().unwrap().is_empty());
        assert!(conn.closed.load(Ordering::SeqCst));
    }

    #[test]
    fn keepalive_constants_sane() {
        assert_eq!(KEEPALIVE_FRAME_LEN, 16);
        assert_eq!(KEEPALIVE_MAGIC, *b"N1KALIVE");
        let d = LinkConfig::default();
        assert_eq!(d.probe_interval, Duration::from_secs(5));
    }
}
