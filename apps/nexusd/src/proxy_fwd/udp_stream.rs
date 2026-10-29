//! UDP 代理流表（PRODUCT §11.18.1 / MODULE P2）：VLESS / AnyTLS 出站的 UDP 承载。
//!
//! - 流键 = （本地源，目的地址）；出站由所属的 `UdpForwarder`（每个 tag 一个）确定。
//!   两个本地 socket 发往同一目的地址各有一条流，回包只回到打开它的源。
//! - 每条流一个 worker 线程：在 dataplane 线程之外建流（`OutboundDialer::open_udp`），
//!   之后循环「排空写命令 → 带短超时读回包」；建流结果、写出、回包与关闭都以事件回到流表。
//! - 流表在 dataplane 线程上记账（时间由调用方传入）：
//!   - 建流期间每条流最多排队 64 个数据报（契约的建流队列）；建流之后未写出的数据以 1 MiB
//!     为上限（写背压，防止节点不读时无限缓存；每个数据报另计 64 B 开销，零长数据报也受限）。
//!     超出的丢弃并计 `udp_send_failed`；
//!   - 建流失败（含节点在确认之前就结束流，如 VLESS 未回响应头即断开）→ 未写出的数据报
//!     每个计一次 `udp_send_failed`，打限频日志 `event=udp_stream_open_failed`
//!     （每 `(tag, cause)` 10 s），同键 1 s 内不重试；
//!   - 任一方向空闲 60 s 关闭；对端关闭或出错同样关闭，下一个数据报重新建流；
//!   - 同时存在的流上限 1024，超出时新流键的数据报丢弃，不驱逐既有流。
//! - Owner = 流表：关闭的 worker 进入回收列表，结束后 join；Drop 时关闭全部流并有界等待。

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nexus_proxy_config::OutboundKind;

use super::ProxyFwdStats;
use super::adapter::{OutboundDialer, UdpStream};
use crate::log_throttle::KeyedLogThrottle;

/// 建流期间每条流的排队上限（数据报数）。
const MAX_QUEUED_DURING_OPEN: u64 = 64;
/// 建流之后每条流未写出的字节上限（写背压）。
const MAX_PENDING_BYTES_AFTER_OPEN: u64 = 1024 * 1024;
/// 写背压里每个数据报的固定开销（缓冲与命令的内存），使零长 / 极小数据报同样受限。
const PER_DATAGRAM_OVERHEAD: u64 = 64;
/// 同时存在的流上限（既有 `MAX_UDP_FLOWS`）。
pub(super) const MAX_STREAMS: usize = 1024;
/// 空闲回收（既有 `UDP_FLOW_TIMEOUT`）。
pub(super) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 建流失败后同一流键的最小重试间隔。
const OPEN_RETRY_SPACING: Duration = Duration::from_secs(1);
/// 建流失败日志的限频间隔（与 `event=udp_unsupported` 相同）。
const OPEN_FAILED_LOG_INTERVAL: Duration = Duration::from_secs(10);
/// worker 读超时 = 两次检查写命令之间的最长间隔，即上行数据报的额外延迟上限。最近
/// `ACTIVE_WINDOW` 内有流量时用短间隔，空闲时用长间隔（少唤醒）。内核把 socket 读超时
/// 向上取整到时钟节拍，真实 socket 上的短间隔约为一个节拍（HZ=250 约 4 ms，HZ=100 为
/// 10 ms）；代价是活跃流每秒数百次唤醒（实测 1024 条活跃流约多 0.65 核，debug 构建）。
/// 读写同线程是这里需要轮询的原因，读写分离是后续改进方向。
const ACTIVE_POLL: Duration = Duration::from_millis(2);
const IDLE_POLL: Duration = Duration::from_millis(20);
const ACTIVE_WINDOW: Duration = Duration::from_secs(1);
/// worker 写超时：对端不读时不无限阻塞。
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Drop 时等待 worker 结束的上限；仍在建流的 worker 在建流返回后立即退出
/// （命令通道已断开），其寿命以拨号超时为界。
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// 节点在确认之前结束流时的建流失败原因。
const UNCONFIRMED_CAUSE: &str = "protocol_handshake";

/// 流键：（本地源，目的地址）。
type StreamKey = (SocketAddr, SocketAddr);

/// 一个回包：来自 `remote`（目的地址），发往 `local`（打开该流的本地源）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpReply {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub payload: Vec<u8>,
}

enum StreamCmd {
    Datagram(Vec<u8>),
    Close,
}

/// worker → 流表。`id` 区分同一流键先后的两条流（旧流的迟到事件不影响新流）。
enum StreamEvent {
    Opened {
        key: StreamKey,
        id: u64,
    },
    OpenFailed {
        key: StreamKey,
        id: u64,
        cause: &'static str,
    },
    Sent {
        key: StreamKey,
        id: u64,
        bytes: u64,
    },
    Reply {
        key: StreamKey,
        id: u64,
        payload: Vec<u8>,
    },
    Closed {
        key: StreamKey,
        id: u64,
    },
}

struct Stream {
    id: u64,
    cmd_tx: Sender<StreamCmd>,
    /// 已建流（决定适用建流队列上限还是写背压上限）。
    opened: bool,
    /// 交给 worker 的数据报数 / 字节数。
    enqueued: u64,
    enqueued_bytes: u64,
    /// worker 已写出的数据报数 / 字节数。
    sent: u64,
    sent_bytes: u64,
    last_activity: Instant,
    worker: JoinHandle<()>,
}

impl Stream {
    /// 本数据报是否超出当前上限。
    fn full(&self, len: u64) -> bool {
        if self.opened {
            self.enqueued_bytes - self.sent_bytes + charge(len) > MAX_PENDING_BYTES_AFTER_OPEN
        } else {
            self.enqueued >= MAX_QUEUED_DURING_OPEN
        }
    }
}

/// 一个数据报在写背压里占用的量。
fn charge(len: u64) -> u64 {
    len + PER_DATAGRAM_OVERHEAD
}

/// 一个出站的 UDP 代理流表（dataplane 线程拥有）。
pub(super) struct StreamTable {
    dialer: Arc<dyn OutboundDialer>,
    kind: OutboundKind,
    tag: String,
    streams: HashMap<StreamKey, Stream>,
    next_id: u64,
    events_tx: Sender<StreamEvent>,
    events_rx: Receiver<StreamEvent>,
    /// 建流失败时刻（重试间隔）。
    failed_at: HashMap<StreamKey, Instant>,
    /// 已关闭、待 join 的 worker。
    closing: Vec<JoinHandle<()>>,
    /// 已收到、尚未交给调用方的回包。
    replies: Vec<UdpReply>,
    open_failures: KeyedLogThrottle,
    /// 实际输出的建流失败日志行（测试观察）。
    #[cfg(test)]
    logged: Vec<String>,
}

impl StreamTable {
    pub(super) fn new(dialer: Arc<dyn OutboundDialer>) -> Self {
        let (events_tx, events_rx) = mpsc::channel();
        Self {
            kind: dialer.kind(),
            tag: dialer.tag().to_string(),
            dialer,
            streams: HashMap::new(),
            next_id: 0,
            events_tx,
            events_rx,
            failed_at: HashMap::new(),
            closing: Vec::new(),
            replies: Vec::new(),
            open_failures: KeyedLogThrottle::new(),
            #[cfg(test)]
            logged: Vec::new(),
        }
    }

    /// 发送一个数据报；进入队列返回 `true`，在本次调用内被丢弃返回 `false`（均已计数）。
    pub(super) fn send(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        payload: Vec<u8>,
        now: Instant,
        stats: &mut ProxyFwdStats,
    ) -> bool {
        self.pump(now, stats);
        let key = (local, remote);
        let len = payload.len() as u64;
        if let Some(stream) = self.streams.get_mut(&key) {
            if stream.full(len) || stream.cmd_tx.send(StreamCmd::Datagram(payload)).is_err() {
                stats.udp_send_failed += 1;
                return false;
            }
            stream.enqueued += 1;
            stream.enqueued_bytes += charge(len);
            stream.last_activity = now;
            return true;
        }
        if self
            .failed_at
            .get(&key)
            .is_some_and(|failed| now.duration_since(*failed) < OPEN_RETRY_SPACING)
            || self.streams.len() >= MAX_STREAMS
        {
            stats.udp_send_failed += 1;
            return false;
        }
        self.failed_at.remove(&key);
        match self.spawn(key, payload, now) {
            Ok(stream) => {
                self.streams.insert(key, stream);
                true
            }
            Err(_) => {
                stats.udp_send_failed += 1;
                false
            }
        }
    }

    /// 处理 worker 事件、回收空闲流与已结束的 worker；返回回包。
    pub(super) fn poll(&mut self, now: Instant, stats: &mut ProxyFwdStats) -> Vec<UdpReply> {
        self.pump(now, stats);
        let idle: Vec<StreamKey> = self
            .streams
            .iter()
            .filter(|(_, stream)| now.duration_since(stream.last_activity) >= STREAM_IDLE_TIMEOUT)
            .map(|(key, _)| *key)
            .collect();
        for key in idle {
            if let Some(stream) = self.streams.remove(&key) {
                let _ = stream.cmd_tx.send(StreamCmd::Close);
                self.retire(stream, stats);
            }
        }
        self.failed_at
            .retain(|_, failed| now.duration_since(*failed) < OPEN_RETRY_SPACING);
        self.reap_finished();
        std::mem::take(&mut self.replies)
    }

    fn spawn(&mut self, key: StreamKey, first: Vec<u8>, now: Instant) -> io::Result<Stream> {
        let id = self.next_id;
        self.next_id += 1;
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let first_len = first.len() as u64;
        let _ = cmd_tx.send(StreamCmd::Datagram(first));
        let dialer = Arc::clone(&self.dialer);
        let events = self.events_tx.clone();
        let worker = std::thread::Builder::new()
            .name("udp-proxy-stream".to_string())
            .spawn(move || run_stream(dialer.as_ref(), key, id, &cmd_rx, &events))?;
        Ok(Stream {
            id,
            cmd_tx,
            opened: false,
            enqueued: 1,
            enqueued_bytes: charge(first_len),
            sent: 0,
            sent_bytes: 0,
            last_activity: now,
            worker,
        })
    }

    fn pump(&mut self, now: Instant, stats: &mut ProxyFwdStats) {
        while let Ok(event) = self.events_rx.try_recv() {
            match event {
                StreamEvent::Opened { key, id } => {
                    if let Some(stream) = self.current(key, id) {
                        stream.opened = true;
                    }
                }
                StreamEvent::Sent { key, id, bytes } => {
                    stats.udp_sent += 1;
                    if let Some(stream) = self.current(key, id) {
                        stream.sent += 1;
                        stream.sent_bytes += charge(bytes);
                    }
                }
                StreamEvent::Reply { key, id, payload } => {
                    if let Some(stream) = self.current(key, id) {
                        stream.last_activity = now;
                    }
                    self.replies.push(UdpReply {
                        local: key.0,
                        remote: key.1,
                        payload,
                    });
                }
                StreamEvent::OpenFailed { key, id, cause } => {
                    if self.current(key, id).is_some()
                        && let Some(stream) = self.streams.remove(&key)
                    {
                        self.failed_at.insert(key, now);
                        self.retire(stream, stats);
                        if let Some(line) = self.open_failed_line(cause, now) {
                            #[cfg(test)]
                            self.logged.push(line.clone());
                            eprintln!("{line}");
                        }
                    }
                }
                StreamEvent::Closed { key, id } => {
                    if self.current(key, id).is_some()
                        && let Some(stream) = self.streams.remove(&key)
                    {
                        self.retire(stream, stats);
                    }
                }
            }
        }
    }

    fn current(&mut self, key: StreamKey, id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&key).filter(|stream| stream.id == id)
    }

    /// 流结束：未写出的数据报计 `udp_send_failed`，worker 进入回收列表。
    fn retire(&mut self, stream: Stream, stats: &mut ProxyFwdStats) {
        stats.udp_send_failed += stream.enqueued.saturating_sub(stream.sent);
        self.closing.push(stream.worker);
    }

    fn reap_finished(&mut self) {
        let mut index = 0;
        while index < self.closing.len() {
            if self.closing[index].is_finished() {
                let _ = self.closing.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
    }

    /// 建流失败日志行（限频后需要输出时返回）。
    fn open_failed_line(&mut self, cause: &str, now: Instant) -> Option<String> {
        let decision = self
            .open_failures
            .decide(&self.tag, cause, now, OPEN_FAILED_LOG_INTERVAL);
        decision.emit.then(|| {
            format!(
                "[proxy-fwd] event=udp_stream_open_failed kind={} tag={} cause={cause} suppressed={}",
                self.kind.as_str(),
                self.tag,
                decision.suppressed
            )
        })
    }

    #[cfg(test)]
    fn live_streams(&self) -> usize {
        self.streams.len()
    }

    #[cfg(test)]
    fn workers_pending_join(&self) -> usize {
        self.closing.len()
    }
}

impl Drop for StreamTable {
    fn drop(&mut self) {
        for (_, stream) in self.streams.drain() {
            let _ = stream.cmd_tx.send(StreamCmd::Close);
            self.closing.push(stream.worker);
        }
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        for worker in self.closing.drain(..) {
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

/// 一条流的 worker：建流，然后在「写命令」与「带超时读回包」之间循环。
fn run_stream(
    dialer: &dyn OutboundDialer,
    key: StreamKey,
    id: u64,
    commands: &Receiver<StreamCmd>,
    events: &Sender<StreamEvent>,
) {
    let mut stream = match dialer.open_udp(key.1) {
        Ok(stream) => stream,
        Err(error) => {
            let _ = events.send(StreamEvent::OpenFailed {
                key,
                id,
                cause: error.reason(),
            });
            return;
        }
    };
    let _ = events.send(StreamEvent::Opened { key, id });
    if stream.set_read_timeout(Some(IDLE_POLL)).is_err()
        || stream
            .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
            .is_err()
    {
        let _ = events.send(StreamEvent::Closed { key, id });
        return;
    }
    if relay(stream.as_mut(), key, id, commands, events) {
        // 节点在确认之前就结束了流：按建流失败处理（日志、重试间隔、计数）。
        let event = if stream.established() {
            StreamEvent::Closed { key, id }
        } else {
            StreamEvent::OpenFailed {
                key,
                id,
                cause: UNCONFIRMED_CAUSE,
            }
        };
        let _ = events.send(event);
    }
    let _ = stream.shutdown();
}

/// 返回 `true` = 流因对端或 I/O 结束（需报告）；`false` = 流表要求关闭。
fn relay(
    stream: &mut dyn UdpStream,
    key: StreamKey,
    id: u64,
    commands: &Receiver<StreamCmd>,
    events: &Sender<StreamEvent>,
) -> bool {
    let mut batch = Vec::new();
    let mut poll = IDLE_POLL;
    let mut last_traffic = Instant::now();
    loop {
        // 先取完当前全部命令：流表已要求关闭时，排在 `Close` 之前的数据报也不再写出。
        loop {
            match commands.try_recv() {
                Ok(StreamCmd::Datagram(datagram)) => batch.push(datagram),
                Ok(StreamCmd::Close) | Err(TryRecvError::Disconnected) => return false,
                Err(TryRecvError::Empty) => break,
            }
        }
        for datagram in batch.drain(..) {
            if stream.send_datagram(&datagram).is_err() {
                return true;
            }
            last_traffic = Instant::now();
            let bytes = datagram.len() as u64;
            let _ = events.send(StreamEvent::Sent { key, id, bytes });
        }
        let wanted = if last_traffic.elapsed() < ACTIVE_WINDOW {
            ACTIVE_POLL
        } else {
            IDLE_POLL
        };
        if wanted != poll {
            if stream.set_read_timeout(Some(wanted)).is_err() {
                return true;
            }
            poll = wanted;
        }
        match stream.recv_datagrams() {
            Ok(Some(datagrams)) => {
                last_traffic = Instant::now();
                for payload in datagrams {
                    let _ = events.send(StreamEvent::Reply { key, id, payload });
                }
            }
            Ok(None) => return true,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return true,
        }
    }
}

#[cfg(test)]
mod tests;
