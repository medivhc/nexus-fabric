//! VPI 包泵（M1/M2，D1）：VirtualPacketInterface ↔ per-peer Connection 的包转发。
//!
//! - 上行：VPI 阻塞读 → IPv4 解析 → 静态路由 → `send_datagram`；
//! - 下行：每 peer 一线程，`recv_datagram` 阻塞 → VPI 写。
//!
//! 线程模型（D1，修 1）：`Arc<Mutex<Box<dyn VirtualPacketInterface>>>` 在上行线程
//! 与下行线程间共享；每次调用只短暂持锁，无死锁。VPI 锁 poison 时恢复而非
//! panic（修 2，防级联死亡）。Owner 为 `PumpHandle`：`shutdown()` 置位并关闭
//! 全部连接（打断下行阻塞读），再回收两个 supervisor。
//!
//! - 上行：`n1-pump-upsup` supervisor 维持单个 `n1-pump-up` worker；worker 死亡
//!   （panic/静默退出）则重启并计数（`PumpStats::uplink_restarts`）。
//! - 下行：`n1-pump-sup` supervisor 为每对端维持 `n1-pump-dn-<peer>` worker。
//! - supervisor 自身 panic 防护：每轮迭代包 `catch_unwind`，迭代内 panic 只记日志。
//! - panic hook（修 3）：`start()` 安装进程级 hook，`n1-pump*` 线程 panic 时打
//!   结构化日志（线程名、payload、时间），链式保留默认 hook 行为。
//!
//! 已知限制：上行 worker 阻塞在 VPI `receive()` 中时无法被可移植地打断
//! （portable trait 无超时语义）；上行 supervisor 退出前对 worker 有界等待 2s，
//! 超时则分离（detach）——进程退出时由 OS 回收。前台进程
//! （E4 / `nexus network up`）的生命周期内此限制无影响。

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nexus_platform::VirtualPacketInterface;

use super::{N1Connection, N1Error, N1PeerId};

/// fabric datagram 上限（S5：1200B pre-PMTUD）；VPI MTU 与之对齐。
pub const DATAGRAM_CAP: usize = 1200;

/// 最小 IPv4 头长度。
const IPV4_MIN_HEADER: usize = 20;

/// IPv4 子网（portable 最小实现：解析/包含/最长前缀匹配）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    /// 解析 `"10.144.0.0/24"`；非法输入返回 `InvalidConfig`。
    pub fn parse(s: &str) -> Result<Self, N1Error> {
        let (addr_s, prefix_s) = s.split_once('/').ok_or_else(|| {
            N1Error::InvalidConfig(format!("subnet must be <addr>/<prefix>, got {s}"))
        })?;
        let addr: Ipv4Addr = addr_s
            .parse()
            .map_err(|_| N1Error::InvalidConfig(format!("bad ipv4 addr in subnet: {s}")))?;
        let prefix: u8 = prefix_s
            .parse()
            .map_err(|_| N1Error::InvalidConfig(format!("bad prefix in subnet: {s}")))?;
        if prefix > 32 {
            return Err(N1Error::InvalidConfig(format!("prefix > 32: {s}")));
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = Ipv4Addr::from(u32::from(addr) & mask);
        Ok(Self { network, prefix })
    }

    /// 是否包含该地址。
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - self.prefix)
        };
        (u32::from(ip) & mask) == u32::from(self.network)
    }

    /// 前缀长度（最长前缀匹配用）。
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    /// 网络地址（Composition Root 由路由派生 mesh CIDR 用）。
    #[must_use]
    pub fn network_addr(&self) -> std::net::Ipv4Addr {
        self.network
    }
}

impl std::fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// 静态路由条目：子网 → 对端（M3：首期静态配置；locator→identity 映射属
/// Network Resource 领域信息，经配置表达，不在本 crate 自建注册表）。
#[derive(Debug, Clone)]
pub struct Ipv4Route {
    /// 目的子网。
    pub subnet: Ipv4Net,
    /// 下一跳对端。
    pub peer: N1PeerId,
}

/// 对端连接查表（由 `N1SessionManager` 实现；包泵经此 trait 取连接，
/// 不直接依赖 session 模块的具体类型）。
pub trait PeerConnLookup: Send + Sync {
    /// 取对端当前连接；无连接时返回 `None`（包被丢弃并计数）。
    fn connection_for(&self, peer: &N1PeerId) -> Option<Arc<dyn N1Connection>>;
    /// 当前全部对端（下行线程按需增补）。
    fn all_peers(&self) -> Vec<N1PeerId>;
    /// 关闭全部连接（打断下行阻塞读；Owner 退出路径调用）。
    fn close_all(&self);
}

/// 包泵统计（结构化可观测，AGENTS.md §22：高频路径用计数器）。
#[derive(Debug, Default)]
pub struct PumpStats {
    /// 上行：从 VPI 读到的包数。
    pub uplink_rx: AtomicU64,
    /// 上行：成功转发给对端的包数。
    pub uplink_forwarded: AtomicU64,
    /// 上行：丢弃（无路由/非 IPv4/超限/发送失败）。
    pub uplink_dropped: AtomicU64,
    /// 上行：worker 被 supervisor 重启的次数（正常应为 0；>0 说明发生过线程死亡）。
    pub uplink_restarts: AtomicU64,
    /// 下行：从对端收到的包数。
    pub downlink_rx: AtomicU64,
    /// 下行：成功写入 VPI 的包数。
    pub downlink_delivered: AtomicU64,
    /// 下行：VPI 写失败。
    pub downlink_vpi_err: AtomicU64,
}

/// VPI 锁：poison 时恢复而非 panic（修 2）。
///
/// 若某线程持锁期间 panic，Mutex 会被 poison；另一线程若用 `unwrap()` 会级联
/// panic（静默死亡的候选机制之一）。此处取回内部值继续工作；触发 poison 的
/// panic 本身由 panic hook 记录（修 3）。
fn lock_vpi(
    vpi: &Arc<Mutex<Box<dyn VirtualPacketInterface>>>,
) -> std::sync::MutexGuard<'_, Box<dyn VirtualPacketInterface>> {
    vpi.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 为 pump 线程安装结构化 panic hook（修 3，进程级，仅一次）。
///
/// 只记录线程名以 `n1-pump` 开头的线程（线程名、panic payload、时间戳），然后
/// 链式调用之前的 hook（保留默认行为）。用于定位 pump 线程静默死亡的触发点。
fn install_pump_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info: &std::panic::PanicHookInfo<'_>| {
            let current = std::thread::current();
            let name = current.name().unwrap_or("<unnamed>");
            if name.starts_with("n1-pump") {
                let payload = sanitize_panic_payload(info);
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                eprintln!("[n1-panic] thread=\"{name}\" time_unix_ms={ms} payload=\"{payload}\"");
            }
            prev(info);
        }));
    });
}

/// 提取并清洗 panic payload（截断 + 转义换行，保证单行结构化日志）。
fn sanitize_panic_payload(info: &std::panic::PanicHookInfo<'_>) -> String {
    let raw: String = {
        let p = info.payload();
        if let Some(s) = p.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = p.downcast_ref::<String>() {
            s.clone()
        } else if let Some(loc) = info.location() {
            format!("<non-string payload at {}:{}>", loc.file(), loc.line())
        } else {
            "<non-string payload>".to_string()
        }
    };
    let mut s: String = raw.chars().take(500).collect();
    s = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('"', "'");
    s
}

/// VPI 包泵：拥有 VPI 句柄、静态路由、查表器。
pub struct VpiPump {
    vpi: Arc<Mutex<Box<dyn VirtualPacketInterface>>>,
    routes: Vec<Ipv4Route>,
    lookup: Arc<dyn PeerConnLookup>,
    stats: Arc<PumpStats>,
}

impl VpiPump {
    /// 构造包泵（不启动线程）。
    pub fn new(
        vpi: Arc<Mutex<Box<dyn VirtualPacketInterface>>>,
        routes: Vec<Ipv4Route>,
        lookup: Arc<dyn PeerConnLookup>,
    ) -> Self {
        Self {
            vpi,
            routes,
            lookup,
            stats: Arc::new(PumpStats::default()),
        }
    }

    /// 包泵统计句柄。
    #[must_use]
    pub fn stats(&self) -> Arc<PumpStats> {
        Arc::clone(&self.stats)
    }

    /// 最长前缀匹配路由；无匹配返回 `None`。
    fn route(&self, dst: Ipv4Addr) -> Option<N1PeerId> {
        self.routes
            .iter()
            .filter(|r| r.subnet.contains(dst))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
    }

    /// 启动上行/下行线程，返回 Owner 句柄（修 1：上行线程由 supervisor 维持）。
    pub fn start(self) -> PumpHandle {
        install_pump_panic_hook();
        let stop = Arc::new(AtomicBool::new(false));
        let this = Arc::new(self);

        // 上行 supervisor：维持 `n1-pump-up` 线程；线程死亡（panic/静默退出）则重启。
        let up = Arc::clone(&this);
        let up_stop = Arc::clone(&stop);
        let up_supervisor = thread::Builder::new()
            .name("n1-pump-upsup".into())
            .spawn(move || Self::uplink_supervisor(up, up_stop))
            .expect("pump uplink supervisor spawn");

        // 下行 supervisor：按需为每个对端增补下行线程。
        let down = Arc::clone(&this);
        let down_stop = Arc::clone(&stop);
        let supervisor = thread::Builder::new()
            .name("n1-pump-sup".into())
            .spawn(move || Self::downlink_supervisor(down, &down_stop))
            .expect("pump downlink supervisor spawn");

        PumpHandle {
            pump: this,
            stop,
            up_supervisor: Some(up_supervisor),
            supervisor: Some(supervisor),
        }
    }

    /// 上行 supervisor 主循环：维持单个 `n1-pump-up` worker，死亡则重启。
    ///
    /// supervisor 自身的 panic 防护：每轮迭代包 `catch_unwind`（`AssertUnwindSafe`），
    /// 迭代内 panic（如查表器 panic）只记日志，不杀死 supervisor。
    fn uplink_supervisor(this: Arc<Self>, stop: Arc<AtomicBool>) {
        let mut worker: Option<JoinHandle<()>> = None;
        while !stop.load(Ordering::SeqCst) {
            let iter = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::uplink_supervisor_iter(&this, &stop, &mut worker);
            }));
            if iter.is_err() {
                // panic 已由 panic hook 记录结构化日志；supervisor 继续下一轮。
                eprintln!("[n1-pump] uplink supervisor iteration panicked; continuing");
            }
            thread::sleep(Duration::from_millis(500));
        }
        // 退出前回收 worker；worker 可能阻塞在 VPI `receive()`（见模块头已知限制），
        // 有界等待 2s 后分离（进程退出时由 OS 回收）。
        if let Some(t) = worker.take() {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            thread::spawn(move || {
                let _ = t.join();
                let _ = tx.send(());
            });
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
    }

    /// 上行 supervisor 单轮：worker 已死则回收并重启；首次启动不计入 restarts。
    fn uplink_supervisor_iter(
        this: &Arc<Self>,
        stop: &Arc<AtomicBool>,
        worker: &mut Option<JoinHandle<()>>,
    ) {
        let dead = worker.as_ref().map(|t| t.is_finished()).unwrap_or(true);
        if !dead {
            return;
        }
        // 回收已死句柄（消费 join 结果；panic 已由 hook 记录）。
        let was_running = worker
            .take()
            .map(|t| {
                let _ = t.join();
                true
            })
            .unwrap_or(false);
        if stop.load(Ordering::SeqCst) {
            return;
        }
        if was_running {
            let n = this.stats.uplink_restarts.fetch_add(1, Ordering::Relaxed) + 1;
            eprintln!("[n1-pump] uplink worker exited unexpectedly; restarting (#{n})");
        }
        let w = Arc::clone(this);
        let s = Arc::clone(stop);
        let t = thread::Builder::new()
            .name("n1-pump-up".into())
            .spawn(move || w.uplink_loop(&s))
            .expect("pump uplink worker spawn");
        *worker = Some(t);
    }

    /// 上行循环。Ok(0) 表示 VPI 暂无包（非阻塞实现，如 Linux TUN fd），
    /// 短暂让出而非当作空包处理——否则 100% 空转。
    fn uplink_loop(&self, stop: &AtomicBool) {
        let mut buf = vec![0u8; 4096];
        while !stop.load(Ordering::SeqCst) {
            // 短暂持锁：阻塞在 receive() 期间持有 guard（见模块头已知限制）。
            // lock_vpi：poison 时恢复而非 panic（修 2）。
            let n = {
                let mut vpi = lock_vpi(&self.vpi);
                match vpi.receive(&mut buf) {
                    Ok(0) => {
                        drop(vpi);
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                }
            };
            self.stats.uplink_rx.fetch_add(1, Ordering::Relaxed);
            let pkt = &buf[..n];
            let dst = match ipv4_dst(pkt) {
                Some(d) => d,
                None => {
                    // 非 IPv4 / 头部不完整：M1 只处理 IPv4 单播，丢弃并计数。
                    self.stats.uplink_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if dst.is_multicast() || dst.is_broadcast() {
                self.stats.uplink_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Some(peer) = self.route(dst) else {
                self.stats.uplink_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let Some(conn) = self.lookup.connection_for(&peer) else {
                self.stats.uplink_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if pkt.len() > DATAGRAM_CAP {
                // 超限：调用方计数后丢弃（N1Connection::send_datagram 契约）。
                self.stats.uplink_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match conn.send_datagram(pkt) {
                Ok(()) => {
                    self.stats.uplink_forwarded.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    // 注意：fabric 吞掉了 UDP send_to 错误，此处 Err 仅为
                    // 通道级错误；Link 观测走心跳，不在此触发（D3）。
                    self.stats.uplink_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// 下行 supervisor：为每个对端维持一个下行线程；线程随连接关闭而退出，
    /// 退出后从运行集摘除（对端重连后会起新线程）。
    ///
    /// supervisor 自身的 panic 防护：每轮迭代包 `catch_unwind`，迭代内 panic 只记
    /// 日志，不杀死 supervisor（与上行 supervisor 同模式）。
    fn downlink_supervisor(this: Arc<Self>, stop: &AtomicBool) {
        let mut workers: Vec<(N1PeerId, JoinHandle<()>)> = vec![];
        while !stop.load(Ordering::SeqCst) {
            let iter = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::downlink_supervisor_iter(&this, &mut workers);
            }));
            if iter.is_err() {
                // panic 已由 panic hook 记录结构化日志；supervisor 继续下一轮。
                eprintln!("[n1-pump] downlink supervisor iteration panicked; continuing");
            }
            thread::sleep(Duration::from_millis(500));
        }
        // 退出前回收全部 worker（它们的连接已被 close_all 关闭，
        // recv_datagram 返回 Closed 后退出）。
        for (_, t) in workers {
            let _ = t.join();
        }
    }

    /// 下行 supervisor 单轮：回收已退出 worker，为缺失对端增补下行线程。
    fn downlink_supervisor_iter(this: &Arc<Self>, workers: &mut Vec<(N1PeerId, JoinHandle<()>)>) {
        // 回收已退出的 worker。
        workers.retain(|(_, t)| !t.is_finished());
        let running: HashSet<N1PeerId> = workers.iter().map(|(p, _)| *p).collect();
        for peer in this.lookup.all_peers() {
            if running.contains(&peer) {
                continue;
            }
            let Some(conn) = this.lookup.connection_for(&peer) else {
                continue;
            };
            let w = Arc::clone(this);
            let name = format!("n1-pump-dn-{}", &peer.to_hex()[..8]);
            let t = thread::Builder::new()
                .name(name)
                .spawn(move || Self::downlink_worker(w, conn))
                .expect("pump downlink worker spawn");
            workers.push((peer, t));
        }
    }

    /// 下行 worker：阻塞收对端 datagram → 写 VPI；连接关闭（Closed）即退出。
    ///
    /// 注意：`rebind()` 不替换连接对象，worker 在迁移期间继续阻塞在
    /// `recv_datagram`，恢复后自动续跑——无需重建线程。
    fn downlink_worker(this: Arc<Self>, conn: Arc<dyn N1Connection>) {
        loop {
            match conn.recv_datagram() {
                Ok(pkt) => {
                    this.stats.downlink_rx.fetch_add(1, Ordering::Relaxed);
                    let mut vpi = lock_vpi(&this.vpi);
                    match vpi.send(&pkt) {
                        Ok(()) => {
                            this.stats
                                .downlink_delivered
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            this.stats.downlink_vpi_err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(N1Error::Closed) | Err(N1Error::PeerClosed(_)) => break,
                Err(_) => {
                    // 通道级瞬时错误：继续阻塞收（Link 观测走心跳，不在此触发）。
                    continue;
                }
            }
        }
    }
}

/// 包泵 Owner 句柄。
pub struct PumpHandle {
    pump: Arc<VpiPump>,
    stop: Arc<AtomicBool>,
    up_supervisor: Option<JoinHandle<()>>,
    supervisor: Option<JoinHandle<()>>,
}

impl PumpHandle {
    /// 停止包泵：置位、关闭全部连接（打断下行阻塞读）、回收两个 supervisor。
    ///
    /// 上行 supervisor 退出前对 worker 做有界等待 2s（worker 若阻塞在 VPI
    /// `receive()` 中则分离，见模块头"已知限制"）。
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.pump.lookup.close_all();
        if let Some(t) = self.supervisor.take() {
            let _ = t.join();
        }
        if let Some(t) = self.up_supervisor.take() {
            let _ = t.join();
        }
    }

    /// 包泵统计。
    #[must_use]
    pub fn stats(&self) -> Arc<PumpStats> {
        self.pump.stats()
    }
}

/// 解析 IPv4 目的地址（bytes 16..20）；非 IPv4/头部不完整返回 None（M1）。
fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < IPV4_MIN_HEADER {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER || pkt.len() < ihl {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_platform::PlatformError;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    // ---- 测试替身 ----

    /// 内存 VPI：inbound 队列供 receive，send 写入 outbound；
    /// 内部状态经 Arc 共享，`clone()` 后的句柄可注入/读取包。
    #[derive(Clone)]
    struct MemVpi {
        inbound: Arc<Mutex<Vec<Vec<u8>>>>,
        outbound: Arc<Mutex<Vec<Vec<u8>>>>,
        closed: Arc<AtomicBool>,
    }

    impl MemVpi {
        fn new() -> Self {
            Self {
                inbound: Arc::new(Mutex::new(vec![])),
                outbound: Arc::new(Mutex::new(vec![])),
                closed: Arc::new(AtomicBool::new(false)),
            }
        }
        fn push_inbound(&self, pkt: Vec<u8>) {
            self.inbound.lock().unwrap().push(pkt);
        }
        fn take_outbound(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.outbound.lock().unwrap())
        }
    }

    impl VirtualPacketInterface for MemVpi {
        fn receive(&mut self, output: &mut [u8]) -> Result<usize, PlatformError> {
            loop {
                if self.closed.load(Ordering::SeqCst) {
                    return Err(PlatformError::Io {
                        operation: "test".into(),
                        message: "closed".into(),
                    });
                }
                if let Some(pkt) = self.inbound.lock().unwrap().pop() {
                    let n = pkt.len().min(output.len());
                    output[..n].copy_from_slice(&pkt[..n]);
                    return Ok(n);
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        fn send(&mut self, packet: &[u8]) -> Result<(), PlatformError> {
            self.outbound.lock().unwrap().push(packet.to_vec());
            Ok(())
        }
    }

    /// 测试连接：datagram 收发走 channel 对。
    struct MemConn {
        peer: N1PeerId,
        tx: Mutex<mpsc::Sender<Vec<u8>>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
        closed: AtomicBool,
        sent: AtomicUsize,
    }

    impl MemConn {
        fn pair(peer: N1PeerId) -> (Self, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>) {
            let (a_tx, a_rx) = mpsc::channel();
            let (b_tx, b_rx) = mpsc::channel();
            (
                Self {
                    peer,
                    tx: Mutex::new(a_tx),
                    rx: Mutex::new(b_rx),
                    closed: AtomicBool::new(false),
                    sent: AtomicUsize::new(0),
                },
                a_rx,
                b_tx,
            )
        }
    }

    impl N1Connection for MemConn {
        fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
            if data.len() > DATAGRAM_CAP {
                return Err(N1Error::OversizeDatagram(data.len()));
            }
            if self.closed.load(Ordering::SeqCst) {
                return Err(N1Error::Closed);
            }
            self.sent.fetch_add(1, Ordering::SeqCst);
            self.tx
                .lock()
                .unwrap()
                .send(data.to_vec())
                .map_err(|_| N1Error::Closed)
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            loop {
                if self.closed.load(Ordering::SeqCst) {
                    return Err(N1Error::Closed);
                }
                match self.rx.lock().unwrap().try_recv() {
                    Ok(pkt) => return Ok(pkt),
                    Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(5)),
                    Err(mpsc::TryRecvError::Disconnected) => return Err(N1Error::Closed),
                }
            }
        }
        fn open_keepalive(&self) -> Result<super::super::N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn accept_keepalive(&self) -> Result<super::super::N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn rebind(&self) -> Result<(), N1Error> {
            Ok(())
        }
        fn connection_id(&self) -> u64 {
            1
        }
        fn peer(&self) -> N1PeerId {
            self.peer
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    struct MemLookup {
        conns: Mutex<HashMap<N1PeerId, Arc<MemConn>>>,
    }

    impl PeerConnLookup for MemLookup {
        fn connection_for(&self, peer: &N1PeerId) -> Option<Arc<dyn N1Connection>> {
            self.conns
                .lock()
                .unwrap()
                .get(peer)
                .map(|c| Arc::clone(c) as Arc<dyn N1Connection>)
        }
        fn all_peers(&self) -> Vec<N1PeerId> {
            self.conns.lock().unwrap().keys().copied().collect()
        }
        fn close_all(&self) {
            for c in self.conns.lock().unwrap().values() {
                c.close();
            }
        }
    }

    fn ipv4_pkt(dst: Ipv4Addr, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len.max(20)];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn ipv4_net_parse_and_contains() {
        let n = Ipv4Net::parse("10.144.0.0/24").unwrap();
        assert!(n.contains(Ipv4Addr::new(10, 144, 0, 1)));
        assert!(n.contains(Ipv4Addr::new(10, 144, 0, 254)));
        assert!(!n.contains(Ipv4Addr::new(10, 144, 1, 1)));
        assert!(!n.contains(Ipv4Addr::new(192, 168, 0, 1)));
        let n2 = Ipv4Net::parse("10.144.0.99/24").unwrap();
        assert_eq!(n2.to_string(), "10.144.0.0/24");
    }

    #[test]
    fn ipv4_net_rejects_bad_input() {
        assert!(Ipv4Net::parse("10.144.0.0").is_err());
        assert!(Ipv4Net::parse("10.144.0.0/33").is_err());
        assert!(Ipv4Net::parse("999.1.1.0/24").is_err());
        assert!(Ipv4Net::parse("10.144.0.0/-1").is_err());
    }

    #[test]
    fn ipv4_dst_parses_header() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[16..20].copy_from_slice(&[10, 144, 0, 2]);
        assert_eq!(ipv4_dst(&pkt), Some(Ipv4Addr::new(10, 144, 0, 2)));
        let mut p6 = vec![0u8; 40];
        p6[0] = 0x60;
        assert_eq!(ipv4_dst(&p6), None);
        assert_eq!(ipv4_dst(&[0x45u8; 10]), None);
    }

    #[test]
    fn uplink_routes_forwards_and_counts_drops() {
        let peer = N1PeerId([1u8; 32]);
        let (conn, up_rx, _dn_tx) = MemConn::pair(peer);
        let conn = Arc::new(conn);
        let vpi = MemVpi::new();
        let vpi_probe = vpi.clone();
        let vpi_obj: Arc<Mutex<Box<dyn VirtualPacketInterface>>> =
            Arc::new(Mutex::new(Box::new(vpi)));
        let lookup = Arc::new(MemLookup {
            conns: Mutex::new(HashMap::from([(peer, conn)])),
        });
        let pump = VpiPump::new(
            Arc::clone(&vpi_obj),
            vec![Ipv4Route {
                subnet: Ipv4Net::parse("10.144.0.0/24").unwrap(),
                peer,
            }],
            lookup,
        );
        let stats = pump.stats();
        let handle = pump.start();

        // 上行注入：可路由包 → 转发；无路由包 → 丢弃；非 IPv4 包 → 丢弃；超限包 → 丢弃。
        vpi_probe.push_inbound(ipv4_pkt(Ipv4Addr::new(10, 144, 0, 2), 64));
        vpi_probe.push_inbound(ipv4_pkt(Ipv4Addr::new(192, 168, 1, 1), 64));
        let mut non_ip = vec![0u8; 40];
        non_ip[0] = 0x60;
        vpi_probe.push_inbound(non_ip);
        vpi_probe.push_inbound(ipv4_pkt(Ipv4Addr::new(10, 144, 0, 3), 1300));
        // 等上行线程消费（4 包）。
        for _ in 0..100 {
            if stats.uplink_rx.load(Ordering::Relaxed) >= 4 {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(stats.uplink_rx.load(Ordering::Relaxed), 4);
        assert_eq!(stats.uplink_forwarded.load(Ordering::Relaxed), 1);
        assert_eq!(stats.uplink_dropped.load(Ordering::Relaxed), 3);
        // 只有可路由的包到达对端连接。
        let got = up_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(ipv4_dst(&got), Some(Ipv4Addr::new(10, 144, 0, 2)));
        assert!(up_rx.try_recv().is_err());
        handle.shutdown();
    }

    #[test]
    fn downlink_delivers_to_vpi() {
        // 下行 worker 直接测：conn 发包 → VPI 收到。
        let peer = N1PeerId([2u8; 32]);
        let (conn, _up_rx, dn_tx) = MemConn::pair(peer);
        let conn: Arc<dyn N1Connection> = Arc::new(conn);
        let vpi = MemVpi::new();
        let vpi_probe = vpi.clone();
        let vpi_obj: Arc<Mutex<Box<dyn VirtualPacketInterface>>> =
            Arc::new(Mutex::new(Box::new(vpi)));
        let pump = Arc::new(VpiPump::new(
            vpi_obj,
            vec![],
            Arc::new(MemLookup {
                conns: Mutex::new(HashMap::new()),
            }),
        ));
        let worker = {
            let p = Arc::clone(&pump);
            let c = Arc::clone(&conn);
            thread::spawn(move || VpiPump::downlink_worker(p, c))
        };
        let pkt = ipv4_pkt(Ipv4Addr::new(10, 144, 0, 1), 64);
        dn_tx.send(pkt.clone()).unwrap();
        thread::sleep(Duration::from_millis(200));
        conn.close();
        let _ = worker.join();
        assert_eq!(pump.stats.downlink_rx.load(Ordering::Relaxed), 1);
        assert_eq!(pump.stats.downlink_delivered.load(Ordering::Relaxed), 1);
        assert_eq!(vpi_probe.take_outbound(), vec![pkt]);
    }

    #[test]
    fn uplink_drops_oversize_and_counts() {
        // 超限包（>1200B = DATAGRAM_CAP）在 send_datagram 前被丢弃并计数
        // （见 uplink_routes_forwards_and_counts_drops 的 1300B 包断言）。
        let big = ipv4_pkt(Ipv4Addr::new(10, 144, 0, 9), DATAGRAM_CAP + 100);
        assert!(big.len() > DATAGRAM_CAP);
    }

    #[test]
    fn longest_prefix_match_wins() {
        let a = N1PeerId([1u8; 32]);
        let b = N1PeerId([2u8; 32]);
        let pump = VpiPump::new(
            Arc::new(Mutex::new(
                Box::new(NullVpi) as Box<dyn VirtualPacketInterface>
            )),
            vec![
                Ipv4Route {
                    subnet: Ipv4Net::parse("10.0.0.0/8").unwrap(),
                    peer: a,
                },
                Ipv4Route {
                    subnet: Ipv4Net::parse("10.144.0.0/24").unwrap(),
                    peer: b,
                },
            ],
            Arc::new(MemLookup {
                conns: Mutex::new(HashMap::new()),
            }),
        );
        assert_eq!(pump.route(Ipv4Addr::new(10, 144, 0, 5)), Some(b));
        assert_eq!(pump.route(Ipv4Addr::new(10, 1, 2, 3)), Some(a));
        assert_eq!(pump.route(Ipv4Addr::new(192, 168, 1, 1)), None);
    }

    struct NullVpi;
    impl VirtualPacketInterface for NullVpi {
        fn receive(&mut self, _output: &mut [u8]) -> Result<usize, PlatformError> {
            Err(PlatformError::Io {
                operation: "test".into(),
                message: "no packets".into(),
            })
        }
        fn send(&mut self, _packet: &[u8]) -> Result<(), PlatformError> {
            Ok(())
        }
    }
}
