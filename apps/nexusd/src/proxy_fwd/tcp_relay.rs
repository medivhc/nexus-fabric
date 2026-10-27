//! TCP 转发：smoltcp 终结 → 代理 dial → 双向中继（P1）。
//!
//! 设计：
//! - `ProxyEngine` 持有 `TcpTerminator`（accounting 层面唯一归属；`TcpForwarder`
//!   只借用终结器，不再自己持有）；
//! - `Syn{stream_id, dst}` → worker 线程 dial 代理（不阻塞 dataplane）；
//! - dial 成功 → 中继线程双向泵字节；proxy→TUN 经 mpsc 回 dataplane 线程
//!   （TUN 所有权仍在 dataplane，D1 不变量）；
//! - dial/中继失败 → 计数 + RST/关闭，不 panic；
//! - dial 窗口期（`Syn` 已到、`DialDone` 未到）：`Data` 按流有界缓冲，
//!   拨号成功后按到达顺序 flush（P7）；FIN/RST 先到按窗口期语义处理。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use nexus_projection::tcp::{TcpEvent, TcpTerminator};

use super::ss_std::SsTcpClient;
use super::{ProxyDialConfig, ProxyFwdStats};

/// dial 失败事件（ProxyEngine 转为 `ProxyStreamEvent::Failed`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpFailure {
    /// stream_id。
    pub stream_id: u32,
    /// 原因。
    pub reason: String,
}

/// 中继线程 → dataplane 线程的事件。
#[derive(Debug)]
pub enum TcpFwdEvent {
    /// dial 完成（成功带流，失败带 stream_id）。
    DialDone {
        stream_id: u32,
        result: Result<RelayHandle, String>,
    },
    /// proxy 侧收到数据 → 注入 smoltcp。
    ProxyData { stream_id: u32, bytes: Vec<u8> },
    /// proxy 侧关闭/EOF → FIN/RST smoltcp 侧。
    ProxyClosed { stream_id: u32, reset: bool },
    /// 待写回 TUN 的包（smoltcp 产生）。
    TunPackets(Vec<Vec<u8>>),
}

/// 中继句柄（dataplane 线程持有，用于向 proxy 写数据）。
#[derive(Debug)]
pub struct RelayHandle {
    /// 向中继线程发送数据的通道。
    tx: Sender<RelayCmd>,
}

/// 中继线程接收的命令。
#[derive(Debug)]
enum RelayCmd {
    Data(Vec<u8>),
    Close,
}

/// dial 超时。
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// 中继读超时（用于定期检查关闭）。
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(100);
/// dial 窗口期单流缓冲上限（字节）。
///
/// 取 64 KiB：smoltcp 终结器的接收窗口为 16 KiB，正常客户端在拨号完成前
/// 最多只能塞进一个窗口的请求字节；64 KiB 给了重传/多段合并足够余量，
/// 同时保证单流占用有硬上限。
const MAX_DIAL_BUFFER_PER_STREAM: usize = 64 * 1024;
/// dial 窗口期全部待拨号流的缓冲合计上限（字节）。
///
/// 单流上限之外再加总量上限，避免「连接表上限 × 单流上限」的乘积占用；
/// 超出时只终止触发超限的那条流。
const MAX_DIAL_BUFFER_TOTAL: usize = 1024 * 1024;

/// 拨号函数（测试可注入；生产用 `dial_through_proxy`）。
type Dialer = Arc<dyn Fn(&ProxyDialConfig, SocketAddr) -> io::Result<ProxyStream> + Send + Sync>;

/// 拨号窗口期内的一条待拨号流。
#[derive(Debug)]
struct PendingDial {
    /// 已收到但尚未写往 proxy 的字节（按到达顺序）。
    buffered: Vec<u8>,
    /// 窗口期内已收到 `Closed`：`Some(reset)`。`Some(true)` 表示 RST
    /// （缓冲已丢弃，不再 flush），`Some(false)` 表示 FIN（拨号成功后
    /// flush 完再关闭写端）。
    closed: Option<bool>,
}

/// TCP 转发器（dataplane 线程拥有）。
pub struct TcpForwarder {
    outbounds: HashMap<String, ProxyDialConfig>,
    /// 当前正在喂给终结器的包的出站 tag（Syn 事件消费）。
    current_tag: Option<String>,
    failures: Vec<TcpFailure>,
    event_tx: Sender<TcpFwdEvent>,
    event_rx: Receiver<TcpFwdEvent>,
    /// stream_id → 中继句柄（dial 成功后）。
    relays: HashMap<u32, RelayHandle>,
    /// stream_id → 拨号中状态（含窗口期缓冲）。
    pending: HashMap<u32, PendingDial>,
    /// 待拨号流缓冲的合计字节（总量上限用）。
    pending_buffered_bytes: usize,
    /// drain_events 暂存的待写 TUN 包。
    pending_tun: Vec<Vec<u8>>,
    dialer: Dialer,
    stats: ProxyFwdStats,
}

impl TcpForwarder {
    pub fn new(outbounds: HashMap<String, ProxyDialConfig>) -> Self {
        Self::with_dialer(outbounds, Arc::new(dial_through_proxy))
    }

    /// 构造可注入拨号实现的转发器（单测用于精确控制拨号窗口期）。
    fn with_dialer(outbounds: HashMap<String, ProxyDialConfig>, dialer: Dialer) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            outbounds,
            current_tag: None,
            failures: Vec::new(),
            event_tx,
            event_rx,
            relays: HashMap::new(),
            pending: HashMap::new(),
            pending_buffered_bytes: 0,
            pending_tun: Vec::new(),
            dialer,
            stats: ProxyFwdStats::default(),
        }
    }

    /// 处理一个 proxy 分类的 TCP 包；返回待写回 TUN 的包。
    pub fn handle_packet(
        &mut self,
        terminator: &mut TcpTerminator,
        packet: &[u8],
        outbound_tag: &str,
    ) -> Vec<Vec<u8>> {
        // 先排空 proxy 事件（dial 完成/数据/关闭）。
        self.drain_events(terminator);
        // P8：drain_events 期间终结器产出的回程包不依赖本次是否还有 TcpEvent，
        // 必须先于本次新包写回（生产序 == 写回序；否则 pending 的旧包会被本次
        // 新包反超，r8 抓包的尾段-先于-头段即此形）。
        let mut out = std::mem::take(&mut self.pending_tun);
        self.current_tag = Some(outbound_tag.to_string());
        // 喂给 smoltcp。
        out.extend(terminator.handle_uplink(packet, "proxy"));
        // 驱动 smoltcp 并处理事件。
        for event in terminator.poll() {
            self.handle_tcp_event(terminator, event, &mut out);
        }
        out
    }

    /// 定期驱动（无包时也调用，处理重传/超时）。
    /// 返回待写回 TUN 的包。
    pub fn poll(&mut self, terminator: &mut TcpTerminator) -> Vec<Vec<u8>> {
        self.drain_events(terminator);
        // P8：无 TcpEvent 时也必须把 drain_events 产出的回程包泵出去。
        let mut out = std::mem::take(&mut self.pending_tun);
        for event in terminator.poll() {
            self.handle_tcp_event(terminator, event, &mut out);
        }
        out
    }

    /// 排空中继线程发来的事件。
    fn drain_events(&mut self, terminator: &mut TcpTerminator) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                TcpFwdEvent::DialDone { stream_id, result } => match result {
                    Ok(handle) => self.on_dial_ok(stream_id, handle),
                    Err(e) => {
                        self.stats.tcp_dials_failed += 1;
                        self.drop_pending(stream_id);
                        self.failures.push(TcpFailure {
                            stream_id,
                            reason: e.clone(),
                        });
                        // RST smoltcp 侧。
                        let pkts = terminator.handle_fabric_rst(stream_id);
                        let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                        eprintln!("[proxy-fwd] dial failed for stream {stream_id}: {e}");
                    }
                },
                TcpFwdEvent::ProxyData { stream_id, bytes } => {
                    let pkts = terminator.handle_fabric_data(stream_id, &bytes);
                    if !pkts.is_empty() {
                        let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                    }
                }
                TcpFwdEvent::ProxyClosed { stream_id, reset } => {
                    self.relays.remove(&stream_id);
                    let pkts = if reset {
                        terminator.handle_fabric_rst(stream_id)
                    } else {
                        terminator.handle_fabric_fin(stream_id)
                    };
                    if !pkts.is_empty() {
                        let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                    }
                }
                TcpFwdEvent::TunPackets(pkts) => {
                    // 转发给调用方（由 handle_packet/poll 的调用方写 TUN）。
                    // 调用入口在 drain_events 返回后立即把本队列泵进输出
                    // （见 handle_packet/poll），不依赖是否再产出 TcpEvent。
                    self.pending_tun.extend(pkts);
                }
            }
        }
    }

    /// smoltcp 事件处理。
    fn handle_tcp_event(
        &mut self,
        terminator: &mut TcpTerminator,
        event: TcpEvent,
        out: &mut Vec<Vec<u8>>,
    ) {
        match event {
            TcpEvent::Syn { stream_id, dst, .. } => {
                let target = SocketAddr::V4(dst);
                self.stats.tcp_streams += 1;
                self.pending.insert(
                    stream_id,
                    PendingDial {
                        buffered: Vec::new(),
                        closed: None,
                    },
                );
                let Some(config) = self
                    .current_tag
                    .as_deref()
                    .and_then(|tag| self.outbounds.get(tag))
                    .cloned()
                else {
                    self.drop_pending(stream_id);
                    self.stats.tcp_dials_failed += 1;
                    let reason = format!(
                        "unknown outbound tag '{}'",
                        self.current_tag.as_deref().unwrap_or("")
                    );
                    self.failures.push(TcpFailure { stream_id, reason });
                    out.extend(terminator.handle_fabric_rst(stream_id));
                    return;
                };
                let tx = self.event_tx.clone();
                let dialer = Arc::clone(&self.dialer);
                std::thread::spawn(move || {
                    let result = dialer(&config, target)
                        .map(|stream| spawn_relay(stream_id, stream, tx.clone()));
                    let _ = tx.send(TcpFwdEvent::DialDone {
                        stream_id,
                        result: result.map_err(|e| e.to_string()),
                    });
                });
            }
            TcpEvent::Data {
                stream_id, bytes, ..
            } => {
                if let Some(relay) = self.relays.get(&stream_id) {
                    // 非阻塞发送（中继线程可能已退出，忽略错误）。
                    let _ = relay.tx.send(RelayCmd::Data(bytes));
                } else if let Some(entry) = self.pending.get_mut(&stream_id) {
                    if entry.closed.is_some() {
                        // 流已在窗口期内关闭：迟到的 Data 不再投递，显式计数。
                        self.stats.tcp_dial_buffer_dropped_bytes += bytes.len() as u64;
                    } else if entry.buffered.len() + bytes.len() > MAX_DIAL_BUFFER_PER_STREAM
                        || self.pending_buffered_bytes + bytes.len() > MAX_DIAL_BUFFER_TOTAL
                    {
                        // 超限：丢弃本流全部缓冲并 RST 该流（fail-fast）。
                        // 静默丢一段会让上游收到带洞的字节流（TCP 语义上更糟），
                        // 所以选择断流，并显式计数丢弃字节与重置流数。
                        let dropped = entry.buffered.len() + bytes.len();
                        self.pending_buffered_bytes = self
                            .pending_buffered_bytes
                            .saturating_sub(entry.buffered.len());
                        entry.buffered.clear();
                        entry.closed = Some(true);
                        self.stats.tcp_dial_buffer_dropped_bytes += dropped as u64;
                        self.stats.tcp_dial_buffer_overflow_resets += 1;
                        out.extend(terminator.handle_fabric_rst(stream_id));
                    } else {
                        entry.buffered.extend_from_slice(&bytes);
                        self.pending_buffered_bytes += bytes.len();
                    }
                } else {
                    // 既无中继也无待拨号条目（流已终止/被清理）：计数后丢弃。
                    self.stats.tcp_dial_buffer_dropped_bytes += bytes.len() as u64;
                }
            }
            TcpEvent::Closed {
                stream_id, reset, ..
            } => {
                if let Some(relay) = self.relays.remove(&stream_id) {
                    let _ = relay.tx.send(RelayCmd::Close);
                }
                // 拨号窗口期内先到的 FIN/RST：记录状态，等 DialDone 收尾。
                // FIN：保留缓冲，拨号成功后 flush 再关闭写端；
                // RST：立即丢弃缓冲并计数，拨号成功后只关闭中继。
                if let Some(entry) = self.pending.get_mut(&stream_id) {
                    if reset {
                        self.pending_buffered_bytes = self
                            .pending_buffered_bytes
                            .saturating_sub(entry.buffered.len());
                        self.stats.tcp_dial_buffer_dropped_bytes += entry.buffered.len() as u64;
                        entry.buffered.clear();
                    }
                    entry.closed = Some(reset);
                }
                // smoltcp 侧已关闭，无需额外动作。
                let _ = reset;
            }
            TcpEvent::TunPacket(pkt) => {
                out.push(pkt);
            }
        }
        self.current_tag = None;
    }

    /// 拨号成功：按到达顺序 flush 窗口期缓冲，随后与后续 Data 同一条
    /// 中继命令通道（FIFO）衔接；窗口期内先到 FIN 则 flush 后关闭写端，
    /// 先到 RST 则只关闭中继。
    fn on_dial_ok(&mut self, stream_id: u32, handle: RelayHandle) {
        self.stats.tcp_dials_ok += 1;
        let Some(entry) = self.pending.remove(&stream_id) else {
            // 流在窗口期内已被 RST/超限清理：关闭中继，不留僵尸条目。
            let _ = handle.tx.send(RelayCmd::Close);
            return;
        };
        self.pending_buffered_bytes = self
            .pending_buffered_bytes
            .saturating_sub(entry.buffered.len());
        match entry.closed {
            Some(true) => {
                // RST 先到：缓冲已在 Closed 处理时丢弃并计数。
                let _ = handle.tx.send(RelayCmd::Close);
            }
            Some(false) => {
                // FIN 先到：先把请求字节送上游，再关闭写端。
                if !entry.buffered.is_empty() {
                    let _ = handle.tx.send(RelayCmd::Data(entry.buffered));
                }
                let _ = handle.tx.send(RelayCmd::Close);
            }
            None => {
                if !entry.buffered.is_empty() {
                    let _ = handle.tx.send(RelayCmd::Data(entry.buffered));
                }
                self.relays.insert(stream_id, handle);
            }
        }
    }

    /// 丢弃并统计某待拨号流的缓冲（条目不存在则无操作）。
    fn drop_pending(&mut self, stream_id: u32) {
        if let Some(entry) = self.pending.remove(&stream_id) {
            self.pending_buffered_bytes = self
                .pending_buffered_bytes
                .saturating_sub(entry.buffered.len());
            self.stats.tcp_dial_buffer_dropped_bytes += entry.buffered.len() as u64;
        }
    }

    /// 取走 dial 失败事件。
    pub fn take_failures(&mut self) -> Vec<TcpFailure> {
        std::mem::take(&mut self.failures)
    }

    pub fn stats(&self) -> ProxyFwdStats {
        self.stats.clone()
    }
}

/// 经代理 dial 到目标，返回可读写的字节流。
fn dial_through_proxy(config: &ProxyDialConfig, target: SocketAddr) -> io::Result<ProxyStream> {
    match config {
        ProxyDialConfig::Socks5 { server } => {
            let cfg = nexus_proxy_transport::Socks5ProxyConfig::new(*server, None);
            nexus_proxy_transport::socks5_connect(&cfg, target)
                .map(ProxyStream::Tcp)
                .map_err(|e| io::Error::other(e.to_string()))
        }
        ProxyDialConfig::Trojan { server, password } => {
            let cfg = nexus_proxy_transport::TrojanProxyConfig::new(*server, password.clone());
            nexus_proxy_transport::trojan_connect(&cfg, target)
                .map(ProxyStream::Tcp)
                .map_err(|e| io::Error::other(e.to_string()))
        }
        ProxyDialConfig::TrojanTls {
            server,
            password,
            sni,
            skip_verify,
        } => {
            let mut cfg =
                nexus_proxy_transport::TrojanTlsConfig::new(*server, password.clone(), sni.clone());
            cfg.skip_cert_verify = *skip_verify;
            nexus_proxy_transport::trojan_tls_connect(&cfg, target)
                .map(|s| ProxyStream::Tls(Box::new(s)))
                .map_err(|e| io::Error::other(e.to_string()))
        }
        ProxyDialConfig::Shadowsocks {
            server, password, ..
        } => {
            // 标准 ss TCP（ss_std），非自定义 SsTransport。
            SsTcpClient::connect(*server, password, target, DIAL_TIMEOUT)
                .map(ProxyStream::Ss)
                .map_err(|e| io::Error::other(e.to_string()))
        }
    }
}

/// 统一代理字节流。
enum ProxyStream {
    Tcp(TcpStream),
    Tls(Box<nexus_proxy_transport::TlsStream>),
    Ss(SsTcpClient),
}

impl ProxyStream {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_read_timeout(dur),
            Self::Tls(s) => s.get_mut().set_read_timeout(dur),
            Self::Ss(_) => {
                // SsTcpClient 内部管理；本期通过 read 超时模拟。
                let _ = dur;
                Ok(())
            }
        }
    }
}

/// 启动中继线程；返回 dataplane 侧句柄。
fn spawn_relay(stream_id: u32, mut stream: ProxyStream, tx: Sender<TcpFwdEvent>) -> RelayHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel::<RelayCmd>();
    std::thread::spawn(move || {
        // 设置读超时以便定期检查命令。
        let _ = stream.set_read_timeout(Some(RELAY_READ_TIMEOUT));
        let mut buf = [0u8; 8192];
        loop {
            // 先检查关闭命令（非阻塞）。
            match cmd_rx.try_recv() {
                Ok(RelayCmd::Close) | Err(mpsc::TryRecvError::Disconnected) => break,
                Ok(RelayCmd::Data(data)) => {
                    if write_proxy(&mut stream, &data).is_err() {
                        break;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // 从 proxy 读。
            match read_proxy(&mut stream, &mut buf) {
                Ok(0) => {
                    // EOF：正常关闭。
                    let _ = tx.send(TcpFwdEvent::ProxyClosed {
                        stream_id,
                        reset: false,
                    });
                    break;
                }
                Ok(n) => {
                    let _ = tx.send(TcpFwdEvent::ProxyData {
                        stream_id,
                        bytes: buf[..n].to_vec(),
                    });
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => {
                    let _ = tx.send(TcpFwdEvent::ProxyClosed {
                        stream_id,
                        reset: true,
                    });
                    break;
                }
            }
        }
    });
    RelayHandle { tx: cmd_tx }
}

/// 向 proxy 写数据。
fn write_proxy(stream: &mut ProxyStream, data: &[u8]) -> io::Result<()> {
    match stream {
        ProxyStream::Tcp(s) => s.write_all(data),
        ProxyStream::Tls(s) => s.write_all(data),
        ProxyStream::Ss(c) => c
            .write_all(data)
            .map_err(|e| io::Error::other(e.to_string())),
    }
}

/// 从 proxy 读数据。
fn read_proxy(stream: &mut ProxyStream, buf: &mut [u8]) -> io::Result<usize> {
    match stream {
        ProxyStream::Tcp(s) => s.read(buf),
        ProxyStream::Tls(s) => s.read(buf),
        ProxyStream::Ss(c) => c.read(buf).map_err(|e| io::Error::other(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::sync::Barrier;

    const STREAM: u32 = 7;

    fn outbounds() -> HashMap<String, ProxyDialConfig> {
        let mut m = HashMap::new();
        m.insert(
            "test".to_string(),
            ProxyDialConfig::Socks5 {
                server: "127.0.0.1:1".parse().expect("addr"),
            },
        );
        m
    }

    /// 测试替身：拨号在 barrier 处暂停，测试可精确把 Data 塞进拨号窗口期；
    /// 放行后 `fail` 决定返回错误还是连到本地上游替身。
    fn harness(fail: bool) -> (TcpForwarder, TcpTerminator, TcpListener, Arc<Barrier>) {
        let upstream = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("addr");
        let release = Arc::new(Barrier::new(2));
        let dial_release = Arc::clone(&release);
        let dialer: Dialer = Arc::new(move |_cfg, _target| {
            dial_release.wait();
            if fail {
                Err(io::Error::other("fake dial failure"))
            } else {
                TcpStream::connect(upstream_addr).map(ProxyStream::Tcp)
            }
        });
        let mut fwd = TcpForwarder::with_dialer(outbounds(), dialer);
        fwd.current_tag = Some("test".to_string());
        (fwd, TcpTerminator::new(), upstream, release)
    }

    fn start_dial(fwd: &mut TcpForwarder, term: &mut TcpTerminator, upstream: &TcpListener) {
        let port = upstream.local_addr().expect("addr").port();
        let mut out = Vec::new();
        fwd.handle_tcp_event(
            term,
            TcpEvent::Syn {
                stream_id: STREAM,
                dst: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
                peer: "proxy".to_string(),
            },
            &mut out,
        );
    }

    fn deliver(fwd: &mut TcpForwarder, term: &mut TcpTerminator, bytes: &[u8]) {
        let mut out = Vec::new();
        fwd.handle_tcp_event(
            term,
            TcpEvent::Data {
                stream_id: STREAM,
                peer: "proxy".to_string(),
                bytes: bytes.to_vec(),
            },
            &mut out,
        );
    }

    fn close(fwd: &mut TcpForwarder, term: &mut TcpTerminator, reset: bool) {
        let mut out = Vec::new();
        fwd.handle_tcp_event(
            term,
            TcpEvent::Closed {
                stream_id: STREAM,
                peer: "proxy".to_string(),
                reset,
            },
            &mut out,
        );
    }

    fn pump_until(
        fwd: &mut TcpForwarder,
        term: &mut TcpTerminator,
        pred: impl Fn(&TcpForwarder) -> bool,
    ) -> bool {
        for _ in 0..5000 {
            fwd.drain_events(term);
            if pred(fwd) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    fn read_exact_bytes(conn: &mut TcpStream, n: usize) -> Vec<u8> {
        conn.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        let mut buf = vec![0u8; n];
        conn.read_exact(&mut buf).expect("read upstream bytes");
        buf
    }

    // --- P8：静默等待回程响应的泵送与顺序 -------------------------------

    fn ip_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp_seg: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        sum += ((src[0] as u32) << 8) | src[1] as u32;
        sum += ((src[2] as u32) << 8) | src[3] as u32;
        sum += ((dst[0] as u32) << 8) | dst[1] as u32;
        sum += ((dst[2] as u32) << 8) | dst[3] as u32;
        sum += 6;
        sum += tcp_seg.len() as u32;
        let mut i = 0;
        while i + 1 < tcp_seg.len() {
            sum += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
            i += 2;
        }
        if i < tcp_seg.len() {
            sum += (tcp_seg[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[allow(clippy::too_many_arguments)]
    fn craft_tcp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40 + payload.len()];
        pkt[0] = 0x45;
        let tot = (40 + payload.len()) as u16;
        pkt[2..4].copy_from_slice(&tot.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        let c = ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        let t = &mut pkt[20..40];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t[14..16].copy_from_slice(&8192u16.to_be_bytes());
        pkt[40..].copy_from_slice(payload);
        let tc = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
        pkt[36..38].copy_from_slice(&tc.to_be_bytes());
        pkt
    }

    fn parse_tcp_seq_ack(pkt: &[u8]) -> Option<(u32, u32, u8)> {
        if pkt.len() < 40 || pkt[9] != 6 {
            return None;
        }
        let seq = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
        let ack = u32::from_be_bytes([pkt[28], pkt[29], pkt[30], pkt[31]]);
        Some((seq, ack, pkt[33]))
    }

    fn tcp_payload(pkt: &[u8]) -> Vec<u8> {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let data_off = ((pkt[ihl + 12] >> 4) as usize) * 4;
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        pkt[ihl + data_off..total].to_vec()
    }

    fn tcp_payloads(pkts: &[Vec<u8>]) -> Vec<u8> {
        pkts.iter().flat_map(|p| tcp_payload(p)).collect()
    }

    /// 在 relay 级完成握手 + 请求投递（拨号完成、中继接管），但不产生回程。
    /// 返回 (终结器分配的 stream_id, 客户端下一个 seq, 服务端 ISN+1, 上游侧
    /// 连接)；上游连接必须保持打开，否则中继线程会先报 EOF，闯入被测的静默窗口。
    fn establish_relay(
        fwd: &mut TcpForwarder,
        term: &mut TcpTerminator,
        upstream: &TcpListener,
        release: Arc<Barrier>,
    ) -> (u32, u32, u32, TcpStream) {
        let port = upstream.local_addr().expect("addr").port();
        let (src, dst) = ([10, 0, 0, 2], [127, 0, 0, 1]);
        let client_port = 40000u16;
        let syn = craft_tcp(src, dst, client_port, port, 1000, 0, 0x02, &[]);
        let syn_ack = fwd.handle_packet(term, &syn, "test");
        assert_eq!(syn_ack.len(), 1, "SYN-ACK expected");
        let (server_seq, _, flags) = parse_tcp_seq_ack(&syn_ack[0]).expect("syn-ack");
        assert_eq!(flags & 0x12, 0x12);
        let ack = craft_tcp(src, dst, client_port, port, 1001, server_seq + 1, 0x10, &[]);
        let _ = fwd.handle_packet(term, &ack, "test");
        let get = craft_tcp(
            src,
            dst,
            client_port,
            port,
            1001,
            server_seq + 1,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        let _ = fwd.handle_packet(term, &get, "test");
        release.wait();
        assert!(
            pump_until(fwd, term, |f| f.stats().tcp_dials_ok == 1),
            "dial completes"
        );
        let (conn, _) = upstream.accept().expect("relay connects upstream");
        let stream_id = *fwd.relays.keys().next().expect("relay registered");
        (stream_id, 1001, server_seq + 1, conn)
    }

    /// P8 核心回归：客户端发完请求后静默等待（不再有任何包 / TcpEvent），
    /// 回程响应必须经一次 `poll` 写回，且字节内容完整。
    #[test]
    fn silent_wait_response_is_flushed_by_single_poll_without_tcp_event() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        let (stream_id, _client_seq, server_isn1, _conn) =
            establish_relay(&mut fwd, &mut term, &upstream, release);

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        fwd.event_tx
            .send(TcpFwdEvent::ProxyData {
                stream_id,
                bytes: response.clone(),
            })
            .expect("inject proxy response");

        // 没有新包、没有后续 TcpEvent：只调用一次 poll。
        let out = fwd.poll(&mut term);
        assert!(
            !out.is_empty(),
            "silent wait must not strand the response in pending_tun"
        );
        assert!(fwd.pending_tun.is_empty(), "pump point drains the queue");
        assert_eq!(tcp_payloads(&out), response, "response bytes written back");
        assert_eq!(
            parse_tcp_seq_ack(&out[0]).expect("pkt").0,
            server_isn1,
            "first response segment starts at the server ISN+1"
        );
    }

    /// P8 顺序：同一次 drain 的多分段必须按终结器产出顺序写回。
    ///
    /// 用一个大于 MSS（536）且正好两段的响应触发 smoltcp 在同一批里产出
    /// 两个段；断言写回顺序与 seq 连续递增一致（尾-before-头 不允许）。
    #[test]
    fn silent_wait_multi_segment_response_keeps_production_order() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        let (stream_id, _client_seq, server_isn1, _conn) =
            establish_relay(&mut fwd, &mut term, &upstream, release);

        let response: Vec<u8> = (0..1072u32).map(|i| b'a' + (i % 26) as u8).collect();
        fwd.event_tx
            .send(TcpFwdEvent::ProxyData {
                stream_id,
                bytes: response.clone(),
            })
            .expect("inject proxy response");

        let out = fwd.poll(&mut term);
        assert_eq!(
            tcp_payloads(&out),
            response,
            "segments written back in production order"
        );
        assert!(out.len() >= 2, "response spans multiple segments");
        let mut expect_seq = server_isn1;
        for pkt in &out {
            let (seq, _, _) = parse_tcp_seq_ack(pkt).expect("pkt");
            let payload = tcp_payload(pkt);
            assert!(!payload.is_empty(), "batch contains only data segments");
            assert_eq!(seq, expect_seq, "segment seq order matches write order");
            expect_seq += payload.len() as u32;
        }
    }

    /// P8 顺序（r8 抓包形状）：`pending_tun` 里的旧响应包不得被同一调用中
    /// 新产生的包（如客户端重传触发的纯 ACK）反超。
    #[test]
    fn pending_response_precedes_packets_produced_by_current_call() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        let (stream_id, client_seq, server_isn1, _conn) =
            establish_relay(&mut fwd, &mut term, &upstream, release);

        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        fwd.event_tx
            .send(TcpFwdEvent::ProxyData {
                stream_id,
                bytes: head.clone(),
            })
            .expect("inject proxy response");

        // 客户端静默期的 GET 重传：本调用会同时产生一个纯 ACK。
        let port = upstream.local_addr().expect("addr").port();
        let retransmit = craft_tcp(
            [10, 0, 0, 2],
            [127, 0, 0, 1],
            40000,
            port,
            client_seq,
            server_isn1,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        let out = fwd.handle_packet(&mut term, &retransmit, "test");
        assert_eq!(
            tcp_payloads(&out),
            head,
            "older pending response is not overtaken by this call's packets"
        );
        let first = parse_tcp_seq_ack(&out[0]).expect("pkt");
        assert_eq!(first.0, server_isn1, "response segment comes first");
        assert_eq!(
            first.2 & 0x10,
            0x10,
            "first packet carries data with ACK set"
        );
        // 本次调用后续的纯 ACK（若有）排在响应之后，且不带应用字节。
        for pkt in &out[1..] {
            assert!(tcp_payload(pkt).is_empty(), "only ACK follows the response");
        }
    }

    /// P8 顺序（r8 抓包形状，含 TcpEvent）：头段在 `pending_tun`，尾段被
    /// Nagle 压到 FIN 处理时才放行。旧实现把 `pending_tun` 追加在本次调用
    /// 输出之后，尾段/FIN 处理包会反超头段（尾-before-头）。
    #[test]
    fn pending_response_precedes_fin_call_packets() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        let (stream_id, client_seq, server_isn1, _conn) =
            establish_relay(&mut fwd, &mut term, &upstream, release);

        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let tail = b"tail".to_vec();
        for bytes in [head.clone(), tail.clone()] {
            fwd.event_tx
                .send(TcpFwdEvent::ProxyData { stream_id, bytes })
                .expect("inject proxy segment");
        }

        // 客户端 FIN：同一调用会产出 ACK 并触发 Closed 事件；Nagle 压住的
        // 尾段在 socket 进入关闭态后才放行。
        let port = upstream.local_addr().expect("addr").port();
        let fin_seq = client_seq + b"GET / HTTP/1.1\r\n\r\n".len() as u32;
        let fin = craft_tcp(
            [10, 0, 0, 2],
            [127, 0, 0, 1],
            40000,
            port,
            fin_seq,
            server_isn1,
            0x11,
            &[],
        );
        let mut written = fwd.handle_packet(&mut term, &fin, "test");
        // 后续 poll 放行 Nagle 压住的尾段/FIN。
        for _ in 0..8 {
            let more = fwd.poll(&mut term);
            if more.is_empty() {
                break;
            }
            written.extend(more);
        }

        assert_eq!(
            tcp_payloads(&written),
            [head.clone(), tail.clone()].concat(),
            "response bytes are written once, in production order"
        );
        assert_eq!(
            tcp_payload(&written[0]),
            head,
            "head segment is not overtaken by FIN-call packets"
        );
        let head_at = written
            .iter()
            .position(|p| !tcp_payload(p).is_empty())
            .expect("response present");
        assert_eq!(tcp_payload(&written[head_at]), head, "head segment first");
        assert!(
            written[head_at + 1..]
                .iter()
                .any(|p| tcp_payload(p) == tail),
            "tail segment follows the head"
        );
    }

    #[test]
    fn dial_window_flush_delivers_buffered_bytes_then_later_data() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        start_dial(&mut fwd, &mut term, &upstream);
        let first: &[u8] = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
        deliver(&mut fwd, &mut term, first);
        // 拨号未完成：字节只在缓冲里，不能丢。
        assert_eq!(fwd.stats().tcp_dial_buffer_dropped_bytes, 0);
        assert!(fwd.relays.is_empty(), "no relay before dial completes");
        assert_eq!(fwd.pending_buffered_bytes, first.len());

        release.wait();
        assert!(pump_until(&mut fwd, &mut term, |f| f.stats().tcp_dials_ok == 1));
        // 拨号完成后的新数据与缓冲走同一条中继命令通道（FIFO）。
        let tail: &[u8] = b"X-Tail: 1\r\n";
        deliver(&mut fwd, &mut term, tail);

        let (mut conn, _) = upstream.accept().expect("relay connects upstream");
        let mut expected = first.to_vec();
        expected.extend_from_slice(tail);
        let got = read_exact_bytes(&mut conn, expected.len());
        assert_eq!(got, expected, "buffered bytes then later data, in order");
        assert_eq!(fwd.stats().tcp_dial_buffer_dropped_bytes, 0);
        assert_eq!(fwd.pending_buffered_bytes, 0);
    }

    #[test]
    fn dial_window_flush_preserves_multi_segment_order() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        start_dial(&mut fwd, &mut term, &upstream);
        let segments: [&[u8]; 3] = [b"segment-A;", b"segment-B;", b"segment-C;"];
        for seg in segments {
            deliver(&mut fwd, &mut term, seg);
        }
        assert_eq!(fwd.pending.get(&STREAM).map(|p| p.buffered.len()), Some(30));

        release.wait();
        assert!(pump_until(&mut fwd, &mut term, |f| f.stats().tcp_dials_ok == 1));

        let (mut conn, _) = upstream.accept().expect("relay connects upstream");
        let got = read_exact_bytes(&mut conn, 30);
        assert_eq!(got, b"segment-A;segment-B;segment-C;".to_vec());
    }

    #[test]
    fn dial_window_overflow_resets_stream_and_counts() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        start_dial(&mut fwd, &mut term, &upstream);
        let oversized = vec![b'z'; MAX_DIAL_BUFFER_PER_STREAM + 1];
        deliver(&mut fwd, &mut term, &oversized);

        let stats = fwd.stats();
        assert_eq!(stats.tcp_dial_buffer_overflow_resets, 1);
        assert_eq!(stats.tcp_dial_buffer_dropped_bytes, oversized.len() as u64);
        assert_eq!(fwd.pending_buffered_bytes, 0);
        let entry = fwd
            .pending
            .get(&STREAM)
            .expect("pending kept until dial ends");
        assert!(entry.buffered.is_empty());
        assert_eq!(entry.closed, Some(true), "overflow fails the stream");

        release.wait();
        assert!(pump_until(&mut fwd, &mut term, |f| f.stats().tcp_dials_ok == 1));
        // 拨号成功后只关闭中继，不留僵尸 relay / pending。
        assert!(fwd.relays.is_empty());
        assert!(fwd.pending.is_empty());
        assert_eq!(fwd.pending_buffered_bytes, 0);
        let (mut conn, _) = upstream.accept().expect("relay still closes upstream");
        conn.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        let mut got = Vec::new();
        conn.read_to_end(&mut got).expect("upstream sees EOF");
        assert!(got.is_empty(), "overflowed bytes are never forwarded");
    }

    #[test]
    fn dial_window_dial_failure_drops_buffer_and_counts() {
        let (mut fwd, mut term, _upstream, release) = harness(true);
        start_dial(&mut fwd, &mut term, &_upstream);
        deliver(&mut fwd, &mut term, b"abc");
        deliver(&mut fwd, &mut term, b"defg");
        assert_eq!(fwd.pending_buffered_bytes, 7);

        release.wait();
        assert!(pump_until(&mut fwd, &mut term, |f| f
            .stats()
            .tcp_dials_failed
            == 1));

        let stats = fwd.stats();
        assert_eq!(stats.tcp_dial_buffer_dropped_bytes, 7);
        assert_eq!(stats.tcp_dials_failed, 1);
        assert_eq!(fwd.pending_buffered_bytes, 0);
        assert!(fwd.pending.is_empty(), "no zombie pending entry");
        assert!(fwd.relays.is_empty(), "no zombie relay entry");
        assert_eq!(fwd.take_failures().len(), 1);
    }

    #[test]
    fn dial_window_fin_first_flushes_then_closes_write_side() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        start_dial(&mut fwd, &mut term, &upstream);
        deliver(&mut fwd, &mut term, b"GET /fin");
        close(&mut fwd, &mut term, false);
        assert_eq!(fwd.pending_buffered_bytes, 8, "FIN keeps buffer for flush");

        release.wait();
        assert!(pump_until(&mut fwd, &mut term, |f| f.stats().tcp_dials_ok == 1));
        assert!(fwd.relays.is_empty());
        assert!(fwd.pending.is_empty());
        assert_eq!(fwd.stats().tcp_dial_buffer_dropped_bytes, 0);

        let (mut conn, _) = upstream.accept().expect("relay connects upstream");
        conn.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        let mut got = Vec::new();
        conn.read_to_end(&mut got).expect("read to EOF");
        assert_eq!(got, b"GET /fin".to_vec(), "FIN-first flush then EOF");
    }

    #[test]
    fn dial_window_rst_first_discards_buffer_and_counts() {
        let (mut fwd, mut term, upstream, release) = harness(false);
        start_dial(&mut fwd, &mut term, &upstream);
        deliver(&mut fwd, &mut term, b"RST-drop-me");
        close(&mut fwd, &mut term, true);
        assert_eq!(fwd.pending_buffered_bytes, 0, "RST drops buffer at once");
        assert_eq!(fwd.stats().tcp_dial_buffer_dropped_bytes, 11);

        release.wait();
        assert!(pump_until(&mut fwd, &mut term, |f| f.stats().tcp_dials_ok == 1));
        assert!(fwd.relays.is_empty());
        assert!(fwd.pending.is_empty());

        let (mut conn, _) = upstream.accept().expect("relay connects upstream");
        conn.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        let mut got = Vec::new();
        conn.read_to_end(&mut got).expect("read to EOF");
        assert!(got.is_empty(), "RST-first bytes are never forwarded");
    }
}
