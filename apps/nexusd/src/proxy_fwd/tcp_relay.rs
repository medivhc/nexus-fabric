//! TCP 转发：smoltcp 终结 → 代理 dial → 双向中继（P1）。
//!
//! 设计：
//! - `ProxyEngine` 持有 `TcpTerminator`（accounting 层面唯一归属；`TcpForwarder`
//!   只借用终结器，不再自己持有）；
//! - `Syn{stream_id, dst}` → worker 线程 dial 代理（不阻塞 dataplane）；
//! - dial 成功 → 中继线程双向泵字节；proxy→TUN 经 mpsc 回 dataplane 线程
//!   （TUN 所有权仍在 dataplane，D1 不变量）；
//! - dial/中继失败 → 计数 + RST/关闭，不 panic。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
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
    /// stream_id → 目标（dial 中，用于失败时 RST）。
    pending: HashMap<u32, SocketAddr>,
    /// drain_events 暂存的待写 TUN 包。
    pending_tun: Vec<Vec<u8>>,
    stats: ProxyFwdStats,
}

impl TcpForwarder {
    pub fn new(outbounds: HashMap<String, ProxyDialConfig>) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            outbounds,
            current_tag: None,
            failures: Vec::new(),
            event_tx,
            event_rx,
            relays: HashMap::new(),
            pending: HashMap::new(),
            pending_tun: Vec::new(),
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
        self.current_tag = Some(outbound_tag.to_string());
        // 喂给 smoltcp。
        let mut out = terminator.handle_uplink(packet, "proxy");
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
        let mut out = Vec::new();
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
                    Ok(handle) => {
                        self.pending.remove(&stream_id);
                        self.relays.insert(stream_id, handle);
                        self.stats.tcp_dials_ok += 1;
                    }
                    Err(e) => {
                        self.pending.remove(&stream_id);
                        self.stats.tcp_dials_failed += 1;
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
                    // 这里暂存，下次 handle_packet 返回时带上。
                    // 简化：直接通过一个内部队列。
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
                self.pending.insert(stream_id, target);
                let Some(config) = self
                    .current_tag
                    .as_deref()
                    .and_then(|tag| self.outbounds.get(tag))
                    .cloned()
                else {
                    self.pending.remove(&stream_id);
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
                std::thread::spawn(move || {
                    let result = dial_through_proxy(&config, target)
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
                }
                // 无中继（dial 中）：丢弃（dial 成功后新数据会正常走）。
            }
            TcpEvent::Closed {
                stream_id, reset, ..
            } => {
                if let Some(relay) = self.relays.remove(&stream_id) {
                    let _ = relay.tx.send(RelayCmd::Close);
                }
                self.pending.remove(&stream_id);
                // smoltcp 侧已关闭，无需额外动作。
                let _ = reset;
            }
            TcpEvent::TunPacket(pkt) => {
                out.push(pkt);
            }
        }
        // 带上之前暂存的 TUN 包。
        out.append(&mut self.pending_tun);
        self.current_tag = None;
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
