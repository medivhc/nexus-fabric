//! TCP 转发：smoltcp 终结 → dialer.dial_tcp → 双向中继（P1）。
//!
//! 设计：
//! - `TcpForwarder` 持有 `TcpTerminator`（dataplane 线程拥有，非 Sync 不跨线程）；
//! - `Syn{stream_id, dst}` → worker 线程 dial 代理（不阻塞 dataplane）；
//! - dial 成功 → 中继线程双向泵字节；proxy→TUN 经 mpsc 回 dataplane 线程
//!   （TUN 所有权仍在 dataplane，D1 不变量）；
//! - dial/中继失败 → 计数 + RST/关闭，不 panic；
//! - 资源边界：`MAX_ACTIVE_TCP_FLOWS` / `MAX_CONCURRENT_DIALS`（spec §2.2）。

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use nexus_projection::tcp::{FourTuple, TcpEvent, TcpTerminator, ip_checksum, tcp_checksum};
use nexus_proxy_config::OutboundKind;

use super::ProxyFwdStats;
use super::adapter::{OutboundDialer, OutboundError, TunnelStream};

/// 中继线程 → dataplane 线程的事件。
#[derive(Debug)]
pub enum TcpFwdEvent {
    /// dial 完成（成功带流，失败带 typed error）。
    DialDone {
        stream_id: u32,
        result: Result<RelayHandle, OutboundError>,
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

/// 单 engine 活跃 TCP 流上限（spec §2.2；与 `MAX_UDP_FLOWS` 对齐）。
pub const MAX_ACTIVE_TCP_FLOWS: usize = 1024;
/// 同时进行中的 dial 上限（spec §2.2）。
pub const MAX_CONCURRENT_DIALS: usize = 256;
/// 中继读超时（用于定期检查关闭，spec §2.2）。
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(100);
/// 中继写超时（防止 proxy 侧背压无限阻塞线程，spec §2.2）。
const RELAY_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// 中继缓冲（spec §2.2）。
const RELAY_BUF_LEN: usize = 8192;
/// dial 在飞期间客户端数据的缓冲上限。
///
/// Gate 2 真机 TUN 暴露：SYN 即开始 dial，客户端可能先于 dial 完成发出首个 TCP
/// 段；必须缓冲后补发，不能丢弃——否则真实 TUN 流量会丢失首个 TCP 段。
/// 超出上限的流在 dial 完成后 fail-closed（RST），绝不静默截断。
/// 上限 × MAX_CONCURRENT_DIALS = 16 MiB 最坏情况。
const DIAL_BUFFER_MAX_BYTES: usize = 64 * 1024;

/// TCP 转发器（dataplane 线程拥有）。
pub struct TcpForwarder {
    terminator: TcpTerminator,
    dialer: Arc<dyn OutboundDialer>,
    /// 选中出站的 kind/tag（仅日志用；spec §6.5）。
    kind: OutboundKind,
    tag: String,
    event_tx: Sender<TcpFwdEvent>,
    event_rx: Receiver<TcpFwdEvent>,
    /// stream_id → 中继句柄（dial 成功后）。
    relays: HashMap<u32, RelayHandle>,
    /// stream_id → 目标（dial 中，用于失败时 RST）。
    pending: HashMap<u32, SocketAddr>,
    /// dial 在飞期间已到达的客户端数据（dial 成功后按序补发）。
    dial_buffer: DialBuffer,
    /// dial 在飞时已被 smoltcp 关闭的流（DialDone 成功后直接丢弃句柄，防泄漏）。
    closed_during_dial: HashSet<u32>,
    /// drain_events 暂存的待写 TUN 包。
    pending_tun: Vec<Vec<u8>>,
    stats: ProxyFwdStats,
}

impl TcpForwarder {
    pub fn new(dialer: Arc<dyn OutboundDialer>) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        let kind = dialer.kind();
        let tag = dialer.tag().to_string();
        Self {
            terminator: TcpTerminator::new(),
            dialer,
            kind,
            tag,
            event_tx,
            event_rx,
            relays: HashMap::new(),
            pending: HashMap::new(),
            dial_buffer: DialBuffer::default(),
            closed_during_dial: HashSet::new(),
            pending_tun: Vec::new(),
            stats: ProxyFwdStats::default(),
        }
    }

    /// 处理一个 proxy 分类的 TCP 包；返回待写回 TUN 的包。
    pub fn handle_packet(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        // 先排空 proxy 事件（dial 完成/数据/关闭）。
        self.drain_events();
        // 喂给 smoltcp。
        let mut out = self.terminator.handle_uplink(packet, "proxy");
        // 驱动 smoltcp 并处理事件。
        for event in self.terminator.poll() {
            self.handle_tcp_event(event, &mut out);
        }
        out.append(&mut self.pending_tun);
        self.fixup_out(&mut out);
        out
    }

    /// 定期驱动（无包时也调用，处理重传/超时）。
    /// 返回待写回 TUN 的包。
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        self.drain_events();
        let mut out = Vec::new();
        for event in self.terminator.poll() {
            self.handle_tcp_event(event, &mut out);
        }
        out.append(&mut self.pending_tun);
        self.fixup_out(&mut out);
        out
    }

    /// 写回 TUN 前把 smoltcp 源 IP（10.254.0.1）改回原始目的（GAP-5 规则）。
    fn fixup_out(&self, out: &mut [Vec<u8>]) {
        for pkt in out.iter_mut() {
            if let Some(fixed) = self.terminator.fixup_tun_packet(pkt) {
                *pkt = fixed;
            }
        }
    }

    /// 排空中继线程发来的事件。
    fn drain_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                TcpFwdEvent::DialDone { stream_id, result } => match result {
                    Ok(handle) => {
                        self.pending.remove(&stream_id);
                        if self.closed_during_dial.remove(&stream_id) {
                            // 流在 dial 期间已关闭：句柄无人消费，直接 drop
                            // （relay 线程因命令通道断开而退出）。
                            drop(handle);
                            self.dial_buffer.discard(stream_id);
                        } else if self.dial_buffer.take_overflowed(stream_id) {
                            // dial 期间缓冲超限：fail-closed（RST），不静默截断。
                            drop(handle);
                            self.stats.tcp_dials_failed += 1;
                            let four = self.terminator.lookup_id(stream_id);
                            let mut pkts = self.terminator.handle_fabric_rst(stream_id);
                            if !has_rst(&pkts)
                                && let Some(four) = four
                            {
                                pkts.push(craft_rst(&four));
                            }
                            let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                            eprintln!(
                                "[proxy-fwd] event=dial_failed stream_id={stream_id} kind={} tag={} error=internal detail=dial_buffer_overflow",
                                self.kind.as_str(),
                                self.tag
                            );
                        } else {
                            self.relays.insert(stream_id, handle);
                            self.stats.tcp_dials_ok += 1;
                            // 补发 dial 期间缓冲的客户端数据（保持字节顺序）。
                            if let Some(buffered) = self.dial_buffer.take(stream_id)
                                && !buffered.is_empty()
                                && let Some(relay) = self.relays.get(&stream_id)
                            {
                                let _ = relay.tx.send(RelayCmd::Data(buffered));
                            }
                        }
                    }
                    Err(error) => {
                        self.pending.remove(&stream_id);
                        self.closed_during_dial.remove(&stream_id);
                        self.dial_buffer.discard(stream_id);
                        self.stats.tcp_dials_failed += 1;
                        // RST smoltcp 侧；terminator 在 SynReceived 直接 release
                        // 时不产包，需按四元组兜底构造 RST（E4 可观察）。
                        let four = self.terminator.lookup_id(stream_id);
                        let mut pkts = self.terminator.handle_fabric_rst(stream_id);
                        if !has_rst(&pkts)
                            && let Some(four) = four
                        {
                            pkts.push(craft_rst(&four));
                        }
                        let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                        eprintln!(
                            "[proxy-fwd] event=dial_failed stream_id={stream_id} kind={} tag={} error={} detail={}",
                            self.kind.as_str(),
                            self.tag,
                            error.reason(),
                            error.detail()
                        );
                    }
                },
                TcpFwdEvent::ProxyData { stream_id, bytes } => {
                    self.stats.tcp_bytes_down += bytes.len() as u64;
                    let pkts = self.terminator.handle_fabric_data(stream_id, &bytes);
                    if !pkts.is_empty() {
                        let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                    }
                }
                TcpFwdEvent::ProxyClosed { stream_id, reset } => {
                    self.relays.remove(&stream_id);
                    let pkts = if reset {
                        self.terminator.handle_fabric_rst(stream_id)
                    } else {
                        self.terminator.handle_fabric_fin(stream_id)
                    };
                    if !pkts.is_empty() {
                        let _ = self.event_tx.send(TcpFwdEvent::TunPackets(pkts));
                    }
                }
                TcpFwdEvent::TunPackets(pkts) => {
                    // 暂存，下次 handle_packet/poll 返回时带上。
                    self.pending_tun.extend(pkts);
                }
            }
        }
    }

    /// smoltcp 事件处理。
    fn handle_tcp_event(&mut self, event: TcpEvent, out: &mut Vec<Vec<u8>>) {
        match event {
            TcpEvent::Syn { stream_id, dst, .. } => {
                let active = self.relays.len() + self.pending.len();
                if active >= MAX_ACTIVE_TCP_FLOWS {
                    self.stats.tcp_flows_rejected += 1;
                    self.reject_stream(stream_id, out);
                    eprintln!(
                        "[proxy-fwd] event=tcp_flow_rejected stream_id={stream_id} active={active} limit={MAX_ACTIVE_TCP_FLOWS}"
                    );
                } else if self.pending.len() >= MAX_CONCURRENT_DIALS {
                    self.stats.tcp_dials_throttled += 1;
                    let dialing = self.pending.len();
                    self.reject_stream(stream_id, out);
                    eprintln!(
                        "[proxy-fwd] event=tcp_dial_throttled stream_id={stream_id} active={dialing} limit={MAX_CONCURRENT_DIALS}"
                    );
                } else {
                    self.stats.tcp_streams_ok += 1;
                    self.closed_during_dial.remove(&stream_id);
                    let target = SocketAddr::V4(dst);
                    self.pending.insert(stream_id, target);
                    let dialer = Arc::clone(&self.dialer);
                    let tx = self.event_tx.clone();
                    std::thread::spawn(move || {
                        let result = dialer
                            .dial_tcp(target)
                            .map(|stream| spawn_relay(stream_id, stream, tx.clone()));
                        let _ = tx.send(TcpFwdEvent::DialDone { stream_id, result });
                    });
                }
            }
            TcpEvent::Data {
                stream_id, bytes, ..
            } => {
                if let Some(relay) = self.relays.get(&stream_id) {
                    // 非阻塞发送（中继线程可能已退出，忽略错误）。
                    self.stats.tcp_bytes_up += bytes.len() as u64;
                    let _ = relay.tx.send(RelayCmd::Data(bytes));
                } else if self.pending.contains_key(&stream_id) {
                    // dial 在飞：先缓冲，dial 成功后按序补发（不丢首个 TCP 段）。
                    self.stats.tcp_bytes_up += bytes.len() as u64;
                    self.dial_buffer.append(stream_id, &bytes);
                }
            }
            TcpEvent::Closed {
                stream_id, reset, ..
            } => {
                if let Some(relay) = self.relays.remove(&stream_id) {
                    let _ = relay.tx.send(RelayCmd::Close);
                }
                if self.pending.remove(&stream_id).is_some() {
                    self.closed_during_dial.insert(stream_id);
                }
                self.dial_buffer.discard(stream_id);
                // smoltcp 侧已关闭，无需额外动作。
                let _ = reset;
            }
            TcpEvent::TunPacket(pkt) => {
                out.push(pkt);
            }
        }
        // 带上之前暂存的 TUN 包。
        out.append(&mut self.pending_tun);
    }

    /// 资源边界拒绝：直接 RST（不 dial，spec §2.6.2 FlowLimit/DialLimit）。
    fn reject_stream(&mut self, stream_id: u32, out: &mut Vec<Vec<u8>>) {
        let four = self.terminator.lookup_id(stream_id);
        let mut pkts = self.terminator.handle_fabric_rst(stream_id);
        if !has_rst(&pkts)
            && let Some(four) = four
        {
            pkts.push(craft_rst(&four));
        }
        out.append(&mut pkts);
    }

    pub fn stats(&self) -> ProxyFwdStats {
        self.stats.clone()
    }
}

/// dial 在飞期间的客户端数据缓冲。
///
/// SYN 即开始 dial，客户端可能在 dial 完成前就发出首个 TCP 段；这段时间的数据
/// 必须按序保存并在 dial 成功后补发。超过 [`DIAL_BUFFER_MAX_BYTES`] 的流标记为
/// overflow，由调用方在 dial 完成后 fail-closed（RST），绝不静默截断字节流。
#[derive(Default)]
struct DialBuffer {
    streams: HashMap<u32, Vec<u8>>,
    overflowed: HashSet<u32>,
}

impl DialBuffer {
    fn append(&mut self, stream_id: u32, bytes: &[u8]) {
        if self.overflowed.contains(&stream_id) {
            return;
        }
        let buffered = self.streams.entry(stream_id).or_default();
        if buffered.len().saturating_add(bytes.len()) > DIAL_BUFFER_MAX_BYTES {
            buffered.clear();
            buffered.shrink_to_fit();
            self.overflowed.insert(stream_id);
        } else {
            buffered.extend_from_slice(bytes);
        }
    }

    /// 取出缓冲数据；无缓冲时返回 `None`。
    fn take(&mut self, stream_id: u32) -> Option<Vec<u8>> {
        self.streams.remove(&stream_id)
    }

    /// 取出并清除 overflow 标记；`true` = 该流 dial 期间超限，必须 fail-closed。
    fn take_overflowed(&mut self, stream_id: u32) -> bool {
        if self.overflowed.remove(&stream_id) {
            self.streams.remove(&stream_id);
            true
        } else {
            false
        }
    }

    fn discard(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
        self.overflowed.remove(&stream_id);
    }
}

fn has_rst(pkts: &[Vec<u8>]) -> bool {
    pkts.iter()
        .any(|pkt| pkt.len() >= 34 && pkt[9] == 6 && pkt[33] & 0x04 != 0)
}

/// 构造 RST（回退路径；src/dst 互换）。
fn craft_rst(four: &FourTuple) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[3] = 40;
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&four.dst_ip);
    pkt[16..20].copy_from_slice(&four.src_ip);
    pkt[20..22].copy_from_slice(&four.dst_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&four.src_port.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x14;
    let c = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    let c2 = tcp_checksum(four.dst_ip, four.src_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&c2.to_be_bytes());
    pkt
}

/// 启动中继线程；返回 dataplane 侧句柄。
fn spawn_relay(
    stream_id: u32,
    mut stream: Box<dyn TunnelStream>,
    tx: Sender<TcpFwdEvent>,
) -> RelayHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel::<RelayCmd>();
    std::thread::spawn(move || {
        // 设置读/写超时：读超时用于定期检查命令，写超时防背压无限阻塞。
        let _ = stream.set_read_timeout(Some(RELAY_READ_TIMEOUT));
        let _ = stream.set_write_timeout(Some(RELAY_WRITE_TIMEOUT));
        let mut buf = [0u8; RELAY_BUF_LEN];
        let mut up_bytes = 0u64;
        let mut down_bytes = 0u64;
        let mut reset = false;
        loop {
            // 先检查关闭命令（非阻塞）。
            match cmd_rx.try_recv() {
                Ok(RelayCmd::Close) | Err(mpsc::TryRecvError::Disconnected) => break,
                Ok(RelayCmd::Data(data)) => {
                    up_bytes += data.len() as u64;
                    if stream.write_all(&data).is_err() {
                        reset = true;
                        break;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // 从 proxy 读。
            match stream.read(&mut buf) {
                Ok(0) => {
                    // EOF：正常关闭。
                    let _ = tx.send(TcpFwdEvent::ProxyClosed {
                        stream_id,
                        reset: false,
                    });
                    break;
                }
                Ok(n) => {
                    down_bytes += n as u64;
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
                    reset = true;
                    let _ = tx.send(TcpFwdEvent::ProxyClosed {
                        stream_id,
                        reset: true,
                    });
                    break;
                }
            }
        }
        if !reset {
            // 客户端正常关闭 → 半关闭写方向（AnyTLS 在此发 Fin 帧；spec §3.2）。
            let _ = stream.shutdown();
        }
        eprintln!(
            "[proxy-fwd] event=relay_closed stream_id={stream_id} reset={reset} up_bytes={up_bytes} down_bytes={down_bytes}"
        );
    });
    RelayHandle { tx: cmd_tx }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_buffer_preserves_order_and_flushes_once() {
        let mut buffer = DialBuffer::default();
        buffer.append(7, b"abc");
        buffer.append(7, b"def");
        assert_eq!(buffer.take(7).as_deref(), Some(&b"abcdef"[..]));
        assert!(buffer.take(7).is_none());
    }

    #[test]
    fn dial_buffer_overflow_is_fail_closed_not_truncated() {
        let mut buffer = DialBuffer::default();
        buffer.append(1, &vec![0u8; DIAL_BUFFER_MAX_BYTES]);
        buffer.append(1, b"x");
        assert!(buffer.take_overflowed(1));
        // overflow 流不会把截断后的字节交给 relay；调用方改发 RST。
        assert!(buffer.take(1).is_none());
    }

    #[test]
    fn dial_buffer_discard_clears_buffered_bytes_and_overflow_flag() {
        let mut buffer = DialBuffer::default();
        buffer.append(2, b"data");
        buffer.discard(2);
        assert!(buffer.take(2).is_none());

        buffer.append(3, &vec![0u8; DIAL_BUFFER_MAX_BYTES]);
        buffer.append(3, b"x");
        buffer.discard(3);
        assert!(!buffer.take_overflowed(3));
    }
}
