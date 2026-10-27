//! 透明前端管道（spec §9.12）：消费 `TransparentDecision`，产出回包/关闭事件。
//!
//! 不依赖 `nexus-flow-session` / `nexus-proxy`；TCP/UDP 的真实 socket 由
//! `DirectEgress` / `ProxyFlowEgress` 提供，UDP 共享单 socket + per-flow 表。

use std::collections::HashMap;
use std::io;
use std::net::SocketAddrV4;

use crate::egress::FlowKey;

use super::direct::DirectEgressEvent;
use super::{
    ProxyEgressEvent, TransparentConfig, TransparentConnection, TransparentDecision,
    TransparentDeps, TransparentFrontendError, TransparentOutput, TransparentStats,
    TransparentTcpInput, TransparentUdpInput,
};

/// 单数据报上限（IPv4 UDP 最大载荷）。
const MAX_UDP_PAYLOAD: usize = 65_507;

/// UDP 流键：对端 + 原始目的地。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    /// 对端。
    pub peer: SocketAddrV4,
    /// 原始目的地。
    pub orig_dst: SocketAddrV4,
}

/// UDP 流状态。
#[derive(Debug, Clone)]
pub struct UdpFlowState {
    /// 原始目的地。
    pub orig_dst: SocketAddrV4,
    /// 对端。
    pub peer: SocketAddrV4,
    /// 最近活动（driver 毫秒）。
    pub last_seen_millis: u64,
    /// 选定的出站 tag（Direct 为 `None`）。
    pub outbound_tag: Option<String>,
}

struct TcpFlow {
    conn: Box<dyn TransparentConnection>,
    proxy: bool,
}

/// 透明前端的失败类别（token 与 LocalAPI `tproxy.counters` 同名，spec §9.16）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentFailureKind {
    /// 代理上游拨号/发送失败（`upstream_failed`）。
    UpstreamFailed,
    /// TCP 直连拨号失败（`direct_tcp_dial_failed`）。
    DirectTcpDialFailed,
    /// Direct 发送失败（`direct_udp_failed`）。
    DirectUdpFailed,
}

impl TransparentFailureKind {
    /// 规范类别 token（可直接与计数器名对齐）。
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::UpstreamFailed => "upstream_failed",
            Self::DirectTcpDialFailed => "direct_tcp_dial_failed",
            Self::DirectUdpFailed => "direct_udp_failed",
        }
    }
}

/// 一次待发布的失败：在递增计数的同一点记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentFailure {
    /// 规范类别。
    pub kind: TransparentFailureKind,
    /// 原始细节（不解析、不改写）。
    pub detail: String,
}

/// 透明 TCP/UDP 前端管道。
pub struct TransparentPipeline {
    deps: TransparentDeps,
    tcp: HashMap<FlowKey, TcpFlow>,
    udp: HashMap<UdpFlowKey, UdpFlowState>,
    udp_by_key: HashMap<FlowKey, UdpFlowKey>,
    stats: TransparentStats,
    /// 最近一次异步失败（同步错误由调用方从 `Result` 持久化）。
    pending_failure: Option<TransparentFailure>,
}

impl TransparentPipeline {
    /// 用组合根注入的依赖构造。
    pub fn new(deps: TransparentDeps) -> Self {
        Self {
            deps,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            udp_by_key: HashMap::new(),
            stats: TransparentStats::default(),
            pending_failure: None,
        }
    }

    /// 当前配置。
    pub fn config(&self) -> &TransparentConfig {
        &self.deps.config
    }

    /// 处理一条已 accept 的透明 TCP 输入。
    ///
    /// # Errors
    ///
    /// 原始目的地非法/缺失、连接数上限、Direct 拨号失败、代理出口失败。
    pub fn on_tcp(&mut self, input: TransparentTcpInput) -> Result<(), TransparentFrontendError> {
        let peer = input.conn.peer();
        let orig_dst = input.conn.orig_dst();
        if orig_dst.port() == 0 {
            self.stats.tcp_rejected += 1;
            return Err(TransparentFrontendError::OrigDstInvalid {
                raw: orig_dst.to_string(),
            });
        }
        if orig_dst.ip().is_unspecified() || orig_dst == peer {
            self.stats.tcp_rejected += 1;
            return Err(TransparentFrontendError::OrigDstMissing { peer });
        }
        if self.tcp.len() >= self.deps.config.max_tcp_conns {
            self.stats.tcp_rejected += 1;
            return Err(TransparentFrontendError::TcpConnLimit {
                limit: self.deps.config.max_tcp_conns,
            });
        }

        let key = tcp_flow_key(peer, orig_dst);
        match input.decision {
            TransparentDecision::Direct => match self.deps.direct.dial_tcp(key, orig_dst) {
                Ok(()) => {
                    self.stats.direct_tcp_dial_ok += 1;
                    self.stats.tcp_accepted += 1;
                    self.stats.tcp_active += 1;
                    self.tcp.insert(
                        key,
                        TcpFlow {
                            conn: input.conn,
                            proxy: false,
                        },
                    );
                    Ok(())
                }
                Err(error) => {
                    self.stats.direct_tcp_dial_failed += 1;
                    Err(TransparentFrontendError::DirectDialFailed {
                        dst: orig_dst,
                        reason: error.to_string(),
                    })
                }
            },
            TransparentDecision::Proxy {
                outbound,
                fallback: _,
            } => {
                let Some(egress) = self.deps.proxy_egress.as_mut() else {
                    self.stats.upstream_failed += 1;
                    return Err(TransparentFrontendError::RuleEngineUnavailable {
                        reason: "no proxy egress configured".to_string(),
                    });
                };
                match egress.open_tcp(key, orig_dst, &outbound) {
                    Ok(()) => {
                        self.stats.tcp_accepted += 1;
                        self.stats.tcp_active += 1;
                        self.tcp.insert(
                            key,
                            TcpFlow {
                                conn: input.conn,
                                proxy: true,
                            },
                        );
                        Ok(())
                    }
                    Err(error) => {
                        self.stats.upstream_failed += 1;
                        Err(error)
                    }
                }
            }
            TransparentDecision::Drop { .. } => {
                self.stats.tcp_rejected += 1;
                Err(TransparentFrontendError::RuleNoMatch {
                    target: orig_dst.to_string(),
                })
            }
        }
    }

    /// 处理一条透明 UDP 数据报。
    ///
    /// # Errors
    ///
    /// 载荷过大、无代理出口、Direct/代理发送失败。
    pub fn on_udp(&mut self, input: TransparentUdpInput) -> Result<(), TransparentFrontendError> {
        if input.payload.len() > MAX_UDP_PAYLOAD {
            self.stats.udp_dropped += 1;
            return Err(TransparentFrontendError::PayloadTooLarge {
                len: input.payload.len(),
                max: MAX_UDP_PAYLOAD,
            });
        }
        if input.orig_dst.port() == 0 {
            self.stats.udp_dropped += 1;
            return Err(TransparentFrontendError::OrigDstInvalid {
                raw: input.orig_dst.to_string(),
            });
        }
        self.stats.udp_datagrams += 1;

        let flow_key = udp_flow_key(input.peer, input.orig_dst);
        let table_key = udp_key(input.peer, input.orig_dst);
        let outbound_tag = match &input.decision {
            TransparentDecision::Direct => None,
            TransparentDecision::Proxy { outbound, .. } => Some(outbound.clone()),
            TransparentDecision::Drop { .. } => {
                self.stats.udp_dropped += 1;
                return Err(TransparentFrontendError::RuleNoMatch {
                    target: input.orig_dst.to_string(),
                });
            }
        };

        match &input.decision {
            TransparentDecision::Direct => {
                match self
                    .deps
                    .direct
                    .send_udp(flow_key, input.orig_dst, &input.payload)
                {
                    Ok(_) => self.stats.direct_udp_sent += 1,
                    Err(error) => {
                        self.stats.direct_udp_failed += 1;
                        self.stats.udp_dropped += 1;
                        return Err(TransparentFrontendError::DirectSendFailed {
                            dst: input.orig_dst,
                            reason: error.to_string(),
                        });
                    }
                }
            }
            TransparentDecision::Proxy { .. } => {
                let Some(egress) = self.deps.proxy_egress.as_mut() else {
                    self.stats.udp_dropped += 1;
                    return Err(TransparentFrontendError::RuleEngineUnavailable {
                        reason: "no proxy egress configured".to_string(),
                    });
                };
                if let Some(tag) = outbound_tag.as_deref() {
                    egress.note_udp_outbound(flow_key, tag);
                }
                if let Err(error) = egress.send_udp(flow_key, input.orig_dst, &input.payload) {
                    self.stats.upstream_failed += 1;
                    self.stats.udp_dropped += 1;
                    return Err(error);
                }
            }
            TransparentDecision::Drop { .. } => unreachable!("handled above"),
        }

        self.udp.insert(
            table_key,
            UdpFlowState {
                orig_dst: input.orig_dst,
                peer: input.peer,
                last_seen_millis: input.received_at_millis,
                outbound_tag,
            },
        );
        self.udp_by_key.insert(flow_key, table_key);
        self.evict_udp_over_capacity();
        Ok(())
    }

    /// 驱动下行与老化；`now_millis` 与 `on_udp` 同一时钟域。
    pub fn poll(&mut self, now_millis: u64) -> Vec<TransparentOutput> {
        let mut out = Vec::new();
        self.pump_tcp_uplink(&mut out);

        // Direct：TCP 下行 + UDP 回包。
        for event in self.deps.direct.poll(now_millis) {
            match event {
                DirectEgressEvent::TcpData { key, bytes } => {
                    self.write_back_tcp(&key, &bytes, &mut out);
                }
                DirectEgressEvent::TcpClosed { key, reset } => {
                    self.finish_tcp(&key, reset, &mut out);
                }
                DirectEgressEvent::UdpReply { key, payload } => {
                    if let Some(dst) = self.udp_by_key.get(&key).copied() {
                        if let Some(state) = self.udp.get_mut(&dst) {
                            state.last_seen_millis = now_millis;
                            out.push(TransparentOutput::UdpReply {
                                orig_dst: state.orig_dst,
                                peer: state.peer,
                                payload,
                            });
                        }
                    }
                }
                DirectEgressEvent::Failed { key, error } => {
                    self.stats.direct_tcp_dial_failed += 1;
                    self.note_failure(
                        TransparentFailureKind::DirectTcpDialFailed,
                        error.to_string(),
                    );
                    self.finish_tcp(&key, true, &mut out);
                }
            }
        }

        // Proxy：下行/关闭/UDP 回包。
        if let Some(egress) = self.deps.proxy_egress.as_mut() {
            for event in egress.poll() {
                match event {
                    ProxyEgressEvent::TcpData { key, bytes } => {
                        self.write_back_tcp(&key, &bytes, &mut out);
                    }
                    ProxyEgressEvent::TcpClosed { key, reset } => {
                        self.finish_tcp(&key, reset, &mut out);
                    }
                    ProxyEgressEvent::UdpReply { key, payload } => {
                        if let Some(dst) = self.udp_by_key.get(&key).copied() {
                            if let Some(state) = self.udp.get_mut(&dst) {
                                state.last_seen_millis = now_millis;
                                out.push(TransparentOutput::UdpReply {
                                    orig_dst: state.orig_dst,
                                    peer: state.peer,
                                    payload,
                                });
                            }
                        }
                    }
                    ProxyEgressEvent::Failed { key, reason } => {
                        self.stats.upstream_failed += 1;
                        self.note_failure(TransparentFailureKind::UpstreamFailed, reason);
                        self.finish_tcp(&key, true, &mut out);
                    }
                }
            }
        }

        self.sweep_udp(now_millis);
        out
    }

    /// 关闭全部 TCP 流并返回关闭事件。
    pub fn shutdown(&mut self) -> Vec<TransparentOutput> {
        let mut out = Vec::new();
        let keys: Vec<FlowKey> = self.tcp.keys().copied().collect();
        for key in keys {
            self.finish_tcp(&key, false, &mut out);
        }
        self.udp.clear();
        self.udp_by_key.clear();
        out
    }

    /// 计数器快照。
    pub fn stats(&self) -> TransparentStats {
        self.stats.clone()
    }

    /// 取走最近一次异步失败（每 tick 由 owner 取一次并发布）。
    ///
    /// 同步失败（`on_tcp`/`on_udp` 的 `Err`）由调用方直接持久化，不在此排队。
    #[must_use]
    pub fn take_failure(&mut self) -> Option<TransparentFailure> {
        self.pending_failure.take()
    }

    fn note_failure(&mut self, kind: TransparentFailureKind, detail: impl Into<String>) {
        self.pending_failure = Some(TransparentFailure {
            kind,
            detail: detail.into(),
        });
    }

    /// 当前 UDP 流表条目数（测试/状态用）。
    pub fn udp_table_len(&self) -> usize {
        self.udp.len()
    }

    /// Direct 出口当前 UDP socket 数（应为 0 或 1，证明多流共享）。
    pub fn direct_udp_socket_count(&self) -> usize {
        self.deps.direct.udp_socket_count()
    }

    /// 从 accepted stream 读取应用字节并写入 Direct/Proxy 出口。
    fn pump_tcp_uplink(&mut self, out: &mut Vec<TransparentOutput>) {
        let keys: Vec<FlowKey> = self.tcp.keys().copied().collect();
        for key in keys {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let read = {
                    let Some(flow) = self.tcp.get_mut(&key) else {
                        break;
                    };
                    flow.conn.read(&mut buf)
                };
                match read {
                    Ok(0) => {
                        self.finish_tcp(&key, false, out);
                        break;
                    }
                    Ok(n) => {
                        let proxy = self.tcp.get(&key).is_some_and(|flow| flow.proxy);
                        let result = if proxy {
                            match self.deps.proxy_egress.as_mut() {
                                Some(egress) => egress.write_tcp(&key, &buf[..n]),
                                None => Err(TransparentFrontendError::RuleEngineUnavailable {
                                    reason: "no proxy egress configured".to_string(),
                                }),
                            }
                        } else {
                            self.deps
                                .direct
                                .write_tcp(&key, &buf[..n])
                                .map(|_| ())
                                .map_err(|e| TransparentFrontendError::DirectSendFailed {
                                    dst: self
                                        .tcp
                                        .get(&key)
                                        .map(|flow| flow.conn.orig_dst())
                                        .unwrap_or_else(|| {
                                            SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
                                        }),
                                    reason: e.to_string(),
                                })
                        };
                        if let Err(error) = result {
                            if proxy {
                                self.stats.upstream_failed += 1;
                                self.note_failure(
                                    TransparentFailureKind::UpstreamFailed,
                                    error.to_string(),
                                );
                            } else {
                                self.stats.direct_udp_failed += 1;
                                self.note_failure(
                                    TransparentFailureKind::DirectUdpFailed,
                                    error.to_string(),
                                );
                            }
                            self.finish_tcp(&key, true, out);
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        self.finish_tcp(&key, true, out);
                        break;
                    }
                }
            }
        }
    }

    fn write_back_tcp(&mut self, key: &FlowKey, bytes: &[u8], out: &mut Vec<TransparentOutput>) {
        let Some(flow) = self.tcp.get_mut(key) else {
            return;
        };
        if flow.conn.write_all(bytes).is_err() {
            self.stats.tcp_closed += 1;
            self.stats.tcp_active = self.stats.tcp_active.saturating_sub(1);
            self.tcp.remove(key);
            out.push(TransparentOutput::FlowClosed {
                key: *key,
                reset: true,
            });
        }
    }

    fn finish_tcp(&mut self, key: &FlowKey, reset: bool, out: &mut Vec<TransparentOutput>) {
        let Some(flow) = self.tcp.remove(key) else {
            return;
        };
        if flow.proxy {
            if let Some(egress) = self.deps.proxy_egress.as_mut() {
                egress.close_tcp(key);
            }
        } else {
            self.deps.direct.close(key, reset);
        }
        self.stats.tcp_closed += 1;
        self.stats.tcp_active = self.stats.tcp_active.saturating_sub(1);
        out.push(TransparentOutput::FlowClosed { key: *key, reset });
    }

    fn evict_udp_over_capacity(&mut self) {
        let capacity = self.deps.config.udp_table_capacity;
        while self.udp.len() > capacity.max(1) {
            let oldest = self
                .udp
                .iter()
                .min_by_key(|(_, state)| state.last_seen_millis)
                .map(|(key, _)| *key);
            let Some(key) = oldest else {
                break;
            };
            self.udp.remove(&key);
            self.udp_by_key
                .remove(&udp_flow_key(key.peer, key.orig_dst));
            self.stats.udp_table_evicted += 1;
        }
    }

    fn sweep_udp(&mut self, now_millis: u64) {
        let idle_ms = u64::try_from(self.deps.config.udp_idle.as_millis()).unwrap_or(u64::MAX);
        let before = self.udp.len();
        self.udp
            .retain(|_, state| now_millis.saturating_sub(state.last_seen_millis) < idle_ms);
        let removed = before - self.udp.len();
        if removed > 0 {
            self.stats.udp_table_evicted += removed as u64;
            let live: Vec<UdpFlowKey> = self.udp.keys().copied().collect();
            self.udp_by_key
                .retain(|_, udp| live.contains(udp) && self.udp.contains_key(udp));
        }
    }
}

fn tcp_flow_key(peer: SocketAddrV4, orig_dst: SocketAddrV4) -> FlowKey {
    FlowKey {
        src_ip: u32::from(*peer.ip()),
        dst_ip: u32::from(*orig_dst.ip()),
        src_port: peer.port(),
        dst_port: orig_dst.port(),
        proto: 6,
    }
}

fn udp_flow_key(peer: SocketAddrV4, orig_dst: SocketAddrV4) -> FlowKey {
    FlowKey {
        src_ip: u32::from(*peer.ip()),
        dst_ip: u32::from(*orig_dst.ip()),
        src_port: peer.port(),
        dst_port: orig_dst.port(),
        proto: 17,
    }
}

fn udp_key(peer: SocketAddrV4, orig_dst: SocketAddrV4) -> UdpFlowKey {
    UdpFlowKey { peer, orig_dst }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use super::super::PathFailurePolicy;
    use super::super::direct::{DirectEgress, DirectEgressConfig};

    struct MemoryConnection {
        peer: SocketAddrV4,
        orig_dst: SocketAddrV4,
        outbound: Vec<u8>,
    }

    impl MemoryConnection {
        fn new(peer: SocketAddrV4, orig_dst: SocketAddrV4) -> Self {
            Self {
                peer,
                orig_dst,
                outbound: Vec::new(),
            }
        }
    }

    impl TransparentConnection for MemoryConnection {
        fn peer(&self) -> SocketAddrV4 {
            self.peer
        }

        fn orig_dst(&self) -> SocketAddrV4 {
            self.orig_dst
        }

        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.outbound.extend_from_slice(buf);
            Ok(())
        }

        fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn v4(ip: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), port)
    }

    fn pipeline(capacity: usize) -> TransparentPipeline {
        let config = TransparentConfig {
            udp_table_capacity: capacity,
            udp_idle: Duration::from_secs(60),
            on_path_failure: PathFailurePolicy::Block,
            ..TransparentConfig::default()
        };
        TransparentPipeline::new(TransparentDeps {
            proxy_egress: None,
            direct: DirectEgress::new(DirectEgressConfig::default()).unwrap(),
            config,
        })
    }

    fn udp_input(peer_port: u16, orig_port: u16, now: u64) -> TransparentUdpInput {
        TransparentUdpInput {
            payload: b"ping".to_vec(),
            peer: v4([192, 168, 1, 5], peer_port),
            orig_dst: v4([127, 0, 0, 1], orig_port),
            received_at_millis: now,
            decision: TransparentDecision::Direct,
        }
    }

    #[test]
    fn transparent_pipeline_udp_shares_one_socket() {
        let mut p = pipeline(8192);
        // 100 条流指向 100 个不同目的端口；共享同一个 UDP socket。
        for i in 0..100u16 {
            p.on_udp(udp_input(40_000 + i, 9, u64::from(i))).unwrap();
        }
        assert_eq!(p.stats().udp_datagrams, 100);
        assert_eq!(p.stats().direct_udp_sent, 100);
        assert_eq!(p.udp_table_len(), 100);
        assert_eq!(p.direct_udp_socket_count(), 1);
        assert_eq!(p.stats().udp_table_evicted, 0);
    }

    #[test]
    fn transparent_pipeline_udp_capacity_lru_evicts() {
        let mut p = pipeline(2);
        p.on_udp(udp_input(1, 9, 1)).unwrap();
        p.on_udp(udp_input(2, 9, 2)).unwrap();
        // 触碰第一条，使第二条成为最久未用。
        p.poll(3);
        p.on_udp(udp_input(3, 9, 4)).unwrap();
        assert_eq!(p.udp_table_len(), 2);
        assert_eq!(p.stats().udp_table_evicted, 1);
    }

    #[test]
    fn transparent_pipeline_udp_idle_evicted_by_poll() {
        let mut p = pipeline(8);
        p.on_udp(udp_input(1, 9, 1_000)).unwrap();
        assert_eq!(p.udp_table_len(), 1);
        // 未到 60s：不淘汰（poll 无输入也驱动老化）。
        p.poll(1_000 + 59_000);
        assert_eq!(p.udp_table_len(), 1);
        p.poll(1_000 + 61_000);
        assert_eq!(p.udp_table_len(), 0);
        assert_eq!(p.stats().udp_table_evicted, 1);
    }

    #[test]
    fn transparent_pipeline_udp_reply_keeps_orig_dst_and_peer() {
        let server = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let orig = match server.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("v4"),
        };
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = server.recv_from(&mut buf) {
                let _ = server.send_to(&buf[..n], from);
            }
        });
        let mut p = pipeline(8);
        let peer = v4([192, 168, 1, 5], 40_000);
        p.on_udp(TransparentUdpInput {
            payload: b"ping".to_vec(),
            peer,
            orig_dst: orig,
            received_at_millis: 1,
            decision: TransparentDecision::Direct,
        })
        .unwrap();
        let mut got = None;
        for t in 0..2_000u64 {
            for out in p.poll(t) {
                if let TransparentOutput::UdpReply {
                    orig_dst,
                    peer: got_peer,
                    payload,
                } = out
                {
                    got = Some((orig_dst, got_peer, payload));
                }
            }
            if got.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let (got_orig, got_peer, payload) = got.expect("udp reply");
        assert_eq!(got_orig, orig);
        assert_eq!(got_peer, peer);
        assert_eq!(payload, b"ping");
        handle.join().unwrap();
    }

    #[test]
    fn transparent_pipeline_tcp_invalid_orig_dst_does_not_write_back() {
        let mut p = pipeline(8);
        let peer = v4([192, 168, 1, 5], 40_000);
        // 端口 0 → Invalid。
        let err = p
            .on_tcp(TransparentTcpInput {
                conn: Box::new(MemoryConnection::new(peer, v4([10, 0, 0, 9], 0))),
                accepted_at_millis: 1,
                decision: TransparentDecision::Direct,
            })
            .expect_err("invalid orig dst");
        assert!(matches!(
            err,
            TransparentFrontendError::OrigDstInvalid { .. }
        ));
        // 未指定地址 → Missing。
        let err = p
            .on_tcp(TransparentTcpInput {
                conn: Box::new(MemoryConnection::new(peer, v4([0, 0, 0, 0], 443))),
                accepted_at_millis: 1,
                decision: TransparentDecision::Direct,
            })
            .expect_err("missing orig dst");
        assert!(matches!(
            err,
            TransparentFrontendError::OrigDstMissing { .. }
        ));
        assert_eq!(p.stats().tcp_accepted, 0);
        assert!(p.poll(2).is_empty());
    }

    #[test]
    fn transparent_pipeline_tcp_direct_echo_writes_back() {
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let orig = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("v4"),
        };
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                use std::io::Read as _;
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });
        let mut p = pipeline(8);
        let peer = v4([192, 168, 1, 5], 40_000);
        p.on_tcp(TransparentTcpInput {
            conn: Box::new(MemoryConnection::new(peer, orig)),
            accepted_at_millis: 1,
            decision: TransparentDecision::Direct,
        })
        .unwrap();
        // 先把上行字节写入 Direct 流，再驱动下行。
        let key = tcp_flow_key(peer, orig);
        p.deps.direct.write_tcp(&key, b"hello").unwrap();
        let mut closed = false;
        for t in 0..2_000u64 {
            for out in p.poll(t) {
                if matches!(out, TransparentOutput::FlowClosed { .. }) {
                    closed = true;
                }
            }
            if closed {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(p.stats().direct_tcp_dial_ok, 1);
        assert_eq!(p.stats().tcp_accepted, 1);
        handle.join().unwrap();
    }
}
