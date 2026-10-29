//! TPROXY 前端的生产 `ProxyFlowEgress` 适配器（spec §9.12）。
//!
//! 把 core 的 `FlowKey` 映射为真实代理字节流 / UDP 中继：
//! - TCP：每个 key 一个中继线程，dial 成功后在 accepted stream 与代理之间泵字节；
//! - UDP：复用 `proxy_fwd::udp_relay::UdpForwarder`（SOCKS5 UDP ASSOCIATE /
//!   ss UDP / trojan UDP），按 key 记录 peer/orig_dst，回包只按该表查。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use nexus_projection::egress::FlowKey;
use nexus_projection::transparent::{ProxyEgressEvent, ProxyFlowEgress, TransparentFrontendError};

use crate::proxy_fwd::{OutboundRegistry, OutboundSlot};

const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(100);

enum RelayCmd {
    Data(Vec<u8>),
    Close,
}

enum RelayEvent {
    Data(FlowKey, Vec<u8>),
    Closed(FlowKey, bool),
    Failed(FlowKey, String),
}

/// 生产代理出口适配器。
pub struct StreamProxyEgress {
    registry: Arc<OutboundRegistry>,
    tcp: HashMap<FlowKey, Sender<RelayCmd>>,
    events_tx: Sender<RelayEvent>,
    events_rx: Receiver<RelayEvent>,
    udp: HashMap<String, crate::proxy_fwd::udp_relay::UdpForwarder>,
    udp_tags: HashMap<FlowKey, String>,
    udp_peers: HashMap<FlowKey, (SocketAddrV4, SocketAddrV4)>,
    /// §12.3 `event=outbound_unavailable` 的限频状态（per `(tag, cause)`）。
    ///
    /// 与 TUN 侧同一语义：首次立即发射、其后 10 s 一行、`suppressed=<n>` 带出。
    unavailable_log: crate::log_throttle::KeyedLogThrottle,
}

impl StreamProxyEgress {
    /// 从共享注册表构造（Q-5=B：TUN 与 TPROXY 同一批 dialer 实例）。
    ///
    /// registry 无任何 dialer 时返回 `None`（等价旧 `outbounds.is_empty()`）。
    #[must_use]
    pub fn from_registry(registry: Arc<OutboundRegistry>) -> Option<Self> {
        if !registry.has_any_dialer() {
            return None;
        }
        let (events_tx, events_rx) = mpsc::channel();
        Some(Self {
            registry,
            tcp: HashMap::new(),
            events_tx,
            events_rx,
            udp: HashMap::new(),
            udp_tags: HashMap::new(),
            udp_peers: HashMap::new(),
            unavailable_log: crate::log_throttle::KeyedLogThrottle::new(),
        })
    }

    /// §12.3：tag 不可用时的结构化行（TPROXY 无 SYN 时刻，仍给出 cause）。
    ///
    /// 与 TUN 侧 `Dataplane::log_outbound_unavailable` 同一限频语义：同一
    /// `(tag, cause)` 首次立即发射，其后每 10 s 一行，被抑制条数以
    /// `suppressed=<n>` 带出并清零（review MAJOR-2/C4）。
    fn log_outbound_unavailable(&mut self, tag: &str, kind: &str, cause: &str, detail: &str) {
        let decision = self.unavailable_log.decide(
            tag,
            cause,
            std::time::Instant::now(),
            crate::log_throttle::OUTBOUND_UNAVAILABLE_LOG_INTERVAL,
        );
        if !decision.emit {
            return;
        }
        eprintln!(
            "[proxy-fwd] event=outbound_unavailable tag={tag} kind={kind} cause={cause} detail=\"{detail}\" suppressed={}",
            decision.suppressed
        );
    }

    fn spawn_tcp_relay(
        &mut self,
        key: FlowKey,
        dialer: Arc<dyn crate::proxy_fwd::adapter::OutboundDialer>,
        target: SocketAddrV4,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let events_tx = self.events_tx.clone();
        std::thread::Builder::new()
            .name("nexusd-tproxy-relay".to_string())
            .spawn(move || {
                let mut stream = match dialer.dial_tcp(target.into()) {
                    Ok(stream) => stream,
                    Err(e) => {
                        let _ = events_tx.send(RelayEvent::Failed(key, e.to_string()));
                        return;
                    }
                };
                let _ = stream.set_read_timeout(Some(RELAY_READ_TIMEOUT));
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match cmd_rx.try_recv() {
                        Ok(RelayCmd::Close) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Ok(RelayCmd::Data(data)) => {
                            if stream.write_all(&data).is_err() {
                                let _ = events_tx.send(RelayEvent::Closed(key, true));
                                break;
                            }
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            let _ = events_tx.send(RelayEvent::Closed(key, false));
                            break;
                        }
                        Ok(n) => {
                            let _ = events_tx.send(RelayEvent::Data(key, buf[..n].to_vec()));
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(_) => {
                            let _ = events_tx.send(RelayEvent::Closed(key, true));
                            break;
                        }
                    }
                }
            })
            .ok();
        self.tcp.insert(key, cmd_tx);
    }
}

impl ProxyFlowEgress for StreamProxyEgress {
    fn open_tcp(
        &mut self,
        key: FlowKey,
        orig_dst: SocketAddrV4,
        outbound_tag: &str,
    ) -> Result<(), TransparentFrontendError> {
        let Some(dialer) = self.registry.dialer(outbound_tag).cloned() else {
            // 不可用槽位（ProtocolNotWired / Invalid）与「tag 不存在」同行为：
            // 前端按 on_path_failure 处置；额外打结构化行（§12.3）。
            let unavailable = self
                .registry
                .unsupported(outbound_tag)
                .map(outbound_unavailable_fields);
            if let Some((kind, cause, detail)) = unavailable {
                self.log_outbound_unavailable(outbound_tag, &kind, cause, &detail);
            }
            return Err(TransparentFrontendError::OutboundUnresolved {
                tag: outbound_tag.to_string(),
            });
        };
        self.spawn_tcp_relay(key, dialer, orig_dst);
        Ok(())
    }

    fn write_tcp(&mut self, key: &FlowKey, bytes: &[u8]) -> Result<(), TransparentFrontendError> {
        let tx =
            self.tcp
                .get(key)
                .ok_or_else(|| TransparentFrontendError::SessionEstablishFailed {
                    flow: format!("{key:?}"),
                    reason: "tcp relay not open".to_string(),
                })?;
        tx.send(RelayCmd::Data(bytes.to_vec())).map_err(|_| {
            TransparentFrontendError::SessionEstablishFailed {
                flow: format!("{key:?}"),
                reason: "tcp relay thread gone".to_string(),
            }
        })
    }

    fn close_tcp(&mut self, key: &FlowKey) {
        if let Some(tx) = self.tcp.remove(key) {
            let _ = tx.send(RelayCmd::Close);
        }
    }

    fn note_udp_outbound(&mut self, key: FlowKey, outbound_tag: &str) {
        self.udp_tags.insert(key, outbound_tag.to_string());
    }

    fn send_udp(
        &mut self,
        key: FlowKey,
        orig_dst: SocketAddrV4,
        payload: &[u8],
    ) -> Result<(), TransparentFrontendError> {
        let tag = self.udp_tags.get(&key).cloned().ok_or_else(|| {
            TransparentFrontendError::OutboundUnresolved {
                tag: "<unset>".to_string(),
            }
        })?;
        let dialer = self.registry.dialer(&tag).cloned().ok_or_else(|| {
            if let Some((kind, cause, detail)) = self
                .registry
                .unsupported(&tag)
                .map(outbound_unavailable_fields)
            {
                self.log_outbound_unavailable(&tag, &kind, cause, &detail);
            }
            TransparentFrontendError::OutboundUnresolved { tag: tag.clone() }
        })?;
        let packet = synthetic_udp_packet(key, orig_dst, payload);
        let forwarder = self
            .udp
            .entry(tag.clone())
            .or_insert_with(|| crate::proxy_fwd::udp_relay::UdpForwarder::new(dialer));
        if forwarder.handle_packet(&packet).accepted() {
            self.udp_peers.insert(key, (key_peer(key), orig_dst));
            Ok(())
        } else {
            Err(TransparentFrontendError::SessionEstablishFailed {
                flow: format!("{key:?}"),
                reason: "udp relay send failed".to_string(),
            })
        }
    }

    fn poll(&mut self) -> Vec<ProxyEgressEvent> {
        let mut out = Vec::new();
        while let Ok(event) = self.events_rx.try_recv() {
            match event {
                RelayEvent::Data(key, bytes) => {
                    out.push(ProxyEgressEvent::TcpData { key, bytes });
                }
                RelayEvent::Closed(key, reset) => {
                    self.tcp.remove(&key);
                    out.push(ProxyEgressEvent::TcpClosed { key, reset });
                }
                RelayEvent::Failed(key, reason) => {
                    self.tcp.remove(&key);
                    out.push(ProxyEgressEvent::Failed { key, reason });
                }
            }
        }
        for forwarder in self.udp.values_mut() {
            for reply in forwarder.drain_replies() {
                let Some((peer, orig_dst)) = self
                    .udp_peers
                    .get(&key_of(reply.local, reply.remote))
                    .copied()
                else {
                    continue;
                };
                let key = flow_key(peer, orig_dst);
                out.push(ProxyEgressEvent::UdpReply {
                    key,
                    payload: reply.payload,
                });
            }
        }
        out
    }
}

fn key_peer(key: FlowKey) -> SocketAddrV4 {
    SocketAddrV4::new(
        std::net::Ipv4Addr::from(key.src_ip.to_be_bytes()),
        key.src_port,
    )
}

fn key_of(peer: SocketAddr, remote: SocketAddr) -> FlowKey {
    match (peer, remote) {
        (SocketAddr::V4(peer), SocketAddr::V4(remote)) => flow_key(peer, remote),
        _ => FlowKey {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            proto: 17,
        },
    }
}

fn flow_key(peer: SocketAddrV4, orig_dst: SocketAddrV4) -> FlowKey {
    FlowKey {
        src_ip: u32::from(*peer.ip()),
        dst_ip: u32::from(*orig_dst.ip()),
        src_port: peer.port(),
        dst_port: orig_dst.port(),
        proto: 17,
    }
}

fn synthetic_udp_packet(key: FlowKey, orig_dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let peer = key_peer(key);
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&peer.ip().octets());
    pkt[16..20].copy_from_slice(&orig_dst.ip().octets());
    pkt[20..22].copy_from_slice(&peer.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&orig_dst.port().to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// §12.3 结构化行的字段：`(kind, cause, detail)`。
///
/// 与 `StreamProxyEgress::log_outbound_unavailable` 拆开是为了先取出 owned 字段，
/// 再以 `&mut self` 更新限频状态（避免与 `registry` 的不可变借用重叠）。
fn outbound_unavailable_fields(slot: &OutboundSlot) -> (String, &'static str, String) {
    match slot {
        OutboundSlot::ProtocolNotWired { kind } => (
            kind.as_str().to_string(),
            "PROTOCOL_NOT_WIRED",
            String::new(),
        ),
        OutboundSlot::Invalid { kind, cause } => (
            kind.as_str().to_string(),
            cause.name(),
            nexus::redact::sanitize(cause.detail()),
        ),
        OutboundSlot::Dialer(dialer) => (
            dialer.kind().as_str().to_string(),
            "UNKNOWN_OUTBOUND",
            String::new(),
        ),
    }
}
