//! TPROXY 前端的生产 `ProxyFlowEgress` 适配器（spec §9.12）。
//!
//! 把 core 的 `FlowKey` 映射为真实代理字节流 / UDP 中继：
//! - TCP：每个 key 一个中继线程，dial 成功后在 accepted stream 与代理之间泵字节；
//! - UDP：复用 `proxy_fwd::udp_relay::UdpForwarder`（SOCKS5 UDP ASSOCIATE /
//!   ss UDP / trojan UDP），按 key 记录 peer/orig_dst，回包只按该表查。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use nexus_projection::egress::FlowKey;
use nexus_projection::transparent::{ProxyEgressEvent, ProxyFlowEgress, TransparentFrontendError};

use crate::proxy_fwd::ProxyDialConfig;

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
    outbounds: HashMap<String, ProxyDialConfig>,
    tcp: HashMap<FlowKey, Sender<RelayCmd>>,
    events_tx: Sender<RelayEvent>,
    events_rx: Receiver<RelayEvent>,
    udp: HashMap<String, crate::proxy_fwd::udp_relay::UdpForwarder>,
    udp_tags: HashMap<FlowKey, String>,
    udp_peers: HashMap<FlowKey, (SocketAddrV4, SocketAddrV4)>,
}

impl StreamProxyEgress {
    /// 从 `proxy.yaml` 构造；没有可拨号出站时返回 `None`。
    #[must_use]
    pub fn from_yaml(proxy_yaml: &str) -> Option<Self> {
        let config = nexus_proxy_config::parse(proxy_yaml).ok()?;
        let mut outbounds = HashMap::new();
        for outbound in &config.outbounds {
            if let Some(dial) = crate::proxy_fwd::dial_config_from_outbound(outbound) {
                outbounds.insert(outbound.tag.clone(), dial);
            }
        }
        if outbounds.is_empty() {
            return None;
        }
        let (events_tx, events_rx) = mpsc::channel();
        Some(Self {
            outbounds,
            tcp: HashMap::new(),
            events_tx,
            events_rx,
            udp: HashMap::new(),
            udp_tags: HashMap::new(),
            udp_peers: HashMap::new(),
        })
    }

    fn spawn_tcp_relay(&mut self, key: FlowKey, config: ProxyDialConfig, target: SocketAddrV4) {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let events_tx = self.events_tx.clone();
        std::thread::Builder::new()
            .name("nexusd-tproxy-relay".to_string())
            .spawn(move || {
                let mut stream = match dial_proxy_stream(&config, target.into()) {
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
        let config = self.outbounds.get(outbound_tag).cloned().ok_or_else(|| {
            TransparentFrontendError::OutboundUnresolved {
                tag: outbound_tag.to_string(),
            }
        })?;
        self.spawn_tcp_relay(key, config, orig_dst);
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
        let config = self
            .outbounds
            .get(&tag)
            .cloned()
            .ok_or_else(|| TransparentFrontendError::OutboundUnresolved { tag: tag.clone() })?;
        let packet = synthetic_udp_packet(key, orig_dst, payload);
        let forwarder = self.udp.entry(tag.clone()).or_insert_with(|| {
            crate::proxy_fwd::udp_relay::UdpForwarder::new(crate::proxy_fwd::legacy_dialer(&config))
        });
        if forwarder.handle_packet(&packet) {
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
            for inbound in forwarder.drain_inbound() {
                let Some(local) = forwarder.lookup_local(&inbound.remote) else {
                    continue;
                };
                let Some((peer, orig_dst)) =
                    self.udp_peers.get(&key_of(local, inbound.remote)).copied()
                else {
                    continue;
                };
                let key = flow_key(peer, orig_dst);
                out.push(ProxyEgressEvent::UdpReply {
                    key,
                    payload: inbound.payload,
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

fn dial_proxy_stream(
    config: &ProxyDialConfig,
    target: SocketAddr,
) -> std::io::Result<Box<dyn crate::proxy_fwd::adapter::TunnelStream>> {
    crate::proxy_fwd::legacy_dialer(config)
        .dial_tcp(target)
        .map_err(|e| std::io::Error::other(e.to_string()))
}
