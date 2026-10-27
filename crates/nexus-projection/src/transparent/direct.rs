//! Direct 真转发原语（spec §9.9）。
//!
//! `DirectEgress` 供透明前端（TPROXY）按 5 元组使用；`DirectTcpRelay` 供 TUN
//! 侧按 smoltcp `stream_id` 使用。两者只持有真实 socket，不做规则/会话语义。

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddrV4, TcpStream, UdpSocket};
use std::time::Duration;

use crate::egress::FlowKey;

/// Direct 转发结构化错误（spec §8.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectForwardError {
    /// 非 TCP/UDP 或分片包。
    UnsupportedProtocol {
        /// IP 协议号。
        ip_proto: u8,
    },
    /// TCP 拨号失败。
    DialFailed {
        /// 目的地。
        dst: SocketAddrV4,
        /// 原因。
        reason: String,
    },
    /// UDP 发送失败。
    SendFailed {
        /// 目的地。
        dst: SocketAddrV4,
        /// 原因。
        reason: String,
    },
    /// 无法创建 socket。
    SocketUnavailable {
        /// 原因。
        reason: String,
    },
}

impl std::fmt::Display for DirectForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProtocol { ip_proto } => {
                write!(f, "DIRECT_UNSUPPORTED_PROTOCOL: ip_proto={ip_proto}")
            }
            Self::DialFailed { dst, reason } => {
                write!(f, "DIRECT_DIAL_FAILED: dst={dst} reason={reason}")
            }
            Self::SendFailed { dst, reason } => {
                write!(f, "DIRECT_SEND_FAILED: dst={dst} reason={reason}")
            }
            Self::SocketUnavailable { reason } => {
                write!(f, "DIRECT_SOCKET_UNAVAILABLE: reason={reason}")
            }
        }
    }
}

impl std::error::Error for DirectForwardError {}

/// Direct 转发配置（默认值见 spec §11.1）。
#[derive(Debug, Clone)]
pub struct DirectEgressConfig {
    /// TCP 拨号超时。
    pub dial_timeout: Duration,
    /// UDP 流空闲老化。
    pub udp_idle: Duration,
    /// TCP 并发流上限。
    pub max_tcp_flows: usize,
    /// UDP 并发流上限。
    pub max_udp_flows: usize,
}

impl Default for DirectEgressConfig {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(10),
            udp_idle: Duration::from_secs(60),
            max_tcp_flows: 4096,
            max_udp_flows: 8192,
        }
    }
}

/// Direct 计数器。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectEgressStats {
    /// TCP 拨号成功数。
    pub tcp_dialed: u64,
    /// TCP 拨号失败数。
    pub tcp_dial_failed: u64,
    /// TCP 已发送字节。
    pub tcp_bytes_sent: u64,
    /// TCP 已接收字节。
    pub tcp_bytes_received: u64,
    /// UDP 发送数。
    pub udp_sent: u64,
    /// UDP 发送失败数。
    pub udp_send_failed: u64,
    /// UDP 回包数。
    pub udp_replies: u64,
    /// 不支持协议丢弃数。
    pub unsupported: u64,
}

/// Direct 异步事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectEgressEvent {
    /// TCP 下行字节。
    TcpData {
        /// 5 元组。
        key: FlowKey,
        /// 字节。
        bytes: Vec<u8>,
    },
    /// TCP 关闭。
    TcpClosed {
        /// 5 元组。
        key: FlowKey,
        /// 是否 RST。
        reset: bool,
    },
    /// UDP 回包。
    UdpReply {
        /// 5 元组。
        key: FlowKey,
        /// 载荷。
        payload: Vec<u8>,
    },
    /// 失败。
    Failed {
        /// 5 元组。
        key: FlowKey,
        /// 错误。
        error: DirectForwardError,
    },
}

struct TcpEntry {
    stream: TcpStream,
    last_seen_millis: u64,
}

struct UdpEntry {
    peer: SocketAddrV4,
    last_seen_millis: u64,
}

/// 按 5 元组索引的 Direct 出口。
pub struct DirectEgress {
    config: DirectEgressConfig,
    tcp: HashMap<FlowKey, TcpEntry>,
    udp_socket: Option<UdpSocket>,
    udp: HashMap<FlowKey, UdpEntry>,
    /// 回包源地址 → 流键（单 socket 复用）。
    udp_by_peer: HashMap<SocketAddrV4, FlowKey>,
    stats: DirectEgressStats,
}

impl DirectEgress {
    /// 创建出口；UDP socket 延迟到首次发送时创建。
    ///
    /// # Errors
    ///
    /// 当前实现不会失败（保留签名以匹配组合根的构造期错误处理）。
    pub fn new(config: DirectEgressConfig) -> std::io::Result<Self> {
        Ok(Self {
            config,
            tcp: HashMap::new(),
            udp_socket: None,
            udp: HashMap::new(),
            udp_by_peer: HashMap::new(),
            stats: DirectEgressStats::default(),
        })
    }

    /// 拨号一条 Direct TCP 流。
    ///
    /// # Errors
    ///
    /// 连接超时/拒绝 → `DialFailed`；流表/无法创建 socket → `SocketUnavailable`。
    pub fn dial_tcp(&mut self, key: FlowKey, dst: SocketAddrV4) -> Result<(), DirectForwardError> {
        if self.tcp.len() >= self.config.max_tcp_flows {
            return Err(DirectForwardError::SocketUnavailable {
                reason: format!("tcp flow limit {}", self.config.max_tcp_flows),
            });
        }
        match TcpStream::connect_timeout(&dst.into(), self.config.dial_timeout) {
            Ok(stream) => {
                if let Err(e) = stream.set_nonblocking(true) {
                    self.stats.tcp_dial_failed += 1;
                    return Err(DirectForwardError::DialFailed {
                        dst,
                        reason: e.to_string(),
                    });
                }
                self.stats.tcp_dialed += 1;
                self.tcp.insert(
                    key,
                    TcpEntry {
                        stream,
                        last_seen_millis: 0,
                    },
                );
                Ok(())
            }
            Err(e) => {
                self.stats.tcp_dial_failed += 1;
                Err(DirectForwardError::DialFailed {
                    dst,
                    reason: e.to_string(),
                })
            }
        }
    }

    /// 写入 Direct TCP 流。
    ///
    /// # Errors
    ///
    /// 流不存在 → `SocketUnavailable`；写失败 → `SendFailed`。
    pub fn write_tcp(&mut self, key: &FlowKey, bytes: &[u8]) -> Result<usize, DirectForwardError> {
        let entry = self
            .tcp
            .get_mut(key)
            .ok_or_else(|| DirectForwardError::SocketUnavailable {
                reason: "tcp flow not open".to_string(),
            })?;
        match entry.stream.write(bytes) {
            Ok(n) => {
                self.stats.tcp_bytes_sent += n as u64;
                entry.last_seen_millis = 0;
                Ok(n)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(DirectForwardError::SendFailed {
                dst: entry
                    .stream
                    .peer_addr()
                    .ok()
                    .and_then(|a| match a {
                        std::net::SocketAddr::V4(v4) => Some(v4),
                        std::net::SocketAddr::V6(_) => None,
                    })
                    .unwrap_or_else(|| SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)),
                reason: e.to_string(),
            }),
        }
    }

    /// 关闭（或重置）一条 Direct TCP 流。
    pub fn close(&mut self, key: &FlowKey, reset: bool) {
        if let Some(entry) = self.tcp.remove(key) {
            let _ = reset;
            let _ = entry.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// 发送一条 Direct UDP 数据报（共享单 socket）。
    ///
    /// # Errors
    ///
    /// 流表满/无法创建 socket → `SocketUnavailable`；发送失败 → `SendFailed`。
    pub fn send_udp(
        &mut self,
        key: FlowKey,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> Result<usize, DirectForwardError> {
        if !self.udp.contains_key(&key) && self.udp.len() >= self.config.max_udp_flows {
            return Err(DirectForwardError::SocketUnavailable {
                reason: format!("udp flow limit {}", self.config.max_udp_flows),
            });
        }
        if self.udp_socket.is_none() {
            let socket = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| {
                DirectForwardError::SocketUnavailable {
                    reason: e.to_string(),
                }
            })?;
            socket
                .set_nonblocking(true)
                .map_err(|e| DirectForwardError::SocketUnavailable {
                    reason: e.to_string(),
                })?;
            self.udp_socket = Some(socket);
        }
        let socket = self.udp_socket.as_ref().expect("created above");
        match socket.send_to(payload, dst) {
            Ok(n) => {
                self.stats.udp_sent += 1;
                self.udp.insert(
                    key,
                    UdpEntry {
                        peer: dst,
                        last_seen_millis: 0,
                    },
                );
                self.udp_by_peer.insert(dst, key);
                Ok(n)
            }
            Err(e) => {
                self.stats.udp_send_failed += 1;
                Err(DirectForwardError::SendFailed {
                    dst,
                    reason: e.to_string(),
                })
            }
        }
    }

    /// 记录一个不支持协议（ICMP/分片/非 TCP-UDP）并计数。
    pub fn record_unsupported(&mut self, ip_proto: u8) -> DirectForwardError {
        self.stats.unsupported += 1;
        DirectForwardError::UnsupportedProtocol { ip_proto }
    }

    /// 驱动非阻塞读与 UDP 空闲老化。
    pub fn poll(&mut self, now_millis: u64) -> Vec<DirectEgressEvent> {
        let mut events = Vec::new();
        // TCP：读取所有可读字节。
        let keys: Vec<FlowKey> = self.tcp.keys().copied().collect();
        for key in keys {
            let Some(entry) = self.tcp.get_mut(&key) else {
                continue;
            };
            loop {
                let mut buf = [0u8; 16 * 1024];
                match entry.stream.read(&mut buf) {
                    Ok(0) => {
                        self.tcp.remove(&key);
                        events.push(DirectEgressEvent::TcpClosed { key, reset: false });
                        break;
                    }
                    Ok(n) => {
                        self.stats.tcp_bytes_received += n as u64;
                        events.push(DirectEgressEvent::TcpData {
                            key,
                            bytes: buf[..n].to_vec(),
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        let error = DirectForwardError::SendFailed {
                            dst: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                            reason: e.to_string(),
                        };
                        self.tcp.remove(&key);
                        events.push(DirectEgressEvent::Failed { key, error });
                        break;
                    }
                }
            }
        }
        // UDP：读取回包。
        if let Some(socket) = self.udp_socket.as_ref() {
            loop {
                let mut buf = [0u8; 65_507];
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let peer = match from {
                            std::net::SocketAddr::V4(v4) => v4,
                            std::net::SocketAddr::V6(_) => continue,
                        };
                        let Some(key) = self.udp_by_peer.get(&peer).copied() else {
                            continue;
                        };
                        if let Some(entry) = self.udp.get_mut(&key) {
                            entry.last_seen_millis = now_millis;
                        }
                        self.stats.udp_replies += 1;
                        events.push(DirectEgressEvent::UdpReply {
                            key,
                            payload: buf[..n].to_vec(),
                        });
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        // UDP 空闲淘汰。
        let idle_ms = u64::try_from(self.config.udp_idle.as_millis()).unwrap_or(u64::MAX);
        let expired: Vec<FlowKey> = self
            .udp
            .iter()
            .filter(|(_, entry)| now_millis.saturating_sub(entry.last_seen_millis) >= idle_ms)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            if let Some(entry) = self.udp.remove(&key) {
                self.udp_by_peer.remove(&entry.peer);
            }
        }
        events
    }

    /// 当前 UDP socket 数（0/1；证明多流共享单 socket）。
    pub fn udp_socket_count(&self) -> usize {
        usize::from(self.udp_socket.is_some())
    }

    /// 计数器快照。
    pub fn stats(&self) -> DirectEgressStats {
        self.stats.clone()
    }
}

/// Direct TCP 中继（按 smoltcp `stream_id` 索引；供 TUN 侧使用）。
pub struct DirectTcpRelay {
    config: DirectEgressConfig,
    streams: HashMap<u32, TcpStream>,
}

/// Direct TCP 中继事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectTcpEvent {
    /// 下行字节。
    Data {
        /// smoltcp stream id。
        stream_id: u32,
        /// 字节。
        bytes: Vec<u8>,
    },
    /// 关闭。
    Closed {
        /// smoltcp stream id。
        stream_id: u32,
        /// 是否 RST。
        reset: bool,
    },
    /// 失败。
    Failed {
        /// smoltcp stream id。
        stream_id: u32,
        /// 错误。
        error: DirectForwardError,
    },
}

impl DirectTcpRelay {
    /// 创建中继（不建立连接）。
    pub fn new(config: DirectEgressConfig) -> Self {
        Self {
            config,
            streams: HashMap::new(),
        }
    }

    /// 为 stream_id 拨号。
    ///
    /// # Errors
    ///
    /// 拨号失败 → `DialFailed`；流表满 → `SocketUnavailable`。
    pub fn open(&mut self, stream_id: u32, dst: SocketAddrV4) -> Result<(), DirectForwardError> {
        if self.streams.len() >= self.config.max_tcp_flows {
            return Err(DirectForwardError::SocketUnavailable {
                reason: format!("tcp flow limit {}", self.config.max_tcp_flows),
            });
        }
        let stream =
            TcpStream::connect_timeout(&dst.into(), self.config.dial_timeout).map_err(|e| {
                DirectForwardError::DialFailed {
                    dst,
                    reason: e.to_string(),
                }
            })?;
        stream
            .set_nonblocking(true)
            .map_err(|e| DirectForwardError::DialFailed {
                dst,
                reason: e.to_string(),
            })?;
        self.streams.insert(stream_id, stream);
        Ok(())
    }

    /// 写入。
    ///
    /// # Errors
    ///
    /// 流不存在 → `SocketUnavailable`；写失败 → `SendFailed`。
    pub fn write(&mut self, stream_id: u32, bytes: &[u8]) -> Result<usize, DirectForwardError> {
        let stream = self.streams.get_mut(&stream_id).ok_or_else(|| {
            DirectForwardError::SocketUnavailable {
                reason: "tcp flow not open".to_string(),
            }
        })?;
        match stream.write(bytes) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(DirectForwardError::SendFailed {
                dst: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                reason: e.to_string(),
            }),
        }
    }

    /// 关闭。
    pub fn close(&mut self, stream_id: u32, reset: bool) {
        if let Some(stream) = self.streams.remove(&stream_id) {
            let _ = reset;
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// 驱动非阻塞读。
    pub fn poll(&mut self) -> Vec<DirectTcpEvent> {
        let mut events = Vec::new();
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for stream_id in ids {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            loop {
                let mut buf = [0u8; 16 * 1024];
                match stream.read(&mut buf) {
                    Ok(0) => {
                        self.streams.remove(&stream_id);
                        events.push(DirectTcpEvent::Closed {
                            stream_id,
                            reset: false,
                        });
                        break;
                    }
                    Ok(n) => events.push(DirectTcpEvent::Data {
                        stream_id,
                        bytes: buf[..n].to_vec(),
                    }),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        let error = DirectForwardError::SendFailed {
                            dst: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                            reason: e.to_string(),
                        };
                        self.streams.remove(&stream_id);
                        events.push(DirectTcpEvent::Failed { stream_id, error });
                        break;
                    }
                }
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn key(src_port: u16) -> FlowKey {
        FlowKey {
            src_ip: u32::from_be_bytes([192, 168, 1, 5]),
            dst_ip: u32::from_be_bytes([127, 0, 0, 1]),
            src_port,
            dst_port: 9,
            proto: 6,
        }
    }

    fn echo_server() -> (SocketAddrV4, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("expected v4"),
        };
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                    let _ = stream.flush();
                }
            }
        });
        (addr, handle)
    }

    fn drain_tcp_until(
        egress: &mut DirectEgress,
        deadline_ms: u64,
        want: impl Fn(&DirectEgressEvent) -> bool,
    ) -> Option<DirectEgressEvent> {
        for t in 0..deadline_ms {
            for event in egress.poll(t) {
                if want(&event) {
                    return Some(event);
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        None
    }

    #[test]
    fn direct_egress_tcp_local_echo_roundtrip() {
        let (addr, handle) = echo_server();
        let mut egress = DirectEgress::new(DirectEgressConfig::default()).unwrap();
        let k = key(12345);
        egress.dial_tcp(k, addr).expect("dial");
        egress.write_tcp(&k, b"ping").expect("write");
        let event = drain_tcp_until(&mut egress, 2_000, |e| {
            matches!(e, DirectEgressEvent::TcpData { .. })
        })
        .expect("echo data");
        match event {
            DirectEgressEvent::TcpData { key: got, bytes } => {
                assert_eq!(got, k);
                assert_eq!(bytes, b"ping");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(egress.stats().tcp_dialed, 1);
        assert_eq!(egress.stats().tcp_bytes_sent, 4);
        assert_eq!(egress.stats().tcp_bytes_received, 4);
        egress.close(&k, false);
        handle.join().unwrap();
    }

    #[test]
    fn direct_egress_udp_local_echo_roundtrip() {
        let server = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
        let addr = match server.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("expected v4"),
        };
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = server.recv_from(&mut buf) {
                let _ = server.send_to(&buf[..n], from);
            }
        });
        let mut egress = DirectEgress::new(DirectEgressConfig::default()).unwrap();
        let k = key(53000);
        egress.send_udp(k, addr, b"pong").expect("send");
        let event = drain_tcp_until(&mut egress, 2_000, |e| {
            matches!(e, DirectEgressEvent::UdpReply { .. })
        })
        .expect("udp reply");
        match event {
            DirectEgressEvent::UdpReply { key: got, payload } => {
                assert_eq!(got, k);
                assert_eq!(payload, b"pong");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(egress.stats().udp_sent, 1);
        assert_eq!(egress.stats().udp_replies, 1);
        handle.join().unwrap();
    }

    #[test]
    fn direct_egress_unsupported_protocol_counted() {
        let mut egress = DirectEgress::new(DirectEgressConfig::default()).unwrap();
        let err = egress.record_unsupported(1); // ICMP
        assert_eq!(err, DirectForwardError::UnsupportedProtocol { ip_proto: 1 });
        let err = egress.record_unsupported(6); // 分片由调用方按分片位判定，此处同计数
        assert_eq!(err, DirectForwardError::UnsupportedProtocol { ip_proto: 6 });
        assert_eq!(egress.stats().unsupported, 2);
    }

    #[test]
    fn direct_egress_dial_failure_reports_dial_failed() {
        // 绑定后立即释放端口，连接应被拒绝。
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => panic!("expected v4"),
        };
        drop(listener);
        let mut egress = DirectEgress::new(DirectEgressConfig {
            dial_timeout: Duration::from_millis(200),
            ..DirectEgressConfig::default()
        })
        .unwrap();
        let err = egress.dial_tcp(key(1), addr).expect_err("dial must fail");
        assert!(matches!(err, DirectForwardError::DialFailed { .. }));
        assert_eq!(egress.stats().tcp_dial_failed, 1);
    }

    #[test]
    fn direct_tcp_relay_roundtrip() {
        let (addr, handle) = echo_server();
        let mut relay = DirectTcpRelay::new(DirectEgressConfig::default());
        relay.open(7, addr).expect("open");
        relay.write(7, b"relay").expect("write");
        let mut got = Vec::new();
        for _ in 0..2_000 {
            for event in relay.poll() {
                if let DirectTcpEvent::Data { bytes, .. } = event {
                    got.extend_from_slice(&bytes);
                }
            }
            if got.len() >= 5 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(got, b"relay");
        relay.close(7, false);
        handle.join().unwrap();
    }
}
