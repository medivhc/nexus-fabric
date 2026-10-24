//! 透明前端共享组件（TUN 与 TPROXY 共用）。
//!
//! - `decision`：5 元组决策缓存（spec §9.13，TUN 与 TPROXY 共用）。
//! - 本文件：原始目的地传递（spec §9.3）、前端配置/统计（spec §9.12）。
//!
//! 本模块是 delivery core：只接收 driver 传入的 `now_millis`，不读系统时钟，
//! 不接触平台句柄或系统调用（平台 socket 由组合根经 trait/组合注入）。

pub mod decision;
pub mod direct;
pub mod runtime;

use std::io;
use std::net::{SocketAddrV4, TcpStream};

use crate::classifier::DropReason;

/// core 看到的“一条已 accept 的透明 TCP 连接”。
///
/// 不暴露任何平台句柄/系统调用；测试可用内存双工实现。
pub trait TransparentConnection: Send {
    /// 对端地址。
    fn peer(&self) -> SocketAddrV4;
    /// 原始目的地（TPROXY accept 时记录）。
    fn orig_dst(&self) -> SocketAddrV4;
    /// 读取应用字节。
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// 写入应用字节。
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    /// 半关闭写方向。
    fn shutdown(&mut self) -> io::Result<()>;
}

/// 真实 `TcpStream` 的透明连接实现。
pub struct TcpConnection {
    stream: TcpStream,
    peer: SocketAddrV4,
    orig_dst: SocketAddrV4,
}

impl TcpConnection {
    /// 用已 accept 的 stream 与记录的地址构造。
    pub fn new(stream: TcpStream, peer: SocketAddrV4, orig_dst: SocketAddrV4) -> Self {
        Self {
            stream,
            peer,
            orig_dst,
        }
    }

    /// 取回底层 stream。
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl TransparentConnection for TcpConnection {
    fn peer(&self) -> SocketAddrV4 {
        self.peer
    }

    fn orig_dst(&self) -> SocketAddrV4 {
        self.orig_dst
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read as _;
        self.stream.read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        self.stream.write_all(buf)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Write)
    }
}

/// 组合根（nexusd owner 线程）在分类/规则/会话之后给出的出口决定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentDecision {
    /// 直连。
    Direct,
    /// 代理出站（含 fallback 候选）。
    Proxy {
        /// 规则选定的出站 tag。
        outbound: String,
        /// 失败时按序重试的候选。
        fallback: Vec<String>,
    },
    /// 丢弃。
    Drop {
        /// 丢弃原因。
        reason: DropReason,
    },
}

/// 一条已 accept 的透明 TCP 输入。
pub struct TransparentTcpInput {
    /// 连接（真实 socket 或测试替身）。
    pub conn: Box<dyn TransparentConnection>,
    /// accept 的单调毫秒。
    pub accepted_at_millis: u64,
    /// 出口决定。
    pub decision: TransparentDecision,
}

impl std::fmt::Debug for TransparentTcpInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparentTcpInput")
            .field("peer", &self.conn.peer())
            .field("orig_dst", &self.conn.orig_dst())
            .field("accepted_at_millis", &self.accepted_at_millis)
            .field("decision", &self.decision)
            .finish()
    }
}

/// 一条透明 UDP 数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentUdpInput {
    /// 载荷。
    pub payload: Vec<u8>,
    /// 对端。
    pub peer: SocketAddrV4,
    /// 原始目的地。
    pub orig_dst: SocketAddrV4,
    /// 收到的单调毫秒。
    pub received_at_millis: u64,
    /// 出口决定。
    pub decision: TransparentDecision,
}

/// 透明前端结构化错误（spec §8.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentFrontendError {
    /// 原始目的地缺失（契约被违反的防御路径）。
    OrigDstMissing {
        /// 对端。
        peer: SocketAddrV4,
    },
    /// 原始目的地非法。
    OrigDstInvalid {
        /// 原始值。
        raw: String,
    },
    /// 规则引擎不可用。
    RuleEngineUnavailable {
        /// 原因。
        reason: String,
    },
    /// 规则未命中。
    RuleNoMatch {
        /// 目标。
        target: String,
    },
    /// 规则选中的出站 tag 不存在。
    OutboundUnresolved {
        /// 出站 tag。
        tag: String,
    },
    /// 会话建连失败。
    SessionEstablishFailed {
        /// 流描述。
        flow: String,
        /// 原因。
        reason: String,
    },
    /// TCP 直连拨号失败。
    DirectDialFailed {
        /// 目的地。
        dst: SocketAddrV4,
        /// 原因。
        reason: String,
    },
    /// UDP 直发失败。
    DirectSendFailed {
        /// 目的地。
        dst: SocketAddrV4,
        /// 原因。
        reason: String,
    },
    /// 非 TCP/UDP 协议。
    UnsupportedProtocol {
        /// IP 协议号。
        ip_proto: u8,
    },
    /// UDP 流表达容量（LRU 淘汰，不拒绝新流）。
    UdpTableFull {
        /// 容量。
        capacity: usize,
    },
    /// 并发 TCP 连接达上限。
    TcpConnLimit {
        /// 上限。
        limit: usize,
    },
    /// UDP 数据报过大。
    PayloadTooLarge {
        /// 实际长度。
        len: usize,
        /// 上限。
        max: usize,
    },
}

impl std::fmt::Display for TransparentFrontendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OrigDstMissing { peer } => {
                write!(f, "TRANSPARENT_ORIG_DST_MISSING: peer={peer}")
            }
            Self::OrigDstInvalid { raw } => {
                write!(f, "TRANSPARENT_ORIG_DST_INVALID: raw={raw}")
            }
            Self::RuleEngineUnavailable { reason } => {
                write!(f, "TRANSPARENT_RULE_ENGINE_UNAVAILABLE: reason={reason}")
            }
            Self::RuleNoMatch { target } => {
                write!(f, "TRANSPARENT_RULE_NO_MATCH: target={target}")
            }
            Self::OutboundUnresolved { tag } => {
                write!(f, "TRANSPARENT_OUTBOUND_UNRESOLVED: tag={tag}")
            }
            Self::SessionEstablishFailed { flow, reason } => {
                write!(f, "TRANSPARENT_SESSION_FAILED: flow={flow} reason={reason}")
            }
            Self::DirectDialFailed { dst, reason } => {
                write!(
                    f,
                    "TRANSPARENT_DIRECT_DIAL_FAILED: dst={dst} reason={reason}"
                )
            }
            Self::DirectSendFailed { dst, reason } => {
                write!(
                    f,
                    "TRANSPARENT_DIRECT_SEND_FAILED: dst={dst} reason={reason}"
                )
            }
            Self::UnsupportedProtocol { ip_proto } => {
                write!(f, "TRANSPARENT_UNSUPPORTED_PROTOCOL: ip_proto={ip_proto}")
            }
            Self::UdpTableFull { capacity } => {
                write!(f, "TRANSPARENT_UDP_TABLE_FULL: capacity={capacity}")
            }
            Self::TcpConnLimit { limit } => {
                write!(f, "TRANSPARENT_TCP_CONN_LIMIT: limit={limit}")
            }
            Self::PayloadTooLarge { len, max } => {
                write!(f, "TRANSPARENT_PAYLOAD_TOO_LARGE: len={len} max={max}")
            }
        }
    }
}

impl std::error::Error for TransparentFrontendError {}

/// 路径失败策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFailurePolicy {
    /// 阻断（不直连）。
    Block,
    /// 回落候选。
    Fallback,
}

/// 前端配置（默认值见 spec §9.12/§11.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentConfig {
    /// 内部 MTU（与 TUN 设备 MTU 不是同一参数）。
    pub mtu: usize,
    /// TCP 空闲超时。
    pub tcp_idle: std::time::Duration,
    /// UDP 空闲超时。
    pub udp_idle: std::time::Duration,
    /// UDP 流表容量。
    pub udp_table_capacity: usize,
    /// 并发 TCP 连接上限。
    pub max_tcp_conns: usize,
    /// 路径失败策略。
    pub on_path_failure: PathFailurePolicy,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            mtu: 1400,
            tcp_idle: std::time::Duration::from_secs(300),
            udp_idle: std::time::Duration::from_secs(60),
            udp_table_capacity: 8192,
            max_tcp_conns: 4096,
            on_path_failure: PathFailurePolicy::Block,
        }
    }
}

/// 前端依赖（组合根注入）。
pub struct TransparentDeps {
    /// 代理出口适配器；`None` 表示无代理配置（Proxy 决策报错/降级）。
    pub proxy_egress: Option<Box<dyn ProxyFlowEgress>>,
    /// Direct 真转发出口。
    pub direct: direct::DirectEgress,
    /// 前端配置。
    pub config: TransparentConfig,
}

/// 前端计数器（counter；禁止 per-packet 日志）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransparentStats {
    /// accept 的 TCP 连接数。
    pub tcp_accepted: u64,
    /// 拒绝的 TCP 连接数。
    pub tcp_rejected: u64,
    /// 关闭的 TCP 连接数。
    pub tcp_closed: u64,
    /// 当前活跃 TCP 连接数。
    pub tcp_active: u64,
    /// UDP 数据报数。
    pub udp_datagrams: u64,
    /// 丢弃的 UDP 数据报数。
    pub udp_dropped: u64,
    /// UDP 表淘汰数。
    pub udp_table_evicted: u64,
    /// UDP 回包失败数。
    pub udp_reply_failed: u64,
    /// Direct TCP 拨号成功数。
    pub direct_tcp_dial_ok: u64,
    /// Direct TCP 拨号失败数。
    pub direct_tcp_dial_failed: u64,
    /// Direct UDP 发送数。
    pub direct_udp_sent: u64,
    /// Direct UDP 发送失败数。
    pub direct_udp_failed: u64,
    /// 不支持协议丢弃数。
    pub direct_dropped_unsupported: u64,
    /// 上游失败数。
    pub upstream_failed: u64,
    /// 域名未命中数。
    pub domain_miss: u64,
}

/// 前端输出事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentOutput {
    /// TCP 流关闭（用于计数与 teardown）。
    FlowClosed {
        /// 5 元组。
        key: crate::egress::FlowKey,
        /// 是否 RST 关闭。
        reset: bool,
    },
    /// UDP 回包（由组合根经原 socket 发出）。
    UdpReply {
        /// 原始目的地。
        orig_dst: SocketAddrV4,
        /// 对端。
        peer: SocketAddrV4,
        /// 载荷。
        payload: Vec<u8>,
    },
}

/// 代理出口适配器（生产实现是 `apps/nexusd` 的 `ProxyEngine` 适配器）。
pub trait ProxyFlowEgress: Send {
    /// 打开一条代理 TCP 流。
    fn open_tcp(
        &mut self,
        key: crate::egress::FlowKey,
        orig_dst: SocketAddrV4,
        outbound_tag: &str,
    ) -> Result<(), TransparentFrontendError>;
    /// 写入代理 TCP 流。
    fn write_tcp(
        &mut self,
        key: &crate::egress::FlowKey,
        bytes: &[u8],
    ) -> Result<(), TransparentFrontendError>;
    /// 关闭代理 TCP 流。
    fn close_tcp(&mut self, key: &crate::egress::FlowKey);
    /// 发送代理 UDP 数据报。
    fn send_udp(
        &mut self,
        key: crate::egress::FlowKey,
        orig_dst: SocketAddrV4,
        payload: &[u8],
    ) -> Result<(), TransparentFrontendError>;
    /// 取出异步事件。
    fn poll(&mut self) -> Vec<ProxyEgressEvent>;
}

/// 代理出口异步事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEgressEvent {
    /// 代理侧下行字节。
    TcpData {
        /// 5 元组。
        key: crate::egress::FlowKey,
        /// 字节。
        bytes: Vec<u8>,
    },
    /// 代理流关闭。
    TcpClosed {
        /// 5 元组。
        key: crate::egress::FlowKey,
        /// 是否 RST。
        reset: bool,
    },
    /// 代理 UDP 回包。
    UdpReply {
        /// 5 元组。
        key: crate::egress::FlowKey,
        /// 载荷。
        payload: Vec<u8>,
    },
    /// 失败。
    Failed {
        /// 5 元组。
        key: crate::egress::FlowKey,
        /// 原因。
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    /// 内存双工连接：写入进入 peer 可见队列，读取来自注入队列。
    struct MemoryConnection {
        peer: SocketAddrV4,
        orig_dst: SocketAddrV4,
        inbound: VecDeque<u8>,
        outbound: Vec<u8>,
        shutdown: bool,
    }

    impl MemoryConnection {
        fn new(peer: [u8; 4], orig_dst: [u8; 4], inbound: &[u8]) -> Self {
            Self {
                peer: SocketAddrV4::new(Ipv4Addr::from(peer), 12345),
                orig_dst: SocketAddrV4::new(Ipv4Addr::from(orig_dst), 443),
                inbound: inbound.iter().copied().collect(),
                outbound: Vec::new(),
                shutdown: false,
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

        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.inbound.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.inbound.pop_front().expect("checked len");
            }
            Ok(n)
        }

        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.outbound.extend_from_slice(buf);
            Ok(())
        }

        fn shutdown(&mut self) -> io::Result<()> {
            self.shutdown = true;
            Ok(())
        }
    }

    #[test]
    fn transparent_connection_memory_duplex_roundtrip() {
        let mut conn = MemoryConnection::new([10, 0, 0, 2], [93, 184, 216, 34], b"hello");
        let mut buf = [0u8; 8];
        assert_eq!(conn.read(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(conn.read(&mut buf).unwrap(), 0);
        conn.write_all(b"world").unwrap();
        conn.shutdown().unwrap();
        assert_eq!(conn.outbound, b"world");
        assert!(conn.shutdown);
        assert_eq!(conn.peer().port(), 12345);
        assert_eq!(conn.orig_dst().port(), 443);
    }

    #[test]
    fn transparent_frontend_error_display_keeps_all_fields() {
        let err = TransparentFrontendError::DirectDialFailed {
            dst: SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443),
            reason: "timeout".to_string(),
        };
        let text = err.to_string();
        assert!(text.contains("1.2.3.4:443"));
        assert!(text.contains("timeout"));
        let err = TransparentFrontendError::PayloadTooLarge {
            len: 70_000,
            max: 65_507,
        };
        assert!(err.to_string().contains("70000"));
        assert!(err.to_string().contains("65507"));
    }

    #[test]
    fn transparent_config_defaults_match_spec() {
        let config = TransparentConfig::default();
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.tcp_idle, std::time::Duration::from_secs(300));
        assert_eq!(config.udp_idle, std::time::Duration::from_secs(60));
        assert_eq!(config.udp_table_capacity, 8192);
        assert_eq!(config.max_tcp_conns, 4096);
        assert_eq!(config.on_path_failure, PathFailurePolicy::Block);
    }
}
