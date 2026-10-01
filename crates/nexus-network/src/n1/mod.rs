//! N1 Universal Connectivity 装配：portable core。
//!
//! 本模块实现 v9 闭环中的 `nexus-network Runtime` 一段
//! （`Create Network Session → Connectivity Establishment → Transport →
//! VirtualPacketInterface`），只做 VirtualPacketInterface 单播 IP 互通（M1）。
//!
//! 依赖反转（AGENTS.md §12）：本模块**不**编译依赖 `nexus-fabric` /
//! `nexus-path` / `nexus-discovery` / `nexus-platform-linux`，只通过本文件
//! 定义的注入 trait 消费它们；具体实现由 Composition Root 装配
//! （MODULE.md Deletion Test：注入 trait 三件）。
//!
//! 术语注意（M4）：这里的"会话/连接"是"Session 中实际建立的传输实例"
//! （v9 §9），不是白皮书 Session（某次实际资源使用的上下文）的替代。

pub mod config;
pub mod link;
pub mod pump;
pub mod session;

use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

/// 节点身份：ed25519 公钥 32 字节（对标 fabric `PeerId`）。
///
/// portable core 不能命名 fabric 类型，故自建；fabric `PeerId` ↔ `N1PeerId`
/// 的转换是 Composition Root 的职责（D2 评审）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct N1PeerId(pub [u8; 32]);

impl N1PeerId {
    /// 小写 hex 编码（配置/日志用）。
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('?'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('?'));
        }
        s
    }

    /// 解析 64 位 hex（大小写均可）；长度或字符非法时返回 `InvalidConfig`。
    pub fn from_hex(s: &str) -> Result<Self, N1Error> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(N1Error::InvalidConfig(format!(
                "peer id must be 64 hex chars, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in bytes.chunks(2).enumerate() {
            let hi = hex_val(chunk[0]).ok_or_else(|| {
                N1Error::InvalidConfig(format!("invalid hex char in peer id: {s}"))
            })?;
            let lo = hex_val(chunk[1]).ok_or_else(|| {
                N1Error::InvalidConfig(format!("invalid hex char in peer id: {s}"))
            })?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for N1PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 日志中只打前 8 hex，避免刷屏；完整身份走 to_hex。
        write!(f, "N1PeerId({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for N1PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// N1 结构化错误：保留可诊断原因，支持 Retry/Fallback/Abort/Escalate 判定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N1Error {
    /// 底层传输失败（携带原因，不以日志文本代替类型）。
    Transport(String),
    /// 对端未知（无配置、无发现结果）。
    PeerUnknown,
    /// 连接/监听已关闭。
    Closed,
    /// 操作超时（心跳超时、握手超时等）。
    Timeout,
    /// 数据报超限（>1200B，调用方计数后丢弃）。
    OversizeDatagram(usize),
    /// 配置非法。
    InvalidConfig(String),
}

impl fmt::Display for N1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "n1 transport failure: {e}"),
            Self::PeerUnknown => write!(f, "n1 peer unknown"),
            Self::Closed => write!(f, "n1 connection closed"),
            Self::Timeout => write!(f, "n1 operation timed out"),
            Self::OversizeDatagram(n) => write!(f, "n1 datagram too large: {n} bytes"),
            Self::InvalidConfig(e) => write!(f, "n1 invalid config: {e}"),
        }
    }
}

impl std::error::Error for N1Error {}

/// 单个对端连接（对标 `FabricConn` 的子集；Composition Root 为 `FabricConn` 实现）。
///
/// `Send + Sync` 是必需的：连接被包泵双线程 + Link 观测器共享（D2 评审）。
pub trait N1Connection: Send + Sync {
    /// 发送不可靠数据报（≤1200B；超限返回 `OversizeDatagram`，调用方计数后丢弃）。
    ///
    /// 注意：fabric driver 吞掉了 UDP `send_to` 的 socket 错误，本方法返回 `Ok`
    /// 不代表包真的发出——"socket 错误"不能作为 Link 观测触发器（D3 评审）。
    fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error>;
    /// 接收不可靠数据报（阻塞；连接关闭时返回 `Closed`）。
    fn recv_datagram(&self) -> Result<Vec<u8>, N1Error>;
    /// 打开可靠双向 keepalive 流（M2：Link 保活走可靠双向流）。
    fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error>;
    /// 接受对端发起的可靠双向流（阻塞；keepalive 响应器用）。
    fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error>;
    /// 重绑底层 UDP socket（主动迁移）；**不改变 connection id**（M4 冻结语义）。
    fn rebind(&self) -> Result<(), N1Error>;
    /// 连接标识（用于断言 `id_unchanged`）。
    fn connection_id(&self) -> u64;
    /// 对端身份。
    fn peer(&self) -> N1PeerId;
    /// 关闭连接；阻塞中的 `recv_datagram` / `accept_keepalive` / keepalive 读
    /// 必须随之返回 `Closed`（结构化并发的取消路径，AGENTS.md §13）。
    fn close(&self);
}

/// keepalive 流的 portable I/O 一半：Composition Root 在 `N1Connection::open_keepalive`
/// / `accept_keepalive` 中以 `(SendStream, RecvStream)` 实现本 trait，
/// portable core 只经此 trait 收发心跳（不暴露 fabric 流类型，D2 评审）。
pub trait N1KeepaliveIo: Send {
    /// 写完 `buf` 全量（阻塞）。
    fn write_all(&mut self, buf: &[u8]) -> Result<(), N1Error>;
    /// 读满 `buf`（阻塞；对端关闭/连接关闭时返回 `Closed`）。
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), N1Error>;
    /// 半关闭写端。
    fn finish(&mut self) -> Result<(), N1Error>;
}

/// 可靠双向 keepalive 流（M2）；封装 `(write, read)`，避免暴露 fabric 流类型。
pub struct N1KeepaliveStream {
    inner: Box<dyn N1KeepaliveIo>,
}

impl N1KeepaliveStream {
    /// Composition Root 用：把具体流实现装入 portable 壳。
    pub fn new(inner: Box<dyn N1KeepaliveIo>) -> Self {
        Self { inner }
    }
}

impl Deref for N1KeepaliveStream {
    type Target = dyn N1KeepaliveIo;
    fn deref(&self) -> &Self::Target {
        &*self.inner
    }
}

impl DerefMut for N1KeepaliveStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.inner
    }
}

/// 建连（对标 `FallbackChain` + `FabricConn::connect_with_transport`；
/// Composition Root 实现）。
pub trait N1Dialer: Send + Sync {
    /// 按 `addrs` 优先级拨号，返回该对端的唯一连接。
    fn dial(&self, peer: &N1PeerId, addrs: &[SocketAddr])
    -> Result<Box<dyn N1Connection>, N1Error>;
}

/// 入向（对标 `FabricListener`；Composition Root 实现）。
pub trait N1Listener: Send {
    /// 阻塞接受一个入向连接，返回对端身份与连接。
    fn accept(&self) -> Result<(N1PeerId, Box<dyn N1Connection>), N1Error>;
}

/// 发现（对标 `AggregateDiscovery`；Composition Root 实现）。
pub trait N1Discovery: Send + Sync {
    /// 解析对端的 locator 候选（优先级已由实现排好）。
    fn resolve(&self, peer: &N1PeerId) -> Result<Vec<SocketAddr>, N1Error>;
}

/// 结构化事件上报（Session Runtime 反馈 Planner 的载体；
/// 本期 Composition Root 落盘/日志）。
pub trait N1EventSink: Send + Sync {
    /// 发送结构化事件；实现不得阻塞调用方关键路径（建议落盘/打日志）。
    fn emit(&self, event: N1Event);
}

/// N1 结构化事件（M5）：携带 `peer_id`/`connection_id`，不以日志文本代替错误类型。
#[derive(Debug, Clone)]
pub struct N1Event {
    /// 事件所属对端。
    pub peer: N1PeerId,
    /// 事件所属连接（rebind 前后不变，用于关联）。
    pub connection_id: u64,
    /// 事件种类。
    pub kind: N1EventKind,
    /// 建议处置（本层只判定+上报，不执行重规划，D6）。
    pub disposition: N1Disposition,
}

/// 事件种类。
#[derive(Debug, Clone)]
pub enum N1EventKind {
    /// Link 失败（心跳超时主触发器；流/datagram 错误为辅）。
    LinkFailed {
        /// 可诊断原因。
        reason: String,
    },
    /// `resolve → rebind` 成功（连接已迁移，CID 不变）。
    RebindSucceeded,
    /// `resolve → rebind` 失败（原因可诊断）。
    RebindFailed {
        /// 可诊断原因。
        reason: String,
    },
}

/// 建议处置（D6）：`Retry`=本层可自愈（rebind 后恢复）；
/// `Fallback`=建议上层尝试备用路径（上报 Planner）；
/// `Abort`=不可恢复（peer 未知、认证失败类）；
/// `Escalate`=需人工/上层决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1Disposition {
    Retry,
    Fallback,
    Abort,
    Escalate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_hex_roundtrip() {
        let bytes = [0xabu8; 32];
        let id = N1PeerId(bytes);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(N1PeerId::from_hex(&hex).unwrap(), id);
        // 大写亦可。
        assert_eq!(N1PeerId::from_hex(&hex.to_uppercase()).unwrap(), id);
    }

    #[test]
    fn peer_id_hex_rejects_bad_input() {
        assert!(N1PeerId::from_hex("abc").is_err());
        assert!(N1PeerId::from_hex(&"zz".repeat(32)).is_err());
        assert!(N1PeerId::from_hex(&"ab".repeat(31)).is_err());
    }

    #[test]
    fn error_display_keeps_diagnosis() {
        let e = N1Error::Transport("udp down".into());
        assert!(e.to_string().contains("udp down"));
        assert!(N1Error::PeerUnknown.to_string().contains("unknown"));
    }
}
