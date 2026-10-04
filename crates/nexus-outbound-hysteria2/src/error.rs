//! Hysteria2 出站结构化错误。
//!
//! 不以日志文本代替类型；错误展示绝不回显密码/密钥材料（`Display` 实现中
//! 不携带任何密钥相关字段）。

use std::fmt;

/// Hysteria2 出站结构化错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2Error {
    /// 认证失败：`:status != 233`、响应非法、密码错误等（不回显密码）。
    AuthFailed,
    /// 服务端协商 `Hysteria-UDP: false`（或配置关闭 UDP）时调用了 UDP 接口。
    UdpDisabled,
    /// 帧格式非法：varint / QPACK / TCPRequest / TCPResponse / UDPMessage /
    /// Salamander 包解析失败。
    InvalidFrame,
    /// QUIC 层失败（握手、流操作、连接丢失等；携带对端/传输层给出的原因文本）。
    Quic(String),
    /// TLS 配置构造或握手失败。
    Tls,
    /// 底层 I/O 失败（携带 `io::Error` 的 kind 描述，不含敏感信息）。
    Io(String),
    /// 操作超时。
    Timeout,
    /// 不支持的混淆方式（如 `obfs = "gecko"`，文档明确拒绝）。
    UnsupportedObfs,
    /// 配置非法（门禁拒绝；携带原因，不含密码原文）。
    InvalidConfig(String),
    /// 连接已关闭。
    Closed,
    /// TCP 建连被服务端拒绝（携带服务端返回的错误文本；这是服务端诊断信息，
    /// 非本地密钥材料）。
    TcpRejected(String),
    /// UDP 数据报超过上限被丢弃。
    DatagramTooLarge {
        /// 数据报字节数。
        len: usize,
    },
    /// 流被对端重置。
    StreamReset {
        /// 对端给出的错误码。
        code: u64,
    },
}

impl fmt::Display for Hysteria2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => write!(f, "hysteria2 authentication failed"),
            Self::UdpDisabled => write!(f, "hysteria2 udp disabled by server or config"),
            Self::InvalidFrame => write!(f, "hysteria2 invalid frame"),
            Self::Quic(e) => write!(f, "hysteria2 quic error: {e}"),
            Self::Tls => write!(f, "hysteria2 tls error"),
            Self::Io(e) => write!(f, "hysteria2 io error: {e}"),
            Self::Timeout => write!(f, "hysteria2 timed out"),
            Self::UnsupportedObfs => write!(f, "hysteria2 unsupported obfuscation"),
            Self::InvalidConfig(e) => write!(f, "hysteria2 invalid config: {e}"),
            Self::Closed => write!(f, "hysteria2 connection closed"),
            Self::TcpRejected(e) => write!(f, "hysteria2 tcp rejected by server: {e}"),
            Self::DatagramTooLarge { len } => {
                write!(f, "hysteria2 datagram too large ({len} bytes)")
            }
            Self::StreamReset { code } => {
                write!(f, "hysteria2 stream reset by peer (code {code})")
            }
        }
    }
}

impl std::error::Error for Hysteria2Error {}

impl From<std::io::Error> for Hysteria2Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
