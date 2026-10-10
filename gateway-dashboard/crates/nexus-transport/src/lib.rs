//! nexus-transport
//!
//! 提供 Stream、Datagram、Multiplexing、Connection Reuse、Backpressure 与 Flow Control 的可移植传输抽象。
//!
//! remote P0 冻结契约：TCP + u32 大端长度前缀帧（scenarios/product/remote_service_access_flow.toml）。
//! transport 不在 harness.toml `[portable_core]` 清单，允许使用 `std::net`。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

/// 传输失败（冻结契约：三变体；诊断信息可在不改变枚举的前提下补全）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// 建立连接失败（对端不可达 / 拒绝 / 超时）。
    ConnectFailed,
    /// 帧流已关闭（对端断开 / 读写失败）。
    Closed,
    /// 帧协议违规（长度前缀非法等）。
    Protocol,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectFailed => f.write_str("transport connect failed"),
            Self::Closed => f.write_str("frame stream closed"),
            Self::Protocol => f.write_str("frame protocol violation"),
        }
    }
}

impl std::error::Error for TransportError {}

/// 长度前缀帧流：`u32` 大端长度前缀 + payload（冻结帧协议）。
///
/// `recv_frame` 每次读取恰好一帧（4 字节头 + payload），天然处理半包/粘包。
pub struct FrameStream {
    stream: TcpStream,
}

impl FrameStream {
    /// 发送一帧：u32 大端长度前缀 + payload（空 payload 合法）。
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let len = u32::try_from(payload.len()).map_err(|_| TransportError::Protocol)?;
        let mut header = [0u8; 4];
        header.copy_from_slice(&len.to_be_bytes());
        self.stream
            .write_all(&header)
            .map_err(|_| TransportError::Closed)?;
        self.stream
            .write_all(payload)
            .map_err(|_| TransportError::Closed)?;
        self.stream.flush().map_err(|_| TransportError::Closed)?;
        Ok(())
    }

    /// 接收一帧；对端关闭或读写失败返回 `Closed`。
    pub fn recv_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut header = [0u8; 4];
        self.stream
            .read_exact(&mut header)
            .map_err(|_| TransportError::Closed)?;
        let len = u32::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; len];
        self.stream
            .read_exact(&mut payload)
            .map_err(|_| TransportError::Closed)?;
        Ok(payload)
    }

    /// 取回底层 TCP 流，供真实 relay 双向字节中继使用（帧格式不变，
    /// 中继对帧字节完全透明）。
    pub fn into_raw(self) -> TcpStream {
        self.stream
    }
}

/// 建立到远端 Endpoint 的 TCP 连接并封装为长度前缀帧流（冻结契约）。
pub fn connect(endpoint: &SocketAddr) -> Result<FrameStream, TransportError> {
    let stream = TcpStream::connect(endpoint).map_err(|_| TransportError::ConnectFailed)?;
    Ok(FrameStream { stream })
}

/// 在已绑定 Listener 上接受一个连接并封装为帧流（remote P0 提供方侧补充 API；
/// 不改动冻结契约中的任何签名与帧协议）。
pub fn accept(listener: &TcpListener) -> Result<FrameStream, TransportError> {
    let (stream, _) = listener.accept().map_err(|_| TransportError::Closed)?;
    Ok(FrameStream { stream })
}
