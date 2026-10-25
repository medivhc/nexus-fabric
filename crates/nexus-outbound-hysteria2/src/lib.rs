//! nexus-outbound-hysteria2
//!
//! Hysteria2 出站 adapter：实现 `nexus-connectivity::OutboundAdapter`。
//! 基于 QUIC（RFC 9000）+ 不可靠数据报扩展（RFC 9221）的 TCP/UDP 代理协议：
//! 认证走一条最小 HTTP/3 `POST /auth` 请求（对未认证探测者表现为普通 H3 Web
//! 服务器），认证通过后同一 QUIC 连接转为代理连接——TCP 走双向 QUIC stream，
//! UDP 走 QUIC DATAGRAM（多路复用天然由 QUIC 提供）。
//!
//! 协议语义见 `docs/protocols/hysteria2.md`（clean-room 实现，不拷贝任何既有
//! 代码；QUIC 层基于 workspace 已有的 `quinn-proto 0.11` sans-IO API + 自写
//! 同步 driver，不引入 quiche——见 `MODULE.md` 的 QUIC 选型结论）。
//!
//! 本 crate 覆盖协议中已确认的部分：
//!
//! - QUIC 建连：SNI、ALPN `h3`、**禁用 QUIC bit greasing**、DATAGRAM 收发、
//!   流窗口 8MB / 连接窗口 20MB / 空闲超时 30s / 最大并发流各 1024、10s 保活；
//! - 证书校验三选一：`pin-sha256`（替代链校验+主机名校验，mihomo 行为）、
//!   `insecure`、系统根证书；
//! - 最小 HTTP/3 认证：单向控制流发空 SETTINGS（`[0x00, 0x04, 0x00]`）+
//!   stream 0 发 QPACK HEADERS（含文档列出的 7 个头）；响应校验 `:status == 233`
//!   （`233 HyOK`），解析 `Hysteria-UDP` / `Hysteria-CC-RX`；
//! - `TCPRequest` / `TCPResponse` 帧编解码（地址为文本 `host:port`）；
//! - `UDPMessage` 编解码（`session u32BE | packet u16BE | frag_id | frag_count |
//!   varint 地址长 | 地址文本 | 载荷`）；
//! - Salamander 混淆：`salt(8) + (payload XOR BLAKE2b-256(key||salt))`；
//! - fast-open 语义：请求发出后不等响应即返回，读侧仍先剥离 `TCPResponse`；
//! - UDP session id 本地从 0 递增分配，无显式关闭（server 按不活跃超时回收）。
//!
//! 暂不实现（见 `MODULE.md` Non-Responsibilities）：Brutal CC 固定速率拥塞
//! 控制（只收发 `Hysteria-CC-RX` 协商字段，拥塞算法用 quinn-proto 默认 Cubic）、
//! 端口跳跃、完整 HTTP/3 连接、server 侧产品实现（只有测试用最小 server）。
//!
//! 未确认的细节在注释中标 `// 未确认：`。

#![forbid(unsafe_code)]

#[cfg(test)]
mod huffman;

pub mod adapter;
pub mod auth;
pub mod client;
pub mod config;
pub mod driver;
pub mod error;
pub mod frames;
pub mod obfs;
pub mod qpack;
pub mod test_server;
pub mod tls;
pub mod varint;

pub use adapter::Hysteria2Adapter;
pub use auth::{AuthResponse, CcRx};
pub use client::Hysteria2Client;
pub use config::{Hysteria2Target, Obfs, parse_pin_sha256};
pub use error::Hysteria2Error;
pub use frames::{MAX_UDP_PAYLOAD, TcpRequest, TcpResponse, UdpMessage};
pub use qpack::STATIC_TABLE;
pub use tls::CertVerify;
