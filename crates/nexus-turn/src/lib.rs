//! RFC 5766 TURN 的最小可用实现（T1–T6，见 MODULE.md）。
//!
//! - [`stun`]: STUN 消息编解码（RFC 5389 头 + 5766 属性）。
//! - [`auth`]: 长效认证（key = MD5(username:realm:password)，HMAC-SHA1）。
//! - [`client`]: `TurnClient`（allocate / permission / channel / refresh）。
//! - [`socket`]: `TurnSocket: nexus_fabric::UdpTransport`。
//! - [`server`]: 最小 TURN server（仅 E4/自测）。
//!
//! 全同步 std API，零 tokio（T5）。

pub(crate) mod auth;
pub mod client;
pub mod server;
pub mod socket;
pub mod stun;

pub use client::{TurnClient, TurnCredentials, TurnStats};
pub use server::TurnServer;
pub use socket::TurnSocket;
