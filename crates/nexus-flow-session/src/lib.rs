//! nexusd TUN 数据面的"流→会话映射"（v9 §10，requirement-change 2026-10-02）。
//!
//! # 两层"会话"澄清（R3）
//!
//! - `smoltcp` 本地 TCP 会话 = **传输终结**（TUN 侧 TCP 状态机，本地完成握手）；
//! - `§10` 资源 `Session` = **资源使用上下文**（`FlowContext → Policy → Planner → SessionOwner`）。
//!
//! 映射关系：一个 §10 Session 绑定一个 smoltcp 终结流（TCP）或一个 UDP 5 元组流。
//! smoltcp 会话的生命周期从属于 §10 Session（Session 进 Draining/Disposed 时终结本地传输会话）。
//!
//! # 调用流（ARCHITECTURE.md#tun-ingress）
//!
//! ```text
//! TUN packet
//!   ==> FlowTable (5-tuple key; DNS 短路/QoS 仍在逐包快路径)
//!   ==> 新流首包：FlowContext(origin=PacketCapture) → Policy → Core Planner
//!   ==> SessionManager (Owner) 创建 Session → 后台线程异步 Establish Connectivity
//!   ==> 会话 Active 后：流表项绑定 session，快路径转发（不再调 Planner）
//! ```

#![forbid(unsafe_code)]

mod buffer;
mod chain;
mod flow;
mod manager;

pub use buffer::UdpBuffer;
pub use chain::{ChainDeps, ChainError, ChainOutcome, run_first_packet_chain};
pub use flow::{FlowDecision, FlowEntry, FlowKey, FlowPhase, FlowTable, IpProto};
pub use manager::{
    ConnectivityEstablisher, EstablishEvent, FlowSignal, SessionManager, SessionManagerConfig,
};
// 建连器 trait 签名需要；重导出避免调用方另引 nexus-planner / nexus-domain。
pub use nexus_domain::SessionId;
pub use nexus_planner::Planned;
