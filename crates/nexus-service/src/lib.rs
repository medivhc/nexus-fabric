//! nexus-service
//!
//! 实现 Service Resource 的解析、授权后的连接、connect/forward 与服务会话行为。
//!
//! remote P0 冻结契约：`ServiceTransport` 依赖注入（避免 service -> transport 依赖边，
//! 架构允许依赖仅 domain/session/delivery）+ `ServiceSession` connect 语义
//! （scenarios/product/remote_service_access_flow.toml）。
//! connect != forward：P0 只冻结 connect；forward 后置。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::fmt;

/// Service 会话阶段（冻结契约）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePhase {
    /// 正在建立服务会话（握手未完成）。
    Connecting,
    /// 服务会话已建立并可承载业务。
    Active,
    /// 服务会话已关闭。
    Closed,
}

impl fmt::Display for ServicePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => f.write_str("Connecting"),
            Self::Active => f.write_str("Active"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

/// 服务会话失败（冻结契约：三变体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// 底层帧通道传输失败。
    Transport,
    /// 服务端拒绝（未授权 / 握手未确认）。
    Unauthorized,
    /// 服务会话已关闭。
    Closed,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport => f.write_str("service transport failure"),
            Self::Unauthorized => f.write_str("service session unauthorized"),
            Self::Closed => f.write_str("service session closed"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// 注入的帧通道（冻结契约）。
///
/// 由组合根以 `nexus_transport::FrameStream` 适配装配，避免 service -> transport 依赖边。
pub trait ServiceTransport {
    /// 发送一帧业务数据。
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), ServiceError>;
    /// 接收一帧业务数据。
    fn recv_frame(&mut self) -> Result<Vec<u8>, ServiceError>;
}

/// Nexus-aware Service Session（PRODUCT §3 connect 语义；冻结契约）。
///
/// `connect` 在已认证的帧通道上完成服务握手（发送 `CONNECT` 帧，
/// 收到 `READY` 确认后进入 `Active`）。系统级 Session 双轨状态由
/// `nexus-session` 的 Owner 管理，本模块不重复实现。
pub struct ServiceSession {
    phase: ServicePhase,
}

impl ServiceSession {
    /// 建立服务会话（冻结契约）。
    ///
    /// 前置条件：帧通道已建立且已通过认证门控（业务帧转发之前，W7）。
    pub fn connect(mut transport: Box<dyn ServiceTransport>) -> Result<Self, ServiceError> {
        transport
            .send_frame(b"CONNECT")
            .map_err(|_| ServiceError::Transport)?;
        let resp = transport
            .recv_frame()
            .map_err(|_| ServiceError::Transport)?;
        if resp == b"READY" {
            Ok(Self {
                phase: ServicePhase::Active,
            })
        } else {
            Err(ServiceError::Unauthorized)
        }
    }

    /// 当前服务会话阶段。
    pub fn phase(&self) -> ServicePhase {
        self.phase
    }
}
