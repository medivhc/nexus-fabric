//! nexus-compute
//!
//! 实现 Compute Resource 的能力描述、估计输入、执行会话、Workspace Snapshot Pin、Artifact 与可选 Write-back。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

/// N3 provider-owned durable acceptance; separate from legacy job sessions.
pub mod task;

/// 计算作业会话阶段（冻结契约，scenarios/product/remote_compute_job_flow.toml）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputePhase {
    /// 作业已发送，结果帧尚未返回。
    Submitting,
    /// 作业往返成功，结果已取回。
    Active,
    /// 作业会话已关闭。
    Closed,
}

impl std::fmt::Display for ComputePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ComputePhase::Submitting => "Submitting",
            ComputePhase::Active => "Active",
            ComputePhase::Closed => "Closed",
        };
        f.write_str(s)
    }
}

/// 计算作业会话错误（冻结契约）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeError {
    /// 底层帧通道读写失败。
    Transport,
    /// 提供方拒绝作业（`REJECTED` 响应帧）。
    Rejected,
    /// 帧通道已关闭。
    Closed,
    /// 响应帧不是可识别协议（非 `OK:<result>` / `REJECTED`）。
    Protocol,
}

impl std::fmt::Display for ComputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ComputeError::Transport => "compute transport failure",
            ComputeError::Rejected => "compute job rejected by provider",
            ComputeError::Closed => "compute session closed",
            ComputeError::Protocol => "compute protocol violation",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ComputeError {}

/// 注入的帧通道（冻结契约）：由 Composition Root 以 `nexus_transport::FrameStream`
/// 适配装配，避免 compute -> transport 依赖边（MODULE.md Allowed Dependencies）。
pub trait ComputeTransport {
    /// 发送一帧作业；失败返回 `ComputeError::Transport`。
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), ComputeError>;
    /// 接收一帧结果；通道关闭返回 `ComputeError::Closed`。
    fn recv_frame(&mut self) -> Result<Vec<u8>, ComputeError>;
}

/// 远程计算作业会话（PRODUCT §2/§6）：在已认证帧通道上提交作业帧、
/// 接收结果帧并取回结果后进入 Active。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeJobSession {
    phase: ComputePhase,
    result: Option<String>,
}

impl ComputeJobSession {
    /// 提交作业：发送 `job` 帧并接收结果帧；响应 `OK:<result>` 提取结果后
    /// 进入 `Active`，`REJECTED` 视为提供方拒绝（`ComputeError::Rejected`），
    /// 其余帧视为协议违规（`ComputeError::Protocol`）。
    ///
    /// 冻结语义（MODULE.md）：作业必须显式提交（submit 完成往返后才 Active）；
    /// 提供方拒绝与协议未识别帧是可诊断失败，不得吞为成功。
    pub fn submit(
        mut transport: Box<dyn ComputeTransport>,
        job: &[u8],
    ) -> Result<Self, ComputeError> {
        let mut session = Self {
            phase: ComputePhase::Submitting,
            result: None,
        };
        transport.send_frame(job)?;
        let resp = transport.recv_frame()?;
        if let Some(payload) = resp.strip_prefix(b"OK:") {
            session.result = Some(String::from_utf8_lossy(payload).to_string());
            session.phase = ComputePhase::Active;
            Ok(session)
        } else if resp == b"REJECTED" {
            Err(ComputeError::Rejected)
        } else {
            Err(ComputeError::Protocol)
        }
    }

    /// 当前计算会话阶段。
    #[must_use]
    pub fn phase(&self) -> ComputePhase {
        self.phase
    }

    /// 成功往返取回的结果（`OK:` 前缀之后的内容）；未成功时为 None。
    #[must_use]
    pub fn result(&self) -> Option<&str> {
        self.result.as_deref()
    }

    /// 关闭已提交的作业会话：Active -> Closed，结果保留。
    /// `observability compute jobs` 借此展示 Closed 阶段快照（2026-09-18）。
    #[must_use]
    pub fn close(self) -> Self {
        Self {
            phase: ComputePhase::Closed,
            result: self.result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransport {
        inbound: Vec<u8>,
    }

    impl ComputeTransport for MockTransport {
        fn send_frame(&mut self, _payload: &[u8]) -> Result<(), ComputeError> {
            Ok(())
        }

        fn recv_frame(&mut self) -> Result<Vec<u8>, ComputeError> {
            Ok(self.inbound.clone())
        }
    }

    #[test]
    fn submit_parses_ok_result_and_activates() {
        let transport = MockTransport {
            inbound: b"OK:42".to_vec(),
        };
        let session =
            ComputeJobSession::submit(Box::new(transport), b"job:compile").expect("submit ok");
        assert_eq!(session.phase(), ComputePhase::Active);
        assert_eq!(session.result(), Some("42"));
    }

    #[test]
    fn submit_rejects_on_rejected_frame() {
        let transport = MockTransport {
            inbound: b"REJECTED".to_vec(),
        };
        let session = ComputeJobSession::submit(Box::new(transport), b"job:bogus");
        assert_eq!(session, Err(ComputeError::Rejected));
    }

    #[test]
    fn submit_protocol_error_on_unknown_frame() {
        let transport = MockTransport {
            inbound: b"GARBAGE".to_vec(),
        };
        let session = ComputeJobSession::submit(Box::new(transport), b"job:x");
        assert_eq!(session, Err(ComputeError::Protocol));
    }
}
