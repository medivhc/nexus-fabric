//! nexus-control-api
//!
//! 定义 CLI/GUI/Agent Client/SDK 使用的 Application Service 契约与稳定 DTO。
//! 本 crate 只承载契约与 DTO，不直接访问 OS/数据库/CAS/Transport/Connectivity。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

// 前端统一入口重导出：CLI/GUI/Agent 只依赖 nexus-control-api，即可获得领域核心类型。
pub use nexus_domain::{NexusError, ResourceId, SessionId};

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_CONTROL_API_MODULE: &str = "nexus-control-api";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "定义 CLI/GUI/Agent Client/SDK 使用的 Application Service 契约与稳定 DTO。"
}

// ---------- 控制面命令（PRODUCT §8 可观察性命令） ----------

/// 控制面命令：产品 CLI/GUI/Agent 的统一入口命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    /// `status`：关键 Resource/Session 总体状态。
    Status,
    /// `plan explain`：展示指定 Resource 的 Plan 决策。
    PlanExplain { resource: ResourceId },
    /// `session watch`：观察指定 Session 的状态。
    SessionWatch { session: SessionId },
    /// `connectivity status`：连接状态。
    ConnectivityStatus,
    /// `connectivity candidates`：候选 Provider。
    ConnectivityCandidates,
    /// `connectivity probe`：探测目标可达性。
    ConnectivityProbe { target: String },
    /// `connectivity links`：活动链路。
    ConnectivityLinks,
    /// `dns status`：DNS 子系统状态。
    DnsStatus,
    /// `dns resolve`：解析域名。
    DnsResolve { name: String },
    /// `dns providers`：DNS Provider 列表。
    DnsProviders,
    /// `dns cache`：DNS 缓存。
    DnsCache,
    /// `workspace heads`：Workspace Head Set。
    WorkspaceHeads { workspace: String },
    /// `workspace conflicts`：未合并冲突。
    WorkspaceConflicts { workspace: String },
    /// `workspace cache`：Workspace 缓存状态。
    WorkspaceCache { workspace: String },
    /// `compute jobs`：Compute 任务。
    ComputeJobs,
    /// `diagnose`：统一诊断。
    Diagnose,
    /// `platform capabilities`：平台能力清单。
    PlatformCapabilities,
}

// ---------- 结构化输出 DTO（机器接口，版本化） ----------

/// 状态视图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusView {
    /// 可观察的 Resource/Session 概览行。
    pub lines: Vec<String>,
}

/// Plan 决策视图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanView {
    pub resource: ResourceId,
    pub provider: String,
    pub placement: String,
    pub path: Vec<String>,
    pub execution_strategy: String,
    pub extension: String,
}

/// Session 观察视图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub session: SessionId,
    pub phase: String,
    pub outcome: String,
}

/// 通用文本视图（连通性/DNS/Workspace/Compute/诊断/能力）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinesView {
    pub lines: Vec<String>,
}

/// 控制面输出：每个命令对应结构化 DTO。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutput {
    Status(StatusView),
    PlanExplain(PlanView),
    SessionWatch(SessionView),
    Connectivity(LinesView),
    Dns(LinesView),
    Workspace(LinesView),
    Compute(LinesView),
    Diagnose(LinesView),
    PlatformCapabilities(LinesView),
}

impl ControlOutput {
    /// 输出为便于终端渲染的行。
    #[must_use]
    pub fn to_lines(&self) -> Vec<String> {
        match self {
            Self::Status(v) => v.lines.clone(),
            Self::PlanExplain(v) => vec![
                format!("resource: {:?}", v.resource),
                format!("provider: {}", v.provider),
                format!("placement: {}", v.placement),
                format!("path: {}", v.path.join(" -> ")),
                format!("execution_strategy: {}", v.execution_strategy),
                format!("extension: {}", v.extension),
            ],
            Self::SessionWatch(v) => vec![
                format!("session: {:?}", v.session),
                format!("phase: {}", v.phase),
                format!("outcome: {}", v.outcome),
            ],
            Self::Connectivity(v)
            | Self::Dns(v)
            | Self::Workspace(v)
            | Self::Compute(v)
            | Self::Diagnose(v)
            | Self::PlatformCapabilities(v) => v.lines.clone(),
        }
    }
}

// ---------- Application Service 契约 ----------

/// 前端统一入口：CLI/GUI/Agent Client/SDK 通过 `execute` 提交命令并获取结构化输出。
pub trait ControlService: Send + Sync {
    /// 执行控制面命令。
    fn execute(&self, command: ControlCommand) -> Result<ControlOutput, NexusError>;
}
