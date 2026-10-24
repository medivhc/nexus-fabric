//! nexus-control-api
//!
//! 定义 CLI/GUI/Agent Client/SDK 使用的 Application Service 契约与稳定 DTO。
//! 本 crate 只承载契约与 DTO，不直接访问 OS/数据库/CAS/Transport/Connectivity。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

// 前端统一入口重导出：CLI/GUI/Agent 只依赖 nexus-control-api，即可获得领域核心类型。
pub use nexus_domain::{NexusError, ResourceId, SessionId};

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
    /// `connectivity nat`：NAT 穿透状态（可带 `--peer <hex>` 过滤）。
    ConnectivityNat { peer: Option<String> },
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
    /// `workspace commit`：显式提交 workspace 暂存变更（C1/D5；经 LocalAPI）。
    WorkspaceCommit { workspace: String },
    /// `compute jobs`：Compute 任务。
    ComputeJobs,
    /// `diagnose`：统一诊断。
    Diagnose,
    /// `platform capabilities`：平台能力清单。
    PlatformCapabilities,
    /// `run <resource>`：执行远程资源访问。
    Run { resource: String },
    /// `network up --config <toml>`：前台装配 N1 Universal Connectivity
    ///（建 TUN → dial 静态 peers → 起包泵；Ctrl-C 退出）。
    ///
    /// M6：经 Application API；由 Composition Root（apps/nexus）实现装配逻辑。
    NetworkUp {
        /// N1 配置文件内容（TOML）。
        config: String,
    },
    /// `network status`：N1 装配状态（无 daemon 时诚实标注）。
    NetworkStatus,
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

/// Versioned N3 Application Service contracts; no transport or TaskOwner.
pub mod task;

/// Bounded N3 snapshot upload contracts, independent of Task submission.
pub mod snapshot;
