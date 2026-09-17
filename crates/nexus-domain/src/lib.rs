//! Nexus stable domain core.
//!
//! 定义稳定核心领域类型：Resource、Provider、Intent、Constraint、Plan、
//! PlanExtension、Session 双轨状态、结构化失败类型及核心不变量。
//! 本 crate 不执行 I/O，不依赖平台 API（Portable Core，零依赖）。

#![forbid(unsafe_code)]

use core::fmt;

// ---------- Identity / Resource ----------

/// 资源标识。Resource 是用户可表达的抽象资源（Network/Service/Workspace/Compute/Device），
/// 不是 Provider，也不是 Locator。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceId(pub String);

/// Provider 标识。Provider 是能力提供方，不是 Node，不是 Resource。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(pub String);

/// Session 标识。Plan 与 Session 分离：Plan 是决策产物，Session 是运行载体。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

// ---------- Intent / Constraint ----------

/// 用户意图：要使用什么资源、以什么 profile 使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub profile: String,
}

/// 单条约束。Policy 将 Intent 展开为 Constraints；Planner 在约束下求解。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    pub key: String,
    pub value: String,
}

// ---------- FlowContext（Ingress 产出的中立流量上下文） ----------

/// 流量来源（PRODUCT §2：由 Virtual Packet Interface、SOCKS、HTTP 或 Native API 产生）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOrigin {
    /// 虚拟网卡 / 包接口（平台实现位于 nexus-platform-*）。
    VirtualPacketInterface,
    /// SOCKS5 代理协议状态机产出。
    Socks5,
    /// HTTP 代理协议状态机产出。
    Http,
    /// 进程内 Native API 直接提交。
    NativeApi,
}

/// 中立流量上下文。
///
/// 由 `nexus-ingress` 构造并提交给 SessionManager / Application Layer；
/// 它只描述“要使用什么资源、去往何处、以什么 profile”，不含 Path/Provider 决策
/// （Policy != Path），也不持有任何平台专有拦截句柄（Portable Core）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowContext {
    /// 产生该流量的输入来源。
    pub origin: FlowOrigin,
    /// 目标资源（如 InternetAccess 对应的 Network Resource）。
    pub resource: ResourceId,
    /// 目标目的地（主机 / URL / 五元组的中立表达）。
    pub destination: String,
    /// 使用画像，供 Policy 展开为 Intent。
    pub profile: String,
}

// ---------- Plan / PlanExtension ----------

/// 类型化、版本化的领域扩展（ARCHITECTURE §5）。
///
/// 领域特有信息只允许进入对应扩展类型，禁止以自由字符串混入 Plan。
/// 各扩展携带 `version` 字段，结构演进时通过版本号识别。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanExtension {
    Network(NetworkPlanExtension),
    Workspace(WorkspacePlanExtension),
    Compute(ComputePlanExtension),
    Service(ServicePlanExtension),
}

/// Network 领域扩展：Exit-DNS Binding、传输偏好等。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlanExtension {
    /// 扩展结构版本。
    pub version: u32,
    /// Exit-DNS Binding（由 nexus-dns 管理）。
    pub exit_dns_binding: Option<String>,
    /// 偏好传输（如 tcp/quic），None 表示由 Planner 决定。
    pub preferred_transport: Option<String>,
}

impl NetworkPlanExtension {
    /// 当前结构版本。
    pub const VERSION: u32 = 1;
}

impl Default for NetworkPlanExtension {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            exit_dns_binding: None,
            preferred_transport: None,
        }
    }
}

/// Workspace 领域扩展：执行前固定的 Commit/Snapshot、WorkingSet 覆盖等。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePlanExtension {
    /// 扩展结构版本。
    pub version: u32,
    /// 执行前固定的 CommitId（pinned snapshot）。
    pub pinned_commit: Option<String>,
    /// WorkingSet 文件/路径列表（非权威内容）。
    pub working_set: Vec<String>,
}

impl WorkspacePlanExtension {
    /// 当前结构版本。
    pub const VERSION: u32 = 1;
}

impl Default for WorkspacePlanExtension {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            pinned_commit: None,
            working_set: Vec::new(),
        }
    }
}

/// Compute 领域扩展：Planner 综合的 9 项输入中的领域部分与 Cache Hints。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputePlanExtension {
    /// 扩展结构版本。
    pub version: u32,
    /// 固定 Snapshot 引用。
    pub pinned_snapshot: Option<String>,
    /// 预估队列延迟（毫秒）。
    pub queue_delay_ms: Option<u64>,
    /// 预估执行时长（毫秒）。
    pub execution_estimate_ms: Option<u64>,
    /// 数据局部性缓存提示。
    pub cache_hints: Vec<String>,
}

impl ComputePlanExtension {
    /// 当前结构版本。
    pub const VERSION: u32 = 1;
}

impl Default for ComputePlanExtension {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            pinned_snapshot: None,
            queue_delay_ms: None,
            execution_estimate_ms: None,
            cache_hints: Vec::new(),
        }
    }
}

/// Service 领域扩展：本地 listener 绑定与授权要求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePlanExtension {
    /// 扩展结构版本。
    pub version: u32,
    /// 本地 listener 地址（如 127.0.0.1:PORT）。
    pub listen: Option<String>,
    /// 非 loopback 监听是否已显式授权。
    pub loopback_authorization_required: bool,
}

impl ServicePlanExtension {
    /// 当前结构版本。
    pub const VERSION: u32 = 1;
}

impl Default for ServicePlanExtension {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            listen: None,
            loopback_authorization_required: true,
        }
    }
}

/// Plan：Planner 的决策产物（Provider / Placement / Path / ExecutionStrategy + 领域扩展）。
///
/// 全系统只有一个系统级 Core Planner 生成 Plan；领域特有信息进入 `extension`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub resource_id: ResourceId,
    pub provider_id: ProviderId,
    pub placement: String,
    pub path: Vec<String>,
    pub execution_strategy: String,
    /// 类型化、版本化的领域扩展；None 表示无领域特有信息。
    pub extension: Option<PlanExtension>,
}

// ---------- Session 双轨状态 ----------

/// 生命周期阶段（资源分配/激活/排空/释放的物理状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecyclePhase {
    Allocating,
    Active,
    Draining,
    Disposed,
}

/// 终态结果（业务结果，与 LifecyclePhase 分离）。
///
/// `Completed / Failed / Cancelled` 为终态，只能提交一次；
/// 由 Session Owner 状态机唯一写入（见 nexus-session）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// 尚未达到终态。
    Unfinished,
    /// 成功完成。
    Completed,
    /// 失败，携带结构化错误。
    Failed(NexusError),
    /// 被协作取消。
    Cancelled,
}

/// Session 双轨状态视图（phase 与 outcome 分离）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub phase: LifecyclePhase,
    pub outcome: TerminalOutcome,
}

// ---------- 结构化失败类型 ----------

/// 失败处置语义（AGENTS.md §18：Error 必须保留 Retry/Fallback/Abort/Escalate 支持）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureDisposition {
    /// 可重试（瞬时失败）。
    Retry,
    /// 可降级/换路径（换 Provider、放宽约束、平台降级）。
    Fallback,
    /// 硬失败，中止（授权、解析等不可恢复）。
    Abort,
    /// 升级处理（内部错误、不支持特性）。
    Escalate,
}

/// 结构化失败类型（PRODUCT §2 七类失败 + 扩展），替代自由文本 `String` 错误。
///
/// 每种失败保留可诊断上下文；`disposition()` 给出失败处置语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NexusError {
    /// 没有可用 Provider。
    NoProvider {
        resource: ResourceId,
        intent: String,
    },
    /// 约束不可满足。
    ConstraintUnsatisfied { constraint: Constraint },
    /// 建连失败。
    ConnectivityEstablishmentFailed {
        provider: ProviderId,
        reason: String,
    },
    /// DNS 解析失败。
    DnsResolutionFailed { name: String },
    /// 授权被拒绝。
    AuthorizationDenied { principal: String },
    /// 远程计算作业被提供方拒绝（PRODUCT §6，remote P0 扩展）。
    ComputeJobRejected { job_id: String, reason: String },
    /// 平台缺少所需能力（PRODUCT §7：必须显式返回，不能静默降级语义）。
    PlatformCapabilityUnavailable { capability: String },
    /// Session 运行失败。
    SessionFailed { session: SessionId, reason: String },
    /// 请求的能力尚未实现。
    Unsupported { feature: String },
    /// 内部错误（不应泄漏给终端用户）。
    Internal { message: String },
}

impl NexusError {
    /// 返回失败处置语义，供调用方选择 Retry/Fallback/Abort/Escalate。
    #[must_use]
    pub fn disposition(&self) -> FailureDisposition {
        match self {
            Self::ConnectivityEstablishmentFailed { .. } => FailureDisposition::Retry,
            Self::NoProvider { .. }
            | Self::ConstraintUnsatisfied { .. }
            | Self::PlatformCapabilityUnavailable { .. } => FailureDisposition::Fallback,
            Self::AuthorizationDenied { .. }
            | Self::DnsResolutionFailed { .. }
            | Self::SessionFailed { .. }
            | Self::ComputeJobRejected { .. } => FailureDisposition::Abort,
            Self::Unsupported { .. } | Self::Internal { .. } => FailureDisposition::Escalate,
        }
    }
}

impl fmt::Display for NexusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProvider { resource, intent } => {
                write!(
                    f,
                    "no provider for resource {resource:?} (intent: {intent})"
                )
            }
            Self::ConstraintUnsatisfied { constraint } => {
                write!(
                    f,
                    "constraint unsatisfied: {} = {}",
                    constraint.key, constraint.value
                )
            }
            Self::ConnectivityEstablishmentFailed { provider, reason } => {
                write!(
                    f,
                    "connectivity establishment failed for provider {provider:?}: {reason}"
                )
            }
            Self::DnsResolutionFailed { name } => {
                write!(f, "dns resolution failed for {name}")
            }
            Self::AuthorizationDenied { principal } => {
                write!(f, "authorization denied for {principal}")
            }
            Self::ComputeJobRejected { job_id, reason } => {
                write!(f, "compute job {job_id} rejected by provider: {reason}")
            }
            Self::PlatformCapabilityUnavailable { capability } => {
                write!(f, "platform capability unavailable: {capability}")
            }
            Self::SessionFailed { session, reason } => {
                write!(f, "session {session:?} failed: {reason}")
            }
            Self::Unsupported { feature } => {
                write!(f, "unsupported feature: {feature}")
            }
            Self::Internal { message } => {
                write!(f, "internal error: {message}")
            }
        }
    }
}

impl fmt::Display for TerminalOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unfinished => f.write_str("unfinished"),
            Self::Completed => f.write_str("completed"),
            Self::Failed(err) => write!(f, "failed({err})"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_extension_is_typed_and_versioned() {
        let network = NetworkPlanExtension::default();
        assert_eq!(network.version, NetworkPlanExtension::VERSION);

        let plan = Plan {
            resource_id: ResourceId("net".into()),
            provider_id: ProviderId("p1".into()),
            placement: "us-east".into(),
            path: vec!["p1".into()],
            execution_strategy: "direct".into(),
            extension: Some(PlanExtension::Network(network)),
        };
        assert!(matches!(
            plan.extension,
            Some(PlanExtension::Network(NetworkPlanExtension {
                version: 1,
                ..
            }))
        ));
    }

    #[test]
    fn nexus_error_dispositions() {
        let err = NexusError::NoProvider {
            resource: ResourceId("net".into()),
            intent: "default".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Fallback);

        let err = NexusError::ConnectivityEstablishmentFailed {
            provider: ProviderId("p1".into()),
            reason: "timeout".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Retry);

        let err = NexusError::AuthorizationDenied {
            principal: "alice".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Abort);

        let err = NexusError::Internal {
            message: "boom".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Escalate);
    }

    #[test]
    fn flow_context_is_neutral_and_portable() {
        let flow = FlowContext {
            origin: FlowOrigin::Socks5,
            resource: ResourceId("internet-access".into()),
            destination: "https://example.invalid/".into(),
            profile: "Balanced".into(),
        };
        assert_eq!(flow.origin, FlowOrigin::Socks5);
        // 中立上下文不携带 Path/Provider 决策字段。
        assert_eq!(flow.resource, ResourceId("internet-access".into()));
    }

    #[test]
    fn terminal_outcome_carries_typed_error() {
        let outcome = TerminalOutcome::Failed(NexusError::DnsResolutionFailed {
            name: "example.com".into(),
        });
        assert!(matches!(
            outcome,
            TerminalOutcome::Failed(NexusError::DnsResolutionFailed { .. })
        ));
    }
}
