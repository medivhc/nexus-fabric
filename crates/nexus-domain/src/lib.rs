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

/// Workspace 标识（N2 §16.1：资源引用的命名空间维度）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceId(pub String);

impl WorkspaceId {
    /// 构造（非空校验由调用方保证；空串视为未命名 workspace 由上层拒绝）。
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Node 标识（N2 §16.1：节点身份）。
///
/// 内容派生：`IdentityManager::peer_id_of`（`nexus-connectivity::identity`），即
/// `hex(SHA-256(X25519 static 公钥)[..16])`；不引入注册中心（D6）。
/// NodeId 是身份（Identity），不是定位（Locator）：同一节点换地址 NodeId 不变。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

impl NodeId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 资源名校验失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceNameError {
    /// 空名。
    Empty,
    /// 含非法字符（只允许 ASCII 字母数字 / `-` / `_`）。
    InvalidChar(char),
    /// 超长（> 128）。
    TooLong,
}

impl fmt::Display for ResourceNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("resource name is empty"),
            Self::InvalidChar(c) => write!(f, "resource name contains invalid char {c:?}"),
            Self::TooLong => f.write_str("resource name too long (max 128)"),
        }
    }
}

/// 资源人类可读名（如 `dev-web`）；只做本地解析，名字≠定位（D2）。
///
/// 字符集：ASCII 字母数字 / `-` / `_`（与 workspace id 既有约定一致）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceName(String);

impl ResourceName {
    /// 校验并构造。
    pub fn new(name: impl Into<String>) -> Result<Self, ResourceNameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ResourceNameError::Empty);
        }
        if name.len() > 128 {
            return Err(ResourceNameError::TooLong);
        }
        if let Some(c) = name
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
        {
            return Err(ResourceNameError::InvalidChar(c));
        }
        Ok(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 资源引用（N2 §16.1 D2）：`{workspace, name}` 两段式寻址。
///
/// kind 不进地址：资源类型是目录属性（`ResourceKind`），不是地址的一部分。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceRef {
    pub workspace: WorkspaceId,
    pub name: ResourceName,
}

impl ResourceRef {
    #[must_use]
    pub fn new(workspace: WorkspaceId, name: ResourceName) -> Self {
        Self { workspace, name }
    }
}

impl fmt::Display for ResourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.workspace, self.name)
    }
}

/// 资源类型：目录属性，不进地址（D2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Network,
    Service,
    Workspace,
    Compute,
    Device,
}

impl ResourceKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Service => "service",
            Self::Workspace => "workspace",
            Self::Compute => "compute",
            Self::Device => "device",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 资源操作（grant 表 `operations` 的闭集合；扩展需走 requirement-change）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceOperation {
    /// 建立 Session 并使用资源（`nexus use`）。
    Use,
    /// 管理资源注册与授权（publish / revoke / grant 管理）。
    Manage,
}

impl ResourceOperation {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Use => "use",
            Self::Manage => "manage",
        }
    }
}

impl fmt::Display for ResourceOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 结构化拒绝原因（D6：`Deny{NoSuchGrant/WrongWorkspace/OperationNotGranted/Expired/Revoked}`）。
///
/// 授权判定在 provider 侧每次建 Session 时执行；"目录返回≠有权限"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// 该 principal 对该资源没有任何 grant。
    NoSuchGrant,
    /// grant 的 workspace 与请求 workspace 不一致。
    WrongWorkspace {
        expected: WorkspaceId,
        actual: WorkspaceId,
    },
    /// grant 存在，但未授予该操作。
    OperationNotGranted { operation: ResourceOperation },
    /// grant 已过期（`not_after`）。
    Expired { not_after: u64, now: u64 },
    /// grant 已被显式撤销。
    Revoked,
}

impl DenyReason {
    /// 机器可读判别名（审计 / JSON `error.deny`）。
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSuchGrant => "NoSuchGrant",
            Self::WrongWorkspace { .. } => "WrongWorkspace",
            Self::OperationNotGranted { .. } => "OperationNotGranted",
            Self::Expired { .. } => "Expired",
            Self::Revoked => "Revoked",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchGrant => f.write_str("no grant for this principal and resource"),
            Self::WrongWorkspace { expected, actual } => write!(
                f,
                "grant is for workspace {expected}, request is for workspace {actual}"
            ),
            Self::OperationNotGranted { operation } => {
                write!(f, "operation {operation} not granted")
            }
            Self::Expired { not_after, now } => {
                write!(f, "grant expired at {not_after} (now {now})")
            }
            Self::Revoked => f.write_str("grant was revoked"),
        }
    }
}

/// 授权判定结果（D6；由 `nexus-auth` 的 grant 表判定产生）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny(DenyReason),
}

impl AuthorizationDecision {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for AuthorizationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny(reason) => write!(f, "deny({})", reason.code()),
        }
    }
}

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

// ---------- Resource Delivery Request（v9 §21） ----------

/// 资源交付请求：缺失 Object/Chunk 进入 Core Planner 的标准 DTO（版本化）。
///
/// v9 §21："任何缺失 Object/Chunk 都转换为标准 Resource Delivery Request，
/// 再进入 Core Planner"。由 `nexus-workspace-intel` 的 PrefetchScheduler 产生，
/// Composition Root 转换为 `PlanningSnapshot` 后调用 Core Planner。
/// 本 DTO 只表达"要什么"，不表达"从哪取"（Provider/Path 选择是 Planner 的事）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDeliveryRequest {
    /// DTO 版本（当前为 1）。
    pub version: u32,
    /// 缺失的资源（workspace 对象/块，如 `ws:<id>/obj:<object-id>`）。
    pub resource: ResourceId,
    /// 取回意图（profile 如 `workspace-object-fetch`）。
    pub intent: Intent,
    /// 硬约束（必须含 capability 约束，Planner 要求）。
    pub constraints: Vec<Constraint>,
    /// 已知持有副本的 Provider（按 Identity，不含 Locator 推导）。
    pub providers: Vec<ProviderId>,
}

impl ResourceDeliveryRequest {
    /// 当前 DTO 版本。
    pub const VERSION: u32 = 1;

    /// 构造交付请求。
    #[must_use]
    pub fn new(
        resource: ResourceId,
        intent: Intent,
        constraints: Vec<Constraint>,
        providers: Vec<ProviderId>,
    ) -> Self {
        Self {
            version: Self::VERSION,
            resource,
            intent,
            constraints,
            providers,
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

// ---------- Connectivity Evaluation（v9 §8.1） ----------

/// Connectivity Evaluation 输出：规划期连通性可行性（DTO，版本化）。
///
/// 由 Connectivity Evaluation 纯函数（`nexus-connectivity::evaluation`）产生，
/// 作为 Core Planner 的 Connectivity Feasibility 输入。只表达"能否建连"的
/// 可行性判断，不建立业务 Link，不含业务评分权重（Measurement ≠ Score）。
///
/// 字段语义（v9 §8.1）：
/// - `direct_likely`：无需 NAT 穿透即可直连；
/// - `punching_likely`：NAT 穿透可能成功；
/// - `relay_available`：中继可用（TURN / peer-relay）；
/// - `existing_link_available`：已有链路可复用；
/// - `estimated_setup_cost_ms`：预估建连成本（毫秒），`None` = 无可行路径；
/// - `confidence_percent`：输入完备度 0..=100（不是业务分数）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityEvaluation {
    /// DTO 版本（当前为 1）。
    pub version: u32,
    /// 直连可能。
    pub direct_likely: bool,
    /// 打洞可能。
    pub punching_likely: bool,
    /// 中继可用。
    pub relay_available: bool,
    /// 已有链路可复用。
    pub existing_link_available: bool,
    /// 预估建连成本（毫秒）；`None` 表示无可行路径。
    pub estimated_setup_cost_ms: Option<u32>,
    /// 置信度 0..=100。
    pub confidence_percent: u8,
}

impl ConnectivityEvaluation {
    /// 当前 DTO 版本。
    pub const VERSION: u32 = 1;

    /// 是否至少有一条可行路径（任一建连方式可行）。
    #[must_use]
    pub fn has_feasible_path(&self) -> bool {
        self.direct_likely
            || self.punching_likely
            || self.relay_available
            || self.existing_link_available
    }
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
    /// 远程 Workspace 提交被提供方拒绝（PRODUCT §6，remote P0 扩展）。
    WorkspaceCommitRejected { workspace: String, reason: String },
    /// 平台缺少所需能力（PRODUCT §7：必须显式返回，不能静默降级语义）。
    PlatformCapabilityUnavailable { capability: String },
    /// Session 运行失败。
    SessionFailed { session: SessionId, reason: String },
    /// 查找 miss：某类领域对象不存在（N2 P0-1：session / resource 参数过滤）。
    NotFound { kind: String, id: String },
    /// 节点身份不可用：未执行 `nexus node init` 或身份记录损坏。
    NodeIdentityUnavailable { reason: String },
    /// 持久化写失败（FileKvStore 原子写 / journal 落盘失败）。
    PersistenceFailed { path: String, reason: String },
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
            | Self::NotFound { .. }
            | Self::NodeIdentityUnavailable { .. }
            | Self::ComputeJobRejected { .. }
            | Self::WorkspaceCommitRejected { .. } => FailureDisposition::Abort,
            Self::Unsupported { .. } | Self::Internal { .. } | Self::PersistenceFailed { .. } => {
                FailureDisposition::Escalate
            }
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
            Self::WorkspaceCommitRejected { workspace, reason } => {
                write!(
                    f,
                    "workspace {workspace} commit rejected by provider: {reason}"
                )
            }
            Self::PlatformCapabilityUnavailable { capability } => {
                write!(f, "platform capability unavailable: {capability}")
            }
            Self::SessionFailed { session, reason } => {
                write!(f, "session {session:?} failed: {reason}")
            }
            Self::NotFound { kind, id } => {
                write!(f, "{kind} not found: {id}")
            }
            Self::NodeIdentityUnavailable { reason } => {
                write!(f, "node identity unavailable: {reason}")
            }
            Self::PersistenceFailed { path, reason } => {
                write!(f, "persistence failed for {path}: {reason}")
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

// ---------- Unified Routing (DESIGN.md §6.4) ----------

/// 统一路由决策：Clash TUN（规则选出口）与 EasyTier TUN（mesh 转发）的
/// 融合抽象。规则引擎输出此类型，投影层消费。
///
/// 长远设计：`Egress { peer: "self" }` 即 Clash 的 DIRECT——本地直连与
/// 经国外节点出口走同一套 NAT 代码，只是 peer 不同。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    /// 虚拟子网内：纯转发，对端注入 TUN。
    MeshPeer { peer: String },
    /// 去互联网：该节点做 NAT 出口（peer 可为 "self"）。
    Egress { peer: String },
    /// 拒绝。
    Drop,
}

/// 路由请求的输入。为 P1 预留 `domain` 字段（DNS 劫持填充），P0 为 None。
#[derive(Debug)]
pub struct RouteRequest<'a> {
    /// 原始 IP 包。
    pub packet: &'a [u8],
    /// 域名（P0 为 None；P1 由 DNS 劫持提供）。
    pub domain: Option<&'a str>,
}

/// 规则引擎 trait：输入路由请求，输出统一路由决策。
///
/// P0 由 `SimpleRuleEngine`（IP/CIDR/端口）实现；P1+ 可替换为完整版
/// （域名/geoip/进程），trait 签名不变。
pub trait RuleEngine: Send + Sync {
    fn decide(&self, req: &RouteRequest) -> RouteTarget;
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

    // ---------- N2 P0-1：持久基座＋身份 ----------

    #[test]
    fn resource_name_validation() {
        assert!(ResourceName::new("dev-web_1").is_ok());
        assert_eq!(ResourceName::new(""), Err(ResourceNameError::Empty));
        assert_eq!(
            ResourceName::new("bad name"),
            Err(ResourceNameError::InvalidChar(' '))
        );
        assert_eq!(
            ResourceName::new("a/b"),
            Err(ResourceNameError::InvalidChar('/'))
        );
        assert_eq!(
            ResourceName::new("x".repeat(129)),
            Err(ResourceNameError::TooLong)
        );
        assert_eq!(ResourceName::new("ws1").unwrap().as_str(), "ws1");
    }

    #[test]
    fn resource_ref_display_kind_not_in_address() {
        // D2：kind 不进地址（目录属性）；地址只有 workspace/name。
        let r = ResourceRef::new(
            WorkspaceId::new("default"),
            ResourceName::new("dev-web").unwrap(),
        );
        assert_eq!(r.to_string(), "default/dev-web");
        assert_eq!(ResourceKind::Service.as_str(), "service");
    }

    #[test]
    fn deny_reason_codes_are_stable() {
        // 审计 / JSON error.deny 的机器可读名冻结。
        assert_eq!(DenyReason::NoSuchGrant.code(), "NoSuchGrant");
        assert_eq!(DenyReason::Revoked.code(), "Revoked");
        assert_eq!(
            DenyReason::Expired {
                not_after: 100,
                now: 200
            }
            .code(),
            "Expired"
        );
        let d = AuthorizationDecision::Deny(DenyReason::NoSuchGrant);
        assert!(!d.is_allow());
        assert_eq!(d.to_string(), "deny(NoSuchGrant)");
        assert!(AuthorizationDecision::Allow.is_allow());
    }

    #[test]
    fn new_nexus_error_variants_dispositions() {
        let err = NexusError::NotFound {
            kind: "session".into(),
            id: "s9".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Abort);
        assert_eq!(err.to_string(), "session not found: s9");

        let err = NexusError::NodeIdentityUnavailable {
            reason: "run `nexus node init` first".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Abort);

        let err = NexusError::PersistenceFailed {
            path: "/x/grants".into(),
            reason: "io error".into(),
        };
        assert_eq!(err.disposition(), FailureDisposition::Escalate);
    }
}
