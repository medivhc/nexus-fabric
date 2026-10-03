//! nexus-session
//!
//! 管理 Plan 的运行生命周期、Replan、Structured Concurrency、LifecyclePhase 与 TerminalOutcome。
//!
//! 本 crate 是 Portable Core：提供纯同步的 Owner 状态机与协作取消原语，不依赖 tokio。
//! 运行时接线（JoinSet + Reaper、异步 Worker）由 domain-runtime 层（network/service/workspace/compute）
//! 在引入异步运行时后完成，但 `TerminalOutcome` 唯一写入者必须是本模块的 `SessionOwner`。
//!
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nexus_domain::{
    LifecyclePhase, NexusError, PlanSnapshot, ProviderId, ResourceId, SessionId, SessionStatus,
    TerminalOutcome,
};

// ---------- 事件（Worker 只发事件，Owner 消费） ----------

/// Worker 上报的结构化事件（ARCHITECTURE §7：Worker 只能发送事件）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Session 开始运行。
    Started { session: SessionId },
    /// 生命周期阶段迁移。
    PhaseChanged {
        session: SessionId,
        phase: LifecyclePhase,
    },
    /// 运行进度。
    Progress { session: SessionId, detail: String },
    /// 收到协作取消请求。
    CancellationRequested { session: SessionId, reason: String },
    /// Connectivity 链路建立成功（Worker 上报，供 connectivity watch 观测）。
    ConnectivityEstablished { session: SessionId, locator: String },
    /// Connectivity 链路建立失败（Worker 上报；终态由 Owner 提交）。
    ConnectivityFailed {
        session: SessionId,
        locator: String,
        reason: String,
    },
    /// Owner 提交终态结果（commit-once 的唯一可见通道）。
    OutcomeCommitted {
        session: SessionId,
        outcome: TerminalOutcome,
    },
}

// ---------- 会话错误 ----------

/// Session 状态机的结构化错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// 已提交终态后再次提交。
    AlreadyTerminated {
        session: SessionId,
        outcome: TerminalOutcome,
    },
    /// 非法的生命周期迁移。
    InvalidPhaseTransition {
        from: LifecyclePhase,
        to: LifecyclePhase,
    },
    /// 尝试读取/使用尚未提交的终态。
    NotTerminated { session: SessionId },
    /// 运行被取消（供 Worker 感知）。
    Cancelled { session: SessionId, reason: String },
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyTerminated { session, outcome } => {
                write!(f, "session {session:?} already terminated with {outcome}")
            }
            Self::InvalidPhaseTransition { from, to } => {
                write!(f, "invalid phase transition: {from:?} -> {to:?}")
            }
            Self::NotTerminated { session } => {
                write!(f, "session {session:?} has no committed terminal outcome")
            }
            Self::Cancelled { session, reason } => {
                write!(f, "session {session:?} cancelled: {reason}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

// ---------- 协作取消原语（std 实现，Portable） ----------

/// 协作取消令牌：`cancel()` 置位，Worker 通过 `is_cancelled()` 轮询。
/// 仅表达"请求停止"，不强制中断。
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// 创建未取消的令牌。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 是否已被请求取消。
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// 请求取消。返回 `true` 表示本次是首次置位，`false` 表示此前已取消。
    pub fn cancel(&self) -> bool {
        !self.0.swap(true, Ordering::AcqRel)
    }
}

/// 所有权失效保护：`AbortOnDropHandle` 被 drop 时自动请求取消，
/// 防止 Owner 消失后任务继续运行（ARCHITECTURE §7 AbortOnDropHandle）。
#[derive(Debug)]
pub struct AbortOnDropHandle(CancelToken);

impl AbortOnDropHandle {
    /// 包装一个取消令牌；drop 时自动 `cancel()`。
    #[must_use]
    pub fn new(token: CancelToken) -> Self {
        Self(token)
    }

    /// 访问底层取消令牌。
    #[must_use]
    pub fn token(&self) -> &CancelToken {
        &self.0
    }
}

impl Drop for AbortOnDropHandle {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

// ---------- Owner 状态机（TerminalOutcome 唯一写入者） ----------

/// Session Owner 状态机。
///
/// 不变量（PRODUCT §6 / ARCHITECTURE §7）：
/// - `TerminalOutcome` 与 `LifecyclePhase` 双轨分离；
/// - `Completed / Failed / Cancelled` 只提交一次（`commit_outcome` 唯一入口）；
/// - Worker 只发送事件，Owner 唯一提交 Outcome；
/// - Outcome 确定后 phase 仍可继续迁移（cleanup），最终到达 `Disposed`。
#[derive(Debug)]
pub struct SessionOwner {
    id: SessionId,
    phase: LifecyclePhase,
    outcome: Option<TerminalOutcome>,
    events: Vec<SessionEvent>,
}

impl SessionOwner {
    /// 新建 Session，初始 phase = `Allocating`，无已提交 Outcome。
    #[must_use]
    pub fn new(id: SessionId) -> Self {
        Self {
            id: id.clone(),
            phase: LifecyclePhase::Allocating,
            outcome: None,
            events: vec![SessionEvent::Started { session: id }],
        }
    }

    /// Session 标识。
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// 当前生命周期阶段。
    #[must_use]
    pub fn phase(&self) -> LifecyclePhase {
        self.phase.clone()
    }

    /// 已提交的终态结果；`None` 表示尚未提交。
    #[must_use]
    pub fn committed_outcome(&self) -> Option<TerminalOutcome> {
        self.outcome.clone()
    }

    /// 双轨状态视图：未提交时 outcome 为 `Unfinished`。
    #[must_use]
    pub fn status(&self) -> SessionStatus {
        SessionStatus {
            phase: self.phase.clone(),
            outcome: self.outcome.clone().unwrap_or(TerminalOutcome::Unfinished),
        }
    }

    /// 事件历史（Worker 事件 + Owner 提交记录）。
    #[must_use]
    pub fn events(&self) -> &[SessionEvent] {
        &self.events
    }

    /// 生命周期迁移（合法迁移表）：
    /// `Allocating -> Active | Disposed`；`Active -> Draining | Disposed`；`Draining -> Disposed`。
    ///
    /// 已到达 `Disposed` 后禁止任何迁移；已提交 Outcome 不阻止迁移
    /// （Outcome 确定后仍可执行 cleanup 到 `Disposed`）。
    pub fn transition_phase(&mut self, to: LifecyclePhase) -> Result<(), SessionError> {
        let allowed = matches!(
            (self.phase.clone(), &to),
            (LifecyclePhase::Allocating, LifecyclePhase::Active)
                | (LifecyclePhase::Allocating, LifecyclePhase::Disposed)
                | (LifecyclePhase::Active, LifecyclePhase::Draining)
                | (LifecyclePhase::Active, LifecyclePhase::Disposed)
                | (LifecyclePhase::Draining, LifecyclePhase::Disposed)
        );
        if !allowed {
            return Err(SessionError::InvalidPhaseTransition {
                from: self.phase.clone(),
                to,
            });
        }
        self.phase = to.clone();
        self.events.push(SessionEvent::PhaseChanged {
            session: self.id.clone(),
            phase: to,
        });
        Ok(())
    }

    /// 提交终态结果（唯一写入入口，commit-once 守卫）。
    ///
    /// 规则：
    /// - `TerminalOutcome::Unfinished` 不允许提交；
    /// - 已提交过任何终态则返回 `AlreadyTerminated`，且状态保持不变；
    /// - 成功后记录 `OutcomeCommitted` 事件。
    pub fn commit_outcome(&mut self, outcome: TerminalOutcome) -> Result<(), SessionError> {
        if outcome == TerminalOutcome::Unfinished {
            return Err(SessionError::InvalidPhaseTransition {
                from: self.phase.clone(),
                to: LifecyclePhase::Disposed,
            });
        }
        if let Some(existing) = &self.outcome {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: existing.clone(),
            });
        }
        self.outcome = Some(outcome.clone());
        self.events.push(SessionEvent::OutcomeCommitted {
            session: self.id.clone(),
            outcome,
        });
        Ok(())
    }

    /// 记录协作取消请求（只记事件，不直接提交 Outcome；
    /// 提交 `Cancelled` 由 Owner 决策并调用 `commit_outcome`）。
    ///
    /// 门控（B1 amendment 2026-10-03）：已提交终态或 phase 已到 `Disposed` 后拒绝记录；
    /// Disposed 是终点 lifecycle phase，之后事件历史不可再变。
    /// `AlreadyTerminated` 在此复用"生命周期已终结"语义：`{phase: Disposed, outcome: Unfinished}`
    /// 时其 `outcome` 字段填 `TerminalOutcome::Unfinished`。
    ///
    /// 返回 `Ok(true)` 表示本次是首次取消请求。
    pub fn request_cancellation(&mut self, reason: String) -> Result<bool, SessionError> {
        if self.outcome.is_some() {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: self.outcome.clone().expect("checked some"),
            });
        }
        if self.phase == LifecyclePhase::Disposed {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: TerminalOutcome::Unfinished,
            });
        }
        let already_requested = self
            .events
            .iter()
            .any(|e| matches!(e, SessionEvent::CancellationRequested { .. }));
        if !already_requested {
            self.events.push(SessionEvent::CancellationRequested {
                session: self.id.clone(),
                reason,
            });
        }
        Ok(!already_requested)
    }

    /// 记录 Connectivity 链路建立成功（Worker 上报事件；不写 Outcome）。
    ///
    /// 已提交终态或 phase 已到 `Disposed` 后拒绝记录（Owner 状态不可再变；
    /// 门控语义见 `request_cancellation` 的 B1 amendment 注释）。
    pub fn record_connectivity_established(&mut self, locator: String) -> Result<(), SessionError> {
        if self.outcome.is_some() {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: self.outcome.clone().expect("checked some"),
            });
        }
        if self.phase == LifecyclePhase::Disposed {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: TerminalOutcome::Unfinished,
            });
        }
        self.events.push(SessionEvent::ConnectivityEstablished {
            session: self.id.clone(),
            locator,
        });
        Ok(())
    }

    /// 记录 Connectivity 链路建立失败（Worker 上报事件；终态由 Owner 决策提交）。
    ///
    /// 门控同 `record_connectivity_established`（B1 amendment 2026-10-03）。
    pub fn record_connectivity_failed(
        &mut self,
        locator: String,
        reason: String,
    ) -> Result<(), SessionError> {
        if self.outcome.is_some() {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: self.outcome.clone().expect("checked some"),
            });
        }
        if self.phase == LifecyclePhase::Disposed {
            return Err(SessionError::AlreadyTerminated {
                session: self.id.clone(),
                outcome: TerminalOutcome::Unfinished,
            });
        }
        self.events.push(SessionEvent::ConnectivityFailed {
            session: self.id.clone(),
            locator,
            reason,
        });
        Ok(())
    }

    /// 从持久记录重建 Owner（仅 `reconcile_session_records` 内部使用）：
    /// 恢复 phase 与已提交 outcome，不产生 `Started` 事件；
    /// 后续 `transition_phase` 调用仍受迁移表权威校验。
    fn from_record(record: &SessionRecord) -> Self {
        Self {
            id: record.session.clone(),
            phase: record.phase.clone(),
            outcome: match &record.outcome {
                TerminalOutcome::Unfinished => None,
                committed => Some(committed.clone()),
            },
            events: Vec::new(),
        }
    }
}

// ---------- 便携错误转换（供 domain-runtime 使用） ----------

impl From<SessionError> for NexusError {
    fn from(value: SessionError) -> Self {
        match value {
            SessionError::AlreadyTerminated { outcome, .. } => match outcome {
                TerminalOutcome::Failed(err) => err,
                _ => Self::Internal {
                    message: "session already terminated".into(),
                },
            },
            SessionError::InvalidPhaseTransition { from, to } => Self::Internal {
                message: format!("invalid session phase transition {from:?} -> {to:?}"),
            },
            SessionError::NotTerminated { session } => Self::SessionFailed {
                session,
                reason: "session has no committed terminal outcome".into(),
            },
            SessionError::Cancelled { session, reason } => Self::SessionFailed {
                session,
                reason: format!("session cancelled: {reason}"),
            },
        }
    }
}

// ---------- 会话持久记录与冷启动 Reconcile ----------

/// Session 持久记录：冷启动 reconcile 的最小持久状态（进程死亡后可恢复）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub session: SessionId,
    pub phase: LifecyclePhase,
    pub outcome: TerminalOutcome,
    /// D3（N2 P0-3）：Session 内嵌 `PlanSnapshot{plan, decision_trace}`。
    /// Plan 可重算、不独立持久化；快照随 Session 记录保存，供
    /// `plan explain <session-id>` 返回"历史真实记录"。
    /// P0-4 的 SessionManager 在建 Session 时填充；`None` = 建连时未做规划
    /// （如 P0-3 之前的旧记录）。
    pub plan_snapshot: Option<PlanSnapshot>,
    /// P1-3：客户端断开时刻（unix 秒）；`None` = 未断开/已重附着。
    ///
    /// 必须落盘：`sweep_detached` 与冷启动 reconcile 按"断开时刻 + attach window"
    /// 判定；只存内存时重启即丢，断开会话永不收敛、泄漏。
    /// 旧记录缺此字段按 `None` 处理（向后兼容）。
    pub detached_at_unix: Option<u64>,
}

/// 会话记录存储契约（Portable；由 Composition Root 注入实现，
/// 如内存/文件/安全存储，参见 `nexus-storage` 的 ContentStore 注入模式）。
///
/// `Send`：D1 要求 daemon 内唯一的 `SessionManager` 被后台终态清扫线程
/// （`sweep_detached`）与 LocalAPI 请求线程共享，实现必须可跨线程移动。
pub trait SessionRecordStore: Send {
    fn load(&self) -> Result<Vec<SessionRecord>, String>;
    fn save(&mut self, record: &SessionRecord) -> Result<(), String>;
}

/// 冷启动会话记录 reconcile 的结构化结果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionReconcileReport {
    /// 检查的记录数。
    pub records_checked: usize,
    /// 分类为孤儿的会话数（进程死亡且未达终态）。
    pub orphans_classified: usize,
}

/// 会话记录 reconcile 的结构化失败（MODULE.md：不以日志文本代替错误类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionReconcileError {
    /// 底层记录存储失败。
    Store { reason: String },
    /// 会话状态机失败。
    Session(SessionError),
}

impl core::fmt::Display for SessionReconcileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store { reason } => write!(f, "session record store failure: {reason}"),
            Self::Session(err) => write!(f, "session reconcile failed: {err}"),
        }
    }
}

impl std::error::Error for SessionReconcileError {}

impl From<SessionError> for SessionReconcileError {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

/// 未达终态记录的冷启动分类（§16.3 断开≠Failed；D7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnfinishedClass {
    /// 无本进程存活 Owner 且不在重附着窗口内 → 孤儿，提交 `Failed`。
    OrphanFailed,
    /// 已断开且超出重附着窗口 → 提交 `Cancelled(ClientDetached)`。
    DetachedCancelled,
    /// 进程内仍有存活 Owner，或断开仍在窗口内 → 不分类（可继续/可重附着）。
    KeepAlive,
}

/// 冷启动 reconcile 会话记录（AGENTS.md §15 Crash Consistency：幂等、孤儿分类）。
///
/// 规则（B2 amendment 2026-10-03，phase 感知）：
/// - `phase == Disposed` → 跳过（cleanup 已完成；含 `{Disposed, Unfinished}` 不可达路径，
///   B1 amendment：永不判为孤儿、永不覆盖重写）；
/// - 已提交终态但 `phase != Disposed`（进程在 `commit_outcome` 之后、
///   `transition_phase(Disposed)` 之前崩溃）→ 重放 cleanup 迁移到 `Disposed` 并回写，
///   outcome 原样保留，**不重新 commit**（Owner 唯一写入者原则不变），不计入孤儿；
/// - 未达终态且进程存活 → 会话可继续，不分类；
/// - 未达终态、进程死亡且 `phase != Disposed` → 孤儿会话：经 `SessionOwner` 恰一次提交
///   `Failed`，清理到 `Disposed`，并回写记录（再次 reconcile 幂等，不会重复提交）。
///
/// 这是**不带时间**的入口（本 crate 无时钟，portable）：等价于"断开即超窗"的语义，
/// 即任何带断开标记的未达终态记录都会被判 `Failed`。生产（daemon boot）应调用
/// [`reconcile_session_records_at`]，用真实 attach window 把断开超窗的会话归为
/// `Cancelled(ClientDetached)`（D7：断开≠Failed）。
pub fn reconcile_session_records<S: SessionRecordStore>(
    store: &mut S,
    process_alive: bool,
) -> Result<SessionReconcileReport, SessionReconcileError> {
    reconcile_session_records_with(store, process_alive, None)
}

/// 时间感知的冷启动 reconcile（生产入口，P1-1）：未达终态记录按
/// **attach window ＋ 存活判断**分类，而不是"一律判 Failed"。
///
/// 分类（§16.3 / D7）：
/// - 进程内仍有存活 Owner（`process_alive`）→ 不分类；
/// - 有 `detached_at_unix` 且 `now - detached >= attach_window` →
///   `Cancelled(ClientDetached)`（客户端早就走了，不是崩溃），不计入孤儿；
/// - 有 `detached_at_unix` 但仍在窗口内 → **不分类**（客户端可重附着，PRODUCT §16.3）；
/// - 无断开标记（`detached_at_unix == None`）且无存活 Owner → 真孤儿，
///   恰一次提交 `Failed`。
///
/// 幂等：终态记录不回退；再次调用不再分类。
pub fn reconcile_session_records_at<S: SessionRecordStore>(
    store: &mut S,
    process_alive: bool,
    now_unix: u64,
    attach_window_secs: u64,
) -> Result<SessionReconcileReport, SessionReconcileError> {
    reconcile_session_records_with(store, process_alive, Some((now_unix, attach_window_secs)))
}

/// reconcile 内核：`window = Some((now, window))` 时启用断开感知分类。
fn reconcile_session_records_with<S: SessionRecordStore>(
    store: &mut S,
    process_alive: bool,
    window: Option<(u64, u64)>,
) -> Result<SessionReconcileReport, SessionReconcileError> {
    let records = store
        .load()
        .map_err(|reason| SessionReconcileError::Store { reason })?;
    let mut report = SessionReconcileReport {
        records_checked: records.len(),
        orphans_classified: 0,
    };
    for record in records {
        // B1 连带：phase 已到 Disposed 的记录无需任何处置。
        if record.phase == LifecyclePhase::Disposed {
            continue;
        }
        let terminal = matches!(
            &record.outcome,
            TerminalOutcome::Completed | TerminalOutcome::Failed(_) | TerminalOutcome::Cancelled
        );
        if terminal {
            // B2：终态但 phase 未到 Disposed → 重放 cleanup 迁移到 Disposed 并回写；
            // outcome 已终态，不重新 commit。
            let mut owner = SessionOwner::from_record(&record);
            let cleanup: &[LifecyclePhase] = match record.phase {
                LifecyclePhase::Allocating => &[LifecyclePhase::Disposed],
                LifecyclePhase::Active => &[LifecyclePhase::Draining, LifecyclePhase::Disposed],
                LifecyclePhase::Draining => &[LifecyclePhase::Disposed],
                // 上方已对 Disposed continue；此分支不可达，留空保穷尽匹配。
                LifecyclePhase::Disposed => &[],
            };
            for next in cleanup {
                owner
                    .transition_phase(next.clone())
                    .map_err(SessionReconcileError::from)?;
            }
            debug_assert_eq!(owner.phase(), LifecyclePhase::Disposed);
            store
                .save(&SessionRecord {
                    session: record.session,
                    phase: LifecyclePhase::Disposed,
                    outcome: record.outcome,
                    // 快照随记录回写（reconcile 不重算 Plan，只搬运）。
                    plan_snapshot: record.plan_snapshot,
                    detached_at_unix: record.detached_at_unix,
                })
                .map_err(|reason| SessionReconcileError::Store { reason })?;
            continue;
        }
        let class = classify_unfinished(record.detached_at_unix, process_alive, window);
        if class == UnfinishedClass::KeepAlive {
            continue;
        }
        // 终态恰一次提交（Owner 是 Outcome 唯一写入者）＋ cleanup 到 Disposed（§14）。
        let mut owner = SessionOwner::from_record(&record);
        owner
            .commit_outcome(match class {
                // 断开超窗：客户端主动离开，不是崩溃（§16.3 断开≠Failed）。
                UnfinishedClass::DetachedCancelled => TerminalOutcome::Cancelled,
                UnfinishedClass::OrphanFailed => TerminalOutcome::Failed(NexusError::Internal {
                    message: "process crashed; session orphaned during cold start".into(),
                }),
                UnfinishedClass::KeepAlive => unreachable!("caller filtered KeepAlive"),
            })
            .map_err(SessionReconcileError::from)?;
        let cleanup: &[LifecyclePhase] = match owner.phase() {
            LifecyclePhase::Allocating => &[LifecyclePhase::Disposed],
            LifecyclePhase::Active => &[LifecyclePhase::Draining, LifecyclePhase::Disposed],
            LifecyclePhase::Draining => &[LifecyclePhase::Disposed],
            LifecyclePhase::Disposed => &[],
        };
        for next in cleanup {
            owner
                .transition_phase(next.clone())
                .map_err(SessionReconcileError::from)?;
        }
        let status = owner.status();
        store
            .save(&SessionRecord {
                session: record.session,
                phase: status.phase,
                outcome: status.outcome,
                plan_snapshot: record.plan_snapshot,
                detached_at_unix: record.detached_at_unix,
            })
            .map_err(|reason| SessionReconcileError::Store { reason })?;
        if class == UnfinishedClass::OrphanFailed {
            report.orphans_classified += 1;
        }
    }
    Ok(report)
}

/// 未达终态记录的分类（纯函数，可单测）。
fn classify_unfinished(
    detached_at_unix: Option<u64>,
    process_alive: bool,
    window: Option<(u64, u64)>,
) -> UnfinishedClass {
    if process_alive {
        return UnfinishedClass::KeepAlive;
    }
    let Some(detached_at) = detached_at_unix else {
        return UnfinishedClass::OrphanFailed;
    };
    match window {
        // 无时间基准（旧入口）：断开即视为已超窗 → 真孤儿 Failed。
        None => UnfinishedClass::OrphanFailed,
        Some((now, window_secs)) => {
            if now.saturating_sub(detached_at) >= window_secs {
                UnfinishedClass::DetachedCancelled
            } else {
                UnfinishedClass::KeepAlive
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionOwner {
        SessionOwner::new(SessionId("s1".into()))
    }

    #[test]
    fn legal_phase_chain() {
        let mut s = session();
        assert_eq!(s.phase(), LifecyclePhase::Allocating);
        s.transition_phase(LifecyclePhase::Active).unwrap();
        s.transition_phase(LifecyclePhase::Draining).unwrap();
        s.transition_phase(LifecyclePhase::Disposed).unwrap();
        assert_eq!(s.phase(), LifecyclePhase::Disposed);
    }

    #[test]
    fn illegal_phase_transition_rejected() {
        let mut s = session();
        s.transition_phase(LifecyclePhase::Active).unwrap();
        let err = s.transition_phase(LifecyclePhase::Allocating);
        assert!(matches!(
            err,
            Err(SessionError::InvalidPhaseTransition {
                from: LifecyclePhase::Active,
                to: LifecyclePhase::Allocating,
            })
        ));
    }

    #[test]
    fn outcome_committed_exactly_once() {
        let mut s = session();
        assert_eq!(s.committed_outcome(), None);
        s.transition_phase(LifecyclePhase::Active).unwrap();
        s.commit_outcome(TerminalOutcome::Completed).unwrap();
        assert_eq!(s.committed_outcome(), Some(TerminalOutcome::Completed));

        let err = s.commit_outcome(TerminalOutcome::Completed);
        assert!(matches!(err, Err(SessionError::AlreadyTerminated { .. })));
        // 状态不被破坏
        assert_eq!(s.committed_outcome(), Some(TerminalOutcome::Completed));
    }

    #[test]
    fn unfinished_outcome_cannot_be_committed() {
        let mut s = session();
        let err = s.commit_outcome(TerminalOutcome::Unfinished);
        assert!(err.is_err());
        assert_eq!(s.committed_outcome(), None);
    }

    #[test]
    fn status_reports_unfinished_before_commit() {
        let mut s = session();
        s.transition_phase(LifecyclePhase::Active).unwrap();
        let status = s.status();
        assert_eq!(status.outcome, TerminalOutcome::Unfinished);
        assert_eq!(status.phase, LifecyclePhase::Active);
    }

    #[test]
    fn outcome_committed_then_cleanup_to_disposed() {
        let mut s = session();
        s.transition_phase(LifecyclePhase::Active).unwrap();
        s.commit_outcome(TerminalOutcome::Failed(NexusError::DnsResolutionFailed {
            name: "x".into(),
        }))
        .unwrap();
        // Outcome 确定后仍可 cleanup 到 Disposed
        s.transition_phase(LifecyclePhase::Draining).unwrap();
        s.transition_phase(LifecyclePhase::Disposed).unwrap();
        assert_eq!(s.phase(), LifecyclePhase::Disposed);
        assert!(s.committed_outcome().is_some());
    }

    #[test]
    fn cancellation_request_records_event_once() {
        let mut s = session();
        assert!(s.request_cancellation("user abort".into()).unwrap());
        assert!(!s.request_cancellation("again".into()).unwrap());
        assert_eq!(
            s.events()
                .iter()
                .filter(|e| matches!(e, SessionEvent::CancellationRequested { .. }))
                .count(),
            1
        );
        // 提交取消终态
        s.commit_outcome(TerminalOutcome::Cancelled).unwrap();
        assert_eq!(s.committed_outcome(), Some(TerminalOutcome::Cancelled));
    }

    #[test]
    fn connectivity_events_recorded_without_touching_outcome() {
        let mut s = session();
        s.transition_phase(LifecyclePhase::Active).unwrap();
        s.record_connectivity_established("edge-a.exit".into())
            .unwrap();
        s.record_connectivity_failed("relay-b.exit".into(), "authentication required".into())
            .unwrap();
        assert!(
            s.committed_outcome().is_none(),
            "worker event must not commit outcome"
        );
        let est = s
            .events()
            .iter()
            .filter(|e| matches!(e, SessionEvent::ConnectivityEstablished { .. }))
            .count();
        let fail = s
            .events()
            .iter()
            .filter(|e| matches!(e, SessionEvent::ConnectivityFailed { .. }))
            .count();
        assert_eq!(est, 1);
        assert_eq!(fail, 1);
        // 终态提交后拒绝再记录。
        s.commit_outcome(TerminalOutcome::Failed(
            NexusError::ConnectivityEstablishmentFailed {
                provider: nexus_domain::ProviderId("p".into()),
                reason: "boom".into(),
            },
        ))
        .unwrap();
        assert!(s.record_connectivity_established("x".into()).is_err());
    }

    #[test]
    fn cancel_token_first_win() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        assert!(token.cancel());
        assert!(!token.cancel());
        assert!(token.is_cancelled());
    }

    #[test]
    fn abort_on_drop_cancels_token() {
        let token = CancelToken::new();
        {
            let _guard = AbortOnDropHandle::new(token.clone());
            assert!(!token.is_cancelled());
        }
        assert!(token.is_cancelled());
    }

    #[test]
    fn session_error_converts_to_nexus_error() {
        let err: NexusError = SessionError::NotTerminated {
            session: SessionId("s".into()),
        }
        .into();
        assert!(matches!(err, NexusError::SessionFailed { .. }));
    }

    // ---------- 会话记录冷启动 reconcile ----------

    /// 测试用内存记录存储（upsert 语义）。
    #[derive(Debug, Default)]
    struct MemRecordStore {
        records: Vec<SessionRecord>,
    }

    impl SessionRecordStore for MemRecordStore {
        fn load(&self) -> Result<Vec<SessionRecord>, String> {
            Ok(self.records.clone())
        }

        fn save(&mut self, record: &SessionRecord) -> Result<(), String> {
            if let Some(slot) = self
                .records
                .iter_mut()
                .find(|r| r.session == record.session)
            {
                *slot = record.clone();
            } else {
                self.records.push(record.clone());
            }
            Ok(())
        }
    }

    fn active_unfinished(session: &str) -> SessionRecord {
        SessionRecord {
            session: SessionId(session.into()),
            phase: LifecyclePhase::Active,
            outcome: TerminalOutcome::Unfinished,
            plan_snapshot: None,
            detached_at_unix: None,
        }
    }

    fn detached_unfinished(session: &str, at: u64) -> SessionRecord {
        SessionRecord {
            detached_at_unix: Some(at),
            ..active_unfinished(session)
        }
    }

    // ---- P1-1：生产 reconcile 入口用 attach window 分类（断开≠Failed） ----

    #[test]
    fn reconcile_at_keeps_detached_within_attach_window() {
        // 客户端断开但在窗口内：daemon 重启后必须保持 Active/Unfinished（可重附着），
        // 旧实现（传死值 false）会立刻判 Failed。
        let mut store = MemRecordStore {
            records: vec![detached_unfinished("s-window", 1000)],
        };
        let report =
            reconcile_session_records_at(&mut store, false, 1000 + 299, DEFAULT_ATTACH_WINDOW_SECS)
                .unwrap();
        assert_eq!(report.records_checked, 1);
        assert_eq!(report.orphans_classified, 0);
        assert_eq!(store.records[0].phase, LifecyclePhase::Active);
        assert_eq!(store.records[0].outcome, TerminalOutcome::Unfinished);
    }

    #[test]
    fn reconcile_at_classifies_detached_beyond_window_as_cancelled() {
        // 断开超窗 → Cancelled（不是 Failed）：断开≠Failed（§16.3 / D7）。
        let mut store = MemRecordStore {
            records: vec![detached_unfinished("s-gone", 1000)],
        };
        let report = reconcile_session_records_at(
            &mut store,
            false,
            1000 + DEFAULT_ATTACH_WINDOW_SECS,
            DEFAULT_ATTACH_WINDOW_SECS,
        )
        .unwrap();
        // 不是崩溃：不算孤儿。
        assert_eq!(report.orphans_classified, 0);
        let rec = &store.records[0];
        assert_eq!(rec.outcome, TerminalOutcome::Cancelled);
        assert_eq!(rec.phase, LifecyclePhase::Disposed);
        // 幂等。
        let again =
            reconcile_session_records_at(&mut store, false, 9999, DEFAULT_ATTACH_WINDOW_SECS)
                .unwrap();
        assert_eq!(again.orphans_classified, 0);
        assert_eq!(store.records[0].outcome, TerminalOutcome::Cancelled);
    }

    #[test]
    fn reconcile_at_still_classifies_true_orphan_as_failed() {
        // 无断开标记 + 无存活 Owner → 真崩溃，仍判 Failed。
        let mut store = MemRecordStore {
            records: vec![active_unfinished("s-orphan2")],
        };
        let report =
            reconcile_session_records_at(&mut store, false, 5000, DEFAULT_ATTACH_WINDOW_SECS)
                .unwrap();
        assert_eq!(report.orphans_classified, 1);
        assert!(matches!(
            store.records[0].outcome,
            TerminalOutcome::Failed(_)
        ));
    }

    #[test]
    fn reconcile_at_respects_process_alive_over_detach_marker() {
        // 进程内仍有存活 Owner → 一律不分类（哪怕有旧断开标记）。
        let mut store = MemRecordStore {
            records: vec![detached_unfinished("s-alive2", 1)],
        };
        let report =
            reconcile_session_records_at(&mut store, true, 999_999, DEFAULT_ATTACH_WINDOW_SECS)
                .unwrap();
        assert_eq!(report.orphans_classified, 0);
        assert_eq!(store.records[0].outcome, TerminalOutcome::Unfinished);
    }

    #[test]
    fn classify_unfinished_matrix() {
        // 纯函数分类矩阵（顺序无关的穷举）。
        use UnfinishedClass::{DetachedCancelled, KeepAlive, OrphanFailed};
        // 无断开标记：无存活 Owner → 孤儿；有 → 保留。
        assert_eq!(
            classify_unfinished(None, false, Some((0, 10))),
            OrphanFailed
        );
        assert_eq!(classify_unfinished(None, true, Some((0, 10))), KeepAlive);
        // 有断开标记：窗口内保留、超窗 Cancelled。
        assert_eq!(
            classify_unfinished(Some(100), false, Some((109, 10))),
            KeepAlive
        );
        assert_eq!(
            classify_unfinished(Some(100), false, Some((110, 10))),
            DetachedCancelled
        );
        // 无时间基准（旧入口）：断开即孤儿。
        assert_eq!(classify_unfinished(Some(100), false, None), OrphanFailed);
    }

    #[test]
    fn reconcile_preserves_detached_marker_on_terminal_replay() {
        // 终态 cleanup 重放必须原样搬运 detached_at_unix（不回写 None）。
        let mut store = MemRecordStore {
            records: vec![SessionRecord {
                phase: LifecyclePhase::Active,
                outcome: TerminalOutcome::Cancelled,
                detached_at_unix: Some(4242),
                ..active_unfinished("s-keep")
            }],
        };
        reconcile_session_records_at(&mut store, false, 9999, DEFAULT_ATTACH_WINDOW_SECS).unwrap();
        assert_eq!(store.records[0].phase, LifecyclePhase::Disposed);
        assert_eq!(store.records[0].detached_at_unix, Some(4242));
    }

    #[test]
    fn orphan_session_classified_and_committed_once() {
        let mut store = MemRecordStore {
            records: vec![active_unfinished("s-orphan")],
        };
        let report = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report.records_checked, 1);
        assert_eq!(report.orphans_classified, 1);

        let rec = &store.records[0];
        assert_eq!(rec.phase, LifecyclePhase::Disposed);
        assert!(matches!(rec.outcome, TerminalOutcome::Failed(_)));

        // 幂等：再次 reconcile 不再分类、不重复提交。
        let report2 = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report2.orphans_classified, 0);
        assert!(matches!(
            store.records[0].outcome,
            TerminalOutcome::Failed(_)
        ));
    }

    #[test]
    fn process_alive_keeps_unfinished_session() {
        let mut store = MemRecordStore {
            records: vec![active_unfinished("s-alive")],
        };
        let report = reconcile_session_records(&mut store, true).unwrap();
        assert_eq!(report.orphans_classified, 0);
        assert_eq!(store.records[0].phase, LifecyclePhase::Active);
        assert_eq!(store.records[0].outcome, TerminalOutcome::Unfinished);
    }

    #[test]
    fn already_terminal_record_is_skipped() {
        let mut store = MemRecordStore {
            records: vec![SessionRecord {
                session: SessionId("s-done".into()),
                phase: LifecyclePhase::Disposed,
                outcome: TerminalOutcome::Completed,
                plan_snapshot: None,
                detached_at_unix: None,
            }],
        };
        let report = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report.orphans_classified, 0);
        assert_eq!(store.records[0].outcome, TerminalOutcome::Completed);
    }

    // ---------- B1: Disposed phase 拒绝追加事件（Red Evidence，先失败后修） ----------

    #[test]
    fn disposed_phase_rejects_event_recording() {
        let mut s = session();
        // Allocating -> Disposed 直接迁移，outcome 仍为 None。
        s.transition_phase(LifecyclePhase::Disposed).unwrap();
        assert_eq!(s.phase(), LifecyclePhase::Disposed);
        assert_eq!(s.committed_outcome(), None);

        let err = s.request_cancellation("late".into());
        assert!(
            matches!(err, Err(SessionError::AlreadyTerminated { .. })),
            "request_cancellation after Disposed must fail, got {err:?}"
        );
        let err = s.record_connectivity_established("edge-a.exit".into());
        assert!(
            matches!(err, Err(SessionError::AlreadyTerminated { .. })),
            "record_connectivity_established after Disposed must fail, got {err:?}"
        );
        let err = s.record_connectivity_failed("edge-a.exit".into(), "late".into());
        assert!(
            matches!(err, Err(SessionError::AlreadyTerminated { .. })),
            "record_connectivity_failed after Disposed must fail, got {err:?}"
        );
        // Disposed 之后事件历史冻结：只有 Started + PhaseChanged。
        assert_eq!(s.events().len(), 2);
    }

    #[test]
    fn disposed_with_terminal_outcome_reports_real_outcome() {
        let mut s = session();
        s.transition_phase(LifecyclePhase::Active).unwrap();
        s.commit_outcome(TerminalOutcome::Completed).unwrap();
        s.transition_phase(LifecyclePhase::Disposed).unwrap();
        // outcome 门控先触发，携带真实 outcome。
        let err = s.request_cancellation("late".into());
        assert!(
            matches!(
                err,
                Err(SessionError::AlreadyTerminated {
                    outcome: TerminalOutcome::Completed,
                    ..
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn reconcile_skips_disposed_unfinished_record_without_overwrite() {
        // {phase: Disposed, outcome: Unfinished}：修复后的 Owner API 已无法产生；
        // reconcile 不得再把它判为孤儿并覆盖重写为 Failed。
        let mut store = MemRecordStore {
            records: vec![SessionRecord {
                session: SessionId("s-disposed-unfinished".into()),
                phase: LifecyclePhase::Disposed,
                outcome: TerminalOutcome::Unfinished,
                plan_snapshot: None,
                detached_at_unix: None,
            }],
        };
        let report = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report.orphans_classified, 0);
        assert_eq!(store.records[0].phase, LifecyclePhase::Disposed);
        assert_eq!(store.records[0].outcome, TerminalOutcome::Unfinished);
    }

    // ---------- B2: 终态但 phase≠Disposed 的 reconcile 重放 cleanup ----------

    #[test]
    fn reconcile_replays_cleanup_for_terminal_not_disposed() {
        let mut store = MemRecordStore {
            records: vec![
                SessionRecord {
                    session: SessionId("s-active".into()),
                    phase: LifecyclePhase::Active,
                    outcome: TerminalOutcome::Completed,
                    plan_snapshot: None,
                    detached_at_unix: None,
                },
                SessionRecord {
                    session: SessionId("s-draining".into()),
                    phase: LifecyclePhase::Draining,
                    outcome: TerminalOutcome::Cancelled,
                    plan_snapshot: None,
                    detached_at_unix: None,
                },
                SessionRecord {
                    session: SessionId("s-alloc".into()),
                    phase: LifecyclePhase::Allocating,
                    outcome: TerminalOutcome::Failed(NexusError::Internal {
                        message: "boom".into(),
                    }),
                    plan_snapshot: None,
                    detached_at_unix: None,
                },
            ],
        };
        let report = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report.records_checked, 3);
        // 终态记录不是孤儿：不计入 orphans_classified。
        assert_eq!(report.orphans_classified, 0);
        for rec in &store.records {
            assert_eq!(
                rec.phase,
                LifecyclePhase::Disposed,
                "terminal record {:?} must converge to Disposed",
                rec.session.0
            );
        }
        // outcome 原样保留：Owner 唯一写入者原则。
        assert_eq!(store.records[0].outcome, TerminalOutcome::Completed);
        assert_eq!(store.records[1].outcome, TerminalOutcome::Cancelled);
        assert!(matches!(
            store.records[2].outcome,
            TerminalOutcome::Failed(NexusError::Internal { .. })
        ));
    }

    #[test]
    fn reconcile_terminal_cleanup_is_idempotent() {
        let mut store = MemRecordStore {
            records: vec![SessionRecord {
                session: SessionId("s-t".into()),
                phase: LifecyclePhase::Active,
                outcome: TerminalOutcome::Completed,
                plan_snapshot: None,
                detached_at_unix: None,
            }],
        };
        let r1 = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(r1.orphans_classified, 0);
        assert_eq!(store.records[0].phase, LifecyclePhase::Disposed);
        let snapshot = store.records.clone();
        let r2 = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(r2.orphans_classified, 0);
        assert_eq!(
            store.records, snapshot,
            "second reconcile must not touch anything"
        );
    }

    #[test]
    fn plan_snapshot_is_carried_not_recomputed() {
        // D3：Session 记录内嵌 PlanSnapshot；reconcile 回写时原样搬运、不重算。
        use nexus_domain::{
            ConsideredCandidate, DecisionTrace, Plan, PlanId, ProviderId, ResourceId,
        };
        let snapshot = PlanSnapshot {
            plan_id: PlanId("deadbeef00112233".into()),
            plan: Plan {
                resource_id: ResourceId("dev-svc".into()),
                provider_id: ProviderId("local-dev-1".into()),
                placement: "local".into(),
                path: vec!["127.0.0.1:8080".into()],
                execution_strategy: "direct".into(),
                extension: None,
            },
            decision_trace: DecisionTrace {
                considered: vec![ConsideredCandidate {
                    provider: ProviderId("local-dev-1".into()),
                    rejected_reason: None,
                    connectivity: None,
                    measurement: None,
                    score: Some(1_000),
                    score_breakdown: None,
                }],
                selected: ProviderId("local-dev-1".into()),
            },
        };
        let mut store = MemRecordStore {
            records: vec![SessionRecord {
                session: SessionId("sess-n2-e4-1".into()),
                phase: LifecyclePhase::Active,
                outcome: TerminalOutcome::Completed,
                plan_snapshot: Some(snapshot.clone()),
                detached_at_unix: None,
            }],
        };
        let report = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report.orphans_classified, 0);
        // 终态重放 cleanup 后快照仍在（搬运，非重算）。
        assert_eq!(store.records[0].plan_snapshot, Some(snapshot));
        assert_eq!(store.records[0].phase, LifecyclePhase::Disposed);
    }
}

// ============================================================================
// SessionManager（N2 P0-4，D1）：daemon 内唯一的 Session 生命周期 Owner
// ============================================================================
//
// D1 裁决：daemon 内全系统唯一的 SessionManager 持有全部资源 Session 生命周期；
// Session＝"一次 Resource 使用"而非"一次连接"；提供方侧只做 admission＋租约，
// 不做第二个领域 Session（两侧各自独立提交 TerminalOutcome，不做分布式共识）。
//
// 结构化并发（AGENTS.md §13）：SessionManager 是 Owner；每个 Session 持有一个
// `CancelToken`（`close()` 触发协作取消）；`TerminalOutcome` 唯一写入者仍是
// 每个 Session 的 `SessionOwner`（`commit_outcome` 唯一入口），SessionManager
// 只做编排、不直接写 outcome（§14 Exactly-One Terminal Outcome）。
//
// 终态语义（PRODUCT §16.3，D7 修正）：断开≠Failed。
// - 客户端断开 attach window 内 → 仍 Active（可重附着），outcome 保持 Unfinished；
// - 窗口外 → `Cancelled`（cancel reason `ClientDetached`）；
// - provider 消失 → `Failed(ProviderLost)`（明确失败才 Failed）；
// - 授权撤销 → `Cancelled`（cancel reason `Revoked`）。
// 连接丢失永不直接变为 Failed；只有明确失败才提交 Failed。

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

/// 默认重附着窗口（秒）：客户端断开后可重附着的时间。
/// P0 取值（风险项，见 synth §6）：P0-5 真机验证后调优。
pub const DEFAULT_ATTACH_WINDOW_SECS: u64 = 300;

/// 取消原因（`Cancelled` 的机器可读注解；`TerminalOutcome::Cancelled` 本身
/// 为 unit 变体，原因记在事件与视图中，不进 outcome 判别）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelReason {
    /// 用户/管理面主动关闭（`session close`）。
    UserClosed,
    /// 客户端断开超过重附着窗口。
    ClientDetached,
    /// 授权被撤销。
    Revoked,
}

impl CancelReason {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserClosed => "UserClosed",
            Self::ClientDetached => "ClientDetached",
            Self::Revoked => "Revoked",
        }
    }
}

/// SessionManager 的结构化错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionManagerError {
    /// 会话不存在。
    NotFound { session: SessionId },
    /// 会话已达终态（幂等关闭/重复提交时返回）。
    AlreadyTerminated {
        session: SessionId,
        outcome: TerminalOutcome,
    },
    /// 底层记录存储失败。
    Store { reason: String },
    /// 会话状态机失败。
    Session(SessionError),
}

impl core::fmt::Display for SessionManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound { session } => write!(f, "session not found: {session:?}"),
            Self::AlreadyTerminated { session, outcome } => {
                write!(f, "session {session:?} already terminated: {outcome:?}")
            }
            Self::Store { reason } => write!(f, "session record store failure: {reason}"),
            Self::Session(err) => write!(f, "session error: {err}"),
        }
    }
}

impl std::error::Error for SessionManagerError {}

impl From<SessionError> for SessionManagerError {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

/// Session 的可观察视图（`session list/watch` 与重附着的读口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub id: SessionId,
    pub resource: ResourceId,
    pub provider: ProviderId,
    pub phase: LifecyclePhase,
    pub outcome: TerminalOutcome,
    /// 取消原因（仅 `outcome == Cancelled` 时有意义）。
    pub cancel_reason: Option<CancelReason>,
    /// 是否可重附着（`Active` 且未达终态）。
    pub reattachable: bool,
    /// 内嵌的历史 PlanSnapshot（D3；`None` = 建连时未做规划）。
    pub plan_snapshot: Option<PlanSnapshot>,
}

/// SessionManager：Session 生命周期的唯一 Owner（D1）。
///
/// - `open`：创建 Session（`Allocating→Active`），内嵌调用方传入的
///   `PlanSnapshot`（D3：快照在建 Session 时填充、不重算），持久化记录；
/// - `close`：协作取消＋提交 `Cancelled`＋清理到 `Disposed`＋持久化；
/// - 终态语义：`note_client_detached` / `sweep_detached` /
///   `note_provider_lost` / `note_revoked`（PRODUCT §16.3）；
/// - `attach`：按 SessionId 重附着查询（完成标志 #3）。
///
/// 本类型无 I/O、无时钟：时间以参数传入（portable）；持久化经
/// `SessionRecordStore` 注入。
pub struct SessionManager {
    store: Box<dyn SessionRecordStore>,
    owners: HashMap<String, SessionOwner>,
    meta: HashMap<String, SessionMeta>,
    tokens: HashMap<String, CancelToken>,
    attach_window_secs: u64,
    id_counter: AtomicU64,
}

/// SessionManager 持有的非状态机元数据（不进 `SessionOwner`）。
#[derive(Debug, Clone)]
struct SessionMeta {
    resource: ResourceId,
    provider: ProviderId,
    plan_snapshot: Option<PlanSnapshot>,
    cancel_reason: Option<CancelReason>,
    /// 客户端断开时间（unix 秒）；`None` = 未断开/已重附着。
    detached_at_unix: Option<u64>,
}

impl SessionManager {
    /// 新建（空内存态；`load_from_store` 从持久层恢复）。
    #[must_use]
    pub fn new(store: Box<dyn SessionRecordStore>, attach_window_secs: u64) -> Self {
        Self {
            store,
            owners: HashMap::new(),
            meta: HashMap::new(),
            tokens: HashMap::new(),
            attach_window_secs,
            id_counter: AtomicU64::new(0),
        }
    }

    /// 重附着窗口（秒）。
    #[must_use]
    pub fn attach_window_secs(&self) -> u64 {
        self.attach_window_secs
    }

    /// 从持久层加载全部记录并重建内存态（boot / CLI 每次调用入口）。
    ///
    /// 已终态的记录重建 Owner（含 outcome）；未终态的重建为可继续态。
    /// 加载后调用方应先跑 `reconcile_session_records`（§15）再接受新工作；
    /// 本方法只做"加载"，不做孤儿分类（分类是 reconcile 的职责）。
    pub fn load_from_store(&mut self) -> Result<usize, SessionManagerError> {
        let records = self
            .store
            .load()
            .map_err(|reason| SessionManagerError::Store { reason })?;
        let count = records.len();
        for record in records {
            let key = record.session.0.clone();
            // review-n2-p04（observability FAIL）：SessionRecord 不携带
            // resource/provider（持久化格式不变），重建时从
            // plan_snapshot.plan.resource_id/provider_id 回填；plan_snapshot 为
            // None 的旧记录保持空字符串（诚实：信息确实不存在）。
            let (resource, provider) = match &record.plan_snapshot {
                Some(snapshot) => (
                    snapshot.plan.resource_id.clone(),
                    snapshot.plan.provider_id.clone(),
                ),
                None => (ResourceId(String::new()), ProviderId(String::new())),
            };
            let meta = SessionMeta {
                resource,
                provider,
                plan_snapshot: record.plan_snapshot.clone(),
                cancel_reason: None,
                detached_at_unix: record.detached_at_unix,
            };
            let owner = SessionOwner::from_record(&record);
            self.owners.insert(key.clone(), owner);
            self.meta.insert(key.clone(), meta);
            self.tokens.insert(key, CancelToken::new());
        }
        Ok(count)
    }

    /// 当前持有会话数（内存态）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// 生成新的 SessionId（`sess-<unix秒>-<pid>-<计数>`；跨进程唯一靠 pid，
    /// 进程内唯一靠计数器）。
    fn next_session_id(&self) -> SessionId {
        let n = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        SessionId(format!("sess-{now}-{}-{n}", std::process::id()))
    }

    /// 创建 Session（四步闭环之 establish；resolve/plan/authorize 由调用方完成
    /// 后传入）：`Allocating→Active`，内嵌 `PlanSnapshot`，持久化记录。
    ///
    /// 返回新 Session 的真实 Id（`nexus use` 输出此 Id）。
    pub fn open(
        &mut self,
        resource: ResourceId,
        provider: ProviderId,
        plan_snapshot: PlanSnapshot,
    ) -> Result<SessionId, SessionManagerError> {
        let id = self.next_session_id();
        let mut owner = SessionOwner::new(id.clone());
        owner.transition_phase(LifecyclePhase::Active)?;
        let record = SessionRecord {
            session: id.clone(),
            phase: LifecyclePhase::Active,
            outcome: TerminalOutcome::Unfinished,
            plan_snapshot: Some(plan_snapshot.clone()),
            detached_at_unix: None,
        };
        self.store
            .save(&record)
            .map_err(|reason| SessionManagerError::Store { reason })?;
        let key = id.0.clone();
        self.owners.insert(key.clone(), owner);
        self.meta.insert(
            key.clone(),
            SessionMeta {
                resource,
                provider,
                plan_snapshot: Some(plan_snapshot),
                cancel_reason: None,
                detached_at_unix: None,
            },
        );
        self.tokens.insert(key, CancelToken::new());
        Ok(id)
    }

    /// 按 Id 查询视图（`session watch` / 重附着的读口；含历史 PlanSnapshot）。
    #[must_use]
    pub fn get(&self, id: &SessionId) -> Option<SessionView> {
        let key = &id.0;
        let owner = self.owners.get(key)?;
        let meta = self.meta.get(key)?;
        let status = owner.status();
        let reattachable =
            status.phase == LifecyclePhase::Active && status.outcome == TerminalOutcome::Unfinished;
        Some(SessionView {
            id: id.clone(),
            resource: meta.resource.clone(),
            provider: meta.provider.clone(),
            phase: status.phase,
            outcome: status.outcome,
            cancel_reason: meta.cancel_reason.clone(),
            reattachable,
            plan_snapshot: meta.plan_snapshot.clone(),
        })
    }

    /// 列出全部会话（`session list`）。
    #[must_use]
    pub fn list(&self) -> Vec<SessionView> {
        let mut views: Vec<SessionView> = self
            .owners
            .keys()
            .filter_map(|k| self.get(&SessionId(k.clone())))
            .collect();
        views.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        views
    }

    /// 重附着：按 SessionId 查询（完成标志 #3）；会话不存在 → `NotFound`。
    ///
    /// 语义：只要记录存在即可查询（含终态会话的历史）；"可重附着"
    /// 由视图的 `reattachable` 表达（Active 且未达终态）。
    pub fn attach(&self, id: &SessionId) -> Result<SessionView, SessionManagerError> {
        self.get(id).ok_or_else(|| SessionManagerError::NotFound {
            session: id.clone(),
        })
    }

    /// 持久化指定会话的当前状态（内存 → store）。
    fn persist(&mut self, id: &SessionId) -> Result<(), SessionManagerError> {
        let key = &id.0;
        let owner = self
            .owners
            .get(key)
            .ok_or_else(|| SessionManagerError::NotFound {
                session: id.clone(),
            })?;
        let meta = self
            .meta
            .get(key)
            .ok_or_else(|| SessionManagerError::NotFound {
                session: id.clone(),
            })?;
        let status = owner.status();
        let record = SessionRecord {
            session: id.clone(),
            phase: status.phase,
            outcome: status.outcome,
            // 快照搬运、不重算（D3）。
            plan_snapshot: meta.plan_snapshot.clone(),
            // P1-3：断开时刻随记录落盘（否则重启后 sweep 永不命中、会话泄漏）。
            detached_at_unix: meta.detached_at_unix,
        };
        self.store
            .save(&record)
            .map_err(|reason| SessionManagerError::Store { reason })?;
        Ok(())
    }

    /// 内部：提交终态（Owner 唯一写入通道；SessionManager 只做编排）。
    fn commit_terminal(
        &mut self,
        id: &SessionId,
        outcome: TerminalOutcome,
        cancel_reason: Option<CancelReason>,
    ) -> Result<SessionView, SessionManagerError> {
        let key = id.0.clone();
        let owner = self
            .owners
            .get_mut(&key)
            .ok_or_else(|| SessionManagerError::NotFound {
                session: id.clone(),
            })?;
        match owner.commit_outcome(outcome) {
            Ok(()) => {}
            Err(SessionError::AlreadyTerminated { outcome, .. }) => {
                return Err(SessionManagerError::AlreadyTerminated {
                    session: id.clone(),
                    outcome,
                });
            }
            Err(e) => return Err(SessionManagerError::Session(e)),
        }
        if let Some(meta) = self.meta.get_mut(&key) {
            meta.cancel_reason = cancel_reason;
            meta.detached_at_unix = None;
        }
        // Outcome 确定后仍可 cleanup 到 Disposed（§14）。
        let owner = self.owners.get_mut(&key).expect("just inserted");
        match owner.phase() {
            LifecyclePhase::Active => {
                owner.transition_phase(LifecyclePhase::Draining)?;
                owner.transition_phase(LifecyclePhase::Disposed)?;
            }
            LifecyclePhase::Allocating | LifecyclePhase::Draining => {
                owner.transition_phase(LifecyclePhase::Disposed)?;
            }
            LifecyclePhase::Disposed => {}
        }
        self.persist(id)?;
        Ok(self.get(id).expect("just persisted"))
    }

    /// 用户/管理面主动关闭：协作取消＋提交 `Cancelled(UserClosed)`。
    ///
    /// 已终态 → `AlreadyTerminated`（幂等语义由调用方决定）。
    pub fn close(
        &mut self,
        id: &SessionId,
        reason: &str,
    ) -> Result<SessionView, SessionManagerError> {
        let key = &id.0;
        let owner = self
            .owners
            .get(key)
            .ok_or_else(|| SessionManagerError::NotFound {
                session: id.clone(),
            })?;
        if owner.committed_outcome().is_some() {
            return Err(SessionManagerError::AlreadyTerminated {
                session: id.clone(),
                outcome: owner.committed_outcome().expect("checked some"),
            });
        }
        // 结构化并发：先请求协作取消（Worker 侧可观测），再由 Owner 提交终态。
        if let Some(token) = self.tokens.get(key) {
            token.cancel();
        }
        let _ = self
            .owners
            .get_mut(key)
            .expect("checked")
            .request_cancellation(reason.to_string());
        self.commit_terminal(
            id,
            TerminalOutcome::Cancelled,
            Some(CancelReason::UserClosed),
        )
    }

    /// 客户端断开（PRODUCT §16.3）：记录断开时间，会话**保持 Active**、
    /// outcome 保持 `Unfinished`（可重附着）。断开≠Failed。
    ///
    /// 返回值是**真实窗口判定**（P1-2：此前无条件 `Ok(true)`，撒谎）：
    /// - `true` = 仍在重附着窗口内，可重附着；
    /// - `false` = 已断开且超出窗口（应交给 `sweep_detached` 提交
    ///   `Cancelled(ClientDetached)`）。
    ///
    /// P1-3：断开时刻随 `persist` 落盘，重启后 `sweep_detached` 仍能命中。
    pub fn note_client_detached(
        &mut self,
        id: &SessionId,
        now_unix: u64,
    ) -> Result<bool, SessionManagerError> {
        let key = id.0.clone();
        let within_window = {
            let owner = self
                .owners
                .get(&key)
                .ok_or_else(|| SessionManagerError::NotFound {
                    session: id.clone(),
                })?;
            if owner.committed_outcome().is_some() {
                return Err(SessionManagerError::AlreadyTerminated {
                    session: id.clone(),
                    outcome: owner.committed_outcome().expect("checked some"),
                });
            }
            let Some(meta) = self.meta.get_mut(&key) else {
                return Err(SessionManagerError::NotFound {
                    session: id.clone(),
                });
            };
            let within = match meta.detached_at_unix {
                // 已断开过：判定"距上次断开是否仍在窗口内"。
                Some(prev) => now_unix.saturating_sub(prev) < self.attach_window_secs,
                // 从未断开 → 本次即首次断开，必在窗口内。
                None => true,
            };
            meta.detached_at_unix = Some(now_unix);
            within
        };
        // 关键：不断开即判 Failed；outcome 保持 Unfinished，phase 保持 Active。
        // 落盘断开时刻（P1-3 crash consistency）。
        self.persist(id)?;
        Ok(within_window)
    }

    /// 重附着成功：清除断开标记（会话回到"客户端在线"）。
    ///
    /// 与 [`SessionManager::note_client_detached`] 成对——detach 记时刻、
    /// attach 清时刻，`sweep_detached` 才不会把已重附着的会话判为超窗。
    pub fn note_client_reattached(
        &mut self,
        id: &SessionId,
    ) -> Result<SessionView, SessionManagerError> {
        let key = id.0.clone();
        let Some(meta) = self.meta.get_mut(&key) else {
            return Err(SessionManagerError::NotFound {
                session: id.clone(),
            });
        };
        meta.detached_at_unix = None;
        self.persist(id)?;
        self.get(id).ok_or_else(|| SessionManagerError::NotFound {
            session: id.clone(),
        })
    }

    /// 扫描断开超窗的会话 → 提交 `Cancelled(ClientDetached)`。
    ///
    /// P1-2：这是 daemon 的周期性终态入口（Owner = daemon 内唯一
    /// SessionManager），保证"客户端一走就不再重附着"的会话最终收敛，
    /// 而不必依赖外部调用者来驱动。
    ///
    /// 返回本次提交终态的会话 Id 列表（幂等：已终态的不再处理）。
    pub fn sweep_detached(&mut self, now_unix: u64) -> Vec<SessionId> {
        let expired: Vec<String> = self
            .meta
            .iter()
            .filter_map(|(k, m)| match m.detached_at_unix {
                Some(t) if now_unix.saturating_sub(t) >= self.attach_window_secs => Some(k.clone()),
                _ => None,
            })
            .filter(|k| {
                self.owners
                    .get(k)
                    .is_some_and(|o| o.committed_outcome().is_none())
            })
            .collect();
        let mut done = Vec::new();
        for key in expired {
            let id = SessionId(key);
            if self
                .commit_terminal(
                    &id,
                    TerminalOutcome::Cancelled,
                    Some(CancelReason::ClientDetached),
                )
                .is_ok()
            {
                done.push(id);
            }
        }
        done
    }

    /// Provider 消失（PRODUCT §16.3）：明确失败 → 提交 `Failed(ProviderLost)`。
    ///
    /// 只有明确失败才 Failed；单纯的连接丢失走 `note_client_detached`
    ///（保持 Unfinished），不进此方法。
    pub fn note_provider_lost(
        &mut self,
        id: &SessionId,
        provider: &ProviderId,
    ) -> Result<SessionView, SessionManagerError> {
        let view = self.commit_terminal(
            id,
            TerminalOutcome::Failed(NexusError::SessionFailed {
                session: id.clone(),
                reason: format!("provider lost: {}", provider.0),
            }),
            None,
        )?;
        Ok(view)
    }

    /// 授权被撤销（PRODUCT §16.3）：提交 `Cancelled(Revoked)`。
    pub fn note_revoked(&mut self, id: &SessionId) -> Result<SessionView, SessionManagerError> {
        self.commit_terminal(id, TerminalOutcome::Cancelled, Some(CancelReason::Revoked))
    }

    /// `use` 成功路径：提交 `Completed`（Owner 唯一提交）＋清理到 `Disposed`。
    pub fn complete(&mut self, id: &SessionId) -> Result<SessionView, SessionManagerError> {
        self.commit_terminal(id, TerminalOutcome::Completed, None)
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;
    use nexus_domain::{ConsideredCandidate, DecisionTrace, Plan, PlanId};

    /// 测试用内存记录存储（与上一个 tests 模块的同名类型独立）。
    #[derive(Debug, Default)]
    struct MemStore {
        records: Vec<SessionRecord>,
    }

    impl SessionRecordStore for MemStore {
        fn load(&self) -> Result<Vec<SessionRecord>, String> {
            Ok(self.records.clone())
        }

        fn save(&mut self, record: &SessionRecord) -> Result<(), String> {
            if let Some(slot) = self
                .records
                .iter_mut()
                .find(|r| r.session == record.session)
            {
                *slot = record.clone();
            } else {
                self.records.push(record.clone());
            }
            Ok(())
        }
    }

    fn snapshot() -> PlanSnapshot {
        PlanSnapshot {
            plan_id: PlanId("abcd1234abcd1234".into()),
            plan: Plan {
                resource_id: ResourceId("dev-svc".into()),
                provider_id: ProviderId("local-dev-1".into()),
                placement: "local".into(),
                path: vec!["127.0.0.1:8080".into()],
                execution_strategy: "direct".into(),
                extension: None,
            },
            decision_trace: DecisionTrace {
                considered: vec![ConsideredCandidate {
                    provider: ProviderId("local-dev-1".into()),
                    rejected_reason: None,
                    connectivity: None,
                    measurement: None,
                    score: Some(1000),
                    score_breakdown: None,
                }],
                selected: ProviderId("local-dev-1".into()),
            },
        }
    }

    fn manager() -> SessionManager {
        SessionManager::new(Box::new(MemStore::default()), DEFAULT_ATTACH_WINDOW_SECS)
    }

    fn open_one(mgr: &mut SessionManager) -> SessionId {
        mgr.open(
            ResourceId("dev-svc".into()),
            ProviderId("local-dev-1".into()),
            snapshot(),
        )
        .unwrap()
    }

    #[test]
    fn open_embeds_plan_snapshot_and_persists() {
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        assert!(id.0.starts_with("sess-"));
        // 视图含内嵌快照（D3：建 Session 时填充）。
        let view = mgr.get(&id).unwrap();
        assert_eq!(view.phase, LifecyclePhase::Active);
        assert_eq!(view.outcome, TerminalOutcome::Unfinished);
        assert_eq!(view.plan_snapshot, Some(snapshot()));
        assert!(view.reattachable);
        // 持久化了（store 里有一条 Active/Unfinished 记录）。
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn open_generates_unique_ids() {
        let mut mgr = manager();
        let a = open_one(&mut mgr);
        let b = open_one(&mut mgr);
        assert_ne!(a, b);
    }

    #[test]
    fn complete_commits_completed_exactly_once() {
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        let view = mgr.complete(&id).unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Completed);
        assert_eq!(view.phase, LifecyclePhase::Disposed);
        // 第二次提交 → AlreadyTerminated（§14 exactly-once）。
        let err = mgr.complete(&id);
        assert!(matches!(
            err,
            Err(SessionManagerError::AlreadyTerminated { .. })
        ));
    }

    #[test]
    fn close_commits_cancelled_with_user_reason() {
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        let view = mgr.close(&id, "user requested").unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Cancelled);
        assert_eq!(view.cancel_reason, Some(CancelReason::UserClosed));
        assert_eq!(view.phase, LifecyclePhase::Disposed);
        // 已终态再 close → AlreadyTerminated（非静默成功）。
        let err = mgr.close(&id, "again");
        assert!(matches!(
            err,
            Err(SessionManagerError::AlreadyTerminated { .. })
        ));
    }

    #[test]
    fn close_unknown_session_is_not_found() {
        let mut mgr = manager();
        let err = mgr.close(&SessionId("sess-nope".into()), "x");
        assert!(matches!(err, Err(SessionManagerError::NotFound { .. })));
    }

    #[test]
    fn client_detach_keeps_session_unfinished_within_window() {
        // D7 终态语义核心：断开≠Failed——窗口内仍 Active/Unfinished（可重附着）。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        let still = mgr.note_client_detached(&id, 1000).unwrap();
        assert!(still);
        let view = mgr.get(&id).unwrap();
        assert_eq!(view.phase, LifecyclePhase::Active);
        assert_eq!(
            view.outcome,
            TerminalOutcome::Unfinished,
            "disconnect must NOT become Failed"
        );
        assert!(view.reattachable);
        // 窗口内 sweep 不提交。
        assert!(
            mgr.sweep_detached(1000 + DEFAULT_ATTACH_WINDOW_SECS - 1)
                .is_empty()
        );
        assert_eq!(mgr.get(&id).unwrap().outcome, TerminalOutcome::Unfinished);
    }

    #[test]
    fn detach_beyond_window_becomes_cancelled_not_failed() {
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        mgr.note_client_detached(&id, 1000).unwrap();
        let swept = mgr.sweep_detached(1000 + DEFAULT_ATTACH_WINDOW_SECS);
        assert_eq!(swept, vec![id.clone()]);
        let view = mgr.get(&id).unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Cancelled);
        assert_eq!(view.cancel_reason, Some(CancelReason::ClientDetached));
        assert!(!view.reattachable);
        // 幂等：再次 sweep 不重复。
        assert!(
            mgr.sweep_detached(1000 + DEFAULT_ATTACH_WINDOW_SECS + 999)
                .is_empty()
        );
    }

    #[test]
    fn provider_lost_commits_failed_with_reason() {
        // 只有明确失败才 Failed（provider 消失是明确失败）。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        let view = mgr
            .note_provider_lost(&id, &ProviderId("local-dev-1".into()))
            .unwrap();
        assert!(matches!(view.outcome, TerminalOutcome::Failed(_)));
        if let TerminalOutcome::Failed(NexusError::SessionFailed { reason, .. }) = view.outcome {
            assert!(reason.contains("provider lost"));
        } else {
            panic!("expected Failed(SessionFailed)");
        }
    }

    #[test]
    fn revoked_commits_cancelled_with_revoked_reason() {
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        let view = mgr.note_revoked(&id).unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Cancelled);
        assert_eq!(view.cancel_reason, Some(CancelReason::Revoked));
    }

    #[test]
    fn attach_returns_view_with_history_after_close() {
        // 完成标志 #3：CLI 退出重进按 SessionId 查询状态＋历史 DecisionTrace。
        // （此处模拟"重进"：新 manager 从同一 store 加载。）
        let store = MemStore::default();
        let mut mgr = SessionManager::new(Box::new(store), DEFAULT_ATTACH_WINDOW_SECS);
        let id = open_one(&mut mgr);
        mgr.complete(&id).unwrap();
        // 把 store 交给新 manager（模拟进程重启）。
        let store2 = std::mem::replace(
            &mut mgr.store,
            Box::new(MemStore::default()) as Box<dyn SessionRecordStore>,
        );
        let mut mgr2 = SessionManager::new(store2, DEFAULT_ATTACH_WINDOW_SECS);
        mgr2.load_from_store().unwrap();
        let view = mgr2.attach(&id).unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Completed);
        // 历史 DecisionTrace 可读（非重算：与建连时内嵌的一致）。
        let trace = &view.plan_snapshot.as_ref().unwrap().decision_trace;
        assert_eq!(trace.selected.0, "local-dev-1");
        assert_eq!(trace.considered.len(), 1);
    }

    #[test]
    fn load_backfills_resource_provider_from_plan_snapshot() {
        // review-n2-p04（observability）：`session list/watch` 的唯一生产读路径
        // 走 load_from_store；SessionRecord 不携带 resource/provider，必须从
        // plan_snapshot.plan.resource_id/provider_id 回填；plan_snapshot 为
        // None 的旧记录诚实保持空字符串（信息确实不存在，不伪造）。
        let mut mgr = manager();
        let with_snap = open_one(&mut mgr);
        // 手工塞一条无 plan_snapshot 的旧记录（持久化格式无此字段的真实旧数据）。
        let legacy = SessionId("sess-legacy-1".into());
        mgr.store
            .save(&SessionRecord {
                session: legacy.clone(),
                phase: LifecyclePhase::Active,
                outcome: TerminalOutcome::Unfinished,
                plan_snapshot: None,
                detached_at_unix: None,
            })
            .unwrap();
        // 模拟进程重启：新 manager 从同一 store 加载（CLI 每次调用的重建路径）。
        let store2 = std::mem::replace(
            &mut mgr.store,
            Box::new(MemStore::default()) as Box<dyn SessionRecordStore>,
        );
        let mut mgr2 = SessionManager::new(store2, DEFAULT_ATTACH_WINDOW_SECS);
        mgr2.load_from_store().unwrap();
        let list = mgr2.list();
        let views: std::collections::HashMap<&str, &SessionView> =
            list.iter().map(|v| (v.id.0.as_str(), v)).collect();
        let v = views[with_snap.0.as_str()];
        assert_eq!(v.resource.0, "dev-svc");
        assert_eq!(v.provider.0, "local-dev-1");
        assert!(v.plan_snapshot.is_some());
        let lv = views["sess-legacy-1"];
        assert_eq!(lv.resource.0, "");
        assert_eq!(lv.provider.0, "");
        assert!(lv.plan_snapshot.is_none());
    }

    #[test]
    fn attach_unknown_is_not_found() {
        let mgr = manager();
        let err = mgr.attach(&SessionId("sess-missing".into()));
        assert!(matches!(err, Err(SessionManagerError::NotFound { .. })));
    }

    #[test]
    fn list_returns_all_sorted() {
        let mut mgr = manager();
        let a = open_one(&mut mgr);
        let b = open_one(&mut mgr);
        mgr.complete(&a).unwrap();
        let views = mgr.list();
        assert_eq!(views.len(), 2);
        let ids: Vec<&str> = views.iter().map(|v| v.id.0.as_str()).collect();
        assert!(ids.contains(&a.0.as_str()) && ids.contains(&b.0.as_str()));
        // 有序（确定性）。
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn plan_snapshot_carried_not_recomputed_on_persist() {
        // D3：persist 回写搬运快照；快照内容恒为 open 时传入的值。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        mgr.note_client_detached(&id, 500).unwrap();
        // detach 不碰 store；close 会 persist。
        mgr.close(&id, "test").unwrap();
        let view = mgr.get(&id).unwrap();
        assert_eq!(view.plan_snapshot, Some(snapshot()));
        assert_eq!(
            view.plan_snapshot.as_ref().unwrap().plan_id.0,
            "abcd1234abcd1234"
        );
    }

    #[test]
    fn terminal_outcome_has_single_owner() {
        // §14：Worker 不直接写 outcome；所有提交经 SessionManager 编排 →
        // SessionOwner::commit_outcome。验证路径：note_provider_lost 后
        // close 必须 AlreadyTerminated（outcome 已被占）。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        mgr.note_provider_lost(&id, &ProviderId("p".into()))
            .unwrap();
        let err = mgr.close(&id, "late close");
        assert!(matches!(
            err,
            Err(SessionManagerError::AlreadyTerminated { .. })
        ));
        // outcome 保持第一次提交的 Failed（不被覆盖）。
        assert!(matches!(
            mgr.get(&id).unwrap().outcome,
            TerminalOutcome::Failed(_)
        ));
    }

    // ---- P1-2 / P1-3：断开时刻落盘 + 真实窗口判定 ----

    fn restart(mgr: &mut SessionManager) -> SessionManager {
        let store = std::mem::replace(
            &mut mgr.store,
            Box::new(MemStore::default()) as Box<dyn SessionRecordStore>,
        );
        let mut next = SessionManager::new(store, mgr.attach_window_secs());
        next.load_from_store().unwrap();
        next
    }

    #[test]
    fn detach_persists_and_survives_restart() {
        // P1-3 回归：detach 时刻只存内存时，重启后 sweep 永不命中 → 会话泄漏。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        assert!(mgr.note_client_detached(&id, 1000).unwrap());
        // 落盘断言：store 里带 detached_at_unix。
        let rec = mgr
            .store
            .load()
            .unwrap()
            .into_iter()
            .find(|r| r.session == id)
            .unwrap();
        assert_eq!(rec.detached_at_unix, Some(1000));
        // 模拟进程重启：新 manager 从同一 store 加载。
        let mut mgr2 = restart(&mut mgr);
        assert_eq!(
            mgr2.get(&id)
                .map(|v| v.outcome == TerminalOutcome::Unfinished),
            Some(true)
        );
        // 窗口内不 sweep。
        assert!(
            mgr2.sweep_detached(1000 + DEFAULT_ATTACH_WINDOW_SECS - 1)
                .is_empty()
        );
        // 窗口外 sweep 命中（重启后仍收敛）。
        let swept = mgr2.sweep_detached(1000 + DEFAULT_ATTACH_WINDOW_SECS);
        assert_eq!(swept, vec![id.clone()]);
        let view = mgr2.get(&id).unwrap();
        assert_eq!(view.outcome, TerminalOutcome::Cancelled);
        assert_eq!(view.cancel_reason, Some(CancelReason::ClientDetached));
    }

    #[test]
    fn note_client_detached_returns_real_window_verdict() {
        // P1-2 回归：此前无条件 Ok(true) 撒谎。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        // 首次断开：窗口内 → true。
        assert!(mgr.note_client_detached(&id, 1000).unwrap());
        // 窗口内再次 detach → true。
        assert!(
            mgr.note_client_detached(&id, 1000 + DEFAULT_ATTACH_WINDOW_SECS - 1)
                .unwrap()
        );
        // 超出窗口后再 detach → false（真实判定）。
        assert!(
            !mgr.note_client_detached(&id, 1000 + 2 * DEFAULT_ATTACH_WINDOW_SECS)
                .unwrap()
        );
    }

    #[test]
    fn reattach_clears_detach_marker() {
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        mgr.note_client_detached(&id, 1000).unwrap();
        mgr.note_client_reattached(&id).unwrap();
        // 已重附着：窗口外也不再判 ClientDetached。
        assert!(
            mgr.sweep_detached(1000 + 10 * DEFAULT_ATTACH_WINDOW_SECS)
                .is_empty()
        );
        let rec = mgr
            .store
            .load()
            .unwrap()
            .into_iter()
            .find(|r| r.session == id)
            .unwrap();
        assert_eq!(rec.detached_at_unix, None);
    }

    #[test]
    fn detach_does_not_change_outcome_or_phase() {
        // D7：断开≠Failed——detach 本身不动 outcome/phase，只记时刻。
        let mut mgr = manager();
        let id = open_one(&mut mgr);
        mgr.note_client_detached(&id, 42).unwrap();
        let view = mgr.get(&id).unwrap();
        assert_eq!(view.phase, LifecyclePhase::Active);
        assert_eq!(view.outcome, TerminalOutcome::Unfinished);
        assert!(view.reattachable);
    }

    #[test]
    fn detach_unknown_session_is_not_found() {
        let mut mgr = manager();
        let err = mgr.note_client_detached(&SessionId("sess-nope".into()), 1);
        assert!(matches!(err, Err(SessionManagerError::NotFound { .. })));
    }
}
