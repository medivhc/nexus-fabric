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
    LifecyclePhase, NexusError, PlanSnapshot, SessionId, SessionStatus, TerminalOutcome,
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
}

/// 会话记录存储契约（Portable；由 Composition Root 注入实现，
/// 如内存/文件/安全存储，参见 `nexus-storage` 的 ContentStore 注入模式）。
pub trait SessionRecordStore {
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
pub fn reconcile_session_records<S: SessionRecordStore>(
    store: &mut S,
    process_alive: bool,
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
                })
                .map_err(|reason| SessionReconcileError::Store { reason })?;
            continue;
        }
        if process_alive {
            continue;
        }
        // 孤儿：恰一次提交 Failed，清理到 Disposed（Owner 是 Outcome 唯一写入者）。
        let mut owner = SessionOwner::new(record.session.clone());
        owner
            .transition_phase(LifecyclePhase::Active)
            .map_err(SessionReconcileError::from)?;
        owner
            .commit_outcome(TerminalOutcome::Failed(NexusError::Internal {
                message: "process crashed; session orphaned during cold start".into(),
            }))
            .map_err(SessionReconcileError::from)?;
        owner
            .transition_phase(LifecyclePhase::Draining)
            .map_err(SessionReconcileError::from)?;
        owner
            .transition_phase(LifecyclePhase::Disposed)
            .map_err(SessionReconcileError::from)?;
        let status = owner.status();
        store
            .save(&SessionRecord {
                session: record.session,
                phase: status.phase,
                outcome: status.outcome,
                plan_snapshot: record.plan_snapshot,
            })
            .map_err(|reason| SessionReconcileError::Store { reason })?;
        report.orphans_classified += 1;
    }
    Ok(report)
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
        }
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
                },
                SessionRecord {
                    session: SessionId("s-draining".into()),
                    phase: LifecyclePhase::Draining,
                    outcome: TerminalOutcome::Cancelled,
                    plan_snapshot: None,
                },
                SessionRecord {
                    session: SessionId("s-alloc".into()),
                    phase: LifecyclePhase::Allocating,
                    outcome: TerminalOutcome::Failed(NexusError::Internal {
                        message: "boom".into(),
                    }),
                    plan_snapshot: None,
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
            }],
        };
        let report = reconcile_session_records(&mut store, false).unwrap();
        assert_eq!(report.orphans_classified, 0);
        // 终态重放 cleanup 后快照仍在（搬运，非重算）。
        assert_eq!(store.records[0].plan_snapshot, Some(snapshot));
        assert_eq!(store.records[0].phase, LifecyclePhase::Disposed);
    }
}
