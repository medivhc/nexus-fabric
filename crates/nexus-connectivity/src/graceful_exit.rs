//! 节点优雅退出（内存骨架，注入逻辑时钟）。
//!
//! 本模块是 delivery 层共享底座的节点下线状态机骨架：
//! - **配置**：`ExitConfig` 持有宽限期 / 是否通知对端 / 是否等待流量排空；
//! - **状态**：`ExitState` 四态（Active / Draining / Exiting / Exited）；
//! - **协调器**：`GracefulExit` 维护当前状态与已通知对端列表，按注入时间推进状态机；
//! - **转移规则**：
//!   - `Active --begin_draining--> Draining`（记录 drain 起始时间）；
//!   - `Draining --wait_for_drain 且仍有连接且未到宽限期--> 仍 Draining`；
//!   - `Draining --连接排空或宽限期超时--> Exiting`；
//!   - `Exiting --advance--> Exited`。
//!
//! 边界（PRODUCT §12-graceful-exit 冻结）：
//! - 纯内存、纯同步、纯函数骨架；时间由调用方经 `now_ms` 注入，本模块不读真实墙钟；
//! - 状态推进只看注入的 `active_connections` 与 `now_ms`，不真实等待 I/O；
//! - 已进入终态（Exiting / Exited）后不再回退；
//! - 真实网络通知对端 / 真实 drain 等待线程留 TODO。
//!
//! TODO（真实下线集成，非本骨架范围）：
//! - 按 `grace_period_ms` 起一个有 Owner 的定时任务（CancellationToken + JoinSet）；
//! - 用真实 I/O 向对端发送再见帧（peer 下线通知），并等待对端 ACK；
//! - 阻塞新会话接入，等待既有连接自然排空或超时强制关闭；
//! - 把最终 Exited 事件反馈给多跳路由 / 健康检查，摘除本节点。
//!
//! 错误面独立：`GracefulExitError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;

// ---------- 错误 ----------

/// 优雅退出相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulExitError {
    /// 配置非法（如 grace_period_ms=0）。
    InvalidConfig(String),
}

impl fmt::Display for GracefulExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => {
                write!(f, "GRACEFUL_EXIT_INVALID_CONFIG: {msg}")
            }
        }
    }
}

impl std::error::Error for GracefulExitError {}

// ---------- 退出状态 ----------

/// 节点退出四态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitState {
    /// 正常服务中，未开始下线。
    Active,
    /// 正在排空：不再接受新会话，等待既有流量结束。
    Draining,
    /// 即将退出：流量已排空或宽限期已到，正在做收尾。
    Exiting,
    /// 已退出：终态，不再接受任何工作。
    Exited,
}

impl ExitState {
    /// 返回稳定的小写字符串标识（供 JSON / 日志 / 断言使用）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Exiting => "exiting",
            Self::Exited => "exited",
        }
    }
}

impl fmt::Display for ExitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 优雅退出配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitConfig {
    /// 排空宽限期（毫秒，逻辑时钟；必须 > 0）。
    pub grace_period_ms: u64,
    /// 是否在进入 Draining 时通知对端 peer。
    pub notify_peers: bool,
    /// 是否等待连接排空（false 时进入 Draining 后立即推进到 Exiting）。
    pub wait_for_drain: bool,
}

impl ExitConfig {
    /// 构造配置并校验不变量。
    ///
    /// 校验：
    /// - `grace_period_ms > 0`。
    ///
    /// 非法返回 `GracefulExitError::InvalidConfig`。
    pub fn new(
        grace_period_ms: u64,
        notify_peers: bool,
        wait_for_drain: bool,
    ) -> Result<Self, GracefulExitError> {
        if grace_period_ms == 0 {
            return Err(GracefulExitError::InvalidConfig(
                "grace_period_ms must be > 0".to_string(),
            ));
        }
        Ok(Self {
            grace_period_ms,
            notify_peers,
            wait_for_drain,
        })
    }
}

// ---------- 协调器 ----------

/// 节点优雅退出协调器：维护退出状态机与已通知对端列表。
///
/// 纯内存、纯同步；时间由调用方经 `now_ms` 注入，便于单测与确定性 replay。
pub struct GracefulExit {
    cfg: ExitConfig,
    state: ExitState,
    /// 进入 Draining 时的注入逻辑时间（仅在 Draining 态有意义）。
    drain_start_ms: u64,
    /// 已通知过的对端 peer 名（仅当 `notify_peers=true` 时记录）。
    notified: Vec<String>,
}

impl GracefulExit {
    /// 用给定配置构造处于 `Active` 态的协调器。
    #[must_use]
    pub fn new(cfg: ExitConfig) -> Self {
        Self {
            cfg,
            state: ExitState::Active,
            drain_start_ms: 0,
            notified: Vec::new(),
        }
    }

    /// 开始排空：`Active -> Draining`，记录 drain 起始时间。
    ///
    /// 幂等：若已不在 `Active`（例如重复调用），保持当前状态不变。
    pub fn begin_draining(&mut self, now_ms: u64) -> ExitState {
        if self.state == ExitState::Active {
            self.state = ExitState::Draining;
            self.drain_start_ms = now_ms;
        }
        self.state
    }

    /// 通知一批对端 peer 本节点即将下线。
    ///
    /// 仅当配置 `notify_peers=true` 时才把 peer 名记入已通知列表并返回它们；
    /// 配置关闭时不记录、返回空列表（真实网络发送留 TODO）。
    pub fn notify_peers(&mut self, peers: &[&str]) -> Vec<String> {
        if !self.cfg.notify_peers {
            return Vec::new();
        }
        let mut recorded = Vec::new();
        for p in peers {
            let p = p.to_string();
            self.notified.push(p.clone());
            recorded.push(p);
        }
        recorded
    }

    /// 推进退出状态机，返回推进后的状态。
    ///
    /// 转移规则：
    /// - `Draining` 且 `wait_for_drain=true` 且 `active_connections > 0`
    ///   且尚未超过宽限期 → 仍为 `Draining`；
    /// - `Draining`：连接已排空（`active_connections == 0`）或宽限期已到 → `Exiting`；
    /// - `Exiting` → `Exited`；
    /// - 其它态（`Active` / `Exited`）保持不变。
    pub fn advance(&mut self, active_connections: u32, now_ms: u64) -> ExitState {
        match self.state {
            ExitState::Draining => {
                let within_grace =
                    now_ms.saturating_sub(self.drain_start_ms) < self.cfg.grace_period_ms;
                let still_busy = self.cfg.wait_for_drain && active_connections > 0;
                if still_busy && within_grace {
                    self.state
                } else {
                    self.state = ExitState::Exiting;
                    self.state
                }
            }
            ExitState::Exiting => {
                self.state = ExitState::Exited;
                self.state
            }
            ExitState::Active | ExitState::Exited => self.state,
        }
    }

    /// 当前退出状态（只读）。
    #[must_use]
    pub fn state(&self) -> ExitState {
        self.state
    }

    /// 已通知过的对端 peer 数量（只读快照）。
    #[must_use]
    pub fn notified_peer_count(&self) -> usize {
        self.notified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(grace: u64, notify: bool, wait: bool) -> ExitConfig {
        ExitConfig::new(grace, notify, wait).expect("valid config")
    }

    #[test]
    fn config_accepts_valid_values() {
        let c = ExitConfig::new(1_000, true, true).expect("valid");
        assert_eq!(c.grace_period_ms, 1_000);
        assert!(c.notify_peers);
        assert!(c.wait_for_drain);
    }

    #[test]
    fn config_rejects_zero_grace() {
        let err = ExitConfig::new(0, true, true).expect_err("grace must be > 0");
        assert!(matches!(err, GracefulExitError::InvalidConfig(_)));
    }

    #[test]
    fn starts_active() {
        let g = GracefulExit::new(cfg(1_000, true, true));
        assert_eq!(g.state(), ExitState::Active);
    }

    #[test]
    fn begin_draining_moves_to_draining() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        assert_eq!(g.begin_draining(0), ExitState::Draining);
        assert_eq!(g.state(), ExitState::Draining);
    }

    #[test]
    fn begin_draining_is_idempotent_when_already_draining() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        // 重复 begin_draining 不应重置 drain_start。
        assert_eq!(g.begin_draining(500), ExitState::Draining);
        // 仍以 t=0 为 drain_start：t=999 仍在宽限期内。
        let s = g.advance(5, 999);
        assert_eq!(s, ExitState::Draining);
    }

    #[test]
    fn stays_draining_while_busy_within_grace() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        let s = g.advance(5, 500);
        assert_eq!(s, ExitState::Draining);
    }

    #[test]
    fn moves_to_exiting_when_drained() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        let s = g.advance(0, 500);
        assert_eq!(s, ExitState::Exiting);
    }

    #[test]
    fn timeout_forces_exiting_even_if_busy() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        // 仍有连接，但已超过宽限期 → 强制 Exiting。
        let s = g.advance(5, 2_000);
        assert_eq!(s, ExitState::Exiting);
    }

    #[test]
    fn exiting_advances_to_exited() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        g.advance(0, 100);
        let s = g.advance(0, 200);
        assert_eq!(s, ExitState::Exited);
        assert_eq!(g.state(), ExitState::Exited);
    }

    #[test]
    fn exited_is_terminal() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        g.begin_draining(0);
        g.advance(0, 100);
        g.advance(0, 200);
        let s = g.advance(0, 300);
        assert_eq!(s, ExitState::Exited);
    }

    #[test]
    fn wait_for_drain_false_skips_drain_wait() {
        let mut g = GracefulExit::new(cfg(1_000, true, false));
        g.begin_draining(0);
        // 即使仍有连接且在宽限期内，也立即 Exiting。
        let s = g.advance(9, 10);
        assert_eq!(s, ExitState::Exiting);
    }

    #[test]
    fn notify_peers_records_when_enabled() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        let recorded = g.notify_peers(&["peer-a", "peer-b"]);
        assert_eq!(recorded, vec!["peer-a".to_string(), "peer-b".to_string()]);
        assert_eq!(g.notified_peer_count(), 2);
    }

    #[test]
    fn notify_peers_skipped_when_disabled() {
        let mut g = GracefulExit::new(cfg(1_000, false, true));
        let recorded = g.notify_peers(&["peer-a", "peer-b"]);
        assert!(recorded.is_empty());
        assert_eq!(g.notified_peer_count(), 0);
    }

    #[test]
    fn full_transition_active_to_exited() {
        let mut g = GracefulExit::new(cfg(1_000, true, true));
        assert_eq!(g.state(), ExitState::Active);
        g.begin_draining(0);
        assert_eq!(g.advance(3, 100), ExitState::Draining);
        assert_eq!(g.advance(0, 200), ExitState::Exiting);
        assert_eq!(g.advance(0, 300), ExitState::Exited);
    }

    #[test]
    fn exit_state_as_str_and_display() {
        assert_eq!(ExitState::Active.as_str(), "active");
        assert_eq!(ExitState::Draining.as_str(), "draining");
        assert_eq!(ExitState::Exiting.as_str(), "exiting");
        assert_eq!(ExitState::Exited.as_str(), "exited");
        assert_eq!(ExitState::Exited.to_string(), "exited");
    }

    #[test]
    fn error_display_is_structured() {
        let e = GracefulExitError::InvalidConfig("bad grace".into());
        assert!(e.to_string().contains("bad grace"));
    }
}
