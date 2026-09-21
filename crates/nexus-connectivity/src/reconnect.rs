//! 自动断线重连（指数退避状态机骨架，内存确定性）。
//!
//! 本模块是 delivery 层共享底座的重连策略骨架：
//! - **指数退避**：`ReconnectController` 在每次断线/失败后按
//!   `min(initial_delay * factor^(n-1), max_delay)` 计算下一次重连应等待的延迟，
//!   不阻塞、不 sleep、不读墙钟；
//! - **可注入时钟**：`ReconnectClock` trait 抽象单调时间；真实实现基于 `std::time::Instant`，
//!   测试/场景用显式 `Duration` 假时钟推进，保证确定性；
//! - **状态机**：`ReconnectState` 在 `Idle / Reconnecting / Connected / Failed / GiveUp`
//!   之间迁移；达到 `max_retries` 后进入 `GiveUp`（放弃），退避中途成功则回到 `Connected`
//!   并把重试计数清零。
//!
//! 边界（PRODUCT §12-auto-reconnect 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实 socket / TUN / 协议握手；
//! - 仅做退避计算与状态迁移；不做异步等待、不引入 tokio；
//! - 时钟由调用方通过 `now: Duration` 显式传入，模块自身不读墙钟；
//! - 不做：抖动（jitter）、熔断半开探测、按拓扑的差异化重试策略留 TODO。
//!
//! TODO（真实数据面集成，非本骨架范围）：
//! - 在 VirtualSubnetTunnel / RelayChannel 断连事件上挂接 `ReconnectController`；
//! - 把 `now` 接入真实单调时钟（`MonotonicReconnectClock`）并在后台驱动 `is_due`；
//! - 退避抖动、成功探测（half-open）、跨连接的共享重试预算与持久化。
//!
//! 错误面独立：`ReconnectError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;
use std::time::{Duration, Instant};

// ---------- 错误 ----------

/// 自动重连相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectError {
    /// 重连参数非法（max_retries 为 0、initial_delay 为 0、max_delay < initial_delay 等）。
    InvalidConfig {
        /// 非法原因（人可读）。
        message: String,
    },
}

impl fmt::Display for ReconnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { message } => write!(f, "RECONNECT_INVALID_CONFIG: {message}"),
        }
    }
}

impl std::error::Error for ReconnectError {}

// ---------- 可注入时钟 ----------

/// 单调时钟抽象（可注入，便于用假时钟做确定性测试）。
///
/// 返回值是一个相对 `Duration`（自某个任意但单调递增的起点起算）；
/// 调用方把它直接作为 `now` 传给 `ReconnectController`。
pub trait ReconnectClock {
    /// 当前单调时间点（相对时长）。
    fn now(&self) -> Duration;
}

/// 真实单调时钟：基于 `std::time::Instant`，返回自构造起经过的时长。
///
/// 线程安全、不回退；`Instant` 在同一进程内单调递增。
pub struct MonotonicReconnectClock {
    /// 起点（构造时刻）。
    start: Instant,
}

impl Default for MonotonicReconnectClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicReconnectClock {
    /// 以当前时刻为起点构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl ReconnectClock for MonotonicReconnectClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

// ---------- 配置 ----------

/// 重连配置：最大重试次数 + 指数退避参数。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReconnectConfig {
    /// 最大重连尝试次数（必须 >= 1）。
    pub max_retries: u32,
    /// 首次退避延迟（必须 > 0）。
    pub initial_delay: Duration,
    /// 退避延迟上限（必须 >= initial_delay）。
    pub max_delay: Duration,
    /// 退避倍率（必须 >= 1.0）。
    pub backoff_factor: f64,
}

impl ReconnectConfig {
    /// 构造并重连配置；任一参数非法返回 `InvalidConfig`。
    ///
    /// 校验：`max_retries >= 1`、`initial_delay > 0`、
    /// `max_delay >= initial_delay`、`backoff_factor >= 1.0`。
    pub fn new(
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        backoff_factor: f64,
    ) -> Result<Self, ReconnectError> {
        if max_retries == 0 {
            return Err(ReconnectError::InvalidConfig {
                message: format!("max_retries must be >= 1 (got {max_retries})"),
            });
        }
        if initial_delay.is_zero() {
            return Err(ReconnectError::InvalidConfig {
                message: "initial_delay must be > 0".to_string(),
            });
        }
        if max_delay < initial_delay {
            return Err(ReconnectError::InvalidConfig {
                message: format!(
                    "max_delay ({max_delay:?}) must be >= initial_delay ({initial_delay:?})"
                ),
            });
        }
        if backoff_factor < 1.0 {
            return Err(ReconnectError::InvalidConfig {
                message: format!("backoff_factor must be >= 1.0 (got {backoff_factor})"),
            });
        }
        Ok(Self {
            max_retries,
            initial_delay,
            max_delay,
            backoff_factor,
        })
    }
}

// ---------- 状态机 ----------

/// 重连状态机状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectState {
    /// 空闲（尚未断开/尚未开始追踪）。
    Idle,
    /// 重连进行中（已断开，正在按退避策略重试）。
    Reconnecting,
    /// 已连接（重连成功，或初始即连通）。
    Connected,
    /// 单次尝试失败（保留语义；当前骨架由 `Reconnecting` 承载重试过程）。
    Failed,
    /// 已放弃（达到 `max_retries`，不再发起新尝试）。
    GiveUp,
}

// ---------- 单次重连记录 ----------

/// 单次重连快照（当前尝试计数 + 最后尝试时间 + 下一次应等待的延迟）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reattempt {
    /// 已发起的重连尝试次数。
    pub attempt_count: u32,
    /// 最后一次尝试/断开事件的时间点（从未发生过为 `Duration::ZERO`）。
    pub last_attempt_time: Duration,
    /// 下一次重连应等待的退避延迟。
    pub next_delay: Duration,
}

// ---------- 控制器 ----------

/// 重连控制器：持有配置与退避状态，驱动状态机迁移。
///
/// 驱动顺序（调用方在合适的时间点调用）：
/// - `on_disconnect(now)`：断开事件，进入 `Reconnecting`，计算首次退避；
/// - `is_due(now)`：判断退避是否到期；
/// - `begin_attempt(now)`：到期后发起一次尝试（计数 +1）；
/// - `on_attempt_failed(now)`：本次尝试失败，按指数公式计算下一次退避；
/// - `on_success(now)`：重连成功，回到 `Connected` 并清零计数。
///
/// 达到 `max_retries` 后 `begin_attempt` 返回 `false` 并转入 `GiveUp`。
pub struct ReconnectController {
    /// 重连配置（退避参数）。
    config: ReconnectConfig,
    /// 当前状态。
    state: ReconnectState,
    /// 已发起的重连尝试次数。
    attempt_count: u32,
    /// 最后一次尝试/断开事件的时间点（`None` 表示从未发生）。
    last_attempt_time: Option<Duration>,
    /// 下一次重连应等待的退避延迟。
    next_delay: Duration,
}

impl ReconnectController {
    /// 用配置构造控制器；初始状态为 `Idle`，退避延迟置为 `initial_delay`。
    #[must_use]
    pub fn new(config: ReconnectConfig) -> Self {
        let initial_delay = config.initial_delay;
        Self {
            config,
            state: ReconnectState::Idle,
            attempt_count: 0,
            last_attempt_time: None,
            next_delay: initial_delay,
        }
    }

    /// 连接断开时调用：进入 `Reconnecting`，记录本次断开时间，计算下一次退避延迟。
    ///
    /// 返回本次 `Reattempt` 快照。若已 `GiveUp` 则不改变任何状态，直接返回当前快照。
    pub fn on_disconnect(&mut self, now: Duration) -> Reattempt {
        if self.state == ReconnectState::GiveUp {
            return self.snapshot();
        }
        self.state = ReconnectState::Reconnecting;
        self.attempt_count = 0;
        self.last_attempt_time = Some(now);
        // 初始断开：attempt_count=0 -> exponent 0 -> next_delay = initial_delay。
        self.next_delay = self.compute_backoff();
        self.snapshot()
    }

    /// 查询在时刻 `now` 是否可以发起下一次重连（`now >= last_attempt_time + next_delay`）。
    ///
    /// 从未断开（无待处理等待）返回 `false`；时钟回退（`now < last_attempt_time`）时
    /// 比较自然为 `false`（保守，不提前放行）；加法溢出时返回 `false`。
    #[must_use]
    pub fn is_due(&self, now: Duration) -> bool {
        let Some(last) = self.last_attempt_time else {
            return false;
        };
        let Some(due_at) = last.checked_add(self.next_delay) else {
            return false;
        };
        now >= due_at
    }

    /// 发起一次重连尝试：`attempt_count += 1`。
    ///
    /// 返回是否允许尝试（未超过 `max_retries` 时 `true`）。
    /// 若已达到 `max_retries`，状态转入 `GiveUp` 并返回 `false`（不再累加计数）。
    pub fn begin_attempt(&mut self, now: Duration) -> bool {
        if self.attempt_count >= self.config.max_retries {
            self.state = ReconnectState::GiveUp;
            return false;
        }
        self.attempt_count += 1;
        self.state = ReconnectState::Reconnecting;
        self.last_attempt_time = Some(now);
        true
    }

    /// 重连成功：状态回 `Connected`，`attempt_count` 清零，`next_delay` 重置为 `initial_delay`。
    pub fn on_success(&mut self, now: Duration) {
        self.state = ReconnectState::Connected;
        self.attempt_count = 0;
        self.next_delay = self.config.initial_delay;
        self.last_attempt_time = Some(now);
    }

    /// 重连失败：保持 `Reconnecting`，按指数公式计算下一次 `next_delay`。
    ///
    /// `next_delay = min(initial_delay * factor^(attempt_count - 1), max_delay)`：
    /// 第 1 次失败后 `factor^0 = 1`（退避 = initial_delay），之后每次失败翻倍。
    pub fn on_attempt_failed(&mut self, now: Duration) {
        self.state = ReconnectState::Reconnecting;
        self.last_attempt_time = Some(now);
        self.next_delay = self.compute_backoff();
    }

    /// 当前状态只读。
    #[must_use]
    pub fn state(&self) -> &ReconnectState {
        &self.state
    }

    /// 当前尝试计数。
    #[must_use]
    pub fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    /// 下一次退避延迟只读。
    #[must_use]
    pub fn next_delay(&self) -> Duration {
        self.next_delay
    }

    /// 当前 `Reattempt` 快照（从未发生过时 `last_attempt_time` 用 `Duration::ZERO`）。
    #[must_use]
    pub fn snapshot(&self) -> Reattempt {
        Reattempt {
            attempt_count: self.attempt_count,
            last_attempt_time: self.last_attempt_time.unwrap_or(Duration::ZERO),
            next_delay: self.next_delay,
        }
    }

    /// 按当前 `attempt_count` 计算指数退避延迟（封顶 `max_delay`）。
    ///
    /// 指数 = `attempt_count.saturating_sub(1)`：初始断开（count=0）与第 1 次失败
    /// （count=1）均为 exponent 0 -> `initial_delay`；之后每次失败指数 +1。
    /// 浮点结果超过 `max_delay` 或非有限（溢出/NaN）时直接取 `max_delay`，避免
    /// `f64 as u64` 对 inf/NaN 取 0 的精度坑。
    fn compute_backoff(&self) -> Duration {
        let initial_ms = self.config.initial_delay.as_millis() as f64;
        let exp = self.attempt_count.saturating_sub(1);
        let raw_ms = initial_ms * self.config.backoff_factor.powi(exp as i32);
        let max_ms = self.config.max_delay.as_millis() as f64;
        if raw_ms >= max_ms || !raw_ms.is_finite() {
            self.config.max_delay
        } else {
            Duration::from_millis(raw_ms as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 假时钟：用一个 Cell 保存当前相对时间，供确定性推进。
    struct FakeClock {
        now: std::cell::Cell<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: std::cell::Cell::new(Duration::ZERO),
            }
        }
        /// 在当前时间上推进。
        fn advance(&self, d: Duration) {
            self.now.set(self.now.get() + d);
        }
    }

    impl ReconnectClock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }
    }

    /// 构造本场景的合法配置（max_retries=3, 100/800ms, factor=2.0）。
    ///
    /// 下面测试中 `.unwrap()` 仅用于这种已校验合法的配置构造，不会在业务路径 panic。
    fn cfg() -> ReconnectConfig {
        ReconnectConfig::new(
            3,
            Duration::from_millis(100),
            Duration::from_millis(800),
            2.0,
        )
        .expect("valid reconnect config")
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn rejects_invalid_configs() {
        // max_retries = 0
        assert!(matches!(
            ReconnectConfig::new(0, ms(100), ms(800), 2.0),
            Err(ReconnectError::InvalidConfig { .. })
        ));
        // initial_delay = 0
        assert!(matches!(
            ReconnectConfig::new(3, ms(0), ms(800), 2.0),
            Err(ReconnectError::InvalidConfig { .. })
        ));
        // max_delay < initial_delay
        assert!(matches!(
            ReconnectConfig::new(3, ms(200), ms(100), 2.0),
            Err(ReconnectError::InvalidConfig { .. })
        ));
        // backoff_factor < 1.0
        assert!(matches!(
            ReconnectConfig::new(3, ms(100), ms(800), 0.5),
            Err(ReconnectError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn initial_backoff_is_initial_delay() {
        let mut ctl = ReconnectController::new(cfg());
        let snap = ctl.on_disconnect(ms(0));
        assert_eq!(snap.next_delay, ms(100));
        assert_eq!(ctl.state(), &ReconnectState::Reconnecting);
        assert_eq!(ctl.attempt_count(), 0);
    }

    #[test]
    fn backoff_doubles_per_failure() {
        let mut ctl = ReconnectController::new(cfg());
        ctl.on_disconnect(ms(0));

        // 第 1 次失败：next_delay 仍为 initial（factor^0）。
        assert!(ctl.begin_attempt(ms(0)));
        ctl.on_attempt_failed(ms(0));
        assert_eq!(ctl.next_delay(), ms(100));

        // 第 2 次失败：翻倍到 200。
        assert!(ctl.begin_attempt(ms(100)));
        ctl.on_attempt_failed(ms(100));
        assert_eq!(ctl.next_delay(), ms(200));

        // 第 3 次失败：翻倍到 400。
        assert!(ctl.begin_attempt(ms(300)));
        ctl.on_attempt_failed(ms(300));
        assert_eq!(ctl.next_delay(), ms(400));
    }

    #[test]
    fn backoff_caps_at_max_delay() {
        // 大倍率 + 小上限：无论失败多少次，next_delay 都不超过 max_delay。
        let cfg = ReconnectConfig::new(100, ms(100), ms(150), 100.0).expect("valid");
        let mut ctl = ReconnectController::new(cfg);
        ctl.on_disconnect(ms(0));

        // 连续失败多次，指数暴涨；每一步都应被钳到 150ms。
        for t in [0u64, 100, 300, 700, 1500, 3100] {
            assert!(ctl.begin_attempt(ms(t)));
            ctl.on_attempt_failed(ms(t));
            assert!(ctl.next_delay() <= ms(150));
        }
        // 至少第二次起已经触顶 150。
        assert_eq!(ctl.next_delay(), ms(150));
    }

    #[test]
    fn gives_up_after_max_retries() {
        let mut ctl = ReconnectController::new(cfg());
        ctl.on_disconnect(ms(0));

        // 前 3 次尝试允许。
        assert!(ctl.begin_attempt(ms(0)));
        ctl.on_attempt_failed(ms(0));
        assert!(ctl.begin_attempt(ms(100)));
        ctl.on_attempt_failed(ms(100));
        assert!(ctl.begin_attempt(ms(300)));
        ctl.on_attempt_failed(ms(300));
        assert_eq!(ctl.attempt_count(), 3);

        // 第 4 次：达到 max_retries -> GiveUp 且不再累加。
        assert!(!ctl.begin_attempt(ms(700)));
        assert_eq!(ctl.state(), &ReconnectState::GiveUp);
        assert_eq!(ctl.attempt_count(), 3);
        // GiveUp 后再尝试仍 false。
        assert!(!ctl.begin_attempt(ms(10_000)));
    }

    #[test]
    fn success_resets_state() {
        let mut ctl = ReconnectController::new(cfg());
        ctl.on_disconnect(ms(0));
        // 失败两次。
        assert!(ctl.begin_attempt(ms(0)));
        ctl.on_attempt_failed(ms(0));
        assert!(ctl.begin_attempt(ms(100)));
        ctl.on_attempt_failed(ms(100));
        assert_eq!(ctl.attempt_count(), 2);
        assert_eq!(ctl.next_delay(), ms(200));

        // 退避中途成功：回到 Connected，计数清零，退避重置为 initial。
        ctl.on_success(ms(200));
        assert_eq!(ctl.state(), &ReconnectState::Connected);
        assert_eq!(ctl.attempt_count(), 0);
        assert_eq!(ctl.next_delay(), ms(100));
    }

    #[test]
    fn is_due_respects_backoff_deadline() {
        let mut ctl = ReconnectController::new(cfg());
        ctl.on_disconnect(ms(0));
        // next_delay = 100，due_at = 100。
        assert!(!ctl.is_due(ms(99))); // 未到期
        assert!(ctl.is_due(ms(100))); // 恰好到期
        assert!(ctl.is_due(ms(500))); // 已过期
    }

    #[test]
    fn clock_rollback_is_never_due() {
        let mut ctl = ReconnectController::new(cfg());
        ctl.on_disconnect(ms(300));
        ctl.begin_attempt(ms(300));
        ctl.on_attempt_failed(ms(300));
        // due_at = 300 + 400 = 700。
        assert!(ctl.is_due(ms(700)));
        // 时钟回退到 100 < last=300：保守返回 false。
        assert!(!ctl.is_due(ms(100)));
        assert!(!ctl.is_due(ms(299)));
    }

    #[test]
    fn give_up_then_disconnect_is_noop() {
        let mut ctl = ReconnectController::new(cfg());
        ctl.on_disconnect(ms(0));
        // 打满 max_retries 进入 GiveUp。
        for t in [0u64, 100, 300] {
            assert!(ctl.begin_attempt(ms(t)));
            ctl.on_attempt_failed(ms(t));
        }
        assert!(!ctl.begin_attempt(ms(700)));
        assert_eq!(ctl.state(), &ReconnectState::GiveUp);

        // GiveUp 后再收到断开事件：状态与计数都不变。
        let snap = ctl.on_disconnect(ms(10_000));
        assert_eq!(ctl.state(), &ReconnectState::GiveUp);
        assert_eq!(ctl.attempt_count(), 3);
        assert_eq!(snap.attempt_count, 3);
    }

    #[test]
    fn fresh_controller_has_no_pending_due() {
        let ctl = ReconnectController::new(cfg());
        // 从未断开：无待处理等待，is_due 恒 false。
        assert!(!ctl.is_due(ms(0)));
        assert!(!ctl.is_due(ms(10_000)));
        assert_eq!(ctl.state(), &ReconnectState::Idle);
    }

    #[test]
    fn clock_trait_real_impl_is_monotonic() {
        let c = MonotonicReconnectClock::new();
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
    }

    #[test]
    fn fake_clock_advances_deterministically() {
        let clock = FakeClock::new();
        let a = clock.now();
        clock.advance(ms(50));
        let b = clock.now();
        assert_eq!(b - a, ms(50));
    }
}
