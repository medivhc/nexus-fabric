//! 智能重试（指数退避 + 错误分类 + 熔断器，内存骨架，纯逻辑）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的智能重试骨架：
//! - **退避**：`RetryExecutor::compute_backoff(attempt)` 按
//!   `initial_delay_ms * backoff_factor^(attempt-1)` 计算下次重试延迟（attempt 从 1 开始）；
//! - **错误分类**：`RetryableClass` 由调用方对错误做分类——`Retryable`（可重试）/
//!   `Fatal`（不可重试，本骨架仅记录，由 `decide` 配合 `max_attempts` 体现停止语义）；
//! - **熔断**：`CircuitState` 三态——`Closed`（正常）/ `Open { opened_at_ms }`
//!   （连续失败达 `failure_threshold` 后熔断）/ `HalfOpen`（冷却期过，放行一次试探）；
//! - **决策**：`decide(attempt, now_ms)` 在熔断未冷却时返回 `CircuitOpen { retry_after_ms }`；
//!   冷却期过返回一次 `AllowAttempt` 试探；超过 `max_attempts` 返回 `StopRetry`；
//!   否则 `AllowAttempt { attempt, next_delay_ms }`。
//!
//! 边界（PRODUCT §12-smart-retry 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不做真实 sleep / 不调度真实任务；
//! - 时间由调用方以 `now_ms: u64` 显式注入（仿 `bandwidth_policy` 的 `now_second`），
//!   模块自身不读墙钟；`HalfOpen` 是 `decide` 的只读计算结果，不持久化到状态；
//! - 退避乘法用 saturating，溢出时 cap 到 `u64::MAX/2`；
//! - 真实调度器、抖动（jitter）、熔断半开后的成功/失败过渡持久化留 TODO。
//!
//! TODO（真实执行集成，非本骨架范围）：
//! - 把 `decide` 接到真实异步调度器（在 `next_delay_ms` 后安排下一次尝试）；
//! - `now_ms` 接入真实单调时钟；加入 jitter 防惊群；
//! - 熔断半开后由真实试探结果决定回到 Closed 或重新 Open。
//!
//! 错误面独立：`RetryError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;

// ---------- 错误 ----------

/// 智能重试相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryError {
    /// 配置字段非法。
    InvalidConfig {
        /// 非法字段名（人可读）。
        field: String,
    },
}

impl fmt::Display for RetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(f, "RETRY_INVALID_CONFIG: field {field:?} is out of range")
            }
        }
    }
}

impl std::error::Error for RetryError {}

// ---------- 错误分类 ----------

/// 错误可重试分类（由调用方对业务错误分类后传入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryableClass {
    /// 可重试（网络抖动、超时等）。
    Retryable,
    /// 不可重试（参数错误、认证失败等）。
    Fatal,
}

impl RetryableClass {
    /// 返回稳定字符串标签（"retryable"/"fatal"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Fatal => "fatal",
        }
    }
}

// ---------- 熔断状态 ----------

/// 熔断器状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// 正常放行。
    Closed,
    /// 熔断打开（携带打开时的逻辑毫秒时间戳）。
    Open {
        /// 熔断打开的逻辑毫秒时间戳。
        opened_at_ms: u64,
    },
    /// 半开（冷却期过，放行一次试探；骨架内由 decide 只读计算）。
    HalfOpen,
}

impl CircuitState {
    /// 返回稳定字符串标签（"closed"/"open"/"half-open"）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open { .. } => "open",
            Self::HalfOpen => "half-open",
        }
    }
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 重试决策 ----------

/// 一次重试决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// 允许第 `attempt` 次尝试，下次延迟 `next_delay_ms`。
    AllowAttempt {
        /// 本次尝试序号（从 1 开始）。
        attempt: u32,
        /// 距上次尝试的建议延迟（毫秒）。
        next_delay_ms: u64,
    },
    /// 停止重试，原因固定。
    StopRetry {
        /// 停止原因（人可读静态串）。
        reason: &'static str,
    },
    /// 熔断中，需等待 `retry_after_ms` 毫秒后再试探。
    CircuitOpen {
        /// 距可再次试探的建议等待毫秒数。
        retry_after_ms: u64,
    },
}

impl RetryDecision {
    /// 返回稳定字符串标签（"allow-attempt"/"stop-retry"/"circuit-open"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AllowAttempt { .. } => "allow-attempt",
            Self::StopRetry { .. } => "stop-retry",
            Self::CircuitOpen { .. } => "circuit-open",
        }
    }
}

impl fmt::Display for RetryDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 智能重试配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryConfig {
    /// 最大尝试次数（含首次），必须 >= 1。
    max_attempts: u32,
    /// 首次重试延迟（毫秒），必须 > 0。
    initial_delay_ms: u64,
    /// 退避因子（必须 >= 1）。
    backoff_factor: u32,
    /// 连续失败达此阈值即熔断，必须 >= 1。
    failure_threshold: u32,
    /// 熔断打开持续时间（毫秒），必须 > 0。
    circuit_open_ms: u64,
}

impl RetryConfig {
    /// 构造配置并校验：
    /// - `max_attempts >= 1`；`initial_delay_ms > 0`；`backoff_factor >= 1`；
    /// - `failure_threshold >= 1`；`circuit_open_ms > 0`。
    pub fn new(
        max_attempts: u32,
        initial_delay_ms: u64,
        backoff_factor: u32,
        failure_threshold: u32,
        circuit_open_ms: u64,
    ) -> Result<Self, RetryError> {
        if max_attempts < 1 {
            return Err(RetryError::InvalidConfig {
                field: "max_attempts".to_string(),
            });
        }
        if initial_delay_ms == 0 {
            return Err(RetryError::InvalidConfig {
                field: "initial_delay_ms".to_string(),
            });
        }
        if backoff_factor < 1 {
            return Err(RetryError::InvalidConfig {
                field: "backoff_factor".to_string(),
            });
        }
        if failure_threshold < 1 {
            return Err(RetryError::InvalidConfig {
                field: "failure_threshold".to_string(),
            });
        }
        if circuit_open_ms == 0 {
            return Err(RetryError::InvalidConfig {
                field: "circuit_open_ms".to_string(),
            });
        }
        Ok(Self {
            max_attempts,
            initial_delay_ms,
            backoff_factor,
            failure_threshold,
            circuit_open_ms,
        })
    }

    /// 最大尝试次数。
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

// ---------- 执行器 ----------

/// 智能重试执行器：持有配置与熔断状态，纯内存纯逻辑。
///
/// 时钟为逻辑毫秒（`now_ms`），由调用方显式传入；不读墙钟、不阻塞、不 sleep。
pub struct RetryExecutor {
    /// 重试配置。
    config: RetryConfig,
    /// 连续失败计数。
    consecutive_failures: u32,
    /// 当前熔断状态。
    circuit: CircuitState,
    /// 最近一次尝试的逻辑毫秒时间戳。
    last_attempt_ms: Option<u64>,
}

impl<E: std::fmt::Debug> std::fmt::Display for RetryRunError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetryRunError::StopAttempts {
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "RETRY_STOP: exhausted after {attempts} attempts; last_error={last_error:?}"
                )
            }
            RetryRunError::Fatal { attempts, error } => {
                write!(
                    f,
                    "RETRY_FATAL: failed at attempt {attempts}; error={error:?}"
                )
            }
        }
    }
}

impl<E: std::fmt::Debug> std::error::Error for RetryRunError<E> {}

impl<E: std::fmt::Debug> RetryRunError<E> {
    /// 实际尝试次数。
    #[must_use]
    pub fn attempts(&self) -> u32 {
        match self {
            Self::StopAttempts { attempts, .. } | Self::Fatal { attempts, .. } => *attempts,
        }
    }
    /// 取走携带的最后一次业务错误（若有）。
    pub fn into_inner(self) -> Option<E> {
        match self {
            Self::StopAttempts { last_error, .. } => last_error,
            Self::Fatal { error, .. } => Some(error),
        }
    }
}

impl RetryExecutor {
    /// 用配置构造执行器；初始熔断 `Closed`、连续失败 0。
    #[must_use]
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            consecutive_failures: 0,
            circuit: CircuitState::Closed,
            last_attempt_ms: None,
        }
    }

    /// 计算第 `attempt` 次尝试的退避延迟（毫秒）。
    ///
    /// `delay = initial_delay_ms * backoff_factor^(attempt-1)`；attempt 从 1 开始。
    /// 溢出时 saturating 并 cap 到 `u64::MAX/2`。
    #[must_use]
    pub fn compute_backoff(&self, attempt: u32) -> u64 {
        let cap = u64::MAX / 2;
        if attempt <= 1 {
            return self.config.initial_delay_ms.min(cap);
        }
        let mut delay = self.config.initial_delay_ms;
        for _ in 1..attempt {
            delay = delay.saturating_mul(u64::from(self.config.backoff_factor));
            if delay >= cap {
                return cap;
            }
        }
        delay.min(cap)
    }

    /// 对第 `attempt` 次尝试做决策（逻辑毫秒 `now_ms`）。
    ///
    /// - 熔断 Open 且未冷却 -> `CircuitOpen { retry_after_ms }`；
    /// - 熔断 Open 且已过冷却 -> 视为 HalfOpen，本次放行一次 `AllowAttempt`；
    /// - `attempt > max_attempts` -> `StopRetry`；
    /// - 否则 `AllowAttempt { attempt, next_delay_ms: compute_backoff(attempt) }`。
    #[must_use]
    pub fn decide(&self, attempt: u32, now_ms: u64) -> RetryDecision {
        // 熔断门控。
        if let CircuitState::Open { opened_at_ms } = self.circuit {
            let elapsed = now_ms.saturating_sub(opened_at_ms);
            if elapsed < self.config.circuit_open_ms {
                let retry_after_ms = self.config.circuit_open_ms.saturating_sub(elapsed);
                return RetryDecision::CircuitOpen { retry_after_ms };
            }
            // 冷却期已过：视为 HalfOpen，本次放行一次试探（不持久化 HalfOpen）。
        }

        if attempt > self.config.max_attempts {
            return RetryDecision::StopRetry {
                reason: "max_attempts exceeded",
            };
        }

        RetryDecision::AllowAttempt {
            attempt,
            next_delay_ms: self.compute_backoff(attempt),
        }
    }

    /// 记录一次成功：清零连续失败、熔断回到 `Closed`。
    pub fn record_success(&mut self, now_ms: u64) {
        self.consecutive_failures = 0;
        self.circuit = CircuitState::Closed;
        self.last_attempt_ms = Some(now_ms);
    }

    /// 记录一次失败（逻辑毫秒 `now_ms`，错误分类 `class`）。
    ///
    /// - 连续失败 +1；记录 `last_attempt_ms`；
    /// - `class == Fatal` 时本骨架仅记录（停止语义由 `decide` 配合 `max_attempts` 体现）；
    /// - 连续失败达 `failure_threshold` -> 熔断 `Open { opened_at_ms: now_ms }`。
    pub fn record_failure(&mut self, now_ms: u64, class: RetryableClass) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_attempt_ms = Some(now_ms);
        if self.consecutive_failures >= self.config.failure_threshold {
            self.circuit = CircuitState::Open {
                opened_at_ms: now_ms,
            };
        }
        // RetryableClass::Fatal 在本骨架不额外改变状态；调用方应在 Fatal 后
        // 自行停止重试（decide 仍按 max_attempts 收敛）。
        let _ = class;
    }

    /// 连续失败计数。
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// 当前熔断状态。
    #[must_use]
    pub fn circuit_state(&self) -> &CircuitState {
        &self.circuit
    }

    /// 最近一次尝试的逻辑毫秒时间戳。
    #[must_use]
    pub fn last_attempt_ms(&self) -> Option<u64> {
        self.last_attempt_ms
    }
}

// === 12.40.3 真实执行集成（真实墙钟 + thread::sleep 退避） =====================

use std::thread;
use std::time::{Duration, Instant};

/// `RetryExecutor::execute` 的失败结果（携带最后一次业务错误与原因）。
#[derive(Debug)]
pub enum RetryRunError<E> {
    /// 超过 `max_attempts` 仍未成功。
    StopAttempts {
        /// 最后一次业务错误（若一次都没成功且 op 从未返回错误，则为 None）。
        last_error: Option<E>,
        /// 实际尝试次数。
        attempts: u32,
    },
    /// 业务侧判定为 `Fatal`，不再重试。
    Fatal {
        /// 触发 Fatal 的业务错误。
        error: E,
        /// 实际尝试次数（含本次）。
        attempts: u32,
    },
}

impl RetryExecutor {
    /// 真实墙钟驱动的退避重试循环（PRODUCT §12.40.3）。
    ///
    /// `op(attempt)` 返回 `Ok(T)` 成功；`Err((E, RetryableClass))`：
    /// - `Retryable`：`record_failure` 后按退避/熔断真实 sleep 再试；
    /// - `Fatal`：立即返回 `RetryRunError::Fatal`。
    ///
    /// 真实时间以本调用开始的 `Instant` 为零点喂给既有 `decide` / `record_*`；
    /// 退避与熔断冷却用 `std::thread::sleep` 真实阻塞。既有纯函数决策语义不变。
    pub fn execute<T, E, F>(&mut self, mut op: F) -> Result<T, RetryRunError<E>>
    where
        F: FnMut(u32) -> Result<T, (E, RetryableClass)>,
    {
        let start = Instant::now();
        let now_ms = || start.elapsed().as_millis() as u64;
        let mut attempt_no: u32 = 1;
        let mut last_error: Option<E> = None;

        loop {
            match self.decide(attempt_no, now_ms()) {
                RetryDecision::StopRetry { .. } => {
                    return Err(RetryRunError::StopAttempts {
                        last_error,
                        attempts: attempt_no.saturating_sub(1),
                    });
                }
                RetryDecision::CircuitOpen { retry_after_ms } => {
                    // 熔断冷却：真实等待后再试探。
                    thread::sleep(Duration::from_millis(retry_after_ms));
                    continue;
                }
                RetryDecision::AllowAttempt { attempt, .. } => {
                    // attempt>=2 时真实退避一个 backoff。
                    if attempt > 1 {
                        thread::sleep(Duration::from_millis(self.compute_backoff(attempt)));
                    }
                    match op(attempt) {
                        Ok(value) => {
                            self.record_success(now_ms());
                            return Ok(value);
                        }
                        Err((error, class)) => {
                            self.record_failure(now_ms(), class);
                            if class == RetryableClass::Fatal {
                                return Err(RetryRunError::Fatal {
                                    error,
                                    attempts: attempt,
                                });
                            }
                            last_error = Some(error);
                            attempt_no = attempt.saturating_add(1);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RetryConfig {
        RetryConfig::new(3, 100, 2, 2, 1000).expect("valid config")
    }

    #[test]
    fn backoff_is_exponential() {
        let ex = RetryExecutor::new(cfg());
        assert_eq!(ex.compute_backoff(1), 100);
        assert_eq!(ex.compute_backoff(2), 200);
        assert_eq!(ex.compute_backoff(3), 400);
    }

    #[test]
    fn decide_allows_within_attempts() {
        let ex = RetryExecutor::new(cfg());
        match ex.decide(1, 0) {
            RetryDecision::AllowAttempt {
                attempt,
                next_delay_ms,
            } => {
                assert_eq!(attempt, 1);
                assert_eq!(next_delay_ms, 100);
            }
            other => panic!("expected AllowAttempt, got {other:?}"),
        }
    }

    #[test]
    fn decide_stops_after_max_attempts() {
        let ex = RetryExecutor::new(cfg());
        match ex.decide(4, 0) {
            RetryDecision::StopRetry { reason } => assert_eq!(reason, "max_attempts exceeded"),
            other => panic!("expected StopRetry, got {other:?}"),
        }
    }

    #[test]
    fn consecutive_failures_open_circuit() {
        let mut ex = RetryExecutor::new(cfg());
        ex.record_failure(1000, RetryableClass::Retryable);
        assert_eq!(ex.consecutive_failures(), 1);
        assert_eq!(ex.circuit_state().as_str(), "closed");
        // 第二次失败达 failure_threshold=2 -> Open。
        ex.record_failure(2000, RetryableClass::Retryable);
        assert_eq!(ex.consecutive_failures(), 2);
        assert_eq!(ex.circuit_state().as_str(), "open");
    }

    #[test]
    fn decide_blocks_while_circuit_open() {
        let mut ex = RetryExecutor::new(cfg());
        ex.record_failure(1000, RetryableClass::Retryable);
        ex.record_failure(2000, RetryableClass::Retryable);
        // opened_at=2000, circuit_open_ms=1000：now=2500 仍在冷却。
        match ex.decide(1, 2500) {
            RetryDecision::CircuitOpen { retry_after_ms } => {
                assert_eq!(retry_after_ms, 500);
            }
            other => panic!("expected CircuitOpen, got {other:?}"),
        }
    }

    #[test]
    fn decide_allows_one_probe_after_cooldown() {
        let mut ex = RetryExecutor::new(cfg());
        ex.record_failure(1000, RetryableClass::Retryable);
        ex.record_failure(2000, RetryableClass::Retryable);
        // now=3000：elapsed=1000 >= circuit_open_ms=1000 -> 放行一次。
        match ex.decide(1, 3000) {
            RetryDecision::AllowAttempt { attempt, .. } => assert_eq!(attempt, 1),
            other => panic!("expected AllowAttempt after cooldown, got {other:?}"),
        }
    }

    #[test]
    fn record_success_resets_circuit() {
        let mut ex = RetryExecutor::new(cfg());
        ex.record_failure(1000, RetryableClass::Retryable);
        ex.record_failure(2000, RetryableClass::Retryable);
        assert_eq!(ex.circuit_state().as_str(), "open");
        ex.record_success(3000);
        assert_eq!(ex.consecutive_failures(), 0);
        assert_eq!(ex.circuit_state().as_str(), "closed");
        assert_eq!(ex.last_attempt_ms(), Some(3000));
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(RetryConfig::new(0, 100, 2, 2, 1000).is_err());
        assert!(RetryConfig::new(3, 0, 2, 2, 1000).is_err());
        assert!(RetryConfig::new(3, 100, 0, 2, 1000).is_err());
        assert!(RetryConfig::new(3, 100, 2, 0, 1000).is_err());
        assert!(RetryConfig::new(3, 100, 2, 2, 0).is_err());
        let err = RetryConfig::new(0, 100, 2, 2, 1000).unwrap_err();
        assert!(err.to_string().starts_with("RETRY_INVALID_CONFIG:"));
    }

    #[test]
    fn as_str_and_display() {
        assert_eq!(CircuitState::Closed.as_str(), "closed");
        assert_eq!(CircuitState::HalfOpen.as_str(), "half-open");
        assert_eq!(CircuitState::Open { opened_at_ms: 1 }.as_str(), "open");
        assert_eq!(
            RetryDecision::StopRetry { reason: "x" }.as_str(),
            "stop-retry"
        );
        assert_eq!(
            RetryDecision::CircuitOpen { retry_after_ms: 1 }.as_str(),
            "circuit-open"
        );
        assert_eq!(RetryableClass::Retryable.as_str(), "retryable");
        assert_eq!(RetryableClass::Fatal.as_str(), "fatal");
        assert_eq!(CircuitState::Closed.to_string(), "closed");
    }
}
