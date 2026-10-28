//! 令牌桶限流基元与类型化错误面（跨栈共享叶 `nexus-qos`）。
//!
//! 仅使用 `std`：不读时钟（`now: Duration` 由调用方注入）、无 I/O、无配置解析。
//! 定义自 `nexus-connectivity::qos` 下沉（2026-10-28，P3），语义逐字不变。

use std::fmt;
use std::time::Duration;

// ---------- 错误 ----------

/// QoS 相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QosError {
    /// 带宽限制参数非法（速率为 0、burst 为 0 等）。
    InvalidLimit {
        /// 非法原因（人可读）。
        message: String,
    },
}

impl fmt::Display for QosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { message } => write!(f, "QOS_INVALID_LIMIT: {message}"),
        }
    }
}

impl std::error::Error for QosError {}

// ---------- 带宽限制 ----------

/// 单方向带宽限制（令牌桶参数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthLimit {
    /// 平均速率（字节/秒），必须 > 0。
    pub max_bytes_per_sec: u64,
    /// 令牌桶容量（允许的初始突发字节数），必须 >= 1。
    pub burst_size: u64,
}

impl BandwidthLimit {
    /// 构造一个带宽限制；速率为 0 或 burst 为 0 返回 `InvalidLimit`。
    ///
    /// # Burst 配置警告（GAP-3 实测）
    ///
    /// `burst_size` 必须 ≥ 2×MTU（3028 字节，MTU=1514）。当 `burst < 2×MTU` 时，
    /// 令牌桶永远攒不够连续发包，实际速率会被**静默拉低**（实测：配置 1000KB/s、
    /// burst=1500 时实际只跑出 750KB/s）。建议 burst ≥ 10×MTU（15140 字节）。
    pub fn new(max_bytes_per_sec: u64, burst_size: u64) -> Result<Self, QosError> {
        if max_bytes_per_sec == 0 {
            return Err(QosError::InvalidLimit {
                message: format!("max_bytes_per_sec must be > 0 (got {max_bytes_per_sec})"),
            });
        }
        if burst_size == 0 {
            return Err(QosError::InvalidLimit {
                message: format!("burst_size must be >= 1 (got {burst_size})"),
            });
        }
        Ok(Self {
            max_bytes_per_sec,
            burst_size,
        })
    }

    /// 平均速率（字节/秒）只读访问。
    #[must_use]
    pub fn rate(&self) -> u64 {
        self.max_bytes_per_sec
    }

    /// 令牌桶容量只读访问。
    #[must_use]
    pub fn burst(&self) -> u64 {
        self.burst_size
    }
}

// ---------- 令牌桶 ----------

/// 令牌桶限流器（字节为单位）。
///
/// 初始令牌数 = `burst_size`；每经过 `elapsed` 时间，按 `rate` 字节/秒线性补充，
/// 上限为 `burst_size`。`try_consume` 不足时**不阻塞、不 sleep**，直接返回 `false`。
///
/// 时钟由调用方显式传入（`now: Duration`），保证单测/场景确定性。
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// 平均速率（字节/秒）。
    rate: u64,
    /// 令牌桶容量（上限）。
    capacity: u64,
    /// 当前可用令牌（浮点累积，避免整数取整误差）。
    tokens: f64,
    /// 上次 refill 的时间点。
    last_refill: Duration,
}

impl TokenBucket {
    /// 用带宽限制构造一个满桶令牌桶（初始即允许 `burst_size` 字节突发）。
    #[must_use]
    pub fn new(limit: &BandwidthLimit) -> Self {
        Self {
            rate: limit.max_bytes_per_sec,
            capacity: limit.burst_size,
            tokens: limit.burst_size as f64,
            last_refill: Duration::ZERO,
        }
    }

    /// 按经过时间补充令牌（线性 refill，封顶 `capacity`）。
    ///
    /// `now` 早于上次 refill（时间回退）时不补充、也不回拨 `last_refill`。
    pub fn refill(&mut self, now: Duration) {
        let Some(elapsed) = now.checked_sub(self.last_refill) else {
            return;
        };
        let added = elapsed.as_secs_f64() * self.rate as f64;
        self.tokens = (self.tokens + added).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// 尝试消费 `bytes` 个令牌；够则扣减并返回 `true`，不够返回 `false`。
    ///
    /// 调用前先按 `now` refill；不阻塞、不 sleep。
    pub fn try_consume(&mut self, bytes: u64, now: Duration) -> bool {
        self.refill(now);
        let need = bytes as f64;
        if self.tokens >= need {
            self.tokens -= need;
            true
        } else {
            false
        }
    }

    /// 当前剩余令牌（向下取整为整数字节；供快照/诊断）。
    #[must_use]
    pub fn remaining_tokens(&self) -> u64 {
        // tokens >= 0（refill 只增不减、consume 只在足够时扣减）。
        self.tokens.floor() as u64
    }

    /// 令牌桶容量。
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// 平均速率（字节/秒）。
    #[must_use]
    pub fn rate(&self) -> u64 {
        self.rate
    }
}
