//! 热路径日志限频（PRODUCT.md：hot path 只计数，不写 per-packet 日志）。
//!
//! 语义与 `proxy_fwd::udp_relay` 的 `event=udp_unsupported` 限频一致（review
//! MAJOR-2/C4）：
//!
//! - 同一 `(tag, cause)` **首次立即发射**（首条不得被窗口吞掉）；
//! - 其后同一键在窗口内只累加抑制计数，不再发射；
//! - 窗口到期后的下一次调用发射，并把累计的抑制条数以 `suppressed=<n>` 带出，
//!   随后清零。
//!
//! 状态按 `(tag, cause)` 分键：不同出站 / 不同失败原因互不吞日志。
//! 稳态抑制路径用 `&str` 借用查找 + 一个 `u64` 自增，**不分配**、不格式化文案。

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// `event=outbound_unavailable` 的限频窗口（与 `udp_unsupported` 同为 10 s）。
pub(crate) const OUTBOUND_UNAVAILABLE_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 单次限频决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThrottleDecision {
    /// 本次是否应发射日志行。
    pub(crate) emit: bool,
    /// 发射时随行带出的被抑制条数（`emit == false` 时恒为 0）。
    pub(crate) suppressed: u64,
}

/// 单个 `(tag, cause)` 的限频状态。
#[derive(Debug, Clone, Copy)]
struct KeyState {
    last_emit: Instant,
    suppressed: u64,
}

/// `(tag, cause)` 维度的限频状态（每个前端各持一份）。
///
/// 两层 `HashMap` 而不是 `HashMap<(String, String), _>`：借用 `&str` 逐层查找
/// 即可命中的键，稳态抑制路径上不构造 owned key（零分配）。
#[derive(Debug, Default)]
pub(crate) struct KeyedLogThrottle {
    state: HashMap<String, HashMap<String, KeyState>>,
}

impl KeyedLogThrottle {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 纯决策（无 IO、无日志）：给定键与时钟返回发射/抑制。
    ///
    /// 时钟由调用方传入，便于单测在固定 `Instant` 上断言窗口边界，
    /// 不依赖 `sleep`。
    pub(crate) fn decide(
        &mut self,
        tag: &str,
        cause: &str,
        now: Instant,
        interval: Duration,
    ) -> ThrottleDecision {
        if let Some(entry) = self
            .state
            .get_mut(tag)
            .and_then(|causes| causes.get_mut(cause))
        {
            if now.duration_since(entry.last_emit) >= interval {
                let suppressed = entry.suppressed;
                entry.suppressed = 0;
                entry.last_emit = now;
                return ThrottleDecision {
                    emit: true,
                    suppressed,
                };
            }
            entry.suppressed += 1;
            return ThrottleDecision {
                emit: false,
                suppressed: 0,
            };
        }
        // 首次出现（或该键从未出现过）：分配键一次，立即发射。
        self.state.entry(tag.to_string()).or_default().insert(
            cause.to_string(),
            KeyState {
                last_emit: now,
                suppressed: 0,
            },
        );
        ThrottleDecision {
            emit: true,
            suppressed: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    /// 窗口内连续调用：只有首个产生发射决策，其余进入抑制计数；
    /// 窗口到期后再次发射并带出抑制条数，随后计数清零。
    #[test]
    fn first_emits_then_window_suppresses_and_reports_count() {
        let mut throttle = KeyedLogThrottle::new();
        let base = Instant::now();
        let interval = OUTBOUND_UNAVAILABLE_LOG_INTERVAL;

        let first = throttle.decide("bad", "PLAINTEXT_TROJAN_UNSUPPORTED", at(base, 0), interval);
        assert!(first.emit, "first occurrence must emit immediately");
        assert_eq!(first.suppressed, 0);

        for step in 1..=4 {
            let decision = throttle.decide(
                "bad",
                "PLAINTEXT_TROJAN_UNSUPPORTED",
                at(base, step * 1000),
                interval,
            );
            assert!(!decision.emit, "in-window calls must not emit");
            assert_eq!(decision.suppressed, 0);
        }

        // 窗口边界之后：发射并带出此前被抑制的 4 条。
        let after = throttle.decide(
            "bad",
            "PLAINTEXT_TROJAN_UNSUPPORTED",
            at(base, 10_000),
            interval,
        );
        assert!(after.emit);
        assert_eq!(after.suppressed, 4);

        // 计数已清零：紧接着的下一次调用重新从 0 开始累加。
        let next = throttle.decide(
            "bad",
            "PLAINTEXT_TROJAN_UNSUPPORTED",
            at(base, 10_500),
            interval,
        );
        assert!(!next.emit);
        let later = throttle.decide(
            "bad",
            "PLAINTEXT_TROJAN_UNSUPPORTED",
            at(base, 20_000),
            interval,
        );
        assert!(later.emit);
        assert_eq!(later.suppressed, 1, "suppressed counter resets after emit");
    }

    /// 键隔离：不同 tag 或不同 cause 各自首次立即发射，互不吞日志。
    #[test]
    fn keys_are_independent() {
        let mut throttle = KeyedLogThrottle::new();
        let base = Instant::now();
        let interval = OUTBOUND_UNAVAILABLE_LOG_INTERVAL;

        assert!(
            throttle
                .decide("a", "UNKNOWN_OUTBOUND", at(base, 0), interval)
                .emit
        );
        assert!(
            throttle
                .decide("b", "UNKNOWN_OUTBOUND", at(base, 1), interval)
                .emit
        );
        assert!(
            throttle
                .decide("a", "PROTOCOL_NOT_WIRED", at(base, 2), interval)
                .emit
        );
        assert!(
            !throttle
                .decide("a", "UNKNOWN_OUTBOUND", at(base, 3), interval)
                .emit
        );
    }
}
