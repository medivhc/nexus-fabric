//! 带宽控制 / QoS（令牌桶限流骨架，内存确定性）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的流量整形骨架：
//! - **令牌桶**（定义已下沉跨栈共享叶 `nexus-qos::bucket`，本模块 `pub use` 重导出）：
//!   `TokenBucket` 按固定字节速率向桶内补充令牌（上限 `burst_size`），
//!   `try_consume(bytes, now)` 够令牌则扣减并放行，不够直接拒绝（不阻塞、不 sleep）；
//! - **可注入时钟**：`QosClock` trait 抽象单调时间；真实实现基于 `std::time::Instant`，
//!   测试/场景用显式 `Duration` 假时钟推进，保证确定性；
//! - **方向与端点**：`QosController` 持有入站（ingress）/出站（egress）两个方向的桶，
//!   并按连接/节点 tag 维护 up/down 累计字节统计；命中限制的字节计入 `bytes_dropped`，
//!   放行字节计入 `bytes_allowed`。
//!
//! 边界（PRODUCT §12.8-bandwidth-qos 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实 socket / TUN / 内核 tc；
//! - 仅做基本令牌桶（refill + try_consume），无异步等待、不引入 tokio；
//! - 时钟由调用方通过 `now: Duration` 显式传入，模块自身不读墙钟；
//! - 不做：整形排队（shaping/缓冲）、优先级队列、公平排队、per-flow 哈希分流留 TODO。
//!
//! TODO（真实数据面集成，非本骨架范围）：
//! - 在 VirtualSubnetTunnel / RelayChannel 收发路径上挂接 `QosController` 作为门控；
//! - 把 `now` 接入真实单调时钟（`MonotonicClock`）并周期性 refill；
//! - 限流配置热加载、按路由/按节点的策略下发与持久化。
//!
//! 错误面：`QosError` 定义已下沉 `nexus_qos::bucket`（本模块 `pub use` 重导出），
//! 仍是类型化 enum，不以 panic / 日志代替。

use std::collections::HashMap;
use std::time::{Duration, Instant};

// 跨栈共享叶：令牌桶三类型与错误面定义已下沉 `nexus-qos`（2026-10-28，P3）。
// `pub use` 同时满足本模块留守代码（QosConfig / QosController）与旧路径消费者
// （`nexus_connectivity::qos::{BandwidthLimit, TokenBucket, QosError}`）零改动。
pub use nexus_qos::bucket::{BandwidthLimit, QosError, TokenBucket};

// ---------- 可注入时钟 ----------

/// 单调时钟抽象（可注入，便于用假时钟做确定性测试）。
///
/// 返回值是一个相对 `Duration`（自某个任意但单调递增的起点起算）；
/// 调用方把它直接作为 `now` 传给 `TokenBucket` / `QosController`。
pub trait QosClock {
    /// 当前单调时间点（相对时长）。
    fn now(&self) -> Duration;
}

/// 真实单调时钟：基于 `std::time::Instant`，返回自构造起经过的时长。
///
/// 线程安全、不回退；`Instant` 在同一进程内单调递增。
pub struct MonotonicClock {
    /// 起点（构造时刻）。
    start: Instant,
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock {
    /// 以当前时刻为起点构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl QosClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

// ---------- 配置与统计 ----------

/// QoS 配置：入站/出站两个方向各自的带宽限制；`None` 表示该方向不限制。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosConfig {
    /// 入站（ingress / 下载）方向限制；`None` 表示不限制。
    pub ingress: Option<BandwidthLimit>,
    /// 出站（egress / 上传）方向限制；`None` 表示不限制。
    pub egress: Option<BandwidthLimit>,
}

impl QosConfig {
    /// 构造配置（参数已在 `BandwidthLimit::new` 校验，这里直接组装）。
    #[must_use]
    pub fn new(ingress: Option<BandwidthLimit>, egress: Option<BandwidthLimit>) -> Self {
        Self { ingress, egress }
    }
}

/// 单个连接/节点的累计字节统计（只统计**放行**字节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PerEndpointStats {
    /// 出站（egress / 上传）累计放行字节。
    pub up_bytes: u64,
    /// 入站（ingress / 下载）累计放行字节。
    pub down_bytes: u64,
}

/// QoS 整体快照（聚合计数 + 各端点累计）。
#[derive(Debug, Clone, PartialEq)]
pub struct QosStats {
    /// 所有方向累计放行字节数。
    pub bytes_allowed: u64,
    /// 所有方向因命中限制被丢弃的字节数。
    pub bytes_dropped: u64,
    /// 出站方向当前剩余令牌（字节）。
    pub tokens_remaining: u64,
    /// 按连接/节点 tag 的累计统计（up/down 放行字节）。
    pub endpoints: HashMap<String, PerEndpointStats>,
}

// ---------- 控制器 ----------

/// QoS 控制器：持有入站/出站令牌桶，并维护聚合 + 按端点统计。
///
/// - `try_egress(tag, bytes, now)`：出站门控；命中限制返回 `false` 并计 `bytes_dropped`；
///   放行则扣令牌并把字节计入该 tag 的 `up_bytes` 与 `bytes_allowed`。
/// - `try_ingress(tag, bytes, now)`：入站门控；放行计入 `down_bytes`。
/// - 方向为 `None` 时不限制（恒放行）。
pub struct QosController {
    /// 出站令牌桶（`None` 表示不限制）。
    egress: Option<TokenBucket>,
    /// 入站令牌桶（`None` 表示不限制）。
    ingress: Option<TokenBucket>,
    /// 累计放行字节。
    bytes_allowed: u64,
    /// 累计被丢弃字节。
    bytes_dropped: u64,
    /// 按端点 tag 的累计统计。
    endpoints: HashMap<String, PerEndpointStats>,
}

impl QosController {
    /// 用配置构造控制器；两个方向的桶按 `BandwidthLimit` 建为满桶。
    #[must_use]
    pub fn new(config: &QosConfig) -> Self {
        Self {
            egress: config.egress.as_ref().map(TokenBucket::new),
            ingress: config.ingress.as_ref().map(TokenBucket::new),
            bytes_allowed: 0,
            bytes_dropped: 0,
            endpoints: HashMap::new(),
        }
    }

    /// 出站门控：尝试放行 `tag` 的 `bytes` 字节出站。
    ///
    /// 命中限制返回 `false`（计入 `bytes_dropped`，不计入任何 up 统计）；
    /// 放行返回 `true`（计入 `bytes_allowed` 与该 tag 的 `up_bytes`）。
    pub fn try_egress(&mut self, tag: &str, bytes: u64, now: Duration) -> bool {
        let allowed = match self.egress.as_mut() {
            Some(bucket) => bucket.try_consume(bytes, now),
            None => true,
        };
        if allowed {
            self.bytes_allowed += bytes;
            self.endpoints.entry(tag.to_string()).or_default().up_bytes += bytes;
        } else {
            self.bytes_dropped += bytes;
        }
        allowed
    }

    /// 入站门控：尝试放行 `tag` 的 `bytes` 字节入站。
    ///
    /// 语义同 `try_egress`，放行计入该 tag 的 `down_bytes`。
    pub fn try_ingress(&mut self, tag: &str, bytes: u64, now: Duration) -> bool {
        let allowed = match self.ingress.as_mut() {
            Some(bucket) => bucket.try_consume(bytes, now),
            None => true,
        };
        if allowed {
            self.bytes_allowed += bytes;
            self.endpoints
                .entry(tag.to_string())
                .or_default()
                .down_bytes += bytes;
        } else {
            self.bytes_dropped += bytes;
        }
        allowed
    }

    /// 当前统计快照（聚合计数 + 各端点 up/down 累计）。
    #[must_use]
    pub fn snapshot(&self) -> QosStats {
        QosStats {
            bytes_allowed: self.bytes_allowed,
            bytes_dropped: self.bytes_dropped,
            tokens_remaining: self
                .egress
                .as_ref()
                .map_or(0, TokenBucket::remaining_tokens),
            endpoints: self.endpoints.clone(),
        }
    }

    /// 出站桶当前剩余令牌（字节）。
    #[must_use]
    pub fn egress_tokens_remaining(&self) -> u64 {
        self.egress
            .as_ref()
            .map_or(0, TokenBucket::remaining_tokens)
    }

    /// 入站桶当前剩余令牌（字节）。
    #[must_use]
    pub fn ingress_tokens_remaining(&self) -> u64 {
        self.ingress
            .as_ref()
            .map_or(0, TokenBucket::remaining_tokens)
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

    impl QosClock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }
    }

    #[test]
    fn limit_rejects_zero_rate_and_zero_burst() {
        assert!(matches!(
            BandwidthLimit::new(0, 1000),
            Err(QosError::InvalidLimit { .. })
        ));
        assert!(matches!(
            BandwidthLimit::new(1000, 0),
            Err(QosError::InvalidLimit { .. })
        ));
        let ok = BandwidthLimit::new(1000, 1000).expect("valid limit");
        assert_eq!(ok.rate(), 1000);
        assert_eq!(ok.burst(), 1000);
    }

    #[test]
    fn initial_burst_is_allowed() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        // 初始满桶：恰好突发 burst_size 字节放行。
        assert!(bucket.try_consume(1000, Duration::ZERO));
        assert_eq!(bucket.remaining_tokens(), 0);
    }

    #[test]
    fn rate_refills_tokens_over_time() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        // 耗尽初始突发。
        assert!(bucket.try_consume(1000, Duration::ZERO));
        assert!(!bucket.try_consume(100, Duration::ZERO));
        // 推进 0.5 秒 -> 补 500 字节令牌。
        bucket.refill(Duration::from_millis(500));
        assert_eq!(bucket.remaining_tokens(), 500);
    }

    #[test]
    fn sustained_over_limit_is_rejected() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        assert!(bucket.try_consume(1000, Duration::ZERO));
        // 同刻再发 100 字节 -> 令牌已空 -> 拒绝。
        assert!(!bucket.try_consume(100, Duration::ZERO));
        // 同一时刻持续发送（无时间推进、无令牌补充）均被拒。
        assert!(!bucket.try_consume(50, Duration::ZERO));
    }

    #[test]
    fn clock_advance_recovers_tokens() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let clock = FakeClock::new();
        let mut bucket = TokenBucket::new(&limit);

        assert!(bucket.try_consume(1000, clock.now()));
        assert!(!bucket.try_consume(100, clock.now()));

        // 推进 1 秒 -> 补满 1000 -> 又可发。
        clock.advance(Duration::from_secs(1));
        assert!(bucket.try_consume(500, clock.now()));
        assert_eq!(bucket.remaining_tokens(), 500);
    }

    #[test]
    fn refill_caps_at_burst_capacity() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        // 长时间不消费，令牌不超过 capacity。
        bucket.refill(Duration::from_secs(60));
        assert_eq!(bucket.remaining_tokens(), 1000);
    }

    #[test]
    fn per_connection_stats_are_independent() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let cfg = QosConfig::new(None, Some(limit));
        let mut ctl = QosController::new(&cfg);
        let t0 = Duration::ZERO;

        // conn-a 放行 1000（突发）。
        assert!(ctl.try_egress("conn-a", 1000, t0));
        // conn-a 再发被拒（共享出站桶已空）。
        assert!(!ctl.try_egress("conn-a", 100, t0));
        // conn-b 也走同一出站桶：此刻同样被拒（聚合限流），但统计独立累计。
        // 推进 1 秒后恢复。
        let t1 = Duration::from_secs(1);
        assert!(ctl.try_egress("conn-b", 400, t1));

        let snap = ctl.snapshot();
        // conn-a 只累计自己放行的 1000，不被 conn-b 的 400 污染。
        assert_eq!(snap.endpoints["conn-a"].up_bytes, 1000);
        assert_eq!(snap.endpoints["conn-b"].up_bytes, 400);
    }

    #[test]
    fn rejected_bytes_count_as_dropped_not_allowed() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let cfg = QosConfig::new(None, Some(limit));
        let mut ctl = QosController::new(&cfg);
        let t0 = Duration::ZERO;

        assert!(ctl.try_egress("conn-a", 1000, t0)); // 放行 1000
        assert!(!ctl.try_egress("conn-a", 250, t0)); // 丢弃 250

        let snap = ctl.snapshot();
        assert_eq!(snap.bytes_allowed, 1000);
        assert_eq!(snap.bytes_dropped, 250);
        // 被拒的 250 不计入该端点 up_bytes。
        assert_eq!(snap.endpoints["conn-a"].up_bytes, 1000);
    }

    #[test]
    fn unlimited_direction_always_allows() {
        let cfg = QosConfig::new(None, None);
        let mut ctl = QosController::new(&cfg);
        assert!(ctl.try_egress("conn-a", 10_000_000, Duration::ZERO));
        assert!(ctl.try_ingress("conn-a", 10_000_000, Duration::ZERO));
        let snap = ctl.snapshot();
        assert_eq!(snap.bytes_dropped, 0);
        assert_eq!(snap.bytes_allowed, 20_000_000);
    }

    #[test]
    fn ingress_and_egress_are_separate_buckets() {
        let egress = BandwidthLimit::new(1000, 1000).unwrap();
        let ingress = BandwidthLimit::new(200, 200).unwrap();
        let cfg = QosConfig::new(Some(ingress), Some(egress));
        let mut ctl = QosController::new(&cfg);
        let t0 = Duration::ZERO;

        // 出站突发 1000 用尽出站桶。
        assert!(ctl.try_egress("a", 1000, t0));
        // 入站桶独立：仍可入站 200（不受出站桶耗尽影响）。
        assert!(ctl.try_ingress("a", 200, t0));
        assert_eq!(ctl.egress_tokens_remaining(), 0);
        assert_eq!(ctl.ingress_tokens_remaining(), 0);

        let snap = ctl.snapshot();
        assert_eq!(snap.endpoints["a"].up_bytes, 1000);
        assert_eq!(snap.endpoints["a"].down_bytes, 200);
    }

    #[test]
    fn clock_trait_real_impl_is_monotonic() {
        let c = MonotonicClock::new();
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
    }
    #[test]
    fn clock_rollback_does_not_grant_extra_tokens() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);

        // 消耗 800，剩 200。
        assert!(bucket.try_consume(800, Duration::ZERO));
        assert_eq!(bucket.remaining_tokens(), 200);
        // 推进到 0.5s：按 1000 B/s 补 500 -> 700，last_refill=0.5s。
        bucket.refill(Duration::from_millis(500));
        assert_eq!(bucket.remaining_tokens(), 700);

        // 时钟回退到 0.1s（< last_refill=0.5s）：refill 保守地不补充、也不改 last_refill。
        bucket.refill(Duration::from_millis(100));
        // 钉住真实行为：回退不导致多给令牌（仍为 700）。
        assert_eq!(bucket.remaining_tokens(), 700);
        // 回退后再正向推进到 0.6s：从 last_refill=0.5s 起算 0.1s 补 100 -> 800。
        bucket.refill(Duration::from_millis(600));
        assert_eq!(bucket.remaining_tokens(), 800);
    }

    #[test]
    fn burst_size_one_allows_only_single_byte_then_recovers() {
        let limit = BandwidthLimit::new(100, 1).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        // 初始 burst=1：只够 1 字节。
        assert!(bucket.try_consume(1, Duration::ZERO));
        // 同刻第 2 字节被拒。
        assert!(!bucket.try_consume(1, Duration::ZERO));
        assert_eq!(bucket.remaining_tokens(), 0);
        // 推进 1 秒：rate=100 B/s 补 100，但封顶 burst=1 -> 仍只有 1 字节。
        bucket.refill(Duration::from_secs(1));
        assert_eq!(bucket.remaining_tokens(), 1);
        assert!(bucket.try_consume(1, Duration::from_secs(1)));
    }

    #[test]
    fn zero_byte_consume_always_allowed_and_spends_nothing() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        let before = bucket.remaining_tokens();
        // 请求 0 字节：放行且不消耗令牌。
        assert!(bucket.try_consume(0, Duration::ZERO));
        assert_eq!(bucket.remaining_tokens(), before);
        // 跨越时间后再请求 0 字节同样放行，令牌不变。
        assert!(bucket.try_consume(0, Duration::from_millis(500)));
        assert_eq!(bucket.remaining_tokens(), before);
    }

    #[test]
    fn oversize_packet_is_rejected_as_whole_and_spends_nothing() {
        let limit = BandwidthLimit::new(1000, 1000).unwrap();
        let mut bucket = TokenBucket::new(&limit);
        // 消耗到剩 200。
        assert!(bucket.try_consume(800, Duration::ZERO));
        assert_eq!(bucket.remaining_tokens(), 200);
        // 单包请求 500 > 剩余 200：整包被拒，不按比例扣减。
        assert!(!bucket.try_consume(500, Duration::ZERO));
        // 令牌保持 200 不变。
        assert_eq!(bucket.remaining_tokens(), 200);
    }
}
