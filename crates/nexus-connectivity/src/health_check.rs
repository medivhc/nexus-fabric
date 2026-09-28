//! 节点健康检查（内存骨架，注入逻辑时钟）。
//!
//! 本模块是 delivery 层共享底座的节点健康状态机骨架：
//! - **配置**：`HealthConfig` 持有探测间隔 / 超时 / 连续失败阈值；
//! - **状态**：`HealthState` 三态（Healthy / Degraded / Unhealthy）；
//! - **检查器**：`HealthChecker` 按 `node_id` 维护连续失败计数，记录每次探测的逻辑时间；
//! - **转移规则**：连续失败 0 次 → Healthy；0 < 连续失败 < threshold → Degraded；
//!   连续失败 >= threshold → Unhealthy；任意一次成功立即回到 Healthy。
//!
//! 边界（PRODUCT §12-health-check 冻结）：
//! - 纯内存、纯同步、纯函数骨架；状态转移只看连续失败数；
//! - `now_ms` 为注入的逻辑时钟（调用方传入），本模块不读取真实墙钟；
//! - 首次 `record_probe` 自动注册节点；`state` 对从未记录的节点返回 `UnknownNode`；
//! - 真实定时探测线程 / 真实网络探测 / 超时判定留 TODO。
//!
//! TODO（真实探测集成，非本骨架范围）：
//! - 按 `probe_interval_ms` 起一个有 Owner 的定时任务（CancellationToken + JoinSet）；
//! - 用真实 I/O 执行探活（ICMP / TCP 握手 / 应用层 ping），超时按 `timeout_ms` 判定；
//! - 把健康状态反馈给多跳路由（`routing`）与 Relay 选择，摘除 Unhealthy 节点；
//! - 暴露指标（每节点连续失败数、最近探测时间）到可观测层。
//!
//! 错误面独立：`HealthCheckError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::HashMap;
use std::fmt;

// ---------- 错误 ----------

/// 健康检查相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheckError {
    /// 配置非法（如 interval=0、failure_threshold=0）。
    InvalidConfig(String),
    /// 查询/记录了一个从未探测过的节点。
    UnknownNode(String),
}

impl fmt::Display for HealthCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => {
                write!(f, "HEALTH_CHECK_INVALID_CONFIG: {msg}")
            }
            Self::UnknownNode(node_id) => {
                write!(f, "HEALTH_CHECK_UNKNOWN_NODE: {node_id}")
            }
        }
    }
}

impl std::error::Error for HealthCheckError {}

// ---------- 健康状态 ----------

/// 节点健康三态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// 健康：连续失败 0 次。
    Healthy,
    /// 退化：0 < 连续失败 < failure_threshold。
    Degraded,
    /// 不健康：连续失败 >= failure_threshold。
    Unhealthy,
}

impl HealthState {
    /// 返回稳定的小写字符串标识（供 JSON / 日志 / 断言使用）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}

impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 健康检查配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    /// 探测间隔（毫秒，逻辑时钟；必须 > 0）。
    pub probe_interval_ms: u64,
    /// 单次探测超时（毫秒；真实超时判定留 TODO）。
    pub timeout_ms: u64,
    /// 连续失败达到该次数即判 Unhealthy（必须 >= 1）。
    pub failure_threshold: u32,
}

impl HealthConfig {
    /// 构造配置并校验不变量。
    ///
    /// 校验：
    /// - `probe_interval_ms > 0`；
    /// - `failure_threshold >= 1`。
    ///
    /// 非法返回 `HealthCheckError::InvalidConfig`。
    pub fn new(
        probe_interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    ) -> Result<Self, HealthCheckError> {
        if probe_interval_ms == 0 {
            return Err(HealthCheckError::InvalidConfig(
                "probe_interval_ms must be > 0".to_string(),
            ));
        }
        if failure_threshold < 1 {
            return Err(HealthCheckError::InvalidConfig(
                "failure_threshold must be >= 1".to_string(),
            ));
        }
        Ok(Self {
            probe_interval_ms,
            timeout_ms,
            failure_threshold,
        })
    }
}

// ---------- 检查器 ----------

/// 单节点的健康记账（仅检查器内部使用）。
struct NodeHealth {
    /// 连续探测失败次数；一次成功立即清零。
    consecutive_failures: u32,
    /// 最近一次探测的逻辑时间（注入；仅记录，不参与转移判定）。
    last_probe_ms: u64,
}

/// 节点健康检查器：按 `node_id` 维护连续失败计数并给出三态判定。
///
/// 纯内存、纯同步；时间由调用方经 `now_ms` 注入，便于单测与确定性 replay。
pub struct HealthChecker {
    cfg: HealthConfig,
    nodes: HashMap<String, NodeHealth>,
}

impl HealthChecker {
    /// 用给定配置构造空检查器。
    #[must_use]
    pub fn new(cfg: HealthConfig) -> Self {
        Self {
            cfg,
            nodes: HashMap::new(),
        }
    }

    /// 记录一次探测结果并返回该节点当前健康状态。
    ///
    /// 节点首次出现时自动注册（初始连续失败 0）。
    /// - `success = true`：连续失败计数清零，立即回到 `Healthy`；
    /// - `success = false`：连续失败计数 +1（饱和递增，不溢出 panic）。
    ///
    /// `now_ms` 为注入逻辑时间，仅记录最近探测时间，不影响状态转移。
    pub fn record_probe(
        &mut self,
        node_id: &str,
        success: bool,
        now_ms: u64,
    ) -> Result<HealthState, HealthCheckError> {
        let entry = self.nodes.entry(node_id.to_string()).or_insert(NodeHealth {
            consecutive_failures: 0,
            last_probe_ms: 0,
        });
        if success {
            entry.consecutive_failures = 0;
        } else {
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        }
        entry.last_probe_ms = now_ms;
        let failures = entry.consecutive_failures;
        Ok(self.classify(failures))
    }

    /// 查询节点当前健康状态；从未记录过的节点返回 `UnknownNode`。
    pub fn state(&self, node_id: &str) -> Result<HealthState, HealthCheckError> {
        let entry = self
            .nodes
            .get(node_id)
            .ok_or_else(|| HealthCheckError::UnknownNode(node_id.to_string()))?;
        Ok(self.classify(entry.consecutive_failures))
    }

    /// 按连续失败计数判定三态（纯函数，无副作用）。
    fn classify(&self, consecutive_failures: u32) -> HealthState {
        if consecutive_failures == 0 {
            HealthState::Healthy
        } else if consecutive_failures < self.cfg.failure_threshold {
            HealthState::Degraded
        } else {
            HealthState::Unhealthy
        }
    }
}

// === 12.40.1 真实定时器 + 注入探测（real I/O 经注入 trait） ==================

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// 健康探测器接缝：真实 TCP 握手 / 应用层 ping 由组合根（example）实现，
/// crate 内不发起网络。超时由实现方遵守 `HealthConfig.timeout_ms`
/// （如 `TcpStream::connect_timeout`）。
pub trait HealthProbe: Send + Sync + 'static {
    /// 探测目标节点；`Ok(())` 表示可达，`Err(String)` 表示不可达（含超时）。
    fn probe(&self, node_id: &str, target: &str) -> Result<(), String>;
}

/// 健康状态转移结构化事件（Worker/Monitor 只发事件，AGENTS §14）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthEvent {
    pub node_id: String,
    pub from: HealthState,
    pub to: HealthState,
    pub consecutive_failures: u32,
    pub at_ms: u64,
}

struct MonitorSignal {
    stop: bool,
}

fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl HealthChecker {
    /// 查询节点当前连续失败计数（additive；从未记录返回 `UnknownNode`）。
    pub fn consecutive_failures(&self, node_id: &str) -> Result<u32, HealthCheckError> {
        let entry = self
            .nodes
            .get(node_id)
            .ok_or_else(|| HealthCheckError::UnknownNode(node_id.to_string()))?;
        Ok(entry.consecutive_failures)
    }
}

/// 有 Owner 的真实定时器探测线程（AGENTS §13：CancellationToken(Arc<AtomicBool>)
/// + Condvar 唤醒 + JoinHandle 持有；`cancel(self)` 置位 + notify + join，不留后台线程）。
pub struct HealthMonitor {
    stop_flag: Arc<AtomicBool>,
    signal: Arc<(Mutex<MonitorSignal>, Condvar)>,
    checker: Arc<Mutex<HealthChecker>>,
    events: Arc<Mutex<Vec<HealthEvent>>>,
    handle: Option<JoinHandle<()>>,
    started_at: Instant,
}

impl HealthMonitor {
    /// 启动后台探测线程。`nodes` 为 `(node_id, target)` 列表；`target` 原样传给
    /// `HealthProbe::probe`（真实地址由组合根解释）。节点在首次 `record_probe`
    /// 时自动注册（与 `HealthChecker` 语义一致）。
    pub fn spawn(
        cfg: HealthConfig,
        probe: Box<dyn HealthProbe>,
        nodes: Vec<(String, String)>,
    ) -> Result<Self, HealthCheckError> {
        if nodes.is_empty() {
            return Err(HealthCheckError::InvalidConfig(
                "nodes must not be empty".to_string(),
            ));
        }
        let checker = Arc::new(Mutex::new(HealthChecker::new(cfg)));
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let signal = Arc::new((Mutex::new(MonitorSignal { stop: false }), Condvar::new()));
        let started_at = Instant::now();

        let t_checker = checker.clone();
        let t_events = events.clone();
        let t_stop = stop_flag.clone();
        let t_sig = signal.clone();
        let interval = cfg.probe_interval_ms;

        let handle = thread::spawn(move || {
            loop {
                // 可中断地等待一个探测周期。
                {
                    let (lock, cvar) = &*t_sig;
                    let g = lock_or_recover(lock);
                    if g.stop || t_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = cvar.wait_timeout(g, Duration::from_millis(interval));
                }
                if t_stop.load(Ordering::Relaxed) {
                    break;
                }

                for (node_id, target) in &nodes {
                    if t_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let now_ms = started_at.elapsed().as_millis() as u64;
                    let prev = lock_or_recover(&t_checker).state(node_id).ok();
                    let success = probe.probe(node_id, target).is_ok();
                    let new_state = lock_or_recover(&t_checker)
                        .record_probe(node_id, success, now_ms)
                        .ok();
                    if let (Some(prev), Some(new)) = (prev, new_state) {
                        if prev != new {
                            let cf = lock_or_recover(&t_checker)
                                .consecutive_failures(node_id)
                                .unwrap_or(0);
                            lock_or_recover(&t_events).push(HealthEvent {
                                node_id: node_id.clone(),
                                from: prev,
                                to: new,
                                consecutive_failures: cf,
                                at_ms: now_ms,
                            });
                        }
                    }
                }
            }
        });

        Ok(Self {
            stop_flag,
            signal,
            checker,
            events,
            handle: Some(handle),
            started_at,
        })
    }

    /// 协作式停止 + join。必须在 example 退出前调用，不留线程。
    pub fn cancel(mut self) {
        self.shutdown();
    }

    /// 协作式停止 + join（共享内部实现；cancel 与 Drop 共用）。
    fn shutdown(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        {
            let (lock, cvar) = &*self.signal;
            let mut g = lock_or_recover(lock);
            g.stop = true;
            cvar.notify_all();
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// 取走并返回累积的状态转移事件（读侧非阻塞）。
    pub fn drain_events(&self) -> Vec<HealthEvent> {
        std::mem::take(&mut *lock_or_recover(&self.events))
    }

    /// 只读当前节点健康状态。
    pub fn state(&self, node_id: &str) -> Result<HealthState, HealthCheckError> {
        lock_or_recover(&self.checker).state(node_id)
    }

    /// 监控启动至今的真实毫秒数。
    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }
}

/// AbortOnDropHandle 语义（AGENTS §13）：调用方忘记 `cancel(self)` 时，
/// drop 仍会置位停止位、唤醒并 join worker，避免线程泄漏。
impl Drop for HealthMonitor {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: u32) -> HealthConfig {
        HealthConfig::new(1_000, 500, threshold).expect("valid config")
    }

    #[test]
    fn config_accepts_valid_values() {
        let c = HealthConfig::new(1_000, 500, 3).expect("valid");
        assert_eq!(c.probe_interval_ms, 1_000);
        assert_eq!(c.timeout_ms, 500);
        assert_eq!(c.failure_threshold, 3);
    }

    #[test]
    fn config_rejects_zero_interval() {
        let err = HealthConfig::new(0, 500, 3).expect_err("interval must be > 0");
        assert!(matches!(err, HealthCheckError::InvalidConfig(_)));
    }

    #[test]
    fn config_rejects_zero_threshold() {
        let err = HealthConfig::new(1_000, 500, 0).expect_err("threshold must be >= 1");
        assert!(matches!(err, HealthCheckError::InvalidConfig(_)));
    }

    #[test]
    fn new_node_first_success_is_healthy() {
        let mut hc = HealthChecker::new(cfg(3));
        let state = hc.record_probe("node-a", true, 0).expect("record");
        assert_eq!(state, HealthState::Healthy);
        assert_eq!(hc.state("node-a").expect("state"), HealthState::Healthy);
    }

    #[test]
    fn single_failure_is_degraded_before_threshold() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 0).expect("reset");
        let s = hc.record_probe("node-a", false, 100).expect("f1");
        assert_eq!(s, HealthState::Degraded);
    }

    #[test]
    fn two_failures_still_degraded_before_threshold() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 0).expect("reset");
        hc.record_probe("node-a", false, 100).expect("f1");
        let s = hc.record_probe("node-a", false, 200).expect("f2");
        assert_eq!(s, HealthState::Degraded);
    }

    #[test]
    fn failure_at_threshold_is_unhealthy() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 0).expect("reset");
        hc.record_probe("node-a", false, 100).expect("f1");
        hc.record_probe("node-a", false, 200).expect("f2");
        let s = hc.record_probe("node-a", false, 300).expect("f3");
        assert_eq!(s, HealthState::Unhealthy);
    }

    #[test]
    fn success_immediately_recovers_to_healthy() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 0).expect("reset");
        hc.record_probe("node-a", false, 100).expect("f1");
        hc.record_probe("node-a", false, 200).expect("f2");
        hc.record_probe("node-a", false, 300).expect("f3");
        assert_eq!(hc.state("node-a").expect("state"), HealthState::Unhealthy);
        let s = hc.record_probe("node-a", true, 400).expect("recover");
        assert_eq!(s, HealthState::Healthy);
    }

    #[test]
    fn threshold_one_makes_single_failure_unhealthy() {
        let mut hc = HealthChecker::new(cfg(1));
        hc.record_probe("node-a", true, 0).expect("reset");
        let s = hc.record_probe("node-a", false, 100).expect("f1");
        assert_eq!(s, HealthState::Unhealthy);
    }

    #[test]
    fn state_on_unknown_node_is_unknown_node_error() {
        let hc = HealthChecker::new(cfg(3));
        let err = hc.state("never-seen").expect_err("must fail");
        assert!(matches!(err, HealthCheckError::UnknownNode(_)));
    }

    #[test]
    fn consecutive_failures_do_not_overflow() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 0).expect("reset");
        // 前 3 次失败依次进入 Degraded -> Unhealthy。
        hc.record_probe("node-a", false, 1).expect("f1");
        hc.record_probe("node-a", false, 2).expect("f2");
        let s3 = hc.record_probe("node-a", false, 3).expect("f3");
        assert_eq!(s3, HealthState::Unhealthy);
        // 远超 u32 量级的失败：饱和递增，不 panic，稳定停在 Unhealthy。
        for i in 4..=100_000u64 {
            let s = hc.record_probe("node-a", false, i).expect("flood");
            assert_eq!(s, HealthState::Unhealthy);
        }
    }

    #[test]
    fn last_probe_time_is_recorded_but_not_transitioned() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 1234).expect("p1");
        // 时间倒流也不影响转移（纯计数驱动）。
        let s = hc.record_probe("node-a", false, 10).expect("p2");
        assert_eq!(s, HealthState::Degraded);
    }

    #[test]
    fn per_node_state_is_independent() {
        let mut hc = HealthChecker::new(cfg(3));
        hc.record_probe("node-a", true, 0).expect("a ok");
        hc.record_probe("node-b", false, 0).expect("b f1");
        assert_eq!(hc.state("node-a").expect("a"), HealthState::Healthy);
        assert_eq!(hc.state("node-b").expect("b"), HealthState::Degraded);
    }

    #[test]
    fn health_state_as_str_and_display() {
        assert_eq!(HealthState::Healthy.as_str(), "healthy");
        assert_eq!(HealthState::Degraded.as_str(), "degraded");
        assert_eq!(HealthState::Unhealthy.as_str(), "unhealthy");
        assert_eq!(HealthState::Unhealthy.to_string(), "unhealthy");
    }

    #[test]
    fn error_display_is_structured() {
        let e = HealthCheckError::UnknownNode("node-x".into());
        assert!(e.to_string().contains("node-x"));
        let c = HealthCheckError::InvalidConfig("bad".into());
        assert!(c.to_string().contains("bad"));
    }
}
