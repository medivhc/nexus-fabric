//! 策略热加载文件 watcher（§12.58 扩展）。
//!
//! 轮询 TOML 配置文件的 `[routing] strategy` 段，变化时解析并调用
//! `SharedFibManager<RoutingStrategy>::set_strategy()` 热应用，无需重启。
//!
//! # 位置理由
//!
//! 配置文件归属 app 层（`crate::subnet_cli::SubnetConfig` 拥有 TOML 解析）；
//! `nexus-discovery` 是可移植纯库，不做文件 I/O、不 spawn 线程、不引入
//! TOML 依赖。watcher 是 app 层装配逻辑，故放在 `apps/nexus`。
//!
//! # 结构化并发（AGENTS.md §13）
//!
//! - **谁创建**：调用 `StrategyWatcher::start()` 的组件（daemon/CLI）。
//! - **谁拥有**：返回的 `StrategyWatcher` handle（拥有 `JoinHandle` +
//!   停止信号 + 事件缓冲），不使用全局单例。
//! - **谁取消**：`stop()` 置 `Arc<AtomicBool>` 停止标志（协作式）。
//! - **谁回收**：`stop()` join 工作线程；`Drop` 在非 watcher 线程时也 join。
//! - **谁记录结果**：有界环形缓冲 `VecDeque<ReloadEvent>`，`events()` 查询。
//!
//! # 加锁顺序
//!
//! 工作线程按 **lsdb 读锁 → fib 写锁** 顺序加锁。应用层不得在持有 fib
//! 读锁（`SharedFibManager::read()` guard）时再取 lsdb 写锁，否则可能与
//! watcher 交叉死锁。

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nexus_discovery::lsa::Lsdb;
use nexus_discovery::routing::{RoutingStrategy, SharedFibManager};

/// 默认轮询间隔：1 秒。
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// 默认事件缓冲容量：64 条。
pub const DEFAULT_MAX_EVENTS: usize = 64;
/// 停止响应性：内部 sleep 切片上限（stop 延迟 ≤ 1 个轮询间隔）。
const SLEEP_SLICE: Duration = Duration::from_millis(100);

/// watcher 配置。
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// 被监听的 subnet TOML 配置文件路径。
    pub config_path: PathBuf,
    /// 轮询间隔。
    pub poll_interval: Duration,
    /// 事件环形缓冲容量（≥1）。
    pub max_events: usize,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            config_path: PathBuf::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

/// reload 事件种类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadEventKind {
    /// 成功应用新策略（含重算后的代际）。
    Applied { strategy: String, generation: u64 },
    /// 文件内容变化但解析出的策略与上次相同（未触发重算）。
    Unchanged,
    /// TOML 解析或策略字符串解析失败；旧策略与旧 FIB 原样保留。
    ParseFailed { reason: String },
    /// 文件读取失败（不存在/权限）；旧策略与旧 FIB 原样保留。
    ReadFailed { reason: String },
}

/// 一次 reload 尝试的记录。
#[derive(Debug, Clone)]
pub struct ReloadEvent {
    /// 单调递增序号（watcher 生命周期内唯一）。
    pub seq: u64,
    /// UNIX 毫秒时间戳。
    pub timestamp_ms: u64,
    /// 事件种类。
    pub kind: ReloadEventKind,
}

/// 策略热加载 watcher handle（§12.58）。
///
/// 拥有工作线程、停止信号与事件缓冲。归属调用 `start()` 的组件。
pub struct StrategyWatcher {
    handle: Option<JoinHandle<()>>,
    /// 工作线程的 ThreadId（用于 Drop 时避免自 join）。
    worker_id: Option<thread::ThreadId>,
    stop: Arc<AtomicBool>,
    events: Arc<Mutex<VecDeque<ReloadEvent>>>,
}

impl StrategyWatcher {
    /// 启动 watcher。
    ///
    /// - 启动时读取一次配置文件建立基线（mtime/哈希/策略），**不**调用
    ///   `set_strategy()`（初始策略由调用方在创建 `SharedFibManager` 时设定）；
    ///   文件不存在或不可读 → 返回 `Err`（fail-fast）。
    /// - 之后按 `poll_interval` 轮询；检测到 `[routing] strategy` 变化 →
    ///   解析 → `set_strategy()`。
    ///
    /// # Errors
    ///
    /// 配置文件不存在、不可读 → `io::Error`。
    pub fn start(
        config: WatcherConfig,
        fib: SharedFibManager<RoutingStrategy>,
        lsdb: Arc<RwLock<Lsdb>>,
    ) -> io::Result<Self> {
        let baseline = initial_baseline(&config.config_path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let seq = Arc::new(AtomicU64::new(0));
        let max_events = config.max_events.max(1);

        let worker_stop = Arc::clone(&stop);
        let worker_events = Arc::clone(&events);
        let worker_seq = Arc::clone(&seq);
        let poll_interval = config.poll_interval;
        let path = config.config_path.clone();

        let handle = thread::Builder::new()
            .name("nexus-strategy-watcher".to_string())
            .spawn(move || {
                watch_loop(
                    &path,
                    poll_interval,
                    max_events,
                    baseline,
                    fib,
                    lsdb,
                    &worker_stop,
                    &worker_events,
                    &worker_seq,
                );
            })
            .map_err(io::Error::other)?;
        let worker_id = handle.thread().id();

        Ok(Self {
            handle: Some(handle),
            worker_id: Some(worker_id),
            stop,
            events,
        })
    }

    /// 停止 watcher：置停止标志并 join 工作线程，干净退出。
    ///
    /// 停止延迟 ≤ 1 个轮询间隔。幂等：重复调用安全（第二次为空操作）。
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            // join 失败（线程 panic）不传播 panic：watcher 是辅助设施，
            // 其 panic 不应拖垮调用方；事件缓冲中无记录，调用方可通过
            // is_running() == false 且无新事件察觉异常。
            let _ = handle.join();
        }
        self.worker_id = None;
    }

    /// 工作线程是否仍在运行。
    pub fn is_running(&self) -> bool {
        match &self.handle {
            Some(h) => !h.is_finished(),
            None => false,
        }
    }

    /// 返回事件快照（按 seq 升序）。
    pub fn events(&self) -> Vec<ReloadEvent> {
        self.events
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 当前缓冲中的事件数。
    pub fn event_count(&self) -> usize {
        self.events.lock().map(|q| q.len()).unwrap_or(0)
    }

    fn push_event(
        events: &Arc<Mutex<VecDeque<ReloadEvent>>>,
        seq: &Arc<AtomicU64>,
        max_events: usize,
        kind: ReloadEventKind,
    ) {
        let seq_no = seq.fetch_add(1, Ordering::SeqCst);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if let Ok(mut q) = events.lock() {
            q.push_back(ReloadEvent {
                seq: seq_no,
                timestamp_ms,
                kind,
            });
            while q.len() > max_events {
                q.pop_front();
            }
        }
    }
}

impl Drop for StrategyWatcher {
    /// Drop 语义（§12.58 契约）：
    /// - 总是置停止标志（协作式取消）。
    /// - 若当前线程**不是** watcher 工作线程自身 → join，回收线程资源。
    /// - 若在 watcher 线程内 drop（自 join 会死锁）→ 跳过 join，线程因
    ///   停止位自行退出，无死锁（JoinHandle 被丢弃即 detach）。
    ///
    /// 推荐显式调用 `stop()` 以便确认 join 完成；仅靠 Drop 也不会泄漏
    /// 长期线程（最坏情况下延迟 ≤ 1 个轮询间隔后线程自行退出）。
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let is_self = self
            .worker_id
            .is_some_and(|id| id == thread::current().id());
        if !is_self {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
        // is_self 时：不能 join（死锁），只丢弃 handle；工作线程见到
        // 停止位后自行退出。
    }
}

/// 基线状态：上次成功读取的 mtime/哈希/策略。
struct Baseline {
    mtime: Option<SystemTime>,
    hash: u64,
    strategy: RoutingStrategy,
    /// 上次是否读取健康（用于 ReadFailed 只在 transition 时记录，避免刷屏）。
    healthy: bool,
}

/// FNV-1a 64（手写零依赖；与 nexus-discovery 内流哈希同算法，本地小函数）。
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// 读取配置文件并解析 `[routing] strategy`。
fn read_strategy(path: &std::path::Path) -> io::Result<RoutingStrategy> {
    let bytes = std::fs::read(path)?;
    let text =
        String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let cfg: crate::subnet_cli::SubnetConfig =
        toml::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    cfg.routing_strategy()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[allow(clippy::too_many_arguments)]
fn watch_loop(
    path: &std::path::Path,
    poll_interval: Duration,
    max_events: usize,
    mut baseline: Baseline,
    fib: SharedFibManager<RoutingStrategy>,
    lsdb: Arc<RwLock<Lsdb>>,
    stop: &AtomicBool,
    events: &Arc<Mutex<VecDeque<ReloadEvent>>>,
    seq: &Arc<AtomicU64>,
) {
    // baseline 已由 initial_baseline() 完整建立（含 mtime/哈希/策略）。
    baseline.healthy = true;

    loop {
        // 切片 sleep：stop() 响应性 ≤ SLEEP_SLICE，不必等满整个 poll_interval。
        let deadline = Instant::now() + poll_interval;
        let mut stopped = stop.load(Ordering::SeqCst);
        while !stopped && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(remaining.min(SLEEP_SLICE));
            stopped = stop.load(Ordering::SeqCst);
        }
        if stopped {
            break;
        }

        poll_once(path, max_events, &mut baseline, &fib, &lsdb, events, seq);

        if stop.load(Ordering::SeqCst) {
            break;
        }
    }
}

/// 单次轮询：内容哈希为真相来源（mtime 仅快速路径）→ 解析 → 比较 → 应用/记录。
///
/// 失败路径（读失败/解析失败）只记录事件，绝不调用 `set_strategy()`。
fn poll_once(
    path: &std::path::Path,
    max_events: usize,
    baseline: &mut Baseline,
    fib: &SharedFibManager<RoutingStrategy>,
    lsdb: &Arc<RwLock<Lsdb>>,
    events: &Arc<Mutex<VecDeque<ReloadEvent>>>,
    seq: &Arc<AtomicU64>,
) {
    // 1. mtime 快速路径。注意：粗粒度时间戳的文件系统上连续写入的 mtime
    //    可能完全不变（2026-09-30 真机复现：/tmp 上 99/100 次紧循环写入
    //    mtime 相同），因此 mtime 只能做提示，不能做决定；内容哈希才是
    //    真相来源，每次轮询都必须验证。
    let mtime = match std::fs::metadata(path) {
        Ok(m) => m.modified().ok(),
        Err(e) => {
            if baseline.healthy {
                baseline.healthy = false;
                StrategyWatcher::push_event(
                    events,
                    seq,
                    max_events,
                    ReloadEventKind::ReadFailed {
                        reason: format!("metadata: {e}"),
                    },
                );
            }
            return;
        }
    };
    let mtime_changed = mtime != baseline.mtime;
    if mtime_changed {
        baseline.mtime = mtime;
    }

    // 2. 读文件 + 哈希确认（配置文件很小，每次轮询读+哈希开销可忽略）
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if baseline.healthy {
                baseline.healthy = false;
                StrategyWatcher::push_event(
                    events,
                    seq,
                    max_events,
                    ReloadEventKind::ReadFailed {
                        reason: format!("read: {e}"),
                    },
                );
            }
            return;
        }
    };
    baseline.healthy = true;
    let hash = fnv1a_64(&bytes);
    if hash == baseline.hash {
        return; // 内容不变 → 静默跳过，不记录事件（无论 mtime 是否变化）
    }
    baseline.hash = hash;

    // 3. 解析（TOML → SubnetConfig → RoutingStrategy），保留配置文件原字符串
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => {
            StrategyWatcher::push_event(
                events,
                seq,
                max_events,
                ReloadEventKind::ParseFailed {
                    reason: format!("utf8: {e}"),
                },
            );
            return;
        }
    };
    let (strategy_raw, strategy) = match toml::from_str::<crate::subnet_cli::SubnetConfig>(&text) {
        Ok(cfg) => {
            let raw = cfg.routing.strategy.clone();
            match cfg.routing_strategy() {
                Ok(s) => (raw, s),
                Err(e) => {
                    // fail-closed：不调用 set_strategy()，旧策略与旧 FIB 原样保留
                    StrategyWatcher::push_event(
                        events,
                        seq,
                        max_events,
                        ReloadEventKind::ParseFailed {
                            reason: format!("strategy: {e}"),
                        },
                    );
                    return;
                }
            }
        }
        Err(e) => {
            // fail-closed：不调用 set_strategy()，旧策略与旧 FIB 原样保留
            StrategyWatcher::push_event(
                events,
                seq,
                max_events,
                ReloadEventKind::ParseFailed {
                    reason: format!("toml: {e}"),
                },
            );
            return;
        }
    };

    // 4. 与上次应用策略比较
    if strategy == baseline.strategy {
        StrategyWatcher::push_event(events, seq, max_events, ReloadEventKind::Unchanged);
        return;
    }

    // 5. 原子切换 + 强制重算（加锁顺序：lsdb 读 → fib 写，见模块文档）
    let generation = match lsdb.read() {
        Ok(db) => fib.set_strategy(strategy, &db),
        Err(e) => {
            StrategyWatcher::push_event(
                events,
                seq,
                max_events,
                ReloadEventKind::ReadFailed {
                    reason: format!("lsdb lock poisoned: {e}"),
                },
            );
            return;
        }
    };
    baseline.strategy = strategy;
    StrategyWatcher::push_event(
        events,
        seq,
        max_events,
        ReloadEventKind::Applied {
            strategy: strategy_raw,
            generation,
        },
    );
}

/// 启动时建立完整基线（策略 + mtime + 内容哈希），不触发 `set_strategy()`。
fn initial_baseline(path: &std::path::Path) -> io::Result<Baseline> {
    let strategy = read_strategy(path)?;
    let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
    let hash = std::fs::read(path).map(|b| fnv1a_64(&b)).unwrap_or(0);
    Ok(Baseline {
        mtime,
        hash,
        strategy,
        healthy: true,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_is_stable() {
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a_64(b"a"), fnv1a_64(b"a"));
        assert_ne!(fnv1a_64(b"a"), fnv1a_64(b"b"));
    }

    #[test]
    fn event_buffer_evicts_oldest() {
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let seq = Arc::new(AtomicU64::new(0));
        for _ in 0..5 {
            StrategyWatcher::push_event(&events, &seq, 3, ReloadEventKind::Unchanged);
        }
        let q = events.lock().unwrap();
        assert_eq!(q.len(), 3);
        let seqs: Vec<u64> = q.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![2, 3, 4]);
    }

    /// 回归测试（2026-09-30）：粗粒度时间戳文件系统上，文件内容变化时
    /// mtime 可能完全不变。`poll_once` 必须以内容哈希为真相来源，不能
    /// 因 mtime 未变而静默跳过。
    #[test]
    fn poll_once_detects_change_when_mtime_unchanged() {
        use nexus_discovery::PeerId;

        let path = std::env::temp_dir().join(format!(
            "nexus-watcher-mtime-test-{}.toml",
            std::process::id()
        ));
        // 文件当前内容：strategy = "ecmp"
        std::fs::write(
            &path,
            "[subnet]\ncidr = \"10.99.0.0/24\"\n[routing]\nstrategy = \"ecmp\"\n",
        )
        .unwrap();

        // 模拟粗粒度时间戳：基线 mtime 取文件当前 mtime（与"变化后"相同），
        // 但哈希/策略是旧的（shortest）。
        let mtime = std::fs::metadata(&path).unwrap().modified().ok();
        let mut baseline = Baseline {
            mtime,
            hash: fnv1a_64(b"stale"),
            strategy: RoutingStrategy::Shortest,
            healthy: true,
        };

        let id = PeerId("a".to_string());
        let lsdb = Arc::new(RwLock::new(Lsdb::new(id.clone())));
        let fib = SharedFibManager::new(id, RoutingStrategy::Shortest, &lsdb.read().unwrap());
        let events = Arc::new(Mutex::new(VecDeque::new()));
        let seq = Arc::new(AtomicU64::new(0));

        poll_once(&path, 16, &mut baseline, &fib, &lsdb, &events, &seq);

        let q = events.lock().unwrap();
        assert!(
            q.iter().any(|e| matches!(
                &e.kind,
                ReloadEventKind::Applied { strategy, .. } if strategy == "ecmp"
            )),
            "mtime 相同但内容变化时必须检测到并应用，否则静默丢更新"
        );
        std::fs::remove_file(&path).ok();
    }
}
