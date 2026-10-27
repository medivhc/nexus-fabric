//! 连接池（内存骨架，逻辑时钟注入）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的连接复用骨架：
//! - **池化**：按 key（即 node_id）管理空闲/在借用连接；
//! - **复用**：`acquire` 优先复用同 key 的空闲连接（取最旧一条），未命中且未超总上限则新建；
//! - **归还**：`release` 把连接归还为空闲并记录归还时间戳；空闲总数超过 `max_idle` 时淘汰最旧；
//! - **过期回收**：`evict_idle(now_ms)` 按注入的逻辑时钟淘汰空闲时间超过 `idle_timeout_ms` 的连接；
//! - **快照**：`snapshot()` 暴露 idle/active/total/created_total 计数，供可观测性与测试断言。
//!
//! 边界（PRODUCT §12-connection-pool 冻结）：
//! - 纯内存、纯同步、纯函数骨架；不接真实 TCP 连接；
//! - refcount 用显式 `acquire` / `release` 模拟，不引入 `Arc` / `Drop` hook；
//! - 时间由调用方注入（`now_ms: u64`），不读取系统时钟，便于确定性测试。
//!
//! TODO（真实网络集成，非本骨架范围）：
//! - 接入真实 TCP / QUIC 连接对象，在 Drop 时自动归还；
//! - 线程安全（`Send + Sync`），用 `Mutex<ConnectionPool>` 或 `dashmap` 并发访问；
//! - 按 LRU 淘汰空闲连接，而非简单 FIFO；
//! - 空闲连接探活（健康检查集成）。
//!
//! 错误面独立：`PoolError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ---------- 错误 ----------

/// 连接池相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// 池已耗尽：活跃 + 空闲总数达到 `max_total`，无法新建连接，且该 key 无空闲连接可复用。
    Exhausted,
    /// 归还或引用的连接不属于本池（未在 active 集合中），key 为归还连接的 node_id。
    UnknownKey(String),
    /// 池配置非法（如 `max_total < 1` 或 `max_idle > max_total`）。
    InvalidConfig(String),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => write!(
                f,
                "POOL_EXHAUSTED: no idle connection and max_total reached"
            ),
            Self::UnknownKey(k) => {
                write!(f, "POOL_UNKNOWN_KEY: connection for {k:?} is not active")
            }
            Self::InvalidConfig(msg) => write!(f, "POOL_INVALID_CONFIG: {msg}"),
        }
    }
}

impl std::error::Error for PoolError {}

// ---------- 配置 ----------

/// 连接池配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// 空闲连接保留上限；超过时淘汰最旧空闲。
    pub max_idle: usize,
    /// 连接总数硬上限（active + idle）。
    pub max_total: usize,
    /// 空闲连接超时（毫秒，逻辑时钟）；超过则被 `evict_idle` 淘汰。
    pub idle_timeout_ms: u64,
}

impl PoolConfig {
    /// 构造配置；校验 `max_total >= 1` 且 `max_idle <= max_total`，否则返回 `InvalidConfig`。
    pub fn new(max_idle: usize, max_total: usize, idle_timeout_ms: u64) -> Result<Self, PoolError> {
        if max_total < 1 {
            return Err(PoolError::InvalidConfig(format!(
                "max_total must be >= 1, got {max_total}"
            )));
        }
        if max_idle > max_total {
            return Err(PoolError::InvalidConfig(format!(
                "max_idle ({max_idle}) must be <= max_total ({max_total})"
            )));
        }
        Ok(Self {
            max_idle,
            max_total,
            idle_timeout_ms,
        })
    }
}

// ---------- 连接句柄 ----------

/// 池化连接句柄（模拟）。
///
/// 真实场景下会持有 socket / transport；本骨架只持有 key 与自增 conn_id。
/// `Clone` 是廉价的（两个 u64 + 一个 String），调用方负责成对 `release`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledConnection {
    /// 所属节点 key（node_id）。
    pub key: String,
    /// 连接唯一 ID（池内自增，从 1 开始）。
    pub conn_id: u64,
}

// ---------- 内部空闲条目 ----------

/// 空闲队列条目：记录连接 ID、所属 key 与归还时间戳（逻辑时钟）。
#[derive(Debug, Clone, Copy)]
struct IdleEntry {
    conn_id: u64,
    key_idx: usize,
    released_at_ms: u64,
}

// ---------- 快照 ----------

/// 连接池只读快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSnapshot {
    /// 当前空闲连接数。
    pub idle_count: usize,
    /// 当前借出（active）连接数。
    pub active_count: usize,
    /// 总连接数 = idle + active。
    pub total_count: usize,
    /// 自池创建以来累计新建连接数（含已淘汰）。
    pub created_total: u64,
}

// ---------- 连接池 ----------

/// 连接池：按 key 管理空闲/在借用连接。
///
/// 并发安全留 TODO；本骨架为单线程纯同步逻辑。
#[derive(Debug)]
pub struct ConnectionPool {
    cfg: PoolConfig,
    /// 空闲连接队列（FIFO，按归还时间排序）；前端最旧。
    idle: VecDeque<IdleEntry>,
    /// 当前借出的 conn_id 集合。
    active: HashSet<u64>,
    /// key 到 key 索引的映射（内部字符串去重，便于 IdleEntry 存索引）。
    keys: HashMap<String, usize>,
    /// 反向映射：key 索引 -> key 字符串。
    key_names: Vec<String>,
    /// 下一个分配的 conn_id。
    next_conn_id: u64,
    /// 累计新建连接数。
    created_total: u64,
}

impl ConnectionPool {
    /// 构造连接池；配置非法直接返回错误。
    pub fn new(cfg: PoolConfig) -> Self {
        Self {
            cfg,
            idle: VecDeque::new(),
            active: HashSet::new(),
            keys: HashMap::new(),
            key_names: Vec::new(),
            next_conn_id: 1,
            created_total: 0,
        }
    }

    /// 获取 key 的空闲连接；命中则复用，未命中且未超上限则新建；超上限返回 `Exhausted`。
    ///
    /// 复用策略：取该 key 最旧的一条空闲连接（FIFO）。
    pub fn acquire(&mut self, key: &str) -> Result<PooledConnection, PoolError> {
        // 1) 尝试复用：在空闲队列中找第一个匹配 key 的条目
        let pos = self
            .idle
            .iter()
            .position(|e| self.key_names[e.key_idx] == key);
        if let Some(pos) = pos {
            let entry = self.idle.remove(pos).expect("pos just verified");
            self.active.insert(entry.conn_id);
            return Ok(PooledConnection {
                key: key.to_string(),
                conn_id: entry.conn_id,
            });
        }

        // 2) 未命中：检查总数上限
        let total = self.active.len() + self.idle.len();
        if total >= self.cfg.max_total {
            return Err(PoolError::Exhausted);
        }

        // 3) 新建
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;
        self.created_total += 1;
        self.active.insert(conn_id);
        Ok(PooledConnection {
            key: key.to_string(),
            conn_id,
        })
    }

    /// 归还连接为空闲；记录归还时间戳；若空闲总数超过 `max_idle` 则淘汰最旧空闲。
    ///
    /// 若 `conn` 不在 active 集合中，返回 `UnknownKey`（防止双归还或归还非本池连接）。
    pub fn release(&mut self, conn: PooledConnection, now_ms: u64) -> Result<(), PoolError> {
        if !self.active.remove(&conn.conn_id) {
            return Err(PoolError::UnknownKey(conn.key));
        }
        let key_idx = self.key_idx(&conn.key);
        self.idle.push_back(IdleEntry {
            conn_id: conn.conn_id,
            key_idx,
            released_at_ms: now_ms,
        });

        // 超过 max_idle：从头部（最旧）淘汰
        while self.idle.len() > self.cfg.max_idle {
            self.idle.pop_front();
        }
        Ok(())
    }

    /// 按注入的逻辑时钟淘汰所有空闲时间超过 `idle_timeout_ms` 的连接，返回淘汰条数。
    ///
    /// 空闲时间 = `now_ms - released_at_ms`；严格大于阈值才淘汰。
    pub fn evict_idle(&mut self, now_ms: u64) -> usize {
        let threshold = self.cfg.idle_timeout_ms;
        let mut evicted = 0;
        while let Some(front) = self.idle.front().copied() {
            if now_ms.saturating_sub(front.released_at_ms) > threshold {
                self.idle.pop_front();
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }

    /// 当前池状态只读快照。
    #[must_use]
    pub fn snapshot(&self) -> PoolSnapshot {
        PoolSnapshot {
            idle_count: self.idle.len(),
            active_count: self.active.len(),
            total_count: self.idle.len() + self.active.len(),
            created_total: self.created_total,
        }
    }

    /// key -> 内部索引映射（不存在则分配新索引）。
    fn key_idx(&mut self, key: &str) -> usize {
        if let Some(&idx) = self.keys.get(key) {
            return idx;
        }
        let idx = self.key_names.len();
        self.keys.insert(key.to_string(), idx);
        self.key_names.push(key.to_string());
        idx
    }
}

// === 12.40.4 真实工厂连接池（包装真实句柄，淘汰时 drop 关闭 socket） ==========

/// 连接工厂接缝：按需创建真实连接对象（组合根实现，如连 loopback echo server
/// 的 TCP 流）。crate 内不发起网络。
pub trait ConnectionFactory {
    /// 真实句柄类型（如 `std::net::TcpStream`）。
    type Handle;
    /// 为 `key`（node_id/目标）新建一条真实连接。
    fn connect(&self, key: &str) -> Result<Self::Handle, PoolError>;
}

/// 空闲队列条目：持有真实句柄（淘汰时 drop 即关闭底层 socket）。
struct IdleRealized<H> {
    conn_id: u64,
    key: String,
    handle: H,
    released_at_ms: u64,
}

/// 从池中借出的真实连接：持有真实句柄，`release` 归还后句柄回到空闲队列。
#[derive(Debug)]
pub struct RealizedConnection<H> {
    /// 所属节点 key。
    pub key: String,
    /// 连接唯一 ID（池内自增，从 1 开始；复用时不变）。
    pub conn_id: u64,
    /// 真实句柄（调用方可读写，如 TCP echo 往返）。
    pub handle: H,
}

/// 真实工厂连接池：在 `PoolConfig` 计数语义上包装真实句柄。
///
/// - `acquire` 命中同 key 空闲则复用同一条真实句柄（conn_id 不变）；
///   未命中调 `factory.connect` 新建；超 `max_total` 返回 `Exhausted`；
/// - `release` 归还句柄到空闲；超 `max_idle` 淘汰最旧（drop 句柄关闭 socket）；
/// - `evict_idle` 按注入逻辑时钟淘汰超时空闲句柄。
///
/// 既有 `ConnectionPool` 纯内存骨架与 `connection_pool.toml` expectation 不受影响。
pub struct RealizedPool<F: ConnectionFactory> {
    cfg: PoolConfig,
    factory: F,
    idle: VecDeque<IdleRealized<F::Handle>>,
    active: HashSet<u64>,
    next_conn_id: u64,
    created_total: u64,
    /// conn_id -> 活跃 key（用于 release 校验）。
    active_keys: HashMap<u64, String>,
}

impl<F: ConnectionFactory> RealizedPool<F> {
    /// 用配置与工厂构造池。
    pub fn new(cfg: PoolConfig, factory: F) -> Self {
        Self {
            cfg,
            factory,
            idle: VecDeque::new(),
            active: HashSet::new(),
            next_conn_id: 1,
            created_total: 0,
            active_keys: HashMap::new(),
        }
    }

    /// 获取 key 的连接；复用同 key 空闲句柄，未命中经工厂新建；超上限 `Exhausted`。
    pub fn acquire(&mut self, key: &str) -> Result<RealizedConnection<F::Handle>, PoolError> {
        // 1) 复用：找同 key 最旧空闲。
        if let Some(pos) = self.idle.iter().position(|e| e.key == key) {
            let e = self.idle.remove(pos).expect("pos just verified");
            self.active.insert(e.conn_id);
            self.active_keys.insert(e.conn_id, e.key.clone());
            return Ok(RealizedConnection {
                key: e.key,
                conn_id: e.conn_id,
                handle: e.handle,
            });
        }
        // 2) 上限。
        let total = self.active.len() + self.idle.len();
        if total >= self.cfg.max_total {
            return Err(PoolError::Exhausted);
        }
        // 3) 新建（工厂失败不改变池状态）。
        let handle = self.factory.connect(key)?;
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;
        self.created_total += 1;
        self.active.insert(conn_id);
        self.active_keys.insert(conn_id, key.to_string());
        Ok(RealizedConnection {
            key: key.to_string(),
            conn_id,
            handle,
        })
    }

    /// 归还连接为空闲；超 `max_idle` 淘汰最旧（drop 句柄关闭 socket）。
    pub fn release(
        &mut self,
        conn: RealizedConnection<F::Handle>,
        now_ms: u64,
    ) -> Result<(), PoolError> {
        if !self.active.remove(&conn.conn_id) {
            return Err(PoolError::UnknownKey(conn.key));
        }
        self.active_keys.remove(&conn.conn_id);
        self.idle.push_back(IdleRealized {
            conn_id: conn.conn_id,
            key: conn.key,
            handle: conn.handle,
            released_at_ms: now_ms,
        });
        while self.idle.len() > self.cfg.max_idle {
            let old = self.idle.pop_front().expect("len > max_idle >= 1");
            // drop old.handle -> 关闭底层真实 socket。
            drop(old);
        }
        Ok(())
    }

    /// 按注入逻辑时钟淘汰空闲超时连接（drop 句柄），返回淘汰条数。
    pub fn evict_idle(&mut self, now_ms: u64) -> usize {
        let threshold = self.cfg.idle_timeout_ms;
        let mut evicted = 0;
        while let Some(front) = self.idle.front() {
            if now_ms.saturating_sub(front.released_at_ms) > threshold {
                let old = self.idle.pop_front().expect("front verified");
                drop(old);
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }

    /// 与 `ConnectionPool::snapshot` 同字段的只读快照。
    #[must_use]
    pub fn snapshot(&self) -> PoolSnapshot {
        PoolSnapshot {
            idle_count: self.idle.len(),
            active_count: self.active.len(),
            total_count: self.idle.len() + self.active.len(),
            created_total: self.created_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PoolConfig {
        PoolConfig::new(2, 3, 1000).expect("valid cfg")
    }

    #[test]
    fn new_rejects_max_total_zero() {
        let err = PoolConfig::new(0, 0, 1000).expect_err("must fail");
        assert!(matches!(err, PoolError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_max_idle_gt_max_total() {
        let err = PoolConfig::new(5, 3, 1000).expect_err("must fail");
        assert!(matches!(err, PoolError::InvalidConfig(_)));
    }

    #[test]
    fn acquire_creates_new_connection() {
        let mut pool = ConnectionPool::new(cfg());
        let c = pool.acquire("node-a").expect("ok");
        assert_eq!(c.conn_id, 1);
        assert_eq!(c.key, "node-a");
        let snap = pool.snapshot();
        assert_eq!(snap.active_count, 1);
        assert_eq!(snap.idle_count, 0);
        assert_eq!(snap.total_count, 1);
        assert_eq!(snap.created_total, 1);
    }

    #[test]
    fn release_then_acquire_reuses_same_conn_id() {
        let mut pool = ConnectionPool::new(cfg());
        let c1 = pool.acquire("node-a").expect("ok");
        pool.release(c1.clone(), 0).expect("ok");
        let c2 = pool.acquire("node-a").expect("ok");
        assert_eq!(
            c2.conn_id, c1.conn_id,
            "should reuse the same idle connection"
        );
        let snap = pool.snapshot();
        assert_eq!(snap.created_total, 1, "no new connection created");
        assert_eq!(snap.active_count, 1);
    }

    #[test]
    fn acquire_different_key_creates_new() {
        let mut pool = ConnectionPool::new(cfg());
        let _a = pool.acquire("node-a").expect("ok");
        let b = pool.acquire("node-b").expect("ok");
        assert_eq!(b.conn_id, 2);
    }

    #[test]
    fn exhausts_at_max_total() {
        let mut pool = ConnectionPool::new(cfg());
        let _a = pool.acquire("a").expect("ok");
        let _b = pool.acquire("b").expect("ok");
        let _c = pool.acquire("c").expect("ok");
        let err = pool.acquire("d").expect_err("exhausted");
        assert_eq!(err, PoolError::Exhausted);
    }

    #[test]
    fn release_double_release_rejected() {
        let mut pool = ConnectionPool::new(cfg());
        let c = pool.acquire("a").expect("ok");
        pool.release(c.clone(), 0).expect("ok");
        let err = pool.release(c, 0).expect_err("double release");
        assert!(matches!(err, PoolError::UnknownKey(_)));
    }

    #[test]
    fn max_idle_discards_oldest_idle() {
        // max_idle=2, max_total=3
        let mut pool = ConnectionPool::new(cfg());
        let a = pool.acquire("a").expect("ok");
        let b = pool.acquire("b").expect("ok");
        let c = pool.acquire("c").expect("ok");
        // release all three; idle len goes 1, 2, 3 -> evict 1 -> stays 2
        pool.release(a, 0).expect("ok");
        pool.release(b, 10).expect("ok");
        pool.release(c, 20).expect("ok");
        let snap = pool.snapshot();
        assert_eq!(snap.idle_count, 2, "oldest (a) should be evicted");
        assert_eq!(snap.active_count, 0);
        // a was evicted; next acquire("a") must create a new conn_id
        let anew = pool.acquire("a").expect("ok");
        assert_eq!(anew.conn_id, 4, "evicted a cannot be reused; new conn");
    }

    #[test]
    fn evict_idle_removes_expired() {
        let mut pool = ConnectionPool::new(cfg());
        let a = pool.acquire("a").expect("ok");
        let b = pool.acquire("b").expect("ok");
        pool.release(a, 0).expect("ok");
        pool.release(b, 500).expect("ok");
        // now=2000, threshold=1000: a expired (2000-0=2000 > 1000), b not (1500 > 1000 actually yes)
        // b: 2000-500=1500 > 1000 -> also expired
        let evicted = pool.evict_idle(2000);
        assert_eq!(evicted, 2);
        assert_eq!(pool.snapshot().idle_count, 0);
    }

    #[test]
    fn evict_idle_respects_threshold() {
        let mut pool = ConnectionPool::new(cfg());
        let a = pool.acquire("a").expect("ok");
        pool.release(a, 100).expect("ok");
        // now=500: delta=400, not > 1000
        assert_eq!(pool.evict_idle(500), 0);
        assert_eq!(pool.snapshot().idle_count, 1);
        // now=1200: delta=1100 > 1000
        assert_eq!(pool.evict_idle(1200), 1);
    }

    // ---- RealizedPool with mock factory ----

    #[derive(Debug)]
    struct MockHandle {
        id: u64,
        dropped: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for MockHandle {
        fn drop(&mut self) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct MockFactory {
        next: std::sync::atomic::AtomicU64,
        fail: std::sync::atomic::AtomicBool,
        dropped: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ConnectionFactory for MockFactory {
        type Handle = MockHandle;
        fn connect(&self, _key: &str) -> Result<MockHandle, PoolError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(PoolError::InvalidConfig("boom".into()));
            }
            let id = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            Ok(MockHandle {
                id,
                dropped: self.dropped.clone(),
            })
        }
    }

    fn realized(
        cfg: PoolConfig,
    ) -> (
        RealizedPool<MockFactory>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f = MockFactory {
            next: std::sync::atomic::AtomicU64::new(0),
            fail: std::sync::atomic::AtomicBool::new(false),
            dropped: dropped.clone(),
        };
        (RealizedPool::new(cfg, f), dropped)
    }

    #[test]
    fn realized_reuses_same_handle() {
        let (mut pool, _d) = realized(cfg());
        let c1 = pool.acquire("a").expect("ok");
        assert_eq!(c1.handle.id, 1);
        pool.release(c1, 0).expect("ok");
        let c2 = pool.acquire("a").expect("ok");
        assert_eq!(c2.conn_id, 1, "reused conn id");
        assert_eq!(c2.handle.id, 1, "same handle object");
        assert_eq!(pool.snapshot().created_total, 1);
    }

    #[test]
    fn realized_exhausted_at_max_total() {
        let (mut pool, _d) = realized(cfg()); // max_total=3
        let _a = pool.acquire("a").unwrap();
        let _b = pool.acquire("b").unwrap();
        let _c = pool.acquire("c").unwrap();
        let err = pool.acquire("d").expect_err("exhausted");
        assert_eq!(err, PoolError::Exhausted);
    }

    #[test]
    fn realized_max_idle_eviction_drops_handle() {
        let (mut pool, dropped) = realized(cfg()); // max_idle=2, max_total=3
        let a = pool.acquire("a").unwrap();
        let b = pool.acquire("b").unwrap();
        let c = pool.acquire("c").unwrap();
        pool.release(a, 0).unwrap();
        pool.release(b, 0).unwrap();
        pool.release(c, 0).unwrap();
        // idle len 3 > max_idle 2 -> evict oldest (a)
        assert_eq!(pool.snapshot().idle_count, 2);
        assert_eq!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "evicted handle dropped"
        );
    }

    #[test]
    fn realized_double_release_unknown_key() {
        let (mut pool, _d) = realized(cfg());
        let c = pool.acquire("a").unwrap();
        pool.release(c, 0).unwrap();
        // can't double release: c was moved into release; build a fake
        let fake = RealizedConnection {
            key: "a".into(),
            conn_id: 999,
            handle: MockHandle {
                id: 999,
                dropped: Default::default(),
            },
        };
        let err = pool.release(fake, 0).expect_err("unknown");
        assert!(matches!(err, PoolError::UnknownKey(_)));
    }

    #[test]
    fn realized_factory_failure_does_not_pollute() {
        let cfg = cfg();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f = MockFactory {
            next: std::sync::atomic::AtomicU64::new(0),
            fail: std::sync::atomic::AtomicBool::new(true),
            dropped: dropped.clone(),
        };
        let mut pool = RealizedPool::new(cfg, f);
        let err = pool.acquire("a").expect_err("factory boom");
        assert!(matches!(err, PoolError::InvalidConfig(_)));
        // pool unchanged: 0 active, 0 idle
        let s = pool.snapshot();
        assert_eq!(s.active_count, 0);
        assert_eq!(s.idle_count, 0);
        assert_eq!(s.total_count, 0);
    }
}
