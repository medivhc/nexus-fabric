//! 连接池（内存骨架，逻辑时钟注入）。
//!
//! 本模块是 delivery 层共享底座的连接复用骨架：
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
}
