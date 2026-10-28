//! 节点发现增强（多策略组合 + 去重 + 超时清理 + 上限驱逐，内存骨架，纯逻辑）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的节点发现增强骨架：
//! - **策略**：`DiscoveryStrategy` 三态——`Multicast` / `Bootstrap` / `Manual`，
//!   可独立启用/停用；停用的策略 `advertise` 被静默忽略；
//! - **配置**：`DiscoveryConfig { interval_ms, timeout_ms, max_peers }`，三者均须 > 0；
//! - **邻居表**：`DiscoveredPeer { node_id, endpoint, last_seen_ms }`，按 `node_id` 去重；
//! - **写路径**：`advertise` 同 `node_id` 已存在则 upsert（刷新 endpoint 与 `last_seen_ms`）；
//!   新邻居在表满 `max_peers` 时先按 `last_seen_ms` 最旧驱逐一条再插入；
//! - **清理**：`prune_expired(now_ms)` 删除 `now_ms - last_seen_ms > timeout_ms` 的邻居；
//! - **确定性快照**：`peers_snapshot()` 按 `node_id` 排序输出，供 JSON / E4 断言稳定消费。
//!
//! 边界（PRODUCT §12-discovery-enhanced 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不发真实组播 / 不连真实 bootstrap / 不做真实握手；
//! - 时间由调用方以 `now_ms: u64` 显式注入（仿 `bandwidth_policy` 的 `now_second`），
//!   模块自身不读墙钟；
//! - 去重键为 `node_id`（字符串精确匹配）；`endpoint` 与 `last_seen_ms` 可被 upsert 刷新；
//! - 真实组播收发、bootstrap 服务器查询、TLS 握手与节点真实性校验留 TODO。
//!
//! TODO（真实数据面集成，非本骨架范围）：
//! - 在 `nexus-platform-*` 上实现真实组播收发与 bootstrap 客户端；
//! - `now_ms` 接入真实单调时钟；邻居表持久化与 crash 后 reconcile；
//! - 节点真实性校验（签名 / 证书）与 endpoint 健康度打分。
//!
//! 错误面独立：`DiscoveryError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------- 错误 ----------

/// 节点发现增强相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// 配置字段非法（interval_ms / timeout_ms / max_peers 非正）。
    InvalidConfig {
        /// 非法字段名（人可读）。
        field: String,
    },
    /// 无法把字符串解析为合法发现策略。
    InvalidStrategy {
        /// 非法的策略字符串（人可读）。
        raw: String,
    },
    /// advertise 入参非法（node_id 或 endpoint 为空）。
    InvalidAdvertise {
        /// 非法原因（人可读）。
        details: String,
    },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(f, "DISCOVERY_INVALID_CONFIG: field {field:?} must be > 0")
            }
            Self::InvalidStrategy { raw } => {
                write!(
                    f,
                    "DISCOVERY_INVALID_STRATEGY: cannot parse strategy {raw:?}"
                )
            }
            Self::InvalidAdvertise { details } => {
                write!(f, "DISCOVERY_INVALID_ADVERTISE: {details}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

// ---------- 策略 ----------

/// 节点发现策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryStrategy {
    /// 组播发现（LAN 内广播）。
    Multicast,
    /// 引导服务器发现（向已知 bootstrap 拉取邻居）。
    Bootstrap,
    /// 手工配置发现（静态 endpoint 列表）。
    Manual,
}

impl DiscoveryStrategy {
    /// 返回稳定字符串标签（"multicast"/"bootstrap"/"manual"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Multicast => "multicast",
            Self::Bootstrap => "bootstrap",
            Self::Manual => "manual",
        }
    }
}

impl std::str::FromStr for DiscoveryStrategy {
    type Err = DiscoveryError;

    /// 大小写不敏感解析策略字符串；非法返回 `DiscoveryError::InvalidStrategy`。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "multicast" => Ok(Self::Multicast),
            "bootstrap" => Ok(Self::Bootstrap),
            "manual" => Ok(Self::Manual),
            _ => Err(DiscoveryError::InvalidStrategy { raw: s.to_string() }),
        }
    }
}

impl fmt::Display for DiscoveryStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 节点发现增强配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// 发现轮询间隔（毫秒），必须 > 0（本骨架仅记录，不做真实轮询）。
    interval_ms: u64,
    /// 邻居超时阈值（毫秒），必须 > 0。
    timeout_ms: u64,
    /// 邻居表上限，必须 > 0。
    max_peers: usize,
}

impl DiscoveryConfig {
    /// 构造配置；三者任一 <= 0 返回 `InvalidConfig`。
    pub fn new(
        interval_ms: u64,
        timeout_ms: u64,
        max_peers: usize,
    ) -> Result<Self, DiscoveryError> {
        if interval_ms == 0 {
            return Err(DiscoveryError::InvalidConfig {
                field: "interval_ms".to_string(),
            });
        }
        if timeout_ms == 0 {
            return Err(DiscoveryError::InvalidConfig {
                field: "timeout_ms".to_string(),
            });
        }
        if max_peers == 0 {
            return Err(DiscoveryError::InvalidConfig {
                field: "max_peers".to_string(),
            });
        }
        Ok(Self {
            interval_ms,
            timeout_ms,
            max_peers,
        })
    }

    /// 发现轮询间隔（毫秒）。
    #[must_use]
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// 邻居超时阈值（毫秒）。
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// 邻居表上限。
    #[must_use]
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }
}

// ---------- 邻居 ----------

/// 一个已发现的邻居节点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// 节点唯一标识（去重键）。
    pub node_id: String,
    /// 该节点的 endpoint（可被 upsert 刷新）。
    pub endpoint: String,
    /// 最近一次被发现的逻辑毫秒时间戳。
    pub last_seen_ms: u64,
}

// ---------- 管理器 ----------

/// 节点发现增强管理器：持有邻居表与启用的策略集合，纯内存纯逻辑。
///
/// 时钟为逻辑毫秒（`now_ms`），由调用方显式传入；不读墙钟、不阻塞。
pub struct EnhancedDiscovery {
    /// 发现配置。
    config: DiscoveryConfig,
    /// 邻居表（node_id -> peer）。
    peers: HashMap<String, DiscoveredPeer>,
    /// 当前启用的策略集合。
    enabled_strategies: HashSet<DiscoveryStrategy>,
}

impl EnhancedDiscovery {
    /// 构造管理器；默认启用全部三种策略。
    #[must_use]
    pub fn new(config: DiscoveryConfig) -> Self {
        let mut enabled_strategies = HashSet::new();
        enabled_strategies.insert(DiscoveryStrategy::Multicast);
        enabled_strategies.insert(DiscoveryStrategy::Bootstrap);
        enabled_strategies.insert(DiscoveryStrategy::Manual);
        Self {
            config,
            peers: HashMap::new(),
            enabled_strategies,
        }
    }

    /// 启用一个策略（幂等）。
    pub fn enable_strategy(&mut self, strategy: DiscoveryStrategy) {
        self.enabled_strategies.insert(strategy);
    }

    /// 停用一个策略（幂等）；停用后经该策略的 `advertise` 被静默忽略。
    pub fn disable_strategy(&mut self, strategy: DiscoveryStrategy) {
        self.enabled_strategies.remove(&strategy);
    }

    /// 查询某策略是否启用。
    #[must_use]
    pub fn is_strategy_enabled(&self, strategy: DiscoveryStrategy) -> bool {
        self.enabled_strategies.contains(&strategy)
    }

    /// 记录一次邻居发现（逻辑毫秒 `now_ms`）。
    ///
    /// 返回 `Ok(true)` 表示真正写入了邻居表；`Ok(false)` 表示策略未启用被静默忽略。
    ///
    /// 失败：
    /// - `node_id` 或 `endpoint` 为空 -> `InvalidAdvertise`；
    /// - 同 `node_id` 已存在 -> upsert（刷新 endpoint 与 `last_seen_ms`），不新增重复项；
    /// - 表满且为新 `node_id` -> 先按 `last_seen_ms` 最旧驱逐一条再插入。
    pub fn advertise(
        &mut self,
        strategy: DiscoveryStrategy,
        node_id: &str,
        endpoint: &str,
        now_ms: u64,
    ) -> Result<bool, DiscoveryError> {
        if !self.enabled_strategies.contains(&strategy) {
            return Ok(false);
        }
        if node_id.is_empty() {
            return Err(DiscoveryError::InvalidAdvertise {
                details: "node_id must not be empty".to_string(),
            });
        }
        if endpoint.is_empty() {
            return Err(DiscoveryError::InvalidAdvertise {
                details: format!("endpoint must not be empty (node_id={node_id:?})"),
            });
        }

        // upsert：已存在直接刷新。
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.endpoint = endpoint.to_string();
            peer.last_seen_ms = now_ms;
            return Ok(true);
        }

        // 新邻居：表满则驱逐最旧。
        if self.peers.len() >= self.config.max_peers {
            let oldest = self
                .peers
                .values()
                .min_by_key(|p| (p.last_seen_ms, p.node_id.clone()))
                .map(|p| p.node_id.clone());
            if let Some(oldest) = oldest {
                self.peers.remove(&oldest);
            }
        }

        self.peers.insert(
            node_id.to_string(),
            DiscoveredPeer {
                node_id: node_id.to_string(),
                endpoint: endpoint.to_string(),
                last_seen_ms: now_ms,
            },
        );
        Ok(true)
    }

    /// 清理超时邻居：删除 `now_ms - last_seen_ms > timeout_ms` 的邻居，返回删除条数。
    pub fn prune_expired(&mut self, now_ms: u64) -> usize {
        let before = self.peers.len();
        self.peers
            .retain(|_, peer| now_ms.saturating_sub(peer.last_seen_ms) <= self.config.timeout_ms);
        before - self.peers.len()
    }

    /// 当前邻居数。
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// 邻居快照（按 `node_id` 升序，确定性输出，供 JSON / E4 断言）。
    #[must_use]
    pub fn peers_snapshot(&self) -> Vec<DiscoveredPeer> {
        let mut v: Vec<DiscoveredPeer> = self.peers.values().cloned().collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    /// 按 `node_id` 查询邻居。
    #[must_use]
    pub fn get_peer(&self, node_id: &str) -> Option<&DiscoveredPeer> {
        self.peers.get(node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DiscoveryConfig {
        DiscoveryConfig::new(1000, 5000, 3).expect("valid config")
    }

    #[test]
    fn starts_with_all_strategies_enabled() {
        let d = EnhancedDiscovery::new(cfg());
        assert!(d.is_strategy_enabled(DiscoveryStrategy::Multicast));
        assert!(d.is_strategy_enabled(DiscoveryStrategy::Bootstrap));
        assert!(d.is_strategy_enabled(DiscoveryStrategy::Manual));
        assert_eq!(d.peer_count(), 0);
    }

    #[test]
    fn advertise_upserts_existing_peer() {
        let mut d = EnhancedDiscovery::new(cfg());
        assert!(
            d.advertise(DiscoveryStrategy::Manual, "n1", "10.0.0.1:1", 1000)
                .unwrap()
        );
        assert!(
            d.advertise(DiscoveryStrategy::Manual, "n1", "10.0.0.2:2", 2000)
                .unwrap()
        );
        assert_eq!(d.peer_count(), 1);
        let peer = d.get_peer("n1").unwrap();
        assert_eq!(peer.endpoint, "10.0.0.2:2");
        assert_eq!(peer.last_seen_ms, 2000);
    }

    #[test]
    fn disabled_strategy_is_silently_ignored() {
        let mut d = EnhancedDiscovery::new(cfg());
        d.disable_strategy(DiscoveryStrategy::Manual);
        let recorded = d
            .advertise(DiscoveryStrategy::Manual, "n1", "10.0.0.1:1", 1000)
            .unwrap();
        assert!(!recorded);
        assert_eq!(d.peer_count(), 0);
        // 重新启用后可记录。
        d.enable_strategy(DiscoveryStrategy::Manual);
        assert!(
            d.advertise(DiscoveryStrategy::Manual, "n1", "10.0.0.1:1", 1000)
                .unwrap()
        );
        assert_eq!(d.peer_count(), 1);
    }

    #[test]
    fn empty_node_id_or_endpoint_rejected() {
        let mut d = EnhancedDiscovery::new(cfg());
        assert!(
            d.advertise(DiscoveryStrategy::Manual, "", "10.0.0.1:1", 1000)
                .is_err()
        );
        assert!(
            d.advertise(DiscoveryStrategy::Manual, "n1", "", 1000)
                .is_err()
        );
        assert_eq!(d.peer_count(), 0);
    }

    #[test]
    fn prune_expired_removes_stale_peers() {
        let mut d = EnhancedDiscovery::new(cfg());
        d.advertise(DiscoveryStrategy::Manual, "fresh", "e1", 9000)
            .unwrap();
        d.advertise(DiscoveryStrategy::Manual, "stale", "e2", 1000)
            .unwrap();
        // timeout_ms=5000：now=9000 时 stale(1000) 差 8000 > 5000 -> 删除。
        let removed = d.prune_expired(9000);
        assert_eq!(removed, 1);
        assert_eq!(d.peer_count(), 1);
        assert!(d.get_peer("fresh").is_some());
        assert!(d.get_peer("stale").is_none());
    }

    #[test]
    fn max_peers_evicts_oldest() {
        let mut d = EnhancedDiscovery::new(cfg());
        d.advertise(DiscoveryStrategy::Manual, "old", "e-old", 1000)
            .unwrap();
        d.advertise(DiscoveryStrategy::Manual, "mid", "e-mid", 2000)
            .unwrap();
        d.advertise(DiscoveryStrategy::Manual, "new", "e-new", 3000)
            .unwrap();
        assert_eq!(d.peer_count(), 3);
        // 插入第 4 个：驱逐 last_seen 最旧的 old。
        d.advertise(DiscoveryStrategy::Manual, "fourth", "e-4", 4000)
            .unwrap();
        assert_eq!(d.peer_count(), 3);
        assert!(d.get_peer("old").is_none());
        assert!(d.get_peer("fourth").is_some());
    }

    #[test]
    fn peers_snapshot_is_sorted_by_node_id() {
        let mut d = EnhancedDiscovery::new(cfg());
        d.advertise(DiscoveryStrategy::Manual, "zeta", "e1", 1000)
            .unwrap();
        d.advertise(DiscoveryStrategy::Manual, "alpha", "e2", 2000)
            .unwrap();
        d.advertise(DiscoveryStrategy::Manual, "mid", "e3", 3000)
            .unwrap();
        let snap = d.peers_snapshot();
        let ids: Vec<&str> = snap.iter().map(|p| p.node_id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "mid", "zeta"]);
    }

    #[test]
    fn from_str_parses_strategy_case_insensitive() {
        assert_eq!(
            "MULTICAST".parse::<DiscoveryStrategy>().unwrap(),
            DiscoveryStrategy::Multicast
        );
        assert_eq!(
            "Bootstrap".parse::<DiscoveryStrategy>().unwrap(),
            DiscoveryStrategy::Bootstrap
        );
        assert_eq!(
            "manual".parse::<DiscoveryStrategy>().unwrap(),
            DiscoveryStrategy::Manual
        );
    }

    #[test]
    fn from_str_rejects_invalid() {
        let err = "udp".parse::<DiscoveryStrategy>().unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidStrategy { .. }));
        assert!(err.to_string().starts_with("DISCOVERY_INVALID_STRATEGY:"));
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(DiscoveryConfig::new(0, 100, 5).is_err());
        assert!(DiscoveryConfig::new(100, 0, 5).is_err());
        assert!(DiscoveryConfig::new(100, 100, 0).is_err());
        let err = DiscoveryConfig::new(0, 100, 5).unwrap_err();
        assert!(err.to_string().starts_with("DISCOVERY_INVALID_CONFIG:"));
    }

    #[test]
    fn as_str_and_display() {
        assert_eq!(DiscoveryStrategy::Multicast.as_str(), "multicast");
        assert_eq!(DiscoveryStrategy::Bootstrap.as_str(), "bootstrap");
        assert_eq!(DiscoveryStrategy::Manual.as_str(), "manual");
        assert_eq!(DiscoveryStrategy::Multicast.to_string(), "multicast");
    }
}
