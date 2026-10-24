//! 共享决策缓存（spec §9.13，TUN 与 TPROXY 共用）。
//!
//! TUN 新流与 TPROXY 新流共用同一实例：key 为 5 元组 + 前端标识；`get` 命中
//! 即复用上次 `RouteTarget`（不再调用规则引擎），未命中才跑规则并 `insert`。
//! 老化只随 driver 传入的 `now_millis` 变化（AC-CORE-01）。

use std::collections::HashMap;

use nexus_domain::RouteTarget;

use crate::egress::FlowKey;

/// 前端标识：同一 5 元组在不同前端是不同决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Frontend {
    /// TUN 前端。
    Tun,
    /// TPROXY 前端。
    Tproxy,
}

/// 缓存键：5 元组 + 前端。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowDecisionKey {
    /// 5 元组。
    pub flow: FlowKey,
    /// 前端。
    pub frontend: Frontend,
}

/// 缓存的决策（含可观测字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDecision {
    /// 规则引擎给出的统一路由目标。
    pub target: RouteTarget,
    /// 命中规则原文（无命中时为空串）。
    pub matched_rule: String,
    /// 选定出站 tag（`self` 表示 DIRECT）。
    pub selected_outbound: String,
    /// 最近一次命中的单调毫秒（driver 时钟域）。
    pub last_seen_millis: u64,
}

/// 缓存计数器（counter；禁止 per-flow 日志）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowDecisionCacheStats {
    /// 当前存活条目数。
    pub entries: u64,
    /// 命中次数。
    pub hits: u64,
    /// 未命中次数。
    pub misses: u64,
    /// 容量淘汰次数。
    pub evicted_capacity: u64,
    /// 空闲淘汰次数。
    pub evicted_idle: u64,
}

/// 5 元组决策缓存。
pub struct FlowDecisionCache {
    capacity: usize,
    idle_millis: u64,
    entries: HashMap<FlowDecisionKey, CachedDecision>,
    hits: u64,
    misses: u64,
    evicted_capacity: u64,
    evicted_idle: u64,
}

impl FlowDecisionCache {
    /// 构造缓存；`capacity == 0` 表示不缓存（每次都是 miss）。
    pub fn new(capacity: usize, idle: std::time::Duration) -> Self {
        Self {
            capacity,
            idle_millis: u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
            entries: HashMap::new(),
            hits: 0,
            misses: 0,
            evicted_capacity: 0,
            evicted_idle: 0,
        }
    }

    /// 查询决策；命中会刷新 `last_seen_millis` 并计入 `hits`。
    pub fn get(&mut self, key: &FlowDecisionKey, now_millis: u64) -> Option<&CachedDecision> {
        match self.entries.get_mut(key) {
            Some(decision) => {
                decision.last_seen_millis = now_millis;
                self.hits += 1;
                Some(decision)
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// 写入决策；容量满时按最久未用淘汰一条，并计入 `evicted_capacity`。
    pub fn insert(&mut self, key: FlowDecisionKey, decision: CachedDecision, now_millis: u64) {
        if self.capacity == 0 {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        let mut decision = decision;
        decision.last_seen_millis = now_millis;
        self.entries.insert(key, decision);
    }

    /// 淘汰空闲超过 `idle` 的条目，返回淘汰数量。
    pub fn sweep(&mut self, now_millis: u64) -> usize {
        let idle = self.idle_millis;
        let before = self.entries.len();
        self.entries
            .retain(|_, decision| now_millis.saturating_sub(decision.last_seen_millis) < idle);
        let removed = before - self.entries.len();
        self.evicted_idle += removed as u64;
        removed
    }

    /// 当前条目数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 当前是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 计数器快照。
    pub fn stats(&self) -> FlowDecisionCacheStats {
        FlowDecisionCacheStats {
            entries: self.entries.len() as u64,
            hits: self.hits,
            misses: self.misses,
            evicted_capacity: self.evicted_capacity,
            evicted_idle: self.evicted_idle,
        }
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, decision)| decision.last_seen_millis)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.entries.remove(&key);
            self.evicted_capacity += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: u32::from_be_bytes([192, 168, 1, 5]),
            dst_ip: u32::from_be_bytes([10, 1, 2, 3]),
            src_port,
            dst_port,
            proto: 6,
        }
    }

    fn key(flow: FlowKey, frontend: Frontend) -> FlowDecisionKey {
        FlowDecisionKey { flow, frontend }
    }

    fn decision(peer: &str, matched_rule: &str) -> CachedDecision {
        CachedDecision {
            target: RouteTarget::Egress {
                peer: peer.to_string(),
            },
            matched_rule: matched_rule.to_string(),
            selected_outbound: peer.to_string(),
            last_seen_millis: 0,
        }
    }

    #[test]
    fn flow_decision_cache_first_packet_misses_then_hits() {
        let mut cache = FlowDecisionCache::new(16, std::time::Duration::from_secs(300));
        let k = key(flow(12345, 443), Frontend::Tun);

        assert!(cache.get(&k, 1_000).is_none());
        cache.insert(k, decision("relay", "IP-CIDR,10.0.0.0/8"), 1_000);

        let hit = cache.get(&k, 1_500).expect("hit");
        assert_eq!(
            hit.target,
            RouteTarget::Egress {
                peer: "relay".into()
            }
        );
        assert_eq!(hit.matched_rule, "IP-CIDR,10.0.0.0/8");
        assert_eq!(hit.selected_outbound, "relay");
        assert_eq!(hit.last_seen_millis, 1_500);
        assert_eq!(cache.len(), 1);

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn flow_decision_cache_distinct_flows_and_frontends_are_distinct() {
        let mut cache = FlowDecisionCache::new(16, std::time::Duration::from_secs(300));
        let tun = key(flow(12345, 443), Frontend::Tun);
        let tproxy = key(flow(12345, 443), Frontend::Tproxy);
        let other_port = key(flow(53000, 53), Frontend::Tun);

        cache.insert(tun, decision("relay", "IP-CIDR,10.0.0.0/8"), 0);
        cache.insert(tproxy, decision("direct", "MATCH"), 0);
        cache.insert(other_port, decision("direct", "MATCH"), 0);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.stats().entries, 3);
        assert_eq!(
            cache.get(&tproxy, 1).unwrap().target,
            RouteTarget::Egress {
                peer: "direct".into()
            }
        );
        assert_eq!(
            cache.get(&other_port, 1).unwrap().target,
            RouteTarget::Egress {
                peer: "direct".into()
            }
        );
    }

    #[test]
    fn flow_decision_cache_capacity_evicts_least_recently_used() {
        let mut cache = FlowDecisionCache::new(2, std::time::Duration::from_secs(300));
        let a = key(flow(1, 443), Frontend::Tun);
        let b = key(flow(2, 443), Frontend::Tun);
        let c = key(flow(3, 443), Frontend::Tun);

        cache.insert(a, decision("relay", "r1"), 10);
        cache.insert(b, decision("relay", "r2"), 20);
        // 触碰 a，使 b 成为最久未用。
        assert!(cache.get(&a, 30).is_some());
        cache.insert(c, decision("relay", "r3"), 40);

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&a, 50).is_some());
        assert!(cache.get(&b, 50).is_none());
        assert!(cache.get(&c, 50).is_some());
        assert_eq!(cache.stats().evicted_capacity, 1);
    }

    #[test]
    fn flow_decision_cache_idle_sweep_evicts_only_expired() {
        let mut cache = FlowDecisionCache::new(16, std::time::Duration::from_secs(60));
        let old = key(flow(1, 443), Frontend::Tun);
        let fresh = key(flow(2, 443), Frontend::Tun);
        cache.insert(old, decision("relay", "r1"), 1_000);
        cache.insert(fresh, decision("relay", "r2"), 50_000);
        assert!(cache.get(&fresh, 55_000).is_some());

        // old：55s 空闲，仍在 60s 内。
        assert_eq!(cache.sweep(56_000), 0);
        // old：66s 空闲 → 淘汰；fresh：6s。
        assert_eq!(cache.sweep(66_000), 1);
        assert!(cache.get(&old, 66_000).is_none());
        assert!(cache.get(&fresh, 66_000).is_some());
        assert_eq!(cache.stats().evicted_idle, 1);
    }

    #[test]
    fn flow_decision_cache_zero_capacity_reports_misses_without_retaining() {
        let mut cache = FlowDecisionCache::new(0, std::time::Duration::from_secs(60));
        let k = key(flow(1, 443), Frontend::Tun);
        cache.insert(k, decision("relay", "r1"), 1);
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&k, 2).is_none());
        assert_eq!(cache.stats().misses, 1);
    }
}
