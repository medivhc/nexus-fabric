//! 流量统计汇总（内存骨架，纯逻辑）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的流量记账与汇总骨架：
//! - **汇总快照**：`TrafficSummary` 持有全节点总上下行字节数 / 活跃连接数 / 活跃节点数；
//! - **节点记账**：`NodeTraffic` 按节点维护 rx/tx 字节与活跃连接数；
//! - **收集器**：`StatsCollector` 按 `node_id` 聚合，提供按节点查询与全量快照；
//! - **累加规则**：字节累加用 `saturating_add`，连接数增减饱和（不回绕、不溢出）。
//!
//! 边界（PRODUCT §12-traffic-stats 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；不读真实网卡、不读真实字节计数；
//! - 节点首次记录时自动注册；`node_summary` 对从未记录的节点返回 `None`；
//! - `snapshot()` 即导出快照，用于监控 / 日志 / 告警；
//! - 真实字节计数 hook / 周期性导出留 TODO。
//!
//! TODO（真实统计集成，非本骨架范围）：
//! - 在数据面收发路径上 hook 真实字节计数（每包回调本收集器）；
//! - 按固定间隔把 `snapshot()` 推送到可观测层（metric / 日志）；
//! - 支持按时间窗口聚合（速率 / 峰值），而非仅累计值。
//!
//! 本模块无配置，故不定义自有错误 enum（保持简单）。

use std::collections::HashMap;

// ---------- 汇总快照 ----------

/// 全节点流量汇总快照（用于监控 / 日志导出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSummary {
    /// 所有节点累计下行字节总和。
    pub total_rx_bytes: u64,
    /// 所有节点累计上行字节总和。
    pub total_tx_bytes: u64,
    /// 所有节点当前活跃连接数之和。
    pub active_connections: u32,
    /// 已登记的节点总数。
    pub active_nodes: u32,
}

// ---------- 节点记账 ----------

/// 单节点流量记账（仅收集器内部使用）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct NodeTraffic {
    /// 累计下行字节。
    rx_bytes: u64,
    /// 累计上行字节。
    tx_bytes: u64,
    /// 当前活跃连接数（饱和，不回绕）。
    active_conns: u32,
}

// ---------- 收集器 ----------

/// 流量统计收集器：按 `node_id` 聚合字节与连接数。
///
/// 纯内存、纯同步；字节累加饱和，连接数增减饱和，便于单测与确定性 replay。
#[derive(Debug, Default)]
pub struct StatsCollector {
    nodes: HashMap<String, NodeTraffic>,
}

impl StatsCollector {
    /// 构造空收集器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// 累加某节点的一次上下行字节（饱和累加；节点首次出现自动注册）。
    pub fn record_node_bytes(&mut self, node_id: &str, rx: u64, tx: u64) {
        let entry = self.nodes.entry(node_id.to_string()).or_default();
        entry.rx_bytes = entry.rx_bytes.saturating_add(rx);
        entry.tx_bytes = entry.tx_bytes.saturating_add(tx);
    }

    /// 记录某节点的一次连接活动（`active=true` 建立 / `false` 关闭）。
    ///
    /// 增减均饱和（活跃连接数不会回绕到 u32::MAX）；节点首次出现自动注册。
    pub fn record_connection(&mut self, node_id: &str, active: bool) {
        let entry = self.nodes.entry(node_id.to_string()).or_default();
        if active {
            entry.active_conns = entry.active_conns.saturating_add(1);
        } else {
            entry.active_conns = entry.active_conns.saturating_sub(1);
        }
    }

    /// 查询某节点的 (rx_bytes, tx_bytes, active_conns)；从未记录的节点返回 `None`。
    #[must_use]
    pub fn node_summary(&self, node_id: &str) -> Option<(u64, u64, u32)> {
        self.nodes
            .get(node_id)
            .map(|n| (n.rx_bytes, n.tx_bytes, n.active_conns))
    }

    /// 汇总所有已登记节点，产出全量快照。
    ///
    /// - `active_nodes` = 已登记节点数；
    /// - `active_connections` = 各节点活跃连接数之和（饱和求和）；
    /// - `total_rx_bytes` / `total_tx_bytes` = 各节点字节总和（饱和求和）。
    #[must_use]
    pub fn snapshot(&self) -> TrafficSummary {
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        let mut total_conns = 0u32;
        for n in self.nodes.values() {
            total_rx = total_rx.saturating_add(n.rx_bytes);
            total_tx = total_tx.saturating_add(n.tx_bytes);
            total_conns = total_conns.saturating_add(n.active_conns);
        }
        TrafficSummary {
            total_rx_bytes: total_rx,
            total_tx_bytes: total_tx,
            active_connections: total_conns,
            active_nodes: u32::try_from(self.nodes.len()).unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_collector_snapshot_is_zero() {
        let c = StatsCollector::new();
        let s = c.snapshot();
        assert_eq!(s.total_rx_bytes, 0);
        assert_eq!(s.total_tx_bytes, 0);
        assert_eq!(s.active_connections, 0);
        assert_eq!(s.active_nodes, 0);
    }

    #[test]
    fn node_bytes_accumulate() {
        let mut c = StatsCollector::new();
        c.record_node_bytes("node-a", 100, 200);
        c.record_node_bytes("node-a", 50, 50);
        assert_eq!(c.node_summary("node-a"), Some((150, 250, 0)));
    }

    #[test]
    fn connection_active_count_increases_and_decreases() {
        let mut c = StatsCollector::new();
        c.record_connection("node-a", true);
        c.record_connection("node-a", true);
        c.record_connection("node-a", false);
        assert_eq!(c.node_summary("node-a"), Some((0, 0, 1)));
    }

    #[test]
    fn closing_without_open_does_not_underflow() {
        let mut c = StatsCollector::new();
        c.record_connection("node-a", false);
        // 饱和：从 0 关闭不会回绕到 u32::MAX。
        assert_eq!(c.node_summary("node-a"), Some((0, 0, 0)));
    }

    #[test]
    fn unknown_node_summary_is_none() {
        let c = StatsCollector::new();
        assert_eq!(c.node_summary("never-seen"), None);
    }

    #[test]
    fn snapshot_sums_across_nodes() {
        let mut c = StatsCollector::new();
        c.record_node_bytes("node-a", 100, 200);
        c.record_node_bytes("node-a", 50, 50);
        c.record_connection("node-a", true);
        c.record_connection("node-a", true);
        c.record_connection("node-a", false);
        c.record_node_bytes("node-b", 10, 20);
        c.record_connection("node-b", true);

        let s = c.snapshot();
        assert_eq!(s.total_rx_bytes, 160);
        assert_eq!(s.total_tx_bytes, 270);
        assert_eq!(s.active_connections, 2);
        assert_eq!(s.active_nodes, 2);
    }

    #[test]
    fn byte_accumulation_saturates() {
        let mut c = StatsCollector::new();
        c.record_node_bytes("node-a", u64::MAX, 0);
        c.record_node_bytes("node-a", 1, 0);
        assert_eq!(c.node_summary("node-a"), Some((u64::MAX, 0, 0)));
    }

    #[test]
    fn connection_count_increments_correctly_without_panic() {
        let mut c = StatsCollector::new();
        // 重复累加证明不溢出 panic；到达 u32::MAX 的饱和由 std::saturating_add 保证。
        for _ in 0..500 {
            c.record_connection("node-a", true);
        }
        assert_eq!(c.node_summary("node-a"), Some((0, 0, 500)));
    }

    #[test]
    fn per_node_state_is_independent() {
        let mut c = StatsCollector::new();
        c.record_node_bytes("node-a", 1, 1);
        c.record_node_bytes("node-b", 2, 2);
        assert_eq!(c.node_summary("node-a"), Some((1, 1, 0)));
        assert_eq!(c.node_summary("node-b"), Some((2, 2, 0)));
    }
}
