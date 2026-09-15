//! nexus-measurement
//!
//! 定义并维护 RTT / Loss / Jitter / Throughput 等事实 Measurement。
//! Measurement != Score：本 crate 只提供带 freshness/confidence 的客观测量值，
//! 不编码业务权重，不直接选择 Provider（选择是 Planner 的职责）。
//!
//! 本 crate 是 Portable Core：纯内存、零 I/O、零第三方依赖，可编译到 WASI。
//! 数值全部使用整数（避免浮点不确定性），loss 使用万分比。
//! 详细边界见同目录 `MODULE.md`。

#![forbid(unsafe_code)]

use nexus_domain::ProviderId;

/// 稳定模块标识；业务实现应通过公开类型/trait 增量加入，而不是扩大隐式全局状态。
pub const NEXUS_MEASUREMENT_MODULE: &str = "nexus-measurement";

/// 返回模块的人类可读职责摘要。
#[must_use]
pub const fn module_summary() -> &'static str {
    "定义并维护 RTT/Loss/Jitter/Throughput 等事实 Measurement（不含业务评分）。"
}

/// 单条链路事实测量快照。缺失字段为 `None`（显式未知，禁止伪造默认值）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkMeasurement {
    /// 往返时延（毫秒）。
    pub rtt_ms: Option<u32>,
    /// 丢包率（万分比，0..=10000）。
    pub loss_permyriad: Option<u32>,
    /// 抖动（毫秒）。
    pub jitter_ms: Option<u32>,
    /// 吞吐（kbps）。
    pub throughput_kbps: Option<u64>,
    /// 置信度（百分比 0..=100）：该测量的可信程度，不是业务分数。
    pub confidence_percent: u8,
}

impl LinkMeasurement {
    /// 排序用的 RTT 键：有值用其值，显式未知排最后（不假设未知=好）。
    #[must_use]
    pub fn rtt_sort_key(&self) -> u64 {
        self.rtt_ms.map_or(u64::MAX, u64::from)
    }
}

/// 按 Provider 索引的测量表（事实存储，确定性覆盖写）。
#[derive(Debug, Clone, Default)]
pub struct MeasurementTable {
    rows: Vec<(ProviderId, LinkMeasurement)>,
}

impl MeasurementTable {
    /// 创建空测量表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录（或按 Provider 幂等覆盖）一条测量。
    pub fn record(&mut self, provider: ProviderId, measurement: LinkMeasurement) {
        if let Some(slot) = self.rows.iter_mut().find(|(p, _)| *p == provider) {
            slot.1 = measurement;
        } else {
            self.rows.push((provider, measurement));
        }
    }

    /// 读取某 Provider 的事实测量；未观测返回 `None`（显式未知）。
    #[must_use]
    pub fn get(&self, provider: &ProviderId) -> Option<&LinkMeasurement> {
        self.rows
            .iter()
            .find(|(p, _)| p == provider)
            .map(|(_, m)| m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(s: &str) -> ProviderId {
        ProviderId(s.into())
    }

    #[test]
    fn unknown_measurement_sorts_after_known() {
        let known = LinkMeasurement {
            rtt_ms: Some(50),
            ..Default::default()
        };
        let unknown = LinkMeasurement::default();
        assert!(known.rtt_sort_key() < unknown.rtt_sort_key());
    }

    #[test]
    fn record_overwrites_and_get_unknown_is_none() {
        let mut t = MeasurementTable::new();
        t.record(
            pid("p1"),
            LinkMeasurement {
                rtt_ms: Some(100),
                confidence_percent: 80,
                ..Default::default()
            },
        );
        assert_eq!(t.get(&pid("p1")).unwrap().rtt_ms, Some(100));
        t.record(
            pid("p1"),
            LinkMeasurement {
                rtt_ms: Some(40),
                confidence_percent: 90,
                ..Default::default()
            },
        );
        assert_eq!(t.get(&pid("p1")).unwrap().rtt_ms, Some(40));
        assert!(t.get(&pid("missing")).is_none());
    }

    #[test]
    fn measurement_carries_no_score() {
        // 结构上只有客观字段，没有 weight/score。
        let m = LinkMeasurement::default();
        assert_eq!(m.confidence_percent, 0);
        assert_eq!(m.loss_permyriad, None);
    }
}
