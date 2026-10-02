//! 缺失对象 → ResourceDeliveryRequest → Core Planner 的接线（v9 §21）。
//!
//! 本模块只做**格式转换**：把 intel 产生的交付请求表达为 Planner 的输入快照。
//! Provider/Path 的选择仍由 Core Planner 完成（Planner ≠ Estimator）。

use nexus_domain::ResourceDeliveryRequest;
use nexus_planner::PlanningSnapshot;
use nexus_registry::ProviderRecord;

/// 把交付请求转换为规划快照：
///
/// - candidates：`records` 中 id 在 `req.providers` 内、resource 匹配的记录；
/// - constraints：`req.constraints` 原样带入（含 capability 硬约束）；
/// - connectivity：空（未评估，保持 Planner 旧行为；调用方可叠加 T2 的评估）。
#[must_use]
pub fn to_snapshot(req: &ResourceDeliveryRequest, records: &[ProviderRecord]) -> PlanningSnapshot {
    let candidates: Vec<ProviderRecord> = records
        .iter()
        .filter(|r| r.resource == req.resource && r.present && req.providers.contains(&r.id))
        .cloned()
        .collect();
    PlanningSnapshot::new(candidates, req.constraints.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::{Constraint, Intent, ProviderId, ResourceId};

    fn req() -> ResourceDeliveryRequest {
        ResourceDeliveryRequest::new(
            ResourceId("ws:w/obj:o".into()),
            Intent {
                profile: "workspace-object-fetch".into(),
            },
            vec![Constraint {
                key: "capability".into(),
                value: "workspace-replica".into(),
            }],
            vec![ProviderId("n1".into())],
        )
    }

    fn record(id: &str, present: bool) -> ProviderRecord {
        ProviderRecord {
            id: ProviderId(id.into()),
            resource: ResourceId("ws:w/obj:o".into()),
            placement: "dc".into(),
            locator: "10.0.0.1:1".into(),
            capabilities: vec!["workspace-replica".into()],
            present,
        }
    }

    #[test]
    fn filters_to_known_present_providers() {
        let records = vec![record("n1", true), record("n2", true), record("n1", false)];
        let snap = to_snapshot(&req(), &records);
        // n2 不在 providers 内；n1 的离线记录被过滤
        assert_eq!(snap.candidates.len(), 1);
        assert_eq!(snap.candidates[0].id.0, "n1");
        assert_eq!(snap.constraints.len(), 1);
        assert!(snap.connectivity.is_empty());
    }
}
