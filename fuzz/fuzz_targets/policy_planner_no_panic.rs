//! Fuzz target：Policy 求值 + Planner 规划路径的任意输入健壮性。
//!
//! 验证（AGENTS.md §24 / PRODUCT §2）：确定性纯函数在任意畸形输入下
//! **不得 panic**（错误必须走结构化 Result），决策必须确定。
//!
//! 覆盖：动作化有序链求值、Filter 硬谓词短路、Score 归一化、
//! 无候选 / 缺能力 / 全部被拒等边界。

#![no_main]

use libfuzzer_sys::fuzz_target;
use nexus_domain::{Constraint, Intent, ProviderId, ResourceId};
use nexus_measurement::LinkMeasurement;
use nexus_policy::{PolicyAction, PolicyEngine, PolicyMatch, PolicyRule};
use nexus_registry::ProviderRecord;

/// 越界安全取字节：任意畸形输入不得触发索引 panic。
fn byte(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ---- Policy：从字节构造引擎，任意输入不得 panic ----
    let profile = format!("p-{}", byte(data, 0) % 5);
    // 直接构造中立 FlowContext（字段公开）。
    let flow = nexus_domain::FlowContext {
        origin: nexus_domain::FlowOrigin::NativeApi,
        resource: ResourceId("internet-access".into()),
        destination: format!("https://{}.example/", byte(data, 1) % 10),
        profile: profile.clone(),
    };
    let rules: Vec<PolicyRule> = data
        .chunks(3)
        .enumerate()
        .take(4)
        .map(|(i, c)| PolicyRule {
            id: format!("rule-{i}"),
            match_: PolicyMatch {
                profile_eq: if byte(c, 0) % 3 == 0 {
                    Some(format!("p-{}", byte(c, 0) % 5))
                } else {
                    None
                },
                destination_prefix: if byte(c, 1) % 3 == 0 {
                    Some("https://".into())
                } else {
                    None
                },
            },
            actions: match byte(c, 2) % 4 {
                0 => vec![PolicyAction::AddConstraint {
                    key: "capability".into(),
                    value: "internet-access".into(),
                }],
                1 => vec![PolicyAction::EnrichMetadata {
                    key: "sniffed-host".into(),
                    value: format!("h{}", byte(c, 2)),
                }],
                2 => vec![PolicyAction::SelectProvider {
                    capability: "internet-access".into(),
                    exit_dns: Some("bound".into()),
                }],
                _ => vec![PolicyAction::Reject {
                    reason: format!("deny-{}", byte(c, 2)),
                }],
            },
        })
        .collect();
    let engine = PolicyEngine::new(rules);
    let result = engine.evaluate(&flow);
    // 确定性：同输入两次求值必须相等。
    assert_eq!(result, engine.evaluate(&flow));

    // ---- Planner：任意候选集不得 panic ----
    let intent = Intent { profile };
    let constraints = vec![
        Constraint {
            key: "capability".into(),
            value: "internet-access".into(),
        },
        Constraint {
            key: "exit-dns".into(),
            value: "bound".into(),
        },
    ];
    let resource = ResourceId("internet-access".into());
    let candidates: Vec<ProviderRecord> = data
        .chunks(8)
        .enumerate()
        .take(6)
        .map(|(i, c)| ProviderRecord {
            id: ProviderId(format!("provider-{i}")),
            resource: resource.clone(),
            placement: format!("placement-{}", byte(c, 0) % 4),
            locator: format!("loc-{i}.exit"),
            capabilities: if byte(c, 1) % 2 == 0 {
                vec!["internet-access".into()]
            } else {
                vec!["other-cap".into()]
            },
            present: byte(c, 2) % 2 == 0,
        })
        .collect();

    let _ = nexus_planner::plan(
        &resource,
        &intent,
        &constraints,
        &candidates,
        |id| {
            let idx: usize = id
                .0
                .strip_prefix("provider-")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            candidates.get(idx).map(|c| LinkMeasurement {
                rtt_ms: Some((c.locator.len() % 100) as u32),
                confidence_percent: 80,
                ..Default::default()
            })
        },
    );
});
