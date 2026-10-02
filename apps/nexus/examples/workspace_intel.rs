//! Workspace Intelligence E4（v9 §21）：访问轨迹 → WorkingSet 预测 → Prefetch →
//! 缺失对象经 ResourceDeliveryRequest → Core Planner 取回。
//!
//! JSON 输出契约（见 scenarios/product/workspace_intel.toml 冻结期望）。

use std::collections::{HashMap, HashSet};

use nexus_domain::{Constraint, Intent, ProviderId, ResourceId};
use nexus_planner::plan_from_snapshot;
use nexus_registry::ProviderRecord;
use nexus_storage::InMemoryContentStore;
use nexus_workspace::{AuthorId, Change, Workspace, WorkspaceId};
use nexus_workspace_intel::{
    AccessTrace, CacheState, EstimatorInput, PrefetchBudget, PrefetchScheduler, Profile,
    ResourceDeliveryRequest, TaskContext, WorkingSetEstimator, WorkspaceGraph, to_snapshot,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    let report = run();
    if json {
        println!(
            "{{\"verdict\":\"{}\",\"hot_files_covered\":{},\"cold_file_not_top\":{},\
             \"prefetch_bytes_within_budget\":{},\"prefetch_count\":{},\"cached_excluded\":{},\
             \"zero_signal_excluded\":{},\"missing_object_planned\":{},\"planned_provider\":\"{}\",\
             \"planner_rejected\":\"{}\"}}",
            if report.pass { "PASS" } else { "FAIL" },
            report.hot_files_covered,
            report.cold_file_not_top,
            report.prefetch_bytes_within_budget,
            report.prefetch_count,
            report.cached_excluded,
            report.zero_signal_excluded,
            report.missing_object_planned,
            report.planned_provider,
            report.planner_rejected,
        );
    } else {
        println!("{report:#?}");
    }
    if !report.pass {
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Report {
    pass: bool,
    hot_files_covered: bool,
    cold_file_not_top: bool,
    prefetch_bytes_within_budget: bool,
    prefetch_count: usize,
    cached_excluded: bool,
    zero_signal_excluded: bool,
    missing_object_planned: bool,
    planned_provider: String,
    planner_rejected: String,
}

const HOT: [&str; 3] = ["src/main.rs", "src/lib.rs", "docs/guide.md"];
const COLD: &str = "README.md";

fn run() -> Report {
    // 1. 建工作区并写入文件（含大小，供 prefetch 预算）。
    let store = InMemoryContentStore::default();
    let mut ws = Workspace::init(
        WorkspaceId("ws-intel-e4".into()),
        store,
        AuthorId("intel-e4".into()),
    )
    .unwrap();
    let files: Vec<(&str, usize)> = vec![
        ("src/main.rs", 20_000),
        ("src/lib.rs", 30_000),
        ("docs/guide.md", 40_000),
        ("docs/api.md", 50_000),
        ("tests/e2e.rs", 60_000),
        (COLD, 10_000),
    ];
    let head = ws.heads().heads[0].clone();
    let changes: Vec<Change> = files
        .iter()
        .map(|(p, n)| Change {
            path: p.to_string(),
            content: vec![b'x'; *n],
        })
        .collect();
    ws.commit_changes(&head, &changes).unwrap();
    let paths: Vec<String> = files.iter().map(|(p, _)| p.to_string()).collect();
    let sizes: HashMap<String, u64> = files
        .iter()
        .map(|(p, n)| (p.to_string(), *n as u64))
        .collect();

    // 2. 构造访问模式：热点反复访问，冷文件只碰一次。
    let mut trace = AccessTrace::new();
    let mut t = 1_000u64;
    for round in 0..6 {
        for p in HOT {
            t += 5;
            trace.record(p, t);
        }
        // 偶尔带一下 api.md（图共现边），round 2 碰一次冷文件。
        if round % 2 == 0 {
            t += 5;
            trace.record("docs/api.md", t);
        }
        if round == 2 {
            t += 5;
            trace.record(COLD, t);
        }
    }

    // 3. 建图 → 估计 WorkingSet。
    let graph = WorkspaceGraph::build(&paths, &trace);
    let profile = Profile::declare(
        "morning-review",
        vec!["src/main.rs".into(), "docs/guide.md".into()],
        1.0,
    );
    let estimator = WorkingSetEstimator::new();
    let cache = CacheState::default();
    let ranked = estimator.estimate(&EstimatorInput {
        snapshot_paths: &paths,
        profile: Some(&profile),
        graph: &graph,
        trace: &trace,
        task_context: &TaskContext::default(),
        cache: &cache,
        top_n: 10,
    });
    let top: Vec<&str> = ranked.iter().take(3).map(|s| s.path.as_str()).collect();
    let hot_set: HashSet<&str> = HOT.iter().copied().collect();
    let top_set: HashSet<&str> = top.iter().copied().collect();
    let hot_files_covered = hot_set.is_subset(&top_set);
    let cold_file_not_top = !top.contains(&COLD);

    // 4. Prefetch：热点已缓存 → 不得出现在拉取列表；预算 120KB。
    // ranked 全量：热点（已缓存，排除）→ docs/api.md(50k) → tests/e2e.rs(60k) →
    // README.md(10k)；贪心按优先级装：50k+60k+10k=120k 恰好装满 → 3 项。
    let mut cached = CacheState::default();
    for p in HOT {
        cached.insert(p, sizes[p]);
    }
    let scheduler = PrefetchScheduler::new();
    let plan = scheduler.schedule(
        &ranked,
        &cached,
        &sizes,
        &PrefetchBudget {
            max_bytes: 120_000,
            max_concurrent: 2,
        },
    );
    let total_bytes: u64 = plan.items.iter().map(|i| i.estimated_bytes).sum();
    let prefetch_bytes_within_budget = total_bytes <= 120_000;
    let cached_excluded = plan.items.iter().all(|i| !HOT.contains(&i.path.as_str()));
    // 零信号路径（tests/e2e.rs：无访问、无图边）不得被预取
    let zero_signal_excluded = plan.items.iter().all(|i| i.path != "tests/e2e.rs");

    // 5. 缺失对象 → ResourceDeliveryRequest → Planner。
    let req = ResourceDeliveryRequest::new(
        ResourceId("ws:ws-intel-e4/obj:docs/missing.md".into()),
        Intent {
            profile: "workspace-object-fetch".into(),
        },
        vec![Constraint {
            key: "capability".into(),
            value: "workspace-replica".into(),
        }],
        vec![ProviderId("node-replica".into())],
    );
    let records = vec![ProviderRecord {
        id: ProviderId("node-replica".into()),
        resource: req.resource.clone(),
        placement: "dc-east".into(),
        locator: "10.0.0.7:9000".into(),
        capabilities: vec!["workspace-replica".into()],
        present: true,
    }];
    let snapshot = to_snapshot(&req, &records);
    let planned = plan_from_snapshot(&req.resource, &snapshot, &req.intent, |_| None);
    let (missing_object_planned, planned_provider, planner_rejected) = match planned {
        Ok(p) => (
            true,
            p.plan.provider_id.0.clone(),
            p.trace
                .considered
                .iter()
                .find(|c| c.provider.0 == "node-replica")
                .and_then(|c| c.rejected_reason.as_ref())
                .map(|r| r.label().to_string())
                .unwrap_or_else(|| "none".into()),
        ),
        Err(_) => (false, String::new(), "plan-failed".into()),
    };

    let pass = hot_files_covered
        && cold_file_not_top
        && prefetch_bytes_within_budget
        && cached_excluded
        && zero_signal_excluded
        && missing_object_planned
        && planned_provider == "node-replica"
        && planner_rejected == "none";

    Report {
        pass,
        hot_files_covered,
        cold_file_not_top,
        prefetch_bytes_within_budget,
        prefetch_count: plan.items.len(),
        cached_excluded,
        zero_signal_excluded,
        missing_object_planned,
        planned_provider,
        planner_rejected,
    }
}
