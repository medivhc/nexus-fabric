//! E4 产品场景 `product.workspace-gc` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/workspace_gc.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus-workspace --example workspace_gc -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）。
//!
//! 流程（v9 §20 两阶段 GC）：
//!
//! ```text
//! store 预置孤儿对象（init 前写入，天然不可达）
//!   -> init + 两次提交（产生可达对象 + 被取代的旧 state 对象）
//!   -> pin 住一个孤儿对象
//!   -> plan_gc（可达闭包，纯规划）
//!   -> apply_tombstones（生成 Tombstone/Deletion Intent，持久化）
//!   -> sweep（保留期后物理删除；pin 阻止删除）
//! ```

#![forbid(unsafe_code)]

use nexus_storage::{ContentStore, InMemoryContentStore, ObjectId};
use nexus_workspace::{
    AuthorId, Change, GcConfig, InFlightSet, QuotaPolicy, ReadOutcome, Workspace, WorkspaceId,
};

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("workspace_gc flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("workspace_gc failed: {err}");
            std::process::exit(1);
        }
    }
}

fn run_flow() -> Result<String, String> {
    // 1. init 之前往 store 放孤儿对象（天然不可达）。
    let mut store = InMemoryContentStore::new();
    let old_orphan = store.put(b"orphan-old-blob")?;
    let pinned_orphan = store.put(b"orphan-pinned-blob")?;

    // 2. init + 两次提交。
    let mut ws = Workspace::init(
        WorkspaceId("ws-gc-1".into()),
        store,
        AuthorId("example".into()),
    )
    .map_err(|e| e.to_string())?;
    let base = ws.heads().heads[0].clone();
    let c1 = ws
        .commit_changes(
            &base,
            &[Change {
                path: "f1.txt".into(),
                content: b"hello".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;
    let c2 = ws
        .commit_changes(
            &c1,
            &[Change {
                path: "f2.txt".into(),
                content: b"world".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;

    // 3. pin 住 pinned_orphan（即使不可达也不得删除）。
    ws.pin(pinned_orphan.clone());

    // 4. 两阶段 GC。本 E4 用 retention 0 验证两阶段语义；
    //    保留期语义由单测（确定性时间）覆盖。
    let config = GcConfig {
        retention_secs: 0,
        max_sweep_per_run: 100_000,
        quota: QuotaPolicy::default(),
    };
    let plan = ws.plan_gc(&config).map_err(|e| e.to_string())?;
    let reachable_count = plan.reachable.len() as u64;
    let tombstones_created = ws.apply_tombstones(&plan).map_err(|e| e.to_string())?;
    let inflight = InFlightSet::new();
    let report = ws.sweep(&config, &inflight).map_err(|e| e.to_string())?;

    // 5. 验证。
    let present = |id: &ObjectId| ws.export_object(id).map(|o| o.is_some()).unwrap_or(false);
    let read_ok = |cid: &nexus_workspace::CommitId, path: &str, expect: &[u8]| {
        matches!(
            ws.read_at_commit(cid, path),
            Ok(ReadOutcome::Found(b)) if b == expect
        )
    };
    let protected_survived = read_ok(&c1, "f1.txt", b"hello")
        && read_ok(&c2, "f2.txt", b"world")
        && read_ok(&c2, "f1.txt", b"hello")
        && present(ws.state_root());
    let old_orphan_swept = !present(&old_orphan);
    let pinned_orphan_survived = present(&pinned_orphan);

    let verdict = if protected_survived && old_orphan_swept && pinned_orphan_survived {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(format!(
        "{{\
            \"verdict\": \"{verdict}\", \
            \"protected_survived\": {protected_survived}, \
            \"old_orphan_swept\": {old_orphan_swept}, \
            \"pinned_orphan_survived\": {pinned_orphan_survived}, \
            \"tombstones_created\": {tombstones_created}, \
            \"swept_total\": {}, \
            \"reachable_count\": {reachable_count}, \
            \"resurrected\": {}\
        }}",
        report.swept, report.resurrected,
    ))
}
