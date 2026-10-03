//! E4 回归场景 `regression.crash-recovery` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/regression/crash_recovery.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus-workspace --example crash_recovery -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。
//!
//! 流程（与场景 [given]/[when] 对应）：
//!
//! ```text
//! [崩溃前] 持久会话记录 Active+Unfinished；Workspace 写前日志登记 C1（进程强杀）
//!   -> [冷启动] reconciliation_started
//!   -> open 恢复 durable state + reconcile_journal（redo 中断写入 -> C1 落 DAG）
//!   -> reconcile 会话记录（孤儿分类：恰一次提交 Failed -> Disposed）
//!   -> accept_new_work（Reconciliation 之后）
//! ```

#![forbid(unsafe_code)]

use nexus_domain::{LifecyclePhase, SessionId, TerminalOutcome};
use nexus_session::{
    ReconcilePolicy, SessionReconcileError, SessionRecord, SessionRecordStore,
    reconcile_session_records,
};
use nexus_storage::{InMemoryContentStore, ObjectId};
use nexus_workspace::{AuthorId, Change, JournalReconcileReport, Workspace, WorkspaceId};

/// 事件常量（与场景 expect 的 events.0..3 一一对应，顺序即被冻结的顺序契约）。
const EV_RECONCILIATION_STARTED: &str = "reconciliation_started";
const EV_WORKSPACE_JOURNAL_RECONCILED: &str = "workspace_journal_reconciled";
const EV_ORPHAN_SESSION_CLASSIFIED: &str = "orphan_session_classified";
const EV_ACCEPT_NEW_WORK: &str = "accept_new_work";

/// Composition Root 注入的会话记录存储（内存实现，模拟持久记录跨越崩溃边界）。
#[derive(Debug, Default)]
struct InMemorySessionRecordStore {
    records: Vec<SessionRecord>,
}

impl SessionRecordStore for InMemorySessionRecordStore {
    fn load(&self) -> Result<Vec<SessionRecord>, String> {
        Ok(self.records.clone())
    }

    fn save(&mut self, record: &SessionRecord) -> Result<(), String> {
        if let Some(slot) = self
            .records
            .iter_mut()
            .find(|r| r.session == record.session)
        {
            *slot = record.clone();
        } else {
            self.records.push(record.clone());
        }
        Ok(())
    }
}

/// 冷启动流程的结构化结果（供 JSON 输出）。
struct FlowReport {
    events: Vec<&'static str>,
    workspace_heads: Vec<String>,
    journal: JournalReconcileReport,
    orphans_classified: usize,
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run_flow() {
        Ok(report) => {
            let json = json_report(&report);
            if as_json {
                println!("{json}");
            } else {
                println!("Crash-recovery cold-start flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("crash_recovery failed: {err}");
            std::process::exit(1);
        }
    }
}

fn run_flow() -> Result<FlowReport, String> {
    let mut events: Vec<&'static str> = Vec::new();
    let ws_id = WorkspaceId("ws-crash-1".into());
    let session_id = SessionId("sess-orphan-1".into());

    // ---- 崩溃前持久状态 ----

    // 1) 持久会话记录：Active + Unfinished（进程强杀时未达终态）。
    let mut rec_store = InMemorySessionRecordStore::default();
    rec_store.records.push(SessionRecord {
        detached_at_unix: None,
        session: session_id.clone(),
        phase: LifecyclePhase::Active,
        outcome: TerminalOutcome::Unfinished,
        plan_snapshot: None,
    });

    // 2) Workspace 写前日志：登记提交 C1（a.txt），随后“进程崩溃”，C1 未落 DAG。
    let mut ws = Workspace::init(
        ws_id.clone(),
        InMemoryContentStore::new(),
        AuthorId("node-local".into()),
    )
    .map_err(|e| e.to_string())?;
    let genesis = ws.heads().heads[0].clone();
    let pending = ws
        .journal_pending(
            &genesis,
            &[Change {
                path: "a.txt".into(),
                content: b"crash-a".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;
    let state_root: ObjectId = ws.state_root().clone();
    // 模拟进程死亡：销毁内存 Workspace，持久对象（状态/journal/内容）留在 store。
    let store = ws.into_store();

    // ---- 冷启动：先 Reconciliation，再接受新工作 ----

    events.push(EV_RECONCILIATION_STARTED);

    // 3) 从 durable state 恢复 Workspace，回放写前日志（redo 中断写入）。
    let mut restored = Workspace::open(ws_id, store, &state_root, AuthorId("node-local".into()))
        .map_err(|e| e.to_string())?;
    let journal = restored.reconcile_journal().map_err(|e| e.to_string())?;
    events.push(EV_WORKSPACE_JOURNAL_RECONCILED);

    // 4) 会话记录 reconcile：进程死亡 + 未达终态 -> 孤儿分类（恰一次 Failed）。
    let session_report =
        reconcile_session_records(&mut rec_store, ReconcilePolicy::process_dead(0))
            .map_err(|e: SessionReconcileError| e.to_string())?;
    if session_report.orphans_classified > 0 {
        events.push(EV_ORPHAN_SESSION_CLASSIFIED);
    }

    // 5) Reconciliation 完成后才接受新工作（冻结顺序契约的核心）。
    events.push(EV_ACCEPT_NEW_WORK);

    // 断言式自检：pending 提交必须已通过 redo 落入 DAG 并成为唯一 Head。
    if restored.heads().len() != 1 || restored.heads().heads[0] != pending {
        return Err(format!(
            "crash recovery failed: expected single head {pending:?}, got {:?}",
            restored.heads().heads
        ));
    }

    Ok(FlowReport {
        events,
        workspace_heads: restored.heads().heads.iter().map(|h| h.0.clone()).collect(),
        journal,
        orphans_classified: session_report.orphans_classified,
    })
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_report(report: &FlowReport) -> String {
    let events: Vec<String> = report.events.iter().map(|e| json_str(e)).collect();
    let heads: Vec<String> = report.workspace_heads.iter().map(|h| json_str(h)).collect();
    format!(
        "{{\"verdict\":\"PASS\",\"events\":[{}],\
\"workspace\":{{\"heads\":[{}],\"journal_reconciled\":{{\"confirmed\":{},\"redone\":{},\"total\":{}}}}},\
\"sessions\":{{\"orphans_classified\":{}}}}}",
        events.join(","),
        heads.join(","),
        report.journal.confirmed,
        report.journal.redone,
        report.journal.total,
        report.orphans_classified
    )
}
