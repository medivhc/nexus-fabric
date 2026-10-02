//! E4 产品场景 `product.workspace-offline-merge` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/workspace_offline_merge.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus-workspace --example workspace_offline_merge -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。
//!
//! 流程（与场景 [given]/[when] 对应）：
//!
//! ```text
//! init (Base C0)
//!   -> 本地节点离线提交 a.txt（Head -> C1）
//!   -> 远端节点离线提交 b.txt（HeadSet 分叉 -> {C1, C2}）
//!   -> 重连三方合并 -> Merge Commit（本地提交零丢失）
//! ```

#![forbid(unsafe_code)]

use nexus_storage::InMemoryContentStore;
use nexus_workspace::{AuthorId, Change, MergeDisposition, MergeReport, Workspace, WorkspaceId};

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run_flow() {
        Ok(report) => {
            let json = json_report(&report);
            if as_json {
                println!("{json}");
            } else {
                println!("Workspace offline-merge flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("workspace_offline_merge failed: {err}");
            std::process::exit(1);
        }
    }
}

fn run_flow() -> Result<MergeReport, String> {
    let mut ws = Workspace::init(
        WorkspaceId("ws-offline-merge-1".into()),
        InMemoryContentStore::new(),
        AuthorId("node-local".into()),
    )
    .map_err(|e| e.to_string())?;
    let base = ws.heads().heads[0].clone();

    // 本地节点离线写入 a.txt（parent = C0，是当前 Head -> 替换为 C1）。
    let local = ws
        .commit_changes(
            &base,
            &[Change {
                path: "a.txt".into(),
                content: b"local-a".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;

    // 远端节点离线写入 b.txt（parent = C0，已不是当前 Head -> 分叉出新 Head C2）。
    let remote = ws
        .commit_changes(
            &base,
            &[Change {
                path: "b.txt".into(),
                content: b"remote-b".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;

    // 重连：三方合并（事件按序：common_ancestor_found -> merge_commit_created）。
    ws.merge_heads(&local, &remote).map_err(|e| e.to_string())
}

fn disposition_name(d: &MergeDisposition) -> &'static str {
    match d {
        MergeDisposition::FastForward => "FastForward",
        MergeDisposition::AlreadyEqual => "AlreadyEqual",
        MergeDisposition::Diverged => "Diverged",
    }
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

fn json_report(report: &MergeReport) -> String {
    let events: Vec<String> = report.events.iter().map(|e| json_str(e)).collect();
    let merge_commit = report
        .merge_commit
        .as_ref()
        .map(|id| json_str(&id.0))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"verdict\":\"PASS\",\"head_count_before_merge\":{},\"events\":[{}],\
\"lost_successful_local_commits\":{},\"disposition\":{},\"merge_commit\":{}}}",
        report.head_count_before_merge,
        events.join(","),
        report.lost_successful_local_commits,
        json_str(disposition_name(&report.disposition)),
        merge_commit
    )
}
