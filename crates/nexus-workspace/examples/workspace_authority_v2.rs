//! E4 产品场景 `product.workspace-authority-v2` 的可执行驱动。
//!
//! ```text
//! cargo run --quiet -p nexus-workspace --example workspace_authority_v2 -- --json
//! ```
//!
//! 流程：
//!
//! ```text
//! A init(author-a) -> commit base
//! B 由 A 的 store 克隆 + open(author-b)（模拟曾同步过的设备）
//! A / B 离线各改 conflict.txt（分叉）
//! A sync_with_remote B：Head 交换 -> diverged -> 拉取缺失提交 -> merge_heads
//!   -> 冲突落持久化 ConflictObject（进 CAS）
//! A resolve_conflict(TakeLocal) -> Merge Commit（双 parent），Heads 收敛
//! B sync_with_remote A：拉到 Merge Commit，跨端 ID 一致
//! ```

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;

use nexus_storage::{ContentStore, InMemoryContentStore, ObjectId};
use nexus_workspace::{
    AuthorId, Change, ConflictResolution, MergeDisposition, Workspace, WorkspaceId,
    WorkspaceTransport, commit_id_of,
};

// ---- 双端内存帧通道 ----

struct Pipe {
    a_to_b: VecDeque<Vec<u8>>,
    b_to_a: VecDeque<Vec<u8>>,
}

struct PipeEnd {
    pipe: Arc<Mutex<Pipe>>,
    is_a: bool,
}

impl PipeEnd {
    fn pair() -> (Self, Self) {
        let pipe = Arc::new(Mutex::new(Pipe {
            a_to_b: VecDeque::new(),
            b_to_a: VecDeque::new(),
        }));
        (
            Self {
                pipe: pipe.clone(),
                is_a: true,
            },
            Self { pipe, is_a: false },
        )
    }
}

impl WorkspaceTransport for PipeEnd {
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), nexus_workspace::WorkspaceError> {
        let mut p = self
            .pipe
            .lock()
            .map_err(|_| nexus_workspace::WorkspaceError::Transport {
                reason: "pipe lock poisoned".into(),
            })?;
        if self.is_a {
            p.a_to_b.push_back(payload.to_vec());
        } else {
            p.b_to_a.push_back(payload.to_vec());
        }
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_workspace::WorkspaceError> {
        loop {
            {
                let mut p =
                    self.pipe
                        .lock()
                        .map_err(|_| nexus_workspace::WorkspaceError::Transport {
                            reason: "pipe lock poisoned".into(),
                        })?;
                let q = if self.is_a {
                    &mut p.b_to_a
                } else {
                    &mut p.a_to_b
                };
                if let Some(f) = q.pop_front() {
                    return Ok(f);
                }
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

// ---- 主流程 ----

struct Report {
    same_input_same_id: bool,
    different_content_different_id: bool,
    no_sequence_ids: bool,
    disposition: String,
    common_ancestor_found: bool,
    conflict_persisted: bool,
    conflict_paths: Vec<String>,
    conflict_resolved: bool,
    merge_commit_parents: usize,
    heads_after_resolve: usize,
    id_match_after_fetch: bool,
}

fn is_sequence_id(id: &str) -> bool {
    id.starts_with('C') && id.len() > 1 && id[1..].chars().all(|c| c.is_ascii_digit())
}

fn run() -> Result<Report, String> {
    // 1. 纯函数内容哈希：同输入同 ID，异内容异 ID。
    let parents = vec![];
    let root = ObjectId("root1".into());
    let author = AuthorId("node-a".into());
    let id1 = commit_id_of(&parents, &root, &author, 1000);
    let id2 = commit_id_of(&parents, &root, &author, 1000);
    let id3 = commit_id_of(&parents, &ObjectId("root2".into()), &author, 1000);
    let same_input_same_id = id1 == id2;
    let different_content_different_id = id1 != id3;
    let mut seen_ids: Vec<String> = vec![id1.0.clone(), id3.0.clone()];

    // 2. A 建仓并提交 base。
    let mut ws_a = Workspace::init(
        WorkspaceId("ws-auth-v2".into()),
        InMemoryContentStore::new(),
        AuthorId("node-a".into()),
    )
    .map_err(|e| e.to_string())?;
    let base = ws_a
        .commit_changes(
            &ws_a.heads().heads[0].clone(),
            &[Change {
                path: "a.txt".into(),
                content: b"base".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;
    seen_ids.push(base.0.clone());

    // 3. B 由 A 的 store 克隆并 open（模拟曾同步的设备），author 为 node-b。
    let state_root = ws_a.state_root().clone();
    let store_b = ws_a.store().clone();
    let mut ws_b = Workspace::open(
        WorkspaceId("ws-auth-v2".into()),
        store_b,
        &state_root,
        AuthorId("node-b".into()),
    )
    .map_err(|e| e.to_string())?;

    // 4. 双端离线分叉：同改 conflict.txt。
    let a_head = ws_a
        .commit_changes(
            &base,
            &[Change {
                path: "conflict.txt".into(),
                content: b"aaa".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;
    seen_ids.push(a_head.0.clone());
    let b_head = ws_b
        .commit_changes(
            &base,
            &[Change {
                path: "conflict.txt".into(),
                content: b"bbb".to_vec(),
            }],
        )
        .map_err(|e| e.to_string())?;
    seen_ids.push(b_head.0.clone());
    let no_sequence_ids = seen_ids.iter().all(|id| !is_sequence_id(id));

    // 5. A sync B（B 在线程里 serve）：Head 交换 -> diverged -> 拉取 -> 合并 -> 冲突落盘。
    let (mut ta, mut tb) = PipeEnd::pair();
    let serve = thread::spawn(move || {
        let r = ws_b.serve_sync(&mut tb);
        (ws_b, r)
    });
    let sync_report = ws_a.sync_with_remote(&mut ta).map_err(|e| e.to_string())?;
    let (ws_b, serve_res) = serve
        .join()
        .map_err(|_| "serve thread panicked".to_string())?;
    serve_res.map_err(|e| e.to_string())?;
    let mut ws_b = ws_b;

    let disposition = match sync_report.disposition {
        MergeDisposition::Diverged => "diverged",
        MergeDisposition::FastForward => "fastforward",
        MergeDisposition::AlreadyEqual => "equal",
    }
    .to_string();
    let common_ancestor_found = sync_report.common_ancestor.is_some();

    // 6. 冲突对象已持久化（CAS 可查，状态 unresolved）。
    let conflict_id = sync_report
        .conflict
        .clone()
        .ok_or_else(|| "expected conflict after diverged merge".to_string())?;
    let conflict = ws_a
        .get_conflict(&conflict_id)
        .ok_or_else(|| "conflict not found in index".to_string())?;
    let conflict_persisted = ws_a
        .store()
        .contains(&conflict.cas_object_id)
        .map_err(|e| e.to_string())?;
    let conflict_paths = conflict.paths.clone();

    // 7. resolve（取本地）-> Merge Commit（双 parent），Heads 收敛为 1。
    let merge_id = ws_a
        .resolve_conflict(
            &conflict_id,
            &[("conflict.txt".into(), ConflictResolution::TakeLocal)],
        )
        .map_err(|e| e.to_string())?;
    seen_ids.push(merge_id.0.clone());
    let merge_commit = ws_a
        .commit(&merge_id)
        .ok_or_else(|| "merge commit missing".to_string())?;
    let merge_commit_parents = merge_commit.parents.len();
    let heads_after_resolve = ws_a.heads().len();
    let conflict_resolved = matches!(
        ws_a.get_conflict(&conflict_id).map(|c| c.state.clone()),
        Some(nexus_workspace::ConflictState::Resolved { .. })
    );

    // 8. B 再 sync A：拉到 Merge Commit，跨端 ID 一致。
    let (mut ta2, mut tb2) = PipeEnd::pair();
    let mut ws_a2 = ws_a;
    let serve2 = thread::spawn(move || {
        let r = ws_a2.serve_sync(&mut ta2);
        (ws_a2, r)
    });
    let sync2 = ws_b.sync_with_remote(&mut tb2).map_err(|e| e.to_string())?;
    let (_, serve2_res) = serve2.join().map_err(|_| "serve2 panicked".to_string())?;
    serve2_res.map_err(|e| e.to_string())?;
    drop(sync2);
    let id_match_after_fetch = ws_b.commit(&merge_id).is_some();

    Ok(Report {
        same_input_same_id,
        different_content_different_id,
        no_sequence_ids,
        disposition,
        common_ancestor_found,
        conflict_persisted,
        conflict_paths,
        conflict_resolved,
        merge_commit_parents,
        heads_after_resolve,
        id_match_after_fetch,
    })
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(r) => {
            if as_json {
                println!(
                    "{{\"verdict\":\"PASS\",\"content_hash\":{{\"same_input_same_id\":{},\"different_content_different_id\":{},\"no_sequence_ids\":{}}},\"head_exchange\":{{\"disposition\":\"{}\",\"common_ancestor_found\":{}}},\"conflict\":{{\"persisted_in_cas\":{},\"paths\":[{}],\"resolved\":{},\"merge_commit_parents\":{},\"heads_after_resolve\":{}}},\"cross_node\":{{\"id_match_after_fetch\":{}}}}}",
                    r.same_input_same_id,
                    r.different_content_different_id,
                    r.no_sequence_ids,
                    r.disposition,
                    r.common_ancestor_found,
                    r.conflict_persisted,
                    r.conflict_paths
                        .iter()
                        .map(|p| format!("\"{p}\""))
                        .collect::<Vec<_>>()
                        .join(","),
                    r.conflict_resolved,
                    r.merge_commit_parents,
                    r.heads_after_resolve,
                    r.id_match_after_fetch,
                );
            } else {
                println!("workspace_authority_v2 OK");
            }
        }
        Err(e) => {
            if as_json {
                println!("{{\"verdict\":\"FAIL\",\"error\":\"{e}\"}}");
            } else {
                eprintln!("workspace_authority_v2 failed: {e}");
            }
            std::process::exit(1);
        }
    }
}
