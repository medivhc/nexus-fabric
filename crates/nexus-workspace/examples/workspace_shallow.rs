//! E4 产品场景 `product.workspace-shallow-sparse` 的可执行驱动。
//!
//! 由 `scenarios/product/workspace_shallow_sparse.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus-workspace --example workspace_shallow -- --json
//! ```
//!
//! 流程（v9 §20）：
//!
//! ```text
//! 远端建 5 提交（C0..C4）
//!   -> shallow clone（depth=2）：只取 C3、C4
//!   -> 老提交本地缺失（预期状态）
//!   -> deepen(C2)：按需拉取缺失祖先，CommitId 不变
//!   -> sparse clone（sparse_paths=["docs/"]）：只持有 docs 对象
//! ```
//!
//! 远端由内存 FakeRemote 扮演（portable-core E4 的诚实替身，不伪装网络）。

#![forbid(unsafe_code)]

use std::collections::HashMap;

use nexus_storage::{ContentStore, InMemoryContentStore, ObjectId};
use nexus_workspace::{
    Change, CommitId, ObjectFetcher, ReadOutcome, ReplicaPolicy, Workspace, WorkspaceCommit,
    WorkspaceError, WorkspaceId,
};

/// 内存远端：从另一个 Workspace 的 store + DAG 提供对象/提交。
struct FakeRemote {
    commits: HashMap<CommitId, WorkspaceCommit>,
    store: InMemoryContentStore,
}

impl ObjectFetcher for FakeRemote {
    fn fetch_object(&mut self, id: &ObjectId) -> Result<Vec<u8>, WorkspaceError> {
        self.store
            .get(id)
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            .ok_or_else(|| WorkspaceError::MissingObject { id: id.clone() })
    }

    fn fetch_commit(&mut self, id: &CommitId) -> Result<WorkspaceCommit, WorkspaceError> {
        self.commits
            .get(id)
            .cloned()
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: id.clone() })
    }
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("workspace_shallow flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("workspace_shallow failed: {err}");
            std::process::exit(1);
        }
    }
}

fn build_remote() -> Result<FakeRemote, String> {
    let mut remote = Workspace::init(WorkspaceId("ws-remote".into()), InMemoryContentStore::new())
        .map_err(|e| e.to_string())?;
    let mut head = remote.heads().heads[0].clone();
    let files = [
        ("f1.txt", "content-1"),
        ("f2.txt", "content-2"),
        ("f3.txt", "content-3"),
        ("docs/guide.txt", "guide-content"),
    ];
    for (path, content) in files {
        head = remote
            .commit_changes(
                &head,
                &[Change {
                    path: path.into(),
                    content: content.as_bytes().to_vec(),
                }],
            )
            .map_err(|e| e.to_string())?;
    }
    // C0..C4
    let mut commits = HashMap::new();
    for i in 0..=4 {
        let id = CommitId(format!("C{i}"));
        let c = remote
            .commit(&id)
            .cloned()
            .ok_or_else(|| format!("remote missing {id:?}"))?;
        commits.insert(id, c);
    }
    let store = remote.into_store();
    Ok(FakeRemote { commits, store })
}

fn run_flow() -> Result<String, String> {
    let mut fetcher = build_remote()?;
    let head_c4 = CommitId("C4".into());

    // ---- shallow clone（depth=2）：只取 C3、C4 ----
    let policy = ReplicaPolicy {
        max_depth: Some(2),
        sparse_paths: Vec::new(),
    };
    let (mut shallow, shallow_report) = Workspace::shallow_clone(
        WorkspaceId("ws-shallow".into()),
        InMemoryContentStore::new(),
        &head_c4,
        &policy,
        &mut fetcher,
    )
    .map_err(|e| e.to_string())?;
    let shallow_commit_count = shallow_report.commits_imported;

    let head_file_readable = matches!(
        shallow.read_at_commit(&head_c4, "docs/guide.txt"),
        Ok(ReadOutcome::Found(b)) if b == b"guide-content"
    );
    // C2 不在本地 DAG：预期缺失（不是损坏）。
    let c2 = CommitId("C2".into());
    let old_file_missing_before_deepen = shallow.commit(&c2).is_none();

    // ---- deepen(C2)：按需拉取缺失祖先 ----
    let deepen_report = shallow
        .deepen(&c2, &mut fetcher)
        .map_err(|e| e.to_string())?;
    let old_file_readable_after_deepen = matches!(
        shallow.read_at_commit(&c2, "f2.txt"),
        Ok(ReadOutcome::Found(b)) if b == b"content-2"
    );
    let deepened_commit_id_unchanged = shallow.commit(&c2).map(|c| c.id == c2).unwrap_or(false)
        && deepen_report.commits_fetched >= 1;

    // ---- sparse clone：只持有 docs/ ----
    let sparse_policy = ReplicaPolicy {
        max_depth: None,
        sparse_paths: vec!["docs/".into()],
    };
    let (sparse, _) = Workspace::shallow_clone(
        WorkspaceId("ws-sparse".into()),
        InMemoryContentStore::new(),
        &head_c4,
        &sparse_policy,
        &mut fetcher,
    )
    .map_err(|e| e.to_string())?;
    let sparse_docs_present = matches!(
        sparse.read_at_commit(&head_c4, "docs/guide.txt"),
        Ok(ReadOutcome::Found(b)) if b == b"guide-content"
    );
    let sparse_other_absent = matches!(
        sparse.read_at_commit(&head_c4, "f1.txt"),
        Ok(ReadOutcome::NotHeldLocally(_))
    );

    let verdict = if shallow_commit_count == 2
        && head_file_readable
        && old_file_missing_before_deepen
        && old_file_readable_after_deepen
        && deepened_commit_id_unchanged
        && sparse_docs_present
        && sparse_other_absent
    {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(format!(
        "{{\
            \"verdict\": \"{verdict}\", \
            \"shallow_commit_count\": {shallow_commit_count}, \
            \"head_file_readable\": {head_file_readable}, \
            \"old_file_missing_before_deepen\": {old_file_missing_before_deepen}, \
            \"old_file_readable_after_deepen\": {old_file_readable_after_deepen}, \
            \"deepened_commit_id_unchanged\": {deepened_commit_id_unchanged}, \
            \"sparse_docs_present\": {sparse_docs_present}, \
            \"sparse_other_absent\": {sparse_other_absent}\
        }}"
    ))
}
