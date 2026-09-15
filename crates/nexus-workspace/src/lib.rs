//! Workspace 权威模型：不可变 Commit DAG + Head Set（AGENTS §16 / PRODUCT §4）。
//!
//! 本切片由 `product.workspace-offline-merge` E4 场景驱动，实现：
//!
//! - Commit DAG 与 Head Set：多端离线写允许产生多个 Head；
//! - 重连后 fast-forward / AlreadyEqual / 三方合并 + 显式冲突检测；
//! - 合并后本地提交零丢失（`lost_successful_local_commits = 0`）；
//! - Manifest 与内容对象存入 `nexus-storage` 的 `ContentStore`（CAS）。
//!
//! 明确不做（MODULE.md Non-Responsibilities）：不选择远端 Replica/Path
//! （归 Core Planner）；不实现平台 FUSE/File Provider（归 `nexus-platform-*`）；
//! WorkingSet / Profile / WorkspaceGraph / Prefetch 为非权威内容，本切片不实现。

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use nexus_storage::{ContentStore, ObjectId};

/// 合并事件：已找到合并基（Common Ancestor）。
pub const EV_COMMON_ANCESTOR_FOUND: &str = "common_ancestor_found";
/// 合并事件：已创建 Merge Commit。
pub const EV_MERGE_COMMIT_CREATED: &str = "merge_commit_created";

/// Workspace 标识（PRODUCT §4 权威模型字段）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceId(pub String);

/// 提交标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitId(pub String);

/// 不可变提交：parent(s) + 根 Manifest 的对象引用。
///
/// 提交一旦写入 DAG 不再变更；新内容只通过新建提交表达。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCommit {
    pub id: CommitId,
    pub parents: Vec<CommitId>,
    pub root_manifest_id: ObjectId,
}

/// Head Set：当前权威端点提交集合（离线分叉时允许多于一个）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeadSet {
    pub heads: Vec<CommitId>,
}

impl HeadSet {
    /// 该 Head 是否已存在。
    #[must_use]
    pub fn contains(&self, id: &CommitId) -> bool {
        self.heads.contains(id)
    }

    /// 当前 Head 数量（分叉时 > 1）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.heads.len()
    }

    /// 是否为空（正常 Workspace 不应为空）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    fn replace(&mut self, old: &CommitId, new: CommitId) {
        if let Some(slot) = self.heads.iter_mut().find(|h| *h == old) {
            *slot = new;
        }
    }

    fn add(&mut self, id: CommitId) {
        if !self.contains(&id) {
            self.heads.push(id);
        }
    }

    fn remove(&mut self, id: &CommitId) {
        self.heads.retain(|h| h != id);
    }
}

/// 单条变更：路径 + 新内容（离线写入的最小单元）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub content: Vec<u8>,
}

/// 合并处置（语义与初版骨架一致）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeDisposition {
    FastForward,
    AlreadyEqual,
    Diverged,
}

/// 三方合并对单一路径的冲突处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeConflict {
    /// 双端相对合并基修改了同一路径且内容不同，需要显式冲突解决。
    ConflictingPath { path: String },
}

/// Workspace 结构化失败（MODULE.md：不以日志文本代替错误类型）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceError {
    /// 引用了 DAG 中不存在的提交。
    UnknownCommit { id: CommitId },
    /// 内容寻址存储中缺少对象。
    MissingObject { id: ObjectId },
    /// Manifest 无法解析。
    CorruptManifest { id: ObjectId, reason: String },
    /// 底层存储失败。
    StoreFailure { reason: String },
    /// 三方合并出现需要显式解决的冲突。
    MergeConflict(MergeConflict),
    /// 两个提交之间不存在公共祖先（异常 DAG）。
    NoCommonAncestor { left: CommitId, right: CommitId },
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommit { id } => write!(f, "unknown commit: {id:?}"),
            Self::MissingObject { id } => write!(f, "missing object: {id}"),
            Self::CorruptManifest { id, reason } => {
                write!(f, "corrupt manifest {id}: {reason}")
            }
            Self::StoreFailure { reason } => write!(f, "store failure: {reason}"),
            Self::MergeConflict(MergeConflict::ConflictingPath { path }) => {
                write!(f, "merge conflict on path: {path}")
            }
            Self::NoCommonAncestor { left, right } => {
                write!(f, "no common ancestor between {left:?} and {right:?}")
            }
        }
    }
}

impl std::error::Error for WorkspaceError {}

/// Manifest：路径 -> 内容对象。确定性序列化（按 path 排序），存入 CAS。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Manifest {
    entries: Vec<(String, ObjectId)>,
}

impl Manifest {
    fn get(&self, path: &str) -> Option<&ObjectId> {
        self.entries
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, id)| id)
    }

    fn set(&mut self, path: String, id: ObjectId) {
        if let Some(slot) = self.entries.iter_mut().find(|(p, _)| *p == path) {
            slot.1 = id;
            return;
        }
        self.entries.push((path, id));
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
    }

    /// 相对 `base` 的增量：本 Manifest 中与 base 不同的所有路径。
    fn diff_from(&self, base: &Manifest) -> Vec<(String, ObjectId)> {
        self.entries
            .iter()
            .filter(|(p, id)| base.get(p) != Some(id))
            .cloned()
            .collect()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (p, id) in &self.entries {
            out.extend_from_slice(p.as_bytes());
            out.push(0);
            out.extend_from_slice(id.0.as_bytes());
            out.push(b'\n');
        }
        out
    }

    fn from_bytes(id: &ObjectId, bytes: &[u8]) -> Result<Self, WorkspaceError> {
        let mut entries = Vec::new();
        for line in bytes.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let Some(sep) = line.iter().position(|b| *b == 0) else {
                return Err(WorkspaceError::CorruptManifest {
                    id: id.clone(),
                    reason: "entry lacks path separator".into(),
                });
            };
            let (path, hex_bytes) = line.split_at(sep);
            let hex_bytes = &hex_bytes[1..];
            let path = std::str::from_utf8(path).map_err(|e| WorkspaceError::CorruptManifest {
                id: id.clone(),
                reason: format!("path not utf8: {e}"),
            })?;
            let hex =
                std::str::from_utf8(hex_bytes).map_err(|e| WorkspaceError::CorruptManifest {
                    id: id.clone(),
                    reason: format!("object id not utf8: {e}"),
                })?;
            entries.push((path.to_string(), ObjectId(hex.to_string())));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self { entries })
    }
}

/// 合并报告：一次 `merge_heads` 的结构化结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeReport {
    pub disposition: MergeDisposition,
    /// 按序发生的事件（common_ancestor_found / merge_commit_created）。
    pub events: Vec<&'static str>,
    /// 若创建了新 Merge Commit，给出其 id。
    pub merge_commit: Option<CommitId>,
    /// 合并前的 Head 数量（分叉判定）。
    pub head_count_before_merge: usize,
    /// 合并后不再可达的既有提交数（必须为 0：本地提交零丢失）。
    pub lost_successful_local_commits: usize,
}

/// Workspace 权威状态：不可变 Commit DAG + Head Set + 内容寻址存储。
#[derive(Debug)]
pub struct Workspace<S: ContentStore> {
    id: WorkspaceId,
    commits: HashMap<CommitId, WorkspaceCommit>,
    heads: HeadSet,
    store: S,
    next_seq: u64,
}

impl<S: ContentStore> Workspace<S> {
    /// 新建 Workspace：创建空 Manifest 的 Base Commit `C0`，Head = `[C0]`。
    pub fn init(id: WorkspaceId, mut store: S) -> Result<Self, WorkspaceError> {
        let empty = Manifest::default();
        let root_manifest_id = store
            .put(&empty.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        let base = WorkspaceCommit {
            id: CommitId("C0".into()),
            parents: Vec::new(),
            root_manifest_id,
        };
        let mut ws = Self {
            id,
            commits: HashMap::new(),
            heads: HeadSet::default(),
            store,
            next_seq: 1,
        };
        ws.commits.insert(base.id.clone(), base.clone());
        ws.heads.add(base.id.clone());
        Ok(ws)
    }

    /// Workspace 标识。
    #[must_use]
    pub fn id(&self) -> &WorkspaceId {
        &self.id
    }

    /// 当前 Head Set。
    #[must_use]
    pub fn heads(&self) -> &HeadSet {
        &self.heads
    }

    /// 按 id 读取提交（只读 DAG 查询）。
    #[must_use]
    pub fn commit(&self, id: &CommitId) -> Option<&WorkspaceCommit> {
        self.commits.get(id)
    }

    /// 离线写入：在 `parent` 之上应用 `changes`，创建新的不可变提交。
    ///
    /// - `parent` 是当前 Head → 替换该 Head；
    /// - 否则 → 追加新 Head（多端离线分叉，AGENTS §16）。
    pub fn commit_changes(
        &mut self,
        parent: &CommitId,
        changes: &[Change],
    ) -> Result<CommitId, WorkspaceError> {
        let parent_commit = self
            .commits
            .get(parent)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: parent.clone() })?;
        let mut manifest = self.load_manifest(&parent_commit.root_manifest_id)?;
        for change in changes {
            let oid = self
                .store
                .put(&change.content)
                .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
            manifest.set(change.path.clone(), oid);
        }
        let root_manifest_id = self
            .store
            .put(&manifest.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        let id = self.next_commit_id();
        let commit = WorkspaceCommit {
            id: id.clone(),
            parents: vec![parent.clone()],
            root_manifest_id,
        };
        self.commits.insert(id.clone(), commit);
        if self.heads.contains(parent) {
            self.heads.replace(parent, id.clone());
        } else {
            self.heads.add(id.clone());
        }
        Ok(id)
    }

    /// 重连合并：把 `remote` 合并进 `local`。
    ///
    /// - `local == remote` → `AlreadyEqual`，无新提交；
    /// - `remote` 是 `local` 的祖先 → `AlreadyEqual`（local 已包含 remote）；
    /// - `local` 是 `remote` 的祖先 → `FastForward`，Head 前进到 remote；
    /// - 否则 → 三方合并：找合并基、检测冲突、创建 Merge Commit。
    ///
    /// 返回报告含 `lost_successful_local_commits`：合并后不可达的既有提交数。
    pub fn merge_heads(
        &mut self,
        local: &CommitId,
        remote: &CommitId,
    ) -> Result<MergeReport, WorkspaceError> {
        let head_count_before_merge = self.heads.len();
        let pre_reachable = self.reachable_from(&self.heads.heads.clone());

        if local == remote {
            return Ok(MergeReport {
                disposition: MergeDisposition::AlreadyEqual,
                events: Vec::new(),
                merge_commit: None,
                head_count_before_merge,
                lost_successful_local_commits: 0,
            });
        }

        let local_commit = self
            .commits
            .get(local)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: local.clone() })?;
        let remote_commit = self
            .commits
            .get(remote)
            .ok_or_else(|| WorkspaceError::UnknownCommit { id: remote.clone() })?;

        // 快进判定：local 是 remote 的祖先 → remote 已包含 local 的全部内容。
        if self
            .reachable_from(std::slice::from_ref(remote))
            .contains(local)
        {
            self.heads.remove(local);
            self.heads.add(remote.clone());
            return Ok(MergeReport {
                disposition: MergeDisposition::FastForward,
                events: Vec::new(),
                merge_commit: None,
                head_count_before_merge,
                lost_successful_local_commits: 0,
            });
        }

        // 已相等判定：remote 是 local 的祖先 → local 已包含 remote。
        if self
            .reachable_from(std::slice::from_ref(local))
            .contains(remote)
        {
            return Ok(MergeReport {
                disposition: MergeDisposition::AlreadyEqual,
                events: Vec::new(),
                merge_commit: None,
                head_count_before_merge,
                lost_successful_local_commits: 0,
            });
        }

        // 分叉：三方合并。
        let base = self.find_common_ancestor(local, remote)?.ok_or_else(|| {
            WorkspaceError::NoCommonAncestor {
                left: local.clone(),
                right: remote.clone(),
            }
        })?;
        let mut events = vec![EV_COMMON_ANCESTOR_FOUND];

        let base_manifest =
            self.load_manifest(&self.commit(&base).expect("base in dag").root_manifest_id)?;
        let local_manifest = self.load_manifest(&local_commit.root_manifest_id)?;
        let remote_manifest = self.load_manifest(&remote_commit.root_manifest_id)?;

        let local_delta = local_manifest.diff_from(&base_manifest);
        let remote_delta = remote_manifest.diff_from(&base_manifest);

        // 显式冲突检测：双端相对合并基改同一路径且内容不同。
        for (path, local_id) in &local_delta {
            if let Some((_, remote_id)) = remote_delta.iter().find(|(p, _)| p == path) {
                if remote_id != local_id {
                    return Err(WorkspaceError::MergeConflict(
                        MergeConflict::ConflictingPath { path: path.clone() },
                    ));
                }
            }
        }

        let mut merged = base_manifest;
        for (path, id) in &local_delta {
            merged.set(path.clone(), id.clone());
        }
        for (path, id) in &remote_delta {
            merged.set(path.clone(), id.clone());
        }
        let root_manifest_id = self
            .store
            .put(&merged.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;

        let id = self.next_commit_id();
        let merge_commit = WorkspaceCommit {
            id: id.clone(),
            parents: vec![local.clone(), remote.clone()],
            root_manifest_id,
        };
        self.commits.insert(id.clone(), merge_commit);

        self.heads.remove(local);
        self.heads.remove(remote);
        self.heads.add(id.clone());
        events.push(EV_MERGE_COMMIT_CREATED);

        let post_reachable = self.reachable_from(&self.heads.heads.clone());
        let lost = pre_reachable.difference(&post_reachable).count();

        Ok(MergeReport {
            disposition: MergeDisposition::Diverged,
            events,
            merge_commit: Some(id),
            head_count_before_merge,
            lost_successful_local_commits: lost,
        })
    }

    /// 读取提交指向的 Manifest（CAS 对象）。
    fn load_manifest(&self, manifest_id: &ObjectId) -> Result<Manifest, WorkspaceError> {
        let bytes = self
            .store
            .get(manifest_id)
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            .ok_or_else(|| WorkspaceError::MissingObject {
                id: manifest_id.clone(),
            })?;
        Manifest::from_bytes(manifest_id, &bytes)
    }

    /// 从一组根提交沿 parent 闭包收集可达提交集。
    fn reachable_from(&self, roots: &[CommitId]) -> HashSet<CommitId> {
        let mut seen = HashSet::new();
        let mut stack: Vec<CommitId> = roots.to_vec();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(c) = self.commits.get(&id) {
                stack.extend(c.parents.iter().cloned());
            }
        }
        seen
    }

    /// 确定性合并基：BFS 自 `remote` 向上，第一个命中 `local` 祖先集的提交。
    ///
    /// 对树状 DAG 给出 LCA；对一般 DAG 给出一个确定性的公共祖先（事件语义
    /// `common_ancestor_found` 成立，三方合并以它为基）。
    fn find_common_ancestor(
        &self,
        local: &CommitId,
        remote: &CommitId,
    ) -> Result<Option<CommitId>, WorkspaceError> {
        let local_ancestors = self.reachable_from(std::slice::from_ref(local));
        let mut queue = VecDeque::from([remote.clone()]);
        let mut visited = HashSet::new();
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id.clone()) {
                continue;
            }
            if local_ancestors.contains(&id) {
                return Ok(Some(id));
            }
            if let Some(c) = self.commits.get(&id) {
                queue.extend(c.parents.iter().cloned());
            }
        }
        Ok(None)
    }

    /// 确定性提交 id 序列（C0 为基；其后 C1、C2、…，与调用顺序一致）。
    fn next_commit_id(&mut self) -> CommitId {
        let id = CommitId(format!("C{}", self.next_seq));
        self.next_seq += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_storage::InMemoryContentStore;

    fn change(path: &str, content: &[u8]) -> Change {
        Change {
            path: path.to_string(),
            content: content.to_vec(),
        }
    }

    fn new_ws() -> Workspace<InMemoryContentStore> {
        Workspace::init(WorkspaceId("ws-test".into()), InMemoryContentStore::new())
            .expect("init ok")
    }

    #[test]
    fn init_creates_base_commit_and_single_head() {
        let ws = new_ws();
        assert_eq!(ws.heads().len(), 1);
        assert_eq!(ws.heads().heads[0], CommitId("C0".into()));
        let base = ws.commit(&CommitId("C0".into())).expect("base exists");
        assert!(base.parents.is_empty());
    }

    #[test]
    fn offline_divergence_produces_two_heads() {
        let mut ws = new_ws();
        let base = CommitId("C0".into());
        let local = ws
            .commit_changes(&base, &[change("a.txt", b"local-a")])
            .expect("local commit ok");
        let remote = ws
            .commit_changes(&base, &[change("b.txt", b"remote-b")])
            .expect("remote commit ok");
        assert_eq!(local, CommitId("C1".into()));
        assert_eq!(remote, CommitId("C2".into()));
        assert_eq!(ws.heads().len(), 2);
    }

    #[test]
    fn commit_on_head_replaces_it() {
        let mut ws = new_ws();
        let base = CommitId("C0".into());
        let c1 = ws
            .commit_changes(&base, &[change("a.txt", b"v1")])
            .expect("commit ok");
        let c2 = ws
            .commit_changes(&c1, &[change("a.txt", b"v2")])
            .expect("commit ok");
        assert_eq!(ws.heads().len(), 1);
        assert_eq!(ws.heads().heads[0], c2);
    }

    #[test]
    fn three_way_merge_keeps_local_commits_and_merges_manifest() {
        let mut ws = new_ws();
        let base = CommitId("C0".into());
        let local = ws
            .commit_changes(&base, &[change("a.txt", b"local-a")])
            .expect("local ok");
        let remote = ws
            .commit_changes(&base, &[change("b.txt", b"remote-b")])
            .expect("remote ok");

        let report = ws.merge_heads(&local, &remote).expect("merge ok");

        assert_eq!(report.disposition, MergeDisposition::Diverged);
        assert_eq!(
            report.events,
            vec![EV_COMMON_ANCESTOR_FOUND, EV_MERGE_COMMIT_CREATED]
        );
        assert_eq!(report.head_count_before_merge, 2);
        assert_eq!(report.lost_successful_local_commits, 0);
        let merge = report.merge_commit.expect("merge commit created");
        assert_eq!(ws.heads().len(), 1);
        assert_eq!(ws.heads().heads[0], merge);

        // 合并提交的 Manifest 必须同时包含 a.txt 与 b.txt。
        let commit = ws.commit(&merge).expect("merge in dag");
        let manifest = ws
            .load_manifest(&commit.root_manifest_id)
            .expect("manifest ok");
        assert!(manifest.get("a.txt").is_some());
        assert!(manifest.get("b.txt").is_some());
    }

    #[test]
    fn fast_forward_when_local_is_ancestor_of_remote() {
        let mut ws = new_ws();
        let base = CommitId("C0".into());
        let c1 = ws
            .commit_changes(&base, &[change("a.txt", b"v1")])
            .expect("c1 ok");
        let c2 = ws
            .commit_changes(&c1, &[change("b.txt", b"v2")])
            .expect("c2 ok");
        // remote 分支从 base 分叉后并不存在；此处构造：local=C1，remote=C2（C1 是 C2 祖先）。
        // 先让 remote 独立于 local：直接把 c2 作为 remote 传入即可（local 是 remote 祖先）。
        let report = ws.merge_heads(&c1, &c2).expect("merge ok");
        assert_eq!(report.disposition, MergeDisposition::FastForward);
        assert!(report.merge_commit.is_none());
        assert_eq!(ws.heads().heads[0], c2);
    }

    #[test]
    fn already_equal_when_remote_is_ancestor_of_local() {
        let mut ws = new_ws();
        let base = CommitId("C0".into());
        let c1 = ws
            .commit_changes(&base, &[change("a.txt", b"v1")])
            .expect("c1 ok");
        let report = ws.merge_heads(&c1, &base).expect("merge ok");
        assert_eq!(report.disposition, MergeDisposition::AlreadyEqual);
        assert_eq!(ws.heads().len(), 1);
        assert_eq!(ws.heads().heads[0], c1);
    }

    #[test]
    fn conflicting_path_requires_explicit_resolution() {
        let mut ws = new_ws();
        let base = CommitId("C0".into());
        let local = ws
            .commit_changes(&base, &[change("a.txt", b"local-a")])
            .expect("local ok");
        let remote = ws
            .commit_changes(&base, &[change("a.txt", b"remote-a")])
            .expect("remote ok");

        let err = ws.merge_heads(&local, &remote).expect_err("must conflict");
        assert_eq!(
            err,
            WorkspaceError::MergeConflict(MergeConflict::ConflictingPath {
                path: "a.txt".into()
            })
        );
        // 冲突不得改变 Head 集（保持两个分叉 Head，等待显式解决）。
        assert_eq!(ws.heads().len(), 2);
    }

    #[test]
    fn unknown_commit_is_rejected() {
        let mut ws = new_ws();
        let err = ws
            .commit_changes(&CommitId("C9".into()), &[])
            .expect_err("must reject");
        assert_eq!(
            err,
            WorkspaceError::UnknownCommit {
                id: CommitId("C9".into())
            }
        );
    }
}
