//! Workspace 权威模型：不可变 Commit DAG + Head Set（AGENTS §16 / PRODUCT §4）。
//!
//! 本切片由 `product.workspace-offline-merge` 与 `regression.crash-recovery`
//! 两个 E4 场景驱动，实现：
//!
//! - Commit DAG 与 Head Set：多端离线写允许产生多个 Head；
//! - 重连后 fast-forward / AlreadyEqual / 三方合并 + 显式冲突检测；
//! - 合并后本地提交零丢失（`lost_successful_local_commits = 0`）；
//! - 持久状态（DAG + Heads + Journal 单对象 CAS 原子替换）与写前日志；
//! - 冷启动 `open` 恢复 + `reconcile_journal` 幂等回放（确认/redo，不丢数据）；
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

/// Head 更新动作（journal 重放时应用，与写入时保持一致）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadAction {
    /// 替换 parent Head 为新提交（普通顺序写入）。
    Replace(CommitId),
    /// 新增一个 Head（离线分叉写入）。
    Add,
}

/// 写前日志条目（journal marker）：登记一次“即将落入 DAG”的提交。
///
/// 顺序：`journal_pending`（marker 落盘，提交不可见）→ 应用提交 → `commit_pending`
/// （marker 清除）。崩溃后由 `reconcile_journal` 回放：提交已在 DAG 则确认，
/// 不在则从 marker 重放（redo），不丢失已写入数据（AGENTS.md §15）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub commit_id: CommitId,
    pub parents: Vec<CommitId>,
    pub root_manifest_id: ObjectId,
    pub head_action: HeadAction,
}

/// 日志回放报告。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalReconcileReport {
    /// marker 对应提交已在 DAG：直接确认（清理 marker）。
    pub confirmed: usize,
    /// marker 对应提交不在 DAG：从 marker 重放完成被中断的写入。
    pub redone: usize,
    /// 处理的 marker 总数。
    pub total: usize,
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
    /// 持久状态对象无法解析或校验失败。
    CorruptState { reason: String },
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
            Self::CorruptState { reason } => write!(f, "corrupt durable state: {reason}"),
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

/// 持久状态：DAG + Heads + Journal，序列化为单个 CAS 对象（原子替换）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableState {
    id: WorkspaceId,
    commits: Vec<WorkspaceCommit>,
    heads: Vec<CommitId>,
    journal: Vec<JournalEntry>,
}

impl DurableState {
    const HEADER: &'static str = "nexus-workspace-state v1";
    const HEADER_TOKEN: &'static str = "nexus-workspace-state";

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(Self::HEADER);
        out.push('\n');
        out.push_str(&format!("id {}\n", self.id.0));
        for c in &self.commits {
            let parents = c
                .parents
                .iter()
                .map(|p| p.0.as_str())
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!(
                "commit {} {} {parents}\n",
                c.id.0, c.root_manifest_id.0
            ));
        }
        for h in &self.heads {
            out.push_str(&format!("head {}\n", h.0));
        }
        for e in &self.journal {
            let action = match &e.head_action {
                HeadAction::Replace(p) => format!("replace:{}", p.0),
                HeadAction::Add => "add".to_string(),
            };
            let parents = e
                .parents
                .iter()
                .map(|p| p.0.as_str())
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!(
                "journal {} {} {action} {parents}\n",
                e.commit_id.0, e.root_manifest_id.0
            ));
        }
        out.into_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, WorkspaceError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| WorkspaceError::CorruptState {
                reason: format!("state not utf8: {e}"),
            })?
            .to_string();
        let mut id = None;
        let mut commits = Vec::new();
        let mut heads = Vec::new();
        let mut journal = Vec::new();
        for line in text.lines() {
            let mut t = line.split_whitespace();
            match t.next() {
                Some("id") => {
                    let raw = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "state line lacks id".into(),
                    })?;
                    id = Some(WorkspaceId(raw.to_string()));
                }
                Some("commit") => {
                    let raw_id = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "commit line lacks id".into(),
                    })?;
                    let raw_manifest = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("commit {raw_id} lacks manifest id"),
                    })?;
                    let parents = t
                        .next()
                        .unwrap_or("")
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(|p| CommitId(p.to_string()))
                        .collect();
                    commits.push(WorkspaceCommit {
                        id: CommitId(raw_id.to_string()),
                        parents,
                        root_manifest_id: ObjectId(raw_manifest.to_string()),
                    });
                }
                Some("head") => {
                    let raw = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "head line lacks id".into(),
                    })?;
                    heads.push(CommitId(raw.to_string()));
                }
                Some("journal") => {
                    let raw_id = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: "journal line lacks commit id".into(),
                    })?;
                    let raw_manifest = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("journal {raw_id} lacks manifest id"),
                    })?;
                    let action = t.next().ok_or_else(|| WorkspaceError::CorruptState {
                        reason: format!("journal {raw_id} lacks head action"),
                    })?;
                    let head_action = if let Some(parent) = action.strip_prefix("replace:") {
                        HeadAction::Replace(CommitId(parent.to_string()))
                    } else if action == "add" {
                        HeadAction::Add
                    } else {
                        return Err(WorkspaceError::CorruptState {
                            reason: format!("unknown head action {action}"),
                        });
                    };
                    let parents = t
                        .next()
                        .unwrap_or("")
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(|p| CommitId(p.to_string()))
                        .collect();
                    journal.push(JournalEntry {
                        commit_id: CommitId(raw_id.to_string()),
                        parents,
                        root_manifest_id: ObjectId(raw_manifest.to_string()),
                        head_action,
                    });
                }
                Some(line) if line == Self::HEADER_TOKEN => {}
                Some(other) => {
                    return Err(WorkspaceError::CorruptState {
                        reason: format!("unexpected line kind {other}"),
                    });
                }
                None => {}
            }
        }
        let id = id.ok_or_else(|| WorkspaceError::CorruptState {
            reason: "state lacks workspace id".into(),
        })?;
        if commits.is_empty() || heads.is_empty() {
            return Err(WorkspaceError::CorruptState {
                reason: "state has no commits or heads".into(),
            });
        }
        Ok(Self {
            id,
            commits,
            heads,
            journal,
        })
    }
}

/// Workspace 权威状态：不可变 Commit DAG + Head Set + 内容寻址存储 + 写前日志。
#[derive(Debug)]
pub struct Workspace<S: ContentStore> {
    id: WorkspaceId,
    commits: HashMap<CommitId, WorkspaceCommit>,
    heads: HeadSet,
    store: S,
    next_seq: u64,
    /// 当前持久状态对象（DAG + Heads + Journal）。
    state_root: ObjectId,
    /// 写前日志（未确认的 pending 提交 marker）。
    journal: Vec<JournalEntry>,
}

/// 从提交 id 解析序号（`C0` -> 0）；无法解析返回 `None`。
fn seq_of(id: &CommitId) -> Option<u64> {
    id.0.strip_prefix('C')?.parse().ok()
}

impl<S: ContentStore> Workspace<S> {
    /// 新建 Workspace：创建空 Manifest 的 Base Commit `C0`，Head = `[C0]`，
    /// 并持久化初始状态。
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
            state_root: ObjectId(String::new()),
            journal: Vec::new(),
        };
        ws.commits.insert(base.id.clone(), base.clone());
        ws.heads.add(base.id.clone());
        ws.persist_state()?;
        Ok(ws)
    }

    /// 冷启动：从持久状态对象恢复 Workspace（AGENTS.md §15：先加载 durable state）。
    pub fn open(id: WorkspaceId, store: S, state_root: &ObjectId) -> Result<Self, WorkspaceError> {
        let bytes = store
            .get(state_root)
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?
            .ok_or_else(|| WorkspaceError::MissingObject {
                id: state_root.clone(),
            })?;
        let state = DurableState::from_bytes(&bytes)?;
        if state.id != id {
            return Err(WorkspaceError::CorruptState {
                reason: format!("state id {:?} does not match {:?}", state.id, id),
            });
        }
        let mut commits = HashMap::new();
        for c in &state.commits {
            commits.insert(c.id.clone(), c.clone());
        }
        let mut heads = HeadSet::default();
        for h in &state.heads {
            heads.add(h.clone());
        }
        let next_seq = state
            .commits
            .iter()
            .map(|c| &c.id)
            .chain(state.journal.iter().map(|e| &e.commit_id))
            .filter_map(seq_of)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1);
        Ok(Self {
            id,
            commits,
            heads,
            store,
            next_seq,
            state_root: state_root.clone(),
            journal: state.journal,
        })
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

    /// 当前持久状态对象 id（供冷启动 `open` 恢复）。
    #[must_use]
    pub fn state_root(&self) -> &ObjectId {
        &self.state_root
    }

    /// 交出底层存储（模拟进程死亡后保留持久对象的场景）。
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// 按 id 读取提交（只读 DAG 查询）。
    #[must_use]
    pub fn commit(&self, id: &CommitId) -> Option<&WorkspaceCommit> {
        self.commits.get(id)
    }

    /// 把当前内存状态（DAG + Heads + Journal）持久化为单个 CAS 对象。
    fn persist_state(&mut self) -> Result<ObjectId, WorkspaceError> {
        let mut commits: Vec<WorkspaceCommit> = self.commits.values().cloned().collect();
        commits.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        let state = DurableState {
            id: self.id.clone(),
            commits,
            heads: self.heads.heads.clone(),
            journal: self.journal.clone(),
        };
        let oid = self
            .store
            .put(&state.to_bytes())
            .map_err(|reason| WorkspaceError::StoreFailure { reason })?;
        self.state_root = oid.clone();
        Ok(oid)
    }

    /// 写前登记：为一次“即将落 DAG”的提交写入 journal marker（marker 落盘，
    /// 提交尚未可见）。返回新提交 id；随后应调用 `commit_pending` 完成写入。
    pub fn journal_pending(
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
        let head_action = if self.heads.contains(parent) {
            HeadAction::Replace(parent.clone())
        } else {
            HeadAction::Add
        };
        self.journal.push(JournalEntry {
            commit_id: id.clone(),
            parents: vec![parent.clone()],
            root_manifest_id,
            head_action,
        });
        // 写前日志：marker 先于提交落盘。
        self.persist_state()?;
        Ok(id)
    }

    /// 完成一次 pending 写入：把 journal 中登记的提交落入 DAG 并更新 Head，
    /// 然后清除 marker（幂等：仅当该提交尚未提交时生效）。
    pub fn commit_pending(&mut self, pending: &CommitId) -> Result<CommitId, WorkspaceError> {
        let Some(idx) = self.journal.iter().position(|e| e.commit_id == *pending) else {
            return Err(WorkspaceError::UnknownCommit {
                id: pending.clone(),
            });
        };
        let entry = self.journal.remove(idx);
        let commit = WorkspaceCommit {
            id: entry.commit_id.clone(),
            parents: entry.parents.clone(),
            root_manifest_id: entry.root_manifest_id.clone(),
        };
        self.commits.insert(entry.commit_id.clone(), commit);
        match &entry.head_action {
            HeadAction::Replace(old) => self.heads.replace(old, entry.commit_id.clone()),
            HeadAction::Add => self.heads.add(entry.commit_id.clone()),
        }
        self.persist_state()?;
        Ok(entry.commit_id)
    }

    /// 离线写入：写前登记 + 完成提交（marker 落盘 -> 落 DAG -> 清除 marker）。
    ///
    /// - `parent` 是当前 Head → 替换该 Head；
    /// - 否则 → 追加新 Head（多端离线分叉，AGENTS §16）。
    pub fn commit_changes(
        &mut self,
        parent: &CommitId,
        changes: &[Change],
    ) -> Result<CommitId, WorkspaceError> {
        let id = self.journal_pending(parent, changes)?;
        self.commit_pending(&id)
    }

    /// 冷启动日志回放（AGENTS.md §15）：对 journal 中每个 marker，
    /// 提交已在 DAG → 确认；不在 → 从 marker 重放（redo）完成中断写入。
    /// 回放后 journal 为空并持久化，幂等。
    pub fn reconcile_journal(&mut self) -> Result<JournalReconcileReport, WorkspaceError> {
        let entries = std::mem::take(&mut self.journal);
        let mut confirmed = 0usize;
        let mut redone = 0usize;
        for entry in entries {
            if self.commits.contains_key(&entry.commit_id) {
                confirmed += 1;
                continue;
            }
            // 提交未落 DAG：从 marker 重放，完成被中断的写入（不丢数据）。
            let commit = WorkspaceCommit {
                id: entry.commit_id.clone(),
                parents: entry.parents.clone(),
                root_manifest_id: entry.root_manifest_id.clone(),
            };
            self.commits.insert(entry.commit_id.clone(), commit);
            match &entry.head_action {
                HeadAction::Replace(old) => self.heads.replace(old, entry.commit_id.clone()),
                HeadAction::Add => self.heads.add(entry.commit_id.clone()),
            }
            self.next_seq = self
                .next_seq
                .max(seq_of(&entry.commit_id).map(|s| s + 1).unwrap_or(1));
            redone += 1;
        }
        self.persist_state()?;
        Ok(JournalReconcileReport {
            confirmed,
            redone,
            total: confirmed + redone,
        })
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
            self.persist_state()?;
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
        self.persist_state()?;
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

    // ---------- 持久状态 / 写前日志 / 冷启动 reconcile ----------

    #[test]
    fn open_restores_durable_state_roundtrip() {
        let mut ws = new_ws();
        let c1 = ws
            .commit_changes(&CommitId("C0".into()), &[change("a.txt", b"v1")])
            .expect("commit ok");
        let root = ws.state_root().clone();
        let store = ws.into_store();

        let mut restored =
            Workspace::open(WorkspaceId("ws-test".into()), store, &root).expect("open ok");
        assert_eq!(restored.heads().len(), 1);
        assert_eq!(restored.heads().heads[0], c1);
        // 恢复后可继续写入（next_seq 越过已恢复提交）。
        let c2 = restored
            .commit_changes(&c1, &[change("b.txt", b"v2")])
            .expect("continue ok");
        assert_eq!(c2, CommitId("C2".into()));
    }

    #[test]
    fn journal_pending_then_commit_clears_marker() {
        let mut ws = new_ws();
        let pending = ws
            .journal_pending(&CommitId("C0".into()), &[change("a.txt", b"v1")])
            .expect("pending ok");
        assert_eq!(pending, CommitId("C1".into()));
        // 提交尚未可见。
        assert!(ws.commit(&pending).is_none());
        let committed = ws.commit_pending(&pending).expect("commit pending ok");
        assert_eq!(committed, pending);
        assert!(ws.commit(&pending).is_some());
        // 日志已清空。
        let report = ws.reconcile_journal().expect("reconcile ok");
        assert_eq!(report.total, 0);
    }

    #[test]
    fn reconcile_redoes_interrupted_write_from_marker() {
        let mut ws = new_ws();
        // 写前登记后“进程崩溃”：marker 落盘，提交未落 DAG。
        let pending = ws
            .journal_pending(&CommitId("C0".into()), &[change("a.txt", b"crash-a")])
            .expect("pending ok");
        let root = ws.state_root().clone();
        let store = ws.into_store();

        // 冷启动：从持久状态恢复，回放日志 → redo 完成中断写入，不丢数据。
        let mut restored =
            Workspace::open(WorkspaceId("ws-test".into()), store, &root).expect("open ok");
        let report = restored.reconcile_journal().expect("reconcile ok");
        assert_eq!(report.redone, 1);
        assert_eq!(report.total, 1);
        assert_eq!(restored.heads().len(), 1);
        assert_eq!(restored.heads().heads[0], pending);
        assert!(restored.commit(&pending).is_some());
        // 幂等：再次回放无内容。
        let report2 = restored.reconcile_journal().expect("reconcile ok 2");
        assert_eq!(report2.total, 0);
    }

    #[test]
    fn reconcile_confirms_already_applied_commit() {
        let mut ws = new_ws();
        let c1 = ws
            .commit_changes(&CommitId("C0".into()), &[change("a.txt", b"v1")])
            .expect("commit ok");
        let root = ws.state_root().clone();
        let store = ws.into_store();

        let mut restored =
            Workspace::open(WorkspaceId("ws-test".into()), store, &root).expect("open ok");
        // 提交已落 DAG（且 marker 已确认），回放无待处理 marker。
        let report = restored.reconcile_journal().expect("reconcile ok");
        assert_eq!(report.total, 0);
        assert_eq!(restored.heads().heads[0], c1);
    }
}
